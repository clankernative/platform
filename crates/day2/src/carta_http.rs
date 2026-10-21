//! Native Carta HTTPS port. Every origin, path, method and header is fixed here:
//! no resource, application field or provider response can select one.
//!
//! The port speaks the wire only. It authenticates the client with HTTP Basic at
//! the fixed token endpoint and presents the capture's bearer to the fixed issuer
//! routes; [`crate::carta_live`] owns order, pagination, bounds and
//! classification. Its own client follows no redirect, retries nothing, uses no
//! proxy, cookie or content encoding, and keeps no idle connection.
use crate::carta_live::{AccessToken, CapturePlan, CartaPort, Collection, Failure, Reply};
use anyhow::Result;
use base64::Engine as _;
use day2_capabilities::integrations::CartaEnvironment;
use std::{io::Read, time::Duration};

const PRODUCTION_LOGIN_ORIGIN: &str = "https://login.app.carta.com";
const PRODUCTION_API_ORIGIN: &str = "https://api.carta.com";
// Pinned for qualification. The inspected client paired the playground login
// with a mock API origin, which is not admitted here.
const PLAYGROUND_LOGIN_ORIGIN: &str = "https://login.playground.carta.team";
const PLAYGROUND_API_ORIGIN: &str = "https://api.playground.carta.team";
const TOKEN_PATH: &str = "/o/access_token/";
/// The whole capture, checked before every request. Each request also has its
/// own transport timeout.
pub const CAPTURE_DEADLINE_SECONDS: i64 = 180;
const MAX_RETRY_AFTER_SECONDS: u32 = 86_400;

/// The fixed (login, API) origins of a Carta environment.
pub fn origins(environment: CartaEnvironment) -> (&'static str, &'static str) {
    match environment {
        CartaEnvironment::Production => (PRODUCTION_LOGIN_ORIGIN, PRODUCTION_API_ORIGIN),
        CartaEnvironment::Playground => (PLAYGROUND_LOGIN_ORIGIN, PLAYGROUND_API_ORIGIN),
    }
}

/// The OAuth client secret. Sent only as HTTP Basic to the fixed token
/// endpoint. A distinct type from bearer credentials, with no Debug, Clone,
/// Serialize or bearer constructor, so it cannot reach an Authorization bearer
/// header, a receipt or a log.
pub struct CartaClientSecret(String);

impl CartaClientSecret {
    pub(crate) fn new(value: String) -> std::result::Result<Self, Failure> {
        if value.is_empty() || value.len() > 16_384 || !value.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(Failure::CredentialUnavailable);
        }
        Ok(Self(value))
    }
}

pub struct NativeCartaPort {
    client: reqwest::blocking::Client,
    token_endpoint: reqwest::Url,
    api_origin: reqwest::Url,
    issuer_id: String,
    client_id: String,
    secret: CartaClientSecret,
    clock: fn() -> Result<i64>,
    deadline: i64,
}

impl NativeCartaPort {
    pub fn new(
        plan: &CapturePlan,
        client_id: &str,
        secret: CartaClientSecret,
    ) -> std::result::Result<Self, Failure> {
        let (login, api) = origins(plan.environment());
        let client = reqwest::blocking::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            // No cookie store is installed (default disabled).
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(0)
            .user_agent("day2-carta-capture/1")
            .build()
            .map_err(|_| Failure::Unavailable)?;
        Self::with(
            client,
            plan,
            client_id,
            secret,
            [login, api],
            crate::oauth::effects::wall_time,
        )
    }

    fn with(
        client: reqwest::blocking::Client,
        plan: &CapturePlan,
        client_id: &str,
        secret: CartaClientSecret,
        [login, api]: [&str; 2],
        clock: fn() -> Result<i64>,
    ) -> std::result::Result<Self, Failure> {
        let parse = |origin: &str| reqwest::Url::parse(origin).map_err(|_| Failure::Unavailable);
        let deadline = clock()
            .ok()
            .and_then(|now| now.checked_add(CAPTURE_DEADLINE_SECONDS))
            .ok_or(Failure::Unavailable)?;
        Ok(Self {
            client,
            token_endpoint: parse(login)?
                .join(TOKEN_PATH)
                .map_err(|_| Failure::Unavailable)?,
            api_origin: parse(api)?,
            issuer_id: plan.issuer_id().into(),
            client_id: client_id.into(),
            secret,
            clock,
            deadline,
        })
    }

    /// Loopback HTTP origins for request-exact transport tests only.
    #[cfg(test)]
    pub(crate) fn transport_fixture(
        plan: &CapturePlan,
        client_id: &str,
        secret: CartaClientSecret,
        origins: [&str; 2],
        clock: fn() -> Result<i64>,
    ) -> Result<Self> {
        for origin in origins {
            let url = reqwest::Url::parse(origin)?;
            anyhow::ensure!(
                url.scheme() == "http"
                    && matches!(url.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && (url.path().is_empty() || url.path() == "/"),
                "invalid_carta_fixture_origin"
            );
        }
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(0)
            .build()?;
        Ok(Self::with(client, plan, client_id, secret, origins, clock)?)
    }

    fn before_request(&self) -> std::result::Result<(), Failure> {
        match (self.clock)() {
            Ok(now) if now < self.deadline => Ok(()),
            _ => Err(Failure::Unavailable),
        }
    }

    fn exchange(
        &self,
        request: reqwest::blocking::RequestBuilder,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Failure> {
        let response = request
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .send()
            .map_err(|_| Failure::Unavailable)?;
        let status = response.status().as_u16();
        let headers = response.headers();
        let json = headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"));
        if headers
            .get(reqwest::header::CONTENT_ENCODING)
            .is_some_and(|value| value != "identity")
        {
            return Err(Failure::ResponseInvalid);
        }
        // Seconds only; an HTTP date is not interpreted.
        let retry_after_seconds = headers
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u32>().ok())
            .filter(|seconds| *seconds <= MAX_RETRY_AFTER_SECONDS);
        if response
            .content_length()
            .is_some_and(|size| size > max_bytes as u64)
        {
            return Err(Failure::ResponseTooLarge);
        }
        let mut body = Vec::new();
        response
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|_| Failure::Unavailable)?;
        Ok(Reply {
            status,
            json,
            body,
            retry_after_seconds,
        })
    }
}

impl CartaPort for NativeCartaPort {
    fn token(&mut self, form: &str, max_bytes: usize) -> std::result::Result<Reply, Failure> {
        self.before_request()?;
        let credentials = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.client_id, self.secret.0));
        let mut authorization =
            reqwest::header::HeaderValue::from_str(&format!("Basic {credentials}"))
                .map_err(|_| Failure::CredentialUnavailable)?;
        authorization.set_sensitive(true);
        self.exchange(
            self.client
                .post(self.token_endpoint.clone())
                .header(reqwest::header::AUTHORIZATION, authorization)
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(form.to_owned()),
            max_bytes,
        )
    }

    fn page(
        &mut self,
        collection: Collection,
        query: Option<&str>,
        token: &AccessToken,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Failure> {
        self.before_request()?;
        let mut url = self
            .api_origin
            .join(&crate::carta_live::collection_path(
                &self.issuer_id,
                collection,
            ))
            .map_err(|_| Failure::Unavailable)?;
        url.set_query(query);
        let mut authorization =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.bearer()))
                .map_err(|_| Failure::AuthenticationFailed)?;
        authorization.set_sensitive(true);
        self.exchange(
            self.client
                .get(url)
                .header(reqwest::header::AUTHORIZATION, authorization),
            max_bytes,
        )
    }
}

#[cfg(test)]
#[path = "carta_http_tests.rs"]
mod tests;
