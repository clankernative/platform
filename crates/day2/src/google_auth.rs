//! Keyless Google service-account tokens, shared by every Google provider.
//!
//! The runtime's workload identity reads the fixed metadata token endpoint; IAM
//! Credentials then mints an access token for the reviewed service account,
//! either directly (`generateAccessToken`) or, for domain-wide delegation, by
//! signing a five-minute JWT for one subject that the fixed token endpoint
//! exchanges. This module decides every byte that is sent and everything that is
//! accepted. A provider's [`TokenWire`] owns only the HTTP: it builds each URL
//! from fixed origins, never retries or follows a redirect, and reads at most the
//! bound it is given plus one probe byte. No token is cached; each lives for one
//! provider action.
use anyhow::Result;
use base64::Engine as _;
use serde::Deserialize;
use std::{io::Read, time::Duration};

pub const METADATA_ORIGIN: &str = "http://metadata.google.internal";
pub const IAM_ORIGIN: &str = "https://iamcredentials.googleapis.com";
pub const OAUTH_ORIGIN: &str = "https://oauth2.googleapis.com";
/// The JWT audience, and where a delegated assertion is exchanged.
pub const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const METADATA_TOKEN_PATH: &str = "/computeMetadata/v1/instance/service-accounts/default/token";
/// Every authentication response: metadata, IAM and the token endpoint.
pub const MAX_EXCHANGE_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_TOKEN_BYTES: usize = 8192;
const DELEGATED_LIFETIME_SECONDS: i64 = 300;
const MAX_RETRY_AFTER_SECONDS: u32 = 86_400;

/// Who the minted token acts as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Identity<'a> {
    /// The service account itself.
    ServiceAccount,
    /// Domain-wide delegation to one subject in the customer's domain.
    Delegated(&'a str),
}

/// Everything a token is minted for. Scopes are fixed by the calling action.
#[derive(Clone, Copy, Debug)]
pub struct TokenRequest<'a> {
    pub service_account: &'a str,
    pub identity: Identity<'a>,
    pub scopes: &'a [&'a str],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IamMethod {
    GenerateAccessToken,
    SignJwt,
}

impl IamMethod {
    pub fn name(self) -> &'static str {
        match self {
            Self::GenerateAccessToken => "generateAccessToken",
            Self::SignJwt => "signJwt",
        }
    }
}

/// The workload identity's own token. Presented only to IAM; no Debug, Clone or
/// Serialize, so it cannot reach a receipt, journal or log.
pub struct WorkloadToken(String);

impl WorkloadToken {
    pub(crate) fn bearer(&self) -> &str {
        &self.0
    }
}

/// The minted provider token. Held in memory for one action only.
pub struct AccessToken(String);

impl AccessToken {
    pub(crate) fn bearer(&self) -> &str {
        &self.0
    }
}

/// One authentication exchange, exactly as decided here.
pub enum Exchange<'a> {
    /// `GET {metadata}/computeMetadata/v1/instance/service-accounts/default/token`
    /// with `Metadata-Flavor: Google`.
    Metadata,
    /// `POST {iam}/v1/projects/-/serviceAccounts/{account}:{method}` with the
    /// workload bearer and a JSON body.
    Iam {
        service_account: &'a str,
        method: IamMethod,
        bearer: &'a WorkloadToken,
        body: &'a [u8],
    },
    /// `POST {oauth}/token` with the form-encoded JWT-bearer grant.
    Token { form: &'a str },
}

impl Exchange<'_> {
    /// The payload a request budget counts: the body of a POST.
    pub fn request_bytes(&self) -> usize {
        match self {
            Self::Metadata => 0,
            Self::Iam { body, .. } => body.len(),
            Self::Token { form } => form.len(),
        }
    }
}

/// A reply as the wire returned it. `body` holds at most the caller's bound plus
/// one probe byte, so an oversized response is observable without being read.
pub struct Reply {
    pub status: u16,
    /// The response declared `Metadata-Flavor: Google`.
    pub metadata_flavor: bool,
    /// The response declared `application/json`.
    pub json: bool,
    pub body: Vec<u8>,
    pub retry_after_seconds: Option<u32>,
}

/// How far an exchange got without a complete reply: the bytes it consumed and
/// any status the response head declared. Never a body, header value or URL.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Unreached {
    pub response_bytes: u64,
    pub http_status: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    /// The response declared a body past the bound, so none of it was read.
    pub too_large: bool,
}

impl Unreached {
    fn failure(self) -> Failure {
        if self.too_large {
            Failure::ResponseTooLarge
        } else {
            Failure::Unavailable
        }
    }
}

/// The HTTP half of token acquisition. Implementations send exactly the
/// exchange they are given and report the reply; classification is here.
pub trait TokenWire {
    fn exchange(
        &mut self,
        exchange: &Exchange<'_>,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Unreached>;
}

/// Stable, redacted acquisition failures. A provider maps them to its own codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The metadata server issued no usable workload token.
    WorkloadIdentityUnavailable,
    /// IAM or the token endpoint refused, or answered outside the plan.
    AuthenticationFailed,
    /// IAM or the token endpoint answered 429.
    RateLimited,
    /// No complete reply, or a 5xx.
    Unavailable,
    /// A reply past the exchange bound.
    ResponseTooLarge,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IamToken {
    pub(crate) access_token: Option<String>,
    pub(crate) signed_jwt: Option<String>,
    pub(crate) key_id: Option<String>,
}

/// The IAM response must match the selected flow, so provider data can never
/// switch a direct plan to a delegated one or back.
pub(crate) fn validate_iam_token_shape(token: &IamToken, delegated: bool) -> Result<(), Failure> {
    let matches_plan = if delegated {
        token.access_token.is_none()
            && token.signed_jwt.is_some()
            && token.key_id.as_ref().is_some_and(|key| !key.is_empty())
    } else {
        token.access_token.is_some() && token.signed_jwt.is_none() && token.key_id.is_none()
    };
    matches_plan
        .then_some(())
        .ok_or(Failure::AuthenticationFailed)
}

fn token_shape(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOKEN_BYTES
        && value.bytes().all(|b| b.is_ascii_graphic())
}

/// Classify an IAM or token-endpoint reply before its body is parsed.
fn accept(reply: &Reply, max_bytes: usize) -> Result<(), Failure> {
    match reply.status {
        200..=299 => {}
        429 => return Err(Failure::RateLimited),
        500..=599 => return Err(Failure::Unavailable),
        _ => return Err(Failure::AuthenticationFailed),
    }
    if reply.body.len() > max_bytes {
        return Err(Failure::ResponseTooLarge);
    }
    Ok(())
}

/// The direct `generateAccessToken` body.
pub fn direct_body(scopes: &[&str]) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(
        &serde_json::json!({"scope":scopes,"lifetime":"3600s"}),
    )?)
}

/// The JWT claims IAM is asked to sign for one delegated subject.
pub fn delegated_claims(
    service_account: &str,
    subject: &str,
    scopes: &[&str],
    now: i64,
) -> Result<String, Failure> {
    let claims = serde_json::json!({"iss":service_account,"sub":subject,"aud":GOOGLE_TOKEN_ENDPOINT,"iat":now,"exp":now.checked_add(DELEGATED_LIFETIME_SECONDS).ok_or(Failure::AuthenticationFailed)?,"scope":scopes.join(" ")});
    serde_json::to_string(&claims).map_err(|_| Failure::AuthenticationFailed)
}

/// The JWT-bearer grant form for a signed assertion.
pub fn assertion_form(jwt: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
        .append_pair("assertion", jwt)
        .finish()
}

/// Every claim of the signed JWT is checked against the plan before it is
/// presented anywhere: IAM cannot widen the subject, scopes or lifetime.
fn validate_signed_jwt(
    jwt: &str,
    key_id: Option<&str>,
    service_account: &str,
    subject: &str,
    scopes: &[&str],
    now: i64,
) -> Result<(), Failure> {
    let failed = |_| Failure::AuthenticationFailed;
    if jwt.len() > MAX_TOKEN_BYTES || jwt.split('.').count() != 3 {
        return Err(Failure::AuthenticationFailed);
    }
    let parts: Vec<_> = jwt.split('.').collect();
    let decode = |part: &str| -> Result<serde_json::Value, Failure> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .map_err(|_| Failure::AuthenticationFailed)?;
        crate::json::decode(&bytes).map_err(failed)
    };
    let header = decode(parts[0])?;
    let claims = decode(parts[1])?;
    let matches = header["alg"] == "RS256"
        && header["kid"].as_str() == key_id
        && claims["iss"] == *service_account
        && claims["sub"] == *subject
        && claims["aud"] == GOOGLE_TOKEN_ENDPOINT
        && claims["iat"] == now
        && now.checked_add(DELEGATED_LIFETIME_SECONDS) == claims["exp"].as_i64()
        && claims["scope"] == scopes.join(" ");
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| Failure::AuthenticationFailed)?;
    (matches && signature.len() >= 64)
        .then_some(())
        .ok_or(Failure::AuthenticationFailed)
}

/// Mint one access token through `wire`. Exchanges run in a fixed order and stop
/// at the first refusal; nothing is retried.
pub fn acquire(
    wire: &mut dyn TokenWire,
    request: &TokenRequest<'_>,
    now: i64,
) -> Result<AccessToken, Failure> {
    let max = MAX_EXCHANGE_RESPONSE_BYTES;
    let workload = {
        let reply = wire
            .exchange(&Exchange::Metadata, max)
            .map_err(|_| Failure::WorkloadIdentityUnavailable)?;
        if !(200..=299).contains(&reply.status) || !reply.metadata_flavor || reply.body.len() > max
        {
            return Err(Failure::WorkloadIdentityUnavailable);
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        struct MetadataToken {
            access_token: String,
            token_type: String,
        }
        let token: MetadataToken =
            crate::json::decode(&reply.body).map_err(|_| Failure::WorkloadIdentityUnavailable)?;
        if token.token_type != "Bearer" || !token_shape(&token.access_token) {
            return Err(Failure::WorkloadIdentityUnavailable);
        }
        WorkloadToken(token.access_token)
    };
    let (method, body) = match request.identity {
        Identity::ServiceAccount => (
            IamMethod::GenerateAccessToken,
            direct_body(request.scopes).map_err(|_| Failure::AuthenticationFailed)?,
        ),
        Identity::Delegated(subject) => {
            let claims = delegated_claims(request.service_account, subject, request.scopes, now)?;
            (
                IamMethod::SignJwt,
                serde_json::to_vec(&serde_json::json!({"payload":claims}))
                    .map_err(|_| Failure::AuthenticationFailed)?,
            )
        }
    };
    let reply = wire
        .exchange(
            &Exchange::Iam {
                service_account: request.service_account,
                method,
                bearer: &workload,
                body: &body,
            },
            max,
        )
        .map_err(Unreached::failure)?;
    accept(&reply, max)?;
    let result: IamToken =
        crate::json::decode(&reply.body).map_err(|_| Failure::AuthenticationFailed)?;
    let delegated = matches!(request.identity, Identity::Delegated(_));
    validate_iam_token_shape(&result, delegated)?;
    let access_token = match request.identity {
        Identity::Delegated(subject) => {
            let jwt = result.signed_jwt.ok_or(Failure::AuthenticationFailed)?;
            validate_signed_jwt(
                &jwt,
                result.key_id.as_deref(),
                request.service_account,
                subject,
                request.scopes,
                now,
            )?;
            let form = assertion_form(&jwt);
            let reply = wire
                .exchange(&Exchange::Token { form: &form }, max)
                .map_err(Unreached::failure)?;
            accept(&reply, max)?;
            #[derive(Deserialize)]
            struct OAuthToken {
                access_token: String,
                token_type: String,
            }
            let token: OAuthToken =
                crate::json::decode(&reply.body).map_err(|_| Failure::AuthenticationFailed)?;
            if token.token_type != "Bearer" {
                return Err(Failure::AuthenticationFailed);
            }
            token.access_token
        }
        Identity::ServiceAccount => result.access_token.ok_or(Failure::AuthenticationFailed)?,
    };
    token_shape(&access_token)
        .then_some(AccessToken(access_token))
        .ok_or(Failure::AuthenticationFailed)
}

/// The fixed authentication origins. Production is the only constructor outside
/// tests; nothing about a URL is configurable.
pub struct Origins {
    metadata: reqwest::Url,
    iam: reqwest::Url,
    token_endpoint: reqwest::Url,
}

impl Origins {
    pub fn production() -> Result<Self> {
        Ok(Self {
            metadata: reqwest::Url::parse(METADATA_ORIGIN)?,
            iam: reqwest::Url::parse(IAM_ORIGIN)?,
            token_endpoint: reqwest::Url::parse(GOOGLE_TOKEN_ENDPOINT)?,
        })
    }

    /// Loopback origins for request-exact transport tests.
    #[cfg(test)]
    pub(crate) fn fixture(
        metadata: reqwest::Url,
        iam: reqwest::Url,
        token_endpoint: reqwest::Url,
    ) -> Self {
        Self {
            metadata,
            iam,
            token_endpoint,
        }
    }
}

/// One authentication exchange over a provider's native client. `provider`
/// names the request-timing phase; it never carries an account or token.
pub fn send_native(
    client: &reqwest::blocking::Client,
    origins: &Origins,
    provider: &'static str,
    exchange: &Exchange<'_>,
    max_bytes: usize,
) -> std::result::Result<Reply, Unreached> {
    // Each exchange sends from its own arm, so every network call site stays a
    // separately reviewed entry in the architecture inventory.
    match exchange {
        Exchange::Metadata => {
            let url = origins
                .metadata
                .join(METADATA_TOKEN_PATH)
                .map_err(|_| Unreached::default())?;
            let mut timing = crate::request_timing::provider(provider, "metadata_token");
            let response = client
                .get(url)
                .header("Metadata-Flavor", "Google")
                .send()
                .map_err(|_| Unreached::default())?;
            timing.status(response.status().as_u16());
            read_native(response, max_bytes)
        }
        Exchange::Iam {
            service_account,
            method,
            bearer,
            body,
        } => {
            let mut url = origins.iam.clone();
            url.path_segments_mut()
                .map_err(|_| Unreached::default())?
                .clear()
                .extend(["v1", "projects", "-", "serviceAccounts"])
                .push(&format!("{service_account}:{}", method.name()));
            let mut authorization =
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", bearer.bearer()))
                    .map_err(|_| Unreached::default())?;
            authorization.set_sensitive(true);
            let mut timing = crate::request_timing::provider(
                provider,
                match method {
                    IamMethod::GenerateAccessToken => "iam_token",
                    IamMethod::SignJwt => "iam_sign_jwt",
                },
            );
            let response = client
                .post(url)
                .header(reqwest::header::AUTHORIZATION, authorization)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec())
                .send()
                .map_err(|_| Unreached::default())?;
            timing.status(response.status().as_u16());
            read_native(response, max_bytes)
        }
        Exchange::Token { form } => {
            let mut timing = crate::request_timing::provider(provider, "oauth_token");
            let response = client
                .post(origins.token_endpoint.clone())
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body((*form).to_owned())
                .send()
                .map_err(|_| Unreached::default())?;
            timing.status(response.status().as_u16());
            read_native(response, max_bytes)
        }
    }
}

/// Read a native response under `max_bytes` plus one probe byte. A failed read
/// keeps the bytes it consumed and the status the head declared.
pub fn read_native(
    response: reqwest::blocking::Response,
    max_bytes: usize,
) -> std::result::Result<Reply, Unreached> {
    let status = response.status().as_u16();
    let headers = response.headers();
    let metadata_flavor = headers
        .get("Metadata-Flavor")
        .is_some_and(|value| value == "Google");
    let json = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"));
    // Seconds only; an HTTP date is not interpreted.
    let retry_after_seconds = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|seconds| *seconds <= MAX_RETRY_AFTER_SECONDS);
    let unreached = |response_bytes: usize| Unreached {
        response_bytes: response_bytes as u64,
        http_status: Some(status),
        retry_after_seconds,
        too_large: false,
    };
    if response
        .content_length()
        .is_some_and(|size| size > max_bytes as u64)
    {
        // Declared too large: nothing is read.
        return Err(Unreached {
            too_large: true,
            ..unreached(0)
        });
    }
    let mut body = Vec::new();
    if response
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut body)
        .is_err()
    {
        return Err(unreached(body.len()));
    }
    Ok(Reply {
        status,
        metadata_flavor,
        json,
        body,
        retry_after_seconds,
    })
}

/// The fixed-origin client every native Google port builds: no proxy, redirect
/// or retry, and bounded connect and request deadlines.
pub fn native_client(https_only: bool) -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .https_only(https_only)
        .build()?)
}

#[cfg(test)]
#[path = "google_auth_tests.rs"]
mod tests;
