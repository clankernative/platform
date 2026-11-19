//! Internal-tools app library: the tools the internal-tools control plane has
//! registered and where each launches, for `internal_tools.app_library.v1`.
//!
//! One read is one complete, bounded collection made as the host's own
//! workload: a keyless IAP credential signed through IAM Credentials for the
//! connection's service account and audience, one service-token exchange for
//! the reviewed `control-plane.app-library.read` scope, then every library
//! page. Nothing is cached. The service token lives in memory for this read
//! only and never reaches a result, journal, receipt or log.
//!
//! This pipeline owns request order, pagination, bounds, classification and
//! the projection to `{app_id, name, url}`. A port owns only the wire: the
//! native port speaks HTTPS to the connection's origin and the simulated port
//! serves the provider's committed world, so both lanes share one parser.
use anyhow::{Result, ensure};
use day2_capabilities::integrations::{LiveConnection, dns_label, dns_name};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt, io::Read, path::Path, sync::Arc, time::Duration};

pub const SERVICE_SCOPE: &str = "control-plane.app-library.read";
pub const SERVICE_TOKEN_PATH: &str = "/api/internal-tools/service-tokens";
pub const LIBRARY_PATH: &str = "/api/app-library";
pub const SERVICE_HEADER: &str = "x-internal-tools-service";
pub const MAX_APPS: usize = 1_000;
pub const PAGE_SIZE: usize = 100;
pub const MAX_PAGES: u16 = (MAX_APPS / PAGE_SIZE) as u16;
pub const MAX_PAGE_RESPONSE_BYTES: usize = 1_048_576;
/// Every library page of one read together.
pub const MAX_AGGREGATE_PAGE_BYTES: usize = 3 * 1_048_576;
pub const MAX_TOKEN_RESPONSE_BYTES: usize = 16 * 1024;
/// The reused IAP signer reports no byte counts, so its two exchanges (the
/// workload's metadata token and IAM `signJwt`) are charged at their bounds
/// whether or not they complete.
pub const SIGNING_CALLS: u64 = 2;
pub const SIGNING_REQUEST_BYTES: u64 = 4 * 1024;
pub const SIGNING_RESPONSE_BYTES: u64 = (12 + 16) * 1024;
pub const MAX_READ_REQUEST_BYTES: u64 = 8 * 1024;
// The token and page allowances, each including the one-byte oversize probe a
// rejected final response may consume before collection stops.
pub const MAX_READ_RESPONSE_BYTES: u64 =
    SIGNING_RESPONSE_BYTES + (MAX_TOKEN_RESPONSE_BYTES + 1 + MAX_AGGREGATE_PAGE_BYTES + 1) as u64;
/// Signing, one service-token exchange and at most `MAX_PAGES` pages.
pub const PLANNED_CALLS: u64 = SIGNING_CALLS + 1 + MAX_PAGES as u64;
/// The whole read, checked before every request. Each request also has its
/// own transport timeout.
pub const READ_DEADLINE_SECONDS: i64 = 60;
const MAX_SERVICE_TOKEN_BYTES: usize = 8192;
const MAX_TOKEN_LIFETIME_SECONDS: i64 = 86_400;
const MAX_NAME_BYTES: usize = 256;

/// Stable, redacted read failures. No variant carries a body, URL, header or
/// token, so an observation error can never become a provider data channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    CredentialUnavailable,
    ServiceTokenRefused,
    AuthenticationFailed,
    ScopeDenied,
    RateLimited,
    Unavailable,
    ResponseInvalid,
    ResponseTooLarge,
    RequestBudget,
    PaginationInvalid,
    AppBudget,
    ConnectionMismatch,
}

impl Failure {
    pub fn code(self) -> &'static str {
        match self {
            Self::CredentialUnavailable => "internal_tools_credential_unavailable",
            Self::ServiceTokenRefused => "internal_tools_service_token_refused",
            Self::AuthenticationFailed => "internal_tools_authentication_failed",
            Self::ScopeDenied => "internal_tools_scope_denied",
            Self::RateLimited => "internal_tools_rate_limited",
            Self::Unavailable => "internal_tools_unavailable",
            Self::ResponseInvalid => "internal_tools_response_invalid",
            Self::ResponseTooLarge => "internal_tools_response_too_large",
            Self::RequestBudget => "internal_tools_request_budget",
            Self::PaginationInvalid => "internal_tools_pagination_invalid",
            Self::AppBudget => "internal_tools_app_budget",
            Self::ConnectionMismatch => "internal_tools_connection_mismatch",
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for Failure {}

/// Facts frozen when the capability is authorized: the reviewed connection,
/// the binding's app domain and the invocation time. Collection cannot widen
/// them, and nothing in the app request selects any of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadPlan {
    service_account: String,
    origin: String,
    iap_audience: String,
    target_app_id: String,
    app_domain: String,
    captured_at: i64,
}

impl ReadPlan {
    pub fn authorize(
        connection: &LiveConnection,
        app_domain: &str,
        captured_at: i64,
    ) -> Result<Self> {
        let LiveConnection::InternalTools {
            service_account,
            origin,
            iap_audience,
            target_app_id,
        } = connection
        else {
            anyhow::bail!("internal_tools_connection_invalid")
        };
        connection
            .validate()
            .map_err(|_| anyhow::anyhow!("internal_tools_connection_invalid"))?;
        ensure!(
            dns_name(app_domain) && captured_at >= 0,
            "internal_tools_target_invalid"
        );
        Ok(Self {
            service_account: service_account.clone(),
            origin: origin.clone(),
            iap_audience: iap_audience.clone(),
            target_app_id: target_app_id.clone(),
            app_domain: app_domain.into(),
            captured_at,
        })
    }

    pub fn service_account(&self) -> &str {
        &self.service_account
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn iap_audience(&self) -> &str {
        &self.iap_audience
    }

    pub fn target_app_id(&self) -> &str {
        &self.target_app_id
    }
}

/// What `internal_tools.app_library.v1` returns. Only the app ID, display name
/// and launch URL: owners, repository, custom fields and every other control
/// plane field are dropped at the parser and never decoded.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct App {
    pub app_id: String,
    pub name: String,
    pub url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Library {
    pub apps: Vec<App>,
    pub captured_at: i64,
}

/// The IAP credential for one read. No Debug, Clone or Serialize, so it cannot
/// reach a receipt, journal or log.
pub struct IapCredential(String);

impl IapCredential {
    pub(crate) fn new(value: String) -> std::result::Result<Self, Failure> {
        if value.is_empty() || value.len() > 8192 || !value.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Failure::CredentialUnavailable);
        }
        Ok(Self(value))
    }

    pub(crate) fn bearer(&self) -> &str {
        &self.0
    }
}

/// The control plane's service token. Held in memory for one read only; it
/// has no Debug, Clone or Serialize.
pub struct ServiceToken(String);

impl ServiceToken {
    pub(crate) fn value(&self) -> &str {
        &self.0
    }
}

/// A reply as the wire returned it. `body` holds at most the caller's bound
/// plus one probe byte, so an oversized response is observable without being read.
pub struct Reply {
    pub status: u16,
    pub json: bool,
    pub body: Vec<u8>,
}

/// An exchange that did not yield a complete reply: a stable code with the
/// response bytes consumed before it stopped and any declared status. Never a
/// body, header value or URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportFailure {
    pub failure: Failure,
    pub response_bytes: u64,
    pub http_status: Option<u16>,
}

/// A failure before any response arrived: nothing was read.
impl From<Failure> for TransportFailure {
    fn from(failure: Failure) -> Self {
        Self {
            failure,
            response_bytes: 0,
            http_status: None,
        }
    }
}

/// The three reviewed exchanges. Implementations build URLs and headers from
/// fixed parts and report transport failures only; they never retry, follow a
/// redirect or interpret a status. Classification belongs to the pipeline.
pub trait LibraryPort {
    fn credential(&mut self) -> std::result::Result<IapCredential, Failure>;
    fn service_token(
        &mut self,
        credential: &IapCredential,
        body: &[u8],
        max_bytes: usize,
    ) -> std::result::Result<Reply, TransportFailure>;
    fn page(
        &mut self,
        credential: &IapCredential,
        token: &ServiceToken,
        query: &str,
        max_bytes: usize,
    ) -> std::result::Result<Reply, TransportFailure>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Signing,
    ServiceToken,
    Library,
}

/// The most recent exchange, kept for correlation. No body or header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exchange {
    pub phase: Phase,
    pub page: u16,
    pub http_status: Option<u16>,
}

/// Measured usage of one read, including requests that failed, so known
/// settlement records everything consumed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Meter {
    pub calls: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    page_bytes: usize,
    pub last: Option<Exchange>,
}

impl Meter {
    fn request(&mut self, calls: u64, request_bytes: u64) -> std::result::Result<(), Failure> {
        let total = self
            .request_bytes
            .checked_add(request_bytes)
            .ok_or(Failure::RequestBudget)?;
        if total > MAX_READ_REQUEST_BYTES {
            return Err(Failure::RequestBudget);
        }
        self.calls += calls;
        self.request_bytes = total;
        Ok(())
    }

    /// Signing is charged at its reviewed bound before it starts, so a failure
    /// partway through it still settles everything it may have consumed.
    fn signing(&mut self) -> std::result::Result<(), Failure> {
        self.request(SIGNING_CALLS, SIGNING_REQUEST_BYTES)?;
        self.response_bytes = self.response_bytes.saturating_add(SIGNING_RESPONSE_BYTES);
        self.last = Some(Exchange {
            phase: Phase::Signing,
            page: 0,
            http_status: None,
        });
        Ok(())
    }

    fn send(
        &mut self,
        phase: Phase,
        page: u16,
        request_bytes: usize,
    ) -> std::result::Result<(), Failure> {
        self.request(1, request_bytes as u64)?;
        self.last = Some(Exchange {
            phase,
            page,
            http_status: None,
        });
        Ok(())
    }

    /// Count every byte consumed and keep the declared status, whether or not
    /// the exchange completed: a truncated or refused response still consumed
    /// provider traffic that known settlement must record.
    fn receive(
        &mut self,
        reply: std::result::Result<Reply, TransportFailure>,
    ) -> std::result::Result<Reply, Failure> {
        let (bytes, status) = match &reply {
            Ok(reply) => (reply.body.len() as u64, Some(reply.status)),
            Err(failure) => (failure.response_bytes, failure.http_status),
        };
        self.response_bytes = self.response_bytes.saturating_add(bytes);
        if let Some(last) = &mut self.last {
            if last.phase == Phase::Library {
                self.page_bytes = self.page_bytes.saturating_add(bytes as usize);
            }
            last.http_status = status.filter(|status| (100..=599).contains(status));
        }
        reply.map_err(|failure| failure.failure)
    }
}

/// The service-token request body: the reviewed target app and the one
/// read scope. Byte-identical to what the native port sends and budgets count.
pub fn service_token_request(target_app_id: &str) -> Vec<u8> {
    serde_json::json!({"target_app_id": target_app_id, "scopes": [SERVICE_SCOPE]})
        .to_string()
        .into_bytes()
}

/// The library query for a 1-based page, in the control plane's casing.
pub fn page_query(page: u16) -> String {
    format!("Page={page}&PageSize={PAGE_SIZE}")
}

/// Classify one reply before any body is parsed. 429 and 5xx keep their own
/// codes in every phase; a refused token exchange is distinguished from a
/// library refusal so an operator can tell a missing `service_callers` grant
/// from a missing IAP or scope grant.
fn accept(phase: Phase, reply: &Reply, max_bytes: usize) -> std::result::Result<(), Failure> {
    match reply.status {
        200 => {}
        429 => return Err(Failure::RateLimited),
        500..=599 => return Err(Failure::Unavailable),
        400 | 401 | 403 | 404 if phase == Phase::ServiceToken => {
            return Err(Failure::ServiceTokenRefused);
        }
        401 => return Err(Failure::AuthenticationFailed),
        403 => return Err(Failure::ScopeDenied),
        _ => return Err(Failure::ResponseInvalid),
    }
    if reply.body.len() > max_bytes {
        return Err(Failure::ResponseTooLarge);
    }
    if !reply.json {
        return Err(Failure::ResponseInvalid);
    }
    Ok(())
}

#[derive(Deserialize)]
struct TokenDto {
    token_type: String,
    expires_in: i64,
    service_token: String,
}

fn parse_token(body: &[u8]) -> std::result::Result<ServiceToken, Failure> {
    let token: TokenDto = crate::json::decode(body).map_err(|_| Failure::ResponseInvalid)?;
    if !token.token_type.eq_ignore_ascii_case("bearer")
        || !(1..=MAX_TOKEN_LIFETIME_SECONDS).contains(&token.expires_in)
        || token.service_token.is_empty()
        || token.service_token.len() > MAX_SERVICE_TOKEN_BYTES
        || !token
            .service_token
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
    {
        return Err(Failure::ResponseInvalid);
    }
    Ok(ServiceToken(token.service_token))
}

/// One `PagedResultDto`. Unknown fields, here and on each entry, are ignored
/// and never decoded into a value that could leave the parser.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PageDto {
    items: Vec<EntryDto>,
    page: u64,
    page_size: u64,
    has_next_page: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EntryDto {
    app_id: String,
    display_name: String,
    #[serde(default)]
    subdomain: Option<String>,
}

fn parse_page(body: &[u8], page: u16) -> std::result::Result<PageDto, Failure> {
    let dto: PageDto = crate::json::decode(body).map_err(|_| Failure::ResponseInvalid)?;
    // The control plane slices full pages until the last; anything else means
    // the request was not honoured as sent or the list moved underneath it.
    if dto.page != u64::from(page)
        || dto.page_size != PAGE_SIZE as u64
        || dto.items.len() > PAGE_SIZE
        || (dto.has_next_page && dto.items.len() != PAGE_SIZE)
    {
        return Err(Failure::PaginationInvalid);
    }
    Ok(dto)
}

/// Project the complete entry list. Entries without a subdomain have nowhere
/// to launch and are skipped; a malformed app ID, name or subdomain fails the
/// read rather than being dropped. The URL is built from the validated
/// subdomain and the binding's app domain, never from a provider URL.
fn project(plan: &ReadPlan, entries: Vec<EntryDto>) -> std::result::Result<Library, Failure> {
    if entries.len() > MAX_APPS {
        return Err(Failure::AppBudget);
    }
    let mut apps = Vec::with_capacity(entries.len());
    for entry in entries {
        let name = entry.display_name.trim();
        if !dns_label(&entry.app_id)
            || name.is_empty()
            || name.len() > MAX_NAME_BYTES
            || name.chars().any(char::is_control)
        {
            return Err(Failure::ResponseInvalid);
        }
        let subdomain = match entry.subdomain.as_deref() {
            None | Some("") => continue,
            Some(subdomain) if dns_label(subdomain) => subdomain,
            Some(_) => return Err(Failure::ResponseInvalid),
        };
        apps.push(App {
            url: format!("https://{subdomain}.{}/", plan.app_domain),
            name: name.to_owned(),
            app_id: entry.app_id,
        });
    }
    // A total order, so the first entry kept for a duplicated app ID does not
    // depend on the order the provider returned them in.
    apps.sort_by(|left, right| {
        (
            left.name.to_lowercase(),
            &left.app_id,
            &left.name,
            &left.url,
        )
            .cmp(&(
                right.name.to_lowercase(),
                &right.app_id,
                &right.name,
                &right.url,
            ))
    });
    let mut seen = BTreeSet::new();
    apps.retain(|app| seen.insert(app.app_id.clone()));
    Ok(Library {
        apps,
        captured_at: plan.captured_at,
    })
}

fn collect_into(
    plan: &ReadPlan,
    port: &mut dyn LibraryPort,
    meter: &mut Meter,
) -> std::result::Result<Library, Failure> {
    meter.signing()?;
    let credential = port.credential()?;
    let body = service_token_request(&plan.target_app_id);
    meter.send(Phase::ServiceToken, 0, body.len())?;
    let reply = meter.receive(port.service_token(&credential, &body, MAX_TOKEN_RESPONSE_BYTES))?;
    accept(Phase::ServiceToken, &reply, MAX_TOKEN_RESPONSE_BYTES)?;
    let token = parse_token(&reply.body)?;
    let mut entries = Vec::new();
    for page in 1..=MAX_PAGES {
        let max =
            MAX_PAGE_RESPONSE_BYTES.min(MAX_AGGREGATE_PAGE_BYTES.saturating_sub(meter.page_bytes));
        let query = page_query(page);
        meter.send(Phase::Library, page, query.len())?;
        let reply = meter.receive(port.page(&credential, &token, &query, max))?;
        accept(Phase::Library, &reply, max)?;
        let dto = parse_page(&reply.body, page)?;
        entries.extend(dto.items);
        if !dto.has_next_page {
            return project(plan, entries);
        }
    }
    // A further page exists past the bound: overflow fails, never truncates.
    Err(Failure::AppBudget)
}

/// Read and project the complete library through `port`. Nothing partial is
/// ever returned; the meter covers every exchange, including failed ones.
pub fn collect(plan: &ReadPlan, port: &mut dyn LibraryPort) -> (Result<Library>, Meter) {
    let mut meter = Meter::default();
    let result = collect_into(plan, port, &mut meter).map_err(anyhow::Error::from);
    (result, meter)
}

/// The workload's own access token from the GKE metadata server, presented
/// only to IAM Credentials to sign the IAP credential.
struct WorkloadTokens(crate::oauth::approval_keys::GkeMetadataAccessTokens);

impl crate::iap_workload::AccessTokens for WorkloadTokens {
    fn authorization(&self) -> Result<reqwest::header::HeaderValue> {
        use crate::oauth::approval_keys::AccessTokenSource;
        let mut value =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", self.0.access_token()?))?;
        value.set_sensitive(true);
        Ok(value)
    }
}

/// Native HTTPS port. The origin, audience and service account come from the
/// reviewed connection; every path, method and header is fixed here. Its own
/// client follows no redirect, retries nothing, uses no proxy, cookie or
/// content encoding, and keeps no idle connection.
pub struct NativeLibraryPort {
    client: reqwest::blocking::Client,
    token_endpoint: reqwest::Url,
    library_endpoint: reqwest::Url,
    audience: reqwest::Url,
    signer: crate::iap_workload::Signer,
    clock: fn() -> Result<i64>,
    deadline: i64,
}

impl NativeLibraryPort {
    pub fn new(plan: &ReadPlan) -> std::result::Result<Self, Failure> {
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
            .timeout(Duration::from_secs(20))
            .pool_max_idle_per_host(0)
            .user_agent("day2-internal-tools/1")
            .build()
            .map_err(|_| Failure::Unavailable)?;
        let audience =
            reqwest::Url::parse(&plan.iap_audience).map_err(|_| Failure::CredentialUnavailable)?;
        let tokens = crate::oauth::approval_keys::GkeMetadataAccessTokens::new()
            .map_err(|_| Failure::CredentialUnavailable)?;
        let signer = crate::iap_workload::Signer::new(
            &plan.service_account,
            [audience.clone()].into(),
            Arc::new(WorkloadTokens(tokens)),
        )
        .map_err(|_| Failure::CredentialUnavailable)?;
        Self::with(
            client,
            &plan.origin,
            audience,
            signer,
            crate::oauth::effects::wall_time,
        )
    }

    fn with(
        client: reqwest::blocking::Client,
        origin: &str,
        audience: reqwest::Url,
        signer: crate::iap_workload::Signer,
        clock: fn() -> Result<i64>,
    ) -> std::result::Result<Self, Failure> {
        let origin = reqwest::Url::parse(origin).map_err(|_| Failure::Unavailable)?;
        let join = |path| origin.join(path).map_err(|_| Failure::Unavailable);
        let deadline = clock()
            .ok()
            .and_then(|now| now.checked_add(READ_DEADLINE_SECONDS))
            .ok_or(Failure::Unavailable)?;
        Ok(Self {
            client,
            token_endpoint: join(SERVICE_TOKEN_PATH)?,
            library_endpoint: join(LIBRARY_PATH)?,
            audience,
            signer,
            clock,
            deadline,
        })
    }

    /// Loopback HTTP origins for request-exact transport tests only.
    #[cfg(test)]
    pub(crate) fn transport_fixture(
        plan: &ReadPlan,
        origin: &str,
        iam_origin: &str,
        tokens: Arc<dyn crate::iap_workload::AccessTokens>,
        clock: fn() -> Result<i64>,
    ) -> Result<Self> {
        let url = reqwest::Url::parse(origin)?;
        ensure!(
            url.scheme() == "http"
                && matches!(url.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && (url.path().is_empty() || url.path() == "/"),
            "invalid_internal_tools_fixture_origin"
        );
        let audience = url.join("/*")?;
        let signer = crate::iap_workload::Signer::transport_fixture(
            &plan.service_account,
            [audience.clone()].into(),
            tokens,
            iam_origin,
        )?;
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
        Ok(Self::with(client, origin, audience, signer, clock)?)
    }

    fn before_request(&self) -> std::result::Result<(), Failure> {
        match (self.clock)() {
            Ok(now) if now < self.deadline => Ok(()),
            _ => Err(Failure::Unavailable),
        }
    }

    fn authorization(value: &str) -> std::result::Result<reqwest::header::HeaderValue, Failure> {
        let mut header = reqwest::header::HeaderValue::from_str(&format!("Bearer {value}"))
            .map_err(|_| Failure::CredentialUnavailable)?;
        header.set_sensitive(true);
        Ok(header)
    }

    /// One request. A failure after the response head keeps its status, and a
    /// failed body read keeps the bytes it had already consumed.
    fn exchange(
        &self,
        request: reqwest::blocking::RequestBuilder,
        max_bytes: usize,
    ) -> std::result::Result<Reply, TransportFailure> {
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
        let failed = |failure, response_bytes: usize| TransportFailure {
            failure,
            response_bytes: response_bytes as u64,
            http_status: Some(status),
        };
        if headers
            .get(reqwest::header::CONTENT_ENCODING)
            .is_some_and(|value| value != "identity")
        {
            return Err(failed(Failure::ResponseInvalid, 0));
        }
        if response
            .content_length()
            .is_some_and(|size| size > max_bytes as u64)
        {
            return Err(failed(Failure::ResponseTooLarge, 0));
        }
        // `read_to_end` appends as it goes: on a close or timeout mid-body,
        // `body` holds exactly what was consumed before the failure.
        let mut body = Vec::new();
        if response
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut body)
            .is_err()
        {
            return Err(failed(Failure::Unavailable, body.len()));
        }
        Ok(Reply { status, json, body })
    }
}

impl LibraryPort for NativeLibraryPort {
    fn credential(&mut self) -> std::result::Result<IapCredential, Failure> {
        self.before_request()?;
        let signed = self
            .signer
            .sign_for(&self.audience)
            .map_err(|_| Failure::CredentialUnavailable)?;
        IapCredential::new(signed.as_str().to_owned())
    }

    fn service_token(
        &mut self,
        credential: &IapCredential,
        body: &[u8],
        max_bytes: usize,
    ) -> std::result::Result<Reply, TransportFailure> {
        self.before_request()?;
        self.exchange(
            self.client
                .post(self.token_endpoint.clone())
                .header(
                    reqwest::header::AUTHORIZATION,
                    Self::authorization(credential.bearer())?,
                )
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec()),
            max_bytes,
        )
    }

    fn page(
        &mut self,
        credential: &IapCredential,
        token: &ServiceToken,
        query: &str,
        max_bytes: usize,
    ) -> std::result::Result<Reply, TransportFailure> {
        self.before_request()?;
        let mut url = self.library_endpoint.clone();
        url.set_query(Some(query));
        let mut service = reqwest::header::HeaderValue::from_str(token.value())
            .map_err(|_| Failure::AuthenticationFailed)?;
        service.set_sensitive(true);
        self.exchange(
            self.client
                .get(url)
                .header(
                    reqwest::header::AUTHORIZATION,
                    Self::authorization(credential.bearer())?,
                )
                .header(SERVICE_HEADER, service),
            max_bytes,
        )
    }
}

/// Offline control-plane exchanges served from the provider's committed world
/// and parsed by the same pipeline as the live adapter. Every exchange
/// compares the world's connection identity with this read's and fails closed
/// on a mismatch.
pub struct SimulatedLibraryPort {
    database: std::path::PathBuf,
    scope: String,
    plan: ReadPlan,
}

impl SimulatedLibraryPort {
    pub fn new(database: &Path, scope: &str, plan: &ReadPlan) -> Result<Self> {
        crate::integrations::simulated::internal_tools_check(database, scope, plan)?;
        Ok(Self {
            database: database.into(),
            scope: scope.into(),
            plan: plan.clone(),
        })
    }
}

impl LibraryPort for SimulatedLibraryPort {
    fn credential(&mut self) -> std::result::Result<IapCredential, Failure> {
        IapCredential::new(crate::integrations::simulated::internal_tools_sign(
            &self.database,
            &self.scope,
            &self.plan,
        )?)
    }

    fn service_token(
        &mut self,
        credential: &IapCredential,
        body: &[u8],
        max_bytes: usize,
    ) -> std::result::Result<Reply, TransportFailure> {
        crate::integrations::simulated::internal_tools_read(
            &self.database,
            &self.scope,
            &self.plan,
            crate::integrations::simulated::InternalToolsRead::ServiceToken {
                bearer: credential.bearer(),
                body,
            },
            max_bytes,
        )
    }

    fn page(
        &mut self,
        credential: &IapCredential,
        token: &ServiceToken,
        query: &str,
        max_bytes: usize,
    ) -> std::result::Result<Reply, TransportFailure> {
        crate::integrations::simulated::internal_tools_read(
            &self.database,
            &self.scope,
            &self.plan,
            crate::integrations::simulated::InternalToolsRead::Page {
                bearer: credential.bearer(),
                service_token: token.value(),
                query,
            },
            max_bytes,
        )
    }
}

#[cfg(test)]
#[path = "internal_tools_tests.rs"]
mod tests;
