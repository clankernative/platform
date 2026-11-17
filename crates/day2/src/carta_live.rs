//! Live Carta capture: one bounded, complete collection of an issuer's
//! stakeholders and option grants, mapped to the typed SDK records and given a
//! content-addressed identity.
//!
//! `carta.snapshot.v2` performs the collection when its resource has a live
//! connection and hands the complete capture to the application, which holds it
//! in its own database (see `crate::capture_delivery`). This pipeline owns
//! request order, pagination, every byte and record bound, status
//! classification and all-or-none completion. A port owns only the wire: the
//! native port speaks HTTPS to Carta's fixed origins and the simulated port
//! serves verbatim wire bodies from a committed world, so both lanes run the same
//! DTO parser and the same failure classification.
//!
//! Stakeholders and option grants are separate endpoints read in sequence. The
//! capture is immutable locally; it is not an upstream point-in-time snapshot.
use crate::carta::{Exercise, Grant, OptionalText, Record, Snapshot, Stakeholder, VestingEvent};
use anyhow::{Result, ensure};
use day2_capabilities::{
    integrations::{CartaEnvironment, LiveConnection},
    resources::{CartaChildren, VersionRef},
};
use serde::Deserialize;
use std::{collections::BTreeSet, fmt, path::Path};

pub const MAX_PAGE_RESPONSE_BYTES: usize = 4 * 1_048_576;
pub const MAX_TOKEN_RESPONSE_BYTES: usize = 16 * 1024;
/// Every page response of one capture together.
pub const MAX_AGGREGATE_PAGE_BYTES: usize = 64 * 1_048_576;
pub const MAX_CAPTURE_REQUEST_BYTES: u64 = 64 * 1024;
// The token and page allowances, each including the one-byte oversize probe a
// rejected final response may consume before collection stops.
pub const MAX_CAPTURE_RESPONSE_BYTES: u64 =
    (MAX_TOKEN_RESPONSE_BYTES + 1 + MAX_AGGREGATE_PAGE_BYTES + 1) as u64;
pub const MAX_PAGE_TOKEN_BYTES: usize = 1024;
/// Pinned per adapter version. Qualification corrects this list explicitly.
pub const REQUIRED_SCOPES: [&str; 2] = ["read_issuer_stakeholders", "read_issuer_securities"];
const MIN_TOKEN_LIFETIME_SECONDS: i64 = 60;
const MAX_ACCESS_TOKEN_BYTES: usize = 8192;

/// Stable, redacted capture failures. No variant carries a body, URL, header or
/// token, so an observation error can never become a provider data channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    CredentialUnavailable,
    AuthenticationFailed,
    ScopeDenied,
    RateLimited,
    Unavailable,
    ResponseInvalid,
    ResponseTooLarge,
    RequestBudget,
    IssuerScopeMismatch,
    PaginationInvalid,
    PageBudget,
    RecordCountBudget,
    RecordByteBudget,
    CaptureByteBudget,
}

impl Failure {
    pub fn code(self) -> &'static str {
        match self {
            Self::CredentialUnavailable => "carta_credential_unavailable",
            Self::AuthenticationFailed => "carta_authentication_failed",
            Self::ScopeDenied => "carta_scope_denied",
            Self::RateLimited => "carta_rate_limited",
            Self::Unavailable => "carta_unavailable",
            Self::ResponseInvalid => "carta_response_invalid",
            Self::ResponseTooLarge => "carta_response_too_large",
            Self::RequestBudget => "carta_request_budget",
            Self::IssuerScopeMismatch => "carta_issuer_scope_mismatch",
            Self::PaginationInvalid => "carta_pagination_invalid",
            Self::PageBudget => "carta_page_budget",
            Self::RecordCountBudget => "carta_record_count_budget",
            Self::RecordByteBudget => "carta_record_byte_budget",
            Self::CaptureByteBudget => "carta_capture_byte_budget",
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for Failure {}

/// Where a capture's records came from. Part of the capture identity and the
/// SDK snapshot, so an application can tell a simulated world from a provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceProfile {
    Production,
    Playground,
    Simulated,
}

impl SourceProfile {
    pub fn name(self) -> &'static str {
        match self {
            Self::Production => "carta_production",
            Self::Playground => "carta_playground",
            Self::Simulated => "carta_simulated",
        }
    }
}

/// The provider authority a capture was collected under: the reviewed
/// connection and revision together with every field of its live profile that
/// names an OAuth client in a Carta deployment. A record read must present the
/// same authority, so a grant bound to another connection, client, credential
/// or environment can never be answered from this capture.
fn connection_authority(
    connection_ref: &VersionRef,
    connection: &LiveConnection,
) -> Result<String> {
    // Every field is named so a new one cannot silently fall out of the binding.
    let LiveConnection::Carta {
        credential_ref,
        client_id,
        environment,
        max_pages_per_collection: _,
    } = connection
    else {
        anyhow::bail!("carta_connection_invalid")
    };
    Ok(crate::digest(&serde_json::to_vec(&(
        "carta-connection-v1",
        &connection_ref.id,
        connection_ref.revision,
        environment.name(),
        client_id,
        &credential_ref.id,
        credential_ref.revision,
    ))?))
}

/// Facts frozen when the capability is authorized: the issuer, child-record
/// mode, connection authority, environment, page ceiling and source. Collection
/// cannot widen them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturePlan {
    scope: String,
    issuer_id: String,
    children: CartaChildren,
    connection: String,
    environment: CartaEnvironment,
    max_pages: u16,
    source_profile: SourceProfile,
}

impl CapturePlan {
    pub fn authorize(
        scope: &str,
        connection_ref: &VersionRef,
        connection: &LiveConnection,
        issuer_id: &str,
        children: CartaChildren,
        simulated: bool,
    ) -> Result<Self> {
        let LiveConnection::Carta {
            environment,
            max_pages_per_collection,
            ..
        } = connection
        else {
            anyhow::bail!("carta_connection_invalid")
        };
        connection
            .validate()
            .map_err(|_| anyhow::anyhow!("carta_connection_invalid"))?;
        day2_capabilities::resources::validate_carta_live_issuer(issuer_id)?;
        ensure!(
            !scope.is_empty() && scope.len() <= 1024,
            "invalid_carta_scope"
        );
        Ok(Self {
            scope: scope.into(),
            issuer_id: issuer_id.into(),
            children,
            connection: connection_authority(connection_ref, connection)?,
            environment: *environment,
            max_pages: *max_pages_per_collection,
            source_profile: if simulated {
                SourceProfile::Simulated
            } else {
                match environment {
                    CartaEnvironment::Production => SourceProfile::Production,
                    CartaEnvironment::Playground => SourceProfile::Playground,
                }
            },
        })
    }

    /// One token exchange and at most `max_pages` pages of each collection.
    pub fn planned_calls(&self) -> u64 {
        1 + 2 * u64::from(self.max_pages)
    }

    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    pub fn environment(&self) -> CartaEnvironment {
        self.environment
    }

    pub fn source_profile(&self) -> SourceProfile {
        self.source_profile
    }

    /// Everything a held delivery is bound to: runtime scope, connection
    /// authority, environment, issuer, child-record mode and source. A page or
    /// release under any other grant is refused.
    pub fn delivery_authority(&self) -> Result<String> {
        Ok(serde_json::to_string(&(
            "carta.issuer.v2",
            &self.scope,
            &self.connection,
            self.environment.name(),
            &self.issuer_id,
            self.children.name(),
            self.source_profile.name(),
        ))?)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Collection {
    Stakeholders,
    OptionGrants,
}

impl Collection {
    pub fn segment(self) -> &'static str {
        match self {
            Self::Stakeholders => "stakeholders",
            Self::OptionGrants => "optionGrants",
        }
    }

    fn phase(self) -> Phase {
        match self {
            Self::Stakeholders => Phase::Stakeholders,
            Self::OptionGrants => Phase::OptionGrants,
        }
    }
}

/// The fixed issuer route. `issuer_id` is a validated numeric identifier.
pub fn collection_path(issuer_id: &str, collection: Collection) -> String {
    format!("/v1alpha1/issuers/{issuer_id}/{}", collection.segment())
}

/// The client-credentials form. It holds no secret: the client authenticates
/// with HTTP Basic, which only the port constructs.
pub fn token_form() -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "CLIENT_CREDENTIALS")
        .append_pair("scope", &REQUIRED_SCOPES.join(" "))
        .finish()
}

/// The encoded query for a continuation, byte-identical to what the native
/// port sends and what request budgets count.
pub fn page_query(token: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("pageToken", token)
        .finish()
}

/// A reply as the wire returned it. `body` holds at most the caller's bound plus
/// one probe byte, so an oversized response is observable without being read.
pub struct Reply {
    pub status: u16,
    pub json: bool,
    pub body: Vec<u8>,
    pub retry_after_seconds: Option<u32>,
}

/// The capture's bearer token. Held in memory for one capture only; it has no
/// Debug, Clone or Serialize, so it cannot reach a receipt, journal or log.
pub struct AccessToken(String);

impl AccessToken {
    pub(crate) fn bearer(&self) -> &str {
        &self.0
    }
}

/// An exchange that did not yield a complete reply. Like the shared transport's
/// `TransportError`, it carries a stable code with what is already known of the
/// exchange: the response bytes consumed before it stopped and any status or
/// `Retry-After` the response declared. Never a body, header value or URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportFailure {
    pub failure: Failure,
    pub response_bytes: u64,
    pub http_status: Option<u16>,
    pub retry_after_seconds: Option<u32>,
}

/// A failure before any response arrived: nothing was read.
impl From<Failure> for TransportFailure {
    fn from(failure: Failure) -> Self {
        Self {
            failure,
            response_bytes: 0,
            http_status: None,
            retry_after_seconds: None,
        }
    }
}

/// The two reviewed exchanges. Implementations build URLs and headers from
/// fixed parts and report transport failures only; they never retry, follow a
/// redirect or interpret a status. Classification belongs to the pipeline.
pub trait CartaPort {
    fn token(
        &mut self,
        form: &str,
        max_bytes: usize,
    ) -> std::result::Result<Reply, TransportFailure>;
    fn page(
        &mut self,
        collection: Collection,
        query: Option<&str>,
        token: &AccessToken,
        max_bytes: usize,
    ) -> std::result::Result<Reply, TransportFailure>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Token,
    Stakeholders,
    OptionGrants,
}

/// The most recent exchange, kept for correlation. No body or header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exchange {
    pub phase: Phase,
    pub page: u16,
    pub http_status: Option<u16>,
    pub retry_after_seconds: Option<u32>,
}

/// Measured usage of one capture, including requests that failed, so known
/// settlement records exactly what was consumed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Meter {
    pub calls: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    page_bytes: usize,
    pub last: Option<Exchange>,
}

impl Meter {
    fn send(&mut self, phase: Phase, page: u16, request_bytes: usize) -> Result<(), Failure> {
        let total = self
            .request_bytes
            .checked_add(request_bytes as u64)
            .ok_or(Failure::RequestBudget)?;
        if total > MAX_CAPTURE_REQUEST_BYTES {
            return Err(Failure::RequestBudget);
        }
        self.calls += 1;
        self.request_bytes = total;
        self.last = Some(Exchange {
            phase,
            page,
            http_status: None,
            retry_after_seconds: None,
        });
        Ok(())
    }

    /// Count every byte consumed and keep what the response declared, whether
    /// or not the exchange completed: a truncated or refused response still
    /// consumed provider traffic that known settlement must record.
    fn receive(
        &mut self,
        reply: std::result::Result<Reply, TransportFailure>,
    ) -> std::result::Result<Reply, Failure> {
        let (bytes, status, retry_after_seconds) = match &reply {
            Ok(reply) => (
                reply.body.len() as u64,
                Some(reply.status),
                reply.retry_after_seconds,
            ),
            Err(failure) => (
                failure.response_bytes,
                failure.http_status,
                failure.retry_after_seconds,
            ),
        };
        self.response_bytes = self.response_bytes.saturating_add(bytes);
        if let Some(last) = &mut self.last {
            last.http_status = status.filter(|status| (100..=599).contains(status));
            last.retry_after_seconds = retry_after_seconds;
        }
        reply.map_err(|failure| failure.failure)
    }
}

/// Classify one reply before any body is parsed. 429 and 5xx keep their own
/// codes in every phase; Basic-authentication refusals at the token endpoint and
/// an unknown or invisible issuer at the API are distinguished from bad shapes.
fn accept(
    phase: Phase,
    reply: &Reply,
    max_bytes: usize,
    continuation: bool,
) -> Result<(), Failure> {
    match reply.status {
        200 => {}
        429 => return Err(Failure::RateLimited),
        500..=599 => return Err(Failure::Unavailable),
        401 => return Err(Failure::AuthenticationFailed),
        403 => return Err(Failure::ScopeDenied),
        400 if phase == Phase::Token => return Err(Failure::AuthenticationFailed),
        400 if continuation => return Err(Failure::PaginationInvalid),
        404 if phase != Phase::Token => return Err(Failure::ScopeDenied),
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
    access_token: String,
    token_type: String,
    expires_in: i64,
    // RFC 6749 permits omitting scope when it equals the request.
    #[serde(default)]
    scope: Option<String>,
}

fn parse_token(body: &[u8]) -> Result<AccessToken, Failure> {
    let token: TokenDto = crate::json::decode(body).map_err(|_| Failure::AuthenticationFailed)?;
    if !token.token_type.eq_ignore_ascii_case("bearer")
        || token.access_token.is_empty()
        || token.access_token.len() > MAX_ACCESS_TOKEN_BYTES
        || !token
            .access_token
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
        || token.expires_in < MIN_TOKEN_LIFETIME_SECONDS
    {
        return Err(Failure::AuthenticationFailed);
    }
    if let Some(granted) = &token.scope {
        let granted: BTreeSet<_> = granted.split(' ').collect();
        if !REQUIRED_SCOPES.iter().all(|scope| granted.contains(scope)) {
            return Err(Failure::ScopeDenied);
        }
    }
    Ok(AccessToken(token.access_token))
}

/// Carta wraps dates, quantities and amounts as `{"value": "..."}`.
#[derive(Deserialize)]
struct Wrapped {
    value: String,
}

fn optional(value: Option<Wrapped>) -> OptionalText {
    text(value.map(|wrapped| wrapped.value))
}

fn text(value: Option<String>) -> OptionalText {
    match value {
        Some(value) => OptionalText::Some(value),
        None => OptionalText::None,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StakeholdersPage {
    #[serde(default)]
    stakeholders: Option<Vec<StakeholderDto>>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StakeholderDto {
    id: String,
    issuer_id: String,
    full_name: String,
    email: String,
    #[serde(default)]
    employee_id: Option<String>,
    relationship: String,
    #[serde(default)]
    group: Option<String>,
    entity_type: String,
    #[serde(default)]
    address: Option<AddressDto>,
}

#[derive(Deserialize)]
struct AddressDto {
    #[serde(default)]
    country: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", bound(deserialize = "G: Deserialize<'de>"))]
struct OptionGrantsPage<G> {
    #[serde(default)]
    option_grants: Option<Vec<G>>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantDto {
    id: String,
    issuer_id: String,
    stakeholder_id: String,
    equity_incentive_plan_name: String,
    issue_date: Wrapped,
    vesting_start_date: Wrapped,
    board_approval_date: Wrapped,
    #[serde(default)]
    stakeholder_acceptance_date: Option<Wrapped>,
    grant_expiration_date: Wrapped,
    iso_nso_split: bool,
    stock_option_type: String,
    quantity: Wrapped,
    outstanding_quantity: Wrapped,
    vested_quantity: Wrapped,
    exercised_quantity: Wrapped,
    exercise_price: ExercisePriceDto,
    security_label: String,
    early_exercisable: bool,
    vesting_schedule: VestingScheduleDto,
    last_modified_datetime: Wrapped,
}

/// A grant with its child arrays. Omit mode decodes `GrantDto` alone, so the
/// arrays count toward response bounds but are never typed or stored.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantWithChildren {
    #[serde(flatten)]
    grant: GrantDto,
    #[serde(default)]
    vesting_events: Option<Vec<VestingEventDto>>,
    #[serde(default)]
    exercises: Option<Vec<ExerciseDto>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExercisePriceDto {
    currency_code: Wrapped,
    amount: Wrapped,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VestingScheduleDto {
    name: String,
    last_modified_date: Wrapped,
    start_date: Wrapped,
    end_date: Wrapped,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VestingEventDto {
    id: String,
    vest_date: Wrapped,
    quantity: Wrapped,
    iso_quantity: Wrapped,
    nso_quantity: Wrapped,
    performance_condition: bool,
    vested: bool,
    max_quantity: Wrapped,
    target_quantity: Wrapped,
    #[serde(default)]
    vested_quantity: Option<Wrapped>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExerciseDto {
    exercise_id: String,
    quantity: Wrapped,
    #[serde(default)]
    fair_market_value_as_of_date: Option<Wrapped>,
    exercise_date: Wrapped,
    status: String,
    certificate_id: String,
    exercise_type: String,
    qualified: bool,
}

impl StakeholderDto {
    fn record(self) -> Stakeholder {
        Stakeholder {
            id: self.id,
            issuer_id: self.issuer_id,
            full_name: self.full_name,
            email: self.email,
            employee_id: text(self.employee_id),
            relationship: self.relationship,
            group: text(self.group),
            entity_type: self.entity_type,
            address_country: text(self.address.and_then(|address| address.country)),
        }
    }
}

impl GrantDto {
    fn record(self) -> Grant {
        Grant {
            id: self.id,
            issuer_id: self.issuer_id,
            stakeholder_id: self.stakeholder_id,
            equity_incentive_plan_name: self.equity_incentive_plan_name,
            issue_date: self.issue_date.value,
            vesting_start_date: self.vesting_start_date.value,
            board_approval_date: self.board_approval_date.value,
            stakeholder_acceptance_date: optional(self.stakeholder_acceptance_date),
            grant_expiration_date: self.grant_expiration_date.value,
            iso_nso_split: self.iso_nso_split,
            stock_option_type: self.stock_option_type,
            quantity: self.quantity.value,
            outstanding_quantity: self.outstanding_quantity.value,
            vested_quantity: self.vested_quantity.value,
            exercised_quantity: self.exercised_quantity.value,
            exercise_price_currency: self.exercise_price.currency_code.value,
            exercise_price_amount: self.exercise_price.amount.value,
            security_label: self.security_label,
            early_exercisable: self.early_exercisable,
            vesting_schedule_name: self.vesting_schedule.name,
            vesting_schedule_last_modified_date: self.vesting_schedule.last_modified_date.value,
            vesting_schedule_start_date: self.vesting_schedule.start_date.value,
            vesting_schedule_end_date: self.vesting_schedule.end_date.value,
            last_modified_datetime: self.last_modified_datetime.value,
        }
    }
}

impl VestingEventDto {
    fn record(self, grant_id: &str) -> VestingEvent {
        VestingEvent {
            id: self.id,
            grant_id: grant_id.into(),
            vest_date: self.vest_date.value,
            quantity: self.quantity.value,
            iso_quantity: self.iso_quantity.value,
            nso_quantity: self.nso_quantity.value,
            performance_condition: self.performance_condition,
            vested: self.vested,
            max_quantity: self.max_quantity.value,
            target_quantity: self.target_quantity.value,
            vested_quantity: optional(self.vested_quantity),
        }
    }
}

impl ExerciseDto {
    fn record(self, grant_id: &str) -> Exercise {
        Exercise {
            grant_id: grant_id.into(),
            exercise_id: self.exercise_id,
            quantity: self.quantity.value,
            fair_market_value_as_of_date: optional(self.fair_market_value_as_of_date),
            exercise_date: self.exercise_date.value,
            status: self.status,
            certificate_id: self.certificate_id,
            exercise_type: self.exercise_type,
            qualified: self.qualified,
        }
    }
}

/// Records in provider order, each encoded once to bound it, bounded as they
/// arrive so an oversized capture fails before it is fully held in memory.
#[derive(Default)]
struct Collected {
    records: Vec<Record>,
    bytes: usize,
}

impl Collected {
    fn push(&mut self, plan: &CapturePlan, record: Record) -> Result<(), Failure> {
        let issuer = match &record {
            Record::Stakeholder(record) => Some(&record.issuer_id),
            Record::Grant(record) => Some(&record.issuer_id),
            Record::VestingEvent(_) | Record::Exercise(_) => None,
        };
        if issuer.is_some_and(|issuer| issuer != &plan.issuer_id) {
            return Err(Failure::IssuerScopeMismatch);
        }
        if self.records.len() >= crate::carta::MAX_RECORDS {
            return Err(Failure::RecordCountBudget);
        }
        let envelope = record.envelope().map_err(|_| Failure::RecordByteBudget)?;
        self.bytes = self
            .bytes
            .checked_add(envelope.len())
            .filter(|bytes| *bytes <= crate::carta::MAX_CAPTURE_BYTES)
            .ok_or(Failure::CaptureByteBudget)?;
        self.records.push(record);
        Ok(())
    }
}

/// A page token, or the end of the collection. Absent, null and empty all end
/// it; anything else must be a bounded printable token.
fn continuation(token: Option<String>) -> Result<Option<String>, Failure> {
    match token {
        None => Ok(None),
        Some(token) if token.is_empty() => Ok(None),
        Some(token)
            if token.len() <= MAX_PAGE_TOKEN_BYTES
                && token.bytes().all(|byte| byte.is_ascii_graphic()) =>
        {
            Ok(Some(token))
        }
        Some(_) => Err(Failure::PaginationInvalid),
    }
}

/// Read one collection to its end. A repeated token fails closed rather than
/// ending the read early, and a token remaining after the page ceiling fails
/// rather than truncating the collection.
fn paginate(
    plan: &CapturePlan,
    port: &mut dyn CartaPort,
    meter: &mut Meter,
    token: &AccessToken,
    collection: Collection,
    page_limit: usize,
    mut page: impl FnMut(&[u8]) -> Result<Option<String>, Failure>,
) -> Result<(), Failure> {
    let mut seen = BTreeSet::new();
    let mut next: Option<String> = None;
    for ordinal in 0..plan.max_pages {
        let remaining = MAX_AGGREGATE_PAGE_BYTES - meter.page_bytes;
        if remaining == 0 {
            return Err(Failure::ResponseTooLarge);
        }
        let max_bytes = page_limit.min(remaining);
        let query = next.as_deref().map(page_query);
        meter.send(
            collection.phase(),
            ordinal,
            query.as_ref().map_or(0, String::len),
        )?;
        let reply = meter.receive(port.page(collection, query.as_deref(), token, max_bytes))?;
        meter.page_bytes = meter.page_bytes.saturating_add(reply.body.len());
        accept(collection.phase(), &reply, max_bytes, query.is_some())?;
        match continuation(page(&reply.body)?)? {
            None => return Ok(()),
            Some(token) => {
                if !seen.insert(token.clone()) {
                    return Err(Failure::PaginationInvalid);
                }
                next = Some(token);
            }
        }
    }
    Err(Failure::PageBudget)
}

fn collect(
    plan: &CapturePlan,
    port: &mut dyn CartaPort,
    page_limit: usize,
    meter: &mut Meter,
) -> Result<Collected, Failure> {
    let form = token_form();
    meter.send(Phase::Token, 0, form.len())?;
    let reply = meter.receive(port.token(&form, MAX_TOKEN_RESPONSE_BYTES))?;
    accept(Phase::Token, &reply, MAX_TOKEN_RESPONSE_BYTES, false)?;
    let token = parse_token(&reply.body)?;
    let mut collected = Collected::default();
    paginate(
        plan,
        port,
        meter,
        &token,
        Collection::Stakeholders,
        page_limit,
        |body| {
            let page: StakeholdersPage =
                crate::json::decode_evidence(body).map_err(|_| Failure::ResponseInvalid)?;
            for stakeholder in page.stakeholders.unwrap_or_default() {
                collected.push(plan, Record::Stakeholder(stakeholder.record()))?;
            }
            Ok(page.next_page_token)
        },
    )?;
    paginate(
        plan,
        port,
        meter,
        &token,
        Collection::OptionGrants,
        page_limit,
        |body| match plan.children {
            CartaChildren::Omit => {
                let page: OptionGrantsPage<GrantDto> =
                    crate::json::decode_evidence(body).map_err(|_| Failure::ResponseInvalid)?;
                for grant in page.option_grants.unwrap_or_default() {
                    collected.push(plan, Record::Grant(Box::new(grant.record())))?;
                }
                Ok(page.next_page_token)
            }
            CartaChildren::Include => {
                let page: OptionGrantsPage<GrantWithChildren> =
                    crate::json::decode_evidence(body).map_err(|_| Failure::ResponseInvalid)?;
                for grant in page.option_grants.unwrap_or_default() {
                    let header = grant.grant.record();
                    let id = header.id.clone();
                    collected.push(plan, Record::Grant(Box::new(header)))?;
                    for event in grant.vesting_events.unwrap_or_default() {
                        collected.push(plan, Record::VestingEvent(event.record(&id)))?;
                    }
                    for exercise in grant.exercises.unwrap_or_default() {
                        collected.push(plan, Record::Exercise(exercise.record(&id)))?;
                    }
                }
                Ok(page.next_page_token)
            }
        },
    )?;
    Ok(collected)
}

/// A validated complete capture, ready to be delivered to the application.
pub struct CompleteCapture {
    snapshot: Snapshot,
    records: Vec<Record>,
}

impl CompleteCapture {
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// The typed records in provider order, for delivery to the application.
    pub fn records(&self) -> &[Record] {
        &self.records
    }
}

fn complete(plan: &CapturePlan, collected: Collected) -> Result<CompleteCapture> {
    let count = |kind: fn(&Record) -> bool| collected.records.iter().filter(|r| kind(r)).count();
    let stakeholder_count = count(|record| matches!(record, Record::Stakeholder(_)));
    let grant_count = count(|record| matches!(record, Record::Grant(_)));
    let vesting_event_count = count(|record| matches!(record, Record::VestingEvent(_)));
    let exercise_count = count(|record| matches!(record, Record::Exercise(_)));
    let source_profile = plan.source_profile.name();
    // No collection time: an unchanged recapture is the same capture. The
    // connection authority is part of it, so the same records collected under
    // another connection, client or credential are a different capture.
    let identity = crate::digest(&serde_json::to_vec(&(
        "carta-live-v1",
        &plan.scope,
        &plan.connection,
        plan.environment.name(),
        &plan.issuer_id,
        plan.children.name(),
        &collected.records,
        stakeholder_count,
        grant_count,
        vesting_event_count,
        exercise_count,
        source_profile,
    ))?);
    Ok(CompleteCapture {
        snapshot: Snapshot {
            id: format!("carta_{}", &identity[7..]),
            issuer_id: plan.issuer_id.clone(),
            record_count: u64::try_from(collected.records.len())?,
            stakeholder_count: u64::try_from(stakeholder_count)?,
            grant_count: u64::try_from(grant_count)?,
            vesting_event_count: u64::try_from(vesting_event_count)?,
            exercise_count: u64::try_from(exercise_count)?,
            source_profile: source_profile.into(),
        },
        records: collected.records,
    })
}

/// Collect a complete capture through `port`. Nothing is published here; the
/// meter reports every request sent, whether or not collection succeeded.
pub fn collect_complete(
    plan: &CapturePlan,
    port: &mut dyn CartaPort,
    page_limit: usize,
) -> (Result<CompleteCapture>, Meter) {
    let mut meter = Meter::default();
    let page_limit = page_limit.min(MAX_PAGE_RESPONSE_BYTES);
    let result = collect(plan, port, page_limit, &mut meter)
        .map_err(anyhow::Error::from)
        .and_then(|collected| complete(plan, collected));
    (result, meter)
}

/// Offline Carta wire bodies parsed by the same DTOs and pipeline as the live
/// adapter. The world is the provider's own scoped simulation store.
pub struct SimulatedCartaPort {
    database: std::path::PathBuf,
    scope: String,
    issuer_id: String,
}

impl SimulatedCartaPort {
    pub fn new(database: &Path, scope: &str, issuer_id: &str) -> Result<Self> {
        crate::integrations::simulated::carta_check(database, scope)?;
        Ok(Self {
            database: database.into(),
            scope: scope.into(),
            issuer_id: issuer_id.into(),
        })
    }
}

impl CartaPort for SimulatedCartaPort {
    fn token(
        &mut self,
        form: &str,
        max_bytes: usize,
    ) -> std::result::Result<Reply, TransportFailure> {
        crate::integrations::simulated::carta_read(
            &self.database,
            &self.scope,
            crate::integrations::simulated::CartaRead::Token { form },
            max_bytes,
        )
    }

    fn page(
        &mut self,
        collection: Collection,
        query: Option<&str>,
        token: &AccessToken,
        max_bytes: usize,
    ) -> std::result::Result<Reply, TransportFailure> {
        crate::integrations::simulated::carta_read(
            &self.database,
            &self.scope,
            crate::integrations::simulated::CartaRead::Page {
                issuer_id: &self.issuer_id,
                collection,
                query,
                bearer: token.bearer(),
            },
            max_bytes,
        )
    }
}

#[cfg(test)]
#[path = "carta_live_tests.rs"]
mod tests;
