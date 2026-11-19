//! Google Workspace organization reads through a keyless service account. See
//! docs/GOOGLE-WORKSPACE.md for the provider's contract.
//!
//! This pipeline owns everything but the wire: each action's fixed identity and
//! scopes, request construction from inputs validated against the grant, every
//! call and byte bound, status classification and response validation. A
//! [`GooglePort`] owns only HTTP. The native port speaks HTTPS to Google's fixed
//! origins; the simulated port answers the same requests from the provider's
//! committed world, so both lanes run the same token flow, the same requests and
//! the same parser.
use crate::google_auth::{self, AccessToken, Exchange, Reply, Unreached};
use anyhow::{Result, ensure};
use day2_capabilities::{
    integrations::LiveConnection,
    resources::{Action, ResourceTarget, google_workspace_address},
};
use serde::Deserialize;
use std::fmt;

use crate::google_workspace_calendar as calendar;
use calendar::{
    ACL_FIELDS, ACL_PAGE_CEILING, ACL_PAGE_SIZE, CALENDAR_ACL_READ_SCOPE, CALENDAR_FIELDS,
    CALENDAR_READ_SCOPE, CalendarOutcome, EVENT_FIELDS, EVENTS_FIELDS, EVENTS_QUERY, EventOutcome,
    EventsOutcome, GroupRole, MAX_CALENDAR_RESPONSE_BYTES, RULE_FIELDS,
};

pub const GROUP_READ_SCOPE: &str = "https://www.googleapis.com/auth/admin.directory.group.readonly";
pub const GROUP_MEMBER_READ_SCOPE: &str =
    "https://www.googleapis.com/auth/admin.directory.group.member.readonly";
pub const DIRECTORY_ORIGIN: &str = "https://admin.googleapis.com";
pub const CALENDAR_ORIGIN: &str = "https://www.googleapis.com";
/// One Directory response. A group or a membership answer is a few hundred bytes.
pub const MAX_DIRECTORY_RESPONSE_BYTES: usize = 16 * 1024;
/// The largest single response any action reads; each plan states its own
/// (`Plan::max_response_bytes`), which its grant must admit.
pub const MAX_RESPONSE_BYTES: usize = MAX_CALENDAR_RESPONSE_BYTES;
/// The posted payload of every exchange of one action together, reserved whole.
pub const MAX_ACTION_REQUEST_BYTES: u64 = 32 * 1024;
/// An application's request: a handle and its bounded inputs (addresses,
/// calendar and event IDs, a window and a page token).
pub const MAX_INPUT_BYTES: usize = 4 * 1024;

/// One declaration of every failure and its code: `ALL` and `code` are both
/// generated from it, so a variant cannot exist without a code or be missing
/// from `ALL`.
macro_rules! failures {
    ($($(#[doc = $doc:literal])* $variant:ident => $code:literal),* $(,)?) => {
        /// Stable, redacted failures. No variant carries a body, URL, header,
        /// token or address, so an observation error can never become a
        /// provider data channel.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Failure {
            $($(#[doc = $doc])* $variant),*
        }

        impl Failure {
            pub const ALL: &'static [Self] = &[$(Self::$variant),*];

            pub fn code(self) -> &'static str {
                match self {
                    $(Self::$variant => $code),*
                }
            }
        }
    };
}

failures! {
    WorkloadIdentityUnavailable => "google_workspace_workload_identity_unavailable",
    AuthenticationFailed => "google_workspace_authentication_failed",
    /// 403: the service account lacks the admin role, or the API is disabled.
    Denied => "google_workspace_denied",
    RateLimited => "google_workspace_rate_limited",
    Unavailable => "google_workspace_unavailable",
    /// 400: Google refused the request as malformed.
    RequestRefused => "google_workspace_request_refused",
    ResponseInvalid => "google_workspace_response_invalid",
    ResponseTooLarge => "google_workspace_response_too_large",
    /// Google answered with a group whose primary address is outside the grant.
    GroupOutsideGrant => "google_workspace_group_outside_grant",
    /// A calendar's ACL has more pages than an action reads, so the group's
    /// role is not answered from a partial list.
    AclPageBudget => "google_workspace_acl_page_budget",
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for Failure {}

impl From<google_auth::Failure> for Failure {
    fn from(failure: google_auth::Failure) -> Self {
        match failure {
            google_auth::Failure::WorkloadIdentityUnavailable => Self::WorkloadIdentityUnavailable,
            google_auth::Failure::AuthenticationFailed => Self::AuthenticationFailed,
            google_auth::Failure::RateLimited => Self::RateLimited,
            google_auth::Failure::Unavailable => Self::Unavailable,
            google_auth::Failure::ResponseTooLarge => Self::ResponseTooLarge,
        }
    }
}

/// What one action reads, validated against its grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Read {
    Group {
        group: String,
    },
    GroupMember {
        group: String,
        member: String,
    },
    Calendar {
        calendar: String,
        group: String,
    },
    CalendarEvents {
        calendar: String,
        time_min: String,
        time_max: String,
        page_token: Option<String>,
    },
    CalendarEvent {
        calendar: String,
        event: String,
    },
}

/// Where an action's exchanges go. Chosen when the capability is authorized,
/// so a simulated host can never reach the native port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The provider's committed simulated world.
    Simulated,
    /// Google's fixed origins.
    Native,
}

/// One action, frozen when the capability is authorized: its source, the
/// connection's service account, the grant's Calendar reader and grantee
/// domains, and the in-grant inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    source: Source,
    service_account: String,
    calendar_reader: String,
    grantee_domains: Vec<String>,
    read: Read,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupRequest {
    handle: String,
    group_email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupMemberRequest {
    handle: String,
    group_email: String,
    member_email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CalendarRequest {
    handle: String,
    calendar_id: String,
    group_email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CalendarEventsRequest {
    handle: String,
    calendar_id: String,
    time_min: String,
    time_max: String,
    page_token: crate::carta::OptionalText,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CalendarEventRequest {
    handle: String,
    calendar_id: String,
    event_id: String,
}

impl Plan {
    /// Decode an application request and bind it to its grant. Returns the plan
    /// and the handle the request presented, which the caller compares with the
    /// resolved resource. Malformed input is `google_workspace_request_invalid`;
    /// an address outside the grant is refused as a resource authorization.
    pub fn authorize(
        action: Action,
        connection: &LiveConnection,
        target: &ResourceTarget,
        request: &str,
        source: Source,
    ) -> Result<(Self, String)> {
        let LiveConnection::GoogleWorkspace { service_account } = connection else {
            anyhow::bail!(crate::error::Failure::ResourceForbidden)
        };
        let ResourceTarget::GoogleWorkspaceDomain {
            calendar_reader,
            grantee_domains,
        } = target
        else {
            anyhow::bail!(crate::error::Failure::ResourceForbidden)
        };
        connection.validate()?;
        target.validate()?;
        ensure!(
            request.len() <= MAX_INPUT_BYTES,
            "google_workspace_request_invalid"
        );
        let invalid = |_| anyhow::anyhow!("google_workspace_request_invalid");
        let group_domain = |group: &str| -> Result<String> {
            let (_, domain) = google_workspace_address(group).map_err(invalid)?;
            ensure!(
                grantee_domains.iter().any(|granted| granted == domain),
                crate::error::Failure::ResourceForbidden
            );
            Ok(domain.to_owned())
        };
        let calendar_id = |value: &str| -> Result<()> {
            ensure!(
                calendar::calendar_id(value),
                "google_workspace_request_invalid"
            );
            Ok(())
        };
        let (read, handle) = match action {
            Action::GoogleWorkspaceGroup => {
                let input: GroupRequest =
                    crate::json::decode(request.as_bytes()).map_err(invalid)?;
                group_domain(&input.group_email)?;
                (
                    Read::Group {
                        group: input.group_email,
                    },
                    input.handle,
                )
            }
            Action::GoogleWorkspaceGroupMember => {
                let input: GroupMemberRequest =
                    crate::json::decode(request.as_bytes()).map_err(invalid)?;
                let domain = group_domain(&input.group_email)?;
                // Google answers a nested membership question only when the
                // member and the group share a domain (otherwise 400 Invalid
                // Input), so a question it cannot answer is never asked.
                let (_, member_domain) =
                    google_workspace_address(&input.member_email).map_err(invalid)?;
                ensure!(
                    member_domain == domain,
                    crate::error::Failure::ResourceForbidden
                );
                (
                    Read::GroupMember {
                        group: input.group_email,
                        member: input.member_email,
                    },
                    input.handle,
                )
            }
            Action::GoogleWorkspaceCalendar => {
                let input: CalendarRequest =
                    crate::json::decode(request.as_bytes()).map_err(invalid)?;
                calendar_id(&input.calendar_id)?;
                group_domain(&input.group_email)?;
                (
                    Read::Calendar {
                        calendar: input.calendar_id,
                        group: input.group_email,
                    },
                    input.handle,
                )
            }
            Action::GoogleWorkspaceCalendarEvents => {
                let input: CalendarEventsRequest =
                    crate::json::decode(request.as_bytes()).map_err(invalid)?;
                calendar_id(&input.calendar_id)?;
                let page_token = calendar::optional_value(input.page_token);
                ensure!(
                    calendar::window(&input.time_min, &input.time_max)
                        && page_token.as_deref().is_none_or(calendar::page_token),
                    "google_workspace_request_invalid"
                );
                (
                    Read::CalendarEvents {
                        calendar: input.calendar_id,
                        time_min: input.time_min,
                        time_max: input.time_max,
                        page_token,
                    },
                    input.handle,
                )
            }
            Action::GoogleWorkspaceCalendarEvent => {
                let input: CalendarEventRequest =
                    crate::json::decode(request.as_bytes()).map_err(invalid)?;
                calendar_id(&input.calendar_id)?;
                ensure!(
                    calendar::event_id(&input.event_id),
                    "google_workspace_request_invalid"
                );
                (
                    Read::CalendarEvent {
                        calendar: input.calendar_id,
                        event: input.event_id,
                    },
                    input.handle,
                )
            }
            _ => anyhow::bail!(crate::error::Failure::ResourceForbidden),
        };
        Ok((
            Self {
                source,
                service_account: service_account.clone(),
                calendar_reader: calendar_reader.clone(),
                grantee_domains: grantee_domains.clone(),
                read,
            },
            handle,
        ))
    }

    pub fn read(&self) -> &Read {
        &self.read
    }

    pub fn source(&self) -> Source {
        self.source
    }

    /// Directory reads run as the service account itself; Calendar reads by
    /// domain-wide delegation as the grant's Calendar reader.
    fn delegated(&self) -> bool {
        matches!(
            self.read,
            Read::Calendar { .. } | Read::CalendarEvents { .. } | Read::CalendarEvent { .. }
        )
    }

    /// Authentication exchanges: metadata and IAM, plus the token exchange
    /// when delegated.
    fn authentication_calls(&self) -> u64 {
        if self.delegated() { 3 } else { 2 }
    }

    /// Calls to the API itself: one per Directory question. Every Calendar
    /// read first reads the reader's own ACL rule, then either the calendar
    /// (to tell a missing calendar from one not shared) or its own call: the
    /// calendar and every ACL page up to the ceiling, one page or one event.
    fn api_calls(&self) -> u64 {
        match self.read {
            Read::Group { .. } => 1,
            Read::GroupMember { .. } => 2,
            Read::Calendar { .. } => 2 + ACL_PAGE_CEILING,
            Read::CalendarEvents { .. } | Read::CalendarEvent { .. } => 2,
        }
    }

    pub fn planned_calls(&self) -> u64 {
        self.authentication_calls() + self.api_calls()
    }

    /// The largest single response the action reads. Its grant must admit it.
    pub fn max_response_bytes(&self) -> usize {
        google_auth::MAX_EXCHANGE_RESPONSE_BYTES.max(self.api_response_bytes())
    }

    fn api_response_bytes(&self) -> usize {
        if self.delegated() {
            MAX_CALENDAR_RESPONSE_BYTES
        } else {
            MAX_DIRECTORY_RESPONSE_BYTES
        }
    }

    /// Every response the action may read, each with its one-byte probe.
    pub fn response_envelope(&self) -> u64 {
        let exchange = (google_auth::MAX_EXCHANGE_RESPONSE_BYTES + 1) as u64;
        let api = (self.api_response_bytes() + 1) as u64;
        self.authentication_calls() * exchange + self.api_calls() * api
    }
}

/// The fixed origin a request goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    Directory,
    Calendar,
}

/// An API request as the wire sends it: a fixed service, path segments built
/// from validated inputs, and a fixed query. `endpoint` names it for timing
/// only; a port routes on the service and segments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiRequest {
    pub service: Service,
    pub endpoint: &'static str,
    pub segments: Vec<String>,
    pub query: Vec<(&'static str, String)>,
}

impl ApiRequest {
    fn new(
        service: Service,
        endpoint: &'static str,
        prefix: &[&str],
        segments: &[&str],
        query: &[(&'static str, &str)],
    ) -> Self {
        Self {
            service,
            endpoint,
            segments: prefix
                .iter()
                .chain(segments)
                .map(|segment| (*segment).to_owned())
                .collect(),
            // Every response is requested compact: prettyPrint only adds bytes.
            query: query
                .iter()
                .chain(&[("prettyPrint", "false")])
                .map(|(name, value)| (*name, (*value).to_owned()))
                .collect(),
        }
    }

    fn directory(
        endpoint: &'static str,
        segments: &[&str],
        query: &[(&'static str, &str)],
    ) -> Self {
        Self::new(
            Service::Directory,
            endpoint,
            &["admin", "directory", "v1"],
            segments,
            query,
        )
    }

    fn calendar(endpoint: &'static str, segments: &[&str], query: &[(&'static str, &str)]) -> Self {
        Self::new(
            Service::Calendar,
            endpoint,
            &["calendar", "v3"],
            segments,
            query,
        )
    }

    /// The encoded query, byte-identical to what the native port sends.
    pub fn query_string(&self) -> Option<String> {
        (!self.query.is_empty()).then(|| {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (name, value) in &self.query {
                serializer.append_pair(name, value);
            }
            serializer.finish()
        })
    }

    /// A GET carries its request in the query.
    pub fn request_bytes(&self) -> usize {
        self.query_string().map_or(0, |query| query.len())
    }
}

/// The two reviewed kinds of exchange. Implementations build URLs and headers
/// from fixed parts and report what the wire returned; they never retry, follow a
/// redirect or interpret a status.
pub trait GooglePort {
    fn authenticate(
        &mut self,
        exchange: &Exchange<'_>,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Unreached>;
    fn call(
        &mut self,
        request: &ApiRequest,
        token: &AccessToken,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Unreached>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Metadata,
    Iam,
    Token,
    Directory,
    Calendar,
}

/// The most recent exchange, kept for correlation. No body or header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LastExchange {
    pub phase: Phase,
    pub http_status: Option<u16>,
    pub retry_after_seconds: Option<u32>,
}

/// Measured usage of one action, including exchanges that failed, so known
/// settlement records exactly what was consumed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Meter {
    pub calls: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub last: Option<LastExchange>,
}

impl Meter {
    /// Request payloads are fixed by the pipeline (a few hundred bytes against
    /// the reserved `MAX_ACTION_REQUEST_BYTES`), so sending is only counted.
    fn send(&mut self, phase: Phase, request_bytes: usize) {
        self.calls += 1;
        self.request_bytes = self.request_bytes.saturating_add(request_bytes as u64);
        self.last = Some(LastExchange {
            phase,
            http_status: None,
            retry_after_seconds: None,
        });
    }

    /// Count every byte consumed and keep what the response declared, whether or
    /// not the exchange completed.
    fn receive(
        &mut self,
        reply: std::result::Result<Reply, Unreached>,
    ) -> std::result::Result<Reply, Unreached> {
        let (bytes, status, retry_after_seconds) = match &reply {
            Ok(reply) => (
                reply.body.len() as u64,
                Some(reply.status),
                reply.retry_after_seconds,
            ),
            Err(unreached) => (
                unreached.response_bytes,
                unreached.http_status,
                unreached.retry_after_seconds,
            ),
        };
        self.response_bytes = self.response_bytes.saturating_add(bytes);
        if let Some(last) = &mut self.last {
            last.http_status = status.filter(|status| (100..=599).contains(status));
            last.retry_after_seconds = retry_after_seconds;
        }
        reply
    }
}

/// Token exchanges through the port, metered like every other exchange.
struct MeteredWire<'a> {
    port: &'a mut dyn GooglePort,
    meter: &'a mut Meter,
}

impl google_auth::TokenWire for MeteredWire<'_> {
    fn exchange(
        &mut self,
        exchange: &Exchange<'_>,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Unreached> {
        let phase = match exchange {
            Exchange::Metadata => Phase::Metadata,
            Exchange::Iam { .. } => Phase::Iam,
            Exchange::Token { .. } => Phase::Token,
        };
        self.meter.send(phase, exchange.request_bytes());
        self.meter
            .receive(self.port.authenticate(exchange, max_bytes))
    }
}

/// The action's token: the service account itself for Directory reads, the
/// grant's Calendar reader by domain-wide delegation for Calendar reads, with
/// exactly the action's scopes either way.
fn access_token(
    plan: &Plan,
    port: &mut dyn GooglePort,
    meter: &mut Meter,
    scopes: &[&str],
    now: i64,
) -> Result<AccessToken, Failure> {
    google_auth::acquire(
        &mut MeteredWire { port, meter },
        &google_auth::TokenRequest {
            service_account: &plan.service_account,
            identity: if plan.delegated() {
                google_auth::Identity::Delegated(&plan.calendar_reader)
            } else {
                google_auth::Identity::ServiceAccount
            },
            scopes,
        },
        now,
    )
    .map_err(Failure::from)
}

fn send(
    port: &mut dyn GooglePort,
    meter: &mut Meter,
    request: &ApiRequest,
    token: &AccessToken,
    max_bytes: usize,
) -> Result<Reply, Failure> {
    meter.send(
        match request.service {
            Service::Directory => Phase::Directory,
            Service::Calendar => Phase::Calendar,
        },
        request.request_bytes(),
    );
    meter
        .receive(port.call(request, token, max_bytes))
        .map_err(|unreached| {
            if unreached.too_large {
                Failure::ResponseTooLarge
            } else {
                Failure::Unavailable
            }
        })
}

/// Classify an API reply other than the statuses an action interprets itself.
fn accept(reply: &Reply, max_bytes: usize) -> Result<(), Failure> {
    match reply.status {
        200 => {}
        400 => return Err(Failure::RequestRefused),
        401 => return Err(Failure::AuthenticationFailed),
        // Google answers both a refusal and a rate or quota limit with 403.
        403 => return Err(calendar::forbidden(&reply.body)),
        429 => return Err(Failure::RateLimited),
        500..=599 => return Err(Failure::Unavailable),
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

/// A group as the Directory reports it, and as an application receives it.
#[derive(Clone, Debug, serde::Serialize, Deserialize, PartialEq, Eq)]
pub struct Group {
    pub id: String,
    pub email: String,
    pub name: String,
}

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub enum GroupOutcome {
    Found(Group),
    NotFound,
}

#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
pub enum MembershipOutcome {
    Member,
    NotMember,
    GroupNotFound,
}

/// An outcome in the SDK's tag encoding: serde's externally tagged form, with
/// object keys in sorted order.
pub fn encode<T: serde::Serialize>(outcome: &T) -> String {
    serde_json::to_value(outcome)
        .map(|value| value.to_string())
        .unwrap_or_default()
}

/// Validate Google's group shape. The address Google reports is the group's
/// primary address, which may differ from an alias the application asked about;
/// it must still be in a grantee domain.
pub fn parse_group(body: &[u8], grantee_domains: &[String]) -> Result<Group, Failure> {
    #[derive(Deserialize)]
    struct DirectoryGroup {
        id: String,
        email: String,
        name: String,
    }
    let group: DirectoryGroup = crate::json::decode(body).map_err(|_| Failure::ResponseInvalid)?;
    let email = group.email.to_ascii_lowercase();
    let (_, domain) = google_workspace_address(&email).map_err(|_| Failure::ResponseInvalid)?;
    if group.id.is_empty()
        || group.id.len() > 256
        || !group.id.bytes().all(|byte| byte.is_ascii_graphic())
        || group.name.trim().is_empty()
        || group.name.len() > 1024
        || group.name.chars().any(char::is_control)
    {
        return Err(Failure::ResponseInvalid);
    }
    if !grantee_domains.iter().any(|granted| granted == domain) {
        return Err(Failure::GroupOutsideGrant);
    }
    Ok(Group {
        id: group.id,
        email,
        name: group.name,
    })
}

pub fn parse_membership(body: &[u8]) -> Result<bool, Failure> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct HasMember {
        is_member: bool,
    }
    crate::json::decode::<HasMember>(body)
        .map(|answer| answer.is_member)
        .map_err(|_| Failure::ResponseInvalid)
}

fn group_lookup(
    plan: &Plan,
    port: &mut dyn GooglePort,
    meter: &mut Meter,
    token: &AccessToken,
    group: &str,
) -> Result<GroupOutcome, Failure> {
    let request = ApiRequest::directory(
        "directory_group",
        &["groups", group],
        &[("fields", "id,email,name")],
    );
    let reply = send(port, meter, &request, token, MAX_DIRECTORY_RESPONSE_BYTES)?;
    if reply.status == 404 {
        return Ok(GroupOutcome::NotFound);
    }
    accept(&reply, MAX_DIRECTORY_RESPONSE_BYTES)?;
    parse_group(&reply.body, &plan.grantee_domains).map(GroupOutcome::Found)
}

fn run(
    plan: &Plan,
    port: &mut dyn GooglePort,
    meter: &mut Meter,
    now: i64,
) -> Result<String, Failure> {
    match &plan.read {
        Read::Group { group } => {
            let token = access_token(plan, port, meter, &[GROUP_READ_SCOPE], now)?;
            Ok(encode(&group_lookup(plan, port, meter, &token, group)?))
        }
        Read::GroupMember { group, member } => {
            let token = access_token(
                plan,
                port,
                meter,
                &[GROUP_READ_SCOPE, GROUP_MEMBER_READ_SCOPE],
                now,
            )?;
            // The group is looked up first: a 404 from hasMember alone cannot say
            // whether the group or the member is missing.
            if group_lookup(plan, port, meter, &token, group)? == GroupOutcome::NotFound {
                return Ok(encode(&MembershipOutcome::GroupNotFound));
            }
            let request = ApiRequest::directory(
                "directory_has_member",
                &["groups", group, "hasMember", member],
                &[],
            );
            let reply = send(port, meter, &request, &token, MAX_DIRECTORY_RESPONSE_BYTES)?;
            if reply.status == 404 {
                return Ok(encode(&MembershipOutcome::NotMember));
            }
            accept(&reply, MAX_DIRECTORY_RESPONSE_BYTES)?;
            Ok(encode(&if parse_membership(&reply.body)? {
                MembershipOutcome::Member
            } else {
                MembershipOutcome::NotMember
            }))
        }
        Read::Calendar { calendar, group } => {
            let token = access_token(
                plan,
                port,
                meter,
                &[CALENDAR_READ_SCOPE, CALENDAR_ACL_READ_SCOPE],
                now,
            )?;
            Ok(encode(&calendar_with_role(
                plan, port, meter, &token, calendar, group,
            )?))
        }
        Read::CalendarEvents {
            calendar,
            time_min,
            time_max,
            page_token,
        } => {
            let token = access_token(
                plan,
                port,
                meter,
                &[CALENDAR_READ_SCOPE, CALENDAR_ACL_READ_SCOPE],
                now,
            )?;
            match reader_access(plan, port, meter, &token, calendar)? {
                Access::Shared => {}
                Access::NotShared => return Ok(encode(&EventsOutcome::NotShared)),
                Access::NotFound => return Ok(encode(&EventsOutcome::NotFound)),
            }
            let mut query: Vec<(&'static str, &str)> = EVENTS_QUERY.to_vec();
            query.push(("timeMin", time_min.as_str()));
            query.push(("timeMax", time_max.as_str()));
            if let Some(page_token) = page_token {
                query.push(("pageToken", page_token.as_str()));
            }
            query.push(("fields", EVENTS_FIELDS));
            let request = ApiRequest::calendar(
                "calendar_events",
                &["calendars", calendar, "events"],
                &query,
            );
            let reply = send(port, meter, &request, &token, MAX_CALENDAR_RESPONSE_BYTES)?;
            // The calendar went away after its rule was read.
            if reply.status == 404 {
                return Ok(encode(&EventsOutcome::NotFound));
            }
            accept(&reply, MAX_CALENDAR_RESPONSE_BYTES)?;
            Ok(encode(&EventsOutcome::Found(calendar::parse_events_page(
                &reply.body,
            )?)))
        }
        Read::CalendarEvent { calendar, event } => {
            let token = access_token(
                plan,
                port,
                meter,
                &[CALENDAR_READ_SCOPE, CALENDAR_ACL_READ_SCOPE],
                now,
            )?;
            match reader_access(plan, port, meter, &token, calendar)? {
                Access::Shared => {}
                Access::NotShared => return Ok(encode(&EventOutcome::NotShared)),
                Access::NotFound => return Ok(encode(&EventOutcome::NotFound)),
            }
            let request = ApiRequest::calendar(
                "calendar_event",
                &["calendars", calendar, "events", event],
                &[("fields", EVENT_FIELDS)],
            );
            let reply = send(port, meter, &request, &token, MAX_CALENDAR_RESPONSE_BYTES)?;
            if matches!(reply.status, 404 | 410) {
                return Ok(encode(&EventOutcome::NotFound));
            }
            accept(&reply, MAX_CALENDAR_RESPONSE_BYTES)?;
            Ok(encode(&calendar::parse_event(&reply.body, event)?))
        }
    }
}

/// Whether a calendar is in play for this grant.
enum Access {
    /// The reader holds its own `writer` or `owner` rule.
    Shared,
    /// The reader can see the calendar some other way, or with a lesser role.
    NotShared,
    /// The reader cannot see a calendar with that ID at all.
    NotFound,
}

/// The bound every Calendar read checks first: the reader's own ACL rule,
/// `acl/user:{reader}`, must exist with `writer` or `owner`. Google also lets
/// the reader see calendars through group, domain and default rules and
/// organization-wide sharing; none of those put a calendar in play.
///
/// Without that rule Google answers `404`, or `403` when the reader may not
/// read rules at all (that needs `writer` or `owner`). Either way the calendar
/// itself is then read: one the reader can see is not shared, one it cannot
/// see is not found, and a refusal there too is a refusal, such as a disabled
/// API, never a calendar that is merely not shared.
fn reader_access(
    plan: &Plan,
    port: &mut dyn GooglePort,
    meter: &mut Meter,
    token: &AccessToken,
    calendar: &str,
) -> Result<Access, Failure> {
    let rule = format!("user:{}", plan.calendar_reader);
    let request = ApiRequest::calendar(
        "calendar_reader_rule",
        &["calendars", calendar, "acl", &rule],
        &[("fields", RULE_FIELDS)],
    );
    let reply = send(port, meter, &request, token, MAX_CALENDAR_RESPONSE_BYTES)?;
    match reply.status {
        200 => {
            accept(&reply, MAX_CALENDAR_RESPONSE_BYTES)?;
            return Ok(
                if calendar::parse_reader_rule(&reply.body, &plan.calendar_reader)? {
                    Access::Shared
                } else {
                    Access::NotShared
                },
            );
        }
        404 => {}
        // A rate or quota limit is not a missing rule.
        403 => match calendar::forbidden(&reply.body) {
            Failure::Denied => {}
            failure => return Err(failure),
        },
        _ => {
            accept(&reply, MAX_CALENDAR_RESPONSE_BYTES)?;
            return Err(Failure::ResponseInvalid);
        }
    }
    let request = ApiRequest::calendar(
        "calendar_get",
        &["calendars", calendar],
        &[("fields", CALENDAR_FIELDS)],
    );
    let reply = send(port, meter, &request, token, MAX_CALENDAR_RESPONSE_BYTES)?;
    if reply.status == 404 {
        return Ok(Access::NotFound);
    }
    accept(&reply, MAX_CALENDAR_RESPONSE_BYTES)?;
    calendar::parse_calendar(&reply.body, calendar)?;
    Ok(Access::NotShared)
}

/// The calendar and the role one group holds in its ACL, once the reader's
/// own rule puts the calendar in play. The ACL is paged up to a fixed ceiling
/// and never returned.
fn calendar_with_role(
    plan: &Plan,
    port: &mut dyn GooglePort,
    meter: &mut Meter,
    token: &AccessToken,
    calendar: &str,
    group: &str,
) -> Result<CalendarOutcome, Failure> {
    match reader_access(plan, port, meter, token, calendar)? {
        Access::Shared => {}
        Access::NotShared => return Ok(CalendarOutcome::NotShared),
        Access::NotFound => return Ok(CalendarOutcome::NotFound),
    }
    let request = ApiRequest::calendar(
        "calendar_get",
        &["calendars", calendar],
        &[("fields", CALENDAR_FIELDS)],
    );
    let reply = send(port, meter, &request, token, MAX_CALENDAR_RESPONSE_BYTES)?;
    if reply.status == 404 {
        return Ok(CalendarOutcome::NotFound);
    }
    accept(&reply, MAX_CALENDAR_RESPONSE_BYTES)?;
    let summary = calendar::parse_calendar(&reply.body, calendar)?;
    let page_size = ACL_PAGE_SIZE.to_string();
    let mut continuation: Option<String> = None;
    for _ in 0..ACL_PAGE_CEILING {
        let mut query = vec![("maxResults", page_size.as_str())];
        if let Some(page_token) = &continuation {
            query.push(("pageToken", page_token.as_str()));
        }
        query.push(("fields", ACL_FIELDS));
        let request = ApiRequest::calendar("calendar_acl", &["calendars", calendar, "acl"], &query);
        let reply = send(port, meter, &request, token, MAX_CALENDAR_RESPONSE_BYTES)?;
        // The calendar went away between the reads.
        if reply.status == 404 {
            return Ok(CalendarOutcome::NotFound);
        }
        accept(&reply, MAX_CALENDAR_RESPONSE_BYTES)?;
        let group_role = match calendar::parse_acl_page(&reply.body, group)? {
            (Some(role), _) => role,
            (None, None) => GroupRole::None,
            (None, Some(next)) => {
                continuation = Some(next);
                continue;
            }
        };
        return Ok(CalendarOutcome::Found(calendar::Calendar {
            id: calendar.to_owned(),
            summary,
            group_role,
        }));
    }
    Err(Failure::AclPageBudget)
}

/// Run one action through `port`. The meter reports every exchange sent,
/// whether or not the action succeeded.
pub fn observe(plan: &Plan, port: &mut dyn GooglePort, now: i64) -> (Result<String>, Meter) {
    let mut meter = Meter::default();
    let result = run(plan, port, &mut meter, now).map_err(anyhow::Error::from);
    (result, meter)
}

/// Offline exchanges answered by the provider's committed world, through the
/// same pipeline and parser as the native port.
pub struct SimulatedGooglePort {
    database: std::path::PathBuf,
    scope: String,
}

impl SimulatedGooglePort {
    pub fn new(database: &std::path::Path, scope: &str) -> Result<Self> {
        crate::integrations::simulated::google_workspace_check(database, scope)?;
        Ok(Self {
            database: database.into(),
            scope: scope.into(),
        })
    }
}

impl GooglePort for SimulatedGooglePort {
    fn authenticate(
        &mut self,
        exchange: &Exchange<'_>,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Unreached> {
        crate::integrations::simulated::google_workspace_serve(
            &self.database,
            &self.scope,
            crate::integrations::simulated::GoogleRequest::Auth(exchange),
            max_bytes,
        )
    }

    fn call(
        &mut self,
        request: &ApiRequest,
        token: &AccessToken,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Unreached> {
        crate::integrations::simulated::google_workspace_serve(
            &self.database,
            &self.scope,
            crate::integrations::simulated::GoogleRequest::Api {
                request,
                bearer: token.bearer(),
            },
            max_bytes,
        )
    }
}

#[cfg(test)]
#[path = "google_workspace_tests.rs"]
pub(crate) mod tests;
