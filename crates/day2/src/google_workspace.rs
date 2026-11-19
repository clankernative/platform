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

pub const GROUP_READ_SCOPE: &str = "https://www.googleapis.com/auth/admin.directory.group.readonly";
pub const GROUP_MEMBER_READ_SCOPE: &str =
    "https://www.googleapis.com/auth/admin.directory.group.member.readonly";
pub const DIRECTORY_ORIGIN: &str = "https://admin.googleapis.com";
/// One Directory response. A group or a membership answer is a few hundred bytes.
pub const MAX_DIRECTORY_RESPONSE_BYTES: usize = 16 * 1024;
/// The posted payload of every exchange of one action together.
pub const MAX_ACTION_REQUEST_BYTES: u64 = 32 * 1024;
/// An application's request: a handle and at most two addresses.
pub const MAX_INPUT_BYTES: usize = 4 * 1024;

/// Stable, redacted failures. No variant carries a body, URL, header, token or
/// address, so an observation error can never become a provider data channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    WorkloadIdentityUnavailable,
    AuthenticationFailed,
    /// 403: the service account lacks the admin role, or the API is disabled.
    Denied,
    RateLimited,
    Unavailable,
    /// 400: Google refused the request as malformed.
    RequestRefused,
    ResponseInvalid,
    ResponseTooLarge,
    RequestBudget,
    /// Google answered with a group whose address is outside the grant.
    GroupOutsideGrant,
}

impl Failure {
    pub fn code(self) -> &'static str {
        match self {
            Self::WorkloadIdentityUnavailable => "google_workspace_workload_identity_unavailable",
            Self::AuthenticationFailed => "google_workspace_authentication_failed",
            Self::Denied => "google_workspace_denied",
            Self::RateLimited => "google_workspace_rate_limited",
            Self::Unavailable => "google_workspace_unavailable",
            Self::RequestRefused => "google_workspace_request_refused",
            Self::ResponseInvalid => "google_workspace_response_invalid",
            Self::ResponseTooLarge => "google_workspace_response_too_large",
            Self::RequestBudget => "google_workspace_request_budget",
            Self::GroupOutsideGrant => "google_workspace_group_outside_grant",
        }
    }

    pub const ALL: [Self; 10] = [
        Self::WorkloadIdentityUnavailable,
        Self::AuthenticationFailed,
        Self::Denied,
        Self::RateLimited,
        Self::Unavailable,
        Self::RequestRefused,
        Self::ResponseInvalid,
        Self::ResponseTooLarge,
        Self::RequestBudget,
        Self::GroupOutsideGrant,
    ];
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
    Group { group: String },
    GroupMember { group: String, member: String },
}

/// One action, frozen when the capability is authorized: the connection's
/// service account, the grant's grantee domains and the in-grant inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    service_account: String,
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
    ) -> Result<(Self, String)> {
        let LiveConnection::GoogleWorkspace { service_account } = connection else {
            anyhow::bail!(crate::error::Failure::ResourceForbidden)
        };
        let ResourceTarget::GoogleWorkspaceDomain {
            email_domain,
            calendar_reader: _,
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
        let group_domain = |group: &str| -> Result<()> {
            let (_, domain) = google_workspace_address(group).map_err(invalid)?;
            ensure!(
                grantee_domains.iter().any(|granted| granted == domain),
                crate::error::Failure::ResourceForbidden
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
                group_domain(&input.group_email)?;
                // A membership question is about the organization's own people
                // or the grantee domains' groups, never an arbitrary outsider.
                let (_, member_domain) =
                    google_workspace_address(&input.member_email).map_err(invalid)?;
                ensure!(
                    member_domain == email_domain
                        || grantee_domains
                            .iter()
                            .any(|granted| granted == member_domain),
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
            _ => anyhow::bail!(crate::error::Failure::ResourceForbidden),
        };
        Ok((
            Self {
                service_account: service_account.clone(),
                grantee_domains: grantee_domains.clone(),
                read,
            },
            handle,
        ))
    }

    pub fn read(&self) -> &Read {
        &self.read
    }

    /// Metadata, IAM, then one Directory call per question.
    pub fn planned_calls(&self) -> u64 {
        match self.read {
            Read::Group { .. } => 3,
            Read::GroupMember { .. } => 4,
        }
    }

    /// Every response the action may read, each with its one-byte probe.
    pub fn response_envelope(&self) -> u64 {
        let exchange = (google_auth::MAX_EXCHANGE_RESPONSE_BYTES + 1) as u64;
        let directory = (MAX_DIRECTORY_RESPONSE_BYTES + 1) as u64;
        2 * exchange + (self.planned_calls() - 2) * directory
    }
}

/// A Directory request as the wire sends it: fixed path segments built from
/// validated inputs and a fixed query. `endpoint` names it for timing and
/// correlation only; a port routes on the segments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiRequest {
    pub endpoint: &'static str,
    pub segments: Vec<String>,
    pub query: Vec<(&'static str, String)>,
}

impl ApiRequest {
    fn directory(
        endpoint: &'static str,
        segments: &[&str],
        query: &[(&'static str, &str)],
    ) -> Self {
        Self {
            endpoint,
            segments: ["admin", "directory", "v1"]
                .iter()
                .chain(segments)
                .map(|segment| (*segment).to_owned())
                .collect(),
            query: query
                .iter()
                .map(|(name, value)| (*name, (*value).to_owned()))
                .collect(),
        }
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
    fn send(&mut self, phase: Phase, request_bytes: usize) -> Result<(), Failure> {
        let total = self
            .request_bytes
            .checked_add(request_bytes as u64)
            .filter(|total| *total <= MAX_ACTION_REQUEST_BYTES)
            .ok_or(Failure::RequestBudget)?;
        self.calls += 1;
        self.request_bytes = total;
        self.last = Some(LastExchange {
            phase,
            http_status: None,
            retry_after_seconds: None,
        });
        Ok(())
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
    over_budget: bool,
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
        if self.meter.send(phase, exchange.request_bytes()).is_err() {
            self.over_budget = true;
            return Err(Unreached::default());
        }
        self.meter
            .receive(self.port.authenticate(exchange, max_bytes))
    }
}

fn service_token(
    plan: &Plan,
    port: &mut dyn GooglePort,
    meter: &mut Meter,
    scopes: &[&str],
    now: i64,
) -> Result<AccessToken, Failure> {
    let mut wire = MeteredWire {
        port,
        meter,
        over_budget: false,
    };
    let token = google_auth::acquire(
        &mut wire,
        &google_auth::TokenRequest {
            service_account: &plan.service_account,
            identity: google_auth::Identity::ServiceAccount,
            scopes,
        },
        now,
    );
    if wire.over_budget {
        return Err(Failure::RequestBudget);
    }
    token.map_err(Failure::from)
}

fn send(
    port: &mut dyn GooglePort,
    meter: &mut Meter,
    request: &ApiRequest,
    token: &AccessToken,
    max_bytes: usize,
) -> Result<Reply, Failure> {
    meter.send(Phase::Directory, request.request_bytes())?;
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

/// Classify a Directory reply other than the 404 an action interprets itself.
fn accept(reply: &Reply, max_bytes: usize) -> Result<(), Failure> {
    match reply.status {
        200 => {}
        400 => return Err(Failure::RequestRefused),
        401 => return Err(Failure::AuthenticationFailed),
        403 => return Err(Failure::Denied),
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupOutcome {
    Found(Group),
    NotFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipOutcome {
    Member,
    NotMember,
    GroupNotFound,
}

/// The SDK's tag encodings.
impl GroupOutcome {
    pub fn encode(&self) -> String {
        match self {
            Self::Found(group) => serde_json::json!({ "Found": group }).to_string(),
            Self::NotFound => serde_json::json!("NotFound").to_string(),
        }
    }
}

impl MembershipOutcome {
    pub fn encode(self) -> String {
        serde_json::json!(match self {
            Self::Member => "Member",
            Self::NotMember => "NotMember",
            Self::GroupNotFound => "GroupNotFound",
        })
        .to_string()
    }
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
            let token = service_token(plan, port, meter, &[GROUP_READ_SCOPE], now)?;
            Ok(group_lookup(plan, port, meter, &token, group)?.encode())
        }
        Read::GroupMember { group, member } => {
            let token = service_token(
                plan,
                port,
                meter,
                &[GROUP_READ_SCOPE, GROUP_MEMBER_READ_SCOPE],
                now,
            )?;
            // The group is looked up first: a 404 from hasMember alone cannot say
            // whether the group or the member is missing.
            if group_lookup(plan, port, meter, &token, group)? == GroupOutcome::NotFound {
                return Ok(MembershipOutcome::GroupNotFound.encode());
            }
            let request = ApiRequest::directory(
                "directory_has_member",
                &["groups", group, "hasMember", member],
                &[],
            );
            let reply = send(port, meter, &request, &token, MAX_DIRECTORY_RESPONSE_BYTES)?;
            if reply.status == 404 {
                return Ok(MembershipOutcome::NotMember.encode());
            }
            accept(&reply, MAX_DIRECTORY_RESPONSE_BYTES)?;
            Ok(if parse_membership(&reply.body)? {
                MembershipOutcome::Member
            } else {
                MembershipOutcome::NotMember
            }
            .encode())
        }
    }
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
