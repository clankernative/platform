//! Offline worlds for the three adapters that were admitted live-first.
//!
//! The simulation sits at the transport seam rather than the adapter seam. These
//! adapters largely *are* their wire protocol: request construction, response
//! validation, error classification, byte accounting and correlation extraction
//! are the parts most likely to be wrong, and an adapter-seam stand-in that
//! returned a finished `AdapterOutcome` would bypass every one of them. Replacing
//! only the socket keeps `prepare`, `execute`, `transmit`, `parse_http_json` and
//! each provider's `response` on the real path, so the offline lane and the live
//! lane differ in exactly one component.
//!
//! Each provider commits to its own SQLite world, matching the synthetic People
//! providers. The `.simulated.` infix distinguishes these from the `.synthetic.`
//! stores: a synthetic provider has no live counterpart and its world *is* the
//! only reality, whereas these worlds stand in for a provider that also exists
//! live and must answer the same conformance suite.

use super::{
    AdapterError, CredentialResolver, Credentials, Transport, TransportError, WireResponse, slack,
};
use crate::integrations::transport::{Method, WireRequest};
use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use day2_capabilities::{integrations::LiveConnection, resources::Provider};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Mutex,
};

const MAX_WORLD_BYTES: usize = 32 * 1_048_576;
const MAX_MESSAGES: usize = 10_000;
const MAX_ROWS: usize = 10_000;
const MAX_FAULTS: usize = 1_024;

/// The world files these simulations commit to, kept beside the app database in
/// the same way as the synthetic People stores. Read from the provider table
/// rather than restated here: the registry is what backup and the deterministic
/// campaign enumerate, so a name declared in one place and used in another is a
/// drift the compiler would not catch.
pub const SLACK_WEBHOOK_WORLD: &str = world_of(Provider::SlackWebhook);
/// Deliberately fake credential, only ever used with the offline transport.
pub const SLACK_WEBHOOK_URL: &str =
    "https://hooks.slack.com/services/TSYNTHETIC/BSYNTHETIC/offline-only";
pub fn slack_webhook_digest() -> String {
    crate::digest(SLACK_WEBHOOK_URL.as_bytes())
        .trim_start_matches("sha256:")
        .into()
}

pub const SLACK_WORLD: &str = world_of(Provider::Slack);
pub const SNOWFLAKE_WORLD: &str = world_of(Provider::Snowflake);
pub const OPENAI_WORLD: &str = world_of(Provider::OpenAi);
pub const OBJECT_STORE_WORLD: &str = world_of(Provider::ObjectStore);
pub const LINEAR_WORK_WORLD: &str = world_of(Provider::LinearWork);
pub const GITEA_ACTIONS_WORLD: &str = world_of(Provider::GiteaActions);
pub const GITHUB_ACTIONS_WORLD: &str = world_of(Provider::GitHubActions);
pub const DELEGATION_WORLD: &str = world_of(Provider::LocalDelegation);
/// Shared with explicitly seeded synthetic captures: one provider, one world
/// file. The wire world occupies its own `simulated_provider` table.
pub const CARTA_WORLD: &str = world_of(Provider::Carta);
pub const GOOGLE_WORKSPACE_WORLD: &str = world_of(Provider::GoogleWorkspace);

const fn world_of(provider: Provider) -> &'static str {
    match provider.world() {
        Some(world) => world,
        // Unreachable once the mandate holds; a provider served by this module
        // with no declared world is a compile error rather than a runtime path.
        None => panic!("a simulated provider must declare its world in the registry"),
    }
}

/// A provider-shaped failure a scenario can schedule. Every `AdapterError` an
/// adapter can classify is reachable from this set, so the coverage gate has a
/// way to exercise each one without patching the adapter under test.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SimulatedFault {
    /// HTTP 429. Classified as `RateLimited`.
    RateLimited,
    /// HTTP 403. Classified as `ProviderDenied`.
    Denied,
    /// HTTP 400: the provider refused the request as malformed.
    BadRequest,
    /// HTTP 403 for a rate or quota limit, as Google reports
    /// `rateLimitExceeded` with a 403 rather than a 429.
    RateLimitForbidden,
    /// HTTP 404 for something the same client was just shown: a Meet
    /// conference record deleted between its listing and a read of its
    /// artifacts, or a Directory user deleted since Home last read them.
    Gone,
    /// The request is served and lands, and its reply is dropped: a write
    /// takes effect and its caller cannot know it. Google Workspace only;
    /// elsewhere it is a lost connection.
    ReplyLost,
    /// HTTP 409. In Google Workspace the request is served first and then
    /// answered as a conflict, as when a concurrent writer made the same
    /// change; elsewhere a plain 409.
    Conflict,
    /// HTTP 500. Classified as `Incomplete`, and leaves a write outcome unknown.
    ServerError,
    /// The response never arrives. Dispatched, so a write outcome is unknown.
    ConnectionLost,
    /// A body past the admitted response budget. Classified as `ResponseTooLarge`.
    Oversized,
    /// HTTP 200 that is not JSON. Classified as `ResponseInvalid`.
    NotJson,
    /// A provider-level rejection inside a 200 body, distinct from an HTTP error.
    /// Slack's `ok:false` shape; the adapter must still call this `ProviderDenied`.
    Rejected,
    /// A result the provider reports as split across partitions. Snowflake only.
    /// Classified as `Incomplete`; the adapter must not follow the partitions.
    Partitioned,
    /// Usage past the admitted ceiling. OpenAI only, classified `ResponseInvalid`.
    TokenOverrun,
    /// A model refusal inside an otherwise well-formed response. OpenAI only.
    Refused,
}

/// A fault queued against one endpoint. An empty `endpoint` matches any request
/// to that provider, including Slack's identity preflight.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScheduledFault {
    #[serde(default)]
    pub endpoint: String,
    pub remaining: u32,
    pub fault: SimulatedFault,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SlackMessage {
    pub text: String,
    pub timestamp: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SlackChannelWorld {
    pub messages: Vec<SlackMessage>,
    #[serde(default)]
    pub archived: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SlackWorld {
    pub workspace_id: String,
    pub channels: BTreeMap<String, SlackChannelWorld>,
    /// Drives message timestamps. Persisted so identifiers stay unique and
    /// reproducible across a host restart, as a real workspace's would.
    #[serde(default)]
    pub sequence: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnowflakeViewWorld {
    pub columns: Vec<String>,
    /// A null cell is `None`; Snowflake reports every non-null cell as text.
    pub rows: Vec<Vec<Option<String>>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnowflakeWorld {
    pub account: String,
    /// Keyed `DATABASE.SCHEMA.VIEW`, matching the identifiers the adapter quotes.
    pub views: BTreeMap<String, SnowflakeViewWorld>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpenAiWorld {
    pub project_id: String,
    #[serde(default)]
    pub organization_id: Option<String>,
    pub model: String,
    /// The ceiling the simulated account reports input usage against, so a
    /// generated response stays inside the reviewed profile's admitted limits.
    pub max_input_tokens: u64,
}

/// Google Directory wire responses committed by the offline provider. Keeping
/// the response bodies in the provider world lets native capture exercise the
/// same strict DTO parser and attribution checks as the live adapter.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceDirectoryWorld {
    /// Provider tenant independent of whether any user lookup is configured.
    pub customer_id: String,
    pub users: BTreeMap<String, Value>,
    pub hierarchy: Value,
}

/// Carta issuer API wire bodies committed by the offline provider. Pages are
/// verbatim provider responses, so a simulated capture runs the live DTO parser,
/// pagination, token validation and failure classification. A continuation
/// token selects the page after the first page that returned it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CartaWireWorld {
    pub issuer_id: String,
    /// The token endpoint's response body. Page requests must present its
    /// `access_token` as their bearer.
    pub token: Value,
    pub stakeholder_pages: Vec<Value>,
    pub grant_pages: Vec<Value>,
}

/// One Google Workspace organization, answering the requests the native port
/// sends: workload metadata, IAM, the token endpoint and the Directory routes.
/// Later actions add calendars, conferences and Drive files beside these fields
/// without restructuring them; every request is served from this one world.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GoogleWorkspaceWorld {
    /// The organization's primary domain. Its people are `users`.
    pub domain: String,
    /// The one service account this world's IAM mints tokens for. Any other is
    /// refused, as Google refuses a caller without token-creator on it.
    pub service_account: String,
    /// The scopes the service account's client is authorized for, domain-wide.
    pub delegated_scopes: BTreeSet<String>,
    /// The service account holds an admin role that reads groups and members.
    pub directory_reader: bool,
    /// People, by primary address. Only these can be a delegated subject.
    pub users: BTreeSet<String>,
    /// Groups, by primary address.
    pub groups: BTreeMap<String, GoogleGroup>,
    /// Calendars, by ID. Who can see one is its ACL, as in Google: any rule
    /// that applies to the delegated subject (its own, a group's, its
    /// domain's or the default) with `reader` or more; otherwise not found.
    #[serde(default)]
    pub calendars: BTreeMap<String, GoogleCalendar>,
    /// People who exist but cannot be delegated to, such as suspended
    /// accounts: the token endpoint refuses them as it refuses a stranger.
    #[serde(default)]
    pub suspended: BTreeSet<String>,
    /// Meet spaces, by ID: the meeting code that names each, and its owner.
    #[serde(default)]
    pub spaces: BTreeMap<String, GoogleSpace>,
    /// Conference records, by ID. A rejoin is another record in the same
    /// space. Only the space's owner can list them.
    #[serde(default)]
    pub conference_records: BTreeMap<String, GoogleConferenceRecord>,
    /// Drive files Meet generated, by ID. Step 4 adds their permissions.
    #[serde(default)]
    pub drive_files: BTreeMap<String, GoogleDriveFile>,
    /// How many records each conference-record page holds, in order, where
    /// Meet serves it short: fewer than asked or none at all, still with a
    /// continuation while records remain, as AIP-158 allows. Later pages are
    /// full.
    #[serde(default)]
    pub meet_record_pages: Vec<usize>,
    /// The domains Drive lets the organization share with, when its policy
    /// restricts sharing; empty is unrestricted. Sharing outside them is
    /// refused as an invalid sharing request.
    #[serde(default)]
    pub drive_trusted_domains: BTreeSet<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GoogleSpace {
    pub meeting_code: String,
    /// The person who owns the space and its conference records.
    pub owner: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GoogleConferenceRecord {
    /// The space's ID.
    pub space: String,
    /// Meet timestamps: UTC with `Z`, optionally fractional.
    pub start_time: String,
    /// Unset while the conference is ongoing.
    #[serde(default)]
    pub end_time: Option<String>,
    #[serde(default)]
    pub recordings: Vec<GoogleArtifact>,
    #[serde(default)]
    pub smart_notes: Vec<GoogleArtifact>,
    #[serde(default)]
    pub transcripts: Vec<GoogleArtifact>,
}

/// A recording, smart note or transcript. It advances `STARTED` → `ENDED` →
/// `FILE_GENERATED`, and generating it saves its Drive file or Docs document.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GoogleArtifact {
    pub id: String,
    pub state: String,
    /// The Drive file or Docs document ID, once Meet has saved one.
    #[serde(default)]
    pub file: Option<String>,
}

/// A file Meet saved. Only its owner can list or change its permissions:
/// `writersCanShare` is not modelled.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GoogleDriveFile {
    pub name: String,
    pub mime_type: String,
    pub owner: String,
    /// In the order Drive lists them; the owner's own comes first.
    #[serde(default)]
    pub permissions: Vec<GoogleDrivePermission>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GoogleDrivePermission {
    pub id: String,
    /// `user`, `group`, `domain` or `anyone`.
    pub kind: String,
    pub role: String,
    #[serde(default)]
    pub email_address: Option<String>,
    #[serde(default)]
    pub deleted: bool,
    /// Who created it, for a campaign's invariants. Never on the wire.
    #[serde(default)]
    pub created_by: Option<String>,
}

impl GoogleDrivePermission {
    /// The owner's own permission, as Drive lists it on every file.
    pub fn owner(owner: &str) -> Self {
        Self {
            id: format!("owner{}", &crate::digest(owner.as_bytes())[7..23]),
            kind: "user".into(),
            role: "owner".into(),
            email_address: Some(owner.into()),
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GoogleCalendar {
    pub summary: String,
    /// In Google's order: the order ACL pages report it.
    pub acl: Vec<GoogleAclRule>,
    /// Single events, as `singleEvents=true` expands them: a recurring
    /// instance has an `original_start` and its own ID.
    pub events: Vec<GoogleEvent>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GoogleAclRule {
    /// `user`, `group`, `domain` or `default`.
    pub scope_type: String,
    /// Absent for `default`.
    #[serde(default)]
    pub scope_value: Option<String>,
    /// `none`, `freeBusyReader`, `reader`, `writer` or `owner`.
    pub role: String,
}

/// An event time: `date_time` for a timed event, `date` for an all-day one.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GoogleTime {
    #[serde(default)]
    pub date_time: Option<String>,
    #[serde(default)]
    pub date: Option<String>,
}

impl GoogleTime {
    pub fn at(date_time: &str) -> Self {
        Self {
            date_time: Some(date_time.into()),
            date: None,
        }
    }

    pub fn day(date: &str) -> Self {
        Self {
            date_time: None,
            date: Some(date.into()),
        }
    }

    /// Seconds since the epoch; an all-day date is its UTC midnight.
    fn seconds(&self) -> Option<i64> {
        use crate::google_workspace_calendar::{date_days, rfc3339_seconds};
        match (&self.date_time, &self.date) {
            (Some(value), None) => rfc3339_seconds(value),
            (None, Some(date)) => date_days(date).map(|days| days * 86_400),
            _ => None,
        }
    }

    fn wire(&self) -> Value {
        match (&self.date_time, &self.date) {
            (Some(value), _) => json!({"dateTime":value,"timeZone":"UTC"}),
            (None, Some(date)) => json!({ "date": date }),
            (None, None) => json!({}),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GoogleEvent {
    pub id: String,
    /// `confirmed`, `tentative` or `cancelled`.
    pub status: String,
    /// Absent is Google's `default`, which it does not report.
    #[serde(default)]
    pub visibility: Option<String>,
    /// Absent only on a cancelled instance Google reports by id alone.
    #[serde(default)]
    pub start: Option<GoogleTime>,
    #[serde(default)]
    pub end: Option<GoogleTime>,
    #[serde(default)]
    pub original_start: Option<GoogleTime>,
    #[serde(default)]
    pub organizer: Option<String>,
    #[serde(default)]
    pub creator: Option<String>,
    #[serde(default)]
    pub conference_id: Option<String>,
    /// The conference solution's key type: `hangoutsMeet` for Google Meet.
    #[serde(default)]
    pub conference_type: Option<String>,
    #[serde(default)]
    pub hangout_link: Option<String>,
}

impl GoogleEvent {
    /// The item Google reports under the reviewed fields mask.
    fn wire(&self) -> Value {
        let mut item = serde_json::Map::new();
        item.insert("id".into(), json!(self.id));
        item.insert("status".into(), json!(self.status));
        if let Some(visibility) = &self.visibility {
            item.insert("visibility".into(), json!(visibility));
        }
        for (name, time) in [
            ("start", &self.start),
            ("end", &self.end),
            ("originalStartTime", &self.original_start),
        ] {
            if let Some(time) = time {
                item.insert(name.into(), time.wire());
            }
        }
        for (name, email) in [("creator", &self.creator), ("organizer", &self.organizer)] {
            if let Some(email) = email {
                item.insert(name.into(), json!({ "email": email }));
            }
        }
        if let Some(conference) = &self.conference_id {
            let mut data = json!({ "conferenceId": conference });
            if let Some(kind) = &self.conference_type {
                data["conferenceSolution"] = json!({"key":{"type":kind}});
            }
            item.insert("conferenceData".into(), data);
        }
        if let Some(link) = &self.hangout_link {
            item.insert("hangoutLink".into(), json!(link));
        }
        Value::Object(item)
    }

    /// The span `timeMin`/`timeMax` compare: its start and end, or for an
    /// instance reported by id alone, its original start.
    fn span(&self) -> Option<(i64, i64)> {
        match (&self.start, &self.end) {
            (Some(start), Some(end)) => Some((start.seconds()?, end.seconds()?)),
            _ => {
                let original = self.original_start.as_ref()?.seconds()?;
                Some((original, original + 1))
            }
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GoogleGroup {
    pub id: String,
    pub name: String,
    /// People or other groups, by primary address. Membership is transitive.
    pub members: BTreeSet<String>,
    /// Other addresses that also name this group. A lookup by alias answers
    /// with the primary address, which may be in another domain.
    #[serde(default)]
    pub aliases: BTreeSet<String>,
}

/// One stored object, as the store reports it.
///
/// No bytes. An application never holds an object's contents: it asks for an
/// authorization and a client transfers directly to the store, so a 300-MiB video
/// never meets a 64-KiB observation and an application that cannot hold the bytes
/// cannot leak them. The simulation models exactly what the platform can observe.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoredObject {
    pub size: u64,
    pub etag: String,
    #[serde(default)]
    pub content_type: String,
}

/// Any S3-compatible store. The instance picks the vendor by endpoint; this world
/// models the protocol they share, and the parity gate holds each vendor to its
/// own recorded base where they differ.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObjectStoreWorld {
    pub bucket: String,
    /// Keyed by object key, as the store keys them.
    pub objects: BTreeMap<String, StoredObject>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct World<W> {
    pub world: W,
    #[serde(default)]
    pub faults: Vec<ScheduledFault>,
    /// Every request served, in order. The campaign diffs this like any other
    /// provider state; it is also what proves a simulation is input-sensitive.
    #[serde(default)]
    pub calls: Vec<String>,
}

/// One tracked issue, as Linear reports it through a view or a label.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinearIssue {
    pub id: String,
    pub identifier: String,
    pub title: String,
    pub url: String,
    /// `YYYY-MM-DD`, or empty when the issue carries no due date. Empty is a
    /// compliance fact here rather than a missing field: an issue without a due
    /// date is exactly what one of the policies looks for.
    #[serde(default)]
    pub due_date: String,
    #[serde(default)]
    pub state_name: String,
    /// `started`, `completed`, `canceled` — what decides whether an issue is
    /// still active work.
    #[serde(default)]
    pub state_type: String,
    #[serde(default)]
    pub assignee_id: String,
    #[serde(default)]
    pub assignee_name: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub labels: Vec<String>,
    /// Which view ids this issue appears in, so one issue can be reachable
    /// through several grants — the duplication the queue has to collapse.
    #[serde(default)]
    pub view_ids: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinearMember {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub email: String,
}

/// A Linear workspace's tracked work, as this platform can observe it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinearWorkWorld {
    #[serde(default)]
    pub team_name: String,
    #[serde(default)]
    pub issues: Vec<LinearIssue>,
    #[serde(default)]
    pub members: Vec<LinearMember>,
}

/// One CI job, as GitHub reports it.
///
/// No log bytes. A build log is unbounded and the platform never carries one —
/// it hands back the signed URL GitHub redirects to — so the world models the
/// redirect, not the content.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GitHubJob {
    pub id: String,
    pub name: String,
    /// `queued`, `in_progress`, `completed`, and whatever GitHub adds next.
    pub status: String,
    #[serde(default)]
    pub conclusion: String,
    #[serde(default)]
    pub started_at: String,
    #[serde(default)]
    pub completed_at: String,
    /// Where a log request redirects, or empty when there is no log.
    #[serde(default)]
    pub log_url: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GitHubActionsWorld {
    pub owner: String,
    pub repo: String,
    #[serde(default)]
    pub jobs: Vec<GitHubJob>,
}

/// Provider-shaped wire fixtures, keyed by the exact API path and query.
/// Missing routes return 404; the simulation never invents an empty success.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GiteaActionsWorld {
    pub origin: String,
    pub responses: BTreeMap<String, Value>,
    pub logs: BTreeMap<String, String>,
}

/// Explicit synthetic Actions data for development and provider parity campaigns.
pub fn gitea_actions_fixture(owner: &str, repo: &str, outcome: &str) -> GiteaActionsWorld {
    let origin = "https://git.example.test";
    let base = format!("{origin}/api/v1/repos/{owner}/{repo}/actions");
    let run = json!({
        "id":7,"run_attempt":1,"url":format!("{base}/runs/7"),
        "display_title":"Deploy example","path":"deploy.yml@refs/heads/main",
        "event":"push","head_branch":"main","head_sha":"abc123",
        "status":"completed","conclusion":outcome,
        "started_at":"2026-01-02T11:00:00Z","completed_at":"2026-01-02T11:10:00Z",
        "html_url":format!("{origin}/{owner}/{repo}/actions/runs/7")
    });
    let job = json!({
        "id":7,"run_id":7,"run_attempt":1,"url":format!("{base}/jobs/7"),
        "name":"Deploy example","status":"completed","conclusion":outcome,
        "created_at":"2026-01-02T10:59:00Z","started_at":"2026-01-02T11:00:00Z",
        "completed_at":"2026-01-02T11:10:00Z","runner_id":1,"runner_name":"runner-example",
        "labels":["linux"],"html_url":format!("{origin}/{owner}/{repo}/actions/runs/7/jobs/7")
    });
    let runner = json!({"id":1,"name":format!("runner-{outcome}"),"status":"online",
        "busy":false,"disabled":false,"ephemeral":false,"labels":[{"name":"linux"}]});
    let mut responses = BTreeMap::from([
        (
            format!("/api/v1/repos/{owner}/{repo}/actions/jobs/7"),
            job.clone(),
        ),
        (
            format!("/api/v1/repos/{owner}/{repo}/actions/runs/7"),
            run.clone(),
        ),
        (
            format!("/api/v1/repos/{owner}/{repo}/actions/runs/7/attempts/1"),
            run.clone(),
        ),
        (
            format!("/api/v1/orgs/{owner}/actions/runners"),
            json!({"runners":[runner],"total_count":1}),
        ),
    ]);
    for limit in [5, 10, 20, 50] {
        for page in 1..=3 {
            responses.insert(format!("/api/v1/orgs/{owner}/actions/runs?page={page}&limit={limit}"),
                json!({"workflow_runs":if page == 1 { vec![run.clone()] } else { vec![] },"total_count":1}));
            responses.insert(
                format!(
                    "/api/v1/repos/{owner}/{repo}/actions/runs/7/jobs?page={page}&limit={limit}"
                ),
                json!({"jobs":if page == 1 { vec![job.clone()] } else { vec![] },"total_count":1}),
            );
            responses.insert(format!("/api/v1/repos/{owner}/{repo}/actions/runs/7/attempts/1/jobs?page={page}&limit={limit}"),
                json!({"jobs":if page == 1 { vec![job.clone()] } else { vec![] },"total_count":1}));
            for status in ["queued", "pending", "in_progress"] {
                responses.insert(format!("/api/v1/orgs/{owner}/actions/runs?page={page}&limit={limit}&status={status}"),
                    json!({"workflow_runs":[],"total_count":0}));
            }
        }
    }
    GiteaActionsWorld {
        origin: origin.into(),
        responses,
        logs: BTreeMap::from([(
            format!("/api/v1/repos/{owner}/{repo}/actions/jobs/7/logs"),
            format!("Build finished: {outcome}"),
        )]),
    }
}

pub fn gitea_development_fixture() -> GiteaActionsWorld {
    let mut world = gitea_actions_fixture("synthetic-org", "synthetic-repo", "failure");
    let other = gitea_actions_fixture("synthetic-tools", "synthetic-repo", "success");
    world.logs.insert(
        "/api/v1/repos/synthetic-org/synthetic-repo/actions/jobs/7/logs".into(),
        "The runner has received a shutdown signal".into(),
    );
    world.responses.extend(other.responses);
    world.logs.extend(other.logs);
    world
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SlackWebhookWorld {
    pub endpoint_sha256: String,
    pub messages: Vec<String>,
    pub archived: bool,
}

pub fn slack_webhook_fixture() -> SlackWebhookWorld {
    SlackWebhookWorld {
        endpoint_sha256: slack_webhook_digest(),
        messages: vec![],
        archived: false,
    }
}

/// The offline fixture a scenario seeds. Seeding is explicit: an unconfigured
/// world reports the provider as unreachable rather than inventing a reply.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimulatedFixture {
    #[serde(default)]
    pub slack_webhook: SlackWebhookWorld,
    pub delegation: DelegationWorld,
    pub github_actions: GitHubActionsWorld,
    #[serde(default)]
    pub gitea_actions: GiteaActionsWorld,
    pub linear_work: LinearWorkWorld,
    pub object_store: ObjectStoreWorld,
    pub slack: SlackWorld,
    pub snowflake: SnowflakeWorld,
    pub openai: OpenAiWorld,
    pub workspace_directory: WorkspaceDirectoryWorld,
    /// Absent leaves the Carta world unseeded, so an explicitly synthetic
    /// Carta store stays the only Carta state a campaign has.
    #[serde(default)]
    pub carta: Option<CartaWireWorld>,
    /// Absent seeds an empty organization: every request then fails as Google
    /// fails for an unknown account, never falling through to the network.
    #[serde(default)]
    pub google_workspace: GoogleWorkspaceWorld,
}

/// What another application answers, for a campaign that is not running it.
///
/// Keyed by the operation and the exact request, because a simulation that
/// returned the same answer whatever it was asked would let a caller's logic
/// pass against a callee it never consulted. A missing key is a refusal rather
/// than an empty answer, for the same reason.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DelegationWorld {
    #[serde(default)]
    pub reads: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub accepted: std::collections::BTreeMap<String, String>,
}

impl DelegationWorld {
    /// The key one delegated read is recorded under.
    pub fn key(app: &str, operation: &str, request: &str) -> String {
        format!("{app}\u{1f}{operation}\u{1f}{request}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Endpoint {
    SlackWebhook,
    SlackIdentity,
    SlackHistory,
    SlackPost,
    SnowflakeStatement,
    OpenAiResponses,
    LinearGraphQL,
    GiteaActions,
    GitHubJobStatus,
    GitHubJobLogs,
    /// Any S3-compatible store. One endpoint rather than one per vendor: the
    /// whole premise of the object-store provider is that the protocol is shared
    /// and the instance picks the vendor.
    ObjectStore,
}

impl Endpoint {
    fn classify(url: &str) -> Option<Self> {
        let path = url.split_once('?').map_or(url, |(base, _)| base);
        Some(match path {
            SLACK_WEBHOOK_URL => Self::SlackWebhook,
            _ if path == slack::IDENTITY => Self::SlackIdentity,
            _ if path == slack::HISTORY => Self::SlackHistory,
            _ if path == slack::POST => Self::SlackPost,
            "https://api.openai.com/v1/responses" => Self::OpenAiResponses,
            _ if path == super::linear_work::GRAPHQL => Self::LinearGraphQL,
            other if other.contains("/api/v1/") && other.contains("/actions/") => {
                Self::GiteaActions
            }
            // Logs first: the log path is the job path with a suffix, so
            // matching the shorter one first would swallow it.
            other if other.contains("/actions/jobs/") && other.ends_with("/logs") => {
                Self::GitHubJobLogs
            }
            other if other.contains("/actions/jobs/") => Self::GitHubJobStatus,
            // A presigned S3 request is recognised by its signature, which every
            // compatible vendor carries and nothing else here does. Matching on the
            // host would mean enumerating vendors, which is exactly the coupling the
            // generic interface exists to avoid.
            _ if url.contains("X-Amz-Signature=") => Self::ObjectStore,
            other
                if other.starts_with("https://")
                    && other.ends_with(".snowflakecomputing.com/api/v2/statements") =>
            {
                Self::SnowflakeStatement
            }
            _ => return None,
        })
    }

    fn world(self) -> &'static str {
        match self {
            Self::SlackWebhook => SLACK_WEBHOOK_WORLD,
            Self::SlackIdentity | Self::SlackHistory | Self::SlackPost => SLACK_WORLD,
            Self::SnowflakeStatement => SNOWFLAKE_WORLD,
            Self::OpenAiResponses => OPENAI_WORLD,
            Self::ObjectStore => OBJECT_STORE_WORLD,
            Self::LinearGraphQL => LINEAR_WORK_WORLD,
            Self::GitHubJobStatus | Self::GitHubJobLogs => GITHUB_ACTIONS_WORLD,
            Self::GiteaActions => GITEA_ACTIONS_WORLD,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::SlackWebhook => "incoming-webhook",
            Self::SlackIdentity => "auth.test",
            Self::SlackHistory => "conversations.history",
            Self::SlackPost => "chat.postMessage",
            Self::SnowflakeStatement => "statements",
            Self::OpenAiResponses => "responses",
            Self::ObjectStore => "object",
            Self::LinearGraphQL => "graphql",
            Self::GiteaActions => "gitea-actions",
            Self::GitHubJobStatus => "job",
            Self::GitHubJobLogs => "job-logs",
        }
    }
}

/// Resolves a fixed offline credential. A simulated run needs no mounted secret;
/// `available` false makes the `CredentialUnavailable` path reachable offline.
pub(crate) struct SimulatedCredentials {
    available: bool,
}

impl SimulatedCredentials {
    pub(crate) fn new(available: bool) -> Self {
        Self { available }
    }
}

impl CredentialResolver for SimulatedCredentials {
    fn resolve(&self, connection: &LiveConnection) -> Result<Credentials, AdapterError> {
        connection
            .validate()
            .map_err(|_| AdapterError::InvalidProfile)?;
        // Carta's client secret is never a bearer, offline or live.
        if !self.available || matches!(connection, LiveConnection::Carta { .. }) {
            return Err(AdapterError::CredentialUnavailable);
        }
        Credentials::bearer(
            if matches!(connection, LiveConnection::SlackWebhook { .. }) {
                SLACK_WEBHOOK_URL.into()
            } else {
                "simulated-offline-credential".into()
            },
        )
    }
}

/// Serves the three live adapters from committed offline worlds.
pub(crate) struct SimulatedTransport {
    database: PathBuf,
    scope: String,
    /// An internal world failure surfaces to the adapter as an unreachable
    /// provider, which is a real offline state. The detail is kept here so a
    /// misconfigured fixture is still diagnosable instead of silently passing.
    fault_detail: Mutex<Vec<String>>,
}

impl SimulatedTransport {
    /// `database` is the app database; worlds live beside it, as the synthetic
    /// People stores do.
    pub(crate) fn new(database: &Path, scope: &str) -> Self {
        Self {
            database: database.to_path_buf(),
            scope: scope.to_owned(),
            fault_detail: Mutex::new(Vec::new()),
        }
    }

    #[cfg(test)]
    pub(crate) fn detail(&self) -> Vec<String> {
        self.fault_detail.lock().unwrap().clone()
    }

    fn path(&self, world: &str) -> PathBuf {
        self.database.with_file_name(world)
    }
}

fn upgrade(connection: &rusqlite::Connection) -> Result<()> {
    connection.execute_batch("CREATE TABLE IF NOT EXISTS simulated_provider (scope TEXT NOT NULL PRIMARY KEY, state TEXT NOT NULL) STRICT;")?;
    Ok(())
}

/// Install a provider world. Explicit setup only: an already-configured world is
/// never silently reset, matching `people_providers::seed_synthetic`.
pub fn seed(database: &Path, scope: &str, fixture: &SimulatedFixture) -> Result<()> {
    ensure!(
        !fixture.slack.workspace_id.is_empty()
            && !fixture.snowflake.account.is_empty()
            && !fixture.openai.model.is_empty()
            && !fixture.openai.project_id.is_empty()
            && fixture.openai.max_input_tokens > 0,
        "simulated_fixture_incomplete"
    );
    seed_world(database, scope, OBJECT_STORE_WORLD, &fixture.object_store)?;
    seed_world(database, scope, LINEAR_WORK_WORLD, &fixture.linear_work)?;
    seed_world(
        database,
        scope,
        GITHUB_ACTIONS_WORLD,
        &fixture.github_actions,
    )?;
    seed_world(database, scope, GITEA_ACTIONS_WORLD, &fixture.gitea_actions)?;
    seed_world(database, scope, SLACK_WEBHOOK_WORLD, &fixture.slack_webhook)?;
    seed_world(database, scope, SLACK_WORLD, &fixture.slack)?;
    seed_world(database, scope, SNOWFLAKE_WORLD, &fixture.snowflake)?;
    seed_world(database, scope, OPENAI_WORLD, &fixture.openai)?;
    seed_world(database, scope, DELEGATION_WORLD, &fixture.delegation)?;
    if let Some(carta) = &fixture.carta {
        seed_world(database, scope, CARTA_WORLD, carta)?;
    }
    seed_world(
        database,
        scope,
        crate::simulations::simulation(Provider::WorkspaceDirectory),
        &fixture.workspace_directory,
    )?;
    seed_world(
        database,
        scope,
        GOOGLE_WORKSPACE_WORLD,
        &fixture.google_workspace,
    )?;
    // The executor simulation is deterministic from its sealed request and needs
    // no scenario payload. Provision its declared database through the same
    // explicit fixture path as the other simulated providers; this also ensures
    // its world file exists before the runtime opens it for the first call.
    seed_world(
        database,
        scope,
        crate::simulations::simulation(Provider::FreetoolExecutor),
        &json!({"service": "freetool_executor", "version": 1}),
    )
}

/// The answer this campaign recorded for one delegated read.
pub fn delegated_read(
    database: &Path,
    scope: &str,
    app: &str,
    operation: &str,
    request: &str,
) -> Result<String> {
    with_world(
        &database.with_file_name(DELEGATION_WORLD),
        scope,
        |world: &mut World<DelegationWorld>| {
            let key = DelegationWorld::key(app, operation, request);
            world.calls.push(key.clone());
            world
                .world
                .reads
                .get(&key)
                .cloned()
                .with_context(|| format!("delegated_read_not_recorded: {app} {operation}"))
        },
    )
}

/// Disposable effect model only: acceptance is not receiver business success.
pub fn delegated_send(
    database: &Path,
    scope: &str,
    call: &crate::delegation::Call,
) -> Result<String> {
    with_world(
        &database.with_file_name(DELEGATION_WORLD),
        scope,
        |world: &mut World<DelegationWorld>| {
            let id = format!(
                "rcp_{}",
                &crate::digest(&serde_json::to_vec(&(
                    scope,
                    &call.source_epoch,
                    &call.origin,
                    &call.step,
                    &call.app
                ))?)[7..]
            );
            let fingerprint = crate::digest(&serde_json::to_vec(call)?);
            if let Some(recorded) = world.world.accepted.get(&id) {
                ensure!(recorded == &fingerprint, "simulated_app_identity_conflict")
            } else {
                world.world.accepted.insert(id.clone(), fingerprint);
            }
            world.calls.push(id.clone());
            Ok(serde_json::json!({"id":id,"status":"accepted"}).to_string())
        },
    )
}

pub fn delegated_status(
    database: &Path,
    scope: &str,
    call: &crate::delegation::Call,
) -> Result<String> {
    with_world(
        &database.with_file_name(DELEGATION_WORLD),
        scope,
        |world: &mut World<DelegationWorld>| {
            let input: serde_json::Value = crate::json::decode(call.input.as_bytes())?;
            let id = input["id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("invalid_app_receipt"))?;
            let status = if world.world.accepted.contains_key(id) {
                "pending"
            } else {
                "unknown"
            };
            world.calls.push(id.to_owned());
            Ok(serde_json::json!({"id":id,"status":status,"output":""}).to_string())
        },
    )
}

fn seed_world<W: Serialize>(database: &Path, scope: &str, world: &str, value: &W) -> Result<()> {
    let mut connection = crate::store::open(&database.with_file_name(world))?;
    let tx = crate::write_queue::immediate(&mut connection)?;
    upgrade(&tx)?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM simulated_provider WHERE scope=?1)",
        [scope],
        |row| row.get(0),
    )?;
    ensure!(!exists, "simulated_provider_already_seeded");
    write_world(
        &tx,
        scope,
        &World {
            world: value,
            faults: Vec::new(),
            calls: Vec::new(),
        },
    )?;
    tx.commit()?;
    Ok(())
}

/// Queue provider failures against an already-seeded world.
pub fn schedule_faults(
    database: &Path,
    scope: &str,
    world: &str,
    faults: Vec<ScheduledFault>,
) -> Result<()> {
    ensure!(faults.len() <= MAX_FAULTS, "simulated_fault_budget");
    with_world::<Value, _, _>(&database.with_file_name(world), scope, |state| {
        state.faults.extend(faults);
        ensure!(state.faults.len() <= MAX_FAULTS, "simulated_fault_budget");
        Ok(())
    })
}

/// A provider's world belongs to the provider, not to a direction of travel.
/// These commit to the same store the transport serves from, so a writer that is
/// not the outbound adapter — a delivered webhook, an operator correction — can
/// change what a later read observes. Each function pins one world file to its
/// one world type, so a caller cannot commit the wrong shape to a store.
/// Write into the simulated object store, as a client completing a transfer would.
///
/// The platform never carries the bytes, so nothing in production writes an object
/// here: a real upload happens between the client and the store. This is how a
/// scenario expresses "the client finished uploading".
pub fn update_object_store<T>(
    database: &Path,
    scope: &str,
    act: impl FnOnce(&mut World<ObjectStoreWorld>) -> Result<T>,
) -> Result<T> {
    with_world(&database.with_file_name(OBJECT_STORE_WORLD), scope, act)
}

pub fn update_slack<T>(
    database: &Path,
    scope: &str,
    act: impl FnOnce(&mut World<SlackWorld>) -> Result<T>,
) -> Result<T> {
    with_world(&database.with_file_name(SLACK_WORLD), scope, act)
}

pub fn update_snowflake<T>(
    database: &Path,
    scope: &str,
    act: impl FnOnce(&mut World<SnowflakeWorld>) -> Result<T>,
) -> Result<T> {
    with_world(&database.with_file_name(SNOWFLAKE_WORLD), scope, act)
}

pub fn update_openai<T>(
    database: &Path,
    scope: &str,
    act: impl FnOnce(&mut World<OpenAiWorld>) -> Result<T>,
) -> Result<T> {
    with_world(&database.with_file_name(OPENAI_WORLD), scope, act)
}

fn read_world<W: serde::de::DeserializeOwned>(
    connection: &rusqlite::Connection,
    scope: &str,
) -> Result<World<W>> {
    let encoded: Option<String> = connection
        .query_row(
            "SELECT state FROM simulated_provider WHERE scope=?1",
            [scope],
            |row| row.get(0),
        )
        .optional()?;
    let encoded = encoded.context("simulated_provider_unconfigured")?;
    ensure!(
        encoded.len() <= MAX_WORLD_BYTES,
        "simulated_provider_world_budget"
    );
    crate::json::decode(encoded.as_bytes())
}

/// Validate a selected world without making a provider request. This cannot
/// establish membership; only the user endpoint can do that.
pub(crate) fn workspace_directory_check(
    database: &Path,
    scope: &str,
    customer_id: &str,
) -> Result<()> {
    let path =
        database.with_file_name(crate::simulations::simulation(Provider::WorkspaceDirectory));
    ensure!(path.is_file(), "simulated_provider_unconfigured");
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let state: World<WorkspaceDirectoryWorld> = read_world(&connection, scope)?;
    ensure!(
        state.world.customer_id == customer_id,
        "workspace_directory_customer_mismatch"
    );
    Ok(())
}

pub const DIRECTORY_USER_ENDPOINT: &str = "workspace_directory.users.get";
pub const DIRECTORY_HIERARCHY_ENDPOINT: &str = "workspace_directory.orgunits.list";

pub(crate) enum DirectoryRead<'a> {
    User(&'a str),
    Hierarchy,
}

/// Provider source state is independent of capture time and adapter caching.
/// Commit request/fault bookkeeping even when the request itself fails. A user
/// the world does not hold answers `None`, as the Directory's 404 does.
pub(crate) fn workspace_directory_read(
    database: &Path,
    scope: &str,
    customer_id: &str,
    read: DirectoryRead<'_>,
) -> Result<Option<Vec<u8>>> {
    let path =
        database.with_file_name(crate::simulations::simulation(Provider::WorkspaceDirectory));
    let (endpoint, max) = match read {
        DirectoryRead::User(_) => (
            DIRECTORY_USER_ENDPOINT,
            crate::workspace_directory::MAX_USER_RESPONSE_BYTES,
        ),
        DirectoryRead::Hierarchy => (
            DIRECTORY_HIERARCHY_ENDPOINT,
            crate::workspace_directory::MAX_RESPONSE_BYTES,
        ),
    };
    with_world::<WorkspaceDirectoryWorld, _, _>(&path, scope, |state| {
        ensure!(
            state.world.customer_id == customer_id,
            "workspace_directory_customer_mismatch"
        );
        ensure!(state.calls.len() < MAX_MESSAGES, "simulated_call_budget");
        state.calls.push(match read {
            DirectoryRead::User(actor) => format!("{endpoint}:{customer_id}:{actor}"),
            DirectoryRead::Hierarchy => format!("{endpoint}:{customer_id}"),
        });
        let fault = take_fault_named(state, endpoint);
        Ok((|| {
            if let Some(fault) = fault {
                let response = fault_response(fault, max as u64)
                    .context("workspace_directory_simulated_fault_unsupported")?
                    .map_err(|_| anyhow::anyhow!("workspace_directory_provider_unavailable"))?;
                // As natively: a user the provider says it does not have.
                if matches!(read, DirectoryRead::User(_)) && response.status == 404 {
                    return Ok(None);
                }
                ensure!(
                    (200..300).contains(&response.status),
                    "workspace_directory_provider_refused"
                );
                ensure!(
                    response.body.len() <= max,
                    "workspace_directory_response_too_large"
                );
                return Ok(Some(response.body));
            }
            let response = match read {
                DirectoryRead::User(actor) => match state.world.users.get(actor) {
                    Some(user) => user,
                    None => return Ok(None),
                },
                DirectoryRead::Hierarchy => &state.world.hierarchy,
            };
            let bytes = serde_json::to_vec(response)?;
            ensure!(bytes.len() <= max, "workspace_directory_response_too_large");
            Ok(Some(bytes))
        })())
    })?
}

/// Validate that a Carta wire world is seeded for this scope, without a request.
pub(crate) fn carta_check(database: &Path, scope: &str) -> Result<()> {
    let path = database.with_file_name(CARTA_WORLD);
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| anyhow::anyhow!("simulated_provider_unconfigured"))?;
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='simulated_provider')",
            [],
            |row| row.get(0),
        )?;
    ensure!(exists, "simulated_provider_unconfigured");
    let _: World<CartaWireWorld> = read_world(&connection, scope)?;
    Ok(())
}

pub const CARTA_TOKEN_ENDPOINT: &str = "carta.oauth.access_token";
pub const CARTA_STAKEHOLDERS_ENDPOINT: &str = "carta.issuers.stakeholders";
pub const CARTA_OPTION_GRANTS_ENDPOINT: &str = "carta.issuers.option_grants";

pub(crate) enum CartaRead<'a> {
    Token {
        form: &'a str,
    },
    Page {
        issuer_id: &'a str,
        collection: crate::carta_live::Collection,
        query: Option<&'a str>,
        bearer: &'a str,
    },
}

/// Serve one Carta exchange from the world, recording it and consuming a
/// scheduled fault. Statuses are provider-shaped; the live pipeline classifies
/// them. An unconfigured or broken world is an unreachable provider.
pub(crate) fn carta_read(
    database: &Path,
    scope: &str,
    read: CartaRead<'_>,
    max: usize,
) -> std::result::Result<crate::carta_live::Reply, crate::carta_live::TransportFailure> {
    use crate::carta_live::{Collection, Failure, Reply, TransportFailure};
    let status = |status: u16| Reply {
        status,
        json: true,
        body: json!({"error":"simulated"}).to_string().into_bytes(),
        retry_after_seconds: None,
    };
    let path = database.with_file_name(CARTA_WORLD);
    let served = with_world::<CartaWireWorld, _, _>(&path, scope, |state| {
        ensure!(state.calls.len() < MAX_MESSAGES, "simulated_call_budget");
        let endpoint = match &read {
            CartaRead::Token { .. } => CARTA_TOKEN_ENDPOINT,
            CartaRead::Page {
                collection: Collection::Stakeholders,
                ..
            } => CARTA_STAKEHOLDERS_ENDPOINT,
            CartaRead::Page {
                collection: Collection::OptionGrants,
                ..
            } => CARTA_OPTION_GRANTS_ENDPOINT,
        };
        state.calls.push(match &read {
            CartaRead::Token { .. } => endpoint.to_owned(),
            CartaRead::Page {
                issuer_id, query, ..
            } => format!("{endpoint}:{issuer_id}:{}", query.unwrap_or_default()),
        });
        if let Some(fault) = take_fault_named(state, endpoint) {
            return Ok(match fault_response(fault, max as u64) {
                None => Err(Failure::Unavailable.into()),
                // Whatever the shared fault consumed is carried, as on the wire.
                Some(Err(error)) => Err(TransportFailure {
                    failure: Failure::Unavailable,
                    response_bytes: error.response_bytes,
                    http_status: error.http_status,
                    retry_after_seconds: None,
                }),
                Some(Ok(response)) => Ok(Reply {
                    status: response.status,
                    json: response.json_content_type,
                    body: response.body,
                    retry_after_seconds: (fault == SimulatedFault::RateLimited).then_some(30),
                }),
            });
        }
        let reply = match read {
            CartaRead::Token { form } => {
                if form != crate::carta_live::token_form() {
                    status(400)
                } else {
                    Reply {
                        status: 200,
                        json: true,
                        body: serde_json::to_vec(&state.world.token)?,
                        retry_after_seconds: None,
                    }
                }
            }
            CartaRead::Page {
                issuer_id,
                collection,
                query,
                bearer,
            } => {
                let pages = match collection {
                    Collection::Stakeholders => &state.world.stakeholder_pages,
                    Collection::OptionGrants => &state.world.grant_pages,
                };
                let token = query.map(|query| {
                    let pairs: Vec<_> = url::form_urlencoded::parse(query.as_bytes())
                        .into_owned()
                        .collect();
                    match pairs.as_slice() {
                        [(name, token)] if name == "pageToken" => Some(token.clone()),
                        _ => None,
                    }
                });
                if state
                    .world
                    .token
                    .get("access_token")
                    .and_then(Value::as_str)
                    != Some(bearer)
                {
                    status(401)
                } else if issuer_id != state.world.issuer_id {
                    status(404)
                } else {
                    let index = match token {
                        None => Some(0),
                        Some(None) => None,
                        Some(Some(token)) => pages
                            .iter()
                            .position(|page| {
                                page.get("nextPageToken").and_then(Value::as_str)
                                    == Some(token.as_str())
                            })
                            .map(|index| index + 1),
                    };
                    match index.and_then(|index| pages.get(index)) {
                        Some(page) => Reply {
                            status: 200,
                            json: true,
                            body: serde_json::to_vec(page)?,
                            retry_after_seconds: None,
                        },
                        None => status(400),
                    }
                }
            }
        };
        Ok(Ok(reply))
    });
    match served {
        Ok(reply) => {
            let mut reply = reply?;
            // The wire never delivers more than the reader asked for plus the
            // probe byte that makes an oversized response observable.
            reply.body.truncate(max.saturating_add(1));
            Ok(reply)
        }
        Err(_) => Err(Failure::Unavailable.into()),
    }
}

/// Scenario changes affect later Carta requests through the same world.
pub fn update_carta<T>(
    database: &Path,
    scope: &str,
    act: impl FnOnce(&mut World<CartaWireWorld>) -> Result<T>,
) -> Result<T> {
    with_world(&database.with_file_name(CARTA_WORLD), scope, act)
}

/// Scenario changes affect later requests through the same provider world.
pub fn update_workspace_directory<T>(
    database: &Path,
    scope: &str,
    act: impl FnOnce(&mut World<WorkspaceDirectoryWorld>) -> Result<T>,
) -> Result<T> {
    with_world(
        &database.with_file_name(crate::simulations::simulation(Provider::WorkspaceDirectory)),
        scope,
        act,
    )
}

/// The service account and organization disposable campaigns use. Synthetic:
/// no such account or domain exists, and nothing here reaches Google.
pub const GOOGLE_DEVELOPMENT_SERVICE_ACCOUNT: &str =
    "workspace-reader@synthetic-project.iam.gserviceaccount.com";
pub const GOOGLE_DEVELOPMENT_CALENDAR_READER: &str = "calendar-reader@synthetic.example";
/// A shared calendar in the development organization.
pub const GOOGLE_DEVELOPMENT_CALENDAR: &str = "c_engineering@group.calendar.google.com";
pub const GOOGLE_DEVELOPMENT_DOMAIN: &str = "synthetic.example";

/// The disposable grant matching [`google_workspace_development_fixture`].
pub fn google_workspace_development_target() -> day2_capabilities::resources::ResourceTarget {
    day2_capabilities::resources::ResourceTarget::GoogleWorkspaceDomain {
        calendar_reader: GOOGLE_DEVELOPMENT_CALENDAR_READER.into(),
        email_domain: GOOGLE_DEVELOPMENT_DOMAIN.into(),
        grantee_domains: vec![GOOGLE_DEVELOPMENT_DOMAIN.into()],
    }
}

/// Move a seeded development world's meetings to the days before `at`, Unix
/// seconds, so the window an application derives from its invocation time
/// finds them: the latest day any event ends becomes `at`'s UTC day.
///
/// A disposable instance seeds the world before its campaign chooses a clock,
/// so the campaign dates it once its clock is known. Whole days keep every
/// event's clock time and all-day dates intact. Dating to the same day again
/// changes nothing, and an instance without a Google Workspace world is left
/// alone.
pub fn date_google_workspace_development(database: &Path, scope: &str, at: i64) -> Result<()> {
    if !database.with_file_name(GOOGLE_WORKSPACE_WORLD).is_file() {
        return Ok(());
    }
    update_google_workspace(database, scope, |state| {
        let Some(latest) = state.world.latest_event_day()? else {
            return Ok(());
        };
        let target = time::OffsetDateTime::from_unix_timestamp(at)
            .context("google_workspace_development_clock")?
            .date()
            .to_julian_day();
        state
            .world
            .shift_days(i64::from(target) - i64::from(latest.to_julian_day()))
    })
}

impl GoogleWorkspaceWorld {
    /// The latest UTC day on which any event ends: an all-day event's
    /// exclusive end date, or the date of a timed end.
    fn latest_event_day(&self) -> Result<Option<time::Date>> {
        let mut latest = None;
        for event in self
            .calendars
            .values()
            .flat_map(|calendar| &calendar.events)
        {
            if let Some(end) = &event.end {
                let day = day_prefix(end.date_time.as_deref().or(end.date.as_deref()))?;
                latest = latest.max(Some(day));
            }
        }
        Ok(latest)
    }

    /// Move every event and conference record by whole days.
    pub fn shift_days(&mut self, days: i64) -> Result<()> {
        if days == 0 {
            return Ok(());
        }
        for event in self
            .calendars
            .values_mut()
            .flat_map(|calendar| &mut calendar.events)
        {
            for time in [&mut event.start, &mut event.end, &mut event.original_start]
                .into_iter()
                .flatten()
            {
                for value in [&mut time.date_time, &mut time.date].into_iter().flatten() {
                    shift_day_prefix(value, days)?;
                }
            }
        }
        for record in self.conference_records.values_mut() {
            shift_day_prefix(&mut record.start_time, days)?;
            if let Some(end) = &mut record.end_time {
                shift_day_prefix(end, days)?;
            }
        }
        Ok(())
    }
}

/// The `YYYY-MM-DD` a fixture time starts with.
fn day_prefix(value: Option<&str>) -> Result<time::Date> {
    let value = value.context("google_workspace_development_time")?;
    let field = |range: std::ops::Range<usize>| {
        value
            .get(range)
            .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_digit()))
            .context("google_workspace_development_time")
    };
    ensure!(
        value.as_bytes().get(4) == Some(&b'-') && value.as_bytes().get(7) == Some(&b'-'),
        "google_workspace_development_time"
    );
    let month = time::Month::try_from(field(5..7)?.parse::<u8>()?)?;
    Ok(time::Date::from_calendar_date(
        field(0..4)?.parse()?,
        month,
        field(8..10)?.parse()?,
    )?)
}

/// Rewrite only the date a fixture time starts with, keeping its clock time,
/// fraction and offset byte for byte.
fn shift_day_prefix(value: &mut String, days: i64) -> Result<()> {
    let day = day_prefix(Some(value))?;
    let shifted = time::Date::from_julian_day(
        i32::try_from(i64::from(day.to_julian_day()) + days)
            .context("google_workspace_development_time")?,
    )?;
    *value = format!(
        "{:04}-{:02}-{:02}{}",
        shifted.year(),
        u8::from(shifted.month()),
        shifted.day(),
        &value[10..]
    );
    Ok(())
}

/// A small organization with nested groups, for local development and
/// verification campaigns that declare Google Workspace reads and shares.
/// Its meetings are dated January 2026; a campaign moves them to the days
/// before its own clock with [`date_google_workspace_development`].
pub fn google_workspace_development_fixture() -> GoogleWorkspaceWorld {
    let address = |local: &str| format!("{local}@{GOOGLE_DEVELOPMENT_DOMAIN}");
    let group = |id: &str, name: &str, members: &[String]| GoogleGroup {
        id: id.into(),
        name: name.into(),
        members: members.iter().cloned().collect(),
        aliases: BTreeSet::new(),
    };
    GoogleWorkspaceWorld {
        domain: GOOGLE_DEVELOPMENT_DOMAIN.into(),
        service_account: GOOGLE_DEVELOPMENT_SERVICE_ACCOUNT.into(),
        delegated_scopes: [
            "https://www.googleapis.com/auth/calendar.acls.readonly",
            "https://www.googleapis.com/auth/calendar.readonly",
            "https://www.googleapis.com/auth/drive",
            "https://www.googleapis.com/auth/meetings.space.readonly",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        directory_reader: true,
        users: ["ada", "grace", "calendar-reader"]
            .into_iter()
            .map(address)
            .collect(),
        groups: BTreeMap::from([
            (
                address("engineering"),
                group(
                    "group-engineering",
                    "Engineering",
                    &[address("ada"), address("platform")],
                ),
            ),
            (
                address("platform"),
                group("group-platform", "Platform", &[address("grace")]),
            ),
            (address("empty"), group("group-empty", "Empty", &[])),
        ]),
        calendars: BTreeMap::from([(
            GOOGLE_DEVELOPMENT_CALENDAR.into(),
            GoogleCalendar {
                summary: "Engineering".into(),
                acl: vec![
                    GoogleAclRule {
                        scope_type: "user".into(),
                        scope_value: Some(address("ada")),
                        role: "owner".into(),
                    },
                    GoogleAclRule {
                        scope_type: "user".into(),
                        scope_value: Some(GOOGLE_DEVELOPMENT_CALENDAR_READER.into()),
                        role: "writer".into(),
                    },
                    GoogleAclRule {
                        scope_type: "group".into(),
                        scope_value: Some(address("engineering")),
                        role: "reader".into(),
                    },
                ],
                events: vec![
                    GoogleEvent {
                        id: "standup0001".into(),
                        status: "confirmed".into(),
                        start: Some(GoogleTime::at("2026-01-05T17:00:00Z")),
                        end: Some(GoogleTime::at("2026-01-05T17:30:00Z")),
                        organizer: Some(address("ada")),
                        creator: Some(address("ada")),
                        conference_id: Some("abc-defg-hij".into()),
                        conference_type: Some("hangoutsMeet".into()),
                        ..GoogleEvent::default()
                    },
                    GoogleEvent {
                        id: "review0002".into(),
                        status: "confirmed".into(),
                        visibility: Some("private".into()),
                        start: Some(GoogleTime::at("2026-01-06T15:00:00Z")),
                        end: Some(GoogleTime::at("2026-01-06T16:00:00Z")),
                        organizer: Some(GOOGLE_DEVELOPMENT_CALENDAR.into()),
                        creator: Some(address("grace")),
                        hangout_link: Some("https://meet.google.com/klm-nopq-rst".into()),
                        ..GoogleEvent::default()
                    },
                    GoogleEvent {
                        id: "offsite0003".into(),
                        status: "confirmed".into(),
                        start: Some(GoogleTime::day("2026-01-07")),
                        end: Some(GoogleTime::day("2026-01-08")),
                        organizer: Some(address("ada")),
                        ..GoogleEvent::default()
                    },
                ],
            },
        )]),
        suspended: BTreeSet::new(),
        // The stand-up's space is ada's: its first call was recorded,
        // transcribed and noted, and a rejoin is still being recorded. The
        // review's space is grace's, who created it on the group calendar.
        spaces: BTreeMap::from([
            (
                "spaceStandup01".into(),
                GoogleSpace {
                    meeting_code: "abc-defg-hij".into(),
                    owner: address("ada"),
                },
            ),
            (
                "spaceReview001".into(),
                GoogleSpace {
                    meeting_code: "klm-nopq-rst".into(),
                    owner: address("grace"),
                },
            ),
        ]),
        conference_records: BTreeMap::from([
            (
                "conf-standup-1".into(),
                GoogleConferenceRecord {
                    space: "spaceStandup01".into(),
                    start_time: "2026-01-05T17:01:02.345Z".into(),
                    end_time: Some("2026-01-05T17:20:00Z".into()),
                    recordings: vec![artifact(
                        "rec-1",
                        "FILE_GENERATED",
                        Some("1recStandupFile01"),
                    )],
                    smart_notes: vec![artifact("note-1", "ENDED", None)],
                    transcripts: vec![artifact(
                        "tr-1",
                        "FILE_GENERATED",
                        Some("1docStandupTranscript"),
                    )],
                },
            ),
            (
                "conf-standup-2".into(),
                GoogleConferenceRecord {
                    space: "spaceStandup01".into(),
                    start_time: "2026-01-05T17:22:00Z".into(),
                    end_time: None,
                    recordings: vec![artifact("rec-2", "STARTED", None)],
                    ..GoogleConferenceRecord::default()
                },
            ),
            (
                "conf-review-1".into(),
                GoogleConferenceRecord {
                    space: "spaceReview001".into(),
                    start_time: "2026-01-06T15:00:30.123456Z".into(),
                    end_time: Some("2026-01-06T15:58:00Z".into()),
                    ..GoogleConferenceRecord::default()
                },
            ),
        ]),
        drive_files: BTreeMap::from([
            (
                "1recStandupFile01".into(),
                GoogleDriveFile {
                    name: "Standup recording".into(),
                    mime_type: "video/mp4".into(),
                    owner: address("ada"),
                    permissions: vec![GoogleDrivePermission::owner(&address("ada"))],
                },
            ),
            (
                "1docStandupTranscript".into(),
                GoogleDriveFile {
                    name: "Standup transcript".into(),
                    mime_type: "application/vnd.google-apps.document".into(),
                    owner: address("ada"),
                    permissions: vec![GoogleDrivePermission::owner(&address("ada"))],
                },
            ),
        ]),
        meet_record_pages: Vec::new(),
        drive_trusted_domains: BTreeSet::new(),
    }
}

fn artifact(id: &str, state: &str, file: Option<&str>) -> GoogleArtifact {
    GoogleArtifact {
        id: id.into(),
        state: state.into(),
        file: file.map(str::to_owned),
    }
}

/// Advance one Meet artifact, named as Meet names it: `STARTED` → `ENDED` →
/// `FILE_GENERATED`. Generating it saves its Drive file or Docs document,
/// owned by the space's owner, and records the ID on the artifact, as Meet
/// does. A generated artifact does not advance further.
pub fn google_meet_advance(world: &mut GoogleWorkspaceWorld, name: &str) -> Result<()> {
    let parts: Vec<&str> = name.split('/').collect();
    let ["conferenceRecords", record_id, collection, artifact_id] = parts.as_slice() else {
        anyhow::bail!("simulated_meet_artifact_unknown");
    };
    let record = world
        .conference_records
        .get_mut(*record_id)
        .context("simulated_meet_artifact_unknown")?;
    let owner = world
        .spaces
        .get(&record.space)
        .context("simulated_meet_artifact_unknown")?
        .owner
        .clone();
    let (artifacts, mime_type) = match *collection {
        "recordings" => (&mut record.recordings, "video/mp4"),
        "smartNotes" => (
            &mut record.smart_notes,
            "application/vnd.google-apps.document",
        ),
        "transcripts" => (
            &mut record.transcripts,
            "application/vnd.google-apps.document",
        ),
        _ => anyhow::bail!("simulated_meet_artifact_unknown"),
    };
    let artifact = artifacts
        .iter_mut()
        .find(|artifact| artifact.id == *artifact_id)
        .context("simulated_meet_artifact_unknown")?;
    match artifact.state.as_str() {
        "STARTED" => artifact.state = "ENDED".into(),
        "ENDED" => {
            let file = format!("1{}", &crate::digest(name.as_bytes())[7..40]);
            artifact.state = "FILE_GENERATED".into();
            artifact.file = Some(file.clone());
            world.drive_files.insert(
                file,
                GoogleDriveFile {
                    name: format!("{collection} {artifact_id}"),
                    mime_type: mime_type.into(),
                    permissions: vec![GoogleDrivePermission::owner(&owner)],
                    owner,
                },
            );
        }
        _ => anyhow::bail!("simulated_meet_artifact_final"),
    }
    Ok(())
}

/// Validate that the Google Workspace world is seeded for this scope, without a
/// request. A simulated host never falls through to the network.
pub(crate) fn google_workspace_check(database: &Path, scope: &str) -> Result<()> {
    let path = database.with_file_name(GOOGLE_WORKSPACE_WORLD);
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| anyhow::anyhow!("simulated_provider_unconfigured"))?;
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='simulated_provider')",
        [],
        |row| row.get(0),
    )?;
    ensure!(exists, "simulated_provider_unconfigured");
    let _: World<GoogleWorkspaceWorld> = read_world(&connection, scope)?;
    Ok(())
}

pub const GOOGLE_METADATA_ENDPOINT: &str = "google_workspace.metadata";
pub const GOOGLE_IAM_TOKEN_ENDPOINT: &str = "google_workspace.iam.generate_access_token";
pub const GOOGLE_IAM_SIGN_ENDPOINT: &str = "google_workspace.iam.sign_jwt";
pub const GOOGLE_OAUTH_TOKEN_ENDPOINT: &str = "google_workspace.oauth.token";
pub const GOOGLE_GROUP_ENDPOINT: &str = "google_workspace.directory.groups.get";
pub const GOOGLE_HAS_MEMBER_ENDPOINT: &str = "google_workspace.directory.groups.has_member";
pub const GOOGLE_CALENDAR_ENDPOINT: &str = "google_workspace.calendar.calendars.get";
pub const GOOGLE_ACL_ENDPOINT: &str = "google_workspace.calendar.acl.list";
pub const GOOGLE_ACL_RULE_ENDPOINT: &str = "google_workspace.calendar.acl.get";
pub const GOOGLE_EVENTS_ENDPOINT: &str = "google_workspace.calendar.events.list";
pub const GOOGLE_EVENT_ENDPOINT: &str = "google_workspace.calendar.events.get";
pub const GOOGLE_MEET_RECORDS_ENDPOINT: &str = "google_workspace.meet.conference_records.list";
pub const GOOGLE_MEET_RECORDINGS_ENDPOINT: &str = "google_workspace.meet.recordings.list";
pub const GOOGLE_MEET_SMART_NOTES_ENDPOINT: &str = "google_workspace.meet.smart_notes.list";
pub const GOOGLE_MEET_TRANSCRIPTS_ENDPOINT: &str = "google_workspace.meet.transcripts.list";
pub const GOOGLE_MEET_ARTIFACT_ENDPOINT: &str = "google_workspace.meet.artifact.get";
pub const GOOGLE_DRIVE_PERMISSIONS_ENDPOINT: &str = "google_workspace.drive.permissions.list";
pub const GOOGLE_DRIVE_SHARE_ENDPOINT: &str = "google_workspace.drive.permissions.create";
/// Every endpoint a scenario can schedule a fault against.
pub const GOOGLE_ENDPOINTS: [&str; 18] = [
    GOOGLE_METADATA_ENDPOINT,
    GOOGLE_IAM_TOKEN_ENDPOINT,
    GOOGLE_IAM_SIGN_ENDPOINT,
    GOOGLE_OAUTH_TOKEN_ENDPOINT,
    GOOGLE_GROUP_ENDPOINT,
    GOOGLE_HAS_MEMBER_ENDPOINT,
    GOOGLE_CALENDAR_ENDPOINT,
    GOOGLE_ACL_ENDPOINT,
    GOOGLE_ACL_RULE_ENDPOINT,
    GOOGLE_EVENTS_ENDPOINT,
    GOOGLE_EVENT_ENDPOINT,
    GOOGLE_MEET_RECORDS_ENDPOINT,
    GOOGLE_MEET_RECORDINGS_ENDPOINT,
    GOOGLE_MEET_SMART_NOTES_ENDPOINT,
    GOOGLE_MEET_TRANSCRIPTS_ENDPOINT,
    GOOGLE_MEET_ARTIFACT_ENDPOINT,
    GOOGLE_DRIVE_PERMISSIONS_ENDPOINT,
    GOOGLE_DRIVE_SHARE_ENDPOINT,
];
/// The key the simulated IAM signs with. Its "signature" is derived from the
/// signed bytes, so the token endpoint can tell its own assertions from others.
const GOOGLE_KEY_ID: &str = "simulated-key-1";

pub(crate) enum GoogleRequest<'a> {
    Auth(&'a crate::google_auth::Exchange<'a>),
    Api {
        request: &'a crate::google_workspace::ApiRequest,
        bearer: &'a str,
    },
}

fn google_signature(payload: &[u8]) -> Vec<u8> {
    let digest = crate::digest(payload);
    let mut signature = digest.as_bytes().to_vec();
    signature.extend_from_slice(digest.as_bytes());
    signature
}

/// Serve one Google exchange from the world, recording it and consuming a
/// scheduled fault. Statuses and bodies are Google-shaped; the shared pipeline
/// classifies them. An unconfigured or broken world is an unreachable provider.
pub(crate) fn google_workspace_serve(
    database: &Path,
    scope: &str,
    request: GoogleRequest<'_>,
    max: usize,
) -> std::result::Result<crate::google_auth::Reply, crate::google_auth::Unreached> {
    use crate::google_auth::{Exchange, IamMethod, Unreached};
    let path = database.with_file_name(GOOGLE_WORKSPACE_WORLD);
    let served = with_world::<GoogleWorkspaceWorld, _, _>(&path, scope, |state| {
        ensure!(state.calls.len() < MAX_MESSAGES, "simulated_call_budget");
        let endpoint = match &request {
            GoogleRequest::Auth(Exchange::Metadata) => GOOGLE_METADATA_ENDPOINT,
            GoogleRequest::Auth(Exchange::Iam {
                method: IamMethod::GenerateAccessToken,
                ..
            }) => GOOGLE_IAM_TOKEN_ENDPOINT,
            GoogleRequest::Auth(Exchange::Iam {
                method: IamMethod::SignJwt,
                ..
            }) => GOOGLE_IAM_SIGN_ENDPOINT,
            GoogleRequest::Auth(Exchange::Token { .. }) => GOOGLE_OAUTH_TOKEN_ENDPOINT,
            GoogleRequest::Api { request, .. } => google_api_endpoint(request),
        };
        state.calls.push(match &request {
            // A signJwt request is logged with the subject it asks to sign
            // for, so a campaign can see exactly who was impersonated.
            GoogleRequest::Auth(Exchange::Iam {
                service_account,
                method: IamMethod::SignJwt,
                body,
                ..
            }) => {
                let subject = serde_json::from_slice::<Value>(body)
                    .ok()
                    .and_then(|body| {
                        let claims: Value = serde_json::from_str(body["payload"].as_str()?).ok()?;
                        claims["sub"].as_str().map(str::to_owned)
                    })
                    .unwrap_or_default();
                format!("{endpoint}:{service_account}:{subject}")
            }
            GoogleRequest::Auth(Exchange::Iam {
                service_account, ..
            }) => {
                format!("{endpoint}:{service_account}")
            }
            GoogleRequest::Api { request, .. } => format!(
                "{endpoint}:{}?{}",
                request.segments.join("/"),
                request.query_string().unwrap_or_default()
            ),
            GoogleRequest::Auth(_) => endpoint.to_owned(),
        });
        if let Some(fault) = take_fault_named(state, endpoint) {
            if fault == SimulatedFault::ReplyLost {
                // Serve it, so whatever it changes is committed, and drop the
                // reply on the way back.
                google_reply(&mut state.world, &request)?;
                return Ok(Err(crate::google_auth::Unreached::default()));
            }
            if fault == SimulatedFault::Conflict {
                google_reply(&mut state.world, &request)?;
                return Ok(Ok(google_error(409, "conflict", "Conflict")));
            }
            return Ok(google_fault(
                fault,
                max,
                endpoint.starts_with("google_workspace.meet."),
            ));
        }
        Ok(Ok(google_reply(&mut state.world, &request)?))
    });
    match served {
        Ok(reply) => {
            let mut reply = reply?;
            // The wire never delivers more than the reader asked for plus the
            // probe byte that makes an oversized response observable.
            reply.body.truncate(max.saturating_add(1));
            Ok(reply)
        }
        Err(_) => Err(Unreached::default()),
    }
}

/// A JSON reply, as Google sends one.
fn google_json(status: u16, body: Value) -> crate::google_auth::Reply {
    crate::google_auth::Reply {
        status,
        metadata_flavor: false,
        json: true,
        body: body.to_string().into_bytes(),
        retry_after_seconds: None,
    }
}

/// Google's error envelope, with the one reason its APIs put in `errors[]`.
fn google_error(status: u16, reason: &str, message: &str) -> crate::google_auth::Reply {
    google_json(
        status,
        json!({"error":{"code":status,"message":message,
            "errors":[{"domain":"global","reason":reason,"message":message}]}}),
    )
}

/// The reason Google gives with each status this world answers.
fn google_status_error(status: u16, message: &str) -> crate::google_auth::Reply {
    let reason = match status {
        400 => "invalid",
        401 => "authError",
        403 => "forbidden",
        404 => "notFound",
        429 => "rateLimitExceeded",
        _ => "backendError",
    };
    google_error(status, reason, message)
}

/// One query parameter of a request.
fn google_query<'a>(
    request: &'a crate::google_workspace::ApiRequest,
    name: &str,
) -> Option<&'a str> {
    request
        .query
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.as_str())
}

/// Whether a request carries exactly the reviewed query: every `fixed` pair
/// with its value, any of the `free` names, and nothing else, each at most
/// once. Any other parameter or mask is refused, so the simulation cannot
/// serve a request the reviewed constants do not describe.
fn google_query_is(
    request: &crate::google_workspace::ApiRequest,
    fixed: &[(&str, &str)],
    free: &[&str],
) -> bool {
    let names: BTreeSet<&str> = request.query.iter().map(|(name, _)| *name).collect();
    names.len() == request.query.len()
        && fixed
            .iter()
            .all(|(name, value)| google_query(request, name) == Some(*value))
        && request
            .query
            .iter()
            .all(|(name, _)| fixed.iter().any(|(fixed, _)| fixed == name) || free.contains(name))
}

/// A scheduled fault as Google would deliver it.
fn google_fault(
    fault: SimulatedFault,
    max: usize,
    meet: bool,
) -> std::result::Result<crate::google_auth::Reply, crate::google_auth::Unreached> {
    use crate::google_auth::{Reply, Unreached};
    // Meet answers in the newer envelope: a status and an ErrorInfo reason.
    let failed = |status: u16, reason: &str, message: &str| {
        if meet {
            let (name, reason) = match status {
                400 => ("INVALID_ARGUMENT", None),
                403 if reason == "rateLimitExceeded" => {
                    ("PERMISSION_DENIED", Some("RATE_LIMIT_EXCEEDED"))
                }
                403 => ("PERMISSION_DENIED", None),
                404 => ("NOT_FOUND", None),
                409 => ("ALREADY_EXISTS", None),
                429 => ("RESOURCE_EXHAUSTED", Some("RATE_LIMIT_EXCEEDED")),
                _ => ("INTERNAL", None),
            };
            google_rpc_error(status, name, message, reason)
        } else {
            google_error(status, reason, message)
        }
    };
    Ok(match fault {
        SimulatedFault::RateLimited => Reply {
            retry_after_seconds: Some(30),
            ..failed(429, "rateLimitExceeded", "Rate Limit Exceeded")
        },
        SimulatedFault::RateLimitForbidden => {
            failed(403, "rateLimitExceeded", "Rate Limit Exceeded")
        }
        SimulatedFault::Denied => failed(403, "forbidden", "Forbidden"),
        SimulatedFault::BadRequest => failed(400, "badRequest", "Bad Request"),
        SimulatedFault::Gone => failed(404, "notFound", "Requested entity was not found."),
        SimulatedFault::Conflict => failed(409, "conflict", "Conflict"),
        SimulatedFault::ServerError => failed(500, "backendError", "Backend Error"),
        SimulatedFault::NotJson => Reply {
            status: 200,
            metadata_flavor: false,
            json: false,
            body: b"not json".to_vec(),
            retry_after_seconds: None,
        },
        SimulatedFault::Oversized => Reply {
            body: vec![b'x'; max + 1],
            ..google_json(200, json!({}))
        },
        SimulatedFault::ConnectionLost
        | SimulatedFault::ReplyLost
        | SimulatedFault::Rejected
        | SimulatedFault::Partitioned
        | SimulatedFault::TokenOverrun
        | SimulatedFault::Refused => return Err(Unreached::default()),
    })
}

/// What a simulated token may do. Tokens are self-describing and verified by
/// recomputing their tag, so serving a read leaves the world unchanged.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoogleGrant {
    workload: bool,
    /// The delegated person, or the service account itself when absent.
    subject: Option<String>,
    scopes: BTreeSet<String>,
}

fn google_token(world: &GoogleWorkspaceWorld, grant: &GoogleGrant) -> Result<String> {
    let payload =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(grant)?);
    let tag = crate::digest(&serde_json::to_vec(&(
        "google-workspace-simulated-token",
        &world.service_account,
        &payload,
    ))?);
    Ok(format!("simulated.{payload}.{}", &tag[7..]))
}

fn google_grant(world: &GoogleWorkspaceWorld, token: &str) -> Option<GoogleGrant> {
    let payload = token.strip_prefix("simulated.")?.split('.').next()?;
    let grant: GoogleGrant = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()?,
    )
    .ok()?;
    (google_token(world, &grant).ok()?.as_str() == token).then_some(grant)
}

/// Whether `member` belongs to `group`, directly or through member groups.
fn google_is_member(world: &GoogleWorkspaceWorld, group: &str, member: &str) -> bool {
    let mut pending = vec![group.to_owned()];
    let mut seen = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if !seen.insert(current.clone()) {
            continue;
        }
        let Some(group) = world.groups.get(&current) else {
            continue;
        };
        if group.members.contains(member) {
            return true;
        }
        pending.extend(
            group
                .members
                .iter()
                .filter(|candidate| world.groups.contains_key(*candidate))
                .cloned(),
        );
    }
    false
}

fn google_reply(
    world: &mut GoogleWorkspaceWorld,
    request: &GoogleRequest<'_>,
) -> Result<crate::google_auth::Reply> {
    use crate::google_auth::{Exchange, IamMethod, Reply};
    let reply = google_json;
    let error = google_status_error;
    Ok(match request {
        GoogleRequest::Auth(Exchange::Metadata) => {
            let token = google_token(
                world,
                &GoogleGrant {
                    workload: true,
                    subject: None,
                    scopes: BTreeSet::new(),
                },
            )?;
            Reply {
                metadata_flavor: true,
                ..reply(
                    200,
                    json!({"access_token":token,"expires_in":3599,"token_type":"Bearer"}),
                )
            }
        }
        GoogleRequest::Auth(Exchange::Iam {
            service_account,
            method,
            bearer,
            body,
        }) => {
            if !google_grant(world, bearer.bearer()).is_some_and(|grant| grant.workload) {
                return Ok(error(
                    401,
                    "Request had invalid authentication credentials.",
                ));
            }
            if *service_account != world.service_account {
                return Ok(error(
                    403,
                    "Permission 'iam.serviceAccounts.getAccessToken' denied",
                ));
            }
            let Ok(body) = serde_json::from_slice::<Value>(body) else {
                return Ok(error(400, "Invalid JSON payload received."));
            };
            match method {
                IamMethod::GenerateAccessToken => {
                    let scopes: Option<BTreeSet<String>> = body["scope"].as_array().map(|scopes| {
                        scopes
                            .iter()
                            .filter_map(|scope| scope.as_str().map(str::to_owned))
                            .collect()
                    });
                    match scopes {
                        Some(scopes) if !scopes.is_empty() => {
                            let token = google_token(
                                world,
                                &GoogleGrant {
                                    workload: false,
                                    subject: None,
                                    scopes,
                                },
                            )?;
                            reply(
                                200,
                                json!({"accessToken":token,"expireTime":"2030-01-01T00:00:00Z"}),
                            )
                        }
                        _ => error(400, "Scope required."),
                    }
                }
                IamMethod::SignJwt => {
                    let Some(payload) = body["payload"].as_str() else {
                        return Ok(error(400, "Payload required."));
                    };
                    let encode = |bytes: &[u8]| {
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
                    };
                    let header = encode(
                        json!({"alg":"RS256","kid":GOOGLE_KEY_ID,"typ":"JWT"})
                            .to_string()
                            .as_bytes(),
                    );
                    let signed = format!("{header}.{}", encode(payload.as_bytes()));
                    let signature = encode(&google_signature(signed.as_bytes()));
                    reply(
                        200,
                        json!({"keyId":GOOGLE_KEY_ID,"signedJwt":format!("{signed}.{signature}")}),
                    )
                }
            }
        }
        GoogleRequest::Auth(Exchange::Token { form }) => {
            let pairs: BTreeMap<String, String> = url::form_urlencoded::parse(form.as_bytes())
                .into_owned()
                .collect();
            if pairs.get("grant_type").map(String::as_str)
                != Some("urn:ietf:params:oauth:grant-type:jwt-bearer")
            {
                return Ok(reply(400, json!({"error":"unsupported_grant_type"})));
            }
            let invalid_grant = reply(400, json!({"error":"invalid_grant"}));
            let Some(jwt) = pairs.get("assertion") else {
                return Ok(invalid_grant);
            };
            let parts: Vec<_> = jwt.split('.').collect();
            let decoded = |part: &str| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(part)
                    .ok()
            };
            let (Some(signed), Some(signature), Some(claims)) = (
                jwt.rsplit_once('.').map(|(signed, _)| signed),
                parts.get(2).and_then(|part| decoded(part)),
                parts
                    .get(1)
                    .and_then(|part| decoded(part))
                    .and_then(|claims| serde_json::from_slice::<Value>(&claims).ok()),
            ) else {
                return Ok(invalid_grant);
            };
            if parts.len() != 3 || signature != google_signature(signed.as_bytes()) {
                return Ok(invalid_grant);
            }
            let lifetime = claims["exp"].as_i64().zip(claims["iat"].as_i64());
            if claims["iss"] != world.service_account.as_str()
                || claims["aud"] != crate::google_auth::GOOGLE_TOKEN_ENDPOINT
                || !lifetime.is_some_and(|(exp, iat)| exp > iat && exp - iat <= 3600)
            {
                return Ok(invalid_grant);
            }
            let scopes: BTreeSet<String> = claims["scope"]
                .as_str()
                .unwrap_or_default()
                .split(' ')
                .filter(|scope| !scope.is_empty())
                .map(str::to_owned)
                .collect();
            if scopes.is_empty() || !scopes.is_subset(&world.delegated_scopes) {
                return Ok(reply(
                    401,
                    json!({"error":"unauthorized_client","error_description":"Client is unauthorized to retrieve access tokens using this method, or client not authorized for any of the scopes requested."}),
                ));
            }
            let Some(subject) = claims["sub"]
                .as_str()
                .filter(|sub| world.users.contains(*sub) && !world.suspended.contains(*sub))
            else {
                return Ok(reply(
                    400,
                    json!({"error":"invalid_grant","error_description":"Invalid email or User ID"}),
                ));
            };
            let token = google_token(
                world,
                &GoogleGrant {
                    workload: false,
                    subject: Some(subject.to_owned()),
                    scopes,
                },
            )?;
            reply(
                200,
                json!({"access_token":token,"expires_in":3599,"token_type":"Bearer"}),
            )
        }
        GoogleRequest::Api { request, bearer } => {
            let Some(issued) = google_grant(world, bearer).filter(|grant| !grant.workload) else {
                return Ok(error(
                    401,
                    "Request had invalid authentication credentials.",
                ));
            };
            if request.service == crate::google_workspace::Service::Calendar {
                return google_calendar_reply(world, request, &issued);
            }
            if request.service == crate::google_workspace::Service::Meet {
                return google_meet_reply(world, request, &issued);
            }
            if request.service == crate::google_workspace::Service::Drive {
                return google_drive_reply(world, request, &issued);
            }
            let segments: Vec<&str> = request.segments.iter().map(String::as_str).collect();
            let (required, group, member) = match segments.as_slice() {
                ["admin", "directory", "v1", "groups", group] => {
                    (crate::google_workspace::GROUP_READ_SCOPE, *group, None)
                }
                [
                    "admin",
                    "directory",
                    "v1",
                    "groups",
                    group,
                    "hasMember",
                    member,
                ] => (
                    crate::google_workspace::GROUP_MEMBER_READ_SCOPE,
                    *group,
                    Some(*member),
                ),
                _ => return Ok(error(404, "Not Found")),
            };
            // The reviewed queries only: the group read's mask, and nothing but
            // compact output for a membership read.
            let admitted = if member.is_none() {
                google_query_is(
                    request,
                    &[("fields", "id,email,name"), ("prettyPrint", "false")],
                    &[],
                )
            } else {
                google_query_is(request, &[("prettyPrint", "false")], &[])
            };
            if !admitted {
                return Ok(error(400, "Unreviewed query"));
            }
            if !issued.scopes.contains(required) {
                return Ok(google_error(
                    403,
                    "insufficientPermissions",
                    "Request had insufficient authentication scopes.",
                ));
            }
            // Only the service account itself holds the Directory role here.
            if issued.subject.is_some() || !world.directory_reader {
                return Ok(error(403, "Not Authorized to access this resource/api"));
            }
            // Keys are matched exactly, never normalised: the adapter sends
            // lowercase addresses, and normalising here would hide a bug there.
            // A group key is its primary address or one of its aliases.
            let Some((key, found)) = world.groups.get_key_value(group).or_else(|| {
                world
                    .groups
                    .iter()
                    .find(|(_, candidate)| candidate.aliases.contains(group))
            }) else {
                return Ok(error(404, "Resource Not Found: groupKey"));
            };
            match member {
                None => reply(200, json!({"id":found.id,"email":key,"name":found.name})),
                Some(member) => {
                    // hasMember's memberKey identifies a user, never a group.
                    if !world.users.contains(member) {
                        return Ok(error(404, "Resource Not Found: memberKey"));
                    }
                    let direct = found.members.contains(member);
                    if !direct
                        && member.rsplit_once('@').map(|(_, domain)| domain)
                            != key.rsplit_once('@').map(|(_, domain)| domain)
                    {
                        return Ok(error(400, "Invalid Input: memberKey"));
                    }
                    reply(
                        200,
                        json!({"isMember":direct || google_is_member(world, key, member)}),
                    )
                }
            }
        }
    })
}

/// The endpoint a request names, for faults and the request log.
fn google_api_endpoint(request: &crate::google_workspace::ApiRequest) -> &'static str {
    use crate::google_workspace::Service;
    let segments: Vec<&str> = request.segments.iter().map(String::as_str).collect();
    match (request.service, segments.as_slice()) {
        (Service::Directory, [.., "hasMember", _]) => GOOGLE_HAS_MEMBER_ENDPOINT,
        (Service::Directory, _) => GOOGLE_GROUP_ENDPOINT,
        (Service::Calendar, [.., "acl"]) => GOOGLE_ACL_ENDPOINT,
        (Service::Calendar, [.., "acl", _]) => GOOGLE_ACL_RULE_ENDPOINT,
        (Service::Calendar, [.., "events"]) => GOOGLE_EVENTS_ENDPOINT,
        (Service::Calendar, [.., "events", _]) => GOOGLE_EVENT_ENDPOINT,
        (Service::Calendar, _) => GOOGLE_CALENDAR_ENDPOINT,
        (Service::Meet, [_, _, _, _, _]) => GOOGLE_MEET_ARTIFACT_ENDPOINT,
        (Service::Meet, [.., "recordings"]) => GOOGLE_MEET_RECORDINGS_ENDPOINT,
        (Service::Meet, [.., "smartNotes"]) => GOOGLE_MEET_SMART_NOTES_ENDPOINT,
        (Service::Meet, [.., "transcripts"]) => GOOGLE_MEET_TRANSCRIPTS_ENDPOINT,
        (Service::Meet, _) => GOOGLE_MEET_RECORDS_ENDPOINT,
        (Service::Drive, _) if request.body().is_some() => GOOGLE_DRIVE_SHARE_ENDPOINT,
        (Service::Drive, _) => GOOGLE_DRIVE_PERMISSIONS_ENDPOINT,
    }
}

/// Serve one Drive permission route as the token's delegated subject. A file
/// is visible to its owner alone here, and only its owner lists or shares it.
/// Every route admits only its reviewed query, and a create only the exact
/// reviewed body: a group as `reader`. Creating a permission for a group that
/// already has one answers that permission, unchanged, with `200`.
fn google_drive_reply(
    world: &mut GoogleWorkspaceWorld,
    request: &crate::google_workspace::ApiRequest,
    grant: &GoogleGrant,
) -> Result<crate::google_auth::Reply> {
    use crate::google_workspace_drive::{
        CREATED_FIELDS, DRIVE_SCOPE, PERMISSION_PAGE_SIZE, PERMISSIONS_FIELDS,
    };
    let error = google_status_error;
    let segments: Vec<&str> = request.segments.iter().map(String::as_str).collect();
    let ["drive", "v3", "files", file_id, "permissions"] = segments.as_slice() else {
        return Ok(error(404, "Not Found"));
    };
    let page_size = PERMISSION_PAGE_SIZE.to_string();
    let compact = ("prettyPrint", "false");
    let admitted = match request.body() {
        Some(_) => google_query_is(
            request,
            &[
                ("supportsAllDrives", "true"),
                ("sendNotificationEmail", "false"),
                ("fields", CREATED_FIELDS),
                compact,
            ],
            &[],
        ),
        None => google_query_is(
            request,
            &[
                ("supportsAllDrives", "true"),
                ("pageSize", page_size.as_str()),
                ("fields", PERMISSIONS_FIELDS),
                compact,
            ],
            &["pageToken"],
        ),
    };
    if !admitted {
        return Ok(google_error(400, "badRequest", "Unreviewed query"));
    }
    if !grant.scopes.contains(DRIVE_SCOPE) {
        return Ok(google_error(
            403,
            "insufficientPermissions",
            "Request had insufficient authentication scopes.",
        ));
    }
    let not_found = google_error(404, "notFound", "File not found.");
    let Some(subject) = grant.subject.clone() else {
        return Ok(not_found);
    };
    let Some(file) = world.drive_files.get(*file_id) else {
        return Ok(not_found);
    };
    if file.owner != subject {
        return Ok(not_found);
    }
    let wire = |permission: &GoogleDrivePermission| {
        let mut item = json!({"id":permission.id,"type":permission.kind,"role":permission.role});
        if let Some(email) = &permission.email_address {
            item["emailAddress"] = json!(email);
            item["deleted"] = json!(permission.deleted);
        }
        item
    };
    let Some(body) = request.body() else {
        let binding = format!("permissions:{file_id}");
        let offset = match google_query(request, "pageToken") {
            None => 0,
            Some(token) => match google_page_offset(world, &binding, token) {
                Some(offset) => offset,
                None => return Ok(google_error(400, "invalid", "Invalid page token")),
            },
        };
        let size = PERMISSION_PAGE_SIZE as usize;
        let items: Vec<Value> = file
            .permissions
            .iter()
            .skip(offset)
            .take(size)
            .map(wire)
            .collect();
        let mut page = json!({ "permissions": items });
        if offset + size < file.permissions.len() {
            page["nextPageToken"] = json!(google_page_token(world, &binding, offset + size)?);
        }
        return Ok(google_json(200, page));
    };
    // Exactly the reviewed body: a group as reader, nothing else.
    let asked: Option<String> = serde_json::from_str::<Value>(body)
        .ok()
        .filter(|value| {
            value.as_object().is_some_and(|object| object.len() == 3)
                && value["type"] == "group"
                && value["role"] == "reader"
        })
        .and_then(|value| value["emailAddress"].as_str().map(str::to_owned));
    let Some(group) = asked else {
        return Ok(google_error(400, "badRequest", "Unreviewed permission"));
    };
    // Drive grants the group itself, under its primary address, whichever
    // address the request named.
    let Some(group) = world
        .groups
        .get_key_value(&group)
        .or_else(|| {
            world
                .groups
                .iter()
                .find(|(_, candidate)| candidate.aliases.contains(&group))
        })
        .map(|(primary, _)| primary.clone())
    else {
        return Ok(google_error(
            400,
            "invalidSharingRequest",
            "Bad Request. User message: \"This sharing request is not allowed.\"",
        ));
    };
    let domain = group.rsplit_once('@').map(|(_, domain)| domain.to_owned());
    let trusted = world.drive_trusted_domains.is_empty()
        || domain.is_some_and(|domain| world.drive_trusted_domains.contains(&domain));
    if !trusted {
        return Ok(google_error(
            400,
            "invalidSharingRequest",
            "Bad Request. User message: \"This sharing request is not allowed.\"",
        ));
    }
    let file = world
        .drive_files
        .get_mut(*file_id)
        .context("simulated_drive_file")?;
    if let Some(existing) = file.permissions.iter().find(|permission| {
        permission.kind == "group"
            && !permission.deleted
            && permission
                .email_address
                .as_deref()
                .is_some_and(|email| email.eq_ignore_ascii_case(&group))
    }) {
        return Ok(google_json(
            200,
            json!({"id":existing.id,"type":existing.kind,"role":existing.role,
                "emailAddress":existing.email_address}),
        ));
    }
    let id = format!(
        "{}",
        u64::from_str_radix(
            &crate::digest(format!("{file_id}:{group}:{}", file.permissions.len()).as_bytes())
                [7..22],
            16
        )?
    );
    file.permissions.push(GoogleDrivePermission {
        id: id.clone(),
        kind: "group".into(),
        role: "reader".into(),
        email_address: Some(group.clone()),
        deleted: false,
        created_by: Some(subject),
    });
    Ok(google_json(
        200,
        json!({"id":id,"type":"group","role":"reader","emailAddress":group}),
    ))
}

/// An error in the envelope Meet and other newer Google APIs send: a status
/// name and, for a reason, an `ErrorInfo` detail.
fn google_rpc_error(
    code: u16,
    status: &str,
    message: &str,
    reason: Option<&str>,
) -> crate::google_auth::Reply {
    let mut error = json!({"code":code,"message":message,"status":status});
    if let Some(reason) = reason {
        error["details"] = json!([{"@type":"type.googleapis.com/google.rpc.ErrorInfo",
            "reason":reason,"domain":"googleapis.com"}]);
    }
    google_json(code, json!({ "error": error }))
}

/// The reviewed conference-record filter, exactly: a Meet code and a
/// start-time window in whole UTC seconds. Anything else is not parsed.
fn google_meet_filter(filter: &str) -> Option<(&str, i64, i64)> {
    use crate::google_workspace_calendar::{meeting_code, rfc3339_seconds};
    let rest = filter.strip_prefix("space.meeting_code = \"")?;
    let (code, rest) = rest.split_once('"')?;
    let rest = rest.strip_prefix(" AND start_time >= \"")?;
    let (from, rest) = rest.split_once('"')?;
    let to = rest
        .strip_prefix(" AND start_time <= \"")?
        .strip_suffix('"')?;
    let instant = |value: &str| {
        (value.len() == 20 && value.ends_with('Z'))
            .then(|| rfc3339_seconds(value))
            .flatten()
    };
    meeting_code(code).then_some(())?;
    Some((code, instant(from)?, instant(to)?))
}

/// Serve one Meet route as the token's delegated subject. Conference records
/// and their artifacts are visible only to the space's owner: another person
/// lists no records and is refused a record's artifacts. Every route admits
/// only its reviewed query.
fn google_meet_reply(
    world: &GoogleWorkspaceWorld,
    request: &crate::google_workspace::ApiRequest,
    grant: &GoogleGrant,
) -> Result<crate::google_auth::Reply> {
    use crate::google_workspace_meet::{
        ARTIFACT_PAGE_SIZE, Collection, MEET_READ_SCOPE, RECORD_PAGE_SIZE, RECORDS_FIELDS,
        meet_timestamp,
    };
    let reply = google_json;
    let error = google_rpc_error;
    let query = |name: &str| google_query(request, name);
    let compact = ("prettyPrint", "false");
    let segments: Vec<&str> = request.segments.iter().map(String::as_str).collect();
    let record_size = RECORD_PAGE_SIZE.to_string();
    let artifact_size = ARTIFACT_PAGE_SIZE.to_string();
    let named = |segment: &str| {
        Collection::ALL
            .into_iter()
            .find(|collection| collection.segment() == segment)
    };
    let (record, collection, single) = match segments.as_slice() {
        ["v2", "conferenceRecords"] => (None, None, None),
        ["v2", "conferenceRecords", record, segment] => match named(segment) {
            Some(collection) => (Some(*record), Some(collection), None),
            None => return Ok(error(404, "NOT_FOUND", "Not found", None)),
        },
        ["v2", "conferenceRecords", record, segment, id] => match named(segment) {
            Some(collection) => (Some(*record), Some(collection), Some(*id)),
            None => return Ok(error(404, "NOT_FOUND", "Not found", None)),
        },
        _ => return Ok(error(404, "NOT_FOUND", "Not found", None)),
    };
    let admitted = match (collection, single) {
        (Some(collection), Some(_)) => google_query_is(
            request,
            &[("fields", collection.artifact_fields()), compact],
            &[],
        ),
        (None, _) => {
            google_query_is(
                request,
                &[
                    ("pageSize", record_size.as_str()),
                    ("fields", RECORDS_FIELDS),
                    compact,
                ],
                &["filter", "pageToken"],
            ) && query("filter").and_then(google_meet_filter).is_some()
        }
        (Some(collection), None) => google_query_is(
            request,
            &[
                ("pageSize", artifact_size.as_str()),
                ("fields", collection.fields()),
                compact,
            ],
            &["pageToken"],
        ),
    };
    if !admitted {
        return Ok(error(400, "INVALID_ARGUMENT", "Unreviewed query", None));
    }
    if !grant.scopes.contains(MEET_READ_SCOPE) {
        return Ok(error(
            403,
            "PERMISSION_DENIED",
            "Request had insufficient authentication scopes.",
            Some("ACCESS_TOKEN_SCOPE_INSUFFICIENT"),
        ));
    }
    let Some(subject) = grant.subject.as_deref() else {
        return Ok(error(
            403,
            "PERMISSION_DENIED",
            "The caller does not have permission",
            None,
        ));
    };
    // Each continuation names the page it leads to, so a page can be short.
    let page = |binding: String,
                items: Vec<Value>,
                key: &str,
                size: usize,
                short: &[usize]|
     -> Result<_> {
        let (index, offset) = match query("pageToken") {
            None => (0, 0),
            Some(token) => match google_page_cursor(world, &binding, token) {
                Some(cursor) => cursor,
                None => {
                    return Ok(error(400, "INVALID_ARGUMENT", "Invalid page token", None));
                }
            },
        };
        let size = short.get(index).copied().unwrap_or(size).min(size);
        let mut body = json!({});
        let slice: Vec<Value> = items.iter().skip(offset).take(size).cloned().collect();
        if !slice.is_empty() {
            body[key] = json!(slice);
        }
        if offset + size < items.len() {
            body["nextPageToken"] = json!(google_page_token(
                world,
                &format!("{binding}#{}", index + 1),
                offset + size
            )?);
        }
        Ok(reply(200, body))
    };
    match (record, collection) {
        (Some(record), Some(collection)) => {
            let Some(found) = world.conference_records.get(record) else {
                return Ok(error(404, "NOT_FOUND", "Conference record not found", None));
            };
            if world
                .spaces
                .get(&found.space)
                .is_none_or(|space| space.owner != subject)
            {
                return Ok(error(
                    403,
                    "PERMISSION_DENIED",
                    "The caller does not have permission",
                    None,
                ));
            }
            let artifacts = match collection {
                Collection::Recordings => &found.recordings,
                Collection::SmartNotes => &found.smart_notes,
                Collection::Transcripts => &found.transcripts,
            };
            let wire = |artifact: &GoogleArtifact| {
                let mut item = json!({
                    "name": format!("conferenceRecords/{record}/{}/{}", collection.segment(), artifact.id),
                    "state": artifact.state,
                });
                if let Some(file) = &artifact.file {
                    if collection == Collection::Recordings {
                        item["driveDestination"] = json!({ "file": file });
                    } else {
                        item["docsDestination"] = json!({ "document": file });
                    }
                }
                item
            };
            if let Some(id) = single {
                return Ok(match artifacts.iter().find(|artifact| artifact.id == id) {
                    Some(artifact) => reply(200, wire(artifact)),
                    None => error(404, "NOT_FOUND", "Requested entity was not found.", None),
                });
            }
            let items = artifacts.iter().map(wire).collect();
            page(
                format!("{}:{record}", collection.segment()),
                items,
                collection.segment(),
                ARTIFACT_PAGE_SIZE as usize,
                &[],
            )
        }
        _ => {
            let filter = query("filter").unwrap_or_default();
            let Some((code, from, to)) = google_meet_filter(filter) else {
                return Ok(error(400, "INVALID_ARGUMENT", "Invalid filter", None));
            };
            let mut selected: Vec<(i64, &String, &GoogleConferenceRecord)> = world
                .conference_records
                .iter()
                .filter_map(|(id, record)| {
                    let space = world.spaces.get(&record.space)?;
                    let start = meet_timestamp(&record.start_time)?;
                    (space.meeting_code == code
                        && space.owner == subject
                        && (from..=to).contains(&start))
                    .then_some((start, id, record))
                })
                .collect();
            // Meet lists records latest start first.
            selected.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(right.1)));
            let items = selected
                .iter()
                .map(|(_, id, record)| {
                    let mut item = json!({
                        "name": format!("conferenceRecords/{id}"),
                        "space": format!("spaces/{}", record.space),
                        "startTime": record.start_time,
                    });
                    if let Some(end) = &record.end_time {
                        item["endTime"] = json!(end);
                    }
                    item
                })
                .collect();
            page(
                format!("records:{subject}:{filter}"),
                items,
                "conferenceRecords",
                RECORD_PAGE_SIZE as usize,
                &world.meet_record_pages,
            )
        }
    }
}

/// An opaque continuation bound to `binding`: a token issued for another
/// binding, or forged, is refused. ACL and record lists bind their whole query,
/// an assumption the adapter never tests (it resends a token only with the
/// identical request). Events lists bind only their calendar: Google accepted
/// another window's token live, and refusing another calendar's is an
/// assumption.
fn google_page_token(world: &GoogleWorkspaceWorld, binding: &str, offset: usize) -> Result<String> {
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&json!({"b":binding,"o":offset}))?);
    let tag = crate::digest(&serde_json::to_vec(&(
        "google-workspace-simulated-page",
        &world.service_account,
        &payload,
    ))?);
    Ok(format!("page.{payload}.{}", &tag[7..39]))
}

/// A continuation's page number and offset, for a list whose page sizes vary:
/// its binding is the query's, followed by `#` and the page it leads to.
fn google_page_cursor(
    world: &GoogleWorkspaceWorld,
    binding: &str,
    token: &str,
) -> Option<(usize, usize)> {
    let payload = token.strip_prefix("page.")?.split('.').next()?;
    let value: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()?,
    )
    .ok()?;
    let bound = value["b"].as_str()?;
    let page = bound
        .strip_prefix(binding)?
        .strip_prefix('#')?
        .parse()
        .ok()?;
    Some((page, google_page_offset(world, bound, token)?))
}

fn google_page_offset(world: &GoogleWorkspaceWorld, binding: &str, token: &str) -> Option<usize> {
    let payload = token.strip_prefix("page.")?.split('.').next()?;
    let value: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()?,
    )
    .ok()?;
    let offset = usize::try_from(value["o"].as_u64()?).ok()?;
    (value["b"] == binding && google_page_token(world, binding, offset).ok()?.as_str() == token)
        .then_some(offset)
}

/// The rank of a Calendar ACL role.
fn google_role_rank(role: &str) -> u8 {
    match role {
        "freeBusyReader" => 1,
        "reader" => 2,
        "writer" => 3,
        "owner" => 4,
        _ => 0,
    }
}

/// The highest role any rule gives `subject`, as Google resolves it: the
/// subject's own `user` rule, a `group` rule for a group it belongs to
/// (directly or nested), a `domain` rule for its domain (how organization-wide
/// sharing appears), and the `default` rule.
fn google_effective_role(
    world: &GoogleWorkspaceWorld,
    calendar: &GoogleCalendar,
    subject: &str,
) -> u8 {
    let domain = subject.rsplit_once('@').map(|(_, domain)| domain);
    calendar
        .acl
        .iter()
        .filter(
            |rule| match (rule.scope_type.as_str(), rule.scope_value.as_deref()) {
                ("user", Some(value)) => value == subject,
                ("group", Some(value)) => google_is_member(world, value, subject),
                ("domain", Some(value)) => Some(value) == domain,
                ("default", None) => true,
                _ => false,
            },
        )
        .map(|rule| google_role_rank(&rule.role))
        .max()
        .unwrap_or(0)
}

/// An ACL rule as Google reports it under the scope/role mask.
fn google_rule(rule: &GoogleAclRule) -> Value {
    let mut scope = json!({ "type": rule.scope_type });
    if let Some(value) = &rule.scope_value {
        scope["value"] = json!(value);
    }
    json!({"scope":scope,"role":rule.role})
}

/// Serve one Calendar route as the token's delegated subject. Visibility
/// follows Google: any rule that applies to the subject with `reader` or more
/// shows a calendar and its events, and reading the ACL, a rule or the whole
/// list, needs `writer` or `owner`. Free/busy access shows the calendar itself
/// and refuses its ACL with `403 forbidden`: on 2026-11-20 Google answered
/// `calendars.get` with `200` and the reader's own rule with that `403`; the
/// list's answer is assumed. Its events stay `404` (not observed: the adapter
/// never reads the events of a calendar out of play). A calendar the subject
/// cannot see at all is `404`. IDs and addresses are matched exactly, and every route
/// admits only its reviewed query.
fn google_calendar_reply(
    world: &GoogleWorkspaceWorld,
    request: &crate::google_workspace::ApiRequest,
    grant: &GoogleGrant,
) -> Result<crate::google_auth::Reply> {
    use crate::google_workspace_calendar::{
        ACL_FIELDS, ACL_PAGE_SIZE, CALENDAR_ACL_READ_SCOPE, CALENDAR_FIELDS, CALENDAR_READ_SCOPE,
        EVENT_FIELDS, EVENT_PAGE_SIZE, EVENTS_FIELDS, EVENTS_QUERY, RULE_FIELDS, rfc3339_seconds,
    };
    let reply = google_json;
    let error = google_status_error;
    let query = |name: &str| google_query(request, name);
    let segments: Vec<&str> = request.segments.iter().map(String::as_str).collect();
    let ["calendar", "v3", "calendars", calendar_id, rest @ ..] = segments.as_slice() else {
        return Ok(error(404, "Not Found"));
    };
    let compact = ("prettyPrint", "false");
    let acl_page_size = ACL_PAGE_SIZE.to_string();
    let admitted = match rest {
        [] => google_query_is(request, &[("fields", CALENDAR_FIELDS), compact], &[]),
        ["acl"] => google_query_is(
            request,
            &[
                ("maxResults", acl_page_size.as_str()),
                ("fields", ACL_FIELDS),
                compact,
            ],
            &["pageToken"],
        ),
        ["acl", _] => google_query_is(request, &[("fields", RULE_FIELDS), compact], &[]),
        ["events"] => {
            let mut fixed = EVENTS_QUERY.to_vec();
            fixed.extend([("fields", EVENTS_FIELDS), compact]);
            google_query_is(request, &fixed, &["timeMin", "timeMax", "pageToken"])
                && query("timeMin").is_some()
                && query("timeMax").is_some()
        }
        ["events", _] => google_query_is(request, &[("fields", EVENT_FIELDS), compact], &[]),
        _ => return Ok(error(404, "Not Found")),
    };
    if !admitted {
        return Ok(error(400, "Unreviewed query"));
    }
    let required = match rest {
        ["acl"] | ["acl", _] => CALENDAR_ACL_READ_SCOPE,
        _ => CALENDAR_READ_SCOPE,
    };
    if !grant.scopes.contains(required) {
        return Ok(google_error(
            403,
            "insufficientPermissions",
            "Request had insufficient authentication scopes.",
        ));
    }
    // The service account itself has no calendars: only a delegated person's
    // sharing applies.
    let not_found = error(404, "Not Found");
    let Some(subject) = grant.subject.as_deref() else {
        return Ok(not_found);
    };
    let Some(calendar) = world.calendars.get(*calendar_id) else {
        return Ok(not_found);
    };
    let role = google_effective_role(world, calendar, subject);
    let hidden = match rest {
        [] | ["acl"] | ["acl", _] => role < google_role_rank("freeBusyReader"),
        _ => role < google_role_rank("reader"),
    };
    if hidden {
        return Ok(not_found);
    }
    let can_read_acl = role >= google_role_rank("writer");
    Ok(match rest {
        [] => reply(200, json!({"id":calendar_id,"summary":calendar.summary})),
        ["acl", rule_id] => {
            if !can_read_acl {
                return Ok(error(403, "Forbidden"));
            }
            match calendar.acl.iter().find(|rule| {
                *rule_id
                    == match &rule.scope_value {
                        Some(value) => format!("{}:{value}", rule.scope_type),
                        None => rule.scope_type.clone(),
                    }
            }) {
                Some(rule) => reply(200, google_rule(rule)),
                None => not_found,
            }
        }
        ["acl"] => {
            if !can_read_acl {
                return Ok(error(403, "Forbidden"));
            }
            let size = ACL_PAGE_SIZE as usize;
            let binding = format!("acl:{calendar_id}");
            let offset = match query("pageToken") {
                None => 0,
                Some(token) => match google_page_offset(world, &binding, token) {
                    Some(offset) => offset,
                    None => return Ok(error(400, "Invalid page token value")),
                },
            };
            let items: Vec<Value> = calendar
                .acl
                .iter()
                .skip(offset)
                .take(size)
                .map(google_rule)
                .collect();
            let mut body = json!({ "items": items });
            if offset + size < calendar.acl.len() {
                body["nextPageToken"] = json!(google_page_token(world, &binding, offset + size)?);
            }
            reply(200, body)
        }
        ["events"] => {
            let bound = |name: &str| query(name).and_then(rfc3339_seconds);
            let (Some(time_min), Some(time_max)) = (bound("timeMin"), bound("timeMax")) else {
                return Ok(error(400, "Bad Request"));
            };
            let size = EVENT_PAGE_SIZE as usize;
            // Google does not bind an events token to its window: given
            // another window's token it answered an empty page (observed
            // 2026-11-20). This models that as the token's position applied
            // to the new window; only the calendar is bound.
            let binding = format!("events:{calendar_id}");
            let offset = match query("pageToken") {
                None => 0,
                Some(token) => match google_page_offset(world, &binding, token) {
                    Some(offset) => offset,
                    None => return Ok(error(400, "Invalid page token value")),
                },
            };
            // An event overlaps the window: it ends after timeMin and starts
            // before timeMax, ordered by start; cancelled events are shown.
            let mut selected: Vec<(i64, &GoogleEvent)> = calendar
                .events
                .iter()
                .filter_map(|event| {
                    let (start, end) = event.span()?;
                    (end > time_min && start < time_max).then_some((start, event))
                })
                .collect();
            selected.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.id.cmp(&right.1.id)));
            let items: Vec<Value> = selected
                .iter()
                .skip(offset)
                .take(size)
                .map(|(_, event)| event.wire())
                .collect();
            let mut body = json!({ "items": items });
            if offset + size < selected.len() {
                body["nextPageToken"] = json!(google_page_token(world, &binding, offset + size)?);
            }
            reply(200, body)
        }
        ["events", event_id] => match calendar.events.iter().find(|event| event.id == *event_id) {
            Some(event) => reply(200, event.wire()),
            None => not_found,
        },
        _ => not_found,
    })
}

/// Scenario changes affect later Google requests through the same world.
pub fn update_google_workspace<T>(
    database: &Path,
    scope: &str,
    act: impl FnOnce(&mut World<GoogleWorkspaceWorld>) -> Result<T>,
) -> Result<T> {
    with_world(&database.with_file_name(GOOGLE_WORKSPACE_WORLD), scope, act)
}

fn write_world<W: Serialize>(
    connection: &rusqlite::Connection,
    scope: &str,
    state: &World<W>,
) -> Result<()> {
    let encoded = serde_json::to_string(state)?;
    ensure!(
        encoded.len() <= MAX_WORLD_BYTES,
        "simulated_provider_world_budget"
    );
    connection.execute(
        "INSERT INTO simulated_provider VALUES(?1,?2) ON CONFLICT(scope) DO UPDATE SET state=excluded.state",
        params![scope, encoded],
    )?;
    Ok(())
}

fn with_world<W, T, F>(path: &Path, scope: &str, act: F) -> Result<T>
where
    W: Serialize + serde::de::DeserializeOwned,
    F: FnOnce(&mut World<W>) -> Result<T>,
{
    ensure!(path.is_file(), "simulated_provider_unconfigured");
    let mut connection = crate::store::open(path)?;
    let tx = crate::write_queue::immediate(&mut connection)?;
    upgrade(&tx)?;
    let mut state: World<W> = read_world(&tx, scope)?;
    let result = act(&mut state)?;
    write_world(&tx, scope, &state)?;
    tx.commit()?;
    Ok(result)
}

/// Remove one queued fault matching this endpoint, if any.
fn take_fault<W>(state: &mut World<W>, endpoint: Endpoint) -> Option<SimulatedFault> {
    take_fault_named(state, endpoint.name())
}

fn take_fault_named<W>(state: &mut World<W>, endpoint: &str) -> Option<SimulatedFault> {
    let index = state
        .faults
        .iter()
        .position(|fault| fault.endpoint.is_empty() || fault.endpoint == endpoint)?;
    let fault = state.faults[index].fault;
    state.faults[index].remaining = state.faults[index].remaining.saturating_sub(1);
    if state.faults[index].remaining == 0 {
        state.faults.remove(index);
    }
    Some(fault)
}

/// A fault that the adapter must classify without seeing a well-formed body.
fn fault_response(
    fault: SimulatedFault,
    max_response_bytes: u64,
) -> Option<std::result::Result<WireResponse, TransportError>> {
    let http = |status: u16| {
        Some(Ok(WireResponse {
            status,
            json_content_type: true,
            body: json!({"ok":false,"error":"simulated"})
                .to_string()
                .into_bytes(),
            request_id: Some("req_simulated".into()),
            metadata: vec![],
        }))
    };
    match fault {
        SimulatedFault::RateLimited => http(429),
        SimulatedFault::Denied => http(403),
        SimulatedFault::BadRequest => http(400),
        SimulatedFault::RateLimitForbidden => http(403),
        SimulatedFault::Gone => http(404),
        SimulatedFault::Conflict => http(409),
        SimulatedFault::ServerError => http(500),
        SimulatedFault::ConnectionLost | SimulatedFault::ReplyLost => Some(Err(TransportError {
            kind: AdapterError::TransportUnavailable,
            response_bytes: 0,
            http_status: None,
            request_id: None,
        })),
        SimulatedFault::NotJson => Some(Ok(WireResponse {
            status: 200,
            json_content_type: false,
            body: b"not json".to_vec(),
            request_id: None,
            metadata: vec![],
        })),
        SimulatedFault::Oversized => Some(Ok(WireResponse {
            status: 200,
            json_content_type: true,
            // One byte past the admitted budget, so `transmit` rejects it on the
            // real path rather than the simulation pre-empting the decision.
            body: vec![b'x'; usize::try_from(max_response_bytes).unwrap_or(usize::MAX) + 1],
            request_id: None,
            metadata: vec![],
        })),
        // Body-level faults are provider-specific and built alongside the reply.
        SimulatedFault::Rejected
        | SimulatedFault::Partitioned
        | SimulatedFault::TokenOverrun
        | SimulatedFault::Refused => None,
    }
}

fn json_response(value: &Value) -> WireResponse {
    WireResponse {
        status: 200,
        json_content_type: true,
        body: value.to_string().into_bytes(),
        request_id: Some("req_simulated".into()),
        metadata: vec![],
    }
}

/// A world that cannot answer reports the provider as unreachable. That is a
/// real offline state rather than a swallowed bug: the reason is kept on the
/// transport (see `detail`) so a misconfigured fixture stays diagnosable, and
/// the adapter is told only what a lost connection would have told it.
fn unreachable_provider() -> TransportError {
    TransportError {
        kind: AdapterError::TransportUnavailable,
        response_bytes: 0,
        http_status: None,
        request_id: None,
    }
}

impl Transport for SimulatedTransport {
    fn send(
        &self,
        request: &WireRequest,
        authorization: super::Authorization<'_>,
        max_response_bytes: u64,
    ) -> std::result::Result<WireResponse, TransportError> {
        // Authorization is resolved and passed exactly as the live path does, so an
        // adapter that forgot to require one still fails offline. A presigned
        // request legitimately carries no credential — its authorization is in the
        // URL — so the arm is accepted rather than treated as a missing one.
        let _ = authorization;
        let Some(endpoint) = Endpoint::classify(&request.url) else {
            self.record("unroutable request url");
            return Err(unreachable_provider());
        };
        let path = self.path(endpoint.world());
        let result = match endpoint {
            Endpoint::SlackWebhook => {
                with_world::<SlackWebhookWorld, _, _>(&path, &self.scope, |state| {
                    serve_slack_webhook(state, request, max_response_bytes)
                })
            }
            Endpoint::SlackIdentity | Endpoint::SlackHistory | Endpoint::SlackPost => {
                with_world::<SlackWorld, _, _>(&path, &self.scope, |state| {
                    serve_slack(state, endpoint, request, max_response_bytes)
                })
            }
            Endpoint::SnowflakeStatement => {
                with_world::<SnowflakeWorld, _, _>(&path, &self.scope, |state| {
                    serve_snowflake(state, request, max_response_bytes)
                })
            }
            Endpoint::OpenAiResponses => {
                with_world::<OpenAiWorld, _, _>(&path, &self.scope, |state| {
                    serve_openai(state, request, max_response_bytes)
                })
            }
            Endpoint::ObjectStore => {
                with_world::<ObjectStoreWorld, _, _>(&path, &self.scope, |state| {
                    serve_object_store(state, request)
                })
            }
            Endpoint::GiteaActions => {
                with_world::<GiteaActionsWorld, _, _>(&path, &self.scope, |state| {
                    state.calls.push(endpoint.name().into());
                    ensure!(state.calls.len() <= MAX_MESSAGES, "simulated_call_budget");
                    let route = request
                        .url
                        .strip_prefix(&state.world.origin)
                        .ok_or_else(|| anyhow::anyhow!("simulated_gitea_origin_mismatch"))?;
                    ensure!(route.starts_with("/api/v1/"), "simulated_gitea_api_path");
                    Ok(Ok(if let Some(value) = state.world.responses.get(route) {
                        json_response(value)
                    } else if let Some(log) = state.world.logs.get(route) {
                        WireResponse {
                            status: 200,
                            json_content_type: false,
                            body: log.as_bytes().to_vec(),
                            request_id: None,
                            metadata: vec![],
                        }
                    } else {
                        WireResponse {
                            status: 404,
                            json_content_type: true,
                            body: b"{}".to_vec(),
                            request_id: None,
                            metadata: vec![],
                        }
                    }))
                })
            }
            Endpoint::GitHubJobStatus | Endpoint::GitHubJobLogs => {
                with_world::<GitHubActionsWorld, _, _>(&path, &self.scope, |state| {
                    serve_github_actions(state, endpoint, request)
                })
            }
            Endpoint::LinearGraphQL => {
                with_world::<LinearWorkWorld, _, _>(&path, &self.scope, |state| {
                    serve_linear_work(state, request, max_response_bytes)
                })
            }
        };
        match result {
            Ok(response) => response,
            Err(error) => {
                self.record(format!("{endpoint:?}: {error:#}"));
                Err(unreachable_provider())
            }
        }
    }
}

impl SimulatedTransport {
    fn record(&self, detail: impl Into<String>) {
        let mut log = self.fault_detail.lock().unwrap();
        if log.len() < MAX_FAULTS {
            log.push(detail.into());
        }
    }
}

type Served = std::result::Result<WireResponse, TransportError>;

/// Serve one GitHub Actions request against the simulated repository.
///
/// The job id is read back out of the URL the adapter built, rather than from a
/// parallel field, so an adapter that assembled the wrong path is visible here
/// instead of only against the real API.
fn serve_github_actions(
    state: &mut World<GitHubActionsWorld>,
    endpoint: Endpoint,
    request: &WireRequest,
) -> Result<Served> {
    state.calls.push(endpoint.name().into());
    ensure!(state.calls.len() <= MAX_MESSAGES, "simulated_call_budget");
    let path = request
        .url
        .split_once('?')
        .map_or(&request.url[..], |(base, _)| base);
    let trimmed = path.strip_suffix("/logs").unwrap_or(path);
    let job_id = trimmed.rsplit('/').next().unwrap_or_default().to_owned();
    // The grant fixes the repository, so a request for another one is a bug in
    // the adapter rather than something to answer.
    ensure!(
        path.contains(&format!(
            "/repos/{}/{}/",
            state.world.owner, state.world.repo
        )),
        "simulated_github_repository_mismatch"
    );
    let job = state
        .world
        .jobs
        .iter()
        .find(|job| job.id == job_id)
        .cloned();
    Ok(Ok(match (endpoint, job) {
        (Endpoint::GitHubJobStatus, Some(job)) => json_response(&json!({
            "id": job.id,
            "name": job.name,
            "status": job.status,
            "conclusion": job.conclusion,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "html_url": format!(
                "https://github.test/{}/{}/runs/{}",
                state.world.owner, state.world.repo, job.id
            ),
        })),
        (Endpoint::GitHubJobLogs, Some(job)) if !job.log_url.is_empty() => WireResponse {
            // A redirect, because that is what GitHub answers with and what the
            // adapter reads. Returning the log inline would be simulating an
            // API nobody has.
            status: 302,
            json_content_type: false,
            body: vec![],
            request_id: None,
            metadata: vec![("location", job.log_url.clone())],
        },
        // A job GitHub does not know about, or one with no log yet.
        _ => WireResponse {
            status: 404,
            json_content_type: false,
            body: vec![],
            request_id: None,
            metadata: vec![],
        },
    }))
}

/// Serve one Linear GraphQL request against the simulated workspace.
///
/// The operation is read from the query document the adapter built, so the
/// simulation answers whatever the adapter actually asked rather than a
/// parallel notion of what it should have asked. An unrecognised operation is
/// refused: a simulation that guessed would hide a query the real API rejects.
fn serve_linear_work(
    state: &mut World<LinearWorkWorld>,
    request: &WireRequest,
    max_response_bytes: u64,
) -> Result<Served> {
    state.calls.push("graphql".into());
    ensure!(state.calls.len() <= MAX_MESSAGES, "simulated_call_budget");
    let body: Value =
        serde_json::from_slice(&request.body).context("simulated_linear_request_invalid")?;
    let query = body
        .get("query")
        .and_then(Value::as_str)
        .context("simulated_linear_query_missing")?;
    let variable = |name: &str| -> String {
        body.get("variables")
            .and_then(|variables| variables.get(name))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let person = |id: &str, name: &str, email: &str| json!({ "id": id, "name": name, "displayName": name, "email": email });
    let issue_node = |issue: &LinearIssue| {
        json!({
            "id": issue.id,
            "identifier": issue.identifier,
            "title": issue.title,
            "url": issue.url,
            "dueDate": issue.due_date,
            "priority": 0,
            "priorityLabel": "",
            "createdAt": issue.created_at,
            "updatedAt": issue.updated_at,
            "state": { "name": issue.state_name, "type": issue.state_type },
            "assignee": if issue.assignee_id.is_empty() {
                Value::Null
            } else {
                person(&issue.assignee_id, &issue.assignee_name, "")
            },
            "parent": Value::Null,
            "project": Value::Null,
            "team": { "key": "TEAM", "name": state.world.team_name },
            "labels": { "nodes": issue.labels.iter()
                .map(|label| json!({"name": label, "color": ""}))
                .collect::<Vec<_>>() },
            "attachments": { "nodes": [] },
        })
    };
    let data = if query.contains("Day2ViewIssues") || query.contains("Day2LabelIssues") {
        // Which issues a grant sees is decided by the grant's own source, so the
        // simulation filters the same way the real API would.
        let matching: Vec<Value> = if query.contains("Day2ViewIssues") {
            let view = variable("viewId");
            state
                .world
                .issues
                .iter()
                .filter(|issue| issue.view_ids.contains(&view))
                .map(&issue_node)
                .collect()
        } else {
            let label = variable("labelName");
            state
                .world
                .issues
                .iter()
                .filter(|issue| issue.labels.contains(&label))
                .map(&issue_node)
                .collect()
        };
        let connection = json!({
            "nodes": matching,
            "pageInfo": { "hasNextPage": false, "endCursor": "" },
        });
        if query.contains("Day2ViewIssues") {
            json!({ "customView": { "id": variable("viewId"), "name": "view",
                "issues": connection } })
        } else {
            json!({ "issues": connection })
        }
    } else if query.contains("Day2IssueDetail") {
        let id = variable("issueId");
        let issue = state.world.issues.iter().find(|issue| issue.id == id);
        json!({ "issue": issue.map(|issue| json!({
            "description": issue.title,
            "comments": { "nodes": [] },
            "history": { "nodes": [] },
        })) })
    } else if query.contains("Day2IssueAssignees") {
        let id = variable("issueId");
        let issue = state.world.issues.iter().find(|issue| issue.id == id);
        json!({ "issue": issue.map(|issue| json!({
            "id": issue.id,
            "assignee": if issue.assignee_id.is_empty() {
                Value::Null
            } else {
                json!({ "id": issue.assignee_id })
            },
            "team": {
                "id": "team",
                "name": state.world.team_name,
                "members": { "nodes": state.world.members.iter()
                    .map(|member| json!({
                        "id": member.id, "name": member.name,
                        "displayName": member.name, "email": member.email,
                        "active": true,
                    }))
                    .collect::<Vec<_>>() },
            },
        })) })
    } else if query.contains("Day2IssueReassign") {
        let id = variable("issueId");
        let assignee = body
            .get("variables")
            .and_then(|variables| variables.get("assigneeId"))
            .cloned()
            .unwrap_or(Value::Null);
        let name = assignee
            .as_str()
            .and_then(|id| state.world.members.iter().find(|member| member.id == id))
            .map(|member| member.name.clone())
            .unwrap_or_default();
        let mut updated = None;
        for issue in &mut state.world.issues {
            if issue.id == id {
                // An explicit null clears the owner, which is the operation the
                // adapter distinguishes from omitting the field entirely.
                issue.assignee_id = assignee.as_str().unwrap_or_default().to_owned();
                issue.assignee_name = name.clone();
                updated = Some(issue.assignee_id.clone());
            }
        }
        match updated {
            Some(assignee_id) => json!({ "issueUpdate": {
                "success": true,
                "issue": { "id": id, "assignee": if assignee_id.is_empty() {
                    Value::Null
                } else {
                    person(&assignee_id, &name, "")
                } },
            } }),
            // Refusing an unknown issue is what the real API does, and it is what
            // stops a reassignment of an untracked issue looking like a success.
            None => json!({ "issueUpdate": { "success": false, "issue": Value::Null } }),
        }
    } else {
        bail!("simulated_linear_operation_unsupported");
    };
    let reply = json_response(&json!({ "data": data }));
    ensure!(
        reply.body.len() as u64 <= max_response_bytes,
        "simulated_linear_response_too_large"
    );
    Ok(Ok(reply))
}

/// Serve one presigned object request against the simulated store.
///
/// Only HEAD and DELETE arrive here. The two grant capabilities never reach a
/// transport at all — they are a signature over the key and the clock — so a
/// simulation that answered them would be simulating something the platform does
/// not do.
fn serve_object_store(
    state: &mut World<ObjectStoreWorld>,
    request: &WireRequest,
) -> Result<Served> {
    state.calls.push("object".into());
    ensure!(state.calls.len() <= MAX_MESSAGES, "simulated_call_budget");
    // Virtual-hosted addressing, matching what the signer builds: the bucket is in
    // the host and the key is the path. Reading the key back from the signed URL
    // rather than from a parallel field is what makes a signer that signs the wrong
    // object visible here instead of only against the real store.
    let path = request.url.split_once('?').map_or("", |(base, _)| base);
    let key = path
        .strip_prefix("https://")
        .and_then(|rest| rest.split_once('/'))
        .map(|(_, key)| decode_key(key))
        .unwrap_or_default();
    ensure!(!key.is_empty(), "simulated_object_key_missing");
    let response = |status: u16, metadata: Vec<(&'static str, String)>| WireResponse {
        status,
        json_content_type: false,
        body: vec![],
        request_id: None,
        metadata,
    };
    Ok(Ok(match request.method {
        Method::Head => match state.world.objects.get(&key) {
            Some(object) => response(
                200,
                vec![
                    ("content-length", object.size.to_string()),
                    ("etag", object.etag.clone()),
                ],
            ),
            None => response(404, vec![]),
        },
        // Idempotent, as S3 is: removing a key that was never there is the same
        // answer as removing one that was.
        Method::Delete => {
            state.world.objects.remove(&key);
            response(204, vec![])
        }
        _ => bail!("simulated_object_method_unsupported"),
    }))
}

/// Percent-decoding for the object key the signer encoded.
fn decode_key(encoded: &str) -> String {
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%'
            && at + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(&encoded[at + 1..at + 3], 16)
        {
            out.push(byte);
            at += 3;
            continue;
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

fn serve_slack_webhook(
    state: &mut World<SlackWebhookWorld>,
    request: &WireRequest,
    limit: u64,
) -> Result<Served> {
    let endpoint = Endpoint::SlackWebhook;
    state.calls.push(endpoint.name().into());
    ensure!(state.calls.len() <= MAX_MESSAGES, "simulated_call_budget");
    let fault = take_fault(state, endpoint);
    if let Some(response) = fault.and_then(|fault| fault_response(fault, limit)) {
        return Ok(response);
    }
    let denied = fault == Some(SimulatedFault::Rejected)
        || state.world.archived
        || state.world.endpoint_sha256 != slack_webhook_digest();
    if !denied {
        let body: Value = serde_json::from_slice(&request.body)?;
        ensure!(
            body.get("channel").is_none(),
            "simulated_webhook_channel_override"
        );
        let text = body
            .pointer("/blocks/0/text/text")
            .and_then(Value::as_str)
            .context("simulated_webhook_text")?;
        state.world.messages.push(text.into());
        ensure!(
            state.world.messages.len() <= MAX_MESSAGES,
            "simulated_slack_message_budget"
        );
    }
    Ok(Ok(WireResponse {
        status: if denied { 403 } else { 200 },
        json_content_type: false,
        body: if denied {
            b"action_prohibited".to_vec()
        } else {
            b"ok".to_vec()
        },
        request_id: None,
        metadata: vec![],
    }))
}

fn serve_slack(
    state: &mut World<SlackWorld>,
    endpoint: Endpoint,
    request: &WireRequest,
    max_response_bytes: u64,
) -> Result<Served> {
    state.calls.push(endpoint.name().into());
    ensure!(state.calls.len() <= MAX_MESSAGES, "simulated_call_budget");
    let fault = take_fault(state, endpoint);
    if let Some(response) = fault.and_then(|fault| fault_response(fault, max_response_bytes)) {
        return Ok(response);
    }
    let rejected = fault == Some(SimulatedFault::Rejected);
    Ok(Ok(json_response(&match endpoint {
        Endpoint::SlackIdentity => {
            if rejected {
                json!({"ok":false,"error":"invalid_auth"})
            } else {
                json!({"ok":true,"team_id":state.world.workspace_id})
            }
        }
        Endpoint::SlackHistory => {
            let (channel, limit) = slack_history_query(&request.url)?;
            if rejected {
                json!({"ok":false,"error":"channel_not_found"})
            } else {
                let Some(world) = state.world.channels.get(&channel) else {
                    return Ok(Ok(json_response(
                        &json!({"ok":false,"error":"channel_not_found"}),
                    )));
                };
                // Newest first, as the provider returns history.
                let total = world.messages.len();
                let page: Vec<_> = world
                    .messages
                    .iter()
                    .rev()
                    .take(usize::from(limit))
                    .map(|message| {
                        json!({"type":"message","text":message.text,"ts":message.timestamp})
                    })
                    .collect();
                json!({"ok":true,"messages":page,"has_more":total > usize::from(limit)})
            }
        }
        Endpoint::SlackPost => {
            let body: Value = serde_json::from_slice(&request.body)?;
            let channel = body
                .get("channel")
                .and_then(Value::as_str)
                .context("simulated_slack_channel")?
                .to_owned();
            let text = body
                .get("text")
                .and_then(Value::as_str)
                .context("simulated_slack_text")?
                .to_owned();
            if rejected {
                json!({"ok":false,"error":"not_in_channel"})
            } else {
                match state.world.channels.get(&channel) {
                    None => {
                        return Ok(Ok(json_response(
                            &json!({"ok":false,"error":"channel_not_found"}),
                        )));
                    }
                    Some(world) if world.archived => {
                        return Ok(Ok(json_response(
                            &json!({"ok":false,"error":"is_archived"}),
                        )));
                    }
                    Some(_) => {}
                }
                // The counter advances before the channel is borrowed again, so
                // timestamps stay unique across every channel in the workspace.
                state.world.sequence += 1;
                let timestamp = format!("{}.{:06}", 1_700_000_000 + state.world.sequence, 0);
                let world = state
                    .world
                    .channels
                    .get_mut(&channel)
                    .context("simulated_slack_channel")?;
                world.messages.push(SlackMessage {
                    text,
                    timestamp: timestamp.clone(),
                });
                ensure!(
                    world.messages.len() <= MAX_MESSAGES,
                    "simulated_slack_channel_budget"
                );
                json!({"ok":true,"channel":channel,"ts":timestamp})
            }
        }
        _ => anyhow::bail!("simulated_slack_endpoint"),
    })))
}

fn slack_history_query(url: &str) -> Result<(String, u16)> {
    let query = url.split_once('?').context("simulated_slack_query")?.1;
    let mut channel = None;
    let mut limit = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "channel" => channel = Some(value.into_owned()),
            "limit" => limit = Some(value.parse::<u16>()?),
            _ => {}
        }
    }
    Ok((
        channel.context("simulated_slack_channel")?,
        limit.context("simulated_slack_limit")?,
    ))
}

fn serve_snowflake(
    state: &mut World<SnowflakeWorld>,
    request: &WireRequest,
    max_response_bytes: u64,
) -> Result<Served> {
    state.calls.push(Endpoint::SnowflakeStatement.name().into());
    ensure!(state.calls.len() <= MAX_ROWS, "simulated_call_budget");
    let fault = take_fault(state, Endpoint::SnowflakeStatement);
    if let Some(response) = fault.and_then(|fault| fault_response(fault, max_response_bytes)) {
        return Ok(response);
    }
    let body: Value = serde_json::from_slice(&request.body)?;
    let statement = body
        .get("statement")
        .and_then(Value::as_str)
        .context("simulated_snowflake_statement")?;
    let query = parse_select(statement)?;
    let Some(view) = state.world.views.get(&format!(
        "{}.{}.{}",
        query.database, query.schema, query.view
    )) else {
        // An unknown view is a provider-side error, not a malformed response.
        return Ok(Ok(json_response(
            &json!({"code":"002003","message":"simulated unknown view"}),
        )));
    };
    let bindings = body
        .get("bindings")
        .context("simulated_snowflake_bindings")?;
    let indices: Vec<usize> = query
        .columns
        .iter()
        .map(|name| {
            view.columns
                .iter()
                .position(|column| column == name)
                .context("simulated_snowflake_column")
        })
        .collect::<Result<_>>()?;
    let mut rows = Vec::new();
    for row in &view.rows {
        ensure!(row.len() == view.columns.len(), "simulated_snowflake_row");
        let matched = query.filters.iter().enumerate().all(|(index, column)| {
            let expected = bindings
                .get((index + 1).to_string())
                .and_then(|binding| binding.get("value"))
                .and_then(Value::as_str);
            view.columns
                .iter()
                .position(|candidate| candidate == column)
                .and_then(|position| row[position].as_deref())
                == expected
        });
        if !matched {
            continue;
        }
        rows.push(Value::Array(
            indices
                .iter()
                .map(|index| match &row[*index] {
                    Some(value) => Value::String(value.clone()),
                    None => Value::Null,
                })
                .collect(),
        ));
        // The adapter asks for one row past its ceiling so it can detect an
        // incomplete result; serving more than that is never useful.
        if rows.len() as u64 >= query.limit {
            break;
        }
    }
    let count = rows.len() as u64;
    let row_type: Vec<Value> = query
        .columns
        .iter()
        .map(|name| json!({"name":name}))
        .collect();
    let partitions = if fault == Some(SimulatedFault::Partitioned) {
        // A split result the adapter must refuse rather than follow.
        json!([{"rowCount":count},{"rowCount":1}])
    } else {
        json!([{"rowCount":count}])
    };
    Ok(Ok(json_response(&json!({
        "code":"090001",
        "resultSetMetaData":{"numRows":count,"format":"jsonv2","rowType":row_type,"partitionInfo":partitions},
        "data":rows,
    }))))
}

struct Select {
    columns: Vec<String>,
    database: String,
    schema: String,
    view: String,
    filters: Vec<String>,
    limit: u64,
}

/// A deliberately strict reader for the one statement shape the adapter builds.
/// Anything else fails loudly: if the generated SQL drifts, the simulation stops
/// answering instead of quietly serving a query the live provider would reject.
fn parse_select(statement: &str) -> Result<Select> {
    let rest = statement
        .strip_prefix("SELECT ")
        .context("simulated_snowflake_select")?;
    let (columns, rest) = rest
        .split_once(" FROM ")
        .context("simulated_snowflake_from")?;
    let columns = columns
        .split(", ")
        .map(unquote)
        .collect::<Result<Vec<_>>>()?;
    // `LIMIT` always terminates the generated statement, so it comes off first.
    let (rest, limit) = rest
        .rsplit_once(" LIMIT ")
        .context("simulated_snowflake_limit")?;
    let (source, predicates) = match rest.split_once(" WHERE ") {
        Some((source, predicates)) => (source, predicates),
        None => (rest, ""),
    };
    let parts = source.split('.').collect::<Vec<_>>();
    ensure!(parts.len() == 3, "simulated_snowflake_source");
    let filters = if predicates.is_empty() {
        Vec::new()
    } else {
        predicates
            .split(" AND ")
            .map(|predicate| {
                unquote(
                    predicate
                        .strip_suffix(" = ?")
                        .context("simulated_snowflake_predicate")?,
                )
            })
            .collect::<Result<Vec<_>>>()?
    };
    Ok(Select {
        columns,
        database: unquote(parts[0])?,
        schema: unquote(parts[1])?,
        view: unquote(parts[2])?,
        filters,
        limit: limit.parse()?,
    })
}

fn unquote(identifier: &str) -> Result<String> {
    let inner = identifier
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .context("simulated_snowflake_identifier")?;
    ensure!(
        !inner.contains('"') || inner.contains("\"\""),
        "simulated_snowflake_identifier"
    );
    Ok(inner.replace("\"\"", "\""))
}

fn serve_openai(
    state: &mut World<OpenAiWorld>,
    request: &WireRequest,
    max_response_bytes: u64,
) -> Result<Served> {
    state.calls.push(Endpoint::OpenAiResponses.name().into());
    ensure!(state.calls.len() <= MAX_ROWS, "simulated_call_budget");
    let fault = take_fault(state, Endpoint::OpenAiResponses);
    if let Some(response) = fault.and_then(|fault| fault_response(fault, max_response_bytes)) {
        return Ok(response);
    }
    let body: Value = serde_json::from_slice(&request.body)?;
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .context("simulated_openai_model")?;
    if model != state.world.model {
        // A model the simulated account does not serve, as the live API reports it.
        return Ok(Ok(WireResponse {
            status: 404,
            json_content_type: true,
            body: json!({"error":{"type":"invalid_request_error"}})
                .to_string()
                .into_bytes(),
            request_id: Some("req_simulated".into()),
            metadata: vec![],
        }));
    }
    let input = body
        .get("input")
        .and_then(Value::as_str)
        .context("simulated_openai_input")?;
    let requested = body
        .get("max_output_tokens")
        .and_then(Value::as_u64)
        .context("simulated_openai_max_output_tokens")?;
    // Deterministic and input-sensitive: the same prompt always produces the same
    // completion, and different prompts do not. A simulation that returned a
    // constant would satisfy the mandate while proving nothing.
    let digest = crate::digest(input.as_bytes());
    let text = format!("simulated completion {}", &digest[7..39]);
    let input_tokens = ((input.len() as u64).div_ceil(4))
        .min(state.world.max_input_tokens)
        .max(1);
    let output_tokens = if fault == Some(SimulatedFault::TokenOverrun) {
        // Past the admitted ceiling: usage is trustworthy, the content is not.
        requested.saturating_add(1)
    } else {
        ((text.len() as u64).div_ceil(4)).min(requested).max(1)
    };
    let content = if fault == Some(SimulatedFault::Refused) {
        json!([{"type":"refusal","refusal":"simulated refusal"}])
    } else {
        json!([{"type":"output_text","text":text}])
    };
    Ok(Ok(json_response(&json!({
        "model":model,
        "status":"completed",
        "store":false,
        "background":false,
        "service_tier":"default",
        "tools":[],
        "output":[{"type":"message","role":"assistant","status":"completed","content":content}],
        "usage":{"input_tokens":input_tokens,"output_tokens":output_tokens,
            "total_tokens":input_tokens + output_tokens},
    }))))
}

#[cfg(test)]
#[path = "simulated_tests.rs"]
mod tests;
