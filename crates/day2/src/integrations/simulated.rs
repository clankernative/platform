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
    AdapterError, CredentialResolver, Credentials, Transport, TransportError, WireRequest,
    WireResponse, slack,
};
use anyhow::{Context, Result, bail, ensure};
use day2_capabilities::{integrations::LiveConnection, resources::Provider};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
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
        if !self.available {
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
    seed_world(database, scope, DELEGATION_WORLD, &fixture.delegation)
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
    let index = state
        .faults
        .iter()
        .position(|fault| fault.endpoint.is_empty() || fault.endpoint == endpoint.name())?;
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
        SimulatedFault::ServerError => http(500),
        SimulatedFault::ConnectionLost => Some(Err(TransportError {
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
        super::Method::Head => match state.world.objects.get(&key) {
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
        super::Method::Delete => {
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
