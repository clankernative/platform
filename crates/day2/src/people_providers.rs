//! Explicit synthetic Google, Linear and fixed-destination alert providers.
//! Each provider commits to its own SQLite database. This is executable provider
//! semantics for conformance, not a live connector or a cross-provider workflow.
use crate::{protocol::Instruction, store::Runtime};
use anyhow::{Context, Result, ensure};
use day2_capabilities::resources::{Provider, ResourceTarget, email_in_domain, path_is_within};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub const MAX_RECORDS: usize = 10_000;
pub const MAX_RECORD_BYTES: usize = 16_384;
const MAX_WORLD_BYTES: usize = 32 * 1_048_576;
const MAX_CALLS: usize = 100_000;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum OptionalText {
    #[default]
    None,
    Some(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectoryUser {
    pub id: String,
    pub primary_email: String,
    pub given_name: String,
    pub family_name: String,
    pub full_name: String,
    pub org_unit_path: String,
    pub thumbnail_photo_url: OptionalText,
    pub suspended: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectoryGroup {
    pub id: String,
    pub email: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OrgUnit {
    pub id: String,
    pub path: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DirectoryRecord {
    User(DirectoryUser),
    Group(DirectoryGroup),
    OrgUnit(OrgUnit),
}

impl DirectoryRecord {
    fn envelope(&self) -> Result<String> {
        let value = serde_json::to_value(self)?;
        let result =
            json!({"kind":value["kind"],"data":serde_json::to_string(&value["data"])?}).to_string();
        ensure!(
            result.len() <= MAX_RECORD_BYTES,
            "google_directory_record_budget"
        );
        Ok(result)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GoogleAccount {
    pub user: DirectoryUser,
    pub personal_email: String,
    pub start_date: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GoogleWorld {
    pub users: BTreeMap<String, GoogleAccount>,
    pub groups: BTreeMap<String, DirectoryGroup>,
    pub org_units: Vec<OrgUnit>,
    pub memberships: BTreeMap<String, BTreeSet<String>>,
    pub captures: BTreeMap<String, Vec<DirectoryRecord>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinearUser {
    pub id: String,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub id: String,
    pub email: String,
    pub accepted: bool,
    pub expired: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinearWorld {
    pub enabled: bool,
    pub users: BTreeMap<String, LinearUser>,
    pub invitations: Vec<Invitation>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Alert {
    pub id: String,
    pub topic: String,
    pub body: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AlertWorld {
    pub enabled: bool,
    pub messages: Vec<Alert>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Problem {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FailureMode {
    Definite {
        code: String,
        message: String,
        retryable: bool,
    },
    /// Models PATCH acceptance followed by a mismatching verification response.
    /// The provider mutation remains even though the business outcome is Failed.
    PatchVerificationMismatch,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScheduledFailure {
    pub capability: String,
    /// Normalized email for directory/Linear, alert topic; empty matches any.
    pub subject: String,
    pub remaining: u32,
    pub mode: FailureMode,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    pub capability: String,
    pub payload: Value,
    pub result: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderCall {
    pub effect_id: String,
    pub capability: String,
    pub replayed: bool,
    pub changed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderState<W> {
    pub world: W,
    pub ledger: BTreeMap<String, LedgerEntry>,
    pub calls: Vec<ProviderCall>,
    pub faults: Vec<ScheduledFailure>,
}

impl<W> ProviderState<W> {
    fn new(world: W) -> Self {
        Self {
            world,
            ledger: BTreeMap::new(),
            calls: Vec::new(),
            faults: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyntheticFixture {
    pub customer_id: String,
    pub google: GoogleWorld,
    pub organization_id: String,
    pub linear: LinearWorld,
    pub destination: String,
    pub alerts: AlertWorld,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyntheticProvider {
    GoogleDirectory,
    Linear,
    OperatorAlerts,
}

impl SyntheticProvider {
    fn database(self) -> &'static str {
        match self {
            Self::GoogleDirectory => "google_directory.synthetic.sqlite",
            Self::Linear => "linear.synthetic.sqlite",
            Self::OperatorAlerts => "operator_alerts.synthetic.sqlite",
        }
    }
    fn permits(self, capability: &str) -> bool {
        match self {
            Self::GoogleDirectory => [
                "google_directory.create_user.v1",
                "google_directory.patch_attributes.v1",
                "google_directory.ensure_group_member.v1",
            ]
            .contains(&capability),
            Self::Linear => ["linear.ensure_access.v1", "linear.suspend.v1"].contains(&capability),
            Self::OperatorAlerts => capability == "operator_alerts.send.v1",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CreateUser {
    pub given_name: String,
    pub family_name: String,
    pub primary_email: String,
    pub personal_email: String,
    pub org_unit_path: String,
    pub start_date: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Attribute {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PatchAttributes {
    pub primary_email: String,
    pub attributes: Vec<Attribute>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnsureGroup {
    pub primary_email: String,
    pub group: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WithInput<T> {
    #[serde(rename = "handle")]
    _handle: String,
    input: T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Handle {
    #[serde(rename = "handle")]
    _handle: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Next {
    #[serde(rename = "handle")]
    _handle: String,
    snapshot_id: String,
    cursor: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Email {
    #[serde(rename = "handle")]
    _handle: String,
    primary_email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Send {
    #[serde(rename = "handle")]
    _handle: String,
    topic: String,
    body: String,
}

pub(crate) enum Action {
    Snapshot {
        customer: String,
        domain: String,
        prefix: String,
        groups: BTreeSet<String>,
    },
    Next {
        customer: String,
        snapshot: String,
        cursor: u64,
        domain: String,
        prefix: String,
        groups: BTreeSet<String>,
    },
    Create {
        customer: String,
        input: CreateUser,
    },
    Patch {
        customer: String,
        prefix: String,
        input: PatchAttributes,
    },
    Group {
        customer: String,
        prefix: String,
        input: EnsureGroup,
        group_email: String,
    },
    Ensure {
        organization: String,
        email: String,
    },
    Suspend {
        organization: String,
        email: String,
    },
    Alert {
        destination: String,
        topic: String,
        body: String,
    },
}

impl Action {
    pub(crate) fn is_write(&self) -> bool {
        !matches!(self, Self::Snapshot { .. } | Self::Next { .. })
    }

    fn provider(&self) -> SyntheticProvider {
        match self {
            Self::Ensure { .. } | Self::Suspend { .. } => SyntheticProvider::Linear,
            Self::Alert { .. } => SyntheticProvider::OperatorAlerts,
            _ => SyntheticProvider::GoogleDirectory,
        }
    }
}

fn bounded(value: &str, max: usize) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control),
        "invalid_people_provider_input"
    );
    Ok(())
}

fn bounded_message(value: &str, max: usize) -> Result<()> {
    // Provider diagnostics and operator messages are text, not identifiers.
    // Preserve line breaks, tabs and other JSON-encoded message content.
    ensure!(
        !value.trim().is_empty() && value.len() <= max,
        "invalid_people_provider_message"
    );
    Ok(())
}

fn email(value: &str, domain: &str) -> Result<String> {
    ensure!(
        email_in_domain(value, domain),
        crate::error::Failure::ResourceForbidden
    );
    Ok(value.to_ascii_lowercase())
}

fn date(value: &str) -> bool {
    let pieces: Vec<_> = value.split('-').collect();
    if pieces.len() != 3
        || pieces[0].len() != 4
        || pieces[1].len() != 2
        || pieces[2].len() != 2
        || !pieces
            .iter()
            .all(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    let (Ok(year), Ok(month), Ok(day)) = (
        pieces[0].parse::<u32>(),
        pieces[1].parse::<u32>(),
        pieces[2].parse::<u32>(),
    ) else {
        return false;
    };
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max = match month {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    year >= 1 && day >= 1 && day <= max
}

pub(crate) fn authorized(
    instruction: &Instruction,
    provider: Provider,
    target: &ResourceTarget,
) -> Result<Action> {
    ensure!(
        instruction.data.len() <= MAX_RECORD_BYTES,
        "people_provider_request_budget"
    );
    match (instruction.model.as_str(), provider, target) {
        (
            capability,
            Provider::SyntheticGoogleDirectory,
            ResourceTarget::GoogleDirectory {
                customer_id,
                email_domain,
                org_unit_prefix,
                groups,
            },
        ) => {
            let customer = customer_id.clone();
            let prefix = org_unit_prefix.clone();
            match capability {
                "google_directory.snapshot.v1" => {
                    let _: Handle = crate::json::decode(instruction.data.as_bytes())?;
                    Ok(Action::Snapshot {
                        customer,
                        domain: email_domain.clone(),
                        prefix,
                        groups: groups.values().cloned().collect(),
                    })
                }
                "google_directory.record.v1" => {
                    let input: Next = crate::json::decode(instruction.data.as_bytes())?;
                    ensure!(
                        input.snapshot_id.len() == 74
                            && input.snapshot_id.starts_with("directory_")
                            && input.snapshot_id[10..]
                                .bytes()
                                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                            && input.cursor <= MAX_RECORDS as u64,
                        "invalid_google_directory_cursor"
                    );
                    Ok(Action::Next {
                        customer,
                        snapshot: input.snapshot_id,
                        cursor: input.cursor,
                        domain: email_domain.clone(),
                        prefix,
                        groups: groups.values().cloned().collect(),
                    })
                }
                "google_directory.create_user.v1" => {
                    let mut input: CreateUser =
                        crate::json::decode::<WithInput<CreateUser>>(instruction.data.as_bytes())?
                            .input;
                    input.primary_email = email(&input.primary_email, email_domain)?;
                    bounded(&input.given_name, 128)?;
                    bounded(&input.family_name, 128)?;
                    ensure!(
                        input
                            .personal_email
                            .rsplit_once('@')
                            .is_some_and(|(_, domain)| email_in_domain(
                                &input.personal_email,
                                domain
                            )),
                        "invalid_people_personal_email"
                    );
                    ensure!(
                        path_is_within(&input.org_unit_path, org_unit_prefix),
                        crate::error::Failure::ResourceForbidden
                    );
                    ensure!(date(&input.start_date), "invalid_people_start_date");
                    Ok(Action::Create { customer, input })
                }
                "google_directory.patch_attributes.v1" => {
                    let mut input: PatchAttributes =
                        crate::json::decode::<WithInput<PatchAttributes>>(
                            instruction.data.as_bytes(),
                        )?
                        .input;
                    input.primary_email = email(&input.primary_email, email_domain)?;
                    ensure!(input.attributes.len() <= 64, "people_attribute_budget");
                    let mut keys = BTreeSet::new();
                    for attribute in &input.attributes {
                        bounded(&attribute.key, 128)?;
                        bounded(&attribute.value, 1024)?;
                        ensure!(keys.insert(&attribute.key), "duplicate_people_attribute");
                    }
                    input
                        .attributes
                        .sort_by(|left, right| left.key.cmp(&right.key));
                    Ok(Action::Patch {
                        customer,
                        prefix,
                        input,
                    })
                }
                "google_directory.ensure_group_member.v1" => {
                    let mut input: EnsureGroup =
                        crate::json::decode::<WithInput<EnsureGroup>>(instruction.data.as_bytes())?
                            .input;
                    input.primary_email = email(&input.primary_email, email_domain)?;
                    let group_email = groups
                        .get(&input.group)
                        .context(crate::error::Failure::ResourceForbidden)?
                        .to_ascii_lowercase();
                    Ok(Action::Group {
                        customer,
                        prefix,
                        input,
                        group_email,
                    })
                }
                _ => anyhow::bail!("unknown_google_directory_capability"),
            }
        }
        (
            capability @ ("linear.ensure_access.v1" | "linear.suspend.v1"),
            Provider::SyntheticLinear,
            ResourceTarget::LinearOrganization {
                organization_id,
                email_domain,
            },
        ) => {
            let input: Email = crate::json::decode(instruction.data.as_bytes())?;
            let email = email(&input.primary_email, email_domain)?;
            Ok(if capability == "linear.ensure_access.v1" {
                Action::Ensure {
                    organization: organization_id.clone(),
                    email,
                }
            } else {
                Action::Suspend {
                    organization: organization_id.clone(),
                    email,
                }
            })
        }
        (
            "operator_alerts.send.v1",
            Provider::SyntheticOperatorAlerts,
            ResourceTarget::OperatorAlertDestination {
                destination,
                topics,
            },
        ) => {
            let input: Send = crate::json::decode(instruction.data.as_bytes())?;
            ensure!(
                topics.contains(&input.topic),
                crate::error::Failure::ResourceForbidden
            );
            bounded_message(&input.body, 8000)?;
            Ok(Action::Alert {
                destination: destination.clone(),
                topic: input.topic,
                body: input.body,
            })
        }
        _ => anyhow::bail!(crate::error::Failure::ResourceForbidden),
    }
}

fn upgrade(connection: &Connection) -> Result<()> {
    connection.execute_batch("CREATE TABLE IF NOT EXISTS people_provider (scope TEXT NOT NULL, target TEXT NOT NULL, state TEXT NOT NULL, PRIMARY KEY(scope,target)) STRICT;")?;
    Ok(())
}

fn read_state<W: DeserializeOwned>(
    connection: &Connection,
    scope: &str,
    target: &str,
) -> Result<ProviderState<W>> {
    let encoded: Option<String> = connection
        .query_row(
            "SELECT state FROM people_provider WHERE scope=?1 AND target=?2",
            params![scope, target],
            |row| row.get(0),
        )
        .optional()?;
    let encoded = encoded.context("people_provider_unconfigured")?;
    ensure!(
        encoded.len() <= MAX_WORLD_BYTES,
        "people_provider_world_budget"
    );
    crate::json::decode(encoded.as_bytes())
}

fn write_state<W: Serialize>(
    connection: &Connection,
    scope: &str,
    target: &str,
    state: &ProviderState<W>,
) -> Result<()> {
    ensure!(
        state.calls.len() <= MAX_CALLS
            && state.ledger.len() <= MAX_CALLS
            && state.faults.len() <= 1024,
        "people_provider_history_budget"
    );
    let encoded = serde_json::to_string(state)?;
    ensure!(
        encoded.len() <= MAX_WORLD_BYTES,
        "people_provider_world_budget"
    );
    connection.execute("INSERT INTO people_provider VALUES(?1,?2,?3) ON CONFLICT(scope,target) DO UPDATE SET state=excluded.state", params![scope,target,encoded])?;
    Ok(())
}

fn open_existing(path: &Path) -> Result<Connection> {
    ensure!(path.is_file(), "people_provider_unconfigured");
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    connection.busy_timeout(std::time::Duration::from_secs(2))?;
    Ok(connection)
}

fn with_state<W: DeserializeOwned + Serialize, T>(
    path: &Path,
    scope: &str,
    target: &str,
    act: impl FnOnce(&mut ProviderState<W>) -> Result<T>,
) -> Result<T> {
    let mut connection = open_existing(path)?;
    let tx = crate::write_queue::immediate(&mut connection)?;
    let mut state = read_state(&tx, scope, target)?;
    let result = act(&mut state)?;
    write_state(&tx, scope, target, &state)?;
    tx.commit()?;
    Ok(result)
}

fn seed<W: Serialize>(
    runtime: &Runtime,
    provider: SyntheticProvider,
    target: &str,
    world: &W,
) -> Result<()> {
    bounded(target, 256)?;
    let mut connection = crate::store::open(&runtime.db().with_file_name(provider.database()))?;
    let tx = crate::write_queue::immediate(&mut connection)?;
    upgrade(&tx)?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM people_provider WHERE scope=?1 AND target=?2)",
        params![runtime.scope(), target],
        |row| row.get(0),
    )?;
    ensure!(!exists, "people_provider_already_seeded");
    write_state(&tx, runtime.scope(), target, &ProviderState::new(world))?;
    tx.commit()?;
    Ok(())
}

/// Explicit setup only. An existing configured provider is never reset by seed.
/// The three independent stores are deliberately not a business transaction.
pub fn seed_synthetic(runtime: &Runtime, fixture: &SyntheticFixture) -> Result<()> {
    validate_fixture(fixture)?;
    for provider in [
        SyntheticProvider::GoogleDirectory,
        SyntheticProvider::Linear,
        SyntheticProvider::OperatorAlerts,
    ] {
        let target = match provider {
            SyntheticProvider::GoogleDirectory => &fixture.customer_id,
            SyntheticProvider::Linear => &fixture.organization_id,
            SyntheticProvider::OperatorAlerts => &fixture.destination,
        };
        let path = runtime.db().with_file_name(provider.database());
        if path.exists() {
            let connection = open_existing(&path)?;
            let exists: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM people_provider WHERE scope=?1 AND target=?2)",
                params![runtime.scope(), target],
                |row| row.get(0),
            )?;
            ensure!(!exists, "people_provider_already_seeded");
        }
    }
    seed(
        runtime,
        SyntheticProvider::GoogleDirectory,
        &fixture.customer_id,
        &fixture.google,
    )?;
    seed(
        runtime,
        SyntheticProvider::Linear,
        &fixture.organization_id,
        &fixture.linear,
    )?;
    seed(
        runtime,
        SyntheticProvider::OperatorAlerts,
        &fixture.destination,
        &fixture.alerts,
    )
}

/// The reviewed canary opt-in is based on declared external effects, never on
/// permissive development authority (which can include unused capabilities).
pub fn uses_synthetic_fixture(artifact: &crate::artifact::LoadedArtifact) -> bool {
    artifact
        .contract()
        .app_contract
        .as_ref()
        .is_some_and(|definition| {
            definition.operations.values().any(|operation| {
                operation.execution.effects.iter().any(|effect| {
                    effect.kind == "external"
                        && [
                            SyntheticProvider::GoogleDirectory,
                            SyntheticProvider::Linear,
                            SyntheticProvider::OperatorAlerts,
                        ]
                        .iter()
                        .any(|provider| provider.permits(&effect.command))
                })
            })
        })
}

/// Called only by explicit development/verification campaigns. Existing custom
/// worlds, including disabled integrations and pending faults, remain untouched.
pub(crate) fn seed_verification_if_unconfigured(runtime: &Runtime) -> Result<()> {
    if !uses_synthetic_fixture(runtime.artifact()) {
        return Ok(());
    }
    let fixture = synthetic_example();
    validate_fixture(&fixture)?;
    fn missing(runtime: &Runtime, provider: SyntheticProvider, target: &str) -> Result<bool> {
        let path = runtime.db().with_file_name(provider.database());
        if !path.exists() {
            return Ok(true);
        }
        let connection = open_existing(&path)?;
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM people_provider WHERE scope=?1 AND target=?2)",
            params![runtime.scope(), target],
            |row| row.get(0),
        )?;
        Ok(!exists)
    }
    if missing(
        runtime,
        SyntheticProvider::GoogleDirectory,
        &fixture.customer_id,
    )? {
        seed(
            runtime,
            SyntheticProvider::GoogleDirectory,
            &fixture.customer_id,
            &fixture.google,
        )?;
    }
    if missing(runtime, SyntheticProvider::Linear, &fixture.organization_id)? {
        seed(
            runtime,
            SyntheticProvider::Linear,
            &fixture.organization_id,
            &fixture.linear,
        )?;
        // The generic app campaign needs a completed offboard with an explicit
        // retryable access failure to exercise retry_deprovision positively.
        // This one-shot schedule belongs only to campaign setup; ordinary
        // synthetic_example() and independently seeded native worlds omit it.
        schedule_failure(
            runtime,
            SyntheticProvider::Linear,
            &fixture.organization_id,
            &ScheduledFailure {
                capability: "linear.suspend.v1".into(),
                subject: "demo_hire@exampleco.example".into(),
                remaining: 1,
                mode: FailureMode::Definite {
                    code: "LinearVerificationUnavailable".into(),
                    message: "Synthetic first deprovision request is unavailable.".into(),
                    retryable: true,
                },
            },
        )?;
    }
    if missing(
        runtime,
        SyntheticProvider::OperatorAlerts,
        &fixture.destination,
    )? {
        seed(
            runtime,
            SyntheticProvider::OperatorAlerts,
            &fixture.destination,
            &fixture.alerts,
        )?;
    }
    Ok(())
}

fn validate_fixture(fixture: &SyntheticFixture) -> Result<()> {
    for target in [
        &fixture.customer_id,
        &fixture.organization_id,
        &fixture.destination,
    ] {
        bounded(target, 256)?;
    }
    ensure!(
        fixture.google.users.len() + fixture.google.groups.len() + fixture.google.org_units.len()
            <= MAX_RECORDS
            && fixture.linear.users.len() <= MAX_RECORDS
            && fixture.linear.invitations.len() <= MAX_RECORDS
            && fixture.alerts.messages.len() <= MAX_RECORDS
            && fixture.google.captures.is_empty(),
        "people_fixture_budget"
    );
    for (key, account) in &fixture.google.users {
        ensure!(
            key == &key.to_ascii_lowercase() && key == &account.user.primary_email,
            "invalid_people_fixture_email"
        );
        bounded(&account.user.id, 256)?;
        DirectoryRecord::User(account.user.clone()).envelope()?;
    }
    for (key, group) in &fixture.google.groups {
        ensure!(
            key == &key.to_ascii_lowercase() && key == &group.email,
            "invalid_people_fixture_group"
        );
        DirectoryRecord::Group(group.clone()).envelope()?;
    }
    for org in &fixture.google.org_units {
        DirectoryRecord::OrgUnit(org.clone()).envelope()?;
    }
    for (group, members) in &fixture.google.memberships {
        ensure!(
            fixture.google.groups.contains_key(group)
                && members
                    .iter()
                    .all(|member| fixture.google.users.contains_key(member)),
            "invalid_people_fixture_membership"
        );
    }
    for (email, user) in &fixture.linear.users {
        ensure!(
            email == &email.to_ascii_lowercase(),
            "invalid_people_fixture_email"
        );
        bounded(&user.id, 256)?;
    }
    ensure!(
        serde_json::to_vec(fixture)?.len() <= MAX_WORLD_BYTES / 2,
        "people_fixture_byte_budget"
    );
    Ok(())
}

pub fn inspect_google(runtime: &Runtime, customer_id: &str) -> Result<ProviderState<GoogleWorld>> {
    read_state(
        &open_existing(
            &runtime
                .db()
                .with_file_name(SyntheticProvider::GoogleDirectory.database()),
        )?,
        runtime.scope(),
        customer_id,
    )
}
pub fn inspect_linear(
    runtime: &Runtime,
    organization_id: &str,
) -> Result<ProviderState<LinearWorld>> {
    read_state(
        &open_existing(
            &runtime
                .db()
                .with_file_name(SyntheticProvider::Linear.database()),
        )?,
        runtime.scope(),
        organization_id,
    )
}
pub fn inspect_alerts(runtime: &Runtime, destination: &str) -> Result<ProviderState<AlertWorld>> {
    read_state(
        &open_existing(
            &runtime
                .db()
                .with_file_name(SyntheticProvider::OperatorAlerts.database()),
        )?,
        runtime.scope(),
        destination,
    )
}

pub fn schedule_failure(
    runtime: &Runtime,
    provider: SyntheticProvider,
    target: &str,
    failure: &ScheduledFailure,
) -> Result<()> {
    ensure!(
        provider.permits(&failure.capability)
            && (1..=1000).contains(&failure.remaining)
            && failure.subject.len() <= 320,
        "invalid_people_failure_schedule"
    );
    match &failure.mode {
        FailureMode::Definite { code, message, .. } => {
            bounded(code, 128)?;
            bounded_message(message, 2048)?;
        }
        FailureMode::PatchVerificationMismatch => ensure!(
            failure.capability == "google_directory.patch_attributes.v1",
            "invalid_people_failure_mode"
        ),
    }
    let path = runtime.db().with_file_name(provider.database());
    let append = |state: &mut ProviderState<Value>| {
        state.faults.push(failure.clone());
        Ok(())
    };
    with_state(&path, runtime.scope(), target, append)
}

fn failed(code: &str, message: &str, retryable: bool) -> Value {
    json!({"Failed":Problem { code:code.into(), message:message.into(), retryable }})
}

fn effect<W: Serialize>(
    state: &mut ProviderState<W>,
    effect_id: &str,
    capability: &str,
    subject: &str,
    payload: Value,
    apply: impl FnOnce(&mut W, Option<FailureMode>) -> Result<Value>,
) -> Result<Value> {
    bounded(effect_id, 512)?;
    if let Some(prior) = state.ledger.get(effect_id) {
        ensure!(
            prior.capability == capability && prior.payload == payload,
            "people_provider_idempotency_conflict"
        );
        state.calls.push(ProviderCall {
            effect_id: effect_id.into(),
            capability: capability.into(),
            replayed: true,
            changed: false,
        });
        return Ok(prior.result.clone());
    }
    let failure = state
        .faults
        .iter_mut()
        .find(|fault| {
            fault.remaining > 0
                && fault.capability == capability
                && (fault.subject.is_empty() || fault.subject == subject)
        })
        .map(|fault| {
            fault.remaining -= 1;
            fault.mode.clone()
        });
    let before = serde_json::to_value(&state.world)?;
    let result = match failure {
        Some(FailureMode::Definite {
            code,
            message,
            retryable,
        }) => failed(&code, &message, retryable),
        other => apply(&mut state.world, other)?,
    };
    let changed = before != serde_json::to_value(&state.world)?;
    state.ledger.insert(
        effect_id.into(),
        LedgerEntry {
            capability: capability.into(),
            payload,
            result: result.clone(),
        },
    );
    state.calls.push(ProviderCall {
        effect_id: effect_id.into(),
        capability: capability.into(),
        replayed: false,
        changed,
    });
    Ok(result)
}

fn permitted_user(world: &GoogleWorld, email: &str, prefix: &str) -> Result<bool> {
    match world.users.get(email) {
        Some(account) => {
            ensure!(
                path_is_within(&account.user.org_unit_path, prefix),
                crate::error::Failure::ResourceForbidden
            );
            Ok(true)
        }
        None => Ok(false),
    }
}

fn google_create(world: &mut GoogleWorld, input: &CreateUser, effect_id: &str) -> Result<Value> {
    if world.users.contains_key(&input.primary_email) {
        return Ok(
            json!({"Conflict":Problem { code:"GoogleAccountExists".into(),message:"A Google account already owns this email.".into(),retryable:false }}),
        );
    }
    if !world
        .org_units
        .iter()
        .any(|unit| unit.path == input.org_unit_path)
    {
        return Ok(failed(
            "GoogleOrgUnitMissing",
            "The selected Google organization unit does not exist.",
            false,
        ));
    }
    ensure!(
        world.users.len() < MAX_RECORDS,
        "google_directory_user_budget"
    );
    let id = format!("google_{}", &crate::digest(effect_id.as_bytes())[7..31]);
    let user = DirectoryUser {
        id: id.clone(),
        primary_email: input.primary_email.clone(),
        given_name: input.given_name.clone(),
        family_name: input.family_name.clone(),
        full_name: format!("{} {}", input.given_name, input.family_name),
        org_unit_path: input.org_unit_path.clone(),
        thumbnail_photo_url: OptionalText::None,
        suspended: false,
    };
    world.users.insert(
        input.primary_email.clone(),
        GoogleAccount {
            user,
            personal_email: input.personal_email.clone(),
            start_date: input.start_date.clone(),
            attributes: BTreeMap::new(),
        },
    );
    Ok(json!({"Created":{"id":id,"primary_email":input.primary_email}}))
}

pub(crate) fn execute(runtime: &Runtime, action: Action, effect_id: &str) -> Result<String> {
    execute_at(
        &runtime.db().with_file_name(action.provider().database()),
        runtime.scope(),
        action,
        effect_id,
    )
}

fn execute_at(path: &Path, scope: &str, action: Action, effect_id: &str) -> Result<String> {
    let result = match action {
        Action::Create { customer, input } => {
            with_state::<GoogleWorld, _>(path, scope, &customer, |state| {
                effect(
                    state,
                    effect_id,
                    "google_directory.create_user.v1",
                    &input.primary_email,
                    serde_json::to_value(&input)?,
                    |world, _| google_create(world, &input, effect_id),
                )
            })?
        }
        Action::Patch {
            customer,
            prefix,
            input,
        } => with_state::<GoogleWorld, _>(path, scope, &customer, |state| {
            permitted_user(&state.world, &input.primary_email, &prefix)?;
            effect(
                state,
                effect_id,
                "google_directory.patch_attributes.v1",
                &input.primary_email,
                serde_json::to_value(&input)?,
                |world, failure| {
                    let Some(account) = world.users.get_mut(&input.primary_email) else {
                        return Ok(failed(
                            "GoogleUserNotFound",
                            "The Google account does not exist.",
                            false,
                        ));
                    };
                    for attribute in &input.attributes {
                        account
                            .attributes
                            .insert(attribute.key.clone(), attribute.value.clone());
                    }
                    if matches!(failure, Some(FailureMode::PatchVerificationMismatch)) {
                        Ok(failed(
                            "GoogleCustomAttributeVerificationFailed",
                            "Google attribute verification did not match the requested values.",
                            true,
                        ))
                    } else {
                        Ok(json!("Patched"))
                    }
                },
            )
        })?,
        Action::Group {
            customer,
            prefix,
            input,
            group_email,
        } => with_state::<GoogleWorld, _>(path, scope, &customer, |state| {
            permitted_user(&state.world, &input.primary_email, &prefix)?;
            effect(
                state,
                effect_id,
                "google_directory.ensure_group_member.v1",
                &input.primary_email,
                json!({"input":input,"group_email":group_email}),
                |world, _| {
                    if !world.users.contains_key(&input.primary_email) {
                        return Ok(failed(
                            "GoogleUserNotFound",
                            "The Google account does not exist.",
                            false,
                        ));
                    }
                    if !world.groups.contains_key(&group_email) {
                        return Ok(failed(
                            "GoogleGroupNotFound",
                            "The Google group does not exist.",
                            false,
                        ));
                    }
                    let added = world
                        .memberships
                        .entry(group_email.clone())
                        .or_default()
                        .insert(input.primary_email.clone());
                    Ok(json!(if added { "Added" } else { "AlreadyMember" }))
                },
            )
        })?,
        Action::Ensure {
            organization,
            email,
        } => with_state::<LinearWorld, _>(path, scope, &organization, |state| {
            effect(
                state,
                effect_id,
                "linear.ensure_access.v1",
                &email,
                json!({"primary_email":email}),
                |world, _| {
                    if !world.enabled {
                        return Ok(json!("Disabled"));
                    }
                    if let Some(user) = world.users.get_mut(&email) {
                        let was_active = user.active;
                        user.active = true;
                        return Ok(if was_active {
                            json!({"Active":user.id})
                        } else {
                            json!({"Reactivated":user.id})
                        });
                    }
                    if let Some(invitation) = world.invitations.iter().find(|invitation| {
                        invitation.email.eq_ignore_ascii_case(&email)
                            && !invitation.accepted
                            && !invitation.expired
                    }) {
                        return Ok(json!({"PendingInvitation":invitation.id}));
                    }
                    ensure!(
                        world.invitations.len() < MAX_RECORDS,
                        "linear_invitation_budget"
                    );
                    let id = format!("invite_{}", &crate::digest(effect_id.as_bytes())[7..31]);
                    world.invitations.push(Invitation {
                        id: id.clone(),
                        email: email.clone(),
                        accepted: false,
                        expired: false,
                    });
                    Ok(json!({"Invited":id}))
                },
            )
        })?,
        Action::Suspend {
            organization,
            email,
        } => with_state::<LinearWorld, _>(path, scope, &organization, |state| {
            effect(
                state,
                effect_id,
                "linear.suspend.v1",
                &email,
                json!({"primary_email":email}),
                |world, _| {
                    if !world.enabled {
                        return Ok(json!("Disabled"));
                    }
                    let Some(user) = world.users.get_mut(&email) else {
                        return Ok(json!("NotFound"));
                    };
                    let was_active = user.active;
                    user.active = false;
                    Ok(if was_active {
                        json!({"Suspended":user.id})
                    } else {
                        json!({"AlreadySuspended":user.id})
                    })
                },
            )
        })?,
        Action::Alert {
            destination,
            topic,
            body,
        } => with_state::<AlertWorld, _>(path, scope, &destination, |state| {
            effect(
                state,
                effect_id,
                "operator_alerts.send.v1",
                &topic,
                json!({"topic":topic,"body":body}),
                |world, _| {
                    if !world.enabled {
                        return Ok(json!("Disabled"));
                    }
                    ensure!(
                        world.messages.len() < MAX_RECORDS,
                        "operator_alert_message_budget"
                    );
                    let id = format!("alert_{}", &crate::digest(effect_id.as_bytes())[7..31]);
                    world.messages.push(Alert {
                        id: id.clone(),
                        topic: topic.clone(),
                        body: body.clone(),
                    });
                    Ok(json!({"Accepted":id}))
                },
            )
        })?,
        _ => anyhow::bail!("unknown_people_effect_capability"),
    };
    Ok(serde_json::to_string(&result)?)
}

fn record_permitted(
    record: &DirectoryRecord,
    domain: &str,
    prefix: &str,
    groups: &BTreeSet<String>,
) -> bool {
    match record {
        DirectoryRecord::User(user) => {
            email_in_domain(&user.primary_email, domain)
                && path_is_within(&user.org_unit_path, prefix)
        }
        DirectoryRecord::Group(group) => groups
            .iter()
            .any(|email| email.eq_ignore_ascii_case(&group.email)),
        DirectoryRecord::OrgUnit(unit) => path_is_within(&unit.path, prefix),
    }
}

pub(crate) fn observe(runtime: &Runtime, action: Action) -> Result<String> {
    let path = runtime
        .db()
        .with_file_name(SyntheticProvider::GoogleDirectory.database());
    observe_at(&path, runtime.scope(), action)
}

fn observe_at(path: &Path, scope: &str, action: Action) -> Result<String> {
    match action {
        Action::Snapshot {
            customer,
            domain,
            prefix,
            groups,
        } => with_state::<GoogleWorld, _>(path, scope, &customer, |state| {
            let records: Vec<_> = state
                .world
                .users
                .values()
                .map(|account| DirectoryRecord::User(account.user.clone()))
                .chain(
                    state
                        .world
                        .groups
                        .values()
                        .cloned()
                        .map(DirectoryRecord::Group),
                )
                .chain(
                    state
                        .world
                        .org_units
                        .iter()
                        .cloned()
                        .map(DirectoryRecord::OrgUnit),
                )
                .filter(|record| record_permitted(record, &domain, &prefix, &groups))
                .collect();
            ensure!(
                records.len() <= MAX_RECORDS,
                "google_directory_capture_budget"
            );
            for record in &records {
                record.envelope()?;
            }
            let id = format!(
                "directory_{}",
                &crate::digest(&serde_json::to_vec(&(
                    scope, &customer, &domain, &prefix, &groups, &records
                ))?)[7..]
            );
            if let Some(prior) = state.world.captures.get(&id) {
                ensure!(prior == &records, "google_directory_capture_conflict");
            } else {
                state.world.captures.insert(id.clone(), records);
            }
            Ok(json!({"id":id,"customer_id":customer}).to_string())
        }),
        Action::Next {
            customer,
            snapshot,
            cursor,
            domain,
            prefix,
            groups,
        } => {
            let state: ProviderState<GoogleWorld> =
                read_state(&open_existing(path)?, scope, &customer)?;
            let records = state
                .world
                .captures
                .get(&snapshot)
                .context("google_directory_capture_unavailable")?;
            // A more restricted handle cannot reuse a broader capture to leak records.
            ensure!(
                records
                    .iter()
                    .all(|record| record_permitted(record, &domain, &prefix, &groups)),
                crate::error::Failure::ResourceForbidden
            );
            ensure!(
                records.len() <= MAX_RECORDS && cursor <= records.len() as u64,
                "invalid_google_directory_cursor"
            );
            match records.get(usize::try_from(cursor)?) {
                Some(record) => record.envelope(),
                None => Ok(json!({"kind":"done","data":"{}"}).to_string()),
            }
        }
        _ => anyhow::bail!("unknown_people_observation_capability"),
    }
}

/// Data construction only; callers must explicitly install this disposable fixture.
pub fn synthetic_example() -> SyntheticFixture {
    let users = [
        ("alice", "/Engineering"),
        ("bob", "/Engineering/Platform"),
        ("outsider", "/Sales"),
    ]
    .into_iter()
    .map(|(name, path)| {
        let email = format!("{name}@exampleco.example");
        let user = DirectoryUser {
            id: format!("google-{name}"),
            primary_email: email.clone(),
            given_name: name.into(),
            family_name: "Example".into(),
            full_name: format!("{name} Example"),
            org_unit_path: path.into(),
            thumbnail_photo_url: OptionalText::None,
            suspended: false,
        };
        (
            email,
            GoogleAccount {
                user,
                personal_email: format!("{name}@personal.example"),
                start_date: "2026-09-01".into(),
                attributes: BTreeMap::new(),
            },
        )
    })
    .collect();
    let groups = ["engineering", "growth"]
        .into_iter()
        .map(|name| {
            let email = format!("{name}@exampleco.example");
            (
                email.clone(),
                DirectoryGroup {
                    id: format!("group-{name}"),
                    email,
                    name: name.into(),
                },
            )
        })
        .collect();
    let org_units = ["/", "/Engineering", "/Engineering/Platform", "/Sales"]
        .into_iter()
        .enumerate()
        .map(|(index, path)| OrgUnit {
            id: format!("ou-{index}"),
            path: path.into(),
            name: path.rsplit('/').next().unwrap_or_default().into(),
        })
        .collect();
    SyntheticFixture {
        customer_id: "synthetic-customer-1".into(),
        google: GoogleWorld {
            users,
            groups,
            org_units,
            ..GoogleWorld::default()
        },
        organization_id: "synthetic-linear-1".into(),
        linear: LinearWorld {
            enabled: true,
            users: BTreeMap::from([
                (
                    "alice@exampleco.example".into(),
                    LinearUser {
                        id: "linear-alice".into(),
                        active: true,
                    },
                ),
                (
                    "bob@exampleco.example".into(),
                    LinearUser {
                        id: "linear-bob".into(),
                        active: false,
                    },
                ),
            ]),
            invitations: vec![Invitation {
                id: "pending-outsider".into(),
                email: "outsider@exampleco.example".into(),
                accepted: false,
                expired: false,
            }],
        },
        destination: "synthetic-people-operator".into(),
        alerts: AlertWorld {
            enabled: true,
            messages: Vec::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install<W: Serialize>(path: &Path, world: W) -> Result<()> {
        let connection = crate::store::open(path)?;
        upgrade(&connection)?;
        write_state(&connection, "first", "target", &ProviderState::new(world))
    }

    fn read<W: DeserializeOwned>(path: &Path) -> Result<ProviderState<W>> {
        read_state(&open_existing(path)?, "first", "target")
    }

    fn create_input() -> CreateUser {
        CreateUser {
            given_name: "New".into(),
            family_name: "Person".into(),
            primary_email: "new@exampleco.example".into(),
            personal_email: "new@personal.example".into(),
            org_unit_path: "/Engineering".into(),
            start_date: "2028-02-29".into(),
        }
    }

    fn create(input: CreateUser) -> Action {
        Action::Create {
            customer: "target".into(),
            input,
        }
    }

    fn patch() -> Action {
        Action::Patch {
            customer: "target".into(),
            prefix: "/Engineering".into(),
            input: PatchAttributes {
                primary_email: "alice@exampleco.example".into(),
                attributes: vec![Attribute {
                    key: "employee_type".into(),
                    value: "full_time".into(),
                }],
            },
        }
    }

    fn group(group_email: &str) -> Action {
        Action::Group {
            customer: "target".into(),
            prefix: "/Engineering".into(),
            input: EnsureGroup {
                primary_email: "alice@exampleco.example".into(),
                group: group_email.into(),
            },
            group_email: group_email.into(),
        }
    }

    fn snapshot(prefix: &str) -> Action {
        Action::Snapshot {
            customer: "target".into(),
            domain: "exampleco.example".into(),
            prefix: prefix.into(),
            groups: BTreeSet::from(["engineering@exampleco.example".into()]),
        }
    }

    fn next(snapshot: &str, cursor: u64, prefix: &str) -> Action {
        Action::Next {
            customer: "target".into(),
            snapshot: snapshot.into(),
            cursor,
            domain: "exampleco.example".into(),
            prefix: prefix.into(),
            groups: BTreeSet::from(["engineering@exampleco.example".into()]),
        }
    }

    fn output(path: &Path, action: Action, id: &str) -> Result<Value> {
        Ok(serde_json::from_str(&execute_at(
            path, "first", action, id,
        )?)?)
    }

    #[test]
    fn durable_create_replay_payload_conflict_and_scope_isolation() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("google.sqlite");
        assert!(execute_at(&path, "first", create(create_input()), "effect").is_err());
        assert!(
            !path.exists(),
            "unconfigured execution must not initialize synthetic data"
        );
        install(&path, synthetic_example().google)?;
        let accepted = output(&path, create(create_input()), "effect")?;
        assert!(accepted.get("Created").is_some());
        assert_eq!(output(&path, create(create_input()), "effect")?, accepted);
        let state: ProviderState<GoogleWorld> = read(&path)?;
        assert_eq!(state.world.users.len(), 4);
        assert_eq!(state.calls.len(), 2);
        assert_eq!(state.ledger.len(), 1);
        assert!(state.calls[0].changed && state.calls[1].replayed && !state.calls[1].changed);
        let mut changed = create_input();
        changed.given_name = "Substituted".into();
        assert!(output(&path, create(changed), "effect").is_err());
        assert_eq!(
            read::<GoogleWorld>(&path)?,
            state,
            "conflicting request must not modify ledger or state"
        );
        assert!(
            output(&path, create(create_input()), "new-business-attempt")?
                .get("Conflict")
                .is_some()
        );
        assert!(execute_at(&path, "second", create(create_input()), "effect").is_err());
        assert!(
            execute_at(
                &path,
                "first",
                Action::Create {
                    customer: "other".into(),
                    input: create_input()
                },
                "effect"
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn definite_failure_is_replayed_but_fresh_attempt_and_partial_patch_are_distinct() -> Result<()>
    {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("google.sqlite");
        install(&path, synthetic_example().google)?;
        with_state::<GoogleWorld, _>(&path, "first", "target", |state| {
            state.faults.push(ScheduledFailure {
                capability: "google_directory.patch_attributes.v1".into(),
                subject: "alice@exampleco.example".into(),
                remaining: 1,
                mode: FailureMode::Definite {
                    code: "RateLimited".into(),
                    message: "Try later".into(),
                    retryable: true,
                },
            });
            Ok(())
        })?;
        assert_eq!(
            output(&path, patch(), "failed")?["Failed"]["code"],
            "RateLimited"
        );
        assert_eq!(
            output(&path, patch(), "failed")?["Failed"]["code"],
            "RateLimited"
        );
        assert!(
            read::<GoogleWorld>(&path)?.world.users["alice@exampleco.example"]
                .attributes
                .is_empty()
        );
        with_state::<GoogleWorld, _>(&path, "first", "target", |state| {
            state.faults.push(ScheduledFailure {
                capability: "google_directory.patch_attributes.v1".into(),
                subject: String::new(),
                remaining: 1,
                mode: FailureMode::PatchVerificationMismatch,
            });
            Ok(())
        })?;
        assert_eq!(
            output(&path, patch(), "mismatch")?["Failed"]["code"],
            "GoogleCustomAttributeVerificationFailed"
        );
        assert_eq!(
            read::<GoogleWorld>(&path)?.world.users["alice@exampleco.example"].attributes["employee_type"],
            "full_time"
        );
        assert_eq!(output(&path, patch(), "retry")?, json!("Patched"));
        assert_eq!(
            output(&path, group("engineering@exampleco.example"), "group1")?,
            json!("Added")
        );
        assert_eq!(
            output(&path, group("engineering@exampleco.example"), "group1")?,
            json!("Added")
        );
        assert_eq!(
            output(&path, group("engineering@exampleco.example"), "group2")?,
            json!("AlreadyMember")
        );
        assert_eq!(
            output(&path, group("missing@exampleco.example"), "group3")?["Failed"]["code"],
            "GoogleGroupNotFound"
        );
        assert_eq!(
            read::<GoogleWorld>(&path)?.world.memberships["engineering@exampleco.example"].len(),
            1
        );
        Ok(())
    }

    #[test]
    fn directory_captures_are_immutable_complete_and_cannot_widen_resource_reads() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("google.sqlite");
        install(&path, synthetic_example().google)?;
        let first: Value =
            serde_json::from_str(&observe_at(&path, "first", snapshot("/Engineering"))?)?;
        let id = first["id"].as_str().unwrap();
        assert_eq!(id.len(), 74);
        let mut records = Vec::new();
        loop {
            let value: Value = serde_json::from_str(&observe_at(
                &path,
                "first",
                next(id, records.len() as u64, "/Engineering"),
            )?)?;
            if value["kind"] == "done" {
                break;
            }
            records.push(value);
        }
        assert_eq!(
            records.len(),
            5,
            "two users, one granted group and two units"
        );
        assert!(
            records
                .iter()
                .all(|record| !record["data"].as_str().unwrap().contains("outsider"))
        );
        assert!(observe_at(&path, "first", next(id, 6, "/Engineering")).is_err());
        assert!(observe_at(&path, "second", next(id, 0, "/Engineering")).is_err());
        assert!(observe_at(&path, "first", next(id, 0, "/Engineering/Platform")).is_err());
        output(&path, create(create_input()), "new-person")?;
        let second: Value =
            serde_json::from_str(&observe_at(&path, "first", snapshot("/Engineering"))?)?;
        assert_ne!(first["id"], second["id"]);
        assert_eq!(
            serde_json::from_str::<Value>(&observe_at(
                &path,
                "first",
                next(id, 5, "/Engineering")
            )?)?["kind"],
            "done"
        );
        assert_eq!(read::<GoogleWorld>(&path)?.world.captures.len(), 2);
        Ok(())
    }

    #[test]
    fn linear_preserves_every_semantic_outcome_and_searches_past_first_invitation_page()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("linear.sqlite");
        let mut world = synthetic_example().linear;
        world.invitations = (0..75)
            .map(|index| Invitation {
                id: format!("old-{index}"),
                email: format!("other{index}@exampleco.example"),
                accepted: false,
                expired: false,
            })
            .collect();
        world.invitations.extend([
            Invitation {
                id: "accepted".into(),
                email: "pending@exampleco.example".into(),
                accepted: true,
                expired: false,
            },
            Invitation {
                id: "expired".into(),
                email: "pending@exampleco.example".into(),
                accepted: false,
                expired: true,
            },
            Invitation {
                id: "pending".into(),
                email: "PENDING@exampleco.example".into(),
                accepted: false,
                expired: false,
            },
        ]);
        install(&path, world)?;
        let ensure = |email: &str| Action::Ensure {
            organization: "target".into(),
            email: email.into(),
        };
        let suspend = |email: &str| Action::Suspend {
            organization: "target".into(),
            email: email.into(),
        };
        assert_eq!(
            output(&path, ensure("alice@exampleco.example"), "active")?,
            json!({"Active":"linear-alice"})
        );
        assert_eq!(
            output(&path, ensure("bob@exampleco.example"), "reactivate")?,
            json!({"Reactivated":"linear-bob"})
        );
        assert_eq!(
            output(&path, ensure("pending@exampleco.example"), "pending")?,
            json!({"PendingInvitation":"pending"})
        );
        let invited = output(&path, ensure("new@exampleco.example"), "invite")?;
        assert!(invited.get("Invited").is_some());
        assert_eq!(
            output(&path, ensure("new@exampleco.example"), "invite")?,
            invited
        );
        assert_eq!(
            output(&path, ensure("new@exampleco.example"), "new-attempt")?["PendingInvitation"],
            invited["Invited"]
        );
        assert_eq!(
            output(&path, suspend("alice@exampleco.example"), "suspend")?,
            json!({"Suspended":"linear-alice"})
        );
        assert_eq!(
            output(&path, suspend("alice@exampleco.example"), "suspend-again")?,
            json!({"AlreadySuspended":"linear-alice"})
        );
        assert_eq!(
            output(&path, suspend("missing@exampleco.example"), "missing")?,
            json!("NotFound")
        );
        with_state::<LinearWorld, _>(&path, "first", "target", |state| {
            state.world.enabled = false;
            Ok(())
        })?;
        assert_eq!(
            output(&path, ensure("new@exampleco.example"), "disabled-ensure")?,
            json!("Disabled")
        );
        assert_eq!(
            output(&path, suspend("bob@exampleco.example"), "disabled-suspend")?,
            json!("Disabled")
        );
        assert_eq!(read::<LinearWorld>(&path)?.world.invitations.len(), 79);
        Ok(())
    }

    #[test]
    fn fixed_destination_alerts_dedupe_unknown_ack_and_preserve_failure() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("alerts.sqlite");
        install(
            &path,
            AlertWorld {
                enabled: true,
                messages: Vec::new(),
            },
        )?;
        let send = || Action::Alert {
            destination: "target".into(),
            topic: "people.failure".into(),
            body: "Manual action required".into(),
        };
        let accepted = output(&path, send(), "lost-ack")?;
        assert_eq!(output(&path, send(), "lost-ack")?, accepted);
        assert_eq!(read::<AlertWorld>(&path)?.world.messages.len(), 1);
        with_state::<AlertWorld, _>(&path, "first", "target", |state| {
            state.faults.push(ScheduledFailure {
                capability: "operator_alerts.send.v1".into(),
                subject: "people.failure".into(),
                remaining: 1,
                mode: FailureMode::Definite {
                    code: "SlackUnavailable".into(),
                    message: "Unavailable".into(),
                    retryable: true,
                },
            });
            Ok(())
        })?;
        assert_eq!(
            output(&path, send(), "failed")?["Failed"]["code"],
            "SlackUnavailable"
        );
        assert_eq!(
            output(&path, send(), "failed")?["Failed"]["code"],
            "SlackUnavailable"
        );
        assert_eq!(read::<AlertWorld>(&path)?.world.messages.len(), 1);
        assert!(output(&path, send(), "fresh")?.get("Accepted").is_some());
        with_state::<AlertWorld, _>(&path, "first", "target", |state| {
            state.world.enabled = false;
            Ok(())
        })?;
        assert_eq!(output(&path, send(), "disabled")?, json!("Disabled"));
        assert_eq!(read::<AlertWorld>(&path)?.world.messages.len(), 2);
        Ok(())
    }

    #[test]
    fn multiline_operator_diagnostics_are_authorized_preserved_and_deduplicated() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("alerts.sqlite");
        install(
            &path,
            AlertWorld {
                enabled: true,
                messages: Vec::new(),
            },
        )?;
        let target = ResourceTarget::OperatorAlertDestination {
            destination: "target".into(),
            topics: day2_capabilities::resources::TopicScope::Only {
                topics: BTreeSet::from(["people_ops".into()]),
            },
        };
        target.validate()?;
        let body = "Linear provisioning failed:\n\tprovider request unavailable\r\nManual action required.";
        let instruction = |body: &str| Instruction {
            model: "operator_alerts.send.v1".into(),
            data: json!({"handle":"opaque","topic":"people_ops","body":body}).to_string(),
            ..Instruction::default()
        };
        let action = || {
            authorized(
                &instruction(body),
                Provider::SyntheticOperatorAlerts,
                &target,
            )
        };
        let accepted = output(&path, action()?, "lost-ack")?;
        assert_eq!(output(&path, action()?, "lost-ack")?, accepted);
        let persisted = read::<AlertWorld>(&path)?;
        assert_eq!(persisted.world.messages.len(), 1);
        assert_eq!(persisted.world.messages[0].body, body);
        assert_eq!(persisted.calls.len(), 2);
        assert!(persisted.calls[0].changed && persisted.calls[1].replayed);
        for invalid in ["\n\t\r\n".to_owned(), "x".repeat(8001)] {
            assert!(
                authorized(
                    &instruction(&invalid),
                    Provider::SyntheticOperatorAlerts,
                    &target,
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn input_and_resource_validation_refuses_foreign_targets_before_dispatch() -> Result<()> {
        let target = ResourceTarget::GoogleDirectory {
            customer_id: "target".into(),
            email_domain: "exampleco.example".into(),
            org_unit_prefix: "/Engineering".into(),
            groups: BTreeMap::from([("developer".into(), "engineering@exampleco.example".into())]),
        };
        target.validate()?;
        let instruction = |capability: &str, input: Value| Instruction {
            model: capability.into(),
            data: json!({"handle":"opaque","input":input}).to_string(),
            ..Instruction::default()
        };
        assert!(
            authorized(
                &instruction(
                    "google_directory.create_user.v1",
                    serde_json::to_value(create_input())?
                ),
                Provider::SyntheticGoogleDirectory,
                &target
            )
            .is_ok()
        );
        for input in [
            CreateUser {
                primary_email: "new@foreign.example".into(),
                ..create_input()
            },
            CreateUser {
                org_unit_path: "/EngineeringOther".into(),
                ..create_input()
            },
            CreateUser {
                org_unit_path: "/Engineering/../Sales".into(),
                ..create_input()
            },
            CreateUser {
                start_date: "2027-02-29".into(),
                ..create_input()
            },
        ] {
            assert!(
                authorized(
                    &instruction(
                        "google_directory.create_user.v1",
                        serde_json::to_value(input)?
                    ),
                    Provider::SyntheticGoogleDirectory,
                    &target
                )
                .is_err()
            );
        }
        let allowed = instruction(
            "google_directory.ensure_group_member.v1",
            json!({"primary_email":"alice@exampleco.example","group":"developer"}),
        );
        assert!(
            matches!(authorized(&allowed,Provider::SyntheticGoogleDirectory,&target)?,Action::Group{group_email,..} if group_email=="engineering@exampleco.example")
        );
        let denied = instruction(
            "google_directory.ensure_group_member.v1",
            json!({"primary_email":"alice@exampleco.example","group":"engineering@exampleco.example"}),
        );
        assert!(authorized(&denied, Provider::SyntheticGoogleDirectory, &target).is_err());
        assert!(authorized(&allowed, Provider::SyntheticLinear, &target).is_err());
        let duplicate = instruction(
            "google_directory.patch_attributes.v1",
            json!({"primary_email":"alice@exampleco.example","attributes":[{"key":"role","value":"a"},{"key":"role","value":"b"}]}),
        );
        assert!(authorized(&duplicate, Provider::SyntheticGoogleDirectory, &target).is_err());
        let alert_target = ResourceTarget::OperatorAlertDestination {
            destination: "fixed".into(),
            topics: day2_capabilities::resources::TopicScope::Prefix {
                prefix: "people.".into(),
            },
        };
        let alert = Instruction {
            model: "operator_alerts.send.v1".into(),
            data: json!({"handle":"opaque","topic":"other","body":"body"}).to_string(),
            ..Instruction::default()
        };
        assert!(authorized(&alert, Provider::SyntheticOperatorAlerts, &alert_target).is_err());
        Ok(())
    }

    #[test]
    fn resource_subsets_preserve_customer_domain_subtree_groups_and_destination() -> Result<()> {
        let parent = ResourceTarget::GoogleDirectory {
            customer_id: "target".into(),
            email_domain: "exampleco.example".into(),
            org_unit_prefix: "/Engineering".into(),
            groups: BTreeMap::from([("developer".into(), "engineering@exampleco.example".into())]),
        };
        let child = ResourceTarget::GoogleDirectory {
            customer_id: "target".into(),
            email_domain: "exampleco.example".into(),
            org_unit_prefix: "/Engineering/Platform".into(),
            groups: BTreeMap::new(),
        };
        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
        for prefix in ["/EngineeringOther", "/", "/Sales"] {
            let target = ResourceTarget::GoogleDirectory {
                customer_id: "target".into(),
                email_domain: "exampleco.example".into(),
                org_unit_prefix: prefix.into(),
                groups: BTreeMap::new(),
            };
            assert!(!target.is_subset_of(&parent));
        }
        let invalid = ResourceTarget::GoogleDirectory {
            customer_id: "target".into(),
            email_domain: "exampleco.example".into(),
            org_unit_prefix: "/Engineering".into(),
            groups: BTreeMap::from([("developer".into(), "foreign@other.example".into())]),
        };
        assert!(invalid.validate().is_err());
        let alerts = ResourceTarget::OperatorAlertDestination {
            destination: "operator".into(),
            topics: day2_capabilities::resources::TopicScope::Prefix {
                prefix: "people.".into(),
            },
        };
        let narrowed = ResourceTarget::OperatorAlertDestination {
            destination: "operator".into(),
            topics: day2_capabilities::resources::TopicScope::Only {
                topics: BTreeSet::from(["people.failure".into()]),
            },
        };
        let foreign = ResourceTarget::OperatorAlertDestination {
            destination: "other".into(),
            topics: day2_capabilities::resources::TopicScope::Only {
                topics: BTreeSet::from(["people.failure".into()]),
            },
        };
        assert!(narrowed.is_subset_of(&alerts));
        assert!(!alerts.is_subset_of(&narrowed));
        assert!(!foreign.is_subset_of(&alerts));
        Ok(())
    }
}
