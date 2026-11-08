//! Owner-authenticated secret writes. Values remain in memory and at the provider.
//! Admission commits before I/O; an uncertain write is never automatically repeated.
use crate::{
    authority_state::{self, AuthorityStamp},
    error::Failure,
    owners::{self, Permission},
    store::Runtime,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::app_secrets::Namespace;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroizing;

mod gcp;
pub use gcp::Gcp;

pub const PATH: &str = "/api/app-secrets";
pub const MAX_VALUE: usize = 65_536;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Create,
    Rotate,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub name: String,
    pub container_created: bool,
    pub version: Option<u64>,
    pub blocked: bool,
    pub request_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listing {
    pub protocol: u32,
    pub kind: String,
    pub scope: String,
    pub actor: String,
    pub authority: AuthorityStamp,
    pub secrets: Vec<Entry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub protocol: u32,
    pub kind: String,
    pub scope: String,
    pub actor: String,
    pub name: String,
    pub operation: Operation,
    pub request_id: String,
    pub authority: AuthorityStamp,
    pub state: State,
    pub version: Option<u64>,
    pub activation_performed: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Admitted,
    ContainerDispatched,
    ContainerCreated,
    VersionDispatched,
    Stored,
    Refused,
    Unknown,
}

/// No secret material, payload hash, CRC or provider response is journalled.
pub struct Write {
    pub operation: Operation,
    pub name: String,
    pub expected_authority: AuthorityStamp,
    pub expected_version: Option<u64>,
    pub request_id: String,
    pub value: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct Target {
    namespace: Namespace,
    scope: String,
    name: String,
}
impl Target {
    pub fn resource(&self) -> String {
        format!(
            "projects/{}/secrets/{}{}",
            self.namespace.project_number,
            day2_capabilities::app_secrets::prefix(&self.scope),
            self.name
        )
    }
    pub fn scope(&self) -> &str {
        &self.scope
    }
}

/// Refused means the provider definitively rejected the write. All uncertain
/// transports, errors after dispatch, and malformed successes are Unknown.
#[derive(Clone, Copy, Debug)]
pub enum ProviderFailure {
    Refused,
    Unknown,
}
pub trait Provider: Send + Sync {
    fn create(&self, target: &Target, request_id: &str)
    -> std::result::Result<(), ProviderFailure>;
    fn add_version(
        &self,
        target: &Target,
        value: &[u8],
    ) -> std::result::Result<u64, ProviderFailure>;
}

pub(crate) fn install(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE day2_app_secrets(
        name TEXT PRIMARY KEY, container_created INTEGER NOT NULL CHECK(container_created IN(0,1)),
        version INTEGER CHECK(version>0), blocked INTEGER NOT NULL CHECK(blocked IN(0,1)),
        request_id TEXT NOT NULL, namespace TEXT NOT NULL
    ) STRICT;
    CREATE TABLE day2_app_secret_requests(
        id TEXT PRIMARY KEY, receipt TEXT NOT NULL
    ) STRICT;
    CREATE TABLE day2_app_secret_events(
        sequence INTEGER PRIMARY KEY, request_id TEXT NOT NULL, event TEXT NOT NULL, receipt TEXT NOT NULL,
        FOREIGN KEY(request_id) REFERENCES day2_app_secret_requests(id)
    ) STRICT;
    CREATE TRIGGER day2_app_secret_events_no_update BEFORE UPDATE ON day2_app_secret_events
      BEGIN SELECT RAISE(ABORT,'append_only_secret_audit'); END;
    CREATE TRIGGER day2_app_secret_events_no_delete BEFORE DELETE ON day2_app_secret_events
      BEGIN SELECT RAISE(ABORT,'append_only_secret_audit'); END;
    CREATE TRIGGER day2_app_secret_events_no_replace BEFORE INSERT ON day2_app_secret_events
      WHEN EXISTS(SELECT 1 FROM day2_app_secret_events WHERE sequence=NEW.sequence)
      BEGIN SELECT RAISE(ABORT,'append_only_secret_audit'); END;
    INSERT INTO day2_meta(key,value) VALUES('app_secrets_schema','1');")?;
    Ok(())
}

fn require_guards(db: &Connection) -> Result<()> {
    for (suffix, operation) in [
        ("no_update", "BEFORE UPDATE ON day2_app_secret_events"),
        ("no_delete", "BEFORE DELETE ON day2_app_secret_events"),
        (
            "no_replace",
            "BEFORE INSERT ON day2_app_secret_events WHEN EXISTS(SELECT 1 FROM day2_app_secret_events WHERE sequence=NEW.sequence)",
        ),
    ] {
        let name = format!("day2_app_secret_events_{suffix}");
        let sql = format!(
            "CREATE TRIGGER {name} {operation} BEGIN SELECT RAISE(ABORT,'append_only_secret_audit'); END"
        );
        crate::audit::validate_trigger(db, &name, &sql)?;
    }
    Ok(())
}

fn read_version(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<Option<u64>> {
    row.get::<_, Option<i64>>(column)?
        .map(|value| {
            u64::try_from(value).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    column,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })
        })
        .transpose()
}

fn namespace_in(
    db: &Connection,
    runtime: &Runtime,
    actor: &str,
    permission: Permission,
) -> Result<(Namespace, AuthorityStamp)> {
    let stamp = owners::authorize_in(db, runtime, actor, permission)?;
    let active = authority_state::current(db)?;
    let namespace = active
        .document
        .managed_secrets
        .context(Failure::Forbidden)?;
    require_guards(db)?;
    let schema: Option<String> = db
        .query_row(
            "SELECT value FROM day2_meta WHERE key='app_secrets_schema'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    ensure!(
        schema.as_deref() == Some("1"),
        "app_secret_schema_requires_fresh_initialization"
    );
    // Host credential selection and namespace changes require deliberate activation.
    let desired = crate::artifact::Instance::load(runtime.instance_path())?;
    ensure!(
        desired.scope(runtime.app())? == runtime.scope(),
        Failure::InstallationChanged
    );
    ensure!(
        desired
            .apps
            .get(runtime.app())
            .and_then(|app| app.managed_secrets.as_ref())
            == Some(&namespace),
        Failure::AuthorityPolicyChanged
    );
    namespace.validate()?;
    Ok((namespace, stamp))
}

fn namespace_id(namespace: &Namespace, runtime: &Runtime) -> Result<String> {
    Ok(
        day2_capabilities::Digest::of(&("app-secret-namespace-v1", runtime.scope(), namespace))?
            .as_str()
            .into(),
    )
}

pub fn list(runtime: &Runtime, actor: &str) -> Result<Listing> {
    runtime.sql_read(|db| {
        let (namespace, authority) = namespace_in(db, runtime, actor, Permission::SecretsList)?;
        let namespace = namespace_id(&namespace, runtime)?;
        let mut query = db.prepare("SELECT name,container_created,version,blocked,request_id FROM day2_app_secrets WHERE namespace=?1 ORDER BY name LIMIT 129")?;
        let secrets = query.query_map([namespace], |row| Ok(Entry {
            name: row.get(0)?, container_created: row.get(1)?, version: read_version(row, 2)?,
            blocked: row.get(3)?, request_id: row.get(4)?,
        }))?.collect::<rusqlite::Result<Vec<_>>>()?;
        ensure!(secrets.len() <= 128, "app_secret_budget");
        Ok(Listing { protocol: 1, kind: "app-secrets".into(), scope: runtime.scope().into(), actor: actor.into(), authority, secrets })
    })
}

pub fn status(runtime: &Runtime, actor: &str, request_id: &str) -> Result<Receipt> {
    validate_request(request_id)?;
    runtime.sql_read(|db| {
        namespace_in(db, runtime, actor, Permission::SecretsList)?;
        receipt_in(db, request_id)
    })
}

fn receipt_in(db: &Connection, id: &str) -> Result<Receipt> {
    let raw: String = db
        .query_row(
            "SELECT receipt FROM day2_app_secret_requests WHERE id=?1",
            [id],
            |row| row.get(0),
        )
        .optional()?
        .context(Failure::NotFound)?;
    let recorded: String = db.query_row("SELECT receipt FROM day2_app_secret_events WHERE request_id=?1 ORDER BY sequence DESC LIMIT 1", [id], |row| row.get(0))?;
    ensure!(raw == recorded, "secret_receipt_audit_mismatch");
    crate::json::decode(raw.as_bytes())
}

fn validate_request(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id != "."
            && id != ".."
            && id.len() <= 128
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)),
        Failure::InvalidIdempotencyKey
    );
    Ok(())
}

fn save(db: &Connection, receipt: &Receipt, event: &str) -> Result<()> {
    db.execute(
        "UPDATE day2_app_secret_requests SET receipt=?2 WHERE id=?1",
        params![receipt.request_id, serde_json::to_string(receipt)?],
    )?;
    db.execute(
        "INSERT INTO day2_app_secret_events(request_id,event,receipt) VALUES(?1,?2,?3)",
        params![receipt.request_id, event, serde_json::to_string(receipt)?],
    )?;
    Ok(())
}

fn admit(runtime: &Runtime, actor: &str, input: &Write) -> Result<(Target, Receipt)> {
    validate_request(&input.request_id)?;
    let _: day2_capabilities::Name = input
        .name
        .clone()
        .try_into()
        .map_err(|_| Failure::InvalidInput)?;
    ensure!(input.name.len() <= 40, Failure::InvalidInput);
    ensure!(
        !input.value.is_empty() && input.value.len() <= MAX_VALUE,
        Failure::InvalidInput
    );
    let permission = match input.operation {
        Operation::Create => Permission::SecretsCreate,
        Operation::Rotate => Permission::SecretsRotate,
    };
    runtime.sql_write(|db| {
        let (namespace, authority) = namespace_in(db, runtime, actor, permission)?;
        ensure!(authority == input.expected_authority, Failure::AuthorityPolicyChanged);
        let exists: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM day2_app_secret_requests WHERE id=?1)", [&input.request_id], |row| row.get(0))?;
        // We never persist secret-derived retry fingerprints. Reusing an ID is
        // always a conflict: inspect its receipt instead of resubmitting values.
        ensure!(!exists, Failure::IdempotencyKeyConflict);
        let namespace_id = namespace_id(&namespace, runtime)?;
        let previous: Option<(bool, Option<u64>, bool, String)> = db.query_row(
            "SELECT container_created,version,blocked,namespace FROM day2_app_secrets WHERE name=?1", [&input.name],
            |row| Ok((row.get(0)?, read_version(row, 1)?, row.get(2)?, row.get(3)?)),
        ).optional()?;
        if let Some((created, version, blocked, selected)) = &previous {
            ensure!(*selected == namespace_id, Failure::AuthorityPolicyChanged);
            ensure!(!blocked, Failure::ExternalAmbiguous);
            ensure!(match input.operation { Operation::Create => !created && input.expected_version.is_none(), Operation::Rotate => *created && *version == input.expected_version }, Failure::Conflict);
        } else {
            ensure!(input.operation == Operation::Create && input.expected_version.is_none(), Failure::Conflict);
            let count: i64 = db.query_row("SELECT count(*) FROM day2_app_secrets", [], |row| row.get(0))?;
            ensure!(count < 128, Failure::InvalidInput);
        }
        let receipt = Receipt { protocol: 1, kind: "app-secret-write".into(), scope: runtime.scope().into(), actor: actor.into(), name: input.name.clone(), operation: input.operation, request_id: input.request_id.clone(), authority, state: State::Admitted, version: None, activation_performed: false };
        db.execute("INSERT INTO day2_app_secret_requests(id,receipt) VALUES(?1,?2)", params![input.request_id, serde_json::to_string(&receipt)?])?;
        db.execute("INSERT INTO day2_app_secrets(name,container_created,version,blocked,request_id,namespace) VALUES(?1,0,NULL,1,?2,?3)
            ON CONFLICT(name) DO UPDATE SET blocked=1,request_id=excluded.request_id", params![input.name, input.request_id, namespace_id])?;
        save(db, &receipt, "admitted")?;
        Ok((Target { namespace, scope: runtime.scope().into(), name: input.name.clone() }, receipt))
    })
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Step {
    CreateContainer,
    AddVersion,
    Complete,
}

fn step(operation: Operation, phase: State) -> Result<Step> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Transition {
        operation: Operation,
        phase: State,
        step: Step,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Table {
        source: String,
        transitions: Vec<Transition>,
    }
    let table: Table = serde_json::from_str(include_str!("app_secrets/steps.json"))?;
    ensure!(
        table.source == crate::digest(include_bytes!("../../../ops/AppSecrets.roc")),
        "secret_recipe_table_stale"
    );
    let mut matching = table
        .transitions
        .into_iter()
        .filter(|row| row.operation == operation && row.phase == phase);
    let selected = matching
        .next()
        .context("invalid_secret_workflow_transition")?;
    ensure!(
        matching.next().is_none(),
        "ambiguous_secret_workflow_transition"
    );
    Ok(selected.step)
}

#[test]
fn embedded_recipe_matches_current_roc() -> Result<()> {
    let actual =
        crate::automation::run(&crate::automation::runner()?, &["app-secret-table"], |_| {
            anyhow::bail!("pure recipe requested an effect")
        })?;
    let embedded: serde_json::Value = serde_json::from_str(include_str!("app_secrets/steps.json"))?;
    ensure!(
        actual == embedded["transitions"],
        "regenerate secret recipe with xtask app-secrets-table"
    );
    for operation in [Operation::Create, Operation::Rotate] {
        for phase in [
            State::Admitted,
            State::ContainerDispatched,
            State::ContainerCreated,
            State::VersionDispatched,
            State::Stored,
            State::Refused,
            State::Unknown,
        ] {
            let input =
                serde_json::to_string(&serde_json::json!({"operation":operation,"phase":phase}))?;
            let roc = crate::automation::run(
                &crate::automation::runner()?,
                &["app-secret-step", &input],
                |_| anyhow::bail!("pure recipe requested an effect"),
            );
            match (step(operation, phase), roc) {
                (Ok(native), Ok(roc)) => assert_eq!(native, serde_json::from_value(roc)?),
                (Err(_), Err(_)) => {}
                _ => anyhow::bail!("embedded secret recipe differs from Roc"),
            }
        }
    }
    Ok(())
}

fn dispatch(runtime: &Runtime, actor: &str, receipt: &mut Receipt, state: State) -> Result<()> {
    runtime.sql_write(|db| {
        let permission = match receipt.operation {
            Operation::Create => Permission::SecretsCreate,
            Operation::Rotate => Permission::SecretsRotate,
        };
        let (_, stamp) = namespace_in(db, runtime, actor, permission)?;
        ensure!(stamp == receipt.authority, Failure::AuthorityPolicyChanged);
        let stored = receipt_in(db, &receipt.request_id)?;
        ensure!(stored == *receipt, Failure::Conflict);
        receipt.state = state;
        save(db, receipt, "dispatch_admitted")
    })
}

fn settle(
    runtime: &Runtime,
    receipt: &Receipt,
    created: bool,
    version: Option<u64>,
    terminal: bool,
) -> Result<()> {
    // Settlement records an already dispatched outcome even after revocation;
    // it confers no right to dispatch again or return it to a revoked caller.
    let version = version.map(i64::try_from).transpose()?;
    runtime.sql_write(|db| {
        authority_state::scope_matches(db, runtime)?;
        runtime.check_binding(db)?;
        db.execute("UPDATE day2_app_secrets SET container_created=max(container_created,?2),version=coalesce(?3,version),blocked=?4
            WHERE name=?1 AND request_id=?5", params![receipt.name, created, version, !terminal, receipt.request_id])?;
        save(db, receipt, "provider_outcome_recorded")
    })
}

pub fn write(
    runtime: &Runtime,
    actor: &str,
    input: &Write,
    provider: &dyn Provider,
) -> Result<Receipt> {
    // Verify installed recipe identity before recording a request or sending I/O.
    let _ = step(input.operation, State::Admitted)?;
    let (target, mut receipt) = admit(runtime, actor, input)?;
    for _ in 0..3 {
        match step(input.operation, receipt.state)? {
            Step::Complete => {
                runtime.sql_read(|db| {
                    namespace_in(db, runtime, actor, Permission::SecretsList)?;
                    Ok(())
                })?;
                return Ok(receipt);
            }
            Step::CreateContainer => {
                if let Err(error) =
                    dispatch(runtime, actor, &mut receipt, State::ContainerDispatched)
                {
                    receipt.state = State::Refused;
                    settle(runtime, &receipt, false, None, true)?;
                    return Err(error);
                }
                match provider.create(&target, &receipt.request_id) {
                    Ok(()) => {
                        receipt.state = State::ContainerCreated;
                        settle(runtime, &receipt, true, None, false)?;
                    }
                    Err(error) => {
                        receipt.state = match error {
                            ProviderFailure::Refused => State::Refused,
                            ProviderFailure::Unknown => State::Unknown,
                        };
                        settle(
                            runtime,
                            &receipt,
                            false,
                            None,
                            matches!(error, ProviderFailure::Refused),
                        )?;
                    }
                }
            }
            Step::AddVersion => {
                if let Err(error) = dispatch(runtime, actor, &mut receipt, State::VersionDispatched)
                {
                    receipt.state = State::Refused;
                    settle(
                        runtime,
                        &receipt,
                        input.operation == Operation::Create,
                        None,
                        true,
                    )?;
                    return Err(error);
                }
                match provider.add_version(&target, &input.value) {
                    Ok(version)
                        if version > 0
                            && i64::try_from(version).is_ok()
                            && input.expected_version.is_none_or(|old| version > old) =>
                    {
                        receipt.state = State::Stored;
                        receipt.version = Some(version);
                        settle(runtime, &receipt, true, Some(version), true)?;
                    }
                    result => {
                        receipt.state = if matches!(result, Err(ProviderFailure::Refused)) {
                            State::Refused
                        } else {
                            State::Unknown
                        };
                        settle(
                            runtime,
                            &receipt,
                            true,
                            None,
                            receipt.state == State::Refused,
                        )?;
                    }
                }
            }
        }
    }
    anyhow::bail!("app_secret_recipe_budget")
}

pub(crate) type Port = Arc<dyn Provider>;
