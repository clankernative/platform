use crate::{
    artifact::{Instance, LoadedArtifact},
    authority::{Change, Policy, RowFilter},
    identity::Id,
    protocol::*,
    schema::{Kind, Record, Schema},
    worker::Worker,
};
use anyhow::{Context as _, Result, bail, ensure};
use rusqlite::{
    Connection, OptionalExtension, Transaction, params, params_from_iter, types::Value as SqlValue,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const MAX_STEPS: usize = 64;

#[cfg(test)]
#[path = "app_effect_tests.rs"]
mod app_effect_tests;

#[cfg(test)]
#[path = "integration_host_tests.rs"]
mod integration_host_tests;

#[cfg(test)]
#[path = "read_coverage_tests.rs"]
mod read_coverage_tests;

#[cfg(test)]
#[path = "supply_tests.rs"]
mod supply_tests;

// Hosted here rather than beside `delegation` because it builds a `Runtime`
// directly, as every in-crate fixture does, and those fields are this module's.
#[cfg(test)]
#[path = "delegation_capability_tests.rs"]
mod delegation_capability_tests;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedPage {
    items: Vec<Row>,
    #[serde(rename = "has_more")]
    _has_more: bool,
    #[serde(rename = "next_after")]
    _next_after: Value,
}

pub(crate) fn observed_target(observation: &Observation, model: &str, target: &Row) -> bool {
    observation.error.is_empty()
        && observation.instruction.model == model
        && match observation.instruction.kind.as_str() {
            "get" | "create" | "update" => {
                serde_json::from_str::<Row>(&observation.result).is_ok_and(|row| row == *target)
            }
            "page" | "select_page" => serde_json::from_str::<ObservedPage>(&observation.result)
                .is_ok_and(|page| page.items.contains(target)),
            "find" => serde_json::from_str::<Vec<Row>>(&observation.result)
                .is_ok_and(|rows| rows.len() == 1 && rows[0] == *target),
            _ => false,
        }
}

#[cfg(test)]
mod observed_target_tests {
    use super::*;

    #[test]
    fn only_the_scheduled_typed_interruption_is_expected() {
        let error = Fault::AfterPrepare
            .interruption("simulated_process_loss")
            .context("execution interrupted");
        assert!(Fault::AfterPrepare.caused(&error));
        assert!(!Fault::AfterCommit.caused(&error));
        assert!(!Fault::None.caused(&error));
        assert!(!Fault::AfterPrepare.caused(&anyhow::anyhow!("simulated_process_loss")));
    }

    #[test]
    fn only_exact_successful_host_rows_authenticate_a_child_target() -> Result<()> {
        let target = Row {
            id: 17.into(),
            version: 3,
            created_at: 100,
            data: "{}".into(),
        };
        for kind in ["get", "create", "update", "page", "select_page", "find"] {
            let result = if matches!(kind, "page" | "select_page") {
                json!({"items":[target],"has_more":false,"next_after":17}).to_string()
            } else if kind == "find" {
                serde_json::to_string(&vec![target.clone()])?
            } else {
                serde_json::to_string(&target)?
            };
            let mut observation = Observation {
                instruction: Instruction {
                    kind: kind.into(),
                    model: "reports".into(),
                    ..Instruction::default()
                },
                result,
                error: String::new(),
            };
            assert!(observed_target(&observation, "reports", &target));
            assert!(!observed_target(&observation, "another_model", &target));
            assert!(!observed_target(
                &observation,
                "reports",
                &Row {
                    id: 18.into(),
                    ..target.clone()
                }
            ));
            assert!(!observed_target(
                &observation,
                "reports",
                &Row {
                    version: 4,
                    ..target.clone()
                }
            ));
            assert!(!observed_target(
                &observation,
                "reports",
                &Row {
                    data: "{\"forged\":true}".into(),
                    ..target.clone()
                }
            ));
            observation.error = "denied".into();
            assert!(!observed_target(&observation, "reports", &target));
        }
        for rows in [vec![], vec![target.clone(), target.clone()]] {
            let observation = Observation {
                instruction: Instruction {
                    kind: "find".into(),
                    model: "reports".into(),
                    ..Instruction::default()
                },
                result: serde_json::to_string(&rows)?,
                error: String::new(),
            };
            assert!(!observed_target(&observation, "reports", &target));
        }
        Ok(())
    }
}
#[cfg(test)]
mod unsigned_storage_tests {
    use super::*;
    use crate::numeric::Unsigned;
    use std::collections::BTreeMap;

    #[test]
    fn u64_values_roundtrip_exactly_through_sqlite_and_json_after_reopen() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("unsigned.sqlite");
        let kind = Kind::Unsigned(Unsigned::U64);
        let record = Record {
            fields: BTreeMap::from([("count".into(), kind.clone())]),
            roc_type: Some("Models.Count".into()),
            identity: None,
        };
        let schema = Schema {
            domains: BTreeMap::new(),
            models: BTreeMap::from([("counts".into(), record.clone())]),
            inputs: BTreeMap::from([("counts".into(), record.clone())]),
            foreign_keys: vec![],
            rollups: Vec::new(),
            indexes: vec![],
        };
        let values = [
            0,
            1,
            u64::from(u32::MAX) + 1,
            i64::MAX as u64,
            i64::MAX as u64 + 1,
            u64::MAX,
        ];
        {
            let connection = Connection::open(&path)?;
            for statement in schema.ddl()? {
                connection.execute_batch(&statement)?;
            }
            for value in values {
                connection.execute(
                    "INSERT INTO counts (version,created_at,count) VALUES (1,0,?1)",
                    [sql_value(&kind, &json!(value))?],
                )?;
            }
        }
        let connection = Connection::open(&path)?;
        for (index, value) in values.into_iter().enumerate() {
            let row = get(&connection, "counts", &record, (index as i64 + 1).into())?;
            assert_eq!(row.data, format!("{{\"count\":{value}}}"));
            let decoded: Value = serde_json::from_str(&row.data)?;
            assert_eq!(decoded["count"].as_u64(), Some(value));
        }
        let mut statement = connection.prepare("SELECT id FROM counts ORDER BY count DESC")?;
        let ids = statement
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(ids, (1..=values.len() as i64).rev().collect::<Vec<_>>());
        for invalid in [
            json!(-1),
            json!(1.5),
            json!("18446744073709551615"),
            Value::Null,
        ] {
            assert!(sql_value(&kind, &invalid).is_err());
        }
        // Fail closed when loading malformed bytes, even if a database was tampered with.
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        connection.execute("UPDATE counts SET count=?1 WHERE id=1", [vec![0_u8; 7]])?;
        assert!(get(&connection, "counts", &record, 1.into()).is_err());
        Ok(())
    }
}

/// Why an invocation exists, and which application asked for it.
///
/// One argument rather than two adjacent strings, because `(trigger, caller)` at
/// a call site is two things a reader has to keep in the right order.
pub(crate) struct Cause<'a> {
    trigger: crate::audit::Trigger,
    /// The principal the work is for.
    actor: &'a str,
    caller: &'a str,
    /// Who the host verified, when that is not the principal the work is for.
    /// Empty means they are the same, which is the ordinary case.
    authenticated: &'a str,
}

/// One principal making a request on behalf of another, at an edge.
///
/// The three travel together because they are meaningless apart: the rule that
/// permits the pair is looked up by the path it arrived on.
pub struct ActingAs<'a> {
    /// Who the host verified.
    pub authenticated: &'a str,
    /// Who the work is for, and whom the operation's policy authorizes.
    pub actor: &'a str,
    pub trigger: crate::audit::Trigger,
}

impl<'a> Cause<'a> {
    /// A call another application in this instance is making, for the principal
    /// it was already acting for.
    pub(crate) fn delegated(actor: &'a str, caller: &'a str, authenticated: &'a str) -> Self {
        Self {
            trigger: crate::audit::Trigger::Delegated,
            actor,
            caller,
            authenticated,
        }
    }
}

pub(crate) const PLATFORM_DDL: &str = "
CREATE TABLE day2_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE day2_invocations(
 id TEXT PRIMARY KEY, operation TEXT NOT NULL, actor TEXT NOT NULL, input TEXT NOT NULL,
 artifact TEXT NOT NULL, now INTEGER NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','success','failure')),
 outcome TEXT, trace TEXT,
 trigger TEXT NOT NULL DEFAULT 'request' CHECK(length(trigger) BETWEEN 1 AND 32),
 caller TEXT NOT NULL DEFAULT '' CHECK(length(caller) <= 512),
 authenticated TEXT NOT NULL DEFAULT '' CHECK(length(authenticated) <= 512),
 delegation_rule TEXT NOT NULL DEFAULT '' CHECK(length(delegation_rule) <= 160)) STRICT;
CREATE TABLE day2_audit(invocation TEXT PRIMARY KEY REFERENCES day2_invocations(id),
 actor TEXT NOT NULL, operation TEXT NOT NULL, status TEXT NOT NULL, at INTEGER NOT NULL) STRICT;
CREATE TABLE day2_migrations(id TEXT PRIMARY KEY, source TEXT NOT NULL, target TEXT NOT NULL) STRICT;
CREATE TABLE day2_id_seeds(invocation TEXT PRIMARY KEY REFERENCES day2_invocations(id), seed BLOB NOT NULL CHECK(length(seed)=32)) STRICT;
";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    None,
    FailAfterWrite(usize),
    InterruptAfterWrite(usize),
    ExitAfterWrite(usize),
    BeforeCommit,
    AfterCommit,
    AfterPrepare,
    AfterDecisionCommit,
    AfterExternal(usize),
}

#[derive(Debug)]
struct InjectedInterruption {
    fault: Fault,
    code: &'static str,
}

impl std::fmt::Display for InjectedInterruption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}

impl std::error::Error for InjectedInterruption {}

impl Fault {
    pub(crate) fn interruption(self, code: &'static str) -> anyhow::Error {
        InjectedInterruption { fault: self, code }.into()
    }

    /// Only the interruption requested by this schedule is an expected failure.
    pub fn caused(self, error: &anyhow::Error) -> bool {
        error
            .downcast_ref::<InjectedInterruption>()
            .is_some_and(|interruption| self != Self::None && interruption.fault == self)
    }
}

#[derive(Clone)]
pub struct Runtime {
    integrations: Arc<crate::integration_host::Host>,
    instance_path: PathBuf,
    app: String,
    db: PathBuf,
    scope: String,
    artifact: Arc<LoadedArtifact>,
    host: Arc<dyn crate::host::Host>,
}

pub(crate) fn open(path: &Path) -> Result<Connection> {
    use std::os::unix::fs::PermissionsExt;
    let connection = Connection::open(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    connection.busy_timeout(Duration::from_secs(2))?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "trusted_schema", false)?;
    let ticks = Arc::new(AtomicUsize::new(0));
    connection.progress_handler(
        1_000,
        Some(move || ticks.fetch_add(1, Ordering::Relaxed) > 10_000),
    )?;
    Ok(connection)
}

impl Runtime {
    pub(crate) fn integrations(&self) -> &crate::integration_host::Host {
        self.integrations.as_ref()
    }

    /// Replace the provider host, selecting live or simulated dispatch. The
    /// deterministic campaign uses this to run every adapter offline; it is no
    /// longer test-only, because running offline is a supported mode rather than
    /// a testing convenience.
    pub(crate) fn with_integrations(mut self, host: crate::integration_host::Host) -> Self {
        self.integrations = Arc::new(host);
        self
    }
    pub fn instance_path(&self) -> &Path {
        &self.instance_path
    }

    pub fn app(&self) -> &str {
        &self.app
    }

    pub fn db(&self) -> &Path {
        &self.db
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    pub fn artifact(&self) -> &LoadedArtifact {
        &self.artifact
    }

    pub(crate) fn with_host(mut self, host: Arc<dyn crate::host::Host>) -> Self {
        self.host = host;
        self
    }

    pub(crate) fn host(&self) -> &dyn crate::host::Host {
        self.host.as_ref()
    }

    pub(crate) fn worker(&self, phase: Phase) -> Result<crate::host::Session> {
        crate::host::Session::start(&self.artifact, self.host.clone(), phase)
    }

    pub fn load(instance_path: &Path, app: &str) -> Result<Self> {
        let instance_path = instance_path.canonicalize()?;
        let instance = Instance::load(&instance_path)?;
        let binding = instance.apps.get(app).context("app_not_installed")?;
        let parent = instance_path.parent().context("instance directory")?;
        let directory = parent.join(".state");
        fs::create_dir_all(&directory)?;
        ensure!(
            !fs::symlink_metadata(&directory)?.file_type().is_symlink(),
            "state directory symlink"
        );
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        let db = directory.join(format!("{app}.sqlite"));
        if db.exists() {
            ensure!(
                !fs::symlink_metadata(&db)?.file_type().is_symlink(),
                "database symlink"
            );
        }
        // The instance file describes desired configuration. Once initialized,
        // only the transactionally activated database binding selects executable code.
        let active = if db.exists() {
            let connection = open(&db)?;
            if crate::authority_state::exists(&connection)? {
                Some(crate::authority_state::current(&connection)?)
            } else {
                None
            }
        } else {
            None
        };
        let artifact = LoadedArtifact::load(&active.as_ref().map_or_else(
            || parent.join(&binding.artifact),
            |authority| PathBuf::from(&authority.artifact_path),
        ))?;
        if let Some(active) = &active {
            ensure!(
                active.artifact_id == artifact.id(),
                "active_artifact_digest_mismatch"
            );
        }
        // A binding for a schedule this artifact does not declare would silently do
        // nothing -- which is exactly how a renamed schedule stops running without
        // anyone noticing. Refuse it here, where the operator can still see why.
        for name in binding.schedules.keys() {
            ensure!(
                artifact
                    .contract()
                    .schedules
                    .iter()
                    .any(|schedule| &schedule.name == name),
                "schedule_binding_names_no_declared_schedule: {name}"
            );
        }
        for (name, schedule) in &binding.schedules {
            ensure!(
                !schedule.actor.trim().is_empty(),
                "schedule_binding_requires_an_actor: {name}"
            );
        }
        // The same rule for endpoints: a binding naming an endpoint this artifact
        // does not declare would accept deliveries for nothing, or silently stop
        // accepting them when an endpoint is renamed.
        for (name, endpoint) in &binding.ingress {
            ensure!(
                artifact
                    .contract()
                    .ingress
                    .iter()
                    .any(|declared| &declared.name == name),
                "endpoint_binding_names_no_declared_endpoint: {name}"
            );
            ensure!(
                !endpoint.actor.trim().is_empty(),
                "endpoint_binding_requires_an_actor: {name}"
            );
            ensure!(
                endpoint.connection.revision > 0 && !endpoint.connection.id.trim().is_empty(),
                "endpoint_binding_requires_a_connection: {name}"
            );
        }
        let runtime = Self {
            integrations: Arc::new(crate::integration_host::Host::local(&instance_path)?),
            scope: instance.scope(app)?,
            instance_path,
            app: app.to_string(),
            db,
            artifact: Arc::new(artifact),
            host: Arc::new(crate::host::System),
        };
        Ok(runtime)
    }
    pub fn initialize(&self) -> Result<()> {
        let mut connection = open(&self.db)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        let tx = crate::write_queue::immediate(&mut connection)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='day2_meta')",
            [],
            |row| row.get(0),
        )?;
        if exists {
            self.check_binding(&tx)?;
            ensure!(
                crate::authority_state::exists(&tx)?,
                "authority_migration_required: explicitly activate current authority"
            );
        } else {
            self.artifact.require_current_api()?;
            tx.execute_batch(PLATFORM_DDL)?;
            for statement in self.artifact.contract().schema.ddl()? {
                tx.execute_batch(&statement)?;
            }
            for (key, value) in [
                ("scope", self.scope.clone()),
                ("schema", self.artifact.contract().schema_digest.clone()),
                (
                    "schema_json",
                    serde_json::to_string(&self.artifact.contract().schema)?,
                ),
            ] {
                tx.execute("INSERT INTO day2_meta VALUES(?1,?2)", (key, value))?;
            }
            let desired = Instance::load(&self.instance_path)?;
            ensure!(
                desired.scope(&self.app)? == self.scope,
                crate::error::Failure::InstallationChanged
            );
            crate::authority_state::initialize_new(&tx, self, &desired)?;
        }
        crate::audit::upgrade(&tx)?;
        crate::invocations::upgrade(&tx)?;
        crate::resources::upgrade(&tx)?;
        crate::budget::upgrade(&tx)?;
        crate::preparation::upgrade(&tx)?;
        crate::execution::upgrade(&tx)?;
        upgrade_selection_cursors(&tx)?;
        crate::authority_state::upgrade(&tx)?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn check_binding(&self, connection: &Connection) -> Result<()> {
        check_storage_binding(connection, &self.artifact, &self.scope)
    }
    pub(crate) fn authority(&self, operation: &str, actor: &str) -> Result<Policy> {
        let mut connection = open(&self.db)?;
        let tx = connection.transaction()?;
        let active = crate::authority_state::authorize_in(&tx, self, operation, actor)?;
        Ok(active.policy()?.clone())
    }
    /// The installation's operators, excluded from AnyHuman delegation.
    ///
    /// Read from the instance rather than the app's policy: an application must
    /// not be able to widen or narrow who counts as an operator of the
    /// installation that hosts it.
    pub(crate) fn operators(&self) -> Result<std::collections::BTreeSet<String>> {
        Ok(Instance::load(&self.instance_path)?
            .control
            .map(|control| control.operators)
            .unwrap_or_default())
    }

    pub(crate) fn authorize(&self, operation: &str, actor: &str) -> Result<()> {
        self.authority(operation, actor).map(|_| ())
    }

    /// A session may belong to a principal whose only permission is acting for
    /// others. This admits the session, never an operation or a chosen target.
    pub(crate) fn may_request_delegation(&self, authenticated: &str) -> Result<bool> {
        let db = open(&self.db)?;
        self.check_binding(&db)?;
        let active = crate::authority_state::current(&db)?;
        Ok(active.document.enabled
            && active.policy()?.delegations.values().any(|rule| {
                rule.authenticated.contains(authenticated) && rule.paths.contains("request")
            }))
    }

    fn check_authority(
        &self,
        connection: &Connection,
        request: &Request,
        policy: &Policy,
    ) -> Result<()> {
        let active = crate::authority_state::require_invocation_in(
            connection,
            self,
            &request.context.invocation_id,
            &request.operation,
            &request.context.actor,
        )?;
        ensure!(
            active.policy()? == policy,
            crate::error::Failure::AuthorityPolicyChanged
        );
        Ok(())
    }
    pub fn accept(
        &self,
        operation: &str,
        actor: &str,
        id: &str,
        input: &Value,
        now: i64,
    ) -> Result<()> {
        if let Err(error) = self.artifact.operation(operation) {
            self.audit_rejection(
                operation,
                actor,
                id,
                now,
                crate::audit::AttemptReason::UnknownOperation,
                crate::audit::Trigger::Request,
            )
            .context("mandatory_audit_unavailable")?;
            return Err(error);
        }
        self.accept_route(
            operation,
            actor,
            id,
            input,
            now,
            crate::audit::Trigger::Request,
        )
    }
    /// Accept a request one principal is making on behalf of another.
    ///
    /// `authenticated` is who the host verified; `actor` is who the work is
    /// for, and is what the operation's policy authorizes. An operator rule must
    /// permit the first to act as the second, by the authentication path this
    /// request arrived on — so a session cookie cannot exercise a rule written
    /// for a verified gateway assertion.
    pub fn accept_on_behalf_of(
        &self,
        operation: &str,
        acting: ActingAs<'_>,
        id: &str,
        input: &Value,
        now: i64,
    ) -> Result<()> {
        let ActingAs {
            authenticated,
            actor,
            trigger,
        } = acting;
        if let Err(error) = crate::authority::valid_actor(authenticated) {
            self.audit_admission_rejection(
                operation,
                (actor, authenticated),
                id,
                now,
                crate::audit::AttemptReason::InvalidIdentity,
                trigger,
            )
            .context("mandatory_audit_unavailable")?;
            return Err(error);
        }
        self.accept_with_caller(
            operation,
            actor,
            id,
            input,
            now,
            Cause {
                trigger,
                actor,
                caller: "",
                // The empty value is the stored representation of a direct
                // request, including an explicit request to act as oneself.
                authenticated: if authenticated == actor {
                    ""
                } else {
                    authenticated
                },
            },
        )
    }

    /// Accept a call another application makes with its existing effective
    /// principal. The callee independently authorizes that principal.
    pub(crate) fn accept_delegated(
        &self,
        operation: &str,
        id: &str,
        input: &Value,
        now: i64,
        // The calling application is who authenticated to this one; the
        // principal the work is for is unchanged by the hop.
        cause: Cause<'_>,
    ) -> Result<()> {
        self.accept_with_caller(operation, cause.actor, id, input, now, cause)
    }

    pub(crate) fn accept_route(
        &self,
        operation: &str,
        actor: &str,
        id: &str,
        input: &Value,
        now: i64,
        trigger: crate::audit::Trigger,
    ) -> Result<()> {
        self.accept_with_caller(
            operation,
            actor,
            id,
            input,
            now,
            Cause {
                trigger,
                actor,
                caller: "",
                authenticated: "",
            },
        )
    }

    fn accept_with_caller(
        &self,
        operation: &str,
        actor: &str,
        id: &str,
        input: &Value,
        now: i64,
        cause: Cause<'_>,
    ) -> Result<()> {
        let Cause {
            trigger,
            actor: _,
            caller,
            authenticated,
        } = cause;
        let initiator = if authenticated.is_empty() {
            actor
        } else {
            authenticated
        };
        use crate::audit::{Attempt, AttemptKind, AttemptOutcome, AttemptReason};
        let mut reason = AttemptReason::ArtifactRejected;
        let result = (|| -> Result<()> {
            self.artifact.require_current_api()?;
            reason = AttemptReason::InvalidIdentity;
            ensure!(
                !id.is_empty()
                    && id.len() <= 128
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)),
                "invalid_invocation_id"
            );
            reason = AttemptReason::InvalidClock;
            ensure!((0..=253_402_300_799).contains(&now), "invalid_clock");
            reason = AttemptReason::InvalidInput;
            ensure!(serde_json::to_vec(input)?.len() < 65_536, "input_too_large");
            reason = AttemptReason::AuthorizationRejected;
            self.authorize(operation, actor)?;
            let definition = self.artifact.route(operation)?;
            reason = AttemptReason::InvalidInput;
            self.artifact.contract().schema.inputs[&definition.input_type].validate_input(input)?;
            if let Some(contract) = &self.artifact.contract().app_contract {
                crate::domain::record(
                    &contract.domains,
                    &self.artifact.contract().schema.inputs[&definition.input_type],
                    input,
                )?;
            }
            reason = AttemptReason::StorageRejected;
            let mut connection = open(&self.db)?;
            let tx = crate::write_queue::immediate(&mut connection)?;
            self.check_binding(&tx)?;
            reason = AttemptReason::AuthorizationRejected;
            let active = crate::authority_state::authorize_in(&tx, self, operation, actor)?;
            // *Whom* the work is for is chosen once, at the outermost
            // invocation, and is immutable for the whole call tree.
            //
            // Two different things wear the same shape here. An edge may settle
            // that this request is for somebody other than whoever
            // authenticated — impersonation — and that needs an operator rule. A
            // hop between applications authenticates as the calling application
            // while carrying the *same* principal forward; it chooses nobody, so
            // it needs no rule and is not impersonation however it looks.
            //
            // What is refused is a later hop choosing a principal. If hop three
            // could, a chain could turn "acting for this customer" into "acting
            // for that one" behind an audit trail that still looked orderly, and
            // "on whose behalf" would have as many answers as there are hops. A
            // job that legitimately acts as many people wants one top-level
            // invocation each, which is the better audit shape anyway.
            let impersonating = !authenticated.is_empty() && authenticated != actor;
            let rule = match trigger {
                crate::audit::Trigger::Request | crate::audit::Trigger::Ingress
                    if impersonating =>
                {
                    ensure!(caller.is_empty(), "delegation_only_at_the_outermost_call");
                    // Use the policy whose revision is pinned below, under the
                    // same writer lock as authority activation and admission.
                    active.policy()?.may_act_as(
                        authenticated,
                        actor,
                        trigger.as_str(),
                        &self.operators()?,
                    )?
                }
                // The calling application, carrying the principal it already
                // had. The delegation grant authorized this hop; there is no
                // second principal to authorize.
                crate::audit::Trigger::Delegated => {
                    ensure!(
                        !caller.is_empty()
                            && authenticated.strip_prefix("app:") == caller.rsplit('.').next(),
                        "delegated_call_requires_a_calling_application"
                    );
                    String::new()
                }
                // Nothing else may introduce one. A schedule and an internal
                // command request both inherit, and neither has an edge at which
                // an operator rule could have been consulted.
                _ => {
                    ensure!(!impersonating, "delegation_only_at_the_outermost_call");
                    String::new()
                }
            };
            reason = AttemptReason::StorageRejected;
            crate::audit::upgrade(&tx)?;
            let canonical = serde_json::to_string(input)?;
            let existing = tx
                .query_row(
                    "SELECT operation,actor,input,artifact,status,
                     COALESCE(NULLIF(authenticated,''),actor)=?2
                        AND delegation_rule=?3 AND trigger=?4 AND caller=?5,
                     receipt
                     FROM day2_invocations WHERE id=?1",
                    params![id, initiator, rule, trigger.as_str(), caller],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, bool>(5)?,
                            row.get::<_, Option<String>>(6)?,
                        ))
                    },
                )
                .optional()?;
            let reused = existing.is_some();
            if let Some((op, user, data, artifact, status, same_cause, receipt)) = existing {
                reason = AttemptReason::IdempotencyConflict;
                // A compacted invocation compares the input's digest instead.
                let same_input = crate::journal::same_input(&data, receipt.as_deref(), &canonical)?;
                ensure!(
                    op == operation
                        && user == actor
                        && same_input
                        && artifact == self.artifact.id()
                        && same_cause,
                    crate::error::Failure::IdempotencyKeyConflict
                );
                // Reuse never transfers an old idempotency key to newly granted authority.
                if status == "pending" {
                    crate::authority_state::require_invocation_in(&tx, self, id, operation, actor)?;
                }
            } else {
                tx.execute("INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status,trigger,caller,authenticated,delegation_rule) VALUES(?1,?2,?3,?4,?5,?6,'pending',?7,?8,?9,?10)",
                params![id,operation,actor,canonical,self.artifact.id(),now,trigger.as_str(),caller,authenticated,rule])?;
                crate::authority_state::pin_invocation(&tx, id, &active.stamp)?;
                crate::resources::capture_root_budgets(&tx, id, &definition.name, &active)?;
                let seed = self.host.entropy(&self.scope, id)?;
                tx.execute(
                    "INSERT INTO day2_id_seeds VALUES(?1,?2)",
                    params![id, seed.as_slice()],
                )?;
                for (field, kind) in
                    &self.artifact.contract().schema.inputs[&definition.input_type].fields
                {
                    if matches!(kind, Kind::IdCursor)
                        && let Some(token) =
                            input[field].as_str().filter(|raw| raw.starts_with("sel1_"))
                    {
                        decode_selection_cursor(&tx, token, now)?;
                        pin_selection_cursor(&tx, token, id)?;
                    }
                }
            }
            reason = AttemptReason::StorageRejected;
            crate::audit::record_attempt(
                &tx,
                self,
                Attempt {
                    kind: AttemptKind::Admission,
                    trigger,
                    identity: id,
                    actor,
                    initiator,
                    operation,
                    outcome: if reused {
                        AttemptOutcome::Reused
                    } else {
                        AttemptOutcome::Accepted
                    },
                    reason: None,
                    at_ms: now.checked_mul(1000).context("audit clock overflow")?,
                },
            )?;
            tx.commit()?;
            Ok(())
        })();
        if result.is_err() {
            self.audit_admission_rejection(operation, (actor, initiator), id, now, reason, trigger)
                .context("mandatory_audit_unavailable")?;
        }
        result
    }
    pub fn invoke(
        &self,
        operation: &str,
        actor: &str,
        id: &str,
        input: &Value,
        now: i64,
        fault: Fault,
    ) -> Result<Outcome> {
        self.accept(operation, actor, id, input, now)?;
        self.execute(id, fault)
    }
    pub fn execute(&self, id: &str, fault: Fault) -> Result<Outcome> {
        // Blocking is host-owned execution metadata, not an application failure or
        // permission to rerun already committed work with another identity.
        let connection = open(&self.db)?;
        self.check_binding(&connection)?;
        if crate::authority_state::is_blocked(&connection, id)? {
            return Ok(blocked_outcome(id));
        }
        drop(connection);
        let result = self.execute_inner(id, fault);
        if let Err(error) = &result
            && matches!(
                crate::error::classify(error),
                crate::error::Failure::AuthorityPolicyChanged
                    | crate::error::Failure::PreparationAuthorityChanged
                    | crate::error::Failure::EffectAuthorityChanged
                    | crate::error::Failure::ContinuationAuthorityChanged
                    | crate::error::Failure::ResourceAuthorityExpired
            )
        {
            let mut connection = open(&self.db)?;
            let tx = crate::write_queue::immediate(&mut connection)?;
            let pending: bool = tx.query_row(
                "SELECT status='pending' FROM day2_invocations WHERE id=?1",
                [id],
                |row| row.get(0),
            )?;
            if pending {
                crate::authority_state::block_invocation(
                    &tx,
                    id,
                    crate::error::classify(error).code(),
                )?;
                tx.commit()?;
                return Ok(blocked_outcome(id));
            }
        }
        if result.is_err() {
            self.audit_execution_interruption(id)
                .context("mandatory_audit_unavailable")?;
        }
        result
    }
    fn execute_inner(&self, id: &str, fault: Fault) -> Result<Outcome> {
        let continuing = crate::execution::advance(self, id, fault)?;
        let prepared = if continuing {
            Vec::new()
        } else {
            crate::preparation::prepare(self, id)?
        };
        if fault == Fault::AfterPrepare {
            return Err(fault.interruption("simulated_process_loss"));
        }
        let mut connection = open(&self.db)?;
        let tx = crate::write_queue::immediate(&mut connection)?;
        self.check_binding(&tx)?;
        crate::audit::upgrade(&tx)?;
        let (operation, actor, input, artifact, status, completed): (String,String,String,String,String,Option<String>) =
            tx.query_row("SELECT operation,actor,input,artifact,status,outcome FROM day2_invocations WHERE id=?1", [id],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
        ensure!(
            artifact == self.artifact.id(),
            "pinned_artifact_unavailable"
        );
        let active = crate::authority_state::authorize_in(&tx, self, &operation, &actor)?;
        let policy = active.policy()?.clone();
        if status != "pending" {
            return completed_outcome(&tx, id, completed.as_deref(), &policy);
        }
        crate::authority_state::require_invocation_in(&tx, self, id, &operation, &actor)?;
        // Still pending, so any saved trace is intact: compaction only touches
        // completed invocations.
        let continuation = crate::execution::load(&tx, id)?;
        if continuation
            .as_ref()
            .is_some_and(|(phase, _)| *phase != Phase::Complete)
        {
            return Ok(Outcome {
                status: "pending".into(),
                result: json!({"invocation_id":id}),
                error: String::new(),
            });
        }
        let definition = self.artifact.route(&operation)?;
        let kind = definition.kind.clone();
        let registered_operation = definition.name.clone();
        let input_value: Value = serde_json::from_str(&input)?;
        self.artifact.contract().schema.inputs[&definition.input_type]
            .validate_input(&input_value)?;
        let execution = app_execution(self.artifact.contract(), &registered_operation);
        let precondition_row =
            match precondition_target(&policy, &registered_operation, &input_value, execution) {
                Ok(Some(target)) => get_optional(
                    &tx,
                    &target.model,
                    &self.artifact.contract().schema.models[&target.model],
                    target.id,
                )?,
                _ => None,
            };
        let mut guard = ExecutionGuard {
            error: check_precondition(
                &policy,
                &registered_operation,
                &actor,
                &input_value,
                precondition_row.as_ref(),
                execution,
            )
            .err()
            .map(|error| crate::error::observation_code(&error))
            .unwrap_or_default(),
            policy: policy.clone(),
            authority: Some(active.stamp.clone()),
            precondition_row,
        };
        let child_guard = crate::invocations::validate_target(self, &tx, id, &policy);
        let mut request = Request {
            operation,
            input,
            context: invocation_context(&tx, id)?,
            observations: prepared,
        };
        if let Some((_, saved)) = continuation {
            ensure!(
                saved.request.operation == request.operation
                    && saved.request.input == request.input
                    && saved.request.context == request.context,
                "continuation_request_mismatch"
            );
            guard = saved.guard.context("continuation_guard_missing")?;
            ensure!(
                guard.policy == policy && guard.authority.as_ref() == Some(&active.stamp),
                crate::error::Failure::ContinuationAuthorityChanged
            );
            request = saved.request;
        } else if let Err(error) =
            crate::preparation::validate_local(self, &tx, &request, &policy, &registered_operation)
            && let Some(boundary) = request
                .observations
                .last_mut()
                .filter(|observation| observation.instruction.kind == "decide")
        {
            boundary.result.clear();
            boundary.error = crate::error::observation_code(&error);
        }
        let outcome = if !guard.error.is_empty() {
            request.observations.clear();
            Outcome {
                status: "failure".into(),
                result: Value::Null,
                error: guard.error.clone(),
            }
        } else {
            if let Err(error) = child_guard
                && let Some(boundary) = request
                    .observations
                    .last_mut()
                    .filter(|entry| entry.instruction.kind == "decide")
            {
                boundary.result.clear();
                boundary.error = crate::error::observation_code(&error);
            }
            for observation in &request.observations {
                crate::resources::validate_cached(&tx, self, &request, observation)?;
            }
            self.run_transaction(
                &tx,
                &mut request,
                &policy,
                &registered_operation,
                &kind,
                fault,
            )?
        };
        let trace = Trace {
            format: 2,
            artifact: self.artifact.id().to_owned(),
            scope: self.scope.clone(),
            request,
            outcome: outcome.clone(),
            guard: Some(guard),
        };
        self.check_authority(&tx, &trace.request, &policy)?;
        if outcome.status == "pending" {
            crate::invocations::validate_requests(self, &tx, &trace.request)?;
            crate::execution::begin(self, &tx, &trace)?;
            if fault == Fault::BeforeCommit {
                return Err(fault.interruption("simulated_process_loss"));
            }
            tx.commit()?;
            if fault == Fault::AfterDecisionCommit || fault == Fault::AfterCommit {
                return Err(fault.interruption("simulated_process_loss"));
            }
            return Ok(outcome);
        }
        if outcome.status == "failure" {
            // A refusal needs a durable receipt but must retain no app effects.
            // Roll back first, then recheck authority and any competing completion.
            tx.rollback()?;
            let tx = crate::write_queue::immediate(&mut connection)?;
            self.check_binding(&tx)?;
            self.check_authority(&tx, &trace.request, &policy)?;
            let existing: Option<String> = tx.query_row(
                "SELECT outcome FROM day2_invocations WHERE id=?1",
                [id],
                |r| r.get(0),
            )?;
            if let Some(existing) = existing {
                return completed_outcome(&tx, id, Some(&existing), &policy);
            }
            complete(&tx, id, &trace)?;
            tx.commit()?;
        } else {
            crate::invocations::validate_requests(self, &tx, &trace.request)?;
            if fault == Fault::BeforeCommit {
                return Err(fault.interruption("simulated_process_loss"));
            }
            complete(&tx, id, &trace)?;
            tx.commit()?;
            if fault == Fault::AfterCommit {
                return Err(fault.interruption("ambiguous_after_commit"));
            }
        }
        Ok(outcome)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_transaction(
        &self,
        connection: &Transaction<'_>,
        request: &mut Request,
        policy: &Policy,
        operation: &str,
        kind: &str,
        fault: Fault,
    ) -> Result<Outcome> {
        let mut writes = 0;
        let mut effect_failed = request
            .observations
            .iter()
            .any(|observation| !observation.error.is_empty());
        let mut phase = Phase::after(&request.observations, self.artifact.contract().format >= 13)?;
        let mut worker = self.worker(phase)?;
        // Pure decisions re-evaluate against the host's ordered observations.
        // Exact consumption and failure latching forbid divergence or swallowed denials.
        loop {
            let response = worker.exchange(request)?;
            let reply = response.decode()?;
            ensure!(
                response.consumed == request.observations.len(),
                "replay_consumption_mismatch"
            );
            ensure!(
                !effect_failed || matches!(reply, Reply::Failed(_)),
                "effect_failure_must_abort_transaction"
            );
            match reply {
                Reply::Done(result) => {
                    ensure!(
                        matches!(phase, Phase::Decide | Phase::Complete),
                        "missing_decision_boundary"
                    );
                    if request
                        .observations
                        .iter()
                        .any(|entry| entry.instruction.kind == "request")
                    {
                        ensure!(
                            request
                                .observations
                                .last()
                                .is_some_and(|entry| entry.instruction.kind == "commit"
                                    && entry.error.is_empty()),
                            "child command requests require final host commit guard"
                        );
                    }
                    return Ok(Outcome {
                        status: "success".into(),
                        result: self.artifact.decode_result(&request.operation, result)?,
                        error: String::new(),
                    });
                }
                Reply::Failed(error) => {
                    if response.error.starts_with("app:") {
                        ensure!(
                            self.artifact
                                .contract()
                                .app_contract
                                .as_ref()
                                .and_then(|definition| definition.operations.get(operation))
                                .is_some_and(|definition| definition
                                    .errors
                                    .contains(&response.error)),
                            "undeclared_application_failure"
                        );
                    }
                    return Ok(Outcome {
                        status: "failure".into(),
                        result: Value::Null,
                        error: error.to_owned(),
                    });
                }
                Reply::Pending(step) => {
                    ensure!(
                        request.observations.len() < MAX_STEPS,
                        "transaction_step_budget"
                    );
                    self.check_authority(connection, request, policy)?;
                    let next_phase = phase.advance(step)?;
                    let instruction = response.instruction.clone();
                    if step == Step::Boundary(Boundary::Effects) {
                        ensure!(
                            kind == "command"
                                && !request
                                    .observations
                                    .iter()
                                    .any(|entry| entry.instruction.kind == "effects"),
                            "invalid_effect_phase"
                        );
                        crate::invocations::validate_requests(self, connection, request)?;
                        request.observations.push(Observation {
                            instruction,
                            result: "{}".into(),
                            error: String::new(),
                        });
                        return Ok(Outcome {
                            status: "pending".into(),
                            result: json!({"invocation_id":request.context.invocation_id}),
                            error: String::new(),
                        });
                    }
                    let mutation = step.mutation();
                    let result = (|| -> Result<String> {
                        ensure!(!mutation || kind != "query", "query_write_forbidden");
                        if matches!(step, Step::Database(Database::Write { .. }))
                            && let Some(contract) = &self.artifact.contract().app_contract
                        {
                            crate::domain::record(
                                &contract.domains,
                                self.artifact
                                    .contract()
                                    .schema
                                    .models
                                    .get(&instruction.model)
                                    .context("unknown_model")?,
                                &serde_json::from_str(&instruction.data)?,
                            )?;
                        }
                        if mutation
                            && kind == "command"
                            && let Some(execution) =
                                app_execution(self.artifact.contract(), operation)
                        {
                            check_app_effect(
                                connection,
                                &self.artifact.contract().schema,
                                execution,
                                &instruction,
                                &serde_json::from_str(&request.input)?,
                                &request.context.invocation_id,
                            )?;
                        }
                        if step == Step::Boundary(Boundary::Commit) {
                            crate::invocations::validate_requests(self, connection, request)?;
                            Ok("{}".into())
                        } else if matches!(step, Step::Request { .. }) {
                            ensure!(kind == "command", "command_request_forbidden");
                            crate::invocations::request(
                                self,
                                connection,
                                request,
                                &instruction,
                                policy,
                                operation,
                            )
                        } else {
                            effect(
                                connection,
                                &self.artifact.contract().schema,
                                &self.scope,
                                request,
                                &instruction,
                                policy,
                                operation,
                            )
                        }
                    })();
                    let result = match result {
                        Ok(result) => result,
                        Err(error) => {
                            request.observations.push(Observation {
                                instruction,
                                result: String::new(),
                                error: crate::error::observation_code(&error),
                            });
                            effect_failed = true;
                            continue;
                        }
                    };
                    request.observations.push(Observation {
                        instruction,
                        result,
                        error: String::new(),
                    });
                    phase = next_phase;
                    if mutation {
                        writes += 1;
                        match fault {
                            Fault::ExitAfterWrite(n) if n == writes => std::process::exit(86),
                            Fault::InterruptAfterWrite(n) if n == writes => {
                                return Err(fault.interruption("simulated_process_loss"));
                            }
                            Fault::FailAfterWrite(n) if n == writes => {
                                let observation =
                                    request.observations.last_mut().context("missing write")?;
                                observation.result.clear();
                                observation.error = "injected_failure".into();
                                effect_failed = true;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    pub fn trace(&self, id: &str) -> Result<Trace> {
        let connection = open(&self.db)?;
        self.check_binding(&connection)?;
        let raw: Option<String> = connection.query_row(
            "SELECT trace FROM day2_invocations WHERE id=?1",
            [id],
            |r| r.get(0),
        )?;
        // Completed invocations keep only a receipt once the journal window passes.
        Ok(serde_json::from_str(
            &raw.context("invocation_trace_compacted")?,
        )?)
    }
    pub fn render_page(
        &self,
        page: &str,
        actor: &str,
        id: &str,
        input: &Value,
        now: i64,
    ) -> Result<Outcome> {
        let operation = format!("$page.{page}");
        if let Err(error) = self.artifact.page(page) {
            self.audit_rejection(
                &operation,
                actor,
                id,
                now,
                crate::audit::AttemptReason::UnknownOperation,
                crate::audit::Trigger::Request,
            )
            .context("mandatory_audit_unavailable")?;
            return Err(error);
        }
        self.accept_route(
            &operation,
            actor,
            id,
            input,
            now,
            crate::audit::Trigger::Request,
        )?;
        self.execute(id, Fault::None)
    }
    /// Validate the complete stored representation without materializing an app
    /// property snapshot. Backups must not inherit the simulator's row budget.
    /// This checks storage bindings, row codecs and references, not app invariants.
    pub fn validate_storage(&self) -> Result<()> {
        let mut connection = open(&self.db)?;
        validate_storage_snapshot(&mut connection, &self.artifact, &self.scope)
    }

    pub fn inspect(&self) -> Result<Value> {
        let mut connection = open(&self.db)?;
        let snapshot = connection.transaction()?;
        self.check_binding(&snapshot)?;
        let limit = crate::properties::MAX_ROWS_PER_MODEL;
        let mut models = serde_json::Map::new();
        for (name, record) in &self.artifact.contract().schema.models {
            let sql = format!(
                "SELECT {} FROM \"{name}\" ORDER BY id LIMIT {}",
                projection(record),
                limit + 1
            );
            let mut statement = snapshot.prepare(&sql)?;
            let rows = statement
                .query_map([], |row| read_row(row, record))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            ensure!(rows.len() <= limit, "inspection_limit");
            models.insert(name.clone(), serde_json::to_value(rows)?);
        }
        for rollup in &self.artifact.contract().schema.rollups {
            ensure!(
                rollup.mismatches(&snapshot)? == 0,
                "rollup_recount_mismatch: {}",
                rollup.table()
            );
        }
        snapshot.commit()?;
        Ok(Value::Object(models))
    }
}

fn check_storage_binding(
    connection: &Connection,
    artifact: &LoadedArtifact,
    expected_scope: &str,
) -> Result<()> {
    let scope: String =
        connection.query_row("SELECT value FROM day2_meta WHERE key='scope'", [], |row| {
            row.get(0)
        })?;
    let schema: String = connection.query_row(
        "SELECT value FROM day2_meta WHERE key='schema'",
        [],
        |row| row.get(0),
    )?;
    ensure!(scope == expected_scope, "database_scope_mismatch");
    ensure!(
        schema == artifact.contract().schema_digest,
        "schema_migration_required"
    );
    if crate::authority_state::exists(connection)? {
        let active = crate::authority_state::current(connection)?;
        ensure!(
            active.artifact_id == artifact.id(),
            crate::error::Failure::ArtifactBindingChanged
        );
    }
    Ok(())
}

/// Stream the complete stored representation in one read transaction. Native
/// backup validation uses the completed copy and its captured artifact, so a
/// concurrently changing source cannot substitute a different sampled world.
/// This checks structural storage validity, not bounded app property invariants.
pub fn validate_storage_snapshot(
    connection: &mut Connection,
    artifact: &LoadedArtifact,
    scope: &str,
) -> Result<()> {
    let snapshot = connection.transaction()?;
    check_storage_binding(&snapshot, artifact, scope)?;
    for (name, record) in &artifact.contract().schema.models {
        let sql = format!("SELECT {} FROM \"{name}\" ORDER BY id", projection(record));
        let mut statement = snapshot.prepare(&sql)?;
        let mut rows = statement.query([])?;
        while let Some(stored) = rows.next()? {
            let row = read_row(stored, record)?;
            ensure!(
                row.id.valid() && row.version > 0,
                "invalid stored row identity"
            );
            record.validate_value(&serde_json::from_str(&row.data)?)?;
        }
    }
    {
        let mut statement = snapshot.prepare("PRAGMA foreign_key_check")?;
        ensure!(
            statement.query([])?.next()?.is_none(),
            "invalid stored foreign key"
        );
    }
    for rollup in &artifact.contract().schema.rollups {
        ensure!(
            rollup.mismatches(&snapshot)? == 0,
            "rollup_recount_mismatch: {}",
            rollup.table()
        );
    }
    snapshot.commit()?;
    Ok(())
}

pub(crate) fn blocked_outcome(id: &str) -> Outcome {
    Outcome {
        status: "blocked".into(),
        result: json!({"invocation_id": id}),
        error: "authority_policy_changed".into(),
    }
}

pub(crate) fn completed_outcome(
    connection: &Connection,
    id: &str,
    outcome: Option<&str>,
    policy: &crate::authority::Policy,
) -> Result<Outcome> {
    let (raw, receipt): (Option<String>, Option<String>) = connection.query_row(
        "SELECT trace,receipt FROM day2_invocations WHERE id=?1",
        [id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if raw.is_none()
        && let Some(receipt) = receipt
    {
        return compacted_outcome(connection, id, outcome, policy, &receipt);
    }
    let trace: Trace =
        serde_json::from_str(&raw.context(crate::error::Failure::ReceiptAuthorityUnavailable)?)?;
    ensure!(
        trace.format == 2,
        crate::error::Failure::ReceiptAuthorityUnavailable
    );
    let guard = trace
        .guard
        .context(crate::error::Failure::ReceiptAuthorityUnavailable)?;
    let active = crate::authority_state::current(connection)?;
    let stamp = crate::authority_state::invocation_stamp(connection, id)?;
    ensure!(
        guard.policy == *policy
            && guard.authority.as_ref() == Some(&stamp)
            && active.stamp == stamp,
        crate::error::Failure::ReceiptPolicyChanged
    );
    let outcome: Outcome = serde_json::from_str(outcome.context("missing durable outcome")?)?;
    outcome.decode()?;
    ensure!(trace.outcome == outcome, "receipt_outcome_mismatch");
    Ok(outcome)
}

/// The same reuse checks as [`completed_outcome`], for an invocation whose trace
/// was compacted: its policy is compared by digest and its outcome is the stored
/// outcome column, which compaction never changes. See `crate::journal`.
fn compacted_outcome(
    connection: &Connection,
    id: &str,
    outcome: Option<&str>,
    policy: &crate::authority::Policy,
    receipt: &str,
) -> Result<Outcome> {
    let receipt = crate::journal::Receipt::parse(receipt)?;
    let recorded = receipt
        .policy
        .context(crate::error::Failure::ReceiptAuthorityUnavailable)?;
    let active = crate::authority_state::current(connection)?;
    let stamp = crate::authority_state::invocation_stamp(connection, id)?;
    ensure!(
        recorded == crate::journal::policy_digest(policy)? && active.stamp == stamp,
        crate::error::Failure::ReceiptPolicyChanged
    );
    let outcome: Outcome = serde_json::from_str(outcome.context("missing durable outcome")?)?;
    outcome.decode()?;
    Ok(outcome)
}

fn complete(connection: &Transaction<'_>, id: &str, trace: &Trace) -> Result<()> {
    ensure!(connection.execute("UPDATE day2_invocations SET status=?1,outcome=?2,trace=?3 WHERE id=?4 AND status='pending'",
        params![trace.outcome.status,serde_json::to_string(&trace.outcome)?,serde_json::to_string(trace)?,id])? == 1, "invocation_completion_conflict");
    connection.execute(
        "INSERT INTO day2_audit VALUES(?1,?2,?3,?4,?5)",
        params![
            id,
            trace.request.context.actor,
            trace.request.operation,
            trace.outcome.status,
            trace.request.context.now
        ],
    )?;
    Ok(())
}

fn projection(record: &Record) -> String {
    std::iter::once("id,version,created_at".to_string())
        .chain(record.fields.keys().map(|name| format!("\"{name}\"")))
        .collect::<Vec<_>>()
        .join(",")
}

fn read_row(row: &rusqlite::Row<'_>, record: &Record) -> rusqlite::Result<Row> {
    let mut data = serde_json::Map::new();
    for (index, (name, kind)) in record.fields.iter().enumerate() {
        let value = match kind {
            Kind::Cursor | Kind::IdCursor | Kind::PageSize | Kind::InputShape { .. } => {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Kind::ModelReference { prefix, .. } => {
                let bytes: Vec<u8> = row.get(index + 3)?;
                let bytes: [u8; 16] = bytes
                    .try_into()
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                json!(Id::from_uuid(prefix, bytes).map_err(|_| rusqlite::Error::InvalidQuery)?)
            }
            Kind::Unsigned(crate::numeric::Unsigned::U64) => {
                let bytes: Vec<u8> = row.get(index + 3)?;
                let bytes: [u8; 8] = bytes
                    .try_into()
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                json!(u64::from_be_bytes(bytes))
            }
            Kind::Integer | Kind::Unsigned(_) | Kind::RowVersion | Kind::Reference { .. } => {
                json!(row.get::<_, i64>(index + 3)?)
            }
            Kind::Boolean => json!(row.get::<_, bool>(index + 3)?),
            Kind::Text | Kind::TextDomain { .. } | Kind::StandardText { .. } | Kind::WebUrl => {
                json!(row.get::<_, String>(index + 3)?)
            }
            Kind::OptionalText => match row.get::<_, Option<String>>(index + 3)? {
                Some(s) => json!({"Some": s}),
                None => json!("None"),
            },
        };
        data.insert(name.clone(), value);
    }
    Ok(Row {
        id: if let Some(identity) = &record.identity {
            let bytes: Vec<u8> = row.get(0)?;
            Id::from_uuid(
                &identity.prefix,
                bytes
                    .try_into()
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
            )
            .map_err(|_| rusqlite::Error::InvalidQuery)?
        } else {
            Id::Legacy(row.get(0)?)
        },
        version: row.get(1)?,
        created_at: row.get(2)?,
        data: Value::Object(data).to_string(),
    })
}

/// A soft-deleted row reads as absent.
///
/// The same default as a selection, for the same reason: an application never
/// has to remember to exclude deleted rows, because excluding them is not
/// something it does. A deleted row that could still be fetched by id would
/// surface as live on every detail page in the fleet, and — since `Entity`
/// carries no deletion flag — with nothing on the row to give it away.
/// What an application is told about how it came to be running.
///
/// One function, because two would be two answers. Preparation and execution
/// both hand a `Context` to the same application code, so a value that differed
/// between them would make an application emit different instructions in each
/// phase and fail its own replay check — a bug whose symptom, `replay_mismatch`,
/// names nothing that would lead anyone back to here.
pub(crate) fn invocation_context(connection: &Connection, id: &str) -> Result<Context> {
    let (actor, now, authentication, caller, authenticated, delegation_rule): (
        String,
        i64,
        String,
        String,
        String,
        String,
    ) = connection.query_row(
        "SELECT actor,now,trigger,caller,authenticated,delegation_rule
         FROM day2_invocations WHERE id=?1",
        [id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )?;
    Ok(Context {
        invocation_id: id.to_owned(),
        actor,
        now,
        authentication,
        caller: crate::delegation::chain(&caller),
        authenticated,
        delegation_rule,
    })
}

pub(crate) fn get(connection: &Connection, model: &str, record: &Record, id: Id) -> Result<Row> {
    get_optional(connection, model, record, id)?.context(crate::error::Failure::NotFound)
}

fn get_optional(
    connection: &Connection,
    model: &str,
    record: &Record,
    id: Id,
) -> Result<Option<Row>> {
    Ok(get_scoped(connection, model, record, id)?
        .filter(|(_, deleted)| !deleted)
        .map(|(row, _)| row))
}

/// Read a row whether or not it is deleted.
///
/// Only the deletion machinery itself is allowed to see past the default: the
/// before-image of a delete, the row a restore is bringing back, and the
/// after-image the audit log records. Every other path goes through `get`.
/// Read a row whether or not it is deleted, saying which it was.
///
/// Only the deletion machinery itself is allowed to see past the default: the
/// before-image of a delete, the row a restore is bringing back, and the
/// after-image the audit log records. Every other path goes through `get`.
/// The flag is returned beside the row rather than on it, so there is no field
/// an application could ever read — `Row` is what an app receives as `Entity`.
fn get_scoped(
    connection: &Connection,
    model: &str,
    record: &Record,
    id: Id,
) -> Result<Option<(Row, bool)>> {
    ensure!(id.valid(), "invalid_id");
    Ok(connection
        .query_row(
            &format!(
                "SELECT {}, deleted_at != 0 FROM \"{model}\" WHERE id=?1",
                projection(record)
            ),
            [id.sql(record.identity.as_ref())?],
            |row| Ok((read_row(row, record)?, row.get(record.fields.len() + 3)?)),
        )
        .optional()?)
}

fn get_any(connection: &Connection, model: &str, record: &Record, id: Id) -> Result<Row> {
    Ok(get_scoped(connection, model, record, id)?
        .context(crate::error::Failure::NotFound)?
        .0)
}

fn check_precondition(
    policy: &Policy,
    operation: &str,
    actor: &str,
    input: &Value,
    row: Option<&Row>,
    execution: Option<&crate::app_contract::Execution>,
) -> Result<()> {
    policy.authorize(operation, actor)?;
    if policy.edit_target(operation, input)?.is_some() {
        policy.check_edit(
            operation,
            actor,
            input,
            row.context(crate::error::Failure::NotFound)?,
        )?;
    }
    if let Some(target) = precondition_target(policy, operation, input, execution)? {
        let row = row.context(crate::error::Failure::NotFound)?;
        policy.check_read(
            operation,
            &target.model,
            actor,
            &serde_json::from_str(&row.data)?,
        )?;
        ensure!(
            row.id == target.id && row.version == target.version,
            crate::error::Failure::Conflict
        );
    } else {
        ensure!(row.is_none(), "unexpected_precondition_row");
    }
    Ok(())
}

fn app_execution<'a>(
    artifact: &'a crate::artifact::Artifact,
    operation: &str,
) -> Option<&'a crate::app_contract::Execution> {
    artifact
        .app_contract
        .as_ref()?
        .operations
        .get(operation)
        .map(|definition| &definition.execution)
}

fn precondition_target(
    policy: &Policy,
    operation: &str,
    input: &Value,
    execution: Option<&crate::app_contract::Execution>,
) -> Result<Option<crate::authority::EditTarget>> {
    let operator = policy.edit_target(operation, input)?;
    let application = execution
        .map(|definition| definition.target(input))
        .transpose()?
        .flatten();
    if let (Some(operator), Some(application)) = (&operator, &application) {
        ensure!(
            operator.model == application.model
                && operator.id == application.id
                && operator.version == application.version,
            "incompatible_edit_preconditions"
        );
    }
    Ok(application.or(operator))
}

fn check_app_effect(
    connection: &Connection,
    schema: &Schema,
    execution: &crate::app_contract::Execution,
    instruction: &Instruction,
    input: &Value,
    invocation: &str,
) -> Result<()> {
    if instruction.kind == "update"
        && let Some(target) = execution.target(input)?
    {
        ensure!(
            if target.model == instruction.model {
                target.id == instruction.id
            } else {
                execution.effects.iter().any(|effect| {
                    effect.kind == "update_created" && effect.model == instruction.model
                })
            },
            "application_edit_target_forbidden"
        );
    }
    if instruction.kind == "request" {
        let target: crate::invocations::CommandRequest = serde_json::from_str(&instruction.data)?;
        ensure!(
            execution
                .effects
                .iter()
                .any(|effect| effect.kind == "request" && effect.command == target.command),
            "undeclared_command_request"
        );
        return Ok(());
    }
    let allowed = execution
        .effects
        .iter()
        .find(|effect| {
            effect.model == instruction.model
                && (effect.kind == instruction.kind
                    || instruction.kind == "update" && effect.kind == "update_created"
                    // One declaration covers both directions: an operation
                    // permitted to delete a row may undo it. Requiring a second
                    // declaration to restore would leave apps able to delete
                    // but not repair, which is the wrong asymmetry.
                    || instruction.kind == "restore" && effect.kind == "soft_delete")
        })
        .context("undeclared_application_effect")?;
    if instruction.kind == "update" {
        if allowed.kind == "update_created" {
            ensure!(
                crate::audit::created_by_invocation(
                    connection,
                    invocation,
                    &instruction.model,
                    instruction.id,
                )?,
                "application_created_update_forbidden"
            );
        }
        let before = get(
            connection,
            &instruction.model,
            &schema.models[&instruction.model],
            instruction.id,
        )?;
        let before: Value = serde_json::from_str(&before.data)?;
        let after: Value = serde_json::from_str(&instruction.data)?;
        ensure!(
            after
                .as_object()
                .context("invalid_update")?
                .iter()
                .all(|(field, value)| before.get(field) == Some(value)
                    || allowed.fields.contains(field)),
            "undeclared_application_update_field"
        );
    }
    Ok(())
}

fn sql_value(kind: &Kind, value: &Value) -> Result<SqlValue> {
    Ok(match kind {
        Kind::Cursor | Kind::IdCursor | Kind::PageSize | Kind::InputShape { .. } => {
            bail!("input_only_types_are_not_persistent_fields")
        }
        Kind::ModelReference { prefix, .. } => SqlValue::Blob(
            Id::from_text(value.as_str().context("invalid_reference")?)?
                .bytes_for(prefix)?
                .to_vec(),
        ),
        Kind::Unsigned(crate::numeric::Unsigned::U64) => SqlValue::Blob(
            value
                .as_u64()
                .context("invalid_unsigned_integer")?
                .to_be_bytes()
                .to_vec(),
        ),
        Kind::Integer | Kind::Unsigned(_) | Kind::RowVersion | Kind::Reference { .. } => {
            SqlValue::Integer(
                value
                    .as_i64()
                    .context(crate::error::Failure::InvalidInteger)?,
            )
        }
        Kind::Boolean => SqlValue::Integer(i64::from(value.as_bool().context("invalid_boolean")?)),
        Kind::Text | Kind::TextDomain { .. } | Kind::StandardText { .. } | Kind::WebUrl => {
            SqlValue::Text(value.as_str().context("invalid_text")?.to_string())
        }
        Kind::OptionalText => {
            if value == "None" {
                SqlValue::Null
            } else {
                SqlValue::Text(
                    value["Some"]
                        .as_str()
                        .context("invalid_optional")?
                        .to_string(),
                )
            }
        }
    })
}

fn selection_field(schema: &Schema, model: &str, field: &str) -> Result<Option<Kind>> {
    if matches!(field, "id" | "version" | "created_at") {
        return Ok(None);
    }
    let record = schema.readable(model).context("unregistered_model")?;
    let kind = record
        .fields
        .get(field)
        .context("unknown_selection_field")?
        .clone();
    ensure!(
        schema.rollup(model).is_some()
            || schema
                .foreign_keys
                .iter()
                .any(|key| key.model == model && key.field == field)
            || schema
                .indexes
                .iter()
                .any(|index| index.model == model && index.fields.iter().any(|item| item == field)),
        "unsupported_unindexed_filter"
    );
    Ok(Some(kind))
}

fn selection_value(schema: &Schema, model: &str, field: &str, value: &Value) -> Result<SqlValue> {
    match selection_field(schema, model, field)? {
        None if field == "id" => {
            let id = if let Some(raw) = value.as_str() {
                crate::identity::parse_public_or_legacy(raw)?
            } else {
                serde_json::from_value::<Id>(value.clone())?
            };
            ensure!(id.valid(), "invalid_selection_value");
            id.sql(
                schema
                    .readable(model)
                    .context("unregistered_model")?
                    .identity
                    .as_ref(),
            )
        }
        None => {
            let number = value.as_i64().context("invalid_selection_value")?;
            ensure!(
                number >= i64::from(field == "version"),
                "invalid_selection_value"
            );
            Ok(SqlValue::Integer(number))
        }
        Some(Kind::Reference { .. }) if value.is_string() => {
            let id = crate::identity::parse_public_or_legacy(value.as_str().unwrap())?;
            id.sql(None)
        }
        Some(kind) => {
            ensure!(kind.valid(value), "invalid_selection_value");
            sql_value(&kind, value)
        }
    }
}

fn selection_predicate(
    schema: &Schema,
    model: &str,
    raw: &str,
    values: &mut Vec<SqlValue>,
) -> Result<String> {
    let node: SelectionPredicate = serde_json::from_str(raw)?;
    if matches!(node.kind.as_str(), "all" | "any") {
        if node.children.is_empty() {
            return Ok(if node.kind == "all" { "1" } else { "0" }.into());
        }
        let parts = node
            .children
            .iter()
            .map(|child| selection_predicate(schema, model, child, values))
            .collect::<Result<Vec<_>>>()?;
        return Ok(format!(
            "({})",
            parts.join(if node.kind == "all" { " AND " } else { " OR " })
        ));
    }
    ensure!(node.model == model, "selection_model_mismatch");
    let kind = selection_field(schema, model, &node.field)?;
    let value: Value = serde_json::from_str(&node.value)?;
    let operator = if node.kind == "like" {
        ensure!(
            matches!(
                kind,
                Some(
                    Kind::Text
                        | Kind::OptionalText
                        | Kind::TextDomain { .. }
                        | Kind::StandardText { .. }
                        | Kind::WebUrl
                )
            ),
            "invalid_selection_operator_type"
        );
        let pattern = value.as_str().context("invalid_selection_value")?;
        ensure!(pattern.len() <= 16_384, "invalid_selection_value");
        values.push(SqlValue::Text(pattern.to_string()));
        "LIKE"
    } else {
        values.push(selection_value(schema, model, &node.field, &value)?);
        "IS"
    };
    Ok(format!("\"{}\" {operator} ?{}", node.field, values.len()))
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectionCursor {
    pub(crate) binding: String,
    pub(crate) values: Vec<Value>,
}

const SELECTION_CURSOR_TTL: i64 = 86_400;
const SELECTION_CURSOR_CAPACITY: i64 = 10_000;
const SELECTION_CURSOR_PIN_CAPACITY: i64 = 100_000;

pub(crate) fn upgrade_selection_cursors(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS day2_selection_cursors (
            token TEXT PRIMARY KEY CHECK(length(token)=69),
            boundary_key TEXT NOT NULL UNIQUE,
            boundary TEXT NOT NULL CHECK(length(boundary)<=8192),
            expires_at INTEGER NOT NULL
        ) STRICT;
        CREATE INDEX IF NOT EXISTS day2_selection_cursors_expiry ON day2_selection_cursors(expires_at);
        CREATE TABLE IF NOT EXISTS day2_selection_cursor_pins (
            token TEXT NOT NULL REFERENCES day2_selection_cursors(token) ON DELETE CASCADE,
            invocation TEXT NOT NULL REFERENCES day2_invocations(id),
            PRIMARY KEY(token,invocation)
        ) STRICT;
        CREATE INDEX IF NOT EXISTS day2_selection_cursor_pins_invocation ON day2_selection_cursor_pins(invocation);"
    )?;
    Ok(())
}

pub(crate) fn pin_selection_cursor(
    connection: &Connection,
    token: &str,
    invocation: &str,
) -> Result<()> {
    if invocation.is_empty() {
        return Ok(());
    }
    release_completed_cursor_pins(connection)?;
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_selection_cursor_pins WHERE token=?1 AND invocation=?2)",
        params![token, invocation],
        |row| row.get(0),
    )?;
    if exists {
        return Ok(());
    }
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM day2_selection_cursor_pins",
        [],
        |row| row.get(0),
    )?;
    ensure!(
        count < SELECTION_CURSOR_PIN_CAPACITY,
        "selection_cursor_pin_capacity"
    );
    connection.execute(
        "INSERT INTO day2_selection_cursor_pins(token,invocation) VALUES(?1,?2)",
        params![token, invocation],
    )?;
    Ok(())
}

fn release_completed_cursor_pins(connection: &Connection) -> Result<()> {
    connection.execute(
        "DELETE FROM day2_selection_cursor_pins WHERE EXISTS
         (SELECT 1 FROM day2_invocations AS i WHERE i.id=day2_selection_cursor_pins.invocation AND i.status!='pending')", [],
    )?;
    Ok(())
}

fn collect_selection_cursors(connection: &Connection, now: i64) -> Result<()> {
    release_completed_cursor_pins(connection)?;
    connection.execute(
        "DELETE FROM day2_selection_cursors WHERE expires_at<=?1 AND NOT EXISTS
         (SELECT 1 FROM day2_selection_cursor_pins AS p JOIN day2_invocations AS i ON i.id=p.invocation
          WHERE p.token=day2_selection_cursors.token AND i.status='pending')", [now],
    )?;
    Ok(())
}

pub(crate) fn encode_selection_cursor(
    connection: &Connection,
    cursor: &SelectionCursor,
    now: i64,
) -> Result<String> {
    let boundary = serde_json::to_string(cursor)?;
    ensure!(boundary.len() <= 8192, "selection_cursor_limit");
    let boundary_key = format!("{:x}", Sha256::digest(boundary.as_bytes()));
    collect_selection_cursors(connection, now)?;
    let expires_at = now
        .checked_add(SELECTION_CURSOR_TTL)
        .context("invalid_cursor_clock")?;
    let existing: Option<(String, String)> = connection
        .query_row(
            "SELECT token,boundary FROM day2_selection_cursors WHERE boundary_key=?1",
            [&boundary_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((token, persisted)) = existing {
        ensure!(
            persisted == boundary && valid_selection_cursor(&token),
            "invalid_persisted_selection_cursor"
        );
        connection.execute(
            "UPDATE day2_selection_cursors SET expires_at=MAX(expires_at,?1) WHERE token=?2",
            params![expires_at, token],
        )?;
        return Ok(token);
    }
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM day2_selection_cursors", [], |row| {
            row.get(0)
        })?;
    ensure!(
        count < SELECTION_CURSOR_CAPACITY,
        "selection_cursor_capacity"
    );
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("selection_cursor_entropy"))?;
    let token = format!(
        "sel1_{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    connection.execute(
        "INSERT INTO day2_selection_cursors(token,boundary_key,boundary,expires_at) VALUES(?1,?2,?3,?4)",
        params![token,boundary_key,boundary,expires_at],
    )?;
    Ok(token)
}

pub(crate) fn decode_selection_cursor(
    connection: &Connection,
    raw: &str,
    now: i64,
) -> Result<SelectionCursor> {
    ensure!(
        valid_selection_cursor(raw),
        crate::error::Failure::InvalidCursor
    );
    let boundary: String = connection
        .query_row(
            "SELECT boundary FROM day2_selection_cursors WHERE token=?1 AND expires_at>?2",
            params![raw, now],
            |row| row.get(0),
        )
        .optional()?
        .context(crate::error::Failure::InvalidCursor)?;
    Ok(serde_json::from_str(&boundary)?)
}

struct SelectionContext<'a> {
    invocation: &'a str,
    actor: &'a str,
    operation: &'a str,
    now: i64,
}

fn select_rows(
    connection: &Connection,
    schema: &Schema,
    model: &str,
    data: &str,
    find: bool,
    row_filter: RowFilter,
    context: SelectionContext<'_>,
) -> Result<String> {
    let record = schema.readable(model).context("unregistered_model")?;
    let record = record.as_ref();
    let plan = SelectionPlan::parse(data, find)?;
    let mut orders = plan.orders;
    let mut ordered = std::collections::BTreeSet::new();
    for order in &orders {
        ensure!(order.model == model, "selection_model_mismatch");
        selection_field(schema, model, &order.field)?;
        ensure!(
            ordered.insert(order.field.clone()),
            "duplicate_selection_order"
        );
    }
    if !ordered.contains("id") {
        orders.push(SelectionOrder {
            model: model.into(),
            field: "id".into(),
            descending: false,
        });
    }
    let binding = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(
            "day2.selection.v1",
            schema.hash()?,
            model,
            &plan.predicate,
            &orders,
            context.actor,
            context.operation,
        ))?)
    );
    let mut values = Vec::new();
    let mut predicates = vec![selection_predicate(
        schema,
        model,
        &plan.predicate,
        &mut values,
    )?];
    // Applied here rather than left to each selection, so every read in the
    // fleet excludes soft-deleted rows without an application remembering to
    // say so. A trash view asks for `Only`, which is why it never has to
    // inspect a row to find out whether it is deleted.
    match plan.deleted.as_str() {
        "include" => {}
        "only" => predicates.push("\"deleted_at\" != 0".to_string()),
        _ => predicates.push("\"deleted_at\" = 0".to_string()),
    }
    if let RowFilter::Owner { field, actor } = row_filter {
        values.push(SqlValue::Text(actor));
        predicates.push(format!("\"{field}\" IS ?{}", values.len()));
    }
    if !plan.after.is_empty() {
        let cursor = decode_selection_cursor(connection, &plan.after, context.now)?;
        ensure!(
            cursor.binding == binding && cursor.values.len() == orders.len(),
            crate::error::Failure::InvalidCursor
        );
        pin_selection_cursor(connection, &plan.after, context.invocation)?;
        let mut previous = Vec::new();
        let mut alternatives = Vec::new();
        for (order, value) in orders.iter().zip(&cursor.values) {
            let value = selection_value(schema, model, &order.field, value)?;
            let null = value == SqlValue::Null;
            values.push(value);
            let parameter = values.len();
            let field = format!("\"{}\"", order.field);
            let comparison = match (order.descending, null) {
                (false, true) => format!("{field} IS NOT NULL"),
                (true, true) => "0".into(),
                (false, false) => format!("{field} > ?{parameter}"),
                (true, false) => format!("({field} < ?{parameter} OR {field} IS NULL)"),
            };
            let mut branch = previous.clone();
            branch.push(comparison);
            alternatives.push(format!("({})", branch.join(" AND ")));
            previous.push(format!("{field} IS ?{parameter}"));
        }
        predicates.push(format!("({})", alternatives.join(" OR ")));
    }
    values.push(SqlValue::Integer(if find { 2 } else { plan.limit + 1 }));
    let ordering = orders
        .iter()
        .map(|order| {
            format!(
                "\"{}\" {}",
                order.field,
                if order.descending { "DESC" } else { "ASC" }
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT {} FROM \"{model}\" WHERE {} ORDER BY {ordering} LIMIT ?{}",
        projection(record),
        predicates.join(" AND "),
        values.len()
    );
    let mut statement = connection.prepare(&sql)?;
    let mut rows = statement
        .query_map(params_from_iter(values), |row| read_row(row, record))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if find {
        ensure!(rows.len() <= 1, crate::error::Failure::AmbiguousSelection);
        return Ok(serde_json::to_string(&rows)?);
    }
    let has_more = rows.len() > plan.limit as usize;
    rows.truncate(plan.limit as usize);
    let next_after = if let Some(row) = rows.last() {
        let data: Value = serde_json::from_str(&row.data)?;
        let values = orders
            .iter()
            .map(|order| match order.field.as_str() {
                "id" => json!(row.id),
                "version" => json!(row.version),
                "created_at" => json!(row.created_at),
                field => data[field].clone(),
            })
            .collect();
        let token = encode_selection_cursor(
            connection,
            &SelectionCursor { binding, values },
            context.now,
        )?;
        pin_selection_cursor(connection, &token, context.invocation)?;
        token
    } else {
        plan.after
    };
    Ok(json!({"items":rows,"has_more":has_more,"next_after":next_after}).to_string())
}

fn mutation_error(error: rusqlite::Error) -> anyhow::Error {
    if matches!(&error, rusqlite::Error::SqliteFailure(code, _)
        if code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE)
    {
        crate::error::Failure::UniqueConstraintConflict.into()
    } else {
        anyhow::Error::new(error).context("constraint_violation")
    }
}

#[cfg(test)]
mod selection_tests {
    use super::*;
    use rusqlite::TransactionBehavior;
    use std::collections::BTreeMap;

    fn fixture() -> Result<(Connection, Schema)> {
        let fields = BTreeMap::from([
            ("name".into(), Kind::Text),
            ("owner".into(), Kind::Text),
            ("active".into(), Kind::Boolean),
            (
                "visits".into(),
                Kind::Unsigned(crate::numeric::Unsigned::U64),
            ),
            ("description".into(), Kind::OptionalText),
            ("unindexed".into(), Kind::Text),
        ]);
        let schema = Schema {
            models: BTreeMap::from([(
                "links".into(),
                Record {
                    fields,
                    roc_type: None,
                    identity: None,
                },
            )]),
            inputs: BTreeMap::new(),
            foreign_keys: vec![],
            domains: BTreeMap::new(),
            rollups: Vec::new(),
            indexes: vec![crate::schema::Index {
                model: "links".into(),
                name: "selection".into(),
                fields: vec![
                    "active".into(),
                    "description".into(),
                    "name".into(),
                    "owner".into(),
                    "visits".into(),
                ],
                unique: false,
            }],
        };
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(PLATFORM_DDL)?;
        upgrade_selection_cursors(&connection)?;
        for sql in schema.ddl()? {
            connection.execute_batch(&sql)?;
        }
        for number in 1..=250_i64 {
            connection.execute("INSERT INTO links(id,version,created_at,name,owner,active,visits,description,unindexed)
                VALUES(?1,?2,0,?3,?4,?5,?6,?7,'hidden')", params![number,number % 7 + 1,format!("item{number:03}"),
                if number % 2 == 0 {"alice"} else {"bob"},number % 3 != 0,
                (u64::MAX - number as u64 % 13).to_be_bytes().to_vec(),
                if number % 2 == 0 {Some("even")} else {None::<&str>}])?;
        }
        Ok((connection, schema))
    }

    fn leaf(field: &str, kind: &str, value: Value) -> String {
        json!({"kind":kind,"model":"links","field":field,"value":value.to_string(),"children":[]})
            .to_string()
    }
    fn group(kind: &str, children: Vec<String>) -> String {
        json!({"kind":kind,"model":"","field":"","value":"","children":children}).to_string()
    }
    fn plan(predicate: &str, orders: &[(&str, bool)], after: &str, limit: i64) -> String {
        json!({"predicate":predicate,"orders":orders.iter().map(|(field,descending)|
            json!({"model":"links","field":field,"descending":descending})).collect::<Vec<_>>(),
            "after":after,"limit":limit})
        .to_string()
    }
    fn select(
        connection: &Connection,
        schema: &Schema,
        data: &str,
        find: bool,
        owner: bool,
    ) -> Result<Value> {
        Ok(serde_json::from_str(&select_rows(
            connection,
            schema,
            "links",
            data,
            find,
            if owner {
                RowFilter::Owner {
                    field: "owner".into(),
                    actor: "alice".into(),
                }
            } else {
                RowFilter::All
            },
            SelectionContext {
                invocation: "",
                actor: "alice",
                operation: "lookup",
                now: 100,
            },
        )?)?)
    }

    /// A soft-deleted row leaves every ordinary read, and only an explicit ask
    /// brings it back into view.
    ///
    /// The default is the whole point. An application cannot forget to exclude
    /// deleted rows, because excluding them is not something it does — the
    /// worst mistake available is a trash screen that shows nothing, which is
    /// visible and harmless. The reverse default would put deleted work back in
    /// front of people silently.
    #[test]
    fn a_deleted_row_leaves_default_reads_and_returns_only_when_asked() -> Result<()> {
        let (connection, schema) = fixture()?;
        let live = |data: &str| -> Result<usize> {
            Ok(select(&connection, &schema, data, false, false)?["items"]
                .as_array()
                .context("items")?
                .len())
        };
        // One row, so the assertion is about that row's visibility rather than
        // about a page that happens to stay full.
        let one = plan(&leaf("name", "equal", json!("item002")), &[], "", 100);
        assert_eq!(live(&one)?, 1, "the fixture holds the row under test");

        connection.execute("UPDATE links SET deleted_at=500 WHERE id=2", [])?;
        assert_eq!(
            live(&one)?,
            0,
            "a soft-deleted row is still visible to an ordinary read"
        );

        // Asking for them brings it back. `only` is what a trash view asks for,
        // and it answers the question the row itself no longer carries: every
        // row it returns is deleted, so nothing has to read a flag per row.
        let scoped = |scope: &str| -> Result<usize> {
            let mut plan: Value = serde_json::from_str(&one)?;
            plan["deleted"] = json!(scope);
            Ok(
                select(&connection, &schema, &plan.to_string(), false, false)?["items"]
                    .as_array()
                    .context("items")?
                    .len(),
            )
        };
        assert_eq!(scoped("include")?, 1, "`include` did not bring it back");
        assert_eq!(scoped("only")?, 1, "`only` did not return the deleted row");

        // And `only` excludes the live rows, which is what makes it a trash
        // view rather than a second way of spelling `include`.
        let every = plan(&group("all", vec![]), &[], "", 100);
        let every_live = select(&connection, &schema, &every, false, false)?["items"]
            .as_array()
            .context("items")?
            .len();
        let mut only_every: Value = serde_json::from_str(&every)?;
        only_every["deleted"] = json!("only");
        let only_deleted =
            select(&connection, &schema, &only_every.to_string(), false, false)?["items"]
                .as_array()
                .context("items")?
                .len();
        assert!(
            every_live > 0 && only_deleted == 1,
            "`only` should return the one deleted row, not the {every_live} live ones"
        );

        // A scope nobody recognises is refused rather than quietly read as the
        // default. Falling back to `exclude` is safe for the data but answers a
        // different question than the one asked, so a trash view built on a
        // typo would render empty forever with nothing to point at.
        let mut typo: Value = serde_json::from_str(&one)?;
        typo["deleted"] = json!("only-deleted");
        assert_eq!(
            select(&connection, &schema, &typo.to_string(), false, false)
                .unwrap_err()
                .to_string(),
            "unsupported_selection_scope"
        );
        Ok(())
    }

    /// A deleted row keeps its unique value.
    ///
    /// The behavioural half of the invariant the schema test pins statically.
    /// If deletion released the name, someone else could claim it and the
    /// original could never be restored — deletion would become a way to lose
    /// a record by having a second one take its place.
    #[test]
    fn a_unique_value_is_not_released_by_deleting_the_row_that_holds_it() -> Result<()> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(PLATFORM_DDL)?;
        let schema: Schema = serde_json::from_value(json!({
            "models": {"rows": {"roc_type": "Models.Row", "fields": {"name": "text"}}},
            "inputs": {}, "foreign_keys": [],
            "indexes": [{"model":"rows","name":"by_name","fields":["name"],"unique":true}],
        }))?;
        for sql in schema.ddl()? {
            connection.execute_batch(&sql)?;
        }
        connection.execute(
            "INSERT INTO rows(id,version,created_at,name) VALUES(1,1,0,'taken')",
            [],
        )?;
        connection.execute("UPDATE rows SET deleted_at=500 WHERE id=1", [])?;
        let second = connection.execute(
            "INSERT INTO rows(id,version,created_at,name) VALUES(2,1,0,'taken')",
            [],
        );
        assert!(
            second.is_err(),
            "deleting a row released its unique name, so it can be taken and never restored"
        );
        Ok(())
    }

    #[test]
    fn find_checks_all_visible_matches_and_keeps_absence_optional() -> Result<()> {
        let (connection, schema) = fixture()?;
        for (name, count) in [("absent", 0), ("item250", 1)] {
            let rows = select(
                &connection,
                &schema,
                &plan(&leaf("name", "equal", json!(name)), &[], "", 1),
                true,
                false,
            )?;
            assert_eq!(rows.as_array().unwrap().len(), count);
        }
        let data = plan(&leaf("owner", "equal", json!("bob")), &[], "", 1);
        let error = select(&connection, &schema, &data, true, false).unwrap_err();
        assert_eq!(
            crate::error::classify(&error),
            crate::error::Failure::AmbiguousSelection
        );
        assert_eq!(select(&connection, &schema, &data, true, true)?, json!([]));
        let data = plan(&leaf("name", "equal", json!("item249")), &[], "", 1);
        assert_eq!(select(&connection, &schema, &data, true, true)?, json!([]));
        Ok(())
    }

    #[test]
    fn cursor_handles_hide_boundaries_reuse_evidence_and_expire() -> Result<()> {
        let (connection, schema) = fixture()?;
        let data = plan(&group("all", vec![]), &[("name", false)], "", 3);
        let first = select(&connection, &schema, &data, false, false)?;
        let repeated = select(&connection, &schema, &data, false, false)?;
        assert_eq!(
            first, repeated,
            "unchanged preparation facts must retain the same cursor"
        );
        let token = first["next_after"].as_str().unwrap();
        assert!(valid_selection_cursor(token));
        assert_eq!(token.len(), 69);
        let random = token.as_bytes()[5..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair)?, 16).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(random.len(), 32);
        assert!(
            serde_json::from_slice::<SelectionCursor>(&random).is_err(),
            "public token must not encode field values"
        );
        let boundary = decode_selection_cursor(&connection, token, 100)?;
        assert_eq!(boundary.values[0], "item003");
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM day2_selection_cursors", [], |row| {
                row.get(0)
            })?;
        assert_eq!(count, 1);
        let expired = decode_selection_cursor(&connection, token, 100 + SELECTION_CURSOR_TTL)
            .err()
            .unwrap();
        assert_eq!(
            crate::error::classify(&expired),
            crate::error::Failure::InvalidCursor
        );
        let replacement =
            encode_selection_cursor(&connection, &boundary, 100 + SELECTION_CURSOR_TTL)?;
        assert_ne!(token, replacement);
        assert!(
            decode_selection_cursor(&connection, token, 100).is_err(),
            "expired entries are removed, not resurrected by an old clock"
        );
        assert_eq!(
            connection.query_row("SELECT COUNT(*) FROM day2_selection_cursors", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        Ok(())
    }

    #[test]
    fn cursor_storage_capacity_fails_without_evicting_active_evidence() -> Result<()> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(PLATFORM_DDL)?;
        upgrade_selection_cursors(&connection)?;
        let cursor = SelectionCursor {
            binding: "private-plan".into(),
            values: vec![json!("private-field")],
        };
        let existing = encode_selection_cursor(&connection, &cursor, 100)?;
        connection.execute(
            "WITH RECURSIVE ids(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM ids WHERE n<?1)
             INSERT INTO day2_selection_cursors SELECT 'sel1_' || printf('%064x',n), 'filler_' || n, '{}', 100000 FROM ids",
            [SELECTION_CURSOR_CAPACITY - 1],
        )?;
        assert_eq!(
            encode_selection_cursor(&connection, &cursor, 101)?,
            existing
        );
        let other = SelectionCursor {
            binding: "another-plan".into(),
            values: vec![json!("private-field")],
        };
        let error = encode_selection_cursor(&connection, &other, 101).unwrap_err();
        assert_eq!(error.to_string(), "selection_cursor_capacity");
        assert_eq!(
            decode_selection_cursor(&connection, &existing, 101)?.binding,
            cursor.binding
        );
        assert!(
            encode_selection_cursor(&connection, &other, 100000).is_ok(),
            "expired handles release capacity"
        );
        assert!(
            encode_selection_cursor(
                &connection,
                &SelectionCursor {
                    binding: "too-large".into(),
                    values: vec![json!("x".repeat(8192))]
                },
                100000
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn pending_invocation_pins_survive_gc_and_preserve_preparation_results() -> Result<()> {
        let (connection, schema) = fixture()?;
        for invocation in ["prepared", "continuation"] {
            connection.execute(
                "INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status)
                VALUES(?1,'lookup','alice','{}','artifact',100,'pending')",
                [invocation],
            )?;
        }
        let data = plan(&group("all", vec![]), &[("name", false)], "", 3);
        let read = |data: &str, invocation: &str, now| {
            select_rows(
                &connection,
                &schema,
                "links",
                data,
                false,
                RowFilter::All,
                SelectionContext {
                    invocation,
                    actor: "alice",
                    operation: "lookup",
                    now,
                },
            )
        };
        let prepared = read(&data, "prepared", 100)?;
        let output: Value = serde_json::from_str(&prepared)?;
        let token = output["next_after"].as_str().unwrap();
        // The accept path pins typed input cursors before any external preparation.
        decode_selection_cursor(&connection, token, 101)?;
        pin_selection_cursor(&connection, token, "continuation")?;
        let continuation = plan(&group("all", vec![]), &[("name", false)], token, 3);
        let later = plan(&group("all", vec![]), &[("name", false)], "", 4);
        read(&later, "", 100 + SELECTION_CURSOR_TTL + 1)?;
        assert_eq!(
            read(&data, "prepared", 100)?,
            prepared,
            "unrelated GC must not change an unchanged prepared observation"
        );
        let resumed: Value = serde_json::from_str(&read(&continuation, "continuation", 101)?)?;
        assert_eq!(resumed["items"][0]["id"], 4);
        assert!(
            decode_selection_cursor(&connection, token, 100 + SELECTION_CURSOR_TTL + 1).is_err(),
            "retention does not admit an expired token to a fresh invocation"
        );
        connection.execute("UPDATE day2_invocations SET status='success'", [])?;
        collect_selection_cursors(&connection, 200000)?;
        assert!(decode_selection_cursor(&connection, token, 100).is_err());
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM day2_selection_cursor_pins",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        Ok(())
    }

    #[test]
    fn immediate_page_transactions_prevent_wal_snapshot_upgrade_races() -> Result<()> {
        let (_fixture, schema) = fixture()?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("cursor-concurrency.sqlite");
        let mut first = open(&path)?;
        first.pragma_update(None, "journal_mode", "WAL")?;
        first.execute_batch(PLATFORM_DDL)?;
        upgrade_selection_cursors(&first)?;
        for statement in schema.ddl()? {
            first.execute_batch(&statement)?;
        }
        first.execute("INSERT INTO links(id,version,created_at,name,owner,active,visits,description,unindexed)
            VALUES(1,1,0,'one','alice',1,?1,NULL,'hidden')", [0_u64.to_be_bytes().to_vec()])?;
        let mut second = open(&path)?;
        second.busy_timeout(Duration::ZERO)?;
        let data = plan(&group("all", vec![]), &[("name", false)], "", 1);
        let read = |connection: &Connection| {
            select_rows(
                connection,
                &schema,
                "links",
                &data,
                false,
                RowFilter::All,
                SelectionContext {
                    invocation: "",
                    actor: "alice",
                    operation: "lookup",
                    now: 100,
                },
            )
        };

        // Positive control for the failure mode: a deferred reader's snapshot
        // cannot be upgraded after another connection commits cursor metadata.
        let stale = first.transaction_with_behavior(TransactionBehavior::Deferred)?;
        stale.query_row("SELECT COUNT(*) FROM links", [], |row| row.get::<_, i64>(0))?;
        let writer = second.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let expected = read(&writer)?;
        writer.commit()?;
        let error = read(&stale).unwrap_err();
        assert!(
            matches!(error.downcast_ref::<rusqlite::Error>(), Some(rusqlite::Error::SqliteFailure(code,_))
            if code.extended_code == rusqlite::ffi::SQLITE_BUSY_SNAPSHOT)
        );
        stale.rollback()?;

        // The prepare path now reserves the writer slot before reading rows.
        let protected = first.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(
            second
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .is_err()
        );
        assert_eq!(read(&protected)?, expected);
        protected.commit()?;
        let next = second.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_eq!(read(&next)?, expected);
        next.commit()?;
        Ok(())
    }

    #[test]
    fn empty_continuations_release_completed_pins_before_enforcing_capacity() -> Result<()> {
        let (connection, schema) = fixture()?;
        let predicate = leaf("name", "equal", json!("item250"));
        let output = select(
            &connection,
            &schema,
            &plan(&predicate, &[], "", 1),
            false,
            false,
        )?;
        let token = output["next_after"].as_str().unwrap();
        connection.execute(
            "WITH RECURSIVE ids(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM ids WHERE n<?1)
             INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status)
             SELECT 'completed_' || n,'lookup','alice','{}','artifact',100,'success' FROM ids",
            [SELECTION_CURSOR_PIN_CAPACITY],
        )?;
        connection.execute(
            "INSERT INTO day2_selection_cursor_pins SELECT ?1,id FROM day2_invocations",
            [token],
        )?;
        connection.execute(
            "INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status)
             VALUES('fresh','lookup','alice','{}','artifact',101,'pending')",
            [],
        )?;
        let result = select_rows(
            &connection,
            &schema,
            "links",
            &plan(&predicate, &[], token, 1),
            false,
            RowFilter::All,
            SelectionContext {
                invocation: "fresh",
                actor: "alice",
                operation: "lookup",
                now: 101,
            },
        )?;
        let result: Value = serde_json::from_str(&result)?;
        assert_eq!(result["items"], json!([]));
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM day2_selection_cursor_pins",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            1
        );
        Ok(())
    }

    #[test]
    fn compound_search_and_owner_filter_precede_page_bounds() -> Result<()> {
        let (connection, schema) = fixture()?;
        let predicate = group(
            "all",
            vec![
                leaf("active", "equal", json!(true)),
                group(
                    "any",
                    vec![
                        leaf("name", "like", json!("item2%")),
                        leaf("description", "like", json!("never%")),
                    ],
                ),
            ],
        );
        let result = select(
            &connection,
            &schema,
            &plan(&predicate, &[], "", 3),
            false,
            true,
        )?;
        let ids = result["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_i64().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec![200, 202, 206]);
        assert_eq!(result["has_more"], true);
        // OptionalText LIKE uses SQL null semantics, and '_' remains a wildcard.
        let predicate = leaf("description", "like", json!("e_en"));
        let result = select(
            &connection,
            &schema,
            &plan(&predicate, &[], "", 100),
            false,
            false,
        )?;
        assert_eq!(result["items"].as_array().unwrap().len(), 100);
        assert_eq!(result["has_more"], true);
        Ok(())
    }

    #[test]
    fn ordered_keysets_visit_more_than_100_rows_and_survive_deleted_boundary() -> Result<()> {
        let (connection, schema) = fixture()?;
        let predicate = group("all", vec![]);
        let orders = [("visits", true), ("version", true), ("id", false)];
        let expected = connection
            .prepare("SELECT id FROM links ORDER BY visits DESC,version DESC,id ASC")?
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut after = String::new();
        let mut actual = Vec::new();
        loop {
            let page = select(
                &connection,
                &schema,
                &plan(&predicate, &orders, &after, 17),
                false,
                false,
            )?;
            actual.extend(
                page["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|row| row["id"].as_i64().unwrap()),
            );
            after = page["next_after"].as_str().unwrap().into();
            if actual.len() == 17 {
                connection.execute("DELETE FROM links WHERE id=?1", [actual[16]])?;
            }
            if !page["has_more"].as_bool().unwrap() {
                break;
            }
        }
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 250);
        let forged = plan(&leaf("active", "equal", json!(true)), &orders, &after, 17);
        assert!(select(&connection, &schema, &forged, false, false).is_err());
        Ok(())
    }

    #[test]
    fn nullable_ordering_and_explicit_id_descending_are_complete() -> Result<()> {
        let (connection, schema) = fixture()?;
        for descending in [false, true] {
            let orders = [("description", descending), ("id", true)];
            let sql = format!(
                "SELECT id FROM links ORDER BY description {},id DESC",
                if descending { "DESC" } else { "ASC" }
            );
            let expected = connection
                .prepare(&sql)?
                .query_map([], |row| row.get::<_, i64>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut after = String::new();
            let mut actual = Vec::new();
            loop {
                let page = select(
                    &connection,
                    &schema,
                    &plan(&group("all", vec![]), &orders, &after, 31),
                    false,
                    false,
                )?;
                actual.extend(
                    page["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|row| row["id"].as_i64().unwrap()),
                );
                after = page["next_after"].as_str().unwrap().into();
                if !page["has_more"].as_bool().unwrap() {
                    break;
                }
            }
            assert_eq!(actual, expected);
        }
        Ok(())
    }

    #[test]
    fn malformed_fields_types_and_undeclared_indexes_fail_closed() -> Result<()> {
        let (connection, schema) = fixture()?;
        for predicate in [
            leaf("unindexed", "equal", json!("hidden")),
            leaf("active", "equal", json!("true")),
            leaf("visits", "like", json!("%")),
            leaf("visits", "equal", json!(-1)),
            leaf("id\" OR 1=1 --", "equal", json!(1)),
            leaf("missing", "equal", json!(1)),
            leaf("created_at", "equal", json!(-1)),
        ] {
            assert!(
                select(
                    &connection,
                    &schema,
                    &plan(&predicate, &[], "", 20),
                    false,
                    false
                )
                .is_err()
            );
        }
        for orders in [
            vec![("unindexed", false)],
            vec![("id", false), ("id", true)],
        ] {
            assert!(
                select(
                    &connection,
                    &schema,
                    &plan(&group("all", vec![]), &orders, "", 20),
                    false,
                    false
                )
                .is_err()
            );
        }
        assert!(
            select(
                &connection,
                &schema,
                &plan(&group("all", vec![]), &[], "sel1_00", 20),
                false,
                false
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn unique_conflict_classification_preserves_other_constraint_failures() -> Result<()> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch("CREATE TABLE checks (name TEXT NOT NULL UNIQUE CHECK(length(name)>0)); INSERT INTO checks VALUES('a');")?;
        let unique = mutation_error(
            connection
                .execute("INSERT INTO checks VALUES('a')", [])
                .unwrap_err(),
        );
        assert_eq!(
            crate::error::classify(&unique),
            crate::error::Failure::UniqueConstraintConflict
        );
        for sql in [
            "INSERT INTO checks VALUES(NULL)",
            "INSERT INTO checks VALUES('')",
        ] {
            let error = mutation_error(connection.execute(sql, []).unwrap_err());
            assert_ne!(
                crate::error::classify(&error),
                crate::error::Failure::UniqueConstraintConflict
            );
        }
        Ok(())
    }
}

pub(crate) fn effect(
    connection: &Connection,
    schema: &Schema,
    scope: &str,
    request: &Request,
    instruction: &Instruction,
    policy: &Policy,
    operation: &str,
) -> Result<String> {
    let Step::Database(instruction) = instruction.decode()? else {
        bail!("unsupported_database_effect");
    };
    let model = instruction.model();
    let record = schema.readable(model).context("unregistered_model")?;
    let record = record.as_ref();
    let source = schema
        .rollup(model)
        .map_or(model, |rollup| rollup.model.as_str());
    let row_filter = policy.read_scope(operation, source, &request.context.actor)?;
    if let Some(rollup) = schema.rollup(model) {
        ensure!(
            matches!(
                instruction,
                Database::Get { .. } | Database::Select { .. } | Database::Page { .. }
            ),
            "rollup_is_read_only"
        );
        if let RowFilter::Owner { field, .. } = &row_filter {
            ensure!(
                rollup
                    .group
                    .iter()
                    .any(|group| group.field == *field && group.bucket.is_none()),
                "rollup_requires_owner_group"
            );
        }
    }
    match instruction {
        Database::Get { id, .. } => {
            let row = get(connection, model, record, id)?;
            policy.check_read(
                operation,
                source,
                &request.context.actor,
                &serde_json::from_str(&row.data)?,
            )?;
            Ok(serde_json::to_string(&row)?)
        }
        Database::Select { data, find, .. } => select_rows(
            connection,
            schema,
            model,
            data,
            find,
            row_filter,
            SelectionContext {
                invocation: &request.context.invocation_id,
                actor: &request.context.actor,
                operation,
                now: request.context.now,
            },
        ),
        Database::Page {
            filter,
            after,
            limit,
            ..
        } => {
            let mut predicates = vec!["id > ?1".to_string()];
            let cursor = if after.empty() {
                if record.identity.is_some() {
                    SqlValue::Blob(vec![0; 16])
                } else {
                    SqlValue::Integer(0)
                }
            } else {
                after.sql(record.identity.as_ref())?
            };
            let mut parameters = vec![cursor];
            if let Some(filter) = filter {
                ensure!(
                    schema
                        .foreign_keys
                        .iter()
                        .any(|fk| fk.model == model && fk.field == filter.field),
                    "unsupported_unindexed_filter"
                );
                let target = schema
                    .foreign_keys
                    .iter()
                    .find(|fk| fk.model == model && fk.field == filter.field)
                    .context("unknown_filter_reference")?;
                parameters.push(
                    filter
                        .value
                        .sql(schema.models[&target.target].identity.as_ref())?,
                );
                predicates.push(format!("\"{}\" = ?{}", filter.field, parameters.len()));
            }
            if let RowFilter::Owner { field, actor } = row_filter {
                parameters.push(SqlValue::Text(actor));
                predicates.push(format!("\"{field}\" = ?{}", parameters.len()));
            }
            parameters.push(SqlValue::Integer(i64::from(limit) + 1));
            let predicate = predicates.join(" AND ");
            let sql = format!(
                "SELECT {} FROM \"{model}\" WHERE {predicate} ORDER BY id LIMIT ?{}",
                projection(record),
                parameters.len()
            );
            let mut statement = connection.prepare(&sql)?;
            let mut rows = statement
                .query_map(params_from_iter(parameters), |row| read_row(row, record))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let has_more = rows.len() > usize::from(limit);
            rows.truncate(usize::from(limit));
            let next_after = rows.last().map_or(*after, |row| row.id);
            Ok(
                json!({ "items": rows, "has_more": has_more, "next_after": next_after })
                    .to_string(),
            )
        }
        Database::Write { data, change, .. } => {
            let before = match change {
                // An update reads the row the way an application does, so a
                // deleted row is simply not there to edit. Restoring it first
                // is the only way back, and that is a decision someone makes
                // rather than a side effect of saving a form.
                Write::Update { id, .. } => Some(get(connection, model, record, id)?),
                Write::SoftDelete { id, .. } | Write::Restore { id, .. } => {
                    Some(get_any(connection, model, record, id)?)
                }
                Write::Create => None,
            };
            // A deletion change carries no payload, so the row's current value
            // stands in. That keeps the authority check below meaningful — it
            // sees a real before-and-after — without letting the instruction
            // alter a single field.
            let value: Value = if data.is_empty() {
                serde_json::from_str(&before.as_ref().context("missing_row_for_deletion")?.data)?
            } else {
                serde_json::from_str(data)?
            };
            record.validate_value(&value)?;
            if let Some(before) = &before {
                policy.check_update(
                    operation,
                    model,
                    &request.context.actor,
                    &serde_json::from_str(&request.input)?,
                    &Change {
                        id: before.id,
                        before: &serde_json::from_str(&before.data)?,
                        after: &value,
                    },
                )?;
            } else {
                policy.check_create(operation, model, &request.context.actor, &value)?;
            }
            let values: Vec<SqlValue> = record
                .fields
                .iter()
                .map(|(name, kind)| sql_value(kind, &value[name]))
                .collect::<Result<_>>()?;
            let id;
            match change {
                Write::Create => {
                    id = if let Some(identity) = &record.identity {
                        let seed: Vec<u8> = connection.query_row(
                            "SELECT seed FROM day2_id_seeds WHERE invocation=?1",
                            [&request.context.invocation_id],
                            |row| row.get(0),
                        )?;
                        let seed: [u8; 32] = seed
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("invalid_id_seed"))?;
                        let millis = u64::try_from(request.context.now)?
                            .checked_mul(1000)
                            .context("invalid_uuid_clock")?;
                        Id::from_uuid(
                            &identity.prefix,
                            crate::identity::generate(
                                &seed,
                                millis,
                                &identity.key,
                                request.observations.len() as u64,
                            )?,
                        )?
                    } else {
                        let hash = Sha256::digest(serde_json::to_vec(&(
                            scope,
                            &request.context.invocation_id,
                            request.observations.len(),
                            model,
                        ))?);
                        Id::Legacy((i64::from_be_bytes(hash[..8].try_into()?) & i64::MAX).max(1))
                    };
                    let mut parameters = vec![
                        id.sql(record.identity.as_ref())?,
                        SqlValue::Integer(1),
                        SqlValue::Integer(request.context.now),
                    ];
                    parameters.extend(values);
                    let placeholders = (1..=parameters.len())
                        .map(|n| format!("?{n}"))
                        .collect::<Vec<_>>()
                        .join(",");
                    connection
                        .execute(
                            &format!(
                                "INSERT INTO \"{model}\" ({}) VALUES({placeholders})",
                                projection(record)
                            ),
                            params_from_iter(parameters),
                        )
                        .map_err(mutation_error)?;
                }
                Write::SoftDelete {
                    id: existing_id,
                    version,
                }
                | Write::Restore {
                    id: existing_id,
                    version,
                } => {
                    id = existing_id;
                    let deleting = matches!(change, Write::SoftDelete { .. });
                    // Refuse the no-op rather than silently bumping a version:
                    // deleting an already-deleted row, or restoring a live one,
                    // is a caller working from a stale view of the row.
                    let already: i64 = connection.query_row(
                        &format!("SELECT deleted_at FROM \"{model}\" WHERE id=?1"),
                        params_from_iter([id.sql(record.identity.as_ref())?]),
                        |row| row.get(0),
                    )?;
                    ensure!(
                        (already == 0) == deleting,
                        if deleting {
                            "row_already_deleted"
                        } else {
                            "row_not_deleted"
                        }
                    );
                    let stamp = if deleting { request.context.now } else { 0 };
                    let changed = connection
                        .execute(
                            &format!(
                                "UPDATE \"{model}\" SET deleted_at=?1,version=version+1 \
                                 WHERE id=?2 AND version=?3"
                            ),
                            params_from_iter([
                                SqlValue::Integer(stamp),
                                id.sql(record.identity.as_ref())?,
                                SqlValue::Integer(version),
                            ]),
                        )
                        .map_err(mutation_error)?;
                    ensure!(changed == 1, crate::error::Failure::VersionConflict);
                }
                Write::Update {
                    id: existing_id,
                    version,
                } => {
                    id = existing_id;
                    let assignments = record
                        .fields
                        .keys()
                        .enumerate()
                        .map(|(n, name)| format!("\"{name}\"=?{}", n + 1))
                        .collect::<Vec<_>>()
                        .join(",");
                    let mut parameters = values;
                    parameters.push(id.sql(record.identity.as_ref())?);
                    parameters.push(SqlValue::Integer(version));
                    let sql = format!(
                        "UPDATE \"{model}\" SET {assignments},version=version+1 WHERE id=?{} AND version=?{}",
                        parameters.len() - 1,
                        parameters.len()
                    );
                    ensure!(
                        connection
                            .execute(&sql, params_from_iter(parameters))
                            .map_err(mutation_error)?
                            == 1,
                        crate::error::Failure::Conflict
                    );
                }
            }
            let after = get_any(connection, model, record, id)?;
            crate::audit::record_change(connection, request, model, before.as_ref(), &after)?;
            Ok(serde_json::to_string(&after)?)
        }
    }
}

pub fn replay(artifact: &LoadedArtifact, trace: &Trace) -> Result<()> {
    let completion = trace.outcome.decode()?;
    ensure!(
        (1..=2).contains(&trace.format) && trace.artifact == artifact.id(),
        "replay_artifact_mismatch"
    );
    ensure!(
        (trace.format == 2) == trace.guard.is_some(),
        "replay_guard_format"
    );
    ensure!(
        trace.guard.is_some()
            || crate::authority_state::required_all_rows(artifact, &trace.request.operation)?
                .is_empty(),
        crate::error::Failure::RequiredAllRowsUnavailable
    );
    if let Some(guard) = &trace.guard {
        let operation = artifact.route(&trace.request.operation)?;
        guard
            .policy
            .validate(&artifact.contract().operations, &artifact.contract().schema)?;
        crate::authority_state::require_all_rows(
            &guard.policy,
            artifact,
            &trace.request.operation,
            &trace.request.context.actor,
        )?;
        let error = {
            let input: Value = serde_json::from_str(&trace.request.input)?;
            artifact.contract().schema.inputs[&operation.input_type].validate_input(&input)?;
            if let Some(row) = &guard.precondition_row {
                let target = precondition_target(
                    &guard.policy,
                    &operation.name,
                    &input,
                    app_execution(artifact.contract(), &operation.name),
                )?
                .context("unexpected_precondition_row")?;
                ensure!(
                    row.id == target.id && row.version > 0 && row.created_at >= 0,
                    "invalid_precondition_row"
                );
                artifact.contract().schema.models[&target.model]
                    .validate_value(&serde_json::from_str(&row.data)?)?;
            }
            check_precondition(
                &guard.policy,
                &operation.name,
                &trace.request.context.actor,
                &input,
                guard.precondition_row.as_ref(),
                app_execution(artifact.contract(), &operation.name),
            )
            .err()
            .map(|error| crate::error::observation_code(&error))
            .unwrap_or_default()
        };
        ensure!(error == guard.error, "replay_guard_mismatch");
        if !error.is_empty() {
            ensure!(
                trace.request.observations.is_empty()
                    && trace.outcome.status == "failure"
                    && trace.outcome.result.is_null()
                    && trace.outcome.error == error,
                "replay_guard_failure_mismatch"
            );
            return Ok(());
        }
    }
    ensure!(
        trace.request.observations.len() <= MAX_STEPS,
        "trace_step_budget"
    );
    let executable = artifact.materialize_worker()?;
    let mut worker = Worker::start(&executable)?;
    let mut request = trace.request.clone();
    request.observations.clear();
    for observation in &trace.request.observations {
        let response: Response =
            serde_json::from_slice(&worker.exchange(&serde_json::to_vec(&request)?)?)?;
        ensure!(
            matches!(response.decode()?, Reply::Pending(_))
                && response.consumed == request.observations.len()
                && response.instruction == observation.instruction,
            "replay_effect_mismatch"
        );
        request.observations.push(observation.clone());
    }
    let response: Response =
        serde_json::from_slice(&worker.exchange(&serde_json::to_vec(&request)?)?)?;
    ensure!(
        response.consumed == request.observations.len(),
        "replay_consumption_mismatch"
    );
    match (completion, response.decode()?) {
        (Completion::Success(expected), Reply::Done(result)) => ensure!(
            artifact.decode_result(&request.operation, result)? == *expected,
            "replay_result_mismatch"
        ),
        (Completion::Failure(expected), Reply::Failed(error)) => {
            ensure!(error == expected, "replay_failure_mismatch")
        }
        (Completion::Pending(_), _) => bail!("invalid_trace_outcome"),
        _ => bail!("replay_outcome_mismatch"),
    }
    Ok(())
}

#[cfg(test)]
mod rollup_read_tests {
    use super::*;

    #[test]
    fn rollups_filter_before_paging_and_inherit_source_authority() -> Result<()> {
        let (db, mut schema) = crate::rollup::tests::fixture()?;
        db.execute_batch(PLATFORM_DDL)?;
        upgrade_selection_cursors(&db)?;
        db.execute_batch("INSERT INTO events(id,version,created_at,owner,time,amount) VALUES(1,1,0,'alice',1,7),(2,1,0,'alice',90000,8),(3,1,0,'bob',1,900)")?;
        let request: Request = serde_json::from_value(
            json!({"operation":"lookup","input":"{}","observations":[],"context":{"invocation_id":"","actor":"alice","now":100,"authentication":"test","caller":[],"authenticated":"alice","delegation_rule":""}}),
        )?;
        let policy: Policy = serde_json::from_value(
            json!({"version":1,"operations":{"lookup":{"actors":["alice"],"mode":{"kind":"read"},"models":{"events":{"read":true,"rows":{"kind":"owner_or_admin","field":"owner"}}}}}}),
        )?;
        let mut instruction = Instruction { kind:"select_page".into(), model:"events_daily".into(), data:json!({"predicate":json!({"kind":"all","model":"","field":"","value":"","children":[]}).to_string(),"orders":[{"model":"events_daily","field":"time","descending":false}],"after":"","limit":1}).to_string(), ..Instruction::default() };
        let first: Value = serde_json::from_str(&effect(
            &db,
            &schema,
            "test",
            &request,
            &instruction,
            &policy,
            "lookup",
        )?)?;
        assert_eq!(first["items"].as_array().unwrap().len(), 1);
        let data: Value = serde_json::from_str(first["items"][0]["data"].as_str().unwrap())?;
        assert_eq!(data["amount"], 7);
        assert_eq!(data["owner"], "alice");
        assert_eq!(first["has_more"], true);
        let mut plan: Value = serde_json::from_str(&instruction.data)?;
        plan["after"] = first["next_after"].clone();
        instruction.data = plan.to_string();
        let second: Value = serde_json::from_str(&effect(
            &db,
            &schema,
            "test",
            &request,
            &instruction,
            &policy,
            "lookup",
        )?)?;
        let data: Value = serde_json::from_str(second["items"][0]["data"].as_str().unwrap())?;
        assert_eq!(data["amount"], 8);
        assert_eq!(second["has_more"], false);
        let write = Instruction {
            kind: "create".into(),
            model: "events_daily".into(),
            data: "{}".into(),
            ..Instruction::default()
        };
        assert!(
            effect(&db, &schema, "test", &request, &write, &policy, "lookup")
                .unwrap_err()
                .to_string()
                .contains("rollup_is_read_only")
        );
        let mut denied = policy.clone();
        denied.operations.get_mut("lookup").unwrap().models.clear();
        assert!(
            effect(
                &db,
                &schema,
                "test",
                &request,
                &instruction,
                &denied,
                "lookup"
            )
            .is_err()
        );
        schema.rollups[0].group.remove(0);
        assert!(
            effect(
                &db,
                &schema,
                "test",
                &request,
                &instruction,
                &policy,
                "lookup"
            )
            .unwrap_err()
            .to_string()
            .contains("rollup_requires_owner_group")
        );
        Ok(())
    }
}
