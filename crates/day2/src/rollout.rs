//! Operator-authorized overlap of ordinary SQLite application artifacts.
//!
//! A release never grants business authority. Both executables continue to use
//! the current authority document and invocation stamps. Immutable artifact
//! bundles live in a separate database so publishing them cannot hold the
//! business writer lock while copying application resources.
use crate::{
    artifact::{Instance, LoadedArtifact},
    authority_state::{self, AuthorityDocument, AuthorityStamp, LocalOperator},
    store::{Runtime, open},
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

const MAX_FILES: usize = 8192;
const MAX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_STORED_BYTES: i64 = 512 * 1024 * 1024;
const DDL: &str = "CREATE TABLE IF NOT EXISTS day2_rollout(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), release TEXT NOT NULL
); CREATE TABLE IF NOT EXISTS day2_rollout_artifacts(
    id TEXT PRIMARY KEY, scope TEXT NOT NULL, epoch TEXT NOT NULL, contract TEXT NOT NULL, admission_id TEXT NOT NULL, retired_ms INTEGER
);";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Prepared,
    Serving,
    Draining,
    Complete,
    Aborted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub id: String,
    pub scope: String,
    pub source: String,
    pub target: String,
    pub source_image: String,
    pub target_image: String,
    pub target_instance_digest: String,
    pub probe: Option<Probe>,
    pub authority: AuthorityStamp,
    pub target_security: Option<crate::security_admission::Requirements>,
    pub placement: Option<Placement>,
    pub phase: Phase,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeDefinition {
    pub actor: String,
    pub command: String,
    pub input: serde_json::Value,
    pub query: String,
    pub query_input: serde_json::Value,
    pub expected: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Pending,
    Verified,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub definition: ProbeDefinition,
    pub status: ProbeStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Placement {
    pub namespace: String,
    pub controller_uid: String,
    pub pvc_uid: String,
    pub node: String,
    pub request_digest: String,
}

pub fn bind_placement(
    runtime: &Runtime,
    id: &str,
    placement: Placement,
    operator_identity: &LocalOperator,
) -> Result<()> {
    operator(runtime, operator_identity)?;
    day2_assets::hash_part(&placement.request_digest)?;
    ensure!(
        [
            &placement.namespace,
            &placement.controller_uid,
            &placement.pvc_uid,
            &placement.node
        ]
        .iter()
        .all(|value| !value.is_empty()
            && value.len() <= 253
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))),
        "rollout_placement_invalid"
    );
    runtime.sql_write(|db| {
        let mut release = state(db)?.context("rollout_not_prepared")?;
        ensure!(
            release.id == id && release.scope == runtime.scope(),
            "rollout_identity_changed"
        );
        if let Some(previous) = &release.placement {
            ensure!(*previous == placement, "rollout_placement_changed");
            return Ok(());
        }
        ensure!(
            release.phase == Phase::Prepared,
            "rollout_placement_must_precede_serving"
        );
        release.placement = Some(placement);
        write(db, &release)
    })
}

pub(crate) fn authority_for(
    runtime: &Runtime,
    db: &Connection,
) -> Result<authority_state::ActiveAuthority> {
    let mut active = authority_state::current(db)?;
    if active.artifact_id != runtime.artifact().id() {
        ensure!(
            admitted(db, runtime.artifact().id(), runtime.scope())?,
            crate::error::Failure::ArtifactBindingChanged
        );
        let release = state(db)?.context("rollout_not_prepared")?;
        if runtime.artifact().id() == release.target {
            active.document.security = release.target_security;
        }
    }
    Ok(active)
}

fn state(connection: &Connection) -> Result<Option<Release>> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='day2_rollout')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    connection
        .query_row(
            "SELECT release FROM day2_rollout WHERE singleton=1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|raw| crate::json::decode(raw.as_bytes()))
        .transpose()
}

pub fn inspect(runtime: &Runtime) -> Result<Option<Release>> {
    runtime.sql_read(state)
}

pub fn inspect_file(instance_path: &Path, app: &str) -> Result<Option<Release>> {
    day2_contracts::names::identifier(app)?;
    let instance = Instance::load(instance_path)?;
    let path = instance_path
        .parent()
        .context("installation root")?
        .join(".state")
        .join(format!("{app}.sqlite"));
    let db = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let release = state(&db)?;
    ensure!(
        release
            .as_ref()
            .is_none_or(|release| release.scope == instance.scope(app).unwrap_or_default()),
        "rollout_scope_changed"
    );
    Ok(release)
}

/// Offline activation and restore replace the serving authorization. Historical
/// overlap is evidence only and must never block or reauthorize a later release.
pub(crate) fn invalidate(connection: &Connection) -> Result<()> {
    if state(connection)?.is_some() {
        connection.execute("DELETE FROM day2_rollout", [])?;
        connection.execute("UPDATE day2_rollout_artifacts SET retired_ms=?1 WHERE id != (SELECT artifact_id FROM day2_authority WHERE singleton=1)", [now_ms()?])?;
    }
    Ok(())
}

/// Policy revisions fence business work without withdrawing an executable that
/// Kubernetes may already have made the only serving replica. Binding changes
/// and restore still discard the pair through the exclusive activation path.
pub(crate) fn authority_changed(
    connection: &Connection,
    previous: Option<&authority_state::ActiveAuthority>,
    next: &authority_state::ActiveAuthority,
) -> Result<()> {
    let Some(mut release) = state(connection)? else {
        return Ok(());
    };
    let preserves_binding = previous.is_some_and(|previous| {
        previous.stamp == release.authority
            && previous.stamp.epoch == next.stamp.epoch
            && previous.artifact_id == next.artifact_id
            && previous.artifact_path == next.artifact_path
    });
    if !preserves_binding {
        return invalidate(connection);
    }
    release.authority = next.stamp.clone();
    release.target_security = next.document.security.clone().map(|mut requirements| {
        requirements.artifact = release.target.clone();
        requirements
    });
    write(connection, &release)
}

/// Queue an immutable canary for the running candidate. Tooling only publishes
/// and observes this request; app execution keeps the serving supervisor pin.
pub fn request_probe(
    runtime: &Runtime,
    id: &str,
    definition: ProbeDefinition,
    operator_identity: &LocalOperator,
) -> Result<()> {
    operator(runtime, operator_identity)?;
    ensure!(
        serde_json::to_vec(&definition)?.len() <= 65_536,
        "release_probe_byte_budget"
    );
    runtime.sql_write(|db| {
        runtime.check_binding(db)?;
        let mut release = state(db)?.context("rollout_not_prepared")?;
        ensure!(
            release.id == id && release.scope == runtime.scope() && release.phase == Phase::Serving,
            "release_probe_phase"
        );
        if let Some(previous) = &mut release.probe {
            ensure!(previous.definition == definition, "release_probe_conflict");
            if previous.status == ProbeStatus::Failed {
                // Explicit retry keeps both invocation IDs, so a committed
                // write cannot be repeated after a lost response or read error.
                previous.status = ProbeStatus::Pending;
                write(db, &release)?;
            }
            return Ok(());
        }
        release.probe = Some(Probe {
            definition,
            status: ProbeStatus::Pending,
        });
        write(db, &release)
    })
}

/// Only the candidate host pump calls this. The incumbent never runs candidate
/// code as proof, and no public HTTP endpoint gains operator authority.
pub(crate) fn run_probe(runtime: &Runtime) -> Result<()> {
    if !runtime.rolling() {
        return Ok(());
    }
    let Some(release) = inspect(runtime)? else {
        return Ok(());
    };
    let Some(probe) = &release.probe else {
        return Ok(());
    };
    if release.target != runtime.artifact().id()
        || release.phase != Phase::Serving
        || probe.status != ProbeStatus::Pending
    {
        return Ok(());
    }
    let result = execute_probe(runtime, &release.id, &probe.definition);
    runtime.sql_write(|db| {
        let mut current = state(db)?.context("rollout_not_prepared")?;
        ensure!(
            current.id == release.id
                && current.target == release.target
                && current.phase == Phase::Serving
                && current.probe == release.probe,
            "release_probe_changed"
        );
        current
            .probe
            .as_mut()
            .context("release_probe_missing")?
            .status = if result.is_ok() {
            ProbeStatus::Verified
        } else {
            ProbeStatus::Failed
        };
        write(db, &current)
    })?;
    result
}

fn execute_probe(runtime: &Runtime, id: &str, probe: &ProbeDefinition) -> Result<()> {
    ensure!(
        runtime.artifact().operation(&probe.command)?.kind == "command"
            && runtime.artifact().operation(&probe.query)?.kind == "query",
        "release_probe_operations"
    );
    let contracts = runtime
        .artifact()
        .contract()
        .app_contract
        .as_ref()
        .context("release_probe_contract")?;
    ensure!(
        [&probe.command, &probe.query].iter().all(|name| contracts
            .operations
            .get(*name)
            .is_some_and(
                |operation| operation.execution.effects.iter().all(|effect| matches!(
                    effect.kind.as_str(),
                    "create" | "update" | "update_created" | "soft_delete"
                )) && operation.observations.is_empty()
                    && !operation.credential_access.enabled
            )),
        "release_probe_must_have_no_external_effects"
    );
    let now = now_ms()? / 1000;
    let write = runtime.invoke(
        &probe.command,
        &probe.actor,
        &format!("{id}_write"),
        &probe.input,
        now,
        crate::store::Fault::None,
    )?;
    ensure!(write.status == "success", "release_probe_write_failed");
    let read = runtime.invoke(
        &probe.query,
        &probe.actor,
        &format!("{id}_read"),
        &probe.query_input,
        now,
        crate::store::Fault::None,
    )?;
    ensure!(
        read.status == "success" && read.result == probe.expected,
        "release_probe_readback_failed"
    );
    Ok(())
}

pub(crate) fn require_expected_release(runtime: &Runtime, id: &str) -> Result<()> {
    runtime.sql_read(|db| {
        ensure!(
            admitted(db, runtime.artifact().id(), runtime.scope())?,
            "rollout_artifact_not_admitted"
        );
        let admission: String = db.query_row(
            "SELECT admission_id FROM day2_rollout_artifacts WHERE id=?1 AND scope=?2",
            params![runtime.artifact().id(), runtime.scope()],
            |row| row.get(0),
        )?;
        ensure!(admission == id, "rollout_database_identity_changed");
        Ok(())
    })
}

// Preserve token boundaries, quoted bytes, constraints and private column order.
// Application SQL always names columns, so additive offline migrations may have
// a different physical column order than a fresh installation of that artifact.
fn schema_sql(sql: &str, app_table: bool) -> Result<String> {
    ensure!(sql.len() <= 1_048_576, "rollout_schema_budget");
    let mut input = sql.chars().peekable();
    let mut tokens = Vec::new();
    while let Some(ch) = input.next() {
        if ch.is_ascii_whitespace() {
            continue;
        }
        let mut token = String::from(ch);
        if matches!(ch, '\'' | '"' | '`') {
            loop {
                let next = input.next().context("rollout_schema_quote")?;
                token.push(next);
                if next == ch {
                    if input.peek() != Some(&ch) {
                        break;
                    }
                    token.push(input.next().context("rollout_schema_quote")?);
                }
            }
        } else if ch.is_ascii_alphanumeric() || ch == '_' {
            while input
                .peek()
                .is_some_and(|next| next.is_ascii_alphanumeric() || matches!(next, '_' | '$'))
            {
                token.push(input.next().context("rollout_schema_token")?);
            }
        } else {
            ensure!(
                !matches!((ch, input.peek()), ('-', Some('-')) | ('/', Some('*'))),
                "rollout_schema_comments_forbidden"
            );
        }
        tokens.push(token);
        ensure!(tokens.len() <= 65_536, "rollout_schema_budget");
    }
    if !app_table {
        return Ok(serde_json::to_string(&tokens)?);
    }
    ensure!(
        tokens.first().is_some_and(|token| token == "CREATE")
            && tokens.get(1).is_some_and(|token| token == "TABLE"),
        "rollout_schema_table_required"
    );
    let start = tokens
        .iter()
        .position(|token| token == "(")
        .context("rollout_schema_columns")?;
    let mut depth = 1;
    let mut from = start + 1;
    let mut clauses = Vec::new();
    for (index, token) in tokens.iter().enumerate().skip(from) {
        match token.as_str() {
            "(" => depth += 1,
            ")" => depth -= 1,
            _ => {}
        }
        ensure!((0..=64).contains(&depth), "rollout_schema_depth");
        if depth == 0 {
            clauses.push(tokens[from..index].to_vec());
            clauses.sort();
            return Ok(serde_json::to_string(&(
                &tokens[..=start],
                clauses,
                &tokens[index..],
            ))?);
        }
        if depth == 1 && token == "," {
            clauses.push(tokens[from..index].to_vec());
            from = index + 1;
        }
    }
    anyhow::bail!("rollout_schema_columns")
}

pub(crate) fn verify_storage_shape(runtime: &Runtime, actual: &Connection) -> Result<()> {
    let metadata =
        crate::store::InitialStoreMetadata::load(runtime.instance_path(), runtime.app())?;
    let mut expected = Connection::open_in_memory()?;
    let tx = expected.transaction()?;
    metadata.initialize_in_transaction(&tx)?;
    install(&tx)?;
    let shape = |db: &Connection| -> Result<Vec<(String, String, String)>> {
        let mut statement = db.prepare(
            "SELECT type,name,coalesce(sql,'') FROM sqlite_master
            WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name",
        )?;
        let objects = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        objects
            .into_iter()
            .map(|(kind, name, sql)| {
                let app_table = kind == "table"
                    && runtime
                        .artifact()
                        .contract()
                        .schema
                        .models
                        .contains_key(&name);
                Ok((kind, name, schema_sql(&sql, app_table)?))
            })
            .collect()
    };
    ensure!(
        shape(actual)? == shape(&tx)?,
        "rollout_store_shape_incompatible_requires_maintenance"
    );
    Ok(())
}

pub(crate) fn ready(runtime: &Runtime, candidate_probe: bool) -> Result<bool> {
    let (ready, warm) = runtime.sql_read(|db| {
        runtime.check_binding(db)?;
        let active = authority_for(runtime, db)?;
        active.document.validate(runtime.artifact())?;
        if !active.document.enabled {
            return Ok((false, Vec::new()));
        }
        let Some(release) = state(db)? else {
            return Ok((true, Vec::new()));
        };
        let ready = candidate_probe
            || runtime.artifact().id() != release.target
            || matches!(release.phase, Phase::Draining | Phase::Complete);
        let mut warm = Vec::new();
        if candidate_probe
            && release.scope == runtime.scope()
            && release.authority == active.stamp
            && matches!(release.phase, Phase::Serving | Phase::Draining)
        {
            for id in [release.source, release.target] {
                if id != runtime.artifact().id() {
                    warm.push(id);
                }
            }
        }
        Ok((ready, warm))
    })?;
    // Never hold a business snapshot while admitting retained code/resources.
    for id in warm {
        retained(runtime, &id)?;
    }
    Ok(ready)
}

pub(crate) fn pending_artifacts(runtime: &Runtime) -> Result<Vec<String>> {
    runtime.sql_read(|db| {
        let mut statement = db.prepare("SELECT DISTINCT artifact FROM day2_invocations WHERE status='pending' ORDER BY artifact")?;
        let ids = statement.query_map([], |row| row.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut admitted_ids = Vec::new();
        for id in ids { if admitted(db, &id, runtime.scope())? { admitted_ids.push(id); } }
        if let Some(release) = state(db)? {
            // New target traffic cannot starve the finite source backlog after
            // its pod terminates; completion depends on settling that work.
            admitted_ids.sort_by_key(|id| id != &release.source);
        }
        Ok(admitted_ids)
    })
}

fn write(connection: &Connection, release: &Release) -> Result<()> {
    connection.execute("INSERT INTO day2_rollout VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET release=excluded.release", [serde_json::to_string(release)?])?;
    Ok(())
}

pub(crate) fn install(connection: &Connection) -> Result<()> {
    connection.execute_batch(DDL)?;
    Ok(())
}

/// The active artifact remains valid during overlap. An additional artifact
/// needs the exact scope and authority revision captured by the operator.
pub(crate) fn admitted(connection: &Connection, id: &str, scope: &str) -> Result<bool> {
    let active = authority_state::current(connection)?;
    if active.artifact_id == id {
        return Ok(true);
    }
    let Some(release) = state(connection)? else {
        return Ok(false);
    };
    Ok(release.scope == scope
        && release.authority == active.stamp
        && match release.phase {
            Phase::Serving | Phase::Draining => id == release.source || id == release.target,
            _ => false,
        })
}

fn operational_contract(artifact: &LoadedArtifact) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(artifact.contract())?;
    // Presentation bytes may change. All execution, authority, input/output,
    // routing, scheduling and credential contracts remain exactly compatible.
    for key in [
        "worker_digest",
        "sources",
        "assets",
        "web_resources",
        "templates",
        "api_docs",
    ] {
        value
            .as_object_mut()
            .context("artifact contract")?
            .remove(key);
    }
    Ok(value)
}

pub(crate) fn compatible_ticket(
    connection: &Connection,
    runtime: &Runtime,
    id: &str,
) -> Result<bool> {
    if id == runtime.artifact().id() {
        return Ok(true);
    }
    if !runtime.rolling() || state(connection)?.is_none() {
        return Ok(false);
    }
    let row: Option<(String, String, String)> = connection
        .query_row(
            "SELECT scope,epoch,contract FROM day2_rollout_artifacts WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((scope, epoch, contract)) = row else {
        return Ok(false);
    };
    Ok(scope == runtime.scope()
        && epoch == authority_state::current(connection)?.stamp.epoch
        && contract
            == crate::digest(&serde_json::to_vec(&operational_contract(
                runtime.artifact(),
            )?)?))
}

fn image(value: &str) -> Result<()> {
    let (repository, digest) = value
        .rsplit_once('@')
        .context("rollout_image_must_be_immutable")?;
    ensure!(
        !repository.is_empty() && !repository.chars().any(char::is_whitespace),
        "rollout_image_invalid"
    );
    day2_assets::hash_part(digest)?;
    Ok(())
}

fn operator(runtime: &Runtime, operator: &LocalOperator) -> Result<()> {
    ensure!(
        runtime.rolling() && !runtime.uses_native_storage(),
        "ordinary_rolling_profile_required"
    );
    let allowed = runtime.operators()?.contains(operator.name())
        || runtime.sql_read(|db| {
            Ok(authority_state::current(db)?
                .policy()?
                .admins
                .contains(operator.name()))
        })?;
    ensure!(allowed, "rollout_operator_required");
    Ok(())
}

fn release_lock(runtime: &Runtime) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(runtime.db().with_extension("release.lock"))?;
    ensure!(file.metadata()?.is_file(), "rollout_lock_invalid");
    file.lock()?;
    Ok(file)
}

fn now_ms() -> Result<i64> {
    Ok(i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

fn collect_retired(runtime: &Runtime) -> Result<()> {
    if !bundle_path(runtime).exists() {
        return Ok(());
    }
    let retired = runtime.sql_read(|db| {
        if state(db)?.is_none() { return Ok(Vec::new()); }
        let mut query = db.prepare("SELECT id FROM day2_rollout_artifacts a WHERE retired_ms IS NOT NULL
            AND retired_ms < ?1 AND NOT EXISTS(SELECT 1 FROM day2_invocations i WHERE i.artifact=a.id AND i.status='pending')")?;
        let ids = query.query_map([now_ms()?.saturating_sub(1_800_000)], |row| row.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let active = authority_state::current(db)?;
        let release = state(db)?;
        Ok(ids.into_iter().filter(|id| id != &active.artifact_id && release.as_ref().is_none_or(|release|
            matches!(release.phase, Phase::Complete | Phase::Aborted) || (id != &release.source && id != &release.target))).collect::<Vec<_>>())
    })?;
    let connection = open(&bundle_path(runtime))?;
    for id in retired {
        connection.execute("DELETE FROM artifacts WHERE id=?1", [id])?;
    }
    Ok(())
}

/// Atomic release admission. Call only after candidate-build admission and
/// online backup/rehearsal; publication alone cannot make the candidate serve.
pub fn prepare(
    runtime: &Runtime,
    candidate_instance: &Path,
    source_image: &str,
    target_image: &str,
    id: &str,
    operator_identity: &LocalOperator,
) -> Result<Release> {
    operator(runtime, operator_identity)?;
    let _preparation = release_lock(runtime)?;
    ensure!(
        !id.is_empty()
            && id.len() <= 96
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
        "rollout_release_id_invalid"
    );
    image(source_image)?;
    image(target_image)?;
    let mut instance_bytes = Vec::new();
    File::open(candidate_instance)?
        .take(1_048_577)
        .read_to_end(&mut instance_bytes)?;
    ensure!(instance_bytes.len() <= 1_048_576, "instance byte budget");
    let target_instance_digest = crate::digest(&instance_bytes);
    let instance = Instance::from_bytes(&instance_bytes)?;
    ensure!(
        instance.scope(runtime.app())? == runtime.scope(),
        "rollout_scope_changed"
    );
    let binding = &instance.apps[runtime.app()];
    ensure!(
        binding
            .runtime
            .as_ref()
            .is_some_and(|profile| profile.rolling())
            && binding.oauth_connections.is_empty(),
        "rollout_profile_changed"
    );
    let target = LoadedArtifact::load(
        &candidate_instance
            .parent()
            .context("candidate root")?
            .join(&binding.artifact),
    )?;
    target.require_current_api()?;
    ensure!(
        target.id() != runtime.artifact().id() && source_image != target_image,
        "rollout_requires_new_artifact"
    );
    ensure!(
        operational_contract(runtime.artifact())? == operational_contract(&target)?,
        "rollout_contract_incompatible_requires_maintenance"
    );
    ensure!(
        crate::security_admission::platform_inventory_digest(runtime.artifact())?
            == crate::security_admission::platform_inventory_digest(&target)?,
        "rollout_platform_changed_requires_maintenance"
    );
    let desired = AuthorityDocument::resolve(&instance, runtime.app(), &target)?;
    let original = Instance::load(runtime.instance_path())?;
    let mut original_instance = serde_json::to_value(&original)?;
    let mut candidate = serde_json::to_value(&instance)?;
    for value in [&mut original_instance, &mut candidate] {
        value["apps"][runtime.app()]["artifact"] = serde_json::Value::Null;
        if !value["apps"][runtime.app()]["security"].is_null() {
            value["apps"][runtime.app()]["security"]["artifact"] = serde_json::Value::Null;
        }
    }
    ensure!(
        original_instance == candidate,
        "rollout_instance_changed_requires_maintenance"
    );
    let mut candidate_binding = serde_json::to_value(binding)?;
    candidate_binding["artifact"] = serde_json::Value::Null;
    if !candidate_binding["security"].is_null() {
        candidate_binding["security"]["artifact"] = serde_json::Value::Null;
    }
    let mut original_binding = serde_json::to_value(&original.apps[runtime.app()])?;
    original_binding["artifact"] = serde_json::Value::Null;
    if !original_binding["security"].is_null() {
        original_binding["security"]["artifact"] = serde_json::Value::Null;
    }
    ensure!(
        candidate_binding == original_binding
            && instance.branding == original.branding
            && serde_json::to_value(&instance.identity)?
                == serde_json::to_value(&original.identity)?,
        "rollout_instance_changed_requires_maintenance"
    );
    collect_retired(runtime)?;
    publish(runtime, runtime.artifact())?;
    publish(runtime, &target)?;
    runtime.sql_write(|tx| {
        runtime.check_binding(tx)?;
        let active = authority_state::current(tx)?;
        let mut normalized = desired.clone();
        if let (Some(next), Some(previous)) = (&mut normalized.security, &active.document.security) { next.artifact = previous.artifact.clone(); }
        ensure!(active.artifact_id == runtime.artifact().id() && normalized == active.document, "rollout_authority_changed");
        let release = Release { id: id.into(), scope: runtime.scope().into(), source: active.artifact_id,
            target: target.id().into(), source_image: source_image.into(), target_image: target_image.into(),
            target_instance_digest, probe: None, authority: active.stamp, target_security: desired.security.clone(), placement: None, phase: Phase::Prepared };
        if let Some(previous) = state(tx)? {
            if previous.id == id {
                let mut retried = release.clone();
                retried.phase = previous.phase.clone();
                retried.placement = previous.placement.clone();
                retried.probe = previous.probe.clone();
                ensure!(previous == retried, "rollout_id_conflict");
                return Ok(previous);
            }
            ensure!(matches!(previous.phase, Phase::Complete | Phase::Aborted), "rollout_already_running");
        }
        write(tx, &release)?;
        let contract = crate::digest(&serde_json::to_vec(&operational_contract(&target)?)?);
        for artifact in [&release.source, &release.target] {
            tx.execute("INSERT INTO day2_rollout_artifacts VALUES(?1,?2,?3,?4,?5,NULL) ON CONFLICT(id) DO UPDATE SET scope=excluded.scope,epoch=excluded.epoch,contract=excluded.contract,retired_ms=NULL,admission_id=CASE WHEN excluded.admission_id='' THEN day2_rollout_artifacts.admission_id ELSE excluded.admission_id END",
                params![artifact, release.scope, release.authority.epoch, contract, if *artifact == release.target { release.id.as_str() } else { "" }])?;
        }
        Ok(release)
    })
}

/// Compare-and-set phase transitions are safe to repeat after a lost response.
/// The caller supplies observed Kubernetes readiness/drain evidence separately;
/// the operational recipe owns that order, not a desired configuration file.
pub fn transition(
    runtime: &Runtime,
    id: &str,
    expected: Phase,
    next: Phase,
    operator_identity: &LocalOperator,
) -> Result<Release> {
    operator(runtime, operator_identity)?;
    let _transition = release_lock(runtime)?;
    runtime.sql_write(|tx| {
        let mut release = state(tx)?.context("rollout_not_prepared")?;
        ensure!(release.id == id && release.scope == runtime.scope(), "rollout_identity_changed");
        ensure!(next == Phase::Aborted || release.authority == authority_state::current(tx)?.stamp, "rollout_authority_changed");
        if release.phase == next { return Ok(release); }
        if next == Phase::Serving && Instance::load(runtime.instance_path())?.identity.is_some() {
            ensure!(release.placement.is_some(), "rollout_placement_required");
        }
        ensure!(release.phase == expected && matches!((&expected, &next),
            (Phase::Prepared, Phase::Serving) | (Phase::Serving, Phase::Draining)
            | (Phase::Draining, Phase::Complete) | (Phase::Prepared, Phase::Aborted)
            | (Phase::Serving, Phase::Aborted)), "rollout_phase_conflict");
        if next == Phase::Complete {
            let pending: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM day2_invocations WHERE status='pending' AND artifact=?1)", [&release.source], |row| row.get(0))?;
            ensure!(!pending, "rollout_source_work_pending");
            // Promotion keeps the policy revision: a release does not revoke or
            // regrant business authority, nor erase completed command outcomes.
            let path = runtime.instance_path().parent().context("installation root")?
                .join("artifacts").join(day2_assets::hash_part(&release.target)?);
            let mut document = authority_state::current(tx)?.document;
            document.security = release.target_security.clone();
            tx.execute("UPDATE day2_authority SET artifact_id=?1,artifact_path=?2,document=?3 WHERE singleton=1", params![release.target, path.to_string_lossy(), serde_json::to_string(&document)?])?;
            tx.execute("UPDATE day2_rollout_artifacts SET retired_ms=?1 WHERE id=?2", params![now_ms()?,release.source])?;
        }
        if next == Phase::Aborted {
            let pending: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM day2_invocations WHERE status='pending' AND artifact=?1)", [&release.target], |row| row.get(0))?;
            ensure!(!pending, "rollout_target_work_pending");
            tx.execute("UPDATE day2_rollout_artifacts SET retired_ms=?1 WHERE id=?2", params![now_ms()?,release.target])?;
        }
        release.phase = next;
        write(tx, &release)?;
        Ok(release)
    })
}

fn bundle_path(runtime: &Runtime) -> PathBuf {
    runtime.db().with_extension("artifacts.sqlite")
}

fn collect(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
    bytes: &mut u64,
    entries: &mut usize,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        *entries += 1;
        ensure!(*entries <= MAX_FILES * 2, "rollout_artifact_entry_bound");
        let entry = entry?;
        let path = entry.path();
        let kind = entry.file_type()?;
        let relative = path.strip_prefix(root)?;
        let name = relative.to_str().context("artifact filename")?;
        ensure!(
            name.len() <= 512 && relative.components().count() <= 16,
            "rollout_artifact_path_bound"
        );
        if kind.is_dir() {
            collect(root, &path, files, bytes, entries)?;
            continue;
        }
        ensure!(
            kind.is_file() && files.len() < MAX_FILES,
            "rollout_artifact_file_bound"
        );
        let mut contents = Vec::new();
        File::open(&path)?
            .take(MAX_BYTES.saturating_sub(*bytes) + 1)
            .read_to_end(&mut contents)?;
        *bytes += u64::try_from(contents.len())?;
        ensure!(*bytes <= MAX_BYTES, "rollout_artifact_byte_bound");
        files.insert(name.into(), contents);
    }
    Ok(())
}

fn publish(runtime: &Runtime, artifact: &LoadedArtifact) -> Result<()> {
    let mut files = BTreeMap::new();
    collect(
        artifact.directory(),
        artifact.directory(),
        &mut files,
        &mut 0,
        &mut 0,
    )?;
    let manifest: BTreeMap<_, _> = files
        .iter()
        .map(|(name, bytes)| (name.clone(), crate::digest(bytes)))
        .collect();
    let encoded = serde_json::to_vec(&manifest)?;
    ensure!(
        encoded.len() <= 4 * 1024 * 1024,
        "rollout_artifact_manifest_bound"
    );
    let mut connection = open(&bundle_path(runtime))?;
    connection.execute_batch("PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY,digest TEXT NOT NULL,bundle BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS artifact_files(artifact TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
            path TEXT NOT NULL,bytes BLOB NOT NULL,PRIMARY KEY(artifact,path))")?;
    let tx = connection.transaction()?;
    let (stored, existing): (i64, bool) = tx.query_row("SELECT coalesce(sum(length(bytes)),0),EXISTS(SELECT 1 FROM artifacts WHERE id=?1) FROM artifact_files", [artifact.id()], |row| Ok((row.get(0)?,row.get(1)?)))?;
    let bytes = files.values().map(Vec::len).sum::<usize>();
    ensure!(
        existing || stored.saturating_add(i64::try_from(bytes)?) <= MAX_STORED_BYTES,
        "rollout_artifact_storage_budget_exceeded"
    );
    if !existing {
        tx.execute(
            "INSERT INTO artifacts VALUES(?1,?2,?3)",
            params![artifact.id(), crate::digest(&encoded), encoded],
        )?;
        for (name, bytes) in &files {
            tx.execute(
                "INSERT INTO artifact_files VALUES(?1,?2,?3)",
                params![artifact.id(), name, bytes],
            )?;
        }
    }
    let digest: String = tx.query_row(
        "SELECT digest FROM artifacts WHERE id=?1",
        [artifact.id()],
        |row| row.get(0),
    )?;
    ensure!(
        digest == crate::digest(&encoded),
        "rollout_artifact_publication_conflict"
    );
    let count: i64 = tx.query_row(
        "SELECT count(*) FROM artifact_files WHERE artifact=?1",
        [artifact.id()],
        |row| row.get(0),
    )?;
    ensure!(
        count == i64::try_from(files.len())?,
        "rollout_artifact_publication_conflict"
    );
    for (name, expected) in &manifest {
        let bytes: Vec<u8> = tx.query_row(
            "SELECT bytes FROM artifact_files WHERE artifact=?1 AND path=?2 AND length(bytes)<=16777216",
            params![artifact.id(), name],
            |row| row.get(0),
        )?;
        ensure!(
            &crate::digest(&bytes) == expected,
            "rollout_artifact_publication_conflict"
        );
    }
    tx.commit()?;
    Ok(())
}

pub(crate) fn retained(runtime: &Runtime, id: &str) -> Result<LoadedArtifact> {
    day2_assets::hash_part(id)?;
    type Cache = Vec<((PathBuf, String), LoadedArtifact)>;
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let key = (runtime.db().to_path_buf(), id.to_owned());
    let mut cached = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("retained_artifact_cache_poisoned"))?;
    if let Some((_, artifact)) = cached.iter().find(|(stored, _)| stored == &key) {
        return Ok(artifact.clone());
    }
    let connection = Connection::open_with_flags(
        bundle_path(runtime),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (digest, encoded): (String, Vec<u8>) = connection.query_row(
        "SELECT digest,bundle FROM artifacts WHERE id=?1 AND length(bundle)<=4194304",
        [id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    ensure!(
        encoded.len() <= 4 * 1024 * 1024 && crate::digest(&encoded) == digest,
        "rollout_retained_artifact_changed"
    );
    let files: BTreeMap<String, String> = crate::json::decode_evidence(&encoded)?;
    ensure!(files.len() <= MAX_FILES, "rollout_artifact_file_bound");
    let temporary = Arc::new(tempfile::tempdir()?);
    let directory = temporary.path().join(day2_assets::hash_part(id)?);
    fs::create_dir(&directory)?;
    let mut total = 0_u64;
    for (name, expected) in files {
        let bytes: Vec<u8> = connection.query_row(
            "SELECT bytes FROM artifact_files WHERE artifact=?1 AND path=?2 AND length(bytes)<=16777216",
            params![id, name],
            |row| row.get(0),
        )?;
        ensure!(
            crate::digest(&bytes) == expected,
            "rollout_retained_artifact_changed"
        );
        let path = Path::new(&name);
        ensure!(
            name.len() <= 512
                && path.components().count() <= 16
                && path
                    .components()
                    .all(|part| matches!(part, Component::Normal(_))),
            "rollout_artifact_path_invalid"
        );
        total += u64::try_from(bytes.len())?;
        ensure!(total <= MAX_BYTES, "rollout_artifact_byte_bound");
        let target = directory.join(path);
        fs::create_dir_all(target.parent().context("artifact parent")?)?;
        fs::write(target, bytes)?;
    }
    let mut artifact = LoadedArtifact::load(&directory)?;
    ensure!(artifact.id() == id, "rollout_retained_artifact_changed");
    artifact.retain(temporary);
    if cached.len() == 2 {
        cached.remove(0);
    }
    cached.push((key, artifact.clone()));
    Ok(artifact)
}

/// Kernel-held ownership survives pauses and is released on process death.
/// No lease timeout can let a second executor overlap a paused provider call.
pub(crate) struct InvocationOwner {
    _file: Option<File>,
}

pub(crate) fn execution_lock(runtime: &Runtime, id: &str) -> Result<Option<InvocationOwner>> {
    if !runtime.rolling() || runtime.uses_native_storage() {
        return Ok(Some(InvocationOwner { _file: None }));
    }
    let query = runtime.sql_read(|db| {
        runtime.check_binding(db)?;
        let operation: String = db.query_row(
            "SELECT operation FROM day2_invocations WHERE id=?1",
            [id],
            |row| row.get(0),
        )?;
        Ok(runtime.artifact().route(&operation)?.kind == "query")
    })?;
    if query {
        // Queries have no external writes and their read/completion transaction
        // already arbitrates duplicates. Unrelated command stripes must not
        // turn ordinary page reads into pending invocations.
        return Ok(Some(InvocationOwner { _file: None }));
    }
    let directory = runtime
        .db()
        .parent()
        .context("state directory")?
        .join("execution-locks");
    fs::create_dir_all(&directory)?;
    ensure!(
        fs::symlink_metadata(&directory)?.is_dir(),
        "rollout_execution_lock_directory"
    );
    // Fixed stripes bound growth; collisions defer work without blocking HTTP.
    let hash = crate::digest(id.as_bytes());
    let stripe = u16::from_str_radix(&hash[7..11], 16)? % 1024;
    let path = directory.join(format!("{}-{stripe}.lock", runtime.app()));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    ensure!(file.metadata()?.is_file(), "rollout_execution_lock_file");
    match file.try_lock() {
        Ok(()) => Ok(Some(InvocationOwner { _file: Some(file) })),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_column_order_is_independent_but_constraints_literals_and_private_order_are_exact()
    -> Result<()> {
        let initial = "CREATE TABLE \"items\" (id BLOB PRIMARY KEY, z TEXT, a TEXT) STRICT";
        let fresh = "CREATE TABLE \"items\" (id BLOB PRIMARY KEY, a TEXT, z TEXT) STRICT";
        assert_eq!(schema_sql(initial, true)?, schema_sql(fresh, true)?);
        assert_ne!(schema_sql(initial, false)?, schema_sql(fresh, false)?);
        for changed in [
            fresh.replace("a TEXT", "a TEXT NOT NULL"),
            fresh.replace("a TEXT", "a TEXTNOTNULL"),
            fresh.replace("a TEXT", "a TEXT DEFAULT 'two words'"),
            fresh.replace("a TEXT", "a TEXT DEFAULT 'twowords'"),
        ] {
            assert_ne!(schema_sql(fresh, true)?, schema_sql(&changed, true)?);
        }
        assert_ne!(
            schema_sql("CREATE TABLE x (a TEXT DEFAULT 'two words')", true)?,
            schema_sql("CREATE TABLE x (a TEXT DEFAULT 'twowords')", true)?
        );
        assert!(schema_sql("CREATE TABLE x (a TEXT /* extra */)", true).is_err());
        let db = Connection::open_in_memory()?;
        db.execute_batch("CREATE TABLE items (id BLOB PRIMARY KEY,z TEXT) STRICT; ALTER TABLE items ADD COLUMN a TEXT")?;
        let actual: String = db.query_row(
            "SELECT sql FROM sqlite_master WHERE name='items'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            schema_sql(&actual, true)?,
            schema_sql(
                "CREATE TABLE items (id BLOB PRIMARY KEY,a TEXT,z TEXT) STRICT",
                true
            )?
        );
        Ok(())
    }
}
