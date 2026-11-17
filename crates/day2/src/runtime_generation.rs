//! Ordinary RWO executor ownership in the existing release journal. These rows
//! describe installed code and accepted work; they never replace live authority.
//! Isolated candidates have no invocation admission. A promoted pair may retain
//! its exact source executor without transferring that executor's accepted work.
use crate::{
    authority_state,
    runtime_pair::RuntimeIdentity,
    security_admission::{self, HostCode},
    store::Runtime,
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

const DDL: &str = "CREATE TABLE IF NOT EXISTS day2_rollout_generations(
    id TEXT PRIMARY KEY, scope TEXT NOT NULL, generation TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS day2_rollout_runtime(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    generation TEXT NOT NULL REFERENCES day2_rollout_generations(id)
) STRICT;
CREATE TABLE IF NOT EXISTS day2_invocation_runtime(
    invocation TEXT PRIMARY KEY REFERENCES day2_invocations(id),
    generation TEXT NOT NULL REFERENCES day2_rollout_generations(id)
) STRICT;
CREATE INDEX IF NOT EXISTS day2_invocation_runtime_generation ON day2_invocation_runtime(generation,invocation);";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Installed {
    runtime: RuntimeIdentity,
    code: HostCode,
}

impl Installed {
    fn id(&self, scope: &str) -> Result<String> {
        Ok(crate::digest(&serde_json::to_vec(&(scope, self))?))
    }
}

pub(crate) fn install(db: &Connection) -> Result<()> {
    db.execute_batch(DDL)?;
    Ok(())
}

fn active(db: &Connection) -> Result<Option<String>> {
    Ok(db
        .query_row(
            "SELECT generation FROM day2_rollout_runtime WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?)
}

fn load(db: &Connection, scope: &str, id: &str) -> Result<Installed> {
    let (stored_scope, encoded): (String, String) = db.query_row(
        "SELECT scope,generation FROM day2_rollout_generations WHERE id=?1",
        [id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let installed: Installed = crate::json::decode(encoded.as_bytes())?;
    ensure!(
        stored_scope == scope && installed.id(scope)? == id,
        "runtime_generation_binding_changed"
    );
    Ok(installed)
}

fn pin_process(runtime: &Runtime, id: &str) -> Result<()> {
    let _ = runtime.executor_generation().set(id.into());
    ensure!(
        runtime
            .executor_generation()
            .get()
            .is_some_and(|selected| selected == id),
        "runtime_generation_process_changed"
    );
    Ok(())
}

/// A restart reads the durable selection, while a running process keeps the
/// identity it already selected. Neither path can silently adopt another host.
pub(crate) fn selected(runtime: &Runtime, db: &Connection) -> Result<String> {
    let measured = security_admission::host_code()?;
    let id = choice(runtime, db, &measured)?;
    bind_admitted(runtime, db, &id)?;
    Ok(id)
}

fn choice(runtime: &Runtime, db: &Connection, measured: &HostCode) -> Result<String> {
    let admitted = active(db)?.context("runtime_generation_not_installed")?;
    let id = if let Some(pinned) = runtime.executor_generation().get() {
        pinned.clone()
    } else if let Some(source) = crate::runtime_pair::retained_source(runtime, db)?
        && load(db, runtime.scope(), &source)?.code == *measured
    {
        // Ordinary source restarts retain their owner even for an image-only
        // pair with identical supervisor/launcher bytes. A candidate binds its
        // exact admitted target explicitly before public host construction.
        source
    } else {
        admitted.clone()
    };
    ensure!(
        id == admitted || crate::runtime_pair::retained_source(runtime, db)?.as_ref() == Some(&id),
        "runtime_generation_not_admitted"
    );
    let installed = load(db, runtime.scope(), &id)?;
    ensure!(
        installed.code == *measured,
        "runtime_generation_code_changed"
    );
    Ok(id)
}

pub(crate) fn bind_admitted(runtime: &Runtime, db: &Connection, id: &str) -> Result<()> {
    ensure!(
        active(db)?.as_deref() == Some(id)
            || crate::runtime_pair::retained_source(runtime, db)?.as_deref() == Some(id),
        "runtime_generation_not_admitted"
    );
    ensure!(
        load(db, runtime.scope(), id)?.code == security_admission::host_code()?,
        "runtime_generation_code_changed"
    );
    pin_process(runtime, id)
}

#[cfg(test)]
pub(crate) fn choice_for_test(
    runtime: &Runtime,
    db: &Connection,
    measured: &HostCode,
) -> Result<String> {
    choice(runtime, db, measured)
}

/// Build prerequisites still validate the original compiled artifact. The
/// installed runtime is a separately approved execution choice: only startup
/// under those prerequisites or an operator-admitted pair can publish it.
pub(crate) fn require_execution(
    runtime: &Runtime,
    db: &Connection,
    requirements: &security_admission::Requirements,
) -> Result<()> {
    if runtime.rolling() && active(db)?.is_some() {
        let id = selected(runtime, db)?;
        let installed = load(db, runtime.scope(), &id)?;
        if matches!(
            installed.runtime.containment,
            Some(security_admission::Containment::LinuxQualifiedV1 { .. })
        ) {
            ensure!(
                installed.runtime.code()? == installed.code,
                "runtime_generation_qualification_changed"
            );
            return Ok(());
        }
    }
    requirements.require_runtime()
}

pub(crate) fn select_pair_target(db: &Connection, source: &str, target: &str) -> Result<()> {
    require_active(db, source)?;
    ensure!(
        db.execute(
            "UPDATE day2_rollout_runtime SET generation=?1 WHERE singleton=1 AND generation=?2",
            params![target, source]
        )? == 1,
        "runtime_generation_not_admitted"
    );
    Ok(())
}

fn initial(runtime: &Runtime, tx: &Transaction<'_>) -> Result<String> {
    // An already-admitted app-artifact candidate may receive the first work.
    // Its rollout requires the same runtime inventory/containment as source;
    // runtime-pair candidates still have no startup or serving admission.
    let active = crate::rollout::authority_for(runtime, tx)?;
    if let Some(requirements) = &active.document.security {
        requirements.require_runtime()?;
    }
    let installed = Installed {
        runtime: RuntimeIdentity::from_artifact(
            runtime.artifact(),
            active.document.security.as_ref(),
        )?,
        code: security_admission::host_code()?,
    };
    let id = installed.id(runtime.scope())?;
    if let Some(previous) = runtime.executor_generation().get() {
        ensure!(*previous == id, "runtime_generation_process_changed");
    }
    tx.execute(
        "INSERT INTO day2_rollout_generations VALUES(?1,?2,?3) ON CONFLICT(id) DO NOTHING",
        params![id, runtime.scope(), serde_json::to_string(&installed)?],
    )?;
    ensure!(
        load(tx, runtime.scope(), &id)? == installed,
        "runtime_generation_binding_changed"
    );
    tx.execute("INSERT INTO day2_rollout_runtime VALUES(1,?1)", [&id])?;
    // The choice is immutable even if the accepting transaction rolls back.
    // A later retry may recreate that exact row; this is not a retained grant.
    pin_process(runtime, &id)?;
    Ok(id)
}

/// Called by an actual serving executor after native code admission, never by
/// operator store-inspection helpers. Only DML binds a fresh process choice.
pub(crate) fn register_active(runtime: &Runtime) -> Result<()> {
    if !runtime.rolling() {
        return Ok(());
    }
    runtime.sql_write(|tx| {
        runtime.check_binding(tx)?;
        if active(tx)?.is_some() {
            selected(runtime, tx)?;
        } else {
            initial(runtime, tx)?;
        }
        Ok(())
    })
}

pub(crate) fn expected_id(scope: &str, identity: &RuntimeIdentity) -> Result<String> {
    Installed {
        runtime: identity.clone(),
        code: identity.code()?,
    }
    .id(scope)
}

/// Register expected candidate code as DATA only. Execution must still measure
/// the actual process and match a current, scoped release admission at every use.
pub(crate) fn register_expected(
    db: &Connection,
    scope: &str,
    identity: &RuntimeIdentity,
) -> Result<String> {
    let installed = Installed {
        runtime: identity.clone(),
        code: identity.code()?,
    };
    let id = installed.id(scope)?;
    db.execute(
        "INSERT INTO day2_rollout_generations VALUES(?1,?2,?3) ON CONFLICT(id) DO NOTHING",
        params![id, scope, serde_json::to_string(&installed)?],
    )?;
    ensure!(
        load(db, scope, &id)? == installed,
        "runtime_generation_binding_changed"
    );
    Ok(id)
}

pub(crate) fn require_expected(
    db: &Connection,
    scope: &str,
    id: &str,
    identity: &RuntimeIdentity,
) -> Result<()> {
    ensure!(
        id == expected_id(scope, identity)?
            && load(db, scope, id)?
                == Installed {
                    runtime: identity.clone(),
                    code: identity.code()?
                },
        "runtime_generation_binding_changed"
    );
    Ok(())
}

pub(crate) fn require_active(db: &Connection, id: &str) -> Result<()> {
    ensure!(
        active(db)?.as_deref() == Some(id),
        "runtime_generation_not_admitted"
    );
    Ok(())
}

pub(crate) fn capture(
    runtime: &Runtime,
    tx: &Transaction<'_>,
    invocation: &str,
    parent: Option<&str>,
) -> Result<()> {
    if !runtime.rolling() {
        return Ok(());
    }
    let generation = if active(tx)?.is_some() {
        selected(runtime, tx)?
    } else {
        initial(runtime, tx)?
    };
    if parent.is_none() {
        crate::runtime_pair::require_root_admission(runtime, tx, &generation)?;
    }
    if let Some(parent) = parent {
        ensure!(
            owner(tx, parent)? == generation,
            "runtime_generation_parent_changed"
        );
    }
    tx.execute(
        "INSERT INTO day2_invocation_runtime VALUES(?1,?2)",
        params![invocation, generation],
    )?;
    Ok(())
}

fn owner(db: &Connection, invocation: &str) -> Result<String> {
    db.query_row(
        "SELECT generation FROM day2_invocation_runtime WHERE invocation=?1",
        [invocation],
        |row| row.get(0),
    )
    .optional()?
    .context("invocation_runtime_missing")
}

pub(crate) fn owns(runtime: &Runtime, db: &Connection, invocation: &str) -> Result<bool> {
    Ok(!runtime.rolling() || owner(db, invocation)? == selected(runtime, db)?)
}

pub(crate) fn require_queue(db: &Connection) -> Result<()> {
    let missing: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM day2_invocations i
        WHERE i.status='pending' AND NOT EXISTS(SELECT 1 FROM day2_authority_blocks b WHERE b.invocation=i.id)
        AND NOT EXISTS(SELECT 1 FROM day2_invocation_runtime r WHERE r.invocation=i.id))", [], |row| row.get(0))?;
    ensure!(!missing, "invocation_runtime_missing");
    Ok(())
}

pub(crate) fn require(runtime: &Runtime, db: &Connection, invocation: &str) -> Result<()> {
    if !runtime.rolling() {
        return Ok(());
    }
    let pending: bool = db.query_row(
        "SELECT status='pending' FROM day2_invocations WHERE id=?1",
        [invocation],
        |row| row.get(0),
    )?;
    ensure!(
        !pending || owns(runtime, db, invocation)?,
        "invocation_runtime_changed"
    );
    Ok(())
}

/// Record knowledge from the executor that actually performed the effect even
/// after revocation. This deliberately grants no fresh dispatch or completion.
pub(crate) fn require_settlement(
    runtime: &Runtime,
    db: &Connection,
    invocation: &str,
) -> Result<()> {
    if !runtime.rolling() {
        return Ok(());
    }
    let id = runtime
        .executor_generation()
        .get()
        .context("runtime_generation_process_unbound")?;
    ensure!(owner(db, invocation)? == *id, "invocation_runtime_changed");
    ensure!(
        load(db, runtime.scope(), id)?.code == security_admission::host_code()?,
        "runtime_generation_code_changed"
    );
    Ok(())
}

/// The installed runtime is independent of the current app build's inventory.
/// Inspection is DATA for the operator, not process or business admission.
pub(crate) fn identity(runtime: &Runtime, db: &Connection) -> Result<Option<RuntimeIdentity>> {
    active(db)?
        .map(|id| load(db, runtime.scope(), &id).map(|value| value.runtime))
        .transpose()
}

pub(crate) fn process_identity(runtime: &Runtime, db: &Connection) -> Result<RuntimeIdentity> {
    load(db, runtime.scope(), &selected(runtime, db)?).map(|installed| installed.runtime)
}

pub(crate) fn installed_process(runtime: &Runtime, db: &Connection) -> Result<bool> {
    let actual = security_admission::host_code()?;
    if let Some(id) = active(db)?
        && load(db, runtime.scope(), &id)?.code == actual
    {
        return Ok(true);
    }
    if let Some(source) = crate::runtime_pair::retained_source(runtime, db)? {
        return Ok(load(db, runtime.scope(), &source)?.code == actual);
    }
    Ok(false)
}

pub(crate) fn authority_changed(
    db: &Connection,
    previous: Option<&authority_state::ActiveAuthority>,
    next: &authority_state::ActiveAuthority,
) -> Result<()> {
    if previous.is_some_and(|previous| {
        previous.artifact_id != next.artifact_id
            || previous.artifact_path != next.artifact_path
            || previous.stamp.epoch != next.stamp.epoch
            || previous.document.security != next.document.security
    }) {
        invalidate(db)?;
    }
    Ok(())
}

/// Native security rebinds and exclusive artifact/restore changes discard the
/// active selection. A policy-only revision does not change installed code.
/// Captured ownership rows remain immutable; missing owners are never backfilled.
pub(crate) fn invalidate(db: &Connection) -> Result<()> {
    let present: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='day2_rollout_runtime')",
        [],
        |row| row.get(0),
    )?;
    if !present {
        return Ok(());
    }
    db.execute("DELETE FROM day2_rollout_runtime", [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::LoadedArtifact;
    use serde_json::json;
    use std::path::Path;

    struct World {
        root: tempfile::TempDir,
        runtime: Runtime,
        db: Connection,
    }

    impl World {
        fn new() -> Result<Self> {
            let root = tempfile::tempdir()?;
            let instance = root.path().join("instance.json");
            let directory = root.path().join("artifact");
            std::fs::create_dir(&directory)?;
            let contract = serde_json::from_value(json!({
                "format":crate::artifact::CURRENT_FORMAT,
                "verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
                "roc_version":"generation-test","worker_digest":crate::digest(b"worker"),
                "schema_digest":crate::digest(b"schema"),
                "schema":{"models":{},"inputs":{"input":{"fields":{}}},"foreign_keys":[]},
                "operations":[{"name":"run","kind":"command","input_type":"input","output_type":""}],
                "sources":{"crates/generation-runtime.rs":crate::digest(b"initial SDK")},
                "admission":"local-spike-only"
            }))?;
            let artifact = LoadedArtifact::from_contract_for_tests(
                crate::digest(b"artifact"),
                directory.clone(),
                contract,
            );
            std::fs::write(
                &instance,
                serde_json::to_vec(&json!({
                    "installation":"generation", "environment":"test",
                    "apps":{"app":{"artifact":directory,"readers":["alice"],"writers":["alice"],
                        "runtime":{"kind":"linux_sqlite_rwo_v1","resources":{
                            "memory_mib":512,"cpu_millis":1000,"process_limit":128,
                            "http_concurrency":16,"shutdown_seconds":30}}}}
                }))?,
            )?;
            let path = root.path().join("app.sqlite");
            let runtime =
                Runtime::from_artifact_for_tests(instance, "app".into(), path.clone(), artifact)?;
            let mut db = Connection::open(path)?;
            db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON")?;
            let tx = db.transaction()?;
            tx.execute_batch(crate::store::PLATFORM_DDL)?;
            for (key, value) in [
                ("scope", runtime.scope().to_owned()),
                (
                    "schema",
                    runtime.artifact().contract().schema_digest.clone(),
                ),
            ] {
                tx.execute("INSERT INTO day2_meta VALUES(?1,?2)", params![key, value])?;
            }
            crate::audit::upgrade(&tx)?;
            authority_state::upgrade(&tx)?;
            crate::invocations::upgrade(&tx)?;
            crate::execution::upgrade(&tx)?;
            crate::rollout::install(&tx)?;
            let document = json!({"enabled":true,"readers":["alice"],"writers":["alice"],
            "policy":{"version":1,"admins":["operator"],"operations":{
                "run":{"actors":["alice"],"mode":{"kind":"current_state"},"models":{}}
            }}});
            tx.execute(
                "INSERT INTO day2_authority VALUES(1,?1,1,?2,?3,?4)",
                params![
                    crate::digest(b"epoch"),
                    document.to_string(),
                    runtime.artifact().id(),
                    directory.to_string_lossy()
                ],
            )?;
            tx.commit()?;
            Ok(Self { root, runtime, db })
        }

        fn accept(&mut self, id: &str, parent: Option<&str>) -> Result<String> {
            let tx = self.db.transaction()?;
            insert(&tx, &self.runtime, id)?;
            capture(&self.runtime, &tx, id, parent)?;
            let id = owner(&tx, id)?;
            tx.commit()?;
            Ok(id)
        }

        fn restart(&self) -> Result<Runtime> {
            Runtime::from_artifact_for_tests(
                self.runtime.instance_path().into(),
                "app".into(),
                self.runtime.db().into(),
                self.runtime.artifact().clone(),
            )
        }

        fn other_generation(&self) -> Result<String> {
            let current = active(&self.db)?.context("active")?;
            let mut other = load(&self.db, self.runtime.scope(), &current)?;
            other.code.supervisor = crate::digest(b"different actual executable");
            let id = other.id(self.runtime.scope())?;
            self.db.execute(
                "INSERT INTO day2_rollout_generations VALUES(?1,?2,?3)",
                params![id, self.runtime.scope(), serde_json::to_string(&other)?],
            )?;
            Ok(id)
        }
    }

    fn insert(tx: &Transaction<'_>, runtime: &Runtime, id: &str) -> Result<()> {
        tx.execute("INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status) VALUES(?1,'run','alice','{}',?2,1,'pending')",
            params![id,runtime.artifact().id()])?;
        authority_state::pin_invocation(tx, id, &authority_state::current(tx)?.stamp)
    }

    #[test]
    fn actual_restart_and_new_worker_build_keep_installed_runtime_identity() -> Result<()> {
        let mut world = World::new()?;
        let generation = world.accept("first", None)?;
        let restarted = world.restart()?;
        assert_eq!(selected(&restarted, &world.db)?, generation);
        let mut contract = world.runtime.artifact().contract().clone();
        contract.sources.insert(
            "crates/generation-runtime.rs".into(),
            crate::digest(b"another app build SDK"),
        );
        let worker = LoadedArtifact::from_contract_for_tests(
            crate::digest(b"new artifact"),
            Path::new("/test/new-worker").into(),
            contract,
        );
        assert_ne!(
            RuntimeIdentity::from_artifact(&worker, None)?,
            identity(&world.runtime, &world.db)?.unwrap()
        );
        let host = Runtime::from_artifact_for_tests(
            world.runtime.instance_path().into(),
            "app".into(),
            world.runtime.db().into(),
            worker,
        )?;
        // Selection metadata is independent of worker build inputs; it does
        // not grant that worker artifact or any operation authority.
        assert_eq!(selected(&host, &world.db)?, generation);
        assert!(owns(&restarted, &world.db, "first")?);
        Ok(())
    }

    #[test]
    fn rollback_never_transfers_choice_or_backfills_unowned_work() -> Result<()> {
        let mut world = World::new()?;
        let foreign = Runtime::from_artifact_for_tests(
            world.runtime.instance_path().into(),
            "app".into(),
            world.runtime.db().into(),
            LoadedArtifact::from_contract_for_tests(
                crate::digest(b"unadmitted artifact"),
                world.runtime.artifact().directory().into(),
                world.runtime.artifact().contract().clone(),
            ),
        )?;
        {
            let tx = world.db.transaction()?;
            insert(&tx, &foreign, "foreign")?;
            assert!(capture(&foreign, &tx, "foreign", None).is_err());
        }
        assert!(active(&world.db)?.is_none());
        assert!(foreign.executor_generation().get().is_none());
        {
            let tx = world.db.transaction()?;
            insert(&tx, &world.runtime, "rolled-back")?;
            capture(&world.runtime, &tx, "rolled-back", None)?;
        }
        assert!(active(&world.db)?.is_none());
        assert!(owner(&world.db, "rolled-back").is_err());
        let chosen = world.runtime.executor_generation().get().unwrap().clone();
        assert_eq!(world.accept("committed", None)?, chosen);
        let tx = world.db.transaction()?;
        insert(&tx, &world.runtime, "unowned")?;
        assert!(owns(&world.runtime, &tx, "unowned").is_err());
        tx.commit()?;
        assert!(owner(&world.db, "unowned").is_err());
        assert!(require_queue(&world.db).is_err());
        Ok(())
    }

    #[test]
    fn same_artifact_cannot_move_pending_work_to_another_runtime_or_scope() -> Result<()> {
        let mut world = World::new()?;
        let original = world.accept("parent", None)?;
        assert_eq!(world.accept("child", Some("parent"))?, original);
        let other = world.other_generation()?;
        world.db.execute(
            "UPDATE day2_invocation_runtime SET generation=?1 WHERE invocation='parent'",
            [&other],
        )?;
        assert!(world.accept("rejected-child", Some("parent")).is_err());
        assert!(owner(&world.db, "rejected-child").is_err());
        world.db.execute(
            "UPDATE day2_invocation_runtime SET generation=?1 WHERE invocation='parent'",
            [&original],
        )?;
        world
            .db
            .execute("UPDATE day2_rollout_runtime SET generation=?1", [&other])?;
        assert!(selected(&world.runtime, &world.db).is_err());
        assert!(selected(&world.restart()?, &world.db).is_err());
        assert_eq!(owner(&world.db, "parent")?, original);
        assert_eq!(owner(&world.db, "child")?, original);
        world
            .db
            .execute("UPDATE day2_rollout_runtime SET generation=?1", [&original])?;
        assert!(owns(&world.runtime, &world.db, "parent")?);
        world.db.execute(
            "UPDATE day2_rollout_generations SET scope='another/scope/app' WHERE id=?1",
            [&original],
        )?;
        assert!(selected(&world.runtime, &world.db).is_err());
        Ok(())
    }

    #[test]
    fn non_rwo_queue_does_not_require_the_generation_schema() -> Result<()> {
        let world = World::new()?;
        let path = world.runtime.instance_path();
        let mut instance: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
        instance["apps"]["app"]
            .as_object_mut()
            .unwrap()
            .remove("runtime");
        std::fs::write(path, serde_json::to_vec(&instance)?)?;
        let runtime = world.restart()?;
        assert!(!runtime.rolling());
        world.db.execute_batch(
            "DROP TABLE day2_invocation_runtime;
            DROP TABLE day2_rollout_runtime; DROP TABLE day2_rollout_generations",
        )?;
        assert!(crate::invocations::drain(&runtime, 1)?.is_empty());
        Ok(())
    }

    #[test]
    fn policy_keeps_runtime_but_native_rebind_and_restore_fence_it_without_transferring_work()
    -> Result<()> {
        let mut world = World::new()?;
        let generation = world.accept("accepted", None)?;
        let tx = world.db.transaction()?;
        let previous = authority_state::current(&tx)?;
        let mut policy = previous.clone();
        policy.stamp.revision += 1;
        authority_changed(&tx, Some(&previous), &policy)?;
        assert_eq!(active(&tx)?.as_deref(), Some(generation.as_str()));
        let mut rebound = policy.clone();
        rebound.document.security = Some(crate::security_admission::Requirements {
            version: 1,
            artifact: world.runtime.artifact().id().into(),
            platform_inventory: load(&tx, world.runtime.scope(), &generation)?
                .runtime
                .platform_inventory,
            roc_version: world.runtime.artifact().contract().roc_version.clone(),
            containment: crate::security_admission::Containment::MacosSandboxV1 {
                supervisor: crate::digest(b"replacement supervisor"),
            },
        });
        authority_changed(&tx, Some(&policy), &rebound)?;
        assert!(active(&tx)?.is_none());
        assert_eq!(owner(&tx, "accepted")?, generation);
        // Independently exercise the restore boundary with an installed slot.
        tx.execute(
            "INSERT INTO day2_rollout_runtime VALUES(1,?1)",
            [&generation],
        )?;
        let mut restored = policy.clone();
        restored.stamp.epoch = crate::digest(b"restore epoch");
        authority_changed(&tx, Some(&policy), &restored)?;
        assert!(active(&tx)?.is_none());
        assert_eq!(owner(&tx, "accepted")?, generation);
        assert!(selected(&world.runtime, &tx).is_err());
        tx.commit()?;
        assert!(selected(&world.restart()?, &world.db).is_err());
        assert_eq!(owner(&world.db, "accepted")?, generation);
        Ok(())
    }

    #[test]
    fn revocation_stops_execution_but_original_executor_can_settle_known_effect() -> Result<()> {
        let mut world = World::new()?;
        let generation = world.accept("accepted", None)?;
        let captured = authority_state::current(&world.db)?.stamp;
        {
            let tx = world.db.transaction()?;
            authority_state::require_execution_in(&tx, &world.runtime, "accepted", "run", "alice")?;
            tx.commit()?;
        }
        world
            .db
            .execute("UPDATE day2_authority SET revision=2", [])?;
        let other = world.other_generation()?;
        world
            .db
            .execute("UPDATE day2_rollout_runtime SET generation=?1", [&other])?;
        let wrong = world.restart()?;
        let tx = world.db.transaction()?;
        assert!(
            authority_state::require_execution_in(&tx, &world.runtime, "accepted", "run", "alice")
                .is_err()
        );
        crate::execution::check_settlement_binding(&tx, &world.runtime, "accepted", &captured)?;
        pin_process(&wrong, &other)?;
        assert!(require_settlement(&wrong, &tx, "accepted").is_err());
        assert_eq!(owner(&tx, "accepted")?, generation);
        tx.commit()?;
        assert!(world.root.path().join("app.sqlite").is_file());
        Ok(())
    }
}
