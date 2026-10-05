use anyhow::Result;
use day2_control::{
    BindingRef, BuildPlan, Digest, GitOid, Name,
    contracts::BuildProfile,
    journal::{AcceptanceProvenance, Claim, Journal, Lease, RecoveryMode},
    kernel::{EffectKind, Observation, State, effect_id},
};
use rusqlite::{Connection, params};
use std::path::Path;

// A historical fixture independent of the migration's schema constants. It must
// remain v2 even after the production schema moves on.
const V2: &str = "
    CREATE TABLE control_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL);
    INSERT INTO control_meta VALUES(1,2);
    CREATE TABLE executions (
        id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, plan TEXT NOT NULL, state TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK(revision>=0), cancel_requested INTEGER NOT NULL CHECK(cancel_requested IN (0,1)));
    CREATE TABLE outbox (
        execution TEXT PRIMARY KEY REFERENCES executions(id), workflow_id TEXT, run_id TEXT);
    CREATE TABLE execution_acceptance (
        execution TEXT PRIMARY KEY REFERENCES executions(id), provenance TEXT NOT NULL);
    CREATE TABLE effects (
        id TEXT PRIMARY KEY, execution TEXT NOT NULL REFERENCES executions(id), kind TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','running','ambiguous','complete')),
        epoch INTEGER NOT NULL CHECK(epoch>=0), owner TEXT NOT NULL, lease_until INTEGER NOT NULL,
        observation TEXT, recovery INTEGER NOT NULL CHECK(recovery IN (0,1)), UNIQUE(execution,kind));
    CREATE TABLE events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT, execution TEXT NOT NULL REFERENCES executions(id),
        kind TEXT NOT NULL, body TEXT NOT NULL);";

fn name(value: &str) -> Name {
    value.to_owned().try_into().unwrap()
}

fn plan(request: &str) -> BuildPlan {
    BuildPlan {
        version: 1,
        company: name("example"),
        app: name("links"),
        request: name(request),
        commit: GitOid::try_from("1234567890abcdef1234567890abcdef12345678".to_owned()).unwrap(),
        profile: BuildProfile {
            source: BindingRef::pin(name("github"), &"repository-42").unwrap(),
            builder: BindingRef::pin(name("hosted"), &"runner-v1").unwrap(),
            durability: BindingRef::pin(name("temporal"), &"namespace-one").unwrap(),
            platform: Digest::new(b"platform"),
            recipe: Digest::new(b"recipe"),
        },
    }
}

fn seed_v2(path: &Path, request: &str, status: &str) -> Result<(Connection, BuildPlan)> {
    let connection = Connection::open(path)?;
    connection.execute_batch(V2)?;
    let plan = seed_execution(&connection, request, status)?;
    Ok((connection, plan))
}

fn seed_execution(connection: &Connection, request: &str, status: &str) -> Result<BuildPlan> {
    let plan = plan(request);
    let id = plan.execution_id()?;
    let source = Digest::new(b"historical-source");
    let completed = status == "complete";
    let state = if completed {
        State::SourceReady {
            source: source.clone(),
        }
    } else {
        State::Accepted
    };
    connection.execute(
        "INSERT INTO executions VALUES(?1,?2,?3,?4,?5,0)",
        params![
            id.as_str(),
            plan.fingerprint()?.as_str(),
            serde_json::to_string(&plan)?,
            serde_json::to_string(&state)?,
            i64::from(completed)
        ],
    )?;
    connection.execute("INSERT INTO outbox(execution) VALUES(?1)", [id.as_str()])?;
    connection.execute(
        "INSERT INTO execution_acceptance VALUES(?1,?2)",
        params![
            id.as_str(),
            serde_json::to_string(&AcceptanceProvenance::PlatformHost)?
        ],
    )?;
    let receipt = serde_json::json!({
        "fingerprint": plan.fingerprint()?,
        "provenance": AcceptanceProvenance::PlatformHost,
    });
    connection.execute(
        "INSERT INTO events(execution,kind,body) VALUES(?1,'accepted',?2)",
        params![id.as_str(), serde_json::to_string(&receipt)?],
    )?;
    let observation = completed
        .then(|| serde_json::to_string(&Observation::Source { source }))
        .transpose()?;
    connection.execute(
        "INSERT INTO effects VALUES(?1,?2,?3,?4,7,'old-worker',?5,?6,?7)",
        params![
            effect_id(&plan, EffectKind::FetchSource)?.as_str(),
            id.as_str(),
            serde_json::to_string(&EffectKind::FetchSource)?,
            status,
            if matches!(status, "pending" | "ambiguous") {
                0
            } else {
                100
            },
            observation,
            i64::from(status == "ambiguous")
        ],
    )?;
    Ok(plan)
}

fn version(connection: &Connection) -> Result<i64> {
    Ok(connection.query_row(
        "SELECT version FROM control_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?)
}

fn schema(connection: &Connection, table: &str) -> Result<String> {
    Ok(connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE name=?1",
        [table],
        |row| row.get(0),
    )?)
}

#[derive(Debug, PartialEq, Eq)]
struct StoredEffect {
    id: String,
    status: String,
    epoch: i64,
    owner: String,
    lease_until: i64,
    observation: Option<String>,
    recovery: i64,
}

fn effects(connection: &Connection) -> Result<Vec<StoredEffect>> {
    Ok(connection.prepare(
        "SELECT id,status,epoch,owner,lease_until,observation,recovery FROM effects ORDER BY id"
    )?.query_map([], |row| Ok(StoredEffect {
        id: row.get(0)?, status: row.get(1)?, epoch: row.get(2)?, owner: row.get(3)?,
        lease_until: row.get(4)?, observation: row.get(5)?, recovery: row.get(6)?,
    }))?.collect::<rusqlite::Result<_>>()?)
}

fn claim(journal: &mut Journal, plan: &BuildPlan, now: u64) -> Result<Lease> {
    match journal.claim(&plan.execution_id()?, name("new-worker"), now, 100)? {
        Claim::Acquired(lease) => Ok(*lease),
        other => anyhow::bail!("expected acquired lease, got {other:?}"),
    }
}

#[test]
fn fresh_database_rejects_inapplicable_effect_fields_on_direct_inserts_and_updates() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let mut journal = Journal::open(&path)?;
    let plan = plan("effect-shapes");
    let id = journal.accept(&plan)?.id;
    let connection = Connection::open(&path)?;
    connection.execute_batch("PRAGMA foreign_keys=ON")?;
    for (status, observation) in [
        ("complete", None),
        ("pending", Some("{}")),
        ("running", Some("{}")),
        ("ambiguous", Some("{}")),
    ] {
        assert!(
            connection
                .execute(
                    "INSERT INTO effects VALUES('malformed',?1,'kind',?2,1,'worker',100,?3,0)",
                    params![id.as_str(), status, observation],
                )
                .is_err(),
            "invalid {status} insert was accepted"
        );
    }
    assert!(
        connection
            .execute(
                "INSERT INTO effects VALUES(NULL,?1,'kind','running',1,'worker',100,NULL,0)",
                [id.as_str()],
            )
            .is_err()
    );
    let lease = claim(&mut journal, &plan, 0)?;
    assert!(connection.execute(
        "INSERT INTO effects VALUES('orphan','absent','kind','running',1,'worker',100,NULL,0)", [],
    ).is_err());
    assert!(
        connection
            .execute(
                "INSERT INTO effects VALUES('duplicate',?1,?2,'running',1,'worker',100,NULL,0)",
                params![
                    id.as_str(),
                    serde_json::to_string(&EffectKind::FetchSource)?
                ],
            )
            .is_err()
    );
    let event_count = journal.event_count(&id)?;
    for (status, observation) in [
        ("complete", None),
        ("pending", Some("{}")),
        ("running", Some("{}")),
        ("ambiguous", Some("{}")),
    ] {
        assert!(
            connection
                .execute(
                    "UPDATE effects SET status=?1,observation=?2 WHERE id=?3",
                    params![status, observation, lease.effect.as_str()],
                )
                .is_err(),
            "invalid {status} update was accepted"
        );
    }
    assert_eq!(journal.event_count(&id)?, event_count);
    let source = Observation::Source {
        source: Digest::new(b"source"),
    };
    journal.complete(&lease, &source, 1)?;
    assert!(
        connection
            .execute(
                "UPDATE effects SET observation=NULL WHERE id=?1",
                [lease.effect.as_str()]
            )
            .is_err()
    );
    drop(journal);
    assert!(matches!(
        Journal::open(&path)?.get(&id)?.state,
        State::SourceReady { .. }
    ));
    Ok(())
}

#[test]
fn receipts_are_paired_and_byte_bounded_even_without_connection_foreign_key_settings() -> Result<()>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let mut journal = Journal::open(&path)?;
    let id = journal.accept(&plan("receipt-shapes"))?.id;
    let connection = Connection::open(&path)?;
    let large_workflow = "x".repeat(257);
    let large_run = "x".repeat(129);
    let multibyte_workflow = "é".repeat(129);
    for (workflow, run) in [
        (Some("workflow"), None),
        (None, Some("run")),
        (Some(""), Some("run")),
        (Some("workflow"), Some("")),
        (Some(large_workflow.as_str()), Some("run")),
        (Some("workflow"), Some(large_run.as_str())),
        (Some(multibyte_workflow.as_str()), Some("run")),
    ] {
        assert!(
            connection
                .execute(
                    "UPDATE outbox SET workflow_id=?1,run_id=?2 WHERE execution=?3",
                    params![workflow, run, id.as_str()],
                )
                .is_err()
        );
    }
    assert!(
        connection
            .execute("INSERT INTO outbox VALUES(NULL,NULL,NULL)", [])
            .is_err()
    );
    assert_eq!(journal.pending_dispatches(8)?, vec![id.clone()]);
    journal.dispatched(&id, &"x".repeat(256), &"y".repeat(128))?;
    assert!(journal.pending_dispatches(8)?.is_empty());
    drop(journal);
    drop(Journal::open(&path)?);
    Ok(())
}

#[test]
fn workflow_affinity_survives_reopen_while_changed_temporal_runs_remain_legal() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let mut journal = Journal::open(&path)?;
    let id = journal.accept(&plan("receipt-replay"))?.id;
    journal.dispatched(&id, "workflow-1", "run-1")?;
    let events = journal.event_count(&id)?;
    drop(journal);
    let mut journal = Journal::open(&path)?;
    journal.dispatched(&id, "workflow-1", "run-1")?;
    journal.dispatched(&id, "workflow-1", "continue-as-new-run")?;
    for (workflow, run) in [
        ("".to_owned(), "run".to_owned()),
        ("workflow-1".to_owned(), String::new()),
        ("x".repeat(257), "run".to_owned()),
        ("workflow-1".to_owned(), "x".repeat(129)),
        ("workflow-1".to_owned(), "é".repeat(65)),
    ] {
        assert!(journal.dispatched(&id, &workflow, &run).is_err());
    }
    assert!(
        journal
            .dispatched(&id, "another-workflow", "run-1")
            .is_err()
    );
    assert!(
        journal
            .dispatched(&Digest::new(b"another-execution"), "workflow-1", "run-1")
            .is_err()
    );
    assert_eq!(journal.event_count(&id)?, events);
    let receipt: (String, String) = Connection::open(&path)?.query_row(
        "SELECT workflow_id,run_id FROM outbox WHERE execution=?1",
        [id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(receipt, ("workflow-1".into(), "run-1".into()));
    Ok(())
}

#[test]
fn supported_v2_upgrade_preserves_recovery_completion_receipts_and_audit_sequences() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let (connection, pending) = seed_v2(&path, "pending", "pending")?;
    let running = seed_execution(&connection, "running", "running")?;
    let ambiguous = seed_execution(&connection, "ambiguous", "ambiguous")?;
    let completed = seed_execution(&connection, "completed", "complete")?;
    connection.execute(
        "UPDATE outbox SET workflow_id='workflow',run_id='initial-run' WHERE execution=?1",
        [completed.execution_id()?.as_str()],
    )?;
    let before_events = connection.query_row("SELECT COUNT(*) FROM events", [], |row| {
        row.get::<_, i64>(0)
    })?;
    let before_effects = effects(&connection)?;
    // Read-only consumers can inspect a valid v2 snapshot without changing it.
    drop(Journal::open_readonly(&path)?);
    assert_eq!(version(&connection)?, 2);
    let mut journal = Journal::open(&path)?;
    assert_eq!(version(&connection)?, 3);
    assert_eq!(before_effects, effects(&connection)?);
    assert_eq!(
        before_events,
        connection.query_row("SELECT COUNT(*) FROM events", [], |row| row
            .get::<_, i64>(0))?
    );
    assert_eq!(journal.accept(&pending)?.revision, 0);
    assert_eq!(
        claim(&mut journal, &pending, 100)?.recovery,
        RecoveryMode::Execute
    );
    assert_eq!(
        claim(&mut journal, &ambiguous, 100)?.recovery,
        RecoveryMode::Reconcile
    );
    let old = Lease {
        execution: journal.get(&running.execution_id()?)?,
        effect: effect_id(&running, EffectKind::FetchSource)?,
        kind: EffectKind::FetchSource,
        epoch: 7,
        owner: name("old-worker"),
        until: 100,
        recovery: RecoveryMode::Execute,
    };
    let recovered = claim(&mut journal, &running, 100)?;
    assert_eq!(recovered.epoch, 8);
    assert_eq!(recovered.recovery, RecoveryMode::Reconcile);
    let observation = Observation::Source {
        source: Digest::new(b"recovered-source"),
    };
    assert!(journal.complete(&old, &observation, 101).is_err());
    journal.complete(&recovered, &observation, 101)?;
    journal.complete(&recovered, &observation, 102)?;
    assert!(matches!(
        journal.get(&completed.execution_id()?)?.state,
        State::SourceReady { .. }
    ));
    journal.dispatched(&completed.execution_id()?, "workflow", "later-run")?;
    let last_sequence: i64 =
        connection.query_row("SELECT MAX(sequence) FROM events", [], |row| row.get(0))?;
    assert!(last_sequence > before_events);
    drop(journal);
    assert_eq!(
        Journal::open(&path)?
            .get(&running.execution_id()?)?
            .revision,
        1
    );
    drop(Journal::open_readonly(&path)?);
    Ok(())
}

#[test]
fn malformed_legacy_rows_refuse_upgrade_without_repair_or_partial_schema_changes() -> Result<()> {
    for corruption in [
        "UPDATE effects SET status='complete',observation=NULL",
        "UPDATE effects SET status='pending',observation='{}'",
        "UPDATE effects SET status='running',observation='{}'",
        "UPDATE effects SET status='ambiguous',observation='{}'",
        "UPDATE effects SET id=NULL",
        "UPDATE outbox SET workflow_id='workflow',run_id=NULL",
        "UPDATE outbox SET workflow_id=NULL,run_id='run'",
        "UPDATE outbox SET workflow_id='',run_id='run'",
        "UPDATE outbox SET workflow_id='workflow',run_id=''",
        "UPDATE outbox SET workflow_id=hex(zeroblob(129)),run_id='run'",
        "UPDATE outbox SET workflow_id='workflow',run_id=hex(zeroblob(65))",
        "UPDATE outbox SET execution=NULL",
        "UPDATE effects SET execution='orphan'",
        "UPDATE execution_acceptance SET execution='orphan'",
        "UPDATE events SET execution='orphan'",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("journal.sqlite");
        let (connection, _) = seed_v2(&path, "malformed", "running")?;
        connection.execute_batch("PRAGMA foreign_keys=OFF")?;
        connection.execute_batch(corruption)?;
        let old_effects = schema(&connection, "effects")?;
        let old_outbox = schema(&connection, "outbox")?;
        assert!(
            Journal::open_readonly(&path).is_err(),
            "readonly accepted {corruption}"
        );
        assert!(
            Journal::open(&path).is_err(),
            "upgrade accepted {corruption}"
        );
        assert_eq!(version(&connection)?, 2);
        assert_eq!(schema(&connection, "effects")?, old_effects);
        assert_eq!(schema(&connection, "outbox")?, old_outbox);
        assert!(!connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name LIKE 'control_%_v3')",
            [],
            |row| row.get::<_, bool>(0)
        )?);
    }
    Ok(())
}

#[test]
fn a_version_stamp_cannot_admit_unconstrained_or_customized_table_layouts() -> Result<()> {
    for legacy in [true, false] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("journal.sqlite");
        let connection = if legacy {
            seed_v2(&path, "forged-layout", "running")?.0
        } else {
            drop(Journal::open(&path)?);
            Connection::open(&path)?
        };
        connection.execute_batch(
            "DROP TABLE outbox; CREATE TABLE outbox (
            execution TEXT PRIMARY KEY REFERENCES executions(id), workflow_id TEXT, run_id TEXT)",
        )?;
        if legacy {
            // The old outbox genuinely was unconstrained. Forge another known
            // table by retaining its columns but dropping its status constraint.
            connection.execute_batch("DROP TABLE effects; CREATE TABLE effects (
                id TEXT PRIMARY KEY, execution TEXT NOT NULL REFERENCES executions(id), kind TEXT NOT NULL,
                status TEXT NOT NULL, epoch INTEGER NOT NULL CHECK(epoch>=0), owner TEXT NOT NULL,
                lease_until INTEGER NOT NULL, observation TEXT, recovery INTEGER NOT NULL CHECK(recovery IN (0,1)), UNIQUE(execution,kind))")?;
        }
        assert!(Journal::open(&path).is_err());
        assert!(Journal::open_readonly(&path).is_err());
        assert_eq!(version(&connection)?, if legacy { 2 } else { 3 });
    }
    for customization in [
        "DROP TABLE execution_acceptance",
        "CREATE INDEX custom_effects ON effects(status)",
        "CREATE TRIGGER custom_effects BEFORE UPDATE ON effects BEGIN SELECT RAISE(ABORT,'custom'); END",
        "CREATE TABLE incoming_relationship(effect TEXT REFERENCES effects(id))",
        "CREATE TABLE incoming_relationship(effect TEXT REFERENCES EfFeCtS(id))",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("journal.sqlite");
        let (connection, _) = seed_v2(&path, "customized", "running")?;
        connection.execute_batch(customization)?;
        assert!(Journal::open(&path).is_err(), "accepted {customization}");
        assert_eq!(version(&connection)?, 2);
    }
    Ok(())
}

#[test]
fn correctly_versioned_layouts_reject_imported_rows_that_bypassed_constraints() -> Result<()> {
    for corruption in [
        "UPDATE effects SET status='complete',observation=NULL",
        "UPDATE effects SET status='running',observation='{}'",
        "UPDATE effects SET status='unknown'",
        "UPDATE effects SET epoch=-1",
        "UPDATE effects SET recovery=2",
        "UPDATE effects SET execution='orphan'",
        "UPDATE outbox SET workflow_id='workflow',run_id=NULL",
        "UPDATE outbox SET workflow_id='workflow',run_id=''",
        "UPDATE outbox SET execution='orphan'",
        "UPDATE execution_acceptance SET execution='orphan'",
        "UPDATE events SET execution='orphan'",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("journal.sqlite");
        let mut journal = Journal::open(&path)?;
        let plan = plan("import-refusal");
        journal.accept(&plan)?;
        claim(&mut journal, &plan, 0)?;
        drop(journal);
        let connection = Connection::open(&path)?;
        connection.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON")?;
        connection.execute_batch(corruption)?;
        assert!(
            Journal::open(&path).is_err(),
            "writer admitted {corruption}"
        );
        assert!(
            Journal::open_readonly(&path).is_err(),
            "reader admitted {corruption}"
        );
        assert_eq!(version(&connection)?, 3);
    }
    Ok(())
}

#[test]
fn replacement_failure_rolls_back_the_first_table_and_retains_original_data() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let (connection, plan) = seed_v2(&path, "rollback-upgrade", "ambiguous")?;
    connection.execute(
        "UPDATE outbox SET workflow_id='workflow',run_id='initial-run'",
        [],
    )?;
    // This collision interrupts the second replacement after the first table
    // has been rebuilt. The enclosing transaction must retain the entire v2 DB.
    connection.execute_batch("CREATE TABLE control_effects_v3(marker TEXT); INSERT INTO control_effects_v3 VALUES('retained')")?;
    let old_outbox = schema(&connection, "outbox")?;
    let old_effects = schema(&connection, "effects")?;
    let original_effects = effects(&connection)?;
    assert!(Journal::open(&path).is_err());
    assert_eq!(version(&connection)?, 2);
    assert_eq!(schema(&connection, "outbox")?, old_outbox);
    assert_eq!(schema(&connection, "effects")?, old_effects);
    assert_eq!(effects(&connection)?, original_effects);
    assert_eq!(
        connection.query_row("SELECT marker FROM control_effects_v3", [], |row| row
            .get::<_, String>(0))?,
        "retained"
    );
    connection.execute_batch("DROP TABLE control_effects_v3")?;
    drop(connection);
    let mut journal = Journal::open(&path)?;
    assert_eq!(
        claim(&mut journal, &plan, 100)?.recovery,
        RecoveryMode::Reconcile
    );
    journal.dispatched(&plan.execution_id()?, "workflow", "later-run")?;
    Ok(())
}

#[test]
fn literal_changes_and_split_type_names_are_not_accepted_as_formatting() -> Result<()> {
    for changed in [
        V2.replace("'pending'", "'pending '"),
        V2.replace("owner TEXT NOT NULL", "owner T E X T NOT NULL"),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("journal.sqlite");
        let connection = Connection::open(&path)?;
        connection.execute_batch(&changed)?;
        assert!(Journal::open(&path).is_err());
        assert_eq!(version(&connection)?, 2);
    }
    Ok(())
}

#[test]
fn a_missing_or_unsupported_version_cannot_create_or_restamp_existing_storage() -> Result<()> {
    for ddl in [
        "CREATE TABLE executions(id TEXT)",
        "CREATE TABLE unrelated(value TEXT)",
        "CREATE TABLE sqliteXshadow(value TEXT)",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("journal.sqlite");
        let connection = Connection::open(&path)?;
        connection.execute_batch(ddl)?;
        assert!(Journal::open(&path).is_err(), "admitted {ddl}");
        assert!(!connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='control_meta')",
            [],
            |row| row.get::<_, bool>(0),
        )?);
    }
    for corruption in [
        "UPDATE control_meta SET version=99",
        "DELETE FROM control_meta",
        "DROP TABLE control_meta; CREATE TABLE control_meta(singleton INTEGER PRIMARY KEY, version INTEGER NOT NULL); INSERT INTO control_meta VALUES(1,2)",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("journal.sqlite");
        let (connection, _) = seed_v2(&path, "version-refusal", "running")?;
        connection.execute_batch(corruption)?;
        let before: Option<i64> =
            connection.query_row("SELECT MAX(version) FROM control_meta", [], |row| {
                row.get(0)
            })?;
        assert!(Journal::open(&path).is_err());
        assert!(Journal::open_readonly(&path).is_err());
        assert_eq!(
            before,
            connection.query_row("SELECT MAX(version) FROM control_meta", [], |row| row
                .get::<_, Option<i64>>(0))?
        );
    }
    Ok(())
}

#[test]
fn concurrent_openers_upgrade_once_without_losing_rows_or_receipts() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let (connection, plan) = seed_v2(&path, "concurrent-upgrade", "ambiguous")?;
    let id = plan.execution_id()?;
    connection.execute(
        "UPDATE outbox SET workflow_id='workflow',run_id='initial-run'",
        [],
    )?;
    drop(connection);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers = (0..2)
        .map(|_| {
            let path = path.clone();
            let id = id.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || -> Result<()> {
                barrier.wait();
                let mut journal = Journal::open(&path)?;
                journal.dispatched(&id, "workflow", "later-run")?;
                assert_eq!(journal.event_count(&id)?, 1);
                Ok(())
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().unwrap()?;
    }
    assert_eq!(version(&Connection::open(&path)?)?, 3);
    let mut journal = Journal::open(&path)?;
    assert_eq!(
        claim(&mut journal, &plan, 100)?.recovery,
        RecoveryMode::Reconcile
    );
    Ok(())
}

#[test]
fn finite_history_exhausts_the_shared_admission_budget_without_restamping_or_losing_rows()
-> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let (connection, plan) = seed_v2(&path, "budget-refusal", "pending")?;
    let effect = effect_id(&plan, EffectKind::FetchSource)?;
    // A fixed, finite history of definitive non-application retries. Each claim
    // has its own epoch and matching deferral; the current effect remains pending.
    connection.execute(
        "WITH RECURSIVE history(epoch) AS (VALUES(8) UNION ALL SELECT epoch+1 FROM history WHERE epoch<100007)
         INSERT INTO events(execution,kind,body)
         SELECT ?1,kind,body FROM (
             SELECT epoch,'claimed' AS kind,json_array(?2,epoch,json('false')) AS body FROM history
             UNION ALL SELECT epoch,'deferred',json_array(?2,'pending') FROM history)
         ORDER BY epoch,kind",
        params![plan.execution_id()?.as_str(), effect.as_str()],
    )?;
    connection.execute("UPDATE effects SET epoch=100007", [])?;
    let before_events: i64 =
        connection.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
    assert_eq!(before_events, 200_001);
    let before_outbox = schema(&connection, "outbox")?;
    let before_effects = schema(&connection, "effects")?;
    for readonly in [false, true] {
        let error = if readonly {
            Journal::open_readonly(&path)
        } else {
            Journal::open(&path)
        }
        .err()
        .expect("the fixed admission work budget must refuse this history");
        assert!(
            matches!(error.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(code, _)) if code.code == rusqlite::ErrorCode::OperationInterrupted),
            "expected a work-budget interruption, got {error:#}"
        );
        assert_eq!(version(&connection)?, 2);
        assert_eq!(schema(&connection, "outbox")?, before_outbox);
        assert_eq!(schema(&connection, "effects")?, before_effects);
        assert_eq!(
            connection.query_row("SELECT COUNT(*) FROM events", [], |row| row
                .get::<_, i64>(0))?,
            before_events
        );
    }
    // An explicit retention action makes a later bounded migration possible;
    // admission itself never trims history to get under its budget.
    connection.execute(
        "DELETE FROM events WHERE kind IN ('claimed','deferred')",
        [],
    )?;
    let mut journal = Journal::open(&path)?;
    assert_eq!(version(&connection)?, 3);
    assert_eq!(claim(&mut journal, &plan, 0)?.epoch, 100_008);
    Ok(())
}

#[test]
fn the_admission_budget_does_not_leak_into_ordinary_journal_operations() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::open(&directory.path().join("journal.sqlite"))?;
    let id = journal.accept(&plan("budget-cleanup"))?.id;
    // Together these fixed, bounded queries exceed the admission budget. They
    // must still work on the admitted connection after its hook is removed.
    for _ in 0..100_000 {
        assert_eq!(journal.event_count(&id)?, 1);
    }
    Ok(())
}
