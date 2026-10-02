use anyhow::{Context, Result};
use day2::identity::{self, Id};
use day2::{
    artifact::{AppBinding, Instance},
    protocol::Outcome,
    store::{Fault, Runtime, replay},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

#[path = "support/evidence.rs"]
mod evidence;

fn artifact() -> PathBuf {
    std::env::var_os("DAY2_TEST_RELATIONAL_ARTIFACT")
        .map(PathBuf::from)
        .expect("build the relational conformance fixture and set DAY2_TEST_RELATIONAL_ARTIFACT")
}

struct World {
    _directory: TempDir,
    property_checks: std::sync::atomic::AtomicUsize,
    runtime: Runtime,
    deal: Id,
    source: Id,
    target: Id,
}
impl World {
    fn new() -> Result<Self> {
        Self::configured(false)
    }

    fn configured(deterministic: bool) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let instance = Instance {
            installation: "testco".into(),
            environment: "test".into(),
            branding: None,
            control: None,
            resources: None,
            apps: BTreeMap::from([(
                "relational".into(),
                AppBinding {
                    retention: Default::default(),
                    journal: None,
                    security: None,
                    resource_policies: Vec::new(),
                    credential_families: Default::default(),
                    oauth_connections: Default::default(),
                    schedules: Default::default(),
                    ingress: Default::default(),
                    runtime: None,
                    authority: Some(serde_json::from_str(include_str!(
                        "../../../fixtures/authority-policies/relational-conformance.json"
                    ))?),
                    artifact: artifact().to_string_lossy().to_string(),
                    readers: BTreeSet::from(["viewer".into()]),
                    writers: BTreeSet::from(["alice".into()]),
                    edge: None,
                },
            )]),
            identity: None,
            security_shell: None,
            oauth_shell_transport: None,
            oauth_clients: None,
        };
        let path = directory.path().join("instance.json");
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let runtime = Runtime::load(&path, "relational")?;
        let runtime = if deterministic {
            day2::simulation::Simulation::new(runtime, [0xda; 32], 200_000)?
                .runtime()
                .clone()
        } else {
            runtime
        };
        runtime.initialize()?;
        let seed = runtime.invoke(
            "deals.seed",
            "alice",
            "seed",
            &json!({"title":"Deterministic relationship"}),
            100,
            Fault::None,
        )?;
        assert_eq!(seed.status, "success", "{seed:?}");
        let deal = Id::from_text(seed.result["deal_id"].as_str().context("seed deal")?)?;
        let source = Id::from_text(
            seed.result["source_stage_id"]
                .as_str()
                .context("seed source")?,
        )?;
        let target = Id::from_text(
            seed.result["target_stage_id"]
                .as_str()
                .context("seed target")?,
        )?;
        Ok(Self {
            _directory: directory,
            property_checks: std::sync::atomic::AtomicUsize::new(0),
            runtime,
            deal,
            source,
            target,
        })
    }
    fn input(&self, stage: Id, version: i64) -> Value {
        json!({"deal_id":self.deal.to_string(),"target_stage_id":stage.to_string(),"expected_version":version})
    }
    fn move_deal(&self, id: &str, stage: Id, version: i64, fault: Fault) -> Result<Outcome> {
        self.runtime.invoke(
            "deals.move",
            "alice",
            id,
            &self.input(stage, version),
            200,
            fault,
        )
    }
    fn assert_state(&self, stage: Id, version: i64, history: usize) -> Result<()> {
        let state = self.runtime.inspect()?;
        let evidence = day2::properties::require(
            self.runtime.artifact(),
            &state,
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/property-failures"),
        )?;
        self.property_checks
            .fetch_add(evidence.checks.len(), std::sync::atomic::Ordering::Relaxed);
        let deals = state["deals"].as_array().unwrap();
        assert_eq!(deals.len(), 1);
        assert_eq!(deals[0]["version"], version);
        let deal: Value = serde_json::from_str(deals[0]["data"].as_str().unwrap())?;
        assert_eq!(deal["stage_id"], json!(stage));
        assert_eq!(state["history"].as_array().unwrap().len(), history);
        for row in state["stages"].as_array().unwrap() {
            let data: Value = serde_json::from_str(row["data"].as_str().unwrap())?;
            assert_eq!(data["deal_count"], i64::from(row["id"] == json!(stage)));
        }
        let connection = rusqlite::Connection::open(self.runtime.db())?;
        assert_eq!(
            connection.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))?,
            "ok"
        );
        let violations = connection
            .prepare("PRAGMA foreign_key_check")?
            .query_map([], |_| Ok(()))?
            .count();
        assert_eq!(violations, 0);
        Ok(())
    }
}

#[test]
fn relational_move_is_atomic_idempotent_and_replayable() -> Result<()> {
    let world = World::new()?;
    world.assert_state(world.source, 1, 0)?;
    let result = world.move_deal("move", world.target, 1, Fault::None)?;
    assert_eq!(result.status, "success", "{result:?}");
    world.assert_state(world.target, 2, 1)?;
    assert_eq!(
        world.move_deal("move", world.target, 1, Fault::None)?,
        result
    );
    assert!(
        world
            .move_deal("move", world.source, 2, Fault::None)
            .unwrap_err()
            .to_string()
            .contains("idempotency_key_conflict")
    );
    replay(world.runtime.artifact(), &world.runtime.trace("seed")?)?;
    replay(world.runtime.artifact(), &world.runtime.trace("move")?)?;
    let page = world.runtime.invoke(
        "deals.list",
        "viewer",
        "query",
        &json!({"stage_id":world.target.to_string(),"after":"","limit":10}),
        300,
        Fault::None,
    )?;
    assert_eq!(page.status, "success", "{page:?}");
    assert_eq!(page.result["items"].as_array().unwrap().len(), 1);
    world.assert_state(world.target, 2, 1)?;
    Ok(())
}

#[test]
fn rejection_after_every_write_rolls_back_and_replays() -> Result<()> {
    for step in 1..=4 {
        let world = World::new()?;
        let result = world.move_deal("failed", world.target, 1, Fault::FailAfterWrite(step))?;
        assert_eq!(result.error, "injected_failure", "{result:?}");
        world.assert_state(world.source, 1, 0)?;
        replay(world.runtime.artifact(), &world.runtime.trace("failed")?)?;
        assert_eq!(
            world.move_deal("failed", world.target, 1, Fault::None)?,
            result
        );
    }
    Ok(())
}

#[test]
fn real_process_exit_at_every_write_recovers_pending_invocation() -> Result<()> {
    for step in 1..=4 {
        let world = World::new()?;
        world.runtime.accept(
            "deals.move",
            "alice",
            "crash",
            &world.input(world.target, 1),
            200,
        )?;
        let status = Command::new(env!("CARGO_BIN_EXE_day2"))
            .arg("lab-crash")
            .arg(world.runtime.instance_path())
            .args(["relational", "crash", &step.to_string()])
            .status()?;
        assert_eq!(status.code(), Some(86));
        world.assert_state(world.source, 1, 0)?;
        let recovered = Runtime::load(world.runtime.instance_path(), "relational")?;
        assert_eq!(recovered.execute("crash", Fault::None)?.status, "success");
        world.assert_state(world.target, 2, 1)?;
        replay(world.runtime.artifact(), &world.runtime.trace("crash")?)?;
    }
    Ok(())
}

#[test]
fn commit_ambiguity_and_version_race_do_not_duplicate_writes() -> Result<()> {
    let world = World::new()?;
    assert!(
        world
            .move_deal("precommit", world.target, 1, Fault::BeforeCommit)
            .is_err()
    );
    world.assert_state(world.source, 1, 0)?;
    assert!(
        world
            .runtime
            .execute("precommit", Fault::AfterCommit)
            .is_err()
    );
    world.assert_state(world.target, 2, 1)?;
    assert_eq!(
        world.runtime.execute("precommit", Fault::None)?.status,
        "success"
    );
    let stale = world.move_deal("stale", world.source, 1, Fault::None)?;
    assert_eq!(stale.error, "app:deals.stale_revision");
    world.assert_state(world.target, 2, 1)?;
    replay(world.runtime.artifact(), &world.runtime.trace("stale")?)?;
    Ok(())
}

#[test]
fn closed_contract_and_authorization_are_rechecked() -> Result<()> {
    let world = World::new()?;
    assert!(
        world
            .runtime
            .invoke(
                "deals.move",
                "viewer",
                "denied",
                &world.input(world.target, 1),
                200,
                Fault::None
            )
            .is_err()
    );
    let mut input = world.input(world.target, 1);
    input["scope"] = json!("another/company/relational");
    assert!(
        world
            .runtime
            .invoke("deals.move", "alice", "forged", &input, 200, Fault::None)
            .is_err()
    );
    world.runtime.accept(
        "deals.move",
        "alice",
        "revoked",
        &world.input(world.target, 1),
        200,
    )?;
    let mut instance = Instance::load(world.runtime.instance_path())?;
    instance.apps.get_mut("relational").unwrap().writers.clear();
    fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    // Desired edits do not revoke authority until explicitly activated.
    world.runtime.accept(
        "deals.move",
        "alice",
        "revoked",
        &world.input(world.target, 1),
        200,
    )?;
    let active = day2::authority_state::current(&rusqlite::Connection::open(world.runtime.db())?)?;
    day2::authority_state::apply_desired(
        &world.runtime,
        &day2::authority_state::LocalOperator::assert_local("test-operator")?,
        "revoke-writers",
        Some(active.stamp),
    )?;
    let blocked = world.runtime.execute("revoked", Fault::None)?;
    assert_eq!(blocked.status, "blocked");
    assert_eq!(blocked.error, "authority_policy_changed");
    world.assert_state(world.source, 1, 0)?;
    Ok(())
}

fn run_schedule(schedule: &[(u8, usize)]) -> Result<usize> {
    let mut evidence = evidence::Evidence::start(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/relational-simulation"),
        json!({"seed":0xDA72_2026u64,"entropy_seed_byte":0xda,"now_ms":200_000,
            "schedule":schedule,"artifact":artifact()}),
    )?;
    evidence.run(|evidence| {
        let world = World::configured(true)?;
        evidence.event(json!({"state":world.runtime.inspect()?}))?;
        world.assert_state(world.source, 1, 0)?;
        let mut at_target = false;
        let mut version = 1;
        let mut history = 0;
        for (index, &(action, write)) in schedule.iter().enumerate() {
            let target = if at_target {
                world.source
            } else {
                world.target
            };
            let id = format!("schedule-{index}");
            let mut expected = version;
            let fault = match action {
                0 => Fault::FailAfterWrite(write),
                1 => Fault::InterruptAfterWrite(write),
                2 => Fault::BeforeCommit,
                3 => Fault::AfterCommit,
                4 => {
                    expected = version + 1;
                    Fault::None
                }
                _ => Fault::None,
            };
            evidence.event(json!({
                "attempt":id, "input":world.input(target, expected), "fault":format!("{fault:?}")
            }))?;
            let attempted = world.move_deal(&id, target, expected, fault);
            evidence.event(json!({
                "state":world.runtime.inspect()?, "trace":world.runtime.trace(&id).ok(),
                "outcome":attempted.as_ref().ok(),
                "error":attempted.as_ref().err().map(|error|format!("{error:#}"))
            }))?;
            let result = if matches!(action, 1..=3) {
                assert!(
                    attempted.as_ref().is_err_and(|error| fault.caused(error)),
                    "{attempted:?}"
                );
                if action != 3 {
                    world.assert_state(
                        if at_target {
                            world.target
                        } else {
                            world.source
                        },
                        version,
                        history,
                    )?;
                }
                world.runtime.execute(&id, Fault::None)?
            } else {
                attempted?
            };
            // This oracle advances from the requested action, never from
            // application assertions or the contents of the observed database.
            if action != 0 && action != 4 {
                assert_eq!(result.status, "success");
                at_target = !at_target;
                version += 1;
                history += 1;
            } else {
                assert_eq!(result.status, "failure");
                assert_eq!(
                    result.error,
                    if action == 0 {
                        "injected_failure"
                    } else {
                        "app:deals.stale_revision"
                    }
                );
            }
            evidence.event(json!({
                "settled":id, "state":world.runtime.inspect()?, "trace":world.runtime.trace(&id)?
            }))?;
            assert_eq!(world.runtime.execute(&id, Fault::None)?, result);
            world.assert_state(
                if at_target {
                    world.target
                } else {
                    world.source
                },
                version,
                history,
            )?;
            replay(world.runtime.artifact(), &world.runtime.trace(&id)?)?;
        }
        Ok(world
            .property_checks
            .load(std::sync::atomic::Ordering::Relaxed))
    })
}

#[test]
fn seeded_state_machine_matches_reference_under_faults() {
    use proptest::{
        prelude::*,
        test_runner::{Config, RngSeed, TestRunner},
    };
    let config = Config {
        cases: 24,
        rng_seed: RngSeed::Fixed(0xDA72_2026),
        max_shrink_iters: 4096,
        source_file: Some(file!()),
        ..Config::default()
    };
    let mut runner = TestRunner::new(config);
    let cases = std::cell::Cell::new(0usize);
    let transitions = std::cell::Cell::new(0usize);
    let property_checks = std::cell::Cell::new(0usize);
    runner
        .run(
            &proptest::collection::vec((0u8..7, 1usize..5), 4..12),
            |schedule| {
                cases.set(cases.get() + 1);
                transitions.set(transitions.get() + schedule.len());
                let checks = run_schedule(&schedule)
                    .map_err(|error| TestCaseError::fail(format!("{error:#}")))?;
                property_checks.set(property_checks.get() + checks);
                Ok(())
            },
        )
        .unwrap();
    let report = json!({
        "seed":0xDA72_2026u64, "cases":cases.get(), "transitions":transitions.get(),
        "replayed_completions":transitions.get(), "app_property_checks":property_checks.get(),
        "artifact":artifact().file_name().unwrap().to_string_lossy()
    });
    fs::write(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/simulation-report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}

#[test]
fn typed_additive_migration_preserves_rows_and_fails_closed() -> Result<()> {
    use day2::{artifact::LoadedArtifact, migration};
    let path = std::env::var_os("DAY2_TEST_RELATIONAL_NEXT_ARTIFACT")
        .context("run cargo run --locked -p xtask -- verify to build the migration fixture")?;
    let next = LoadedArtifact::load(Path::new(&path))?;
    let world = World::new()?;
    let plan = migration::plan(&world.runtime, &next)?;
    assert_eq!(plan.add_nullable_text.len(), 1);
    // Destructive candidate contracts are checked by migration's pure unit
    // tests; admitted artifacts cannot be modified to construct such a case.
    let mut forged = plan.clone();
    forged.scope = "other/test/relational".into();
    assert!(migration::apply(&world.runtime, &next, &forged).is_err());
    world.runtime.accept(
        "deals.move",
        "alice",
        "pending",
        &world.input(world.target, 1),
        200,
    )?;
    assert!(
        migration::apply(&world.runtime, &next, &plan)
            .unwrap_err()
            .to_string()
            .contains("drained")
    );
    assert_eq!(
        world.runtime.execute("pending", Fault::None)?.status,
        "success"
    );
    migration::apply(&world.runtime, &next, &plan)?;
    migration::apply(&world.runtime, &next, &plan)?;
    assert!(
        world
            .runtime
            .inspect()
            .unwrap_err()
            .to_string()
            .contains("schema_migration_required")
    );
    migration::activate(&world.runtime, &next)?;
    let migrated = Runtime::load(world.runtime.instance_path(), "relational")?;
    migrated.initialize()?;
    let before = migrated.inspect()?;
    let data: Value = serde_json::from_str(before["deals"][0]["data"].as_str().unwrap())?;
    assert_eq!(data["note"], "None");
    let storage = rusqlite::Connection::open(migrated.db())?;
    storage.execute("UPDATE deals SET note='preserved nullable value'", [])?;
    let result = migrated.invoke(
        "deals.move",
        "alice",
        "after-migration",
        &world.input(world.source, 2),
        300,
        Fault::None,
    )?;
    assert_eq!(result.status, "success", "{result:?}");
    replay(migrated.artifact(), &migrated.trace("after-migration")?)?;
    let state = migrated.inspect()?;
    let evidence = day2::properties::evaluate(migrated.artifact(), &state)?;
    assert!(
        evidence.checks.iter().all(|check| check.passed),
        "{evidence:?}"
    );
    let deal: Value = serde_json::from_str(state["deals"][0]["data"].as_str().unwrap())?;
    assert_eq!(deal["note"], json!({"Some":"preserved nullable value"}));
    let connection = rusqlite::Connection::open(migrated.db())?;
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM day2_migrations", [], |r| r
            .get::<_, i64>(0))?,
        1
    );
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM history", [], |r| r.get::<_, i64>(0))?,
        2
    );
    Ok(())
}

#[test]
fn operation_names_are_namespaced_by_app_and_installation() -> Result<()> {
    let world = World::new()?;
    let mut instance = Instance::load(world.runtime.instance_path())?;
    instance.apps.insert(
        "other_relational".into(),
        instance.apps["relational"].clone(),
    );
    fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    let other = Runtime::load(world.runtime.instance_path(), "other_relational")?;
    other.initialize()?;
    let seed = other.invoke(
        "deals.seed",
        "alice",
        "seed",
        &json!({"title":"Other app"}),
        100,
        Fault::None,
    )?;
    assert_eq!(seed.status, "success");
    assert_ne!(seed.result["deal_id"], world.deal.to_string());
    let crossing = other.invoke(
        "deals.move",
        "alice",
        "cross-app",
        &world.input(world.target, 1),
        200,
        Fault::None,
    )?;
    assert_eq!(crossing.error, "not_found");
    world.assert_state(world.source, 1, 0)?;
    instance.installation = "another_company".into();
    fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    let changed = Runtime::load(world.runtime.instance_path(), "relational")?;
    assert!(
        changed
            .initialize()
            .unwrap_err()
            .to_string()
            .contains("database_scope_mismatch")
    );
    Ok(())
}

#[test]
fn concurrent_expected_version_commands_have_exactly_one_winner() -> Result<()> {
    let world = World::new()?;
    let barrier = std::sync::Barrier::new(2);
    let outcomes = std::thread::scope(|threads| {
        let handles: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|id| {
                let world = &world;
                let barrier = &barrier;
                threads.spawn(move || {
                    barrier.wait();
                    world.move_deal(id, world.target, 1, Fault::None)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Result<Vec<_>>>()
    })?;
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| result.status == "success")
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| result.error == "app:deals.stale_revision")
            .count(),
        1
    );
    world.assert_state(world.target, 2, 1)?;
    Ok(())
}

#[test]
fn reference_transport_and_domain_constructors_fail_closed() -> Result<()> {
    let world = World::new()?;
    for (index, invalid) in [
        json!(1),
        json!(world.source),
        json!(world.deal.to_string().to_uppercase()),
        json!("0"),
        json!("-1"),
        json!("01"),
        json!("+1"),
        json!(" 1"),
        json!("1 "),
        json!("1.0"),
        json!(""),
        json!("9223372036854775808"),
        Value::Null,
    ]
    .into_iter()
    .enumerate()
    {
        let mut input = world.input(world.target, 1);
        input["deal_id"] = invalid;
        let error = world
            .runtime
            .accept(
                "deals.move",
                "alice",
                &format!("bad-ref-{index}"),
                &input,
                200,
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid field: deal_id"), "{error}");
    }
    let mut missing = world.input(world.target, 1);
    missing["deal_id"] = json!(identity::example("dea"));
    let result = world.runtime.invoke(
        "deals.move",
        "alice",
        "missing-ref",
        &missing,
        200,
        Fault::None,
    )?;
    assert_eq!(result.error, "not_found");
    for (index, title) in ["".to_string(), " \t\n".into(), "x".repeat(201)]
        .into_iter()
        .enumerate()
    {
        let id = format!("bad-title-{index}");
        let error = world
            .runtime
            .accept("deals.seed", "alice", &id, &json!({"title":title}), 200)
            .unwrap_err();
        assert_eq!(error.to_string(), "invalid_domain_value");
        assert!(
            world.runtime.trace(&id).is_err(),
            "invalid domains fail before app execution"
        );
    }
    let valid = world.runtime.invoke(
        "deals.seed",
        "alice",
        "valid-title-boundary",
        &json!({"title":"x".repeat(200)}),
        200,
        Fault::None,
    )?;
    assert_eq!(valid.error, "app:deals.already_initialized");
    assert!(
        world
            .runtime
            .invoke(
                "$properties",
                "alice",
                "private-operation",
                &json!({}),
                200,
                Fault::None
            )
            .unwrap_err()
            .to_string()
            .contains("unknown_operation")
    );
    world.assert_state(world.source, 1, 0)?;
    Ok(())
}

#[test]
fn generated_indexed_query_is_bounded_paginated_and_projects_domain_values() -> Result<()> {
    let world = World::new()?;
    let connection = rusqlite::Connection::open(world.runtime.db())?;
    // A later UUID timestamp makes the independent ordering assertion stable.
    let second_bytes = identity::generate(&[7; 32], 200_000, "deals", 0)?;
    let second_id = Id::from_uuid("dea", second_bytes)?;
    connection.execute(
        "INSERT INTO deals(id,version,created_at,title,stage_id) VALUES(?1,1,100,'Second deal',?2)",
        rusqlite::params![
            second_bytes.as_slice(),
            world.source.bytes_for("sta")?.as_slice()
        ],
    )?;
    connection.execute(
        "UPDATE stages SET deal_count=2 WHERE id=?1",
        [world.source.bytes_for("sta")?.as_slice()],
    )?;
    let query = |id: &str, after: &str, limit: i64, stage: Id| {
        world.runtime.invoke(
            "deals.list",
            "viewer",
            id,
            &json!({"stage_id":stage,"after":after,"limit":limit}),
            300,
            Fault::None,
        )
    };
    let first = query("first-page", "", 1, world.source)?;
    assert_eq!(first.status, "success", "{first:?}");
    assert_eq!(first.result["has_more"], true);
    assert_eq!(first.result["items"][0]["id"], json!(world.deal));
    assert_eq!(
        first.result["items"][0]["title"],
        "Deterministic relationship"
    );
    assert_eq!(first.result["items"][0]["stage_id"], json!(world.source));
    let second = query(
        "second-page",
        first.result["next_after"].as_str().unwrap(),
        1,
        world.source,
    )?;
    assert_eq!(second.result["items"][0]["id"], json!(second_id));
    assert_eq!(second.result["has_more"], false);
    let empty = query("other-stage", "", 10, world.target)?;
    assert_eq!(empty.result["items"], json!([]));
    for (index, (after, limit)) in [("-1", 1), ("", 0), ("", 101)].into_iter().enumerate() {
        let id = format!("invalid-page-{index}");
        assert!(query(&id, after, limit, world.source).is_err());
        assert!(
            world.runtime.trace(&id).is_err(),
            "invalid pagination must fail before app execution"
        );
    }
    let report = day2::properties::evaluate(world.runtime.artifact(), &world.runtime.inspect()?)?;
    assert!(report.checks.iter().all(|check| check.passed));
    replay(
        world.runtime.artifact(),
        &world.runtime.trace("first-page")?,
    )?;
    Ok(())
}

#[test]
fn app_properties_detect_corruption_and_persist_replayable_evidence() -> Result<()> {
    use day2::properties;
    let world = World::new()?;
    world.move_deal("move", world.target, 1, Fault::None)?;
    let state = world.runtime.inspect()?;
    let report = properties::evaluate(world.runtime.artifact(), &state)?;
    assert_eq!(report.checks.len(), 3);
    assert!(report.checks.iter().all(|check| check.passed), "{report:?}");
    assert_eq!(
        properties::replay(world.runtime.artifact(), &report)?,
        report
    );
    let mut mismatched = report.clone();
    mismatched.checks.reverse();
    assert!(
        properties::replay(world.runtime.artifact(), &mismatched)
            .unwrap_err()
            .to_string()
            .contains("property replay diverged")
    );
    let evidence_dir = tempfile::tempdir()?;
    for (model, field, value, property) in [
        ("stages", "deal_count", json!(42), "stages"),
        (
            "history",
            "deal_id",
            json!(identity::example("dea")),
            "history",
        ),
        (
            "deals",
            "stage_id",
            json!(identity::example("sta")),
            "deals",
        ),
    ] {
        let mut broken = state.clone();
        let mut data: Value = serde_json::from_str(broken[model][0]["data"].as_str().unwrap())?;
        data[field] = value;
        broken[model][0]["data"] = json!(serde_json::to_string(&data)?);
        let checks = properties::evaluate(world.runtime.artifact(), &broken)?;
        assert!(
            !checks
                .checks
                .iter()
                .find(|check| check.name == property)
                .unwrap()
                .passed
        );
        let error = properties::require(world.runtime.artifact(), &broken, evidence_dir.path())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(property) && error.contains("evidence:"),
            "{error}"
        );
    }
    let files = fs::read_dir(evidence_dir.path())?.collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(files.len(), 3);
    for file in files {
        let saved: properties::Evidence = serde_json::from_slice(&fs::read(file.path())?)?;
        assert!(saved.checks.iter().any(|check| !check.passed));
        properties::replay(world.runtime.artifact(), &saved)?;
        let output = Command::new(env!("CARGO_BIN_EXE_day2"))
            .arg("replay-properties")
            .arg(world.runtime.artifact().directory())
            .arg(file.path())
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut forged = saved.clone();
        forged.artifact = "sha256:wrong".into();
        assert!(properties::replay(world.runtime.artifact(), &forged).is_err());
        forged = saved;
        forged.checks[0].passed = !forged.checks[0].passed;
        assert!(properties::replay(world.runtime.artifact(), &forged).is_err());
    }
    let mut bad_domain = state.clone();
    let mut data: Value = serde_json::from_str(bad_domain["deals"][0]["data"].as_str().unwrap())?;
    data["title"] = json!("");
    bad_domain["deals"][0]["data"] = json!(serde_json::to_string(&data)?);
    let failed = properties::evaluate(world.runtime.artifact(), &bad_domain)?;
    assert!(
        failed
            .checks
            .iter()
            .all(|check| !check.passed && check.error == "invalid_domain_value")
    );
    let mut partial = state.clone();
    partial.as_object_mut().unwrap().remove("history");
    assert!(properties::evaluate(world.runtime.artifact(), &partial).is_err());
    let mut duplicate = state.clone();
    duplicate["deals"]
        .as_array_mut()
        .unwrap()
        .push(state["deals"][0].clone());
    assert!(properties::evaluate(world.runtime.artifact(), &duplicate).is_err());
    let mut oversized = state.clone();
    oversized["deals"] = json!(vec![
        state["deals"][0].clone();
        properties::MAX_ROWS_PER_MODEL + 1
    ]);
    assert!(
        properties::evaluate(world.runtime.artifact(), &oversized)
            .unwrap_err()
            .to_string()
            .contains("snapshot row budget")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_day2"))
        .arg("check-properties")
        .arg(world.runtime.instance_path())
        .arg("relational")
        .arg(evidence_dir.path())
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<properties::Evidence>(&output.stdout)?,
        report
    );
    world.assert_state(world.target, 2, 1)?;
    Ok(())
}

#[test]
fn inspection_refuses_to_check_a_truncated_world() -> Result<()> {
    let world = World::new()?;
    let mut connection = rusqlite::Connection::open(world.runtime.db())?;
    let tx = connection.transaction()?;
    for ordinal in 1..=day2::properties::MAX_ROWS_PER_MODEL as u64 {
        let id = identity::generate(&[9; 32], 200_000, "deals", ordinal)?;
        tx.execute(
            "INSERT INTO deals(id,version,created_at,title,stage_id) VALUES(?1,1,100,?2,?3)",
            rusqlite::params![
                id.as_slice(),
                format!("Fixture {ordinal}"),
                world.source.bytes_for("sta")?.as_slice(),
            ],
        )?;
    }
    tx.commit()?;
    assert!(
        world
            .runtime
            .inspect()
            .unwrap_err()
            .to_string()
            .contains("inspection_limit")
    );
    // Operational storage validation streams every row and remains available
    // when the deliberately bounded app-property snapshot cannot be produced.
    world.runtime.validate_storage()?;
    connection.pragma_update(None, "ignore_check_constraints", true)?;
    connection.execute("UPDATE deals SET version=0 WHERE title='Fixture 256'", [])?;
    assert!(world.runtime.validate_storage().is_err());
    Ok(())
}
