//! Seeded process-loss schedules over the real interpreter and local adapter.
//! The reference is the product contract: one row, one analysis, one delivery.
#[path = "support/evidence.rs"]
mod evidence;
#[path = "support/commands.rs"]
mod support;
use anyhow::{Context, Result, ensure};
use day2::{
    capabilities::NotificationWorld,
    invocations,
    simulation::{Simulation, WorkerFailure},
    store::{Fault, replay},
};
use rusqlite::OptionalExtension;
use serde_json::{Value, json};
use support::World;

fn pending_notification(world: &World, actor: &str, id: &str) -> Result<String> {
    world.runtime.invoke(
        "reports.submit",
        actor,
        id,
        &json!({"title":id,"text":"test"}),
        1,
        Fault::None,
    )?;
    let analyze = world.child(id)?;
    world.finish(&analyze)?;
    world.child(&analyze)
}

#[test]
fn resource_handles_reject_forgery_cross_invocation_actor_and_authority_widening() -> Result<()> {
    let mut world = World::uninitialized("DAY2_TEST_REPORTS_ARTIFACT")?;
    let simulation = Simulation::new(world.runtime.clone(), [63; 32], 100_000)?;
    world.runtime = simulation.runtime().clone();
    world.runtime.initialize()?;
    let first = pending_notification(&world, "alice", "resource-a")?;
    let second = pending_notification(&world, "alice", "resource-b")?;
    let other_actor = pending_notification(&world, "bob", "resource-c")?;
    let handle = simulation.resource_probe(
        &first,
        "resources.bind.v1",
        json!({"binding":"notifications"}),
    )?["token"]
        .as_str()
        .context("handle")?
        .to_owned();
    assert_eq!(
        simulation.resource_probe(
            &first,
            "resources.bind.v1",
            json!({"binding":"notifications"})
        )?["token"],
        handle,
        "replay reissues the same opaque handle"
    );
    let resolve = |handle: &str, actor: &str| json!({"handle":handle,"actor":actor});
    simulation.resource_probe(
        &first,
        "notifications.recipient.v1",
        resolve(&handle, "alice"),
    )?;
    for (id, token, actor) in [
        (second.as_str(), handle.clone(), "alice"),
        (other_actor.as_str(), handle.clone(), "bob"),
        (
            first.as_str(),
            format!("resource_{}", "0".repeat(64)),
            "alice",
        ),
        (first.as_str(), handle.clone(), "bob"),
    ] {
        assert!(
            simulation
                .resource_probe(id, "notifications.recipient.v1", resolve(&token, actor))
                .is_err()
        );
    }
    assert!(
        simulation
            .resource_probe(&first, "resources.bind.v1", json!({"binding":"carta"}))
            .is_err(),
        "only named active slots can issue handles"
    );
    let narrow = simulation.resource_probe(&first,"resources.attenuate.v1",json!({"handle":handle,"actions":["notifications_send"],"topics":{"kind":"only","topics":["allowed"]}}))?["token"].as_str().context("narrow handle")?.to_owned();
    let send = |topic: &str| json!({"handle":narrow,"actor":"alice","topic":topic,"body":"hello"});
    simulation.resource_probe(&first, "notifications.send.v1", send("allowed"))?;
    assert!(
        simulation
            .resource_probe(&first, "notifications.send.v1", send("other"))
            .is_err()
    );
    assert!(
        simulation
            .resource_probe(
                &first,
                "notifications.recipient.v1",
                resolve(&narrow, "alice")
            )
            .is_err()
    );
    assert!(
        simulation
            .resource_probe(
                &first,
                "resources.attenuate.v1",
                json!({"handle":narrow,"topics":{"kind":"any"}})
            )
            .is_err()
    );
    assert!(
        simulation
            .resource_probe(
                &first,
                "resources.attenuate.v1",
                json!({"handle":narrow,"actions":["notifications_send","notifications_resolve"]})
            )
            .is_err()
    );
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.notify")
            .unwrap()
            .effects
            .clear();
    })?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.notify")
            .unwrap()
            .effects
            .insert("notifications.send.v1".into());
    })?;
    assert!(
        simulation
            .resource_probe(
                &first,
                "notifications.recipient.v1",
                resolve(&handle, "alice")
            )
            .is_err(),
        "A-B-A does not revive a captured handle"
    );
    Ok(())
}

#[test]
fn attenuated_expiry_uses_dispatch_clock_and_cannot_be_extended() -> Result<()> {
    let mut world = World::uninitialized("DAY2_TEST_REPORTS_ARTIFACT")?;
    let simulation = Simulation::new(world.runtime.clone(), [64; 32], 100_000)?;
    world.runtime = simulation.runtime().clone();
    simulation.runtime().initialize()?;
    let notify = pending_notification(&world, "alice", "expiry-submit")?;
    let handle = simulation.resource_probe(
        &notify,
        "resources.bind.v1",
        json!({"binding":"notifications"}),
    )?["token"]
        .as_str()
        .context("handle")?
        .to_owned();
    let expiring = simulation.resource_probe(
        &notify,
        "resources.attenuate.v1",
        json!({"handle":handle,"expires_at_ms":101_000}),
    )?["token"]
        .as_str()
        .context("expiring")?
        .to_owned();
    assert!(
        simulation
            .resource_probe(
                &notify,
                "resources.attenuate.v1",
                json!({"handle":expiring,"expires_at_ms":102_000})
            )
            .is_err()
    );
    simulation.resource_probe(
        &notify,
        "notifications.recipient.v1",
        json!({"handle":expiring,"actor":"alice"}),
    )?;
    simulation.set_time(101_000)?;
    let error = simulation
        .resource_probe(
            &notify,
            "notifications.recipient.v1",
            json!({"handle":expiring,"actor":"alice"}),
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "resource_authority_expired");
    Ok(())
}

#[test]
fn expired_resource_blocks_prepared_replay_before_application_or_provider_work() -> Result<()> {
    let mut world = World::uninitialized("DAY2_TEST_REPORTS_ARTIFACT")?;
    let simulation = Simulation::new(world.runtime.clone(), [65; 32], 100_000)?;
    world.runtime = simulation.runtime().clone();
    world.runtime.initialize()?;
    let mut instance = day2::artifact::Instance::load(world.runtime.instance_path())?;
    for attachment in &mut instance
        .apps
        .get_mut("reports")
        .context("app")?
        .resource_policies
    {
        if attachment.operation == "reports.notify" {
            attachment.expires_at_ms = Some(101_000);
        }
    }
    std::fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    let active = day2::authority_state::current(&rusqlite::Connection::open(world.runtime.db())?)?;
    day2::authority_state::apply_desired(
        &world.runtime,
        &day2::authority_state::LocalOperator::assert_local("test-operator")?,
        "expiring-resource",
        Some(active.stamp),
    )?;
    world.submit("expiry-root", Fault::None)?;
    let analyze = world.child("expiry-root")?;
    world.finish(&analyze)?;
    let notify = world.child(&analyze)?;
    let failure = world
        .runtime
        .execute(&notify, Fault::AfterPrepare)
        .unwrap_err();
    assert!(Fault::AfterPrepare.caused(&failure));
    simulation.set_time(101_000)?;
    assert_eq!(
        world.runtime.execute(&notify, Fault::None)?.status,
        "blocked"
    );
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let attempts: i64 = db.query_row("SELECT count(*) FROM day2_external_attempts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        attempts, 0,
        "cached observation expiry is checked before pure code can request a write"
    );
    Ok(())
}

#[test]
fn page_alias_inherits_root_budget_from_an_unused_operation_binding() -> Result<()> {
    use day2_capabilities::resources::{BudgetDefinition, BudgetLimits, BudgetScope, VersionRef};
    let world = World::new()?;
    let report = world.submit("page-report", Fault::None)?.result["id"].clone();
    let mut instance = day2::artifact::Instance::load(world.runtime.instance_path())?;
    let app = instance.apps.get_mut("reports").context("app")?;
    let mut attachment = app
        .resource_policies
        .iter()
        .find(|attachment| attachment.operation == "reports.detail")
        .context("detail binding")?
        .clone();
    let catalog = instance.resources.as_mut().context("catalog")?;
    let mut policy = catalog.policies[&attachment.policy.id].clone();
    let mut slot = policy
        .slots
        .remove("notifications")
        .context("notification slot")?;
    slot.budgets = vec![VersionRef {
        id: "page_bytes".into(),
        revision: 1,
    }];
    policy.slots.insert("root_budget".into(), slot);
    catalog.policies.insert("page_root".into(), policy);
    catalog.budgets.insert(
        "page_bytes".into(),
        BudgetDefinition {
            revision: 1,
            scope: BudgetScope::InvocationRoot,
            period_seconds: 60,
            limits: BudgetLimits {
                calls: None,
                bytes: Some(1),
                cost_microunits: None,
                concurrency: None,
            },
        },
    );
    attachment.policy = VersionRef {
        id: "page_root".into(),
        revision: 1,
    };
    let target = attachment
        .bindings
        .remove("notifications")
        .context("notification resource")?;
    attachment.bindings.insert("root_budget".into(), target);
    app.resource_policies.push(attachment);
    std::fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    let active = day2::authority_state::current(&rusqlite::Connection::open(world.runtime.db())?)?;
    day2::authority_state::apply_desired(
        &world.runtime,
        &day2::authority_state::LocalOperator::assert_local("test-operator")?,
        "page-root-budget",
        Some(active.stamp),
    )?;
    let active = day2::authority_state::current(&rusqlite::Connection::open(world.runtime.db())?)?;
    assert!(
        active.document.resources.operations["reports.detail"]["notifications"]
            .budgets
            .is_empty()
    );
    let error = world
        .runtime
        .render_page(
            "report",
            "alice",
            "budget-page",
            &json!({"report_id":report}),
            100,
        )
        .unwrap_err();
    assert!(
        error
            .chain()
            .any(|cause| cause.to_string() == "budget_exhausted"),
        "{error:#}"
    );
    assert!(
        !world
            .runtime
            .db()
            .with_file_name("notifications.sqlite")
            .exists(),
        "the page alias must charge every operation root obligation before provider I/O"
    );
    Ok(())
}

#[test]
fn child_without_budget_refs_cannot_escape_accepted_root_budget_obligations() -> Result<()> {
    use day2_capabilities::resources::{BudgetDefinition, BudgetLimits, BudgetScope, VersionRef};
    let mut world = World::uninitialized("DAY2_TEST_REPORTS_ARTIFACT")?;
    let simulation = Simulation::new(world.runtime.clone(), [66; 32], 100_000)?;
    world.runtime = simulation.runtime().clone();
    world.runtime.initialize()?;
    let mut instance = day2::artifact::Instance::load(world.runtime.instance_path())?;
    let app = instance.apps.get_mut("reports").context("app")?;
    app.authority
        .as_mut()
        .context("policy")?
        .operations
        .get_mut("reports.submit")
        .context("submit")?
        .observations
        .insert("notifications.recipient.v1".into());
    let mut attachment = app
        .resource_policies
        .iter()
        .find(|attachment| attachment.operation == "reports.notify")
        .context("notify binding")?
        .clone();
    let catalog = instance.resources.as_mut().context("catalog")?;
    let mut policy = catalog.policies[&attachment.policy.id].clone();
    for slot in policy.slots.values_mut() {
        slot.budgets = vec![VersionRef {
            id: "root-calls".into(),
            revision: 1,
        }];
    }
    catalog.budgets.insert(
        "root-calls".into(),
        BudgetDefinition {
            revision: 1,
            scope: BudgetScope::InvocationRoot,
            period_seconds: 60,
            limits: BudgetLimits {
                calls: Some(1),
                bytes: None,
                cost_microunits: None,
                concurrency: None,
            },
        },
    );
    catalog.policies.insert("root-policy".into(), policy);
    attachment.policy = VersionRef {
        id: "root-policy".into(),
        revision: 1,
    };
    attachment.operation = "reports.submit".into();
    app.resource_policies.push(attachment);
    std::fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    let active = day2::authority_state::current(&rusqlite::Connection::open(world.runtime.db())?)?;
    day2::authority_state::apply_desired(
        &world.runtime,
        &day2::authority_state::LocalOperator::assert_local("test-operator")?,
        "root-obligations",
        Some(active.stamp),
    )?;
    world.submit("budget-root", Fault::None)?;
    let analyze = world.child("budget-root")?;
    world.finish(&analyze)?;
    let notify = world.child(&analyze)?;
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let active = day2::authority_state::current(&db)?;
    assert_eq!(
        active.document.resources.operations["reports.submit"]["notifications"]
            .budgets
            .len(),
        1
    );
    assert!(
        active.document.resources.operations["reports.notify"]["notifications"]
            .budgets
            .is_empty()
    );
    assert_eq!(
        world.runtime.execute(&notify, Fault::None)?.status,
        "pending"
    );
    let effect = simulation.claim_effect(&notify)?.context("effect")?;
    let error = simulation
        .admit_effect(effect)
        .err()
        .context("inherited budget must reject second call")?;
    assert!(
        error
            .chain()
            .any(|cause| cause.to_string() == "budget_exhausted"),
        "{error:#}"
    );
    let usage: i64 = db.query_row(
        "SELECT sum(used) FROM day2_budget_accounts WHERE budget_id='root-calls' AND unit='calls'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        usage, 1,
        "the child observation consumed the parent's shared allowance"
    );
    let attempts: i64 = db.query_row("SELECT count(*) FROM day2_external_attempts", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        attempts, 0,
        "rejected call and its provisional reservation roll back together"
    );
    Ok(())
}

fn recorded<T>(
    name: &str,
    parameters: Value,
    run: impl FnOnce(&mut evidence::Evidence) -> Result<T>,
) -> Result<T> {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/command-simulation");
    let mut evidence = evidence::Evidence::start(
        &root,
        json!({"name":name,"parameters":parameters,
        "campaign_source":day2::digest(include_bytes!("command_simulation.rs")),
        "artifact":std::env::var("DAY2_TEST_REPORTS_ARTIFACT").ok()}),
    )?;
    evidence.run(run)
}

fn campaign(seed: u64) -> Result<Value> {
    recorded(
        "crash_schedule",
        json!({"seed":seed,"entropy":vec![42;32],"now_ms":100_000,"steps":18}),
        |evidence| campaign_recorded(seed, evidence),
    )
}

fn campaign_recorded(seed: u64, evidence: &mut evidence::Evidence) -> Result<Value> {
    let mut world = World::uninitialized("DAY2_TEST_REPORTS_ARTIFACT")?;
    let simulation = Simulation::new(world.runtime.clone(), [42; 32], 100_000)?;
    world.runtime = simulation.runtime().clone();
    world.runtime.initialize()?;
    world.runtime.accept(
        "reports.submit",
        "alice",
        "simulation",
        &json!({"title":"Simulation","text":"A\nB"}),
        100,
    )?;
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let mut random = seed;
    for _ in 0..18 {
        let next: Option<String> = db
            .query_row(
                "SELECT id FROM day2_invocations WHERE status='pending' ORDER BY rowid LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(id) = next else { break };
        random = random
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let fault = match (random >> 32) % 6 {
            0 => Fault::AfterPrepare,
            1 => Fault::AfterDecisionCommit,
            2 => Fault::AfterExternal(1),
            3 => Fault::BeforeCommit,
            4 => Fault::AfterCommit,
            _ => Fault::None,
        };
        evidence.event(json!({"attempt":id,"fault":format!("{fault:?}")}))?;
        let result = world.runtime.execute(&id, fault);
        evidence.event(
            json!({"invocation":id,"state":simulation.snapshot()?,"result":match &result {
                Ok(outcome) => serde_json::to_value(outcome)?,
                Err(error) => json!({"error":format!("{error:#}"),"expected":fault.caused(error)}),
            }}),
        )?;
        if let Err(error) = result {
            ensure!(
                fault.caused(&error),
                "unexpected execution failure: {error:#}"
            );
        }
        let snapshot = world.runtime.inspect()?;
        let rows = snapshot["reports"].as_array().context("reports")?;
        ensure!(rows.len() <= 1, "duplicate report at seed {seed}");
        if let Some(row) = rows.first() {
            let data: Value = serde_json::from_str(row["data"].as_str().unwrap())?;
            let ready = data["ready"].as_bool().unwrap();
            ensure!(
                data["bytes"] == if ready { 3 } else { 0 },
                "incorrect byte count at seed {seed}"
            );
            ensure!(
                data["lines"] == if ready { 2 } else { 0 },
                "incorrect line count at seed {seed}"
            );
            let announced = data["announced"].as_bool().unwrap();
            // Announcement is recorded on the row, so a report now has three
            // legitimate revisions rather than two: submitted, analyzed, announced.
            // The exact revision for each state is still what catches a decision
            // that committed twice -- any duplicate pushes the row past it.
            ensure!(
                !announced || ready,
                "report announced before it was ready at seed {seed}"
            );
            let expected = match (ready, announced) {
                (false, _) => 1,
                (true, false) => 2,
                (true, true) => 3,
            };
            ensure!(
                row["version"] == expected,
                "duplicate decision at seed {seed}"
            );
        }
    }
    let drained = invocations::drain(&world.runtime, 32);
    evidence.event(json!({"after_recovery":simulation.snapshot()?}))?;
    drained?;
    let analysis = world.child("simulation")?;
    let notify = world.child(&analysis)?;
    let traces = ["simulation", analysis.as_str(), notify.as_str()]
        .into_iter()
        .map(|id| world.runtime.trace(id))
        .collect::<Result<Vec<_>>>()?;
    evidence.event(json!({"artifact":world.runtime.artifact().id(),"traces":traces}))?;
    for trace in &traces {
        ensure!(
            trace.outcome.status == "success",
            "terminal failure at seed {seed}"
        );
        replay(world.runtime.artifact(), trace)?;
    }
    let mailbox =
        rusqlite::Connection::open(world.runtime.db().with_file_name("notifications.sqlite"))?;
    let encoded: String = mailbox.query_row(
        "SELECT state FROM notification_world WHERE id=1",
        [],
        |row| row.get(0),
    )?;
    let model: NotificationWorld = serde_json::from_str(&encoded)?;
    ensure!(
        model.messages.len() == 1 && model.order.len() == 1,
        "provider state contains duplicate or missing acceptances"
    );
    let snapshot = world.runtime.inspect()?;
    let report = snapshot["reports"][0]["id"].as_str().unwrap();
    let delivery = model.latest(world.runtime.scope(), "alice", report);
    ensure!(
        delivery["count"] == 1,
        "duplicate external delivery at seed {seed}"
    );
    Ok(
        json!({"business":{"snapshot":snapshot,"delivery":delivery},"logical":simulation.snapshot()?}),
    )
}

#[test]
fn seeded_crash_schedules_converge_on_the_same_business_and_provider_state() -> Result<()> {
    let expected = campaign(0)?;
    assert_eq!(
        campaign(0)?,
        expected,
        "identical schedules reproduce the complete logical trace"
    );
    for seed in [1, 42, 3664912422, 0xdeadbeef] {
        assert_eq!(
            campaign(seed)?["business"],
            expected["business"],
            "schedule {seed}"
        );
    }
    Ok(())
}

#[test]
fn logical_time_worker_failures_and_duplicate_acceptance_are_replayable() -> Result<()> {
    fn run() -> Result<Value> {
        recorded(
            "logical_time_and_worker_failures",
            json!({"entropy":vec![7;32]}),
            |evidence| {
                let world = World::uninitialized("DAY2_TEST_REPORTS_ARTIFACT")?;
                let simulation = Simulation::new(world.runtime, [7; 32], 100_000)?;
                let runtime = simulation.runtime();
                runtime.initialize()?;
                let input = json!({"title":"Recovery","text":"A"});
                runtime.accept("reports.submit", "alice", "one", &input, 100)?;
                runtime.accept("reports.submit", "alice", "one", &input, 101)?;
                let before = simulation.snapshot()?;
                evidence.event(json!({"after_acceptance":before}))?;
                assert_eq!(
                    before["journal"]["day2_id_seeds"].as_array().unwrap().len(),
                    1
                );
                assert_eq!(
                    before["host"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|event| event["entropy"] == "one")
                        .count(),
                    1
                );
                for (time, failure, code) in [
                    (101_000, WorkerFailure::Timeout, "worker_timeout"),
                    (102_000, WorkerFailure::Crash, "worker_crashed"),
                ] {
                    simulation.set_time(time)?;
                    simulation.fail_next_worker(failure);
                    evidence.event(
                        json!({"attempt":"one","failure":failure,"state":simulation.snapshot()?}),
                    )?;
                    let result = runtime.execute("one", Fault::None);
                    evidence.event(json!({"after_attempt":simulation.snapshot()?}))?;
                    assert_eq!(result.unwrap_err().to_string(), code);
                }
                invocations::drain(runtime, 32)?;
                assert_eq!(runtime.trace("one")?.outcome.status, "success");
                let state = simulation.snapshot()?;
                evidence.event(json!({"completed":state}))?;
                let db = rusqlite::Connection::open(runtime.db())?;
                let at: Vec<i64> = db.prepare("SELECT at_ms FROM day2_audit_events WHERE outcome='interrupted' ORDER BY sequence")?
            .query_map([], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?;
                assert_eq!(at, [101_000, 102_000]);
                Ok(state)
            },
        )
    }
    assert_eq!(run()?, run()?);
    Ok(())
}

#[test]
fn two_executors_interleave_provider_calls_and_settlement_without_duplicate_delivery() -> Result<()>
{
    fn run(reverse: bool, lose_result: bool) -> Result<Value> {
        recorded(
            "two_executors",
            json!({"reverse":reverse,"lose_result":lose_result,"entropy":vec![19;32]}),
            |evidence| {
                let mut world = World::uninitialized("DAY2_TEST_REPORTS_ARTIFACT")?;
                let simulation = Simulation::new(world.runtime.clone(), [19; 32], 100_000)?;
                world.runtime = simulation.runtime().clone();
                world.runtime.initialize()?;
                world.submit("submit", Fault::None)?;
                let analyze = world.child("submit")?;
                world.finish(&analyze)?;
                let notify = world.child(&analyze)?;
                assert_eq!(
                    world.runtime.execute(&notify, Fault::None)?.status,
                    "pending"
                );
                evidence.event(json!({"before_claims":simulation.snapshot()?}))?;
                // Both executors hold the same journaled intent before either calls the provider.
                let first = simulation.claim_effect(&notify)?.context("first claim")?;
                let second = simulation.claim_effect(&notify)?.context("second claim")?;
                evidence.event(json!({"before_provider_calls":simulation.snapshot()?}))?;
                let first = simulation.perform_effect(first)?;
                let second = simulation.perform_effect(second)?;
                evidence.event(json!({"before_settlement":simulation.snapshot()?}))?;
                if lose_result {
                    drop(first); // Provider acceptance survives executor loss.
                    simulation.settle_effect(second)?;
                } else if reverse {
                    simulation.settle_effect(second)?;
                    simulation.settle_effect(first)?;
                } else {
                    simulation.settle_effect(first)?;
                    simulation.settle_effect(second)?;
                }
                world.finish(&notify)?;
                let journal = rusqlite::Connection::open(world.runtime.db())?;
                let usage: (i64,i64) = journal.query_row(
                    "SELECT count(*),count(s.id) FROM day2_budget_reservations r LEFT JOIN day2_budget_settlements s ON s.id=r.id",[],|row|Ok((row.get(0)?,row.get(1)?)),
                )?;
                assert_eq!(
                    usage,
                    (3, if lose_result { 2 } else { 3 }),
                    "every physical provider attempt is budgeted; unknown outcomes keep their reservation"
                );
                let wrong_roots: i64 = journal.query_row(
                    "SELECT count(*) FROM day2_resource_roots WHERE root!='submit'",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(
                    wrong_roots, 0,
                    "descendants retain the invocation root for shared budget accounts"
                );
                let state = simulation.snapshot()?;
                evidence.event(json!({"completed":state}))?;
                let mailbox = rusqlite::Connection::open(
                    world.runtime.db().with_file_name("notifications.sqlite"),
                )?;
                let encoded: String = mailbox.query_row(
                    "SELECT state FROM notification_world WHERE id=1",
                    [],
                    |row| row.get(0),
                )?;
                let provider: NotificationWorld = serde_json::from_str(&encoded)?;
                assert_eq!(provider.messages.len(), 1);
                assert_eq!(provider.order.len(), 1);
                let report = world.runtime.inspect()?["reports"][0]["id"]
                    .as_str()
                    .context("report")?
                    .to_owned();
                assert_eq!(
                    provider.latest(world.runtime.scope(), "alice", &report)["count"],
                    1
                );
                Ok(state)
            },
        )
    }
    let first = run(false, false)?;
    assert_eq!(run(false, false)?, first);
    for (reverse, lost) in [(true, false), (false, true)] {
        let other = run(reverse, lost)?;
        let mut actual_journal = other["journal"].clone();
        let mut expected_journal = first["journal"].clone();
        // Settlement records both usage and provider support correlations. A
        // lost response cannot supply either, even when another attempt settles
        // the same idempotent effect. Assert that exact knowledge difference
        // before comparing every remaining journal table and provider state.
        let actual_attempts = actual_journal
            .as_object_mut()
            .unwrap()
            .remove("day2_external_attempts")
            .unwrap();
        let mut expected_attempts = expected_journal
            .as_object_mut()
            .unwrap()
            .remove("day2_external_attempts")
            .unwrap();
        assert_eq!(expected_attempts.as_array().unwrap().len(), 2);
        assert_eq!(expected_attempts[0][2], 1);
        assert_eq!(expected_attempts[1][2], 2);
        assert_eq!(expected_attempts[0][1], expected_attempts[1][1]);
        let effect = expected_attempts[0][1]
            .as_str()
            .context("effect identity")?;
        let first_attempt = format!("{effect}_attempt_1");
        let second_attempt = format!("{effect}_attempt_2");
        assert_eq!(expected_attempts[0][0], first_attempt);
        assert_eq!(expected_attempts[1][0], second_attempt);
        assert!(expected_attempts[0][5].is_string());
        assert_eq!(expected_attempts[0][5], expected_attempts[1][5]);
        let accepted: day2::protocol::Observation = serde_json::from_str(
            expected_attempts[0][5]
                .as_str()
                .context("settled observation")?,
        )?;
        assert_eq!(accepted.instruction.model, "notifications.send.v1");
        assert!(accepted.error.is_empty());
        assert_eq!(
            serde_json::from_str::<Value>(&accepted.result)?["status"],
            "accepted"
        );
        if lost {
            expected_attempts[0][5] = Value::Null;
        }
        assert_eq!(actual_attempts, expected_attempts);
        let actual_usage = actual_journal
            .as_object_mut()
            .unwrap()
            .remove("day2_budget_settlements")
            .unwrap();
        let expected_usage = expected_journal
            .as_object_mut()
            .unwrap()
            .remove("day2_budget_settlements")
            .unwrap();
        let expected_usage = expected_usage.as_array().context("settlements")?;
        assert_eq!(expected_usage.len(), 3);
        assert_eq!(expected_usage[0][0], first_attempt);
        assert_eq!(expected_usage[1][0], second_attempt);
        assert!(
            expected_usage[2][0]
                .as_str()
                .context("observation identity")?
                .starts_with("observation_")
        );
        for usage in expected_usage {
            let receipt: Value =
                serde_json::from_str(usage[2].as_str().context("settlement receipt")?)?;
            assert_eq!(receipt["reservation"]["id"], usage[0]);
            assert_eq!(receipt["settled"], true);
            assert_eq!(receipt["overrun"], false);
        }
        let actual_correlations = actual_journal
            .as_object_mut()
            .unwrap()
            .remove("day2_resource_correlations")
            .unwrap();
        let baseline_correlations = expected_journal
            .as_object_mut()
            .unwrap()
            .remove("day2_resource_correlations")
            .unwrap();
        let expected_correlations: Vec<_> = expected_usage
            .iter()
            .map(|usage| json!([usage[0], "[]"]))
            .collect();
        assert_eq!(baseline_correlations, json!(expected_correlations));
        let expected_usage: Vec<_> = expected_usage
            .iter()
            .filter(|usage| !lost || usage[0] != first_attempt)
            .cloned()
            .collect();
        let expected_correlations: Vec<_> = expected_correlations
            .into_iter()
            .filter(|correlation| !lost || correlation[0] != first_attempt)
            .collect();
        assert_eq!(actual_usage, json!(expected_usage));
        assert_eq!(actual_correlations, json!(expected_correlations));
        // Losing the first result leaves its physical reservation outstanding;
        // successful completion through attempt 2 must not erase that evidence.
        assert!(
            actual_journal["day2_budget_reservations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reservation| reservation[0] == first_attempt)
        );
        assert_eq!(actual_journal["day2_budget_unknown"], json!([]));
        assert_eq!(actual_journal["day2_budget_accounts"], json!([]));
        assert_eq!(actual_journal, expected_journal);
        assert_eq!(other["provider"], first["provider"]);
    }
    Ok(())
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config {
        cases: 12,
        max_shrink_iters: 64,
        rng_seed: proptest::test_runner::RngSeed::Fixed(0xDA72_51A1),
        failure_persistence: Some(Box::new(proptest::test_runner::FileFailurePersistence::Direct(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../artifacts/command-simulation/seeds.txt")))),
        ..proptest::test_runner::Config::default()
    })]
    #[test]
    fn generated_crash_schedules_preserve_the_reference_invariants(seed in proptest::prelude::any::<u64>()) {
        let result = campaign(seed);
        proptest::prop_assert!(result.is_ok(), "{:#}", result.unwrap_err());
    }
}

#[test]
fn revocation_before_admission_and_restoration_never_revive_an_old_intent() -> Result<()> {
    recorded(
        "authority_during_provider_call",
        json!({"entropy":vec![23;32]}),
        |evidence| {
            let mut world = World::uninitialized("DAY2_TEST_REPORTS_ARTIFACT")?;
            let simulation = Simulation::new(world.runtime.clone(), [23; 32], 100_000)?;
            world.runtime = simulation.runtime().clone();
            world.runtime.initialize()?;
            world.submit("submit", Fault::None)?;
            let analyze = world.child("submit")?;
            world.finish(&analyze)?;
            let notify = world.child(&analyze)?;
            world.runtime.execute(&notify, Fault::None)?;
            let denied = simulation.claim_effect(&notify)?.context("claim")?;
            world.change_policy(|policy| {
                policy
                    .operations
                    .get_mut("reports.notify")
                    .unwrap()
                    .effects
                    .clear();
            })?;
            evidence.event(json!({"revoked_before_perform":simulation.snapshot()?}))?;
            assert!(simulation.perform_effect(denied).is_err());
            assert!(simulation.snapshot()?["provider"].is_null());
            world.change_policy(|policy| {
                policy
                    .operations
                    .get_mut("reports.notify")
                    .unwrap()
                    .effects
                    .insert("notifications.send.v1".into());
            })?;
            assert!(
                simulation.claim_effect(&notify).is_err(),
                "A→B→A must retain the acceptance revision"
            );
            assert!(simulation.snapshot()?["provider"].is_null());
            let db = rusqlite::Connection::open(world.runtime.db())?;
            let attempts: i64 =
                db.query_row("SELECT count(*) FROM day2_external_attempts", [], |row| {
                    row.get(0)
                })?;
            assert_eq!(attempts, 0);
            Ok(())
        },
    )
}

#[test]
fn an_admitted_attempt_can_finish_after_revocation_and_preserves_provider_knowledge() -> Result<()>
{
    recorded(
        "revocation_after_dispatch_admission",
        json!({"entropy":vec![23;32]}),
        |evidence| {
            let mut world = World::uninitialized("DAY2_TEST_REPORTS_ARTIFACT")?;
            let simulation = Simulation::new(world.runtime.clone(), [23; 32], 100_000)?;
            world.runtime = simulation.runtime().clone();
            world.runtime.initialize()?;
            world.submit("submit", Fault::None)?;
            let analyze = world.child("submit")?;
            world.finish(&analyze)?;
            let notify = world.child(&analyze)?;
            world.runtime.execute(&notify, Fault::None)?;
            let effect = simulation.claim_effect(&notify)?.context("claim")?;
            let admitted = simulation.admit_effect(effect)?;
            // The process pauses after admission, before its provider call.
            world.change_policy(|policy| {
                policy
                    .operations
                    .get_mut("reports.notify")
                    .unwrap()
                    .effects
                    .clear();
            })?;
            evidence.event(json!({"revoked_after_admission":simulation.snapshot()?}))?;
            assert!(simulation.snapshot()?["provider"].is_null());
            let result = simulation.perform_admitted_effect(admitted)?;
            simulation.settle_effect(result)?;
            let snapshot = simulation.snapshot()?;
            evidence.event(json!({"settled_without_authority":snapshot}))?;
            let db = rusqlite::Connection::open(world.runtime.db())?;
            let recorded: i64 = db.query_row("SELECT count(*) FROM day2_external_effects WHERE invocation=?1 AND observation IS NOT NULL", [&notify], |row| row.get(0))?;
            assert_eq!(recorded, 1);
            let attempts: (i64, i64) = db.query_row(
                "SELECT count(*),count(observation) FROM day2_external_attempts",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert_eq!(attempts, (1, 1));
            assert_eq!(
                world.runtime.execute(&notify, Fault::None)?.status,
                "blocked"
            );
            assert_eq!(simulation.snapshot()?["provider"], snapshot["provider"]);
            Ok(())
        },
    )
}

#[test]
fn settlement_of_an_admitted_attempt_survives_artifact_activation() -> Result<()> {
    let mut world = World::uninitialized("DAY2_TEST_REPORTS_ARTIFACT")?;
    let replacement = World::artifact("DAY2_TEST_REPORTS_PROBE_ARTIFACT")?;
    let simulation = Simulation::new(world.runtime.clone(), [29; 32], 100_000)?;
    world.runtime = simulation.runtime().clone();
    world.runtime.initialize()?;
    world.submit("submit", Fault::None)?;
    let analyze = world.child("submit")?;
    world.finish(&analyze)?;
    let notify = world.child(&analyze)?;
    world.runtime.execute(&notify, Fault::None)?;
    let effect = simulation.claim_effect(&notify)?.context("claim")?;
    let admitted = simulation.admit_effect(effect)?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.notify")
            .unwrap()
            .effects
            .clear();
    })?;
    let candidate = replacement.runtime.artifact();
    let plan = day2::migration::plan(&world.runtime, candidate)?;
    day2::migration::apply(&world.runtime, candidate, &plan)?;
    day2::migration::activate(&world.runtime, candidate)?;
    let result = simulation.perform_admitted_effect(admitted)?;
    simulation.settle_effect(result)?;
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let recorded: i64 = db.query_row(
        "SELECT count(*) FROM day2_external_attempts WHERE observation IS NOT NULL",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(recorded, 1);
    assert!(world.runtime.execute(&notify, Fault::None).is_err());
    Ok(())
}

#[test]
fn lost_provider_response_remains_unresolved_when_authority_is_revoked_and_restored() -> Result<()>
{
    let mut world = World::uninitialized("DAY2_TEST_REPORTS_ARTIFACT")?;
    let simulation = Simulation::new(world.runtime.clone(), [31; 32], 100_000)?;
    world.runtime = simulation.runtime().clone();
    world.runtime.initialize()?;
    world.submit("submit", Fault::None)?;
    let analyze = world.child("submit")?;
    world.finish(&analyze)?;
    let notify = world.child(&analyze)?;
    world.runtime.execute(&notify, Fault::None)?;
    let effect = simulation.claim_effect(&notify)?.context("claim")?;
    let result = simulation.perform_effect(effect)?;
    drop(result); // The mailbox accepted; the host does not know the outcome.
    let provider = simulation.snapshot()?["provider"].clone();
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.notify")
            .unwrap()
            .effects
            .clear();
    })?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.notify")
            .unwrap()
            .effects
            .insert("notifications.send.v1".into());
    })?;
    assert!(simulation.claim_effect(&notify).is_err());
    assert_eq!(simulation.snapshot()?["provider"], provider);
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let attempts: (i64, i64) = db.query_row(
        "SELECT count(*),count(observation) FROM day2_external_attempts",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(
        attempts,
        (1, 0),
        "restoration never treats an unknown send as unperformed"
    );
    let held:i64 = db.query_row("SELECT count(*) FROM day2_budget_reservations r LEFT JOIN day2_budget_settlements s ON s.id=r.id WHERE s.id IS NULL",[],|row|row.get(0))?;
    assert_eq!(
        held, 1,
        "revocation and regrant do not refund an unknown provider outcome"
    );
    Ok(())
}
