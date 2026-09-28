#[path = "support/oncall.rs"]
mod support;
use anyhow::{Context, Result};
use day2::{
    authority_state::LocalOperator,
    deferrals, invocations,
    recovery::{self, Request},
    store::Runtime,
};
use support::World;

const OPEN_AT: i64 = 100;
const FIRST_DUE: i64 = 400_000;

fn open(world: &World, key: &str) -> Result<(String, String)> {
    let result = world.open(key, "Example service unavailable", OPEN_AT)?;
    assert_eq!(result.status, "success", "{}", result.error);
    let incident = result.result["id"]
        .as_str()
        .context("incident id")?
        .to_owned();
    let deferral = child_id(world, key)?;
    Ok((incident, deferral))
}

fn child_id(world: &World, parent: &str) -> Result<String> {
    let children = invocations::children(&world.runtime, parent)?;
    assert_eq!(children.len(), 1);
    Ok(children[0].id.clone())
}

fn deferral(world: &World, parent: &str) -> Result<(String, i64)> {
    let connection = rusqlite::Connection::open(world.runtime.db())?;
    Ok(connection.query_row(
        "SELECT id,due_ms FROM day2_deferrals WHERE parent=?1",
        [parent],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?)
}

fn offer_and_drain(world: &World, due: i64, id: &str) -> Result<serde_json::Value> {
    let offered = deferrals::tick(&world.runtime, due)?;
    assert!(
        offered
            .iter()
            .any(|item| item.id == id && item.outcome == "admitted")
    );
    assert!(
        invocations::drain(&world.runtime, 64)?
            .iter()
            .any(|item| item.id == id && item.status == "success")
    );
    Ok(world.runtime.trace(id)?.outcome.result)
}

#[test]
fn open_defers_once_until_its_due_time() -> Result<()> {
    let world = World::new()?;
    let (incident, deferred) = open(&world, "open-due")?;
    assert_eq!(world.incident(&incident)?["data"]["status"], "Open");
    assert_eq!(world.incident(&incident)?["data"]["rung"], 0);
    assert_eq!(deferral(&world, "open-due")?, (deferred.clone(), FIRST_DUE));
    assert!(deferrals::tick(&world.runtime, FIRST_DUE - 1)?.is_empty());
    assert_eq!(
        invocations::children(&world.runtime, "open-due")?[0].status,
        "deferred"
    );
    Ok(())
}

#[test]
fn open_incident_advances_through_three_rungs_then_stops() -> Result<()> {
    let world = World::new()?;
    let (incident, mut current) = open(&world, "open-escalates")?;
    let mut due = FIRST_DUE;
    for rung in 1..=3 {
        let result = offer_and_drain(&world, due, &current)?;
        assert_eq!(result["escalated"], true);
        assert_eq!(result["rung"], rung);
        assert_eq!(world.incident(&incident)?["data"]["rung"], rung);
        let (next, next_due) = deferral(&world, &current)?;
        assert_eq!(next_due, due + 300_000);
        current = next;
        due = next_due;
    }
    let stopped = offer_and_drain(&world, due, &current)?;
    assert_eq!(stopped["escalated"], false);
    assert_eq!(stopped["reason"], "max_rung");
    assert_eq!(stopped["rung"], 3);
    assert_eq!(world.incident(&incident)?["data"]["rung"], 3);
    assert!(invocations::children(&world.runtime, &current)?.is_empty());
    Ok(())
}

#[test]
fn acknowledged_incident_is_re_read_and_escalation_is_a_successful_noop() -> Result<()> {
    let world = World::new()?;
    let (incident, deferred) = open(&world, "ack-before-due")?;
    let acknowledged = world.acknowledge(&incident, "ack-before-due-request", 1, 150)?;
    assert_eq!(acknowledged.status, "success", "{}", acknowledged.error);
    assert_eq!(world.incident(&incident)?["data"]["status"], "Acknowledged");
    let result = offer_and_drain(&world, FIRST_DUE, &deferred)?;
    assert_eq!(result["escalated"], false);
    assert_eq!(result["reason"], "acknowledged");
    assert_eq!(world.incident(&incident)?["data"]["rung"], 0);
    assert!(invocations::children(&world.runtime, &deferred)?.is_empty());
    Ok(())
}

#[test]
fn admitted_escalation_observes_acknowledgement_committed_before_drain() -> Result<()> {
    let world = World::new()?;
    let (incident, deferred) = open(&world, "ack-race")?;
    assert_eq!(
        deferrals::tick(&world.runtime, FIRST_DUE)?[0].outcome,
        "admitted"
    );
    let acknowledged = world.acknowledge(&incident, "ack-race-ack", 1, 401)?;
    assert_eq!(acknowledged.status, "success", "{}", acknowledged.error);
    let result = world.runtime.execute(&deferred, day2::store::Fault::None)?;
    assert_eq!(result.status, "success", "{}", result.error);
    assert_eq!(
        world.runtime.trace(&deferred)?.outcome.result["reason"],
        "acknowledged"
    );
    assert_eq!(world.incident(&incident)?["data"]["rung"], 0);
    Ok(())
}

#[test]
fn repeated_ticks_and_runtime_reload_do_not_repeat_an_escalation() -> Result<()> {
    let world = World::new()?;
    let (incident, deferred) = open(&world, "reload-once")?;
    assert_eq!(deferrals::tick(&world.runtime, FIRST_DUE)?.len(), 1);
    assert!(deferrals::tick(&world.runtime, FIRST_DUE)?.is_empty());
    let restarted = Runtime::load(world.runtime.instance_path(), "oncall")?;
    assert!(deferrals::tick(&restarted, FIRST_DUE + 60_000)?.is_empty());
    assert_eq!(
        invocations::drain(&restarted, 64)?
            .iter()
            .filter(|item| item.id == deferred)
            .count(),
        1
    );
    assert_eq!(world.incident(&incident)?["data"]["rung"], 1);
    let connection = rusqlite::Connection::open(world.runtime.db())?;
    assert_eq!(
        connection.query_row(
            "SELECT count(*) FROM day2_invocations WHERE id=?1",
            [&deferred],
            |row| row.get::<_, i64>(0)
        )?,
        1
    );
    Ok(())
}

#[test]
fn downtime_catch_up_offers_once_and_advances_one_rung() -> Result<()> {
    let world = World::new()?;
    let (incident, deferred) = open(&world, "downtime-catchup")?;
    assert_eq!(
        deferrals::tick(&world.runtime, FIRST_DUE + 86_400_000)?[0].id,
        deferred
    );
    assert!(deferrals::tick(&world.runtime, FIRST_DUE + 86_400_000)?.is_empty());
    invocations::drain(&world.runtime, 64)?;
    assert_eq!(world.incident(&incident)?["data"]["rung"], 1);
    Ok(())
}

#[test]
fn unrelated_policy_change_preserves_waiting_escalation() -> Result<()> {
    let world = World::new()?;
    let (_, deferred) = open(&world, "policy-waiting")?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("oncall.acknowledge")
            .unwrap()
            .actors
            .insert("viewer".into());
    })?;
    assert_eq!(
        deferrals::tick(&world.runtime, FIRST_DUE)?[0].outcome,
        "admitted"
    );
    let result = invocations::drain(&world.runtime, 64)?;
    assert!(
        result
            .iter()
            .any(|item| item.id == deferred && item.status == "success")
    );
    Ok(())
}

#[test]
fn revoked_actor_is_blocked_then_operator_reissue_runs_after_regrant() -> Result<()> {
    let world = World::new()?;
    let (incident, deferred) = open(&world, "recovery-escalation")?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("oncall.escalate")
            .unwrap()
            .actors
            .remove("alice");
    })?;
    let offered = deferrals::tick(&world.runtime, FIRST_DUE)?;
    assert_eq!(offered[0].outcome, "blocked");
    assert_eq!(offered[0].reason, "deferral_forbidden");
    assert_eq!(
        invocations::children(&world.runtime, "recovery-escalation")?[0].status,
        "blocked"
    );

    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("oncall.escalate")
            .unwrap()
            .actors
            .insert("alice".into());
    })?;
    let receipt = recovery::reissue(
        &world.runtime,
        &LocalOperator::assert_local("test-operator")?,
        &Request {
            request_id: "oncall-reissue".into(),
            invocation: deferred.clone(),
            expected_artifact: world.runtime.artifact().id().into(),
            expected_revision: 0,
            reason: "restore escalation after authority review".into(),
        },
    )?;
    let successor = receipt.successor.context("reissued invocation")?;
    assert!(
        invocations::drain(&world.runtime, 64)?
            .iter()
            .any(|item| item.id == successor && item.status == "success")
    );
    assert_eq!(world.incident(&incident)?["data"]["rung"], 1);
    Ok(())
}
