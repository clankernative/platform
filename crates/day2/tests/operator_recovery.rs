#[path = "support/commands.rs"]
mod support;
use anyhow::{Context, Result};
use day2::{
    authority_state::LocalOperator,
    deferrals, invocations,
    recovery::{self, Request},
    simulation::Simulation,
    store::Fault,
};
use serde_json::json;
use support::World;

fn blocked_deferral() -> Result<(World, String)> {
    let world = World::artifact("DAY2_TEST_REPORTS_DEFERRALS_ARTIFACT")?;
    let outcome = world.runtime.invoke(
        "reports.submit",
        "alice",
        "recover-parent",
        &json!({"title":"defer","text":"first line\nsecond line"}),
        100,
        Fault::None,
    )?;
    assert_eq!(outcome.status, "success");
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.analyze")
            .unwrap()
            .actors
            .remove("alice");
    })?;
    let connection = rusqlite::Connection::open(world.runtime.db())?;
    let id: String = connection.query_row(
        "SELECT id FROM day2_deferrals WHERE parent='recover-parent'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        deferrals::tick(&world.runtime, 110_000)?[0].outcome,
        "blocked"
    );
    Ok((world, id))
}

fn request(runtime: &day2::store::Runtime, id: &str, request_id: &str) -> Request {
    Request {
        request_id: request_id.into(),
        invocation: id.into(),
        expected_artifact: runtime.artifact().id().into(),
        reason: "restore access after policy review".into(),
    }
}

#[test]
fn blocked_invocation_abandon_is_idempotent_and_fenced() -> Result<()> {
    let (world, id) = blocked_deferral()?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.analyze")
            .unwrap()
            .actors
            .insert("alice".into());
    })?;
    let operator = LocalOperator::assert_local("test-operator")?;
    let req = request(&world.runtime, &id, "abandon-once");
    let first = recovery::abandon(&world.runtime, &operator, &req)?;
    let repeated = recovery::abandon(&world.runtime, &operator, &req)?;
    assert_eq!(first, repeated);
    assert_eq!(first.resolution, "abandoned");
    assert_eq!(first.evidence.never_admitted, 0);
    assert_eq!(
        invocations::status(&world.runtime, &id, "alice")?
            .resolution
            .as_deref(),
        Some("abandoned")
    );
    let connection = rusqlite::Connection::open(world.runtime.db())?;
    let status: String = connection.query_row(
        "SELECT status FROM day2_invocations WHERE id=?1",
        [&id],
        |row| row.get(0),
    )?;
    assert_eq!(status, "failure");
    let event: (String, String, String, String) = connection.query_row(
        "SELECT kind,outcome,trigger,reason FROM day2_audit_events WHERE identity=?1 AND kind='recovery'",
        [&id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(
        event,
        (
            "recovery".into(),
            "abandoned".into(),
            "recovery".into(),
            "operator_recovery".into()
        )
    );
    assert_eq!(
        connection.query_row(
            "SELECT reason FROM day2_recoveries WHERE invocation=?1",
            [&id],
            |row| row.get::<_, String>(0)
        )?,
        "restore access after policy review"
    );
    assert_eq!(
        connection.query_row(
            "SELECT count(*) FROM day2_authority_blocks WHERE invocation=?1",
            [&id],
            |row| row.get::<_, i64>(0)
        )?,
        1
    );
    assert!(
        recovery::abandon(
            &world.runtime,
            &operator,
            &Request {
                reason: "different".into(),
                ..req.clone()
            }
        )
        .unwrap_err()
        .to_string()
        .contains("recovery_request_conflict")
    );
    assert!(
        recovery::abandon(
            &world.runtime,
            &operator,
            &request(&world.runtime, &id, "abandon-competing")
        )
        .unwrap_err()
        .to_string()
        .contains("recovery_already_resolved")
    );
    Ok(())
}

#[test]
fn safe_reissue_admits_one_fresh_successor_under_restored_authority() -> Result<()> {
    let (world, id) = blocked_deferral()?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.analyze")
            .unwrap()
            .actors
            .insert("alice".into());
    })?;
    let operator = LocalOperator::assert_local("test-operator")?;
    let req = request(&world.runtime, &id, "reissue-once");
    let receipt = recovery::reissue(&world.runtime, &operator, &req)?;
    let repeated = recovery::reissue(&world.runtime, &operator, &req)?;
    assert_eq!(receipt, repeated);
    let successor = receipt.successor.as_deref().unwrap();
    assert_eq!(
        successor,
        format!(
            "rcv_{}",
            &day2::digest(format!("{}\n{}", world.runtime.scope(), id).as_bytes())[7..]
        )
    );
    assert_eq!(
        invocations::drain(&world.runtime, 16)?
            .iter()
            .find(|entry| entry.id == successor)
            .unwrap()
            .status,
        "success"
    );
    let trace = world.runtime.trace(successor)?;
    assert_eq!(trace.request.context.authentication, "recovery");
    // The successor is new work within the original root: the blocked deferral
    // and its successor both belong to the parent that deferred it.
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let root = |invocation: &str| -> Result<String> {
        Ok(db.query_row(
            "SELECT root FROM day2_resource_roots WHERE invocation=?1",
            [invocation],
            |row| row.get(0),
        )?)
    };
    assert_eq!(root(&id)?, "recover-parent");
    assert_eq!(root(successor)?, "recover-parent");
    assert_eq!(
        db.query_row(
            "SELECT successor FROM day2_recoveries WHERE invocation=?1",
            [&id],
            |row| row.get::<_, String>(0)
        )?,
        successor
    );
    Ok(())
}

#[test]
fn an_issued_permit_is_fenced_and_unknown_budget_is_retained() -> Result<()> {
    let mut world = World::artifact("DAY2_TEST_REPORTS_ARTIFACT")?;
    let simulation = Simulation::new(world.runtime.clone(), [41; 32], 100_000)?;
    world.runtime = simulation.runtime().clone();
    world.runtime.initialize()?;
    world.submit("submit", Fault::None)?;
    let analyze = world.child("submit")?;
    world.finish(&analyze)?;
    let notify = world.child(&analyze)?;
    world.runtime.execute(&notify, Fault::None)?;
    let effect = simulation
        .claim_effect(&notify)?
        .context("claimed effect")?;
    let permit = simulation.admit_effect(effect)?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.notify")
            .unwrap()
            .effects
            .clear();
    })?;
    assert_eq!(
        world.runtime.execute(&notify, Fault::None)?.status,
        "blocked"
    );
    let operator = LocalOperator::assert_local("test-operator")?;
    let blocked_request = Request {
        request_id: "effect-reissue-refused".into(),
        invocation: notify.clone(),
        expected_artifact: world.runtime.artifact().id().into(),
        reason: "must not replay an effect".into(),
    };
    assert!(
        recovery::reissue(&world.runtime, &operator, &blocked_request)
            .unwrap_err()
            .to_string()
            .contains("recovery_reissue_requires_uncommitted_invocation")
    );
    let receipt = recovery::abandon(
        &world.runtime,
        &operator,
        &Request {
            request_id: "permit-fence".into(),
            invocation: notify.clone(),
            expected_artifact: world.runtime.artifact().id().into(),
            reason: "operator stopped blocked send".into(),
        },
    )?;
    assert_eq!(receipt.evidence.unknown_outcome, 1);
    let perform = simulation.perform_admitted_effect(permit);
    assert!(
        perform
            .err()
            .unwrap()
            .to_string()
            .contains("resolved_invocation_perform_fenced")
    );
    let db = rusqlite::Connection::open(world.runtime.db())?;
    assert_eq!(db.query_row("SELECT count(*) FROM day2_external_attempts WHERE observation IS NULL AND effect IN (SELECT identity FROM day2_external_effects WHERE invocation=?1)", [&notify], |row| row.get::<_,i64>(0))?, 1);
    assert_eq!(db.query_row("SELECT count(*) FROM day2_budget_reservations r JOIN day2_external_attempts a ON a.identity=r.id WHERE a.effect IN (SELECT identity FROM day2_external_effects WHERE invocation=?1) AND NOT EXISTS(SELECT 1 FROM day2_budget_settlements s WHERE s.id=r.id)", [&notify], |row| row.get::<_,i64>(0))?, 1);
    assert!(simulation.snapshot()?["provider"].is_null());
    Ok(())
}

#[test]
fn late_settlement_after_abandon_records_provider_knowledge_without_completion() -> Result<()> {
    let mut world = World::artifact("DAY2_TEST_REPORTS_ARTIFACT")?;
    let simulation = Simulation::new(world.runtime.clone(), [42; 32], 100_000)?;
    world.runtime = simulation.runtime().clone();
    world.runtime.initialize()?;
    world.submit("submit", Fault::None)?;
    let analyze = world.child("submit")?;
    world.finish(&analyze)?;
    let notify = world.child(&analyze)?;
    world.runtime.execute(&notify, Fault::None)?;
    let effect = simulation
        .claim_effect(&notify)?
        .context("claimed effect")?;
    let permit = simulation.admit_effect(effect)?;
    let performed = simulation.perform_admitted_effect(permit)?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.notify")
            .unwrap()
            .effects
            .clear();
    })?;
    assert_eq!(
        world.runtime.execute(&notify, Fault::None)?.status,
        "blocked"
    );
    recovery::abandon(
        &world.runtime,
        &LocalOperator::assert_local("test-operator")?,
        &Request {
            request_id: "late-settle".into(),
            invocation: notify.clone(),
            expected_artifact: world.runtime.artifact().id().into(),
            reason: "preserve late provider result".into(),
        },
    )?;
    simulation.settle_effect(performed)?;
    let db = rusqlite::Connection::open(world.runtime.db())?;
    assert_eq!(
        db.query_row(
            "SELECT status FROM day2_invocations WHERE id=?1",
            [&notify],
            |row| row.get::<_, String>(0)
        )?,
        "failure"
    );
    assert_eq!(db.query_row("SELECT count(*) FROM day2_external_effects WHERE invocation=?1 AND observation IS NOT NULL", [&notify], |row| row.get::<_,i64>(0))?, 1);
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM day2_external_attempts WHERE observation IS NOT NULL",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        1
    );
    Ok(())
}

#[test]
fn reissue_admission_failure_leaves_old_invocation_unresolved() -> Result<()> {
    let (world, id) = blocked_deferral()?;
    let operator = LocalOperator::assert_local("test-operator")?;
    let req = request(&world.runtime, &id, "unauthorized-reissue");
    assert!(recovery::reissue(&world.runtime, &operator, &req).is_err());
    let db = rusqlite::Connection::open(world.runtime.db())?;
    assert_eq!(
        db.query_row(
            "SELECT status FROM day2_invocations WHERE id=?1",
            [&id],
            |row| row.get::<_, String>(0)
        )?,
        "pending"
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM day2_recoveries WHERE invocation=?1",
            [&id],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM day2_invocations WHERE id LIKE 'rcv_%'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    Ok(())
}

#[test]
fn nonblocked_invocation_and_wrong_artifact_are_rejected() -> Result<()> {
    let world = World::artifact("DAY2_TEST_REPORTS_DEFERRALS_ARTIFACT")?;
    world.submit("ordinary", Fault::None)?;
    let operator = LocalOperator::assert_local("test-operator")?;
    let req = request(&world.runtime, "ordinary", "not-blocked");
    assert!(
        recovery::abandon(&world.runtime, &operator, &req)
            .unwrap_err()
            .to_string()
            .contains("recovery_requires_blocked_invocation")
    );
    let (blocked_world, blocked) = blocked_deferral()?;
    let bad = Request {
        expected_artifact: "sha256:wrong".into(),
        ..request(&blocked_world.runtime, &blocked, "wrong-artifact")
    };
    assert!(recovery::abandon(&world.runtime, &operator, &bad).is_err());
    Ok(())
}

/// A notify invocation whose decision committed, driven to `blocked` by removing
/// its effect grant. `before_block` runs after the decision commit and before the
/// policy change, so each test chooses how far the effect got.
fn blocked_notify(
    seed: u8,
    before_block: impl FnOnce(&Simulation, &str) -> Result<()>,
) -> Result<(World, String)> {
    let mut world = World::artifact("DAY2_TEST_REPORTS_ARTIFACT")?;
    let simulation = Simulation::new(world.runtime.clone(), [seed; 32], 100_000)?;
    world.runtime = simulation.runtime().clone();
    world.runtime.initialize()?;
    world.submit("submit", Fault::None)?;
    let analyze = world.child("submit")?;
    world.finish(&analyze)?;
    let notify = world.child(&analyze)?;
    world.runtime.execute(&notify, Fault::None)?;
    before_block(&simulation, &notify)?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.notify")
            .unwrap()
            .effects
            .clear();
    })?;
    assert_eq!(
        world.runtime.execute(&notify, Fault::None)?.status,
        "blocked"
    );
    Ok((world, notify))
}

fn effect_rows(world: &World, invocation: &str) -> Result<i64> {
    let db = rusqlite::Connection::open(world.runtime.db())?;
    Ok(db.query_row(
        "SELECT count(*) FROM day2_external_effects WHERE invocation=?1",
        [invocation],
        |row| row.get(0),
    )?)
}

fn refuses_reissue(world: &World, invocation: &str, request_id: &str) -> Result<()> {
    let error = recovery::reissue(
        &world.runtime,
        &LocalOperator::assert_local("test-operator")?,
        &request(&world.runtime, invocation, request_id),
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("recovery_reissue_requires_uncommitted_invocation"),
        "{error}"
    );
    Ok(())
}

#[test]
fn a_settled_effect_is_classified_as_a_known_result() -> Result<()> {
    let (world, notify) = blocked_notify(43, |simulation, notify| {
        let effect = simulation.claim_effect(notify)?.context("claimed effect")?;
        let performed = simulation.perform_effect(effect)?;
        simulation.settle_effect(performed)
    })?;
    refuses_reissue(&world, &notify, "known-reissue")?;
    let receipt = recovery::abandon(
        &world.runtime,
        &LocalOperator::assert_local("test-operator")?,
        &request(&world.runtime, &notify, "known-abandon"),
    )?;
    assert_eq!(
        (
            receipt.evidence.known_result,
            receipt.evidence.unknown_outcome,
            receipt.evidence.never_admitted
        ),
        (1, 0, 0)
    );
    Ok(())
}

#[test]
fn a_claimed_but_unadmitted_effect_is_classified_as_never_admitted() -> Result<()> {
    let (world, notify) = blocked_notify(44, |simulation, notify| {
        simulation.claim_effect(notify)?.context("claimed effect")?;
        Ok(())
    })?;
    assert_eq!(effect_rows(&world, &notify)?, 1);
    refuses_reissue(&world, &notify, "never-reissue")?;
    let receipt = recovery::abandon(
        &world.runtime,
        &LocalOperator::assert_local("test-operator")?,
        &request(&world.runtime, &notify, "never-abandon"),
    )?;
    assert_eq!(
        (
            receipt.evidence.known_result,
            receipt.evidence.unknown_outcome,
            receipt.evidence.never_admitted
        ),
        (0, 0, 1)
    );
    Ok(())
}

#[test]
fn a_committed_decision_without_effects_cannot_be_reissued() -> Result<()> {
    // The decision committed (execution journal row exists) but no effect was
    // ever claimed, so evidence alone would look empty. Reissue must still refuse:
    // rerunning the decision would repeat committed business writes.
    let (world, notify) = blocked_notify(45, |_, _| Ok(()))?;
    assert_eq!(effect_rows(&world, &notify)?, 0);
    let db = rusqlite::Connection::open(world.runtime.db())?;
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM day2_execution WHERE invocation=?1",
            [&notify],
            |row| row.get::<_, i64>(0)
        )?,
        1
    );
    refuses_reissue(&world, &notify, "decided-reissue")?;
    Ok(())
}
