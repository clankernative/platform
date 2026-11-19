use crate::support::commands::World;
use anyhow::{Context, Result};
use day2::{
    authority_state::LocalOperator,
    invocations,
    recovery::{self, EvidenceSummary, Request},
    simulation::Simulation,
    store::Fault,
};

fn operator() -> Result<LocalOperator> {
    // The Reports policy names `admin` as an administrator.
    LocalOperator::assert_local("admin")
}

fn request(world: &World, invocation: &str, request_id: &str) -> Request {
    Request {
        request_id: request_id.into(),
        invocation: invocation.into(),
        expected_artifact: world.runtime.artifact().id().into(),
        reason: "send stopped by policy review".into(),
    }
}

fn refused(result: Result<recovery::Receipt>, code: &str) {
    let error = format!("{:#}", result.unwrap_err());
    assert!(error.contains(code), "{error}");
}

/// A notify invocation whose decision committed, driven to `blocked` by removing
/// its effect grant. `before_block` runs after the decision commit and before the
/// policy change, so each test chooses how far the effect got.
fn blocked_notify(
    seed: u8,
    before_block: impl FnOnce(&Simulation, &str) -> Result<()>,
) -> Result<(World, Simulation, String)> {
    let mut world = World::new()?;
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
    Ok((world, simulation, notify))
}

fn evidence(receipt: &recovery::Receipt) -> (u32, u32, u32) {
    let EvidenceSummary {
        never_admitted,
        known_result,
        unknown_outcome,
    } = receipt.evidence;
    (never_admitted, known_result, unknown_outcome)
}

fn abandoned(outcome: &day2::protocol::Outcome) -> bool {
    outcome.status == "failure" && outcome.error == "invocation_abandoned"
}

#[test]
fn abandon_finishes_blocked_work_once_and_records_who_and_why() -> Result<()> {
    let (world, _simulation, notify) = blocked_notify(40, |_, _| Ok(()))?;
    let operator = operator()?;
    refused(
        recovery::abandon(
            &world.runtime,
            &LocalOperator::assert_local("bob")?,
            &request(&world, &notify, "not-an-operator"),
        ),
        "recovery_operator_required",
    );
    let first = recovery::abandon(&world.runtime, &operator, &request(&world, &notify, "once"))?;
    assert_eq!(first.invocation, notify);
    assert_eq!(evidence(&first), (0, 0, 0));
    // The same request returns the same receipt and changes nothing.
    assert_eq!(
        recovery::abandon(&world.runtime, &operator, &request(&world, &notify, "once"))?,
        first
    );
    refused(
        recovery::abandon(
            &world.runtime,
            &operator,
            &Request {
                reason: "a different reason".into(),
                ..request(&world, &notify, "once")
            },
        ),
        "recovery_request_conflict",
    );
    refused(
        recovery::abandon(
            &world.runtime,
            &operator,
            &request(&world, &notify, "again"),
        ),
        "recovery_already_resolved",
    );

    let db = rusqlite::Connection::open(world.runtime.db())?;
    let (status, actor): (String, String) = db.query_row(
        "SELECT status,actor FROM day2_invocations WHERE id=?1",
        [&notify],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(status, "failure");
    // The block row stays, but execution reports the abandonment instead of
    // `blocked`, and the pump has nothing to run.
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM day2_authority_blocks WHERE invocation=?1",
            [&notify],
            |row| row.get::<_, i64>(0)
        )?,
        1
    );
    assert!(abandoned(&world.runtime.execute(&notify, Fault::None)?));
    assert!(invocations::drain(&world.runtime, 16)?.is_empty());
    let receipt = invocations::status(&world.runtime, &notify, &actor)?;
    assert_eq!(
        (receipt.status.as_str(), receipt.error.as_str()),
        ("failure", "invocation_abandoned")
    );
    // The abandonment carries no application result.
    assert_eq!(receipt.result, serde_json::json!({}));
    assert_eq!(
        db.query_row(
            "SELECT operator,reason FROM day2_abandonments WHERE invocation=?1",
            [&notify],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        )?,
        ("admin".into(), "send stopped by policy review".into())
    );
    // The audit event names the operator and carries no free-text reason.
    assert_eq!(
        db.query_row(
            "SELECT actor,initiator,operation,outcome,trigger,reason IS NULL FROM day2_audit_events
             WHERE identity=?1 AND kind='recovery'",
            [&notify],
            |row| Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, bool>(5)?
            ))
        )?,
        (
            "admin".into(),
            "admin".into(),
            "reports.notify".into(),
            "abandoned".into(),
            "recovery".into(),
            true
        )
    );
    // Abandonments are append-only, including against INSERT OR REPLACE.
    assert!(db.execute("DELETE FROM day2_abandonments", []).is_err());
    assert!(
        db.execute("UPDATE day2_abandonments SET reason='edited'", [])
            .is_err()
    );
    assert!(
        db.execute(
            "INSERT OR REPLACE INTO day2_abandonments SELECT * FROM day2_abandonments",
            []
        )
        .is_err()
    );
    // The receipt is withheld from an owner whose grant is revoked, like any other.
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.notify")
            .unwrap()
            .actors
            .remove(&actor);
    })?;
    assert!(invocations::status(&world.runtime, &notify, &actor).is_err());
    Ok(())
}

#[test]
fn only_blocked_work_on_the_expected_artifact_can_be_abandoned() -> Result<()> {
    let (world, _simulation, notify) = blocked_notify(41, |_, _| Ok(()))?;
    let operator = operator()?;
    world.submit("ordinary", Fault::None)?;
    refused(
        recovery::abandon(
            &world.runtime,
            &operator,
            &request(&world, "ordinary", "done"),
        ),
        "recovery_requires_blocked_invocation",
    );
    // Runnable pending work is not blocked, so it cannot be abandoned.
    world.runtime.accept(
        "reports.submit",
        "alice",
        "runnable",
        &serde_json::json!({"title":"x","text":"y"}),
        100,
    )?;
    refused(
        recovery::abandon(
            &world.runtime,
            &operator,
            &request(&world, "runnable", "runnable"),
        ),
        "recovery_requires_blocked_invocation",
    );
    refused(
        recovery::abandon(
            &world.runtime,
            &operator,
            &request(&world, "missing", "missing"),
        ),
        "not_found",
    );
    refused(
        recovery::abandon(
            &world.runtime,
            &operator,
            &Request {
                expected_artifact: "sha256:other".into(),
                ..request(&world, &notify, "wrong-artifact")
            },
        ),
        "artifact_binding_changed",
    );
    for reason in ["", "   ", "line\nbreak"] {
        refused(
            recovery::abandon(
                &world.runtime,
                &operator,
                &Request {
                    reason: reason.into(),
                    ..request(&world, &notify, "bad-reason")
                },
            ),
            "invalid_recovery_reason",
        );
    }
    // None of the refusals changed anything.
    let db = rusqlite::Connection::open(world.runtime.db())?;
    assert_eq!(
        db.query_row("SELECT count(*) FROM day2_abandonments", [], |row| row
            .get::<_, i64>(0))?,
        0
    );
    assert_eq!(
        recovery::abandon(
            &world.runtime,
            &operator,
            &request(&world, &notify, "valid")
        )?
        .invocation,
        notify
    );
    Ok(())
}

#[test]
fn a_permit_that_has_not_started_is_refused_and_settles_as_not_dispatched() -> Result<()> {
    let mut permit = None;
    let (world, simulation, notify) = blocked_notify(42, |simulation, notify| {
        let effect = simulation.claim_effect(notify)?.context("claimed effect")?;
        permit = Some(simulation.admit_effect(effect)?);
        Ok(())
    })?;
    let receipt = recovery::abandon(
        &world.runtime,
        &operator()?,
        &request(&world, &notify, "fence"),
    )?;
    // At abandonment the admitted attempt may already be calling the provider.
    assert_eq!(evidence(&receipt), (0, 0, 1));
    let performed = simulation.perform_admitted_effect(permit.context("permit")?);
    let error = format!("{:#}", performed.err().context("permit was fenced")?);
    assert!(error.contains("invocation_abandoned"), "{error}");
    assert!(simulation.snapshot()?["provider"].is_null());
    // The provider was never called: the attempt records that, and its
    // reservation settles with known zero usage instead of staying held.
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let attempt: (String, String) = db.query_row(
        "SELECT identity,json_extract(observation,'$.error') FROM day2_external_attempts
         WHERE effect IN (SELECT identity FROM day2_external_effects WHERE invocation=?1)",
        [&notify],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(attempt.1, "invocation_abandoned");
    assert!(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_budget_settlements WHERE id=?1)
         AND NOT EXISTS(SELECT 1 FROM day2_budget_unknown WHERE id=?1)",
        [&attempt.0],
        |row| row.get::<_, bool>(0)
    )?);
    Ok(())
}

#[test]
fn a_provider_result_arriving_after_abandon_is_recorded_without_completion() -> Result<()> {
    let mut performed = None;
    let (world, simulation, notify) = blocked_notify(43, |simulation, notify| {
        let effect = simulation.claim_effect(notify)?.context("claimed effect")?;
        let permit = simulation.admit_effect(effect)?;
        performed = Some(simulation.perform_admitted_effect(permit)?);
        Ok(())
    })?;
    let receipt = recovery::abandon(
        &world.runtime,
        &operator()?,
        &request(&world, &notify, "late"),
    )?;
    assert_eq!(evidence(&receipt), (0, 0, 1));
    simulation.settle_effect(performed.context("performed")?)?;
    let db = rusqlite::Connection::open(world.runtime.db())?;
    assert_eq!(
        db.query_row(
            "SELECT status FROM day2_invocations WHERE id=?1",
            [&notify],
            |row| row.get::<_, String>(0)
        )?,
        "failure"
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM day2_external_effects WHERE invocation=?1 AND observation IS NOT NULL",
            [&notify],
            |row| row.get::<_, i64>(0)
        )?,
        1
    );
    assert!(abandoned(&world.runtime.execute(&notify, Fault::None)?));
    Ok(())
}

#[test]
fn abandon_reports_settled_and_never_admitted_effects() -> Result<()> {
    let (world, _simulation, settled) = blocked_notify(44, |simulation, notify| {
        let effect = simulation.claim_effect(notify)?.context("claimed effect")?;
        let performed = simulation.perform_effect(effect)?;
        simulation.settle_effect(performed)
    })?;
    let receipt = recovery::abandon(
        &world.runtime,
        &operator()?,
        &request(&world, &settled, "known"),
    )?;
    assert_eq!(evidence(&receipt), (0, 1, 0));

    let (world, _simulation, claimed) = blocked_notify(45, |simulation, notify| {
        simulation.claim_effect(notify)?.context("claimed effect")?;
        Ok(())
    })?;
    let receipt = recovery::abandon(
        &world.runtime,
        &operator()?,
        &request(&world, &claimed, "never"),
    )?;
    assert_eq!(evidence(&receipt), (1, 0, 0));
    Ok(())
}
