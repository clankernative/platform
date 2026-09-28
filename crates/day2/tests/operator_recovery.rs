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
        expected_revision: 0,
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
        expected_revision: 0,
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
            expected_revision: 0,
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
            expected_revision: 0,
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
fn readmit_reuses_known_result_and_completes_without_resending_provider_effect() -> Result<()> {
    let (world, notify) = blocked_notify_by_unrelated_policy_change(51, |simulation, notify| {
        let effect = simulation.claim_effect(notify)?.context("claimed effect")?;
        simulation.settle_effect(simulation.perform_effect(effect)?)
    })?;
    let operator = LocalOperator::assert_local("test-operator")?;
    let receipt = recovery::readmit(
        &world.runtime,
        &operator,
        &request(&world.runtime, &notify, "known-readmit"),
    )?;
    assert_eq!(
        (receipt.resolution.as_str(), receipt.revision),
        ("readmitted", 1)
    );
    let drained = invocations::drain(&world.runtime, 16)?;
    assert!(
        drained
            .iter()
            .any(|row| row.id == notify && row.status == "success")
    );
    let status = invocations::status(&world.runtime, &notify, "alice")?;
    assert_eq!(status.resolution.as_deref(), Some("readmitted"));
    assert_eq!(status.revision, Some(1));
    assert_eq!(status.status, "success");
    let trace = world.runtime.trace(&notify)?;
    day2::store::replay(world.runtime.artifact(), &trace)?;
    let db = rusqlite::Connection::open(world.runtime.db())?;
    assert_eq!(db.query_row("SELECT count(*) FROM day2_external_attempts WHERE effect IN (SELECT identity FROM day2_external_effects WHERE invocation=?1)", [&notify], |row| row.get::<_, i64>(0))?, 1);
    let provider =
        rusqlite::Connection::open(world.runtime.db().with_file_name("notifications.sqlite"))?;
    let state: String = provider.query_row(
        "SELECT state FROM notification_world WHERE id=1",
        [],
        |row| row.get(0),
    )?;
    let accepted: serde_json::Value = serde_json::from_str(&state)?;
    assert_eq!(
        accepted["order"]
            .as_array()
            .context("provider order")?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn readmit_retries_unknown_mailbox_outcome_with_the_same_effect_identity() -> Result<()> {
    let mut world = World::artifact("DAY2_TEST_REPORTS_ARTIFACT")?;
    let simulation = Simulation::new(world.runtime.clone(), [52; 32], 100_000)?;
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
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let identity: String = db.query_row(
        "SELECT identity FROM day2_external_effects WHERE invocation=?1",
        [&notify],
        |row| row.get(0),
    )?;
    let performed = simulation.perform_effect(effect)?;
    drop(performed);
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.detail")
            .unwrap()
            .actors
            .insert("reviewer".into());
    })?;
    assert_eq!(
        world.runtime.execute(&notify, Fault::None)?.status,
        "blocked"
    );
    let operator = LocalOperator::assert_local("test-operator")?;
    recovery::readmit(
        &world.runtime,
        &operator,
        &request(&world.runtime, &notify, "unknown-readmit"),
    )?;
    let drained = invocations::drain(&world.runtime, 16)?;
    assert!(
        drained
            .iter()
            .any(|row| row.id == notify && row.status == "success")
    );
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let effects: (i64, i64, String) = db.query_row(
        "SELECT count(*),count(DISTINCT identity),min(identity) FROM day2_external_effects WHERE invocation=?1",
        [&notify],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(effects, (1, 1, identity.clone()));
    let attempts: i64 = db.query_row(
        "SELECT count(*) FROM day2_external_attempts WHERE effect=?1",
        [&identity],
        |row| row.get(0),
    )?;
    assert_eq!(attempts, 2);
    let provider =
        rusqlite::Connection::open(world.runtime.db().with_file_name("notifications.sqlite"))?;
    let state: String = provider.query_row(
        "SELECT state FROM notification_world WHERE id=1",
        [],
        |row| row.get(0),
    )?;
    let accepted: serde_json::Value = serde_json::from_str(&state)?;
    assert_eq!(
        accepted["order"]
            .as_array()
            .context("provider order")?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn readmit_dispatches_a_never_admitted_effect_once() -> Result<()> {
    let (world, notify) = blocked_notify_by_unrelated_policy_change(53, |simulation, notify| {
        simulation.claim_effect(notify)?.context("claimed effect")?;
        Ok(())
    })?;
    let operator = LocalOperator::assert_local("test-operator")?;
    let receipt = recovery::readmit(
        &world.runtime,
        &operator,
        &request(&world.runtime, &notify, "never-readmit"),
    )?;
    assert_eq!(receipt.evidence.never_admitted, 1);
    assert!(
        invocations::drain(&world.runtime, 16)?
            .iter()
            .any(|row| row.id == notify && row.status == "success")
    );
    let db = rusqlite::Connection::open(world.runtime.db())?;
    assert_eq!(db.query_row("SELECT count(*) FROM day2_external_attempts WHERE effect IN (SELECT identity FROM day2_external_effects WHERE invocation=?1)", [&notify], |row| row.get::<_, i64>(0))?, 1);
    Ok(())
}

#[test]
fn repeated_readmission_rechecks_authority_and_revision_and_terminal_abandon_wins() -> Result<()> {
    let (world, id) = blocked_notify_by_unrelated_policy_change(54, |simulation, notify| {
        let effect = simulation.claim_effect(notify)?.context("claimed effect")?;
        simulation.settle_effect(simulation.perform_effect(effect)?)
    })?;
    let operator = LocalOperator::assert_local("test-operator")?;
    recovery::readmit(
        &world.runtime,
        &operator,
        &request(&world.runtime, &id, "readmit-one"),
    )?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.detail")
            .unwrap()
            .actors
            .insert("second_reviewer".into());
    })?;
    assert_eq!(world.runtime.execute(&id, Fault::None)?.status, "blocked");
    let stale = Request {
        expected_revision: 0,
        request_id: "stale-revision".into(),
        ..request(&world.runtime, &id, "unused")
    };
    assert!(
        recovery::readmit(&world.runtime, &operator, &stale)
            .unwrap_err()
            .to_string()
            .contains("recovery_revision_conflict")
    );
    let second = Request {
        expected_revision: 1,
        request_id: "readmit-two".into(),
        ..request(&world.runtime, &id, "unused")
    };
    let receipt = recovery::readmit(&world.runtime, &operator, &second)?;
    assert_eq!(receipt.revision, 2);
    assert!(
        invocations::drain(&world.runtime, 16)?
            .iter()
            .any(|row| row.id == id && row.status == "success")
    );
    Ok(())
}

#[test]
fn readmit_refuses_actor_no_longer_authorized_without_mutating_block_or_recovery() -> Result<()> {
    let (world, id) = blocked_deferral()?;
    let request = request(&world.runtime, &id, "unauthorized-readmit");
    assert!(
        recovery::readmit(
            &world.runtime,
            &LocalOperator::assert_local("test-operator")?,
            &request
        )
        .is_err()
    );
    let db = rusqlite::Connection::open(world.runtime.db())?;
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
            "SELECT count(*) FROM day2_authority_blocks WHERE invocation=?1",
            [&id],
            |row| row.get::<_, i64>(0)
        )?,
        1
    );
    Ok(())
}

#[test]
fn abandon_accepts_blocked_invocation_from_previous_artifact() -> Result<()> {
    let (world, id) = blocked_notify(55, |_, _| Ok(()))?;
    let old_artifact = world.runtime.artifact().id().to_owned();
    let target_path = std::env::var("DAY2_TEST_REPORTS_DEFERRALS_ARTIFACT")?;
    let target = day2::artifact::LoadedArtifact::load(std::path::Path::new(&target_path))?;
    let active = day2::authority_state::current(&rusqlite::Connection::open(world.runtime.db())?)?;
    day2::migration::activate_checked(
        &world.runtime,
        &target,
        &LocalOperator::assert_local("test-operator")?,
        &active.stamp,
        "activate-before-old-abandon",
    )?;
    let active_runtime = day2::store::Runtime::load(world.runtime.instance_path(), "reports")?;
    let request = Request {
        request_id: "abandon-old-artifact".into(),
        invocation: id.clone(),
        expected_artifact: old_artifact,
        expected_revision: 0,
        reason: "old artifact work must remain abandonable".into(),
    };
    let receipt = recovery::abandon(
        &active_runtime,
        &LocalOperator::assert_local("test-operator")?,
        &request,
    )?;
    assert_eq!(receipt.resolution, "abandoned");
    assert_eq!(
        invocations::status(&active_runtime, &id, "alice")?
            .resolution
            .as_deref(),
        Some("abandoned")
    );
    Ok(())
}

#[test]
fn readmit_then_terminal_abandon_is_final() -> Result<()> {
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
    recovery::readmit(
        &world.runtime,
        &operator,
        &request(&world.runtime, &id, "readmit-before-abandon"),
    )?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.detail")
            .unwrap()
            .actors
            .insert("reviewer".into());
    })?;
    assert_eq!(world.runtime.execute(&id, Fault::None)?.status, "blocked");
    let abandon = Request {
        expected_revision: 1,
        request_id: "terminal-abandon".into(),
        ..request(&world.runtime, &id, "unused")
    };
    assert_eq!(
        recovery::abandon(&world.runtime, &operator, &abandon)?.resolution,
        "abandoned"
    );
    let later = Request {
        expected_revision: 2,
        request_id: "after-terminal".into(),
        ..request(&world.runtime, &id, "unused")
    };
    assert!(
        recovery::readmit(&world.runtime, &operator, &later)
            .unwrap_err()
            .to_string()
            .contains("recovery_already_resolved")
    );
    Ok(())
}

#[test]
fn readmit_refreshes_command_child_policy_but_preserves_target_version_fence() -> Result<()> {
    let world = World::new()?;
    let saved = world.submit("submit", Fault::None)?;
    let child = world.child("submit")?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.detail")
            .unwrap()
            .actors
            .insert("reviewer".into());
    })?;
    assert_eq!(
        world.runtime.execute(&child, Fault::None)?.status,
        "blocked"
    );
    let receipt = recovery::readmit(
        &world.runtime,
        &LocalOperator::assert_local("test-operator")?,
        &request(&world.runtime, &child, "child-policy-readmit"),
    )?;
    assert_eq!(receipt.resolution, "readmitted");
    assert!(
        invocations::drain(&world.runtime, 16)?
            .iter()
            .any(|row| row.id == child && row.status == "success")
    );
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let captured: String = db.query_row(
        "SELECT policy FROM day2_command_requests WHERE id=?1",
        [&child],
        |row| row.get(0),
    )?;
    let active = day2::authority_state::current(&db)?;
    assert_eq!(
        serde_json::from_str::<day2::authority::Policy>(&captured)?,
        active.policy()?.clone()
    );
    assert!(
        world.runtime.inspect()?["reports"]
            .as_array()
            .context("reports")?
            .iter()
            .any(|row| row["id"] == saved.result["id"])
    );

    let world = World::new()?;
    let saved = world.submit("submit", Fault::None)?;
    let child = world.child("submit")?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.detail")
            .unwrap()
            .actors
            .insert("reviewer".into());
    })?;
    assert_eq!(
        world.runtime.execute(&child, Fault::None)?.status,
        "blocked"
    );
    world.runtime.invoke(
        "reports.revise",
        "alice",
        "edit-child-target",
        &json!({"report_id":saved.result["id"],"expected_version":1,"text":"changed"}),
        101,
        Fault::None,
    )?;
    let before: String = rusqlite::Connection::open(world.runtime.db())?.query_row(
        "SELECT policy FROM day2_command_requests WHERE id=?1",
        [&child],
        |row| row.get(0),
    )?;
    let failed = recovery::readmit(
        &world.runtime,
        &LocalOperator::assert_local("test-operator")?,
        &request(&world.runtime, &child, "changed-target-readmit"),
    );
    assert!(failed.unwrap_err().to_string().contains("conflict"));
    let db = rusqlite::Connection::open(world.runtime.db())?;
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM day2_recoveries WHERE invocation=?1",
            [&child],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(
        db.query_row(
            "SELECT policy FROM day2_command_requests WHERE id=?1",
            [&child],
            |row| row.get::<_, String>(0)
        )?,
        before
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM day2_authority_blocks WHERE invocation=?1",
            [&child],
            |row| row.get::<_, i64>(0)
        )?,
        1
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

fn blocked_notify_by_unrelated_policy_change(
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
            .get_mut("reports.detail")
            .unwrap()
            .actors
            .insert("reviewer".into());
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

#[test]
fn readmit_refuses_an_unknown_outcome_on_a_non_deduplicating_capability() -> Result<()> {
    let (world, notify) = blocked_notify_by_unrelated_policy_change(53, |simulation, notify| {
        let effect = simulation.claim_effect(notify)?.context("claimed effect")?;
        // Performed but never settled: the host does not know the outcome.
        drop(simulation.perform_effect(effect)?);
        Ok(())
    })?;
    let db = rusqlite::Connection::open(world.runtime.db())?;
    // Public fixtures only reach the deduplicating mailbox. Record the same
    // unknown outcome as if a capability without deduplication had produced it.
    assert_eq!(
        db.execute(
            "UPDATE day2_external_effects SET instruction=json_set(instruction,'$.model','slack.post.v1') WHERE invocation=?1",
            [&notify],
        )?,
        1
    );
    let error = recovery::readmit(
        &world.runtime,
        &LocalOperator::assert_local("test-operator")?,
        &request(&world.runtime, &notify, "unknown-slack-readmit"),
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("recovery_readmit_requires_known_outcomes"),
        "{error}"
    );
    let unchanged: (String, i64, i64) = db.query_row(
        "SELECT i.status,
                (SELECT count(*) FROM day2_authority_blocks WHERE invocation=i.id),
                (SELECT count(*) FROM day2_recoveries WHERE invocation=i.id)
         FROM day2_invocations i WHERE i.id=?1",
        [&notify],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(unchanged, ("pending".into(), 1, 0));
    Ok(())
}
