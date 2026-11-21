use crate::support::commands::World;
use anyhow::{Context, Result};
use day2::{
    authority_state::LocalOperator,
    invocations,
    recovery::{self, Cause, EvidenceSummary, Request},
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

/// One request, as most of these tests make.
fn abandon_one(
    runtime: &day2::store::Runtime,
    operator: &LocalOperator,
    request: &Request,
) -> Result<recovery::Receipt> {
    let mut receipts = recovery::abandon(runtime, operator, std::slice::from_ref(request))?;
    assert_eq!(receipts.len(), 1);
    Ok(receipts.remove(0))
}

fn refused<T: std::fmt::Debug>(result: Result<T>, code: &str) {
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
        abandon_one(
            &world.runtime,
            &LocalOperator::assert_local("bob")?,
            &request(&world, &notify, "not-an-operator"),
        ),
        "recovery_operator_required",
    );
    let first = abandon_one(&world.runtime, &operator, &request(&world, &notify, "once"))?;
    assert_eq!(first.invocation, notify);
    assert_eq!(evidence(&first), (0, 0, 0));
    // The same request returns the same receipt and changes nothing.
    assert_eq!(
        abandon_one(&world.runtime, &operator, &request(&world, &notify, "once"))?,
        first
    );
    refused(
        abandon_one(
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
        abandon_one(
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
        abandon_one(
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
        abandon_one(
            &world.runtime,
            &operator,
            &request(&world, "runnable", "runnable"),
        ),
        "recovery_requires_blocked_invocation",
    );
    refused(
        abandon_one(
            &world.runtime,
            &operator,
            &request(&world, "missing", "missing"),
        ),
        "not_found",
    );
    refused(
        abandon_one(
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
            abandon_one(
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
        abandon_one(
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
    let receipt = abandon_one(
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
    let receipt = abandon_one(
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
    let receipt = abandon_one(
        &world.runtime,
        &operator()?,
        &request(&world, &settled, "known"),
    )?;
    assert_eq!(evidence(&receipt), (0, 1, 0));

    let (world, _simulation, claimed) = blocked_notify(45, |simulation, notify| {
        simulation.claim_effect(notify)?.context("claimed effect")?;
        Ok(())
    })?;
    let receipt = abandon_one(
        &world.runtime,
        &operator()?,
        &request(&world, &claimed, "never"),
    )?;
    assert_eq!(evidence(&receipt), (1, 0, 0));
    Ok(())
}

/// What every `day2-serve` holds on its store while it runs.
fn serving_lease(world: &World) -> Result<std::fs::File> {
    let lease = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(
            world
                .runtime
                .db()
                .parent()
                .context("store directory")?
                .join("reports.serve.lock"),
        )?;
    lease.try_lock_shared()?;
    Ok(lease)
}

fn pending(world: &World) -> Result<i64> {
    Ok(rusqlite::Connection::open(world.runtime.db())?.query_row(
        "SELECT count(*) FROM day2_invocations WHERE status='pending'",
        [],
        |row| row.get(0),
    )?)
}

fn abandonments(world: &World) -> Result<i64> {
    Ok(rusqlite::Connection::open(world.runtime.db())?.query_row(
        "SELECT count(*) FROM day2_abandonments",
        [],
        |row| row.get(0),
    )?)
}

/// A query a direct request admitted, cut off before it ran. The scheduler of
/// an ordinary non-rolling store never resumes a query.
fn interrupted_read(world: &World, id: &str) -> Result<()> {
    world.runtime.accept(
        "reports.list",
        "alice",
        id,
        &serde_json::json!({"after":"","limit":2}),
        100,
    )
}

#[test]
fn an_operator_leaves_orphaned_requests_to_a_migration() -> Result<()> {
    let world = World::new()?;
    let operator = operator()?;
    interrupted_read(&world, "orphan")?;
    // An orphaned request is not blocked, so an operator's request is refused,
    // with no server holding the store, and changes nothing.
    refused(
        abandon_one(
            &world.runtime,
            &operator,
            &request(&world, "orphan", "cut-off"),
        ),
        "recovery_requires_blocked_invocation",
    );
    assert_eq!((pending(&world)?, abandonments(&world)?), (1, 0));
    // An operator's request names no cause: blocked is the only one it may abandon.
    let error = serde_json::from_value::<Request>(serde_json::json!({
        "request_id": "cut-off", "invocation": "orphan",
        "expected_artifact": world.runtime.artifact().id(),
        "reason": "request cut off when maintenance stopped the app",
        "cause": "orphaned_request",
    }))
    .unwrap_err();
    assert!(
        error.to_string().contains("unknown field `cause`"),
        "{error}"
    );
    // The next migration abandons it.
    assert_eq!(
        ids(&migrate(&world)?),
        vec![("orphan", Cause::OrphanedRequest)]
    );
    assert_eq!((pending(&world)?, abandonments(&world)?), (0, 1));
    Ok(())
}

#[test]
fn a_list_is_abandoned_all_or_nothing_and_checked_before_any_change() -> Result<()> {
    // Reads cut off before the policy change that blocks the notify are blocked
    // with it.
    let (world, _simulation, notify) = blocked_notify(43, |simulation, _| {
        for id in ["first-read", "second-read"] {
            simulation.runtime().accept(
                "reports.list",
                "alice",
                id,
                &serde_json::json!({"after":"","limit":2}),
                100,
            )?;
        }
        Ok(())
    })?;
    let operator = operator()?;
    world.runtime.accept(
        "reports.submit",
        "alice",
        "accepted-command",
        &serde_json::json!({"title":"x","text":"y"}),
        100,
    )?;
    let before = pending(&world)?;
    // One ineligible item refuses the list, and the others stay pending.
    refused(
        recovery::abandon(
            &world.runtime,
            &operator,
            &[
                request(&world, "first-read", "first"),
                request(&world, "accepted-command", "command"),
            ],
        ),
        "recovery_requires_blocked_invocation",
    );
    assert_eq!((pending(&world)?, abandonments(&world)?), (before, 0));
    for (requests, code) in [
        (Vec::new(), "recovery_requests_count"),
        (
            vec![request(&world, "first-read", "first"); recovery::MAX_REQUESTS + 1],
            "recovery_requests_count",
        ),
        (
            vec![
                request(&world, "first-read", "first"),
                request(&world, "first-read", "again"),
            ],
            "recovery_request_duplicate",
        ),
        (
            vec![
                request(&world, "first-read", "same-key"),
                request(&world, "second-read", "same-key"),
            ],
            "recovery_request_duplicate",
        ),
    ] {
        refused(
            recovery::abandon(&world.runtime, &operator, &requests),
            code,
        );
    }
    // Every listed invocation in one transaction.
    let receipts = recovery::abandon(
        &world.runtime,
        &operator,
        &[
            request(&world, "first-read", "first"),
            request(&world, "second-read", "second"),
            request(&world, &notify, "notify"),
        ],
    )?;
    assert_eq!(
        ids(&receipts),
        vec![
            ("first-read", Cause::Blocked),
            ("second-read", Cause::Blocked),
            (notify.as_str(), Cause::Blocked),
        ]
    );
    // Only the accepted command remains pending, for the scheduler.
    assert_eq!(pending(&world)?, 1);
    Ok(())
}

/// One migration of the store onto its own artifact, as each activation runs,
/// under `operator`.
fn migrate_as(world: &World, operator: &LocalOperator) -> Result<Vec<recovery::Receipt>> {
    let plan = day2::migration::plan(&world.runtime, world.runtime.artifact())?;
    day2::migration::apply(&world.runtime, world.runtime.artifact(), &plan, operator)
}

fn migrate(world: &World) -> Result<Vec<recovery::Receipt>> {
    migrate_as(world, &operator()?)
}

fn ids(receipts: &[recovery::Receipt]) -> Vec<(&str, Cause)> {
    receipts
        .iter()
        .map(|receipt| (receipt.invocation.as_str(), receipt.cause))
        .collect()
}

#[test]
fn a_migration_abandons_its_orphaned_requests_once_nothing_else_is_runnable() -> Result<()> {
    let world = World::new()?;
    interrupted_read(&world, "first-read")?;
    interrupted_read(&world, "second-read")?;
    world.runtime.accept(
        "reports.submit",
        "alice",
        "accepted-command",
        &serde_json::json!({"title":"x","text":"y"}),
        100,
    )?;
    // Work the scheduler finishes must drain first. The refusal changes nothing,
    // so the reads stay pending beside the command.
    let before = world.runtime.inspect()?;
    refused(migrate(&world), "migration_requires_drained_invocations");
    assert_eq!(world.runtime.inspect()?, before);
    assert_eq!((pending(&world)?, abandonments(&world)?), (3, 0));
    // The scheduler finishes the command and the commands it requests, never a read.
    assert!(
        invocations::drain(&world.runtime, 16)?
            .iter()
            .all(|item| item.status == "success")
    );
    assert_eq!(pending(&world)?, 2);
    // While a server holds the store, its requests may still be running.
    let lease = serving_lease(&world)?;
    refused(migrate(&world), "another server owns this SQLite app");
    drop(lease);
    // Abandoning needs an instance operator or a policy administrator.
    refused(
        migrate_as(&world, &LocalOperator::assert_local("bob")?),
        "recovery_operator_required",
    );
    assert_eq!((pending(&world)?, abandonments(&world)?), (2, 0));

    let receipts = migrate(&world)?;
    assert_eq!(
        ids(&receipts),
        vec![
            ("first-read", Cause::OrphanedRequest),
            ("second-read", Cause::OrphanedRequest),
        ]
    );
    assert!(
        receipts
            .iter()
            .all(|receipt| evidence(receipt) == (0, 0, 0) && receipt.children.is_empty())
    );
    assert_eq!((pending(&world)?, abandonments(&world)?), (0, 2));
    assert!(abandoned(
        &world.runtime.execute("first-read", Fault::None)?
    ));
    let status = invocations::status(&world.runtime, "second-read", "alice")?;
    assert_eq!(
        (status.status.as_str(), status.error.as_str()),
        ("failure", "invocation_abandoned")
    );
    // Recorded under the migration's operator, marked as the migration's own.
    let db = rusqlite::Connection::open(world.runtime.db())?;
    assert_eq!(
        db.query_row(
            "SELECT request_id,operator,reason,json_extract(receipt,'$.cause'),
                json_extract(payload,'$[1]')
             FROM day2_abandonments WHERE invocation='first-read'",
            [],
            |row| Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        )?,
        (
            "migration:first-read".into(),
            "admin".into(),
            "no server held the store when a migration began, so nothing will finish this request"
                .into(),
            "orphaned_request".into(),
            "admin".into(),
        )
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM day2_audit_events
             WHERE kind='recovery' AND outcome='abandoned' AND actor='admin'
             AND operation='reports.list'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        2
    );
    // Replaying the recorded migration still abandons a request orphaned since,
    // and commits it although the schema is already current.
    assert!(migrate(&world)?.is_empty());
    interrupted_read(&world, "late-read")?;
    assert_eq!(
        ids(&migrate(&world)?),
        vec![("late-read", Cause::OrphanedRequest)]
    );
    assert_eq!((pending(&world)?, abandonments(&world)?), (0, 3));
    day2::migration::activate(&world.runtime, world.runtime.artifact())?;
    // An operator's request for an invocation the migration abandoned is
    // refused, and operator requests cannot take the migration's keys.
    refused(
        abandon_one(
            &world.runtime,
            &operator()?,
            &request(&world, "late-read", "too-late"),
        ),
        "recovery_already_resolved",
    );
    refused(
        abandon_one(
            &world.runtime,
            &operator()?,
            &request(&world, "late-read", "migration:late-read"),
        ),
        "invalid_recovery_request_id",
    );
    Ok(())
}

#[test]
fn a_migration_abandons_only_direct_requests_and_nothing_when_it_fails() -> Result<()> {
    let world = World::new()?;
    // A read another app asked for on the actor's behalf: no direct request
    // admitted it, so the migration leaves it, and its drain check refuses.
    interrupted_read(&world, "delegated-read")?;
    let db = rusqlite::Connection::open(world.runtime.db())?;
    db.execute(
        "UPDATE day2_invocations SET trigger='delegated' WHERE id='delegated-read'",
        [],
    )?;
    refused(migrate(&world), "migration_requires_drained_invocations");
    assert_eq!((pending(&world)?, abandonments(&world)?), (1, 0));
    db.execute(
        "UPDATE day2_invocations SET status='success' WHERE id='delegated-read'",
        [],
    )?;
    // A migration that fails after deciding abandons nothing: a stale plan
    // rolls the abandonment back with it.
    interrupted_read(&world, "cut-off-read")?;
    let schema: String = db.query_row(
        "SELECT value FROM day2_meta WHERE key='schema'",
        [],
        |row| row.get(0),
    )?;
    db.execute(
        "UPDATE day2_meta SET value='sha256:elsewhere' WHERE key='schema'",
        [],
    )?;
    refused(migrate(&world), "stale_migration_plan");
    assert_eq!((pending(&world)?, abandonments(&world)?), (1, 0));
    db.execute(
        "UPDATE day2_meta SET value=?1 WHERE key='schema'",
        [&schema],
    )?;
    assert_eq!(
        ids(&migrate(&world)?),
        vec![("cut-off-read", Cause::OrphanedRequest)]
    );
    Ok(())
}

#[test]
fn a_migration_leaves_blocked_work_to_an_operator() -> Result<()> {
    // A read cut off before the policy change that blocks the notify is blocked
    // with it.
    let (world, _simulation, notify) = blocked_notify(44, |simulation, _| {
        simulation.runtime().accept(
            "reports.list",
            "alice",
            "blocked-read",
            &serde_json::json!({"after":"","limit":2}),
            100,
        )
    })?;
    interrupted_read(&world, "cut-off-read")?;
    let blocked = |invocation: &str| -> Result<bool> {
        Ok(rusqlite::Connection::open(world.runtime.db())?.query_row(
            "SELECT EXISTS(SELECT 1 FROM day2_authority_blocks WHERE invocation=?1)",
            [invocation],
            |row| row.get(0),
        )?)
    };
    assert!(blocked(&notify)? && blocked("blocked-read")? && !blocked("cut-off-read")?);
    // A block never refuses a migration, and it is for an operator to judge,
    // even for a request: only the unblocked read is abandoned.
    assert_eq!(
        ids(&migrate(&world)?),
        vec![("cut-off-read", Cause::OrphanedRequest)]
    );
    assert_eq!((pending(&world)?, abandonments(&world)?), (2, 1));
    assert_eq!(
        world.runtime.execute(&notify, Fault::None)?.status,
        "blocked"
    );
    assert_eq!(
        ids(&recovery::abandon(
            &world.runtime,
            &operator()?,
            &[
                request(&world, &notify, "notify-as-blocked"),
                request(&world, "blocked-read", "read-as-blocked"),
            ],
        )?),
        vec![
            (notify.as_str(), Cause::Blocked),
            ("blocked-read", Cause::Blocked)
        ]
    );
    Ok(())
}
