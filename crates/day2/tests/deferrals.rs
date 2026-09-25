#[path = "support/commands.rs"]
mod support;
use anyhow::{Context, Result};
use day2::{
    authority_state, deferrals, invocations,
    store::{Fault, Runtime},
};
use serde_json::json;
use support::World;

fn world() -> Result<World> {
    World::artifact("DAY2_TEST_REPORTS_DEFERRALS_ARTIFACT")
}

fn submit(world: &World, id: &str, title: &str, fault: Fault) -> Result<day2::protocol::Outcome> {
    world.runtime.invoke(
        "reports.submit",
        "alice",
        id,
        &json!({"title":title,"text":"first line\nsecond line"}),
        100,
        fault,
    )
}

fn count(world: &World, sql: &str, id: &str) -> Result<i64> {
    let connection = rusqlite::Connection::open(world.runtime.db())?;
    Ok(connection.query_row(sql, [id], |row| row.get(0))?)
}

fn deferral_id(world: &World, parent: &str) -> Result<String> {
    let connection = rusqlite::Connection::open(world.runtime.db())?;
    Ok(connection.query_row(
        "SELECT id FROM day2_deferrals WHERE parent=?1",
        [parent],
        |row| row.get(0),
    )?)
}

#[test]
fn deferral_commits_with_parent_and_rejected_parent_leaves_no_deferral() -> Result<()> {
    let world = world()?;
    let accepted = submit(&world, "defer-atomic", "defer", Fault::None)?;
    assert_eq!(accepted.status, "success", "{}", accepted.error);
    let id = deferral_id(&world, "defer-atomic")?;
    assert!(id.starts_with("dfr_"));
    let expected_id = format!(
        "dfr_{}",
        &day2::digest(format!("{}\n{}\n0", world.runtime.scope(), "defer-atomic").as_bytes())[7..]
    );
    assert_eq!(id, expected_id);
    assert_eq!(
        count(
            &world,
            "SELECT count(*) FROM day2_invocations WHERE id=?1",
            &id
        )?,
        0
    );
    assert_eq!(
        invocations::status(&world.runtime, "defer-atomic", "alice")?.children[0].status,
        "deferred"
    );

    let rejected = submit(
        &world,
        "defer-rejected",
        "defer-rejected",
        Fault::FailAfterWrite(2),
    )?;
    assert_eq!(rejected.status, "failure");
    assert_eq!(
        count(
            &world,
            "SELECT count(*) FROM day2_deferrals WHERE parent=?1",
            "defer-rejected"
        )?,
        0
    );
    assert_eq!(
        count(
            &world,
            "SELECT count(*) FROM reports WHERE title=?1",
            "defer-rejected"
        )?,
        0
    );
    Ok(())
}

#[test]
fn due_deferrals_offer_once_across_ticks_and_runtime_reload() -> Result<()> {
    let world = world()?;
    submit(&world, "defer-once", "defer", Fault::None)?;
    let id = deferral_id(&world, "defer-once")?;
    assert!(deferrals::tick(&world.runtime, 109_999)?.is_empty());
    assert_eq!(
        count(
            &world,
            "SELECT count(*) FROM day2_invocations WHERE id=?1",
            &id
        )?,
        0
    );

    let first = deferrals::tick(&world.runtime, 110_000)?;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].outcome, "admitted");
    assert_eq!(
        count(
            &world,
            "SELECT count(*) FROM day2_deferrals WHERE id=?1 AND offered_ms=110000",
            &id
        )?,
        1
    );
    let second = deferrals::tick(&world.runtime, 110_000)?;
    assert!(second.is_empty());
    let restarted = Runtime::load(world.runtime.instance_path(), "reports")?;
    assert!(deferrals::tick(&restarted, 120_000)?.is_empty());
    assert_eq!(
        count(
            &world,
            "SELECT count(*) FROM day2_invocations WHERE id=?1",
            &id
        )?,
        1
    );
    Ok(())
}

#[test]
fn waiting_deferral_survives_policy_change_and_runs_on_current_stamp() -> Result<()> {
    let world = world()?;
    let parent = submit(&world, "defer-policy", "defer", Fault::None)?;
    let report_id = parent.result["id"]
        .as_str()
        .context("report id")?
        .to_owned();
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.detail")
            .unwrap()
            .actors
            .insert("new_reader".into());
    })?;
    let id = deferral_id(&world, "defer-policy")?;
    assert_eq!(
        deferrals::tick(&world.runtime, 110_000)?[0].outcome,
        "admitted"
    );
    let connection = rusqlite::Connection::open(world.runtime.db())?;
    let active = authority_state::current(&connection)?;
    let pinned: (String, i64) = connection.query_row(
        "SELECT epoch,revision FROM day2_invocation_authority WHERE invocation=?1",
        [&id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(
        pinned,
        (active.stamp.epoch, i64::try_from(active.stamp.revision)?)
    );

    let drained = invocations::drain(&world.runtime, 64)?;
    assert!(
        drained
            .iter()
            .any(|invocation| invocation.id == id && invocation.status == "success")
    );
    let inspection = world.runtime.inspect()?;
    let report = inspection["reports"]
        .as_array()
        .context("reports")?
        .iter()
        .find(|row| row["id"] == report_id)
        .context("deferred analysis report")?;
    let report_data: serde_json::Value =
        serde_json::from_str(report["data"].as_str().context("report data")?)?;
    assert_eq!(report_data["ready"], true);
    Ok(())
}

#[test]
fn revoked_actor_is_blocked_at_offer_and_does_not_block_activation_or_drain() -> Result<()> {
    let world = world()?;
    submit(&world, "defer-revoked", "defer", Fault::None)?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.analyze")
            .unwrap()
            .actors
            .remove("alice");
    })?;
    let id = deferral_id(&world, "defer-revoked")?;
    let offered = deferrals::tick(&world.runtime, 110_000)?;
    assert_eq!(offered.len(), 1);
    assert_eq!(offered[0].outcome, "blocked");
    assert_eq!(offered[0].reason, "deferral_forbidden");
    let connection = rusqlite::Connection::open(world.runtime.db())?;
    assert_eq!(
        connection.query_row(
            "SELECT reason FROM day2_authority_blocks WHERE invocation=?1",
            [&id],
            |row| row.get::<_, String>(0)
        )?,
        "deferral_forbidden"
    );
    let active = authority_state::current(&connection)?;
    day2::migration::activate_checked(
        &world.runtime,
        world.runtime.artifact(),
        &authority_state::LocalOperator::assert_local("test-operator")?,
        &active.stamp,
        "activate-after-deferral-block",
    )?;
    assert!(
        invocations::drain(&world.runtime, 64)?
            .iter()
            .all(|item| item.id != id)
    );
    assert_eq!(
        invocations::children(&world.runtime, "defer-revoked")?[0].status,
        "blocked"
    );
    Ok(())
}

#[test]
fn activation_rejects_an_unoffered_deferral_with_incompatible_command() -> Result<()> {
    let world = world()?;
    submit(&world, "defer-incompatible", "defer", Fault::None)?;
    let connection = rusqlite::Connection::open(world.runtime.db())?;
    connection.execute(
        "UPDATE day2_deferrals SET command='reports.missing' WHERE parent='defer-incompatible'",
        [],
    )?;
    let active = authority_state::current(&connection)?;
    let error = day2::migration::activate_checked(
        &world.runtime,
        world.runtime.artifact(),
        &authority_state::LocalOperator::assert_local("test-operator")?,
        &active.stamp,
        "deferral-incompatible-activation",
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("activation_incompatible_deferrals")
    );
    Ok(())
}

#[test]
fn requests_and_deferrals_share_ordinals_and_have_distinct_identities() -> Result<()> {
    let world = world()?;
    submit(&world, "defer-both", "both", Fault::None)?;
    let children = invocations::children(&world.runtime, "defer-both")?;
    assert_eq!(children.len(), 2);
    let request = children[0].id.clone();
    let deferred = children[1].id.clone();
    assert_eq!(children[0].status, "pending");
    assert_eq!(children[1].status, "deferred");
    assert_ne!(request, deferred);
    assert!(request.starts_with("cmd_"));
    assert!(deferred.starts_with("dfr_"));
    let connection = rusqlite::Connection::open(world.runtime.db())?;
    let ordinals: Vec<i64> = connection
        .prepare("SELECT ordinal FROM (SELECT ordinal FROM day2_command_requests WHERE parent='defer-both' UNION ALL SELECT ordinal FROM day2_deferrals WHERE parent='defer-both') ORDER BY ordinal")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    assert_eq!(ordinals, vec![0, 1]);
    Ok(())
}

#[test]
fn due_bounds_reject_past_and_more_than_thirty_days() -> Result<()> {
    for id in ["past", "far"] {
        let world = world()?;
        let outcome = submit(&world, id, id, Fault::None)?;
        assert_eq!(outcome.status, "failure");
        assert_eq!(
            count(
                &world,
                "SELECT count(*) FROM day2_deferrals WHERE parent=?1",
                id
            )?,
            0
        );
        assert_eq!(
            count(&world, "SELECT count(*) FROM reports WHERE title=?1", id)?,
            0
        );
    }
    Ok(())
}

#[test]
fn offered_invocation_has_deferral_context_and_audit_trigger() -> Result<()> {
    let world = world()?;
    submit(&world, "defer-context", "defer", Fault::None)?;
    let id = deferral_id(&world, "defer-context")?;
    deferrals::tick(&world.runtime, 110_000)?;
    world.finish(&id)?;
    let trace = world.runtime.trace(&id)?;
    assert_eq!(trace.request.context.authentication, "deferral");
    let connection = rusqlite::Connection::open(world.runtime.db())?;
    assert_eq!(
        connection.query_row(
            "SELECT trigger FROM day2_invocations WHERE id=?1",
            [&id],
            |row| row.get::<_, String>(0)
        )?,
        "deferral"
    );
    Ok(())
}

#[test]
fn restore_turns_unoffered_deferrals_into_visible_blocked_invocations() -> Result<()> {
    let world = world()?;
    submit(&world, "defer-restore", "defer", Fault::None)?;
    let id = deferral_id(&world, "defer-restore")?;
    let mut database = rusqlite::Connection::open(world.runtime.db())?;
    let transaction =
        database.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    authority_state::invalidate_restored(&transaction, world.runtime.artifact().directory())?;
    transaction.commit()?;
    let connection = rusqlite::Connection::open(world.runtime.db())?;
    assert_eq!(
        connection.query_row(
            "SELECT reason FROM day2_authority_blocks WHERE invocation=?1",
            [&id],
            |row| row.get::<_, String>(0)
        )?,
        "deferral_restored"
    );
    assert_eq!(
        count(
            &world,
            "SELECT count(*) FROM day2_invocations WHERE id=?1",
            &id
        )?,
        1
    );
    assert_eq!(
        count(
            &world,
            "SELECT count(*) FROM day2_deferrals WHERE id=?1 AND offered_ms IS NOT NULL",
            &id
        )?,
        1
    );
    assert_eq!(
        invocations::children(&world.runtime, "defer-restore")?[0].status,
        "blocked"
    );
    assert!(
        invocations::drain(&world.runtime, 64)?
            .iter()
            .all(|item| item.id != id)
    );
    Ok(())
}
