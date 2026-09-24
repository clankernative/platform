#[path = "support/commands.rs"]
mod support;
use anyhow::{Context, Result};
use day2::{
    invocations,
    store::{Fault, Runtime, replay},
};
use serde_json::{Value, json};
use support::World;

fn notification(world: &World) -> Result<(Value, String)> {
    let saved = world.submit("submit", Fault::None)?;
    let analysis = world.child("submit")?;
    assert_eq!(world.finish(&analysis)?.status, "success");
    Ok((saved.result["id"].clone(), world.child(&analysis)?))
}

#[test]
fn provider_acceptance_ack_loss_restart_and_completion_ack_loss_do_not_duplicate_delivery()
-> Result<()> {
    let world = World::new()?;
    let (report, notify) = notification(&world)?;
    assert!(
        world
            .runtime
            .execute(&notify, Fault::AfterDecisionCommit)
            .is_err()
    );
    assert!(
        !world
            .runtime
            .db()
            .with_file_name("notifications.sqlite")
            .exists()
    );
    let restarted = Runtime::load(world.runtime.instance_path(), "reports")?;
    assert!(restarted.execute(&notify, Fault::AfterExternal(1)).is_err());
    assert_eq!(world.detail(&report, "accepted")?["delivery"]["count"], 1);
    let db = rusqlite::Connection::open(world.runtime.db())?;
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM day2_external_effects WHERE observation IS NULL",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        1
    );
    assert!(restarted.execute(&notify, Fault::AfterCommit).is_err());
    let receipt = world.finish(&notify)?;
    assert_eq!(receipt.status, "success");
    assert_eq!(world.detail(&report, "completed")?["delivery"]["count"], 1);
    let before = world.runtime.inspect()?;
    replay(world.runtime.artifact(), &world.runtime.trace(&notify)?)?;
    assert_eq!(world.runtime.inspect()?, before);
    assert_eq!(world.finish(&notify)?, receipt);
    assert_eq!(
        db.query_row("SELECT count(*) FROM day2_external_effects", [], |r| r
            .get::<_, i64>(0))?,
        1
    );
    let attempts: (i64, i64, i64) = db.query_row(
        "SELECT count(*),count(DISTINCT effect),count(observation) FROM day2_external_attempts",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(
        attempts,
        (2, 1, 1),
        "lost response records an unresolved attempt; deduplicated retry has its own identity"
    );
    Ok(())
}

#[test]
fn preparation_restart_preserves_acceptance_authority_across_revoke_and_restore() -> Result<()> {
    let world = World::new()?;
    let (_, notify) = notification(&world)?;
    assert!(world.runtime.execute(&notify, Fault::AfterPrepare).is_err());
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let before: i64 = db.query_row(
        "SELECT count(*) FROM day2_observation_attempts WHERE invocation=?1",
        [&notify],
        |row| row.get(0),
    )?;
    assert_eq!(before, 1);
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.notify")
            .unwrap()
            .observations
            .clear();
    })?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.notify")
            .unwrap()
            .observations
            .insert("notifications.recipient.v1".into());
    })?;
    let restarted = Runtime::load(world.runtime.instance_path(), "reports")?;
    assert_eq!(restarted.execute(&notify, Fault::None)?.status, "blocked");
    let after: i64 = db.query_row(
        "SELECT count(*) FROM day2_observation_attempts WHERE invocation=?1",
        [&notify],
        |row| row.get(0),
    )?;
    assert_eq!(
        after, before,
        "stale preparation cannot replay inputs or issue another observation"
    );
    assert!(
        !world
            .runtime
            .db()
            .with_file_name("notifications.sqlite")
            .exists()
    );
    Ok(())
}

#[test]
fn dependent_effects_reuse_earlier_provider_results_after_restart() -> Result<()> {
    let world = World::artifact("DAY2_TEST_REPORTS_PROBE_ARTIFACT")?;
    let (report, notify) = notification(&world)?;
    assert_eq!(
        world.runtime.execute(&notify, Fault::None)?.status,
        "pending"
    );
    assert!(
        world
            .runtime
            .execute(&notify, Fault::AfterExternal(2))
            .is_err()
    );
    assert_eq!(world.finish(&notify)?.status, "success");
    let trace = world.runtime.trace(&notify)?;
    let effects: Vec<_> = trace
        .request
        .observations
        .iter()
        .filter(|entry| entry.instruction.kind == "external")
        .collect();
    assert_eq!(effects.len(), 2);
    let first: Value = serde_json::from_str(&effects[0].result)?;
    let second: Value = serde_json::from_str(&effects[1].instruction.data)?;
    assert!(
        second["body"]
            .as_str()
            .context("body")?
            .contains(first["id"].as_str().context("receipt")?)
    );
    assert_eq!(world.detail(&report, "linked")?["delivery"]["count"], 2);
    replay(world.runtime.artifact(), &trace)?;
    Ok(())
}

#[test]
fn query_preparation_restarts_without_frozen_reads_and_commands_validate_prepared_local_reads()
-> Result<()> {
    let world = World::new()?;
    let (report, notify) = notification(&world)?;
    world.runtime.accept(
        "reports.detail",
        "alice",
        "query",
        &json!({"report_id":report}),
        101,
    )?;
    assert!(world.runtime.execute("query", Fault::AfterPrepare).is_err());
    let db = rusqlite::Connection::open(world.runtime.db())?;
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM day2_preparation WHERE invocation='query'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(world.finish(&notify)?.status, "success");
    assert_eq!(world.finish("query")?.result["delivery"]["count"], 1);

    let world = World::new()?;
    let (report, notify) = notification(&world)?;
    assert!(world.runtime.execute(&notify, Fault::AfterPrepare).is_err());
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let prepared: String = db.query_row(
        "SELECT observation FROM day2_preparation WHERE invocation=?1 AND json_extract(observation,'$.instruction.model')='notifications.recipient.v1'",
        [&notify],
        |r| r.get(0),
    )?;
    assert!(prepared.contains("notifications.recipient.v1"));
    let edit = world.runtime.invoke(
        "reports.revise",
        "alice",
        "edit",
        &json!({"report_id":report,"expected_version":2,"text":"new"}),
        102,
        Fault::None,
    )?;
    assert_eq!(edit.status, "success");
    assert_eq!(world.finish(&notify)?.error, "conflict");
    assert!(
        !world
            .runtime
            .db()
            .with_file_name("notifications.sqlite")
            .exists()
    );
    Ok(())
}

#[test]
fn concurrent_schedulers_resume_one_durable_command_without_duplicate_writes() -> Result<()> {
    let world = World::new()?;
    let (report, notify) = notification(&world)?;
    assert_eq!(
        world.runtime.execute(&notify, Fault::None)?.status,
        "pending"
    );
    std::thread::scope(|scope| {
        let tasks: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| world.runtime.execute(&notify, Fault::None)))
            .collect();
        for task in tasks {
            let outcome = task.join().unwrap()?;
            assert!(matches!(outcome.status.as_str(), "success" | "pending"));
        }
        Ok::<_, anyhow::Error>(())
    })?;
    assert_eq!(world.finish(&notify)?.status, "success");
    assert_eq!(world.detail(&report, "one")?["delivery"]["count"], 1);
    // One write each from submit, analyze and notify's announcement. Five
    // schedulers raced this invocation; any duplicated write would push the row
    // past three, so the exact revision is the no-duplicate-writes claim.
    assert_eq!(world.runtime.inspect()?["reports"][0]["version"], 3);
    Ok(())
}

#[test]
fn scheduler_executes_durably_accepted_public_commands_without_background_binding() -> Result<()> {
    let world = World::new()?;
    world.runtime.accept(
        "reports.submit",
        "alice",
        "accepted",
        &json!({"title":"Async","text":"A\nB"}),
        100,
    )?;
    assert_eq!(
        invocations::status(&world.runtime, "accepted", "alice")?.status,
        "pending"
    );
    let completed = invocations::drain(&world.runtime, 16)?;
    assert_eq!(completed.len(), 3);
    assert!(
        completed
            .iter()
            .all(|invocation| invocation.status == "success")
    );
    assert_eq!(
        invocations::status(&world.runtime, "accepted", "alice")?.status,
        "success"
    );
    let row = world.runtime.inspect()?["reports"][0].clone();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(row["data"].as_str().unwrap())?["bytes"],
        3
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(row["data"].as_str().unwrap())?["lines"],
        2
    );
    Ok(())
}

#[test]
fn compacted_journal_keeps_receipts_and_never_touches_unfinished_work() -> Result<()> {
    let world = World::new()?;
    let saved = world.submit("submit", Fault::None)?;
    let (_, notify) = notification(&world)?;
    // Long after the window, so everything completed is due.
    let later = 100 + 365 * 24 * 3_600;
    let compact = || -> Result<usize> {
        let mut total = 0;
        loop {
            let batch = day2::journal::compact(&world.runtime, later, 2)?;
            total += batch;
            if batch < 2 {
                return Ok(total);
            }
        }
    };
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let row = |id: &str| -> Result<(String, bool, bool)> {
        Ok(db.query_row(
            "SELECT status,input!='' AND trace IS NOT NULL,receipt IS NOT NULL FROM day2_invocations WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?)
    };
    assert_eq!(compact()?, 2, "submit and analysis are complete");
    assert_eq!(row(&notify)?.0, "pending");
    assert!(
        !row(&notify)?.2,
        "unfinished work keeps its input and trace"
    );
    assert_eq!(row("submit")?, ("success".into(), false, true));

    let receipt = world.finish(&notify)?;
    assert_eq!(receipt.status, "success");
    assert_eq!(compact()?, 1);
    assert_eq!(compact()?, 0, "compaction is idempotent");
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM day2_execution WHERE phase='complete' AND trace!=''",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0,
        "the completion copy of an effectful trace is compacted too"
    );

    // Retries are still answered from the receipt, by both paths.
    assert_eq!(world.submit("submit", Fault::None)?, saved);
    assert_eq!(world.finish(&notify)?, receipt);
    let conflict = world
        .runtime
        .invoke(
            "reports.submit",
            "alice",
            "submit",
            &json!({"title":"Another report","text":"different"}),
            100,
            Fault::None,
        )
        .unwrap_err();
    assert!(
        conflict.to_string().contains("idempotency_key_conflict"),
        "{conflict:#}"
    );
    let trace = world.runtime.trace(&notify).unwrap_err();
    assert!(
        trace.to_string().contains("invocation_trace_compacted"),
        "{trace:#}"
    );

    // A compacted receipt is still bound to the authority it ran under.
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.notify")
            .unwrap()
            .observations
            .clear();
    })?;
    let stale = world.finish(&notify).unwrap_err();
    assert!(
        stale.to_string().contains("receipt_policy_changed"),
        "{stale:#}"
    );
    Ok(())
}
