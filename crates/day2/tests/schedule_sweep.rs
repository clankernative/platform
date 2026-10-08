//! The Reports schedule prototype, end to end.
//!
//! The hold gate proves an occurrence runs at most once. This proves the thing the
//! occurrence is for: that a report which became ready but was never announced is
//! found and announced by the scheduled sweep. Without this, the prototype would
//! only show that a schedule can be declared and admitted, not that declaring one
//! accomplishes anything.
//!
//! What is still missing is the loop: nothing calls `offer` on a timer yet, so the
//! occurrence here is offered explicitly, at a chosen instant.

use crate::support::commands as support;
use anyhow::{Context, Result};
use day2::{
    invocations,
    schedules::{Missed, Schedule},
    store::Fault,
};
use support::World;

/// The schedule as the application declared it, read back out of the artifact
/// rather than restated here -- the point is that the declaration drives the run.
fn declared(world: &World) -> Result<(Schedule, String, serde_json::Value)> {
    let contract = world.runtime.artifact().contract();
    let declaration = contract
        .schedules
        .iter()
        .find(|schedule| schedule.name == "sweep")
        .context("reports declares a sweep schedule")?;
    let schedule = Schedule {
        app: contract.namespace.clone(),
        name: declaration.name.clone(),
        interval_ms: declaration.interval_ms as i64,
        missed: match declaration.missed.as_str() {
            "run_each" => Missed::RunEach {
                bound: declaration.catch_up_bound as usize,
            },
            _ => Missed::Coalesce,
        },
    };
    Ok((
        schedule,
        declaration.operation.clone(),
        serde_json::from_str(&declaration.input)?,
    ))
}

fn announced(world: &World) -> Result<i64> {
    let db = rusqlite::Connection::open(world.runtime.db())?;
    Ok(db.query_row(
        "SELECT count(*) FROM reports WHERE announced=1",
        [],
        |row| row.get(0),
    )?)
}

fn ready(world: &World) -> Result<i64> {
    let db = rusqlite::Connection::open(world.runtime.db())?;
    Ok(
        db.query_row("SELECT count(*) FROM reports WHERE ready=1", [], |row| {
            row.get(0)
        })?,
    )
}

/// Put one report into the state the sweep exists to repair: analysis finished, so
/// it is ready, but the announcement never landed.
fn a_ready_report_whose_announcement_was_lost(world: &World) -> Result<()> {
    world.submit("submitted", Fault::None)?;
    invocations::drain(&world.runtime, 64)?;
    assert_eq!(ready(world)?, 1, "analysis did not complete");
    assert_eq!(announced(world)?, 1, "the write path did not announce");
    // The notification was accepted and then lost -- a provider that reported
    // success without delivering, a crash between effect and completion. The
    // application cannot distinguish this from never having announced.
    let db = rusqlite::Connection::open(world.runtime.db())?;
    db.execute("UPDATE reports SET announced=0", [])?;
    assert_eq!(announced(world)?, 0);
    Ok(())
}

#[test]
fn a_scheduled_sweep_announces_a_report_the_write_path_lost() -> Result<()> {
    let world = World::new()?;
    a_ready_report_whose_announcement_was_lost(&world)?;
    let (schedule, operation, input) = declared(&world)?;

    let outcome = day2::schedules::offer(
        &world.runtime,
        &schedule,
        "alice",
        &operation,
        &input,
        1_758_067_230_000,
    )?;
    assert_eq!(outcome.status, "success", "{}", outcome.error);
    assert_eq!(
        outcome.result["reconciled"], 1,
        "the sweep found nothing to reconcile"
    );
    assert_eq!(outcome.result["remaining"], false);

    // The sweep requests notify rather than announcing directly, so the repair
    // completes when the requested command drains.
    invocations::drain(&world.runtime, 64)?;
    assert_eq!(announced(&world)?, 1, "the sweep did not repair the report");
    Ok(())
}

#[test]
fn a_sweep_with_nothing_to_reconcile_is_a_successful_empty_run() -> Result<()> {
    let world = World::new()?;
    world.submit("submitted", Fault::None)?;
    invocations::drain(&world.runtime, 64)?;
    assert_eq!(announced(&world)?, 1);
    let (schedule, operation, input) = declared(&world)?;

    // Most occurrences of a reconciliation sweep have nothing to do. That must be
    // an ordinary success, not an error and not a no-op that looks like failure.
    let outcome = day2::schedules::offer(
        &world.runtime,
        &schedule,
        "alice",
        &operation,
        &input,
        1_758_067_230_000,
    )?;
    assert_eq!(outcome.status, "success", "{}", outcome.error);
    assert_eq!(outcome.result["reconciled"], 0);
    assert_eq!(announced(&world)?, 1, "an empty sweep changed state");
    Ok(())
}

#[test]
fn offering_one_occurrence_twice_repairs_once() -> Result<()> {
    let world = World::new()?;
    a_ready_report_whose_announcement_was_lost(&world)?;
    let (schedule, operation, input) = declared(&world)?;

    // Two ticks inside one interval, each deriving its own identity. The second
    // must not request a second notification for the same report.
    for now in [1_758_067_230_000, 1_758_067_240_000] {
        let outcome =
            day2::schedules::offer(&world.runtime, &schedule, "alice", &operation, &input, now)?;
        assert_eq!(outcome.status, "success", "{}", outcome.error);
    }
    let drained = invocations::drain(&world.runtime, 64)?;
    assert_eq!(
        drained
            .iter()
            .filter(|command| command.operation == "reports.notify")
            .count(),
        1,
        "the duplicate tick requested a second notification"
    );
    assert_eq!(announced(&world)?, 1);
    Ok(())
}
