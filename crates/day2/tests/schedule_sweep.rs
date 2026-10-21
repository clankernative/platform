//! The Reports schedule prototype, end to end.
//!
//! The hold gate proves an occurrence runs at most once. This proves the thing the
//! occurrence is for: that a report which became ready but was never announced is
//! found and announced by the scheduled sweep. Without this, the prototype would
//! only show that a schedule can be declared and admitted, not that declaring one
//! accomplishes anything.
//!
//! Occurrences here are offered explicitly, at chosen instants, either directly or
//! through `advance`, the per-schedule step of the occurrence source's tick. The
//! daily cases check that an anchored schedule runs at its declared UTC hour.

use crate::support::commands as support;
use anyhow::{Context, Result};
use day2::{
    invocations,
    schedules::{Missed, Schedule, Skipped},
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
    let schedule = day2::schedules::from_declaration(&contract.namespace, declaration)?;
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

/// 2025-09-17T00:00:00Z.
const MIDNIGHT: i64 = 1_758_067_200_000;
const HOUR_MS: i64 = day2::schedules::HOUR_MS;
const DAY_MS: i64 = day2::schedules::DAY_MS;

/// The sweep command on a daily schedule anchored at 10:00 UTC, as
/// `Schedule.daily_at_hour(10, ...)` declares one. Reports declares no daily
/// schedule, so this reuses its command under a schedule of its own name.
fn daily_at_ten(world: &World, missed: Missed) -> Result<(Schedule, String, serde_json::Value)> {
    let (sweep, operation, input) = declared(world)?;
    let schedule = Schedule {
        name: "daily".into(),
        interval_ms: DAY_MS,
        anchor_hour: Some(10),
        missed,
        ..sweep
    };
    schedule.validate()?;
    Ok((schedule, operation, input))
}

/// Every occurrence of the daily schedule the invocation table holds, and the
/// logical time each run saw, in order.
fn daily_runs(world: &World) -> Result<Vec<(i64, i64)>> {
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let mut statement = db.prepare(
        "SELECT id, now FROM day2_invocations WHERE id LIKE 'schedule.reports.daily.%' ORDER BY id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut runs = Vec::new();
    for row in rows {
        let (id, now) = row?;
        let occurrence = id
            .strip_prefix("schedule.reports.daily.")
            .context("daily identity")?
            .parse()?;
        runs.push((occurrence, now));
    }
    Ok(runs)
}

#[test]
fn a_daily_schedule_runs_at_its_declared_hour() -> Result<()> {
    let world = World::new()?;
    let (schedule, operation, input) = daily_at_ten(&world, Missed::Coalesce)?;
    let ten = MIDNIGHT + 10 * HOUR_MS;
    let advance =
        |now| day2::schedules::advance(&world.runtime, &schedule, "alice", &operation, &input, now);

    // First tick after 10:00 runs today's 10:00 occurrence.
    let first = advance(ten + 500)?;
    assert_eq!(first.skipped, None);
    assert_eq!(first.offered.len(), 1);
    assert_eq!(first.offered[0].0, ten);
    assert_eq!(
        first.offered[0].1.status, "success",
        "{}",
        first.offered[0].1.error
    );

    // Nothing more that day, including at the following midnight, where every
    // daily schedule used to fire.
    for at in [ten + HOUR_MS, MIDNIGHT + DAY_MS, ten + DAY_MS - 1] {
        assert_eq!(advance(at)?.skipped, Some(Skipped::NotDue), "at {at}");
    }
    let next = advance(ten + DAY_MS)?;
    assert_eq!(next.offered.len(), 1);
    assert_eq!(next.offered[0].0, ten + DAY_MS);

    // Each run saw its 10:00 occurrence as the current time.
    assert_eq!(
        daily_runs(&world)?,
        vec![(ten, ten / 1_000), (ten + DAY_MS, (ten + DAY_MS) / 1_000)]
    );
    Ok(())
}

#[test]
fn a_daily_outage_is_caught_up_on_the_anchor() -> Result<()> {
    let ten = MIDNIGHT + 10 * HOUR_MS;
    let back = ten + 3 * DAY_MS + 5 * HOUR_MS;

    let world = World::new()?;
    let (schedule, operation, input) = daily_at_ten(&world, Missed::Coalesce)?;
    day2::schedules::advance(&world.runtime, &schedule, "alice", &operation, &input, ten)?;
    let tick =
        day2::schedules::advance(&world.runtime, &schedule, "alice", &operation, &input, back)?;
    // Coalesce runs the most recent 10:00 once.
    assert_eq!(
        tick.offered
            .iter()
            .map(|offered| offered.0)
            .collect::<Vec<_>>(),
        vec![ten + 3 * DAY_MS]
    );

    let world = World::new()?;
    let (schedule, operation, input) = daily_at_ten(&world, Missed::RunEach { bound: 3 })?;
    day2::schedules::advance(&world.runtime, &schedule, "alice", &operation, &input, ten)?;
    let tick =
        day2::schedules::advance(&world.runtime, &schedule, "alice", &operation, &input, back)?;
    // RunEach runs every missed 10:00, and nothing at midnight.
    assert_eq!(
        tick.offered
            .iter()
            .map(|offered| offered.0)
            .collect::<Vec<_>>(),
        vec![ten + DAY_MS, ten + 2 * DAY_MS, ten + 3 * DAY_MS]
    );
    assert!(
        daily_runs(&world)?
            .iter()
            .all(|(occurrence, _)| occurrence.rem_euclid(DAY_MS) == 10 * HOUR_MS)
    );
    Ok(())
}

#[test]
fn an_installation_that_last_ran_at_midnight_neither_repeats_nor_skips() -> Result<()> {
    let ten = MIDNIGHT + 10 * HOUR_MS;
    for missed in [Missed::Coalesce, Missed::RunEach { bound: 3 }] {
        let world = World::new()?;
        let (schedule, operation, input) = daily_at_ten(&world, missed)?;
        // Before anchors were honoured the source ran every daily schedule at
        // 00:00 UTC. That run is in the invocation table when the upgraded source
        // starts reading it.
        let legacy = day2::schedules::offer_occurrence(
            &world.runtime,
            &schedule,
            "alice",
            &operation,
            &input,
            MIDNIGHT,
        )?;
        assert_eq!(legacy.status, "success", "{}", legacy.error);
        let advance = |now| {
            day2::schedules::advance(&world.runtime, &schedule, "alice", &operation, &input, now)
        };

        // The midnight run is taken as yesterday's 10:00 occurrence, so the
        // morning after the upgrade runs nothing more...
        for at in [MIDNIGHT + 1, MIDNIGHT + 5 * HOUR_MS, ten - 1] {
            let tick = advance(at)?;
            assert_eq!(tick.skipped, Some(Skipped::NotDue), "{missed:?} at {at}");
        }
        // ...and today's 10:00 is not skipped.
        let tick = advance(ten)?;
        assert_eq!(tick.offered.len(), 1, "{missed:?}");
        assert_eq!(tick.offered[0].0, ten, "{missed:?}");
        assert_eq!(advance(ten + DAY_MS - 1)?.skipped, Some(Skipped::NotDue));
        assert_eq!(advance(ten + DAY_MS)?.offered[0].0, ten + DAY_MS);
        assert_eq!(
            daily_runs(&world)?
                .into_iter()
                .map(|(occurrence, _)| occurrence)
                .collect::<Vec<_>>(),
            vec![MIDNIGHT, ten, ten + DAY_MS],
            "{missed:?}"
        );
    }
    Ok(())
}
