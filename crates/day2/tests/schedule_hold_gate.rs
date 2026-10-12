//! Schedule hold gate.
//!
//! The proposed design derives occurrences from the clock instead of storing
//! durable timers, so nothing has to be recovered after a restart. That only works
//! if a derived identity is stable enough for the existing exactly-once invocation
//! machinery to carry a scheduled run. These tests answer that against the real
//! runtime and a real database, not a model of one.
//!
//! If any of these fail, the design is wrong and no application should declare a
//! schedule: a schedule that can run twice is worse than no schedule, because the
//! application cannot tell.

use crate::support::commands as support;
use anyhow::Result;
use day2::{
    schedules::{Missed, Schedule},
    store::{Fault, Runtime},
};
use serde_json::json;
use support::World;

fn sweep() -> Schedule {
    Schedule {
        app: "reports".into(),
        name: "sweep".into(),
        interval_ms: day2::schedules::MINIMUM_INTERVAL_MS,
        missed: Missed::Coalesce,
    }
}

fn reports(world: &World) -> Result<i64> {
    let db = rusqlite::Connection::open(world.runtime.db())?;
    Ok(db.query_row("SELECT count(*) FROM reports", [], |row| row.get(0))?)
}

/// One scheduler tick. The identity is derived here, from this tick's own clock
/// reading, exactly as a real tick would derive it -- never passed in. A test that
/// computes the identity once and reuses the string proves only that the runtime
/// deduplicates a constant, which was already true; it would pass even if the
/// derivation followed the raw clock and produced a fresh identity every tick.
fn tick(runtime: &Runtime, schedule: &Schedule, now_ms: i64) -> Result<day2::protocol::Outcome> {
    let identity = schedule.identity(schedule.occurrence_at(now_ms));
    // Any durable command serves; the claim under test is about identity, not about
    // what the operation does.
    runtime.invoke(
        "reports.submit",
        "alice",
        &identity,
        &json!({"title":"Scheduled sweep","text":"body"}),
        now_ms / 1_000,
        Fault::None,
    )
}

#[test]
fn an_occurrence_offered_twice_commits_once() -> Result<()> {
    let world = World::new()?;
    let schedule = sweep();

    // Two ticks land at different instants inside one interval -- a duplicate tick,
    // a second host, or a retry after a lost response. Each derives its own
    // identity from its own reading; they must agree, and the run must happen once.
    let first = tick(&world.runtime, &schedule, 1_758_067_230_000)?;
    assert_eq!(first.status, "success");
    let second = tick(&world.runtime, &schedule, 1_758_067_240_000)?;
    assert_eq!(second.status, "success");
    assert_eq!(
        first.result, second.result,
        "a second offer created new work"
    );
    assert_eq!(reports(&world)?, 1);
    Ok(())
}

#[test]
fn a_restart_recomputes_the_same_identity_and_does_not_rerun() -> Result<()> {
    let world = World::new()?;
    let schedule = sweep();
    assert_eq!(
        tick(&world.runtime, &schedule, 1_758_067_230_000)?.status,
        "success"
    );
    assert_eq!(reports(&world)?, 1);

    // Restarting loads the same durable state and keeps nothing in memory. The
    // restarted runtime ticks at a later instant in the same interval and must
    // re-derive the identity that already ran -- this is what replaces a recovered
    // durable timer.
    let restarted = Runtime::load(world.runtime.instance_path(), "reports")?;
    let again = tick(&restarted, &schedule, 1_758_067_250_000)?;
    assert_eq!(again.status, "success");
    assert_eq!(reports(&world)?, 1, "restart reran the occurrence");
    Ok(())
}

#[test]
fn distinct_occurrences_are_distinct_runs() -> Result<()> {
    let world = World::new()?;
    let schedule = sweep();

    // Two ticks in adjacent intervals. Deduplication must not be so eager that a
    // schedule only ever runs once.
    assert_eq!(
        tick(&world.runtime, &schedule, 1_758_067_230_000)?.status,
        "success"
    );
    assert_eq!(
        tick(&world.runtime, &schedule, 1_758_067_290_000)?.status,
        "success"
    );
    assert_eq!(reports(&world)?, 2);
    Ok(())
}

#[test]
fn two_schedules_in_one_application_do_not_absorb_each_other() -> Result<()> {
    let world = World::new()?;
    let sweep = sweep();
    let digest = Schedule {
        name: "digest".into(),
        ..sweep.clone()
    };

    // Both schedules share an application and an interval, so they tick together and
    // their occurrences are the same instant. Only the name separates them. If the
    // identity dropped it, the second would be absorbed as a duplicate of the first
    // and would silently never run -- as undetectable to the application as running
    // twice, and equally a reason not to ship the design.
    assert_eq!(
        tick(&world.runtime, &sweep, 1_758_067_230_000)?.status,
        "success"
    );
    assert_eq!(
        tick(&world.runtime, &digest, 1_758_067_230_000)?.status,
        "success"
    );
    assert_eq!(reports(&world)?, 2, "one schedule absorbed the other");
    Ok(())
}

#[test]
fn a_clock_moved_backwards_produces_no_second_run() -> Result<()> {
    let world = World::new()?;
    let schedule = sweep();
    let occurrence = schedule.occurrence_at(1_758_067_230_000);
    assert_eq!(
        tick(&world.runtime, &schedule, 1_758_067_230_000)?.status,
        "success"
    );

    // An NTP correction moves the clock back inside the interval that already ran.
    assert!(
        schedule
            .due(Some(occurrence), 1_758_067_205_000)?
            .is_empty()
    );
    // Even if a caller ignored that and ticked anyway, the earlier reading floors to
    // the same occurrence, so the re-derived identity absorbs the run.
    assert_eq!(
        tick(&world.runtime, &schedule, 1_758_067_205_000)?.status,
        "success"
    );
    assert_eq!(reports(&world)?, 1);
    Ok(())
}
