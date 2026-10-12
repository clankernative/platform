//! The occurrence source: what actually drives a declared schedule.
//!
//! The hold gate proved an occurrence can run at most once. These tests cover the
//! loop around that -- which occurrences are offered, which are refused, and what
//! the source says when it refuses. A schedule that silently does nothing is
//! indistinguishable from one that is working, so every refusal is asserted to
//! carry its reason rather than merely to produce no run.

use crate::support::commands as support;
use anyhow::{Context, Result};
use day2::{
    invocations,
    schedules::{self, Skipped},
    store::{Fault, Runtime},
};
use serde_json::{Value, json};
use std::fs;
use support::World;

/// Five minutes, as `apps/reports-app/schedules/Schedules.roc` declares.
const INTERVAL_MS: i64 = 5 * 60_000;
const MONDAY: i64 = 1_758_067_230_000;

/// Bind the declared sweep to an actor, as an instance operator would.
fn bind(world: &World, actor: &str, disabled: bool) -> Result<()> {
    let path = world.directory.path().join("instance.json");
    let mut instance: Value = serde_json::from_slice(&fs::read(&path)?)?;
    instance["apps"]["reports"]["schedules"] =
        json!({"sweep": {"actor": actor, "disabled": disabled}});
    fs::write(&path, serde_json::to_vec(&instance)?)?;
    Ok(())
}

fn sweep_tick(runtime: &Runtime, now_ms: i64) -> Result<schedules::Tick> {
    schedules::tick(runtime, now_ms)?
        .into_iter()
        .find(|tick| tick.schedule == "sweep")
        .context("reports declares a sweep schedule")
}

fn reports_announced(world: &World) -> Result<i64> {
    let db = rusqlite::Connection::open(world.runtime.db())?;
    Ok(db.query_row(
        "SELECT count(*) FROM reports WHERE announced=1",
        [],
        |row| row.get(0),
    )?)
}

#[test]
fn an_unbound_schedule_does_not_run_and_says_so() -> Result<()> {
    let world = World::new()?;
    // The instance binds no actor. An application cannot choose one -- that would
    // let it grant itself authority by declaring a schedule -- so the only safe
    // outcome is not running, and saying which decision is missing.
    let tick = sweep_tick(&world.runtime, MONDAY)?;
    assert_eq!(tick.skipped, Some(Skipped::Unbound));
    assert!(tick.offered.is_empty());
    Ok(())
}

#[test]
fn a_disabled_schedule_does_not_run() -> Result<()> {
    let world = World::new()?;
    bind(&world, "alice", true)?;
    let tick = sweep_tick(&world.runtime, MONDAY)?;
    assert_eq!(tick.skipped, Some(Skipped::Disabled));
    assert!(tick.offered.is_empty());
    // Enabling is the only difference between this and a run.
    bind(&world, "alice", false)?;
    let tick = sweep_tick(&world.runtime, MONDAY)?;
    assert_eq!(tick.skipped, None);
    assert_eq!(tick.offered.len(), 1);
    Ok(())
}

#[test]
fn a_bound_schedule_runs_once_per_interval() -> Result<()> {
    let world = World::new()?;
    bind(&world, "alice", false)?;

    let first = sweep_tick(&world.runtime, MONDAY)?;
    assert_eq!(first.offered.len(), 1, "the first tick did not run");
    assert_eq!(first.offered[0].1.status, "success");

    // Ticking again inside the same occurrence must not start a second run. The
    // source is expected to be called far more often than the interval. Offsets are
    // measured from the occurrence, not from MONDAY, which sits partway into it.
    let occurrence = first.offered[0].0;
    assert_eq!(
        occurrence % INTERVAL_MS,
        0,
        "occurrences are interval-aligned"
    );
    for at in [occurrence, MONDAY, occurrence + INTERVAL_MS - 1] {
        let again = sweep_tick(&world.runtime, at)?;
        assert_eq!(again.skipped, Some(Skipped::NotDue), "at {at}");
        assert!(again.offered.is_empty(), "at {at}");
    }

    // The next occurrence begins exactly one interval later.
    let next = sweep_tick(&world.runtime, occurrence + INTERVAL_MS)?;
    assert_eq!(next.skipped, None);
    assert_eq!(next.offered.len(), 1);
    assert_eq!(next.offered[0].0, occurrence + INTERVAL_MS);
    Ok(())
}

#[test]
fn a_restart_does_not_rerun_the_occurrence_it_already_ran() -> Result<()> {
    let world = World::new()?;
    bind(&world, "alice", false)?;
    assert_eq!(sweep_tick(&world.runtime, MONDAY)?.offered.len(), 1);

    // A restarted source holds nothing in memory. It re-derives what ran last from
    // the invocation table, which is the whole reason there is no timer to recover.
    let restarted = Runtime::load(world.runtime.instance_path(), "reports")?;
    let tick = sweep_tick(&restarted, MONDAY + 1_000)?;
    assert_eq!(tick.skipped, Some(Skipped::NotDue));
    assert!(tick.offered.is_empty());
    Ok(())
}

#[test]
fn a_running_occurrence_blocks_the_next() -> Result<()> {
    let world = World::new()?;
    bind(&world, "alice", false)?;
    // A run that has not finished, as a slow occurrence would leave behind.
    // Overlapping runs of a reconciliation sweep would race on the same rows.
    let db = rusqlite::Connection::open(world.runtime.db())?;
    db.execute(
        "INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status) VALUES(?1,'reports.sweep','alice','{}',?2,?3,'pending')",
        rusqlite::params![
            format!("schedule.reports.sweep.{:016}", MONDAY - INTERVAL_MS),
            world.runtime.artifact().id(),
            (MONDAY - INTERVAL_MS) / 1_000
        ],
    )?;
    drop(db);

    let tick = sweep_tick(&world.runtime, MONDAY)?;
    assert_eq!(
        tick.skipped,
        Some(Skipped::InFlight {
            since_ms: MONDAY - INTERVAL_MS
        })
    );
    assert!(tick.offered.is_empty());
    Ok(())
}

#[test]
fn the_schedule_runs_as_the_actor_the_instance_bound() -> Result<()> {
    let world = World::new()?;
    bind(&world, "bob", false)?;
    let tick = sweep_tick(&world.runtime, MONDAY)?;
    assert_eq!(tick.offered.len(), 1);

    let db = rusqlite::Connection::open(world.runtime.db())?;
    let actor: String = db.query_row(
        "SELECT actor FROM day2_invocations WHERE id=?1",
        rusqlite::params![format!(
            "schedule.reports.sweep.{:016}",
            MONDAY - MONDAY % INTERVAL_MS
        )],
        |row| row.get(0),
    )?;
    // Not a default, not the application's choice, not an implicit system identity.
    assert_eq!(actor, "bob");
    Ok(())
}

#[test]
fn an_actor_the_instance_did_not_authorize_cannot_be_bound_into_a_run() -> Result<()> {
    let world = World::new()?;
    // "viewer" is a reader, not a writer of reports.sweep. Binding a schedule must
    // not widen authority: the run is refused exactly as the same actor calling the
    // command directly would be.
    bind(&world, "viewer", false)?;
    let refused = schedules::tick(&world.runtime, MONDAY);
    assert!(
        refused.is_err(),
        "an unauthorized actor produced a scheduled run"
    );
    Ok(())
}

#[test]
fn a_binding_for_a_schedule_that_does_not_exist_is_refused() -> Result<()> {
    let world = World::new()?;
    let path = world.directory.path().join("instance.json");
    let mut instance: Value = serde_json::from_slice(&fs::read(&path)?)?;
    // A schedule renamed in a new artifact version leaves a binding behind. Without
    // this check the schedule simply stops running and nothing says so.
    instance["apps"]["reports"]["schedules"] = json!({"nightly": {"actor": "alice"}});
    fs::write(&path, serde_json::to_vec(&instance)?)?;
    assert!(Runtime::load(&path, "reports").is_err());

    // An empty actor is the other way to bind nothing while appearing bound.
    instance["apps"]["reports"]["schedules"] = json!({"sweep": {"actor": " "}});
    fs::write(&path, serde_json::to_vec(&instance)?)?;
    assert!(Runtime::load(&path, "reports").is_err());

    instance["apps"]["reports"]["schedules"] = json!({"sweep": {"actor": "alice"}});
    fs::write(&path, serde_json::to_vec(&instance)?)?;
    assert!(Runtime::load(&path, "reports").is_ok());
    Ok(())
}

/// Every audit event recorded for one invocation.
fn causes(world: &World, identity: &str) -> Result<Vec<String>> {
    let page = world.runtime.audit_event_page(
        "admin",
        &day2::audit::PageRequest {
            identity: Some(identity.to_owned()),
            ..Default::default()
        },
    )?;
    Ok(page.items.into_iter().map(|event| event.trigger).collect())
}

#[test]
fn a_scheduled_run_sees_its_occurrence_as_the_current_time() -> Result<()> {
    let world = World::new()?;
    bind(&world, "alice", false)?;
    let tick = sweep_tick(&world.runtime, MONDAY)?;
    let occurrence = tick.offered[0].0;

    // Context.now inside a scheduled command is the occurrence, not the wall clock
    // that noticed it. This is what lets a scheduled sweep compare stored due times
    // against "now" and still replay identically: a tick that arrives late produces
    // the same answer it would have produced on time.
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let seen: i64 = db.query_row(
        "SELECT now FROM day2_invocations WHERE id=?1",
        rusqlite::params![format!("schedule.reports.sweep.{occurrence:016}")],
        |row| row.get(0),
    )?;
    assert_eq!(seen, occurrence / 1_000);

    // And a later tick in the same occurrence does not move it.
    assert_eq!(
        sweep_tick(&world.runtime, MONDAY + 60_000)?.skipped,
        Some(Skipped::NotDue)
    );
    let unchanged: i64 = db.query_row(
        "SELECT now FROM day2_invocations WHERE id=?1",
        rusqlite::params![format!("schedule.reports.sweep.{occurrence:016}")],
        |row| row.get(0),
    )?;
    assert_eq!(unchanged, occurrence / 1_000);
    Ok(())
}

#[test]
fn the_audit_stream_says_what_caused_each_invocation() -> Result<()> {
    let world = World::new()?;
    bind(&world, "alice", false)?;

    // An actor asked for this one.
    world.submit("asked-for", Fault::None)?;
    let requested = causes(&world, "asked-for")?;
    assert!(!requested.is_empty(), "the submit recorded no audit events");
    assert!(
        requested.iter().all(|cause| cause == "request"),
        "{requested:?}"
    );

    // Analysis was requested by the submit, not by anyone.
    let analysis = world.child("asked-for")?;
    invocations::drain(&world.runtime, 64)?;
    let requested_by_a_command = causes(&world, &analysis)?;
    assert!(!requested_by_a_command.is_empty());
    assert!(
        requested_by_a_command
            .iter()
            .all(|cause| cause == "command_request"),
        "{requested_by_a_command:?}"
    );

    // And the scheduled run is typed as one, rather than being recognisable only
    // by the shape of its identity.
    let tick = sweep_tick(&world.runtime, MONDAY)?;
    let occurrence = tick.offered[0].0;
    let scheduled = causes(&world, &format!("schedule.reports.sweep.{occurrence:016}"))?;
    assert!(!scheduled.is_empty(), "the scheduled run recorded nothing");
    assert!(
        scheduled.iter().all(|cause| cause == "schedule"),
        "{scheduled:?}"
    );
    Ok(())
}

#[test]
fn the_source_reconciles_a_report_whose_announcement_was_lost() -> Result<()> {
    let world = World::new()?;
    bind(&world, "alice", false)?;
    world.submit("submitted", Fault::None)?;
    invocations::drain(&world.runtime, 64)?;
    assert_eq!(reports_announced(&world)?, 1);
    // The announcement is lost: a provider that reported success without
    // delivering, or a crash between the effect and its completion.
    rusqlite::Connection::open(world.runtime.db())?
        .execute("UPDATE reports SET announced=0", [])?;

    let tick = sweep_tick(&world.runtime, MONDAY)?;
    assert_eq!(tick.offered.len(), 1);
    assert_eq!(tick.offered[0].1.result["reconciled"], 1);
    // The sweep requests notify; the repair lands when that drains.
    invocations::drain(&world.runtime, 64)?;
    assert_eq!(
        reports_announced(&world)?,
        1,
        "the scheduled sweep did not repair the report"
    );
    Ok(())
}
