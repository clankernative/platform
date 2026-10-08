//! What an application is told about how it came to be running.
//!
//! `Context.authentication` is the first server-verified fact about the caller
//! that reaches app code. The properties worth pinning are not that the value
//! exists but that it is *the same fact the audit log records*, that the
//! application cannot influence it, and that it survives replay — a decision an
//! app makes on this basis has to be reproducible, or it is not a decision the
//! platform can stand behind.

use crate::support::commands as support;
use anyhow::{Context as _, Result};
use day2::{
    invocations,
    schedules::{Missed, Schedule},
    store::{Fault, replay},
};
use support::World;

/// What the application was told, and what the host recorded, for one invocation.
fn told_and_recorded(world: &World, id: &str) -> Result<(String, String)> {
    let trace = world.runtime.trace(id)?;
    // A trace that does not replay is not evidence of what the app saw.
    replay(world.runtime.artifact(), &trace)?;
    let recorded: String = rusqlite::Connection::open(world.runtime.db())?.query_row(
        "SELECT trigger FROM day2_invocations WHERE id=?1",
        [id],
        |row| row.get(0),
    )?;
    Ok((trace.request.context.authentication, recorded))
}

fn sweep(world: &World) -> Result<(Schedule, String, serde_json::Value)> {
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

/// Every cause the platform has reaches the application as the cause it was.
///
/// Three of the four in one test on purpose: what matters is that they are
/// *distinguishable*. A context that reported `request` for everything would
/// satisfy any test that checked one path, and would quietly tell an application
/// that a schedule firing at 4am was a person asking.
#[test]
fn each_cause_reaches_the_application_as_the_cause_the_host_recorded() -> Result<()> {
    let world = World::new()?;

    // A person asked.
    world.submit("asked", Fault::None)?;
    let (told, recorded) = told_and_recorded(&world, "asked")?;
    assert_eq!(told, "request");
    assert_eq!(told, recorded, "the app and the audit log disagree");

    // Leave the sweep something to repair, so the occurrence below actually
    // requests a command and the third case is a real invocation rather than
    // an assertion about an empty run.
    invocations::drain(&world.runtime, 64)?;
    rusqlite::Connection::open(world.runtime.db())?
        .execute("UPDATE reports SET announced=0", [])?;

    // Nobody asked: the instance bound a schedule and it fired.
    let (schedule, operation, input) = sweep(&world)?;
    let outcome = day2::schedules::offer(
        &world.runtime,
        &schedule,
        "alice",
        &operation,
        &input,
        1_758_067_230_000,
    )?;
    assert_eq!(outcome.status, "success", "{}", outcome.error);
    let occurrence = rusqlite::Connection::open(world.runtime.db())?.query_row(
        "SELECT id FROM day2_invocations WHERE trigger='schedule' ORDER BY id LIMIT 1",
        [],
        |row| row.get::<_, String>(0),
    )?;
    let (told, recorded) = told_and_recorded(&world, &occurrence)?;
    assert_eq!(told, "schedule", "a scheduled run looked like a request");
    assert_eq!(told, recorded);

    // Another command in this app asked, inside its own transaction.
    invocations::drain(&world.runtime, 64)?;
    let child = invocations::children(&world.runtime, &occurrence)?
        .first()
        .context("the sweep requests a command")?
        .id
        .clone();
    let (told, recorded) = told_and_recorded(&world, &child)?;
    assert_eq!(
        told, "command_request",
        "a command requested by another command looked like a request"
    );
    assert_eq!(told, recorded);
    Ok(())
}

/// The application cannot choose what it is told about its caller.
///
/// The value comes from the invocation record, so the only way an application
/// could influence it is if something on the input path could reach it. Two
/// submissions differing only in their input must be told the same thing, and
/// changing the record must change what the app sees — otherwise the field is a
/// constant that happens to read correctly.
#[test]
fn what_the_application_is_told_follows_the_record_and_not_the_input() -> Result<()> {
    let world = World::new()?;
    world.submit("first", Fault::None)?;
    world.submit("second", Fault::None)?;
    assert_eq!(told_and_recorded(&world, "first")?.0, "request");
    assert_eq!(told_and_recorded(&world, "second")?.0, "request");

    // The record is the source. Rewriting it rewrites what a fresh invocation is
    // told — which is what proves the app is reading the record rather than a
    // constant the test cannot tell apart from one.
    let connection = rusqlite::Connection::open(world.runtime.db())?;
    connection.execute(
        "UPDATE day2_invocations SET trigger='ingress' WHERE id='third'",
        [],
    )?;
    world.runtime.accept(
        "reports.submit",
        "alice",
        "third",
        &serde_json::json!({"title":"Quarterly report","text":"first line\nsecond line"}),
        100,
    )?;
    connection.execute(
        "UPDATE day2_invocations SET trigger='ingress' WHERE id='third'",
        [],
    )?;
    world.runtime.execute("third", Fault::None)?;
    assert_eq!(told_and_recorded(&world, "third")?.0, "ingress");
    Ok(())
}

/// Every authorized read leaves a mandatory record of who read what.
///
/// An example application records an audit entry per authorized read —
/// effective human, authentication path, operation and subject — and its own
/// implementation is best effort, warning when the audit write fails. The
/// platform's answer is the invocation audit, which is not best effort: the
/// receipt commits with the read or the read does not happen. This pins that a
/// *query* produces one, because an audit that covered only writes would look
/// correct in every test and miss the entire read surface that app exists to
/// serve.
#[test]
fn an_authorized_read_is_audited_with_its_actor_operation_and_cause() -> Result<()> {
    let world = World::new()?;
    world.submit("subject", Fault::None)?;
    let submitted = world.runtime.trace("subject")?.outcome.result;
    let report = submitted["id"].as_str().context("submitted report id")?;

    // A read, not a write.
    let outcome = world.runtime.invoke(
        "reports.detail",
        "alice",
        "read-one",
        &serde_json::json!({ "report_id": report }),
        200,
        Fault::None,
    )?;
    assert_eq!(outcome.status, "success", "{}", outcome.error);

    let connection = rusqlite::Connection::open(world.runtime.db())?;
    let (actor, operation, status): (String, String, String) = connection.query_row(
        "SELECT actor,operation,status FROM day2_audit WHERE invocation='read-one'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(
        (actor.as_str(), operation.as_str(), status.as_str()),
        ("alice", "reports.detail", "success"),
        "a read completed without naming who read what"
    );

    // The cause is on the same record, and the subject is recoverable from the
    // input the invocation was accepted with — so "who read which thing, how
    // they were authenticated" is answerable without the application keeping
    // its own audit at all.
    let (cause, input): (String, String) = connection.query_row(
        "SELECT trigger,input FROM day2_invocations WHERE id='read-one'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(cause, "request");
    assert!(
        input.contains(report),
        "the subject of the read is not recorded"
    );

    // And it reaches the operator's one feed, beside every other event.
    let streamed: i64 = connection.query_row(
        "SELECT count(*) FROM day2_audit_events
         WHERE kind='invocation' AND identity='read-one' AND actor='alice'
           AND operation='reports.detail' AND trigger='request'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(streamed, 1, "the read is missing from the audit stream");
    Ok(())
}
