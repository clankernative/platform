//! Adapter conformance: real Tokio Skip timers and blocking tasks, with real
//! SQLite writes. This is not a substitute for admitted Roc command conformance.
use super::*;
use crate::host_inputs::{TickStream, TokioTicks};
use std::{future::Future, path::PathBuf, pin::Pin};
use tokio::sync::{mpsc, watch};

struct ObservedTicks(mpsc::UnboundedSender<Duration>);

struct ObservedStream {
    native: Box<dyn TickStream>,
    period: Duration,
    delivered: mpsc::UnboundedSender<Duration>,
}

impl LiveTicks for ObservedTicks {
    fn start(&self, period: Duration) -> Box<dyn TickStream> {
        Box::new(ObservedStream {
            native: TokioTicks.start(period),
            period,
            delivered: self.0.clone(),
        })
    }
}

impl TickStream for ObservedStream {
    fn next(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.native.next().await;
            self.delivered.send(self.period).unwrap();
        })
    }
}

struct SqliteWork {
    db: PathBuf,
    entered: mpsc::UnboundedSender<Pump>,
    gates: [Mutex<std::sync::mpsc::Receiver<()>>; 3],
    trace: Mutex<Trace>,
    path: PathBuf,
    stop_observed: tokio::sync::Notify,
}

impl Work for SqliteWork {
    fn execute(&self, pump: Pump) -> Completion {
        self.entered.send(pump).unwrap();
        // This is a failure watchdog, never a scheduling assertion or a sleep.
        // Drop below releases gates even if an assertion panics.
        self.gates[pump.index()]
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(10))
            .expect("native test gate watchdog");
        let db = crate::store::open(&self.db).unwrap();
        db.execute(
            "INSERT INTO pump_commits(pump) VALUES(?1)",
            [pump.index() as i64],
        )
        .unwrap();
        Completion::Finished
    }

    fn observe(&self, event: Event, state: &State) {
        let mut trace = self.trace.lock().unwrap();
        assert!(trace.events.len() < STEPS, "native trace bound exceeded");
        trace.events.push(event);
        trace.observations.push(snapshot(state, None));
        std::fs::write(&self.path, serde_json::to_vec_pretty(&*trace).unwrap()).unwrap();
        if event == Event::Stop {
            self.stop_observed.notify_one();
        }
    }
}

struct StopRelease {
    admitting: Arc<AtomicBool>,
    stop: watch::Sender<bool>,
    release: [std::sync::mpsc::Sender<()>; 3],
}

impl Drop for StopRelease {
    fn drop(&mut self) {
        self.admitting.store(false, Ordering::Release);
        let _ = self.stop.send(true);
        for sender in &self.release {
            let _ = sender.send(());
        }
    }
}

fn fixture(
    declared: bool,
) -> (
    Arc<SqliteWork>,
    mpsc::UnboundedReceiver<Pump>,
    StopRelease,
    watch::Receiver<bool>,
) {
    let root = std::path::Path::new("/tmp/dst-platform-host-loops");
    std::fs::create_dir_all(root).unwrap();
    let directory = tempfile::Builder::new()
        .prefix("native-pump-")
        .tempdir_in(root)
        .unwrap()
        .keep();
    let db = directory.join("native.sqlite");
    crate::store::open(&db)
        .unwrap()
        .execute_batch(
            "CREATE TABLE pump_commits(sequence INTEGER PRIMARY KEY, pump INTEGER NOT NULL) STRICT",
        )
        .unwrap();
    let path = directory.join("trace.json");
    let trace = Trace {
        format: 1,
        source: decision_source(),
        seed: 0,
        declared,
        events: Vec::new(),
        observations: Vec::new(),
    };
    std::fs::write(&path, serde_json::to_vec_pretty(&trace).unwrap()).unwrap();
    let (entered, observed) = mpsc::unbounded_channel();
    let pairs = std::array::from_fn::<_, 3, _>(|_| std::sync::mpsc::channel());
    let (release, gates): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
    let (stop, stopped) = watch::channel(false);
    let cleanup = StopRelease {
        admitting: Arc::new(AtomicBool::new(true)),
        stop,
        release: release.try_into().unwrap(),
    };
    (
        Arc::new(SqliteWork {
            db,
            entered,
            gates: gates
                .into_iter()
                .map(Mutex::new)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            trace: Mutex::new(trace),
            path,
            stop_observed: tokio::sync::Notify::new(),
        }),
        observed,
        cleanup,
        stopped,
    )
}

fn commits(work: &SqliteWork) -> [i64; 3] {
    let db = crate::store::open(&work.db).unwrap();
    std::array::from_fn(|i| {
        db.query_row(
            "SELECT count(*) FROM pump_commits WHERE pump=?1",
            [i as i64],
            |row| row.get(0),
        )
        .unwrap()
    })
}

#[tokio::test(start_paused = true)]
async fn native_timers_skip_busy_deliveries_and_stop_awaits_real_sqlite_commits() {
    let (work, mut entered, control, stopped) = fixture(true);
    let (delivered, mut ticks) = mpsc::unbounded_channel();
    let driver = tokio::spawn(drive(
        work.clone(),
        Arc::new(ObservedTicks(delivered)),
        control.admitting.clone(),
        stopped,
        true,
    ));
    for period in [COMMAND_TICK, SCHEDULE_TICK, JOURNAL_TICK] {
        assert_eq!(ticks.recv().await, Some(period));
    }
    let mut seen = [false; 3];
    for _ in 0..3 {
        let pump = entered.recv().await.unwrap();
        assert!(!seen[pump.index()]);
        seen[pump.index()] = true;
    }
    assert_eq!(commits(&work), [0; 3]);
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(
        ticks.try_recv().is_err(),
        "busy pumps must not accumulate delivered ticks"
    );
    assert!(entered.try_recv().is_err(), "one native call per pump");

    // Independently control completion order. Each Skip stream delivers just
    // one late wakeup after settlement, not 300 queued command calls.
    for (pump, period) in [
        (Pump::Journal, JOURNAL_TICK),
        (Pump::Schedules, SCHEDULE_TICK),
        (Pump::Commands, COMMAND_TICK),
    ] {
        control.release[pump.index()].send(()).unwrap();
        assert_eq!(ticks.recv().await, Some(period));
        assert_eq!(entered.recv().await, Some(pump));
    }
    assert_eq!(commits(&work), [1; 3]);
    control.admitting.store(false, Ordering::Release);
    control.stop.send(true).unwrap();
    work.stop_observed.notified().await;
    assert!(
        !driver.is_finished(),
        "admitted blocking calls cannot be interrupted"
    );
    for sender in &control.release {
        sender.send(()).unwrap();
    }
    driver.await.unwrap().unwrap();
    assert_eq!(
        commits(&work),
        [2; 3],
        "already admitted calls can commit after stop"
    );
    assert!(ticks.try_recv().is_err());
    assert!(entered.try_recv().is_err());
    replay(&work.path);
    assert!(
        work.trace
            .lock()
            .unwrap()
            .observations
            .last()
            .unwrap()
            .drained
    );
}

#[test]
fn native_shutdown_refuses_blocking_tasks_queued_behind_uninterruptible_work() {
    // One blocking thread makes queue/start ordering explicit, without sleeps
    // or a global Tokio hook. Only already-present native Rust/SQLite is used.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (work, mut entered, control, stopped) = fixture(true);
        let (blocking_entered, blocking_started) = tokio::sync::oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            blocking_entered.send(()).unwrap();
            gate.recv_timeout(Duration::from_secs(10))
                .expect("blocking queue watchdog");
        });
        blocking_started.await.unwrap();
        let (delivered, mut ticks) = mpsc::unbounded_channel();
        let driver = tokio::spawn(drive(
            work.clone(),
            Arc::new(ObservedTicks(delivered)),
            control.admitting.clone(),
            stopped,
            true,
        ));
        for period in [COMMAND_TICK, SCHEDULE_TICK, JOURNAL_TICK] {
            assert_eq!(ticks.recv().await, Some(period));
        }
        assert!(entered.try_recv().is_err());
        control.stop.send(true).unwrap();
        work.stop_observed.notified().await;
        assert!(!driver.is_finished());
        release.send(()).unwrap();
        blocker.await.unwrap();
        driver.await.unwrap().unwrap();
        assert!(!control.admitting.load(Ordering::Acquire));
        assert_eq!(commits(&work), [0; 3]);
        assert!(entered.try_recv().is_err());
        replay(&work.path);
        let trace = work.trace.lock().unwrap();
        assert_eq!(
            trace
                .events
                .iter()
                .filter(|event| matches!(event, Event::Complete(_, Completion::Refused)))
                .count(),
            3
        );
    });
}

#[tokio::test(start_paused = true)]
async fn native_stop_before_dispatch_and_undeclared_schedules_never_run() {
    let (work, mut entered, control, stopped) = fixture(false);
    control.stop.send(true).unwrap();
    drive(
        work.clone(),
        Arc::new(TokioTicks),
        control.admitting.clone(),
        stopped,
        false,
    )
    .await
    .unwrap();
    assert_eq!(commits(&work), [0; 3]);
    assert!(entered.try_recv().is_err());
    replay(&work.path);
    assert_eq!(work.trace.lock().unwrap().events, vec![Event::Stop]);
}

#[test]
fn journal_batches_use_real_sqlite_and_keep_pending_young_and_audit_rows() -> Result<()> {
    let root = std::path::Path::new("/tmp/dst-platform-host-loops");
    std::fs::create_dir_all(root)?;
    let directory = tempfile::Builder::new()
        .prefix("journal-bounds-")
        .tempdir_in(root)?
        .keep();
    let db = directory.join("journal.sqlite");
    let mut connection = crate::store::open(&db)?;
    let tx = crate::write_queue::immediate(&mut connection)?;
    tx.execute_batch(crate::store::PLATFORM_DDL)?;
    tx.execute(
        "INSERT INTO day2_meta(key,value) VALUES('scope','synthetic-scope')",
        [],
    )?;
    crate::audit::upgrade(&tx)?;
    crate::execution::upgrade(&tx)?;
    crate::preparation::upgrade(&tx)?;
    let raw = serde_json::to_string(&crate::protocol::Trace {
        format: 1,
        artifact: "synthetic-artifact".into(),
        scope: "synthetic-scope".into(),
        request: crate::protocol::Request {
            operation: "synthetic-command".into(),
            input: "{}".into(),
            context: crate::protocol::Context {
                invocation_id: "synthetic".into(),
                actor: "synthetic-actor".into(),
                now: 0,
                authentication: "request".into(),
                caller: Vec::new(),
                authenticated: String::new(),
                delegation_rule: String::new(),
            },
            observations: Vec::new(),
        },
        outcome: crate::protocol::Outcome {
            status: "success".into(),
            result: serde_json::Value::Null,
            error: String::new(),
        },
        guard: None,
    })?;
    {
        let mut insert = tx.prepare(
            "INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status,trace)
             VALUES(?1,'synthetic-command','synthetic-actor','{}','synthetic-artifact',?2,?3,?4)",
        )?;
        for i in 0..10_001 {
            insert.execute(rusqlite::params![format!("old-{i}"), 0, "success", raw])?;
        }
        insert.execute(rusqlite::params!["pending", 0, "pending", raw])?;
        insert.execute(rusqlite::params!["young", 100, "success", raw])?;
    }
    tx.execute(
        "INSERT INTO day2_audit SELECT id,actor,operation,status,now FROM day2_invocations",
        [],
    )?;
    tx.commit()?;
    let mut batches = Vec::new();
    compact_batches(|batch| {
        assert_eq!(batch, 500);
        let count = crate::journal::compact_before(&db, 50, batch)?;
        batches.push(count);
        // Save every completed batch; DB and prefix evidence survive failures.
        std::fs::write(
            directory.join("batches.json"),
            serde_json::to_vec(&batches)?,
        )?;
        Ok(count)
    })?;
    assert_eq!(batches, vec![500; 20]);
    assert_eq!(
        connection.query_row(
            "SELECT count(*) FROM day2_invocations WHERE trace IS NULL",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        10_000
    );
    assert_eq!(
        connection.query_row(
            "SELECT count(*) FROM day2_invocations WHERE trace IS NOT NULL AND input='{}'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        3
    );
    assert_eq!(
        connection.query_row("SELECT count(*) FROM day2_audit", [], |row| row
            .get::<_, i64>(0))?,
        10_003
    );
    let mut remaining = Vec::new();
    compact_batches(|batch| {
        let count = crate::journal::compact_before(&db, 50, batch)?;
        remaining.push(count);
        Ok(count)
    })?;
    assert_eq!(remaining, vec![1], "short batches end the pass");
    assert_eq!(crate::journal::compact_before(&db, 50, 500)?, 0);
    assert!(crate::journal::same_input(
        "",
        Some(&connection.query_row(
            "SELECT receipt FROM day2_invocations WHERE id='old-0'",
            [],
            |row| row.get::<_, String>(0)
        )?),
        "{}"
    )?);

    // Unknown trace shapes fail, with the entire short transaction rolled back.
    connection.execute(
        "UPDATE day2_invocations SET trace=?1,input='{}' WHERE id='old-0'",
        [&raw],
    )?;
    connection.execute(
        "UPDATE day2_invocations SET trace='invalid',input='{}' WHERE id='old-1'",
        [],
    )?;
    assert!(compact_batches(|batch| crate::journal::compact_before(&db, 50, batch)).is_err());
    assert_eq!(connection.query_row("SELECT count(*) FROM day2_invocations WHERE id IN ('old-0','old-1') AND trace IS NOT NULL AND input='{}'", [], |row| row.get::<_, i64>(0))?, 2);
    Ok(())
}
