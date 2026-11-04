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

#[tokio::test(start_paused = true)]
async fn owner_sql_failure_closes_admission_without_a_later_timer_retry() -> Result<()> {
    struct Refused {
        attempts: std::sync::atomic::AtomicUsize,
        admitting: Arc<AtomicBool>,
        owner: std::thread::ThreadId,
    }
    impl Work for Refused {
        fn execute(&self, _pump: Pump) -> Completion {
            assert_eq!(self.owner, std::thread::current().id());
            // Bound the counterexample too: restoring the retry must fail the
            // assertions after a second call rather than hang this test.
            if self.attempts.fetch_add(1, Ordering::Relaxed) > 0 {
                self.admitting.store(false, Ordering::Release);
            }
            Completion::Failed
        }
    }
    let admitting = Arc::new(AtomicBool::new(true));
    let work = Arc::new(Refused {
        attempts: std::sync::atomic::AtomicUsize::new(0),
        admitting: admitting.clone(),
        owner: std::thread::current().id(),
    });
    let (_stop, stopped) = watch::channel(false);
    let error = drive_mode(
        work.clone(),
        Arc::new(TokioTicks),
        admitting.clone(),
        stopped,
        true,
        Execution::OwnerThread,
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "native_owner_pump_failed");
    assert_eq!(work.attempts.load(Ordering::Relaxed), 1);
    assert!(!admitting.load(Ordering::Acquire));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn selected_native_pump_commits_on_its_owner_thread_and_drains() -> Result<()> {
    struct Owned {
        work: Arc<SqliteWork>,
        owner: std::thread::ThreadId,
        admitting: Arc<AtomicBool>,
    }
    impl Work for Owned {
        fn execute(&self, pump: Pump) -> Completion {
            assert_eq!(std::thread::current().id(), self.owner);
            let result = self.work.execute(pump);
            self.admitting.store(false, Ordering::Release);
            result
        }
        fn observe(&self, event: Event, state: &State) {
            self.work.observe(event, state);
        }
    }
    let (work, _observed, cleanup, stopped) = fixture(false);
    for release in &cleanup.release {
        release.send(()).unwrap();
    }
    drive_mode(
        Arc::new(Owned {
            work: work.clone(),
            owner: std::thread::current().id(),
            admitting: cleanup.admitting.clone(),
        }),
        Arc::new(TokioTicks),
        cleanup.admitting.clone(),
        stopped,
        false,
        Execution::OwnerThread,
    )
    .await?;
    assert_eq!(commits(&work), [1, 0, 0]);
    Ok(())
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
    eprintln!("Host-loop decision replay: {}", replay_command(&path));
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
    replay(&work.path).unwrap();
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
        replay(&work.path).unwrap();
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
    replay(&work.path).unwrap();
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

/// Real task/SQLite interleavings at the existing private Work port. The
/// controlled returned failures are not observed worker-process timeouts.
mod execution_histories {
    use super::*;
    use anyhow::Context as _;
    use serde::{Deserialize, Serialize};
    use std::collections::VecDeque;

    const MAX_EPISODES: usize = 16;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Outcome {
        Commit,
        FailedBeforeWrite,
        FailedAfterCommit,
        PanicBeforeCommit,
        PanicAfterCommit,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Episode {
        pump: u8,
        outcome: Outcome,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Control {
        Correct,
        ForgetFailedCommit,
        AbortObservationAfterEntry,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Program {
        format: u8,
        owner_thread: bool,
        source: String,
        seed: u64,
        stop_during_last: bool,
        episodes: Vec<Episode>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Point {
        Entered,
        Began,
        Wrote,
        Committed,
        ReturnedFailure,
        Panicked,
        Finished,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Progress {
        call: u8,
        pump: u8,
        point: Point,
    }

    #[derive(Clone)]
    struct Observation {
        event: Event,
        state: Snapshot,
    }

    struct ManualTicks {
        receive: [Mutex<Option<mpsc::UnboundedReceiver<()>>>; 3],
    }
    struct ManualTick {
        receive: mpsc::UnboundedReceiver<()>,
    }
    impl LiveTicks for ManualTicks {
        fn start(&self, period: Duration) -> Box<dyn TickStream> {
            let index = [COMMAND_TICK, SCHEDULE_TICK, JOURNAL_TICK]
                .iter()
                .position(|value| *value == period)
                .expect("fixture tick period");
            Box::new(ManualTick {
                receive: self.receive[index]
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one fixture stream"),
            })
        }
    }
    impl TickStream for ManualTick {
        fn next(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(async move {
                self.receive
                    .recv()
                    .await
                    .expect("fixture tick owner retained");
            })
        }
    }

    struct TaskWork {
        db: PathBuf,
        plans: [Mutex<VecDeque<(u8, Outcome)>>; 3],
        gates: [Mutex<std::sync::mpsc::Receiver<()>>; 3],
        entered: mpsc::UnboundedSender<(u8, u8)>,
        observed: mpsc::UnboundedSender<Observation>,
        progress: Mutex<Vec<Progress>>,
    }
    impl TaskWork {
        fn mark(&self, call: u8, pump: u8, point: Point) {
            let mut progress = self.progress.lock().unwrap();
            assert!(progress.len() < MAX_EPISODES * 8, "fixture progress bound");
            progress.push(Progress { call, pump, point });
        }
    }
    impl Work for TaskWork {
        fn execute(&self, pump: Pump) -> Completion {
            let index = pump.index();
            let (call, outcome) = self.plans[index]
                .lock()
                .unwrap()
                .pop_front()
                .expect("fixture plan");
            self.mark(call, index as u8, Point::Entered);
            let _ = self.entered.send((call, index as u8));
            // Failure watchdog only. Explicit gates, not elapsed time, order work.
            if self.gates[index]
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .is_err()
            {
                return Completion::Refused;
            }
            if outcome == Outcome::FailedBeforeWrite {
                self.mark(call, index as u8, Point::ReturnedFailure);
                return Completion::Failed;
            }
            let mut db = rusqlite::Connection::open(&self.db).expect("fixture SQLite");
            let tx = db.transaction().expect("fixture transaction");
            self.mark(call, index as u8, Point::Began);
            tx.execute(
                "INSERT INTO task_rows(call,pump) VALUES(?1,?2)",
                rusqlite::params![i64::from(call), index as i64],
            )
            .expect("fixture insert");
            self.mark(call, index as u8, Point::Wrote);
            if outcome == Outcome::PanicBeforeCommit {
                self.mark(call, index as u8, Point::Panicked);
                panic!("controlled host task panic before commit");
            }
            tx.commit().expect("fixture commit");
            self.mark(call, index as u8, Point::Committed);
            match outcome {
                Outcome::PanicAfterCommit => {
                    self.mark(call, index as u8, Point::Panicked);
                    panic!("controlled host task panic after commit");
                }
                Outcome::FailedAfterCommit => {
                    self.mark(call, index as u8, Point::ReturnedFailure);
                    Completion::Failed
                }
                Outcome::Commit => {
                    self.mark(call, index as u8, Point::Finished);
                    Completion::Finished
                }
                _ => unreachable!(),
            }
        }
        fn observe(&self, event: Event, state: &State) {
            let _ = self.observed.send(Observation {
                event,
                state: snapshot(state, None),
            });
        }
    }

    struct Release {
        admitting: Arc<AtomicBool>,
        stop: watch::Sender<bool>,
        gates: [std::sync::mpsc::Sender<()>; 3],
    }
    impl Drop for Release {
        fn drop(&mut self) {
            self.admitting.store(false, Ordering::Release);
            let _ = self.stop.send(true);
            for gate in &self.gates {
                let _ = gate.send(());
            }
        }
    }

    fn source() -> String {
        crate::digest(
            concat!(
                include_str!("host_loop.rs"),
                include_str!("host_loop_tests.rs"),
                include_str!("host_loop_native_tests.rs")
            )
            .as_bytes(),
        )
    }
    fn validate(program: &Program) -> Result<()> {
        anyhow::ensure!(
            program.format == 1 && program.source == source(),
            "task_history_source"
        );
        anyhow::ensure!(
            !program.episodes.is_empty()
                && program.episodes.len() <= MAX_EPISODES
                && program.episodes.iter().all(|episode| episode.pump < 3),
            "task_history_bound"
        );
        anyhow::ensure!(
            !program.owner_thread
                || (!program.stop_during_last
                    && program.episodes.iter().enumerate().all(|(index, episode)| {
                        episode.outcome == Outcome::Commit
                            || index + 1 == program.episodes.len()
                                && matches!(
                                    episode.outcome,
                                    Outcome::FailedBeforeWrite | Outcome::FailedAfterCommit
                                )
                    })),
            "task_history_owner_script"
        );
        Ok(())
    }
    fn generated(seed: u64) -> Program {
        let mut episodes = vec![
            Episode {
                pump: 0,
                outcome: Outcome::PanicBeforeCommit,
            },
            Episode {
                pump: 1,
                outcome: Outcome::PanicAfterCommit,
            },
            Episode {
                pump: 2,
                outcome: Outcome::FailedBeforeWrite,
            },
            Episode {
                pump: 0,
                outcome: Outcome::FailedAfterCommit,
            },
            Episode {
                pump: 1,
                outcome: Outcome::Commit,
            },
        ];
        let mut random = seed;
        for _ in 0..7 {
            random = random
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            episodes.push(Episode {
                pump: ((random >> 32) % 3) as u8,
                outcome: match random % 5 {
                    0 => Outcome::Commit,
                    1 => Outcome::FailedBeforeWrite,
                    2 => Outcome::FailedAfterCommit,
                    3 => Outcome::PanicBeforeCommit,
                    _ => Outcome::PanicAfterCommit,
                },
            });
        }
        Program {
            format: 1,
            owner_thread: false,
            source: source(),
            seed,
            stop_during_last: seed.is_multiple_of(2),
            episodes,
        }
    }

    fn rows(db: &std::path::Path) -> Result<Vec<[i64; 2]>> {
        let connection =
            rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut query = connection.prepare("SELECT call,pump FROM task_rows ORDER BY call")?;
        Ok(query
            .query_map([], |row| Ok([row.get(0)?, row.get(1)?]))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
    fn expected_progress(call: u8, episode: Episode) -> Vec<Progress> {
        let points = match episode.outcome {
            Outcome::FailedBeforeWrite => vec![Point::Entered, Point::ReturnedFailure],
            Outcome::PanicBeforeCommit => {
                vec![Point::Entered, Point::Began, Point::Wrote, Point::Panicked]
            }
            Outcome::PanicAfterCommit => vec![
                Point::Entered,
                Point::Began,
                Point::Wrote,
                Point::Committed,
                Point::Panicked,
            ],
            Outcome::FailedAfterCommit => vec![
                Point::Entered,
                Point::Began,
                Point::Wrote,
                Point::Committed,
                Point::ReturnedFailure,
            ],
            Outcome::Commit => vec![
                Point::Entered,
                Point::Began,
                Point::Wrote,
                Point::Committed,
                Point::Finished,
            ],
        };
        points
            .into_iter()
            .map(|point| Progress {
                call,
                pump: episode.pump,
                point,
            })
            .collect()
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Cut {
        expected_events: Vec<Event>,
        events: Vec<Event>,
        observations: Vec<Snapshot>,
        expected_rows: Vec<[i64; 2]>,
        rows: Option<Vec<[i64; 2]>>,
        expected_progress: Vec<Progress>,
        progress: Vec<Progress>,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Refusal {
        Mismatch,
        Execution,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum DriverEnd {
        AlreadyAwaited,
        Completed,
        Refused,
        JoinFailed,
        Unresolved,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Cleanup {
        driver: DriverEnd,
        final_cut: Cut,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Run {
        program: Program,
        control: Control,
        cuts: Vec<Cut>,
        failed_at: Option<usize>,
        refusal: Option<Refusal>,
        cleanup: Option<Cleanup>,
    }

    async fn observe(
        receiver: &mut mpsc::UnboundedReceiver<Observation>,
        expected: Event,
        events: &mut Vec<Event>,
        observations: &mut Vec<Snapshot>,
        expected_events: &mut Vec<Event>,
    ) -> Result<bool> {
        let actual = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("fixture observation closed"))?;
        events.push(actual.event);
        observations.push(actual.state.clone());
        expected_events.push(expected);
        Ok(actual.event == expected && actual.state == reference(true, expected_events))
    }

    async fn execute(program: &Program, control: Control) -> Result<Run> {
        validate(program)?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("tasks.sqlite");
        rusqlite::Connection::open(&path)?.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE task_rows(call INTEGER PRIMARY KEY,pump INTEGER NOT NULL) STRICT;")?;
        let pairs = std::array::from_fn::<_, 3, _>(|_| mpsc::unbounded_channel());
        let (tick_send, tick_receive): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        let ticks = Arc::new(ManualTicks {
            receive: tick_receive
                .into_iter()
                .map(|receive| Mutex::new(Some(receive)))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        });
        let pairs = std::array::from_fn::<_, 3, _>(|_| std::sync::mpsc::channel());
        let (release, gates): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        let (stop, stopped) = watch::channel(false);
        let admitting = Arc::new(AtomicBool::new(true));
        let cleanup = Release {
            admitting: admitting.clone(),
            stop,
            gates: release.try_into().unwrap(),
        };
        let mut plans: [VecDeque<(u8, Outcome)>; 3] = std::array::from_fn(|_| VecDeque::new());
        for (index, episode) in program.episodes.iter().enumerate() {
            plans[usize::from(episode.pump)].push_back((index as u8, episode.outcome));
        }
        let (entered, mut entries) = mpsc::unbounded_channel();
        let (observed, mut actual) = mpsc::unbounded_channel();
        let work = Arc::new(TaskWork {
            db: path.clone(),
            plans: plans.map(Mutex::new),
            gates: gates
                .into_iter()
                .map(Mutex::new)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            entered,
            observed,
            progress: Mutex::new(vec![]),
        });
        let execution = if program.owner_thread {
            Execution::OwnerThread
        } else {
            Execution::BlockingPool
        };
        let mut driver = Some(tokio::spawn(drive_mode(
            work.clone(),
            ticks,
            admitting.clone(),
            stopped,
            true,
            execution,
        )));
        let mut cuts = vec![];
        let mut events = vec![];
        let mut observations = vec![];
        let mut expected_events = vec![];
        let mut expected_rows = vec![];
        let mut progress = vec![];
        let attempted: Result<Option<usize>> = async {
            for (index, &episode) in program.episodes.iter().enumerate() {
                let pump = Pump::ALL[usize::from(episode.pump)];
                if program.owner_thread {
                    cleanup.gates[usize::from(episode.pump)].send(())?;
                }
                tick_send[usize::from(episode.pump)].send(())?;
                let mut matched = observe(
                    &mut actual,
                    Event::Wake(pump),
                    &mut events,
                    &mut observations,
                    &mut expected_events,
                )
                .await?;
                matched &= observe(
                    &mut actual,
                    Event::Dispatch(pump, true),
                    &mut events,
                    &mut observations,
                    &mut expected_events,
                )
                .await?;
                let entry = tokio::time::timeout(Duration::from_secs(10), entries.recv())
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("fixture entry closed"))?;
                matched &= entry == (index as u8, episode.pump);
                anyhow::ensure!(
                    control != Control::AbortObservationAfterEntry,
                    "controlled_observer_refusal"
                );
                if !program.owner_thread {
                    matched &= rows(&path)? == expected_rows;
                }
                if program.stop_during_last && index + 1 == program.episodes.len() {
                    cleanup.stop.send(true)?;
                    for _ in 0..2 {
                        matched &= observe(
                            &mut actual,
                            Event::Stop,
                            &mut events,
                            &mut observations,
                            &mut expected_events,
                        )
                        .await?;
                    }
                    matched &= !driver.as_ref().expect("fixture driver").is_finished();
                }
                if !program.owner_thread {
                    cleanup.gates[usize::from(episode.pump)].send(())?;
                }
                let completion = if episode.outcome == Outcome::Commit {
                    Completion::Finished
                } else {
                    Completion::Failed
                };
                matched &= observe(
                    &mut actual,
                    Event::Complete(pump, completion),
                    &mut events,
                    &mut observations,
                    &mut expected_events,
                )
                .await?;
                if matches!(
                    episode.outcome,
                    Outcome::Commit | Outcome::FailedAfterCommit | Outcome::PanicAfterCommit
                ) && !(control == Control::ForgetFailedCommit
                    && episode.outcome != Outcome::Commit)
                {
                    expected_rows.push([index as i64, i64::from(episode.pump)]);
                }
                progress.extend(expected_progress(index as u8, episode));
                let durable = rows(&path)?;
                let observed_progress = work.progress.lock().unwrap().clone();
                matched &= durable == expected_rows && observed_progress == progress;
                cuts.push(Cut {
                    expected_events: expected_events.clone(),
                    events: events.clone(),
                    observations: observations.clone(),
                    expected_rows: expected_rows.clone(),
                    rows: Some(durable),
                    expected_progress: progress.clone(),
                    progress: observed_progress,
                });
                if !matched {
                    return Ok(Some(index));
                }
            }
            let owner_failed = program.owner_thread
                && program
                    .episodes
                    .last()
                    .is_some_and(|episode| episode.outcome != Outcome::Commit);
            if owner_failed {
                for _ in 0..2 {
                    anyhow::ensure!(
                        observe(
                            &mut actual,
                            Event::Stop,
                            &mut events,
                            &mut observations,
                            &mut expected_events
                        )
                        .await?,
                        "task_history_owner_stop"
                    );
                }
            } else if !program.stop_during_last {
                cleanup.stop.send(true)?;
                for _ in 0..2 {
                    anyhow::ensure!(
                        observe(
                            &mut actual,
                            Event::Stop,
                            &mut events,
                            &mut observations,
                            &mut expected_events
                        )
                        .await?,
                        "task_history_idle_stop"
                    );
                }
            } else {
                anyhow::ensure!(
                    observe(
                        &mut actual,
                        Event::Stop,
                        &mut events,
                        &mut observations,
                        &mut expected_events
                    )
                    .await?,
                    "task_history_final_stop"
                );
            }
            let outcome = driver.take().expect("fixture driver").await?;
            if owner_failed {
                anyhow::ensure!(
                    outcome.is_err(),
                    "task_history_owner_failure_became_success"
                );
            } else {
                outcome?;
            }
            anyhow::ensure!(
                actual.try_recv().is_err()
                    && entries.try_recv().is_err()
                    && !admitting.load(Ordering::Acquire),
                "task_history_not_drained"
            );
            cuts.push(Cut {
                expected_events: expected_events.clone(),
                events: events.clone(),
                observations: observations.clone(),
                expected_rows: expected_rows.clone(),
                rows: Some(rows(&path)?),
                expected_progress: progress.clone(),
                progress: work.progress.lock().unwrap().clone(),
            });
            Ok(None)
        }
        .await;
        let (failed_at, refusal) = match attempted {
            Ok(Some(index)) => (Some(index), Some(Refusal::Mismatch)),
            Ok(None) => (None, None),
            Err(_) => {
                let index = cuts.len();
                // Preserve the complete prefix already observed before cleanup,
                // without formatting arbitrary IO/panic/provider errors.
                cuts.push(Cut {
                    expected_events: expected_events.clone(),
                    events: events.clone(),
                    observations: observations.clone(),
                    expected_rows: expected_rows.clone(),
                    rows: rows(&path).ok(),
                    expected_progress: progress.clone(),
                    progress: work.progress.lock().unwrap().clone(),
                });
                (Some(index), Some(Refusal::Execution))
            }
        };
        let cleanup_record = if refusal.is_some() {
            admitting.store(false, Ordering::Release);
            let _ = cleanup.stop.send(true);
            for gate in &cleanup.gates {
                let _ = gate.send(());
            }
            let driver_end = match driver.as_mut() {
                None => DriverEnd::AlreadyAwaited,
                Some(driver) => match tokio::time::timeout(Duration::from_secs(10), driver).await {
                    Ok(Ok(Ok(()))) => DriverEnd::Completed,
                    Ok(Ok(Err(_))) => DriverEnd::Refused,
                    Ok(Err(_)) => DriverEnd::JoinFailed,
                    Err(_) => DriverEnd::Unresolved,
                },
            };
            while let Ok(observation) = actual.try_recv() {
                events.push(observation.event);
                observations.push(observation.state);
            }
            Some(Cleanup {
                driver: driver_end,
                final_cut: Cut {
                    expected_events,
                    events,
                    observations,
                    expected_rows,
                    rows: rows(&path).ok(),
                    expected_progress: progress,
                    progress: work.progress.lock().unwrap().clone(),
                },
            })
        } else {
            None
        };
        Ok(Run {
            program: program.clone(),
            control,
            cuts,
            failed_at,
            refusal,
            cleanup: cleanup_record,
        })
    }

    fn run(program: &Program, control: Control) -> Result<Run> {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .max_blocking_threads(1)
            .build()?
            .block_on(execute(program, control))
    }

    #[test]
    fn task_failures_before_and_after_commit_replay_with_independent_rows() -> Result<()> {
        for seed in [0, 1, 17, 71] {
            let program = generated(seed);
            let first = run(&program, Control::Correct)?;
            let second = run(&program, Control::Correct)?;
            if first.failed_at.is_some() || first != second {
                let a = retain(&first)?;
                let b = retain(&second)?;
                anyhow::bail!(
                    "host task history divergence; first={} second={}",
                    a.display(),
                    b.display()
                );
            }
            anyhow::ensure!(
                first.cuts.len() == program.episodes.len() + 1,
                "host task history incomplete"
            );
        }
        Ok(())
    }

    fn retain(value: &Run) -> Result<std::path::PathBuf> {
        use std::os::unix::fs::PermissionsExt;
        let root = std::path::Path::new("/tmp/dst-platform-host-loops/task-execution");
        std::fs::create_dir_all(root)?;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        let file = tempfile::Builder::new()
            .prefix("replay-")
            .suffix(".json")
            .tempfile_in(root)?;
        let bytes = serde_json::to_vec(value)?;
        anyhow::ensure!(bytes.len() <= 2 * 1024 * 1024, "task_history_record_bound");
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))?;
        std::fs::write(file.path(), bytes)?;
        let (_, path) = file.keep()?;
        Ok(path)
    }

    fn read_replay(path: &std::path::Path) -> Result<Run> {
        use std::io::Read;
        anyhow::ensure!(
            std::fs::symlink_metadata(path)?.file_type().is_file(),
            "task_history_replay_regular_file"
        );
        let mut bytes = vec![];
        std::fs::File::open(path)?
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        anyhow::ensure!(bytes.len() <= 2 * 1024 * 1024, "task_history_record_bound");
        let input: serde_json::Value = crate::json::decode_evidence(&bytes)?;
        let saved: Run = serde_json::from_value(input.clone())?;
        anyhow::ensure!(
            input == serde_json::to_value(&saved)?,
            "task_history_canonical_shape"
        );
        validate(&saved.program)?;
        anyhow::ensure!(
            !saved.cuts.is_empty() && saved.cuts.len() <= MAX_EPISODES + 1,
            "task_history_cut_bound"
        );
        Ok(saved)
    }

    fn replay_file(path: &std::path::Path) -> Result<()> {
        let saved = read_replay(path)?;
        let first = run(&saved.program, saved.control)?;
        let second = run(&saved.program, saved.control)?;
        anyhow::ensure!(
            saved
                .cleanup
                .as_ref()
                .is_none_or(|cleanup| cleanup.driver != DriverEnd::Unresolved),
            "task_history_cleanup_unresolved"
        );
        anyhow::ensure!(
            first == saved && second == saved,
            "task_history_replay_changed"
        );
        Ok(())
    }

    #[test]
    fn failed_task_does_not_prove_rollback_and_wrong_oracle_replays() -> Result<()> {
        let mut program = generated(17);
        program.episodes.truncate(2);
        program.stop_during_last = false;
        let first = run(&program, Control::ForgetFailedCommit)?;
        let second = run(&program, Control::ForgetFailedCommit)?;
        anyhow::ensure!(
            first.failed_at == Some(1)
                && first == second
                && first.refusal == Some(Refusal::Mismatch),
            "task_history_false_rollback_oracle_escaped"
        );
        let failed = first.cuts.last().context("false rollback cut absent")?;
        anyhow::ensure!(
            failed.expected_rows.is_empty()
                && failed.rows == Some(vec![[1, 1]])
                && failed
                    .progress
                    .iter()
                    .filter(|point| point.call == 1
                        && point.pump == 1
                        && point.point == Point::Committed)
                    .count()
                    == 1,
            "false rollback did not observe the actual committed row"
        );
        let mut before_commit = program.clone();
        before_commit.episodes[1].outcome = Outcome::PanicBeforeCommit;
        anyhow::ensure!(
            run(&before_commit, Control::ForgetFailedCommit)?
                .failed_at
                .is_none(),
            "false rollback control spuriously disagreed without commit"
        );
        let path = retain(&first)?;
        let saved = read_replay(&path)?;
        anyhow::ensure!(
            run(&saved.program, saved.control)? == saved,
            "task_history_failure_replay_changed"
        );
        Ok(())
    }

    #[test]
    fn owner_thread_failure_fences_new_work_without_erasing_committed_rows() -> Result<()> {
        for pump in 0..3 {
            for outcome in [Outcome::FailedBeforeWrite, Outcome::FailedAfterCommit] {
                let mut program = generated(u64::from(pump));
                program.owner_thread = true;
                program.stop_during_last = false;
                program.episodes = vec![
                    Episode {
                        pump,
                        outcome: Outcome::Commit,
                    },
                    Episode { pump, outcome },
                ];
                let first = run(&program, Control::Correct)?;
                let second = run(&program, Control::Correct)?;
                if first.failed_at.is_some() || first != second {
                    let a = retain(&first)?;
                    let b = retain(&second)?;
                    anyhow::bail!(
                        "owner task history divergence; first={} second={}",
                        a.display(),
                        b.display()
                    );
                }
                anyhow::ensure!(
                    first.cuts.last().is_some_and(|cut| cut
                        .observations
                        .last()
                        .is_some_and(|state| state.stopping && state.drained)),
                    "task_history_owner_not_permanently_stopped"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn saved_task_history_refuses_unknown_source_shapes_and_changed_observations() -> Result<()> {
        let mut program = generated(17);
        program.episodes.truncate(2);
        program.stop_during_last = false;
        let saved = run(&program, Control::ForgetFailedCommit)?;
        let file = retain(&saved)?;
        replay_file(&file)?;
        let original = std::fs::read(&file)?;
        let value: serde_json::Value = crate::json::decode_evidence(&original)?;
        let mut changes = vec![];
        let mut changed = value.clone();
        changed["program"]["source"] = serde_json::json!("not-the-reviewed-source");
        changes.push(changed);
        let mut changed = value.clone();
        changed["program"]["format"] = serde_json::json!(2);
        changes.push(changed);
        let mut changed = value.clone();
        changed["program"]["episodes"][0]["pump"] = serde_json::json!(3);
        changes.push(changed);
        let mut changed = value.clone();
        changed["program"]["episodes"] = serde_json::json!([]);
        changes.push(changed);
        let mut changed = value.clone();
        changed["program"]["episodes"] =
            serde_json::to_value(vec![program.episodes[0]; MAX_EPISODES + 1])?;
        changes.push(changed);
        let mut changed = value.clone();
        changed["program"]["episodes"][0]["outcome"] = serde_json::json!({"Commit":null});
        changes.push(changed);
        let mut changed = value.clone();
        changed["program"]["unknown"] = serde_json::json!(true);
        changes.push(changed);
        let mut changed = value.clone();
        changed["unknown"] = serde_json::json!(true);
        changes.push(changed);
        for changed in changes {
            std::fs::write(&file, serde_json::to_vec(&changed)?)?;
            anyhow::ensure!(
                read_replay(&file).is_err(),
                "task_history_invalid_input_accepted"
            );
        }
        std::fs::write(&file, b"{\"control\":\"Correct\",\"control\":\"Correct\"}")?;
        anyhow::ensure!(
            read_replay(&file).is_err(),
            "task_history_duplicate_field_accepted"
        );
        std::fs::write(&file, &original[..original.len() / 2])?;
        anyhow::ensure!(
            read_replay(&file).is_err(),
            "task_history_truncated_input_accepted"
        );
        std::fs::write(&file, vec![b' '; 2 * 1024 * 1024 + 1])?;
        anyhow::ensure!(
            read_replay(&file).is_err(),
            "task_history_oversize_input_accepted"
        );
        let mut changed = value;
        changed["cuts"][1]["rows"] = serde_json::json!([]);
        std::fs::write(&file, serde_json::to_vec(&changed)?)?;
        anyhow::ensure!(
            replay_file(&file).is_err(),
            "task_history_changed_observation_accepted"
        );
        std::fs::write(&file, original)?;
        replay_file(&file)?;
        Ok(())
    }

    #[test]
    fn maximum_task_history_replays_without_dropping_any_cut() -> Result<()> {
        let mut program = generated(0);
        while program.episodes.len() < MAX_EPISODES {
            program.episodes.push(Episode {
                pump: (program.episodes.len() % 3) as u8,
                outcome: Outcome::Commit,
            });
        }
        let first = run(&program, Control::Correct)?;
        let second = run(&program, Control::Correct)?;
        if first.failed_at.is_some() || first != second {
            let a = retain(&first)?;
            let b = retain(&second)?;
            anyhow::bail!(
                "maximum task history divergence; first={} second={}",
                a.display(),
                b.display()
            );
        }
        anyhow::ensure!(
            first.cuts.len() == MAX_EPISODES + 1,
            "task_history_maximum_truncated"
        );
        let path = retain(&first)?;
        replay_file(&path)?;
        Ok(())
    }

    #[test]
    fn external_task_history_replays_twice_when_explicitly_supplied() -> Result<()> {
        let Some(path) = std::env::var_os("DAY2_HOST_TASK_REPLAY") else {
            return Ok(());
        };
        replay_file(std::path::Path::new(&path))
    }

    #[test]
    fn observer_refusal_keeps_the_inflight_prefix_and_actual_cleanup_commit() -> Result<()> {
        let mut program = generated(17);
        program.stop_during_last = false;
        program.episodes = vec![Episode {
            pump: 0,
            outcome: Outcome::Commit,
        }];
        let first = run(&program, Control::AbortObservationAfterEntry)?;
        let second = run(&program, Control::AbortObservationAfterEntry)?;
        anyhow::ensure!(
            first == second
                && first.failed_at == Some(0)
                && first.refusal == Some(Refusal::Execution),
            "observer_refusal_prefix_changed"
        );
        anyhow::ensure!(
            first.cuts[0].rows == Some(vec![])
                && first.cuts[0].progress
                    == vec![Progress {
                        call: 0,
                        pump: 0,
                        point: Point::Entered
                    }],
            "observer_refusal_lost_pending_work"
        );
        let cleanup = first.cleanup.as_ref().context("observer cleanup absent")?;
        anyhow::ensure!(
            cleanup.driver == DriverEnd::Completed
                && cleanup.final_cut.rows == Some(vec![[0, 0]])
                && cleanup
                    .final_cut
                    .progress
                    .last()
                    .is_some_and(|p| p.point == Point::Finished),
            "observer_refusal_claimed_rollback_or_unresolved_cleanup"
        );
        anyhow::ensure!(
            cleanup
                .final_cut
                .observations
                .last()
                .is_some_and(|s| s.drained && s.stopping),
            "observer_cleanup_not_drained"
        );
        let path = retain(&first)?;
        replay_file(&path)?;
        Ok(())
    }
}
