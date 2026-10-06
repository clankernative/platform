//! First-come-first-served write transactions per SQLite file, within this process.
//!
//! SQLite admits one writer per database. Its busy handler is not a queue: a
//! waiting connection sleeps with growing backoff and retries, so under steady
//! contention a writer can keep losing the lock to others until its timeout
//! expires, even though every transaction is short. Taking a turn in this line
//! before `BEGIN IMMEDIATE` serves writers in arrival order instead. SQLite's own
//! busy timeout remains the backstop for writers in other processes.
//!
//! A turn that cannot start within [`WAIT`] fails as `SQLITE_BUSY`, which callers
//! already treat as a retryable storage failure. A thread that already holds the
//! turn for a database passes through, so nested use behaves exactly as SQLite
//! alone would.
//!
//! Admission retains at most 64 queued waiters per database and 1024 database
//! lines with live users. Saturation and arithmetic exhaustion also fail as busy.
//! The registry holds weak references: an idle line can disappear only after
//! every holder, waiter and caller enrolling in that line releases its strong
//! reference. Reclaiming an idle path therefore cannot split an active FIFO.
use rusqlite::{Connection, Transaction, TransactionBehavior};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex, OnceLock, Weak},
    time::{Duration, Instant},
};

/// How long a writer waits for its turn before failing as busy.
pub const WAIT: Duration = Duration::from_secs(30);

// Fixed native admission budgets, independent of instance/app configuration.
const MAX_WAITERS: usize = 64;
const MAX_DATABASES: usize = 1024;

#[derive(Default)]
struct Line {
    state: Mutex<State>,
    ready: Condvar,
}

#[derive(Default)]
struct State {
    next: u64,
    waiting: VecDeque<u64>,
    holder: Option<u64>,
}

impl State {
    fn enqueue(&mut self) -> rusqlite::Result<u64> {
        if self.waiting.len() >= MAX_WAITERS {
            return Err(busy("write queue waiter capacity exceeded"));
        }
        let ticket = self.next;
        let next = ticket
            .checked_add(1)
            .ok_or_else(|| busy("write queue ticket space exhausted"))?;
        self.waiting.push_back(ticket);
        self.next = next;
        Ok(ticket)
    }
}

#[derive(Default)]
struct Registry {
    lines: HashMap<PathBuf, Weak<Line>>,
}

impl Registry {
    fn line(&mut self, path: &Path) -> rusqlite::Result<Arc<Line>> {
        if let Some(line) = self.lines.get(path).and_then(Weak::upgrade) {
            return Ok(line);
        }
        // Only a zero strong count is reclaimable. Even a caller that has not
        // yet acquired the state mutex keeps its queue's identity alive.
        self.lines.retain(|_, line| line.strong_count() != 0);
        if self.lines.len() >= MAX_DATABASES {
            return Err(busy("write queue database capacity exceeded"));
        }
        let line = Arc::new(Line::default());
        self.lines.insert(path.to_owned(), Arc::downgrade(&line));
        Ok(line)
    }
}

fn lines() -> &'static Mutex<Registry> {
    static LINES: OnceLock<Mutex<Registry>> = OnceLock::new();
    LINES.get_or_init(Default::default)
}

thread_local! {
    static HELD: RefCell<HashSet<PathBuf>> = RefCell::new(HashSet::new());
    static CAP: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

/// Run `work` with every write turn on this thread waiting at most `wait`.
///
/// For callers answering someone with a deadline of their own, such as a webhook
/// provider that abandons a delivery after ten seconds: failing fast and visibly
/// beats recording a delivery the provider has already given up on.
pub fn bounded<T>(wait: Duration, work: impl FnOnce() -> T) -> T {
    let previous = CAP.with(|cap| cap.replace(Some(wait)));
    struct Restore(Option<Duration>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CAP.with(|cap| cap.set(self.0));
        }
    }
    let _restore = Restore(previous);
    work()
}

fn busy(message: &str) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
        Some(message.into()),
    )
}

/// This thread's place at the front of one database's line, released on drop.
enum Turn {
    Held {
        line: Arc<Line>,
        path: PathBuf,
    },
    /// In-memory databases, and nested use by the thread already holding the turn.
    Passthrough,
}

impl Turn {
    fn take(path: Option<&str>, wait: Duration) -> rusqlite::Result<Self> {
        let Some(path) = path.filter(|path| !path.is_empty()).map(PathBuf::from) else {
            return Ok(Self::Passthrough);
        };
        if HELD.with(|held| held.borrow().contains(&path)) {
            return Ok(Self::Passthrough);
        }
        let deadline = Instant::now()
            .checked_add(wait)
            .ok_or_else(|| busy("write queue deadline overflow"))?;
        let line = lines()
            .lock()
            .map_err(|_| busy("write queue unavailable"))?
            .line(&path)?;
        let mut state = line
            .state
            .lock()
            .map_err(|_| busy("write queue unavailable"))?;
        let ticket = state.enqueue()?;
        #[cfg(test)]
        line.ready.notify_all();
        loop {
            if state.holder.is_none() && state.waiting.front() == Some(&ticket) {
                state.waiting.pop_front();
                state.holder = Some(ticket);
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                state.waiting.retain(|waiting| *waiting != ticket);
                drop(state);
                // The next writer in line may now be at the front.
                line.ready.notify_all();
                return Err(busy("write queue wait exceeded"));
            }
            state = line
                .ready
                .wait_timeout(state, remaining)
                .map_err(|_| busy("write queue unavailable"))?
                .0;
        }
        drop(state);
        HELD.with(|held| held.borrow_mut().insert(path.clone()));
        Ok(Self::Held { line, path })
    }
}

impl Drop for Turn {
    fn drop(&mut self) {
        if let Self::Held { line, path } = self {
            HELD.with(|held| held.borrow_mut().remove(path));
            if let Ok(mut state) = line.state.lock() {
                state.holder = None;
            }
            line.ready.notify_all();
        }
    }
}

/// An immediate transaction that holds this process's write turn for its database
/// until it commits or rolls back. Field order matters: the transaction rolls back
/// before the turn is released.
pub struct WriteTransaction<'connection> {
    transaction: Option<Transaction<'connection>>,
    _turn: Turn,
}

impl<'connection> WriteTransaction<'connection> {
    pub fn commit(mut self) -> rusqlite::Result<()> {
        self.transaction
            .take()
            .expect("write transaction is present until consumed")
            .commit()
    }

    pub fn rollback(mut self) -> rusqlite::Result<()> {
        self.transaction
            .take()
            .expect("write transaction is present until consumed")
            .rollback()
    }
}

impl<'connection> Deref for WriteTransaction<'connection> {
    type Target = Transaction<'connection>;

    fn deref(&self) -> &Self::Target {
        self.transaction
            .as_ref()
            .expect("write transaction is present until consumed")
    }
}

impl DerefMut for WriteTransaction<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.transaction
            .as_mut()
            .expect("write transaction is present until consumed")
    }
}

/// Begin an immediate transaction after this process's earlier writers to the same
/// database, in arrival order.
pub fn immediate(connection: &mut Connection) -> rusqlite::Result<WriteTransaction<'_>> {
    let wait = CAP.with(|cap| cap.get()).map_or(WAIT, |cap| cap.min(WAIT));
    immediate_within(connection, wait)
}

fn immediate_within(
    connection: &mut Connection,
    wait: Duration,
) -> rusqlite::Result<WriteTransaction<'_>> {
    let turn = Turn::take(connection.path(), wait)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    Ok(WriteTransaction {
        transaction: Some(transaction),
        _turn: turn,
    })
}

/// Configure the main journal under the same line as its writers, outside a
/// transaction: SQLite cannot enter WAL while a transaction is active. This
/// fixed setup admits no callback, alternate settings or escaping queue turn.
/// File-backed journals must actually enter WAL; private temporary/in-memory
/// databases retain SQLite's DELETE/MEMORY modes, as before.
pub fn configure_journal(connection: &mut Connection) -> rusqlite::Result<()> {
    if !connection.is_autocommit() {
        return Err(configuration_refused(
            "journal configuration requires autocommit",
        ));
    }
    let path = connection
        .path()
        .ok_or_else(|| configuration_refused("journal database path unavailable"))?;
    let file_backed = !path.is_empty();
    let wait = CAP.with(|cap| cap.get()).map_or(WAIT, |cap| cap.min(WAIT));
    let _turn = Turn::take(Some(path), wait)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    let mode: String =
        connection
            .pragma_update_and_check(Some("main"), "journal_mode", "WAL", |row| row.get(0))?;
    if (file_backed && mode != "wal")
        || (!file_backed && !matches!(mode.as_str(), "delete" | "memory"))
    {
        return Err(configuration_refused(
            "journal WAL configuration unavailable",
        ));
    }
    connection.pragma_update(Some("main"), "synchronous", "FULL")?;
    let foreign_keys: i64 =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let synchronous: i64 =
        connection.pragma_query_value(Some("main"), "synchronous", |row| row.get(0))?;
    if foreign_keys != 1 || synchronous != 2 {
        return Err(configuration_refused("journal safety settings unavailable"));
    }
    Ok(())
}

fn configuration_refused(message: &'static str) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISUSE),
        Some(message.into()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    const TEST_WAIT: Duration = Duration::from_secs(5);

    fn database() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("queue.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE log(writer INTEGER NOT NULL);")
            .unwrap();
        // SQLite reports the normalized file path used by production admission
        // (macOS temporary-directory aliases may have a different spelling).
        let path = PathBuf::from(connection.path().unwrap());
        (directory, path)
    }

    fn registered_line(path: &Path) -> Arc<Line> {
        let line = lines()
            .lock()
            .unwrap()
            .lines
            .get(path)
            .and_then(Weak::upgrade);
        line.expect("a holding transaction keeps its line alive")
    }

    fn await_waiters(line: &Line, expected: usize) {
        let deadline = Instant::now().checked_add(TEST_WAIT).unwrap();
        let mut state = line.state.lock().unwrap();
        while state.waiting.len() != expected {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "waiter acknowledgement deadline exceeded"
            );
            state = line.ready.wait_timeout(state, remaining).unwrap().0;
        }
    }

    fn writer(
        path: PathBuf,
        value: i64,
        wait: Duration,
    ) -> std::thread::JoinHandle<rusqlite::Result<()>> {
        std::thread::spawn(move || {
            let mut connection = Connection::open(path)?;
            let transaction = immediate_within(&mut connection, wait)?;
            transaction.execute("INSERT INTO log VALUES (?1)", [value])?;
            transaction.commit()
        })
    }

    fn written(connection: &Connection) -> Vec<i64> {
        connection
            .prepare("SELECT writer FROM log ORDER BY rowid")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn assert_busy(error: &rusqlite::Error, message: &str) {
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy)
        );
        assert!(
            error.to_string().contains(message),
            "wrong rejection: {error}"
        );
    }

    #[test]
    fn writers_are_served_in_arrival_order() {
        let (_directory, path) = database();
        let mut first = Connection::open(&path).unwrap();
        let holding = immediate(&mut first).unwrap();
        let line = registered_line(&path);
        let mut writers = Vec::new();
        for value in 0..6_i64 {
            writers.push(writer(path.clone(), value, TEST_WAIT));
            // Acknowledge actual enrollment under the queue mutex, rather than
            // guessing arrival order from scheduling or an arbitrary sleep.
            await_waiters(&line, writers.len());
        }
        holding.commit().unwrap();
        for writer in writers {
            writer.join().unwrap().unwrap();
        }
        assert_eq!(written(&first), (0..6).collect::<Vec<_>>());
    }

    #[test]
    fn journal_configuration_takes_the_same_turn_before_a_later_writer() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rollback.sqlite");
        let mut first = Connection::open(&path).unwrap();
        first
            .execute_batch("CREATE TABLE log(writer INTEGER NOT NULL)")
            .unwrap();
        let path = PathBuf::from(first.path().unwrap());
        let holding = immediate(&mut first).unwrap();
        holding.execute("INSERT INTO log VALUES (-1)", []).unwrap();
        let line = registered_line(&path);
        let configuration = {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut connection = Connection::open(path).unwrap();
                connection.busy_timeout(TEST_WAIT).unwrap();
                configure_journal(&mut connection)?;
                let mode: String =
                    connection
                        .pragma_query_value(Some("main"), "journal_mode", |row| row.get(0))?;
                let foreign_keys: i64 =
                    connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
                let synchronous: i64 =
                    connection.pragma_query_value(Some("main"), "synchronous", |row| row.get(0))?;
                Ok::<_, rusqlite::Error>((mode, foreign_keys, synchronous))
            })
        };
        await_waiters(&line, 1);
        let later = writer(path.clone(), 7, TEST_WAIT);
        await_waiters(&line, 2);
        holding.commit().unwrap();
        let configured = configuration.join();
        let written_later = later.join();
        assert_eq!(configured.unwrap().unwrap(), ("wal".into(), 1, 2));
        written_later.unwrap().unwrap();
        assert_eq!(written(&first), [-1, 7]);
        let reopened = Connection::open(path).unwrap();
        assert_eq!(
            reopened
                .pragma_query_value(Some("main"), "journal_mode", |row| row.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
    }

    #[test]
    fn journal_configuration_refuses_an_active_transaction_without_committing_or_changing_settings()
    {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE log(writer INTEGER NOT NULL); BEGIN; INSERT INTO log VALUES (1)",
            )
            .unwrap();
        let error = configure_journal(&mut connection).unwrap_err();
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::ApiMisuse)
        );
        assert!(!connection.is_autocommit());
        assert_eq!(
            connection
                .pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
        connection.execute_batch("ROLLBACK").unwrap();
        assert!(written(&connection).is_empty());
        configure_journal(&mut connection).unwrap();
    }

    #[test]
    fn journal_configuration_keeps_private_database_modes_explicit() {
        for (mut connection, expected) in [
            (Connection::open_in_memory().unwrap(), "memory"),
            (Connection::open("").unwrap(), "delete"),
        ] {
            assert_eq!(connection.path(), Some(""));
            configure_journal(&mut connection).unwrap();
            assert_eq!(
                connection
                    .pragma_query_value(Some("main"), "journal_mode", |row| row.get::<_, String>(0))
                    .unwrap(),
                expected
            );
            assert_eq!(
                connection
                    .pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))
                    .unwrap(),
                1
            );
            assert_eq!(
                connection
                    .pragma_query_value(Some("main"), "synchronous", |row| row.get::<_, i64>(0))
                    .unwrap(),
                2
            );
        }
    }

    #[test]
    fn journal_configuration_respects_the_existing_bounded_turn_before_any_setting_changes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bounded.sqlite");
        let mut first = Connection::open(&path).unwrap();
        first
            .execute_batch("CREATE TABLE log(writer INTEGER NOT NULL)")
            .unwrap();
        let holding = immediate(&mut first).unwrap();
        let rejected = std::thread::spawn(move || {
            let mut connection = Connection::open(path).unwrap();
            let error = bounded(Duration::ZERO, || configure_journal(&mut connection)).unwrap_err();
            let foreign_keys = connection
                .pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))
                .unwrap();
            (error, foreign_keys)
        })
        .join()
        .unwrap();
        assert_busy(&rejected.0, "wait exceeded");
        assert_eq!(rejected.1, 0);
        holding.rollback().unwrap();
    }

    #[test]
    fn waiter_cap_plus_one_rejects_without_reordering_admitted_sqlite_writes() {
        let (_directory, path) = database();
        let mut first = Connection::open(&path).unwrap();
        let holding = immediate(&mut first).unwrap();
        let line = registered_line(&path);
        let mut writers = Vec::new();
        for value in 0..MAX_WAITERS {
            writers.push(writer(path.clone(), value as i64, TEST_WAIT));
            await_waiters(&line, writers.len());
        }
        let next = line.state.lock().unwrap().next;
        let rejected = writer(path.clone(), -1, Duration::ZERO)
            .join()
            .unwrap()
            .unwrap_err();
        assert_busy(&rejected, "waiter capacity exceeded");
        let state = line.state.lock().unwrap();
        assert_eq!(state.waiting.len(), MAX_WAITERS);
        assert_eq!(state.next, next);
        drop(state);
        holding.commit().unwrap();
        for writer in writers {
            writer.join().unwrap().unwrap();
        }
        assert_eq!(written(&first), (0..MAX_WAITERS as i64).collect::<Vec<_>>());
    }

    #[test]
    fn checked_ticket_exhaustion_rejects_without_mutating_the_queue() {
        let mut state = State {
            next: u64::MAX - 1,
            waiting: VecDeque::new(),
            holder: Some(u64::MAX - 2),
        };
        assert_eq!(state.enqueue().unwrap(), u64::MAX - 1);
        let waiting = state.waiting.clone();
        assert_busy(&state.enqueue().unwrap_err(), "ticket space exhausted");
        assert_eq!(state.next, u64::MAX);
        assert_eq!(state.waiting, waiting);
        assert_eq!(state.holder, Some(u64::MAX - 2));
        assert_eq!(State::default().enqueue().unwrap(), 0);
    }

    #[test]
    fn an_unrepresentable_deadline_rejects_before_registering_a_line() {
        let (_directory, path) = database();
        let error = Turn::take(path.to_str(), Duration::MAX)
            .map(|_| ())
            .unwrap_err();
        assert_busy(&error, "deadline overflow");
        assert!(!lines().lock().unwrap().lines.contains_key(&path));
        // Zero wait still admits a free line immediately, as before.
        drop(Turn::take(path.to_str(), Duration::ZERO).unwrap());
    }

    #[test]
    fn registry_cap_preserves_live_identity_before_enrollment_and_reclaims_only_dead_lines() {
        let mut registry = Registry::default();
        let path = PathBuf::from("pending.sqlite");
        let pending = registry.line(&path).unwrap();
        let identity = Arc::downgrade(&pending);
        let mut live = Vec::new();
        for index in 1..MAX_DATABASES {
            live.push(
                registry
                    .line(&PathBuf::from(format!("{index}.sqlite")))
                    .unwrap(),
            );
        }
        assert_eq!(registry.lines.len(), MAX_DATABASES);
        let same = registry.line(&path).unwrap();
        assert!(Arc::ptr_eq(&pending, &same));
        let extra = PathBuf::from("over-cap.sqlite");
        let rejected = registry.line(&extra).err().unwrap();
        assert_busy(&rejected, "database capacity exceeded");
        drop(pending);
        // The remaining caller has not enqueued a ticket, but still owns the
        // identity. Treating an empty State as idle would split its queue.
        assert_busy(
            &registry.line(&extra).err().unwrap(),
            "database capacity exceeded",
        );
        drop(same);
        assert!(identity.upgrade().is_none());
        let admitted = registry.line(&extra).unwrap();
        assert_eq!(registry.lines.len(), MAX_DATABASES);
        assert!(!registry.lines.contains_key(&path));
        drop(admitted);
        let renewed = registry.line(&path).unwrap();
        assert!(Arc::ptr_eq(&renewed, &registry.line(&path).unwrap()));
        assert_eq!(live.len(), MAX_DATABASES - 1);
    }

    #[test]
    fn repeated_idle_paths_do_not_grow_the_process_registry() {
        let mut registry = Registry::default();
        for _ in 0..3 {
            for index in 0..=MAX_DATABASES {
                let path = PathBuf::from(format!("churn-{index}.sqlite"));
                let line = registry.line(&path).unwrap();
                let identity = Arc::downgrade(&line);
                assert!(Arc::ptr_eq(&line, &registry.line(&path).unwrap()));
                drop(line);
                assert!(identity.upgrade().is_none());
                assert!(registry.lines.len() <= MAX_DATABASES);
            }
        }
        assert_eq!(registry.lines.len(), 1);
    }

    #[test]
    fn timeout_and_holder_drop_preserve_fifo_and_rollback_before_the_next_writer() {
        let (_directory, path) = database();
        let mut first = Connection::open(&path).unwrap();
        let holding = immediate(&mut first).unwrap();
        holding.execute("INSERT INTO log VALUES (-1)", []).unwrap();
        let line = registered_line(&path);
        let expires = writer(path.clone(), 0, Duration::from_millis(500));
        await_waiters(&line, 1);
        let second = writer(path.clone(), 1, TEST_WAIT);
        await_waiters(&line, 2);
        let third = writer(path.clone(), 2, TEST_WAIT);
        await_waiters(&line, 3);
        assert_busy(&expires.join().unwrap().unwrap_err(), "wait exceeded");
        await_waiters(&line, 2);
        drop(holding);
        second.join().unwrap().unwrap();
        third.join().unwrap().unwrap();
        assert_eq!(written(&first), [1, 2]);
    }

    #[test]
    fn a_waiting_database_does_not_block_an_independent_database() {
        let (_first_directory, first_path) = database();
        let (_second_directory, second_path) = database();
        let mut first = Connection::open(&first_path).unwrap();
        let holding = immediate(&mut first).unwrap();
        let line = registered_line(&first_path);
        let blocked = writer(first_path.clone(), 1, TEST_WAIT);
        await_waiters(&line, 1);
        writer(second_path.clone(), 2, Duration::ZERO)
            .join()
            .unwrap()
            .unwrap();
        assert_eq!(written(&Connection::open(second_path).unwrap()), [2]);
        assert_eq!(line.state.lock().unwrap().waiting.len(), 1);
        holding.commit().unwrap();
        blocked.join().unwrap().unwrap();
        assert_eq!(written(&first), [1]);
    }

    #[test]
    fn a_writer_that_waits_too_long_fails_as_busy_and_leaves_the_line() {
        let (_directory, path) = database();
        let mut first = Connection::open(&path).unwrap();
        let holding = immediate(&mut first).unwrap();
        let waiter = {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut connection = Connection::open(&path).unwrap();
                immediate_within(&mut connection, Duration::from_millis(50))
                    .map(|_| ())
                    .unwrap_err()
            })
        };
        let error = waiter.join().unwrap();
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy)
        );
        holding.commit().unwrap();
        // The abandoned ticket does not block the next writer.
        let mut next = Connection::open(&path).unwrap();
        immediate_within(&mut next, Duration::from_millis(500))
            .unwrap()
            .commit()
            .unwrap();
    }

    #[test]
    fn a_bounded_caller_fails_fast_and_restores_the_default_wait() {
        let (_directory, path) = database();
        let mut first = Connection::open(&path).unwrap();
        let holding = immediate(&mut first).unwrap();
        let waited = {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut connection = Connection::open(&path).unwrap();
                let started = Instant::now();
                let error = bounded(Duration::from_millis(50), || {
                    immediate(&mut connection).map(|_| ())
                })
                .unwrap_err();
                let restored = CAP.with(|cap| cap.get()).is_none();
                (error.sqlite_error_code(), started.elapsed(), restored)
            })
        };
        let (code, elapsed, restored) = waited.join().unwrap();
        assert_eq!(code, Some(rusqlite::ErrorCode::DatabaseBusy));
        assert!(elapsed < Duration::from_secs(5));
        assert!(restored);
        holding.commit().unwrap();
    }

    #[test]
    fn the_holding_thread_passes_through_and_dropping_releases_the_turn() {
        let (_directory, path) = database();
        let mut first = Connection::open(&path).unwrap();
        let mut second = Connection::open(&path).unwrap();
        let holding = immediate(&mut first).unwrap();
        // Same thread, second connection: no deadlock in the line; SQLite decides.
        second.busy_timeout(Duration::from_millis(10)).unwrap();
        let nested = immediate(&mut second).map(|_| ()).unwrap_err();
        assert_eq!(
            nested.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy)
        );
        drop(holding);
        let barrier = Arc::new(Barrier::new(2));
        let other = {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut connection = Connection::open(&path).unwrap();
                let transaction = immediate_within(&mut connection, Duration::from_millis(500));
                barrier.wait();
                transaction.map(|transaction| transaction.commit())
            })
        };
        barrier.wait();
        other.join().unwrap().unwrap().unwrap();
    }
}
