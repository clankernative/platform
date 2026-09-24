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
use rusqlite::{Connection, Transaction, TransactionBehavior};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    ops::{Deref, DerefMut},
    path::PathBuf,
    sync::{Arc, Condvar, Mutex, OnceLock},
    time::{Duration, Instant},
};

/// How long a writer waits for its turn before failing as busy.
pub const WAIT: Duration = Duration::from_secs(30);

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

fn lines() -> &'static Mutex<HashMap<PathBuf, Arc<Line>>> {
    static LINES: OnceLock<Mutex<HashMap<PathBuf, Arc<Line>>>> = OnceLock::new();
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
        let line = lines()
            .lock()
            .map_err(|_| busy("write queue unavailable"))?
            .entry(path.clone())
            .or_default()
            .clone();
        let deadline = Instant::now() + wait;
        let mut state = line
            .state
            .lock()
            .map_err(|_| busy("write queue unavailable"))?;
        let ticket = state.next;
        state.next += 1;
        state.waiting.push_back(ticket);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Barrier, mpsc};

    fn database() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("queue.sqlite");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE log(writer INTEGER NOT NULL);")
            .unwrap();
        (directory, path)
    }

    #[test]
    fn writers_are_served_in_arrival_order() {
        let (_directory, path) = database();
        let mut first = Connection::open(&path).unwrap();
        let holding = immediate(&mut first).unwrap();
        let (arrived, order) = mpsc::channel();
        let mut writers = Vec::new();
        for writer in 0..6_i64 {
            let path = path.clone();
            let arrived = arrived.clone();
            writers.push(std::thread::spawn(move || {
                let mut connection = Connection::open(&path).unwrap();
                arrived.send(()).unwrap();
                let transaction = immediate(&mut connection).unwrap();
                transaction
                    .execute("INSERT INTO log VALUES (?1)", [writer])
                    .unwrap();
                transaction.commit().unwrap();
            }));
            // Queue each writer before starting the next, so arrival order is known.
            order.recv().unwrap();
            std::thread::sleep(Duration::from_millis(20));
        }
        holding.commit().unwrap();
        for writer in writers {
            writer.join().unwrap();
        }
        let written: Vec<i64> = first
            .prepare("SELECT writer FROM log ORDER BY rowid")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(written, (0..6).collect::<Vec<_>>());
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
