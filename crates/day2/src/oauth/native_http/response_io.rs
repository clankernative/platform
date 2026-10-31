//! One inline, owner-thread response driver. The slot carries bounded socket
//! arguments/results only; the pinned future retains all genuine native borrows.
//! There is no spawned task, cross-thread queue, permission DTO or lifetime cast.

use super::super::effects;
use anyhow::{Result, ensure};
use hyper::rt;
use std::{
    cell::{Cell, RefCell},
    future::Future,
    io,
    pin::Pin,
    rc::Rc,
    task::{Context as TaskContext, Poll, Waker},
    thread::ThreadId,
};

const MAX_WRITE: usize = 64 * 1024;

#[derive(Clone, Copy, serde::Serialize)]
struct Counts {
    scope_attempts: Option<u32>,
    scope_entries: Option<u32>,
    socket_polls: Option<u32>,
    pending_polls: Option<u32>,
    raw_written_bytes: Option<u64>,
    postchecked_written_bytes: Option<u64>,
}

impl Default for Counts {
    fn default() -> Self {
        Self {
            scope_attempts: Some(0),
            scope_entries: Some(0),
            socket_polls: Some(0),
            pending_polls: Some(0),
            raw_written_bytes: Some(0),
            postchecked_written_bytes: Some(0),
        }
    }
}

fn increment(value: &mut Option<u32>) {
    *value = value.and_then(|value| value.checked_add(1));
}

fn record_line(
    sequence: u32,
    completed: bool,
    elapsed_us: Option<u64>,
    counts: Counts,
) -> Option<String> {
    if sequence == 0 || sequence > 4096 {
        return None;
    }
    #[derive(serde::Serialize)]
    struct Record {
        format: &'static str,
        sequence: u32,
        outcome: &'static str,
        clock: &'static str,
        elapsed_us: Option<u64>,
        counts: Counts,
    }
    let record = Record {
        format: "finite_app_response_delivery_v1",
        sequence,
        outcome: if completed { "completed" } else { "refused" },
        clock: "controlled_monotonic_data",
        elapsed_us,
        counts,
    };
    let json = serde_json::to_string(&record).ok()?;
    let line = format!("day2-native-response-delivery {json}\n");
    (line.len() <= 768).then_some(line)
}

#[derive(Clone, PartialEq, Eq)]
pub(in crate::oauth) enum Operation {
    Write {
        bytes: Rc<Vec<u8>>,
        requested: usize,
    },
    Flush,
    Shutdown,
    Complete,
}

pub(in crate::oauth) fn require_first_io(operation: &Operation) -> Result<()> {
    ensure!(
        *operation != Operation::Complete,
        "native response completed before first I/O"
    );
    Ok(())
}

struct Command {
    sequence: u64,
    operation: Operation,
    started: bool,
}

enum Output {
    Wrote(usize),
    Unit,
}

struct Slot {
    next: u64,
    command: Option<Command>,
    output: Option<(u64, io::Result<Output>)>,
    waiter: Option<Waker>,
    refused: bool,
    counts: Counts,
}

pub(in crate::oauth) struct Transport<T> {
    inner: Rc<RefCell<T>>,
    slot: Rc<RefCell<Slot>>,
}

type DriverFuture = Pin<Box<dyn Future<Output = Result<()>>>>;

/// Response DATA only. This local handoff never carries an owner or permit.
/// Cookies and CSRF values must not gain Debug/log/serialization exposure.
#[derive(Clone)]
pub(in crate::oauth) struct HostReplySlot(Rc<RefCell<HostReply>>);

enum HostReply {
    Pending,
    Ready(axum::response::Response),
    Consumed,
}

impl HostReplySlot {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(HostReply::Pending)))
    }

    pub(in crate::oauth) fn publish(&self, response: axum::response::Response) -> Result<()> {
        let mut slot = self.0.try_borrow_mut()?;
        ensure!(
            matches!(*slot, HostReply::Pending),
            "native host reply already published"
        );
        *slot = HostReply::Ready(response);
        Ok(())
    }

    fn take(&self) -> Result<Option<axum::response::Response>> {
        let mut slot = self.0.try_borrow_mut()?;
        match &*slot {
            HostReply::Pending => Ok(None),
            HostReply::Consumed => anyhow::bail!("native host reply already consumed"),
            HostReply::Ready(_) => {
                let HostReply::Ready(response) = std::mem::replace(&mut *slot, HostReply::Consumed)
                else {
                    unreachable!()
                };
                Ok(Some(response))
            }
        }
    }

    fn consumed(&self) -> bool {
        matches!(*self.0.borrow(), HostReply::Consumed)
    }
}

struct Shared {
    future: RefCell<Option<DriverFuture>>,
    slot: Rc<RefCell<Slot>>,
    owner: ThreadId,
    sink: super::super::native_management::Sink,
    finished: Cell<bool>,
    started: effects::Instant,
    ended: Cell<Option<effects::Instant>>,
    reported: Cell<bool>,
    reply: Option<HostReplySlot>,
}

/// Clones address this SAME driver, not a replacement stage. Only the HTTP
/// executor retains a completion handle after Hyper drops its transport.
#[derive(Clone)]
pub(super) struct Driver(Rc<Shared>);

impl Driver {
    pub(super) fn new<T: rt::Write + Unpin + 'static>(
        inner: Rc<RefCell<T>>,
        sink: super::super::native_management::Sink,
    ) -> Self {
        let slot = Rc::new(RefCell::new(Slot {
            next: 0,
            command: None,
            output: None,
            waiter: None,
            refused: false,
            counts: Counts::default(),
        }));
        let transport = Transport {
            inner,
            slot: slot.clone(),
        };
        let owned_sink = sink.clone();
        Self(Rc::new(Shared {
            future: RefCell::new(Some(Box::pin(async move {
                owned_sink.drive_response(transport).await
            }))),
            slot,
            owner: std::thread::current().id(),
            sink,
            finished: Cell::new(false),
            started: effects::Instant::now(),
            ended: Cell::new(None),
            reported: Cell::new(false),
            reply: None,
        }))
    }

    pub(super) fn for_host<T: rt::Write + Unpin + 'static>(
        inner: Rc<RefCell<T>>,
        sink: super::super::native_management::Sink,
        host: std::sync::Arc<crate::web::Host>,
        request: crate::web::PreparedHostRequest,
    ) -> Self {
        let slot = Rc::new(RefCell::new(Slot {
            next: 0,
            command: None,
            output: None,
            waiter: None,
            refused: false,
            counts: Counts::default(),
        }));
        let transport = Transport {
            inner,
            slot: slot.clone(),
        };
        let reply = HostReplySlot::new();
        let publish = reply.clone();
        let owned_sink = sink.clone();
        let effects = host.prepared_host_effects();
        Self(Rc::new(Shared {
            future: RefCell::new(Some(Box::pin(async move {
                effects
                    .run_async(owned_sink.drive_host_request(host, request, transport, publish))
                    .await
            }))),
            slot,
            owner: std::thread::current().id(),
            sink,
            finished: Cell::new(false),
            started: effects::Instant::now(),
            ended: Cell::new(None),
            reported: Cell::new(false),
            reply: Some(reply),
        }))
    }

    /// Advance the SAME owning future without inventing a socket operation.
    pub(super) fn poll_host_reply(
        &self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<axum::response::Response>> {
        if self.0.owner != std::thread::current().id()
            || !self.0.sink.is_open()
            || self.0.slot.borrow().refused
            || self.0.slot.borrow().command.is_some()
            || self.0.finished.get()
        {
            return Poll::Ready(Err(self.refuse()));
        }
        if let Err(error) = self.advance(cx) {
            return Poll::Ready(Err(error));
        }
        let result = self
            .0
            .reply
            .as_ref()
            .ok_or(())
            .and_then(|reply| reply.take().map_err(|_| ()));
        match result {
            Ok(Some(response)) => Poll::Ready(Ok(response)),
            Ok(None) => Poll::Pending,
            Err(()) => Poll::Ready(Err(self.refuse())),
        }
    }

    fn refuse(&self) -> io::Error {
        self.0.slot.borrow_mut().refused = true;
        self.0.sink.abort();
        // Drop the actual future after its poll borrow has unwound. Its lease
        // records terminal disposition without a new clock or role grant.
        if let Ok(mut future) = self.0.future.try_borrow_mut() {
            future.take();
        }
        io::Error::other("native response authority or delivery unavailable")
    }

    fn poll(&self, cx: &mut TaskContext<'_>, operation: Operation) -> Poll<io::Result<Output>> {
        if self.0.owner != std::thread::current().id() {
            return Poll::Ready(Err(self.refuse()));
        }
        if self.0.reply.as_ref().is_some_and(|reply| !reply.consumed()) {
            return Poll::Ready(Err(self.refuse()));
        }
        {
            let mut slot = self.0.slot.borrow_mut();
            if slot.refused || !self.0.sink.is_open() {
                drop(slot);
                return Poll::Ready(Err(self.refuse()));
            }
            if let Some(command) = &slot.command {
                if command.operation != operation {
                    drop(slot);
                    return Poll::Ready(Err(self.refuse()));
                }
                if slot
                    .output
                    .as_ref()
                    .is_some_and(|(sequence, _)| *sequence != command.sequence || !command.started)
                {
                    drop(slot);
                    return Poll::Ready(Err(self.refuse()));
                }
            } else {
                if self.0.finished.get() {
                    drop(slot);
                    return Poll::Ready(Err(self.refuse()));
                }
                let Some(next) = slot.next.checked_add(1) else {
                    drop(slot);
                    return Poll::Ready(Err(self.refuse()));
                };
                slot.next = next;
                slot.command = Some(Command {
                    sequence: next,
                    operation,
                    started: false,
                });
            }
            slot.waiter = Some(cx.waker().clone());
        }
        if let Err(error) = self.advance(cx) {
            return Poll::Ready(Err(error));
        }
        let mut slot = self.0.slot.borrow_mut();
        let Some((sequence, result)) = slot.output.take() else {
            return Poll::Pending;
        };
        if slot
            .command
            .as_ref()
            .is_none_or(|command| command.sequence != sequence)
        {
            drop(slot);
            return Poll::Ready(Err(self.refuse()));
        }
        slot.command = None;
        Poll::Ready(result)
    }

    fn advance(&self, cx: &mut TaskContext<'_>) -> io::Result<()> {
        let completed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut future = self.0.future.borrow_mut();
            match future.as_mut().map(|future| future.as_mut().poll(cx)) {
                Some(Poll::Ready(result)) => {
                    future.take();
                    Some(result)
                }
                _ => None,
            }
        }));
        let completed = match completed {
            Ok(completed) => completed,
            Err(payload) => {
                self.refuse();
                std::panic::resume_unwind(payload)
            }
        };
        if let Some(result) = completed {
            self.0.ended.set(Some(effects::Instant::now()));
            if result.is_err() {
                return Err(self.refuse());
            }
            self.0.finished.set(true);
        }
        Ok(())
    }

    pub(super) fn poll_write(
        &self,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let prefix = bytes[..bytes.len().min(MAX_WRITE)].to_vec();
        match self.poll(
            cx,
            Operation::Write {
                bytes: Rc::new(prefix),
                requested: bytes.len(),
            },
        ) {
            Poll::Ready(Ok(Output::Wrote(count))) if count <= bytes.len().min(MAX_WRITE) => {
                Poll::Ready(Ok(count))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Err(self.refuse())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_unit(&self, cx: &mut TaskContext<'_>, operation: Operation) -> Poll<io::Result<()>> {
        match self.poll(cx, operation) {
            Poll::Ready(Ok(Output::Unit)) => Poll::Ready(Ok(())),
            Poll::Ready(Ok(_)) => Poll::Ready(Err(self.refuse())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    pub(super) fn poll_flush(&self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.poll_unit(cx, Operation::Flush)
    }

    pub(super) fn poll_shutdown(&self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.poll_unit(cx, Operation::Shutdown)
    }

    pub(super) async fn finish(&self) -> io::Result<()> {
        std::future::poll_fn(|cx| self.poll_unit(cx, Operation::Complete)).await
    }

    pub(super) fn abort(&self) {
        self.refuse();
    }

    /// Historical bounded DATA only, after all native borrows unwind. The
    /// controlled stopwatch is distinct from admission's original native clock.
    /// It must never be used to extend a lease or assert five-second fitness.
    pub(super) fn report(&self) {
        use std::io::Write;
        use std::sync::atomic::{AtomicU32, Ordering};
        static RECORDS: AtomicU32 = AtomicU32::new(0);
        if self.0.future.borrow().is_some() || self.0.reported.replace(true) {
            return;
        }
        let Some(sequence) = RECORDS
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                (value < 4096).then_some(value + 1)
            })
            .ok()
            .map(|value| value + 1)
        else {
            return;
        };
        let ended = self.0.ended.get().unwrap_or_else(effects::Instant::now);
        let elapsed = ended
            .checked_duration_since(self.0.started)
            .and_then(|elapsed| u64::try_from(elapsed.as_micros()).ok());
        if let Some(line) = record_line(
            sequence,
            self.0.sink.is_complete(),
            elapsed,
            self.0.slot.borrow().counts,
        ) {
            let _ = std::io::stderr().lock().write_all(line.as_bytes());
        }
    }
}

impl<T: rt::Write + Unpin> Transport<T> {
    pub(in crate::oauth) fn scope_attempt(&mut self) {
        increment(&mut self.slot.borrow_mut().counts.scope_attempts);
    }
    pub(in crate::oauth) fn scope_entered(&mut self) {
        increment(&mut self.slot.borrow_mut().counts.scope_entries);
    }
    pub(in crate::oauth) async fn next(&mut self) -> Result<(u64, Operation)> {
        std::future::poll_fn(|cx| {
            let mut slot = self.slot.borrow_mut();
            if slot.refused {
                return Poll::Ready(Err(anyhow::anyhow!("native response canceled")));
            }
            if let Some(command) = &mut slot.command
                && !command.started
            {
                command.started = true;
                return Poll::Ready(Ok((command.sequence, command.operation.clone())));
            }
            slot.waiter = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    /// Each actual socket poll is invoked ONCE between the same scope's fresh
    /// checks. Pending is progress, not a known result, settlement or new grant.
    pub(in crate::oauth) async fn execute(
        &mut self,
        sequence: u64,
        operation: Operation,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        ensure!(
            operation != Operation::Complete,
            "response completion is not socket I/O"
        );
        let result = std::future::poll_fn(|cx| {
            if self.slot.borrow().refused {
                return Poll::Ready(Err(io::Error::other("native response canceled")));
            }
            if check().is_err() {
                return Poll::Ready(Err(io::Error::other("native response precheck refused")));
            }
            let result = {
                increment(&mut self.slot.borrow_mut().counts.socket_polls);
                let mut inner = self.inner.borrow_mut();
                match &operation {
                    Operation::Write { bytes, .. } => Pin::new(&mut *inner)
                        .poll_write(cx, bytes)
                        .map_ok(Output::Wrote),
                    Operation::Flush => Pin::new(&mut *inner)
                        .poll_flush(cx)
                        .map_ok(|()| Output::Unit),
                    Operation::Shutdown => Pin::new(&mut *inner)
                        .poll_shutdown(cx)
                        .map_ok(|()| Output::Unit),
                    Operation::Complete => unreachable!(),
                }
            };
            {
                let mut slot = self.slot.borrow_mut();
                if result.is_pending() {
                    increment(&mut slot.counts.pending_polls);
                }
                if let (Operation::Write { bytes, .. }, Poll::Ready(Ok(Output::Wrote(count)))) =
                    (&operation, &result)
                {
                    slot.counts.raw_written_bytes = slot
                        .counts
                        .raw_written_bytes
                        .zip(u64::try_from(*count).ok().filter(|_| *count <= bytes.len()))
                        .and_then(|(total, count)| total.checked_add(count));
                }
            }
            if check().is_err() {
                return Poll::Ready(Err(io::Error::other("native response postcheck refused")));
            }
            if let (Operation::Write { bytes, .. }, Poll::Ready(Ok(Output::Wrote(count)))) =
                (&operation, &result)
            {
                let mut slot = self.slot.borrow_mut();
                slot.counts.postchecked_written_bytes = slot
                    .counts
                    .postchecked_written_bytes
                    .zip(u64::try_from(*count).ok().filter(|_| *count <= bytes.len()))
                    .and_then(|(total, count)| total.checked_add(count));
            }
            result
        })
        .await;
        let output = result?;
        if let (Operation::Write { bytes, requested }, Output::Wrote(count)) = (&operation, &output)
        {
            ensure!(
                *count <= bytes.len() && bytes.len() <= *requested && bytes.len() <= MAX_WRITE,
                "native response write count invalid"
            );
        }
        self.output(sequence, Ok(output))
    }

    fn output(&mut self, sequence: u64, output: io::Result<Output>) -> Result<()> {
        let mut slot = self.slot.borrow_mut();
        ensure!(
            !slot.refused
                && slot.output.is_none()
                && slot
                    .command
                    .as_ref()
                    .is_some_and(|command| command.sequence == sequence && command.started),
            "native response result changed"
        );
        slot.output = Some((sequence, output));
        if let Some(waiter) = slot.waiter.take() {
            waiter.wake();
        }
        Ok(())
    }

    pub(in crate::oauth) fn complete(&mut self, sequence: u64) -> Result<()> {
        ensure!(
            self.slot
                .borrow()
                .command
                .as_ref()
                .is_some_and(|command| command.sequence == sequence
                    && command.operation == Operation::Complete),
            "native response terminal request changed"
        );
        self.output(sequence, Ok(Output::Unit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Clone, Copy)]
    enum Event {
        Pending,
        Write(usize),
        Fail,
        ChangedEpoch(usize),
        Panic,
    }

    #[derive(Default)]
    struct Model {
        now: Cell<u64>,
        latest: Cell<u64>,
        epoch: Cell<u64>,
        refused: Cell<bool>,
        scopes: Cell<u32>,
        polls: Cell<u32>,
        settled: Cell<u32>,
        deny_completion: Cell<bool>,
        writes: RefCell<Vec<Vec<u8>>>,
    }

    // Protocol model DATA only; this neither constructs a native stage nor
    // implements the sealed CurrentServingPhase. Live suppliers remain owed.
    struct ModelScope {
        model: Rc<Model>,
        known: bool,
    }

    impl ModelScope {
        fn check(&mut self) -> Result<()> {
            let model = &self.model;
            ensure!(
                !model.refused.get()
                    && model.now.get() >= model.latest.get()
                    && model.now.get() < 5
                    && model.epoch.get() == 0,
                "model original clock or epoch refused"
            );
            model.latest.set(model.now.get());
            Ok(())
        }
    }

    impl Drop for ModelScope {
        fn drop(&mut self) {
            if !self.known {
                self.model.refused.set(true);
            }
        }
    }

    struct Socket {
        events: VecDeque<Event>,
        model: Rc<Model>,
    }

    impl rt::Write for Socket {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.model.polls.set(self.model.polls.get() + 1);
            self.model.writes.borrow_mut().push(bytes.to_vec());
            match self.events.pop_front().unwrap_or(Event::Write(bytes.len())) {
                Event::Pending => Poll::Pending,
                Event::Write(count) => Poll::Ready(Ok(count)),
                Event::Fail => Poll::Ready(Err(io::Error::other("controlled socket failure"))),
                Event::ChangedEpoch(count) => {
                    self.model.epoch.set(1);
                    Poll::Ready(Ok(count))
                }
                Event::Panic => panic!("controlled socket panic"),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            self.model.polls.set(self.model.polls.get() + 1);
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            self.model.polls.set(self.model.polls.get() + 1);
            Poll::Ready(Ok(()))
        }
    }

    fn fixture(events: impl IntoIterator<Item = Event>) -> (Driver, Rc<Model>) {
        fixture_entry(events, false)
    }

    fn fixture_entry(events: impl IntoIterator<Item = Event>, host: bool) -> (Driver, Rc<Model>) {
        let model = Rc::new(Model::default());
        let slot = Rc::new(RefCell::new(Slot {
            next: 0,
            command: None,
            output: None,
            waiter: None,
            refused: false,
            counts: Counts::default(),
        }));
        let mut transport = Transport {
            inner: Rc::new(RefCell::new(Socket {
                events: events.into_iter().collect(),
                model: model.clone(),
            })),
            slot: slot.clone(),
        };
        let captured = model.clone();
        let reply = host.then(HostReplySlot::new);
        let publish = reply.clone();
        let future = async move {
            let first = if publish.is_some() {
                None
            } else {
                Some(transport.next().await?)
            };
            transport.scope_attempt();
            transport.scope_entered();
            captured.scopes.set(captured.scopes.get() + 1);
            let mut guard = ModelScope {
                model: captured,
                known: false,
            };
            if let Some(reply) = publish {
                guard.check()?;
                // Real SQLite adapter work, but only model lifetime DATA:
                // this constructs no native stage or serving permission.
                {
                    let mut db = rusqlite::Connection::open_in_memory()?;
                    db.execute_batch("CREATE TABLE probe(value INTEGER)")?;
                    let tx = db.transaction()?;
                    tx.execute("INSERT INTO probe VALUES(1)", [])?;
                    tx.commit()?;
                    let count: i64 =
                        db.query_row("SELECT count(*) FROM probe", [], |row| row.get(0))?;
                    ensure!(count == 1, "model SQL result changed");
                    db.close().map_err(|(_, error)| error)?;
                }
                guard.check()?;
                reply.publish(axum::response::Response::new(axum::body::Body::from(
                    "metadata",
                )))?;
            }
            let mut request = match first {
                Some(first) => first,
                None => transport.next().await?,
            };
            require_first_io(&request.1)?;
            loop {
                if request.1 == Operation::Complete {
                    guard.check()?;
                    if guard.model.deny_completion.get() {
                        transport.slot.borrow_mut().output = Some((request.0, Ok(Output::Unit)));
                    }
                    transport.complete(request.0)?;
                    guard.model.settled.set(guard.model.settled.get() + 1);
                    guard.known = true;
                    return Ok(());
                }
                transport
                    .execute(request.0, request.1, || guard.check())
                    .await?;
                request = transport.next().await?;
            }
        };
        (
            Driver(Rc::new(Shared {
                future: RefCell::new(Some(Box::pin(future))),
                slot,
                owner: std::thread::current().id(),
                sink: super::super::super::native_management::Sink::new(),
                finished: Cell::new(false),
                started: effects::Instant::now(),
                ended: Cell::new(None),
                reported: Cell::new(false),
                reply,
            })),
            model,
        )
    }

    fn context() -> TaskContext<'static> {
        TaskContext::from_waker(futures_util::task::noop_waker_ref())
    }

    #[test]
    fn host_reply_starts_same_pinned_model_without_socket_command_and_settles_after_transport_only()
    {
        let (driver, model) = fixture_entry([Event::Pending, Event::Write(4)], true);
        let mut cx = context();
        let response = match driver.poll_host_reply(&mut cx) {
            Poll::Ready(Ok(response)) => response,
            _ => panic!("host reply did not advance before socket I/O"),
        };
        assert_eq!(response.status(), 200);
        assert!(
            driver.0.slot.borrow().command.is_none(),
            "reply polling must not enqueue a fake write"
        );
        assert_eq!(
            (model.scopes.get(), model.polls.get(), model.settled.get()),
            (1, 0, 0)
        );
        assert!(driver.poll_write(&mut cx, b"data").is_pending());
        assert!(matches!(
            driver.poll_write(&mut cx, b"data"),
            Poll::Ready(Ok(4))
        ));
        assert!(matches!(driver.poll_flush(&mut cx), Poll::Ready(Ok(()))));
        assert!(matches!(driver.poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!((model.scopes.get(), model.settled.get()), (1, 0));
        futures_executor::block_on(driver.finish()).unwrap();
        assert_eq!((model.scopes.get(), model.settled.get()), (1, 1));
    }

    #[test]
    fn host_reply_one_shot_and_pre_reply_transport_refusals_are_terminal() {
        let slot = HostReplySlot::new();
        assert!(slot.take().unwrap().is_none());
        slot.publish(axum::response::Response::new(axum::body::Body::empty()))
            .unwrap();
        assert!(
            slot.publish(axum::response::Response::new(axum::body::Body::empty()))
                .is_err()
        );
        assert!(slot.take().unwrap().is_some());
        assert!(slot.take().is_err());

        let (driver, model) = fixture_entry([], true);
        assert!(matches!(
            driver.poll_write(&mut context(), b"x"),
            Poll::Ready(Err(_))
        ));
        assert_eq!((model.scopes.get(), model.polls.get()), (0, 0));
        assert!(matches!(
            driver.poll_host_reply(&mut context()),
            Poll::Ready(Err(_))
        ));
        let (driver, model) = fixture_entry([], true);
        assert!(matches!(
            driver.poll_host_reply(&mut context()),
            Poll::Ready(Ok(_))
        ));
        assert!(matches!(
            driver.poll_host_reply(&mut context()),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            driver.poll_write(&mut context(), b"x"),
            Poll::Ready(Err(_))
        ));
        assert_eq!(
            (model.scopes.get(), model.polls.get(), model.settled.get()),
            (1, 0, 0)
        );
        assert!(model.refused.get());

        let (driver, model) = fixture_entry([], true);
        assert!(matches!(
            driver.poll_host_reply(&mut context()),
            Poll::Ready(Ok(_))
        ));
        assert!(
            futures_executor::block_on(driver.finish()).is_err(),
            "reply DATA without any socket operation cannot settle delivery"
        );
        assert_eq!((model.polls.get(), model.settled.get()), (0, 0));
        assert!(model.refused.get());
    }

    #[test]
    fn seeded_host_reply_pause_abort_epoch_and_deadline_never_reacquire_the_model_parent() {
        // Fixed replayable schedules include equality and pause/rollback after
        // SQL and reply production but before the first real socket poll.
        for seed in 0u64..32 {
            let (driver, model) = fixture_entry([Event::Pending, Event::Write(1)], true);
            model.now.set(1);
            assert!(matches!(
                driver.poll_host_reply(&mut context()),
                Poll::Ready(Ok(_))
            ));
            assert_eq!(model.settled.get(), 0);
            match seed % 4 {
                0 => model.now.set(5),
                1 => model.now.set(0),
                2 => model.epoch.set(1),
                _ => driver.abort(),
            }
            assert!(matches!(
                driver.poll_write(&mut context(), b"x"),
                Poll::Ready(Err(_))
            ));
            assert!(futures_executor::block_on(driver.finish()).is_err());
            assert_eq!(
                (model.scopes.get(), model.polls.get(), model.settled.get()),
                (1, 0, 0),
                "seed {seed}"
            );
            assert!(model.refused.get(), "seed {seed}");
        }
        let (driver, model) = fixture_entry([], true);
        assert!(matches!(
            driver.poll_host_reply(&mut context()),
            Poll::Ready(Ok(_))
        ));
        drop(driver);
        assert!(model.refused.get());
        assert_eq!(model.settled.get(), 0);
    }

    #[test]
    fn one_model_scope_spans_pending_partial_write_flush_shutdown_and_final_completion() {
        let (driver, model) = fixture([
            Event::Pending,
            Event::Pending,
            Event::Write(2),
            Event::Write(3),
        ]);
        let mut cx = context();
        assert!(driver.poll_write(&mut cx, b"hello").is_pending());
        assert!(driver.poll_write(&mut cx, b"hello").is_pending());
        assert!(matches!(
            driver.poll_write(&mut cx, b"hello"),
            Poll::Ready(Ok(2))
        ));
        assert!(matches!(
            driver.poll_write(&mut cx, b"llo"),
            Poll::Ready(Ok(3))
        ));
        assert!(matches!(driver.poll_flush(&mut cx), Poll::Ready(Ok(()))));
        assert!(matches!(driver.poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(model.scopes.get(), 1);
        assert_eq!(model.polls.get(), 6);
        let counts = driver.0.slot.borrow().counts;
        assert_eq!(counts.scope_attempts, Some(1));
        assert_eq!(counts.scope_entries, Some(1));
        assert_eq!(counts.socket_polls, Some(6));
        assert_eq!(counts.pending_polls, Some(2));
        assert_eq!(counts.raw_written_bytes, Some(5));
        assert_eq!(counts.postchecked_written_bytes, Some(5));
        assert_eq!(
            model.settled.get(),
            0,
            "no partial progress or shutdown ACK settles the response"
        );
        futures_executor::block_on(driver.finish()).unwrap();
        assert_eq!(model.scopes.get(), 1);
        assert_eq!(model.settled.get(), 1);
        assert!(!model.refused.get());
        assert!(futures_executor::block_on(driver.finish()).is_err());
    }

    #[test]
    fn original_deadline_equality_rewind_and_changed_epoch_refuse_before_more_io() {
        for (now, epoch) in [(5, 0), (1, 1), (0, 0)] {
            let (driver, model) = fixture([Event::Pending, Event::Write(1)]);
            model.now.set(1);
            assert!(driver.poll_write(&mut context(), b"x").is_pending());
            model.now.set(now);
            model.epoch.set(epoch);
            assert!(matches!(
                driver.poll_write(&mut context(), b"x"),
                Poll::Ready(Err(_))
            ));
            assert_eq!(model.polls.get(), 1);
            assert_eq!(model.scopes.get(), 1);
            assert_eq!(model.settled.get(), 0);
            assert!(model.refused.get());
        }
    }

    #[test]
    fn pending_request_kind_prefix_and_original_length_cannot_change() {
        for changed in [
            Operation::Flush,
            Operation::Write {
                bytes: Rc::new(b"other".to_vec()),
                requested: 5,
            },
            Operation::Write {
                bytes: Rc::new(b"hello".to_vec()),
                requested: 6,
            },
        ] {
            let (driver, model) = fixture([Event::Pending, Event::Write(5)]);
            assert!(driver.poll_write(&mut context(), b"hello").is_pending());
            assert!(matches!(
                driver.poll(&mut context(), changed),
                Poll::Ready(Err(_))
            ));
            assert_eq!(model.polls.get(), 1);
            assert_eq!(model.settled.get(), 0);
            assert!(model.refused.get());
        }
    }

    #[test]
    fn actual_write_then_failed_postcheck_or_lost_delivery_is_never_replayed() {
        for event in [
            Event::Fail,
            Event::ChangedEpoch(3),
            Event::Write(MAX_WRITE + 1),
        ] {
            let (driver, model) = fixture([event]);
            assert!(matches!(
                driver.poll_write(&mut context(), b"abc"),
                Poll::Ready(Err(_))
            ));
            assert!(matches!(
                driver.poll_write(&mut context(), b"abc"),
                Poll::Ready(Err(_))
            ));
            assert!(futures_executor::block_on(driver.finish()).is_err());
            assert_eq!(model.polls.get(), 1);
            assert!(model.refused.get());
            assert_eq!(model.settled.get(), 0);
        }
    }

    #[test]
    fn completion_handle_survives_transport_drop_but_cancellation_refuses() {
        let (driver, model) = fixture([Event::Write(3)]);
        let completion = driver.clone();
        assert!(matches!(
            driver.poll_write(&mut context(), b"abc"),
            Poll::Ready(Ok(3))
        ));
        drop(driver);
        assert_eq!(model.settled.get(), 0);
        futures_executor::block_on(completion.finish()).unwrap();
        assert_eq!(model.settled.get(), 1);
        drop(completion);
        assert!(!model.refused.get());

        for pending in [false, true] {
            let (driver, model) = fixture([if pending {
                Event::Pending
            } else {
                Event::Write(3)
            }]);
            let _ = driver.poll_write(&mut context(), b"abc");
            model.now.set(6);
            drop(driver);
            assert!(
                model.refused.get(),
                "Drop needs no clock, new grant or finalization request"
            );
            assert_eq!(model.settled.get(), 0);
        }
    }

    #[test]
    fn rejected_terminal_publication_never_marks_known_or_restores_the_model_owner() {
        let (driver, model) = fixture([Event::Write(3)]);
        assert!(matches!(
            driver.poll_write(&mut context(), b"abc"),
            Poll::Ready(Ok(3))
        ));
        model.deny_completion.set(true);
        assert!(futures_executor::block_on(driver.finish()).is_err());
        assert_eq!(model.settled.get(), 0);
        assert!(model.refused.get());
        assert!(matches!(
            driver.poll_write(&mut context(), b"abc"),
            Poll::Ready(Err(_))
        ));
        assert_eq!(model.polls.get(), 1);
    }

    #[test]
    fn failed_postcheck_meters_actual_bytes_and_panic_cannot_resume_the_driver() {
        let (driver, _) = fixture([Event::ChangedEpoch(3)]);
        assert!(matches!(
            driver.poll_write(&mut context(), b"abc"),
            Poll::Ready(Err(_))
        ));
        let counts = driver.0.slot.borrow().counts;
        assert_eq!(counts.raw_written_bytes, Some(3));
        assert_eq!(counts.postchecked_written_bytes, Some(0));

        let (driver, model) = fixture([Event::Write(2), Event::Panic]);
        assert!(matches!(
            driver.poll_write(&mut context(), b"abc"),
            Poll::Ready(Ok(2))
        ));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            driver.poll_write(&mut context(), b"c")
        }));
        assert!(result.is_err());
        assert!(model.refused.get());
        assert_eq!(model.settled.get(), 0);
        assert!(matches!(
            driver.poll_write(&mut context(), b"c"),
            Poll::Ready(Err(_))
        ));
        assert_eq!(model.polls.get(), 2);
    }

    #[test]
    fn historical_report_is_bounded_and_overflow_is_missing_not_zero() {
        let counts = Counts {
            scope_attempts: Some(u32::MAX),
            scope_entries: Some(u32::MAX),
            socket_polls: Some(u32::MAX),
            pending_polls: Some(u32::MAX),
            raw_written_bytes: Some(u64::MAX),
            postchecked_written_bytes: Some(u64::MAX),
        };
        for complete in [false, true] {
            let line = record_line(4096, complete, Some(u64::MAX), counts).unwrap();
            assert!(line.len() <= 768);
            let row: serde_json::Value =
                serde_json::from_str(line.strip_prefix("day2-native-response-delivery ").unwrap())
                    .unwrap();
            assert_eq!(row["clock"], "controlled_monotonic_data");
            assert!(row.get("permission").is_none() && row.get("token").is_none());
        }
        assert!(record_line(4097, true, None, counts).is_none());
        let mut counter = Some(u32::MAX);
        increment(&mut counter);
        increment(&mut counter);
        assert!(counter.is_none());
    }

    #[test]
    fn bounded_prefix_is_partial_and_count_sequence_and_thread_fail_closed() {
        let (driver, model) = fixture([Event::Write(MAX_WRITE)]);
        let bytes = vec![b'x'; MAX_WRITE * 2];
        assert!(matches!(
            driver.poll_write(&mut context(), &bytes),
            Poll::Ready(Ok(MAX_WRITE))
        ));
        assert_eq!(model.writes.borrow()[0].len(), MAX_WRITE);
        assert_eq!(model.scopes.get(), 1);
        assert_eq!(model.settled.get(), 0);
        drop(driver);
        assert!(model.refused.get());

        let (driver, model) = fixture([]);
        driver.0.slot.borrow_mut().next = u64::MAX;
        assert!(matches!(
            driver.poll_write(&mut context(), b"x"),
            Poll::Ready(Err(_))
        ));
        assert_eq!(model.polls.get(), 0);
        assert_eq!(model.scopes.get(), 0);

        let (mut driver, model) = fixture([]);
        Rc::get_mut(&mut driver.0).unwrap().owner =
            std::thread::spawn(|| std::thread::current().id())
                .join()
                .unwrap();
        assert!(matches!(
            driver.poll_write(&mut context(), b"x"),
            Poll::Ready(Err(_))
        ));
        assert_eq!(model.polls.get(), 0);
        assert_eq!(model.scopes.get(), 0);

        let (driver, model) = fixture([]);
        {
            let mut slot = driver.0.slot.borrow_mut();
            slot.command = Some(Command {
                sequence: 7,
                operation: Operation::Write {
                    bytes: Rc::new(b"x".to_vec()),
                    requested: 1,
                },
                started: true,
            });
            slot.output = Some((6, Ok(Output::Wrote(1))));
        }
        assert!(matches!(
            driver.poll_write(&mut context(), b"x"),
            Poll::Ready(Err(_))
        ));
        assert_eq!(model.polls.get(), 0);
        assert_eq!(model.scopes.get(), 0);
    }
}
