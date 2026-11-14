//! Per-request phase timing for the serving host.
//!
//! Each HTTP request produces exactly one JSON line on stdout. The line is
//! written when the last holder of the request's recorder lets go: the async
//! handler, a blocking dispatch still running after its caller disconnected, or
//! the native transport after it finished writing the response. An aborted
//! request therefore still reports every phase it reached. Background pump runs
//! that are slow, fail or wait for the writer get a line of their own; the rest
//! fold into one summary line per pump each minute.
//!
//! Diagnostics only. Durations come from the OS monotonic clock and no decision
//! reads them. Everything recorded is closed DATA: static phase names,
//! app-declared page, operation and capability identifiers, fixed provider
//! endpoint kinds, HTTP status numbers, platform failure codes and byte counts.
//! Actors appear only as a keyed hash computed by the caller. Never pass a
//! token, cookie, path, query, body, form value or provider payload here.
//!
//! Instrumented code calls the free functions below. They act on the recorder
//! the current thread entered for its synchronous work and cost one
//! thread-local read when there is none.
use serde_json::{Map, Value, json};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// Timeline entries kept per line; later ones are counted, not kept.
const MAX_PHASES: usize = 128;
/// Longest identifier recorded; longer or unexpected names are replaced.
const MAX_NAME: usize = 96;
/// A background run at least this slow gets its own line.
const SLOW_JOB: Duration = Duration::from_millis(100);
/// So does one that waited at least this long for the writer.
const JOB_WRITER_WAIT: Duration = Duration::from_millis(10);
/// How often background runs are summarized.
const SUMMARY_EVERY: Duration = Duration::from_secs(60);

static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

/// The one monotonic clock reading in this module. Diagnostics only.
pub(crate) fn now() -> Instant {
    Instant::now()
}

fn since(start: Instant) -> Duration {
    now().saturating_duration_since(start)
}

fn ms(duration: Duration) -> Value {
    // Tenths of a millisecond: enough to separate phases, short on the wire.
    json!((duration.as_micros() / 100) as f64 / 10.0)
}

/// An app-declared identifier, or a fixed marker when the value is not one.
/// Operation, page and capability names are declared in the artifact; this
/// guard keeps anything else (an email, a path) from reaching the log.
fn name(value: &str) -> Value {
    let declared = !value.is_empty()
        && value.len() <= MAX_NAME
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'$'));
    Value::String(if declared { value } else { "<undeclared>" }.to_owned())
}

/// Where lines go. Production writes stdout, which GKE ships to Cloud Logging.
#[derive(Clone)]
pub(crate) enum Output {
    Stdout,
    #[cfg(test)]
    Capture(Arc<Mutex<Vec<String>>>),
}

impl Output {
    fn write(&self, mut line: String) {
        match self {
            Self::Stdout => {
                use std::io::Write;
                line.push('\n');
                // One write of one complete line under the stdout lock, so lines
                // from concurrent requests never interleave. A closed stdout
                // loses diagnostics only; it must never fail the request.
                let _ = std::io::stdout().lock().write_all(line.as_bytes());
            }
            #[cfg(test)]
            Self::Capture(lines) => lines
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(line),
        }
    }
}

/// Repeated small costs, summed over the request (or over one command).
#[derive(Clone, Copy, Default)]
struct Totals {
    sql_reads: u32,
    sql_read: Duration,
    sql_writes: u32,
    sql_write: Duration,
    writer_turns: u32,
    writer_wait: Duration,
    writer_wait_max: Duration,
    writer_begin: Duration,
    writer_hold: Duration,
    writer_busy: u32,
    worker_starts: u32,
    worker_start: Duration,
    worker_exchanges: u32,
    worker_exchange: Duration,
    trace_writes: u32,
    trace_bytes: u64,
    trace_write: Duration,
    provider_calls: u32,
    provider: Duration,
}

impl Totals {
    fn minus(&self, earlier: &Self) -> Self {
        Self {
            sql_reads: self.sql_reads.saturating_sub(earlier.sql_reads),
            sql_read: self.sql_read.saturating_sub(earlier.sql_read),
            sql_writes: self.sql_writes.saturating_sub(earlier.sql_writes),
            sql_write: self.sql_write.saturating_sub(earlier.sql_write),
            writer_turns: self.writer_turns.saturating_sub(earlier.writer_turns),
            writer_wait: self.writer_wait.saturating_sub(earlier.writer_wait),
            // A maximum cannot be subtracted; a span reports only sums.
            writer_wait_max: Duration::ZERO,
            writer_begin: self.writer_begin.saturating_sub(earlier.writer_begin),
            writer_hold: self.writer_hold.saturating_sub(earlier.writer_hold),
            writer_busy: self.writer_busy.saturating_sub(earlier.writer_busy),
            worker_starts: self.worker_starts.saturating_sub(earlier.worker_starts),
            worker_start: self.worker_start.saturating_sub(earlier.worker_start),
            worker_exchanges: self
                .worker_exchanges
                .saturating_sub(earlier.worker_exchanges),
            worker_exchange: self.worker_exchange.saturating_sub(earlier.worker_exchange),
            trace_writes: self.trace_writes.saturating_sub(earlier.trace_writes),
            trace_bytes: self.trace_bytes.saturating_sub(earlier.trace_bytes),
            trace_write: self.trace_write.saturating_sub(earlier.trace_write),
            provider_calls: self.provider_calls.saturating_sub(earlier.provider_calls),
            provider: self.provider.saturating_sub(earlier.provider),
        }
    }

    /// Request totals always list every key so log queries can rely on them;
    /// per-command breakdowns leave out what did not happen.
    fn json(&self, sparse: bool) -> Value {
        let groups: [(u64, Vec<(&str, Value)>); 7] = [
            (
                u64::from(self.sql_reads),
                vec![
                    ("sql_reads", json!(self.sql_reads)),
                    ("sql_read_ms", ms(self.sql_read)),
                ],
            ),
            (
                u64::from(self.sql_writes),
                vec![
                    ("sql_writes", json!(self.sql_writes)),
                    ("sql_write_ms", ms(self.sql_write)),
                ],
            ),
            (
                u64::from(self.writer_turns) + u64::from(self.writer_busy),
                vec![
                    ("writer_turns", json!(self.writer_turns)),
                    ("writer_wait_ms", ms(self.writer_wait)),
                    ("writer_begin_ms", ms(self.writer_begin)),
                    ("writer_hold_ms", ms(self.writer_hold)),
                    ("writer_busy", json!(self.writer_busy)),
                ],
            ),
            (
                u64::from(self.worker_starts),
                vec![
                    ("worker_starts", json!(self.worker_starts)),
                    ("worker_start_ms", ms(self.worker_start)),
                ],
            ),
            (
                u64::from(self.worker_exchanges),
                vec![
                    ("worker_exchanges", json!(self.worker_exchanges)),
                    ("worker_exchange_ms", ms(self.worker_exchange)),
                ],
            ),
            (
                u64::from(self.trace_writes),
                vec![
                    ("trace_writes", json!(self.trace_writes)),
                    ("trace_bytes", json!(self.trace_bytes)),
                    ("trace_write_ms", ms(self.trace_write)),
                ],
            ),
            (
                u64::from(self.provider_calls),
                vec![
                    ("provider_calls", json!(self.provider_calls)),
                    ("provider_ms", ms(self.provider)),
                ],
            ),
        ];
        let mut out = Map::new();
        for (count, entries) in groups {
            if !sparse || count > 0 {
                for (key, value) in entries {
                    out.insert(key.to_owned(), value);
                }
            }
        }
        if !sparse {
            out.insert("writer_wait_max_ms".into(), ms(self.writer_wait_max));
        }
        Value::Object(out)
    }
}

struct Phase {
    name: &'static str,
    start: Duration,
    duration: Duration,
    attributes: Map<String, Value>,
}

enum Kind {
    Request,
    Job(&'static str),
}

struct Record {
    output: Output,
    kind: Kind,
    id: u64,
    started: Instant,
    attributes: Map<String, Value>,
    reached: &'static str,
    status: Option<u16>,
    outcome: Option<&'static str>,
    error: Option<&'static str>,
    aborted: Option<(Duration, &'static str)>,
    responded: Option<Instant>,
    phases: Vec<Phase>,
    dropped: u32,
    totals: Totals,
    suppressed: bool,
}

impl Record {
    fn new(output: Output, kind: Kind, started: Instant) -> Self {
        Self {
            output,
            kind,
            id: NEXT_REQUEST.fetch_add(1, Ordering::Relaxed),
            started,
            attributes: Map::new(),
            reached: "start",
            status: None,
            outcome: None,
            error: None,
            aborted: None,
            responded: None,
            phases: Vec::new(),
            dropped: 0,
            totals: Totals::default(),
            suppressed: false,
        }
    }

    fn push(&mut self, phase: Phase) {
        if self.phases.len() < MAX_PHASES {
            self.phases.push(phase);
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    fn render(&mut self, total: Duration) -> String {
        // Spans close innermost first; list them in the order they started.
        self.phases.sort_by_key(|phase| phase.start);
        let phases = self
            .phases
            .iter()
            .map(|phase| {
                let mut entry = Map::new();
                entry.insert("phase".into(), json!(phase.name));
                entry.insert("at_ms".into(), ms(phase.start));
                entry.insert("ms".into(), ms(phase.duration));
                entry.extend(phase.attributes.clone());
                Value::Object(entry)
            })
            .collect::<Vec<_>>();
        let mut line = Map::new();
        let server_error = self.status.is_some_and(|status| status >= 500);
        let severity = if self.aborted.is_some() || server_error || self.error.is_some() {
            "WARNING"
        } else {
            "INFO"
        };
        line.insert("severity".into(), json!(severity));
        match self.kind {
            Kind::Request => {
                line.insert("event".into(), json!("day2_request"));
                line.insert("request".into(), json!(self.id));
            }
            Kind::Job(pump) => {
                line.insert("event".into(), json!("day2_background"));
                line.insert("run".into(), json!(self.id));
                line.insert("pump".into(), json!(pump));
            }
        }
        line.extend(std::mem::take(&mut self.attributes));
        line.insert("status".into(), json!(self.status));
        let outcome = match (self.outcome, self.aborted) {
            (_, Some(_)) => "aborted",
            (Some(outcome), None) => outcome,
            (None, None) => "unknown",
        };
        line.insert("outcome".into(), json!(outcome));
        if let Some((at, phase)) = self.aborted {
            line.insert("aborted_at_ms".into(), ms(at));
            line.insert("aborted_in".into(), json!(phase));
        }
        line.insert("error".into(), json!(self.error));
        line.insert("reached".into(), json!(self.reached));
        line.insert("total_ms".into(), ms(total));
        line.insert("phases".into(), Value::Array(phases));
        line.insert("dropped_phases".into(), json!(self.dropped));
        line.insert("totals".into(), self.totals.json(false));
        Value::Object(line).to_string()
    }
}

impl Drop for Record {
    fn drop(&mut self) {
        if self.suppressed {
            return;
        }
        let total = since(self.started);
        match self.kind {
            Kind::Request => {
                let line = self.render(total);
                self.output.write(line);
            }
            Kind::Job(pump) => {
                let failed = self.error.is_some();
                let notable = failed
                    || total >= SLOW_JOB
                    || self.totals.writer_wait >= JOB_WRITER_WAIT
                    || self.totals.writer_busy > 0;
                let summary = summarize(pump, total, &self.totals, failed, notable);
                if notable {
                    let line = self.render(total);
                    self.output.write(line);
                }
                if let Some(summary) = summary {
                    self.output.write(summary);
                }
            }
        }
    }
}

#[derive(Default)]
struct PumpSummary {
    runs: u32,
    failed: u32,
    lines: u32,
    total: Duration,
    max: Duration,
    writer_wait: Duration,
    writer_hold: Duration,
    trace_bytes: u64,
}

struct Summaries {
    since: Instant,
    pumps: BTreeMap<&'static str, PumpSummary>,
}

static SUMMARIES: Mutex<Option<Summaries>> = Mutex::new(None);

/// Fold one background run into its pump's summary; return the summary line
/// when a minute has passed since the last one.
fn summarize(
    pump: &'static str,
    total: Duration,
    totals: &Totals,
    failed: bool,
    notable: bool,
) -> Option<String> {
    let mut summaries = SUMMARIES.lock().unwrap_or_else(PoisonError::into_inner);
    let summaries = summaries.get_or_insert_with(|| Summaries {
        since: now(),
        pumps: BTreeMap::new(),
    });
    let entry = summaries.pumps.entry(pump).or_default();
    entry.runs = entry.runs.saturating_add(1);
    entry.failed = entry.failed.saturating_add(u32::from(failed));
    entry.lines = entry.lines.saturating_add(u32::from(notable));
    entry.total = entry.total.saturating_add(total);
    entry.max = entry.max.max(total);
    entry.writer_wait = entry.writer_wait.saturating_add(totals.writer_wait);
    entry.writer_hold = entry.writer_hold.saturating_add(totals.writer_hold);
    entry.trace_bytes = entry.trace_bytes.saturating_add(totals.trace_bytes);
    let window = since(summaries.since);
    if window < SUMMARY_EVERY {
        return None;
    }
    let pumps = std::mem::take(&mut summaries.pumps)
        .into_iter()
        .map(|(pump, summary)| {
            (
                pump.to_owned(),
                json!({
                    "runs": summary.runs,
                    "failed": summary.failed,
                    "logged": summary.lines,
                    "total_ms": ms(summary.total),
                    "max_ms": ms(summary.max),
                    "writer_wait_ms": ms(summary.writer_wait),
                    "writer_hold_ms": ms(summary.writer_hold),
                    "trace_bytes": summary.trace_bytes,
                }),
            )
        })
        .collect::<Map<_, _>>();
    summaries.since = now();
    Some(
        json!({
            "severity": "INFO",
            "event": "day2_background_summary",
            "window_ms": ms(window),
            "pumps": pumps,
        })
        .to_string(),
    )
}

/// One request's (or background run's) shared timing record. Clones share it;
/// the line is written when the last clone is dropped.
#[derive(Clone)]
pub(crate) struct Recorder(Arc<Mutex<Record>>);

impl Recorder {
    /// A request that began at `started`, for example when the native transport
    /// accepted its connection.
    pub(crate) fn request(output: Output, started: Instant) -> Self {
        Self(Arc::new(Mutex::new(Record::new(
            output,
            Kind::Request,
            started,
        ))))
    }

    /// One background pump run.
    pub(crate) fn job(output: Output, pump: &'static str) -> Self {
        Self(Arc::new(Mutex::new(Record::new(
            output,
            Kind::Job(pump),
            now(),
        ))))
    }

    fn with<T>(&self, update: impl FnOnce(&mut Record) -> T) -> T {
        update(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn offset(&self, at: Instant) -> Duration {
        self.with(|record| at.saturating_duration_since(record.started))
    }

    /// A fixed, non-identifying request attribute, set once.
    pub(crate) fn attribute(&self, key: &'static str, value: Value) {
        self.with(|record| {
            record.attributes.entry(key).or_insert(value);
        });
    }

    /// An app-declared identifier attribute, such as the page served.
    pub(crate) fn name(&self, key: &'static str, value: &str) {
        self.attribute(key, name(value));
    }

    /// A phase that already happened, measured by the caller.
    pub(crate) fn completed(&self, phase: &'static str, start: Instant, end: Instant) {
        let start_offset = self.offset(start);
        self.with(|record| {
            record.push(Phase {
                name: phase,
                start: start_offset,
                duration: end.saturating_duration_since(start),
                attributes: Map::new(),
            });
        });
    }

    /// Start a phase on this recorder. Use from async code, which must not
    /// keep a thread entered across an await.
    pub(crate) fn span(&self, phase: &'static str) -> Span {
        Span::start(self.clone(), phase, false)
    }

    /// Make this the current recorder for synchronous work on this thread.
    pub(crate) fn enter(&self) -> Entered {
        let previous = CURRENT.with(|current| current.replace(Some(self.clone())));
        Entered { previous }
    }

    /// The handler produced a response. The first answer wins, so a specific
    /// outcome such as `busy` is not replaced by the generic `complete`.
    pub(crate) fn respond(&self, status: u16, outcome: &'static str) {
        let at = now();
        self.with(|record| {
            if record.outcome.is_none() {
                record.status = Some(status);
                record.outcome = Some(outcome);
                record.responded = Some(at);
            }
        });
    }

    /// A platform failure code: closed, never a message.
    pub(crate) fn failure(&self, code: &'static str) {
        self.with(|record| {
            record.error.get_or_insert(code);
        });
    }

    /// How the native transport finished delivering the response.
    pub(crate) fn delivered(&self, delivery: &'static str) {
        let at = now();
        self.with(|record| {
            record
                .attributes
                .insert("delivery".into(), Value::String(delivery.to_owned()));
            if let Some(responded) = record.responded {
                let start = responded.saturating_duration_since(record.started);
                record.push(Phase {
                    name: "respond",
                    start,
                    duration: at.saturating_duration_since(responded),
                    attributes: Map::new(),
                });
            }
            if record.status.is_none() && record.aborted.is_none() {
                record.aborted =
                    Some((at.saturating_duration_since(record.started), record.reached));
            }
        });
    }

    /// Not a request worth a line, such as a health probe.
    pub(crate) fn suppress(&self) {
        self.with(|record| record.suppressed = true);
    }

    /// Mark the request aborted if the handler is dropped before it responds:
    /// the client went away or the connection timed out.
    pub(crate) fn handler(&self) -> Handler {
        Handler(self.clone())
    }
}

/// See [`Recorder::handler`].
pub(crate) struct Handler(Recorder);

impl Drop for Handler {
    fn drop(&mut self) {
        let at = now();
        self.0.with(|record| {
            if record.outcome.is_none() && record.aborted.is_none() {
                record.aborted =
                    Some((at.saturating_duration_since(record.started), record.reached));
            }
        });
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Recorder>> = const { RefCell::new(None) };
}

fn current() -> Option<Recorder> {
    CURRENT.with(|current| {
        current
            .try_borrow()
            .ok()
            .and_then(|current| current.clone())
    })
}

/// Restores the previously entered recorder when dropped.
pub(crate) struct Entered {
    previous: Option<Recorder>,
}

impl Drop for Entered {
    fn drop(&mut self) {
        let previous = self.previous.take();
        CURRENT.with(|current| {
            if let Ok(mut current) = current.try_borrow_mut() {
                *current = previous;
            }
        });
    }
}

/// One timed phase on the timeline, recorded when dropped.
pub(crate) struct Span {
    inner: Option<SpanState>,
}

struct SpanState {
    recorder: Recorder,
    name: &'static str,
    started: Instant,
    attributes: Map<String, Value>,
    before: Option<Totals>,
}

impl Span {
    fn start(recorder: Recorder, name: &'static str, breakdown: bool) -> Self {
        let before = recorder.with(|record| {
            record.reached = name;
            breakdown.then_some(record.totals)
        });
        Self {
            inner: Some(SpanState {
                recorder,
                name,
                started: now(),
                attributes: Map::new(),
                before,
            }),
        }
    }

    fn none() -> Self {
        Self { inner: None }
    }

    fn put(&mut self, key: &'static str, value: Value) {
        if let Some(state) = &mut self.inner {
            state.attributes.insert(key.to_owned(), value);
        }
    }

    /// An app-declared identifier, such as the operation a command ran.
    pub(crate) fn name(&mut self, key: &'static str, value: &str) {
        if self.inner.is_some() {
            self.put(key, name(value));
        }
    }

    /// A host-generated identifier such as a page preparation invocation id.
    pub(crate) fn identifier(&mut self, key: &'static str, value: &str) {
        if self.inner.is_some() {
            self.put(key, name(value));
        }
    }

    /// A fixed result marker.
    pub(crate) fn result(&mut self, value: &'static str) {
        self.put("result", Value::String(value.to_owned()));
    }

    /// A closed platform failure code.
    pub(crate) fn failure(&mut self, code: &'static str) {
        self.put("error", Value::String(code.to_owned()));
    }

    pub(crate) fn status(&mut self, status: u16) {
        self.put("status", json!(status));
    }

    /// An invocation's result: a fixed status marker and, for a host error, its
    /// closed platform failure code. App error text is never recorded.
    pub(crate) fn outcome(&mut self, result: &anyhow::Result<crate::protocol::Outcome>) {
        if self.inner.is_none() {
            return;
        }
        match result {
            Ok(outcome) => self.result(match outcome.status.as_str() {
                "success" => "success",
                "failure" => "failure",
                "pending" => "pending",
                _ => "other",
            }),
            Err(error) => {
                self.result("error");
                self.failure(crate::error::classify(error).code());
            }
        }
    }

    /// A count, such as how many requests were already queued.
    pub(crate) fn number(&mut self, key: &'static str, value: u64) {
        self.put(key, json!(value));
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        let Some(state) = self.inner.take() else {
            return;
        };
        let end = now();
        state.recorder.with(|record| {
            let mut attributes = state.attributes;
            if let Some(before) = state.before {
                attributes.insert("totals".into(), record.totals.minus(&before).json(true));
            }
            let start = state.started.saturating_duration_since(record.started);
            record.push(Phase {
                name: state.name,
                start,
                duration: end.saturating_duration_since(state.started),
                attributes,
            });
        });
    }
}

/// A timed phase on the current thread's recorder, if any.
pub(crate) fn span(phase: &'static str) -> Span {
    current().map_or_else(Span::none, |recorder| Span::start(recorder, phase, false))
}

/// A command or query invocation: a timed phase that also carries the
/// database, worker, trace and provider costs incurred inside it.
pub(crate) fn invocation(phase: &'static str, operation: &str) -> Span {
    let mut span = current().map_or_else(Span::none, |recorder| Span::start(recorder, phase, true));
    span.name("operation", operation);
    span
}

/// Name what the request served (a page or operation), if not named yet.
pub(crate) fn route(value: &str) {
    if let Some(recorder) = current() {
        recorder.name("route", value);
    }
}

/// Record the closed failure code a request ended with.
pub(crate) fn failure(code: &'static str) {
    if let Some(recorder) = current() {
        recorder.failure(code);
    }
}

/// One provider HTTP exchange. Set its status once known; dropping the guard
/// records it (status 0 when no response arrived).
pub(crate) struct ProviderCall {
    span: Span,
    started: Option<Instant>,
}

/// Time one provider HTTP exchange: a fixed capability and endpoint kind,
/// never a URL, account, token or response.
pub(crate) fn provider(capability: &'static str, endpoint: &'static str) -> ProviderCall {
    let mut span = span("provider");
    let started = span.inner.is_some().then(|| {
        span.put("capability", json!(capability));
        span.put("endpoint", json!(endpoint));
        span.put("status", json!(0));
        now()
    });
    ProviderCall { span, started }
}

impl ProviderCall {
    pub(crate) fn status(&mut self, status: u16) {
        self.span.status(status);
    }
}

impl Drop for ProviderCall {
    fn drop(&mut self) {
        if let (Some(state), Some(started)) = (&self.span.inner, self.started) {
            let elapsed = since(started);
            state.recorder.with(|record| {
                record.totals.provider_calls = record.totals.provider_calls.saturating_add(1);
                record.totals.provider = record.totals.provider.saturating_add(elapsed);
            });
        }
    }
}

#[derive(Clone, Copy)]
enum Cost {
    SqlRead,
    SqlWrite,
    WorkerStart,
    WorkerExchange,
}

/// A repeated cost summed into the totals when dropped.
pub(crate) struct Measure(Option<(Recorder, Instant, Cost)>);

fn measure(cost: Cost) -> Measure {
    Measure(current().map(|recorder| (recorder, now(), cost)))
}

/// One runtime SQL read unit (connection open, snapshot, callback, close).
pub(crate) fn sql_read() -> Measure {
    measure(Cost::SqlRead)
}

/// One runtime SQL write unit, including its wait for the writer.
pub(crate) fn sql_write() -> Measure {
    measure(Cost::SqlWrite)
}

/// Starting one sandboxed Roc worker process.
pub(crate) fn worker_start() -> Measure {
    measure(Cost::WorkerStart)
}

/// One request/response exchange with a Roc worker: handler execution.
pub(crate) fn worker_exchange() -> Measure {
    measure(Cost::WorkerExchange)
}

impl Drop for Measure {
    fn drop(&mut self) {
        let Some((recorder, started, cost)) = self.0.take() else {
            return;
        };
        let elapsed = since(started);
        recorder.with(|record| {
            let totals = &mut record.totals;
            let (count, sum) = match cost {
                Cost::SqlRead => (&mut totals.sql_reads, &mut totals.sql_read),
                Cost::SqlWrite => (&mut totals.sql_writes, &mut totals.sql_write),
                Cost::WorkerStart => (&mut totals.worker_starts, &mut totals.worker_start),
                Cost::WorkerExchange => (&mut totals.worker_exchanges, &mut totals.worker_exchange),
            };
            *count = count.saturating_add(1);
            *sum = sum.saturating_add(elapsed);
        });
    }
}

/// Serializing and storing one invocation trace.
pub(crate) struct TraceWrite(Option<(Recorder, Instant, u64)>);

pub(crate) fn trace_write() -> TraceWrite {
    TraceWrite(current().map(|recorder| (recorder, now(), 0)))
}

impl TraceWrite {
    pub(crate) fn bytes(&mut self, bytes: usize) {
        if let Some((_, _, recorded)) = &mut self.0 {
            *recorded = u64::try_from(bytes).unwrap_or(u64::MAX);
        }
    }
}

impl Drop for TraceWrite {
    fn drop(&mut self) {
        let Some((recorder, started, bytes)) = self.0.take() else {
            return;
        };
        let elapsed = since(started);
        recorder.with(|record| {
            let totals = &mut record.totals;
            totals.trace_writes = totals.trace_writes.saturating_add(1);
            totals.trace_bytes = totals.trace_bytes.saturating_add(bytes);
            totals.trace_write = totals.trace_write.saturating_add(elapsed);
        });
    }
}

/// Waiting for this process's write turn and then SQLite's own write lock.
/// Dropped without [`WriterWait::began`], it counts as a busy refusal.
pub(crate) struct WriterWait(Option<(Recorder, Instant, Option<Instant>)>);

pub(crate) fn writer_wait() -> WriterWait {
    WriterWait(current().map(|recorder| (recorder, now(), None)))
}

impl WriterWait {
    /// This process's FIFO turn was granted; next is `BEGIN IMMEDIATE`, which
    /// waits for writers in other processes.
    pub(crate) fn turned(&mut self) {
        if let Some((_, _, turned)) = &mut self.0 {
            *turned = Some(now());
        }
    }

    /// The write transaction began. Its hold is timed until the returned
    /// guard is dropped.
    pub(crate) fn began(mut self) -> WriterHold {
        let Some((recorder, started, turned)) = self.0.take() else {
            return WriterHold(None);
        };
        let began = now();
        let turned = turned.unwrap_or(began);
        let wait = turned.saturating_duration_since(started);
        recorder.with(|record| {
            let totals = &mut record.totals;
            totals.writer_turns = totals.writer_turns.saturating_add(1);
            totals.writer_wait = totals.writer_wait.saturating_add(wait);
            totals.writer_wait_max = totals.writer_wait_max.max(wait);
            totals.writer_begin = totals
                .writer_begin
                .saturating_add(began.saturating_duration_since(turned));
        });
        WriterHold(Some((recorder, began)))
    }
}

impl Drop for WriterWait {
    fn drop(&mut self) {
        let Some((recorder, started, _)) = self.0.take() else {
            return;
        };
        let wait = since(started);
        recorder.with(|record| {
            let totals = &mut record.totals;
            totals.writer_busy = totals.writer_busy.saturating_add(1);
            totals.writer_wait = totals.writer_wait.saturating_add(wait);
            totals.writer_wait_max = totals.writer_wait_max.max(wait);
        });
    }
}

/// How long one write transaction held the writer.
pub(crate) struct WriterHold(Option<(Recorder, Instant)>);

impl Drop for WriterHold {
    fn drop(&mut self) {
        let Some((recorder, began)) = self.0.take() else {
            return;
        };
        let held = since(began);
        recorder.with(|record| {
            record.totals.writer_hold = record.totals.writer_hold.saturating_add(held);
        });
    }
}

#[cfg(test)]
#[path = "request_timing_tests.rs"]
mod tests;
