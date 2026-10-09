use anyhow::{Context, Result, bail, ensure};
#[cfg(not(target_os = "macos"))]
use std::io::BufReader;
use std::io::{BufRead, Write};
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(not(target_os = "macos"))]
use std::process::{Child, Stdio};
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU8, AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
#[cfg(not(target_os = "macos"))]
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[cfg(all(test, target_os = "macos"))]
#[path = "../../worker/src/first_request.rs"]
mod child_milestone_producer;
#[cfg(target_os = "macos")]
mod child_milestones;
#[cfg(target_os = "macos")]
mod mac_lifetime;

const MAX_FRAME: usize = 1_048_576;
const NO_ERRNO: i64 = i64::MIN;

/// Fixed-size, cumulative transport observations for one worker lifetime.
/// These counters saturate rather than wrap. They contain no frame bytes or
/// timestamps, and their snapshot is observational rather than an atomic trace.
struct StageProgress {
    #[cfg(target_os = "macos")]
    child: child_milestones::Progress,
    requests_enqueued: AtomicU32,
    writer_entered: AtomicU8,
    writer_dequeued: AtomicU32,
    writer_flushed: AtomicU32,
    reader_entered: AtomicU8,
    reader_first_byte: AtomicU8,
    reader_frames_completed: AtomicU32,
    write_failed: AtomicU8,
    write_errno: AtomicI64,
}

impl StageProgress {
    fn new() -> Self {
        Self {
            #[cfg(target_os = "macos")]
            child: child_milestones::Progress::new(),
            requests_enqueued: AtomicU32::new(0),
            writer_entered: AtomicU8::new(0),
            writer_dequeued: AtomicU32::new(0),
            writer_flushed: AtomicU32::new(0),
            reader_entered: AtomicU8::new(0),
            reader_first_byte: AtomicU8::new(0),
            reader_frames_completed: AtomicU32::new(0),
            write_failed: AtomicU8::new(0),
            write_errno: AtomicI64::new(NO_ERRNO),
        }
    }

    fn snapshot(&self, exit: &ExitEvidence) -> StageEvidence {
        let errno = self.write_errno.load(Ordering::Acquire);
        StageEvidence {
            #[cfg(target_os = "macos")]
            child_before_termination: Some(self.child.snapshot()),
            #[cfg(target_os = "macos")]
            child_after_termination_drain: None,
            requests_enqueued: self.requests_enqueued.load(Ordering::Acquire),
            writer_entered: self.writer_entered.load(Ordering::Acquire),
            writer_dequeued: self.writer_dequeued.load(Ordering::Acquire),
            writer_flushed: self.writer_flushed.load(Ordering::Acquire),
            reader_entered: self.reader_entered.load(Ordering::Acquire),
            reader_first_byte: self.reader_first_byte.load(Ordering::Acquire),
            reader_frames_completed: self.reader_frames_completed.load(Ordering::Acquire),
            write_failed: self.write_failed.load(Ordering::Acquire),
            write_errno: if errno == NO_ERRNO {
                None
            } else {
                i32::try_from(errno).ok()
            },
            child_code: exit.code,
            child_signal: exit.signal,
            try_wait_failed: exit.try_wait_failed,
            try_wait_errno: exit.try_wait_errno,
        }
    }
}

fn increment(counter: &AtomicU32) {
    // Every counter has one producer: the supervisor, writer, or reader.
    // Snapshot readers never mutate it, so no compare-and-swap retry loop is needed.
    counter.store(
        counter.load(Ordering::Relaxed).saturating_add(1),
        Ordering::Release,
    );
}

/// Only the native supervisor creates this snapshot. It carries no application
/// data and does not change failure classification, deadlines, or retry policy.
#[derive(Debug, serde::Serialize)]
pub(crate) struct StageEvidence {
    #[cfg(target_os = "macos")]
    child_before_termination: Option<child_milestones::Snapshot>,
    #[cfg(target_os = "macos")]
    child_after_termination_drain: Option<mac_lifetime::Final>,
    requests_enqueued: u32,
    writer_entered: u8,
    writer_dequeued: u32,
    writer_flushed: u32,
    reader_entered: u8,
    reader_first_byte: u8,
    reader_frames_completed: u32,
    write_failed: u8,
    write_errno: Option<i32>,
    child_code: Option<i32>,
    child_signal: Option<i32>,
    try_wait_failed: u8,
    try_wait_errno: Option<i32>,
}

impl std::fmt::Display for StageEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "worker stages [requests_enqueued={} writer_entered={} writer_dequeued={} writer_flushed={} reader_entered={} reader_first_byte={} reader_frames_completed={} write_failed={} write_errno={:?} child_code={:?} child_signal={:?} try_wait_failed={} try_wait_errno={:?}]",
            self.requests_enqueued,
            self.writer_entered,
            self.writer_dequeued,
            self.writer_flushed,
            self.reader_entered,
            self.reader_first_byte,
            self.reader_frames_completed,
            self.write_failed,
            self.write_errno,
            self.child_code,
            self.child_signal,
            self.try_wait_failed,
            self.try_wait_errno,
        )?;
        #[cfg(target_os = "macos")]
        {
            formatter.write_str(" first-child-before[")?;
            if let Some(before) = &self.child_before_termination {
                write!(formatter, "{before}")?;
            } else {
                formatter.write_str("none")?;
            }
            formatter.write_str("] first-child-after-drain[")?;
            if let Some(after) = &self.child_after_termination_drain {
                write!(formatter, "{after}")?;
            } else {
                formatter.write_str("none")?;
            }
            formatter.write_str("]")?;
        }
        Ok(())
    }
}

/// Exit state observed before the supervisor terminates a failed exchange.
/// This carries no worker output or application data and does not classify it.
/// A successful wait returning no status only observes an unexited child at that
/// instant. A failed wait remains distinct and retains only a numeric OS code.
/// Missing code/signal never proves that the child is still running later.
#[derive(Debug)]
pub(crate) struct ExitEvidence {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub try_wait_failed: u8,
    pub try_wait_errno: Option<i32>,
}

fn exit_evidence(observed: std::io::Result<Option<ExitStatus>>) -> ExitEvidence {
    let (status, try_wait_failed, try_wait_errno) = match observed {
        Ok(status) => (status, 0, None),
        Err(error) => (None, 1, error.raw_os_error()),
    };
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        status.as_ref().and_then(|status| status.signal())
    };
    #[cfg(not(unix))]
    let signal = None;
    ExitEvidence {
        code: status.as_ref().and_then(|status| status.code()),
        signal,
        try_wait_failed,
        try_wait_errno,
    }
}

impl std::fmt::Display for ExitEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("isolated worker exchange failed")
    }
}

pub struct Worker {
    #[cfg(target_os = "macos")]
    owner: mac_lifetime::Owner,
    #[cfg(not(target_os = "macos"))]
    child: Child,
    #[cfg(not(target_os = "macos"))]
    requests: Option<SyncSender<Vec<u8>>>,
    #[cfg(not(target_os = "macos"))]
    responses: Option<Receiver<Result<Vec<u8>>>>,
    #[cfg(not(target_os = "macos"))]
    reader: Option<JoinHandle<()>>,
    #[cfg(not(target_os = "macos"))]
    writer: Option<JoinHandle<()>>,
    progress: Arc<StageProgress>,
}

impl Worker {
    pub fn start(path: &Path) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Self::start_with_trusted_launcher(path, &sibling("day2-sandbox")?)
        }
        #[cfg(target_os = "macos")]
        {
            Self::start_macos(path)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        bail!("worker sandbox unsupported on this operating system");
    }

    /// The launcher path is supplied by trusted host installation/tests, never app input.
    #[cfg(target_os = "linux")]
    pub fn start_with_trusted_launcher(path: &Path, launcher: &Path) -> Result<Self> {
        let mut command = Command::new(
            launcher
                .canonicalize()
                .context("trusted worker launcher missing")?,
        );
        command
            .arg(path.canonicalize()?)
            .arg(std::process::id().to_string());
        Self::spawn(command)
    }

    #[cfg(target_os = "macos")]
    fn start_macos(path: &Path) -> Result<Self> {
        let path = path.canonicalize()?;
        let executable = path.to_str().context("non UTF-8 path")?;
        ensure!(
            !executable.contains(['"', '\\']),
            "unsupported sandbox path"
        );
        let profile = format!(
            r#"(version 1)(deny default)
            (allow process-exec (literal "{executable}"))
            (allow file-read*)
            (deny file-read-data (require-all (vnode-type REGULAR-FILE)
                (require-not (literal "{executable}"))
                (require-not (subpath "/usr/lib"))
                (require-not (subpath "/System"))))
            (allow sysctl-read)
            (allow mach-lookup (global-name "com.apple.system.logger"))
            (allow file-write-data (literal "/dev/null"))"#
        );
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.args(["-p", &profile, executable]);
        Self::spawn(command)
    }

    fn spawn(command: Command) -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let progress = Arc::new(StageProgress::new());
            let mut owner = mac_lifetime::Owner::new(Arc::clone(&progress))?;
            owner.launch(command)?;
            Ok(Self { owner, progress })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let mut command: Command = command;
            let mut child = command
                .env_clear()
                .env("LANG", "C")
                .env("LC_ALL", "C")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .context("spawn isolated Roc worker")?;
            let mut stdin = child.stdin.take().context("worker stdin")?;
            let stdout = child.stdout.take().context("worker stdout")?;
            let (sender, responses) = mpsc::sync_channel(1);
            let (requests, incoming) = mpsc::sync_channel::<Vec<u8>>(1);
            let progress = Arc::new(StageProgress::new());
            let write_progress = Arc::clone(&progress);
            let writer = thread::Builder::new()
                .name("day2-worker-input".into())
                .spawn(move || {
                    write_progress.writer_entered.store(1, Ordering::Release);
                    while let Ok(frame) = incoming.recv() {
                        if write_frame(&mut stdin, &frame, &write_progress).is_err() {
                            break;
                        }
                    }
                });
            let writer = match writer {
                Ok(writer) => writer,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error).context("start worker input thread");
                }
            };
            let read_progress = Arc::clone(&progress);
            let reader = thread::Builder::new()
                .name("day2-worker-output".into())
                .spawn(move || {
                    read_progress.reader_entered.store(1, Ordering::Release);
                    let mut reader = BufReader::new(stdout);
                    loop {
                        let result = read_frame(&mut reader, &read_progress);
                        let failed = result.is_err();
                        if sender.send(result).is_err() || failed {
                            break;
                        }
                    }
                });
            let reader = match reader {
                Ok(reader) => reader,
                Err(error) => {
                    drop(requests);
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = writer.join();
                    return Err(error).context("start worker output thread");
                }
            };
            Ok(Self {
                child,
                requests: Some(requests),
                responses: Some(responses),
                reader: Some(reader),
                writer: Some(writer),
                progress,
            })
        }
    }

    pub fn exchange(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let result = self.exchange_frame(input);
        match result {
            Ok(frame) => Ok(frame),
            Err(error) => {
                #[cfg(target_os = "macos")]
                let evidence = self.owner.observe_exit();
                #[cfg(not(target_os = "macos"))]
                let evidence = exit_evidence(self.child.try_wait());
                let stages = self.progress.snapshot(&evidence);
                self.terminate();
                #[cfg(target_os = "macos")]
                let stages = StageEvidence {
                    child_after_termination_drain: Some(self.owner.final_snapshot()),
                    ..stages
                };
                Err(error.context(stages).context(evidence))
            }
        }
    }

    fn exchange_frame(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            input.len() < MAX_FRAME && !input.contains(&b'\n'),
            "invalid worker frame"
        );
        self.requests()
            .as_ref()
            .context("closed worker")?
            .try_send(input.to_vec())
            .context("worker request backlog")?;
        increment(&self.progress.requests_enqueued);
        self.responses()
            .as_ref()
            .context("closed worker")?
            .recv_timeout(Duration::from_secs(3))
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => crate::error::Failure::WorkerTimeout,
                mpsc::RecvTimeoutError::Disconnected => crate::error::Failure::WorkerCrashed,
            })?
    }

    fn terminate(&mut self) {
        #[cfg(target_os = "macos")]
        self.owner.close();
        #[cfg(not(target_os = "macos"))]
        {
            self.requests.take();
            self.responses.take();
            let _ = self.child.kill();
            let _ = self.child.wait();
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
            if let Some(writer) = self.writer.take() {
                let _ = writer.join();
            }
        }
    }

    fn requests(&self) -> &Option<SyncSender<Vec<u8>>> {
        #[cfg(target_os = "macos")]
        {
            &self.owner.requests
        }
        #[cfg(not(target_os = "macos"))]
        {
            &self.requests
        }
    }

    fn responses(&self) -> &Option<Receiver<Result<Vec<u8>>>> {
        #[cfg(target_os = "macos")]
        {
            &self.owner.responses
        }
        #[cfg(not(target_os = "macos"))]
        {
            &self.responses
        }
    }
}

#[cfg(target_os = "linux")]
fn sibling(name: &str) -> Result<PathBuf> {
    let supervisor = std::env::current_exe()?.canonicalize()?;
    Ok(supervisor
        .parent()
        .context("supervisor installation directory")?
        .join(name))
}

/// Mandatory Linux startup qualification using the same launcher and a host-only probe.
pub fn qualify_sandbox() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mut worker = Worker::start(&sibling("day2-sandbox-probe")?)?;
        ensure!(
            worker.exchange(b"qualify")? == day2_sandbox::QUALIFIED,
            "Linux worker sandbox qualification failed"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    bail!("Linux worker qualification requires Linux");
}

fn write_frame(
    writer: &mut impl Write,
    frame: &[u8],
    progress: &StageProgress,
) -> std::io::Result<()> {
    increment(&progress.writer_dequeued);
    let result = writer
        .write_all(frame)
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush());
    match &result {
        Ok(()) => increment(&progress.writer_flushed),
        Err(error) => {
            progress.write_errno.store(
                error.raw_os_error().map_or(NO_ERRNO, i64::from),
                Ordering::Release,
            );
            progress.write_failed.store(1, Ordering::Release);
        }
    }
    result
}

fn read_frame(reader: &mut impl BufRead, progress: &StageProgress) -> Result<Vec<u8>> {
    let mut frame = Vec::new();
    loop {
        let data = reader.fill_buf()?;
        if data.is_empty() {
            return Err(anyhow::Error::new(crate::error::Failure::WorkerCrashed)
                .context("worker exited before response"));
        }
        progress.reader_first_byte.store(1, Ordering::Release);
        let count = data
            .iter()
            .position(|b| *b == b'\n')
            .map_or(data.len(), |i| i + 1);
        ensure!(
            frame.len() + count <= MAX_FRAME,
            "oversized worker response"
        );
        frame.extend_from_slice(&data[..count]);
        reader.consume(count);
        if frame.last() == Some(&b'\n') {
            frame.pop();
            increment(&progress.reader_frames_completed);
            return Ok(frame);
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExitEvidence, MAX_FRAME, StageProgress, exit_evidence, increment, read_frame, write_frame,
    };
    use std::io::{Cursor, Write};
    use std::sync::atomic::Ordering;

    fn snapshot(progress: &StageProgress) -> super::StageEvidence {
        progress.snapshot(&ExitEvidence {
            code: None,
            signal: None,
            try_wait_failed: 0,
            try_wait_errno: None,
        })
    }

    #[test]
    fn wait_failures_remain_distinct_and_carry_only_numeric_evidence() {
        let waiting = exit_evidence(Ok(None));
        assert_eq!(waiting.code, None);
        assert_eq!(waiting.signal, None);
        assert_eq!(waiting.try_wait_failed, 0);
        assert_eq!(waiting.try_wait_errno, None);
        for errno in [Some(10), Some(5), None] {
            let fault = errno.map_or_else(
                || std::io::Error::other("PRIVATE_WAIT_ERROR"),
                std::io::Error::from_raw_os_error,
            );
            let evidence = exit_evidence(Err(fault));
            assert_eq!(evidence.code, None);
            assert_eq!(evidence.signal, None);
            assert_eq!(evidence.try_wait_failed, 1);
            assert_eq!(evidence.try_wait_errno, errno);
            let stages = StageProgress::new().snapshot(&evidence);
            let error = anyhow::Error::new(crate::error::Failure::WorkerTimeout)
                .context(stages)
                .context(evidence);
            assert_eq!(
                crate::error::classify(&error),
                crate::error::Failure::WorkerTimeout
            );
            let diagnostic = crate::error::diagnostic(&error);
            assert_eq!(diagnostic["worker_exit"]["try_wait_failed"], 1);
            assert_eq!(diagnostic["worker_stage"]["try_wait_failed"], 1);
            assert_eq!(
                diagnostic["worker_exit"]["try_wait_errno"],
                serde_json::json!(errno)
            );
            assert_eq!(
                diagnostic["worker_stage"]["try_wait_errno"],
                serde_json::json!(errno)
            );
            assert!(!diagnostic.to_string().contains("PRIVATE"));
            assert!(!error.to_string().contains("PRIVATE"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn observed_exit_and_signal_preserve_status_without_a_wait_fault() {
        use std::os::unix::process::ExitStatusExt;

        for (raw, code, signal) in [(70 << 8, Some(70), None), (9, None, Some(9))] {
            let evidence = exit_evidence(Ok(Some(std::process::ExitStatus::from_raw(raw))));
            assert_eq!(evidence.code, code);
            assert_eq!(evidence.signal, signal);
            assert_eq!(evidence.try_wait_failed, 0);
            assert_eq!(evidence.try_wait_errno, None);
            let stages = StageProgress::new().snapshot(&evidence);
            assert_eq!(stages.child_code, code);
            assert_eq!(stages.child_signal, signal);
            assert_eq!(stages.try_wait_failed, 0);
            assert_eq!(stages.try_wait_errno, None);
        }
    }

    #[test]
    fn frames_preserve_exact_payload_and_buffered_next_response() {
        let mut bytes = Cursor::new(b"first\n\nlast\n");
        let progress = StageProgress::new();
        assert_eq!(read_frame(&mut bytes, &progress).unwrap(), b"first");
        assert_eq!(read_frame(&mut bytes, &progress).unwrap(), b"");
        assert_eq!(read_frame(&mut bytes, &progress).unwrap(), b"last");
        assert!(read_frame(&mut bytes, &progress).is_err());
        let observed = snapshot(&progress);
        assert_eq!(observed.reader_first_byte, 1);
        assert_eq!(observed.reader_frames_completed, 3);
    }

    #[test]
    fn eof_and_size_limit_fail_without_accepting_partial_frames() {
        let partial = StageProgress::new();
        let error = read_frame(&mut Cursor::new(b"partial"), &partial).unwrap_err();
        assert_eq!(
            crate::error::classify(&error),
            crate::error::Failure::WorkerCrashed
        );
        assert_eq!(snapshot(&partial).reader_first_byte, 1);
        assert_eq!(snapshot(&partial).reader_frames_completed, 0);
        let empty = StageProgress::new();
        assert!(read_frame(&mut Cursor::new(b""), &empty).is_err());
        assert_eq!(snapshot(&empty).reader_first_byte, 0);
        let mut maximum = vec![b'x'; MAX_FRAME - 1];
        maximum.push(b'\n');
        let accepted = StageProgress::new();
        assert_eq!(
            read_frame(&mut Cursor::new(&maximum), &accepted)
                .unwrap()
                .len(),
            MAX_FRAME - 1
        );
        assert_eq!(snapshot(&accepted).reader_frames_completed, 1);
        maximum.insert(0, b'x');
        let oversized = StageProgress::new();
        let error = read_frame(&mut Cursor::new(maximum), &oversized).unwrap_err();
        assert!(error.to_string().contains("oversized worker response"));
        assert_eq!(snapshot(&oversized).reader_first_byte, 1);
        assert_eq!(snapshot(&oversized).reader_frames_completed, 0);
    }

    #[test]
    fn actual_write_helper_preserves_frames_and_counts_only_completed_flushes() {
        let progress = StageProgress::new();
        let mut output = Vec::new();
        for frame in [b"first".as_slice(), b"", b"last"] {
            write_frame(&mut output, frame, &progress).unwrap();
        }
        assert_eq!(output, b"first\n\nlast\n");
        let observed = snapshot(&progress);
        assert_eq!(observed.writer_dequeued, 3);
        assert_eq!(observed.writer_flushed, 3);
        assert_eq!(observed.write_failed, 0);
        assert_eq!(observed.write_errno, None);
    }

    struct FaultWriter {
        fail_flush: bool,
        errno: Option<i32>,
        bytes: Vec<u8>,
    }

    impl FaultWriter {
        fn error(&self) -> std::io::Error {
            self.errno.map_or_else(
                || std::io::Error::new(std::io::ErrorKind::BrokenPipe, "PRIVATE_WRITE_ERROR"),
                std::io::Error::from_raw_os_error,
            )
        }
    }

    impl Write for FaultWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !self.fail_flush {
                return Err(self.error());
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(self.error())
        }
    }

    #[test]
    fn write_and_flush_faults_record_only_numeric_evidence_without_changing_failure() {
        for (fail_flush, errno) in [(false, Some(32)), (true, Some(5)), (false, None)] {
            let progress = StageProgress::new();
            let mut writer = FaultWriter {
                fail_flush,
                errno,
                bytes: Vec::new(),
            };
            let error = write_frame(&mut writer, b"PRIVATE_FRAME", &progress).unwrap_err();
            assert_eq!(error.raw_os_error(), errno);
            let observed = snapshot(&progress);
            assert_eq!(observed.writer_dequeued, 1);
            assert_eq!(observed.writer_flushed, 0);
            assert_eq!(observed.write_failed, 1);
            assert_eq!(observed.write_errno, errno);
            if fail_flush {
                assert_eq!(writer.bytes, b"PRIVATE_FRAME\n");
            } else {
                assert!(writer.bytes.is_empty());
            }
            let encoded = serde_json::to_string(&observed).unwrap();
            assert!(!encoded.contains("PRIVATE"));
            assert!(!observed.to_string().contains("PRIVATE"));
        }
    }

    #[test]
    fn cumulative_counters_saturate_and_failure_context_keeps_closed_diagnostics() {
        let progress = StageProgress::new();
        progress
            .requests_enqueued
            .store(u32::MAX - 1, Ordering::Relaxed);
        increment(&progress.requests_enqueued);
        increment(&progress.requests_enqueued);
        assert_eq!(snapshot(&progress).requests_enqueued, u32::MAX);
        progress.writer_dequeued.store(u32::MAX, Ordering::Relaxed);
        progress.writer_flushed.store(u32::MAX, Ordering::Relaxed);
        progress
            .reader_frames_completed
            .store(u32::MAX, Ordering::Relaxed);
        progress.writer_entered.store(1, Ordering::Release);
        progress.reader_entered.store(1, Ordering::Release);
        progress.reader_first_byte.store(1, Ordering::Release);
        let stages = progress.snapshot(&ExitEvidence {
            code: Some(70),
            signal: None,
            try_wait_failed: 0,
            try_wait_errno: None,
        });
        let error = anyhow::Error::new(crate::error::Failure::WorkerTimeout)
            .context(stages)
            .context(ExitEvidence {
                code: Some(70),
                signal: None,
                try_wait_failed: 0,
                try_wait_errno: None,
            })
            .context("PRIVATE_FRAME_OR_PATH");
        assert_eq!(
            crate::error::classify(&error),
            crate::error::Failure::WorkerTimeout
        );
        let diagnostic = crate::error::diagnostic(&error);
        assert_eq!(diagnostic["failure"], "worker_timeout");
        assert_eq!(diagnostic["worker_exit"]["code"], 70);
        assert_eq!(diagnostic["worker_stage"]["child_code"], 70);
        assert_eq!(diagnostic["worker_stage"]["requests_enqueued"], u32::MAX);
        assert_eq!(diagnostic["worker_stage"]["writer_entered"], 1);
        assert_eq!(diagnostic["worker_stage"]["reader_entered"], 1);
        assert!(!diagnostic.to_string().contains("PRIVATE"));
        // Fixed field names and bounded primitive values remain below one KiB,
        // even at maximum counter values and through text workflow transport.
        let text = error
            .downcast_ref::<super::StageEvidence>()
            .unwrap()
            .to_string();
        assert!(text.len() < 1024);
        assert!(text.contains("requests_enqueued=4294967295"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn child_phase_diagnostics_keep_late_invalid_tail_separate_and_category_unchanged() {
        let progress = StageProgress::new();
        let before = snapshot(&progress);
        let mut unknown_tail = std::io::Cursor::new(b"D2ST1:1\nPRIVATE_TOKEN_PATH");
        super::child_milestones::drain(&mut unknown_tail, &progress.child);
        let after = super::mac_lifetime::Final {
            stream: progress.child.snapshot(),
            cleanup: super::mac_lifetime::Cleanup::default(),
        };
        let phases = super::StageEvidence {
            child_after_termination_drain: Some(after),
            ..before
        };
        let error = anyhow::Error::new(crate::error::Failure::WorkerTimeout).context(phases);
        assert_eq!(
            crate::error::classify(&error),
            crate::error::Failure::WorkerTimeout
        );
        let diagnostic = crate::error::diagnostic(&error);
        let first = &diagnostic["worker_stage"]["child_before_termination"];
        let final_stream = &diagnostic["worker_stage"]["child_after_termination_drain"]["stream"];
        assert_eq!(first["prefix"], 0);
        assert_eq!(first["eof"], 0);
        assert_eq!(final_stream["prefix"], 1);
        assert_eq!(final_stream["invalid"], 1);
        assert_eq!(final_stream["eof"], 1);
        assert_eq!(first["first_request_only"], true);
        assert_eq!(final_stream["first_request_only"], true);
        assert!(!diagnostic.to_string().contains("PRIVATE"));
        assert!(!error.to_string().contains("PRIVATE"));
        assert!(error.to_string().len() < 1024);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn child_diagnostic_text_has_a_fixed_bound_even_for_maximal_numeric_fields() {
        let mut stages = snapshot(&StageProgress::new());
        let child = super::child_milestones::Snapshot {
            first_request_only: true,
            prefix: u8::MAX,
            bytes: u32::MAX,
            partial: u8::MAX,
            invalid: u8::MAX,
            overflow: u8::MAX,
            truncated: u8::MAX,
            eof: u8::MAX,
            read_failed: u8::MAX,
            read_errno: Some(i32::MIN),
            entered: u8::MAX,
            unwound: u8::MAX,
        };
        stages.child_before_termination = Some(child);
        stages.child_after_termination_drain = Some(super::mac_lifetime::Final {
            stream: child,
            cleanup: super::mac_lifetime::Cleanup {
                kill_failed: u8::MAX,
                kill_errno: Some(i32::MIN),
                wait_failed: u8::MAX,
                wait_errno: Some(i32::MIN),
                terminal: u8::MAX,
                unresolved: u8::MAX,
            },
        });
        stages.requests_enqueued = u32::MAX;
        stages.writer_dequeued = u32::MAX;
        stages.writer_flushed = u32::MAX;
        stages.reader_frames_completed = u32::MAX;
        stages.write_errno = Some(i32::MIN);
        stages.child_code = Some(i32::MIN);
        stages.child_signal = Some(i32::MIN);
        stages.try_wait_errno = Some(i32::MIN);
        let text = stages.to_string();
        assert!(text.len() < 1024);
        assert!(text.contains("first-child-before["));
        assert!(text.contains("first-child-after-drain["));
    }
}
