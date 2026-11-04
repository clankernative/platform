#[cfg(not(target_os = "linux"))]
use anyhow::bail;
use anyhow::{Context, Result, ensure};
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
pub(crate) const PROPERTY_MAX_FRAME: usize = 6 * 32 * 1024 * 1024 + 65_536;
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
            #[cfg(not(target_os = "macos"))]
            child_after_termination: None,
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
    #[cfg(not(target_os = "macos"))]
    child_after_termination: Option<TerminationEvidence>,
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
        #[cfg(not(target_os = "macos"))]
        if let Some(after) = &self.child_after_termination {
            write!(formatter, " child-after-termination[{after}]")?;
        }
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

/// Results of the existing supervisor kill and wait, never the original exit
/// cause. In particular, signal 9 here can be the supervisor's requested kill.
/// Error messages, paths, frame bytes and environment values are not retained.
#[cfg(not(target_os = "macos"))]
#[derive(Debug, serde::Serialize)]
struct TerminationEvidence {
    kill_requested: bool,
    kill_failed: u8,
    kill_errno: Option<i32>,
    wait_failed: u8,
    wait_errno: Option<i32>,
    code: Option<i32>,
    signal: Option<i32>,
}

#[cfg(not(target_os = "macos"))]
impl TerminationEvidence {
    fn observe(kill: std::io::Result<()>, wait: std::io::Result<ExitStatus>) -> Self {
        let kill_failed = u8::from(kill.is_err());
        let kill_errno = kill.err().and_then(|error| error.raw_os_error());
        let waited = exit_evidence(wait.map(Some));
        Self {
            kill_requested: true,
            kill_failed,
            kill_errno,
            wait_failed: waited.try_wait_failed,
            wait_errno: waited.try_wait_errno,
            code: waited.code,
            signal: waited.signal,
        }
    }
}

#[cfg(not(target_os = "macos"))]
impl std::fmt::Display for TerminationEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "kill_requested={} kill_failed={} kill_errno={:?} wait_failed={} wait_errno={:?} code={:?} signal={:?}",
            self.kill_requested,
            self.kill_failed,
            self.kill_errno,
            self.wait_failed,
            self.wait_errno,
            self.code,
            self.signal,
        )
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
    #[cfg(not(target_os = "macos"))]
    termination: Option<TerminationEvidence>,
    progress: Arc<StageProgress>,
    frame_limit: usize,
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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn start_verification(
        path: &Path,
        heap_bytes: u64,
        timeout: Duration,
        frame_limit: usize,
    ) -> Result<Self> {
        ensure!(
            heap_bytes == 512 * 1024 * 1024,
            "unsupported property worker heap profile"
        );
        ensure!(
            !timeout.is_zero()
                && timeout <= Duration::from_secs(30)
                && frame_limit == PROPERTY_MAX_FRAME,
            "unsupported property worker limits"
        );
        #[cfg(target_os = "linux")]
        {
            Self::start_with_profile(path, &sibling("day2-sandbox")?, heap_bytes, 30, frame_limit)
        }
        #[cfg(target_os = "macos")]
        {
            Self::start_macos_profile(path, frame_limit)
        }
    }

    /// The launcher path is supplied by trusted host installation/tests, never app input.
    #[cfg(target_os = "linux")]
    pub fn start_with_trusted_launcher(path: &Path, launcher: &Path) -> Result<Self> {
        Self::start_with_profile(
            path,
            launcher,
            day2_sandbox::ADDRESS_SPACE_BYTES,
            day2_sandbox::CPU_SECONDS,
            MAX_FRAME,
        )
    }

    #[cfg(target_os = "linux")]
    fn start_with_profile(
        path: &Path,
        launcher: &Path,
        memory_bytes: u64,
        cpu_seconds: u64,
        frame_limit: usize,
    ) -> Result<Self> {
        let mut command = Command::new(
            launcher
                .canonicalize()
                .context("trusted worker launcher missing")?,
        );
        command
            .arg(path.canonicalize()?)
            .arg(std::process::id().to_string())
            .arg(memory_bytes.to_string())
            .arg(cpu_seconds.to_string());
        Self::spawn(command, frame_limit)
    }

    #[cfg(target_os = "macos")]
    fn start_macos(path: &Path) -> Result<Self> {
        Self::start_macos_profile(path, MAX_FRAME)
    }

    #[cfg(target_os = "macos")]
    fn start_macos_profile(path: &Path, frame_limit: usize) -> Result<Self> {
        ensure!(
            matches!(frame_limit, MAX_FRAME | PROPERTY_MAX_FRAME),
            "unsupported macOS worker profile"
        );
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
        if frame_limit == PROPERTY_MAX_FRAME {
            command.arg("--day2-qualified-property-v1");
        }
        Self::spawn(command, frame_limit)
    }

    fn spawn(command: Command, frame_limit: usize) -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let progress = Arc::new(StageProgress::new());
            let mut owner = mac_lifetime::Owner::new(Arc::clone(&progress))?;
            owner.launch(command, frame_limit)?;
            Ok(Self {
                owner,
                progress,
                frame_limit,
            })
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
                        let result = read_frame(&mut reader, &read_progress, frame_limit);
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
                termination: None,
                progress,
                frame_limit,
            })
        }
    }

    pub fn exchange(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.exchange_bounded(input, MAX_FRAME, Duration::from_secs(3))
    }

    pub fn exchange_bounded(
        &mut self,
        input: &[u8],
        frame_limit: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        ensure!(
            frame_limit <= self.frame_limit,
            "worker frame limit exceeds profile"
        );
        let maximum_timeout = if self.frame_limit == PROPERTY_MAX_FRAME {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(3)
        };
        ensure!(
            !timeout.is_zero() && timeout <= maximum_timeout,
            "worker timeout exceeds profile"
        );
        let result = self.exchange_frame(input, frame_limit, timeout);
        match result {
            Ok(frame) => Ok(frame),
            Err(error) => {
                #[cfg(target_os = "macos")]
                let evidence = self.owner.observe_exit();
                #[cfg(not(target_os = "macos"))]
                let evidence = exit_evidence(self.child.try_wait());
                let stages = self.progress.snapshot(&evidence);
                self.terminate();
                #[cfg(not(target_os = "macos"))]
                let stages = StageEvidence {
                    child_after_termination: self.termination.take(),
                    ..stages
                };
                #[cfg(target_os = "macos")]
                let stages = StageEvidence {
                    child_after_termination_drain: Some(self.owner.final_snapshot()),
                    ..stages
                };
                Err(error.context(stages).context(evidence))
            }
        }
    }

    fn exchange_frame(
        &mut self,
        input: &[u8],
        frame_limit: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        ensure!(
            input.len() < frame_limit && !input.contains(&b'\n'),
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
            .recv_timeout(timeout)
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
            let kill = self.child.kill();
            let wait = self.child.wait();
            self.termination = Some(TerminationEvidence::observe(kill, wait));
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
    let supervisor = std::env::current_exe()?
        .canonicalize()
        .context("current worker supervisor executable is unavailable")?;
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

fn read_frame(
    reader: &mut impl BufRead,
    progress: &StageProgress,
    frame_limit: usize,
) -> Result<Vec<u8>> {
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
            frame.len() + count <= frame_limit,
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
        ExitEvidence, MAX_FRAME, PROPERTY_MAX_FRAME, StageProgress, exit_evidence, increment,
        read_frame, write_frame,
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

    #[cfg(target_os = "linux")]
    #[test]
    fn natural_exit_keeps_original_status_separate_from_requested_cleanup() {
        let mut worker =
            super::Worker::spawn(std::process::Command::new("/usr/bin/false"), MAX_FRAME).unwrap();
        // This controlled child has already exited before the exchange. The
        // production exchange still performs its unchanged try-wait/kill/wait.
        assert_eq!(worker.child.wait().unwrap().code(), Some(1));
        let error = worker.exchange(b"PRIVATE_FRAME").unwrap_err();
        let diagnostic = crate::error::diagnostic(&error);
        assert_eq!(diagnostic["failure"], "worker_crashed");
        assert_eq!(diagnostic["worker_exit"]["code"], 1);
        let after = &diagnostic["worker_stage"]["child_after_termination"];
        assert_eq!(after["kill_requested"], true);
        assert_eq!(after["wait_failed"], 0);
        assert_eq!(after["code"], 1);
        assert!(after["signal"].is_null());
        assert!(!diagnostic.to_string().contains("PRIVATE"));
        assert!(worker.reader.is_none() && worker.writer.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn actual_timeout_labels_supervisor_kill_and_reaps_the_child() {
        use std::os::unix::process::ExitStatusExt;

        let mut command = std::process::Command::new("/usr/bin/sleep");
        command.arg("60");
        let mut worker = super::Worker::spawn(command, MAX_FRAME).unwrap();
        let error = worker.exchange(b"PRIVATE_FRAME").unwrap_err();
        let diagnostic = crate::error::diagnostic(&error);
        assert_eq!(diagnostic["failure"], "worker_timeout");
        assert!(diagnostic["worker_exit"]["code"].is_null());
        assert!(diagnostic["worker_exit"]["signal"].is_null());
        let after = &diagnostic["worker_stage"]["child_after_termination"];
        assert_eq!(after["kill_requested"], true);
        assert_eq!(after["kill_failed"], 0);
        assert_eq!(after["wait_failed"], 0);
        assert_eq!(after["signal"], 9);
        assert!(after["code"].is_null());
        assert_eq!(worker.child.try_wait().unwrap().unwrap().signal(), Some(9));
        assert!(worker.reader.is_none() && worker.writer.is_none());
        assert!(!diagnostic.to_string().contains("PRIVATE"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn actual_trusted_launcher_refusal_retains_exit_without_private_bytes() {
        // The ordinary native preparation supplies the admitted sibling launcher.
        // A regular, non-executable file must be refused before worker execution.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("PRIVATE_WORKER_PATH");
        std::fs::write(&path, b"PRIVATE_WORKER_IMAGE").unwrap();
        let mut worker = super::Worker::start(&path).unwrap();
        assert_eq!(worker.child.wait().unwrap().code(), Some(77));
        let error = worker.exchange(b"PRIVATE_FRAME").unwrap_err();
        let diagnostic = crate::error::diagnostic(&error);
        assert_eq!(diagnostic["failure"], "worker_crashed");
        assert_eq!(diagnostic["worker_exit"]["code"], 77);
        let after = &diagnostic["worker_stage"]["child_after_termination"];
        assert_eq!(after["kill_requested"], true);
        assert_eq!(after["wait_failed"], 0);
        assert_eq!(after["code"], 77);
        assert!(!diagnostic.to_string().contains("PRIVATE"));
        assert!(worker.reader.is_none() && worker.writer.is_none());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn cleanup_faults_and_maximal_evidence_remain_bounded_and_redacted() {
        for errno in [Some(5), None] {
            let fault = || {
                errno.map_or_else(
                    || std::io::Error::other("PRIVATE_TERMINATION_ERROR"),
                    std::io::Error::from_raw_os_error,
                )
            };
            let after = super::TerminationEvidence::observe(Err(fault()), Err(fault()));
            assert!(after.kill_requested);
            assert_eq!(after.kill_failed, 1);
            assert_eq!(after.kill_errno, errno);
            assert_eq!(after.wait_failed, 1);
            assert_eq!(after.wait_errno, errno);
            assert!(after.code.is_none() && after.signal.is_none());
            let mut stages = snapshot(&StageProgress::new());
            stages.child_after_termination = Some(after);
            let error = anyhow::Error::new(crate::error::Failure::WorkerCrashed).context(stages);
            let diagnostic = crate::error::diagnostic(&error);
            assert_eq!(diagnostic["failure"], "worker_crashed");
            assert!(!diagnostic.to_string().contains("PRIVATE"));
            assert!(!error.to_string().contains("PRIVATE"));
        }
        let mut stages = snapshot(&StageProgress::new());
        stages.requests_enqueued = u32::MAX;
        stages.writer_dequeued = u32::MAX;
        stages.writer_flushed = u32::MAX;
        stages.reader_frames_completed = u32::MAX;
        stages.write_errno = Some(i32::MIN);
        stages.child_code = Some(i32::MIN);
        stages.child_signal = Some(i32::MIN);
        stages.try_wait_errno = Some(i32::MIN);
        stages.child_after_termination = Some(super::TerminationEvidence {
            kill_requested: true,
            kill_failed: u8::MAX,
            kill_errno: Some(i32::MIN),
            wait_failed: u8::MAX,
            wait_errno: Some(i32::MIN),
            code: Some(i32::MIN),
            signal: Some(i32::MIN),
        });
        let text = stages.to_string();
        assert!(text.len() < 1024);
        assert!(text.contains("child-after-termination[kill_requested=true"));
    }

    #[test]
    fn frames_preserve_exact_payload_and_buffered_next_response() {
        let mut bytes = Cursor::new(b"first\n\nlast\n");
        let progress = StageProgress::new();
        assert_eq!(
            read_frame(&mut bytes, &progress, MAX_FRAME).unwrap(),
            b"first"
        );
        assert_eq!(read_frame(&mut bytes, &progress, MAX_FRAME).unwrap(), b"");
        assert_eq!(
            read_frame(&mut bytes, &progress, MAX_FRAME).unwrap(),
            b"last"
        );
        assert!(read_frame(&mut bytes, &progress, MAX_FRAME).is_err());
        let observed = snapshot(&progress);
        assert_eq!(observed.reader_first_byte, 1);
        assert_eq!(observed.reader_frames_completed, 3);
    }

    #[test]
    fn eof_and_size_limit_fail_without_accepting_partial_frames() {
        let partial = StageProgress::new();
        let error = read_frame(&mut Cursor::new(b"partial"), &partial, MAX_FRAME).unwrap_err();
        assert_eq!(
            crate::error::classify(&error),
            crate::error::Failure::WorkerCrashed
        );
        assert_eq!(snapshot(&partial).reader_first_byte, 1);
        assert_eq!(snapshot(&partial).reader_frames_completed, 0);
        let empty = StageProgress::new();
        assert!(read_frame(&mut Cursor::new(b""), &empty, MAX_FRAME).is_err());
        assert_eq!(snapshot(&empty).reader_first_byte, 0);
        let mut maximum = vec![b'x'; MAX_FRAME - 1];
        maximum.push(b'\n');
        let accepted = StageProgress::new();
        assert_eq!(
            read_frame(&mut Cursor::new(&maximum), &accepted, MAX_FRAME)
                .unwrap()
                .len(),
            MAX_FRAME - 1
        );
        assert_eq!(snapshot(&accepted).reader_frames_completed, 1);
        maximum.insert(0, b'x');
        let oversized = StageProgress::new();
        let error = read_frame(&mut Cursor::new(maximum), &oversized, MAX_FRAME).unwrap_err();
        assert!(error.to_string().contains("oversized worker response"));
        assert_eq!(snapshot(&oversized).reader_first_byte, 1);
        assert_eq!(snapshot(&oversized).reader_frames_completed, 0);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn qualified_profile_rejects_wrong_limits_before_materializing_or_spawning() {
        let absent = std::path::Path::new("/DAY2_PROFILE_MUST_NOT_SPAWN");
        for (heap, timeout, frame, message) in [
            (64 * 1024 * 1024, 30, PROPERTY_MAX_FRAME, "heap profile"),
            (512 * 1024 * 1024, 0, PROPERTY_MAX_FRAME, "worker limits"),
            (512 * 1024 * 1024, 31, PROPERTY_MAX_FRAME, "worker limits"),
            (512 * 1024 * 1024, 30, MAX_FRAME, "worker limits"),
        ] {
            let error = super::Worker::start_verification(
                absent,
                heap,
                std::time::Duration::from_secs(timeout),
                frame,
            )
            .err()
            .expect("unsupported profile must refuse before spawning");
            assert!(error.to_string().contains(message), "{error}");
        }
    }

    #[test]
    fn property_frame_profile_reads_responses_above_the_invocation_limit() {
        let mut frame = vec![b'x'; MAX_FRAME + 1];
        frame.push(b'\n');
        let progress = StageProgress::new();
        assert_eq!(
            read_frame(&mut Cursor::new(&frame), &progress, PROPERTY_MAX_FRAME)
                .unwrap()
                .len(),
            MAX_FRAME + 1
        );
        assert_eq!(snapshot(&progress).reader_frames_completed, 1);
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

/// Real supervisor transport with fixed disposable children. No launcher,
/// sandbox, application ABI or enrolled execution authority is supplied here.
#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod exchange_histories {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::sync::Weak;

    const MAX_CASES: usize = 8;
    const MAX_CUTS: usize = 128;
    const MAX_BYTES: u64 = 512 * 1024;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum ChildKind {
        Echo,
        Exited,
        Silent,
        Missing,
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Case {
        kind: ChildKind,
        requests: u8,
        bad_budget: bool,
        malformed: bool,
        empty_first: bool,
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Program {
        version: u8,
        source: String,
        seed: u64,
        cases: Vec<Case>,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Control {
        Correct,
        TimeoutCompletes,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Step {
        Start,
        ZeroBudget,
        LargeBudget,
        Request(u8),
        Malformed,
        Reuse,
        Close,
        CloseAgain,
        Discard,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Fault {
        Timeout,
        Crashed,
        Missing,
        Other,
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Reply {
        Started,
        Refused(Fault),
        Echo { length: usize, digest: String },
        Closed,
        Discarded,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Counters {
        enqueued: u32,
        writer_entered: u8,
        dequeued: u32,
        flushed: u32,
        reader_entered: u8,
        first_byte: u8,
        frames: u32,
        write_failed: u8,
        write_errno: Option<i32>,
    }
    impl Counters {
        fn read(p: &StageProgress) -> Self {
            // Sample flush before dequeue: one writer publishes dequeue first.
            // These cumulative fields are not an atomic scheduling trace.
            let flushed = p.writer_flushed.load(Ordering::Acquire);
            let dequeued = p.writer_dequeued.load(Ordering::Acquire);
            Self {
                enqueued: p.requests_enqueued.load(Ordering::Acquire),
                writer_entered: p.writer_entered.load(Ordering::Acquire),
                dequeued,
                flushed,
                reader_entered: p.reader_entered.load(Ordering::Acquire),
                first_byte: p.reader_first_byte.load(Ordering::Acquire),
                frames: p.reader_frames_completed.load(Ordering::Acquire),
                write_failed: p.write_failed.load(Ordering::Acquire),
                write_errno: match p.write_errno.load(Ordering::Acquire) {
                    NO_ERRNO => None,
                    n => i32::try_from(n).ok(),
                },
            }
        }
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Observation {
        present: bool,
        requests_open: bool,
        responses_open: bool,
        same_owner: Option<bool>,
        terminal: Option<bool>,
        released: Option<bool>,
        counters: Option<Counters>,
    }
    fn observe(
        worker: &mut Option<Worker>,
        weak: &Option<Weak<StageProgress>>,
        discarded: bool,
    ) -> Observation {
        match worker {
            Some(w) => {
                let open = w.requests().is_some();
                let terminal = if !open {
                    #[cfg(target_os = "macos")]
                    {
                        let end = w.owner.final_snapshot().cleanup;
                        Some(end.terminal == 1 && end.unresolved == 0)
                    }
                    #[cfg(target_os = "linux")]
                    {
                        Some(w.child.try_wait().ok().flatten().is_some())
                    }
                } else {
                    None
                };
                Observation {
                    present: true,
                    requests_open: open,
                    responses_open: w.responses().is_some(),
                    same_owner: weak
                        .as_ref()
                        .map(|old| old.ptr_eq(&Arc::downgrade(&w.progress))),
                    terminal,
                    released: None,
                    counters: Some(Counters::read(&w.progress)),
                }
            }
            None => Observation {
                present: false,
                requests_open: false,
                responses_open: false,
                same_owner: None,
                terminal: None,
                released: if discarded {
                    weak.as_ref().map(|old| old.upgrade().is_none())
                } else {
                    None
                },
                counters: None,
            },
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Expected {
        present: bool,
        closed: bool,
        enqueued: u32,
        frames: u32,
        released: Option<bool>,
    }
    struct Model {
        kind: ChildKind,
        state: Expected,
    }
    impl Model {
        fn new(kind: ChildKind) -> Self {
            Self {
                kind,
                state: Expected {
                    present: false,
                    closed: false,
                    enqueued: 0,
                    frames: 0,
                    released: None,
                },
            }
        }
        fn step(&mut self, step: Step, frame: &[u8]) -> Reply {
            match step {
                Step::Start => {
                    if self.kind == ChildKind::Missing {
                        Reply::Refused(Fault::Missing)
                    } else {
                        self.state.present = true;
                        Reply::Started
                    }
                }
                Step::ZeroBudget | Step::LargeBudget => Reply::Refused(Fault::Other),
                Step::Request(_) | Step::Reuse => {
                    if self.state.closed {
                        return Reply::Refused(Fault::Other);
                    }
                    self.state.enqueued += 1;
                    match self.kind {
                        ChildKind::Echo => {
                            self.state.frames += 1;
                            Reply::Echo {
                                length: frame.len(),
                                digest: crate::digest(frame),
                            }
                        }
                        ChildKind::Exited => {
                            self.state.closed = true;
                            Reply::Refused(Fault::Crashed)
                        }
                        ChildKind::Silent => {
                            self.state.closed = true;
                            Reply::Refused(Fault::Timeout)
                        }
                        ChildKind::Missing => unreachable!(),
                    }
                }
                Step::Malformed => {
                    self.state.closed = true;
                    Reply::Refused(Fault::Other)
                }
                Step::Close | Step::CloseAgain => {
                    self.state.closed = true;
                    Reply::Closed
                }
                Step::Discard => {
                    self.state.present = false;
                    self.state.released = (self.kind != ChildKind::Missing).then_some(true);
                    Reply::Discarded
                }
            }
        }
        fn accepts(&self, observed: &Observation) -> bool {
            let e = &self.state;
            if observed.present != e.present || observed.released != e.released {
                return false;
            }
            if !e.present {
                return !observed.requests_open
                    && !observed.responses_open
                    && observed.same_owner.is_none()
                    && observed.terminal.is_none()
                    && observed.counters.is_none();
            }
            let Some(c) = &observed.counters else {
                return false;
            };
            if observed.requests_open == e.closed
                || observed.responses_open == e.closed
                || observed.same_owner != Some(true)
                || observed.terminal != if e.closed { Some(true) } else { None }
            {
                return false;
            }
            c.enqueued == e.enqueued
                && c.frames == e.frames
                && c.writer_entered <= 1
                && c.reader_entered <= 1
                && c.flushed <= c.dequeued
                && c.dequeued <= c.enqueued
                && c.dequeued.saturating_sub(c.flushed) >= u32::from(c.write_failed)
                && c.first_byte == u8::from(c.frames > 0)
                && (c.frames == 0 || c.reader_entered == 1)
                && (!e.closed
                    || (c.writer_entered == 1 && c.reader_entered == 1 && c.dequeued == c.enqueued))
                && c.write_failed <= 1
                && if c.write_failed == 0 {
                    c.write_errno.is_none()
                } else {
                    e.closed
                        && matches!(self.kind, ChildKind::Exited | ChildKind::Silent)
                        && c.enqueued > c.frames
                        && c.write_errno == Some(32)
                }
        }
    }
    fn closed_counters_stable(
        expected: &Expected,
        observed: &Observation,
        first: &mut Option<Counters>,
    ) -> bool {
        if !expected.present || !expected.closed {
            return true;
        }
        let Some(current) = &observed.counters else {
            return false;
        };
        match first.as_ref() {
            Some(old) => current == old,
            None => {
                *first = Some(current.clone());
                true
            }
        }
    }

    fn classify(error: &anyhow::Error) -> Fault {
        match crate::error::classify(error) {
            crate::error::Failure::WorkerTimeout => Fault::Timeout,
            crate::error::Failure::WorkerCrashed => Fault::Crashed,
            _ => {
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
                {
                    Fault::Missing
                } else {
                    Fault::Other
                }
            }
        }
    }
    fn actual_reply(result: Result<Vec<u8>>) -> Reply {
        match result {
            Ok(bytes) => Reply::Echo {
                length: bytes.len(),
                digest: crate::digest(&bytes),
            },
            Err(error) => Reply::Refused(classify(&error)),
        }
    }
    fn source() -> String {
        crate::digest(
            format!(
                "worker-exchange-v1:{}:{}:{}:{}:{}",
                std::env::consts::OS,
                include_str!("worker.rs"),
                include_str!("worker/mac_lifetime.rs"),
                include_str!("worker/child_milestones.rs"),
                include_str!("error.rs")
            )
            .as_bytes(),
        )
    }
    fn validate(program: &Program) -> Result<()> {
        ensure!(
            program.version == 1 && program.source == source(),
            "worker_history_source"
        );
        ensure!(
            !program.cases.is_empty()
                && program.cases.len() <= MAX_CASES
                && program.cases.iter().all(|case| case.requests <= 3
                    && (case.kind != ChildKind::Missing
                        || (case.requests == 0 && !case.bad_budget && !case.malformed))
                    && (!case.bad_budget || case.kind == ChildKind::Echo)),
            "worker_history_bound"
        );
        Ok(())
    }
    fn frame(program: &Program, case: usize, index: u8, empty: bool) -> Vec<u8> {
        if empty && index == 0 {
            vec![]
        } else {
            format!("frame-{case}-{index}-{:x}", program.seed).into_bytes()
        }
    }
    fn steps(case: &Case) -> Vec<Step> {
        let mut steps = vec![Step::Start];
        if case.kind != ChildKind::Missing {
            if case.bad_budget {
                steps.extend([Step::ZeroBudget, Step::LargeBudget])
            }
            for n in 0..case.requests {
                steps.push(Step::Request(n));
            }
            if case.malformed {
                steps.push(Step::Malformed);
            }
            steps.extend([Step::Close, Step::CloseAgain, Step::Reuse]);
        }
        steps.push(Step::Discard);
        steps
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Cut {
        case: usize,
        step: Step,
        expected: Reply,
        actual: Reply,
        state: Expected,
        observation: Observation,
        state_match: bool,
        matched: bool,
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Run {
        cuts: Vec<Cut>,
        failed_at: Option<usize>,
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Pair {
        program: Program,
        control: Control,
        runs: [Run; 2],
    }

    fn run(program: &Program, control: Control) -> Result<Run> {
        validate(program)?;
        let directory = tempfile::tempdir()?;
        let mut run = Run {
            cuts: vec![],
            failed_at: None,
        };
        for (case_index, case) in program.cases.iter().enumerate() {
            let mut model = Model::new(case.kind);
            let mut worker: Option<Worker> = None;
            let mut weak = None;
            let mut failed = false;
            let mut closed_counters = None;
            for step in steps(case) {
                if failed && step != Step::Discard {
                    continue;
                }
                let payload = frame(
                    program,
                    case_index,
                    match step {
                        Step::Request(n) => n,
                        _ => 9,
                    },
                    case.empty_first,
                );
                let mut expected = model.step(step, &payload);
                if control == Control::TimeoutCompletes
                    && expected == Reply::Refused(Fault::Timeout)
                {
                    expected = Reply::Echo {
                        length: payload.len(),
                        digest: crate::digest(&payload),
                    };
                }
                let actual = match step {
                    Step::Start => {
                        let command = match case.kind {
                            ChildKind::Echo => Command::new("/bin/cat"),
                            ChildKind::Exited => Command::new("/usr/bin/false"),
                            ChildKind::Silent => {
                                let mut c = Command::new("/bin/sleep");
                                c.arg("60");
                                c
                            }
                            ChildKind::Missing => {
                                Command::new(directory.path().join("missing-worker"))
                            }
                        };
                        // The real supervisor clears environment and owns all pipes/threads.
                        match Worker::spawn(command, MAX_FRAME) {
                            Ok(value) => {
                                weak = Some(Arc::downgrade(&value.progress));
                                worker = Some(value);
                                Reply::Started
                            }
                            Err(error) => Reply::Refused(classify(&error)),
                        }
                    }
                    Step::ZeroBudget | Step::LargeBudget => actual_reply(
                        worker
                            .as_mut()
                            .context("fixture worker absent")?
                            .exchange_bounded(
                                &payload,
                                MAX_FRAME,
                                if step == Step::ZeroBudget {
                                    Duration::ZERO
                                } else {
                                    Duration::from_secs(4)
                                },
                            ),
                    ),
                    Step::Request(_) | Step::Reuse => {
                        let value = worker.as_mut().context("fixture worker absent")?;
                        actual_reply(if case.kind == ChildKind::Silent {
                            value.exchange_bounded(&payload, MAX_FRAME, Duration::from_millis(2))
                        } else {
                            value.exchange(&payload)
                        })
                    }
                    Step::Malformed => actual_reply(
                        worker
                            .as_mut()
                            .context("fixture worker absent")?
                            .exchange(b"invalid\nframe"),
                    ),
                    Step::Close | Step::CloseAgain => {
                        worker
                            .as_mut()
                            .context("fixture worker absent")?
                            .terminate();
                        Reply::Closed
                    }
                    Step::Discard => {
                        drop(worker.take());
                        Reply::Discarded
                    }
                };
                let observation = observe(&mut worker, &weak, step == Step::Discard);
                let stable =
                    closed_counters_stable(&model.state, &observation, &mut closed_counters);
                let state_match = model.accepts(&observation) && stable;
                let matched = state_match && expected == actual;
                run.cuts.push(Cut {
                    case: case_index,
                    step,
                    expected,
                    actual,
                    state: model.state.clone(),
                    observation,
                    state_match,
                    matched,
                });
                ensure!(run.cuts.len() <= MAX_CUTS, "worker_history_cut_bound");
                if !matched && run.failed_at.is_none() {
                    run.failed_at = Some(run.cuts.len() - 1);
                    failed = true;
                }
            }
            if run.failed_at.is_some() {
                break;
            }
        }
        Ok(run)
    }
    // Preserve every raw observation. Compare stable protocol facts and validate
    // every counter using explicit bounds, rather than inventing an OS schedule.
    fn same_semantics(a: &Run, b: &Run) -> bool {
        a.failed_at == b.failed_at
            && a.cuts.len() == b.cuts.len()
            && a.cuts.iter().zip(&b.cuts).all(|(a, b)| {
                a.case == b.case
                    && a.step == b.step
                    && a.expected == b.expected
                    && a.actual == b.actual
                    && a.state == b.state
                    && a.state_match == b.state_match
                    && a.matched == b.matched
                    && a.observation.present == b.observation.present
                    && a.observation.requests_open == b.observation.requests_open
                    && a.observation.responses_open == b.observation.responses_open
                    && a.observation.same_owner == b.observation.same_owner
                    && a.observation.terminal == b.observation.terminal
                    && a.observation.released == b.observation.released
                    && a.observation
                        .counters
                        .as_ref()
                        .map(|c| (c.enqueued, c.frames, c.first_byte))
                        == b.observation
                            .counters
                            .as_ref()
                            .map(|c| (c.enqueued, c.frames, c.first_byte))
            })
    }
    fn pair(program: &Program, control: Control) -> Result<Pair> {
        Ok(Pair {
            program: program.clone(),
            control,
            runs: [run(program, control)?, run(program, control)?],
        })
    }
    fn retain(pair: &Pair) -> Result<std::path::PathBuf> {
        use std::os::unix::fs::PermissionsExt;
        let root = Path::new("/tmp/dst-platform-host-loops/worker-exchange");
        std::fs::create_dir_all(root)?;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        let file = tempfile::Builder::new()
            .prefix("replay-")
            .suffix(".json")
            .tempfile_in(root)?;
        let bytes = serde_json::to_vec(pair)?;
        ensure!(bytes.len() <= MAX_BYTES as usize, "worker_history_bytes");
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))?;
        std::fs::write(file.path(), bytes)?;
        Ok(file.keep()?.1)
    }
    fn verify(program: &Program) -> Result<Pair> {
        let value = pair(program, Control::Correct)?;
        if value.runs.iter().any(|run| run.failed_at.is_some())
            || !same_semantics(&value.runs[0], &value.runs[1])
        {
            let path = retain(&value)?;
            anyhow::bail!("worker history divergence; replay {}", path.display());
        }
        Ok(value)
    }
    fn validate_saved(value: &Pair) -> Result<()> {
        validate(&value.program)?;
        for run in &value.runs {
            ensure!(
                !run.cuts.is_empty() && run.cuts.len() <= MAX_CUTS,
                "worker_history_saved_cuts"
            );
            let mut case_index = 0;
            let mut step_index = 0;
            let mut model = Model::new(value.program.cases[0].kind);
            let mut first_failed = None;
            let mut closed_counters = None;
            for (index, cut) in run.cuts.iter().enumerate() {
                ensure!(
                    case_index < value.program.cases.len() && cut.case == case_index,
                    "worker_history_saved_case"
                );
                let planned = steps(&value.program.cases[case_index]);
                let planned_step = if first_failed.is_some() {
                    Step::Discard
                } else {
                    *planned
                        .get(step_index)
                        .context("worker history saved step absent")?
                };
                ensure!(cut.step == planned_step, "worker_history_saved_order");
                let payload = frame(
                    &value.program,
                    cut.case,
                    match cut.step {
                        Step::Request(n) => n,
                        _ => 9,
                    },
                    value.program.cases[cut.case].empty_first,
                );
                let mut expected = model.step(cut.step, &payload);
                if value.control == Control::TimeoutCompletes
                    && expected == Reply::Refused(Fault::Timeout)
                {
                    expected = Reply::Echo {
                        length: payload.len(),
                        digest: crate::digest(&payload),
                    }
                }
                let stable =
                    closed_counters_stable(&model.state, &cut.observation, &mut closed_counters);
                let state_match = model.accepts(&cut.observation) && stable;
                let matched = state_match && expected == cut.actual;
                ensure!(
                    cut.expected == expected
                        && cut.state == model.state
                        && cut.state_match == state_match
                        && cut.matched == matched,
                    "worker_history_saved_observation"
                );
                if !matched && first_failed.is_none() {
                    first_failed = Some(index)
                }
                if cut.step == Step::Discard {
                    case_index += 1;
                    step_index = 0;
                    closed_counters = None;
                    if first_failed.is_some() {
                        ensure!(index + 1 == run.cuts.len(), "worker_history_after_failure");
                        break;
                    }
                    if case_index < value.program.cases.len() {
                        model = Model::new(value.program.cases[case_index].kind)
                    }
                } else {
                    step_index += 1
                }
            }
            ensure!(
                first_failed == run.failed_at
                    && run.cuts.last().is_some_and(|cut| cut.step == Step::Discard)
                    && (first_failed.is_some() || case_index == value.program.cases.len()),
                "worker_history_saved_failure"
            );
        }
        Ok(())
    }
    fn replay(path: &Path) -> Result<()> {
        use std::io::Read;
        ensure!(
            std::fs::symlink_metadata(path)?.file_type().is_file(),
            "worker_history_regular"
        );
        let mut bytes = vec![];
        std::fs::File::open(path)?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= MAX_BYTES as usize, "worker_history_bytes");
        let input: serde_json::Value = crate::json::decode_evidence(&bytes)
            .map_err(|_| anyhow::anyhow!("worker_history_decode"))?;
        let saved: Pair = serde_json::from_value(input.clone())
            .map_err(|_| anyhow::anyhow!("worker_history_shape"))?;
        ensure!(
            input == serde_json::to_value(&saved)?,
            "worker_history_shape"
        );
        validate_saved(&saved)?;
        let actual = pair(&saved.program, saved.control)?;
        ensure!(
            same_semantics(&saved.runs[0], &actual.runs[0])
                && same_semantics(&saved.runs[1], &actual.runs[1]),
            "worker_history_replay_changed"
        );
        Ok(())
    }
    fn generated(seed: u64) -> Program {
        let mut cases = vec![];
        for kind in [
            ChildKind::Echo,
            ChildKind::Missing,
            ChildKind::Silent,
            ChildKind::Exited,
        ] {
            cases.push(Case {
                kind,
                requests: if kind == ChildKind::Missing { 0 } else { 2 },
                bad_budget: kind == ChildKind::Echo,
                malformed: kind == ChildKind::Echo,
                empty_first: seed.is_multiple_of(2),
            });
        }
        let mut random = seed;
        for _ in 0..2 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            cases.push(Case {
                kind: ChildKind::Echo,
                requests: 1 + (random % 3) as u8,
                bad_budget: random & 2 != 0,
                malformed: random & 4 != 0,
                empty_first: random & 8 != 0,
            });
        }
        Program {
            version: 1,
            source: source(),
            seed,
            cases,
        }
    }

    #[test]
    fn real_worker_startup_watchdog_and_terminal_lifetimes_match_independent_histories()
    -> Result<()> {
        for seed in 0..8 {
            verify(&generated(seed))?;
        }
        Ok(())
    }
    #[test]
    fn timeout_cannot_complete_and_saved_disagreement_replays_twice() -> Result<()> {
        let mut program = generated(71);
        program.cases = vec![Case {
            kind: ChildKind::Silent,
            requests: 2,
            bad_budget: false,
            malformed: false,
            empty_first: false,
        }];
        let value = pair(&program, Control::TimeoutCompletes)?;
        ensure!(
            value.runs.iter().all(|run| run.failed_at == Some(1)
                && run.cuts[1].actual == Reply::Refused(Fault::Timeout)
                && run.cuts[1]
                    .observation
                    .counters
                    .as_ref()
                    .is_some_and(|c| c.enqueued == 1 && c.frames == 0)
                && run.cuts[1].observation.terminal == Some(true)),
            "worker_timeout_control_not_actual"
        );
        let path = retain(&value)?;
        replay(&path)?;
        Ok(())
    }
    #[test]
    fn saved_worker_history_requires_source_bounds_full_observations_and_both_runs() -> Result<()> {
        let mut program = generated(17);
        program.cases = vec![program.cases[2].clone()];
        let value = pair(&program, Control::TimeoutCompletes)?;
        let file = retain(&value)?;
        replay(&file)?;
        let bytes = std::fs::read(&file)?;
        let original: serde_json::Value = crate::json::decode_evidence(&bytes)?;
        for slot in 0..2 {
            let mut changed = original.clone();
            changed["runs"][slot]["cuts"][1]["observation"]["counters"]["enqueued"] =
                serde_json::json!(2);
            std::fs::write(&file, serde_json::to_vec(&changed)?)?;
            ensure!(replay(&file).is_err(), "worker_changed_counter_accepted");
        }
        let mut reordered = original.clone();
        reordered["runs"][0]["cuts"][0]["step"] = serde_json::json!({"Request":255});
        std::fs::write(&file, serde_json::to_vec(&reordered)?)?;
        ensure!(
            replay(&file).is_err(),
            "worker_saved_operation_order_accepted"
        );
        for field in ["source", "unknown"] {
            let mut changed = original.clone();
            changed["program"][field] = serde_json::json!("unknown");
            std::fs::write(&file, serde_json::to_vec(&changed)?)?;
            ensure!(
                replay(&file).is_err(),
                "worker_changed_source_or_shape_accepted"
            );
        }
        std::fs::write(&file, &bytes[..bytes.len() / 2])?;
        ensure!(replay(&file).is_err(), "worker_truncated_record_accepted");
        std::fs::write(&file, vec![b' '; MAX_BYTES as usize + 1])?;
        ensure!(replay(&file).is_err(), "worker_oversize_record_accepted");
        for raw in [
            b"PRIVATE_REPLAY_VALUE".as_slice(),
            br#"{"PRIVATE_REPLAY_VALUE":null}"#,
        ] {
            std::fs::write(&file, raw)?;
            let error = replay(&file)
                .err()
                .context("malformed replay must refuse")?;
            ensure!(
                !error.to_string().contains("PRIVATE_REPLAY_VALUE")
                    && error.downcast_ref::<serde_json::Error>().is_none(),
                "worker_replay_parser_leaked_input"
            );
        }
        std::fs::write(&file, bytes)?;
        replay(&file)?;
        Ok(())
    }
    #[test]
    fn joined_terminal_counters_cannot_change_during_closed_reuse_or_replay() -> Result<()> {
        let mut program = generated(17);
        program.cases = vec![program.cases[2].clone()];
        let value = verify(&program)?;
        let file = retain(&value)?;
        replay(&file)?;
        let bytes = std::fs::read(&file)?;
        let index = value.runs[0]
            .cuts
            .iter()
            .position(|cut| cut.step == Step::Request(1))
            .context("closed reuse cut absent")?;
        let mut changed: serde_json::Value = crate::json::decode_evidence(&bytes)?;
        let counters = changed["runs"][0]["cuts"][index]["observation"]["counters"]
            .as_object_mut()
            .unwrap();
        if counters["write_failed"] == serde_json::json!(1) {
            counters.insert("write_failed".into(), serde_json::json!(0));
            counters.insert("write_errno".into(), serde_json::Value::Null);
        } else {
            let old = counters["flushed"].as_u64().context("flush count absent")?;
            counters.insert("flushed".into(), serde_json::json!(1 - old));
        }
        let tampered: Pair = serde_json::from_value(changed.clone())?;
        let model = Model {
            kind: ChildKind::Silent,
            state: value.runs[0].cuts[index].state.clone(),
        };
        ensure!(
            model.accepts(&tampered.runs[0].cuts[index].observation),
            "counter mutation must remain inside ordinary race bounds"
        );
        std::fs::write(&file, serde_json::to_vec(&changed)?)?;
        ensure!(replay(&file).is_err(), "quiescent_terminal_counter_changed");
        std::fs::write(&file, bytes)?;
        replay(&file)?;
        Ok(())
    }
    #[test]
    fn maximum_worker_history_keeps_every_lifetime_and_cleanup() -> Result<()> {
        let mut program = generated(0);
        while program.cases.len() < MAX_CASES {
            program.cases.push(program.cases[0].clone())
        }
        let value = verify(&program)?;
        ensure!(
            value.runs.iter().all(|run| run
                .cuts
                .iter()
                .filter(|cut| cut.step == Step::Discard)
                .count()
                == MAX_CASES),
            "worker_history_lifetime_truncated"
        );
        let path = retain(&value)?;
        replay(&path)?;
        Ok(())
    }
    fn path_is(expr: &syn::Expr, expected: &[&str]) -> bool {
        matches!(expr,syn::Expr::Path(value) if value.qself.is_none() && value.path.leading_colon.is_none()
            && value.path.segments.len()==expected.len() && value.path.segments.iter().zip(expected).all(|(segment,name)|segment.ident==*name && segment.arguments.is_empty()))
    }
    fn worker_impl(value: &syn::ItemImpl) -> bool {
        matches!(&*value.self_ty,syn::Type::Path(value) if value.qself.is_none() && value.path.is_ident("Worker"))
    }
    fn default_budget_is_pinned(file: &syn::File) -> bool {
        let methods: Vec<_> = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Impl(value) if worker_impl(value) => Some(&value.items),
                _ => None,
            })
            .flatten()
            .filter_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "exchange" => Some(method),
                _ => None,
            })
            .collect();
        if methods.len() != 1 || methods[0].block.stmts.len() != 1 {
            return false;
        }
        let syn::Stmt::Expr(syn::Expr::MethodCall(call), None) = &methods[0].block.stmts[0] else {
            return false;
        };
        if call.method != "exchange_bounded"
            || call.args.len() != 3
            || call.turbofish.is_some()
            || !path_is(&call.receiver, &["self"])
            || !path_is(&call.args[0], &["input"])
            || !path_is(&call.args[1], &["MAX_FRAME"])
        {
            return false;
        }
        let syn::Expr::Call(timeout) = &call.args[2] else {
            return false;
        };
        path_is(&timeout.func, &["Duration", "from_secs"])
            && timeout.args.len() == 1
            && matches!(&timeout.args[0],syn::Expr::Lit(value) if matches!(&value.lit,syn::Lit::Int(value) if value.base10_parse::<u64>().ok()==Some(3)))
    }
    #[test]
    fn actual_default_worker_bound_stays_three_seconds_and_uses_bounded_exchange() -> Result<()> {
        let source = include_str!("worker.rs");
        let actual: syn::File = syn::parse_file(source)?;
        ensure!(
            default_budget_is_pinned(&actual),
            "worker_default_bound_changed"
        );
        let blocks: [syn::Block; 3] = [
            syn::parse_quote!({ self.exchange_bounded(input, MAX_FRAME, Duration::from_secs(4)) }),
            syn::parse_quote!({ self.exchange_frame(input, MAX_FRAME, Duration::from_secs(3)) }),
            syn::parse_quote!({
                self.exchange_bounded(input, PROPERTY_MAX_FRAME, Duration::from_secs(3))
            }),
        ];
        for block in blocks {
            let mut file: syn::File = syn::parse_file(source)?;
            let mut replaced = 0;
            for item in &mut file.items {
                if let syn::Item::Impl(value) = item
                    && worker_impl(value)
                {
                    for item in &mut value.items {
                        if let syn::ImplItem::Fn(method) = item
                            && method.sig.ident == "exchange"
                        {
                            method.block = block.clone();
                            replaced += 1;
                        }
                    }
                }
            }
            ensure!(
                replaced == 1 && !default_budget_is_pinned(&file),
                "worker_default_bound_mutation_escaped"
            );
        }
        Ok(())
    }
    #[test]
    fn external_worker_history_replays_twice_when_supplied() -> Result<()> {
        let Some(path) = std::env::var_os("DAY2_WORKER_HISTORY_REPLAY") else {
            return Ok(());
        };
        replay(Path::new(&path))
    }
}
