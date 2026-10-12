//! Temporary macOS diagnostic ownership, not a new worker recipe or authority.
use super::{
    ExitEvidence, StageProgress, child_milestones, exit_evidence, read_frame, write_frame,
};
use anyhow::{Context, Result, anyhow, ensure};
use std::io::{self, Write};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

pub(super) const UNRESOLVED: &[u8] = b"DAY2_DIAGNOSTIC_CLEANUP_UNRESOLVED\n";

#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub(super) struct Cleanup {
    pub kill_failed: u8,
    pub kill_errno: Option<i32>,
    pub wait_failed: u8,
    pub wait_errno: Option<i32>,
    pub terminal: u8,
    pub unresolved: u8,
}

impl Cleanup {
    fn after_attempts(
        &mut self,
        kill: io::Result<()>,
        wait: io::Result<ExitStatus>,
        terminal: &mut Option<ExitStatus>,
    ) -> Disposition {
        if let Err(error) = kill {
            self.kill_failed = 1;
            self.kill_errno = error.raw_os_error();
        }
        match wait {
            Ok(status) => *terminal = Some(status),
            Err(error) => {
                self.wait_failed = 1;
                self.wait_errno = error.raw_os_error();
            }
        }
        cleanup_disposition(terminal.is_some())
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub(super) struct Final {
    pub stream: child_milestones::Snapshot,
    pub cleanup: Cleanup,
}

impl std::fmt::Display for Final {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "stream[{}] close[k:{} ke:{:?} w:{} we:{:?} terminal:{} unresolved:{}]",
            self.stream,
            self.cleanup.kill_failed,
            self.cleanup.kill_errno,
            self.cleanup.wait_failed,
            self.cleanup.wait_errno,
            self.cleanup.terminal,
            self.cleanup.unresolved
        )
    }
}

pub(super) struct Owner {
    child: Option<Child>,
    terminal_status: Option<ExitStatus>,
    // Child::wait takes/drops its own stdin even when wait fails. Retain any
    // pipe not yet extracted by a partial constructor before calling it.
    pending_stdin: Option<ChildStdin>,
    stdin: Option<Arc<Mutex<ChildStdin>>>,
    stdout: Option<Arc<Mutex<ChildStdout>>>,
    stderr: Option<Arc<Mutex<ChildStderr>>>,
    handoff: Option<SyncSender<Arc<Mutex<ChildStderr>>>>,
    pub requests: Option<SyncSender<Vec<u8>>>,
    pub responses: Option<Receiver<Result<Vec<u8>>>>,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
    collector: Option<JoinHandle<()>>,
    progress: Arc<StageProgress>,
    cleanup: Cleanup,
    closed: bool,
    launch_attempted: bool,
    #[cfg(test)]
    setup_fault: Option<SetupFault>,
    #[cfg(test)]
    cleanup_attempts: u8,
}

impl Owner {
    /// This owner and its receiving thread exist before any Child is launched.
    pub(super) fn new(progress: Arc<StageProgress>) -> Result<Self> {
        Self::new_with_collector(progress, |receive, observed| {
            thread::Builder::new()
                .name("day2-worker-stage".into())
                .spawn(move || {
                    if let Ok(retained) = receive.recv() {
                        let mut input = retained
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        observed.child.entered();
                        child_milestones::drain(&mut *input, &observed.child);
                    }
                })
        })
    }

    // Private native setup seam; no app-supplied callback or alternate worker.
    fn new_with_collector(
        progress: Arc<StageProgress>,
        start: impl FnOnce(
            Receiver<Arc<Mutex<ChildStderr>>>,
            Arc<StageProgress>,
        ) -> io::Result<JoinHandle<()>>,
    ) -> Result<Self> {
        let (handoff, receive) = mpsc::sync_channel::<Arc<Mutex<ChildStderr>>>(1);
        let observed = Arc::clone(&progress);
        let collector = start(receive, observed)
            .context("diagnostic startup: create worker stage collector")?;
        Ok(Self {
            child: None,
            terminal_status: None,
            pending_stdin: None,
            stdin: None,
            stdout: None,
            stderr: None,
            handoff: Some(handoff),
            requests: None,
            responses: None,
            reader: None,
            writer: None,
            collector: Some(collector),
            progress,
            cleanup: Cleanup::default(),
            closed: false,
            launch_attempted: false,
            #[cfg(test)]
            setup_fault: None,
            #[cfg(test)]
            cleanup_attempts: 0,
        })
    }

    pub(super) fn launch(&mut self, mut command: Command) -> Result<()> {
        ensure!(
            !self.closed && !self.launch_attempted,
            "diagnostic startup: owner already used"
        );
        self.launch_attempted = true;
        self.child = Some(
            command
                .env_clear()
                .env("LANG", "C")
                .env("LC_ALL", "C")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .context("spawn isolated Roc worker")?,
        );
        #[cfg(test)]
        self.setup_checkpoint(SetupFault::AfterSpawn)?;
        let child = self
            .child
            .as_mut()
            .context("diagnostic startup: missing worker owner")?;
        self.stdin = Some(retain_pipe(child.stdin.take(), "worker stdin")?);
        #[cfg(not(test))]
        {
            self.stdout = Some(retain_pipe(child.stdout.take(), "worker stdout")?);
        }
        #[cfg(test)]
        {
            // A missing-pipe refusal keeps the other actual pipe in Child.
            let stdout = if self.setup_fault == Some(SetupFault::MissingStdout) {
                None
            } else {
                child.stdout.take()
            };
            self.stdout = Some(retain_pipe(stdout, "worker stdout")?);
        }
        self.stderr = Some(retain_pipe(
            child.stderr.take(),
            "diagnostic startup: worker stderr",
        )?);
        #[cfg(test)]
        self.setup_checkpoint(SetupFault::BeforeHandoff)?;
        // The owner retains the same descriptor before handing a clone to the thread.
        // Neither SendError nor a collector return/unwind closes the last read end.
        offer_retained(
            self.stderr
                .as_ref()
                .context("diagnostic startup: retained stderr")?,
            self.handoff
                .take()
                .context("diagnostic startup: stage handoff missing")?,
        )?;

        let (sender, responses) = mpsc::sync_channel(1);
        let (requests, incoming) = mpsc::sync_channel::<Vec<u8>>(1);
        self.requests = Some(requests);
        self.responses = Some(responses);
        let retained_input = Arc::clone(self.stdin.as_ref().context("worker stdin owner")?);
        let write_progress = Arc::clone(&self.progress);
        #[cfg(test)]
        self.setup_checkpoint(SetupFault::WriterSetup)
            .context("start worker input thread")?;
        self.writer = Some(
            thread::Builder::new()
                .name("day2-worker-input".into())
                .spawn(move || {
                    let mut stdin = retained_input
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    write_progress.writer_entered.store(1, Ordering::Release);
                    while let Ok(frame) = incoming.recv() {
                        if write_frame(&mut *stdin, &frame, &write_progress).is_err() {
                            break;
                        }
                    }
                })
                .context("start worker input thread")?,
        );
        let retained_output = Arc::clone(self.stdout.as_ref().context("worker stdout owner")?);
        let read_progress = Arc::clone(&self.progress);
        #[cfg(test)]
        self.setup_checkpoint(SetupFault::ReaderSetup)
            .context("start worker output thread")?;
        self.reader = Some(
            thread::Builder::new()
                .name("day2-worker-output".into())
                .spawn(move || {
                    let mut stdout = retained_output
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    read_progress.reader_entered.store(1, Ordering::Release);
                    let mut reader = std::io::BufReader::new(&mut *stdout);
                    loop {
                        let result = read_frame(&mut reader, &read_progress);
                        let failed = result.is_err();
                        if sender.send(result).is_err() || failed {
                            break;
                        }
                    }
                })
                .context("start worker output thread")?,
        );
        Ok(())
    }

    #[cfg(test)]
    fn setup_checkpoint(&self, point: SetupFault) -> io::Result<()> {
        if self.setup_fault == Some(point) {
            Err(io::Error::other("injected diagnostic setup fault"))
        } else {
            Ok(())
        }
    }

    pub(super) fn observe_exit(&mut self) -> ExitEvidence {
        let result = if let Some(child) = self.child.as_mut() {
            child.try_wait()
        } else {
            Ok(self.terminal_status)
        };
        if let Ok(Some(status)) = &result {
            self.terminal_status = Some(*status);
        }
        exit_evidence(result)
    }

    pub(super) fn close(&mut self) {
        if self.closed {
            return;
        }
        self.requests.take();
        self.responses.take();
        self.retain_wait_stdin();
        if let Some(child) = self.child.as_mut() {
            #[cfg(test)]
            {
                self.cleanup_attempts += 1;
            }
            // These actual OS calls occur once, in order, before interpreting either result.
            let kill = child.kill();
            let wait = child.wait();
            if self
                .cleanup
                .after_attempts(kill, wait, &mut self.terminal_status)
                == Disposition::Unresolved
            {
                self.quarantine();
            }
            self.cleanup.terminal = 1;
        }
        // Child absence here means no spawn succeeded, or its actual exit was observed.
        self.handoff.take();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
        if let Some(collector) = self.collector.take()
            && collector.join().is_err()
        {
            self.progress.child.unwound();
        }
        self.child.take();
        self.pending_stdin.take();
        self.stdin.take();
        self.stdout.take();
        self.stderr.take();
        self.closed = true;
    }

    fn retain_wait_stdin(&mut self) {
        if self.pending_stdin.is_none()
            && let Some(child) = self.child.as_mut()
        {
            self.pending_stdin = child.stdin.take();
        }
    }

    pub(super) fn final_snapshot(&self) -> Final {
        Final {
            stream: self.progress.child.snapshot(),
            cleanup: self.cleanup,
        }
    }

    fn quarantine(&mut self) -> ! {
        self.cleanup.unresolved = 1;
        // Best effort only. The outer guardian must fail even if this is blocked/missing.
        let _ = std::io::stderr().write_all(UNRESOLVED);
        let retained_owner: &mut Self = self;
        loop {
            std::hint::black_box(&*retained_owner);
            // No cleanup retry, return, descriptor release or result on this branch.
            // std/OS parking/output can initialize/allocate/abort; no hard bound.
            thread::park();
        }
    }
}

fn retain_pipe<T>(pipe: Option<T>, label: &'static str) -> Result<Arc<Mutex<T>>> {
    Ok(Arc::new(Mutex::new(pipe.context(label)?)))
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SetupFault {
    AfterSpawn,
    MissingStdout,
    BeforeHandoff,
    WriterSetup,
    ReaderSetup,
}

fn offer_retained<T>(owner: &Arc<Mutex<T>>, handoff: SyncSender<Arc<Mutex<T>>>) -> Result<()> {
    handoff
        .send(Arc::clone(owner))
        .map_err(|_| anyhow!("diagnostic startup: stage handoff failed"))
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Disposition {
    Terminal,
    Unresolved,
}

fn cleanup_disposition(observed_terminal: bool) -> Disposition {
    if observed_terminal {
        Disposition::Terminal
    } else {
        Disposition::Unresolved
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Cleanup, Disposition, Owner, SetupFault, UNRESOLVED, cleanup_disposition, offer_retained,
        retain_pipe,
    };
    use crate::worker::{StageProgress, child_milestones};
    use std::io::{self, Read};
    use std::os::unix::process::ExitStatusExt;
    use std::sync::{Arc, Mutex};

    #[test]
    fn collector_setup_refusal_happens_before_a_child_owner_exists() {
        let progress = Arc::new(StageProgress::new());
        let observed = Arc::clone(&progress);
        let result = Owner::new_with_collector(progress, |receive, _| {
            drop(receive);
            Err(io::Error::from_raw_os_error(11))
        });
        let error = result.err().expect("collector setup must refuse");
        assert!(
            error
                .to_string()
                .contains("diagnostic startup: create worker stage collector")
        );
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(11)
        );
        assert_eq!(Arc::strong_count(&observed), 1);
        assert_eq!(observed.child.snapshot().entered, 0);
    }

    #[test]
    fn real_spawn_refusal_cancels_and_joins_the_preexisting_collector() {
        let mut owner = Owner::new(Arc::new(StageProgress::new())).unwrap();
        let error = owner
            .launch(std::process::Command::new(
                "/DAY2_DIAGNOSTIC_MISSING_EXECUTABLE",
            ))
            .unwrap_err();
        assert!(error.to_string().contains("spawn isolated Roc worker"));
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::NotFound
        );
        assert!(owner.child.is_none());
        assert!(owner.collector.is_some());
        owner.close();
        assert!(owner.closed && owner.collector.is_none() && owner.handoff.is_none());
        assert_eq!(owner.cleanup_attempts, 0);
    }

    #[test]
    fn missing_pipe_refuses_without_releasing_an_already_retained_descriptor() {
        let retained = retain_pipe(Some(io::Cursor::new(b"PRIVATE_PIPE")), "worker stdin").unwrap();
        let error = retain_pipe::<io::Cursor<&[u8]>>(None, "worker stdout").unwrap_err();
        assert_eq!(error.to_string(), "worker stdout");
        assert_eq!(Arc::strong_count(&retained), 1);
        assert!(Arc::try_unwrap(retained).is_ok());
    }

    #[test]
    fn partial_construction_faults_reap_the_exact_new_child_and_join_every_created_thread() {
        for point in [
            SetupFault::AfterSpawn,
            SetupFault::MissingStdout,
            SetupFault::BeforeHandoff,
            SetupFault::WriterSetup,
            SetupFault::ReaderSetup,
        ] {
            let mut owner = Owner::new(Arc::new(StageProgress::new())).unwrap();
            owner.setup_fault = Some(point);
            let error = owner
                .launch(std::process::Command::new("/bin/cat"))
                .unwrap_err();
            if point == SetupFault::MissingStdout {
                assert_eq!(error.to_string(), "worker stdout");
                assert!(owner.stdin.is_some() && owner.stdout.is_none() && owner.stderr.is_none());
                assert!(owner.child.as_ref().unwrap().stdout.is_some());
                assert!(owner.child.as_ref().unwrap().stderr.is_some());
            } else {
                assert!(error.downcast_ref::<io::Error>().is_some());
            }
            assert!(owner.child.is_some());
            assert!(owner.collector.is_some());
            assert_eq!(owner.writer.is_some(), point == SetupFault::ReaderSetup);
            assert!(owner.reader.is_none());
            if point == SetupFault::AfterSpawn {
                assert!(owner.child.as_ref().unwrap().stdin.is_some());
                owner.retain_wait_stdin();
                assert!(owner.child.as_ref().unwrap().stdin.is_none());
                assert!(owner.pending_stdin.is_some());
                // Re-entry must not overwrite/drop the raw retained pipe.
                owner.retain_wait_stdin();
                assert!(owner.pending_stdin.is_some());
            }
            if point != SetupFault::AfterSpawn && point != SetupFault::MissingStdout {
                assert!(owner.stdin.is_some() && owner.stdout.is_some() && owner.stderr.is_some());
            }
            owner.close();
            assert!(owner.closed && owner.terminal_status.is_some());
            assert_eq!(owner.cleanup.terminal, 1);
            assert_eq!(owner.cleanup_attempts, 1);
            assert!(
                owner.child.is_none()
                    && owner.stdin.is_none()
                    && owner.stdout.is_none()
                    && owner.stderr.is_none()
            );
            assert!(owner.pending_stdin.is_none());
            assert!(owner.reader.is_none() && owner.writer.is_none() && owner.collector.is_none());
            assert!(
                owner.requests.is_none() && owner.responses.is_none() && owner.handoff.is_none()
            );
            let first = serde_json::to_value(owner.final_snapshot()).unwrap();
            owner.close();
            assert_eq!(owner.cleanup_attempts, 1);
            assert_eq!(first, serde_json::to_value(owner.final_snapshot()).unwrap());
        }
    }

    #[test]
    fn successful_original_frames_keep_the_same_child_alive_until_owner_close() {
        let progress = Arc::new(StageProgress::new());
        let mut owner = Owner::new(Arc::clone(&progress)).unwrap();
        owner
            .launch(std::process::Command::new("/bin/cat"))
            .unwrap();
        let child = owner.child.as_ref().unwrap().id();
        let mut worker = crate::worker::Worker { owner, progress };
        for frame in [
            b"first original frame".as_slice(),
            b"second original frame".as_slice(),
        ] {
            assert_eq!(worker.exchange(frame).unwrap(), frame);
            assert_eq!(worker.owner.child.as_ref().unwrap().id(), child);
            assert!(
                worker
                    .owner
                    .child
                    .as_mut()
                    .unwrap()
                    .try_wait()
                    .unwrap()
                    .is_none()
            );
            assert!(!worker.owner.closed);
            assert!(worker.owner.requests.is_some() && worker.owner.responses.is_some());
            assert_eq!(worker.owner.cleanup_attempts, 0);
        }
        // This echo control emits no diagnostic markers. Their absence cannot
        // replace either successful original stdout result with a failure.
        assert_eq!(worker.progress.child.snapshot().prefix, 0);
        worker.terminate();
        assert!(worker.owner.closed && worker.owner.terminal_status.is_some());
        assert_eq!(worker.owner.cleanup_attempts, 1);
        worker.terminate();
        assert_eq!(worker.owner.cleanup_attempts, 1);
    }

    #[test]
    fn failed_one_shot_handoff_keeps_the_exact_parent_descriptor_owner() {
        let owner = Arc::new(Mutex::new(io::Cursor::new(b"PRIVATE_PIPE")));
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        drop(receive);
        let error = offer_retained(&owner, send).unwrap_err();
        assert_eq!(Arc::strong_count(&owner), 1);
        assert!(!error.to_string().contains("PRIVATE"));
        assert!(Arc::try_unwrap(owner).is_ok());
    }

    #[test]
    fn no_child_cancellation_closes_the_one_collector_and_is_idempotent() {
        let mut owner = Owner::new(Arc::new(StageProgress::new())).unwrap();
        assert!(owner.child.is_none());
        owner.close();
        assert!(owner.closed);
        assert!(owner.collector.is_none());
        assert!(owner.handoff.is_none());
        assert_eq!(owner.cleanup.terminal, 0);
        let first = serde_json::to_value(owner.final_snapshot()).unwrap();
        owner.close();
        assert_eq!(first, serde_json::to_value(owner.final_snapshot()).unwrap());
        let error = owner
            .launch(std::process::Command::new(
                "/DAY2_DIAGNOSTIC_DO_NOT_EXECUTE",
            ))
            .unwrap_err();
        assert!(error.to_string().contains("owner already used"));
        assert!(!owner.launch_attempted);
        assert!(owner.child.is_none());
    }

    #[test]
    fn only_observed_terminal_status_permits_release_not_kill_or_wait_fault() {
        assert_eq!(cleanup_disposition(false), Disposition::Unresolved);
        assert_eq!(cleanup_disposition(true), Disposition::Terminal);
        assert_eq!(UNRESOLVED, b"DAY2_DIAGNOSTIC_CLEANUP_UNRESOLVED\n");
        assert_eq!(UNRESOLVED.len(), 35);
        let mut cleanup = Cleanup::default();
        let mut terminal = None;
        let disposition = cleanup.after_attempts(
            Err(io::Error::from_raw_os_error(3)),
            Ok(std::process::ExitStatus::from_raw(0)),
            &mut terminal,
        );
        assert_eq!(disposition, Disposition::Terminal);
        assert!(terminal.is_some());
        assert_eq!(
            (cleanup.kill_failed, cleanup.kill_errno, cleanup.wait_failed),
            (1, Some(3), 0)
        );
        let mut cleanup = Cleanup::default();
        let mut unknown = None;
        assert_eq!(
            cleanup.after_attempts(Ok(()), Err(io::Error::from_raw_os_error(10)), &mut unknown),
            Disposition::Unresolved
        );
        assert!(unknown.is_none());
        assert_eq!(
            (cleanup.wait_failed, cleanup.wait_errno, cleanup.terminal),
            (1, Some(10), 0)
        );
        assert_eq!(
            cleanup.after_attempts(Ok(()), Err(io::Error::from_raw_os_error(10)), &mut terminal),
            Disposition::Terminal
        );
    }

    struct FaultRead {
        panic: bool,
    }

    impl Read for FaultRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            if self.panic {
                panic!("PRIVATE_DECODER_PANIC");
            }
            Err(io::Error::other("PRIVATE_READER_FAULT"))
        }
    }

    #[test]
    fn retained_owner_survives_reader_fault_and_collector_unwind() {
        for panic in [false, true] {
            let retained = Arc::new(Mutex::new(FaultRead { panic }));
            let received = Arc::clone(&retained);
            let progress = Arc::new(child_milestones::Progress::new());
            let observed = Arc::clone(&progress);
            let collector = std::thread::spawn(move || {
                let mut read = received
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                child_milestones::drain(&mut *read, &observed);
            });
            let joined = collector.join();
            assert_eq!(joined.is_err(), panic);
            assert_eq!(Arc::strong_count(&retained), 1);
            if joined.is_err() {
                progress.unwound();
            }
            let state = progress.snapshot();
            assert_eq!(state.eof, 0);
            assert_eq!(state.unwound, u8::from(panic));
            assert_eq!(state.read_failed, u8::from(!panic));
            assert!(!serde_json::to_string(&state).unwrap().contains("PRIVATE"));
            // The same parent owner remains present after either thread outcome.
            assert!(Arc::try_unwrap(retained).is_ok());
        }
    }

    // Temporary fixture; this deliberately cannot produce a native test pass.
    #[test]
    #[ignore = "Requires the separately reviewed external unresolved-owner guardian"]
    fn parked_owner_requires_external_guardian_closure() {
        let mut owner = Owner::new(Arc::new(StageProgress::new())).unwrap();
        owner
            .launch(std::process::Command::new("/bin/cat"))
            .unwrap();
        assert!(!owner.closed && owner.terminal_status.is_none());
        assert!(owner.child.is_some());
        assert!(owner.stdin.is_some() && owner.stdout.is_some() && owner.stderr.is_some());
        assert!(owner.writer.is_some() && owner.reader.is_some() && owner.collector.is_some());
        assert!(owner.requests.is_some() && owner.responses.is_some());
        assert!(owner.child.as_mut().unwrap().try_wait().unwrap().is_none());
        println!(
            "\nDAY2_DIAGNOSTIC_PARK_CHILD={}",
            owner.child.as_ref().unwrap().id()
        );
        owner.quarantine();
    }
}
