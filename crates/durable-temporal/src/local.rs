//! Isolated real-server test fixture. This is not a production deployment adapter.

use crate::TemporalAdapter;
use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

pub const CLI_VERSION: &str = "1.6.1";
pub const LOCAL_NAMESPACE: &str = "day2-local-verification";
pub const LOCAL_TASK_QUEUE: &str = "day2-release-v1";
const STARTUP_LOG_LIMIT: usize = 4096;

#[derive(Debug, Clone, Copy)]
enum StartupPhase {
    Initial,
    Restart,
}

/// Only fixed categories from a bounded log tail leave this private fixture.
/// Raw server output can contain workflow data and is never embedded in errors.
#[derive(Debug, Default)]
struct StartupLogEvidence {
    bytes: usize,
    prefix_omitted: bool,
    log_reset: bool,
    read_limit_reached: bool,
    read_failed: bool,
    read_errno: Option<i32>,
    address_in_use: bool,
    permission_denied: bool,
    database_locked: bool,
    resource_exhausted: bool,
}

impl StartupLogEvidence {
    fn from_bytes(bytes: &[u8], prefix_omitted: bool) -> Self {
        let bounded = &bytes[..bytes.len().min(STARTUP_LOG_LIMIT)];
        let text = String::from_utf8_lossy(bounded).to_ascii_lowercase();
        Self {
            bytes: bounded.len(),
            prefix_omitted,
            read_limit_reached: bounded.len() == STARTUP_LOG_LIMIT,
            address_in_use: text.contains("address already in use"),
            permission_denied: text.contains("permission denied"),
            database_locked: text.contains("database is locked")
                || text.contains("database is busy"),
            resource_exhausted: text.contains("resource temporarily unavailable")
                || text.contains("cannot allocate memory")
                || text.contains("too many open files")
                || text.contains("no space left on device"),
            ..Self::default()
        }
    }

    fn capture(path: &Path, launch_offset: u64) -> Self {
        let read = || -> std::io::Result<Self> {
            let mut file = fs::File::open(path)?;
            let end = file.seek(SeekFrom::End(0))?;
            if end < launch_offset {
                return Ok(Self {
                    log_reset: true,
                    ..Self::default()
                });
            }
            let start = launch_offset.max(end.saturating_sub(STARTUP_LOG_LIMIT as u64));
            file.seek(SeekFrom::Start(start))?;
            let mut bytes = vec![0; (end - start) as usize];
            file.read_exact(&mut bytes)?;
            Ok(Self::from_bytes(&bytes, start > launch_offset))
        };
        read().unwrap_or_else(|error| Self {
            read_failed: true,
            read_errno: error.raw_os_error(),
            ..Self::default()
        })
    }
}

#[derive(Debug)]
struct StartupFailure {
    phase: StartupPhase,
    code: Option<i32>,
    signal: Option<i32>,
    readiness_timed_out: bool,
    log: StartupLogEvidence,
}

impl StartupFailure {
    fn capture(
        phase: StartupPhase,
        status: Option<ExitStatus>,
        path: &Path,
        launch_offset: u64,
    ) -> Self {
        #[cfg(unix)]
        let signal = {
            use std::os::unix::process::ExitStatusExt;
            status.as_ref().and_then(|status| status.signal())
        };
        #[cfg(not(unix))]
        let signal = None;
        Self {
            phase,
            code: status.as_ref().and_then(|status| status.code()),
            signal,
            readiness_timed_out: status.is_none(),
            log: StartupLogEvidence::capture(path, launch_offset),
        }
    }
}

impl std::fmt::Display for StartupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Temporal startup failed [phase={:?} code={:?} signal={:?} readiness_timed_out={} log_bytes={} log_prefix_omitted={} log_reset={} log_read_limit_reached={} log_read_failed={} log_read_errno={:?} address_in_use={} permission_denied={} database_locked={} resource_exhausted={}]",
            self.phase,
            self.code,
            self.signal,
            self.readiness_timed_out,
            self.log.bytes,
            self.log.prefix_omitted,
            self.log.log_reset,
            self.log.read_limit_reached,
            self.log.read_failed,
            self.log.read_errno,
            self.log.address_in_use,
            self.log.permission_denied,
            self.log.database_locked,
            self.log.resource_exhausted,
        )
    }
}

impl std::error::Error for StartupFailure {}

pub struct LocalServer {
    cli: PathBuf,
    directory: PathBuf,
    address: SocketAddr,
    namespace: String,
    child: Option<Child>,
}

impl LocalServer {
    pub async fn start(directory: &Path) -> Result<Self> {
        fs::create_dir_all(directory)?;
        let directory = directory.canonicalize()?;
        ensure!(
            !directory.join("temporal.sqlite").exists(),
            "new local fixture requires a fresh Temporal database; use restart on its existing owner"
        );
        let cli = std::env::var_os("DAY2_TEMPORAL_CLI")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("temporal"));
        let version = Command::new(&cli)
            .arg("--version")
            .output()
            .context("Temporal CLI is required for real persistence verification")?;
        ensure!(
            version.status.success(),
            "Temporal CLI version check failed"
        );
        ensure!(
            String::from_utf8_lossy(&version.stdout)
                .starts_with(&format!("temporal version {CLI_VERSION} ")),
            "Temporal CLI version must be pinned to {CLI_VERSION}"
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        drop(listener);
        let namespace = format!(
            "{LOCAL_NAMESPACE}-{}-{}",
            std::process::id(),
            address.port()
        );
        let mut server = Self {
            cli,
            directory,
            address,
            namespace,
            child: None,
        };
        server.launch(StartupPhase::Initial).await?;
        Ok(server)
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn database(&self) -> PathBuf {
        self.directory.join("temporal.sqlite")
    }

    pub fn log(&self) -> PathBuf {
        self.directory.join("temporal.log")
    }

    pub async fn adapter(&self) -> Result<TemporalAdapter> {
        TemporalAdapter::connect_local(self.address, &self.namespace, LOCAL_TASK_QUEUE).await
    }

    /// Hard process termination intentionally tests persistence without graceful flush.
    pub fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
            child.wait()?;
        }
        Ok(())
    }

    pub async fn restart(&mut self) -> Result<()> {
        ensure!(
            self.child.is_none(),
            "stop the local server before restarting"
        );
        ensure!(
            self.database().is_file(),
            "persisted Temporal database is missing"
        );
        self.launch(StartupPhase::Restart).await
    }

    async fn launch(&mut self, phase: StartupPhase) -> Result<()> {
        let mut log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log())?;
        let launch_offset = log.seek(SeekFrom::End(0))?;
        let child = Command::new(&self.cli)
            .args([
                "--disable-config-env",
                "--disable-config-file",
                "--env-file",
            ])
            .arg(self.directory.join("unused-temporal-environment.yaml"))
            .args([
                "server",
                "start-dev",
                "--headless",
                "--ip",
                "127.0.0.1",
                "--port",
            ])
            .arg(self.address.port().to_string())
            .arg("--db-filename")
            .arg(self.database())
            .arg("--namespace")
            .arg(&self.namespace)
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()
            .context("start isolated persisted Temporal server")?;
        self.child = Some(child);
        let deadline = Instant::now() + Duration::from_secs(45);
        while Instant::now() < deadline {
            if let Some(status) = self
                .child
                .as_mut()
                .context("missing server process")?
                .try_wait()?
            {
                return Err(StartupFailure::capture(
                    phase,
                    Some(status),
                    &self.log(),
                    launch_offset,
                )
                .into());
            }
            if matches!(
                tokio::time::timeout(Duration::from_secs(3), self.adapter()).await,
                Ok(Ok(_))
            ) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        self.stop()?;
        Err(StartupFailure::capture(phase, None, &self.log(), launch_offset).into())
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn startup_log_evidence_is_bounded_phase_specific_and_redacted() -> Result<()> {
        use std::os::unix::process::ExitStatusExt;

        let directory = tempfile::tempdir()?;
        let log = directory.path().join("PRIVATE_LOG_PATH");
        let mut bytes = vec![b'x'; STARTUP_LOG_LIMIT * 2];
        bytes.extend_from_slice(b"PRIVATE_TOKEN address already in use; database is locked");
        fs::write(&log, bytes)?;
        for phase in [StartupPhase::Initial, StartupPhase::Restart] {
            let failure =
                StartupFailure::capture(phase, Some(ExitStatus::from_raw(1 << 8)), &log, 0);
            assert_eq!(failure.code, Some(1));
            assert_eq!(failure.signal, None);
            assert!(!failure.readiness_timed_out);
            assert_eq!(failure.log.bytes, STARTUP_LOG_LIMIT);
            assert!(failure.log.prefix_omitted && failure.log.read_limit_reached);
            assert!(failure.log.address_in_use && failure.log.database_locked);
            assert!(!failure.log.read_failed);
            assert!(!failure.to_string().contains("PRIVATE"));
            assert!(!format!("{failure:?}").contains("PRIVATE"));
            assert!(failure.to_string().len() < 1024);
        }
        let missing = StartupFailure::capture(
            StartupPhase::Initial,
            None,
            &directory.path().join("PRIVATE_MISSING_LOG"),
            0,
        );
        assert!(missing.readiness_timed_out);
        assert!(missing.log.read_failed);
        assert_eq!(missing.log.read_errno, Some(2));
        assert_eq!(missing.log.bytes, 0);
        assert!(missing.code.is_none() && missing.signal.is_none());
        assert!(!missing.to_string().contains("PRIVATE"));
        let old = b"address already in use PRIVATE_PREVIOUS_LAUNCH\n";
        let mut bytes = old.to_vec();
        bytes.extend_from_slice(b"PRIVATE_CURRENT_UNKNOWN_FAILURE");
        fs::write(&log, bytes)?;
        let current = StartupLogEvidence::capture(&log, old.len() as u64);
        assert!(!current.address_in_use);
        assert!(!current.prefix_omitted);
        assert!(!format!("{current:?}").contains("PRIVATE"));
        let reset = StartupLogEvidence::capture(&log, u64::MAX);
        assert!(reset.log_reset);
        assert_eq!(reset.bytes, 0);
        Ok(())
    }

    #[test]
    fn unknown_startup_output_stays_unknown_and_categories_are_not_exit_causes() {
        let unknown = StartupLogEvidence::from_bytes(b"PRIVATE_UNRECOGNIZED_OUTPUT", false);
        assert!(!unknown.address_in_use);
        assert!(!unknown.permission_denied);
        assert!(!unknown.database_locked);
        assert!(!unknown.resource_exhausted);
        assert!(!format!("{unknown:?}").contains("PRIVATE"));
        let categories = StartupLogEvidence::from_bytes(
            b"permission denied; database is busy; too many open files",
            false,
        );
        assert!(categories.permission_denied);
        assert!(categories.database_locked);
        assert!(categories.resource_exhausted);
    }

    #[tokio::test]
    async fn actual_temporal_bind_refusal_identifies_initial_and_restart_phase() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut server = LocalServer::start(&directory.path().join("restart")).await?;
        server.stop()?;
        // Keep a real listener open. This is a controlled bind failure, not a
        // claim that a port race caused any historical failure.
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        server.address = occupied.local_addr()?;
        let restart = server.restart().await.unwrap_err();
        let restart = restart
            .downcast_ref::<StartupFailure>()
            .context("missing restart evidence")?;
        assert!(matches!(restart.phase, StartupPhase::Restart));
        assert_eq!(restart.code, Some(1));
        assert!(restart.log.address_in_use);
        let initial_directory = directory.path().join("initial");
        fs::create_dir(&initial_directory)?;
        let mut initial = LocalServer {
            cli: server.cli.clone(),
            directory: initial_directory,
            address: occupied.local_addr()?,
            namespace: "day2-local-controlled-startup-refusal".to_owned(),
            child: None,
        };
        let failure = initial.launch(StartupPhase::Initial).await.unwrap_err();
        let failure = failure
            .downcast_ref::<StartupFailure>()
            .context("missing initial evidence")?;
        assert!(matches!(failure.phase, StartupPhase::Initial));
        assert_eq!(failure.code, Some(1));
        assert!(failure.log.address_in_use);
        Ok(())
    }
}
