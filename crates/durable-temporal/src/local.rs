//! Isolated real-server test fixture. This is not a production deployment adapter.

use crate::TemporalAdapter;
use anyhow::{Context, Result, bail, ensure};
use std::{
    fs::{self, OpenOptions},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

pub const CLI_VERSION: &str = "1.6.1";
pub const LOCAL_NAMESPACE: &str = "day2-local-verification";
pub const LOCAL_TASK_QUEUE: &str = "day2-release-v1";

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
        server.launch().await?;
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
        self.launch().await
    }

    async fn launch(&mut self) -> Result<()> {
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log())?;
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
                bail!(
                    "Temporal server exited with {status}; inspect {}",
                    self.log().display()
                );
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
        bail!(
            "Temporal server readiness timed out; inspect {}",
            self.log().display()
        )
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
