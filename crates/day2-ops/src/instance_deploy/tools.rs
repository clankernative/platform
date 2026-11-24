//! What a deploy session reaches outside itself, with closed verbs: `kubectl`
//! reads and the rollout wait in the app's namespace through a private
//! kubeconfig built from derived names, `gcloud storage` for the archive, and
//! the candidate SDK's operator as a supervised child process. Argument lists
//! and the environment are pure functions pinned by tests; tests also run the
//! adapters against stub executables and substitute fakes above them.
use super::request::Operation;
use crate::maintenance::{self, Sink, Supervision};
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::{
    ffi::OsString,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// The ambient variables tools and the operator may see: the search path and
/// home, Google credential and account selection (including impersonation),
/// and proxy and CA settings, as for `day2 instance plan`.
pub const PASSED: [&str; 13] = [
    "PATH",
    "HOME",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
    "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT",
    "CLOUDSDK_CONFIG",
    "CLOUDSDK_ACTIVE_CONFIG_NAME",
    "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
    "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
];

/// The most the operator may print on stdout: its finish receipt.
pub const STDOUT_LIMIT: usize = 1 << 20;

/// The environment every tool and the operator run with: the allowlisted
/// ambient variables, then the session's private kubeconfig, the GKE auth
/// plugin, the instance's project, `LANG=C` and `TMPDIR=/tmp`. Nothing else
/// (no `DAY2_*`, no CI mode, no forge token) reaches them.
pub fn environment(
    ambient: &dyn Fn(&str) -> Option<OsString>,
    kubeconfig: &Path,
    project: &str,
) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = PASSED
        .iter()
        .filter_map(|name| ambient(name).map(|value| (OsString::from(name), value)))
        .collect();
    env.extend([
        ("KUBECONFIG".into(), kubeconfig.into()),
        ("USE_GKE_GCLOUD_AUTH_PLUGIN".into(), "True".into()),
        ("CLOUDSDK_CORE_PROJECT".into(), project.into()),
        ("LANG".into(), "C".into()),
        ("TMPDIR".into(), "/tmp".into()),
    ]);
    env.sort();
    env
}

/// What a session's tools need once the request is read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub kubeconfig: PathBuf,
    pub env: Vec<(OsString, OsString)>,
    pub project: String,
    pub zone: String,
    pub cluster: String,
}

/// The objects a deploy reads in the app's namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    StatefulSet,
    ConfigMap,
    Pod,
    CronJob,
    Claim,
}

impl Kind {
    pub fn resource(self) -> &'static str {
        match self {
            Self::StatefulSet => "statefulset",
            Self::ConfigMap => "configmap",
            Self::Pod => "pod",
            Self::CronJob => "cronjob",
            Self::Claim => "persistentvolumeclaim",
        }
    }
}

/// `gcloud container clusters get-credentials <cluster> --zone <zone> --project <project>`.
pub fn credentials_args(project: &str, zone: &str, cluster: &str) -> Vec<OsString> {
    [
        "container",
        "clusters",
        "get-credentials",
        cluster,
        "--zone",
        zone,
        "--project",
        project,
    ]
    .map(OsString::from)
    .to_vec()
}

/// `kubectl --namespace <namespace> get <kind> <name> --ignore-not-found --output=json`.
pub fn get_args(namespace: &str, kind: Kind, name: &str) -> Vec<OsString> {
    [
        "--namespace",
        namespace,
        "get",
        kind.resource(),
        name,
        "--ignore-not-found",
        "--output=json",
    ]
    .map(OsString::from)
    .to_vec()
}

/// `kubectl --namespace <namespace> rollout status statefulset/<workload> --timeout=600s`.
pub fn rollout_args(namespace: &str, workload: &str) -> Vec<OsString> {
    vec![
        "--namespace".into(),
        namespace.into(),
        "rollout".into(),
        "status".into(),
        format!("statefulset/{workload}").into(),
        format!("--timeout={}s", super::fence::budget::ROLLOUT_WAIT).into(),
    ]
}

/// How an operator run ended.
#[derive(Debug, Default)]
pub struct Ran {
    /// The direct child's exit code; `None` when a signal ended it.
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    /// Why the session was asked to stop: `deadline` or `interrupt`.
    pub stopped: Option<&'static str>,
    /// The process group outlived its grace and was killed.
    pub killed: bool,
}

/// The session's outside world.
pub trait Tools {
    /// The private kubeconfig, environment and cluster, once the request is read.
    fn configure(&mut self, config: Config);
    /// The cluster's credentials into the private kubeconfig.
    fn credentials(&mut self) -> Result<()>;
    /// One object in `namespace`, or nothing when it is absent.
    fn get(&mut self, namespace: &str, kind: Kind, name: &str) -> Result<Option<Value>>;
    /// Wait for the StatefulSet's rollout.
    fn rollout(&mut self, namespace: &str, workload: &str) -> Result<()>;
    /// `gcloud storage cp --recursive --no-clobber <directory> <destination>`.
    fn upload(&mut self, directory: &Path, prefix: &str, phase: &str) -> Result<()>;
    /// The phase's objects as `[{name, size, crc32c_hash}]`.
    fn list(&mut self, prefix: &str, phase: &str) -> Result<Vec<u8>>;
    /// `operator platform maintain <operation> <request>` until `deadline`,
    /// then SIGINT to its process group and its cleanup grace.
    fn maintain(
        &mut self,
        operator: &Path,
        operation: Operation,
        request: &Path,
        deadline: Duration,
    ) -> Result<Ran>;
    /// Unix seconds.
    fn now(&mut self) -> Result<u64>;
    /// 16 bytes from the system's secure random source.
    fn random(&mut self) -> Result<[u8; 16]>;
}

/// kubectl, gcloud and the operator from the job, with the session's
/// environment only. Each tool runs in its own process group, killed whole at
/// its deadline; a failed tool's stderr goes to the job log.
pub struct Native {
    config: Option<Config>,
    interrupted: Arc<AtomicBool>,
    /// Executables tests substitute; else found on `PATH`.
    pub kubectl: Option<PathBuf>,
    pub gcloud: Option<PathBuf>,
    pub grace: Duration,
}

impl Native {
    pub fn new(interrupted: Arc<AtomicBool>) -> Self {
        Self {
            config: None,
            interrupted,
            kubectl: None,
            gcloud: None,
            grace: Duration::from_secs(super::fence::budget::MAINTAIN_GRACE),
        }
    }

    fn config(&self) -> Result<&Config> {
        self.config
            .as_ref()
            .context("the deploy tools are not configured")
    }

    fn run(
        &self,
        program: &str,
        at: Option<&Path>,
        args: Vec<OsString>,
        timeout: Duration,
        what: &str,
    ) -> Result<Vec<u8>> {
        let config = self.config()?;
        let mut command = maintenance::tool(program, at)?;
        command
            .env_clear()
            .envs(config.env.iter().cloned())
            .args(args);
        let finished = maintenance::supervise(
            &mut command,
            Supervision {
                stdin: None,
                timeout,
                interrupted: Some(&self.interrupted),
                sink: Sink::Capture,
                group: true,
            },
        )
        .map_err(|error| match error.to_string().as_str() {
            "timed out" => anyhow::anyhow!("{what} timed out after {} s", timeout.as_secs()),
            "interrupted" => anyhow::anyhow!("{what} was interrupted"),
            _ => error.context(format!("run {program} for {what}")),
        })?;
        if !finished.status.success() {
            crate::instance_candidate::tools::log_tail(what, &finished.stderr);
            bail!(
                "{what} failed ({})",
                crate::instance_candidate::tools::exit(finished.status.code())
            );
        }
        Ok(finished.stdout)
    }
}

impl Tools for Native {
    fn configure(&mut self, config: Config) {
        self.config = Some(config);
    }

    fn credentials(&mut self) -> Result<()> {
        let config = self.config()?.clone();
        self.run(
            "gcloud",
            self.gcloud.as_deref(),
            credentials_args(&config.project, &config.zone, &config.cluster),
            Duration::from_secs(120),
            "read the cluster's credentials",
        )?;
        ensure!(
            std::fs::symlink_metadata(&config.kubeconfig).is_ok_and(|metadata| metadata.is_file()),
            "gcloud wrote no kubeconfig"
        );
        Ok(())
    }

    fn get(&mut self, namespace: &str, kind: Kind, name: &str) -> Result<Option<Value>> {
        let what = format!("read {} {name}", kind.resource());
        let raw = self.run(
            "kubectl",
            self.kubectl.as_deref(),
            get_args(namespace, kind, name),
            Duration::from_secs(super::fence::budget::KUBECTL_READ),
            &what,
        )?;
        if raw.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        Ok(Some(
            serde_json::from_slice(&raw).with_context(|| format!("{what}: not JSON"))?,
        ))
    }

    fn rollout(&mut self, namespace: &str, workload: &str) -> Result<()> {
        self.run(
            "kubectl",
            self.kubectl.as_deref(),
            rollout_args(namespace, workload),
            Duration::from_secs(super::fence::budget::ROLLOUT),
            &format!("wait for statefulset/{workload}'s rollout"),
        )?;
        Ok(())
    }

    fn upload(&mut self, directory: &Path, prefix: &str, phase: &str) -> Result<()> {
        self.run(
            "gcloud",
            self.gcloud.as_deref(),
            super::archive::upload_args(directory, prefix, phase),
            Duration::from_secs(super::fence::budget::ARCHIVE_UPLOAD),
            &format!("archive the backup to {prefix}{phase}/"),
        )?;
        Ok(())
    }

    fn list(&mut self, prefix: &str, phase: &str) -> Result<Vec<u8>> {
        self.run(
            "gcloud",
            self.gcloud.as_deref(),
            super::archive::list_args(prefix, phase),
            Duration::from_secs(super::fence::budget::ARCHIVE_LIST),
            &format!("list {prefix}{phase}/"),
        )
    }

    fn maintain(
        &mut self,
        operator: &Path,
        operation: Operation,
        request: &Path,
        deadline: Duration,
    ) -> Result<Ran> {
        let config = self.config()?;
        let mut command = Command::new(operator);
        command
            .env_clear()
            .envs(config.env.iter().cloned())
            .args(["platform", "maintain", operation.name()])
            .arg(request);
        supervise_operator(command, deadline, self.grace, &self.interrupted)
    }

    fn now(&mut self) -> Result<u64> {
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs())
    }

    fn random(&mut self) -> Result<[u8; 16]> {
        use ring::rand::SecureRandom;
        let mut bytes = [0_u8; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| anyhow::anyhow!("no secure random source"))?;
        Ok(bytes)
    }
}

/// Run the operator in its own process group with stdin closed, stderr to the
/// job log and stdout captured (bounded). At `deadline`, or when this process
/// is interrupted, the whole group gets SIGINT, which the maintenance session
/// handles by cleaning up and (before the fence) restoring the app. Its CLI may
/// exit at once while its host keeps cleaning up in the same group, so the run
/// ends only once the group is empty; after `grace` the group is killed.
pub fn supervise_operator(
    mut command: Command,
    deadline: Duration,
    grace: Duration,
    interrupted: &AtomicBool,
) -> Result<Ran> {
    use std::os::unix::process::CommandExt;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .process_group(0);
    let mut child = command.spawn().context("start the SDK operator")?;
    let group = rustix::process::Pid::from_raw(child.id() as i32)
        .context("the operator's process group")?;
    let stdout = child.stdout.take().context("the operator's stdout")?;
    let reader = std::thread::spawn(move || -> Vec<u8> {
        let mut bytes = Vec::new();
        let _ = stdout.take(STDOUT_LIMIT as u64 + 1).read_to_end(&mut bytes);
        bytes
    });
    let started = Instant::now();
    let mut ran = Ran::default();
    let mut signalled: Option<Instant> = None;
    let mut status = None;
    loop {
        if status.is_none() {
            status = child.try_wait()?;
        }
        let alive = rustix::process::test_kill_process_group(group).is_ok();
        if status.is_some() && !alive {
            break;
        }
        match signalled {
            None => {
                let reason = if interrupted.load(Ordering::SeqCst) {
                    Some("interrupt")
                } else if started.elapsed() > deadline {
                    Some("deadline")
                } else if status.is_some() {
                    // The CLI exited but something it started is still running
                    // in its group: give it the same grace, then kill it.
                    Some("exit")
                } else {
                    None
                };
                if let Some(reason) = reason {
                    if reason != "exit" {
                        ran.stopped = Some(reason);
                        let _ = rustix::process::kill_process_group(
                            group,
                            rustix::process::Signal::INT,
                        );
                    }
                    signalled = Some(Instant::now());
                }
            }
            Some(at) if at.elapsed() > grace => {
                let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
                let _ = child.kill();
                status = Some(child.wait()?);
                ran.killed = true;
                break;
            }
            Some(_) => {}
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let status = match status {
        Some(status) => status,
        None => child.wait()?,
    };
    ran.code = status.code();
    ran.stdout = reader
        .join()
        .map_err(|_| anyhow::anyhow!("the operator's stdout reader"))?;
    ensure!(
        ran.stdout.len() <= STDOUT_LIMIT,
        "the operator's output exceeds its bound"
    );
    Ok(ran)
}

/// Whether an operator run finished `operation`: exit 0, not stopped, and a
/// last stdout line that is its finish receipt.
pub fn finished(ran: &Ran, operation: Operation) -> Result<Value> {
    match (ran.stopped, ran.killed, ran.code) {
        (Some("interrupt"), _, _) => bail!(
            "day2 platform maintain {} was interrupted",
            operation.name()
        ),
        (Some(_), _, _) => bail!(
            "day2 platform maintain {} stopped at its deadline",
            operation.name()
        ),
        (None, true, _) => bail!(
            "day2 platform maintain {} left processes running and was killed",
            operation.name()
        ),
        (None, false, Some(0)) => {}
        (None, false, code) => bail!(
            "day2 platform maintain {} failed ({})",
            operation.name(),
            crate::instance_candidate::tools::exit(code)
        ),
    }
    let text = String::from_utf8_lossy(&ran.stdout);
    let last = text
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .context("the operator printed no receipt")?;
    let receipt: Value = serde_json::from_str(last.trim()).with_context(|| {
        format!(
            "day2 platform maintain {} printed no receipt",
            operation.name()
        )
    })?;
    ensure!(
        receipt["operation"] == operation.name(),
        "day2 platform maintain {} reported another operation",
        operation.name()
    );
    Ok(receipt)
}
