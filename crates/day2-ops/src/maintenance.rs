//! GKE maintenance of one day2 app: stop it, run day2's own workflows against
//! its state volume in a short-lived pod, then bring it back. ops/Maintain.roc
//! orders the steps; this session owns every native action and the guards no
//! recipe can skip:
//!
//! - the maintenance pod is removed on every exit;
//! - activation prepares its helper on the incumbent node while the app serves;
//!   only filesystem metadata is read, never the live SQLite stores;
//! - after stopping, activation rechecks the original placement and scratch
//!   bound before opening a store or taking its final recovery backup;
//! - before the migration fence, any failure restores the app on its image;
//! - before the confirmation and the fence, `activate` rehearses the migration
//!   and activation on a copy of the verified backup and opens the copy with
//!   the target build's own store admission (what day2-serve runs at startup);
//!   a store the target would refuse is refused there, nothing else changed;
//! - after the fence, the old image is never restarted on the migrated volume;
//! - the fence needs a verified local backup, the target's admission of the
//!   store and a confirmation from this session, and `migration apply` refuses
//!   to run without it;
//! - one session per namespace; closed sets of workflows and kubectl verbs;
//! - only a successful fresh activation stamps the StatefulSet with the target
//!   app image, the precondition day2-gke-release and the day2-app stack hold
//!   every image change to: a new image of the running artifact (another
//!   platform build of the same app build) carries another day2-serve, whose
//!   store admission only this rehearsal runs before it starts;
//!   `mark-activated` repeats that stamp only for a target whose new artifact
//!   the database already activated, on the still-stopped old image.
//!
//! Every step is journalled beside the backups before it runs, so a session
//! killed outright (no `Drop`) can still be reconstructed.
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
mod activation;
pub use activation::Recovery;
use activation::{Intent as ActivationIntent, Phase as ActivationPhase};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant, SystemTime},
};

/// The reviewed pod spec. Rust fills a fixed placeholder set and refuses any other.
const POD_TEMPLATE: &str = include_str!("../../../deploy/gke/k8s/maintenance-pod.yaml");
const IMAGE_INIT_TEMPLATE: &str =
    include_str!("../../../deploy/gke/k8s/activation-image-init.yaml");
const POD_DEADLINE_SECONDS: u32 = 3_600;
const MAINTENANCE_LABEL: &str = "app.kubernetes.io/name=day2-maintenance";
const ROOT: &str = "/srv/day2";
/// The app's state volume in the pod.
const STATE: &str = "/srv/day2/.state";
const CURRENT: &str = "/srv/day2/current-instance.json";
const TARGET: &str = "/srv/day2/instance.json";
const PLAN: &str = "/srv/day2/migration-plan.json";
/// A disposable installation beside the real one (on the pod's scratch volume,
/// not the app's): the target instance over a copy of the verified backup.
const ADMISSION: &str = "/srv/day2/admission";
const ADMISSION_INSTANCE: &str = "/srv/day2/admission/instance.json";
const HOST: &str = "/workspace/platform/cli/day2-host";
const DAY2: &str = "/workspace/platform/build-out/bin/day2";
const OUTPUT_LIMIT: usize = 16 << 20;
const LAYER_LIMIT: u64 = 1 << 30;
/// day2-gke-release and the day2-app stack change an app's image only to the
/// one this annotation names, and the change removes it.
const ACTIVATED: &str = "day2.dev/activated-image";

// The pod's /srv/day2 scratch volume is sized from the store it maintains; see
// `scratch_bytes`.
const MIB: u64 = 1 << 20;
/// The smallest scratch volume, whatever the store.
const SCRATCH_FLOOR: u64 = 1 << 30;
/// Instance files, the migration plan and rounding.
const SCRATCH_SLACK: u64 = 256 * MIB;
/// The container's own writes beside its volumes (its root is read-only):
/// added to the scratch for its ephemeral-storage request and limit.
const CONTAINER_EPHEMERAL: u64 = 64 * MIB;
/// The short-lived pod that measures the store writes nothing.
const PROBE_SCRATCH: u64 = 64 * MIB;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Inspect,
    Backup,
    AuthorityApply,
    Activate,
    /// Recovery for `activate` of a new artifact when its own stamp step failed.
    MarkActivated,
    Rollout,
}

impl Operation {
    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "inspect" => Self::Inspect,
            "backup" => Self::Backup,
            "authority-apply" => Self::AuthorityApply,
            "activate" => Self::Activate,
            "rollout" => Self::Rollout,
            "mark-activated" => Self::MarkActivated,
            _ => bail!(
                "maintain operation must be inspect, backup, authority-apply, activate or mark-activated"
            ),
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Backup => "backup",
            Self::AuthorityApply => "authority-apply",
            Self::Activate => "activate",
            Self::Rollout => "rollout",
            Self::MarkActivated => "mark-activated",
        }
    }

    /// `activate` and its `mark-activated` recovery take the same request.
    fn targeted(self) -> bool {
        matches!(self, Self::Activate | Self::MarkActivated | Self::Rollout)
    }

    /// How many times the app's stores fit on the pod's scratch volume at the
    /// operation's peak.
    fn store_copies(self) -> u64 {
        match self {
            Self::Inspect | Self::MarkActivated => 0,
            // The verified backup.
            Self::Backup | Self::AuthorityApply => 1,
            // The backup, which the rehearsal then migrates as its copy, and
            // the WAL and SQLite temporary files that migration grows. The
            // real migration's WAL is on the app's volume; its temporary files
            // reuse the space the removed rehearsal freed.
            Self::Activate | Self::Rollout => 2,
        }
    }
}

/// The scratch volume for `copies` of stores measuring `stores` bytes, with a
/// quarter more for their growth, beside `artifacts` bytes of artifacts copied
/// in (the pod, backup, and, for targeted operations, rehearsal each hold a
/// copy). Whole MiB, at
/// least `SCRATCH_FLOOR`.
fn scratch_bytes(copies: u64, stores: u64, artifacts: u64) -> u64 {
    let stores = copies.saturating_mul(stores);
    let bytes = stores
        .saturating_add(stores / 4)
        .saturating_add(artifacts.saturating_mul(if copies > 1 { 3 } else { 2 }))
        .saturating_add(SCRATCH_SLACK)
        .max(SCRATCH_FLOOR);
    bytes.div_ceil(MIB).saturating_mul(MIB)
}

/// The store files the session copies, from `stat -c '%s %n'` of the regular
/// files at the top of the state volume: the app's database and every local
/// provider store the backup takes, each with its WAL.
fn store_sizes(listing: &str, app: &str) -> Result<BTreeMap<String, u64>> {
    let database = format!("{app}.sqlite");
    let mut wanted = vec![database.clone(), format!("{app}.artifacts.sqlite")];
    wanted.extend(
        day2::capabilities::LOCAL_PROVIDER_DATABASES
            .iter()
            .map(|name| (*name).to_owned()),
    );
    let mut sizes = BTreeMap::new();
    for line in listing.lines().filter(|line| !line.is_empty()) {
        let (size, path) = line.split_once(' ').context("unexpected stat output")?;
        let name = path
            .strip_prefix(STATE)
            .and_then(|name| name.strip_prefix('/'))
            .context("stat path outside the state volume")?;
        let store = name.strip_suffix("-wal").unwrap_or(name);
        if wanted.iter().any(|wanted| wanted == store) {
            sizes.insert(name.to_owned(), size.parse::<u64>().context("stat size")?);
        }
    }
    ensure!(
        sizes.contains_key(&database),
        "no {database} on the state volume"
    );
    Ok(sizes)
}

fn mebibytes(bytes: u64) -> String {
    format!("{}Mi", bytes.div_ceil(MIB))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Label {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// The desired instance.json, e.g. rendered from the day2-app plan.
    pub instance: PathBuf,
    pub app_image: String,
    pub artifact_id: String,
    /// App-owned canary operations, required only by the rolling release lane.
    pub probe: Option<day2::rollout::ProbeDefinition>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OffsiteBackup {
    pub cronjob: String,
    pub bucket: String,
    pub service_account: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Placement {
    pub controller_uid: String,
    pub pvc_uid: String,
    pub node: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadKind {
    #[default]
    Statefulset,
    Deployment,
}

impl WorkloadKind {
    fn resource(self) -> &'static str {
        match self {
            Self::Statefulset => "statefulset",
            Self::Deployment => "deployment",
        }
    }
}

/// Everything the old flags carried, as one reviewed file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub namespace: String,
    pub statefulset: String,
    #[serde(default)]
    pub workload_kind: WorkloadKind,
    pub configmap: String,
    pub app: String,
    pub pvc: String,
    pub app_image: String,
    pub artifact_id: String,
    pub tooling_image: String,
    pub operator: String,
    /// The pod label the platform's policy admits for non-serving app pods.
    pub pod_label: Label,
    #[serde(default)]
    pub backup_dir: Option<PathBuf>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub target: Option<Target>,
    /// Reviewed namespace backup identity and destination. Required for rolling
    /// releases; the source image takes an online snapshot before preparation.
    #[serde(default)]
    pub offsite_backup: Option<OffsiteBackup>,
    /// Captured before selecting a release; recovery never adopts a replacement
    /// controller or claim that happens to have the same name.
    #[serde(default)]
    pub placement: Option<Placement>,
    /// Skip the typed confirmation; recorded in the journal.
    #[serde(default)]
    pub yes: bool,
}

impl Request {
    fn kind(&self, operation: Operation) -> WorkloadKind {
        if operation == Operation::Rollout {
            WorkloadKind::Deployment
        } else {
            self.workload_kind
        }
    }

    pub fn validate(&self, operation: Operation) -> Result<()> {
        match (&self.placement, operation) {
            (Some(placement), Operation::Rollout) => {
                for uid in [&placement.controller_uid, &placement.pvc_uid] {
                    ensure!(
                        !uid.is_empty()
                            && uid.len() <= 128
                            && uid
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
                        "invalid rolling placement UID"
                    );
                }
                ensure!(dns_label(&placement.node), "invalid rolling placement node");
            }
            (None, Operation::Rollout) => bail!("rolling_release_requires_captured_placement"),
            (None, _) => {}
            (Some(_), _) => bail!("placement requires rollout"),
        }
        match (&self.offsite_backup, operation) {
            (Some(backup), Operation::Rollout) => {
                ensure!(
                    dns_label(&backup.cronjob) && dns_label(&backup.service_account),
                    "invalid rolling backup identity"
                );
                crate::offsite::validate_bucket(&backup.bucket)?;
            }
            (None, Operation::Rollout) => bail!("rolling_release_requires_offsite_backup"),
            (None, _) => {}
            (Some(_), _) => bail!("offsite_backup requires rollout"),
        }
        for (field, value) in [
            ("namespace", &self.namespace),
            ("statefulset", &self.statefulset),
            ("configmap", &self.configmap),
            ("pvc", &self.pvc),
        ] {
            ensure!(dns_label(value), "{field} must be a Kubernetes DNS label");
        }
        ensure!(
            !self.app.is_empty()
                && self.app.len() <= 48
                && self.app.starts_with(|c: char| c.is_ascii_lowercase())
                && self
                    .app
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "app must be a day2 app id"
        );
        pinned_image(&self.app_image)?;
        pinned_image(&self.tooling_image)?;
        hex64(&self.artifact_id, "artifact_id")?;
        ensure!(
            self.operator.len() <= 254
                && self.operator.split('@').count() == 2
                && !self.operator.starts_with('@')
                && !self.operator.ends_with('@')
                && !self
                    .operator
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control()),
            "operator must be the operator's e-mail address"
        );
        ensure!(
            label_key(&self.pod_label.key)
                && label_value(&self.pod_label.value)
                && !matches!(
                    self.pod_label.key.as_str(),
                    "app.kubernetes.io/name" | "app.kubernetes.io/part-of"
                ),
            "pod_label must be a Kubernetes label key and value"
        );
        let needs_id = operation == Operation::AuthorityApply || operation.targeted();
        match &self.request_id {
            Some(id) => ensure!(
                needs_id
                    && !id.is_empty()
                    && id.len()
                        <= if operation == Operation::Rollout {
                            96
                        } else {
                            128
                        }
                    && id
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)),
                "request_id is 1-128 letters, digits, dots, dashes or underscores, for authority-apply, activate, mark-activated or rollout (96 maximum)"
            ),
            None => ensure!(!needs_id, "{} requires request_id", operation.name()),
        }
        match (&self.target, operation.targeted()) {
            (Some(target), true) => {
                pinned_image(&target.app_image)?;
                hex64(&target.artifact_id, "target.artifact_id")?;
                // The target may keep the running artifact: a new image of it
                // carries another day2-serve, so it is activated like any other.
                ensure!(
                    target.app_image != self.app_image,
                    "the target names the running image; nothing to activate"
                );
                // The database activated the running artifact before this
                // session, so it cannot show that `activate` ran for the new
                // image; rerunning `activate` is the recovery instead.
                ensure!(
                    operation != Operation::MarkActivated || target.artifact_id != self.artifact_id,
                    "mark-activated cannot vouch for a target that keeps the running artifact; run activate for it"
                );
            }
            (None, true) => bail!("{} requires target", operation.name()),
            (Some(_), false) => bail!("only activate and mark-activated take a target"),
            (None, false) => {}
        }
        Ok(())
    }
}

fn dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

fn label_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.starts_with(|c: char| c.is_ascii_alphanumeric())
        && value.ends_with(|c: char| c.is_ascii_alphanumeric())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

fn label_key(value: &str) -> bool {
    let (prefix, name) = value.rsplit_once('/').unwrap_or(("", value));
    label_value(name)
        && (prefix.is_empty() || prefix.len() <= 253 && prefix.split('.').all(dns_label))
}

fn hex64(value: &str, field: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
        "{field} must be 64 lowercase hex characters"
    );
    Ok(())
}

/// `host[:port]/repository@sha256:<64 hex>`; returns (host, repository, digest).
fn pinned_image(image: &str) -> Result<(&str, &str, &str)> {
    let parsed = image.split_once('/').and_then(|(host, rest)| {
        rest.rsplit_once('@')
            .map(|(repository, digest)| (host, repository, digest))
    });
    let (host, repository, digest) =
        parsed.with_context(|| format!("{image} must be pinned by digest"))?;
    ensure!(
        !host.is_empty()
            && host
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || ".-:".contains(c))
            && !repository.is_empty()
            && repository
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._/-".contains(c))
            && !repository.contains("..")
            && digest
                .strip_prefix("sha256:")
                .is_some_and(|hex| hex64(hex, "digest").is_ok()),
        "{image} must be pinned by digest"
    );
    Ok((host, repository, digest))
}

// ---------------------------------------------------------------------------
// Native tools. Production runs kubectl, gcloud and the terminal; tests fake them.

/// kubectl, always scoped to the session's namespace by the caller.
pub trait Cluster {
    fn kubectl(
        &mut self,
        args: &[String],
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<String>;
    /// From now on ignore interrupts and keep tools out of the terminal's
    /// process group: cleanup must finish even under a second Ctrl-C.
    fn unstoppable(&mut self) {}
}

/// Read-only access to an OCI registry's manifests and blobs.
pub trait Registry {
    fn get(&mut self, host: &str, path: &str, accept: &str, limit: u64) -> Result<Vec<u8>>;
}

/// Typed confirmation from the operator.
pub trait Prompt {
    fn confirm(&mut self, question: &str, word: &str) -> Result<bool>;
}

pub struct Tools {
    pub cluster: Box<dyn Cluster>,
    pub registry: Box<dyn Registry>,
    pub prompt: Box<dyn Prompt>,
}

impl Tools {
    pub fn native(interrupted: Arc<AtomicBool>) -> Result<Self> {
        Ok(Self {
            cluster: Box::new(Kubectl {
                executable: on_path("kubectl")?,
                interrupted: interrupted.clone(),
                unstoppable: false,
            }),
            registry: Box::new(Oci {
                gcloud: on_path("gcloud")?,
                token: None,
                interrupted: interrupted.clone(),
            }),
            prompt: Box::new(Terminal { interrupted }),
        })
    }
}

fn on_path(name: &str) -> Result<PathBuf> {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|directory| directory.join(name))
                .find(|path| path.is_file())
        })
        .with_context(|| format!("{name} is required on PATH"))?
        .canonicalize()
        .map_err(Into::into)
}

/// Run a trusted tool with a deadline, bounded captured output and interrupt
/// checks. A child killed by Ctrl-C fails the step, and the session cleans up.
fn bounded(
    command: &mut Command,
    stdin: Option<&[u8]>,
    timeout: Duration,
    interrupted: Option<&AtomicBool>,
) -> Result<String> {
    let interrupted = || interrupted.is_some_and(|flag| flag.load(Ordering::SeqCst));
    let mut child = command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(bytes) = stdin {
        child
            .stdin
            .take()
            .context("child stdin")?
            .write_all(bytes)?;
    }
    let reader = |stream: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || -> Vec<u8> {
            let mut bytes = Vec::new();
            if let Some(stream) = stream {
                let _ = stream.take(OUTPUT_LIMIT as u64 + 1).read_to_end(&mut bytes);
            }
            bytes
        })
    };
    let stdout = reader(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let stderr = reader(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if interrupted() || started.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!(if interrupted() {
                "interrupted"
            } else {
                "timed out"
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let stdout = stdout
        .join()
        .map_err(|_| anyhow::anyhow!("stdout reader"))?;
    let stderr = stderr
        .join()
        .map_err(|_| anyhow::anyhow!("stderr reader"))?;
    ensure!(
        stdout.len() <= OUTPUT_LIMIT,
        "tool output exceeds its bound"
    );
    if !status.success() {
        let tail = String::from_utf8_lossy(&stderr);
        let tail: String = tail
            .chars()
            .rev()
            .take(2_000)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        bail!("{} ({status})", tail.trim());
    }
    Ok(String::from_utf8(stdout)?)
}

struct Kubectl {
    executable: PathBuf,
    interrupted: Arc<AtomicBool>,
    unstoppable: bool,
}

impl Cluster for Kubectl {
    fn kubectl(
        &mut self,
        args: &[String],
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<String> {
        let mut command = Command::new(&self.executable);
        command.args(args);
        if self.unstoppable {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let interrupted = (!self.unstoppable).then_some(self.interrupted.as_ref());
        bounded(&mut command, stdin, timeout, interrupted)
            .with_context(|| format!("kubectl {}", args.get(2).map_or("", String::as_str)))
    }

    fn unstoppable(&mut self) {
        self.unstoppable = true;
    }
}

struct Oci {
    gcloud: PathBuf,
    token: Option<String>,
    interrupted: Arc<AtomicBool>,
}

impl Registry for Oci {
    fn get(&mut self, host: &str, path: &str, accept: &str, limit: u64) -> Result<Vec<u8>> {
        if self.token.is_none() {
            let token = bounded(
                Command::new(&self.gcloud).args(["auth", "print-access-token"]),
                None,
                Duration::from_secs(60),
                Some(&self.interrupted),
            )
            .context("gcloud auth print-access-token")?;
            self.token = Some(token.trim().to_owned());
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(300))
            .build()?;
        let response = client
            .get(format!("https://{host}/v2/{path}"))
            .bearer_auth(self.token.as_deref().unwrap_or_default())
            .header("Accept", accept)
            .send()?
            .error_for_status()?;
        let mut bytes = Vec::new();
        response.take(limit + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= limit,
            "registry object exceeds its bound"
        );
        Ok(bytes)
    }
}

/// Reads the answer from the controlling terminal: the recipe's stdin is the
/// supervisor pipe. Ctrl-C while waiting is a refusal.
struct Terminal {
    interrupted: Arc<AtomicBool>,
}

impl Prompt for Terminal {
    fn confirm(&mut self, question: &str, word: &str) -> Result<bool> {
        let tty = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .context(
                "confirmation needs a terminal; pass \"yes\": true in the request to skip it",
            )?;
        let mut writer = tty.try_clone()?;
        write!(writer, "{question}")?;
        writer.flush()?;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::BufReader::new(tty).read_line(&mut line);
            let _ = sender.send(line);
        });
        loop {
            if self.interrupted.load(Ordering::SeqCst) {
                return Ok(false);
            }
            match receiver.recv_timeout(Duration::from_millis(200)) {
                Ok(line) => return Ok(line.trim() == word),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(false),
            }
        }
    }
}

/// Once installed, Ctrl-C and SIGTERM no longer kill the host outright: the
/// running tool dies (it shares the terminal's process group), the step fails
/// and the session's guards clean up.
pub fn interrupt_flag() -> Arc<AtomicBool> {
    fn mark(flag: &AtomicBool) {
        if !flag.swap(true, Ordering::SeqCst) {
            eprintln!("\n== interrupted: stopping the current step and cleaning up");
        }
    }
    let flag = Arc::new(AtomicBool::new(false));
    let set = flag.clone();
    let (ready, installed) = mpsc::channel();
    std::thread::spawn(move || {
        use tokio::signal::unix::{SignalKind, signal};
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            let _ = ready.send(false);
            return;
        };
        runtime.block_on(async move {
            let (Ok(mut interrupt), Ok(mut terminate)) = (
                signal(SignalKind::interrupt()),
                signal(SignalKind::terminate()),
            ) else {
                let _ = ready.send(false);
                return;
            };
            let _ = ready.send(true);
            let other = set.clone();
            tokio::spawn(async move {
                while terminate.recv().await.is_some() {
                    mark(&other);
                }
            });
            while interrupt.recv().await.is_some() {
                mark(&set);
            }
        });
    });
    // Without handlers, Ctrl-C keeps its default: nothing has changed yet at open.
    let _ = installed.recv_timeout(Duration::from_secs(5));
    flag
}

// ---------------------------------------------------------------------------
// Artifacts from digest-pinned app images (deploy/gke/images/app puts the
// artifact in the image's top layer under /srv/day2/artifacts/<id>/).

const INDEX: &str = "application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json";
const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json";

fn verified(bytes: Vec<u8>, expected: &str) -> Result<Vec<u8>> {
    let actual = day2::digest(&bytes);
    ensure!(
        actual == expected,
        "registry digest mismatch: {actual} != {expected}"
    );
    Ok(bytes)
}

pub fn fetch_artifact(
    registry: &mut dyn Registry,
    image: &str,
    artifact_id: &str,
    output: &Path,
) -> Result<Value> {
    let (host, repository, digest) = pinned_image(image)?;
    hex64(artifact_id, "artifact_id")?;
    let accept = format!("{INDEX},{MANIFEST}");
    let get =
        |registry: &mut dyn Registry, path: String, accept: &str, limit: u64, digest: &str| {
            verified(
                registry.get(host, &format!("{repository}/{path}"), accept, limit)?,
                digest,
            )
        };
    let mut manifest: Value = serde_json::from_slice(&get(
        registry,
        format!("manifests/{digest}"),
        &accept,
        4 << 20,
        digest,
    )?)?;
    if let Some(manifests) = manifest.get("manifests").and_then(Value::as_array) {
        let amd64: Vec<&Value> = manifests
            .iter()
            .filter(|entry| {
                entry["platform"]["architecture"] == "amd64" && entry["platform"]["os"] == "linux"
            })
            .collect();
        ensure!(
            amd64.len() == 1,
            "expected exactly one linux/amd64 manifest in {image}"
        );
        let digest = amd64[0]["digest"]
            .as_str()
            .context("platform manifest digest")?
            .to_owned();
        manifest = serde_json::from_slice(&get(
            registry,
            format!("manifests/{digest}"),
            MANIFEST,
            4 << 20,
            &digest,
        )?)?;
    }
    let layer = manifest["layers"]
        .as_array()
        .and_then(|layers| layers.last())
        .context("image has no layers")?;
    let layer_digest = layer["digest"].as_str().context("layer digest")?.to_owned();
    let blob = get(
        registry,
        format!("blobs/{layer_digest}"),
        "*/*",
        LAYER_LIMIT,
        &layer_digest,
    )?;
    let (files, bytes) = extract_artifact(&blob, artifact_id, output)?;
    Ok(
        json!({"image": image, "artifact": artifact_id, "layer": layer_digest, "files": files, "bytes": bytes}),
    )
}

/// Extract `srv/day2/artifacts/<id>/` from a (gzip or plain) tar layer into
/// `output/<id>`, read-only, refusing links, devices and escaping paths, then
/// check the artifact's own identity and worker digest. Returns the number of
/// files and their bytes.
pub fn extract_artifact(layer: &[u8], artifact_id: &str, output: &Path) -> Result<(usize, u64)> {
    let reader: Box<dyn Read> = match layer {
        [0x1f, 0x8b, ..] => Box::new(flate2::read::GzDecoder::new(layer)),
        [0x28, 0xb5, 0x2f, 0xfd, ..] => bail!("zstd image layers are not supported"),
        _ => Box::new(layer),
    };
    let prefix = format!("srv/day2/artifacts/{artifact_id}/");
    let destination = output.join(artifact_id);
    ensure!(!destination.exists(), "artifact output already exists");
    let mut archive = tar::Archive::new(reader);
    let (mut files, mut size) = (0_usize, 0_u64);
    let mut directories = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw =
            String::from_utf8(entry.path_bytes().into_owned()).context("non UTF-8 layer path")?;
        let name = raw.trim_start_matches("./");
        let Some(relative) = name.strip_prefix(&prefix) else {
            continue;
        };
        ensure!(
            Path::new(relative)
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
            "refusing layer path {raw}"
        );
        let path = destination.join(relative);
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            fs::create_dir_all(&path)?;
            directories.push(path);
        } else if kind.is_file() {
            fs::create_dir_all(path.parent().context("artifact file parent")?)?;
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            size += bytes.len() as u64;
            fs::write(&path, bytes)?;
            // day2 requires artifacts write-protected; keep only read and execute bits.
            let mode = entry.header().mode()? & 0o555;
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(mode | 0o400))?;
            files += 1;
        } else {
            bail!("refusing non-regular layer entry {raw}");
        }
    }
    ensure!(files > 0, "the image's top layer holds no {prefix}");
    let manifest: Value = serde_json::from_slice(&fs::read(destination.join("artifact.json"))?)?;
    ensure!(
        day2::digest(&serde_json::to_vec(&manifest)?) == format!("sha256:{artifact_id}"),
        "artifact identity mismatch"
    );
    if let Some(worker) = manifest.get("worker_digest").and_then(Value::as_str) {
        ensure!(
            day2::digest(&fs::read(destination.join("worker"))?) == worker,
            "artifact worker digest mismatch"
        );
    }
    use std::os::unix::fs::PermissionsExt;
    directories.push(destination.clone());
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o555))?;
    }
    Ok((files, size))
}

// ---------------------------------------------------------------------------
// Byte manifests: what the pod holds must be what arrived here.

/// Relative path -> sha256 of every regular file under `root`.
pub fn local_manifest(root: &Path) -> Result<BTreeMap<String, String>> {
    fn walk(root: &Path, directory: &Path, out: &mut BTreeMap<String, String>) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            let path = entry.path();
            if kind.is_dir() {
                walk(root, &path, out)?;
            } else if kind.is_file() {
                let relative = path
                    .strip_prefix(root)?
                    .to_str()
                    .context("non UTF-8 path")?
                    .to_owned();
                out.insert(relative, day2::digest(&fs::read(&path)?));
            } else {
                bail!("unexpected non-regular file {}", path.display());
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out)?;
    Ok(out)
}

/// Parse `sha256sum` output for files under `root` (as `find -exec sha256sum`).
fn remote_manifest(output: &str, root: &str) -> Result<BTreeMap<String, String>> {
    let prefix = format!("{root}/");
    let mut out = BTreeMap::new();
    for line in output.lines().filter(|line| !line.is_empty()) {
        let (hash, path) = line
            .split_once("  ")
            .context("unexpected sha256sum output")?;
        hex64(hash, "sha256sum")?;
        let relative = path
            .strip_prefix(&prefix)
            .context("sha256sum path outside the bundle")?;
        ensure!(
            out.insert(relative.to_owned(), format!("sha256:{hash}"))
                .is_none(),
            "duplicate path in sha256sum output"
        );
    }
    ensure!(!out.is_empty(), "the pod reported an empty bundle");
    Ok(out)
}

fn writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.is_dir() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                writable(&entry.path());
            }
        }
    } else if metadata.is_file() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
}

fn private(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        for entry in fs::read_dir(path)? {
            private(&entry?.path())?;
        }
    } else {
        let mode = metadata.permissions().mode() & 0o700;
        fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o400))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The session.

#[derive(Default)]
struct State {
    offsite_backup: Option<Value>,
    backup_job: Option<String>,
    resumed: bool,
    candidate_observed: bool,
    probe_verified: bool,
    artifacts: bool,
    stopped: bool,
    /// The pod measuring the store may exist.
    probe: bool,
    /// Bytes of the artifacts the pod holds.
    artifact_bytes: u64,
    /// The pod's scratch volume in bytes, once the store is measured.
    scratch: Option<u64>,
    preparation_verified: bool,
    pod: bool,
    pod_backup: bool,
    backup: Option<PathBuf>,
    /// Local provider stores the in-pod backup holds beside app.sqlite.
    providers: Vec<String>,
    stamp: Option<Value>,
    plan: Option<Value>,
    /// The rehearsal runs once per session, refused or not.
    rehearsed: bool,
    /// What the target build reported opening the rehearsed copy.
    admission: Option<Value>,
    confirmed: bool,
    fenced: bool,
    fence_entered: bool,
    migrated: bool,
    activated: bool,
    store_admitted: bool,
    /// The artifact the app's database activates, from `authority-inspect`.
    active_artifact: Option<String>,
    marked: bool,
    result: Option<Value>,
    finished: bool,
}

pub struct Session {
    tools: Tools,
    request: Request,
    /// For the `mark-activated` recovery command an `activate` failure prints.
    request_file: PathBuf,
    request_json: String,
    request_digest: String,
    operation: Operation,
    stamp: String,
    pod: String,
    replicas: u64,
    work: tempfile::TempDir,
    backup_root: PathBuf,
    journal: PathBuf,
    events: Vec<Value>,
    target_instance: Option<String>,
    controller: Value,
    online_node: Option<String>,
    pvc_uid: Option<String>,
    /// The exact serving pod whose node hosts activation's preparation.
    incumbent: Option<Value>,
    activation: Option<ActivationIntent>,
    state: State,
}

impl Session {
    pub fn open(operation: &str, request_file: &Path, mut tools: Tools) -> Result<Self> {
        let operation = Operation::parse(operation)?;
        let metadata = fs::metadata(request_file).context("maintenance request file")?;
        ensure!(
            metadata.is_file() && metadata.len() <= 65_536,
            "maintenance request file size"
        );
        let request_bytes = fs::read(request_file)?;
        let request_digest = day2::digest(&request_bytes);
        let request: Request = day2::json::decode(&request_bytes)?;
        request.validate(operation)?;
        ensure!(
            operation != Operation::Rollout
                || request
                    .target
                    .as_ref()
                    .is_some_and(|target| target.probe.is_some()),
            "rolling_release_requires_app_owned_probe"
        );
        let target_instance = match &request.target {
            Some(target) => {
                let metadata = fs::metadata(&target.instance).context("target instance")?;
                ensure!(
                    metadata.is_file() && metadata.len() <= 1 << 20,
                    "target instance size"
                );
                let text = fs::read_to_string(&target.instance)?;
                let value: Value =
                    serde_json::from_str(&text).context("target instance is not JSON")?;
                ensure!(
                    value["apps"][&request.app]["artifact"]
                        == format!("artifacts/{}", target.artifact_id),
                    "the target instance does not bind {} to the target artifact",
                    request.app
                );
                Some(text)
            }
            None => None,
        };
        let namespace = request.namespace.clone();
        let mut kubectl = |args: &[&str]| -> Result<String> {
            let mut full = vec!["-n".to_owned(), namespace.clone()];
            full.extend(args.iter().map(|arg| (*arg).to_owned()));
            tools.cluster.kubectl(&full, None, Duration::from_secs(60))
        };
        let statefulset: Value = serde_json::from_str(&kubectl(&[
            "get",
            request.kind(operation).resource(),
            &request.statefulset,
            "-o",
            "json",
        ])?)?;
        let replicas = statefulset["spec"]["replicas"]
            .as_u64()
            .context("StatefulSet replicas")?;
        let running = statefulset["spec"]["template"]["spec"]["containers"][0]["image"]
            .as_str()
            .context("StatefulSet image")?;
        let resuming = operation == Operation::Rollout
            && statefulset["metadata"]["annotations"]["day2.dev/rollout"].as_str()
                == request.request_id.as_deref()
            && request
                .target
                .as_ref()
                .is_some_and(|target| target.app_image == running);
        ensure!(
            running == request.app_image || resuming,
            "the StatefulSet runs {running}, not app_image {}",
            request.app_image
        );
        let marked = statefulset["metadata"]["annotations"][ACTIVATED]
            .as_str()
            .map(str::to_owned);
        if operation == Operation::MarkActivated {
            unmarked(&request, replicas, marked.as_deref())?;
        }
        let mut incumbent = None;
        let online_node = if operation == Operation::Rollout {
            ensure!(
                replicas == 1
                    && statefulset["spec"]["strategy"]["type"] == "RollingUpdate"
                    && statefulset["spec"]["strategy"]["rollingUpdate"]["maxSurge"] == 1
                    && statefulset["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"] == 0
                    && statefulset["spec"]["template"]["spec"]["volumes"]
                        .as_array()
                        .is_some_and(|volumes| volumes
                            .iter()
                            .any(|volume| volume["name"] == "state"
                                && volume["persistentVolumeClaim"]["claimName"] == request.pvc)),
                "rolling_deployment_required"
            );
            let pods: Value = serde_json::from_str(&kubectl(&[
                "get",
                "pods",
                "-l",
                &format!("app.kubernetes.io/name={}", request.statefulset),
                "-o",
                "json",
            ])?)?;
            let replicasets: Value =
                serde_json::from_str(&kubectl(&["get", "replicasets", "-o", "json"])?)?;
            let owners: Vec<_> = replicasets["items"]
                .as_array()
                .context("replicasets")?
                .iter()
                .filter(|replica| {
                    replica["metadata"]["ownerReferences"]
                        .as_array()
                        .is_some_and(|owners| {
                            owners.iter().any(|owner| {
                                owner["controller"] == true
                                    && owner["uid"] == statefulset["metadata"]["uid"]
                            })
                        })
                })
                .filter_map(|replica| replica["metadata"]["uid"].as_str())
                .collect();
            for pod in pods["items"].as_array().context("pods")? {
                if matches!(
                    pod["status"]["phase"].as_str(),
                    Some("Succeeded" | "Failed")
                ) {
                    continue;
                }
                ensure!(
                    pod["metadata"]["ownerReferences"]
                        .as_array()
                        .is_some_and(|references| references.iter().any(
                            |owner| owner["controller"] == true
                                && owner["uid"]
                                    .as_str()
                                    .is_some_and(|uid| owners.contains(&uid))
                        ))
                        && pod["spec"]["volumes"]
                            .as_array()
                            .is_some_and(|volumes| volumes.iter().any(|volume| volume["name"]
                                == "state"
                                && volume["persistentVolumeClaim"]["claimName"] == request.pvc)),
                    "rollout_pod_owner_or_claim_changed"
                );
            }
            let services: Value =
                serde_json::from_str(&kubectl(&["get", "services", "-o", "json"])?)?;
            let mut helper_labels = serde_json::Map::from_iter([
                ("app.kubernetes.io/name".into(), json!("day2-maintenance")),
                ("app.kubernetes.io/part-of".into(), json!("day2")),
            ]);
            helper_labels.insert(
                request.pod_label.key.clone(),
                json!(request.pod_label.value),
            );
            for service in services["items"].as_array().context("services")? {
                ensure!(
                    !service["spec"]["selector"]
                        .as_object()
                        .is_some_and(|selector| !selector.is_empty()
                            && selector
                                .iter()
                                .all(|(key, value)| helper_labels.get(key) == Some(value))),
                    "maintenance_pod_must_not_match_a_service"
                );
            }
            let nodes: Vec<_> = pods["items"]
                .as_array()
                .context("pod list")?
                .iter()
                .filter(|pod| {
                    pod["metadata"]["deletionTimestamp"].is_null()
                        && pod["spec"]["containers"]
                            .as_array()
                            .is_some_and(|containers| {
                                containers.iter().any(|container| {
                                    container["name"] == "day2"
                                        && (container["image"] == request.app_image
                                            || (resuming && container["image"] == running))
                                })
                            })
                })
                .filter_map(|pod| pod["spec"]["nodeName"].as_str().map(str::to_owned))
                .collect();
            ensure!(
                !nodes.is_empty() && nodes.iter().all(|node| node == &nodes[0]),
                "one_incumbent_node_required"
            );
            Some(nodes[0].clone())
        } else if operation == Operation::Activate && replicas > 0 {
            ensure!(replicas == 1, "activation_preparation_requires_one_replica");
            let pods: Value = serde_json::from_str(&kubectl(&[
                "get",
                "pods",
                "-l",
                &format!("app.kubernetes.io/name={}", request.statefulset),
                "-o",
                "json",
            ])?)?;
            let mut owners = vec![statefulset["metadata"]["uid"].clone()];
            if request.kind(operation) == WorkloadKind::Deployment {
                let replicasets: Value =
                    serde_json::from_str(&kubectl(&["get", "replicasets", "-o", "json"])?)?;
                owners = replicasets["items"]
                    .as_array()
                    .context("replicasets")?
                    .iter()
                    .filter(|replica| {
                        replica["metadata"]["ownerReferences"]
                            .as_array()
                            .is_some_and(|refs| {
                                refs.iter().any(|owner| {
                                    owner["controller"] == true
                                        && owner["uid"] == statefulset["metadata"]["uid"]
                                })
                            })
                    })
                    .map(|replica| replica["metadata"]["uid"].clone())
                    .collect();
            }
            let live: Vec<_> = pods["items"]
                .as_array()
                .context("pods")?
                .iter()
                .filter(|pod| {
                    !matches!(
                        pod["status"]["phase"].as_str(),
                        Some("Succeeded" | "Failed")
                    )
                })
                .collect();
            ensure!(
                live.len() == 1,
                "activation_preparation_requires_one_incumbent"
            );
            let pod = live[0];
            ensure!(
                pod["metadata"]["deletionTimestamp"].is_null()
                    && pod["metadata"]["uid"]
                        .as_str()
                        .is_some_and(|uid| !uid.is_empty())
                    && pod["metadata"]["ownerReferences"]
                        .as_array()
                        .is_some_and(|refs| {
                            refs.iter().any(|owner| {
                                owner["controller"] == true
                                    && !owner["uid"].is_null()
                                    && owners.contains(&owner["uid"])
                            })
                        })
                    && pod["spec"]["volumes"].as_array().is_some_and(|volumes| {
                        volumes.iter().any(|volume| {
                            volume["name"] == "state"
                                && volume["persistentVolumeClaim"]["claimName"] == request.pvc
                        })
                    })
                    && pod["spec"]["containers"]
                        .as_array()
                        .is_some_and(|containers| {
                            containers.iter().any(|container| {
                                container["name"] == "day2"
                                    && container["image"] == request.app_image
                            })
                        })
                    && pod["status"]["phase"] == "Running"
                    && pod["status"]["conditions"]
                        .as_array()
                        .is_some_and(|conditions| {
                            conditions.iter().any(|condition| {
                                condition["type"] == "Ready" && condition["status"] == "True"
                            })
                        }),
                "activation_incumbent_owner_claim_image_or_readiness_changed"
            );
            let node = pod["spec"]["nodeName"].as_str().context("incumbent node")?;
            ensure!(dns_label(node), "invalid_incumbent_node");
            incumbent = Some(pod.clone());
            Some(node.to_owned())
        } else {
            None
        };
        let pvc_uid = if matches!(
            operation,
            Operation::Rollout | Operation::Activate | Operation::MarkActivated
        ) {
            let pvc: Value =
                serde_json::from_str(&kubectl(&["get", "pvc", &request.pvc, "-o", "json"])?)?;
            ensure!(
                pvc["status"]["phase"] == "Bound"
                    && pvc["spec"]["accessModes"] == json!(["ReadWriteOnce"]),
                "bound_read_write_once_claim_required"
            );
            Some(
                pvc["metadata"]["uid"]
                    .as_str()
                    .context("PVC UID")?
                    .to_owned(),
            )
        } else {
            None
        };
        let activation = ActivationIntent::read(&statefulset)?;
        let recovering_fence = activation.as_ref().is_some_and(|intent| intent.active());
        if recovering_fence {
            let intent = activation.as_ref().context("activation checkpoint")?;
            ensure!(
                matches!(operation, Operation::Activate | Operation::MarkActivated)
                    && intent.phase == ActivationPhase::Fenced
                    && intent.request_digest == request_digest
                    && target_instance.as_ref().is_some_and(
                        |text| day2::digest(text.as_bytes()) == intent.target_instance_digest
                    )
                    && intent.controller_uid == statefulset["metadata"]["uid"]
                    && intent.template_digest == activation::template_digest(&statefulset)?
                    && Some(intent.pvc_uid.as_str()) == pvc_uid.as_deref()
                    && replicas == 0,
                "activation_recovery_required: recover the saved activation journal before starting another operation"
            );
        }
        if operation == Operation::Activate {
            let services: Value =
                serde_json::from_str(&kubectl(&["get", "services", "-o", "json"])?)?;
            let labels = serde_json::Map::from_iter([
                (
                    "app.kubernetes.io/name".to_owned(),
                    json!("day2-maintenance"),
                ),
                ("app.kubernetes.io/part-of".to_owned(), json!("day2")),
                (
                    request.pod_label.key.clone(),
                    json!(request.pod_label.value),
                ),
            ]);
            ensure!(
                services["items"]
                    .as_array()
                    .context("services")?
                    .iter()
                    .all(|service| {
                        !service["spec"]["selector"]
                            .as_object()
                            .is_some_and(|selector| {
                                !selector.is_empty()
                                    && selector
                                        .iter()
                                        .all(|(key, value)| labels.get(key) == Some(value))
                            })
                    }),
                "maintenance_pod_must_not_match_a_service"
            );
        }
        if operation == Operation::Rollout {
            let expected = request
                .placement
                .as_ref()
                .context("captured placement required")?;
            ensure!(
                statefulset["metadata"]["uid"] == expected.controller_uid
                    && pvc_uid.as_deref() == Some(expected.pvc_uid.as_str())
                    && online_node.as_deref() == Some(expected.node.as_str()),
                "rollout_captured_placement_changed"
            );
            let others: Value = serde_json::from_str(&kubectl(&[
                "get",
                "pods",
                "-l",
                MAINTENANCE_LABEL,
                "-o",
                "json",
            ])?)?;
            ensure!(
                others["items"]
                    .as_array()
                    .context("maintenance pods")?
                    .iter()
                    .all(
                        |pod| pod["metadata"]["annotations"]["day2.dev/rollout-request"]
                            == request_digest
                    ),
                "another_maintenance_session_is_running"
            );
        } else {
            let others = kubectl(&["get", "pods", "-l", MAINTENANCE_LABEL, "-o", "name"])?;
            ensure!(
                others.trim().is_empty(),
                "another maintenance session is running in {namespace}: {}",
                others.trim()
            );
        }
        let work = tempfile::Builder::new()
            .prefix("day2-maintenance-")
            .tempdir()?;
        let nonce = day2::digest(work.path().as_os_str().as_encoded_bytes());
        let stamp = format!(
            "{}-{}",
            &nonce[7..23],
            crate::offsite::utc_stamp(SystemTime::now())?
        );
        let pod = format!("day2-maintenance-{}", stamp.to_ascii_lowercase());
        let backup_root = match &request.backup_dir {
            Some(directory) => directory.clone(),
            None => PathBuf::from(std::env::var_os("HOME").context("HOME")?)
                .join("day2-backups")
                .join(&request.namespace),
        };
        fs::create_dir_all(&backup_root)?;
        private_directory(&backup_root)?;
        let journal = backup_root.join(format!("{stamp}.session.json"));
        ensure!(!journal.exists(), "session journal already exists");
        let mut session = Self {
            tools,
            request_file: request_file.to_path_buf(),
            request_json: String::from_utf8(request_bytes)?,
            request_digest,
            operation,
            stamp,
            pod,
            replicas,
            work,
            backup_root,
            journal,
            events: Vec::new(),
            target_instance,
            controller: statefulset,
            online_node,
            pvc_uid,
            incumbent,
            activation,
            state: State {
                fenced: recovering_fence,
                ..State::default()
            },
            request,
        };
        session.record(
            "open",
            json!({"operation":operation.name(),"namespace":session.request.namespace,
                "statefulset":session.request.statefulset,"replicas":replicas,
                "app_image":session.request.app_image,"artifact":session.request.artifact_id,
                "target":session.request.target.as_ref().map(|target| json!({"app_image":target.app_image,"artifact":target.artifact_id})),
                "activated":marked,"pod":session.pod,"operator":session.request.operator}),
        )?;
        eprintln!(
            "== {} {}/{} ({replicas} replica(s)); journal {}",
            operation.name(),
            session.request.namespace,
            session.request.statefulset,
            session.journal.display()
        );
        Ok(session)
    }

    fn record(&mut self, step: &str, detail: Value) -> Result<()> {
        self.events.push(json!({
            "step": step,
            "at": crate::offsite::utc_stamp(SystemTime::now())?,
            "detail": detail,
        }));
        let temporary = self.journal.with_extension("json.tmp");
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&serde_json::to_vec_pretty(&json!({
                "format": 2,
                "session": self.stamp,
                "request_digest": self.request_digest,
                "request": self.request_json,
                "target_instance": self.target_instance,
                "source_controller_uid": self.controller["metadata"]["uid"],
                "source_template": self.controller["spec"]["template"],
                "source_pvc_uid": self.pvc_uid,
                "source_pod": self.incumbent,
                "original_replicas": self.activation.as_ref().filter(|_| self.state.fenced)
                    .map_or(self.replicas, |intent| intent.replicas),
                "events": self.events,
            }))?)?;
            file.sync_all()?;
        }
        fs::rename(&temporary, &self.journal)?;
        fs::File::open(self.journal.parent().context("journal parent")?)?.sync_all()?;
        Ok(())
    }

    fn kubectl(
        &mut self,
        args: &[&str],
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<String> {
        let mut full = vec!["-n".to_owned(), self.request.namespace.clone()];
        full.extend(args.iter().map(|arg| (*arg).to_owned()));
        self.tools.cluster.kubectl(&full, stdin, timeout)
    }

    pub fn artifacts(&mut self) -> Result<Value> {
        ensure!(!self.state.artifacts, "artifacts already fetched");
        eprintln!("== artifacts from the app images (digest-verified)");
        let directory = self.work.path().join("artifacts");
        fs::create_dir_all(&directory)?;
        let mut fetched = vec![fetch_artifact(
            self.tools.registry.as_mut(),
            &self.request.app_image,
            &self.request.artifact_id,
            &directory,
        )?];
        // The pod holds each artifact once.
        let mut bytes = fetched[0]["bytes"].as_u64().unwrap_or_default();
        if let Some(target) = self.request.target.clone() {
            // A target image of the running artifact must carry it too.
            let same = target.artifact_id == self.request.artifact_id;
            let output = if same {
                self.work.path().join("target-image")
            } else {
                directory.clone()
            };
            let receipt = fetch_artifact(
                self.tools.registry.as_mut(),
                &target.app_image,
                &target.artifact_id,
                &output,
            )?;
            if !same {
                bytes += receipt["bytes"].as_u64().unwrap_or_default();
            }
            fetched.push(receipt);
        }
        // Reconciliation may have updated the mutable bootstrap ConfigMap
        // after completion but before CI recorded ready. The owned target's
        // selected instance remains exact; never reconstruct or replan it.
        let released = self.operation == Operation::Rollout
            && self.controller["metadata"]["annotations"]["day2.dev/rollout"].as_str()
                == self.request.request_id.as_deref()
            && self.request.target.as_ref().is_some_and(|target| {
                self.controller["spec"]["template"]["spec"]["containers"]
                    .as_array()
                    .is_some_and(|containers| {
                        containers
                            .iter()
                            .any(|c| c["name"] == "day2" && c["image"] == target.app_image)
                    })
            });
        let current_configmap = if released {
            self.controller["spec"]["template"]["spec"]["volumes"]
                .as_array()
                .context("released volumes")?
                .iter()
                .find(|volume| volume["name"] == "instance")
                .and_then(|volume| volume["configMap"]["name"].as_str())
                .context("released instance ConfigMap")?
                .to_owned()
        } else {
            self.request.configmap.clone()
        };
        let configmap: Value = serde_json::from_str(&self.kubectl(
            &["get", "configmap", &current_configmap, "-o", "json"],
            None,
            Duration::from_secs(60),
        )?)?;
        let current = configmap["data"]["instance.json"]
            .as_str()
            .with_context(|| {
                format!("ConfigMap {} has no instance.json", self.request.configmap)
            })?;
        let value: Value = serde_json::from_str(current).context("current instance is not JSON")?;
        if released {
            ensure!(
                Some(current) == self.target_instance.as_deref(),
                "rollout_current_instance_changed"
            );
        } else {
            ensure!(
                value["apps"][&self.request.app]["artifact"]
                    == format!("artifacts/{}", self.request.artifact_id),
                "the ConfigMap's instance does not bind {} to artifact_id",
                self.request.app
            );
        }
        fs::write(self.work.path().join("current-instance.json"), current)?;
        if let Some(text) = &self.target_instance {
            fs::write(self.work.path().join("instance.json"), text)?;
        }
        self.state.artifacts = true;
        self.state.artifact_bytes = bytes;
        self.record("artifacts", json!(fetched))?;
        Ok(json!({"artifacts": fetched}))
    }

    pub fn stop(&mut self) -> Result<Value> {
        ensure!(
            self.state.artifacts && !self.state.stopped,
            "stop follows the artifact fetch, once"
        );
        if self.operation == Operation::Rollout {
            self.state.stopped = true; // Ordering marker; no workload is scaled.
            self.record("incumbent-kept-serving", json!({"node":self.online_node}))?;
            return Ok(json!({"incumbent_running":true}));
        }
        let prepared_controller = if self.operation == Operation::Activate {
            ensure!(
                self.state.pod && self.state.scratch.is_some(),
                "activation_helper_must_be_prepared_before_stop"
            );
            Some(self.prepared_controller()?)
        } else {
            None
        };
        eprintln!(
            "== stopping {} (was {} replica(s))",
            self.request.statefulset, self.replicas
        );
        // Recorded first: from here any exit restores the replicas.
        self.state.stopped = true;
        self.record("stop", json!({"replicas": self.replicas}))?;
        let statefulset = self.request.statefulset.clone();
        if let Some(controller) = prepared_controller {
            // The stop cannot silently adopt a replacement or a concurrent
            // template edit between revalidation and scaling.
            let previous = self
                .activation
                .clone()
                .context("activation preparation intent")?;
            let mut stopped = previous.clone();
            if !self.state.fenced {
                stopped.phase = ActivationPhase::Stopped;
            }
            self.activation = Some(stopped.clone());
            activation::replace(
                self.tools.cluster.as_mut(),
                &self.request,
                &controller,
                Some(&previous),
                &stopped,
                Some(0),
            )?;
        } else if self.operation == Operation::MarkActivated {
            let current = self.activation_controller()?;
            self.require_activation_owner(&current)?;
            ensure!(
                current["metadata"]["uid"] == self.controller["metadata"]["uid"]
                    && current["spec"]["template"] == self.controller["spec"]["template"]
                    && current["spec"]["replicas"] == 0,
                "mark_activated_source_changed"
            );
        } else {
            self.kubectl(
                &[
                    "scale",
                    self.request.kind(self.operation).resource(),
                    &statefulset,
                    "--replicas=0",
                ],
                None,
                Duration::from_secs(60),
            )?;
        }
        if self.request.kind(self.operation) == WorkloadKind::Deployment {
            self.kubectl(
                &[
                    "wait",
                    "--for=delete",
                    "pods",
                    "-l",
                    &format!("app.kubernetes.io/name={statefulset}"),
                    "--timeout=300s",
                ],
                None,
                Duration::from_secs(330),
            )?;
        } else {
            for ordinal in 0..self.replicas.max(1) {
                let pod = format!("{statefulset}-{ordinal}");
                let started = Instant::now();
                loop {
                    let found = self.kubectl(
                        &["get", "pod", &pod, "--ignore-not-found", "-o", "name"],
                        None,
                        Duration::from_secs(60),
                    )?;
                    if found.trim().is_empty() {
                        break;
                    }
                    ensure!(
                        started.elapsed() < Duration::from_secs(300),
                        "{pod} did not stop"
                    );
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
        }
        Ok(json!({"stopped": statefulset}))
    }

    /// Recheck every source binding after the potentially slow helper pull and
    /// copy, while the source is still serving. Never stop a replacement.
    fn prepared_controller(&mut self) -> Result<Value> {
        let resource = self.request.kind(self.operation).resource();
        let name = self.request.statefulset.clone();
        let controller: Value = serde_json::from_str(&self.kubectl(
            &["get", resource, &name, "-o", "json"],
            None,
            Duration::from_secs(60),
        )?)?;
        ensure!(
            controller["metadata"]["uid"].is_string()
                && controller["metadata"]["uid"] == self.controller["metadata"]["uid"]
                && controller["spec"]["template"] == self.controller["spec"]["template"]
                && controller["spec"]["replicas"] == self.replicas,
            "activation_source_controller_changed"
        );
        self.require_activation_owner(&controller)?;
        self.require_helper_identity()?;
        self.source_storage_bindings()?;
        if let Some(incumbent) = self.incumbent.clone() {
            let name = incumbent["metadata"]["name"]
                .as_str()
                .context("incumbent name")?;
            let pod: Value = serde_json::from_str(&self.kubectl(
                &["get", "pod", name, "-o", "json"],
                None,
                Duration::from_secs(60),
            )?)?;
            ensure!(
                pod["metadata"]["uid"] == incumbent["metadata"]["uid"]
                    && pod["metadata"]["deletionTimestamp"].is_null()
                    && pod["spec"] == incumbent["spec"]
                    && pod["status"]["conditions"]
                        .as_array()
                        .is_some_and(|conditions| {
                            conditions.iter().any(|condition| {
                                condition["type"] == "Ready" && condition["status"] == "True"
                            })
                        }),
                "activation_source_pod_changed"
            );
        }
        Ok(controller)
    }

    fn source_storage_bindings(&mut self) -> Result<()> {
        let pvc = self.request.pvc.clone();
        let claim: Value = serde_json::from_str(&self.kubectl(
            &["get", "pvc", &pvc, "-o", "json"],
            None,
            Duration::from_secs(60),
        )?)?;
        ensure!(
            claim["metadata"]["uid"].as_str() == self.pvc_uid.as_deref()
                && claim["status"]["phase"] == "Bound",
            "activation_source_claim_changed"
        );
        let configmap = self.request.configmap.clone();
        let config: Value = serde_json::from_str(&self.kubectl(
            &["get", "configmap", &configmap, "-o", "json"],
            None,
            Duration::from_secs(60),
        )?)?;
        ensure!(
            config["data"]["instance.json"].as_str()
                == Some(
                    fs::read_to_string(self.work.path().join("current-instance.json"))?.as_str()
                ),
            "activation_source_instance_changed"
        );
        Ok(())
    }

    fn require_activation_owner(&self, controller: &Value) -> Result<()> {
        let intent = self
            .activation
            .as_ref()
            .context("activation preparation intent required")?;
        ensure!(
            intent.owner == self.stamp
                && controller["metadata"]["uid"] == intent.controller_uid
                && activation::template_digest(controller)? == intent.template_digest
                && ActivationIntent::read(controller)?.as_ref() == Some(intent),
            "activation_checkpoint_changed"
        );
        Ok(())
    }

    fn activation_controller(&mut self) -> Result<Value> {
        let resource = self.request.kind(self.operation).resource();
        let name = self.request.statefulset.clone();
        Ok(serde_json::from_str(&self.kubectl(
            &["get", resource, &name, "-o", "json"],
            None,
            Duration::from_secs(60),
        )?)?)
    }

    fn check_activation_owner(&mut self) -> Result<()> {
        if matches!(
            self.operation,
            Operation::Activate | Operation::MarkActivated
        ) {
            let live = self.activation_controller()?;
            self.require_activation_owner(&live)?;
            if self.state.pod {
                self.require_helper_identity()?;
            }
        }
        Ok(())
    }

    fn require_helper_identity(&mut self) -> Result<()> {
        let expected = self
            .activation
            .as_ref()
            .and_then(|intent| intent.pod_uid.clone())
            .context("activation_helper_identity_required")?;
        let name = self.pod.clone();
        let pod: Value = serde_json::from_str(&self.kubectl(
            &["get", "pod", &name, "-o", "json"],
            None,
            Duration::from_secs(60),
        )?)?;
        ensure!(
            pod["metadata"]["uid"] == expected
                && pod["metadata"]["deletionTimestamp"].is_null()
                && pod["status"]["conditions"]
                    .as_array()
                    .is_some_and(|conditions| {
                        conditions.iter().any(|condition| {
                            condition["type"] == "Ready" && condition["status"] == "True"
                        })
                    })
                && pod["metadata"]["annotations"]["day2.dev/rollout-request"]
                    == self.request_digest
                && pod["spec"]["containers"]
                    .as_array()
                    .is_some_and(|containers| {
                        containers.len() == 1
                            && containers[0]["image"] == self.request.tooling_image
                    }),
            "activation_helper_changed"
        );
        Ok(())
    }

    pub fn begin_preparation(&mut self) -> Result<Value> {
        ensure!(
            matches!(
                self.operation,
                Operation::Activate | Operation::MarkActivated
            ) && self.state.artifacts
                && !self.state.pod
                && !self.state.stopped,
            "activation_artifacts_required_before_preparation"
        );
        let live = self.activation_controller()?;
        if self.operation == Operation::MarkActivated {
            ensure!(self.replicas == 0, "mark_activated_must_remain_stopped");
            self.state.fenced = true;
        }
        ensure!(
            ActivationIntent::read(&live)? == self.activation
                && live["spec"]["replicas"] == self.replicas
                && self
                    .activation
                    .as_ref()
                    .is_none_or(|intent| !intent.active()
                        || (self.state.fenced && intent.phase == ActivationPhase::Fenced)),
            "another_activation_is_running"
        );
        self.source_storage_bindings()?;
        let instance = fs::read(self.work.path().join("current-instance.json"))?;
        let intent = ActivationIntent {
            format: 1,
            owner: self.stamp.clone(),
            request_digest: self.request_digest.clone(),
            target_instance_digest: day2::digest(
                self.target_instance
                    .as_ref()
                    .context("target instance")?
                    .as_bytes(),
            ),
            controller_uid: self.controller["metadata"]["uid"]
                .as_str()
                .context("controller UID")?
                .into(),
            template_digest: activation::template_digest(&self.controller)?,
            source_instance_digest: day2::digest(&instance),
            pvc_uid: self.pvc_uid.clone().context("PVC UID")?,
            replicas: self
                .activation
                .as_ref()
                .filter(|_| self.state.fenced)
                .map_or(self.replicas, |intent| intent.replicas),
            pod: self.pod.clone(),
            pod_uid: None,
            phase: if self.state.fenced {
                ActivationPhase::Fenced
            } else {
                ActivationPhase::Prepared
            },
        };
        self.record("preparation-intent", serde_json::to_value(&intent)?)?;
        activation::replace(
            self.tools.cluster.as_mut(),
            &self.request,
            &live,
            self.activation.as_ref(),
            &intent,
            None,
        )?;
        self.activation = Some(intent);
        Ok(json!({"prepared_intent":true}))
    }

    fn render_pod(&self, pod: &str, scratch: u64) -> Result<String> {
        let deadline = POD_DEADLINE_SECONDS.to_string();
        let (ephemeral, scratch) = (mebibytes(scratch + CONTAINER_EPHEMERAL), mebibytes(scratch));
        let values = [
            ("DAY2_MAINT_NAMESPACE", self.request.namespace.as_str()),
            ("DAY2_MAINT_POD", pod),
            (
                "DAY2_MAINT_TOOLING_IMAGE",
                self.request.tooling_image.as_str(),
            ),
            ("DAY2_MAINT_PVC", self.request.pvc.as_str()),
            (
                "DAY2_MAINT_SERVICE_LABEL_KEY",
                self.request.pod_label.key.as_str(),
            ),
            (
                "DAY2_MAINT_SERVICE_LABEL_VALUE",
                self.request.pod_label.value.as_str(),
            ),
            ("DAY2_MAINT_DEADLINE_SECONDS", deadline.as_str()),
            ("DAY2_MAINT_SCRATCH", scratch.as_str()),
            ("DAY2_MAINT_EPHEMERAL_STORAGE", ephemeral.as_str()),
        ];
        let rendered = render_template(POD_TEMPLATE, &values)?;
        let rendered = if matches!(
            self.operation,
            Operation::Activate | Operation::MarkActivated
        ) {
            let target = self
                .request
                .target
                .as_ref()
                .context("target runtime image")?;
            let init = render_template(
                IMAGE_INIT_TEMPLATE,
                &[("DAY2_MAINT_TARGET_IMAGE", target.app_image.as_str())],
            )?;
            rendered.replacen("  containers:\n", &format!("{init}  containers:\n"), 1)
        } else {
            rendered
        };
        let rendered = if self.online_node.is_some()
            || matches!(
                self.operation,
                Operation::Activate | Operation::MarkActivated
            ) {
            rendered.replacen(
                "\nmetadata:\n",
                &format!(
                    "\nmetadata:\n  annotations:\n    day2.dev/rollout-request: {}\n",
                    self.request_digest
                ),
                1,
            )
        } else {
            rendered
        };
        if let Some(node) = &self.online_node {
            ensure!(label_value(node), "invalid_incumbent_node");
            if self.operation == Operation::Activate {
                // Use the scheduler, with an exact node-name field constraint:
                // nodeName would skip its CPU/memory/storage capacity checks.
                return Ok(rendered.replacen("\nspec:\n", &format!(
                    "\nspec:\n  affinity:\n    nodeAffinity:\n      requiredDuringSchedulingIgnoredDuringExecution:\n        nodeSelectorTerms:\n          - matchFields:\n              - key: metadata.name\n                operator: In\n                values: [{node}]\n"), 1));
            }
            return Ok(rendered.replacen(
                "\nspec:\n",
                &format!("\nspec:\n  nodeName: {node}\n"),
                1,
            ));
        }
        Ok(rendered)
    }

    /// Apply a rendered pod and wait until it runs. A pod that never starts
    /// fails with the scheduler's reason, e.g. no node with the ephemeral
    /// storage it requests.
    fn run_pod(&mut self, pod: &str, manifest: &str, scratch: u64) -> Result<()> {
        let size = || {
            format!(
                "pod {pod} requests {} of ephemeral storage ({} scratch)",
                mebibytes(scratch + CONTAINER_EPHEMERAL),
                mebibytes(scratch)
            )
        };
        self.kubectl(
            &["apply", "-f", "-"],
            Some(manifest.as_bytes()),
            Duration::from_secs(60),
        )
        .with_context(|| format!("{}; the namespace's LimitRange and ResourceQuota (app-edge resource_guardrails) must admit it", size()))?;
        let waited = self.kubectl(
            &[
                "wait",
                "--for=condition=Ready",
                &format!("pod/{pod}"),
                "--timeout=600s",
            ],
            None,
            Duration::from_secs(660),
        );
        if let Err(error) = waited {
            let scheduling = self
                .kubectl(
                    &["get", "pod", pod, "-o", "json"],
                    None,
                    Duration::from_secs(60),
                )
                .ok()
                .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                .and_then(|status| {
                    status["status"]["conditions"]
                        .as_array()?
                        .iter()
                        .find(|condition| {
                            condition["type"] == "PodScheduled" && condition["status"] != "True"
                        })
                        .and_then(|condition| condition["message"].as_str().map(str::to_owned))
                });
            return Err(match scheduling {
                Some(reason) => error.context(format!("{}; not scheduled: {reason}", size())),
                None => error.context(size()),
            });
        }
        Ok(())
    }

    /// File-size metadata only: activation measures while the incumbent serves,
    /// on that same node. No SQLite connection or serving lease is opened.
    pub fn measure(&mut self) -> Result<Value> {
        ensure!(
            self.state.artifacts
                && !self.state.pod
                && self.state.scratch.is_none()
                && (if self.operation == Operation::Activate {
                    !self.state.stopped
                } else {
                    self.state.stopped
                }),
            "activation measures before the stop; other operations after it, once, before the pod"
        );
        let copies = self.operation.store_copies();
        self.check_activation_owner()?;
        let stores = if copies == 0 {
            BTreeMap::new()
        } else {
            self.measure_stores().map_err(|error| {
                anyhow::anyhow!(
                    "maintenance_scratch_unmeasured: the stores of {} on {} could not be measured, so the maintenance pod cannot be sized; no migration was attempted for {}: {error:#}",
                    self.request.app,
                    self.request.pvc,
                    self.request.statefulset
                )
            })?
        };
        let artifacts = self.state.artifact_bytes;
        let scratch = scratch_bytes(copies, stores.values().sum(), artifacts);
        let sized = json!({
            "stores": stores,
            "copies": copies,
            "artifacts": artifacts,
            "scratch": mebibytes(scratch),
            "ephemeral_storage": mebibytes(scratch + CONTAINER_EPHEMERAL),
        });
        eprintln!(
            "   scratch {} for {} copies of {} bytes of stores",
            mebibytes(scratch),
            copies,
            stores.values().sum::<u64>()
        );
        self.state.scratch = Some(scratch);
        self.record("scratch", sized.clone())?;
        Ok(sized)
    }

    fn probe(&self) -> String {
        format!("{}-measure", self.pod)
    }

    fn measure_stores(&mut self) -> Result<BTreeMap<String, u64>> {
        let probe = self.probe();
        eprintln!(
            "== measuring the stores of {} on {}",
            self.request.app, self.request.pvc
        );
        let manifest = self.render_pod(&probe, PROBE_SCRATCH)?;
        // Recorded first: from here any exit deletes the probe.
        self.state.probe = true;
        self.record("measure", json!({"pod": probe}))?;
        self.run_pod(&probe, &manifest, PROBE_SCRATCH)?;
        let stores = self.read_store_sizes(&probe)?;
        self.kubectl(
            &["delete", "pod", &probe, "--ignore-not-found", "--wait=true"],
            None,
            Duration::from_secs(300),
        )?;
        self.state.probe = false;
        Ok(stores)
    }

    fn read_store_sizes(&mut self, pod: &str) -> Result<BTreeMap<String, u64>> {
        let listing = self.kubectl(
            &[
                "exec",
                pod,
                "--",
                "find",
                STATE,
                "-maxdepth",
                "1",
                "-type",
                "f",
                "-exec",
                "stat",
                "-c",
                "%s %n",
                "{}",
                "+",
            ],
            None,
            Duration::from_secs(300),
        )?;
        store_sizes(&listing, &self.request.app)
    }

    /// The live measurement reserves space; it is never the final recovery
    /// checkpoint. Refuse growth beyond that reservation before opening a DB.
    pub fn verify_preparation(&mut self) -> Result<Value> {
        ensure!(
            self.operation == Operation::Activate
                && self.state.stopped
                && self.state.pod
                && !self.state.preparation_verified,
            "stopped_prepared_activation_required"
        );
        self.check_activation_owner()?;
        let pod = self.pod.clone();
        let stores = self.read_store_sizes(&pod)?;
        let needed = scratch_bytes(
            self.operation.store_copies(),
            stores.values().sum(),
            self.state.artifact_bytes,
        );
        let reserved = self.state.scratch.context("prepared scratch")?;
        ensure!(
            needed <= reserved,
            "activation_preparation_outgrown: need {}, reserved {}; source will be restored before migration",
            mebibytes(needed),
            mebibytes(reserved)
        );
        self.record(
            "preparation-verified",
            json!({"stores":stores,"reserved":reserved,"required":needed}),
        )?;
        self.state.preparation_verified = true;
        Ok(json!({"prepared":true}))
    }

    pub fn start_pod(&mut self) -> Result<Value> {
        ensure!(
            !self.state.pod
                && (if self.operation == Operation::Activate {
                    !self.state.stopped
                } else {
                    self.state.stopped
                }),
            "activation prepares its pod before the stop; other operations after it, once"
        );
        self.check_activation_owner()?;
        let scratch = self
            .state
            .scratch
            .context("the pod follows the store's measurement")?;
        eprintln!(
            "== maintenance pod {} ({} scratch)",
            self.pod,
            mebibytes(scratch)
        );
        let pod = self.pod.clone();
        let manifest = self.render_pod(&pod, scratch)?;
        // Recorded first: from here any exit deletes the pod.
        self.state.pod = true;
        self.record(
            "pod",
            json!({"pod": self.pod, "tooling_image": self.request.tooling_image, "scratch": mebibytes(scratch)}),
        )?;
        self.run_pod(&pod, &manifest, scratch)?;
        if matches!(
            self.operation,
            Operation::Activate | Operation::MarkActivated
        ) {
            let current: Value = serde_json::from_str(&self.kubectl(
                &["get", "pod", &pod, "-o", "json"],
                None,
                Duration::from_secs(60),
            )?)?;
            let uid = current["metadata"]["uid"]
                .as_str()
                .context("activation helper UID")?;
            ensure!(
                !uid.is_empty() && uid.len() <= 128,
                "invalid_activation_helper_uid"
            );
            let previous = self.activation.clone().context("activation checkpoint")?;
            let mut bound = previous.clone();
            bound.pod_uid = Some(uid.into());
            let live = self.activation_controller()?;
            self.require_activation_owner(&live)?;
            activation::replace(
                self.tools.cluster.as_mut(),
                &self.request,
                &live,
                Some(&previous),
                &bound,
                None,
            )?;
            self.activation = Some(bound);
            self.require_helper_identity()?;
        }
        self.exec(
            &["mkdir", "-p", &format!("{ROOT}/artifacts")],
            Duration::from_secs(60),
        )?;
        let local = self.work.path().join("artifacts");
        let mut ids = vec![self.request.artifact_id.clone()];
        ids.extend(
            self.request
                .target
                .as_ref()
                .map(|target| target.artifact_id.clone()),
        );
        ids.dedup();
        for id in ids {
            let remote = format!("{ROOT}/artifacts/{id}");
            self.copy_in(&local.join(&id), &remote)?;
            self.verify_remote(&local.join(&id), &remote)?;
        }
        let mut instances = vec![("current-instance.json", CURRENT)];
        if self.target_instance.is_some() {
            instances.push(("instance.json", TARGET));
        }
        for (name, remote) in instances {
            let file = self.work.path().join(name);
            self.copy_in(&file, remote)?;
            let sums = self.exec(&["sha256sum", remote], Duration::from_secs(60))?;
            ensure!(
                sums.split_whitespace()
                    .next()
                    .map(|hex| format!("sha256:{hex}"))
                    == Some(day2::digest(&fs::read(&file)?)),
                "{remote} differs in the pod"
            );
        }
        Ok(json!({"pod": self.pod}))
    }

    fn exec(&mut self, argv: &[&str], timeout: Duration) -> Result<String> {
        let pod = self.pod.clone();
        let mut args = vec!["exec", pod.as_str(), "--"];
        args.extend_from_slice(argv);
        self.kubectl(&args, None, timeout)
    }

    fn copy_in(&mut self, local: &Path, remote: &str) -> Result<()> {
        let source = local.to_str().context("non UTF-8 local path")?.to_owned();
        let destination = format!("{}:{remote}", self.pod);
        self.kubectl(
            &["cp", "--retries=5", &source, &destination],
            None,
            Duration::from_secs(600),
        )?;
        Ok(())
    }

    fn remote_sums(&mut self, remote: &str) -> Result<BTreeMap<String, String>> {
        let output = self.exec(
            &[
                "find",
                remote,
                "-type",
                "f",
                "-exec",
                "sha256sum",
                "{}",
                "+",
            ],
            Duration::from_secs(300),
        )?;
        remote_manifest(&output, remote)
    }

    fn verify_remote(&mut self, local: &Path, remote: &str) -> Result<()> {
        let theirs = self.remote_sums(remote)?;
        ensure!(
            local_manifest(local)? == theirs,
            "{remote} in the pod differs from what was fetched"
        );
        Ok(())
    }

    fn host_workflow(&mut self, args: &[&str]) -> Result<Value> {
        let request =
            json!({"protocol":1,"action":"workflow","input":serde_json::to_string(args)?})
                .to_string();
        let output = self.exec(&[HOST, &request], Duration::from_secs(1_800))?;
        let response: Value = serde_json::from_str(output.trim()).context("day2-host response")?;
        // day2-host exits 0 even when the workflow fails.
        ensure!(
            response["ok"] == true,
            "day2-host: {}",
            response["error"].as_str().unwrap_or("workflow failed")
        );
        let result = response["result"].as_str().unwrap_or("{}");
        Ok(serde_json::from_str(result).unwrap_or_else(|_| Value::String(result.to_owned())))
    }

    fn stamp_json(&self) -> Result<String> {
        Ok(serde_json::to_string(
            self.state
                .stamp
                .as_ref()
                .context("read the authority stamp first")?,
        )?)
    }

    pub fn workflow(&mut self, name: &str) -> Result<Value> {
        ensure!(
            self.state.pod
                && self.state.stopped
                && !self.state.finished
                && (self.operation != Operation::Activate || self.state.preparation_verified),
            "workflows require the stop and, for activation, verified preparation"
        );
        self.check_activation_owner()?;
        let app = self.request.app.clone();
        let operator = self.request.operator.clone();
        let request_id = self.request.request_id.clone().unwrap_or_default();
        match name {
            "backup" => {
                ensure!(
                    matches!(
                        self.operation,
                        Operation::Backup
                            | Operation::AuthorityApply
                            | Operation::Activate
                            | Operation::Rollout
                    ) && !self.state.pod_backup,
                    "one backup per session, not for inspect or mark-activated"
                );
                eprintln!("== backup (current instance)");
                let output = format!("{ROOT}/backup-{}", self.stamp);
                let receipt = self.host_workflow(&["backup", CURRENT, &app, &output])?;
                self.state.pod_backup = true;
                self.record("backup", receipt.clone())?;
                Ok(receipt)
            }
            "authority-inspect" => {
                let inspected = self.host_workflow(&["authority", "inspect", CURRENT, &app])?;
                let stamp = inspected["active"]["stamp"].clone();
                ensure!(stamp.is_object(), "no active authority stamp");
                let document = &inspected["active"]["document"];
                let summary = json!({
                    "scope": inspected["scope"],
                    "stamp": stamp,
                    "artifact": inspected["active"]["artifact_id"],
                    "readers": document["readers"],
                    "writers": document["writers"],
                    "operations": document["policy"]["operations"].as_object().map_or(0, |ops| ops.len()),
                });
                self.state.stamp = Some(stamp);
                self.state.active_artifact = inspected["active"]["artifact_id"]
                    .as_str()
                    .map(str::to_owned);
                self.record("authority-inspect", summary.clone())?;
                if self.operation == Operation::Inspect {
                    self.state.result = Some(summary.clone());
                }
                Ok(summary)
            }
            "authority-apply" => {
                ensure!(
                    self.operation == Operation::AuthorityApply
                        && self.state.backup.is_some()
                        && self.state.confirmed,
                    "authority-apply needs a verified backup and a confirmation"
                );
                let expected = self.stamp_json()?;
                eprintln!("== authority apply (expected {expected})");
                self.record(
                    "authority-apply",
                    json!({"expected": expected, "request_id": request_id}),
                )?;
                let receipt = self.host_workflow(&[
                    "authority",
                    "apply",
                    CURRENT,
                    &app,
                    &operator,
                    &expected,
                    &request_id,
                ])?;
                self.state.stamp = None;
                self.state.result = Some(receipt.clone());
                self.record("authority-applied", receipt.clone())?;
                Ok(receipt)
            }
            "authority-activate" => {
                ensure!(
                    self.operation == Operation::Activate && self.state.migrated,
                    "authority-activate follows the migration"
                );
                let target = self.request.target.clone().context("target")?;
                let expected = self.stamp_json()?;
                eprintln!("== authority activate (expected {expected})");
                self.record(
                    "authority-activate",
                    json!({"expected": expected, "request_id": request_id}),
                )?;
                let artifact = format!("{ROOT}/artifacts/{}", target.artifact_id);
                let receipt = if self.request.kind(self.operation) == WorkloadKind::Deployment {
                    let raw = self.exec(
                        &[
                            DAY2,
                            "activate-maintenance",
                            CURRENT,
                            &app,
                            TARGET,
                            &artifact,
                            &operator,
                            &expected,
                            &request_id,
                        ],
                        Duration::from_secs(600),
                    )?;
                    serde_json::from_str(raw.trim())?
                } else {
                    self.host_workflow(&[
                        "authority",
                        "activate",
                        TARGET,
                        &app,
                        &artifact,
                        &operator,
                        &expected,
                        &request_id,
                    ])?
                };
                self.state.stamp = None;
                self.state.activated = true;
                self.state.result = Some(receipt.clone());
                self.record("authority-activated", receipt.clone())?;
                Ok(receipt)
            }
            _ => bail!("unknown maintenance workflow {name}"),
        }
    }

    pub fn copy_backup(&mut self) -> Result<Value> {
        ensure!(
            self.state.pod_backup && self.state.backup.is_none(),
            "copy follows the in-pod backup, once"
        );
        let remote = format!("{ROOT}/backup-{}", self.stamp);
        let destination = self.backup_root.join(&self.stamp);
        ensure!(
            !destination.exists(),
            "{} already exists",
            destination.display()
        );
        let theirs = self.remote_sums(&remote)?;
        let source = format!("{}:{remote}", self.pod);
        let local = destination
            .to_str()
            .context("non UTF-8 backup path")?
            .to_owned();
        // kubectl cp creates the destination (an existing one would nest).
        let copied = self.kubectl(
            &["cp", "--retries=5", &source, &local],
            None,
            Duration::from_secs(1_800),
        );
        if let Err(error) = copied {
            writable(&destination);
            let _ = fs::rename(
                &destination,
                self.backup_root.join(format!("{}.INCOMPLETE", self.stamp)),
            );
            return Err(
                error.context("copying the backup failed; the partial copy is marked INCOMPLETE")
            );
        }
        let ours = local_manifest(&destination)?;
        if ours != theirs {
            writable(&destination);
            let _ = fs::rename(
                &destination,
                self.backup_root.join(format!("{}.INCOMPLETE", self.stamp)),
            );
            bail!("the local backup copy differs from the pod's; marked INCOMPLETE and refused");
        }
        fs::copy(
            self.work.path().join("current-instance.json"),
            destination.join("instance.json"),
        )?;
        private(&destination)?;
        eprintln!("   verified backup copied to {}", destination.display());
        self.state.providers = ours
            .keys()
            .filter_map(|path| path.strip_prefix("providers/"))
            .map(str::to_owned)
            .collect();
        self.state.backup = Some(destination.clone());
        self.record(
            "backup-copied",
            json!({"directory": destination, "files": ours}),
        )?;
        Ok(json!({"backup": destination, "files": ours.len()}))
    }

    pub fn migration(&mut self, step: &str) -> Result<Value> {
        ensure!(
            matches!(self.operation, Operation::Activate | Operation::Rollout)
                && self.state.pod
                && self.state.stopped
                && (self.operation != Operation::Activate || self.state.preparation_verified),
            "migrations require stopped or rolling admission and verified activation preparation"
        );
        self.check_activation_owner()?;
        let target = self.request.target.clone().context("target")?;
        let artifact = format!("{ROOT}/artifacts/{}", target.artifact_id);
        let app = self.request.app.clone();
        match step {
            "plan" => {
                ensure!(
                    self.state.backup.is_some() && self.state.plan.is_none(),
                    "plan follows the verified backup, once"
                );
                eprintln!("== migration plan to {}", target.artifact_id);
                self.exec(
                    &[
                        DAY2,
                        "migration-plan",
                        if self.request.kind(self.operation) == WorkloadKind::Deployment {
                            CURRENT
                        } else {
                            TARGET
                        },
                        &app,
                        &artifact,
                        PLAN,
                    ],
                    Duration::from_secs(600),
                )?;
                let plan: Value =
                    serde_json::from_str(&self.exec(&["cat", PLAN], Duration::from_secs(60))?)?;
                if self.operation == Operation::Rollout {
                    ensure!(
                        plan["source_schema"] == plan["target_schema"]
                            && self.state.providers.is_empty(),
                        "rolling_release_requires_unchanged_schema_and_single_store"
                    );
                }
                let backup = self.state.backup.clone().context("backup")?;
                fs::write(
                    backup.join("migration-plan.json"),
                    serde_json::to_vec_pretty(&plan)?,
                )?;
                eprintln!("{}", serde_json::to_string_pretty(&plan)?);
                self.state.plan = Some(plan.clone());
                self.record("migration-plan", plan.clone())?;
                Ok(plan)
            }
            "apply" => {
                ensure!(
                    self.state.fenced && self.state.fence_entered && !self.state.migrated,
                    "migration apply needs the fence, once"
                );
                let receipt = self.exec(
                    &[
                        DAY2,
                        "migration-apply",
                        if self.request.kind(self.operation) == WorkloadKind::Deployment {
                            CURRENT
                        } else {
                            TARGET
                        },
                        &app,
                        &artifact,
                        PLAN,
                    ],
                    Duration::from_secs(1_800),
                )?;
                eprintln!("{}", receipt.trim());
                self.state.migrated = true;
                self.state.stamp = None;
                self.record("migration-applied", json!({"output": receipt.trim()}))?;
                Ok(json!({"applied": true}))
            }
            _ => bail!("migration step must be plan or apply"),
        }
    }

    /// Rehearse what the fence would commit to on a disposable copy, then open
    /// the copy with the target build's maintenance admission and the actual
    /// request operator. The copy is the verified
    /// in-pod backup, moved under the target instance once its verified local
    /// copy is the session's backup, and removed with it after the admission;
    /// it is migrated with the shown plan and activated for the target exactly
    /// as the real steps will be.
    /// Nothing outside the copy changes. A refusal fails the session before
    /// the confirmation and the fence, so the app is restored on its image.
    pub fn admission(&mut self) -> Result<Value> {
        ensure!(
            matches!(self.operation, Operation::Activate | Operation::Rollout)
                && self.state.plan.is_some()
                && !self.state.rehearsed
                && !self.state.confirmed,
            "the target's store admission follows the migration plan, once, before the confirmation"
        );
        let target = self.request.target.clone().context("target")?;
        eprintln!(
            "== store admission by {} (a migrated, activated copy of the backup)",
            target.artifact_id
        );
        self.state.rehearsed = true;
        self.record(
            "target-admission",
            json!({"artifact": target.artifact_id, "copy": ADMISSION}),
        )?;
        match self.rehearse(&target) {
            Ok(admitted) => {
                self.state.admission = Some(admitted.clone());
                self.record("target-admitted", admitted.clone())?;
                Ok(admitted)
            }
            Err(error) => {
                let cause = format!("{error:#}");
                self.record("target-admission-refused", json!({"error": cause}))?;
                bail!(
                    "target_store_admission_refused: artifact {} would not open the store of {}; nothing was migrated or activated and {} is restored on its image: {cause}",
                    target.artifact_id,
                    self.request.app,
                    self.request.statefulset
                )
            }
        }
    }

    fn rehearse(&mut self, target: &Target) -> Result<Value> {
        let app = self.request.app.clone();
        let operator = self.request.operator.clone();
        let request_id = self.request.request_id.clone().unwrap_or_default();
        let artifact = format!("{ROOT}/artifacts/{}", target.artifact_id);
        let backup = format!("{ROOT}/backup-{}", self.stamp);
        let state = format!("{ADMISSION}/.state");
        // No -p: a leftover copy is refused, never reused.
        self.exec(&["mkdir", ADMISSION, &state], Duration::from_secs(60))?;
        // A rolling runtime resolves its selected artifact beside its instance,
        // including while opening the source copy before rollout preparation.
        // Keep the rehearsal self-contained under the same reviewed bytes.
        self.exec(
            &[
                "cp",
                "-a",
                &format!("{ROOT}/artifacts"),
                &format!("{ADMISSION}/artifacts"),
            ],
            Duration::from_secs(300),
        )?;
        self.exec(
            &[
                "cp",
                if self.request.kind(self.operation) == WorkloadKind::Deployment {
                    CURRENT
                } else {
                    TARGET
                },
                ADMISSION_INSTANCE,
            ],
            Duration::from_secs(60),
        )?;
        let mut stores = vec![("app.sqlite".to_owned(), format!("{app}.sqlite"))];
        for name in self.state.providers.clone() {
            ensure!(
                day2::capabilities::LOCAL_PROVIDER_DATABASES.contains(&name.as_str()),
                "unknown provider store {name} in the backup"
            );
            stores.push((format!("providers/{name}"), name));
        }
        // Moved, not copied: the session's backup is the verified local copy,
        // and the in-pod one is not read again, so the rehearsal needs no
        // second copy of the store on the scratch volume.
        for (from, to) in stores {
            self.exec(
                &["mv", &format!("{backup}/{from}"), &format!("{state}/{to}")],
                Duration::from_secs(60),
            )?;
        }
        if self.operation == Operation::Rollout {
            let source_image = self.request.app_image.clone();
            self.exec(
                &[
                    DAY2,
                    "rollout-prepare",
                    ADMISSION_INSTANCE,
                    &app,
                    TARGET,
                    &source_image,
                    &target.app_image,
                    &request_id,
                    &operator,
                ],
                Duration::from_secs(600),
            )?;
            let path = self.work.path().join("rehearsal-placement.json");
            fs::write(
                &path,
                serde_json::to_vec(
                    &json!({"namespace":self.request.namespace,"controller_uid":self.controller["metadata"]["uid"],"pvc_uid":self.pvc_uid,"node":self.online_node,"request_digest":self.request_digest}),
                )?,
            )?;
            self.copy_in(&path, "/srv/day2/rehearsal-placement.json")?;
            self.exec(
                &[
                    DAY2,
                    "rollout-bind",
                    ADMISSION_INSTANCE,
                    &app,
                    &request_id,
                    "/srv/day2/rehearsal-placement.json",
                    &operator,
                ],
                Duration::from_secs(60),
            )?;
            self.exec(
                &[
                    DAY2,
                    "rollout-transition",
                    ADMISSION_INSTANCE,
                    &app,
                    &request_id,
                    "prepared",
                    "serving",
                    &operator,
                ],
                Duration::from_secs(60),
            )?;
            self.exec(&["cp", TARGET, ADMISSION_INSTANCE], Duration::from_secs(60))?;
        } else {
            self.exec(
                &[
                    DAY2,
                    "migration-apply",
                    ADMISSION_INSTANCE,
                    &app,
                    &artifact,
                    PLAN,
                ],
                Duration::from_secs(1_800),
            )?;
            let inspected =
                self.host_workflow(&["authority", "inspect", ADMISSION_INSTANCE, &app])?;
            let stamp = &inspected["active"]["stamp"];
            ensure!(stamp.is_object(), "no active authority stamp in the copy");
            let expected = serde_json::to_string(stamp)?;
            if self.request.kind(self.operation) == WorkloadKind::Deployment {
                self.exec(
                    &[
                        DAY2,
                        "activate-maintenance",
                        ADMISSION_INSTANCE,
                        &app,
                        TARGET,
                        &artifact,
                        &operator,
                        &expected,
                        &request_id,
                    ],
                    Duration::from_secs(600),
                )?;
            } else {
                self.host_workflow(&[
                    "authority",
                    "activate",
                    ADMISSION_INSTANCE,
                    &app,
                    &artifact,
                    &operator,
                    &expected,
                    &request_id,
                ])?;
            }
            if self.request.kind(self.operation) == WorkloadKind::Deployment {
                self.exec(&["cp", TARGET, ADMISSION_INSTANCE], Duration::from_secs(60))?;
            }
        }
        // Rehearse the same maintenance operation and operator used after the
        // fence, including for exclusive StatefulSet activation.
        let admission_args = if self.operation == Operation::Activate {
            vec![
                DAY2,
                "admit-maintenance",
                ADMISSION_INSTANCE,
                &app,
                &operator,
            ]
        } else {
            vec![DAY2, "admit", ADMISSION_INSTANCE, &app]
        };
        let output = self.exec(&admission_args, Duration::from_secs(600))?;
        let admitted: Value = serde_json::from_str(output.trim()).context("day2 admit output")?;
        ensure!(
            admitted["admitted"] == true
                && admitted["artifact"] == format!("sha256:{}", target.artifact_id),
            "the activated copy did not open with the target artifact: {admitted}"
        );
        // Free the scratch volume for the real migration's temporary files.
        self.exec(&["rm", "-rf", ADMISSION, &backup], Duration::from_secs(300))?;
        Ok(admitted)
    }

    fn rollout_state(&mut self) -> Result<Value> {
        let app = self.request.app.clone();
        let raw = self.exec(
            &[DAY2, "rollout-inspect", CURRENT, &app],
            Duration::from_secs(60),
        )?;
        Ok(serde_json::from_str(raw.trim())?)
    }

    fn require_target_instance(&self, state: &Value) -> Result<()> {
        ensure!(
            state["target_instance_digest"]
                == day2::digest(
                    self.target_instance
                        .as_ref()
                        .context("target instance")?
                        .as_bytes()
                ),
            "rollout_target_instance_changed"
        );
        Ok(())
    }

    pub fn rollout_resume(&mut self) -> Result<Value> {
        ensure!(
            self.operation == Operation::Rollout && self.state.pod,
            "rolling_session_required"
        );
        let state = self.rollout_state()?;
        if state["id"].as_str() != self.request.request_id.as_deref() {
            return Ok(json!({"resuming":false}));
        }
        let target = self.request.target.as_ref().context("target")?;
        self.require_target_instance(&state)?;
        ensure!(
            state["source_image"] == self.request.app_image
                && state["target_image"] == target.app_image
                && state["target"] == format!("sha256:{}", target.artifact_id)
                && state["phase"] != "aborted",
            "rollout_resume_conflict"
        );
        if !state["placement"].is_null() {
            ensure!(
                state["placement"]["controller_uid"] == self.controller["metadata"]["uid"]
                    && state["placement"]["pvc_uid"].as_str() == self.pvc_uid.as_deref()
                    && state["placement"]["node"].as_str() == self.online_node.as_deref()
                    && state["placement"]["request_digest"] == self.request_digest,
                "rollout_placement_changed"
            );
        }
        self.state.resumed = true;
        self.record("rollout-resumed", state)?;
        Ok(json!({"resuming":true}))
    }

    /// Start only the namespace's reviewed backup recipe, bound to the exact
    /// incumbent image, instance and PVC. No serving replica is stopped.
    pub fn offsite_backup(&mut self) -> Result<Value> {
        ensure!(
            self.operation == Operation::Rollout
                && self.state.pod
                && self.state.backup.is_some()
                && !self.state.resumed
                && self.state.offsite_backup.is_none(),
            "rolling_backup_preconditions_required"
        );
        let backup = self
            .request
            .offsite_backup
            .clone()
            .context("offsite backup required")?;
        let cronjob: Value = serde_json::from_str(&self.kubectl(
            &["get", "cronjob", &backup.cronjob, "-o", "json"],
            None,
            Duration::from_secs(60),
        )?)?;
        let mut template = cronjob["spec"]["jobTemplate"]["spec"]["template"].clone();
        let spec = &template["spec"];
        let containers = spec["containers"].as_array().context("backup containers")?;
        ensure!(
            containers.len() == 1
                && containers[0]["name"] == "backup"
                && containers[0]["image"] == self.request.app_image
                && containers[0]["command"] == json!(["/usr/local/bin/day2-backup"])
                && containers[0]["args"]
                    == json!([
                        "/srv/day2/instance.json",
                        self.request.app,
                        "/backup/snapshot",
                        "--upload-gcs",
                        backup.bucket,
                        "--object-prefix",
                        self.request.app
                    ])
                && spec["serviceAccountName"] == backup.service_account
                && spec["automountServiceAccountToken"] == false
                && spec["restartPolicy"] == "Never"
                && spec["initContainers"].as_array().is_none_or(Vec::is_empty)
                && spec["ephemeralContainers"]
                    .as_array()
                    .is_none_or(Vec::is_empty)
                && spec["hostNetwork"].as_bool() != Some(true)
                && spec["hostPID"].as_bool() != Some(true)
                && spec["hostIPC"].as_bool() != Some(true)
                && containers[0]["securityContext"]["allowPrivilegeEscalation"] == false
                && containers[0]["securityContext"]["privileged"] == false
                && containers[0]["securityContext"]["readOnlyRootFilesystem"] == true
                && containers[0]["securityContext"]["capabilities"]["drop"] == json!(["ALL"]),
            "rolling_backup_source_or_identity_changed"
        );
        let volumes = spec["volumes"].as_array().context("backup volumes")?;
        ensure!(
            volumes.len() == 4
                && volumes.iter().any(|v| v["name"] == "state"
                    && v["persistentVolumeClaim"]["claimName"] == self.request.pvc)
                && volumes
                    .iter()
                    .any(|v| v["name"] == "instance"
                        && v["configMap"]["name"] == self.request.configmap)
                && volumes.iter().all(|v| match v["name"].as_str() {
                    Some("state") => v["persistentVolumeClaim"].is_object(),
                    Some("instance") => v["configMap"].is_object(),
                    Some("backup" | "tmp") => v["emptyDir"].is_object(),
                    _ => false,
                }),
            "rolling_backup_instance_or_claim_changed"
        );
        let labels = template["metadata"]["labels"]
            .as_object()
            .context("backup labels")?;
        let services: Value = serde_json::from_str(&self.kubectl(
            &["get", "services", "-o", "json"],
            None,
            Duration::from_secs(60),
        )?)?;
        ensure!(
            services["items"]
                .as_array()
                .context("namespace services")?
                .iter()
                .all(|service| !service["spec"]["selector"]
                    .as_object()
                    .is_some_and(|selector| !selector.is_empty()
                        && selector
                            .iter()
                            .all(|(key, value)| labels.get(key) == Some(value)))),
            "backup_pod_must_not_match_a_service"
        );
        let prefix = format!("rollouts/{}", &self.request_digest[7..]);
        template["spec"]["containers"][0]["args"][6] = json!(prefix);
        template["spec"]["nodeName"] = json!(self.online_node);
        template["metadata"]["annotations"] =
            json!({"day2.dev/rollout-request":self.request_digest});
        // A failed or interrupted job cannot restart indefinitely, and a stale
        // helper cannot escape its original source identity through retries.
        let name = format!("day2-release-backup-{}", self.stamp.to_ascii_lowercase());
        let job = json!({"apiVersion":"batch/v1","kind":"Job",
            "metadata":{"name":name,"namespace":self.request.namespace,
                "labels":template["metadata"]["labels"],
                "annotations":{"day2.dev/rollout-request":self.request_digest}},
            "spec":{"backoffLimit":0,"activeDeadlineSeconds":1200,
                "ttlSecondsAfterFinished":3600,"template":template}});
        self.record("offsite-backup-start", json!({"job":name,"image":self.request.app_image,
            "instance":self.request.configmap,"pvc_uid":self.pvc_uid,"bucket":backup.bucket,"prefix":prefix}))?;
        self.kubectl(
            &["create", "-f", "-"],
            Some(&serde_json::to_vec(&job)?),
            Duration::from_secs(60),
        )?;
        self.state.backup_job = Some(name.clone());
        let started = Instant::now();
        let completed: Value = loop {
            let observed: Value = serde_json::from_str(&self.kubectl(
                &["get", "job", &name, "-o", "json"],
                None,
                Duration::from_secs(60),
            )?)?;
            let condition = |kind: &str| {
                observed["status"]["conditions"]
                    .as_array()
                    .is_some_and(|conditions| {
                        conditions
                            .iter()
                            .any(|c| c["type"] == kind && c["status"] == "True")
                    })
            };
            ensure!(
                !condition("Failed")
                    && !condition("FailureTarget")
                    && observed["status"]["failed"].as_u64().unwrap_or(0) == 0,
                "offsite_backup_job_failed"
            );
            if condition("Complete") {
                break observed;
            }
            ensure!(
                started.elapsed() < Duration::from_secs(1200),
                "offsite_backup_job_deadline"
            );
            std::thread::sleep(Duration::from_secs(2));
        };
        let uid = completed["metadata"]["uid"]
            .as_str()
            .context("backup Job UID")?;
        let pods: Value = serde_json::from_str(&self.kubectl(
            &[
                "get",
                "pods",
                "-l",
                &format!("batch.kubernetes.io/job-name={name}"),
                "-o",
                "json",
            ],
            None,
            Duration::from_secs(60),
        )?)?;
        let pods = pods["items"].as_array().context("backup pods")?;
        ensure!(pods.len() == 1, "one_exact_backup_pod_required");
        let pod = &pods[0];
        ensure!(
            pod["metadata"]["ownerReferences"]
                .as_array()
                .is_some_and(
                    |owners| owners.iter().any(|owner| owner["controller"] == true
                        && owner["kind"] == "Job"
                        && owner["uid"] == uid)
                )
                && pod["metadata"]["annotations"]["day2.dev/rollout-request"]
                    == self.request_digest
                && pod["spec"]["nodeName"].as_str() == self.online_node.as_deref()
                && pod["spec"]["containers"][0]["image"] == self.request.app_image
                && pod["status"]["phase"] == "Succeeded"
                && pod["status"]["containerStatuses"]
                    .as_array()
                    .is_some_and(|statuses| statuses.iter().any(|status| status["name"]
                        == "backup"
                        && status["state"]["terminated"]["exitCode"] == 0
                        && status["imageID"]
                            .as_str()
                            .is_some_and(|image| image.ends_with(&format!(
                                "@{}",
                                self.request.app_image.split_once('@').unwrap().1
                            ))))),
            "backup_pod_owner_image_or_completion_changed"
        );
        let pod_name = pod["metadata"]["name"]
            .as_str()
            .context("backup pod name")?;
        let raw = self.kubectl(
            &["logs", pod_name, "-c", "backup", "--tail=1"],
            None,
            Duration::from_secs(60),
        )?;
        ensure!(raw.len() <= 65_536, "backup receipt byte budget");
        let summary: Value = day2::json::decode(raw.trim().as_bytes())?;
        let uploaded = &summary["upload"];
        let uploaded_prefix = uploaded["prefix"]
            .as_str()
            .context("uploaded backup prefix")?;
        let suffix = uploaded_prefix
            .strip_prefix(&format!("{prefix}/"))
            .context("backup prefix changed")?;
        ensure!(
            summary["verified"] == true
                && summary["app"] == self.request.app
                && summary["artifact"] == format!("sha256:{}", self.request.artifact_id)
                && uploaded["bucket"] == backup.bucket
                && !suffix.is_empty()
                && !suffix.contains('/')
                && uploaded["complete"]
                    == format!("gs://{}/{uploaded_prefix}/COMPLETE", backup.bucket)
                && uploaded["objects"].as_u64().is_some_and(|count| count >= 3)
                && uploaded["bytes"].as_u64().is_some_and(|bytes| bytes > 0),
            "offsite_backup_completion_required"
        );
        let receipt = json!({"job":name,"source_image":self.request.app_image,
            "source_artifact":summary["artifact"],"upload":uploaded});
        self.record("offsite-backup-complete", receipt.clone())?;
        self.state.offsite_backup = Some(receipt.clone());
        Ok(receipt)
    }

    fn rollout_transition(&mut self, expected: &str, next: &str) -> Result<Value> {
        let app = self.request.app.clone();
        let id = self.request.request_id.clone().context("release id")?;
        let operator = self.request.operator.clone();
        let instance = if next == "complete" { TARGET } else { CURRENT };
        let raw = self.exec(
            &[
                DAY2,
                "rollout-transition",
                instance,
                &app,
                &id,
                expected,
                next,
                &operator,
            ],
            Duration::from_secs(300),
        )?;
        Ok(serde_json::from_str(raw.trim())?)
    }

    fn immutable_map(&mut self, name: &str, data: Value) -> Result<()> {
        let found = self.kubectl(
            &["get", "configmap", name, "--ignore-not-found", "-o", "json"],
            None,
            Duration::from_secs(60),
        )?;
        if !found.trim().is_empty() {
            let existing: Value = serde_json::from_str(&found)?;
            ensure!(
                existing["immutable"] == true && existing["data"] == data,
                "rollout_configmap_conflict"
            );
            return Ok(());
        }
        let object = json!({"apiVersion":"v1","kind":"ConfigMap","immutable":true,
            "metadata":{"name":name,"namespace":self.request.namespace},"data":data});
        self.kubectl(
            &["create", "-f", "-"],
            Some(&serde_json::to_vec(&object)?),
            Duration::from_secs(60),
        )?;
        Ok(())
    }

    /// Each step is selected by ops/Maintain.roc. This lane never scales down
    /// the incumbent, migrates live state, or restores a backup over live writes.
    pub fn rollout(&mut self, step: &str) -> Result<Value> {
        ensure!(
            self.operation == Operation::Rollout
                && self.state.pod
                && ((self.state.admission.is_some() && self.state.confirmed) || self.state.resumed),
            "rollout_preparation_required"
        );
        let target = self.request.target.clone().context("target")?;
        let app = self.request.app.clone();
        let id = self.request.request_id.clone().context("release id")?;
        let operator = self.request.operator.clone();
        let suffix = day2::digest(id.as_bytes())[7..23].to_owned();
        let state = self.rollout_state()?;
        ensure!(
            state.is_null()
                || state["id"] == id
                || matches!(state["phase"].as_str(), Some("complete" | "aborted")),
            "another_rollout_is_running"
        );
        if state["id"] == id {
            self.require_target_instance(&state)?;
        }
        match step {
            "prepare" => {
                if state["id"] != id {
                    ensure!(
                        self.state.offsite_backup.is_some(),
                        "offsite_backup_completion_required"
                    );
                    let source_image = self.request.app_image.clone();
                    let raw = self.exec(
                        &[
                            DAY2,
                            "rollout-prepare",
                            CURRENT,
                            &app,
                            TARGET,
                            &source_image,
                            &target.app_image,
                            &id,
                            &operator,
                        ],
                        Duration::from_secs(600),
                    )?;
                    self.record("rollout-prepared", serde_json::from_str(raw.trim())?)?;
                } else {
                    ensure!(
                        state["source_image"] == self.request.app_image
                            && state["target_image"] == target.app_image
                            && state["target"] == format!("sha256:{}", target.artifact_id),
                        "rollout_id_conflict"
                    );
                }
                Ok(json!({"prepared":true}))
            }
            "bind" => {
                ensure!(state["id"] == id, "rollout_preparation_required");
                let placement = json!({"namespace":self.request.namespace,"controller_uid":self.controller["metadata"]["uid"],"pvc_uid":self.pvc_uid,"node":self.online_node,"request_digest":self.request_digest});
                let path = self.work.path().join("placement.json");
                fs::write(&path, serde_json::to_vec(&placement)?)?;
                self.copy_in(&path, "/srv/day2/placement.json")?;
                // Raw inspection above allows a completed release to reconcile
                // after its final response was lost, without loading old code.
                if state["phase"] != "complete" {
                    self.exec(
                        &[
                            DAY2,
                            "rollout-bind",
                            CURRENT,
                            &app,
                            &id,
                            "/srv/day2/placement.json",
                            &operator,
                        ],
                        Duration::from_secs(60),
                    )?;
                }
                Ok(json!({"placement_bound":true}))
            }
            "admit" => {
                ensure!(state["id"] == id, "rollout_preparation_required");
                if state["phase"] == "prepared" {
                    self.rollout_transition("prepared", "serving")?;
                }
                self.state.marked = true;
                Ok(json!({"overlap_admitted":true}))
            }
            "deploy" => {
                ensure!(
                    self.state.marked
                        && matches!(
                            state["phase"].as_str(),
                            Some("serving" | "draining" | "complete")
                        ),
                    "rollout_admission_required"
                );
                let name = self.request.statefulset.clone();
                let live: Value = serde_json::from_str(&self.kubectl(
                    &["get", "deployment", &name, "-o", "json"],
                    None,
                    Duration::from_secs(60),
                )?)?;
                ensure!(
                    live["metadata"]["uid"] == self.controller["metadata"]["uid"]
                        && live["spec"]["replicas"] == 1,
                    "rollout_controller_changed"
                );
                if live["metadata"]["annotations"]["day2.dev/rollout"] == id {
                    ensure!(
                        live["spec"]["template"]["metadata"]["annotations"]["day2.dev/artifact"]
                            == format!("sha256:{}", target.artifact_id)
                            && live["spec"]["template"]["spec"]["containers"]
                                .as_array()
                                .is_some_and(|containers| containers
                                    .iter()
                                    .any(|container| container["name"] == "day2"
                                        && container["image"] == target.app_image))
                            && live["spec"]["template"]["metadata"]["annotations"]["day2.dev/instance-sha256"]
                                == day2::digest(
                                    self.target_instance
                                        .as_ref()
                                        .context("target instance")?
                                        .as_bytes()
                                )
                                .trim_start_matches("sha256:"),
                        "rollout_deployment_conflict"
                    );
                    return Ok(json!({"already_deployed":true}));
                }
                ensure!(
                    live["metadata"]["resourceVersion"]
                        == self.controller["metadata"]["resourceVersion"],
                    "rollout_controller_changed"
                );
                let instance_name = format!("day2-rollout-{suffix}-instance");
                let instance_text = self.target_instance.clone().context("target instance")?;
                self.immutable_map(&instance_name, json!({"instance.json":instance_text}))?;
                let mut template = live["spec"]["template"].clone();
                template["metadata"]["labels"]["day2.dev/rollout"] = json!(suffix);
                template["metadata"]["annotations"]["day2.dev/artifact"] =
                    json!(format!("sha256:{}", target.artifact_id));
                template["metadata"]["annotations"]["day2.dev/instance-sha256"] =
                    json!(day2::digest(instance_text.as_bytes()).trim_start_matches("sha256:"));
                for container in template["spec"]["containers"]
                    .as_array_mut()
                    .context("containers")?
                {
                    if container["name"] == "day2" {
                        container["image"] = json!(target.app_image);
                        let env = container["env"].as_array_mut().context("runtime env")?;
                        env.retain(|entry| entry["name"] != "DAY2_EXPECTED_ROLLOUT");
                        env.push(json!({"name":"DAY2_EXPECTED_ROLLOUT","value":id}));
                        for env in container["env"].as_array_mut().context("runtime env")? {
                            if env["name"] == "DAY2_EXPECTED_ARTIFACT" {
                                env["value"] = json!(format!("sha256:{}", target.artifact_id));
                            }
                        }
                    }
                }
                // Provider keys and grants are unchanged by admission. Re-render
                // their reviewed instance and plan for the target artifact only.
                let credential_source = template["spec"]["volumes"]
                    .as_array()
                    .context("volumes")?
                    .iter()
                    .find(|volume| volume["name"] == "credential-metadata")
                    .and_then(|volume| volume["configMap"]["name"].as_str())
                    .map(str::to_owned);
                let credential_name = if let Some(source) = credential_source {
                    let metadata: Value = serde_json::from_str(&self.kubectl(
                        &["get", "configmap", &source, "-o", "json"],
                        None,
                        Duration::from_secs(60),
                    )?)?;
                    let mut data = metadata["data"].clone();
                    let mut instance: Value = serde_json::from_str(
                        data["operator-instance.json"]
                            .as_str()
                            .context("credential instance")?,
                    )?;
                    instance["apps"][&app]["artifact"] =
                        json!(format!("artifacts/{}", target.artifact_id));
                    let encoded = serde_json::to_string(&instance)?;
                    let mut plan: Value = serde_json::from_str(
                        data["provisioning.json"]
                            .as_str()
                            .context("credential plan")?,
                    )?;
                    plan["instance_digest"] = json!(day2::digest(encoded.as_bytes()));
                    data["operator-instance.json"] = json!(encoded);
                    data["provisioning.json"] = json!(serde_json::to_string(&plan)?);
                    let name = format!("day2-rollout-{suffix}-credentials");
                    self.immutable_map(&name, data)?;
                    Some(name)
                } else {
                    None
                };
                if let Some(inits) = template["spec"]["initContainers"].as_array_mut() {
                    for init in inits {
                        if init["name"] == "credential-registration" {
                            init["image"] = json!(target.app_image);
                        }
                    }
                }
                for volume in template["spec"]["volumes"]
                    .as_array_mut()
                    .context("volumes")?
                {
                    if volume["name"] == "instance" {
                        volume["configMap"]["name"] = json!(instance_name);
                    }
                    if volume["name"] == "credential-metadata" {
                        volume["configMap"]["name"] = json!(credential_name);
                    }
                }
                let mut annotations = live["metadata"]["annotations"]
                    .as_object()
                    .cloned()
                    .unwrap_or_default();
                annotations.insert("day2.dev/rollout".into(), json!(id));
                let patch = json!([
                    {"op":"test","path":"/metadata/uid","value":live["metadata"]["uid"]},
                    {"op":"test","path":"/metadata/resourceVersion","value":live["metadata"]["resourceVersion"]},
                    {"op":"add","path":"/metadata/annotations","value":annotations},
                    {"op":"replace","path":"/spec/template","value":template}
                ]);
                self.record(
                    "rollout-apply-started",
                    json!({"controller":live["metadata"],"image":target.app_image}),
                )?;
                self.kubectl(
                    &[
                        "patch",
                        "deployment",
                        &name,
                        "--type=json",
                        "-p",
                        &patch.to_string(),
                    ],
                    None,
                    Duration::from_secs(60),
                )?;
                Ok(json!({"candidate_requested":true}))
            }
            "observe" => {
                if state["phase"] == "complete" {
                    return Ok(state);
                }
                ensure!(
                    matches!(state["phase"].as_str(), Some("serving" | "draining")),
                    "rollout_not_serving"
                );
                if state["phase"] == "serving" {
                    let selector = format!("day2.dev/rollout={suffix}");
                    self.kubectl(
                        &[
                            "wait",
                            "--for=jsonpath={.status.phase}=Running",
                            "pod",
                            "-l",
                            &selector,
                            "--timeout=300s",
                        ],
                        None,
                        Duration::from_secs(330),
                    )?;
                    let pods: Value = serde_json::from_str(&self.kubectl(
                        &["get", "pods", "-l", &selector, "-o", "json"],
                        None,
                        Duration::from_secs(60),
                    )?)?;
                    let pod = pods["items"].as_array().context("candidate pods")?;
                    ensure!(
                        pod.len() == 1
                            && pod[0]["spec"]["nodeName"].as_str() == self.online_node.as_deref(),
                        "same_node_candidate_required"
                    );
                    let pod_name = pod[0]["metadata"]["name"]
                        .as_str()
                        .context("candidate name")?;
                    self.kubectl(
                        &[
                            "exec",
                            pod_name,
                            "-c",
                            "day2",
                            "--",
                            "/usr/local/bin/day2-health",
                            "8080",
                            "--candidate",
                        ],
                        None,
                        Duration::from_secs(60),
                    )?;
                    let all: Value = serde_json::from_str(&self.kubectl(
                        &[
                            "get",
                            "pods",
                            "-l",
                            &format!("app.kubernetes.io/name={}", self.request.statefulset),
                            "-o",
                            "json",
                        ],
                        None,
                        Duration::from_secs(60),
                    )?)?;
                    for peer in all["items"].as_array().context("serving peers")? {
                        if !peer["metadata"]["deletionTimestamp"].is_null() {
                            continue;
                        }
                        ensure!(
                            peer["spec"]["nodeName"].as_str() == self.online_node.as_deref(),
                            "same_node_peer_required"
                        );
                        let name = peer["metadata"]["name"].as_str().context("peer name")?;
                        self.kubectl(
                            &[
                                "exec",
                                name,
                                "-c",
                                "day2",
                                "--",
                                "/usr/local/bin/day2-health",
                                "8080",
                                "--candidate",
                            ],
                            None,
                            Duration::from_secs(60),
                        )?;
                    }
                    let pvc: Value = serde_json::from_str(&self.kubectl(
                        &["get", "pvc", &self.request.pvc.clone(), "-o", "json"],
                        None,
                        Duration::from_secs(60),
                    )?)?;
                    ensure!(
                        pvc["metadata"]["uid"].as_str() == self.pvc_uid.as_deref(),
                        "rollout_pvc_changed"
                    );
                }
                self.state.candidate_observed = true;
                Ok(json!({"candidate_observed":true}))
            }
            "probe" => {
                if matches!(state["phase"].as_str(), Some("draining" | "complete")) {
                    return Ok(state);
                }
                ensure!(
                    state["phase"] == "serving" && self.state.candidate_observed,
                    "candidate_observation_required"
                );
                let probe = target.probe.context("app-owned release probe")?;
                let path = self.work.path().join("release-probe.json");
                fs::write(&path, serde_json::to_vec(&probe)?)?;
                self.copy_in(&path, "/srv/day2/release-probe.json")?;
                self.exec(
                    &[
                        DAY2,
                        "rollout-probe",
                        CURRENT,
                        &app,
                        "/srv/day2/release-probe.json",
                        &id,
                        &operator,
                    ],
                    Duration::from_secs(60),
                )?;
                let started = Instant::now();
                loop {
                    let observed = self.rollout_state()?;
                    ensure!(observed["id"] == id, "release_probe_changed");
                    match observed["probe"]["status"].as_str() {
                        Some("verified") => {
                            self.record(
                                "candidate-read-write-verified",
                                json!({"release":id,"artifact":observed["target"]}),
                            )?;
                            break;
                        }
                        Some("failed") => bail!("candidate_release_probe_failed"),
                        _ => ensure!(
                            started.elapsed() < Duration::from_secs(300),
                            "candidate_release_probe_timeout"
                        ),
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
                self.state.probe_verified = true;
                Ok(json!({"probe_verified":true}))
            }
            "promote" => {
                if matches!(state["phase"].as_str(), Some("draining" | "complete")) {
                    return Ok(state);
                }
                ensure!(
                    self.state.probe_verified,
                    "candidate_read_write_proof_required"
                );
                self.rollout_transition("serving", "draining")
            }
            "wait" => {
                if state["phase"] == "complete" {
                    return Ok(state);
                }
                ensure!(state["phase"] == "draining", "rollout_promotion_required");
                let controller = format!("deployment/{}", self.request.statefulset);
                self.kubectl(
                    &["rollout", "status", &controller, "--timeout=300s"],
                    None,
                    Duration::from_secs(330),
                )?;
                self.record("candidate-serving", json!({"release":id}))?;
                Ok(json!({"candidate_serving":true}))
            }
            "complete" => {
                if state["phase"] != "complete" {
                    ensure!(state["phase"] == "draining", "rollout_not_drained");
                    let pods: Value = serde_json::from_str(&self.kubectl(
                        &[
                            "get",
                            "pods",
                            "-l",
                            &format!("app.kubernetes.io/name={}", self.request.statefulset),
                            "-o",
                            "json",
                        ],
                        None,
                        Duration::from_secs(60),
                    )?)?;
                    for pod in pods["items"].as_array().context("pods")? {
                        if pod["metadata"]["labels"]["day2.dev/rollout"] != suffix
                            && !matches!(
                                pod["status"]["phase"].as_str(),
                                Some("Succeeded" | "Failed")
                            )
                        {
                            let name =
                                pod["metadata"]["name"].as_str().context("incumbent name")?;
                            self.kubectl(
                                &[
                                    "wait",
                                    "--for=delete",
                                    &format!("pod/{name}"),
                                    "--timeout=300s",
                                ],
                                None,
                                Duration::from_secs(330),
                            )?;
                        }
                    }
                    let latest: Value = serde_json::from_str(&self.kubectl(
                        &[
                            "get",
                            "pods",
                            "-l",
                            &format!("app.kubernetes.io/name={}", self.request.statefulset),
                            "-o",
                            "json",
                        ],
                        None,
                        Duration::from_secs(60),
                    )?)?;
                    let live: Vec<_> = latest["items"]
                        .as_array()
                        .context("pods")?
                        .iter()
                        .filter(|pod| {
                            !matches!(
                                pod["status"]["phase"].as_str(),
                                Some("Succeeded" | "Failed")
                            )
                        })
                        .collect();
                    ensure!(
                        live.len() == 1
                            && live[0]["metadata"]["labels"]["day2.dev/rollout"] == suffix
                            && live[0]["status"]["conditions"].as_array().is_some_and(
                                |conditions| conditions
                                    .iter()
                                    .any(|condition| condition["type"] == "Ready"
                                        && condition["status"] == "True")
                            ),
                        "rollout_incumbent_not_terminated"
                    );
                    let result = self.rollout_transition("draining", "complete")?;
                    self.record("rollout-completed", result.clone())?;
                    self.state.result = Some(result.clone());
                    Ok(result)
                } else {
                    self.state.result = Some(state.clone());
                    Ok(state)
                }
            }
            _ => bail!("unknown rollout step"),
        }
    }

    pub fn store_admission(&mut self) -> Result<Value> {
        self.check_activation_owner()?;
        ensure!(
            self.operation == Operation::Activate && self.state.activated && self.state.fenced,
            "activated_offline_store_required"
        );
        let app = self.request.app.clone();
        let operator = self.request.operator.clone();
        let raw = self.exec(
            &[DAY2, "admit-maintenance", TARGET, &app, &operator],
            Duration::from_secs(600),
        )?;
        let admitted: Value = serde_json::from_str(raw.trim())?;
        ensure!(
            admitted["admitted"] == true,
            "maintenance_store_admission_required"
        );
        self.state.store_admitted = true;
        self.record("live-store-admitted", admitted.clone())?;
        Ok(admitted)
    }

    pub fn confirm(&mut self) -> Result<Value> {
        let (question, word) = match self.operation {
            Operation::Activate | Operation::Rollout => {
                ensure!(
                    self.state.plan.is_some() && self.state.admission.is_some(),
                    "confirm the migration plan after it is shown and the target admitted the store"
                );
                let target = self.request.target.as_ref().context("target")?;
                (
                    format!(
                        "Type 'activate' to apply this migration and activate {}: ",
                        target.artifact_id
                    ),
                    "activate",
                )
            }
            Operation::AuthorityApply => {
                ensure!(
                    self.state.stamp.is_some(),
                    "confirm after reading the authority stamp"
                );
                (
                    format!(
                        "Type 'apply' to apply the authority policy in {}'s instance: ",
                        self.request.configmap
                    ),
                    "apply",
                )
            }
            _ => bail!("{} needs no confirmation", self.operation.name()),
        };
        ensure!(!self.state.confirmed, "already confirmed");
        let by = if self.request.yes {
            "request yes"
        } else if self.tools.prompt.confirm(&question, word)? {
            "operator"
        } else {
            bail!("not confirmed; nothing was changed")
        };
        self.state.confirmed = true;
        self.record("confirmed", json!({"by": by}))?;
        Ok(json!({"confirmed": by}))
    }

    pub fn fence(&mut self) -> Result<Value> {
        ensure!(
            self.operation == Operation::Activate
                && self.state.backup.is_some()
                && self.state.plan.is_some()
                && self.state.admission.is_some()
                && self.state.confirmed
                && !self.state.fence_entered,
            "the fence needs this session's verified backup, migration plan, target store admission and confirmation"
        );
        // Recorded before the flag: a journal that stops here means "maybe migrated".
        self.record("fence", json!({"backup": self.state.backup}))?;
        self.state.fence_entered = true;
        let live = self.activation_controller()?;
        self.require_activation_owner(&live)?;
        let previous = self.activation.clone().context("activation checkpoint")?;
        let mut fenced = previous.clone();
        fenced.phase = ActivationPhase::Fenced;
        // Fail closed even if the server applies the fence but its response is
        // lost: Drop must never infer permission to start the old runtime.
        self.state.fenced = true;
        self.activation = Some(fenced.clone());
        activation::replace(
            self.tools.cluster.as_mut(),
            &self.request,
            &live,
            Some(&previous),
            &fenced,
            None,
        )?;
        Ok(json!({"fenced": true}))
    }

    /// Stamp the stopped StatefulSet with the target app image, whose artifact
    /// its database now activates, so a release or a direct apply may roll it
    /// to that image. For `activate` this follows its own fresh activation; for
    /// `mark-activated` the database's active artifact (read by
    /// `authority-inspect`) must already be the target's new artifact.
    pub fn mark_activated(&mut self) -> Result<Value> {
        self.check_activation_owner()?;
        let target = self.request.target.clone().context("target")?;
        match self.operation {
            Operation::Activate => ensure!(
                self.state.activated && !self.state.marked,
                "the activation mark follows a successful activation, once"
            ),
            Operation::MarkActivated => {
                ensure!(
                    self.state.pod && !self.state.marked,
                    "mark-activated runs once, in the maintenance pod"
                );
                let active = self
                    .state
                    .active_artifact
                    .clone()
                    .context("read the database's active artifact first")?;
                let artifact = format!("sha256:{}", target.artifact_id);
                ensure!(
                    active == artifact,
                    "the database of {} activates {active}, not the target {artifact}; nothing was marked",
                    self.request.app
                );
            }
            _ => bail!("only activate and mark-activated mark the StatefulSet"),
        }
        ensure!(
            self.operation != Operation::Activate || self.state.store_admitted,
            "live_store_admission_required"
        );
        let marked = self.stamp(&target.app_image);
        if self.operation == Operation::Activate {
            return marked.with_context(|| self.recovery());
        }
        marked
    }

    /// The command that repeats a failed stamp after a successful activation.
    /// A target that keeps the running artifact has no recovery of its own:
    /// `activate` runs again (its migration plan is empty).
    fn recovery(&self) -> String {
        let keeps = self
            .request
            .target
            .as_ref()
            .is_some_and(|target| target.artifact_id == self.request.artifact_id);
        format!(
            "{} is activated for the target in the database, but {} is not marked; once the cause is fixed run: day2 platform maintain {} {}",
            self.request.app,
            self.request.statefulset,
            if keeps { "activate" } else { "mark-activated" },
            self.request_file.display()
        )
    }

    fn stamp(&mut self, value: &str) -> Result<Value> {
        eprintln!(
            "== marking {} activated for {value}",
            self.request.statefulset
        );
        self.record(
            "mark-activated",
            json!({"annotation": ACTIVATED, "image": value}),
        )?;
        let statefulset = self.request.statefulset.clone();
        let live: Value = serde_json::from_str(&self.kubectl(
            &[
                "get",
                self.request.kind(self.operation).resource(),
                &statefulset,
                "-o",
                "json",
            ],
            None,
            Duration::from_secs(60),
        )?)?;
        let replicas = live["spec"]["replicas"]
            .as_u64()
            .context("StatefulSet replicas")?;
        let running = live["spec"]["template"]["spec"]["containers"][0]["image"]
            .as_str()
            .context("StatefulSet image")?;
        ensure!(
            running == self.request.app_image,
            "{statefulset} now runs {running}, not app_image {}; nothing was marked",
            self.request.app_image
        );
        let existing = live["metadata"]["annotations"][ACTIVATED].as_str();
        // A fresh activation is authoritative; the recovery only repeats it.
        if self.operation == Operation::MarkActivated {
            unmarked(&self.request, replicas, existing)?;
        } else {
            ensure!(
                replicas == 0,
                "{statefulset} has {replicas} replica(s), not 0; nothing was marked"
            );
        }
        let already = existing == Some(value);
        self.require_activation_owner(&live)?;
        let previous = self.activation.clone().context("activation checkpoint")?;
        let mut activated = previous.clone();
        activated.phase = ActivationPhase::Activated;
        activation::activate(
            self.tools.cluster.as_mut(),
            &self.request,
            &live,
            &previous,
            &activated,
            value,
        )?;
        self.activation = Some(activated);
        let actual: Value = serde_json::from_str(&self.kubectl(
            &[
                "get",
                self.request.kind(self.operation).resource(),
                &statefulset,
                "-o",
                "json",
            ],
            None,
            Duration::from_secs(60),
        )?)?;
        ensure!(
            actual["metadata"]["annotations"][ACTIVATED] == value,
            "{statefulset} does not carry {ACTIVATED}={value}"
        );
        self.state.marked = true;
        let receipt = json!({"statefulset": statefulset, "activated_image": value, "already_marked": already});
        if self.operation == Operation::MarkActivated {
            self.state.result = Some(receipt.clone());
        }
        self.record(
            "activation-marked",
            json!({"image": value, "already_marked": already}),
        )?;
        Ok(receipt)
    }

    pub fn finish(&mut self) -> Result<Value> {
        ensure!(
            self.state.pod && !self.state.finished,
            "finish closes an open session, once"
        );
        match self.operation {
            Operation::Rollout => ensure!(self.state.result.is_some(), "rollout has not finished"),
            Operation::Inspect => ensure!(self.state.result.is_some(), "inspect has not run"),
            Operation::Backup => ensure!(
                self.state.backup.is_some(),
                "the backup has not been copied"
            ),
            Operation::AuthorityApply => {
                ensure!(self.state.result.is_some(), "authority-apply has not run")
            }
            Operation::Activate => ensure!(
                self.state.marked,
                "activate has not run and marked the StatefulSet"
            ),
            Operation::MarkActivated => {
                ensure!(self.state.marked, "the StatefulSet has not been marked")
            }
        }
        let restored = self.close()?;
        self.state.finished = true;
        let receipt = json!({
            "operation": self.operation.name(),
            "namespace": self.request.namespace,
            "statefulset": self.request.statefulset,
            "backup": self.state.backup,
            "migration_plan": self.state.plan,
            "target_admission": self.state.admission,
            "result": self.state.result,
            "replicas_restored": restored,
            "journal": self.journal,
        });
        self.record("finish", receipt.clone())?;
        if self.operation.targeted() && self.operation != Operation::Rollout {
            eprintln!(
                "\nActivated. {} stays at 0 replicas. Release the activated image\nnext: day2-gke-release restores the replica for a release-managed app.\nOtherwise apply day2-app with image and artifact_id set to the activated build.",
                self.request.statefulset
            );
        }
        Ok(receipt)
    }

    fn restore_prepared_source(&mut self) -> Result<()> {
        self.source_storage_bindings()?;
        let current = self.activation_controller()?;
        let previous =
            ActivationIntent::read(&current)?.context("activation checkpoint required")?;
        let mut expected = previous.clone();
        expected.phase = self
            .activation
            .as_ref()
            .context("owned activation checkpoint")?
            .phase
            .clone();
        ensure!(
            previous.owner == self.stamp
                && matches!(
                    previous.phase,
                    ActivationPhase::Prepared | ActivationPhase::Stopped
                )
                && Some(&expected) == self.activation.as_ref(),
            "activation_restore_checkpoint_changed"
        );
        let replicas = current["spec"]["replicas"]
            .as_u64()
            .context("current replicas")?;
        ensure!(
            replicas == 0 || replicas == self.replicas,
            "activation_restore_replica_count_changed"
        );
        let mut restored = previous.clone();
        restored.phase = ActivationPhase::Restored;
        self.record(
            "restore",
            json!({"controller_uid":restored.controller_uid,"replicas":self.replicas}),
        )?;
        activation::replace(
            self.tools.cluster.as_mut(),
            &self.request,
            &current,
            Some(&previous),
            &restored,
            if replicas == self.replicas {
                None
            } else {
                Some(self.replicas)
            },
        )?;
        self.activation = Some(restored);
        Ok(())
    }

    /// Remove the pod; restore replicas unless the fence was passed.
    fn close(&mut self) -> Result<bool> {
        self.tools.cluster.unstoppable();
        let mut failures = Vec::new();
        if let Some(job) = self.state.backup_job.clone()
            && let Err(error) = self.kubectl(
                &["delete", "job", &job, "--ignore-not-found", "--wait=true"],
                None,
                Duration::from_secs(300),
            )
        {
            failures.push(format!("deleting backup {job}: {error:#}"));
        }
        let mut pods = Vec::new();
        if self.state.probe {
            pods.push(self.probe());
        }
        if self.state.pod {
            pods.push(self.pod.clone());
        }
        for pod in pods {
            let removed = if matches!(
                self.operation,
                Operation::Activate | Operation::MarkActivated
            ) {
                let uid = self
                    .activation
                    .as_ref()
                    .filter(|intent| intent.pod == pod)
                    .and_then(|intent| intent.pod_uid.as_deref());
                activation::remove_helper(
                    self.tools.cluster.as_mut(),
                    &self.request,
                    &pod,
                    &self.request_digest,
                    uid,
                )
            } else {
                self.kubectl(
                    &["delete", "pod", &pod, "--ignore-not-found", "--wait=true"],
                    None,
                    Duration::from_secs(300),
                )
                .map(|_| ())
            };
            if let Err(error) = removed {
                failures.push(format!("deleting {pod}: {error:#}"));
            }
        }
        let restore = self.operation != Operation::Rollout
            && self.state.stopped
            && !self.state.fenced
            && self.replicas > 0
            && failures.is_empty();
        if !restore
            && failures.is_empty()
            && self.operation == Operation::Activate
            && !self.state.fenced
            && self.activation.as_ref().is_some_and(|intent| {
                intent.owner == self.stamp
                    && matches!(
                        intent.phase,
                        ActivationPhase::Prepared | ActivationPhase::Stopped
                    )
            })
            && let Err(error) = self.restore_prepared_source()
        {
            failures.push(format!("closing preparation: {error:#}"));
        }
        if restore {
            eprintln!(
                "== restoring {} to {} replica(s)",
                self.request.statefulset, self.replicas
            );
            let statefulset = self.request.statefulset.clone();
            let replicas = format!("--replicas={}", self.replicas);
            let restored = if self.operation == Operation::Activate {
                self.restore_prepared_source()
            } else {
                self.kubectl(
                    &[
                        "scale",
                        self.request.kind(self.operation).resource(),
                        &statefulset,
                        &replicas,
                    ],
                    None,
                    Duration::from_secs(60),
                )
                .map(|_| ())
            };
            match restored {
                Ok(_) => {
                    if let Err(error) = self.kubectl(
                        &[
                            "rollout",
                            "status",
                            &format!(
                                "{}/{statefulset}",
                                self.request.kind(self.operation).resource()
                            ),
                            "--timeout=300s",
                        ],
                        None,
                        Duration::from_secs(330),
                    ) {
                        eprintln!("WARNING: {statefulset} is not ready yet: {error:#}");
                    }
                }
                Err(error) => failures.push(format!("restoring {statefulset}: {error:#}")),
            }
        }
        if failures.is_empty() {
            Ok(restore)
        } else {
            bail!("cleanup incomplete: {}", failures.join("; "))
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        writable(self.work.path());
        if self.state.finished {
            return;
        }
        eprintln!("== maintenance did not finish; cleaning up");
        let fenced = self.state.fenced;
        let outcome = self.close();
        self.state.finished = true;
        let _ = self.record(
            "aborted",
            json!({"fenced": fenced, "cleanup": outcome.as_ref().map_err(|error| format!("{error:#}")).err()}),
        );
        if let Err(error) = outcome {
            eprintln!("WARNING: {error:#}");
        }
        if self.state.activated && !self.state.marked {
            eprintln!("{}", self.recovery());
        } else if fenced {
            eprintln!(
                "The migration fence was passed, so {} was NOT restarted on its old image.\n\
                 Either apply the day2-app plan for the new image, or restore the backup in {}.\n\
                 Journal: {}",
                self.request.statefulset,
                self.state
                    .backup
                    .as_ref()
                    .map_or_else(|| "(none)".into(), |path| path.display().to_string()),
                self.journal.display()
            );
        }
    }
}

/// `mark-activated` repeats a stamp on the app exactly as `activate` left it:
/// stopped, and unmarked or marked for the same target.
fn unmarked(request: &Request, replicas: u64, marked: Option<&str>) -> Result<()> {
    let target = request.target.as_ref().context("target")?;
    let value = target.app_image.as_str();
    ensure!(
        replicas == 0,
        "mark-activated needs {} stopped at 0 replicas, as activate leaves it; it has {replicas}",
        request.statefulset
    );
    if let Some(other) = marked {
        ensure!(
            other == value,
            "{} is already marked activated for {other}, not {value}",
            request.statefulset
        );
    }
    Ok(())
}

fn private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Fill `${NAME}` placeholders from a fixed set; refuse unknown or unfilled ones.
pub fn render_template(template: &str, values: &[(&str, &str)]) -> Result<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    let mut used = std::collections::BTreeSet::new();
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .context("unterminated template placeholder")?;
        let name = &after[..end];
        let value = values
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| *value)
            .with_context(|| format!("unknown template placeholder {name}"))?;
        ensure!(
            !value.is_empty()
                && !value
                    .chars()
                    .any(|c| c.is_control() || "\"'{}#&*!|>%`".contains(c)),
            "template value for {name} is not a plain YAML scalar"
        );
        used.insert(name);
        out.push_str(value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    ensure!(
        used.len() == values.len(),
        "template does not use every value"
    );
    Ok(out)
}

#[cfg(test)]
mod tests;
