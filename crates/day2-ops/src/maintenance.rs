//! GKE maintenance of one day2 app: stop it, run day2's own workflows against
//! its state volume in a short-lived pod, then bring it back. ops/Maintain.roc
//! orders the steps; this session owns every native action and the guards no
//! recipe can skip:
//!
//! - the maintenance pod is removed on every exit;
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
//! - only a successful fresh activation stamps the StatefulSet with the
//!   activated artifact, the release workflow's precondition for changing it;
//!   `mark-activated` repeats that stamp only for the artifact the database
//!   already activated, on the still-stopped old image.
//!
//! Every step is journalled beside the backups before it runs, so a session
//! killed outright (no `Drop`) can still be reconstructed.
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
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
const POD_DEADLINE_SECONDS: u32 = 3_600;
const MAINTENANCE_LABEL: &str = "app.kubernetes.io/name=day2-maintenance";
const ROOT: &str = "/srv/day2";
const CURRENT: &str = "/srv/day2/current-instance.json";
const TARGET: &str = "/srv/day2/instance.json";
const PLAN: &str = "/srv/day2/migration-plan.json";
/// A disposable installation beside the real one (on the pod's scratch volume,
/// not the app's): the target instance over a copy of the verified backup.
const ADMISSION: &str = "/srv/day2/admission";
const ADMISSION_INSTANCE: &str = "/srv/day2/admission/instance.json";
const HOST: &str = "/workspace/platform/cli/day2-host";
const DAY2: &str = "/workspace/platform/target/debug/day2";
const OUTPUT_LIMIT: usize = 16 << 20;
const LAYER_LIMIT: u64 = 1 << 30;
/// day2-gke-release changes a release-managed app's artifact only to the one
/// this annotation names, and removes it when it does.
const ACTIVATED: &str = "day2.dev/activated-artifact";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Inspect,
    Backup,
    AuthorityApply,
    Activate,
    /// Recovery for `activate` when its own stamp step failed.
    MarkActivated,
}

impl Operation {
    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "inspect" => Self::Inspect,
            "backup" => Self::Backup,
            "authority-apply" => Self::AuthorityApply,
            "activate" => Self::Activate,
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
            Self::MarkActivated => "mark-activated",
        }
    }

    /// `activate` and its `mark-activated` recovery take the same request.
    fn targeted(self) -> bool {
        matches!(self, Self::Activate | Self::MarkActivated)
    }
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
}

/// Everything the old flags carried, as one reviewed file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub namespace: String,
    pub statefulset: String,
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
    /// Skip the typed confirmation; recorded in the journal.
    #[serde(default)]
    pub yes: bool,
}

impl Request {
    pub fn validate(&self, operation: Operation) -> Result<()> {
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
            label_key(&self.pod_label.key) && label_value(&self.pod_label.value),
            "pod_label must be a Kubernetes label key and value"
        );
        let needs_id = operation == Operation::AuthorityApply || operation.targeted();
        match &self.request_id {
            Some(id) => ensure!(
                needs_id
                    && !id.is_empty()
                    && id.len() <= 128
                    && id
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)),
                "request_id is 1-128 letters, digits, dots, dashes or underscores, for authority-apply, activate and mark-activated only"
            ),
            None => ensure!(!needs_id, "{} requires request_id", operation.name()),
        }
        match (&self.target, operation.targeted()) {
            (Some(target), true) => {
                pinned_image(&target.app_image)?;
                hex64(&target.artifact_id, "target.artifact_id")?;
                ensure!(
                    target.app_image != self.app_image && target.artifact_id != self.artifact_id,
                    "the target names the running image or artifact; nothing to activate"
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
    let files = extract_artifact(&blob, artifact_id, output)?;
    Ok(json!({"image": image, "artifact": artifact_id, "layer": layer_digest, "files": files}))
}

/// Extract `srv/day2/artifacts/<id>/` from a (gzip or plain) tar layer into
/// `output/<id>`, read-only, refusing links, devices and escaping paths, then
/// check the artifact's own identity and worker digest.
pub fn extract_artifact(layer: &[u8], artifact_id: &str, output: &Path) -> Result<usize> {
    let reader: Box<dyn Read> = match layer {
        [0x1f, 0x8b, ..] => Box::new(flate2::read::GzDecoder::new(layer)),
        [0x28, 0xb5, 0x2f, 0xfd, ..] => bail!("zstd image layers are not supported"),
        _ => Box::new(layer),
    };
    let prefix = format!("srv/day2/artifacts/{artifact_id}/");
    let destination = output.join(artifact_id);
    ensure!(!destination.exists(), "artifact output already exists");
    let mut archive = tar::Archive::new(reader);
    let mut files = 0_usize;
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
    Ok(files)
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
    artifacts: bool,
    stopped: bool,
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
    migrated: bool,
    activated: bool,
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
    operation: Operation,
    stamp: String,
    pod: String,
    replicas: u64,
    work: tempfile::TempDir,
    backup_root: PathBuf,
    journal: PathBuf,
    events: Vec<Value>,
    target_instance: Option<String>,
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
        let request: Request = day2::json::decode(&fs::read(request_file)?)?;
        request.validate(operation)?;
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
            "statefulset",
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
        ensure!(
            running == request.app_image,
            "the StatefulSet runs {running}, not app_image {}",
            request.app_image
        );
        let marked = statefulset["metadata"]["annotations"][ACTIVATED]
            .as_str()
            .map(str::to_owned);
        if operation == Operation::MarkActivated {
            unmarked(&request, replicas, marked.as_deref())?;
        }
        let others = kubectl(&["get", "pods", "-l", MAINTENANCE_LABEL, "-o", "name"])?;
        ensure!(
            others.trim().is_empty(),
            "another maintenance session is running in {namespace}: {}",
            others.trim()
        );
        let stamp = crate::offsite::utc_stamp(SystemTime::now())?;
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
        let work = tempfile::Builder::new()
            .prefix("day2-maintenance-")
            .tempdir()?;
        let mut session = Self {
            tools,
            request_file: request_file.to_path_buf(),
            operation,
            stamp,
            pod,
            replicas,
            work,
            backup_root,
            journal,
            events: Vec::new(),
            target_instance,
            state: State::default(),
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
                "format": 1,
                "session": self.stamp,
                "events": self.events,
            }))?)?;
            file.sync_all()?;
        }
        fs::rename(&temporary, &self.journal)?;
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
        if let Some(target) = self.request.target.clone() {
            fetched.push(fetch_artifact(
                self.tools.registry.as_mut(),
                &target.app_image,
                &target.artifact_id,
                &directory,
            )?);
        }
        let configmap: Value = serde_json::from_str(&self.kubectl(
            &[
                "get",
                "configmap",
                &self.request.configmap.clone(),
                "-o",
                "json",
            ],
            None,
            Duration::from_secs(60),
        )?)?;
        let current = configmap["data"]["instance.json"]
            .as_str()
            .with_context(|| {
                format!("ConfigMap {} has no instance.json", self.request.configmap)
            })?;
        let value: Value = serde_json::from_str(current).context("current instance is not JSON")?;
        ensure!(
            value["apps"][&self.request.app]["artifact"]
                == format!("artifacts/{}", self.request.artifact_id),
            "the ConfigMap's instance does not bind {} to artifact_id",
            self.request.app
        );
        fs::write(self.work.path().join("current-instance.json"), current)?;
        if let Some(text) = &self.target_instance {
            fs::write(self.work.path().join("instance.json"), text)?;
        }
        self.state.artifacts = true;
        self.record("artifacts", json!(fetched))?;
        Ok(json!({"artifacts": fetched}))
    }

    pub fn stop(&mut self) -> Result<Value> {
        ensure!(
            self.state.artifacts && !self.state.stopped,
            "stop follows the artifact fetch, once"
        );
        eprintln!(
            "== stopping {} (was {} replica(s))",
            self.request.statefulset, self.replicas
        );
        // Recorded first: from here any exit restores the replicas.
        self.state.stopped = true;
        self.record("stop", json!({"replicas": self.replicas}))?;
        let statefulset = self.request.statefulset.clone();
        self.kubectl(
            &["scale", "statefulset", &statefulset, "--replicas=0"],
            None,
            Duration::from_secs(60),
        )?;
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
        Ok(json!({"stopped": statefulset}))
    }

    fn render_pod(&self) -> Result<String> {
        let deadline = POD_DEADLINE_SECONDS.to_string();
        let values = [
            ("DAY2_MAINT_NAMESPACE", self.request.namespace.as_str()),
            ("DAY2_MAINT_POD", self.pod.as_str()),
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
        ];
        render_template(POD_TEMPLATE, &values)
    }

    pub fn start_pod(&mut self) -> Result<Value> {
        ensure!(
            self.state.stopped && !self.state.pod,
            "the pod follows the stop, once"
        );
        eprintln!("== maintenance pod {}", self.pod);
        let manifest = self.render_pod()?;
        // Recorded first: from here any exit deletes the pod.
        self.state.pod = true;
        self.record(
            "pod",
            json!({"pod": self.pod, "tooling_image": self.request.tooling_image}),
        )?;
        self.kubectl(
            &["apply", "-f", "-"],
            Some(manifest.as_bytes()),
            Duration::from_secs(60),
        )?;
        let pod = self.pod.clone();
        self.kubectl(
            &[
                "wait",
                "--for=condition=Ready",
                &format!("pod/{pod}"),
                "--timeout=600s",
            ],
            None,
            Duration::from_secs(660),
        )?;
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
            self.state.pod && !self.state.finished,
            "workflows run in the maintenance pod"
        );
        let app = self.request.app.clone();
        let operator = self.request.operator.clone();
        let request_id = self.request.request_id.clone().unwrap_or_default();
        match name {
            "backup" => {
                ensure!(
                    matches!(
                        self.operation,
                        Operation::Backup | Operation::AuthorityApply | Operation::Activate
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
                let receipt = self.host_workflow(&[
                    "authority",
                    "activate",
                    TARGET,
                    &app,
                    &artifact,
                    &operator,
                    &expected,
                    &request_id,
                ])?;
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
            self.operation == Operation::Activate && self.state.pod,
            "migrations belong to activate"
        );
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
                    &[DAY2, "migration-plan", TARGET, &app, &artifact, PLAN],
                    Duration::from_secs(600),
                )?;
                let plan: Value =
                    serde_json::from_str(&self.exec(&["cat", PLAN], Duration::from_secs(60))?)?;
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
                    self.state.fenced && !self.state.migrated,
                    "migration apply needs the fence, once"
                );
                let receipt = self.exec(
                    &[DAY2, "migration-apply", TARGET, &app, &artifact, PLAN],
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
    /// the copy with the target build's store admission (`day2 admit`, the code
    /// day2-serve runs on its store at startup). The copy is the verified
    /// in-pod backup under the target instance; it is migrated with the shown
    /// plan and activated for the target exactly as the real steps will be.
    /// Nothing outside the copy changes. A refusal fails the session before
    /// the confirmation and the fence, so the app is restored on its image.
    pub fn admission(&mut self) -> Result<Value> {
        ensure!(
            self.operation == Operation::Activate
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
        self.exec(&["cp", TARGET, ADMISSION_INSTANCE], Duration::from_secs(60))?;
        let mut stores = vec![("app.sqlite".to_owned(), format!("{app}.sqlite"))];
        for name in self.state.providers.clone() {
            ensure!(
                day2::capabilities::LOCAL_PROVIDER_DATABASES.contains(&name.as_str()),
                "unknown provider store {name} in the backup"
            );
            stores.push((format!("providers/{name}"), name));
        }
        for (from, to) in stores {
            self.exec(
                &["cp", &format!("{backup}/{from}"), &format!("{state}/{to}")],
                Duration::from_secs(600),
            )?;
        }
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
        let inspected = self.host_workflow(&["authority", "inspect", ADMISSION_INSTANCE, &app])?;
        let stamp = &inspected["active"]["stamp"];
        ensure!(stamp.is_object(), "no active authority stamp in the copy");
        let expected = serde_json::to_string(stamp)?;
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
        let output = self.exec(
            &[DAY2, "admit", ADMISSION_INSTANCE, &app],
            Duration::from_secs(600),
        )?;
        let admitted: Value = serde_json::from_str(output.trim()).context("day2 admit output")?;
        ensure!(
            admitted["admitted"] == true
                && admitted["artifact"] == format!("sha256:{}", target.artifact_id),
            "the activated copy did not open with the target artifact: {admitted}"
        );
        self.exec(&["rm", "-rf", ADMISSION], Duration::from_secs(300))?;
        Ok(admitted)
    }

    pub fn confirm(&mut self) -> Result<Value> {
        let (question, word) = match self.operation {
            Operation::Activate => {
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
                && !self.state.fenced,
            "the fence needs this session's verified backup, migration plan, target store admission and confirmation"
        );
        // Recorded before the flag: a journal that stops here means "maybe migrated".
        self.record("fence", json!({"backup": self.state.backup}))?;
        self.state.fenced = true;
        Ok(json!({"fenced": true}))
    }

    /// Stamp the stopped StatefulSet with the artifact its database now
    /// activates, so the release workflow may roll it to that artifact. For
    /// `activate` this follows its own fresh activation; for `mark-activated`
    /// the database's active artifact (read by `authority-inspect`) must
    /// already be the target.
    pub fn mark_activated(&mut self) -> Result<Value> {
        let target = self.request.target.clone().context("target")?;
        let value = format!("sha256:{}", target.artifact_id);
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
                ensure!(
                    active == value,
                    "the database of {} activates {active}, not the target {value}; nothing was marked",
                    self.request.app
                );
            }
            _ => bail!("only activate and mark-activated mark the StatefulSet"),
        }
        let marked = self.stamp(&value);
        if self.operation == Operation::Activate {
            return marked.with_context(|| self.recovery());
        }
        marked
    }

    /// The command that repeats a failed stamp after a successful activation.
    fn recovery(&self) -> String {
        format!(
            "{} is activated for the target in the database, but {} is not marked; once the cause is fixed run: day2 platform maintain mark-activated {}",
            self.request.app,
            self.request.statefulset,
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
            json!({"annotation": ACTIVATED, "artifact": value}),
        )?;
        let statefulset = self.request.statefulset.clone();
        let live: Value = serde_json::from_str(&self.kubectl(
            &["get", "statefulset", &statefulset, "-o", "json"],
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
        if !already {
            self.kubectl(
                &[
                    "annotate",
                    "--overwrite",
                    "statefulset",
                    &statefulset,
                    &format!("{ACTIVATED}={value}"),
                ],
                None,
                Duration::from_secs(60),
            )?;
        }
        let actual: Value = serde_json::from_str(&self.kubectl(
            &["get", "statefulset", &statefulset, "-o", "json"],
            None,
            Duration::from_secs(60),
        )?)?;
        ensure!(
            actual["metadata"]["annotations"][ACTIVATED] == value,
            "{statefulset} does not carry {ACTIVATED}={value}"
        );
        self.state.marked = true;
        let receipt = json!({"statefulset": statefulset, "activated_artifact": value, "already_marked": already});
        if self.operation == Operation::MarkActivated {
            self.state.result = Some(receipt.clone());
        }
        self.record(
            "activation-marked",
            json!({"artifact": value, "already_marked": already}),
        )?;
        Ok(receipt)
    }

    pub fn finish(&mut self) -> Result<Value> {
        ensure!(
            self.state.pod && !self.state.finished,
            "finish closes an open session, once"
        );
        match self.operation {
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
        if self.operation.targeted() {
            eprintln!(
                "\nActivated. {} stays at 0 replicas. Release the activated artifact\nnext: day2-gke-release restores the replica for a release-managed app.\nOtherwise apply day2-app with image and artifact_id set to the activated build.",
                self.request.statefulset
            );
        }
        Ok(receipt)
    }

    /// Remove the pod; restore replicas unless the fence was passed.
    fn close(&mut self) -> Result<bool> {
        self.tools.cluster.unstoppable();
        let mut failures = Vec::new();
        if self.state.pod {
            let pod = self.pod.clone();
            if let Err(error) = self.kubectl(
                &["delete", "pod", &pod, "--ignore-not-found", "--wait=true"],
                None,
                Duration::from_secs(300),
            ) {
                failures.push(format!("deleting {pod}: {error:#}"));
            }
        }
        let restore = self.state.stopped && !self.state.fenced && self.replicas > 0;
        if restore {
            eprintln!(
                "== restoring {} to {} replica(s)",
                self.request.statefulset, self.replicas
            );
            let statefulset = self.request.statefulset.clone();
            let replicas = format!("--replicas={}", self.replicas);
            match self.kubectl(
                &["scale", "statefulset", &statefulset, &replicas],
                None,
                Duration::from_secs(60),
            ) {
                Ok(_) => {
                    if let Err(error) = self.kubectl(
                        &[
                            "rollout",
                            "status",
                            &format!("statefulset/{statefulset}"),
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
    let value = format!("sha256:{}", target.artifact_id);
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
