//! Host-side, operator-only Docker capabilities for ops/Linux.roc. App build and
//! verification still execute the ordinary Build/Check recipes in the tooling
//! image. No Docker socket or operator capability enters an app container.
use super::*;
use day2_control::build::{PinnedTree, PlatformInputs};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const RUNTIME_ACTIONS: &[&str] = &[
    "linux-runtime-package",
    "linux-runtime-start",
    "linux-runtime-read-write",
    "linux-runtime-revoke",
    "linux-runtime-graceful-restart",
    "linux-runtime-forced-restart",
    "linux-runtime-isolation",
    "linux-runtime-restore",
    "linux-runtime-stop",
];

/// The Linux platform this machine's Docker engine runs natively.
///
/// Qualification is only ever native. An emulated container translates its
/// system calls into the host's, so a seccomp filter or Landlock ruleset
/// qualified that way says nothing about the target: the architecture is read
/// from the engine, never chosen, and x86_64 is qualified on an x86_64 kernel.
pub(super) struct NativePlatform {
    /// `docker --platform` value.
    pub docker: &'static str,
    /// The kernel architecture Docker reports.
    pub architecture: &'static str,
    /// The compiler pin applications are built with there.
    pub pin: &'static str,
}

pub(super) fn native_platform() -> Result<&'static NativePlatform> {
    static PLATFORM: std::sync::OnceLock<Result<NativePlatform, String>> =
        std::sync::OnceLock::new();
    PLATFORM
        .get_or_init(|| {
            let response = Command::new("docker")
                .args(["info", "--format", "{{.OSType}} {{.Architecture}}"])
                .output()
                .map_err(|error| error.to_string())?;
            if !response.status.success() {
                return Err("running Docker engine required".into());
            }
            match String::from_utf8_lossy(&response.stdout).trim() {
                "linux aarch64" => Ok(NativePlatform {
                    docker: "linux/arm64",
                    architecture: "aarch64",
                    pin: "toolchains/linux-aarch64.json",
                }),
                "linux x86_64" => Ok(NativePlatform {
                    docker: "linux/amd64",
                    architecture: "x86_64",
                    pin: "toolchains/linux-x86_64.json",
                }),
                other => Err(format!("unsupported native Linux engine: {other}")),
            }
        })
        .as_ref()
        .map_err(|error| anyhow::anyhow!("{error}"))
}

fn required_steps() -> BTreeSet<String> {
    [
        "linux-capture",
        "linux-build-tooling",
        "linux-build-runtime",
        "linux-start-tooling",
        "linux-build-check",
        "linux-build-probe",
        "linux-build-owned",
        "linux-build-delegation",
        "linux-build-delegation-business",
        "linux-test-delegation",
        "test-sandbox",
        "test-worker",
        "test-http",
        "test-backup",
        "linux-stop-tooling",
    ]
    .into_iter()
    .chain(RUNTIME_ACTIONS.iter().copied())
    .map(str::to_owned)
    .collect()
}

fn request_key(action: &str, input: &Value) -> Result<String> {
    let key = if action == "linux-test-suite" {
        let suite = input["suite"].as_str().context("Linux test suite")?;
        ensure!(
            *input == json!({"suite":suite})
                && ["sandbox", "worker", "http", "backup"].contains(&suite),
            "closed Linux test suite required"
        );
        format!("test-{suite}")
    } else {
        ensure!(
            *input == json!({}),
            "Linux qualification accepts no step overrides"
        );
        action.to_owned()
    };
    ensure!(
        key == "linux-receipt" || required_steps().contains(&key),
        "unknown Linux qualification capability"
    );
    Ok(key)
}

/// Exercise every request emitted by the actual Roc recipe before expensive
/// native effects. This validates the wire contract without performing any
/// build, Docker operation, source capture, or qualification admission.
pub(super) fn preflight(runner: &Path) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut completed = false;
    let result = day2::automation::run(runner, &["qualify-linux"], |request| {
        ensure!(!completed, "Linux recipe continued after receipt");
        let input: Value = request.decode()?;
        let key = request_key(&request.action, &input)?;
        if key == "linux-receipt" {
            ensure!(
                seen == required_steps(),
                "incomplete Linux recipe preflight"
            );
            day2::security_admission::require_linux_checks(&seen)?;
            completed = true;
            Ok(json!({"recipe_preflight":true}))
        } else {
            ensure!(seen.insert(key), "duplicate Linux recipe step");
            Ok(json!({}))
        }
    })?;
    ensure!(
        completed && result == json!({"recipe_preflight":true}),
        "Linux recipe preflight did not complete"
    );
    Ok(())
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    format: u32,
    status: &'static str,
    scope: &'static str,
    platform: String,
    platform_inventory: String,
    workflow: String,
    toolchain: String,
    source: String,
    artifact: String,
    worker: String,
    /// Applications built and admitted natively beside the Reports fixtures.
    applications: BTreeMap<String, Value>,
    tooling_image: String,
    runtime_image: String,
    runtime_supervisor: String,
    runtime_sandbox: String,
    environment: Value,
    checks: BTreeSet<String>,
    runtime: BTreeMap<String, Value>,
    evidence: BTreeMap<String, String>,
    exclusions: Vec<&'static str>,
}

struct Session {
    root: PathBuf,
    output: PathBuf,
    inputs: Option<PlatformInputs>,
    source: Option<PinnedTree>,
    owned_source: Option<PinnedTree>,
    owned: Option<Value>,
    delegation: BTreeMap<String, Value>,
    tooling_image: Option<String>,
    runtime_image: Option<String>,
    container: String,
    tooling_started: bool,
    artifact: Option<PathBuf>,
    artifact_evidence: Option<Value>,
    probe: Option<PathBuf>,
    environment: Value,
    checks: BTreeSet<String>,
    results: BTreeMap<String, Value>,
    runtime: Option<super::linux_runtime_qualification::RuntimeSession>,
}

fn read_json(path: &Path) -> Result<Value> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 8 * 1024 * 1024,
        "bounded qualification JSON required"
    );
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn image_id(path: &Path) -> Result<String> {
    let value = fs::read_to_string(path)?.trim().to_owned();
    day2::assets::hash_part(&value)?;
    Ok(value)
}

/// Foreign native workers cannot execute on the source host. This checks only
/// transport identity; full admission remains mandatory in the Linux tooling
/// helper and each packaged Linux runtime.
pub(super) fn inspect_artifact(path: &Path) -> Result<Value> {
    let path = path.canonicalize()?;
    let contract = read_json(&path.join("artifact.json"))?;
    let artifact = digest(&serde_json::to_vec(&contract)?);
    ensure!(
        path.file_name().and_then(|name| name.to_str())
            == Some(day2::assets::hash_part(&artifact)?),
        "exported artifact address mismatch"
    );
    let worker = contract["worker_digest"]
        .as_str()
        .context("artifact worker digest")?;
    day2::assets::hash_part(worker)?;
    let metadata = fs::symlink_metadata(path.join("worker"))?;
    ensure!(
        metadata.is_file() && metadata.len() <= 256 * 1024 * 1024,
        "bounded regular exported worker required"
    );
    ensure!(
        digest(&fs::read(path.join("worker"))?) == worker,
        "exported worker digest mismatch"
    );
    Ok(json!({"artifact":artifact,"worker":worker}))
}

/// The logged child is a trusted platform/Docker command, never an app-selected
/// command. Logs are private fixture evidence, bounded separately from workers.
fn logged(output: &Path, name: &str, command: &mut Command, seconds: u64) -> Result<()> {
    eprintln!("Linux qualification: {name}");
    let path = output.join(format!("{name}.log"));
    let log = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()?;
    let started = Instant::now();
    let outcome = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(seconds)
            || fs::metadata(&path)?.len() > 16 * 1024 * 1024
        {
            let _ = child.kill();
            let _ = child.wait();
            bail!("Linux qualification command exceeded time/log bound: {name}");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    ensure!(
        outcome.success(),
        "Linux qualification step {name} failed; evidence: {}",
        path.display()
    );
    ensure!(
        fs::metadata(path)?.len() <= 16 * 1024 * 1024,
        "qualification log budget"
    );
    eprintln!("Linux qualification passed: {name}");
    Ok(())
}

impl Session {
    fn new(root: &Path, output: &Path) -> Result<Self> {
        ensure!(!output.exists(), "Linux qualification output must be new");
        fs::create_dir(output)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(output, fs::Permissions::from_mode(0o700))?;
        }
        let output = output.canonicalize()?;
        let identity = digest(output.as_os_str().as_encoded_bytes());
        Ok(Self {
            root: root.canonicalize()?,
            output,
            inputs: None,
            source: None,
            owned_source: None,
            owned: None,
            delegation: BTreeMap::new(),
            tooling_image: None,
            runtime_image: None,
            container: format!("day2-linux-qualification-{}", &identity[7..27]),
            tooling_started: false,
            artifact: None,
            artifact_evidence: None,
            probe: None,
            environment: Value::Null,
            checks: BTreeSet::new(),
            results: BTreeMap::new(),
            runtime: None,
        })
    }

    /// Give a path copied out of the tooling container to whoever runs this
    /// qualification. The container copies as root; on a native Linux engine
    /// the bind-mounted export keeps that ownership (and cp's 0600 modes),
    /// so the host could not read what it exported. The owner of this run's
    /// private output directory is the host user, on every engine.
    fn hand_over(&self, exported: String) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            exported.starts_with("/qualification-export/") && !exported.contains(".."),
            "export ownership is limited to the private export directory"
        );
        let owner = fs::metadata(&self.output)?;
        let status = Command::new("docker")
            .args(["exec", &self.container, "chown", "-R"])
            .arg(format!("{}:{}", owner.uid(), owner.gid()))
            .arg(&exported)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        ensure!(status.success(), "could not hand over {exported}");
        Ok(())
    }

    fn build_image(&mut self, target: &str) -> Result<()> {
        let input = self.output.join("inputs/platform");
        let id = self.output.join(format!("{target}-image.id"));
        logged(
            &self.output,
            &format!("build-{target}"),
            Command::new("docker")
                .args([
                    "build",
                    "--platform",
                    native_platform()?.docker,
                    "--target",
                    target,
                    "--iidfile",
                ])
                .arg(&id)
                .arg("-f")
                .arg(input.join("deploy/linux-sqlite/Dockerfile"))
                .arg(&input),
            3600,
        )?;
        let id = image_id(&id)?;
        if target == "tooling" {
            self.tooling_image = Some(id);
        } else {
            self.runtime_image = Some(id);
        }
        Ok(())
    }

    fn effect(&mut self, request: day2::automation::Request) -> Result<Value> {
        let input: Value = request.decode()?;
        let action = request.action.as_str();
        let key = request_key(action, &input)?;
        ensure!(
            !self.checks.contains(&key),
            "duplicate Linux qualification step"
        );
        let result = match action {
            "linux-capture" => {
                ensure!(self.inputs.is_none(), "one Linux source capture required");
                let inputs =
                    PlatformInputs::capture(&self.root, &self.root.join("../.toolchains"))?;
                let source = PinnedTree::capture(&self.root.join("examples/reports"))?;
                let owned =
                    PinnedTree::capture(&self.root.join("fixtures/row-authority-web-conformance"))?;
                let directory = self.output.join("inputs");
                fs::create_dir(&directory)?;
                inputs.materialize(&directory)?;
                fs::create_dir(directory.join("examples"))?;
                source.materialize(&directory.join("examples/reports"))?;
                owned.materialize(&directory.join("public-owned"))?;
                self.owned_source = Some(owned);
                fs::create_dir(self.output.join("artifacts"))?;
                let response = Command::new("docker")
                    .args(["info", "--format", "{{json .}}"])
                    .output()?;
                ensure!(response.status.success(), "running Docker engine required");
                let engine: Value = serde_json::from_slice(&response.stdout)?;
                ensure!(
                    engine["OSType"] == "linux"
                        && engine["Architecture"] == native_platform()?.architecture,
                    "native Linux engine required"
                );
                self.environment = json!({"kernel":engine["KernelVersion"], "architecture":engine["Architecture"], "engine":engine["ServerVersion"], "security_options":engine["SecurityOptions"]});
                self.inputs = Some(inputs);
                self.source = Some(source);
                self.environment.clone()
            }
            "linux-build-tooling" => {
                ensure!(self.inputs.is_some(), "capture inputs first");
                self.build_image("tooling")?;
                json!({"image":self.tooling_image})
            }
            "linux-build-runtime" => {
                ensure!(self.tooling_image.is_some(), "tooling image required");
                self.build_image("runtime")?;
                json!({"image":self.runtime_image})
            }
            "linux-start-tooling" => {
                ensure!(self.runtime_image.is_some(), "runtime image required");
                logged(
                    &self.output,
                    "start-tooling",
                    Command::new("docker")
                        .args(["run", "--detach", "--name"])
                        .arg(&self.container)
                        .args([
                            "--memory=6g",
                            "--memory-swap=6g",
                            "--cpus=4",
                            "--pids-limit=512",
                            "--cgroupns=private",
                            "--tmpfs",
                            "/workspace/platform/artifacts:rw,exec,nosuid,nodev,size=1g",
                            "--tmpfs",
                            "/workspace/platform/crates/worker/generated:rw,nosuid,nodev,size=64m",
                            "--mount",
                        ])
                        .arg(format!(
                            "type=bind,source={},target=/workspace/platform/examples/reports,readonly",
                            self.output.join("inputs/examples/reports").display()
                        ))
                        .arg("--mount")
                        .arg(format!(
                            "type=bind,source={},target=/workspace/platform/fixtures/row-authority-web-conformance,readonly",
                            self.output.join("inputs/public-owned").display()
                        ))
                        .arg("--mount")
                        .arg(format!(
                            "type=bind,source={},target=/qualification-export",
                            self.output.join("artifacts").display()
                        ))
                        .arg(self.tooling_image.as_ref().context("tooling image")?)
                        .args(["sleep", "infinity"]),
                    120,
                )?;
                self.tooling_started = true;
                json!({"container":self.container,"memory_bytes":6_u64*1024*1024*1024,"cpu_millis":4000,"pids":512,"artifact_tmpfs_bytes":1024_u64*1024*1024,"abi_tmpfs_bytes":64_u64*1024*1024})
            }
            "linux-build-check" => {
                ensure!(self.tooling_started, "start tooling first");
                logged(
                    &self.output,
                    "app-check",
                    Command::new("docker").args([
                        "exec",
                        &self.container,
                        "cli/day2",
                        "platform",
                        "check",
                        "/workspace/platform/examples/reports",
                        "42",
                        "16",
                    ]),
                    1800,
                )?;
                logged(
                    &self.output,
                    "copy-pointer",
                    Command::new("docker").args([
                        "exec",
                        &self.container,
                        "cp",
                        "/workspace/platform/artifacts/current.json",
                        "/qualification-export/current.json",
                    ]),
                    60,
                )?;
                self.hand_over("/qualification-export/current.json".to_owned())?;
                // Docker's archive endpoint cannot see this tmpfs mount. A
                // fixed native copy exports only to this run's private bind;
                // the host still validates the complete addressed artifact.
                let pointer = read_json(&self.output.join("artifacts/current.json"))?;
                let artifact = pointer["artifact"]
                    .as_str()
                    .context("selected Linux artifact")?;
                let hash = day2::assets::hash_part(artifact)?;
                let destination = self.output.join("artifacts").join(hash);
                logged(
                    &self.output,
                    "copy-artifact",
                    Command::new("docker")
                        .args(["exec", &self.container, "cp", "-a"])
                        .arg(format!("/workspace/platform/artifacts/{hash}"))
                        .arg(format!("/qualification-export/{hash}")),
                    120,
                )?;
                self.hand_over(format!("/qualification-export/{hash}"))?;
                let copied = inspect_artifact(&destination)?;
                ensure!(
                    copied["artifact"] == artifact,
                    "copied artifact identity mismatch"
                );
                logged(
                    &self.output,
                    "artifact-admission",
                    Command::new("docker")
                        .args([
                            "exec",
                            &self.container,
                            "target/debug/xtask",
                            "linux-artifact-evidence",
                        ])
                        .arg(format!("/workspace/platform/artifacts/{hash}")),
                    60,
                )?;
                let admitted = read_json(&self.output.join("artifact-admission.log"))?;
                ensure!(
                    copied["artifact"] == admitted["artifact"]
                        && copied["worker"] == admitted["worker"],
                    "native admission differs from exported artifact"
                );
                logged(
                    &self.output,
                    "copy-app-check",
                    Command::new("docker").args([
                        "exec",
                        &self.container,
                        "cp",
                        "-a",
                        "/workspace/platform/artifacts/operations",
                        "/qualification-export/app-check-evidence",
                    ]),
                    120,
                )?;
                self.hand_over("/qualification-export/app-check-evidence".to_owned())?;
                self.artifact = Some(destination);
                self.artifact_evidence = Some(admitted);
                json!({"artifact":artifact, "seed":42, "cases_per_generator":16})
            }
            "linux-build-probe" => {
                ensure!(
                    self.artifact.is_some(),
                    "checked Reports artifact required before probe build"
                );
                logged(
                    &self.output,
                    "build-probe",
                    Command::new("docker").args([
                        "exec",
                        &self.container,
                        "target/debug/xtask",
                        "linux-build-probe",
                    ]),
                    1800,
                )?;
                logged(
                    &self.output,
                    "copy-probe-pointer",
                    Command::new("docker").args([
                        "exec",
                        &self.container,
                        "cp",
                        "/workspace/platform/artifacts/current.json",
                        "/qualification-export/probe-current.json",
                    ]),
                    60,
                )?;
                self.hand_over("/qualification-export/probe-current.json".to_owned())?;
                let pointer = read_json(&self.output.join("artifacts/probe-current.json"))?;
                let id = pointer["artifact"]
                    .as_str()
                    .context("probe artifact identity")?;
                let hash = day2::assets::hash_part(id)?;
                let destination = self.output.join("artifacts").join(hash);
                ensure!(
                    !destination.exists(),
                    "probe must be distinct from base artifact"
                );
                logged(
                    &self.output,
                    "copy-probe",
                    Command::new("docker")
                        .args(["exec", &self.container, "cp", "-a"])
                        .arg(format!("/workspace/platform/artifacts/{hash}"))
                        .arg(format!("/qualification-export/{hash}")),
                    120,
                )?;
                self.hand_over(format!("/qualification-export/{hash}"))?;
                let exported = inspect_artifact(&destination)?;
                logged(
                    &self.output,
                    "probe-admission",
                    Command::new("docker")
                        .args([
                            "exec",
                            &self.container,
                            "target/debug/xtask",
                            "linux-artifact-evidence",
                        ])
                        .arg(format!("/workspace/platform/artifacts/{hash}")),
                    60,
                )?;
                let evidence = read_json(&self.output.join("probe-admission.log"))?;
                ensure!(
                    exported["artifact"] == evidence["artifact"]
                        && exported["worker"] == evidence["worker"],
                    "probe export differs from native admission"
                );
                self.probe = Some(destination);
                evidence
            }
            // A second public conformance app is built with the same admitted
            // compiler and generator as the runtime image.
            "linux-build-owned" => {
                ensure!(
                    self.probe.is_some() && self.owned.is_none(),
                    "Reports fixtures required before the row-authority fixture build"
                );
                logged(
                    &self.output,
                    "owned-check",
                    Command::new("docker").args([
                        "exec",
                        &self.container,
                        "cli/day2",
                        "platform",
                        "check",
                        "/workspace/platform/fixtures/row-authority-web-conformance",
                        "42",
                        // Keep the independent example campaign bounded.
                        "8",
                    ]),
                    3600,
                )?;
                logged(
                    &self.output,
                    "copy-owned-pointer",
                    Command::new("docker").args([
                        "exec",
                        &self.container,
                        "cp",
                        "/workspace/platform/artifacts/current.json",
                        "/qualification-export/owned-current.json",
                    ]),
                    60,
                )?;
                self.hand_over("/qualification-export/owned-current.json".to_owned())?;
                let pointer = read_json(&self.output.join("artifacts/owned-current.json"))?;
                let id = pointer["artifact"]
                    .as_str()
                    .context("row-authority fixture artifact identity")?;
                let hash = day2::assets::hash_part(id)?;
                let destination = self.output.join("artifacts").join(hash);
                ensure!(
                    !destination.exists(),
                    "row-authority fixture must be distinct from the Reports artifacts"
                );
                logged(
                    &self.output,
                    "copy-owned",
                    Command::new("docker")
                        .args(["exec", &self.container, "cp", "-a"])
                        .arg(format!("/workspace/platform/artifacts/{hash}"))
                        .arg(format!("/qualification-export/{hash}")),
                    120,
                )?;
                self.hand_over(format!("/qualification-export/{hash}"))?;
                let exported = inspect_artifact(&destination)?;
                logged(
                    &self.output,
                    "owned-admission",
                    Command::new("docker")
                        .args([
                            "exec",
                            &self.container,
                            "target/debug/xtask",
                            "linux-artifact-evidence",
                        ])
                        .arg(format!("/workspace/platform/artifacts/{hash}")),
                    60,
                )?;
                let evidence = read_json(&self.output.join("owned-admission.log"))?;
                ensure!(
                    exported["artifact"] == evidence["artifact"]
                        && exported["worker"] == evidence["worker"],
                    "row-authority fixture export differs from native admission"
                );
                self.owned =
                    Some(json!({"artifact":exported["artifact"],"worker":exported["worker"]}));
                json!({"artifact":exported["artifact"],"seed":42,"cases_per_generator":8})
            }
            "linux-build-delegation" | "linux-build-delegation-business" => {
                ensure!(self.owned.is_some(), "native baseline fixtures required");
                let command = if action == "linux-build-delegation" {
                    "build-delegation"
                } else {
                    "build-delegation-business"
                };
                logged(
                    &self.output,
                    &key,
                    Command::new("docker").args([
                        "exec",
                        &self.container,
                        "target/debug/xtask",
                        command,
                    ]),
                    1800,
                )?;
                json!({"built":command})
            }
            "linux-test-delegation" => {
                ensure!(
                    self.checks.contains("linux-build-delegation")
                        && self.checks.contains("linux-build-delegation-business"),
                    "both delegation fixture recipes required"
                );
                let mut paths = BTreeMap::new();
                for file in [
                    "delegation-fixtures.json",
                    "delegation-business-fixtures.json",
                ] {
                    logged(
                        &self.output,
                        &format!("copy-{file}"),
                        Command::new("docker")
                            .args(["exec", &self.container, "cp"])
                            .arg(format!("/workspace/platform/artifacts/{file}"))
                            .arg(format!("/qualification-export/{file}")),
                        60,
                    )?;
                    self.hand_over(format!("/qualification-export/{file}"))?;
                    let pointer = read_json(&self.output.join("artifacts").join(file))?;
                    paths.extend(serde_json::from_value::<BTreeMap<String, String>>(pointer)?);
                }
                ensure!(
                    paths.keys().map(String::as_str).collect::<BTreeSet<_>>()
                        == BTreeSet::from([
                            "delegation",
                            "delegation-peer",
                            "app-ownership",
                            "notifications",
                            "request-desk",
                            "stock-ledger"
                        ]),
                    "exact delegation fixtures required"
                );
                let mut command = Command::new("docker");
                command.args(["exec", &self.container, "env"]);
                for (fixture, variable) in [
                    ("delegation", "DAY2_TEST_DELEGATION_ARTIFACT"),
                    ("delegation-peer", "DAY2_TEST_DELEGATION_PEER_ARTIFACT"),
                    ("request-desk", "DAY2_TEST_REQUEST_DESK_ARTIFACT"),
                    ("stock-ledger", "DAY2_TEST_STOCK_LEDGER_ARTIFACT"),
                    ("app-ownership", "DAY2_TEST_APP_OWNERSHIP_ARTIFACT"),
                    ("notifications", "DAY2_TEST_NOTIFICATIONS_ARTIFACT"),
                ] {
                    let path = Path::new(&paths[fixture]);
                    let hash = path
                        .file_name()
                        .and_then(|value| value.to_str())
                        .context("native delegation address")?;
                    day2::assets::hash_part(&format!("sha256:{hash}"))?;
                    ensure!(
                        path == Path::new("/workspace/platform/artifacts").join(hash),
                        "native delegation artifact path changed"
                    );
                    command.arg(format!("{variable}={}", path.display()));
                }
                command.args(["target/debug/xtask", "linux-test-delegation"]);
                logged(&self.output, &key, &mut command, 1800)?;
                for (fixture, path) in paths {
                    let hash = Path::new(&path)
                        .file_name()
                        .and_then(|value| value.to_str())
                        .context("delegation address")?;
                    logged(
                        &self.output,
                        &format!("export-{fixture}"),
                        Command::new("docker")
                            .args(["exec", &self.container, "cp", "-a", &path])
                            .arg(format!("/qualification-export/{hash}")),
                        120,
                    )?;
                    self.hand_over(format!("/qualification-export/{hash}"))?;
                    self.delegation.insert(
                        fixture,
                        inspect_artifact(&self.output.join("artifacts").join(hash))?,
                    );
                }
                logged(
                    &self.output,
                    "export-delegation-business-evidence",
                    Command::new("docker").args([
                        "exec",
                        &self.container,
                        "cp",
                        "-a",
                        "/workspace/platform/artifacts/delegation-business-evidence",
                        "/qualification-export/delegation-business-evidence",
                    ]),
                    60,
                )?;
                self.hand_over("/qualification-export/delegation-business-evidence".into())?;
                json!({"applications":self.delegation,"passed":true})
            }
            "linux-test-suite" => {
                let artifact = self
                    .artifact
                    .as_ref()
                    .context("checked Linux artifact required")?;
                let hash = artifact
                    .file_name()
                    .context("artifact address")?
                    .to_str()
                    .context("artifact encoding")?;
                let suite = input["suite"].as_str().context("test suite")?;
                let probe = self
                    .probe
                    .as_ref()
                    .context("admitted Reports probe fixture required")?;
                let probe_hash = probe
                    .file_name()
                    .and_then(|name| name.to_str())
                    .context("probe address")?;
                logged(
                    &self.output,
                    &key,
                    Command::new("docker")
                        .args([
                            "exec",
                            &self.container,
                            "target/debug/xtask",
                            "linux-test-suite",
                            suite,
                        ])
                        .arg(format!("/workspace/platform/artifacts/{hash}"))
                        .arg(format!("/workspace/platform/artifacts/{probe_hash}")),
                    1800,
                )?;
                json!({"suite":suite,"passed":true})
            }
            action if RUNTIME_ACTIONS.contains(&action) => {
                ensure!(
                    self.checks.contains("test-backup"),
                    "native Linux suites required"
                );
                if self.runtime.is_none() {
                    ensure!(action == "linux-runtime-package", "package runtime first");
                    let mut runtime = super::linux_runtime_qualification::RuntimeSession::new(
                        &self.root,
                        &self.output,
                        self.artifact.as_ref().context("checked artifact")?,
                        self.runtime_image.as_ref().context("runtime image")?,
                    )?;
                    runtime
                        .set_tooling_image(self.tooling_image.as_ref().context("tooling image")?)?;
                    runtime.set_artifact_evidence(
                        self.artifact_evidence
                            .as_ref()
                            .context("native artifact admission")?,
                    )?;
                    self.runtime = Some(runtime);
                }
                self.runtime
                    .as_mut()
                    .context("runtime session")?
                    .effect(action)?
            }
            "linux-stop-tooling" => {
                ensure!(
                    self.checks.contains("linux-runtime-stop"),
                    "runtime completion required"
                );
                logged(
                    &self.output,
                    "stop-tooling",
                    Command::new("docker").args(["rm", "--force", &self.container]),
                    120,
                )?;
                self.tooling_started = false;
                json!({"stopped":true})
            }
            "linux-receipt" => return self.receipt(),
            _ => bail!("unknown Linux qualification capability"),
        };
        self.checks.insert(key.clone());
        self.results.insert(key, result.clone());
        Ok(result)
    }

    fn receipt(&self) -> Result<Value> {
        ensure!(
            self.checks == required_steps() && !self.tooling_started,
            "incomplete Linux qualification"
        );
        day2::security_admission::require_linux_checks(&self.checks)?;
        let inputs = self.inputs.as_ref().context("captured platform")?;
        let source = self.source.as_ref().context("captured application")?;
        ensure!(
            PlatformInputs::capture(&self.root, &self.root.join("../.toolchains"))?.digest()
                == inputs.digest(),
            "platform sources changed during Linux qualification"
        );
        ensure!(
            PinnedTree::capture(&self.root.join("examples/reports"))?.digest() == source.digest()
                && Some(
                    PinnedTree::capture(&self.root.join("fixtures/row-authority-web-conformance"))?
                        .digest()
                        .as_str()
                        .to_owned()
                ) == self
                    .owned_source
                    .as_ref()
                    .map(|tree| tree.digest().as_str().to_owned()),
            "application source changed during Linux qualification"
        );
        let artifact = inspect_artifact(self.artifact.as_ref().context("artifact")?)?;
        let admitted = self
            .artifact_evidence
            .as_ref()
            .context("native artifact admission")?;
        ensure!(
            artifact["artifact"] == admitted["artifact"]
                && artifact["worker"] == admitted["worker"],
            "exported artifact changed after native admission"
        );
        let mut evidence = BTreeMap::new();
        for entry in fs::read_dir(&self.output)? {
            let entry = entry?;
            if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "log")
            {
                ensure!(
                    entry.file_type()?.is_file() && entry.metadata()?.len() <= 16 * 1024 * 1024,
                    "bounded qualification log required"
                );
                evidence.insert(
                    entry.file_name().to_string_lossy().into_owned(),
                    digest(&fs::read(entry.path())?),
                );
            }
        }
        let receipt = Receipt {
            format: 1,
            status: "passed",
            scope: "linux_sqlite_single_v1",
            platform: inputs.digest().as_str().to_owned(),
            workflow: day2::automation::source_digest(),
            platform_inventory: admitted["platform_inventory"]
                .as_str()
                .context("native platform inventory")?
                .to_owned(),
            toolchain: digest(&fs::read(self.root.join(native_platform()?.pin))?),
            source: source.digest().as_str().to_owned(),
            artifact: artifact["artifact"]
                .as_str()
                .context("artifact identity")?
                .to_owned(),
            worker: artifact["worker"]
                .as_str()
                .context("worker identity")?
                .to_owned(),
            applications: self
                .delegation
                .clone()
                .into_iter()
                .chain([(
                    "owned".to_owned(),
                    self.owned.clone().context("row-authority fixture build")?,
                )])
                .collect(),
            tooling_image: self.tooling_image.clone().context("tooling image")?,
            runtime_image: self.runtime_image.clone().context("runtime image")?,
            runtime_supervisor: self.results["linux-runtime-start"]["runtime_supervisor"]
                .as_str()
                .context("qualified runtime supervisor digest")?
                .to_owned(),
            runtime_sandbox: self.results["linux-runtime-start"]["runtime_sandbox"]
                .as_str()
                .context("qualified runtime sandbox digest")?
                .to_owned(),
            environment: self.environment.clone(),
            checks: self.checks.clone(),
            runtime: self.results.clone(),
            evidence,
            exclusions: vec![
                "complete-platform-verification",
                "formatter-qualification",
                "production-identity",
                "hostile-native-code-certification",
            ],
        };
        let path = self.output.join("qualification.json");
        let bytes = serde_json::to_vec_pretty(&receipt)?;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(
            json!({"status":"passed","scope":receipt.scope,"artifact":receipt.artifact,"runtime_image":receipt.runtime_image,"receipt":path,"digest":digest(&bytes)}),
        )
    }

    fn preserve_failed_tooling(&self) -> Result<()> {
        if !self.tooling_started || self.artifact.is_some() {
            return Ok(());
        }
        logged(
            &self.output,
            "failed-operation-export",
            Command::new("docker").args([
                "exec",
                &self.container,
                "cp",
                "-a",
                "/workspace/platform/artifacts/operations",
                "/qualification-export/failed-operations",
            ]),
            60,
        )?;
        self.hand_over("/qualification-export/failed-operations".to_owned())?;
        logged(
            &self.output,
            "failed-pointer-export",
            Command::new("docker").args([
                "exec",
                &self.container,
                "cp",
                "/workspace/platform/artifacts/current.json",
                "/qualification-export/failed-current.json",
            ]),
            60,
        )?;
        self.hand_over("/qualification-export/failed-current.json".to_owned())?;
        let pointer = read_json(&self.output.join("artifacts/failed-current.json"))?;
        let hash = day2::assets::hash_part(
            pointer["artifact"]
                .as_str()
                .context("failed artifact address")?,
        )?;
        let destination = self.output.join("artifacts").join(hash);
        if !destination.exists() {
            logged(
                &self.output,
                "failed-artifact-export",
                Command::new("docker")
                    .args(["exec", &self.container, "cp", "-a"])
                    .arg(format!("/workspace/platform/artifacts/{hash}"))
                    .arg(format!("/qualification-export/{hash}")),
                60,
            )?;
            self.hand_over(format!("/qualification-export/{hash}"))?;
        }
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.tooling_started {
            let _ = Command::new("docker")
                .args(["rm", "--force", &self.container])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

pub fn execute(root: &Path, output: &Path) -> Result<()> {
    let runner = workflows::build(root)?;
    preflight(&runner)?;
    let mut session = Session::new(root, output)?;
    let result = day2::automation::run(&runner, &["qualify-linux"], |request| {
        session.effect(request)
    });
    match result {
        Ok(receipt) => {
            println!("{receipt}");
            Ok(())
        }
        Err(error) => {
            let preservation = session.preserve_failed_tooling();
            fs::write(
                session.output.join("failure.json"),
                serde_json::to_vec_pretty(
                    &json!({"status":"failed","completed":session.checks,"error":format!("{error:#}"),
                        "platform":session.inputs.as_ref().map(|value|value.digest().as_str()),
                        "source":session.source.as_ref().map(|value|value.digest().as_str()),
                        "tooling_image":session.tooling_image,"runtime_image":session.runtime_image,
                        "failure_export_error":preservation.err().map(|error|format!("{error:#}"))}),
                )?,
            )?;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_linux_recipe_satisfies_receipt_and_security_admission() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let runner = workflows::build(&root)?;
        preflight(&runner)?;
        super::super::linux_runtime_qualification::strict_preflight(&runner)?;
        super::super::linux_runtime_qualification::provision_preflight(&runner)?;
        assert_eq!(required_steps().len(), 24);
        assert!(request_key("linux-test-suite", &json!("sandbox")).is_err());
        assert!(request_key("linux-test-suite", &json!({"suite":"other"})).is_err());
        assert!(request_key("linux-runtime-start", &json!({"image":"override"})).is_err());
        Ok(())
    }

    #[test]
    fn receipt_checks_reject_every_omission_and_obsolete_or_extra_names() -> Result<()> {
        // This is the producer's receipt vocabulary, independently checked by
        // the admission guard and by the actual compiled recipe test above.
        let checks: BTreeSet<String> =
            serde_json::from_value(serde_json::to_value(required_steps())?)?;
        day2::security_admission::require_linux_checks(&checks)?;
        for missing in &checks {
            let mut incomplete = checks.clone();
            incomplete.remove(missing);
            assert!(
                day2::security_admission::require_linux_checks(&incomplete).is_err(),
                "missing check admitted: {missing}"
            );
        }
        let mut obsolete = checks.clone();
        assert!(obsolete.remove("linux-build-owned"));
        obsolete.insert("linux-build-golinks".into());
        assert!(day2::security_admission::require_linux_checks(&obsolete).is_err());
        let mut extra = checks;
        extra.insert("unreviewed-check".into());
        assert!(day2::security_admission::require_linux_checks(&extra).is_err());
        Ok(())
    }

    #[test]
    fn foreign_artifact_transport_never_executes_worker_and_rejects_changed_bytes() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let worker = b"\x7fELFforeign-native-transport-fixture";
        let contract = json!({"worker_digest":digest(worker)});
        let id = digest(&serde_json::to_vec(&contract)?);
        let directory = temporary.path().join(day2::assets::hash_part(&id)?);
        fs::create_dir(&directory)?;
        fs::write(
            directory.join("artifact.json"),
            serde_json::to_vec(&contract)?,
        )?;
        fs::write(directory.join("worker"), worker)?;
        assert_eq!(inspect_artifact(&directory)?["artifact"], id);
        fs::write(directory.join("worker"), b"changed worker")?;
        assert!(inspect_artifact(&directory).is_err());
        fs::write(directory.join("worker"), worker)?;
        fs::write(
            directory.join("artifact.json"),
            b"{\"worker_digest\":\"changed\"}",
        )?;
        assert!(inspect_artifact(&directory).is_err());
        Ok(())
    }
}
