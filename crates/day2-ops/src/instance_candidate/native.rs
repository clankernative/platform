//! The build host's side of a candidate, run as root by
//! `day2 instance candidate native-build|native-probe JOB` in the private job
//! directory the deploy job created and filled over IAP. Value for value what
//! the earlier build host did:
//! - **native-build** takes one of two kernel-locked build slots, checks the
//!   source inputs and the checked main artifact, starts the app's pinned SDK
//!   tooling image with the native profile, proves its maintenance protocol,
//!   admits the artifact with the tooling's own `linux-artifact-security`,
//!   packages it on the pinned runtime image with the tooling's Dockerfile,
//!   pushes it and writes `result.json` and `build.log`. App code is never
//!   compiled here and no app build hook runs.
//! - **native-probe** proves a tooling image's maintenance protocol, under its
//!   own lock and with no other state.
//!
//! The request names a budget below the deploy job's own deadline: the slot
//! wait and every Docker command fit inside it, and no step starts after it, so
//! the session ends (and cleans up) before the deploy job gives up on it.
//!
//! The CLI running this was copied over the authenticated SSH channel with the
//! other job files. It checks those files against the request's identities
//! before anything else, which catches a short or corrupt copy, and logs the
//! digests of its own files; it cannot vouch for the binary already running it.
//!
//! Files copied out of the tooling image land in the slot's root-only staging
//! directory and are used only as regular files there. The registry token is
//! the build host's own (its metadata server), held only in a root-only tmpfs
//! Docker configuration that is wiped on every exit; it never reaches an
//! argument, a log, a receipt or an error.
use super::{Mode, NativeRequest, Receipt, inputs::source_inputs, read_bounded, record};
use crate::instance_source::{self, ARCHIVE_LIMIT, ARTIFACT_LIMIT, File, TarText, read_tar};
use crate::maintenance::{self, Sink, Supervision};
use anyhow::{Context, Result, anyhow, bail, ensure};
use day2::python_json::{self, Layout};
use day2::sdk_release::{self, BlobIdentity, EVIDENCE_LIMIT, FILE_LIMIT, MANIFEST_LIMIT, Release};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fmt, fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// The SDK tooling's day2 CLI inside its image.
pub const TOOLING_CLI: &str = "/workspace/platform/build-out/bin/day2";
/// The ABI seed paths a tooling image may carry, newest first.
pub const SEEDS: [&str; 2] = [
    "/usr/local/lib/day2/roc_platform_abi.rs",
    "/workspace/platform/crates/worker/generated/roc_platform_abi.rs",
];
const SEED_TARGET: &str = "/workspace/platform/crates/worker/generated/roc_platform_abi.rs";
/// The tooling's app Dockerfile inside its image.
const DOCKERFILE: &str = "/workspace/platform/deploy/gke/images/app/Dockerfile";
/// The most an ABI seed or a Dockerfile copied out of the tooling image may hold.
const SEED_LIMIT: u64 = 16 << 20;
const DOCKERFILE_LIMIT: u64 = 1 << 20;
/// What a recognized maintenance operation says about a deliberately absent
/// instance file. A legacy host prints its usage instead.
const PROTOCOL_ERROR: &str = "Error: No such file or directory (os error 2)";
const PROTOCOL_REFUSED: &str = "SDK lacks the required offline admission protocol; select a \
    compatible SDK release before deployment (no application was stopped)";
const DOCKERIGNORE: &[u8] = b"**\n!Dockerfile\n!artifacts/\n!artifacts/**\n";
/// Two bounded 4-CPU/6-GiB checks on the reviewed 8-vCPU build host.
pub const SLOTS: usize = 2;
/// How long a build waits for a free slot, within its budget.
pub const SLOT_WAIT: Duration = Duration::from_secs(900);
/// How long a probe waits for the probe lock, within its budget.
pub const PROBE_WAIT: Duration = Duration::from_secs(60);
/// The longest budget a request may name.
pub const BUDGET_LIMIT: u64 = 7200;
/// After a Docker failure, each native operation log read and all of them
/// together; then the container and tag removals, each `Verb::timeout`.
const EVIDENCE_READ: Duration = Duration::from_secs(30);
const EVIDENCE_TOTAL: Duration = Duration::from_secs(120);

/// The files a native build reads from its job directory, by request name.
pub const BUILD_FILES: [&str; 8] = [
    "ci-artifact.tar.gz",
    "cli/day2",
    "cli/day2-host",
    "cli/day2-workflows",
    "cli/day2-workflows.json",
    "qualification.json",
    "qualified-release.json",
    "source.tar.gz",
];

/// The files a native probe reads: the CLI only.
pub const PROBE_FILES: [&str; 4] = [
    "cli/day2",
    "cli/day2-host",
    "cli/day2-workflows",
    "cli/day2-workflows.json",
];

fn limit(name: &str) -> u64 {
    match name {
        "source.tar.gz" => ARCHIVE_LIMIT,
        "ci-artifact.tar.gz" => ARTIFACT_LIMIT,
        "qualified-release.json" => MANIFEST_LIMIT,
        "qualification.json" => EVIDENCE_LIMIT,
        _ => FILE_LIMIT,
    }
}

/// A registry token. Its bytes are never formatted, and are overwritten when
/// it is dropped.
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value.into_bytes())
    }

    fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
        std::hint::black_box(&self.0);
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret(<redacted>)")
    }
}

/// The build host's registry credential.
pub trait Token {
    fn fetch(&mut self) -> Result<Secret>;
}

/// A held build slot (or the probe lock): its index (none for the probe), its
/// root-only private directory, fresh and empty when taken, and the lock that
/// holds it, released when dropped or on exit.
pub struct Slot {
    pub index: Option<usize>,
    pub directory: PathBuf,
    pub lock: Option<fs::File>,
}

impl Slot {
    /// The private Docker configuration directory.
    pub fn auth(&self) -> PathBuf {
        self.directory.join("docker-auth")
    }

    /// Where files copied out of the tooling image land.
    pub fn staging(&self) -> PathBuf {
        self.directory.join("staging")
    }
}

/// The build slots, the probe lock and their private directories.
pub trait Slots {
    /// Take a free build slot within `wait`, its private directory (with empty
    /// `docker-auth` and `staging` directories) fresh.
    fn acquire(&mut self, wait: Duration) -> Result<Slot>;
    /// Take the probe lock within `wait`, its private directory fresh.
    fn probe(&mut self, wait: Duration) -> Result<Slot>;
    /// Wipe a slot's private directory.
    fn release(&mut self, slot: &Slot);
}

/// One Docker CLI invocation, with closed arguments built from validated
/// values only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verb {
    /// `docker login -u oauth2accesstoken --password-stdin <host>`.
    Login {
        host: String,
    },
    RemoveForce {
        container: String,
    },
    Remove {
        container: String,
    },
    RemoveImage {
        tag: String,
    },
    Create {
        name: String,
        image: String,
    },
    CopyOut {
        container: String,
        path: String,
        destination: PathBuf,
    },
    CopyIn {
        source: PathBuf,
        container: String,
        path: String,
    },
    /// The tooling container, with the native profile.
    Start {
        name: String,
        image: String,
        export: PathBuf,
        seed: Option<PathBuf>,
    },
    /// The maintenance protocol probe through a running tooling container.
    Protocol {
        container: String,
        absent: String,
    },
    InstallSeed {
        container: String,
    },
    Security {
        container: String,
        artifact: String,
    },
    Sha256 {
        container: String,
        path: String,
    },
    FindOperations {
        container: String,
    },
    Head {
        container: String,
        path: String,
    },
    Build {
        runtime: String,
        artifact_id: String,
        dockerfile: PathBuf,
        tag: String,
        context: PathBuf,
    },
    Push {
        tag: String,
    },
    RepoDigests {
        tag: String,
    },
    /// The maintenance protocol probe of a tooling image, without a slot.
    Probe {
        image: String,
        absent: String,
    },
}

impl Verb {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Login { .. } => "login",
            Self::RemoveForce { .. } | Self::Remove { .. } => "rm",
            Self::RemoveImage { .. } => "image rm",
            Self::Create { .. } => "create",
            Self::CopyOut { .. } | Self::CopyIn { .. } => "cp",
            Self::Start { .. } => "run",
            Self::Protocol { .. }
            | Self::InstallSeed { .. }
            | Self::Security { .. }
            | Self::Sha256 { .. }
            | Self::FindOperations { .. }
            | Self::Head { .. } => "exec",
            Self::Build { .. } => "build",
            Self::Push { .. } => "push",
            Self::RepoDigests { .. } => "image inspect",
            Self::Probe { .. } => "run --rm",
        }
    }

    /// The deadline: the earlier build host's.
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(match self {
            Self::Login { .. } | Self::Protocol { .. } | Self::Probe { .. } => 60,
            Self::RemoveForce { .. } | Self::RemoveImage { .. } => 120,
            _ => 3600,
        })
    }

    /// The Docker CLI arguments.
    pub fn args(&self) -> Vec<OsString> {
        let strings = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
        let protocol = |absent: &str| {
            vec![
                "admit-maintenance".to_owned(),
                absent.to_owned(),
                "sdk-probe".to_owned(),
                "sdk-probe@example.invalid".to_owned(),
            ]
        };
        match self {
            Self::Login { host } => {
                strings(&["login", "-u", "oauth2accesstoken", "--password-stdin", host])
            }
            Self::RemoveForce { container } => strings(&["rm", "--force", container]),
            Self::Remove { container } => strings(&["rm", container]),
            Self::RemoveImage { tag } => strings(&["image", "rm", tag]),
            Self::Create { name, image } => {
                strings(&["create", "--name", name, image, "sleep", "infinity"])
            }
            Self::CopyOut {
                container,
                path,
                destination,
            } => {
                let mut args = strings(&["cp", &format!("{container}:{path}")]);
                args.push(destination.into());
                args
            }
            Self::CopyIn {
                source,
                container,
                path,
            } => {
                let mut args = strings(&["cp"]);
                args.push(source.into());
                args.push(format!("{container}:{path}").into());
                args
            }
            Self::Start {
                name,
                image,
                export,
                seed,
            } => {
                let mut args = strings(&[
                    "run",
                    "--detach",
                    "--name",
                    name,
                    "--env",
                    "DAY2_PRECOMPILED_TOOLING=1",
                    "--network=none",
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
                ]);
                args.push(
                    format!(
                        "type=bind,source={},target=/qualification-export",
                        export.display()
                    )
                    .into(),
                );
                if let Some(seed) = seed {
                    args.push("--mount".into());
                    args.push(
                        format!(
                            "type=bind,source={},target=/qualification-abi-seed,readonly",
                            seed.display()
                        )
                        .into(),
                    );
                }
                args.extend(strings(&[image, "sleep", "infinity"]));
                args
            }
            Self::Protocol { container, absent } => {
                let mut args = strings(&["exec", container, TOOLING_CLI]);
                args.extend(protocol(absent).into_iter().map(OsString::from));
                args
            }
            Self::InstallSeed { container } => strings(&[
                "exec",
                container,
                "install",
                "-m",
                "0644",
                "/qualification-abi-seed",
                SEED_TARGET,
            ]),
            Self::Security {
                container,
                artifact,
            } => strings(&[
                "exec",
                container,
                "cli/xtask",
                "linux-artifact-security",
                artifact,
                "/qualification.json",
            ]),
            Self::Sha256 { container, path } => strings(&["exec", container, "sha256sum", path]),
            Self::FindOperations { container } => strings(&[
                "exec",
                container,
                "find",
                "/workspace/platform/artifacts/operations",
                "-maxdepth",
                "2",
                "-type",
                "f",
                "-name",
                "*.log",
                "-print",
            ]),
            Self::Head { container, path } => {
                strings(&["exec", container, "head", "-c", "262144", path])
            }
            Self::Build {
                runtime,
                artifact_id,
                dockerfile,
                tag,
                context,
            } => {
                let mut args = strings(&[
                    "build",
                    "--build-arg",
                    &format!("DAY2_RUNTIME_IMAGE={runtime}"),
                    "--build-arg",
                    &format!("ARTIFACT_ID={artifact_id}"),
                    "-f",
                ]);
                args.push(dockerfile.into());
                args.extend(strings(&["-t", tag]));
                args.push(context.into());
                args
            }
            Self::Push { tag } => strings(&["push", tag]),
            Self::RepoDigests { tag } => {
                strings(&["image", "inspect", "--format", "{{json .RepoDigests}}", tag])
            }
            Self::Probe { image, absent } => {
                let mut args = strings(&[
                    "run",
                    "--rm",
                    "--network=none",
                    "--memory=256m",
                    "--memory-swap=256m",
                    "--cpus=1",
                    "--pids-limit=64",
                    &format!("--entrypoint={TOOLING_CLI}"),
                    image,
                ]);
                args.extend(protocol(absent).into_iter().map(OsString::from));
                args
            }
        }
    }
}

/// Where a Docker command's output goes.
pub enum Output<'a> {
    /// stdout and stderr appended to the build log.
    Log(&'a fs::File),
    /// stdout captured, stderr appended to the build log.
    Split(&'a fs::File),
    /// Both captured.
    Capture,
}

/// What a Docker command returned.
pub struct Ran {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// The Docker CLI.
pub trait Docker {
    /// Run `verb` with `auth` as its Docker configuration, `stdin` and a
    /// deadline. Fails only when Docker could not be run or timed out; the
    /// caller judges the exit code.
    fn run(
        &mut self,
        verb: &Verb,
        auth: Option<&Path>,
        stdin: Option<&[u8]>,
        output: Output<'_>,
        timeout: Duration,
    ) -> Result<Ran>;
}

/// A Docker command that failed, timed out or could not run: after one, the
/// native operation logs are kept as evidence.
#[derive(Debug)]
pub struct DockerFailed(pub String);

impl fmt::Display for DockerFailed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for DockerFailed {}

/// What the build host reaches outside the job directory.
pub struct Effects {
    pub docker: Box<dyn Docker>,
    pub token: Box<dyn Token>,
    pub slots: Box<dyn Slots>,
    /// 32 lowercase hex digits.
    pub random: Box<dyn FnMut() -> Result<String>>,
}

impl Effects {
    /// The build host's own: refused unless this is root on linux-x86_64.
    pub fn native() -> Result<Self> {
        ensure!(
            cfg!(all(target_os = "linux", target_arch = "x86_64")),
            "native candidate commands run only on the linux-x86_64 build host"
        );
        ensure!(
            rustix::process::geteuid().is_root(),
            "native candidate commands run as root on the build host"
        );
        Ok(Self {
            docker: Box::new(DockerCli::native()?),
            token: Box::new(Metadata),
            slots: Box::new(HostSlots::native()),
            random: Box::new(super::random_hex),
        })
    }
}

/// The session a native command runs.
pub struct Native {
    mode: Mode,
    effects: Effects,
    job: PathBuf,
    owner: (u32, u32),
    /// When the session began; its budget runs from here.
    began: Instant,
    budget: Option<Duration>,
    done: usize,
    request: Option<NativeRequest>,
    release: Option<Release>,
    log: Option<fs::File>,
    slot: Option<Slot>,
    container: Option<String>,
    seed: Option<PathBuf>,
    artifact_id: Option<String>,
    security: Option<Value>,
    tag: Option<String>,
    image: Option<String>,
    started: bool,
    cleaned: bool,
}

impl Native {
    pub fn steps(mode: Mode) -> &'static [&'static str] {
        match mode {
            Mode::NativeBuild => &[
                "request", "slot", "inputs", "artifact", "tooling", "protocol", "security",
                "package", "push", "result",
            ],
            _ => &["request", "probe"],
        }
    }

    /// Open the session for the private job directory `job`: a directory, not
    /// a link, with no group or other access. Nothing in it is read yet.
    pub fn prepare(mode: Mode, job: &Path, effects: Effects) -> Result<Self> {
        let began = Instant::now();
        let metadata = fs::symlink_metadata(job)
            .with_context(|| format!("the native job directory {}", job.display()))?;
        ensure!(
            metadata.is_dir() && metadata.mode() & 0o077 == 0,
            "the native job directory must be a private directory: {}",
            job.display()
        );
        Ok(Self {
            mode,
            effects,
            job: job.to_owned(),
            owner: (metadata.uid(), metadata.gid()),
            began,
            budget: None,
            done: 0,
            request: None,
            release: None,
            log: None,
            slot: None,
            container: None,
            seed: None,
            artifact_id: None,
            security: None,
            tag: None,
            image: None,
            started: false,
            cleaned: false,
        })
    }

    /// Run the mode's next step, which must be `name`. No step starts after the
    /// request's budget. A failed step leaves its evidence in the build log and
    /// cleans up; the last step cleans up too.
    pub fn step(&mut self, name: &str) -> Result<Value> {
        let steps = Self::steps(self.mode);
        let expected = steps.get(self.done).copied();
        let Some(next) = expected.filter(|next| *next == name) else {
            bail!(
                "instance candidate {} runs {} next, not {name}",
                self.mode.name(),
                expected.unwrap_or("nothing more")
            );
        };
        let ran = if next == "request" {
            self.request()
        } else {
            self.remaining().and_then(|_| match next {
                "slot" => self.slot(),
                "inputs" => self.inputs(),
                "artifact" => self.artifact(),
                "tooling" => self.tooling(),
                "protocol" => self.protocol(),
                "security" => self.security(),
                "package" => self.package(),
                "push" => self.push(),
                "probe" => self.probe(),
                _ => self.result(),
            })
        };
        match ran {
            Ok(value) => {
                self.done += 1;
                Ok(value)
            }
            Err(error) => {
                self.failed(&error);
                Err(error)
            }
        }
    }

    /// What is left of the request's budget; refused once it is spent.
    fn remaining(&self) -> Result<Duration> {
        let budget = self.budget.context("native request")?;
        let left = budget.saturating_sub(self.began.elapsed());
        ensure!(
            !left.is_zero(),
            "the build host's {} exceeded its {} s budget",
            self.mode.name(),
            budget.as_secs()
        );
        Ok(left)
    }

    fn request_ref(&self) -> Result<&NativeRequest> {
        self.request.as_ref().context("native request")
    }

    fn binding(&self) -> Result<&Value> {
        self.request_ref()?
            .binding
            .as_ref()
            .context("native build binding")
    }

    fn container(&self) -> Result<String> {
        self.container.clone().context("build slot")
    }

    fn auth(&self) -> Option<PathBuf> {
        self.slot.as_ref().map(Slot::auth)
    }

    fn staging(&self) -> Result<PathBuf> {
        Ok(self.slot.as_ref().context("build slot")?.staging())
    }

    /// The build log, created 0600 without following a link, appended to.
    fn log(&mut self) -> Result<&fs::File> {
        if self.log.is_none() {
            let file = fs::OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(self.job.join("build.log"))
                .context("the native build log")?;
            self.log = Some(file);
        }
        self.log.as_ref().context("native build log")
    }

    fn note(&mut self, text: &str) -> Result<()> {
        let mut log = self.log()?;
        log.write_all(text.as_bytes())?;
        log.flush()?;
        Ok(())
    }

    /// Run a Docker verb within what is left of the budget; Docker failing to
    /// run or timing out is a Docker failure, the exit code is the caller's.
    fn run(
        &mut self,
        verb: &Verb,
        stdin: Option<&[u8]>,
        output: Output<'_>,
        timeout: Duration,
    ) -> Result<Ran> {
        let auth = self.auth();
        self.effects
            .docker
            .run(verb, auth.as_deref(), stdin, output, timeout)
            .map_err(|error| anyhow!(DockerFailed(format!("docker {}: {error:#}", verb.name()))))
    }

    /// A Docker verb whose output goes to the build log; a non-zero exit is a
    /// Docker failure.
    fn docker(&mut self, verb: &Verb) -> Result<()> {
        let timeout = verb.timeout().min(self.remaining()?);
        let log = self.log()?.try_clone()?;
        let ran = self.run(verb, None, Output::Log(&log), timeout)?;
        ensure!(
            ran.code == Some(0),
            DockerFailed(format!("docker {} exited {}", verb.name(), exit(ran.code)))
        );
        Ok(())
    }

    /// A Docker verb's stdout; its stderr goes to the build log.
    fn captured(&mut self, verb: &Verb, timeout: Duration) -> Result<Vec<u8>> {
        let log = self.log()?.try_clone()?;
        let ran = self.run(verb, None, Output::Split(&log), timeout)?;
        ensure!(
            ran.code == Some(0),
            DockerFailed(format!("docker {} exited {}", verb.name(), exit(ran.code)))
        );
        Ok(ran.stdout)
    }

    /// A fresh token from the build host's metadata server, given to
    /// `docker login` on stdin only.
    fn login(&mut self, logged: bool) -> Result<()> {
        let host = registry_host(&self.request_ref()?.registry)?;
        let verb = Verb::Login { host };
        let timeout = verb.timeout().min(self.remaining()?);
        let token = self.effects.token.fetch()?;
        let log = if logged {
            Some(self.log()?.try_clone()?)
        } else {
            None
        };
        let output = match &log {
            Some(file) => Output::Log(file),
            None => Output::Capture,
        };
        let ran = self.run(&verb, Some(token.bytes()), output, timeout)?;
        drop(token);
        if !logged && ran.code != Some(0) {
            eprint!("{}", String::from_utf8_lossy(&ran.stderr));
        }
        ensure!(
            ran.code == Some(0),
            DockerFailed(format!("docker login exited {}", exit(ran.code)))
        );
        Ok(())
    }

    /// Check the request and every file it names, before anything else.
    fn request(&mut self) -> Result<Value> {
        let raw = read_bounded(&self.job.join("request.json"), record::RECORD_LIMIT)?;
        let request: NativeRequest = day2::json::decode(&raw).context("invalid native request")?;
        ensure!(
            request.format == 1 && request.mode == self.mode,
            "the host started an instance candidate {} but the job is for another command",
            self.mode.name()
        );
        ensure!(
            (1..=BUDGET_LIMIT).contains(&request.budget_seconds),
            "the native request's budget must be 1 to {BUDGET_LIMIT} s"
        );
        self.budget = Some(Duration::from_secs(request.budget_seconds));
        ensure!(
            super::registry(&request.registry),
            "the native request's registry must be <region>-docker.pkg.dev/<project>"
        );
        let wanted: BTreeSet<&str> = match self.mode {
            Mode::NativeBuild => BUILD_FILES.into_iter().collect(),
            _ => PROBE_FILES.into_iter().collect(),
        };
        ensure!(
            request
                .files
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == wanted,
            "the native request must name exactly its job files"
        );
        for (name, expected) in &request.files {
            let path = self.job.join(name);
            ensure!(
                sdk_release::identity(&path, limit(name)).ok().as_ref() == Some(expected),
                "the native job's {name} differs from the request"
            );
        }
        let reported = match self.mode {
            Mode::NativeBuild => {
                ensure!(
                    request.tooling_image.is_none(),
                    "a native build request names its images in its binding"
                );
                let binding = request.binding.as_ref().context("native build binding")?;
                let app = record::native_binding(binding, &request.registry)?;
                ensure!(app == request.app, "the native request is for another app");
                let commit = request.source_commit.as_deref().unwrap_or_default();
                ensure!(
                    instance_source::commit(commit),
                    "exact build commit required"
                );
                ensure!(
                    request
                        .source_inputs
                        .as_deref()
                        .is_some_and(instance_source::hash)
                        && request.ci_artifact.is_some(),
                    "checked-main artifact provenance required"
                );
                let reference: BlobIdentity =
                    serde_json::from_value(binding["qualified_release"].clone())?;
                ensure!(
                    request.files["qualified-release.json"] == reference,
                    "builder received another qualified platform release"
                );
                // The bytes decoded are the bytes checked.
                let manifest = verified(
                    &self.job.join("qualified-release.json"),
                    &reference,
                    MANIFEST_LIMIT,
                    "builder received another qualified platform release",
                )?;
                let release = Release::decode(&manifest)?;
                release.pinned_under(&request.registry)?;
                let digest =
                    |image: &str| image.split_once('@').map(|(_, digest)| digest.to_owned());
                ensure!(
                    digest(binding["runtime_image"].as_str().unwrap_or_default())
                        == digest(&release.runtime.image)
                        && digest(binding["tooling_image"].as_str().unwrap_or_default())
                            == digest(&release.tooling.image),
                    "builder images differ from the qualified release"
                );
                ensure!(
                    request.files["qualification.json"] == release.evidence.native,
                    "builder received another native qualification receipt"
                );
                self.release = Some(release);
                json!({"app": app, "commit": commit})
            }
            _ => {
                ensure!(
                    instance_source::identifier(&request.app),
                    "invalid SDK probe app"
                );
                ensure!(
                    request.binding.is_none()
                        && request.source_commit.is_none()
                        && request.source_inputs.is_none()
                        && request.ci_artifact.is_none(),
                    "a native probe request names only its tooling image"
                );
                let image = request.tooling_image.as_deref().unwrap_or_default();
                ensure!(
                    instance_source::app_image(image, &request.registry, &request.app, true),
                    "SDK probe requires a pinned app-local image"
                );
                json!({"app": request.app, "tooling_image": image})
            }
        };
        self.request = Some(request);
        Ok(reported)
    }

    /// Take a build slot: kernel-owned, so a slot survives a lost connection
    /// and is released when this process exits.
    fn slot(&mut self) -> Result<Value> {
        let wait = SLOT_WAIT.min(self.remaining()?);
        let slot = self.effects.slots.acquire(wait)?;
        let index = slot.index.context("a build slot has an index")?;
        self.container = Some(format!("day2-app-slot-{index}"));
        self.slot = Some(slot);
        Ok(json!({"slot": index}))
    }

    /// The app's source inputs, again, from the archive's own bytes.
    fn inputs(&mut self) -> Result<Value> {
        let binding = self.binding()?.clone();
        let expected = self.request_ref()?.files["source.tar.gz"].clone();
        let archive = verified(
            &self.job.join("source.tar.gz"),
            &expected,
            ARCHIVE_LIMIT,
            "the native job's source.tar.gz differs from the request",
        )?;
        let inputs = source_inputs(&archive, binding["directory"].as_str().unwrap_or_default())?;
        ensure!(
            Some(inputs.as_str()) == self.request_ref()?.source_inputs.as_deref(),
            "builder received different app source inputs"
        );
        Ok(json!({"source_inputs": inputs}))
    }

    /// The checked main artifact's provenance, then its archive, extracted for
    /// transport only: the SDK's own admission is authoritative.
    fn artifact(&mut self) -> Result<Value> {
        let request = self.request_ref()?;
        let binding = self.binding()?.clone();
        let checked = request.ci_artifact.clone().context("checked artifact")?;
        let commit = request.source_commit.clone().context("commit")?;
        let inputs = request.source_inputs.clone().context("source inputs")?;
        let transported = request.files["ci-artifact.tar.gz"].clone();
        let cli = PROBE_FILES
            .iter()
            .map(|name| format!("{name} {}", request.files[*name].digest))
            .collect::<Vec<_>>()
            .join(", ");
        instance_source::proof(&checked, &binding, &commit, &inputs)?;
        ensure!(
            serde_json::to_value(&transported)? == checked["receipt"]["archive"],
            "checked artifact archive changed"
        );
        let artifacts = self.job.join("artifacts");
        fs::create_dir(&artifacts).context("the native artifacts directory")?;
        let artifact_id = extract(
            &self.job.join("ci-artifact.tar.gz"),
            &artifacts,
            &checked["receipt"],
        )?;
        let mut header =
            b"Promoting checked main artifact; no app compilation or campaign rerun\n".to_vec();
        header.extend(python_json::dumps(&checked, Layout::Default)?);
        header.push(b'\n');
        self.note(std::str::from_utf8(&header)?)?;
        self.note(&format!("Native build by the instance's day2 CLI: {cli}\n"))?;
        self.artifact_id = Some(artifact_id.clone());
        Ok(json!({"artifact_id": artifact_id}))
    }

    /// Copy `path` out of the container into the slot's staging directory, as
    /// `name`. Returns `None` when Docker could not copy it, and the staged file,
    /// opened without following a link, only when it is a single regular file
    /// within `limit`; anything else the image put there is refused.
    fn copy_out(
        &mut self,
        container: &str,
        path: &str,
        name: &str,
        limit: u64,
    ) -> Result<Option<(PathBuf, fs::File)>> {
        let destination = self.staging()?.join(name);
        remove_staged(&destination)?;
        let verb = Verb::CopyOut {
            container: container.to_owned(),
            path: path.to_owned(),
            destination: destination.clone(),
        };
        let timeout = verb.timeout().min(self.remaining()?);
        let log = self.log()?.try_clone()?;
        if self.run(&verb, None, Output::Log(&log), timeout)?.code != Some(0) {
            return Ok(None);
        }
        let file = staged_file(&destination, limit).with_context(|| {
            format!("the tooling image's {path} must be a regular file of at most {limit} bytes")
        })?;
        Ok(Some((destination, file)))
    }

    /// Reap the slot's container, log in, read the tooling's own ABI seed, then
    /// start the tooling container with the native profile.
    fn tooling(&mut self) -> Result<Value> {
        let container = self.container()?;
        let image = self.binding()?["tooling_image"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        self.started = true;
        // A killed build can leave its container alive; reap only this
        // kernel-locked slot's container before admitting more work.
        let reap = Verb::RemoveForce {
            container: container.clone(),
        };
        let timeout = reap.timeout().min(self.remaining()?);
        let log = self.log()?.try_clone()?;
        self.run(&reap, None, Output::Log(&log), timeout)?;
        self.login(true)?;
        self.docker(&Verb::Create {
            name: container.clone(),
            image: image.clone(),
        })?;
        for path in SEEDS {
            if let Some((staged, file)) =
                self.copy_out(&container, path, "roc_platform_abi.rs", SEED_LIMIT)?
            {
                // On the descriptor of the regular file checked, never a link.
                file.set_permissions(fs::Permissions::from_mode(0o444))?;
                self.seed = Some(staged);
                break;
            }
        }
        if self.seed.is_none() {
            self.note("No prepackaged ABI seed; using native tooling generation\n")?;
        }
        self.docker(&Verb::Remove {
            container: container.clone(),
        })?;
        self.docker(&Verb::Start {
            name: container,
            image,
            export: self.job.join("artifacts"),
            seed: self.seed.clone(),
        })?;
        Ok(json!({"seed": self.seed.is_some()}))
    }

    /// The tooling's maintenance protocol, then its own ABI seed restored.
    fn protocol(&mut self) -> Result<Value> {
        let container = self.container()?;
        let absent = format!("/tmp/day2-sdk-protocol-{}.json", (self.effects.random)()?);
        let verb = Verb::Protocol {
            container: container.clone(),
            absent,
        };
        let timeout = verb.timeout().min(self.remaining()?);
        let ran = self.run(&verb, None, Output::Capture, timeout)?;
        self.judge(&ran)?;
        self.note("Verified native maintenance protocol before application mutation\n")?;
        if self.seed.is_some() {
            self.docker(&Verb::InstallSeed { container })?;
        }
        Ok(json!({"protocol": "admit-maintenance"}))
    }

    /// A recognized maintenance operation fails to open the absent instance:
    /// exit 1, no stdout, exactly the file error. Anything else is refused, and
    /// its output goes to the build log (native-build) or stderr (native-probe).
    fn judge(&mut self, ran: &Ran) -> Result<()> {
        let supported = ran.code == Some(1)
            && ran.stdout.is_empty()
            && String::from_utf8_lossy(&ran.stderr).trim() == PROTOCOL_ERROR;
        if !supported {
            let cut = |bytes: &[u8]| {
                String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]).into_owned()
            };
            let text = format!(
                "SDK protocol probe refused (exit {}):\n{}{}\n",
                exit(ran.code),
                cut(&ran.stdout),
                cut(&ran.stderr)
            );
            if self.mode == Mode::NativeBuild {
                self.note(&text)?;
            } else {
                eprint!("{text}");
            }
            bail!(PROTOCOL_REFUSED);
        }
        Ok(())
    }

    /// The tooling's own native admission of this artifact, bound to the
    /// release's native qualification. Its output must be encodable as the
    /// candidate record encodes it, before anything is pushed.
    fn security(&mut self) -> Result<Value> {
        let container = self.container()?;
        let artifact_id = self.artifact_id.clone().context("artifact")?;
        let native = self
            .release
            .as_ref()
            .context("release")?
            .evidence
            .native
            .clone();
        // The bytes copied in are the bytes checked, from the root-only staging.
        let evidence = verified(
            &self.job.join("qualification.json"),
            &native,
            EVIDENCE_LIMIT,
            "builder received another native qualification receipt",
        )?;
        let staged = self.staging()?.join("qualification.json");
        remove_staged(&staged)?;
        super::tools::write_private(&staged, &evidence)?;
        self.docker(&Verb::CopyIn {
            source: staged,
            container: container.clone(),
            path: "/qualification.json".to_owned(),
        })?;
        let verb = Verb::Security {
            container,
            artifact: format!("/qualification-export/{artifact_id}"),
        };
        let timeout = verb.timeout().min(self.remaining()?);
        let raw = self.captured(&verb, timeout)?;
        let security: Value = day2::json::decode_with_limits(
            &raw,
            record::RECORD_LIMIT as usize,
            record::RECORD_LIMIT as usize,
        )
        .context("invalid native admission evidence")?;
        ensure!(
            security["artifact"] == format!("sha256:{artifact_id}")
                && security["containment"]["evidence"]["receipt_digest"] == native.digest,
            "native admission evidence mismatch"
        );
        python_json::dumps(&security, Layout::Default)
            .context("the native admission evidence cannot be recorded")?;
        self.security = Some(security);
        Ok(json!({"artifact": format!("sha256:{artifact_id}")}))
    }

    /// The exported artifact must be the one admitted; then it is packaged on
    /// the pinned runtime image with the tooling's own Dockerfile.
    fn package(&mut self) -> Result<Value> {
        let container = self.container()?;
        let artifact_id = self.artifact_id.clone().context("artifact")?;
        let binding = self.binding()?.clone();
        let commit = self
            .request_ref()?
            .source_commit
            .clone()
            .context("commit")?;
        let verb = Verb::Sha256 {
            container: container.clone(),
            path: format!("/qualification-export/{artifact_id}/artifact.json"),
        };
        let timeout = verb.timeout().min(self.remaining()?);
        let output = self.captured(&verb, timeout)?;
        let admitted = String::from_utf8_lossy(&output)
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned();
        let root = self.job.join("artifacts").join(&artifact_id);
        let exported = day2::digest(&read_bounded(&root.join("artifact.json"), ARTIFACT_LIMIT)?);
        ensure!(
            exported["sha256:".len()..] == admitted,
            "exported artifact differs from the checked artifact"
        );
        write_protect(&root)?;
        let Some((dockerfile, _)) =
            self.copy_out(&container, DOCKERFILE, "Dockerfile", DOCKERFILE_LIMIT)?
        else {
            bail!(DockerFailed(
                "docker cp could not copy the tooling's Dockerfile".to_owned()
            ));
        };
        super::tools::write_private(&self.job.join(".dockerignore"), DOCKERIGNORE)?;
        let random = (self.effects.random)()?;
        let repository = binding["image_repository"].as_str().unwrap_or_default();
        let tag = format!("{repository}:source-{commit}-{}", &random[..12]);
        self.tag = Some(tag.clone());
        self.docker(&Verb::Build {
            runtime: binding["runtime_image"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            artifact_id,
            dockerfile,
            tag: tag.clone(),
            context: self.job.clone(),
        })?;
        Ok(json!({"tag": tag}))
    }

    /// A fresh token, the push, and the one exact digest the registry returned.
    fn push(&mut self) -> Result<Value> {
        let tag = self.tag.clone().context("tag")?;
        let repository = self.binding()?["image_repository"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        self.login(true)?;
        self.docker(&Verb::Push { tag: tag.clone() })?;
        let verb = Verb::RepoDigests { tag };
        let timeout = verb.timeout().min(self.remaining()?);
        let raw = self.captured(&verb, timeout)?;
        let digests: Vec<String> = serde_json::from_slice(&raw)
            .map_err(|_| anyhow!("registry did not return an exact app image digest"))?;
        let pinned: Vec<&String> = digests
            .iter()
            .filter(|value| value.starts_with(&format!("{repository}@")))
            .collect();
        ensure!(
            pinned.len() == 1,
            "registry did not return an exact app image digest"
        );
        self.image = Some(pinned[0].clone());
        Ok(json!({"image": pinned[0]}))
    }

    /// result.json, the build log, and the receipt.
    fn result(&mut self) -> Result<Value> {
        let request = self.request_ref()?;
        let commit = request.source_commit.clone().context("commit")?;
        let result = json!({
            "version": 1,
            "binding": request.binding,
            "source_commit": commit,
            "image": self.image.clone().context("image")?,
            "artifact_id": self.artifact_id.clone().context("artifact")?,
            "security_requirements": self.security.clone().context("native admission")?,
            "source_inputs": request.source_inputs,
            "checked_commit": commit,
            "ci_artifact": request.ci_artifact,
        });
        let app = request.app.clone();
        let mut bytes = serde_json::to_vec(&result)?;
        bytes.push(b'\n');
        let path = self.job.join("result.json");
        super::tools::write_private(&path, &bytes)?;
        let slot = self
            .slot
            .as_ref()
            .and_then(|slot| slot.index)
            .map(|index| index as u64);
        self.cleanup();
        let file = |path: &Path| -> Result<File> {
            let identity = sdk_release::identity(path, FILE_LIMIT)?;
            Ok(File {
                path: path.to_str().context("job path must be UTF-8")?.to_owned(),
                digest: identity.digest,
                bytes: identity.bytes,
            })
        };
        Ok(serde_json::to_value(Receipt {
            app_id: Some(app),
            commit: Some(commit),
            slot,
            result: Some(file(&path)?),
            log: Some(file(&self.job.join("build.log"))?),
            image: self.image.clone(),
            artifact_id: self.artifact_id.clone(),
            ..Receipt::new(self.mode)
        })?)
    }

    /// The tooling image's maintenance protocol, under the probe lock and from
    /// its fresh private Docker configuration.
    fn probe(&mut self) -> Result<Value> {
        let request = self.request_ref()?;
        let image = request.tooling_image.clone().context("tooling image")?;
        let app = request.app.clone();
        let wait = PROBE_WAIT.min(self.remaining()?);
        self.slot = Some(self.effects.slots.probe(wait)?);
        self.login(false)?;
        let absent = format!("/tmp/day2-sdk-protocol-{}.json", (self.effects.random)()?);
        let verb = Verb::Probe {
            image: image.clone(),
            absent,
        };
        let timeout = verb.timeout().min(self.remaining()?);
        let ran = self.run(&verb, None, Output::Capture, timeout)?;
        self.judge(&ran)?;
        self.cleanup();
        Ok(serde_json::to_value(Receipt {
            app_id: Some(app),
            tooling_image: Some(image),
            ..Receipt::new(self.mode)
        })?)
    }

    /// A failed step: the native operation logs after a Docker failure, then
    /// the container and tag are removed, then the error is logged last.
    fn failed(&mut self, error: &anyhow::Error) {
        let docker = error.chain().any(|cause| cause.is::<DockerFailed>());
        if self.mode == Mode::NativeBuild && docker && self.started {
            self.evidence();
        }
        self.cleanup();
        if self.mode == Mode::NativeBuild {
            let _ = self.note(&format!("\nnative build failed: {error:#}\n"));
            self.hand_over();
        }
    }

    /// The native CLI reports a private operation log instead of printing
    /// compiler diagnostics: keep up to 16 of them (the first 16 found, then
    /// only well-named logs) before the container goes, within
    /// `EVIDENCE_TOTAL`, even past the budget.
    fn evidence(&mut self) {
        let Ok(container) = self.container() else {
            return;
        };
        let began = Instant::now();
        let found = self.captured(
            &Verb::FindOperations {
                container: container.clone(),
            },
            EVIDENCE_READ,
        );
        let kept = found.map(|raw| {
            String::from_utf8_lossy(&raw)
                .lines()
                .take(16)
                .filter(|path| operation_log(path))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        });
        let ok = match kept {
            Ok(paths) => paths.into_iter().all(|path| {
                let left = EVIDENCE_TOTAL.saturating_sub(began.elapsed());
                if left.is_zero() {
                    return false;
                }
                let head = self.captured(
                    &Verb::Head {
                        container: container.clone(),
                        path: path.clone(),
                    },
                    EVIDENCE_READ.min(left),
                );
                match head {
                    Ok(bytes) => self
                        .note(&format!(
                            "\nNative operation evidence: {path}\n{}",
                            String::from_utf8_lossy(&bytes)
                        ))
                        .is_ok(),
                    Err(_) => false,
                }
            }),
            Err(_) => false,
        };
        if !ok {
            let _ = self.note("Could not retrieve native operation evidence\n");
        }
    }

    /// Remove this job's container and local tag, wipe the slot's private
    /// directory and hand the job's outputs to the directory's owner.
    fn cleanup(&mut self) {
        if self.cleaned {
            return;
        }
        self.cleaned = true;
        if let Some(container) = self.container.clone()
            && let Ok(log) = self.log().and_then(|log| Ok(log.try_clone()?))
        {
            let reap = Verb::RemoveForce { container };
            let _ = self.run(&reap, None, Output::Log(&log), reap.timeout());
            if let Some(tag) = self.tag.clone() {
                let untag = Verb::RemoveImage { tag };
                let _ = self.run(&untag, None, Output::Log(&log), untag.timeout());
            }
        }
        if let Some(slot) = self.slot.take() {
            self.effects.slots.release(&slot);
        }
        self.hand_over();
    }

    /// The job's outputs belong to the job directory's owner, mode 0600.
    fn hand_over(&self) {
        for name in ["build.log", "result.json"] {
            let path = self.job.join(name);
            if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_file()) {
                let _ = std::os::unix::fs::chown(&path, Some(self.owner.0), Some(self.owner.1));
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            }
        }
    }
}

impl Drop for Native {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn exit(code: Option<i32>) -> String {
    code.map_or_else(|| "by a signal".to_owned(), |code| code.to_string())
}

/// `<region>-docker.pkg.dev`, the registry's host.
fn registry_host(registry: &str) -> Result<String> {
    registry
        .split_once('/')
        .map(|(host, _)| host.to_owned())
        .context("invalid registry")
}

/// `/workspace/platform/artifacts/operations/<id>/<name>.log`.
fn operation_log(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/workspace/platform/artifacts/operations/") else {
        return false;
    };
    let Some((directory, name)) = rest.split_once('/') else {
        return false;
    };
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    !directory.is_empty()
        && directory.bytes().all(word)
        && name.ends_with(".log")
        && name.len() > ".log".len()
        && name.bytes().all(|b| word(b) || b == b'.')
}

/// A file's bytes, read once, which must be exactly `expected`.
fn verified(path: &Path, expected: &BlobIdentity, limit: u64, message: &str) -> Result<Vec<u8>> {
    let bytes = read_bounded(path, limit)?;
    ensure!(BlobIdentity::of(&bytes) == *expected, "{message}");
    Ok(bytes)
}

/// Remove whatever is at a staging path, without following a link.
fn remove_staged(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path)?,
        Ok(_) => fs::remove_file(path)?,
        Err(_) => {}
    }
    Ok(())
}

/// A staged file, opened without following a link: one regular file (a single
/// link to it) of at most `limit` bytes.
pub(crate) fn staged_file(path: &Path, limit: u64) -> Result<fs::File> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file(),
        "not a regular file: {}",
        path.display()
    );
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let opened = file.metadata()?;
    ensure!(
        opened.file_type().is_file()
            && opened.nlink() == 1
            && opened.len() <= limit
            && opened.ino() == metadata.ino(),
        "not a single regular file within its bound: {}",
        path.display()
    );
    Ok(file)
}

/// Refuse links in the artifact tree and remove every write bit.
pub(crate) fn write_protect(root: &Path) -> Result<()> {
    let mut pending = vec![root.to_owned()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(!metadata.file_type().is_symlink(), "artifact links refused");
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        }
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(metadata.mode() & 0o7777 & !0o222),
        )?;
    }
    Ok(())
}

const ARTIFACT_TEXT: TarText = TarText {
    unreadable: "unreadable checked artifact",
    unsupported: "unsafe checked artifact entry",
    global: "unsafe checked artifact entry",
    budget: "checked artifact expands beyond byte budget",
};

/// The checked artifact archive named by `receipt`, extracted below
/// `destination` for transport only, as the earlier build host extracted it.
/// Returns its artifact ID. The archive's bytes are read once and checked
/// against the receipt. Every entry is one regular file below the artifact's
/// directory, with a canonical name of at most 1024 bytes and mode 0444 or
/// 0555, at most once; 4096 entries and 128 MiB in all; the manifest, worker
/// and verification record must be present.
pub fn extract(archive: &Path, destination: &Path, receipt: &Value) -> Result<String> {
    let expected: BlobIdentity = serde_json::from_value(receipt["archive"].clone())
        .map_err(|_| anyhow!("checked artifact archive changed"))?;
    let bytes = verified(
        archive,
        &expected,
        ARTIFACT_LIMIT,
        "checked artifact archive changed",
    )?;
    let artifact_id = receipt["artifact_id"]
        .as_str()
        .filter(|id| instance_source::lower_hex(id, 64))
        .context("invalid checked artifact")?
        .to_owned();
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    read_tar(
        &bytes,
        ARTIFACT_LIMIT + (8 << 20) + 1,
        &ARTIFACT_TEXT,
        |member, data| {
            let name: String = member
                .name
                .iter()
                .map(|code| char::from_u32(*code).unwrap_or('\u{fffd}'))
                .collect();
            let canonical = member
                .parts
                .iter()
                .map(|part| {
                    part.iter()
                        .map(|code| char::from_u32(*code).unwrap_or('\u{fffd}'))
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("/");
            ensure!(
                member.parts.len() > 1
                    && member.parts[0].first() != Some(&u32::from(b'/'))
                    && member.parts[0]
                        .iter()
                        .copied()
                        .eq(artifact_id.chars().map(u32::from))
                    && !member
                        .parts
                        .iter()
                        .any(|part| crate::instance_source::ascii(part, ".."))
                    && !member.name.contains(&u32::from(b'\\'))
                    && member
                        .name
                        .iter()
                        .all(|code| char::from_u32(*code).is_some())
                    && canonical == name
                    && name.len() <= 1024
                    && member.kind == crate::instance_source::Kind::Regular
                    && matches!(member.mode, 0o444 | 0o555)
                    && !seen.contains(&name),
                "unsafe checked artifact entry"
            );
            seen.insert(name.clone());
            total = total.saturating_add(member.size);
            ensure!(
                member.size <= ARTIFACT_LIMIT && total <= ARTIFACT_LIMIT && seen.len() <= 4096,
                "checked artifact exceeds byte/file budget"
            );
            let target = destination.join(&name);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(&target)?;
            let copied = std::io::copy(&mut data.take(member.size), &mut file)?;
            ensure!(copied == member.size, "unreadable checked artifact");
            file.set_permissions(fs::Permissions::from_mode(member.mode))?;
            Ok(())
        },
    )?;
    ensure!(
        ["artifact.json", "worker", "verification.json"]
            .iter()
            .all(|file| seen.contains(&format!("{artifact_id}/{file}"))),
        "checked artifact is incomplete"
    );
    Ok(artifact_id)
}

/// The Docker CLI: root's `docker`, or a stub executable in tests. Each run is
/// in its own process group, killed whole at its deadline.
pub struct DockerCli {
    program: Option<PathBuf>,
}

impl DockerCli {
    pub fn native() -> Result<Self> {
        Ok(Self {
            program: Some(maintenance::on_path("docker")?),
        })
    }

    pub fn at(program: PathBuf) -> Self {
        Self {
            program: Some(program),
        }
    }
}

impl Docker for DockerCli {
    fn run(
        &mut self,
        verb: &Verb,
        auth: Option<&Path>,
        stdin: Option<&[u8]>,
        output: Output<'_>,
        timeout: Duration,
    ) -> Result<Ran> {
        let mut command = maintenance::tool("docker", self.program.as_deref())?;
        command.args(verb.args());
        if let Some(auth) = auth {
            command.env("DOCKER_CONFIG", auth);
        }
        let sink = match output {
            Output::Log(log) => Sink::Log(log),
            Output::Split(log) => Sink::Split(log),
            Output::Capture => Sink::Capture,
        };
        let finished = maintenance::supervise(
            &mut command,
            Supervision {
                stdin,
                timeout,
                interrupted: None,
                sink,
                group: true,
            },
        )
        .map_err(|error| {
            if error.to_string() == "timed out" {
                anyhow!("timed out after {} s", timeout.as_secs())
            } else {
                error
            }
        })?;
        Ok(Ran {
            code: finished.status.code(),
            stdout: finished.stdout,
            stderr: finished.stderr,
        })
    }
}

/// The build host's service account token, from its metadata server.
pub struct Metadata;

const METADATA_TOKEN: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

impl Token for Metadata {
    fn fetch(&mut self) -> Result<Secret> {
        let unavailable = || anyhow!("the build host's registry token is unavailable");
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| unavailable())?;
        let response = client
            .get(METADATA_TOKEN)
            .header("Metadata-Flavor", "Google")
            .send()
            .map_err(|_| unavailable())?;
        ensure!(response.status().is_success(), unavailable());
        let mut body = Vec::new();
        response
            .take(65_537)
            .read_to_end(&mut body)
            .map_err(|_| unavailable())?;
        ensure!(body.len() <= 65_536, unavailable());
        let value: Value = serde_json::from_slice(&body).map_err(|_| unavailable())?;
        let token = value["access_token"]
            .as_str()
            .filter(|token| !token.is_empty())
            .ok_or_else(unavailable)?;
        Ok(Secret::new(token.to_owned()))
    }
}

/// The build slots and the probe lock: flocks on `<locks>/0`, `<locks>/1` and
/// `<locks>/probe` (the slot files are the ones the earlier build host locked),
/// and their private directories under `<runs>` (tmpfs).
pub struct HostSlots {
    pub locks: PathBuf,
    pub runs: PathBuf,
}

impl HostSlots {
    pub fn native() -> Self {
        Self {
            locks: PathBuf::from("/var/lock/day2-app-builds"),
            runs: PathBuf::from("/run/day2-app-builds"),
        }
    }

    /// Lock `<locks>/<name>` within `wait`, polling at most every second.
    fn lock(&self, names: &[String], wait: Duration, busy: &str) -> Result<(String, fs::File)> {
        private_directory(&self.locks, "native build lock directory")?;
        let deadline = Instant::now() + wait;
        loop {
            for name in names {
                let lock = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .mode(0o600)
                    .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                    .open(self.locks.join(name))?;
                match lock.try_lock() {
                    Ok(()) => return Ok((name.clone(), lock)),
                    Err(fs::TryLockError::WouldBlock) => {}
                    Err(fs::TryLockError::Error(error)) => return Err(error.into()),
                }
            }
            let now = Instant::now();
            ensure!(now < deadline, "{busy}");
            std::thread::sleep((deadline - now).min(Duration::from_secs(1)));
        }
    }

    /// A held lock's private directory under `<runs>`, wiped and recreated.
    fn fresh(&self, name: &str, subdirectories: &[&str]) -> Result<PathBuf> {
        private_directory(&self.runs, "native build run directory")?;
        let directory = self.runs.join(name);
        if fs::symlink_metadata(&directory).is_ok() {
            fs::remove_dir_all(&directory)?;
        }
        private_directory(&directory, "native build slot directory")?;
        for subdirectory in subdirectories {
            private_directory(&directory.join(subdirectory), "native build slot directory")?;
        }
        Ok(directory)
    }
}

/// Create `path` 0700 if absent; it must be a directory owned by this user
/// (root on the build host) with no group or other access, and is refused
/// with what it is otherwise.
fn private_directory(path: &Path, what: &str) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Err(error) if error.kind() != std::io::ErrorKind::AlreadyExists => {
            return Err(error).with_context(|| format!("create the {what} {}", path.display()));
        }
        _ => {}
    }
    let metadata = fs::symlink_metadata(path)?;
    let uid = rustix::process::geteuid().as_raw();
    ensure!(
        metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o077 == 0,
        "the {what} {} must be a directory owned by uid {uid} with mode 0700; it is {} owned by \
         uid {} with mode {:04o}",
        path.display(),
        if metadata.file_type().is_symlink() {
            "a link"
        } else if metadata.is_dir() {
            "a directory"
        } else {
            "not a directory"
        },
        metadata.uid(),
        metadata.mode() & 0o7777
    );
    Ok(())
}

impl Slots for HostSlots {
    fn acquire(&mut self, wait: Duration) -> Result<Slot> {
        let names: Vec<String> = (0..SLOTS).map(|index| index.to_string()).collect();
        let (name, lock) = self.lock(&names, wait, "native build pool wait budget exhausted")?;
        Ok(Slot {
            index: Some(name.parse()?),
            directory: self.fresh(&name, &["docker-auth", "staging"])?,
            lock: Some(lock),
        })
    }

    fn probe(&mut self, wait: Duration) -> Result<Slot> {
        let (name, lock) = self.lock(
            &["probe".to_owned()],
            wait,
            "native probe lock wait budget exhausted",
        )?;
        Ok(Slot {
            index: None,
            directory: self.fresh(&name, &["docker-auth"])?,
            lock: Some(lock),
        })
    }

    fn release(&mut self, slot: &Slot) {
        let _ = fs::remove_dir_all(&slot.directory);
    }
}
