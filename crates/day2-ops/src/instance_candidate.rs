//! An app's deployment candidate, for `day2 instance candidate`: the instance
//! deploy controller's candidate build, its build host probe and its candidate
//! record check. The CLI renders the request from day2.json (the forge, its
//! org, the registry, the state bucket, the project, zone, apply identity and
//! build host, and each app's sdk and verification cases) and
//! InstanceCandidate.roc chooses the step order; this adapter validates the
//! request and refuses any step out of order. Two steps look a record up; the
//! recipe branches on what they report, and the host refuses a step outside the
//! branch its own lookup implies. A few steps are atomic native operations that
//! touch more than one outside system: `collect` turns one verified build host
//! result into its archived log and checked-inputs record, and the build host's
//! `tooling` takes one tooling container from a reaped slot to running.
//!
//! Value for value what the instance's existing controller and its build host
//! did, so a record either one wrote serves the other:
//! - **build** returns the candidate for a binding and a source commit: the
//!   stored candidate record, else the checked-inputs record for the same app
//!   inputs (reused for another commit with a reuse proof), else a native build
//!   of the commit's checked main artifact on the build host. Records are
//!   created only while absent, byte for byte as the controller wrote them.
//! - **preflight** proves on the build host that a candidate's tooling image
//!   carries the maintenance protocol, before any app is stopped.
//! - **check** validates a candidate record exactly as the controller did.
//! - **native-build** and **native-probe** run on the build host as root, in
//!   the private job directory the deploy job filled (see `native`).
//!
//! The build host runs this same CLI, copied over the authenticated IAP SSH
//! channel with the job's inputs. There it checks the other job files against
//! the request's identities before anything else (catching a short or corrupt
//! copy) and logs the digests of its own files; it cannot vouch for the binary
//! already running it. Its session has a budget below this job's deadline, so
//! it ends before the job gives up on it; when the job cannot know whether it
//! ended (a lost connection or this job's own deadline), the job leaves its
//! directory in place rather than remove it under a running build. Failures
//! are permanent (exit 6), except the forge reads of `day2 instance source`,
//! whose transient failures stay retryable (exit 7).
pub mod inputs;
pub mod native;
pub mod record;
pub mod tools;

#[cfg(test)]
pub(crate) mod tests;

use crate::{
    instance_release,
    instance_source::{self, App, Binding, File},
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use day2::sdk_release::{self, BlobIdentity, EVIDENCE_LIMIT, FILE_LIMIT, MANIFEST_LIMIT};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

pub use inputs::{Unpacked, source_inputs, unpack};

/// The instance's build host: the qualification runner stack's VM.
pub const BUILD_HOST: &str = "day2-x86-qualify";
/// The CLI files the build host runs, from beside the running host.
pub const CLI_FILES: [&str; 4] = ["day2", "day2-host", "day2-workflows", "day2-workflows.json"];
const REQUEST_LIMIT: u64 = 65_536;
/// The remote build's deadline in the deploy job (the earlier controller's),
/// and the budget the build host's session gets: its slot wait and every
/// Docker command fit inside the budget, and the margin covers SSH and IAP
/// setup, starting the CLI and the cleanup after a failure (at most 120 s of
/// operation logs and two 120 s Docker removals).
pub const NATIVE_TIMEOUT: Duration = Duration::from_secs(5400);
pub const NATIVE_BUDGET: u64 = 4800;
/// The remote probe's deadline and budget: the probe lock wait, the login and
/// the probe fit inside the budget.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(300);
pub const PROBE_BUDGET: u64 = 180;

/// The command a session runs; the host's action fixes it.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Build,
    Preflight,
    Check,
    NativeBuild,
    NativeProbe,
}

impl Mode {
    pub const ALL: [Self; 5] = [
        Self::Build,
        Self::Preflight,
        Self::Check,
        Self::NativeBuild,
        Self::NativeProbe,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Preflight => "preflight",
            Self::Check => "check",
            Self::NativeBuild => "native-build",
            Self::NativeProbe => "native-probe",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.name() == name)
    }

    /// Run on the build host, from its job directory, without day2.json.
    pub fn native(self) -> bool {
        matches!(self, Self::NativeBuild | Self::NativeProbe)
    }
}

/// The instance names the CLI derived from day2.json.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Instance {
    /// forge.server, `https://<host>`.
    pub server: String,
    /// forge.org.
    pub org: String,
    /// The project's Artifact Registry, `<region>-docker.pkg.dev/<project>`.
    pub registry: String,
    /// The derived state bucket, `<project>-tofu-state`.
    pub bucket: String,
    pub project: String,
    pub zone: String,
    /// `<org>-infra@<project>.iam.gserviceaccount.com`.
    pub apply_identity: String,
    /// The derived build host.
    pub build_host: String,
    pub apps: Vec<App>,
    /// App CI's names, only with forge.oidc: then a checked artifact comes
    /// only from app CI's results bucket.
    pub app_ci: Option<instance_source::app_ci::AppCi>,
}

impl Instance {
    fn source(&self) -> instance_source::Instance {
        instance_source::Instance {
            server: self.server.clone(),
            org: self.org.clone(),
            registry: self.registry.clone(),
            bucket: self.bucket.clone(),
            apps: self.apps.clone(),
            app_ci: self.app_ci.clone(),
        }
    }

    /// Where this instance admits candidate records from.
    pub(crate) fn scope(&self) -> record::Scope<'_> {
        record::Scope {
            server: &self.server,
            org: &self.org,
            registry: &self.registry,
            bucket: &self.bucket,
        }
    }

    fn target(&self) -> tools::Target {
        tools::Target {
            host: self.build_host.clone(),
            project: self.project.clone(),
            zone: self.zone.clone(),
            account: self.apply_identity.clone(),
        }
    }

    fn validate(&self) -> Result<()> {
        instance_source::validate_instance(&self.source())?;
        let lower = |value: &str| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        ensure!(
            lower(&self.project)
                && self.bucket == format!("{}-tofu-state", self.project)
                && self
                    .registry
                    .ends_with(&format!("-docker.pkg.dev/{}", self.project))
                && registry(&self.registry),
            "the instance's bucket and registry must be its project's"
        );
        ensure!(
            lower(&self.zone) && self.zone.matches('-').count() == 2,
            "the instance zone must be <region>-<zone>"
        );
        ensure!(
            self.apply_identity
                == format!(
                    "{}-infra@{}.iam.gserviceaccount.com",
                    self.org, self.project
                ),
            "the apply identity must be the instance's <org>-infra@<project>.iam.gserviceaccount.com"
        );
        ensure!(
            self.build_host == BUILD_HOST,
            "the build host must be the instance's {BUILD_HOST}"
        );
        Ok(())
    }

    fn app(&self, app: &str) -> Result<&App> {
        self.apps
            .iter()
            .find(|entry| entry.id == app)
            .with_context(|| format!("the candidate's app {app} is not in day2.json"))
    }
}

/// `<region>-docker.pkg.dev/<project>`.
pub fn registry(value: &str) -> bool {
    value
        .split_once("-docker.pkg.dev/")
        .is_some_and(|(region, project)| {
            !region.is_empty()
                && !project.is_empty()
                && region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && project
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// The CLI's rendered request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub mode: Mode,
    pub instance: Option<Instance>,
    /// build: the deploy controller's binding file for one app.
    pub binding: Option<PathBuf>,
    /// build: the exact source commit.
    pub commit: Option<String>,
    /// check: the app the candidate must be for.
    pub app_id: Option<String>,
    /// preflight and check: a candidate record file.
    pub candidate: Option<PathBuf>,
    /// build: the new file the candidate record's bytes are written to.
    pub output: Option<PathBuf>,
    /// native-build and native-probe: the private job directory.
    pub job: Option<PathBuf>,
}

/// The request's fields belong to its mode.
pub fn validate(request: &Request) -> Result<()> {
    let wanted = match request.mode {
        Mode::Build => [true, true, true, false, false, true, false],
        Mode::Preflight => [true, false, false, false, true, false, false],
        Mode::Check => [true, false, false, true, true, false, false],
        Mode::NativeBuild | Mode::NativeProbe => [false, false, false, false, false, false, true],
    };
    let given = [
        request.instance.is_some(),
        request.binding.is_some(),
        request.commit.is_some(),
        request.app_id.is_some(),
        request.candidate.is_some(),
        request.output.is_some(),
        request.job.is_some(),
    ];
    ensure!(
        given == wanted,
        "an instance candidate {} request names only its own inputs",
        request.mode.name()
    );
    if let Some(instance) = &request.instance {
        instance.validate()?;
    }
    if let Some(commit) = &request.commit {
        ensure!(
            instance_source::commit(commit),
            "build requires an exact commit"
        );
    }
    if let Some(app) = &request.app_id {
        ensure!(
            instance_source::identifier(app),
            "invalid deployment app ID"
        );
    }
    Ok(())
}

/// The request the deploy job writes into the build host's job directory.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeRequest {
    pub format: u32,
    pub mode: Mode,
    pub registry: String,
    pub app: String,
    /// native-build: the binding, exactly as the deploy job received it.
    pub binding: Option<Value>,
    pub source_commit: Option<String>,
    pub source_inputs: Option<String>,
    /// native-build: the checked main artifact's provenance proof.
    pub ci_artifact: Option<Value>,
    /// native-probe: the image to probe.
    pub tooling_image: Option<String>,
    /// Every file the job directory holds, by its name there.
    pub files: BTreeMap<String, BlobIdentity>,
    /// How long the build host's session may run, from its start: no step
    /// starts after it, and every wait and Docker command fits inside it.
    pub budget_seconds: u64,
}

/// What a copy to the build host took.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transfer {
    pub bytes: u64,
    pub milliseconds: u64,
}

/// What a candidate command reports. The host owns this shape; the CLI decodes
/// only it and passes it through verbatim, and cli/fixtures/candidate-receipt.json
/// pins it for both sides. Every field is present; those a mode does not
/// report are null.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub format: u32,
    pub mode: Mode,
    pub app_id: Option<String>,
    pub commit: Option<String>,
    /// build: `stored`, `reused` or `built`.
    pub outcome: Option<String>,
    /// build: the new file holding the candidate record's exact bytes.
    pub candidate: Option<File>,
    /// build: the candidate record.
    pub record: Option<String>,
    /// build and check: the candidate's build log.
    pub build_log: Option<String>,
    pub image: Option<String>,
    pub artifact_id: Option<String>,
    /// preflight and native-probe: the image probed.
    pub tooling_image: Option<String>,
    /// build (a native build only) and preflight: the copy to the build host.
    pub transfer: Option<Transfer>,
    /// native-build: the build slot, result.json and build.log.
    pub slot: Option<u64>,
    pub result: Option<File>,
    pub log: Option<File>,
}

impl Receipt {
    pub fn new(mode: Mode) -> Self {
        Self {
            format: 1,
            mode,
            app_id: None,
            commit: None,
            outcome: None,
            candidate: None,
            record: None,
            build_log: None,
            image: None,
            artifact_id: None,
            tooling_image: None,
            transfer: None,
            slot: None,
            result: None,
            log: None,
        }
    }
}

/// 32 lowercase hex digits from the system's secure random source.
pub fn random_hex() -> Result<String> {
    use ring::rand::SecureRandom;
    let mut bytes = [0_u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("no secure random source"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// What a deploy job's session reaches outside itself.
pub struct JobEffects {
    /// The forge, the clock (and stderr) and the release cache, for the
    /// source reads this session runs in-process.
    pub source: instance_source::Effects,
    pub store: Box<dyn tools::Store>,
    pub host: Box<dyn tools::BuildHost>,
    /// The directory of the running CLI, when it is the linux-x86_64 CLI the
    /// build host can run.
    pub cli: Option<PathBuf>,
    /// 32 lowercase hex digits.
    pub random: Box<dyn FnMut() -> Result<String>>,
}

impl JobEffects {
    pub fn native() -> Result<Self> {
        let cli = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            std::env::current_exe()?
                .canonicalize()?
                .parent()
                .map(Path::to_owned)
        } else {
            None
        };
        Ok(Self {
            source: instance_source::Effects::native()?,
            store: Box::new(tools::Gcloud::native()),
            host: Box::new(tools::Gcloud::native()),
            cli,
            random: Box::new(random_hex),
        })
    }
}

/// What a session reaches outside itself.
pub enum Effects {
    Job(Box<JobEffects>),
    Native(native::Effects),
}

impl Effects {
    /// The effects a mode runs with.
    pub fn native(mode: Mode) -> Result<Self> {
        Ok(if mode.native() {
            Self::Native(native::Effects::native()?)
        } else {
            Self::Job(Box::new(JobEffects::native()?))
        })
    }
}

pub enum Session {
    Job(Box<Job>),
    Native(Box<native::Native>),
}

/// A file's bytes, within `limit`, opened without following a link.
pub(crate) fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut bytes = Vec::new();
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .with_context(|| format!("read {}", path.display()))?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "{} exceeds its {limit}-byte budget",
        path.display()
    );
    Ok(bytes)
}

impl Session {
    /// Validate the CLI's request for a session the host started in `mode`
    /// before anything is read from the forge, the bucket or the build host.
    pub fn prepare(raw: &Path, mode: Mode, effects: Effects) -> Result<Self> {
        let request: Request = day2::json::decode(&read_bounded(raw, REQUEST_LIMIT)?)?;
        ensure!(
            request.mode == mode,
            "the host started an instance candidate {} but the request is for an instance candidate {}",
            mode.name(),
            request.mode.name()
        );
        validate(&request)?;
        match effects {
            Effects::Native(effects) => {
                ensure!(mode.native(), "a native session needs a native command");
                let job = std::path::absolute(request.job.as_ref().context("job")?)?;
                Ok(Self::Native(Box::new(native::Native::prepare(
                    mode, &job, effects,
                )?)))
            }
            Effects::Job(effects) => {
                ensure!(!mode.native(), "a native command runs on the build host");
                Ok(Self::Job(Box::new(Job::prepare(request, *effects)?)))
            }
        }
    }

    /// Run the mode's next step, which must be `name`.
    pub fn step(&mut self, name: &str) -> Result<Value> {
        match self {
            Self::Job(job) => job.step(name),
            Self::Native(native) => native.step(name),
        }
    }
}

/// A deploy job's session: build, preflight or check.
pub struct Job {
    mode: Mode,
    store: Box<dyn tools::Store>,
    host: Box<dyn tools::BuildHost>,
    cli: Option<PathBuf>,
    random: Box<dyn FnMut() -> Result<String>>,
    /// The source effects, while no in-process source session holds them.
    source: Option<instance_source::Effects>,
    instance: Instance,
    binding: Option<Binding>,
    digest: Option<String>,
    app: String,
    commit: Option<String>,
    output: Option<PathBuf>,
    candidate_file: Option<PathBuf>,
    /// The steps the mode runs from here, and how many are done.
    plan: Vec<&'static str>,
    done: usize,
    work: Option<tempfile::TempDir>,
    inputs: Option<String>,
    candidate: Option<Value>,
    /// The stored record's exact bytes, when it was found.
    stored: Option<Vec<u8>>,
    outcome: Option<&'static str>,
    candidate_generation: String,
    inputs_generation: String,
    /// With forge.oidc, a checked-inputs record of the earlier provenance exists: it is kept as it is, never reused
    /// and never written over.
    keep_inputs: bool,
    cached: Option<Value>,
    proof: Option<Value>,
    sub: Option<instance_source::Session>,
    remote: Option<String>,
    /// Whether the build host's session was started and is not known to have
    /// ended: its directory is then never removed.
    remote_running: bool,
    transfer: Option<Transfer>,
}

const BUILT: [&str; 10] = [
    "run", "job", "artifact", "download", "attempt", "release", "stage", "native", "collect",
    "record",
];

impl Job {
    fn prepare(request: Request, effects: JobEffects) -> Result<Self> {
        let instance = request.instance.clone().context("instance")?;
        let (binding, digest, app) = match &request.binding {
            Some(path) => {
                let value =
                    instance_source::decode(&read_bounded(path, instance_source::JSON_LIMIT)?)
                        .context("invalid binding JSON")?;
                let binding = Binding::check(value, &instance.source())?;
                let digest = record::binding_digest(&binding.value)?;
                let app = binding.app.clone();
                (Some(binding), Some(digest), app)
            }
            None => (None, None, request.app_id.clone().unwrap_or_default()),
        };
        let output = match &request.output {
            Some(path) => {
                let path = std::path::absolute(path)?;
                ensure!(
                    fs::symlink_metadata(&path).is_err(),
                    "instance candidate requires a new file: {}",
                    path.display()
                );
                ensure!(
                    path.parent().is_some_and(Path::is_dir),
                    "the new file's directory must exist: {}",
                    path.display()
                );
                Some(path)
            }
            None => None,
        };
        let candidate_file = match &request.candidate {
            Some(path) => {
                let path = std::path::absolute(path)?;
                ensure!(
                    fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_file()),
                    "the candidate must be a regular file: {}",
                    path.display()
                );
                Some(path)
            }
            None => None,
        };
        let plan = match request.mode {
            Mode::Build => vec!["stored"],
            Mode::Preflight => vec!["validate", "stage", "probe"],
            _ => vec!["validate"],
        };
        let JobEffects {
            source,
            store,
            host,
            cli,
            random,
        } = effects;
        Ok(Self {
            mode: request.mode,
            store,
            host,
            cli,
            random,
            source: Some(source),
            instance,
            binding,
            digest,
            app,
            commit: request.commit.clone(),
            output,
            candidate_file,
            plan,
            done: 0,
            work: None,
            inputs: None,
            candidate: None,
            stored: None,
            outcome: None,
            candidate_generation: "0".to_owned(),
            inputs_generation: "0".to_owned(),
            keep_inputs: false,
            cached: None,
            proof: None,
            sub: None,
            remote: None,
            remote_running: false,
            transfer: None,
        })
    }

    /// Run the mode's next step, which must be `name`.
    pub fn step(&mut self, name: &str) -> Result<Value> {
        let expected = self.plan.get(self.done).copied();
        let Some(next) = expected.filter(|next| *next == name) else {
            bail!(
                "instance candidate {} runs {} next, not {name}",
                self.mode.name(),
                expected.unwrap_or("nothing more")
            );
        };
        let value = match (self.mode, next) {
            (Mode::Build, "stored") => self.stored()?,
            (Mode::Build, "archive") => self.archive()?,
            (Mode::Build, "inputs") => self.inputs()?,
            (Mode::Build, "controls") => self.controls()?,
            (Mode::Build, "cached") => self.cached()?,
            (Mode::Build, "reuse") => self.reuse()?,
            (Mode::Build, "run" | "job" | "artifact" | "download" | "attempt") => {
                self.checked_artifact(next)?
            }
            (Mode::Build, "release") => self.release()?,
            (Mode::Build, "stage") => self.stage_build()?,
            (Mode::Build, "native") => self.native()?,
            (Mode::Build, "collect") => self.collect()?,
            (Mode::Build, _) => self.record()?,
            (Mode::Preflight, "validate") | (Mode::Check, _) => self.validate()?,
            (Mode::Preflight, "stage") => self.stage_probe()?,
            _ => self.probe()?,
        };
        self.done += 1;
        Ok(value)
    }

    fn binding(&self) -> Result<&Binding> {
        self.binding.as_ref().context("binding")
    }

    fn digest(&self) -> Result<&str> {
        self.digest.as_deref().context("binding digest")
    }

    fn commit(&self) -> Result<&str> {
        self.commit.as_deref().context("commit")
    }

    fn work(&mut self) -> Result<PathBuf> {
        if self.work.is_none() {
            self.work = Some(
                tempfile::Builder::new()
                    .prefix("day2-app-build-")
                    .tempdir()
                    .context("a private work directory")?,
            );
        }
        Ok(self
            .work
            .as_ref()
            .context("work directory")?
            .path()
            .to_owned())
    }

    fn log_uri(&self, commit: &str) -> Result<String> {
        Ok(record::log_uri(
            &self.instance.bucket,
            &self.app,
            self.digest()?,
            commit,
        ))
    }

    /// The stored candidate for this binding and commit, if there is one.
    fn stored(&mut self) -> Result<Value> {
        let uri = record::candidate_uri(
            &self.instance.bucket,
            &self.app,
            self.digest()?,
            self.commit()?,
        );
        let Some((bytes, generation)) = self.store.read(&uri)? else {
            self.plan
                .extend(["archive", "inputs", "controls", "cached"]);
            return Ok(json!({"found": false}));
        };
        let value = record::decode(&bytes)?;
        record::check(&value, &self.app, &self.instance.scope())?;
        ensure!(
            value["binding"] == self.binding()?.value && value["source_commit"] == self.commit()?,
            "stored candidate does not match the selected source"
        );
        self.candidate_generation = generation;
        self.candidate = Some(value);
        self.stored = Some(bytes);
        self.outcome = Some("stored");
        self.plan.push("record");
        Ok(json!({"found": true}))
    }

    /// Run one in-process source session to its end and take its effects back.
    fn source_session(
        &mut self,
        mode: instance_source::Mode,
        inputs: Option<String>,
        archive: Option<PathBuf>,
        output: Option<PathBuf>,
    ) -> Result<Value> {
        let binding = self.binding()?.clone();
        let effects = self.source.take().context("source effects")?;
        let mut session = instance_source::Session::embedded(
            mode,
            effects,
            self.instance.source(),
            binding,
            instance_source::Embedded {
                commit: self
                    .commit
                    .clone()
                    .filter(|_| mode != instance_source::Mode::VerifyControls),
                inputs,
                archive,
                output,
            },
        );
        let mut last = Value::Null;
        let mut failed = None;
        for name in mode.steps() {
            match session.step(name) {
                Ok(value) => last = value,
                Err(error) => {
                    failed = Some(error);
                    break;
                }
            }
        }
        self.source = Some(session.into_effects());
        match failed {
            Some(error) => Err(error),
            None => Ok(last),
        }
    }

    /// The commit's source archive, into the private work directory.
    fn archive(&mut self) -> Result<Value> {
        let output = self.work()?.join("source.tar.gz");
        let receipt =
            self.source_session(instance_source::Mode::Archive, None, None, Some(output))?;
        ensure!(
            receipt["commit"] == self.commit()?,
            "day2 archived another source commit"
        );
        Ok(json!({"archive": receipt["archive"]}))
    }

    /// The app's checked source inputs.
    fn inputs(&mut self) -> Result<Value> {
        let archive = read_bounded(
            &self.work()?.join("source.tar.gz"),
            instance_source::ARCHIVE_LIMIT,
        )?;
        let inputs = source_inputs(&archive, &self.binding()?.directory)?;
        self.inputs = Some(inputs.clone());
        Ok(json!({"source_inputs": inputs}))
    }

    /// The archive's CI controls against the instance-approved contract and its
    /// qualified release, before any cached result may be reused.
    fn controls(&mut self) -> Result<Value> {
        let archive = self.work()?.join("source.tar.gz");
        let receipt = self.source_session(
            instance_source::Mode::VerifyControls,
            None,
            Some(archive),
            None,
        )?;
        ensure!(
            receipt["controls"] == self.binding()?.controls,
            "source CI differs from the instance-approved contract"
        );
        Ok(json!({"controls": receipt["controls"], "platform_commit": receipt["platform_commit"]}))
    }

    /// The checked-inputs record for the same binding and app inputs.
    fn cached(&mut self) -> Result<Value> {
        let inputs = self.inputs.clone().context("source inputs")?;
        let uri = record::inputs_uri(&self.instance.bucket, &self.app, self.digest()?, &inputs);
        match self.store.read(&uri)? {
            // With forge.oidc a build creates only version 2 records. A checked result recorded from the app
            // repository's own workflow before the switch stays as it is, but is not reused: the artifact is read from
            // app CI and built again, and only this commit's candidate record is created.
            Some((bytes, _))
                if self.instance.app_ci.is_some()
                    && instance_source::int(&record::decode(&bytes)?["ci_artifact"]["version"])
                        != Some(instance_source::app_ci::VERSION) =>
            {
                self.keep_inputs = true;
                self.plan.extend(BUILT);
                Ok(json!({"found": false}))
            }
            Some((bytes, generation)) => {
                self.cached = Some(record::decode(&bytes)?);
                self.inputs_generation = generation;
                self.plan.extend(["reuse", "record"]);
                Ok(json!({"found": true}))
            }
            None => {
                self.plan.extend(BUILT);
                Ok(json!({"found": false}))
            }
        }
    }

    /// The cached result, as it is for its own commit, else for
    /// this commit with a reuse proof at this commit's build log.
    fn reuse(&mut self) -> Result<Value> {
        let cached = self.cached.clone().context("cached result")?;
        let inputs = self.inputs.clone().context("source inputs")?;
        let commit = self.commit()?.to_owned();
        record::check(&cached, &self.app, &self.instance.scope())?;
        ensure!(
            cached["binding"] == self.binding()?.value
                && cached["source_inputs"] == inputs
                && cached["checked_commit"] == cached["source_commit"],
            "checked-input cache identity changed"
        );
        let candidate = if cached["source_commit"] == commit {
            // Keep the native log; never replace it with a self-referencing proof.
            cached
        } else {
            let log = self.log_uri(&commit)?;
            let proof = record::reuse_proof(self.digest()?, &commit, &inputs, &cached);
            let path = self.work()?.join("reuse.json");
            tools::write_private(&path, &record::encode(&proof)?)?;
            self.store.put(&path, &log)?;
            let reused = record::reused(&cached, &commit, &log);
            record::check(&reused, &self.app, &self.instance.scope())?;
            reused
        };
        self.candidate = Some(candidate);
        self.outcome = Some("reused");
        Ok(json!({"reused": true}))
    }

    /// One step of the checked main artifact's in-process source session.
    fn checked_artifact(&mut self, name: &str) -> Result<Value> {
        if name == "run" {
            let output = self.work()?.join("ci-artifact.tar.gz");
            let binding = self.binding()?.clone();
            let effects = self.source.take().context("source effects")?;
            self.sub = Some(instance_source::Session::embedded(
                instance_source::Mode::CheckedArtifact,
                effects,
                self.instance.source(),
                binding,
                instance_source::Embedded {
                    commit: self.commit.clone(),
                    inputs: self.inputs.clone(),
                    archive: None,
                    output: Some(output),
                },
            ));
        }
        let mut session = self.sub.take().context("checked artifact session")?;
        let stepped = session.step(name);
        if stepped.is_err() || name == "attempt" {
            self.source = Some(session.into_effects());
        } else {
            self.sub = Some(session);
        }
        let value = stepped?;
        if name == "attempt" {
            let inputs = self.inputs.clone().context("source inputs")?;
            ensure!(
                value["commit"] == self.commit()? && value["source_inputs"] == inputs,
                "day2 returned another checked artifact"
            );
            let proof = value["proof"].clone();
            instance_source::proof(&proof, &self.binding()?.value, self.commit()?, &inputs)?;
            // With forge.oidc a build trusts only app CI's results; without it, only the earlier provenance.
            let expected = if self.instance.app_ci.is_some() {
                instance_source::app_ci::VERSION
            } else {
                1
            };
            ensure!(
                instance_source::int(&proof["version"]) == Some(expected),
                "day2 returned a checked artifact of another provenance"
            );
            self.proof = Some(proof);
        }
        Ok(value)
    }

    /// The binding's release manifest and native evidence through the release
    /// cache, verified and bound as a fetch binds them, copied into the work
    /// directory.
    fn release(&mut self) -> Result<Value> {
        let work = self.work()?;
        let reference = self.binding()?.qualified_release.clone();
        let source = self.source.as_mut().context("source effects")?;
        let root = match &source.cache {
            Some(root) => root.clone(),
            None => instance_release::cache_root()?,
        };
        let objects = format!(
            "gs://{}/{}",
            self.instance.bucket,
            instance_release::OBJECTS
        );
        let cache = instance_release::Cache::open(&root, &objects)?;
        let verified = instance_release::verified(
            cache,
            &self.instance.registry,
            &reference,
            source.tools.as_mut(),
        )?;
        for (name, path, expected, limit) in [
            (
                "qualified-release.json",
                &verified.manifest,
                &reference,
                MANIFEST_LIMIT,
            ),
            (
                "qualification.json",
                &verified.native,
                &verified.release.evidence.native,
                EVIDENCE_LIMIT,
            ),
        ] {
            let bytes = sdk_release::verify(path, expected, limit)
                .context("cached release bytes changed")?;
            tools::write_private(&work.join(name), &bytes)?;
        }
        Ok(json!({"platform_commit": verified.release.platform_commit}))
    }

    /// The running CLI's files, which the build host runs.
    fn cli(&self) -> Result<Vec<(String, PathBuf, BlobIdentity)>> {
        let directory = self.cli.as_ref().context(
            "the build host runs this CLI: run day2 instance candidate from the linux-x86_64 CLI \
             (the instance's CI job image)",
        )?;
        CLI_FILES
            .iter()
            .map(|name| {
                let path = directory.join(name);
                let identity = sdk_release::identity(&path, FILE_LIMIT)
                    .with_context(|| format!("the running CLI's {name}"))?;
                Ok((format!("cli/{name}"), path, identity))
            })
            .collect()
    }

    /// Create the build host's private job directory and copy the request, its
    /// inputs and the CLI in. From the create on (it may time out after the
    /// directory was made), a failure removes the directory; once files are in
    /// it, a build's failure first keeps its build log as evidence.
    fn stage(
        &mut self,
        prefix: &str,
        request: NativeRequest,
        inputs: Vec<PathBuf>,
        cli: Vec<PathBuf>,
    ) -> Result<()> {
        let work = self.work()?;
        let path = work.join("request.json");
        tools::write_private(&path, &serde_json::to_vec(&request)?)?;
        let remote = format!("{prefix}{}", (self.random)()?);
        let target = self.instance.target();
        self.remote = Some(remote.clone());
        if let Err(error) = self.host.create(&target, &remote) {
            self.remove_remote();
            return Err(error);
        }
        let mut files = vec![path];
        files.extend(inputs);
        let bytes = files
            .iter()
            .chain(&cli)
            .map(|path| fs::metadata(path).map(|metadata| metadata.len()))
            .sum::<std::io::Result<u64>>()?;
        let source = self.source.as_mut().context("source effects")?;
        let started = source.clock.now();
        let copied = self
            .host
            .upload(&target, &files, &format!("{remote}/"))
            .and_then(|()| self.host.upload(&target, &cli, &format!("{remote}/cli/")));
        if let Err(error) = copied {
            return Err(self.fail_remote(error));
        }
        let elapsed = self.source.as_mut().context("source effects")?.clock.now() - started;
        self.transfer = Some(Transfer {
            bytes,
            milliseconds: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        });
        Ok(())
    }

    /// The build host's request: the binding, the commit, its inputs and proof,
    /// and the identity of every file copied.
    fn stage_build(&mut self) -> Result<Value> {
        let work = self.work()?;
        let binding = self.binding()?.value.clone();
        let mut files = BTreeMap::new();
        let mut inputs = Vec::new();
        for (name, limit) in [
            ("source.tar.gz", instance_source::ARCHIVE_LIMIT),
            ("ci-artifact.tar.gz", instance_source::ARTIFACT_LIMIT),
            ("qualified-release.json", MANIFEST_LIMIT),
            ("qualification.json", EVIDENCE_LIMIT),
        ] {
            let path = work.join(name);
            files.insert(name.to_owned(), sdk_release::identity(&path, limit)?);
            inputs.push(path);
        }
        let mut cli = Vec::new();
        for (name, path, identity) in self.cli()? {
            files.insert(name, identity);
            cli.push(path);
        }
        let request = NativeRequest {
            format: 1,
            mode: Mode::NativeBuild,
            registry: self.instance.registry.clone(),
            app: self.app.clone(),
            binding: Some(binding),
            source_commit: self.commit.clone(),
            source_inputs: self.inputs.clone(),
            ci_artifact: self.proof.clone(),
            tooling_image: None,
            files,
            budget_seconds: NATIVE_BUDGET,
        };
        self.stage("/tmp/day2-build-", request, inputs, cli)?;
        Ok(json!({"remote": self.remote, "transfer": self.transfer}))
    }

    /// The native build on the build host.
    fn native(&mut self) -> Result<Value> {
        match self.run_remote(Mode::NativeBuild, NATIVE_TIMEOUT, "native build") {
            Ok(receipt) => Ok(json!({"slot": receipt["slot"]})),
            Err(error) => Err(self.fail_remote(error)),
        }
    }

    /// Run one native command in the build host's job directory. Once its
    /// command line has exited, the session is known to have ended; after this
    /// job's deadline or a lost connection (ssh's own exit 255) it is not. A
    /// failed run's stderr goes to this job's stderr (the job log), never to an
    /// error, a receipt or a record.
    fn run_remote(&mut self, mode: Mode, timeout: Duration, what: &str) -> Result<Value> {
        let remote = self.remote.clone().context("build host job directory")?;
        self.remote_running = true;
        let ran = self
            .host
            .run(&self.instance.target(), &remote, mode, timeout)?;
        self.remote_running = matches!(ran.code, None | Some(255));
        let outcome = remote_outcome(&ran, what);
        if outcome.is_err()
            && let Some(source) = self.source.as_mut()
        {
            for line in tools::tail(&ran.stderr).lines() {
                source.clock.announce(&format!("build host: {line}"));
            }
        }
        outcome
    }

    /// The build host's result, checked against what was asked for; its build
    /// log is archived, then the checked-inputs record is created.
    fn collect(&mut self) -> Result<Value> {
        match self.collected() {
            Ok(value) => {
                self.remove_remote();
                Ok(value)
            }
            Err(error) => Err(self.fail_remote(error)),
        }
    }

    fn collected(&mut self) -> Result<Value> {
        let remote = self.remote.clone().context("build host job directory")?;
        let work = self.work()?;
        let commit = self.commit()?.to_owned();
        let inputs = self.inputs.clone().context("source inputs")?;
        self.host.download(
            &self.instance.target(),
            &[
                format!("{remote}/result.json"),
                format!("{remote}/build.log"),
            ],
            &work,
        )?;
        let mut result = record::decode(&read_bounded(
            &work.join("result.json"),
            record::RECORD_LIMIT,
        )?)?;
        ensure!(
            result["binding"] == self.binding()?.value && result["source_commit"] == commit,
            "builder returned another source or toolchain"
        );
        ensure!(
            result["source_inputs"] == inputs && result["checked_commit"] == commit,
            "builder checked different app inputs"
        );
        ensure!(
            Some(&result["ci_artifact"]) == self.proof.as_ref(),
            "builder changed main CI provenance"
        );
        let log = self.log_uri(&commit)?;
        result["build_log"] = json!(log);
        record::check(&result, &self.app, &self.instance.scope())?;
        self.store.put(&work.join("build.log"), &log)?;
        if !self.keep_inputs {
            let uri = record::inputs_uri(&self.instance.bucket, &self.app, self.digest()?, &inputs);
            let generation = self.inputs_generation.clone();
            self.write_record(&uri, &result, &generation)?;
        }
        self.candidate = Some(result);
        self.outcome = Some("built");
        Ok(json!({"build_log": log}))
    }

    /// A record's bytes from a private `record.json`, written
    /// only while the object's generation is still `generation`.
    fn write_record(&mut self, uri: &str, value: &Value, generation: &str) -> Result<()> {
        let path = self.work()?.join("record.json");
        if fs::symlink_metadata(&path).is_ok() {
            fs::remove_file(&path)?;
        }
        tools::write_private(&path, &record::encode(value)?)?;
        self.store.write(&path, uri, generation)
    }

    /// The candidate record, unless it was stored already, and the new file
    /// holding its exact bytes.
    fn record(&mut self) -> Result<Value> {
        let candidate = self.candidate.clone().context("candidate")?;
        let commit = self.commit()?.to_owned();
        let uri = record::candidate_uri(&self.instance.bucket, &self.app, self.digest()?, &commit);
        let bytes = match self.stored.clone() {
            Some(bytes) => bytes,
            None => {
                record::check(&candidate, &self.app, &self.instance.scope())?;
                ensure!(
                    candidate["binding"] == self.binding()?.value
                        && candidate["source_commit"] == commit,
                    "built candidate does not match the selected source"
                );
                let generation = self.candidate_generation.clone();
                self.write_record(&uri, &candidate, &generation)?;
                record::encode(&candidate)?
            }
        };
        let output = self.output.clone().context("new candidate file")?;
        tools::write_private(&output, &bytes)?;
        let identity = BlobIdentity::of(&bytes);
        Ok(serde_json::to_value(Receipt {
            app_id: Some(self.app.clone()),
            commit: Some(commit.clone()),
            outcome: self.outcome.map(str::to_owned),
            candidate: Some(File {
                path: output
                    .to_str()
                    .context("the new file's path must be UTF-8")?
                    .to_owned(),
                digest: identity.digest,
                bytes: identity.bytes,
            }),
            record: Some(uri),
            build_log: candidate["build_log"].as_str().map(str::to_owned),
            image: candidate["image"].as_str().map(str::to_owned),
            artifact_id: candidate["artifact_id"].as_str().map(str::to_owned),
            transfer: self.transfer.clone(),
            ..Receipt::new(self.mode)
        })?)
    }

    /// A candidate record file, validated as the controller validated
    /// candidates: for the app check names, else for its own app, which must be
    /// in day2.json.
    fn validate(&mut self) -> Result<Value> {
        let path = self.candidate_file.clone().context("candidate file")?;
        let value = record::decode(&read_bounded(&path, record::RECORD_LIMIT)?)?;
        if self.mode == Mode::Preflight {
            self.app = value["binding"]["app"]
                .as_str()
                .filter(|app| instance_source::identifier(app))
                .context("invalid deployment app ID")?
                .to_owned();
            self.instance.app(&self.app)?;
        }
        record::check(&value, &self.app, &self.instance.scope())?;
        let receipt = Receipt {
            app_id: Some(self.app.clone()),
            commit: value["source_commit"].as_str().map(str::to_owned),
            build_log: value["build_log"].as_str().map(str::to_owned),
            image: value["image"].as_str().map(str::to_owned),
            artifact_id: value["artifact_id"].as_str().map(str::to_owned),
            ..Receipt::new(self.mode)
        };
        self.candidate = Some(value);
        Ok(serde_json::to_value(receipt)?)
    }

    /// The probe's request and the CLI, into a new private job directory.
    fn stage_probe(&mut self) -> Result<Value> {
        let candidate = self.candidate.clone().context("candidate")?;
        let mut files = BTreeMap::new();
        let mut cli = Vec::new();
        for (name, path, identity) in self.cli()? {
            files.insert(name, identity);
            cli.push(path);
        }
        let request = NativeRequest {
            format: 1,
            mode: Mode::NativeProbe,
            registry: self.instance.registry.clone(),
            app: self.app.clone(),
            binding: None,
            source_commit: None,
            source_inputs: None,
            ci_artifact: None,
            tooling_image: candidate["binding"]["tooling_image"]
                .as_str()
                .map(str::to_owned),
            files,
            budget_seconds: PROBE_BUDGET,
        };
        self.stage("/tmp/day2-sdk-probe-", request, Vec::new(), cli)?;
        Ok(json!({"remote": self.remote, "transfer": self.transfer}))
    }

    /// The tooling image's maintenance protocol, on the build host; its job
    /// directory is removed once the probe is known to have ended.
    fn probe(&mut self) -> Result<Value> {
        let ran = self.run_remote(Mode::NativeProbe, PROBE_TIMEOUT, "native probe");
        self.remove_remote();
        ran?;
        let candidate = self.candidate.clone().context("candidate")?;
        Ok(serde_json::to_value(Receipt {
            app_id: Some(self.app.clone()),
            commit: candidate["source_commit"].as_str().map(str::to_owned),
            tooling_image: candidate["binding"]["tooling_image"]
                .as_str()
                .map(str::to_owned),
            transfer: self.transfer.clone(),
            ..Receipt::new(self.mode)
        })?)
    }

    /// A failure once the build host's job directory exists: archive its
    /// build log as private evidence when there is one, then remove it.
    fn fail_remote(&mut self, error: anyhow::Error) -> anyhow::Error {
        if self.mode == Mode::Build
            && let Some(remote) = self.remote.clone()
        {
            let archived = (|| -> Result<String> {
                let work = self.work()?;
                let log = self.log_uri(self.commit()?)?;
                let path = work.join("build.log");
                if fs::symlink_metadata(&path).is_ok() {
                    fs::remove_file(&path)?;
                }
                self.host.download(
                    &self.instance.target(),
                    &[format!("{remote}/build.log")],
                    &work,
                )?;
                self.store.put(&path, &log)?;
                Ok(log)
            })();
            let line = match archived {
                Ok(log) => format!("build failed; private evidence: {log}"),
                Err(_) => "build failed before evidence could be archived".to_owned(),
            };
            if let Some(source) = self.source.as_mut() {
                source.clock.announce(&line);
            }
        }
        self.remove_remote();
        error
    }

    /// Remove the build host's job directory, if this session made one, unless
    /// a session there may still be running: then it is left in place, said so,
    /// and that session ends by its own budget.
    fn remove_remote(&mut self) {
        let Some(remote) = self.remote.take() else {
            return;
        };
        let line = if self.remote_running {
            Some(format!(
                "the build host's job directory {remote} is left in place: its session may still \
                 be running and ends by its own budget; the directory is on tmpfs"
            ))
        } else if self.host.remove(&self.instance.target(), &remote).is_err() {
            Some(format!(
                "could not remove the build host's job directory {remote}"
            ))
        } else {
            None
        };
        if let Some(line) = line
            && let Some(source) = self.source.as_mut()
        {
            source.clock.announce(&line);
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        self.remove_remote();
    }
}

/// A remote CLI run's outcome: its receipt, or the build host's own message.
/// The CLI prints its envelope as one line; anything the SSH session printed
/// before it is ignored.
fn remote_outcome(ran: &tools::Remote, what: &str) -> Result<Value> {
    let envelope: Option<Value> = serde_json::from_slice(&ran.stdout).ok().or_else(|| {
        ran.stdout
            .split(|byte| *byte == b'\n')
            .rfind(|line| !line.iter().all(u8::is_ascii_whitespace))
            .and_then(|line| serde_json::from_slice(line).ok())
    });
    if ran.code == Some(0)
        && let Some(envelope) = &envelope
        && envelope["ok"] == true
    {
        return Ok(envelope["result"]["receipt"].clone());
    }
    let message = envelope
        .as_ref()
        .and_then(|envelope| envelope["error"]["message"].as_str())
        .filter(|message| !message.is_empty())
        .map(|message| message.chars().take(2000).collect::<String>());
    Err(match message {
        Some(message) => anyhow!(message),
        None => anyhow!(
            "{what} failed on the build host ({})",
            ran.code
                .map_or_else(|| "killed".to_owned(), |code| format!("exit {code}"))
        ),
    })
}
