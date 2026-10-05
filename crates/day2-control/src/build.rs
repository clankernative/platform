//! Fixed local build recipe. The trusted runner is an operator capability, not app input.

use crate::{
    BindingRef, BuildPlan, Digest, Name,
    kernel::{CredentialPresence, VerificationEvidence},
    source::SourceSnapshot,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const RECIPE: &str = "day2-local-build-v4:roc-workflows:darwin-arm64:private-inputs:trusted-supervisor:per-stage-sandboxes:xtask-build-isolated:offline-cargo:artifact-admission:empty-state-properties:examples-generators-replay:control-simulation-corpus-and-8-cases";
const MAX_FILES: usize = 100_000;
const MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;
const BUILD_TIMEOUT: Duration = Duration::from_secs(600);

pub fn recipe_digest() -> Digest {
    Digest::new(
        &[
            RECIPE.as_bytes(),
            include_bytes!("build.rs"),
            include_bytes!("simulation_campaign.rs"),
            day2::automation::source_digest().as_bytes(),
        ]
        .concat(),
    )
}

pub fn supported_host() -> Result<()> {
    ensure!(
        cfg!(all(target_os = "macos", target_arch = "aarch64")),
        "local build containment is only supported on macOS arm64; Linux runner is not implemented"
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputFile {
    pub digest: Digest,
    pub bytes: u64,
    pub executable: bool,
}

#[derive(Clone, Debug)]
pub struct PinnedTree {
    root: PathBuf,
    files: BTreeMap<String, InputFile>,
    digest: Digest,
}

impl PinnedTree {
    /// Capture is an explicit operator approval step, never performed from an app request.
    pub fn capture(path: &Path) -> Result<Self> {
        ensure!(
            fs::symlink_metadata(path)?.file_type().is_dir(),
            "pinned tree must be a real directory"
        );
        let root = path.canonicalize()?;
        let mut files = BTreeMap::new();
        collect(&root, &root, &mut files, &mut 0, false)?;
        ensure!(!files.is_empty(), "empty pinned tree");
        let digest = Digest::of(&files)?;
        Ok(Self {
            root,
            files,
            digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
    pub fn files(&self) -> &BTreeMap<String, InputFile> {
        &self.files
    }

    pub fn materialize(&self, target: &Path) -> Result<()> {
        fs::create_dir(target).context("fresh pinned tree target required")?;
        for (name, expected) in &self.files {
            write_pinned(&self.root.join(name), &target.join(name), expected)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PlatformInputs {
    root: PathBuf,
    toolchains: PathBuf,
    files: BTreeMap<String, InputFile>,
    digest: Digest,
}

impl PlatformInputs {
    pub fn capture(root: &Path, toolchains: &Path) -> Result<Self> {
        ensure!(
            fs::symlink_metadata(root)?.file_type().is_dir(),
            "platform root must be a real directory"
        );
        ensure!(
            fs::symlink_metadata(toolchains)?.file_type().is_dir(),
            "toolchain root must be a real directory"
        );
        let root = root.canonicalize()?;
        let toolchains = toolchains.canonicalize()?;
        let mut files = BTreeMap::new();
        let mut total = 0;
        for name in [
            "Cargo.toml",
            "Cargo.lock",
            "architecture-rules.json",
            "architecture-boundaries.json",
            "rust-toolchain.toml",
            "toolchain.json",
            ".dockerignore",
            "LICENSE",
            "THIRD-PARTY-NOTICES.txt",
            "dependency-inventory.json",
        ] {
            let file = pin_file(&root.join(name))?;
            total += file.bytes;
            files.insert(format!("platform/{name}"), file);
        }
        for name in [
            "crates",
            "sdk",
            "tools",
            "vendor",
            "assets",
            "fixtures",
            "examples",
            "ops",
            "infra",
            "toolchains",
            "deploy",
        ] {
            let mut selected = BTreeMap::new();
            collect(&root, &root.join(name), &mut selected, &mut total, true)?;
            for (path, file) in selected {
                if !path.starts_with("crates/worker/generated/") {
                    files.insert(format!("platform/{path}"), file);
                }
            }
        }
        // CLI tests are a workspace member. Stage its authored sources explicitly,
        // excluding the locally built distribution and cache from trusted inputs.
        let mut cli_files = BTreeMap::new();
        collect_cli(&root, &root.join("cli"), &mut cli_files, &mut total)?;
        files.extend(
            cli_files
                .into_iter()
                .map(|(name, file)| (format!("platform/{name}"), file)),
        );
        let toolchain_files: &[&str] = if cfg!(target_os = "macos") {
            &["roc", "darwin/usr/lib/libSystem.tbd"]
        } else {
            // Linux linker inputs belong to the pinned tooling image. A fresh
            // Linux compiler archive need not contain Apple's SDK stub.
            &["roc"]
        };
        for name in toolchain_files {
            let file = pin_file(&toolchains.join(name))?;
            total += file.bytes;
            files.insert(format!(".toolchains/{name}"), file);
        }
        ensure!(
            total <= MAX_BYTES && files.len() <= MAX_FILES,
            "platform input budget"
        );
        let digest = Digest::of(&files)?;
        Ok(Self {
            root,
            toolchains,
            files,
            digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
    pub fn files(&self) -> &BTreeMap<String, InputFile> {
        &self.files
    }

    pub fn materialize(&self, workspace: &Path) -> Result<()> {
        for (name, expected) in &self.files {
            let source = if let Some(name) = name.strip_prefix("platform/") {
                self.root.join(name)
            } else {
                self.toolchains.join(
                    name.strip_prefix(".toolchains/")
                        .context("platform input path")?,
                )
            };
            write_pinned(&source, &workspace.join(name), expected)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct TrustedRunner {
    identity: Name,
    executable: PathBuf,
    executable_pin: InputFile,
    workflow: PathBuf,
    workflow_pin: InputFile,
    supervisor_pin: InputFile,
    system_ssl: Option<InputFile>,
    rust: PinnedTree,
    registry: PinnedTree,
}

pub struct BuildRequest {
    pub plan: BuildPlan,
    pub source: SourceSnapshot,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildCheck {
    pub name: String,
    pub passed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct BuildEvidence {
    format: u32,
    plan: Digest,
    source: Digest,
    platform: Digest,
    recipe: Digest,
    builder: BindingRef,
    artifact: Option<Digest>,
    #[serde(default, skip_serializing_if = "CredentialPresence::is_unknown")]
    credential_presence: CredentialPresence,
    checks: Vec<BuildCheck>,
    log: Digest,
    inputs: Digest,
    properties: Option<Digest>,
    development: Option<Digest>,
    simulation: Option<Digest>,
    failure: Option<String>,
    containment: String,
    verification_scope: String,
}

impl BuildEvidence {
    pub fn artifact(&self) -> Option<&Digest> {
        self.artifact.as_ref()
    }
    pub fn checks(&self) -> &[BuildCheck] {
        &self.checks
    }
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }
    pub fn digest(&self) -> Result<Digest> {
        Digest::of(self)
    }
    pub fn artifact_directory(&self, evidence_directory: &Path) -> Result<PathBuf> {
        Ok(evidence_directory.join("artifacts").join(
            self.artifact
                .as_ref()
                .context("no verified artifact")?
                .as_str()
                .trim_start_matches("sha256:"),
        ))
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Stored {
            format: u32,
            plan: Digest,
            source: Digest,
            platform: Digest,
            recipe: Digest,
            builder: BindingRef,
            artifact: Option<Digest>,
            #[serde(default)]
            credential_presence: CredentialPresence,
            checks: Vec<BuildCheck>,
            log: Digest,
            inputs: Digest,
            properties: Option<Digest>,
            development: Option<Digest>,
            #[serde(default)]
            simulation: Option<Digest>,
            failure: Option<String>,
            containment: String,
            verification_scope: String,
        }
        let value: Stored = serde_json::from_slice(bytes)?;
        Ok(Self {
            format: value.format,
            plan: value.plan,
            source: value.source,
            platform: value.platform,
            recipe: value.recipe,
            builder: value.builder,
            artifact: value.artifact,
            credential_presence: value.credential_presence,
            checks: value.checks,
            log: value.log,
            inputs: value.inputs,
            properties: value.properties,
            development: value.development,
            simulation: value.simulation,
            failure: value.failure,
            containment: value.containment,
            verification_scope: value.verification_scope,
        })
    }

    pub fn verification_evidence(&self) -> Result<VerificationEvidence> {
        ensure!(
            self.format == 1
                && self.failure.is_none()
                && self.properties.is_some()
                && self.development.is_some()
                && self.simulation.is_some()
                && self.checks.iter().map(|check| check.name.as_str()).eq([
                    "control-simulation",
                    "fixed-offline-recipe",
                    "artifact-admission",
                    "empty-state-properties",
                    "development-campaign"
                ])
                && self.checks.iter().all(|check| check.passed),
            "build verification did not pass"
        );
        Ok(VerificationEvidence {
            plan: self.plan.clone(),
            source: self.source.clone(),
            platform: self.platform.clone(),
            recipe: self.recipe.clone(),
            builder: self.builder.clone(),
            artifact: self.artifact.clone().context("verified artifact missing")?,
            checks: self.digest()?,
            credential_presence: self.credential_presence,
        })
    }
}

impl TrustedRunner {
    pub fn capture(
        identity: Name,
        executable: &Path,
        rust_toolchain: &Path,
        cargo_registry: &Path,
    ) -> Result<Self> {
        let executable_pin = pin_file(executable)?;
        ensure!(
            executable_pin.executable,
            "runner executable permission required"
        );
        let rust = PinnedTree::capture(rust_toolchain)?;
        for name in ["bin/cargo", "bin/rustc"] {
            ensure!(
                rust.files.get(name).is_some_and(|file| file.executable),
                "pinned Rust toolchain missing {name}"
            );
        }
        validate_registry_layout(cargo_registry)?;
        let registry = PinnedTree::capture(cargo_registry)?;
        ensure!(
            registry.files.keys().all(|name| {
                ["cache/", "src/", "index/"]
                    .iter()
                    .any(|prefix| name.starts_with(prefix))
                    || name == "CACHEDIR.TAG"
            }),
            "only the offline Cargo registry may be approved; credentials/config are forbidden"
        );
        let workflow = day2::automation::runner()?;
        let workflow_pin = pin_file(&workflow)?;
        Ok(Self {
            identity,
            workflow,
            workflow_pin,
            executable: executable.canonicalize()?,
            executable_pin,
            supervisor_pin: pin_file(&std::env::current_exe()?)?,
            system_ssl: if cfg!(target_os = "macos") {
                Some(pin_file(Path::new("/private/etc/ssl/openssl.cnf"))?)
            } else {
                None
            },
            rust,
            registry,
        })
    }

    pub fn binding(&self) -> Result<BindingRef> {
        BindingRef::pin(
            self.identity.clone(),
            &json!({
            "recipe":recipe_digest(), "executable":self.executable_pin, "workflow":self.workflow_pin, "supervisor":self.supervisor_pin, "system_ssl":self.system_ssl,
                "simulation":crate::simulation::implementation_digest()?,
                "rust":self.rust.digest(), "registry":self.registry.digest(),
                "containment":"macos-arm64-local-sandbox-v1", "system_tools":"trusted-host-OS-and-Xcode"
            }),
        )
    }

    pub fn validate_request(
        &self,
        request: &BuildRequest,
        platform: &PlatformInputs,
    ) -> Result<()> {
        request.plan.validate()?;
        ensure!(
            &request.plan.commit == request.source.commit(),
            "source commit differs from the approved plan"
        );
        ensure!(
            &request.plan.profile.platform == platform.digest(),
            "platform input revision changed"
        );
        ensure!(
            request.plan.profile.recipe == recipe_digest(),
            "unapproved build recipe"
        );
        ensure!(
            request.plan.profile.builder == self.binding()?,
            "trusted builder binding changed"
        );
        Ok(())
    }

    pub fn evidence_directory(request: &BuildRequest, output_root: &Path) -> Result<PathBuf> {
        Ok(output_root.join(
            request
                .plan
                .execution_id()?
                .as_str()
                .strip_prefix("sha256:")
                .context("execution digest")?,
        ))
    }

    pub fn execute(
        &self,
        request: &BuildRequest,
        platform: &PlatformInputs,
        output_root: &Path,
    ) -> Result<BuildEvidence> {
        supported_host()?;
        self.validate_request(request, platform)?;
        private_directory(output_root)?;
        let output_root = output_root.canonicalize()?;
        let execution = request.plan.execution_id()?;
        let locks = output_root.join("locks");
        private_directory(&locks)?;
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(locks.join(format!(
                "{}.lock",
                execution.as_str().trim_start_matches("sha256:")
            )))?;
        lock.try_lock()
            .context("build execution is already running")?;
        let destination = Self::evidence_directory(request, &output_root)?;
        if destination.exists() {
            return self.load_evidence(request, platform, &destination);
        }
        let job = tempfile::Builder::new()
            .prefix("build-private-")
            .tempdir_in(&output_root)?;
        let result = tempfile::Builder::new()
            .prefix("build-result-")
            .tempdir_in(&output_root)?;
        let mut evidence = BuildEvidence {
            format: 1, plan: request.plan.fingerprint()?, source: request.source.digest().clone(),
            platform: platform.digest().clone(), recipe: recipe_digest(), builder: self.binding()?,
            artifact: None, credential_presence: CredentialPresence::Unknown,
            checks: Vec::new(), log: Digest::new(b""), inputs: Digest::new(b""),
            properties: None, development: None, simulation: None, failure: None,
            containment: "trusted local supervisor; separate macOS arm64 Cargo/compiler/worker sandboxes; trusted OS/Xcode; no production hostile-code containment or resource-quota claim".into(),
            verification_scope: "pinned build/admission, empty-state properties and optional pure examples/generators through real commands, replay and duplicate delivery; no claim of full state-machine/DST certification".into(),
        };
        let input_manifest = self.input_manifest(request, platform)?;
        evidence.inputs = Digest::new(&input_manifest);
        fs::write(result.path().join("inputs.json"), &input_manifest)?;
        fs::write(result.path().join("build.log"), [])?;
        let outcome = self.run_recipe(request, platform, job.path(), result.path(), &mut evidence);
        if let Err(error) = outcome {
            evidence.failure = Some("build_recipe_failed".into());
            // Detailed diagnostics are protected local evidence, never Temporal payloads.
            append_log(
                &result.path().join("build.log"),
                format!("\nExecutor: {error:#}\n").as_bytes(),
            )?;
        }
        let (log, oversized) = read_log(&result.path().join("build.log"))?;
        ensure!(!oversized, "stored build log budget");
        evidence.log = Digest::new(&log);
        fs::write(
            result.path().join("evidence.json"),
            serde_json::to_vec_pretty(&evidence)?,
        )?;
        seal(result.path())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // macOS requires a writable directory while publishing its name.
            fs::set_permissions(result.path(), fs::Permissions::from_mode(0o700))?;
        }
        let staged = result.keep();
        fs::rename(staged, &destination)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o555))?;
        }
        fs::File::open(&output_root)?.sync_all()?;
        Ok(evidence)
    }

    fn input_manifest(&self, request: &BuildRequest, platform: &PlatformInputs) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(&json!({
            "source_commit":request.source.commit(),
            "source":request.source.files().iter().map(|(path,bytes)| (path,Digest::new(bytes))).collect::<BTreeMap<_,_>>(),
            "platform":platform.files(), "runner":self.executable_pin, "workflow":self.workflow_pin, "supervisor":self.supervisor_pin, "system_ssl":self.system_ssl,
            "rust":self.rust.files(), "cargo_registry":self.registry.files()
        }))?)
    }

    fn run_recipe(
        &self,
        request: &BuildRequest,
        platform: &PlatformInputs,
        job: &Path,
        result: &Path,
        evidence: &mut BuildEvidence,
    ) -> Result<()> {
        if let Some(expected) = &self.system_ssl {
            ensure!(
                &pin_file(Path::new("/private/etc/ssl/openssl.cnf"))? == expected,
                "approved system OpenSSL configuration changed"
            );
        }
        ensure!(
            pin_file(&self.workflow)? == self.workflow_pin,
            "approved Roc workflow changed"
        );
        let mut materialized = false;
        let mut built = false;
        let mut admitted_artifact: Option<Digest> = None;
        let mut admitted_target: Option<PathBuf> = None;
        let mut campaign: Option<day2::development::Campaign> = None;
        let mut simulation = crate::simulation_campaign::Session::new(
            &result.join("control-simulation"),
            crate::simulation_campaign::DEFAULT_SEED,
            crate::simulation_campaign::CI_CASES,
        )?;
        let outcome = day2::automation::run(&self.workflow, &["ci-recipe"], |effect| {
            if effect.action.starts_with("simulation-") {
                let result = simulation.effect(effect)?;
                if simulation.is_complete() {
                    evidence.simulation = Some(simulation.receipt_digest()?);
                    evidence.checks.push(BuildCheck {
                        name: "control-simulation".into(),
                        passed: true,
                    });
                }
                return Ok(result);
            }
            if effect.action.starts_with("dev-") && effect.action != "dev-create" {
                return campaign
                    .as_mut()
                    .context("CI development instance required")?
                    .effect(effect);
            }
            if effect.action != "dev-create" {
                let parameters: Value = effect.decode()?;
                ensure!(
                    parameters == json!({}),
                    "CI capabilities accept no source or recipe overrides"
                );
            }
            match effect.action.as_str() {
                "ci-materialize" => {
                    ensure!(
                        simulation.is_complete(),
                        "control simulation must pass before CI build"
                    );
                    ensure!(!materialized, "CI inputs already materialized");
                    platform.materialize(job)?;
                    request.source.materialize(&job.join("app"))?;
                    self.rust.materialize(&job.join("rust"))?;
                    private_directory(&job.join("cargo"))?;
                    self.registry.materialize(&job.join("cargo/registry"))?;
                    write_pinned(&self.executable, &job.join("xtask"), &self.executable_pin)?;
                    for name in ["home", "tmp"] {
                        private_directory(&job.join(name))?;
                    }
                    write_pinned(
                        &self.workflow,
                        &job.join("day2-workflows"),
                        &self.workflow_pin,
                    )?;
                    materialized = true;
                }
                "ci-build" => {
                    ensure!(materialized && !built, "fresh pinned CI inputs required");
                    // Registry files are read-only; Cargo's lock files belong only to the private home.
                    let child_log = job.join("build.log");
                    let log = fs::OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .open(&child_log)?;
                    let mut command = Command::new(job.join("xtask"));
                    command
                        .arg("build-isolated")
                        .arg(job.join("platform"))
                        .arg(job.join("app"))
                        .current_dir(job.join("platform"))
                        .env_clear()
                        .env("LANG", "C")
                        .env("LC_ALL", "C")
                        .env("TZ", "UTC")
                        .env("HOME", job.join("home"))
                        .env("TMPDIR", job.join("tmp"))
                        .env("CARGO_HOME", job.join("cargo"))
                        .env("CARGO_NET_OFFLINE", "true")
                        .env("CARGO_TARGET_DIR", job.join("platform/target"))
                        .env("RUSTC", job.join("rust/bin/rustc"))
                        .env(
                            "PATH",
                            format!("{}:/usr/bin:/bin", job.join("rust/bin").display()),
                        )
                        .stdin(Stdio::null())
                        .stdout(log.try_clone()?)
                        .stderr(log);
                    let outcome = run_bounded(&mut command, &child_log);
                    let (log, oversized) = read_log(&child_log)?;
                    fs::write(result.join("build.log"), log)?;
                    ensure!(!oversized, "build log budget exceeded");
                    let success = outcome?;
                    evidence.checks.push(BuildCheck {
                        name: "fixed-offline-recipe".into(),
                        passed: success,
                    });
                    ensure!(success, "fixed build recipe exited unsuccessfully");
                    built = true;
                }
                "ci-admit" => {
                    ensure!(
                        built && admitted_target.is_none(),
                        "successful isolated build required"
                    );
                    let pointer: Value = serde_json::from_slice(&fs::read(
                        job.join("platform/artifacts/current.json"),
                    )?)?;
                    let artifact = Digest::try_from(
                        pointer["artifact"]
                            .as_str()
                            .context("artifact pointer")?
                            .to_owned(),
                    )?;
                    let input = job
                        .join("platform/artifacts")
                        .join(artifact.as_str().trim_start_matches("sha256:"));
                    let admitted = day2::artifact::LoadedArtifact::load(&input)?;
                    ensure!(
                        admitted.id() == artifact.as_str(),
                        "artifact identity differs from recipe result"
                    );
                    let artifacts = result.join("artifacts");
                    private_directory(&artifacts)?;
                    let target = artifacts.join(artifact.as_str().trim_start_matches("sha256:"));
                    PinnedTree::capture(&input)?.materialize(&target)?;
                    let _ = day2::artifact::LoadedArtifact::load(&target)?;
                    evidence.checks.push(BuildCheck {
                        name: "artifact-admission".into(),
                        passed: true,
                    });
                    admitted_artifact = Some(artifact);
                    evidence.credential_presence =
                        if admitted.contract().credential_manifest.is_empty() {
                            CredentialPresence::Absent
                        } else {
                            CredentialPresence::Present
                        };
                    admitted_target = Some(target);
                }
                "ci-properties" => {
                    let target = admitted_target
                        .as_ref()
                        .context("admitted artifact required")?;
                    let admitted = day2::artifact::LoadedArtifact::load(target)?;
                    let empty: BTreeMap<_, Value> = admitted
                        .contract()
                        .schema
                        .models
                        .keys()
                        .map(|name| (name, json!([])))
                        .collect();
                    let properties =
                        day2::properties::evaluate(&admitted, &serde_json::to_value(empty)?)?;
                    let passed = properties.checks.iter().all(|check| check.passed);
                    let bytes = serde_json::to_vec_pretty(&properties)?;
                    evidence.properties = Some(Digest::new(&bytes));
                    fs::write(result.join("properties.json"), bytes)?;
                    evidence.checks.push(BuildCheck {
                        name: "empty-state-properties".into(),
                        passed,
                    });
                    ensure!(passed, "app empty-state properties failed");
                }
                "ci-development" => {
                    return Ok(
                        json!({"artifact":admitted_target.as_ref().context("admitted artifact required")?,"output":result.join("development")}),
                    );
                }
                "dev-create" => {
                    #[derive(Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct Input {
                        artifact: PathBuf,
                        output: PathBuf,
                        example: String,
                        seed: String,
                        count: u64,
                    }
                    let input: Input = effect.decode()?;
                    ensure!(
                        campaign.is_none()
                            && Some(&input.artifact) == admitted_target.as_ref()
                            && input.output == result.join("development")
                            && input.example.is_empty()
                            && (1..=100).contains(&input.count),
                        "CI campaign binding or budget mismatch"
                    );
                    let runtime = day2::development::create(&input.artifact, &input.output, None)?;
                    campaign = Some(day2::development::Campaign::new(
                        runtime,
                        None,
                        input.seed.parse()?,
                        input.count,
                    )?);
                }
                "ci-evidence" => {
                    ensure!(
                        simulation.is_complete() && evidence.simulation.is_some(),
                        "control simulation evidence required"
                    );
                    let campaign = campaign.as_ref().context("development campaign required")?;
                    ensure!(campaign.is_complete(), "development campaign incomplete");
                    evidence.development = Some(Digest::new(&fs::read(
                        result.join("development/development.json"),
                    )?));
                    evidence.checks.push(BuildCheck {
                        name: "development-campaign".into(),
                        passed: true,
                    });
                    evidence.artifact = admitted_artifact.clone();
                    evidence.verification_evidence()?;
                }
                _ => anyhow::bail!("unknown CI capability: {}", effect.action),
            }
            Ok(json!({}))
        });
        if !simulation.is_complete() && outcome.is_err() {
            evidence.checks.push(BuildCheck {
                name: "control-simulation".into(),
                passed: false,
            });
        }
        if let Some(campaign) = campaign.as_mut() {
            campaign.persist(outcome.as_ref().err().map(|error| format!("{error:#}")))?;
            evidence.development = Some(Digest::new(&fs::read(
                result.join("development/development.json"),
            )?));
            if outcome.is_err() {
                evidence.checks.push(BuildCheck {
                    name: "development-campaign".into(),
                    passed: false,
                });
            }
        }
        outcome?;
        Ok(())
    }

    fn load_evidence(
        &self,
        request: &BuildRequest,
        platform: &PlatformInputs,
        directory: &Path,
    ) -> Result<BuildEvidence> {
        ensure!(
            fs::symlink_metadata(directory)?.file_type().is_dir(),
            "evidence directory type"
        );
        let evidence = BuildEvidence::decode(&read_regular(&directory.join("evidence.json"))?)?;
        ensure!(
            evidence.format == 1
                && evidence.plan == request.plan.fingerprint()?
                && &evidence.source == request.source.digest()
                && &evidence.platform == platform.digest()
                && evidence.builder == self.binding()?
                && evidence.recipe == recipe_digest(),
            "cached evidence input mismatch"
        );
        ensure!(
            Digest::new(&read_regular(&directory.join("inputs.json"))?) == evidence.inputs,
            "evidence input manifest changed"
        );
        let expected_inputs = self.input_manifest(request, platform)?;
        ensure!(
            Digest::new(&expected_inputs) == evidence.inputs,
            "cached input manifest does not match approved inputs"
        );
        let (log, oversized) = read_log(&directory.join("build.log"))?;
        ensure!(!oversized, "cached build log exceeds budget");
        ensure!(Digest::new(&log) == evidence.log, "build log changed");
        let properties = if let Some(properties) = &evidence.properties {
            let bytes = read_cached_properties(&directory.join("properties.json"))?;
            ensure!(
                &Digest::new(&bytes) == properties,
                "property evidence changed"
            );
            Some(serde_json::from_slice::<day2::properties::Evidence>(
                &bytes,
            )?)
        } else {
            None
        };
        if let Some(expected) = &evidence.development {
            let bytes = read_regular(&directory.join("development/development.json"))?;
            ensure!(
                &Digest::new(&bytes) == expected,
                "development evidence changed"
            );
            let report: Value = serde_json::from_slice(&bytes)?;
            if let Some(artifact) = &evidence.artifact {
                ensure!(
                    report["format"] == 1
                        && report["artifact"].as_str() == Some(artifact.as_str())
                        && report["failure"].is_null(),
                    "invalid development evidence"
                );
            }
        }
        if let Some(expected) = &evidence.simulation {
            crate::simulation_campaign::verify_receipt(
                &directory.join("control-simulation"),
                expected,
                crate::simulation_campaign::DEFAULT_SEED,
                crate::simulation_campaign::CI_CASES,
            )?;
        }
        if let Some(artifact) = &evidence.artifact {
            let admitted =
                day2::artifact::LoadedArtifact::load(&evidence.artifact_directory(directory)?)?;
            ensure!(
                admitted.id() == artifact.as_str(),
                "cached artifact changed"
            );
            ensure!(
                evidence.credential_presence == CredentialPresence::Unknown
                    || evidence.credential_presence
                        == if admitted.contract().credential_manifest.is_empty() {
                            CredentialPresence::Absent
                        } else {
                            CredentialPresence::Present
                        },
                "cached credential presence changed"
            );
            evidence.verification_evidence()?;
            let empty = admitted
                .contract()
                .schema
                .models
                .keys()
                .map(|name| (name.clone(), json!([])))
                .collect::<BTreeMap<_, _>>();
            validate_cached_properties(
                properties
                    .as_ref()
                    .context("verified property evidence missing")?,
                admitted.id(),
                &admitted.contract().properties,
                &serde_json::to_value(empty)?,
            )?;
        } else {
            ensure!(evidence.failure.is_some(), "incomplete build evidence");
        }
        Ok(evidence)
    }
}

fn validate_cached_properties(
    report: &day2::properties::Evidence,
    artifact: &str,
    catalog: &[String],
    empty: &Value,
) -> Result<()> {
    day2::properties::validate_catalog(catalog)?;
    ensure!(
        report.format == 1 && report.artifact == artifact,
        "cached property artifact mismatch"
    );
    ensure!(
        &report.snapshot == empty,
        "cached property snapshot must contain exactly all empty model tables"
    );
    ensure!(
        report
            .checks
            .iter()
            .map(|check| &check.name)
            .eq(catalog.iter()),
        "cached property catalog mismatch"
    );
    ensure!(
        report
            .checks
            .iter()
            .all(|check| check.passed && check.error.is_empty()),
        "cached property checks did not pass"
    );
    Ok(())
}

fn read_cached_properties(path: &Path) -> Result<Vec<u8>> {
    const LIMIT: u64 = 2 * 1024 * 1024;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= LIMIT,
        "regular bounded property evidence required"
    );
    let mut input = std::io::Read::take(fs::File::open(path)?, LIMIT + 1);
    let mut bytes = vec![];
    std::io::Read::read_to_end(&mut input, &mut bytes)?;
    ensure!(bytes.len() as u64 <= LIMIT, "property evidence byte budget");
    Ok(bytes)
}

fn relative(path: &Path) -> Result<String> {
    ensure!(
        !path.as_os_str().is_empty()
            && path
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
        "noncanonical input path"
    );
    let text = path.to_str().context("non UTF-8 input path")?;
    ensure!(
        !text.contains(['\\', '\n', '\r', '\0']),
        "unsupported input path"
    );
    Ok(text.into())
}

fn validate_registry_layout(root: &Path) -> Result<()> {
    fn visit(directory: &Path, depth: usize) -> Result<()> {
        ensure!(
            depth <= 32 && fs::symlink_metadata(directory)?.file_type().is_dir(),
            "registry directory type/budget"
        );
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("registry filename"))?;
            ensure!(
                ![".git", ".hg", ".svn", "credentials", "credentials.toml"]
                    .contains(&name.as_str()),
                "registry VCS metadata or credentials forbidden"
            );
            if depth == 0 {
                ensure!(
                    ["src", "cache", "index", "CACHEDIR.TAG"].contains(&name.as_str()),
                    "only offline registry inputs are allowed"
                );
            }
            let kind = entry.file_type()?;
            ensure!(
                kind.is_file() || kind.is_dir(),
                "registry symlink or special file forbidden"
            );
            if kind.is_dir() {
                visit(&entry.path(), depth + 1)?;
            }
        }
        Ok(())
    }
    visit(root, 0)
}

/// Local credentials, Terraform providers/state and runtime outputs are never
/// platform build inputs, even when an operator has initialized a public stack.
pub fn local_platform_input(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    [
        ".terraform",
        ".cache",
        ".state",
        ".git",
        "target",
        "secrets",
        "credentials",
        "instance.json",
        "secrets.json",
        "credentials.json",
        "plan.bin",
        ".DS_Store",
    ]
    .contains(&name)
        || name == ".env"
        || name.starts_with(".env.") && !name.ends_with(".example")
        || name.ends_with(".tfvars")
        || name.ends_with(".tfvars.json")
        || name.contains(".tfstate")
        || [
            "pem", "key", "p12", "pfx", "sqlite", "sqlite3", "db", "log", "tfplan",
        ]
        .contains(
            &path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or_default(),
        )
}

fn collect(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, InputFile>,
    total: &mut u64,
    platform: bool,
) -> Result<()> {
    ensure!(
        fs::symlink_metadata(directory)?.file_type().is_dir(),
        "input directory symlink or special file"
    );
    ensure!(
        directory.strip_prefix(root)?.components().count() <= 32,
        "input nesting budget"
    );
    let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if platform && local_platform_input(&path) {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_dir() {
            collect(root, &path, files, total, platform)?;
        } else {
            ensure!(kind.is_file(), "input symlink or special file forbidden");
            let file = pin_file(&path)?;
            *total += file.bytes;
            ensure!(
                *total <= MAX_BYTES && files.len() < MAX_FILES,
                "input tree budget"
            );
            files.insert(relative(path.strip_prefix(root)?)?, file);
        }
    }
    Ok(())
}

fn collect_cli(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, InputFile>,
    total: &mut u64,
) -> Result<()> {
    ensure!(
        directory.strip_prefix(root)?.components().count() <= 32,
        "CLI input nesting budget"
    );
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        if [
            ".git",
            ".cache",
            "target",
            "day2",
            "day2-host",
            "day2-workflows",
            "day2-workflows.json",
            "day2-sandbox",
            "day2-sandbox-probe",
            "day2-compiler-sandbox",
            "xtask",
            "distribution.json",
            "LICENSE",
            "THIRD-PARTY-NOTICES.txt",
            "dependency-inventory.json",
        ]
        .iter()
        .any(|excluded| name == *excluded)
        {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_dir() {
            collect_cli(root, &entry.path(), files, total)?;
        } else {
            ensure!(
                kind.is_file(),
                "CLI input symlink or special file forbidden"
            );
            let file = pin_file(&entry.path())?;
            *total += file.bytes;
            ensure!(
                *total <= MAX_BYTES && files.len() < MAX_FILES,
                "CLI input budget"
            );
            files.insert(relative(entry.path().strip_prefix(root)?)?, file);
        }
    }
    Ok(())
}

fn read_regular(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= MAX_FILE_BYTES,
        "regular bounded input required"
    );
    let bytes = fs::read(path)?;
    ensure!(bytes.len() as u64 <= MAX_FILE_BYTES, "input file budget");
    Ok(bytes)
}

fn pin_file(path: &Path) -> Result<InputFile> {
    let bytes = read_regular(path)?;
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;
        fs::symlink_metadata(path)?.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = false;
    Ok(InputFile {
        digest: Digest::new(&bytes),
        bytes: bytes.len() as u64,
        executable,
    })
}

fn write_pinned(source: &Path, destination: &Path, expected: &InputFile) -> Result<()> {
    let bytes = read_regular(source)?;
    ensure!(
        Digest::new(&bytes) == expected.digest && bytes.len() as u64 == expected.bytes,
        "approved input changed: {}",
        source.display()
    );
    fs::create_dir_all(destination.parent().context("input parent")?)?;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    file.write_all(&bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(if expected.executable {
            0o555
        } else {
            0o444
        }))?;
    }
    Ok(())
}

fn private_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_dir(),
        "private directory type"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn seal(directory: &Path) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            seal(&entry.path())?;
        } else {
            ensure!(
                entry.file_type()?.is_file(),
                "evidence special file forbidden"
            );
            fs::File::open(entry.path())?.sync_all()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = entry.metadata()?.permissions().mode();
                fs::set_permissions(
                    entry.path(),
                    fs::Permissions::from_mode(if mode & 0o111 != 0 { 0o555 } else { 0o444 }),
                )?;
            }
        }
    }
    fs::File::open(directory)?.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o555))?;
    }
    Ok(())
}

fn read_log(path: &Path) -> Result<(Vec<u8>, bool)> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "build log must be a regular file"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_LOG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let oversized = bytes.len() as u64 > MAX_LOG_BYTES;
    bytes.truncate(MAX_LOG_BYTES as usize);
    Ok((bytes, oversized))
}

fn append_log(path: &Path, detail: &[u8]) -> Result<()> {
    let (existing, oversized) = read_log(path)?;
    ensure!(!oversized, "stored build log budget");
    let remaining = MAX_LOG_BYTES as usize - existing.len();
    let mut file = fs::OpenOptions::new().append(true).open(path)?;
    file.write_all(&detail[..detail.len().min(remaining)])?;
    Ok(())
}

fn run_bounded(command: &mut Command, log: &Path) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().context("start fixed isolated build")?;
    let start = Instant::now();
    let mut outcome = loop {
        if start.elapsed() >= BUILD_TIMEOUT
            || fs::metadata(log).map_or(true, |metadata| metadata.len() > MAX_LOG_BYTES)
        {
            break Err(anyhow::anyhow!("build time or log budget exceeded"));
        }
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status.success()),
            Err(error) => break Err(error.into()),
            Ok(None) => {}
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // Terminate the whole private process group, including abandoned build subprocesses.
    #[cfg(unix)]
    {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", &format!("-{}", child.id())])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
    if fs::metadata(log).map_or(true, |metadata| metadata.len() > MAX_LOG_BYTES) {
        outcome = Err(anyhow::anyhow!("build log budget exceeded"));
    }
    outcome
}

#[cfg(test)]
mod cached_evidence_tests {
    use super::*;

    fn success() -> Result<BuildEvidence> {
        Ok(BuildEvidence {
            format: 1,
            plan: Digest::new(b"plan"),
            source: Digest::new(b"source"),
            platform: Digest::new(b"platform"),
            recipe: recipe_digest(),
            builder: BindingRef::pin(
                Name::try_from("test-runner".to_owned())?,
                &json!({"fixture":true}),
            )?,
            artifact: Some(Digest::new(b"artifact")),
            credential_presence: CredentialPresence::Absent,
            checks: [
                "control-simulation",
                "fixed-offline-recipe",
                "artifact-admission",
                "empty-state-properties",
                "development-campaign",
            ]
            .into_iter()
            .map(|name| BuildCheck {
                name: name.into(),
                passed: true,
            })
            .collect(),
            log: Digest::new(b"log"),
            inputs: Digest::new(b"inputs"),
            properties: Some(Digest::new(b"properties")),
            development: Some(Digest::new(b"development")),
            simulation: Some(Digest::new(b"simulation")),
            failure: None,
            containment: "test-only".into(),
            verification_scope: "test-only".into(),
        })
    }

    #[test]
    fn cached_success_requires_exact_closed_checks_and_mandatory_evidence() -> Result<()> {
        let valid = serde_json::to_value(success()?)?;
        BuildEvidence::decode(&serde_json::to_vec(&valid)?)?.verification_evidence()?;
        let mut cases = vec![];
        let mut value = valid.clone();
        value["simulation"] = Value::Null;
        cases.push(value);
        let mut value = valid.clone();
        value["properties"] = Value::Null;
        cases.push(value);
        let mut value = valid.clone();
        value["artifact"] = Value::Null;
        cases.push(value);
        let mut value = valid.clone();
        value["format"] = 2.into();
        cases.push(value);
        let mut value = valid.clone();
        value["failure"] = "failed".into();
        cases.push(value);
        let mut value = valid.clone();
        value["checks"][0]["passed"] = false.into();
        cases.push(value);
        let mut value = valid.clone();
        value["checks"][0]["name"] = "arbitrary-check".into();
        cases.push(value);
        let mut value = valid.clone();
        value["checks"][1] = value["checks"][0].clone();
        cases.push(value);
        let mut value = valid.clone();
        value["checks"].as_array_mut().unwrap().swap(0, 1);
        cases.push(value);
        let mut value = valid.clone();
        value["checks"].as_array_mut().unwrap().pop();
        cases.push(value);
        let mut value = valid;
        value["checks"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":"extra","passed":true}));
        cases.push(value);
        for value in cases {
            let evidence = BuildEvidence::decode(&serde_json::to_vec(&value)?)?;
            ensure!(
                evidence.verification_evidence().is_err(),
                "invalid cached success admitted: {value}"
            );
        }
        Ok(())
    }

    #[test]
    fn cached_property_report_binds_artifact_catalog_and_complete_empty_snapshot() -> Result<()> {
        let artifact = Digest::new(b"artifact");
        let catalog = vec!["owners_consistent".into(), "versions_positive".into()];
        let empty = json!({"links":[],"history":[]});
        let valid = json!({"format":1,"artifact":artifact,"snapshot":empty,"checks":[
            {"name":"owners_consistent","passed":true,"error":""},
            {"name":"versions_positive","passed":true,"error":""}
        ]});
        validate_cached_properties(
            &serde_json::from_value(valid.clone())?,
            artifact.as_str(),
            &catalog,
            &empty,
        )?;
        let mut cases = vec![];
        let mut value = valid.clone();
        value["format"] = 2.into();
        cases.push(value);
        let mut value = valid.clone();
        value["artifact"] = Digest::new(b"other-artifact").as_str().into();
        cases.push(value);
        let mut value = valid.clone();
        value["snapshot"] = json!({"links":[]});
        cases.push(value);
        let mut value = valid.clone();
        value["snapshot"]["extra"] = json!([]);
        cases.push(value);
        let mut value = valid.clone();
        value["snapshot"]["links"] = json!([{"id":1}]);
        cases.push(value);
        let mut value = valid.clone();
        value["checks"] = json!([]);
        cases.push(value);
        let mut value = valid.clone();
        value["checks"][1] = value["checks"][0].clone();
        cases.push(value);
        let mut value = valid.clone();
        value["checks"][0]["passed"] = false.into();
        cases.push(value);
        let mut value = valid;
        value["checks"][0]["error"] = "decoding failed".into();
        cases.push(value);
        for value in cases {
            let report = serde_json::from_value(value.clone())?;
            ensure!(
                validate_cached_properties(&report, artifact.as_str(), &catalog, &empty).is_err(),
                "invalid cached property report admitted: {value}"
            );
        }
        Ok(())
    }

    #[test]
    fn cached_property_file_is_bounded_and_cannot_be_a_symlink() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("properties.json");
        fs::write(&path, b"{}")?;
        ensure!(
            read_cached_properties(&path)? == b"{}",
            "property read mismatch"
        );
        fs::OpenOptions::new()
            .write(true)
            .open(&path)?
            .set_len(2 * 1024 * 1024 + 1)?;
        ensure!(
            read_cached_properties(&path).is_err(),
            "oversized property evidence admitted"
        );
        #[cfg(unix)]
        {
            let link = directory.path().join("link.json");
            std::os::unix::fs::symlink(&path, &link)?;
            ensure!(
                read_cached_properties(&link).is_err(),
                "symlink property evidence admitted"
            );
        }
        Ok(())
    }
}
