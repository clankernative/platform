//! Exact-run transport and admission for the Verify.roc hosted campaigns.
//! Cargo builds its ordinary full package/target graph once. The recipes select
//! campaigns; this module admits their binaries and joins complete evidence.
use super::{
    WORKSPACE_TEST_ARGUMENTS, cached_fixture, configure_tests, required_steps, test_command,
};
use crate::{CommandStatusError, command_status_with_budget, run_with_budget};
use anyhow::{Context, Result, ensure};
use day2::digest;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

const PREPARED: &str = "artifacts/ci-prepared.json";
const BINARIES: &str = "artifacts/ci-test-binaries.json";
const BUILD_CACHE: &str = "artifacts/ci-test-build-cache.json";
const PROGRAM_CACHE: &str = "artifacts/ci-test-programs";
const RESULTS: &str = "artifacts/ci-results";
const CARGO_FAILURE_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
const SHARDS: &[&str] = &[
    "workspace-day2",
    "workspace-control",
    "workspace-other",
    "simulation",
    "parallel-runtime",
    "isolated-build",
    "installation-build",
];

pub(super) mod mac;
pub(super) mod reuse;

#[derive(Clone, Debug, Serialize)]
struct CargoProcessOutcome {
    category: &'static str,
    code: Option<i32>,
    signal: Option<i32>,
    os_error: Option<i32>,
}

impl CargoProcessOutcome {
    fn observed(
        outcome: std::result::Result<std::process::ExitStatus, CommandStatusError>,
    ) -> Self {
        match outcome {
            Ok(status) => {
                #[cfg(unix)]
                let signal = {
                    use std::os::unix::process::ExitStatusExt;
                    status.signal()
                };
                #[cfg(not(unix))]
                let signal = None;
                Self {
                    category: if status.success() { "success" } else { "exit" },
                    code: status.code(),
                    signal,
                    os_error: None,
                }
            }
            Err(CommandStatusError::Spawn(error)) => Self {
                category: "spawn",
                code: None,
                signal: None,
                os_error: error.raw_os_error(),
            },
            Err(CommandStatusError::Wait(error)) => Self {
                category: "wait",
                code: None,
                signal: None,
                os_error: error.raw_os_error(),
            },
            Err(CommandStatusError::Timeout) => Self {
                category: "timeout",
                code: None,
                signal: None,
                os_error: None,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct CargoCaptureProblem {
    category: &'static str,
    line: Option<usize>,
    byte_offset: Option<usize>,
    os_error: Option<i32>,
}

#[derive(Debug)]
struct CargoReportingFailure {
    stage: &'static str,
    process: CargoProcessOutcome,
    capture: Option<CargoCaptureProblem>,
    retained: bool,
}

impl std::fmt::Display for CargoReportingFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Cargo {} failed: primary={}, cargo_exit={:?}, signal={:?}, errno={:?}; capture={}; evidence_retained={}",
            self.stage,
            if self.process.category == "success" {
                "capture"
            } else {
                self.process.category
            },
            self.process.code,
            self.process.signal,
            self.process.os_error,
            self.capture
                .as_ref()
                .map_or("valid", |problem| problem.category),
            self.retained,
        )
    }
}

impl std::error::Error for CargoReportingFailure {}

fn retain_cargo_failure(
    root: &Path,
    stage: &'static str,
    process: &CargoProcessOutcome,
    problem: &Option<CargoCaptureProblem>,
    output: Option<&[u8]>,
) -> Result<PathBuf> {
    use std::io::Write;
    // The raw spool is local operator evidence, never an Actions upload input.
    // Unix tempdirs otherwise use 0777 subject to umask. Make this directory
    // owner-only at creation, before any raw bytes; NamedTempFile uses 0600.
    let mut builder = tempfile::Builder::new();
    builder.prefix("ci-compiler-failure-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    let directory = builder.tempdir_in(root.join("artifacts"))?;
    let mut spool = tempfile::NamedTempFile::new_in(directory.path())?;
    let retained = output.map(|bytes| &bytes[..bytes.len().min(CARGO_FAILURE_CAPTURE_BYTES)]);
    if let Some(bytes) = retained {
        spool.write_all(bytes)?;
    }
    spool.persist(directory.path().join("stdout.bin"))?;
    write_cargo_failure_manifest(
        directory.path(),
        root,
        stage,
        process,
        problem,
        output,
        &BTreeSet::new(),
    )?;
    Ok(directory.keep())
}

fn write_cargo_failure_manifest(
    directory: &Path,
    root: &Path,
    stage: &'static str,
    process: &CargoProcessOutcome,
    problem: &Option<CargoCaptureProblem>,
    output: Option<&[u8]>,
    diagnostic_codes: &BTreeSet<String>,
) -> Result<()> {
    let retained = output.map(|bytes| &bytes[..bytes.len().min(CARGO_FAILURE_CAPTURE_BYTES)]);
    let (evidence_identity, identity_status) = match cargo_failure_identity(root) {
        Ok(identity) => (Some(identity), "bound"),
        Err(_) => (None, "unavailable"),
    };
    let metadata = json!({
        "format":1,
        "stage":stage,
        "identity":evidence_identity,
        "identity_status":identity_status,
        "diagnostic_only_not_a_preparation_or_runtime_receipt":true,
        "log_pointer":{"job":std::env::var("GITHUB_JOB").ok(),"stage":stage,"channel":"Actions Cargo outcome metadata"},
        "cargo_process":process,
        "capture_problem":problem,
        "capture_bytes":output.map(<[u8]>::len),
        "capture_digest":output.map(digest),
        "retained_bytes":retained.map(<[u8]>::len),
        "retained_digest":retained.map(digest),
        "complete":output.is_some_and(|bytes| bytes.len() <= CARGO_FAILURE_CAPTURE_BYTES),
        "rust_diagnostic_codes":diagnostic_codes,
        "raw_retention":"private job-workspace spool only; not durable after runner disposal",
        "cleanup_signal_is_not_original_exit":true,
    });
    fs::write(
        directory.join("manifest.json"),
        serde_json::to_vec_pretty(&metadata)?,
    )?;
    Ok(())
}

fn cargo_failure_identity(root: &Path) -> Result<Identity> {
    let snapshot = super::verification_snapshot(root, "verify")?;
    identity(root, &snapshot)
}

fn report_cargo_capture(
    root: &Path,
    stage: &'static str,
    process: CargoProcessOutcome,
    output: std::io::Result<Vec<u8>>,
) -> Result<Vec<serde_json::Value>> {
    let (output, mut problem) = match output {
        Ok(output) => (Some(output), None),
        Err(error) => (
            None,
            Some(CargoCaptureProblem {
                category: "read",
                line: None,
                byte_offset: None,
                os_error: error.raw_os_error(),
            }),
        ),
    };
    let mut messages = Vec::new();
    let mut offset = 0;
    // Preserve failed-command evidence before any JSON decoding. A parser or
    // evidence failure can add context, but cannot replace this process result.
    let early_evidence = (process.category != "success")
        .then(|| retain_cargo_failure(root, stage, &process, &problem, output.as_deref()));
    if let Some(output) = &output {
        for (index, line) in output.split(|byte| *byte == b'\n').enumerate() {
            if !line.is_empty() {
                match day2::json::decode::<serde_json::Value>(line) {
                    Ok(value) => messages.push(value),
                    Err(_) => {
                        if problem.is_none() {
                            problem = Some(CargoCaptureProblem {
                                category: "json",
                                line: Some(index + 1),
                                byte_offset: Some(offset),
                                os_error: None,
                            });
                        }
                    }
                }
            }
            offset += line.len() + 1;
        }
    }
    if process.category != "success" || problem.is_some() {
        let diagnostic_codes: BTreeSet<String> = messages
            .iter()
            .filter(|message| message["reason"] == "compiler-message")
            .filter_map(|message| message["message"]["code"]["code"].as_str())
            .filter(|code| {
                code.len() == 5
                    && code.starts_with('E')
                    && code.as_bytes()[1..].iter().all(u8::is_ascii_digit)
            })
            .take(32)
            .map(str::to_owned)
            .collect();
        let evidence = match early_evidence {
            Some(result) => result,
            None => retain_cargo_failure(root, stage, &process, &problem, output.as_deref()),
        };
        let retained = evidence
            .and_then(|directory| {
                write_cargo_failure_manifest(
                    &directory,
                    root,
                    stage,
                    &process,
                    &problem,
                    output.as_deref(),
                    &diagnostic_codes,
                )
            })
            .is_ok();
        // Neither free-form compiler text nor malformed bytes enter the error.
        // Registered-secret masking on the runner is not a private raw archive.
        let failure = CargoReportingFailure {
            stage,
            process,
            capture: problem,
            retained,
        };
        eprintln!("{failure}");
        eprintln!("Cargo diagnostic codes: {diagnostic_codes:?}");
        return Err(failure.into());
    }
    for message in &messages {
        if message["reason"] == "compiler-message"
            && let Some(rendered) = message["message"]["rendered"].as_str()
        {
            print!("{rendered}");
        }
    }
    Ok(messages)
}

fn capture_cargo(
    root: &Path,
    stage: &'static str,
    command: &mut Command,
    budget: Duration,
) -> Result<Vec<serde_json::Value>> {
    let capture = tempfile::NamedTempFile::new_in(root.join("artifacts"))?;
    command.stdout(capture.as_file().try_clone()?);
    let process = CargoProcessOutcome::observed(command_status_with_budget(root, command, budget));
    // Observe process status before reading or decoding its captured output.
    report_cargo_capture(root, stage, process, fs::read(capture.path()))
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    checkout: String,
    tree: String,
    source_identity: String,
    workspace: PathBuf,
    run: String,
    attempt: String,
    host: String,
    architecture: String,
    workflow: String,
    snapshot: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Binary {
    package: String,
    target: String,
    kind: Vec<String>,
    directory: PathBuf,
    executable: PathBuf,
    digest: String,
    permissions: u32,
}

/// Completed compiler outputs, without any runtime outcome or run receipt.
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BuildIdentity {
    snapshot: String,
    workflow: String,
    workspace: PathBuf,
    host: String,
    architecture: String,
    rustc: String,
    cargo: String,
    cc: String,
    environment: String,
    cargo_configuration: BTreeMap<String, Option<String>>,
    ci_workflow: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BuildCache {
    identity: BuildIdentity,
    binaries: Vec<Binary>,
    programs: Vec<Binary>,
    auxiliaries: Vec<Binary>,
}

pub(super) fn build_identity(root: &Path, snapshot: &str) -> Result<BuildIdentity> {
    let version = |tool: &str, verbose: bool| -> Result<String> {
        let mut command = Command::new(tool);
        command.arg("--version").current_dir(root);
        if verbose {
            command.arg("--verbose");
        }
        let output = command.output()?;
        ensure!(output.status.success(), "compiler cache tool identity");
        Ok(String::from_utf8(output.stdout)?)
    };
    // Hash values rather than exporting compiler environment or credential data.
    let environment: BTreeMap<_, _> = std::env::vars()
        .filter(|(name, _)| {
            [
                "CARGO",
                "RUST",
                "CC",
                "CXX",
                "CFLAGS",
                "CPPFLAGS",
                "CMAKE",
                "LDFLAGS",
                "SDKROOT",
                "MACOSX_DEPLOYMENT_TARGET",
                "DEVELOPER_DIR",
                "SOURCE_DATE_EPOCH",
                "ImageOS",
                "ImageVersion",
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix))
        })
        .collect();
    let mut cargo_configuration = BTreeMap::new();
    for name in [".cargo/config", ".cargo/config.toml"] {
        let contents = match fs::read(root.join(name)) {
            Ok(bytes) => Some(digest(&bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        cargo_configuration.insert(name.into(), contents);
    }
    Ok(BuildIdentity {
        snapshot: snapshot.into(),
        workflow: day2::automation::source_digest(),
        workspace: root.canonicalize()?,
        host: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        rustc: version("rustc", true)?,
        cargo: version("cargo", true)?,
        cc: version("cc", false)?,
        environment: digest(&serde_json::to_vec(&environment)?),
        cargo_configuration,
        ci_workflow: digest(&fs::read(root.join(".github/workflows/ci.yml"))?),
    })
}

fn admit_build_cache(
    root: &Path,
    cache: &BuildCache,
    identity: &BuildIdentity,
    expected: &BTreeSet<(String, String, Vec<String>)>,
    expected_programs: &BTreeSet<(String, String, Vec<String>)>,
    expected_auxiliaries: &BTreeSet<(String, String, Vec<String>)>,
    directories: &BTreeMap<String, PathBuf>,
) -> Result<()> {
    ensure!(
        cache.identity == *identity,
        "cached test compiler inputs changed"
    );
    let mut executables = BTreeSet::new();
    for (binaries, targets, programs) in [
        (&cache.binaries, expected, false),
        (&cache.programs, expected_programs, true),
        (&cache.auxiliaries, expected_auxiliaries, true),
    ] {
        let mut observed = BTreeSet::new();
        for binary in binaries {
            ensure!(
                observed.insert((
                    binary.package.clone(),
                    binary.target.clone(),
                    binary.kind.clone()
                )) && executables.insert(&binary.executable)
                    && directories.get(&binary.package) == Some(&binary.directory),
                "cached compiler target identity or package directory changed"
            );
            let directory = if programs {
                "target/debug"
            } else {
                "target/debug/deps"
            };
            ensure!(
                binary.executable.parent() == Some(Path::new(directory))
                    && binary
                        .executable
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_))),
                "cached executable outside ordinary Cargo output"
            );
            let path = if programs {
                ensure!(
                    binary.executable == program_output(&binary.target),
                    "ordinary Cargo program name required"
                );
                root.join(PROGRAM_CACHE)
                    .join(binary.executable.file_name().context("program file name")?)
            } else {
                root.join(&binary.executable)
            };
            admit_executable(&path, &binary.digest, binary.permissions)?;
            if binary.package == "day2-sandbox" {
                crate::native_toolchain::verify_executable_target(
                    crate::native_toolchain::load(root)?.target,
                    &path,
                )?;
            }
        }
        ensure!(
            observed == *targets,
            "cached compiler inventory must cover every default target and supporting program"
        );
    }
    Ok(())
}

fn program_output(target: &str) -> PathBuf {
    Path::new("target/debug").join(format!("{target}{}", std::env::consts::EXE_SUFFIX))
}

fn executable_permissions(path: &Path) -> Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::symlink_metadata(path)?.permissions().mode() & 0o7777)
}

fn admit_executable(path: &Path, expected: &str, permissions: u32) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "compiler executable must be a regular file"
    );
    ensure!(
        path.canonicalize()? == path,
        "compiler output has a symlink ancestor"
    );
    #[cfg(unix)]
    {
        ensure!(
            permissions & 0o111 != 0
                && permissions & !0o777 == 0
                && executable_permissions(path)? == permissions,
            "compiler output lacks execute permission"
        );
    }
    ensure!(
        digest(&fs::read(path)?) == expected,
        "compiler executable bytes changed"
    );
    Ok(())
}

/// Copy only metadata-admitted normal programs, preserving executable permissions.
/// Cache storage stays separate from ordinary Cargo outputs and run receipts.
fn copy_programs(root: &Path, programs: &[Binary], restoring: bool) -> Result<()> {
    let destination = root.join(if restoring {
        "target/debug"
    } else {
        PROGRAM_CACHE
    });
    fs::create_dir_all(&destination)?;
    ensure!(
        destination.canonicalize()? == destination,
        "program output directory has a symlink ancestor"
    );
    for program in programs {
        ensure!(
            program.executable == program_output(&program.target)
                && program.executable.parent() == Some(Path::new("target/debug"))
                && program
                    .executable
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_))),
            "ordinary Cargo program path required"
        );
        let ordinary = root.join(&program.executable);
        let cached = root.join(PROGRAM_CACHE).join(
            program
                .executable
                .file_name()
                .context("program file name")?,
        );
        let (source, target) = if restoring {
            (cached, ordinary)
        } else {
            (ordinary, cached)
        };
        admit_executable(&source, &program.digest, program.permissions)?;
        match fs::symlink_metadata(&target) {
            Ok(metadata) => ensure!(
                metadata.file_type().is_file(),
                "program copy destination must be a regular file"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        fs::copy(source, &target)?;
        admit_executable(&target, &program.digest, program.permissions)?;
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Prepared {
    identity: Identity,
    binaries: Vec<Binary>,
    programs: Vec<Binary>,
    auxiliaries: Vec<Binary>,
    fixtures: BTreeMap<String, String>,
    passed: BTreeSet<String>,
    timings_ms: BTreeMap<String, u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    prepared_digest: String,
    shard: String,
    passed: BTreeSet<String>,
    timings_ms: BTreeMap<String, u64>,
    binaries: BTreeSet<PathBuf>,
}

pub(super) fn valid(shard: &str) -> bool {
    SHARDS.contains(&shard)
}

fn identity(root: &Path, snapshot: &str) -> Result<Identity> {
    let checkout = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()?;
    ensure!(checkout.status.success(), "resolve verification checkout");
    let checkout = String::from_utf8(checkout.stdout)?.trim().to_owned();
    ensure!(
        checkout.len() == 40 && checkout.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "exact checkout SHA required"
    );
    let tree = Command::new("git")
        .args(["rev-parse", "HEAD^{tree}"])
        .current_dir(root)
        .output()?;
    ensure!(tree.status.success(), "resolve exact verification tree");
    let tree = String::from_utf8(tree.stdout)?.trim().to_owned();
    ensure!(
        tree.len() == 40 && tree.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "exact checkout tree required"
    );
    Ok(Identity {
        checkout,
        tree,
        source_identity: super::verification_source_identity(root, "verify")?,
        workspace: root.canonicalize()?,
        run: std::env::var("GITHUB_RUN_ID").context("hosted verification run identity required")?,
        attempt: std::env::var("GITHUB_RUN_ATTEMPT")
            .context("hosted verification attempt required")?,
        host: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        workflow: day2::automation::source_digest(),
        snapshot: snapshot.into(),
    })
}

fn packages() -> BTreeSet<&'static str> {
    WORKSPACE_TEST_ARGUMENTS
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| pair[1])
        .collect()
}

struct Targets {
    tests: BTreeSet<(String, String, Vec<String>)>,
    programs: BTreeSet<(String, String, Vec<String>)>,
    auxiliaries: BTreeSet<(String, String, Vec<String>)>,
    members: BTreeMap<String, (String, PathBuf)>,
}

fn auxiliary_targets(host: &str) -> BTreeSet<(String, String, Vec<String>)> {
    if host != "linux" {
        return BTreeSet::new();
    }
    [
        "day2-sandbox",
        "day2-compiler-sandbox",
        "day2-sandbox-probe",
    ]
    .map(|target| ("day2-sandbox".into(), target.into(), vec!["bin".into()]))
    .into()
}

fn validate_auxiliary_inventory(auxiliaries: &[Binary], host: &str) -> Result<()> {
    let mut observed = BTreeSet::new();
    for binary in auxiliaries {
        ensure!(
            binary.permissions & 0o111 != 0
                && binary.permissions & !0o777 == 0
                && binary.directory == Path::new("crates/day2-sandbox")
                && binary.executable == program_output(&binary.target)
                && binary
                    .digest
                    .strip_prefix("sha256:")
                    .is_some_and(|value| value.len() == 64
                        && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
                && observed.insert((
                    binary.package.clone(),
                    binary.target.clone(),
                    binary.kind.clone()
                )),
            "Linux launcher source, path, digest or target changed"
        );
    }
    ensure!(
        observed == auxiliary_targets(host),
        "all three exact Linux launchers required"
    );
    Ok(())
}

fn build_auxiliaries(
    root: &Path,
    expected: &BTreeSet<(String, String, Vec<String>)>,
    members: &BTreeMap<String, (String, PathBuf)>,
) -> Result<Vec<Binary>> {
    if expected.is_empty() {
        return Ok(Vec::new());
    }
    ensure!(
        std::env::consts::OS == "linux",
        "native Linux launcher preparation required"
    );
    let messages = capture_cargo(
        root,
        "auxiliaries",
        Command::new("cargo").args([
            "build",
            "--locked",
            "-p",
            "day2-sandbox",
            "--bins",
            "--message-format=json-render-diagnostics",
        ]),
        Duration::from_secs(12600),
    )?;
    let mut binaries = Vec::new();
    let mut finished = false;
    for value in messages {
        if value["reason"] == "build-finished" {
            finished = value["success"] == true;
        }
        if value["reason"] != "compiler-artifact" || value["executable"].is_null() {
            continue;
        }
        ensure!(
            value["profile"]["test"] == false,
            "ordinary launcher program required"
        );
        let (package, directory) = members
            .get(
                value["package_id"]
                    .as_str()
                    .context("launcher package ID")?,
            )
            .context("launcher outside declared Cargo graph")?;
        let target = value["target"]["name"]
            .as_str()
            .context("launcher target")?
            .to_owned();
        let executable = Path::new(
            value["executable"]
                .as_str()
                .context("launcher executable")?,
        )
        .strip_prefix(root)?
        .to_owned();
        binaries.push(Binary {
            package: package.clone(),
            target,
            kind: serde_json::from_value(value["target"]["kind"].clone())?,
            directory: directory.clone(),
            digest: digest(&fs::read(root.join(&executable))?),
            permissions: executable_permissions(&root.join(&executable))?,
            executable,
        });
    }
    ensure!(finished, "Linux launcher build incomplete");
    binaries.sort_by(|a, b| a.target.cmp(&b.target));
    validate_auxiliary_inventory(&binaries, "linux")?;
    ensure!(
        binaries
            .iter()
            .map(|b| (b.package.clone(), b.target.clone(), b.kind.clone()))
            .collect::<BTreeSet<_>>()
            == *expected,
        "Linux launcher Cargo inventory changed"
    );
    Ok(binaries)
}

fn install_auxiliaries(root: &Path, auxiliaries: &[Binary]) -> Result<()> {
    validate_auxiliary_inventory(auxiliaries, std::env::consts::OS)?;
    for binary in auxiliaries {
        let source = root.join(&binary.executable);
        let target = root.join("target/debug/deps").join(&binary.target);
        admit_executable(&source, &binary.digest, binary.permissions)?;
        crate::native_toolchain::verify_executable_target(
            crate::native_toolchain::load(root)?.target,
            &source,
        )?;
        crate::install_cli_file(&source, &target)?;
        admit_executable(&target, &binary.digest, binary.permissions)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn prepare_linux_installation(root: &Path) -> Result<()> {
    let targets = compiler_targets(root)?;
    let auxiliaries = build_auxiliaries(root, &targets.auxiliaries, &targets.members)?;
    install_auxiliaries(root, &auxiliaries)
}

fn compiler_targets(root: &Path) -> Result<Targets> {
    let metadata = Command::new("cargo")
        .args(["metadata", "--locked", "--no-deps", "--format-version=1"])
        .current_dir(root)
        .output()?;
    ensure!(metadata.status.success(), "Cargo test target metadata");
    let metadata: serde_json::Value = day2::json::decode(&metadata.stdout)?;
    let mut expected = BTreeSet::new();
    let mut expected_programs = BTreeSet::new();
    let mut auxiliaries = BTreeSet::new();
    let mut members = BTreeMap::new();
    for package in metadata["packages"].as_array().context("Cargo packages")? {
        let name = package["name"].as_str().context("package name")?;
        let auxiliary = std::env::consts::OS == "linux" && name == "day2-sandbox";
        if !packages().contains(name) && !auxiliary {
            continue;
        }
        let directory = Path::new(package["manifest_path"].as_str().context("manifest path")?)
            .parent()
            .context("package directory")?
            .strip_prefix(root)?
            .to_owned();
        members.insert(
            package["id"].as_str().context("package ID")?.to_owned(),
            (name.to_owned(), directory),
        );
        let targets = package["targets"].as_array().context("Cargo targets")?;
        if auxiliary {
            for target in targets {
                let kind: Vec<String> = serde_json::from_value(target["kind"].clone())?;
                if kind == ["bin"] {
                    ensure!(
                        target.get("required-features").is_none(),
                        "unreviewed launcher features"
                    );
                    auxiliaries.insert((
                        name.to_owned(),
                        target["name"]
                            .as_str()
                            .context("launcher target")?
                            .to_owned(),
                        kind,
                    ));
                }
            }
            continue;
        }
        let integration_tests = targets.iter().any(|target| {
            target["kind"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|kind| kind == "test"))
        });
        for target in targets {
            let kind: Vec<String> = serde_json::from_value(target["kind"].clone())?;
            if integration_tests && kind == ["bin"] {
                ensure!(
                    target["test"] == true && target.get("required-features").is_none(),
                    "review feature-gated or harness-disabled supporting program partition"
                );
                expected_programs.insert((
                    name.to_owned(),
                    target["name"]
                        .as_str()
                        .context("program target name")?
                        .to_owned(),
                    kind.clone(),
                ));
            }
            if target["test"] == true && !kind.iter().any(|kind| kind == "bench") {
                ensure!(
                    target.get("required-features").is_none(),
                    "review feature-gated test target partition"
                );
                expected.insert((
                    name.to_owned(),
                    target["name"].as_str().context("target name")?.to_owned(),
                    kind,
                ));
            }
        }
    }
    ensure!(
        members.len() == packages().len() + usize::from(std::env::consts::OS == "linux")
            && auxiliaries == auxiliary_targets(std::env::consts::OS),
        "complete full-gate Cargo package graph required"
    );
    Ok(Targets {
        tests: expected,
        programs: expected_programs,
        auxiliaries,
        members,
    })
}

pub(super) fn build(root: &Path, snapshot: &str) -> Result<()> {
    let Targets {
        tests: expected,
        programs: expected_programs,
        auxiliaries: expected_auxiliaries,
        members,
    } = compiler_targets(root)?;
    let compiler = build_identity(root, snapshot)?;
    let directories = members.values().cloned().collect();
    if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
        let cached = (|| -> Result<BuildCache> {
            let cache: BuildCache = day2::json::decode(&fs::read(root.join(BUILD_CACHE))?)?;
            admit_build_cache(
                root,
                &cache,
                &compiler,
                &expected,
                &expected_programs,
                &expected_auxiliaries,
                &directories,
            )?;
            copy_programs(root, &cache.programs, true)?;
            copy_programs(root, &cache.auxiliaries, true)?;
            install_auxiliaries(root, &cache.auxiliaries)?;
            Ok(cache)
        })();
        match cached {
            Ok(cache) => {
                fs::write(
                    root.join(BINARIES),
                    serde_json::to_vec_pretty(&cache.binaries)?,
                )?;
                println!(
                    "Reusing {} admitted compiled test binaries and {} supporting programs plus {} native Linux launchers; runtime campaigns and doc tests execute fresh",
                    cache.binaries.len(),
                    cache.programs.len(),
                    cache.auxiliaries.len()
                );
                return Ok(());
            }
            Err(error) => eprintln!(
                "Completed test-output cache unavailable or invalid; compiling every default target: {error:#}"
            ),
        }
    }
    // Capture Cargo's authoritative executable inventory, including empty
    // binary harnesses. No package or target selection differs from `verify`.
    let messages = capture_cargo(
        root,
        "tests",
        Command::new("cargo")
            .args([
                "test",
                "--locked",
                "--no-run",
                "--message-format=json-render-diagnostics",
            ])
            .args(WORKSPACE_TEST_ARGUMENTS),
        Duration::from_secs(12600),
    )?;
    let mut binaries = Vec::new();
    let mut programs = Vec::new();
    let mut observed = BTreeSet::new();
    let mut observed_programs = BTreeSet::new();
    let mut finished = false;
    for message in messages {
        if message["reason"] == "build-finished" {
            finished = message["success"] == true;
        }
        if message["reason"] != "compiler-artifact" {
            continue;
        }
        let test = message["profile"]["test"] == true;
        let kind: Vec<String> = serde_json::from_value(message["target"]["kind"].clone())?;
        if !test && (kind != ["bin"] || message["executable"].is_null()) {
            continue;
        }
        let executable = message["executable"]
            .as_str()
            .context("compiler executable required")?;
        let (package, directory) = members
            .get(message["package_id"].as_str().context("artifact package")?)
            .context("test binary outside full-gate package graph")?;
        let target = message["target"]["name"]
            .as_str()
            .context("test target name")?
            .to_owned();
        ensure!(
            (if test {
                &mut observed
            } else {
                &mut observed_programs
            })
            .insert((package.clone(), target.clone(), kind.clone())),
            "duplicate Cargo compiler target"
        );
        let executable = Path::new(executable).strip_prefix(root)?.to_owned();
        ensure!(
            if test {
                executable.parent() == Some(Path::new("target/debug/deps"))
            } else {
                executable == program_output(&target)
            },
            "ordinary full-gate compiler output required"
        );
        (if test { &mut binaries } else { &mut programs }).push(Binary {
            package: package.clone(),
            target,
            kind,
            directory: directory.clone(),
            digest: digest(&fs::read(root.join(&executable))?),
            permissions: executable_permissions(&root.join(&executable))?,
            executable,
        });
    }
    ensure!(
        finished && observed == expected && observed_programs == expected_programs,
        "Cargo compiler inventory does not cover every default target and supporting program"
    );
    binaries.sort_by(|left, right| left.executable.cmp(&right.executable));
    programs.sort_by(|left, right| left.executable.cmp(&right.executable));
    copy_programs(root, &programs, false)?;
    let auxiliaries = build_auxiliaries(root, &expected_auxiliaries, &members)?;
    copy_programs(root, &auxiliaries, false)?;
    install_auxiliaries(root, &auxiliaries)?;
    fs::write(root.join(BINARIES), serde_json::to_vec_pretty(&binaries)?)?;
    let cache = BuildCache {
        identity: compiler,
        binaries: binaries.clone(),
        programs,
        auxiliaries,
    };
    admit_build_cache(
        root,
        &cache,
        &cache.identity,
        &expected,
        &expected_programs,
        &expected_auxiliaries,
        &directories,
    )?;
    fs::write(root.join(BUILD_CACHE), serde_json::to_vec_pretty(&cache)?)?;
    println!(
        "Prepared {} test binaries and {} supporting programs from all {} full-gate packages",
        binaries.len(),
        cache.programs.len(),
        packages().len()
    );
    Ok(())
}

fn preparation_steps() -> Result<BTreeSet<String>> {
    let mut steps: BTreeSet<String> = required_steps("all")?
        .iter()
        .filter(|step| !step.starts_with("test-") && **step != "control-simulation")
        .map(|step| (*step).into())
        .collect();
    steps.extend(["test-binaries".into(), "test-docs".into()]);
    Ok(steps)
}

fn part_steps(part: &str) -> Result<BTreeSet<String>> {
    ensure!(
        ["all", "inputs", "tests"].contains(&part),
        "unknown preparation part"
    );
    Ok(preparation_steps()?
        .into_iter()
        .filter(|step| match part {
            "inputs" => !step.starts_with("test-"),
            "tests" => step.starts_with("test-"),
            _ => true,
        })
        .collect())
}

fn preparation_path(part: &str) -> Result<&'static str> {
    match part {
        "all" => Ok(PREPARED),
        "inputs" => Ok("artifacts/ci-preparation-inputs.json"),
        "tests" => Ok("artifacts/ci-preparation-tests.json"),
        _ => anyhow::bail!("unknown preparation part"),
    }
}

pub(super) fn save(
    root: &Path,
    snapshot: &str,
    fixtures: &BTreeMap<String, PathBuf>,
    passed: &BTreeSet<String>,
    timings: &BTreeMap<String, u64>,
    part: &str,
) -> Result<()> {
    ensure!(
        *passed == part_steps(part)?,
        "incomplete hosted verification preparation"
    );
    let binaries: Vec<Binary> = if part == "inputs" {
        Vec::new()
    } else {
        day2::json::decode(&fs::read(root.join(BINARIES))?)?
    };
    let programs = if part == "inputs" {
        Vec::new()
    } else {
        let cache: BuildCache = day2::json::decode(&fs::read(root.join(BUILD_CACHE))?)?;
        ensure!(
            cache.binaries == binaries,
            "current compiler and preparation inventories differ"
        );
        cache.programs
    };
    let auxiliaries = if part == "inputs" {
        Vec::new()
    } else {
        let cache: BuildCache = day2::json::decode(&fs::read(root.join(BUILD_CACHE))?)?;
        cache.auxiliaries
    };
    let fixtures = fixtures
        .iter()
        .map(|(name, path)| {
            Ok((
                name.clone(),
                day2::artifact::LoadedArtifact::load(path)?.id().to_owned(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let prepared = Prepared {
        identity: identity(root, snapshot)?,
        binaries,
        programs,
        auxiliaries,
        fixtures,
        passed: passed.clone(),
        timings_ms: timings.clone(),
    };
    validate_preparation(&prepared, part)?;
    fs::write(
        root.join(preparation_path(part)?),
        serde_json::to_vec_pretty(&prepared)?,
    )?;
    Ok(())
}

fn validate_preparation(prepared: &Prepared, part: &str) -> Result<()> {
    ensure!(
        prepared.passed == part_steps(part)?
            && prepared.timings_ms.keys().cloned().collect::<BTreeSet<_>>() == prepared.passed,
        "complete preparation effects and timings required"
    );
    ensure!(
        prepared
            .fixtures
            .keys()
            .map(|fixture| format!("build-{fixture}"))
            .collect::<BTreeSet<_>>()
            == prepared
                .passed
                .iter()
                .filter(|step| step.starts_with("build-"))
                .cloned()
                .collect(),
        "exact full-gate fixture set required"
    );
    ensure!(
        prepared
            .binaries
            .iter()
            .map(|binary| binary.package.as_str())
            .collect::<BTreeSet<_>>()
            == if part == "inputs" {
                BTreeSet::new()
            } else {
                packages()
            },
        "all full-gate test packages required"
    );
    let unique: BTreeSet<_> = prepared
        .binaries
        .iter()
        .map(|binary| &binary.executable)
        .collect();
    ensure!(
        unique.len() == prepared.binaries.len(),
        "duplicate prepared executable"
    );
    for binary in &prepared.binaries {
        ensure!(
            binary.permissions & 0o111 != 0
                && binary.permissions & !0o777 == 0
                && binary.executable.starts_with("target/debug/deps")
                && !binary
                    .executable
                    .components()
                    .chain(binary.directory.components())
                    .any(|part| !matches!(part, std::path::Component::Normal(_))),
            "prepared test paths must stay within the workspace"
        );
    }
    let integration_packages: BTreeSet<_> = prepared
        .binaries
        .iter()
        .filter(|binary| binary.kind == ["test"])
        .map(|binary| &binary.package)
        .collect();
    let expected_programs: BTreeSet<_> = prepared
        .binaries
        .iter()
        .filter(|binary| binary.kind == ["bin"] && integration_packages.contains(&binary.package))
        .map(|binary| (&binary.package, &binary.target, &binary.directory))
        .collect();
    let programs: BTreeSet<_> = prepared
        .programs
        .iter()
        .map(|binary| (&binary.package, &binary.target, &binary.directory))
        .collect();
    ensure!(
        programs == expected_programs && programs.len() == prepared.programs.len(),
        "prepared supporting program inventory incomplete or duplicated"
    );
    for program in &prepared.programs {
        ensure!(
            program.permissions & 0o111 != 0
                && program.permissions & !0o777 == 0
                && program.kind == ["bin"]
                && program.executable == program_output(&program.target)
                && program.executable.parent() == Some(Path::new("target/debug"))
                && program
                    .executable
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_))),
            "prepared ordinary program path required"
        );
    }
    validate_auxiliary_inventory(
        &prepared.auxiliaries,
        if part == "inputs" {
            "none"
        } else {
            &prepared.identity.host
        },
    )?;
    Ok(())
}

fn combine_parts(mut inputs: Prepared, tests: Prepared, expected: &Identity) -> Result<Prepared> {
    ensure!(
        inputs.identity == *expected && tests.identity == *expected,
        "preparation parts belong to another checkout, run, attempt or host"
    );
    validate_preparation(&inputs, "inputs")?;
    validate_preparation(&tests, "tests")?;
    ensure!(
        inputs.passed.is_disjoint(&tests.passed),
        "preparation effects must be disjoint"
    );
    inputs.binaries = tests.binaries;
    inputs.programs = tests.programs;
    inputs.auxiliaries = tests.auxiliaries;
    inputs.passed.extend(tests.passed);
    inputs.timings_ms.extend(tests.timings_ms);
    validate_preparation(&inputs, "all")?;
    Ok(inputs)
}

pub(super) fn combine(root: &Path, snapshot: &str) -> Result<()> {
    let inputs: Prepared = day2::json::decode(&fs::read(
        root.join("artifacts/ci-preparation-inputs.json"),
    )?)?;
    let tests: Prepared =
        day2::json::decode(&fs::read(root.join("artifacts/ci-preparation-tests.json"))?)?;
    let prepared = combine_parts(inputs, tests, &identity(root, snapshot)?)?;
    fs::write(root.join(PREPARED), serde_json::to_vec_pretty(&prepared)?)?;
    // Admit all transported executable bytes and every native fixture before
    // the workflow can publish the complete workspace to runtime campaigns.
    let prepared = load(root, snapshot)?;
    fixtures(root, &prepared)?;
    println!("Joined both preparation parts with all fixtures and test executables");
    Ok(())
}

pub(super) fn load(root: &Path, snapshot: &str) -> Result<Prepared> {
    let prepared: Prepared = day2::json::decode(&fs::read(root.join(PREPARED))?)?;
    ensure!(
        prepared.identity == identity(root, snapshot)?,
        "prepared verification belongs to another checkout, run, attempt or host"
    );
    validate_preparation(&prepared, "all")?;
    for binary in prepared.binaries.iter().chain(&prepared.programs) {
        admit_executable(
            &root.join(&binary.executable),
            &binary.digest,
            binary.permissions,
        )?;
    }
    for auxiliary in &prepared.auxiliaries {
        admit_executable(
            &root.join(&auxiliary.executable),
            &auxiliary.digest,
            auxiliary.permissions,
        )?;
        admit_executable(
            &root.join("target/debug/deps").join(&auxiliary.target),
            &auxiliary.digest,
            auxiliary.permissions,
        )?;
        crate::native_toolchain::verify_executable_target(
            crate::native_toolchain::load(root)?.target,
            &root.join(&auxiliary.executable),
        )?;
    }
    Ok(prepared)
}

pub(super) fn fixtures(root: &Path, prepared: &Prepared) -> Result<BTreeMap<String, PathBuf>> {
    prepared
        .fixtures
        .iter()
        .map(|(fixture, artifact)| {
            Ok((
                fixture.clone(),
                cached_fixture(root, artifact)?.context("prepared verified fixture missing")?,
            ))
        })
        .collect()
}

fn selected(package: &str, shard: &str) -> bool {
    match shard {
        "workspace-day2" => package == "day2",
        "workspace-control" => package == "day2-control",
        "workspace-other" => package != "day2" && package != "day2-control",
        "parallel-runtime" | "isolated-build" | "installation-build" => true,
        _ => false,
    }
}

fn expected_binaries(prepared: &Prepared, shard: &str) -> BTreeSet<PathBuf> {
    prepared
        .binaries
        .iter()
        .filter(|binary| selected(&binary.package, shard))
        .map(|binary| binary.executable.clone())
        .collect()
}

pub(super) fn tests(
    root: &Path,
    prepared: &Prepared,
    shard: &str,
    fixtures: &BTreeMap<String, PathBuf>,
    budget: Duration,
) -> Result<BTreeSet<PathBuf>> {
    ensure!(valid(shard) && shard != "simulation", "test shard required");
    let suite = if shard.starts_with("workspace-") {
        "workspace-runtime"
    } else {
        shard
    };
    let cargo = test_command(suite)?;
    let arguments: Vec<_> = cargo
        .get_args()
        .skip_while(|arg| *arg != "--")
        .skip(1)
        .collect();
    let started = Instant::now();
    let mut executed = BTreeSet::new();
    for binary in prepared
        .binaries
        .iter()
        .filter(|binary| selected(&binary.package, shard))
    {
        let mut command = Command::new(root.join(&binary.executable));
        command.args(&arguments);
        configure_tests(root, suite, fixtures, &mut command)?;
        // Cargo's package cwd is part of the harness contract. Compile-time
        // CARGO_MANIFEST_DIR / CARGO_BIN_EXE paths are admitted by workspace identity.
        let remaining = budget
            .checked_sub(started.elapsed())
            .context("test campaign budget exhausted")?;
        println!(
            "Prepared test {} / {} ({shard})",
            binary.package, binary.target
        );
        run_with_budget(&root.join(&binary.directory), &mut command, remaining)?;
        ensure!(
            executed.insert(binary.executable.clone()),
            "duplicate test executable invocation"
        );
    }
    ensure!(
        executed == expected_binaries(prepared, shard),
        "test executable campaign incomplete"
    );
    Ok(executed)
}

fn effects(shard: &str) -> BTreeSet<String> {
    [if shard == "simulation" {
        "control-simulation".into()
    } else {
        format!("test-{shard}")
    }]
    .into()
}

pub(super) fn receipt(
    root: &Path,
    prepared: &Prepared,
    shard: &str,
    passed: &BTreeSet<String>,
    timings: &BTreeMap<String, u64>,
    executed: &BTreeSet<PathBuf>,
) -> Result<()> {
    ensure!(
        valid(shard)
            && *passed == effects(shard)
            && timings.keys().cloned().collect::<BTreeSet<_>>() == *passed
            && *executed == expected_binaries(prepared, shard),
        "incomplete verification shard"
    );
    let receipt = Receipt {
        prepared_digest: digest(&serde_json::to_vec(prepared)?),
        shard: shard.into(),
        passed: passed.clone(),
        timings_ms: timings.clone(),
        binaries: executed.clone(),
    };
    fs::create_dir_all(root.join(RESULTS))?;
    fs::write(
        root.join(RESULTS).join(format!("{shard}.json")),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    Ok(())
}

fn validate_receipt(prepared: &Prepared, receipt: &Receipt, shard: &str) -> Result<()> {
    ensure!(
        valid(shard)
            && receipt.shard == shard
            && receipt.prepared_digest == digest(&serde_json::to_vec(prepared)?)
            && receipt.passed == effects(shard)
            && receipt.timings_ms.keys().cloned().collect::<BTreeSet<_>>() == receipt.passed
            && receipt.binaries == expected_binaries(prepared, shard),
        "missing, foreign or incomplete verification shard"
    );
    Ok(())
}

fn admit_join(
    prepared: &Prepared,
    receipts: &[Receipt],
    mac: Option<&mac::Proof>,
) -> Result<BTreeMap<String, u64>> {
    ensure!(
        prepared.identity.host != "linux" || mac.is_some(),
        "Linux full verification requires real Mac domain"
    );
    let selected: Vec<_> = SHARDS
        .iter()
        .copied()
        .filter(|shard| mac.is_none() || !["isolated-build", "installation-build"].contains(shard))
        .collect();
    ensure!(
        receipts.len() == selected.len(),
        "exact complete native shard receipt set required"
    );
    let mut timings = prepared.timings_ms.clone();
    for shard in &selected {
        let matching: Vec<_> = receipts
            .iter()
            .filter(|receipt| receipt.shard == *shard)
            .collect();
        ensure!(
            matching.len() == 1,
            "exactly one receipt per shard required"
        );
        let receipt = matching[0];
        validate_receipt(prepared, receipt, shard)?;
        for (step, elapsed) in &receipt.timings_ms {
            ensure!(
                timings.insert(step.clone(), *elapsed).is_none(),
                "duplicate verification effect"
            );
        }
    }
    if let Some(proof) = mac {
        for receipt in mac::campaigns(proof) {
            for (step, elapsed) in &receipt.timings_ms {
                ensure!(
                    timings.insert(step.clone(), *elapsed).is_none(),
                    "duplicate native campaign effect"
                );
            }
        }
    }
    let mut workspace = 0u64;
    for step in [
        "test-binaries",
        "test-docs",
        "test-workspace-day2",
        "test-workspace-control",
        "test-workspace-other",
    ] {
        workspace = workspace
            .checked_add(
                timings
                    .remove(step)
                    .context("workspace verification partition missing")?,
            )
            .context("workspace timing overflow")?;
    }
    ensure!(
        workspace <= 12_600_000,
        "aggregate workspace campaign exceeded its original budget"
    );
    timings.insert("test-workspace-runtime".into(), workspace);
    let passed: BTreeSet<_> = timings.keys().cloned().collect();
    ensure!(
        passed
            == required_steps("all")?
                .iter()
                .map(|step| (*step).into())
                .collect(),
        "joined receipt must cover exactly the ordinary full recipe"
    );
    Ok(timings)
}

pub(super) fn join(
    root: &Path,
    prepared: &Prepared,
) -> Result<(BTreeSet<String>, BTreeMap<String, u64>)> {
    ensure!(
        prepared.identity.host == "linux" && prepared.identity.architecture == "x86_64",
        "hosted full composition requires Linux portable domain"
    );
    let mac_path = root.join(mac::PATH);
    ensure!(
        mac_path.canonicalize()? == mac_path
            && fs::symlink_metadata(&mac_path)?.is_file()
            && fs::metadata(&mac_path)?.len() <= 1024 * 1024,
        "bounded regular native Mac proof required"
    );
    let mac: mac::Proof = day2::json::decode(&fs::read(&mac_path)?)?;
    mac::admit(
        &mac,
        &prepared.identity,
        &super::verification_snapshot_for(root, "verify", "macos", "aarch64")?,
        &build_identity(root, &prepared.identity.snapshot)?,
        &compiler_targets(root)?,
    )?;
    let portable: Vec<_> = SHARDS
        .iter()
        .filter(|shard| !["isolated-build", "installation-build"].contains(shard))
        .collect();
    let files = fs::read_dir(root.join(RESULTS))?.collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        files.len() == portable.len(),
        "exact five portable receipts required"
    );
    let mut receipts = Vec::new();
    for shard in portable {
        receipts.push(day2::json::decode(&fs::read(
            root.join(RESULTS).join(format!("{shard}.json")),
        )?)?);
    }
    let timings = admit_join(prepared, &receipts, Some(&mac))?;
    let passed: BTreeSet<_> = timings.keys().cloned().collect();
    fs::write(
        root.join("artifacts/ci-verification.json"),
        serde_json::to_vec_pretty(&json!({
            "identity":prepared.identity,"prepared_digest":digest(&serde_json::to_vec(prepared)?),
            "shards":receipts,"mac":mac,"effects":passed,"timings_ms":timings,
            "timing_scope":"sum of admitted campaign work; use hosted job timestamps for critical-path duration"
        }))?,
    )?;
    println!(
        "Joined all {} verification steps and {} verified fixtures",
        passed.len(),
        prepared.fixtures.len()
    );
    for (step, elapsed) in &timings {
        println!("Verification step {step}: {:.3}s", *elapsed as f64 / 1000.0);
    }
    Ok((passed, timings))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cargo_capture_root() -> Result<tempfile::TempDir> {
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join("artifacts"))?;
        Ok(root)
    }

    fn cargo_failure_manifest(root: &Path) -> Result<(PathBuf, serde_json::Value)> {
        let entries = fs::read_dir(root.join("artifacts"))?.collect::<std::io::Result<Vec<_>>>()?;
        let directories: Vec<_> = entries
            .into_iter()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("ci-compiler-failure-")
            })
            .collect();
        ensure!(directories.len() == 1, "one current failure spool required");
        let directory = directories[0].path();
        let manifest = day2::json::decode(&fs::read(directory.join("manifest.json"))?)?;
        Ok((directory, manifest))
    }

    fn cargo_control_command(mode: &str) -> Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "verification::shards::tests::cargo_failure_child",
                "--nocapture",
            ])
            .env("DAY2_CARGO_CAPTURE_CONTROL", mode);
        Ok(command)
    }

    // Subprocess helper, not an independent semantic control. The real child
    // exercises the same spawn/timeout/wait and stdout path as Cargo.
    #[test]
    fn cargo_failure_child() {
        let Ok(mode) = std::env::var("DAY2_CARGO_CAPTURE_CONTROL") else {
            return;
        };
        println!("PRIVATE-CARGO-CONTROL-INVALID-OUTPUT");
        if mode == "timeout" {
            std::thread::sleep(Duration::from_secs(10));
        }
        std::process::exit(if mode == "success" { 0 } else { 2 });
    }

    #[test]
    fn cargo_nonzero_remains_primary_when_real_child_stdout_is_malformed() -> Result<()> {
        let root = cargo_capture_root()?;
        let error = capture_cargo(
            root.path(),
            "tests",
            &mut cargo_control_command("failure")?,
            Duration::from_secs(3),
        )
        .unwrap_err();
        let failure = error
            .downcast_ref::<CargoReportingFailure>()
            .context("typed Cargo outcome")?;
        assert_eq!(failure.process.category, "exit");
        assert_eq!(failure.process.code, Some(2));
        assert_eq!(failure.capture.as_ref().map(|p| p.category), Some("json"));
        assert!(failure.retained);
        assert!(!error.to_string().contains("PRIVATE-CARGO"));
        let (directory, manifest) = cargo_failure_manifest(root.path())?;
        let raw = fs::read(directory.join("stdout.bin"))?;
        assert!(String::from_utf8_lossy(&raw).contains("PRIVATE-CARGO-CONTROL-INVALID-OUTPUT"));
        assert_eq!(manifest["cargo_process"]["code"], 2);
        assert_eq!(manifest["complete"], true);
        assert_eq!(manifest["identity_status"], "unavailable");
        assert!(manifest["identity"].is_null());
        assert_eq!(
            manifest["diagnostic_only_not_a_preparation_or_runtime_receipt"],
            true
        );
        assert!(!manifest.to_string().contains("PRIVATE-CARGO"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(directory.join("stdout.bin"))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(fs::metadata(directory)?.permissions().mode() & 0o777, 0o700);
        }
        assert!(!root.path().join(PREPARED).exists());
        assert!(!root.path().join(BINARIES).exists());
        Ok(())
    }

    #[test]
    fn cargo_success_with_real_malformed_output_cannot_be_admitted() -> Result<()> {
        let root = cargo_capture_root()?;
        let error = capture_cargo(
            root.path(),
            "auxiliaries",
            &mut cargo_control_command("success")?,
            Duration::from_secs(3),
        )
        .unwrap_err();
        let failure = error
            .downcast_ref::<CargoReportingFailure>()
            .context("typed Cargo outcome")?;
        assert_eq!(failure.process.category, "success");
        assert_eq!(failure.process.code, Some(0));
        assert_eq!(failure.capture.as_ref().map(|p| p.category), Some("json"));
        assert!(error.to_string().contains("primary=capture"));
        assert!(!root.path().join(PREPARED).exists());
        Ok(())
    }

    #[test]
    fn cargo_timeout_remains_primary_without_fabricating_an_original_signal() -> Result<()> {
        let root = cargo_capture_root()?;
        let started = Instant::now();
        let error = capture_cargo(
            root.path(),
            "tests",
            &mut cargo_control_command("timeout")?,
            Duration::from_millis(100),
        )
        .unwrap_err();
        let failure = error
            .downcast_ref::<CargoReportingFailure>()
            .context("typed Cargo outcome")?;
        assert_eq!(failure.process.category, "timeout");
        assert_eq!(failure.process.code, None);
        assert_eq!(failure.process.signal, None);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!error.to_string().contains("PRIVATE-CARGO"));
        Ok(())
    }

    #[test]
    fn cargo_spawn_refusal_keeps_errno_without_exporting_the_command_path() -> Result<()> {
        let root = cargo_capture_root()?;
        let mut command = Command::new(root.path().join("PRIVATE-CARGO-NONEXISTENT-COMMAND"));
        let error =
            capture_cargo(root.path(), "tests", &mut command, Duration::from_secs(1)).unwrap_err();
        let failure = error
            .downcast_ref::<CargoReportingFailure>()
            .context("typed Cargo outcome")?;
        assert_eq!(failure.process.category, "spawn");
        assert!(failure.process.os_error.is_some());
        assert_eq!(failure.process.code, None);
        assert!(!error.to_string().contains("PRIVATE-CARGO"));
        Ok(())
    }

    fn failed_cargo_outcome() -> CargoProcessOutcome {
        CargoProcessOutcome {
            category: "exit",
            code: Some(2),
            signal: None,
            os_error: None,
        }
    }

    #[test]
    fn cargo_later_valid_diagnostics_survive_an_earlier_malformed_record() -> Result<()> {
        let root = cargo_capture_root()?;
        let mut output = b"PRIVATE-CARGO-INVALID\n".to_vec();
        output.extend(serde_json::to_vec(&json!({
            "reason":"compiler-message",
            "message":{"code":{"code":"E0308"},"rendered":"PRIVATE-CARGO-RENDERED"}
        }))?);
        let error = report_cargo_capture(root.path(), "tests", failed_cargo_outcome(), Ok(output))
            .unwrap_err();
        let failure = error
            .downcast_ref::<CargoReportingFailure>()
            .context("typed Cargo outcome")?;
        assert_eq!(failure.process.code, Some(2));
        assert_eq!(failure.capture.as_ref().and_then(|p| p.line), Some(1));
        let (_, manifest) = cargo_failure_manifest(root.path())?;
        assert_eq!(manifest["rust_diagnostic_codes"], json!(["E0308"]));
        assert!(!manifest.to_string().contains("PRIVATE-CARGO"));
        Ok(())
    }

    #[test]
    fn cargo_valid_output_does_not_turn_a_failed_compile_into_success() -> Result<()> {
        let root = cargo_capture_root()?;
        let output = serde_json::to_vec(&json!({"reason":"build-finished","success":false}))?;
        let error = report_cargo_capture(
            root.path(),
            "auxiliaries",
            failed_cargo_outcome(),
            Ok(output),
        )
        .unwrap_err();
        let failure = error
            .downcast_ref::<CargoReportingFailure>()
            .context("typed Cargo outcome")?;
        assert_eq!(failure.process.code, Some(2));
        assert!(failure.capture.is_none());
        assert!(failure.retained);
        Ok(())
    }

    #[test]
    fn cargo_evidence_write_and_capture_read_failures_stay_secondary() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::write(root.path().join("artifacts"), b"not a directory")?;
        for (output, category) in [
            (Err(std::io::Error::from_raw_os_error(5)), "read"),
            (Ok(b"PRIVATE-CARGO-INVALID".to_vec()), "json"),
        ] {
            let error = report_cargo_capture(root.path(), "tests", failed_cargo_outcome(), output)
                .unwrap_err();
            let failure = error
                .downcast_ref::<CargoReportingFailure>()
                .context("typed Cargo outcome")?;
            assert_eq!(failure.process.code, Some(2));
            assert_eq!(failure.capture.as_ref().map(|p| p.category), Some(category));
            assert!(!failure.retained);
            assert!(error.to_string().contains("primary=exit"));
            assert!(!error.to_string().contains("PRIVATE-CARGO"));
        }
        Ok(())
    }

    #[test]
    fn cargo_failure_spool_is_bounded_and_explicitly_incomplete() -> Result<()> {
        let root = cargo_capture_root()?;
        let output = vec![b'x'; CARGO_FAILURE_CAPTURE_BYTES + 1];
        let error = report_cargo_capture(root.path(), "tests", failed_cargo_outcome(), Ok(output))
            .unwrap_err();
        assert!(
            error
                .downcast_ref::<CargoReportingFailure>()
                .context("typed Cargo outcome")?
                .retained
        );
        let (directory, manifest) = cargo_failure_manifest(root.path())?;
        assert_eq!(manifest["capture_bytes"], CARGO_FAILURE_CAPTURE_BYTES + 1);
        assert_eq!(manifest["retained_bytes"], CARGO_FAILURE_CAPTURE_BYTES);
        assert_eq!(manifest["complete"], false);
        assert_eq!(
            fs::metadata(directory.join("stdout.bin"))?.len(),
            CARGO_FAILURE_CAPTURE_BYTES as u64
        );
        Ok(())
    }

    #[test]
    fn cargo_success_keeps_valid_messages_without_a_failure_spool() -> Result<()> {
        let root = cargo_capture_root()?;
        let message = json!({"reason":"build-finished","success":true});
        let outcome = CargoProcessOutcome {
            category: "success",
            code: Some(0),
            signal: None,
            os_error: None,
        };
        let messages = report_cargo_capture(
            root.path(),
            "tests",
            outcome,
            Ok(serde_json::to_vec(&message)?),
        )?;
        assert_eq!(messages, vec![message]);
        assert_eq!(fs::read_dir(root.path().join("artifacts"))?.count(), 0);
        // Hosted controls also exercise the genuine source/run/snapshot path.
        // Local unit runs without hosted run identity do not fabricate one.
        if let (Ok(run), Ok(attempt)) = (
            std::env::var("GITHUB_RUN_ID"),
            std::env::var("GITHUB_RUN_ATTEMPT"),
        ) {
            let source_root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .context("crates directory")?
                .parent()
                .context("workspace directory")?;
            let binding = cargo_failure_identity(source_root)?;
            assert_eq!(binding.run, run);
            assert_eq!(binding.attempt, attempt);
            assert_eq!(
                binding.snapshot,
                super::super::verification_snapshot(source_root, "verify")?
            );
            assert_eq!(
                binding.source_identity,
                super::super::verification_source_identity(source_root, "verify")?
            );
            assert_eq!(binding.workspace, source_root.canonicalize()?);
            assert_eq!(binding.workflow, day2::automation::source_digest());
            assert_eq!(binding.checkout.len(), 40);
            assert_eq!(binding.tree.len(), 40);
        }
        Ok(())
    }

    pub(super) fn sample_identity() -> Identity {
        Identity {
            checkout: "a".repeat(40),
            tree: "tree".into(),
            source_identity: "source-identity".into(),
            workspace: "/workspace/platform".into(),
            run: "123".into(),
            attempt: "1".into(),
            host: "macos".into(),
            architecture: "aarch64".into(),
            workflow: "workflow".into(),
            snapshot: "snapshot".into(),
        }
    }

    pub(super) fn sample_part(part: &str) -> Result<Prepared> {
        let passed = part_steps(part)?;
        Ok(Prepared {
            identity: sample_identity(),
            binaries: if part == "tests" {
                packages()
                    .into_iter()
                    .map(|package| Binary {
                        package: package.into(),
                        target: package.into(),
                        kind: vec!["lib".into()],
                        directory: format!("crates/{package}").into(),
                        executable: format!("target/debug/deps/{package}-test").into(),
                        digest: "binary".into(),
                        permissions: 0o755,
                    })
                    .collect()
            } else {
                Vec::new()
            },
            programs: Vec::new(),
            auxiliaries: Vec::new(),
            fixtures: passed
                .iter()
                .filter_map(|step| step.strip_prefix("build-"))
                .map(|fixture| (fixture.into(), "artifact".into()))
                .collect(),
            timings_ms: passed.iter().map(|step| (step.clone(), 100)).collect(),
            passed,
        })
    }

    #[test]
    fn preparation_join_rejects_foreign_identity_and_incomplete_or_swapped_parts() -> Result<()> {
        let complete = combine_parts(
            sample_part("inputs")?,
            sample_part("tests")?,
            &sample_identity(),
        )?;
        assert_eq!(complete.passed, preparation_steps()?);
        assert_eq!(complete.fixtures.len(), 23);
        for fixture in ["lifecycle", "verification-actors", "chart-live"] {
            assert!(complete.fixtures.contains_key(fixture));
            let mut incomplete = sample_part("inputs")?;
            incomplete.fixtures.remove(fixture);
            assert!(combine_parts(incomplete, sample_part("tests")?, &sample_identity()).is_err());
        }
        for field in [
            "checkout",
            "tree",
            "source_identity",
            "workspace",
            "run",
            "attempt",
            "host",
            "architecture",
            "workflow",
            "snapshot",
        ] {
            for part in ["inputs", "tests"] {
                let mut value = serde_json::to_value(sample_part(part)?)?;
                value["identity"][field] = json!("foreign");
                let invalid = serde_json::from_value(value)?;
                let (inputs, tests) = if part == "inputs" {
                    (invalid, sample_part("tests")?)
                } else {
                    (sample_part("inputs")?, invalid)
                };
                assert!(combine_parts(inputs, tests, &sample_identity()).is_err());
            }
        }
        for (part, field) in [
            ("inputs", "fixtures"),
            ("inputs", "passed"),
            ("tests", "binaries"),
            ("tests", "timings_ms"),
        ] {
            let mut value = serde_json::to_value(sample_part(part)?)?;
            value[field] = if ["fixtures", "timings_ms"].contains(&field) {
                json!({})
            } else {
                json!([])
            };
            let invalid = serde_json::from_value(value)?;
            let (inputs, tests) = if part == "inputs" {
                (invalid, sample_part("tests")?)
            } else {
                (sample_part("inputs")?, invalid)
            };
            assert!(combine_parts(inputs, tests, &sample_identity()).is_err());
        }
        assert!(
            combine_parts(
                sample_part("tests")?,
                sample_part("inputs")?,
                &sample_identity()
            )
            .is_err()
        );
        assert!(part_steps("unknown").is_err());
        Ok(())
    }

    #[test]
    fn completed_test_cache_rejects_changed_inputs_targets_paths_and_bytes() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        fs::create_dir_all(root.join("target/debug/deps"))?;
        let executable = PathBuf::from("target/debug/deps/example-test");
        fs::write(root.join(&executable), b"compiled output")?;
        let identity = BuildIdentity {
            snapshot: "snapshot".into(),
            workflow: "workflow".into(),
            workspace: root.clone(),
            host: "macos".into(),
            architecture: "aarch64".into(),
            rustc: "rustc pinned".into(),
            cargo: "cargo pinned".into(),
            cc: "cc pinned".into(),
            environment: "environment".into(),
            cargo_configuration: BTreeMap::from([(".cargo/config.toml".into(), None)]),
            ci_workflow: "ci-workflow".into(),
        };
        let binary = Binary {
            package: "example".into(),
            target: "example-test".into(),
            kind: vec!["test".into()],
            directory: "crates/example".into(),
            executable: executable.clone(),
            digest: digest(b"compiled output"),
            permissions: 0o755,
        };
        let expected =
            BTreeSet::from([("example".into(), "example-test".into(), vec!["test".into()])]);
        let directories = BTreeMap::from([("example".into(), PathBuf::from("crates/example"))]);
        fs::create_dir_all(root.join(PROGRAM_CACHE))?;
        fs::write(
            root.join(PROGRAM_CACHE).join("example"),
            b"supporting program",
        )?;
        let program = Binary {
            package: "example".into(),
            target: "example".into(),
            kind: vec!["bin".into()],
            directory: "crates/example".into(),
            executable: program_output("example"),
            digest: digest(b"supporting program"),
            permissions: 0o755,
        };
        let expected_programs =
            BTreeSet::from([("example".into(), "example".into(), vec!["bin".into()])]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join(&executable), fs::Permissions::from_mode(0o755))?;
            fs::set_permissions(
                root.join(PROGRAM_CACHE).join("example"),
                fs::Permissions::from_mode(0o755),
            )?;
        }
        let cache = BuildCache {
            identity,
            binaries: vec![binary],
            programs: vec![program],
            auxiliaries: Vec::new(),
        };
        admit_build_cache(
            &root,
            &cache,
            &cache.identity,
            &expected,
            &expected_programs,
            &BTreeSet::new(),
            &directories,
        )?;
        assert!(!root.join(program_output("example")).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                root.join(PROGRAM_CACHE).join("example"),
                fs::Permissions::from_mode(0o755),
            )?;
        }
        copy_programs(&root, &cache.programs, true)?;
        assert_eq!(
            fs::read(root.join(program_output("example")))?,
            b"supporting program"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_ne!(
                fs::metadata(root.join(program_output("example")))?
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
        }
        for field in [
            "package",
            "target",
            "kind",
            "directory",
            "executable",
            "digest",
        ] {
            let mut value = serde_json::to_value(&cache)?;
            value["programs"][0][field] = if field == "kind" {
                json!(["test"])
            } else {
                json!("foreign")
            };
            let invalid = serde_json::from_value(value)?;
            assert!(
                admit_build_cache(
                    &root,
                    &invalid,
                    &cache.identity,
                    &expected,
                    &expected_programs,
                    &BTreeSet::new(),
                    &directories
                )
                .is_err()
            );
        }
        for programs in [json!([]), json!([&cache.programs[0], &cache.programs[0]])] {
            let mut value = serde_json::to_value(&cache)?;
            value["programs"] = programs;
            let invalid = serde_json::from_value(value)?;
            assert!(
                admit_build_cache(
                    &root,
                    &invalid,
                    &cache.identity,
                    &expected,
                    &expected_programs,
                    &BTreeSet::new(),
                    &directories
                )
                .is_err()
            );
        }
        let cached_program = root.join(PROGRAM_CACHE).join("example");
        fs::write(&cached_program, b"tampered program")?;
        assert!(
            admit_build_cache(
                &root,
                &cache,
                &cache.identity,
                &expected,
                &expected_programs,
                &BTreeSet::new(),
                &directories
            )
            .is_err()
        );
        fs::remove_file(&cached_program)?;
        assert!(
            admit_build_cache(
                &root,
                &cache,
                &cache.identity,
                &expected,
                &expected_programs,
                &BTreeSet::new(),
                &directories
            )
            .is_err()
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join(program_output("example")), &cached_program)?;
            assert!(
                admit_build_cache(
                    &root,
                    &cache,
                    &cache.identity,
                    &expected,
                    &expected_programs,
                    &BTreeSet::new(),
                    &directories
                )
                .is_err()
            );
            fs::remove_file(&cached_program)?;
        }
        fs::write(&cached_program, b"supporting program")?;
        for field in [
            "snapshot",
            "workflow",
            "workspace",
            "host",
            "architecture",
            "rustc",
            "cargo",
            "cc",
            "environment",
            "ci_workflow",
        ] {
            let mut value = serde_json::to_value(&cache)?;
            value["identity"][field] = json!("foreign");
            let invalid = serde_json::from_value(value)?;
            assert!(
                admit_build_cache(
                    &root,
                    &invalid,
                    &cache.identity,
                    &expected,
                    &expected_programs,
                    &BTreeSet::new(),
                    &directories
                )
                .is_err()
            );
        }
        let mut value = serde_json::to_value(&cache)?;
        value["identity"]["cargo_configuration"] = json!({".cargo/config.toml": "changed"});
        let invalid = serde_json::from_value(value)?;
        assert!(
            admit_build_cache(
                &root,
                &invalid,
                &cache.identity,
                &expected,
                &expected_programs,
                &BTreeSet::new(),
                &directories
            )
            .is_err()
        );
        for (field, value) in [
            ("package", "foreign"),
            ("target", "foreign"),
            ("directory", "crates/foreign"),
            ("executable", "../outside"),
            ("digest", "changed"),
        ] {
            let mut invalid = serde_json::to_value(&cache)?;
            invalid["binaries"][0][field] = json!(value);
            let invalid = serde_json::from_value(invalid)?;
            assert!(
                admit_build_cache(
                    &root,
                    &invalid,
                    &cache.identity,
                    &expected,
                    &expected_programs,
                    &BTreeSet::new(),
                    &directories
                )
                .is_err()
            );
        }
        for binaries in [json!([]), json!([&cache.binaries[0], &cache.binaries[0]])] {
            let mut value = serde_json::to_value(&cache)?;
            value["binaries"] = binaries;
            let invalid = serde_json::from_value(value)?;
            assert!(
                admit_build_cache(
                    &root,
                    &invalid,
                    &cache.identity,
                    &expected,
                    &expected_programs,
                    &BTreeSet::new(),
                    &directories
                )
                .is_err()
            );
        }
        fs::write(root.join(&executable), b"tampered output")?;
        assert!(
            admit_build_cache(
                &root,
                &cache,
                &cache.identity,
                &expected,
                &expected_programs,
                &BTreeSet::new(),
                &directories
            )
            .is_err()
        );
        fs::remove_file(root.join(&executable))?;
        assert!(
            admit_build_cache(
                &root,
                &cache,
                &cache.identity,
                &expected,
                &expected_programs,
                &BTreeSet::new(),
                &directories
            )
            .is_err()
        );
        #[cfg(unix)]
        {
            let outside = temporary.path().join("outside");
            fs::write(&outside, b"compiled output")?;
            std::os::unix::fs::symlink(&outside, root.join(&executable))?;
            assert!(
                admit_build_cache(
                    &root,
                    &cache,
                    &cache.identity,
                    &expected,
                    &expected_programs,
                    &BTreeSet::new(),
                    &directories
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn preparation_join_requires_supporting_programs_without_expanding_test_partition() -> Result<()>
    {
        let make_tests = || -> Result<Prepared> {
            let mut tests = sample_part("tests")?;
            for (target, kind, executable) in [
                ("day2", "bin", "target/debug/deps/day2-harness"),
                ("integration", "test", "target/debug/deps/integration"),
            ] {
                tests.binaries.push(Binary {
                    package: "day2".into(),
                    target: target.into(),
                    kind: vec![kind.into()],
                    directory: "crates/day2".into(),
                    executable: executable.into(),
                    digest: "binary".into(),
                    permissions: 0o755,
                });
            }
            tests.programs.push(Binary {
                package: "day2".into(),
                target: "day2".into(),
                kind: vec!["bin".into()],
                directory: "crates/day2".into(),
                executable: program_output("day2"),
                digest: "program".into(),
                permissions: 0o755,
            });
            Ok(tests)
        };
        let complete = combine_parts(sample_part("inputs")?, make_tests()?, &sample_identity())?;
        assert_eq!(complete.programs.len(), 1);
        assert!(!expected_binaries(&complete, "workspace-day2").contains(&program_output("day2")));
        for field in ["programs", "executable", "target", "kind", "directory"] {
            let mut value = serde_json::to_value(make_tests()?)?;
            if field == "programs" {
                value[field] = json!([]);
            } else {
                value["programs"][0][field] = if field == "kind" {
                    json!(["test"])
                } else {
                    json!("foreign")
                };
            }
            let invalid = serde_json::from_value(value)?;
            assert!(combine_parts(sample_part("inputs")?, invalid, &sample_identity()).is_err());
        }
        Ok(())
    }

    #[test]
    fn workspace_partition_is_disjoint_and_exhaustive() {
        for package in packages() {
            assert_eq!(
                ["workspace-day2", "workspace-control", "workspace-other"]
                    .iter()
                    .filter(|shard| selected(package, shard))
                    .count(),
                1,
                "{package}"
            );
        }
        assert!(!valid("unknown"));
    }

    #[test]
    fn preparation_retains_every_fixture_and_no_runtime_claim() -> Result<()> {
        let steps = preparation_steps()?;
        assert_eq!(
            steps
                .iter()
                .filter(|step| step.starts_with("build-"))
                .count(),
            23
        );
        assert!(steps.contains("build-lifecycle"));
        assert!(steps.contains("build-verification-actors"));
        assert!(!steps.contains("test-workspace-runtime"));
        assert!(!steps.contains("control-simulation"));
        assert!(steps.contains("test-binaries") && steps.contains("test-docs"));
        Ok(())
    }

    #[test]
    fn shard_admission_rejects_missing_targets_effects_timings_and_foreign_preparation()
    -> Result<()> {
        let prepared = Prepared {
            identity: Identity {
                checkout: "a".repeat(40),
                tree: "tree".into(),
                source_identity: "source-identity".into(),
                workspace: "/workspace/platform".into(),
                run: "123".into(),
                attempt: "1".into(),
                host: "macos".into(),
                architecture: "aarch64".into(),
                workflow: "workflow".into(),
                snapshot: "snapshot".into(),
            },
            binaries: vec![Binary {
                package: "day2".into(),
                target: "day2_integration".into(),
                kind: vec!["test".into()],
                directory: "crates/day2".into(),
                executable: "target/debug/deps/day2_integration-test".into(),
                digest: "binary".into(),
                permissions: 0o755,
            }],
            programs: Vec::new(),
            auxiliaries: Vec::new(),
            fixtures: BTreeMap::new(),
            passed: BTreeSet::new(),
            timings_ms: BTreeMap::new(),
        };
        let shard = "workspace-day2";
        let valid = Receipt {
            prepared_digest: digest(&serde_json::to_vec(&prepared)?),
            shard: shard.into(),
            passed: effects(shard),
            timings_ms: [("test-workspace-day2".into(), 100)].into(),
            binaries: expected_binaries(&prepared, shard),
        };
        validate_receipt(&prepared, &valid, shard)?;
        for field in [
            "prepared_digest",
            "shard",
            "passed",
            "timings_ms",
            "binaries",
        ] {
            let mut value = serde_json::to_value(&valid)?;
            value[field] = match field {
                "prepared_digest" | "shard" => json!("foreign"),
                "timings_ms" => json!({}),
                _ => json!([]),
            };
            let invalid = serde_json::from_value(value)?;
            assert!(
                validate_receipt(&prepared, &invalid, shard).is_err(),
                "{field}"
            );
        }
        assert!(validate_receipt(&prepared, &valid, "workspace-control").is_err());
        Ok(())
    }
    #[test]
    fn linux_launchers_cannot_be_missing_duplicated_foreign_or_added_to_mac() -> Result<()> {
        let complete: Vec<_> = auxiliary_targets("linux")
            .into_iter()
            .map(|(package, target, kind)| Binary {
                directory: "crates/day2-sandbox".into(),
                executable: program_output(&target),
                digest: format!("sha256:{}", "a".repeat(64)),
                permissions: 0o755,
                package,
                target,
                kind,
            })
            .collect();
        validate_auxiliary_inventory(&complete, "linux")?;
        assert!(validate_auxiliary_inventory(&complete[..2], "linux").is_err());
        assert!(validate_auxiliary_inventory(&complete, "macos").is_err());
        for field in [
            "package",
            "target",
            "kind",
            "directory",
            "executable",
            "digest",
        ] {
            let mut value = serde_json::to_value(&complete)?;
            value[0][field] = if field == "kind" {
                json!(["lib"])
            } else {
                json!("foreign")
            };
            let invalid: Vec<Binary> = serde_json::from_value(value)?;
            assert!(
                validate_auxiliary_inventory(&invalid, "linux").is_err(),
                "{field}"
            );
        }
        let mut duplicate: Vec<Binary> = serde_json::from_value(serde_json::to_value(&complete)?)?;
        duplicate.push(complete[0].clone());
        assert!(validate_auxiliary_inventory(&duplicate, "linux").is_err());
        Ok(())
    }
}
