//! Exact-run transport and admission for the Verify.roc hosted campaigns.
//! Cargo builds its ordinary full package/target graph once. The recipes select
//! campaigns; this module admits their binaries and joins complete evidence.
use super::{
    WORKSPACE_TEST_ARGUMENTS, cached_fixture, configure_tests, required_steps, test_command,
};
use crate::run_with_budget;
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
const SHARDS: &[&str] = &[
    "workspace-day2",
    "workspace-control",
    "workspace-other",
    "simulation",
    "parallel-runtime",
    "isolated-build",
    "installation-build",
];

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    checkout: String,
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
}

/// Completed compiler outputs, without any runtime outcome or run receipt.
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BuildIdentity {
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
}

fn build_identity(root: &Path, snapshot: &str) -> Result<BuildIdentity> {
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
            admit_executable(&path, &binary.digest)?;
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

fn admit_executable(path: &Path, expected: &str) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "compiler executable must be a regular file"
    );
    ensure!(
        path.canonicalize()? == path,
        "compiler output has a symlink ancestor"
    );
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
        admit_executable(&source, &program.digest)?;
        match fs::symlink_metadata(&target) {
            Ok(metadata) => ensure!(
                metadata.file_type().is_file(),
                "program copy destination must be a regular file"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        fs::copy(source, &target)?;
        admit_executable(&target, &program.digest)?;
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Prepared {
    identity: Identity,
    binaries: Vec<Binary>,
    programs: Vec<Binary>,
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
    Ok(Identity {
        checkout,
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

pub(super) fn build(root: &Path, snapshot: &str) -> Result<()> {
    let metadata = Command::new("cargo")
        .args(["metadata", "--locked", "--no-deps", "--format-version=1"])
        .current_dir(root)
        .output()?;
    ensure!(metadata.status.success(), "Cargo test target metadata");
    let metadata: serde_json::Value = day2::json::decode(&metadata.stdout)?;
    let mut expected = BTreeSet::new();
    let mut expected_programs = BTreeSet::new();
    let mut members = BTreeMap::new();
    for package in metadata["packages"].as_array().context("Cargo packages")? {
        let name = package["name"].as_str().context("package name")?;
        if !packages().contains(name) {
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
        members.len() == packages().len(),
        "complete full-gate Cargo package graph required"
    );
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
                &directories,
            )?;
            copy_programs(root, &cache.programs, true)?;
            Ok(cache)
        })();
        match cached {
            Ok(cache) => {
                fs::write(
                    root.join(BINARIES),
                    serde_json::to_vec_pretty(&cache.binaries)?,
                )?;
                println!(
                    "Reusing {} admitted compiled test binaries and {} supporting programs; runtime campaigns and doc tests execute fresh",
                    cache.binaries.len(),
                    cache.programs.len()
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
    let capture = tempfile::NamedTempFile::new_in(root.join("artifacts"))?;
    let compilation = run_with_budget(
        root,
        Command::new("cargo")
            .args([
                "test",
                "--locked",
                "--no-run",
                "--message-format=json-render-diagnostics",
            ])
            .args(WORKSPACE_TEST_ARGUMENTS)
            .stdout(capture.as_file().try_clone()?),
        Duration::from_secs(12600),
    );
    let output = fs::read(capture.path())?;
    for line in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let message: serde_json::Value = day2::json::decode(line)?;
        if message["reason"] == "compiler-message"
            && let Some(rendered) = message["message"]["rendered"].as_str()
        {
            print!("{rendered}");
        }
    }
    compilation?;
    let mut binaries = Vec::new();
    let mut programs = Vec::new();
    let mut observed = BTreeSet::new();
    let mut observed_programs = BTreeSet::new();
    let mut finished = false;
    for line in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let message: serde_json::Value = day2::json::decode(line)?;
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
    fs::write(root.join(BINARIES), serde_json::to_vec_pretty(&binaries)?)?;
    let cache = BuildCache {
        identity: compiler,
        binaries: binaries.clone(),
        programs,
    };
    admit_build_cache(
        root,
        &cache,
        &cache.identity,
        &expected,
        &expected_programs,
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
            binary.executable.starts_with("target/debug/deps")
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
            program.kind == ["bin"]
                && program.executable == program_output(&program.target)
                && program.executable.parent() == Some(Path::new("target/debug"))
                && program
                    .executable
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_))),
            "prepared ordinary program path required"
        );
    }
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
        admit_executable(&root.join(&binary.executable), &binary.digest)?;
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

pub(super) fn join(
    root: &Path,
    prepared: &Prepared,
) -> Result<(BTreeSet<String>, BTreeMap<String, u64>)> {
    let files = fs::read_dir(root.join(RESULTS))?.collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        files.len() == SHARDS.len(),
        "exact complete shard receipt set required"
    );
    let mut timings = prepared.timings_ms.clone();
    let mut receipts = Vec::new();
    for shard in SHARDS {
        let receipt: Receipt =
            day2::json::decode(&fs::read(root.join(RESULTS).join(format!("{shard}.json")))?)?;
        validate_receipt(prepared, &receipt, shard)?;
        for (step, elapsed) in &receipt.timings_ms {
            ensure!(
                timings.insert(step.clone(), *elapsed).is_none(),
                "duplicate verification effect"
            );
        }
        receipts.push(receipt);
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
    fs::write(
        root.join("artifacts/ci-verification.json"),
        serde_json::to_vec_pretty(&json!({
            "identity":prepared.identity,"prepared_digest":digest(&serde_json::to_vec(prepared)?),
            "shards":receipts,"effects":passed,"timings_ms":timings,
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

    fn sample_identity() -> Identity {
        Identity {
            checkout: "a".repeat(40),
            workspace: "/workspace/platform".into(),
            run: "123".into(),
            attempt: "1".into(),
            host: "macos".into(),
            architecture: "aarch64".into(),
            workflow: "workflow".into(),
            snapshot: "snapshot".into(),
        }
    }

    fn sample_part(part: &str) -> Result<Prepared> {
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
                    })
                    .collect()
            } else {
                Vec::new()
            },
            programs: Vec::new(),
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
        assert_eq!(complete.fixtures.len(), 21);
        assert!(complete.fixtures.contains_key("lifecycle"));
        let mut without_lifecycle = sample_part("inputs")?;
        without_lifecycle.fixtures.remove("lifecycle");
        assert!(
            combine_parts(without_lifecycle, sample_part("tests")?, &sample_identity()).is_err()
        );
        for field in [
            "checkout",
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
        };
        let expected_programs =
            BTreeSet::from([("example".into(), "example".into(), vec!["bin".into()])]);
        let cache = BuildCache {
            identity,
            binaries: vec![binary],
            programs: vec![program],
        };
        admit_build_cache(
            &root,
            &cache,
            &cache.identity,
            &expected,
            &expected_programs,
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
                });
            }
            tests.programs.push(Binary {
                package: "day2".into(),
                target: "day2".into(),
                kind: vec!["bin".into()],
                directory: "crates/day2".into(),
                executable: program_output("day2"),
                digest: "program".into(),
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
            21
        );
        assert!(steps.contains("build-lifecycle"));
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
            }],
            programs: Vec::new(),
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
}
