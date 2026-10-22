//! Exact-run transport and admission for the Verify.roc hosted campaigns.
//! Bazel builds its complete declared package/target graph once. The recipes select
//! campaigns; this module admits their binaries and joins complete evidence.
use super::{
    WORKSPACE_TEST_PACKAGES, cached_fixture, configure_tests, required_steps, test_selection,
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

pub(super) mod mac;
pub(super) mod reuse;

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
    bazel: String,
    cc: String,
    environment: String,
    bazel_configuration: BTreeMap<String, String>,
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
    let bazel_configuration = crate::bazel::configuration(root)?;
    Ok(BuildIdentity {
        snapshot: snapshot.into(),
        workflow: day2::automation::source_digest(),
        workspace: root.canonicalize()?,
        host: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        rustc: {
            let compiler = crate::bazel::tool(root, "rustc")?;
            let output = Command::new(&compiler)
                .args(["--version", "--verbose"])
                .output()?;
            ensure!(
                output.status.success(),
                "configured Bazel Rust compiler required"
            );
            format!(
                "{}\ncompiler-digest: {}",
                String::from_utf8(output.stdout)?,
                digest(&fs::read(compiler)?)
            )
        },
        bazel: {
            let mut command = crate::bazel::command(root);
            command.args(["version", "--gnu_format"]);
            let output = command.current_dir(root).output()?;
            ensure!(output.status.success(), "actual Bazel version required");
            String::from_utf8(output.stdout)?
        },
        cc: version("cc", false)?,
        environment: digest(&serde_json::to_vec(&environment)?),
        bazel_configuration,
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
                crate::bazel::PROGRAMS
            } else {
                crate::bazel::TESTS
            };
            ensure!(
                binary.executable.parent() == Some(Path::new(directory))
                    && binary
                        .executable
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_))),
                "cached executable outside declared Bazel output"
            );
            let path = if programs {
                ensure!(
                    binary.executable == program_output(&binary.target),
                    "declared Bazel program name required"
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
    Path::new(crate::bazel::PROGRAMS).join(format!("{target}{}", std::env::consts::EXE_SUFFIX))
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
/// Cache storage stays separate from ordinary Bazel outputs and run receipts.
fn copy_programs(root: &Path, programs: &[Binary], restoring: bool) -> Result<()> {
    let destination = root.join(if restoring {
        crate::bazel::PROGRAMS
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
                && program.executable.parent() == Some(Path::new(crate::bazel::PROGRAMS))
                && program
                    .executable
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_))),
            "installed Bazel program path required"
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
    WORKSPACE_TEST_PACKAGES.iter().copied().collect()
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

fn built_binary(root: &Path, target: &crate::bazel::Target, executable: PathBuf) -> Result<Binary> {
    Ok(Binary {
        package: target.package.clone(),
        target: target.target.clone(),
        kind: target.kind.clone(),
        directory: target.directory.clone(),
        digest: digest(&fs::read(root.join(&executable))?),
        permissions: executable_permissions(&root.join(&executable))?,
        executable,
    })
}

fn build_auxiliaries(
    root: &Path,
    expected: &BTreeSet<(String, String, Vec<String>)>,
    _members: &BTreeMap<String, (String, PathBuf)>,
) -> Result<Vec<Binary>> {
    if expected.is_empty() {
        return Ok(Vec::new());
    }
    ensure!(
        std::env::consts::OS == "linux",
        "native Linux launcher preparation required"
    );
    let selected = crate::bazel::targets(root)?
        .into_iter()
        .filter(|target| {
            !target.test
                && expected.contains(&(
                    target.package.clone(),
                    target.target.clone(),
                    target.kind.clone(),
                ))
        })
        .collect::<Vec<_>>();
    let outputs = crate::bazel::build(root, &selected, Duration::from_secs(12600))?;
    let mut binaries = selected
        .iter()
        .map(|target| {
            built_binary(
                root,
                target,
                outputs
                    .get(&target.label)
                    .context("built launcher required")?
                    .clone(),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    binaries.sort_by(|a, b| a.target.cmp(&b.target));
    validate_auxiliary_inventory(&binaries, "linux")?;
    ensure!(
        binaries
            .iter()
            .map(|b| (b.package.clone(), b.target.clone(), b.kind.clone()))
            .collect::<BTreeSet<_>>()
            == *expected,
        "complete Linux launcher Bazel inventory required"
    );
    Ok(binaries)
}

fn install_auxiliaries(root: &Path, auxiliaries: &[Binary]) -> Result<()> {
    validate_auxiliary_inventory(auxiliaries, std::env::consts::OS)?;
    for binary in auxiliaries {
        let source = root.join(&binary.executable);
        let target = root.join(crate::bazel::TESTS).join(&binary.target);
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
pub(super) fn install_built_linux_auxiliaries(
    root: &Path,
    outputs: &BTreeMap<String, PathBuf>,
) -> Result<()> {
    let expected = auxiliary_targets("linux");
    let mut auxiliaries = Vec::new();
    for target in crate::bazel::targets(root)? {
        if !target.test
            && expected.contains(&(
                target.package.clone(),
                target.target.clone(),
                target.kind.clone(),
            ))
        {
            auxiliaries.push(built_binary(
                root,
                &target,
                outputs
                    .get(&target.label)
                    .context("current built Linux launcher required")?
                    .clone(),
            )?);
        }
    }
    install_auxiliaries(root, &auxiliaries)
}

fn compiler_targets(root: &Path) -> Result<Targets> {
    let catalog = crate::bazel::targets(root)?;
    let mut expected = BTreeSet::new();
    let mut programs = BTreeSet::new();
    let mut auxiliaries = BTreeSet::new();
    let mut members = BTreeMap::new();
    for target in &catalog {
        let auxiliary = std::env::consts::OS == "linux" && target.package == "day2-sandbox";
        if !packages().contains(target.package.as_str()) && !auxiliary {
            continue;
        }
        members.insert(
            target.package.clone(),
            (target.package.clone(), target.directory.clone()),
        );
        let key = (
            target.package.clone(),
            target.target.clone(),
            target.kind.clone(),
        );
        if auxiliary {
            if !target.test && target.kind == ["bin"] {
                auxiliaries.insert(key);
            }
        } else if target.test {
            expected.insert(key);
        } else if target.kind == ["bin"]
            && catalog
                .iter()
                .any(|other| other.package == target.package && other.kind == ["test"])
        {
            programs.insert(key);
        }
    }
    ensure!(
        members.len() == packages().len() + usize::from(std::env::consts::OS == "linux")
            && auxiliaries == auxiliary_targets(std::env::consts::OS),
        "complete full-gate Bazel package graph required"
    );
    Ok(Targets {
        tests: expected,
        programs,
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
    let selected = crate::bazel::targets(root)?
        .into_iter()
        .filter(|target| {
            let key = (
                target.package.clone(),
                target.target.clone(),
                target.kind.clone(),
            );
            if target.test {
                expected.contains(&key)
            } else {
                expected_programs.contains(&key)
            }
        })
        .collect::<Vec<_>>();
    let outputs = crate::bazel::build(root, &selected, Duration::from_secs(12600))?;
    let mut binaries = Vec::new();
    let mut programs = Vec::new();
    let mut observed = BTreeSet::new();
    let mut observed_programs = BTreeSet::new();
    for target in &selected {
        let key = (
            target.package.clone(),
            target.target.clone(),
            target.kind.clone(),
        );
        let output = outputs
            .get(&target.label)
            .context("built default target required")?
            .clone();
        let binary = built_binary(root, target, output)?;
        if target.test {
            ensure!(observed.insert(key), "duplicate test target");
            binaries.push(binary);
        } else {
            ensure!(
                observed_programs.insert(key),
                "duplicate supporting program"
            );
            programs.push(binary);
        }
    }
    ensure!(
        observed == expected && observed_programs == expected_programs,
        "Bazel inventory must cover every default target and supporting program"
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
                && binary.executable.starts_with(crate::bazel::TESTS)
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
                && program.executable.parent() == Some(Path::new(crate::bazel::PROGRAMS))
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
            &root.join(crate::bazel::TESTS).join(&auxiliary.target),
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
    let arguments = test_selection(suite)?.arguments;
    let started = Instant::now();
    let private_build = super::prepare_private_build_inputs(root, suite)?;
    let mut executed = BTreeSet::new();
    for binary in prepared
        .binaries
        .iter()
        .filter(|binary| selected(&binary.package, shard))
    {
        let mut command = Command::new(root.join(&binary.executable));
        command.args(&arguments);
        configure_tests(root, suite, fixtures, private_build.as_ref(), &mut command)?;
        // Manifest and supporting executable paths are workspace-relative and
        // admitted by the current Bazel graph and prepared-byte identity.
        let remaining = budget
            .checked_sub(started.elapsed())
            .context("test campaign budget exhausted")?;
        println!(
            "Prepared test {} / {} ({shard})",
            binary.package, binary.target
        );
        run_with_budget(root, &mut command, remaining)?;
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
                        executable: format!("build-out/tests/{package}-test").into(),
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
        fs::create_dir_all(root.join(crate::bazel::TESTS))?;
        let executable = PathBuf::from("build-out/tests/example-test");
        fs::write(root.join(&executable), b"compiled output")?;
        let identity = BuildIdentity {
            snapshot: "snapshot".into(),
            workflow: "workflow".into(),
            workspace: root.clone(),
            host: "macos".into(),
            architecture: "aarch64".into(),
            rustc: "rustc pinned".into(),
            bazel: "bazel pinned".into(),
            cc: "cc pinned".into(),
            environment: "environment".into(),
            bazel_configuration: BTreeMap::from([(".bazelrc".into(), "config".into())]),
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
            "bazel",
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
        value["identity"]["bazel_configuration"] = json!({".bazelrc": "changed"});
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
                ("day2", "bin", "build-out/tests/day2-harness"),
                ("integration", "test", "build-out/tests/integration"),
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
                executable: "build-out/tests/day2_integration-test".into(),
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
