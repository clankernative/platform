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

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Binary {
    package: String,
    target: String,
    kind: Vec<String>,
    directory: PathBuf,
    executable: PathBuf,
    digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Prepared {
    identity: Identity,
    binaries: Vec<Binary>,
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

pub(super) fn build(root: &Path) -> Result<()> {
    let metadata = Command::new("cargo")
        .args(["metadata", "--locked", "--no-deps", "--format-version=1"])
        .current_dir(root)
        .output()?;
    ensure!(metadata.status.success(), "Cargo test target metadata");
    let metadata: serde_json::Value = day2::json::decode(&metadata.stdout)?;
    let mut expected = BTreeSet::new();
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
        for target in package["targets"].as_array().context("Cargo targets")? {
            let kind: Vec<String> = serde_json::from_value(target["kind"].clone())?;
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
    let mut observed = BTreeSet::new();
    let mut finished = false;
    for line in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let message: serde_json::Value = day2::json::decode(line)?;
        if message["reason"] == "build-finished" {
            finished = message["success"] == true;
        }
        if message["reason"] != "compiler-artifact" || message["profile"]["test"] != true {
            continue;
        }
        let executable = message["executable"]
            .as_str()
            .context("test harness executable required")?;
        let (package, directory) = members
            .get(message["package_id"].as_str().context("artifact package")?)
            .context("test binary outside full-gate package graph")?;
        let kind: Vec<String> = serde_json::from_value(message["target"]["kind"].clone())?;
        let target = message["target"]["name"]
            .as_str()
            .context("test target name")?
            .to_owned();
        ensure!(
            observed.insert((package.clone(), target.clone(), kind.clone())),
            "duplicate Cargo test target"
        );
        let executable = Path::new(executable).strip_prefix(root)?.to_owned();
        ensure!(
            executable.starts_with("target/debug/deps"),
            "ordinary full-gate test output required"
        );
        binaries.push(Binary {
            package: package.clone(),
            target,
            kind,
            directory: directory.clone(),
            digest: digest(&fs::read(root.join(&executable))?),
            executable,
        });
    }
    ensure!(
        finished && observed == expected,
        "Cargo test binary inventory does not cover every default target"
    );
    binaries.sort_by(|left, right| left.executable.cmp(&right.executable));
    fs::write(root.join(BINARIES), serde_json::to_vec_pretty(&binaries)?)?;
    println!(
        "Prepared {} test binaries from all {} full-gate packages",
        binaries.len(),
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

pub(super) fn save(
    root: &Path,
    snapshot: &str,
    fixtures: &BTreeMap<String, PathBuf>,
    passed: &BTreeSet<String>,
    timings: &BTreeMap<String, u64>,
) -> Result<()> {
    ensure!(
        *passed == preparation_steps()?,
        "incomplete hosted verification preparation"
    );
    let binaries: Vec<Binary> = day2::json::decode(&fs::read(root.join(BINARIES))?)?;
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
        fixtures,
        passed: passed.clone(),
        timings_ms: timings.clone(),
    };
    validate_preparation(&prepared)?;
    fs::write(root.join(PREPARED), serde_json::to_vec_pretty(&prepared)?)?;
    Ok(())
}

fn validate_preparation(prepared: &Prepared) -> Result<()> {
    ensure!(
        prepared.passed == preparation_steps()?
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
            == packages(),
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
    Ok(())
}

pub(super) fn load(root: &Path, snapshot: &str) -> Result<Prepared> {
    let prepared: Prepared = day2::json::decode(&fs::read(root.join(PREPARED))?)?;
    ensure!(
        prepared.identity == identity(root, snapshot)?,
        "prepared verification belongs to another checkout, run, attempt or host"
    );
    validate_preparation(&prepared)?;
    for binary in &prepared.binaries {
        ensure!(
            digest(&fs::read(root.join(&binary.executable))?) == binary.digest,
            "prepared test executable changed"
        );
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
            20
        );
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
