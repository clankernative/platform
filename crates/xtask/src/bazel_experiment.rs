//! Private measurement-branch adapter. Recipes remain in ops/BazelExperiment.roc.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const PROGRAMS: &[(&str, &str)] = &[
    ("bazel-bin/crates/xtask/xtask", "target/debug/xtask"),
    (
        "bazel-bin/crates/day2/day2_integration",
        "target/debug/day2-integration-bazel",
    ),
    (
        "bazel-bin/crates/day2-sandbox/day2-sandbox",
        "target/debug/day2-sandbox",
    ),
    (
        "bazel-bin/crates/day2-sandbox/day2-compiler-sandbox",
        "target/debug/day2-compiler-sandbox",
    ),
    (
        "bazel-bin/crates/day2-sandbox/day2-sandbox-probe",
        "target/debug/day2-sandbox-probe",
    ),
];

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Program {
    path: PathBuf,
    bytes: u64,
    permissions: u32,
    digest: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bundle {
    kind: String,
    run: String,
    attempt: String,
    checkout: String,
    workflow: String,
    programs: Vec<Program>,
}

fn bundle(root: &Path) -> Result<Bundle> {
    Ok(Bundle {
        kind: "isolated-bazel-rust-programs-v1".into(),
        run: std::env::var("GITHUB_RUN_ID")?,
        attempt: std::env::var("GITHUB_RUN_ATTEMPT")?,
        checkout: std::env::var("GITHUB_SHA")?,
        workflow: day2::automation::source_digest(),
        programs: PROGRAMS
            .iter()
            .map(|(_, destination)| inspect(root, destination))
            .collect::<Result<Vec<_>>>()?,
    })
}

fn inspect(root: &Path, path: &str) -> Result<Program> {
    let full = root.join(path);
    let metadata = fs::symlink_metadata(&full)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "regular experiment program required"
    );
    let permissions = metadata.permissions().mode() & 0o7777;
    ensure!(
        permissions & 0o111 != 0 && permissions & 0o7000 == 0,
        "ordinary executable permissions required"
    );
    ensure!(
        metadata.len() <= 256 * 1024 * 1024,
        "experiment program size budget exceeded"
    );
    let bytes = fs::read(&full)?;
    ensure!(
        bytes.len() as u64 == metadata.len(),
        "experiment program size changed"
    );
    ensure!(
        bytes.len() >= 20
            && &bytes[..4] == b"\x7fELF"
            && bytes[4] == 2
            && bytes[5] == 1
            && u16::from_le_bytes([bytes[18], bytes[19]]) == 62,
        "Linux x86_64 ELF header required"
    );
    Ok(Program {
        path: path.into(),
        bytes: metadata.len(),
        permissions,
        digest: day2::digest(&bytes),
    })
}

/// Fixed bootstrap bundle only, never an arbitrary installer or app capability.
pub(super) fn install(root: &Path) -> Result<()> {
    ensure!(
        std::env::consts::OS == "linux",
        "Linux experiment scope required"
    );
    for (source, destination) in PROGRAMS {
        // Resolve only trusted Bazel program outputs, never application sources.
        let source = root.join(source).canonicalize()?;
        let built = inspect(
            root,
            source
                .to_str()
                .context("experiment program path encoding")?,
        )?;
        super::install_cli_file(source, root.join(destination))?;
        let installed = inspect(root, destination)?;
        ensure!(
            built.digest == installed.digest
                && built.bytes == installed.bytes
                && built.permissions == installed.permissions,
            "copied experiment program differs"
        );
    }
    let installed = bundle(root)?;
    fs::write(
        root.join("artifacts/bazel-programs.json"),
        serde_json::to_vec_pretty(&installed)?,
    )?;
    Ok(())
}

fn case_names(source: &str) -> Result<BTreeSet<String>> {
    let mut cases = BTreeSet::new();
    for item in syn::parse_file(source)?.items {
        let syn::Item::Fn(function) = item else {
            continue;
        };
        if !function
            .attrs
            .iter()
            .any(|attribute| attribute.path().is_ident("test"))
        {
            continue;
        }
        ensure!(
            !function
                .attrs
                .iter()
                .any(|attribute| attribute.path().is_ident("ignore")
                    || attribute.path().is_ident("cfg")),
            "unignored unconditional experiment case required"
        );
        ensure!(
            cases.insert(format!("command_atomicity::{}", function.sig.ident)),
            "duplicate experiment case"
        );
    }
    ensure!(
        !cases.is_empty(),
        "nonempty experiment case inventory required"
    );
    Ok(cases)
}

fn harness(root: &Path) -> Command {
    Command::new(root.join("target/debug/day2-integration-bazel"))
}

fn remaining(started: Instant, maximum: Duration) -> Result<Duration> {
    Ok(Duration::from_secs(600)
        .checked_sub(started.elapsed())
        .context("Reports experiment case budget exhausted")?
        .min(maximum))
}

fn list(root: &Path, name: &str, ignored: bool, started: Instant) -> Result<bool> {
    let file = tempfile::NamedTempFile::new()?;
    let mut command = harness(root);
    command.args([name, "--exact", "--list"]);
    if ignored {
        command.arg("--ignored");
    }
    command.stdout(Stdio::from(file.reopen()?));
    super::run_with_budget(
        root,
        &mut command,
        remaining(started, Duration::from_secs(60))?,
    )?;
    ensure!(
        file.as_file().metadata()?.len() <= 1024 * 1024,
        "bounded experiment case inventory required"
    );
    let expected = format!("{name}: test");
    let count = fs::read_to_string(file.path())?
        .lines()
        .filter(|line| *line == expected)
        .count();
    ensure!(count <= 1, "duplicate experiment case listing");
    Ok(count == 1)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    source: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    artifact: PathBuf,
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

pub(super) fn reports(root: &Path) -> Result<()> {
    ensure!(
        std::env::consts::OS == "linux",
        "Linux experiment scope required"
    );
    let expected: Bundle =
        serde_json::from_slice(&fs::read(root.join("artifacts/bazel-programs.json"))?)?;
    let actual = bundle(root)?;
    ensure!(actual == expected, "installed experiment programs changed");
    ensure!(
        std::env::current_exe()?.canonicalize()?
            == root.join("target/debug/xtask").canonicalize()?,
        "installed experiment driver required"
    );
    let cases = case_names(include_str!("../../day2/tests/command_atomicity.rs"))?;
    let runner = super::workflows::build(root)?;
    let mut artifact = None;
    let mut started = None;
    let mut passed = BTreeSet::new();
    let mut timings = std::collections::BTreeMap::new();
    let mut finished = false;
    day2::automation::run(&runner, &["bazel-reports"], |request| {
        match request.action.as_str() {
            "build-source" => {
                let source: Source = request.decode()?;
                ensure!(
                    artifact.is_none() && source.source == "examples/reports",
                    "one fresh Reports build required"
                );
                let built = super::build_recipe(root, &root.join(source.source), None, None, None)?;
                artifact = Some(built.clone());
                Ok(json!({"artifact":built}))
            }
            "bazel-reports-cases" => {
                let _: Empty = request.decode()?;
                ensure!(
                    artifact.is_some() && started.is_none(),
                    "fresh build before one case inventory required"
                );
                let begin = Instant::now();
                for name in &cases {
                    ensure!(
                        list(root, name, false, begin)? && !list(root, name, true, begin)?,
                        "missing or changed ignored status for experiment case: {name}"
                    );
                }
                started = Some(begin);
                Ok(json!(cases))
            }
            "bazel-reports-case" => {
                let case: Case = request.decode()?;
                ensure!(
                    Some(&case.artifact) == artifact.as_ref()
                        && cases.contains(&case.name)
                        && !passed.contains(&case.name),
                    "current artifact and unique selected case required"
                );
                let begin = started.context("case inventory required")?;
                let mut command = harness(root);
                command.args([&case.name, "--exact", "--nocapture", "--test-threads=1"]);
                command.env("DAY2_TEST_REPORTS_ARTIFACT", &case.artifact);
                let now = Instant::now();
                super::run_with_budget(
                    root,
                    &mut command,
                    remaining(begin, Duration::from_secs(600))?,
                )?;
                timings.insert(case.name.clone(), now.elapsed().as_millis());
                passed.insert(case.name);
                Ok(json!({}))
            }
            "bazel-reports-receipt" => {
                let _: Empty = request.decode()?;
                ensure!(
                    passed == cases && artifact.is_some() && !finished,
                    "complete fresh experiment case set required"
                );
                let receipt = json!({"kind":"bazel-reports-runtime-diagnostic-v1","bundle":actual,"host":std::env::consts::OS,"architecture":std::env::consts::ARCH,"artifact":artifact,"cases":passed,"case_ms":timings,"fresh_runtime_executed":true,"fixture_cache_used":false,"Cargo_dep_info_used_for_Bazel_identity":false});
                fs::write(
                    root.join("artifacts/bazel-reports-runtime.json"),
                    serde_json::to_vec_pretty(&receipt)?,
                )?;
                finished = true;
                Ok(receipt)
            }
            _ => bail!("unsupported Reports experiment capability"),
        }
    })?;
    ensure!(finished, "experiment workflow omitted its final receipt");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_reports_cases_are_nonempty_unignored_and_source_derived() -> Result<()> {
        let cases = case_names(include_str!("../../day2/tests/command_atomicity.rs"))?;
        ensure!(cases.contains("command_atomicity::a_changed_authority_snapshot_blocks_a_child_without_business_execution"), "actual Reports authority control required");
        Ok(())
    }

    #[test]
    fn case_admission_refuses_empty_ignored_conditional_and_duplicate_names() {
        for source in [
            "fn helper() {}",
            "#[test] #[ignore] fn skipped() {}",
            "#[test] #[cfg(unix)] fn conditional() {}",
            "#[test] fn duplicate() {} #[test] fn duplicate() {}",
        ] {
            assert!(case_names(source).is_err());
        }
    }
}
