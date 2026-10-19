//! Private measurement-branch adapter. Recipes remain in ops/BazelExperiment.roc.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

// Same effective Rust code-generation options for both measurement arms.
const TIMING_FLAGS: &str = "-Ccodegen-units=16 -Cembed-bitcode=no -Cstrip=none -Cdebuginfo=0 -Cdebug-assertions=on -Coverflow-checks=on";
const TIMING_TARGETS: &[&str] = &[
    "//crates/day2:unit_lib",
    "//crates/day2:day2",
    "//crates/day2:unit_day2",
    "//crates/day2:day2-health",
    "//crates/day2:unit_day2_health",
    "//crates/day2:day2-inspect",
    "//crates/day2:unit_day2_inspect",
    "//crates/day2:day2-package",
    "//crates/day2:unit_day2_package",
    "//crates/day2:day2-security-shell",
    "//crates/day2:unit_day2_security_shell",
    "//crates/day2:sandbox_probe",
    "//crates/day2:unit_sandbox_probe",
    "//crates/day2:day2_integration",
    "//crates/day2-sandbox:unit_lib",
    "//crates/day2-sandbox:day2-compiler-sandbox",
    "//crates/day2-sandbox:unit_day2_compiler_sandbox",
    "//crates/day2-sandbox:day2-sandbox",
    "//crates/day2-sandbox:unit_day2_sandbox",
    "//crates/day2-sandbox:day2-sandbox-probe",
    "//crates/day2-sandbox:unit_day2_sandbox_probe",
    "//crates/day2-sandbox:isolation",
    "//crates/xtask:xtask",
    "//crates/xtask:unit_xtask",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Timing {
    backend: String,
    phase: String,
}

/// One fixed compiler invocation; Roc owns cold/warm ordering.
fn timed_build(root: &Path, timing: Timing) -> Result<serde_json::Value> {
    ensure!(
        ["cold", "warm-1", "warm-2", "warm-3"].contains(&timing.phase.as_str()),
        "fixed timing phase required"
    );
    let mut command = match timing.backend.as_str() {
        "cargo" => {
            let mut command = Command::new("cargo");
            command.args([
                "build",
                "--locked",
                "--offline",
                "-p",
                "day2",
                "-p",
                "xtask",
                "-p",
                "day2-sandbox",
                "--all-targets",
                "--message-format=json",
                "--jobs=2",
            ]);
            command.env(
                "CARGO_TARGET_DIR",
                "/tmp/day2-comparison-cargo-alltargets-target",
            );
            command.env("RUSTC_WRAPPER", "");
            command.env("RUSTC_WORKSPACE_WRAPPER", "");
            command.env("CARGO_INCREMENTAL", "0");
            command.env("RUSTFLAGS", TIMING_FLAGS);
            let output = format!("/tmp/day2-comparison-cargo-{}.jsonl", timing.phase);
            command.stdout(Stdio::from(fs::File::create(output)?));
            command
        }
        "bazel" => {
            let mut command = Command::new("/tmp/day2-bazel-tools/bazel-9.3.0-linux-x86_64");
            command.args([
                "--batch",
                "--output_user_root=/tmp/day2-bazel-Cargo-context-model",
                "build",
                "--symlink_prefix=bazel-",
            ]);
            command.args(TIMING_TARGETS);
            command
        }
        _ => bail!("fixed timing backend required"),
    };
    command.env("SCCACHE_DISABLE", "1");
    let started = Instant::now();
    let result = super::run_with_budget(root, &mut command, Duration::from_secs(3600));
    let receipt = json!({
        "kind": "isolated-build-timing-v1",
        "backend": timing.backend,
        "phase": timing.phase,
        "seconds": started.elapsed().as_secs_f64(),
        "success": result.is_ok(),
        "run": std::env::var("GITHUB_RUN_ID")?,
        "attempt": std::env::var("GITHUB_RUN_ATTEMPT")?,
        "checkout": std::env::var("GITHUB_SHA")?,
        "workflow": day2::automation::source_digest(),
        "jobs": 2,
        "common_rustflags": TIMING_FLAGS,
        "compiler_cache": false,
        "incremental": false,
        "targets": TIMING_TARGETS,
        "cold_definition": "empty build outputs; source downloads and OS page cache are not cold",
    });
    let output = format!("artifacts/timing-{}-{}.json", timing.backend, timing.phase);
    fs::write(root.join(output), serde_json::to_vec_pretty(&receipt)?)?;
    result?;
    Ok(receipt)
}

pub(super) fn timings(root: &Path) -> Result<()> {
    let runner = super::workflows::build(root)?;
    day2::automation::run(&runner, &["bazel-timings"], |request| {
        match request.action.as_str() {
            "bazel-timing-build" => timed_build(root, request.decode()?),
            "bazel-timing-resources" => {
                let phase: String = request.decode()?;
                resources(root, &phase)?;
                Ok(json!({}))
            }
            _ => bail!("unsupported build timing capability"),
        }
    })?;
    Ok(())
}

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

fn bounded_measurement(path: &str, maximum: u64) -> Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "experiment measurement byte limit exceeded"
    );
    Ok(bytes)
}

fn server_pid(bytes: &[u8]) -> Result<u32> {
    let text = std::str::from_utf8(bytes)?.trim();
    ensure!(
        !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()),
        "decimal experiment server PID required"
    );
    let pid: u32 = text.parse()?;
    ensure!(pid > 1, "ordinary experiment server PID required");
    Ok(pid)
}

fn memory_fact(name: &str, bytes: &[u8]) -> Result<serde_json::Value> {
    let text = std::str::from_utf8(bytes)?;
    if name == "memory.current" {
        return Ok(json!(text.trim().parse::<u64>()?));
    }
    ensure!(name == "memory.events", "fixed memory fact required");
    let mut events = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let key = fields.next().context("memory event key required")?;
        ensure!(
            !key.is_empty()
                && key.len() <= 64
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "numeric kernel memory event required"
        );
        let value = fields
            .next()
            .context("memory event value required")?
            .parse::<u64>()?;
        ensure!(
            fields.next().is_none() && events.insert(key, value).is_none(),
            "one value per memory event required"
        );
    }
    ensure!(!events.is_empty(), "nonempty memory events required");
    Ok(serde_json::to_value(events)?)
}

/// Diagnostic data only; no compiler exit or OOM cause is inferred from counters.
pub(super) fn resources(root: &Path, phase: &str) -> Result<()> {
    ensure!(
        std::env::consts::OS == "linux",
        "Linux experiment scope required"
    );
    let output = match phase {
        "before-cargo" => "artifacts/bazel-cargo-before-resources.json",
        "after-cargo" => "artifacts/bazel-cargo-after-resources.json",
        "before-bazel-build" => "artifacts/bazel-build-before-resources.json",
        "after-bazel-build" => "artifacts/bazel-build-after-resources.json",
        _ => bail!("fixed experiment measurement phase required"),
    };
    let pid_metadata = fs::symlink_metadata("/tmp/day2-bazel-context-server.pid")?;
    ensure!(
        pid_metadata.is_file() && !pid_metadata.file_type().is_symlink(),
        "regular experiment server PID file required"
    );
    let pid = server_pid(&bounded_measurement(
        "/tmp/day2-bazel-context-server.pid",
        64,
    )?)?;
    let server_absent = match fs::symlink_metadata(format!("/proc/{pid}")) {
        Ok(_) => false,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => return Err(error.into()),
    };
    ensure!(
        phase != "before-cargo" || server_absent,
        "experiment Bazel server remains visible after shutdown"
    );
    let facts: BTreeMap<_, _> = ["memory.current", "memory.events"]
        .into_iter()
        .map(|name| {
            let observed = bounded_measurement(&format!("/sys/fs/cgroup/{name}"), 4096)
                .and_then(|bytes| memory_fact(name, &bytes));
            let fact = match observed {
                Ok(value) => json!({"status":"observed","value":value}),
                Err(error) => {
                    let errno = error
                        .downcast_ref::<std::io::Error>()
                        .and_then(std::io::Error::raw_os_error);
                    json!({"status":"unavailable","errno":errno})
                }
            };
            (name, fact)
        })
        .collect();
    let run = std::env::var("GITHUB_RUN_ID")?;
    let attempt = std::env::var("GITHUB_RUN_ATTEMPT")?;
    let checkout = std::env::var("GITHUB_SHA")?;
    let receipt = json!({"kind":"bazel-resource-observation-v1","phase":phase,"run":run,"attempt":attempt,"checkout":checkout,"workflow":day2::automation::source_digest(),"server_pid":pid,"server_absent_snapshot":server_absent,"memory":facts,"cause_attribution":false});
    fs::write(root.join(output), serde_json::to_vec_pretty(&receipt)?)?;
    Ok(())
}

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
    fn resource_measurements_accept_only_numeric_kernel_facts() -> Result<()> {
        assert_eq!(memory_fact("memory.current", b"123\n")?, json!(123));
        assert_eq!(
            memory_fact("memory.events", b"oom 0\noom_kill 1\n")?,
            json!({"oom":0,"oom_kill":1})
        );
        for bytes in [&b"oom private\n"[..], &b"oom 1\noom 2\n"[..], &b""[..]] {
            assert!(memory_fact("memory.events", bytes).is_err());
        }
        assert!(memory_fact("foreign", b"1").is_err());
        Ok(())
    }

    #[test]
    fn experiment_server_pid_refuses_nondecimal_and_special_processes() -> Result<()> {
        assert_eq!(server_pid(b"123\n")?, 123);
        for bytes in [&b"0"[..], &b"1"[..], &b"-1"[..], &b"12/../"[..], &b""[..]] {
            assert!(server_pid(bytes).is_err());
        }
        Ok(())
    }

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
