//! Disjoint case admission for the two serial day2 campaigns. The current
//! executable supplies the inventory; source filters never stand in for tests.
use super::{Binary, Prepared, configure_tests, test_selection};
use anyhow::{Context, Result, ensure};
use day2::simulation::coverage::Observation;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

pub(super) const RUNTIME: &str = "workspace-day2-runtime";
const PREFIX: &str = "oauth::management::app::tests::native_lifecycle::";

pub(super) fn part(shard: &str) -> bool {
    ["workspace-day2", RUNTIME].contains(&shard)
}

pub(super) fn binary(binary: &Binary, shard: &str) -> bool {
    binary.package == "day2"
        && part(shard)
        && (binary.kind == ["lib"] || (binary.kind == ["test"]) == (shard == RUNTIME))
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inventory {
    library: bool,
    listed_digest: String,
    listed_count: usize,
    ignored: Vec<String>,
    selected: Vec<String>,
    outcome: Option<Outcome>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Outcome {
    passed: usize,
    ignored: usize,
    cases_digest: String,
}

#[derive(Debug, Serialize)]
struct Failure {
    category: &'static str,
    exit_code: Option<i32>,
    signal: Option<i32>,
    os_error: Option<i32>,
    capture_available: bool,
    failed_case_count: usize,
    failed_cases: Vec<String>,
    names_truncated: bool,
    last_observed_case: Option<String>,
    cause_attribution: bool,
}

fn failure(
    status: &std::result::Result<ExitStatus, crate::CommandStatusError>,
    capture: &Result<String>,
    inventory: &Inventory,
) -> Failure {
    let (category, exit_code, signal, os_error) = match status {
        Ok(status) => {
            #[cfg(unix)]
            let signal = status.signal();
            #[cfg(not(unix))]
            let signal = None;
            ("exit_or_signal", status.code(), signal, None)
        }
        Err(crate::CommandStatusError::Spawn(error)) => ("spawn_error", None, None, error.raw_os_error()),
        Err(crate::CommandStatusError::Wait(error)) => ("wait_error_closure_unknown", None, None, error.raw_os_error()),
        Err(crate::CommandStatusError::Timeout) => ("timeout", None, None, None),
    };
    let runnable: BTreeSet<_> = inventory.selected.iter()
        .filter(|name| !inventory.ignored.contains(name)).map(String::as_str).collect();
    let mut failed = BTreeSet::new();
    let mut last = None;
    if let Ok(output) = capture {
        for line in output.lines() {
            if let Some((name, tail)) = line.strip_prefix("test ").and_then(|line| line.split_once(" ..."))
                && runnable.contains(name) {
                last = Some(name.to_owned());
                if tail.trim_start().starts_with("FAILED") { failed.insert(name.to_owned()); }
            }
        }
    }
    Failure {
        category, exit_code, signal, os_error, capture_available: capture.is_ok(),
        failed_case_count: failed.len(), failed_cases: failed.iter().take(16).cloned().collect(),
        names_truncated: failed.len() > 16, last_observed_case: last, cause_attribution: false,
    }
}

fn require_success(
    status: std::result::Result<ExitStatus, crate::CommandStatusError>,
    capture: &Result<String>,
    inventory: &Inventory,
) -> Result<()> {
    if status.as_ref().is_ok_and(ExitStatus::success) { return Ok(()); }
    if let Ok(record) = serde_json::to_string(&failure(&status, capture, inventory)) {
        eprintln!("Day2 child failure: {record}");
    }
    match status {
        Ok(status) => anyhow::bail!("day2 case campaign failed: {status}"),
        Err(crate::CommandStatusError::Spawn(_)) => anyhow::bail!("day2 case campaign could not spawn"),
        Err(crate::CommandStatusError::Wait(_)) => anyhow::bail!("day2 case campaign wait failed; closure unknown"),
        Err(crate::CommandStatusError::Timeout) => anyhow::bail!("day2 case campaign exceeded its original budget"),
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::verification) struct Evidence {
    inventories: BTreeMap<PathBuf, Inventory>,
    pub(super) observations: Vec<Observation>,
}

impl Evidence {
    pub(super) fn new(
        inventories: BTreeMap<PathBuf, Inventory>,
        observations: Vec<Observation>,
    ) -> Self {
        Self {
            inventories,
            observations,
        }
    }
}

fn names(values: &[String]) -> Result<BTreeSet<String>> {
    ensure!(values.len() <= 10_000, "case inventory count bound");
    let mut names = BTreeSet::new();
    for name in values {
        ensure!(
            !name.is_empty()
                && name.len() <= 1024
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_:".contains(&byte))
                && names.insert(name.clone()),
            "invalid or duplicate libtest case name"
        );
    }
    Ok(names)
}

fn name_digest(values: &[String]) -> Result<String> {
    Ok(day2::digest(&serde_json::to_vec(&names(values)?)?))
}

fn inventory(
    library: bool,
    listed: &[String],
    ignored: Vec<String>,
    shard: &str,
) -> Result<Inventory> {
    Ok(Inventory {
        library,
        listed_digest: name_digest(listed)?,
        listed_count: listed.len(),
        ignored,
        selected: listed
            .iter()
            .filter(|name| assigned(name, shard, library))
            .cloned()
            .collect(),
        outcome: None,
    })
}

fn parse(output: &str) -> Result<Vec<String>> {
    let mut listed = Vec::new();
    let mut footer = None;
    for line in output.lines().filter(|line| !line.is_empty()) {
        if let Some(name) = line.strip_suffix(": test") {
            ensure!(footer.is_none(), "case after inventory footer");
            listed.push(name.to_owned());
        } else {
            ensure!(
                footer.replace(line).is_none(),
                "unexpected libtest inventory output"
            );
        }
    }
    let count = names(&listed)?.len();
    let expected = format!(
        "{count} test{}, 0 benchmarks",
        if count == 1 { "" } else { "s" }
    );
    ensure!(
        footer == Some(expected.as_str()),
        "complete libtest inventory required"
    );
    listed.sort();
    Ok(listed)
}

pub(super) fn command(
    root: &Path,
    binary: &Binary,
    fixtures: &BTreeMap<String, PathBuf>,
    selected: &[String],
) -> Result<Command> {
    let mut command = Command::new(root.join(&binary.executable));
    command.args(test_selection("workspace-runtime")?.arguments);
    command.args(selected);
    configure_tests(root, "workspace-runtime", fixtures, None, &mut command)?;
    Ok(command)
}

fn list(
    root: &Path,
    binary: &Binary,
    fixtures: &BTreeMap<String, PathBuf>,
    selected: &[String],
    ignored: bool,
    budget: Duration,
) -> Result<Vec<String>> {
    let file = tempfile::NamedTempFile::new()?;
    let mut command = command(root, binary, fixtures, selected)?;
    command.arg("--list").stdout(Stdio::from(file.reopen()?));
    if ignored {
        command.arg("--ignored");
    }
    let status =
        crate::command_status_with_budget(root, &mut command, budget.min(Duration::from_secs(60)))
            .map_err(|_| anyhow::anyhow!("case inventory child did not close successfully"))?;
    ensure!(status.success(), "case inventory child failed: {status}");
    let output: &fs::File = file.as_file();
    ensure!(
        output.metadata()?.len() <= 1024 * 1024,
        "case inventory byte bound"
    );
    parse(&fs::read_to_string(file.path())?)
}

fn assigned(name: &str, shard: &str, library: bool) -> bool {
    !library || name.starts_with(PREFIX) == (shard == RUNTIME)
}

fn admit(inventory: &Inventory, shard: &str) -> Result<()> {
    ensure!(part(shard), "day2 part required");
    let ignored = names(&inventory.ignored)?;
    let selected = names(&inventory.selected)?;
    ensure!(
        inventory.listed_count <= 10_000
            && ignored.len() <= inventory.listed_count
            && selected.len() <= inventory.listed_count
            && inventory
                .listed_digest
                .strip_prefix("sha256:")
                .is_some_and(
                    |value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                )
            && selected
                .iter()
                .all(|name| assigned(name, shard, inventory.library)),
        "day2 inventory partition changed"
    );
    if !inventory.library {
        ensure!(
            ignored.is_subset(&selected)
                && selected.len() == inventory.listed_count
                && name_digest(&inventory.selected)? == inventory.listed_digest,
            "whole harness inventory changed"
        );
    }
    Ok(())
}

fn completed(inventory: &Inventory) -> Result<()> {
    let outcome = inventory
        .outcome
        .as_ref()
        .context("actual day2 test outcome required")?;
    let selected = names(&inventory.selected)?;
    let ignored = names(&inventory.ignored)?;
    let runnable: BTreeSet<_> = selected.difference(&ignored).cloned().collect();
    ensure!(
        outcome.cases_digest == name_digest(&runnable.iter().cloned().collect::<Vec<_>>())?
            && outcome.passed == runnable.len()
            && outcome.ignored == selected.intersection(&ignored).count(),
        "actual day2 execution did not cover its exact admitted case inventory"
    );
    Ok(())
}

pub(super) fn capture(
    root: &Path,
    binary: &Binary,
    fixtures: &BTreeMap<String, PathBuf>,
    shard: &str,
    started: Instant,
    budget: Duration,
) -> Result<Inventory> {
    let remaining = || {
        budget
            .checked_sub(started.elapsed())
            .context("day2 campaign budget exhausted")
    };
    let listed = list(root, binary, fixtures, &[], false, remaining()?)?;
    let ignored = list(root, binary, fixtures, &[], true, remaining()?)?;
    let inventory = inventory(binary.kind == ["lib"], &listed, ignored, shard)?;
    admit(&inventory, shard)?;
    ensure!(
        !inventory.selected.is_empty() || inventory.listed_count == 0,
        "empty positive case selection cannot mean run every case"
    );
    ensure!(
        list(
            root,
            binary,
            fixtures,
            &inventory.selected,
            false,
            remaining()?
        )? == inventory.selected,
        "actual libtest selection differs from its admitted case inventory"
    );
    Ok(inventory)
}

pub(super) fn selected(inventory: &Inventory) -> &[String] {
    &inventory.selected
}

fn execution(output: &str, inventory: &Inventory) -> Result<Outcome> {
    let selected = names(&inventory.selected)?;
    let ignored = names(&inventory.ignored)?;
    let runnable: BTreeSet<_> = selected.difference(&ignored).cloned().collect();
    let mut cases = Vec::new();
    for line in output.lines() {
        if let Some((name, _)) = line
            .strip_prefix("test ")
            .and_then(|line| line.split_once(" ..."))
            && runnable.contains(name)
        {
            cases.push(name.to_owned());
        }
    }
    let summary = output
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix("test result: ok. "))
        .context("successful outer libtest summary required")?;
    let fields: Vec<_> = summary.split("; ").collect();
    ensure!(
        fields.len() == 6 && fields[1] == "0 failed" && fields[3] == "0 measured",
        "complete successful libtest outcome required"
    );
    let passed = fields[0]
        .strip_suffix(" passed")
        .context("libtest passed count")?
        .parse()?;
    let ignored = fields[2]
        .strip_suffix(" ignored")
        .context("libtest ignored count")?
        .parse()?;
    ensure!(
        fields[4]
            .strip_suffix(" filtered out")
            .and_then(|v| v.parse::<usize>().ok())
            .is_some()
            && fields[5].starts_with("finished in ")
            && fields[5].ends_with('s'),
        "libtest outcome shape"
    );
    Ok(Outcome {
        passed,
        ignored,
        cases_digest: name_digest(&cases)?,
    })
}

pub(super) fn run(
    root: &Path,
    binary: &Binary,
    fixtures: &BTreeMap<String, PathBuf>,
    inventory: &mut Inventory,
    budget: Duration,
    dst: &super::super::dst::Session,
) -> Result<()> {
    let file = tempfile::NamedTempFile::new()?;
    let mut command = command(root, binary, fixtures, selected(inventory))?;
    dst.configure(&mut command);
    command.stdout(Stdio::from(file.reopen()?));
    let status = crate::command_status_with_budget(root, &mut command, budget);
    let output: &fs::File = file.as_file();
    let capture = (|| -> Result<String> {
        ensure!(output.metadata()?.len() <= 16 * 1024 * 1024, "day2 outcome byte bound");
        Ok(fs::read_to_string(file.path())?)
    })();
    require_success(status, &capture, inventory)?;
    inventory.outcome = Some(execution(&capture?, inventory)?);
    completed(inventory)?;
    let outcome = inventory.outcome.as_ref().context("actual day2 outcome")?;
    println!(
        "Day2 exact inventory: {} passed; {} declared ignored",
        outcome.passed, outcome.ignored
    );
    Ok(())
}

fn equal_union(original: &Inventory, runtime: &Inventory, current: &Inventory) -> Result<()> {
    admit(original, "workspace-day2")?;
    admit(runtime, RUNTIME)?;
    ensure!(
        original.library
            && runtime.library
            && current.library
            && original.listed_digest == current.listed_digest
            && runtime.listed_digest == current.listed_digest
            && original.listed_count == current.listed_count
            && runtime.listed_count == current.listed_count
            && original.ignored == current.ignored
            && runtime.ignored == current.ignored,
        "case inventory or ignored status differs from the current executable"
    );
    let left = names(&original.selected)?;
    let right = names(&runtime.selected)?;
    let union: Vec<_> = left.union(&right).cloned().collect();
    let ignored = names(&current.ignored)?;
    ensure!(
        left.is_disjoint(&right)
            && union.len() == current.listed_count
            && name_digest(&union)? == current.listed_digest
            && ignored.is_subset(&names(&union)?),
        "day2 parts must preserve exactly the original case inventory"
    );
    ensure!(
        right.difference(&ignored).next().is_some(),
        "runtime library part ran no nonignored cases"
    );
    Ok(())
}

pub(super) fn validate(evidence: &Evidence, prepared: &Prepared, shard: &str) -> Result<()> {
    ensure!(
        evidence
            .inventories
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            == prepared
                .binaries
                .iter()
                .filter(|value| binary(value, shard))
                .map(|value| value.executable.clone())
                .collect(),
        "exact current day2 harness inventory required"
    );
    for binary in prepared
        .binaries
        .iter()
        .filter(|value| binary(value, shard))
    {
        let inventory = evidence
            .inventories
            .get(&binary.executable)
            .context("current day2 harness required")?;
        ensure!(
            inventory.library == (binary.kind == ["lib"]),
            "case source-kind changed"
        );
        admit(inventory, shard)?;
        completed(inventory)?;
    }
    ensure!(
        evidence.inventories.values().any(|inventory| inventory
            .outcome
            .as_ref()
            .is_some_and(|outcome| outcome.passed > 0)),
        "day2 part ran no nonignored tests"
    );
    Ok(())
}

pub(super) fn validate_join(
    prepared: &Prepared,
    original: &Evidence,
    runtime: &Evidence,
) -> Result<()> {
    validate(original, prepared, "workspace-day2")?;
    validate(runtime, prepared, RUNTIME)?;
    for binary in prepared
        .binaries
        .iter()
        .filter(|value| value.package == "day2")
    {
        match (
            original.inventories.get(&binary.executable),
            runtime.inventories.get(&binary.executable),
        ) {
            (Some(left), Some(right)) => equal_union(left, right, left)?,
            (Some(whole), None) | (None, Some(whole)) => {
                ensure!(!whole.library, "library partition missing");
            }
            _ => anyhow::bail!("day2 harness partition missing"),
        }
    }
    super::super::dst::validate(original.observations.iter().chain(&runtime.observations))
}

pub(super) fn join(
    root: &Path,
    prepared: &Prepared,
    original: &Evidence,
    runtime: &Evidence,
) -> Result<()> {
    validate_join(prepared, original, runtime)?;
    let fixtures = super::fixtures(root, prepared)?;
    for binary in prepared
        .binaries
        .iter()
        .filter(|value| value.package == "day2")
    {
        let listed = list(root, binary, &fixtures, &[], false, Duration::from_secs(60))?;
        let current = inventory(
            binary.kind == ["lib"],
            &listed,
            list(root, binary, &fixtures, &[], true, Duration::from_secs(60))?,
            "workspace-day2",
        )?;
        match (
            original.inventories.get(&binary.executable),
            runtime.inventories.get(&binary.executable),
        ) {
            (Some(left), Some(right)) => equal_union(left, right, &current)?,
            (Some(whole), None) | (None, Some(whole)) => {
                ensure!(
                    whole.listed_digest == current.listed_digest
                        && whole.listed_count == current.listed_count
                        && whole.ignored == current.ignored,
                    "whole day2 harness inventory changed"
                );
            }
            _ => anyhow::bail!("day2 harness partition missing"),
        }
    }
    super::super::dst::join(
        root,
        original.observations.iter().chain(&runtime.observations),
    )
}

#[cfg(test)]
pub(in crate::verification) fn sample(prepared: &Prepared, shard: &str) -> Evidence {
    let inventories = prepared
        .binaries
        .iter()
        .filter(|value| binary(value, shard))
        .map(|binary| {
            let mut listed = vec!["ordinary::unit_case".to_owned()];
            if binary.kind == ["lib"] {
                listed.push(format!("{PREFIX}history"));
            }
            listed.sort();
            let mut inventory =
                inventory(binary.kind == ["lib"], &listed, Vec::new(), shard).unwrap();
            inventory.outcome = Some(Outcome {
                passed: inventory.selected.len(),
                ignored: 0,
                cases_digest: name_digest(&inventory.selected).unwrap(),
            });
            (binary.executable.clone(), inventory)
        })
        .collect();
    Evidence {
        inventories,
        observations: if shard == "workspace-day2" {
            super::super::dst::tests::complete()
        } else {
            Vec::new()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type ChildProbe = (
        std::result::Result<ExitStatus, crate::CommandStatusError>,
        Result<String>,
        Inventory,
    );

    fn probe(fixture: &str, budget: Duration) -> Result<ChildProbe> {
        let directory = tempfile::tempdir()?;
        let file = tempfile::NamedTempFile::new_in(directory.path())?;
        let mut command = Command::new(std::env::current_exe()?);
        command.args([fixture, "--exact", "--ignored", "--test-threads=1"])
            .stdout(Stdio::from(file.reopen()?)).stderr(Stdio::null());
        let status = crate::command_status_with_budget(directory.path(), &mut command, budget);
        let capture = fs::read_to_string(file.path()).map_err(anyhow::Error::from);
        let inventory = super::inventory(false, &[fixture.to_owned()], Vec::new(), RUNTIME)?;
        Ok((status, capture, inventory))
    }

    #[test]
    #[ignore = "fixture exercised only by the child-status diagnostic controls"]
    fn failure_fixture() { panic!("synthetic child failure"); }

    #[test]
    #[ignore = "fixture exercised only by the bounded timeout diagnostic control"]
    fn timeout_fixture() {
        use std::io::Write;
        // Bypass libtest's thread-local capture so even a killed fixture leaves
        // only this fixed, selected case marker in the owned stdout capture.
        let mut output = std::io::stdout();
        output.write_all(b"test verification::shards::cases::tests::timeout_fixture ... started\n").unwrap();
        output.flush().unwrap();
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn real_failed_child_retains_only_its_selected_case_and_waited_numeric_status() -> Result<()> {
        let name = "verification::shards::cases::tests::failure_fixture";
        let (status, capture, inventory) = probe(name, Duration::from_secs(10))?;
        assert!(status.as_ref().is_ok_and(|status| !status.success()));
        let report = failure(&status, &capture, &inventory);
        assert_eq!(report.exit_code, status.as_ref().ok().and_then(ExitStatus::code));
        assert_eq!(report.failed_cases, vec![name]);
        assert_eq!(report.last_observed_case.as_deref(), Some(name));
        assert!(!report.cause_attribution);
        assert!(require_success(status, &capture, &inventory).is_err());
        let redacted = serde_json::to_string(&report)?;
        assert!(!redacted.contains("synthetic child failure"));
        Ok(())
    }

    #[test]
    fn real_timeout_retains_last_case_and_capture_errors_cannot_replace_the_primary_failure() -> Result<()> {
        let name = "verification::shards::cases::tests::timeout_fixture";
        let (status, capture, inventory) = probe(name, Duration::from_secs(2))?;
        assert!(matches!(&status, Err(crate::CommandStatusError::Timeout)));
        let report = failure(&status, &capture, &inventory);
        assert_eq!(report.category, "timeout");
        assert_eq!(report.last_observed_case.as_deref(), Some(name));
        assert!(report.exit_code.is_none() && report.signal.is_none());
        assert!(require_success(status, &capture, &inventory).unwrap_err().to_string().contains("original budget"));
        let missing: Result<String> = Err(anyhow::anyhow!("synthetic capture unavailable"));
        let primary = require_success(Err(crate::CommandStatusError::Timeout), &missing, &inventory).unwrap_err();
        assert!(primary.to_string().contains("original budget"));
        assert!(!primary.to_string().contains("capture unavailable"));
        Ok(())
    }

    #[test]
    fn failure_diagnostics_are_allowlisted_bounded_and_explicit_about_omitted_names() -> Result<()> {
        let listed: Vec<_> = (0..20).map(|index| format!("fixture::case_{index}")).collect();
        let inventory = super::inventory(false, &listed, Vec::new(), RUNTIME)?;
        let output = listed.iter().map(|name| format!("test {name} ... FAILED opaque provider detail\n")).collect::<String>()
            + "test unknown::case ... FAILED\n";
        let report = failure(&Err(crate::CommandStatusError::Timeout), &Ok(output), &inventory);
        assert_eq!(report.failed_case_count, 20);
        assert_eq!(report.failed_cases.len(), 16);
        assert!(report.names_truncated);
        let text = serde_json::to_string(&report)?;
        assert!(!text.contains("unknown::case") && !text.contains("opaque provider detail"));
        Ok(())
    }

    fn inventory(shard: &str) -> Inventory {
        let listed = vec![
            "ordinary::new_case".into(),
            format!("{PREFIX}history"),
            format!("{PREFIX}ignored"),
        ];
        super::inventory(true, &listed, vec![format!("{PREFIX}ignored")], shard).unwrap()
    }

    #[test]
    fn current_case_union_is_disjoint_exhaustive_and_preserves_ignored_status() -> Result<()> {
        let current = inventory("workspace-day2");
        equal_union(&current, &inventory(RUNTIME), &current)?;
        for field in ["listed_digest", "ignored", "selected"] {
            let mut value = serde_json::to_value(inventory(RUNTIME))?;
            value[field] = if field == "listed_digest" {
                serde_json::json!(format!("sha256:{}", "0".repeat(64)))
            } else {
                serde_json::json!([])
            };
            assert!(equal_union(&current, &serde_json::from_value(value)?, &current).is_err());
        }
        let mut duplicate = inventory(RUNTIME);
        duplicate.selected.push(duplicate.selected[0].clone());
        assert!(equal_union(&current, &duplicate, &current).is_err());
        let mut changed = inventory("workspace-day2");
        changed.listed_count += 1;
        assert!(equal_union(&current, &inventory(RUNTIME), &changed).is_err());
        Ok(())
    }

    #[test]
    fn integration_moves_once_and_only_the_library_has_two_case_partitions() -> Result<()> {
        let mut prepared = super::super::tests::sample_part("tests")?;
        for kind in ["test", "bin"] {
            prepared.binaries.push(Binary {
                package: "day2".into(),
                target: kind.into(),
                kind: vec![kind.into()],
                directory: "crates/day2".into(),
                executable: format!("build-out/tests/{kind}").into(),
                digest: "unit-fixture".into(),
                permissions: 0o755,
            });
        }
        for value in prepared
            .binaries
            .iter()
            .filter(|value| value.package == "day2")
        {
            let primary = binary(value, "workspace-day2");
            let runtime = binary(value, RUNTIME);
            assert_eq!(
                u8::from(primary) + u8::from(runtime),
                if value.kind == ["lib"] { 2 } else { 1 }
            );
            if value.kind == ["test"] {
                assert!(!primary && runtime);
            }
            if value.kind == ["bin"] {
                assert!(primary && !runtime);
            }
        }
        let mut changed = sample(&prepared, RUNTIME);
        let library = prepared
            .binaries
            .iter()
            .find(|value| value.package == "day2" && value.kind == ["lib"])
            .unwrap();
        changed
            .inventories
            .get_mut(&library.executable)
            .unwrap()
            .library = false;
        assert!(validate(&changed, &prepared, RUNTIME).is_err());
        Ok(())
    }

    #[test]
    fn libtest_inventory_refuses_duplicates_truncation_and_unrecognized_output() -> Result<()> {
        assert_eq!(
            parse("a::case: test\n\n1 test, 0 benchmarks\n")?,
            vec!["a::case"]
        );
        assert!(parse("a: test\na: test\n2 tests, 0 benchmarks\n").is_err());
        assert!(parse("a: test\n").is_err());
        assert!(parse("a: test\n2 tests, 0 benchmarks\n").is_err());
        assert!(parse("a: benchmark\n0 tests, 1 benchmark\n").is_err());
        assert!(parse("1 test, 0 benchmarks\na: test\n").is_err());
        assert!(parse("--ignored: test\n1 test, 0 benchmarks\n").is_err());
        Ok(())
    }

    #[test]
    fn actual_runner_output_cannot_replace_selected_cases_with_zero_or_other_tests() -> Result<()> {
        let mut inventory = inventory("workspace-day2");
        inventory.outcome = Some(execution(
            "test ordinary::new_case ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.01s\n",
            &inventory,
        )?);
        completed(&inventory)?;
        for body in [
            "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.01s\n",
            "test other::case ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.01s\n",
            "test ordinary::new_case ... ok\ntest ordinary::new_case ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.01s\n",
        ] {
            let result = execution(body, &inventory).and_then(|outcome| {
                inventory.outcome = Some(outcome);
                completed(&inventory)
            });
            assert!(result.is_err());
        }
        Ok(())
    }
}
