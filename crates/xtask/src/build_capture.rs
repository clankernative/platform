//! Preserve the actual compiler-driver outcome before decoding its evidence.
//! Public diagnostics contain fixed observations and bounded numeric fields,
//! never raw source text, argv or environment values.
use crate::{CommandStatusError, command_status_with_budget};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, io::Read, path::Path, process::Command, time::Duration};

const MAX_CAPTURE: usize = 16 * 1024 * 1024;

/// Advisory counters from the pinned Bazel BEP schema. Missing/default-omitted
/// fields stay unknown. Action requests include spawn-cache hits but exclude
/// local action-cache hits; they are not codegen counts. The counters overlap
/// and must not be added together.
#[derive(Debug, PartialEq, Eq, Serialize)]
struct BuildMetrics {
    wall_time_ms: Option<u64>,
    analysis_time_ms: Option<u64>,
    execution_time_ms: Option<u64>,
    action_requests_including_cache: Option<u64>,
    rustc_requests_including_cache: Option<u64>,
    disk_cache_hit_spawns: Option<u64>,
    local_action_cache_hits: Option<u64>,
    local_action_cache_misses: Option<u64>,
}

fn metric_number(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::String(value)
            if !value.is_empty()
                && value.len() <= 20
                && value.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            value.parse().ok()
        }
        value => value.as_u64(),
    }
}

fn build_metrics(bytes: &[u8]) -> Option<BuildMetrics> {
    if bytes.len() > MAX_CAPTURE {
        return None;
    }
    let mut metrics = None;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let value: Value = day2::json::decode(line).ok()?;
        if value.pointer("/id/buildMetrics").is_none() {
            continue;
        }
        if metrics.is_some() {
            return None;
        }
        let data = value.get("buildMetrics")?.as_object()?;
        let action = data.get("actionSummary");
        let timing = data.get("timingMetrics");
        let number = |value: Option<&Value>, path: &str| {
            metric_number(value.and_then(|value| value.pointer(path)))
        };
        let named = |array: &str, field: &str, name: &str, count: &str| {
            let mut matches = action?
                .get(array)?
                .as_array()?
                .iter()
                .filter(|entry| entry.get(field).and_then(Value::as_str) == Some(name));
            let entry = matches.next()?;
            if matches.next().is_some() {
                return None;
            }
            metric_number(entry.get(count))
        };
        metrics = Some(BuildMetrics {
            wall_time_ms: number(timing, "/wallTimeInMs"),
            analysis_time_ms: number(timing, "/analysisPhaseTimeInMs"),
            execution_time_ms: number(timing, "/executionPhaseTimeInMs"),
            action_requests_including_cache: number(action, "/actionsExecuted"),
            rustc_requests_including_cache: named(
                "actionData",
                "mnemonic",
                "Rustc",
                "actionsExecuted",
            ),
            disk_cache_hit_spawns: named("runnerCount", "name", "disk cache hit", "count"),
            local_action_cache_hits: number(action, "/actionCacheStatistics/hits"),
            local_action_cache_misses: number(action, "/actionCacheStatistics/misses"),
        });
    }
    metrics
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Outcome {
    category: &'static str,
    code: Option<i32>,
    signal: Option<i32>,
    os_error: Option<i32>,
}

impl Outcome {
    fn observe(value: std::result::Result<std::process::ExitStatus, CommandStatusError>) -> Self {
        match value {
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

#[derive(Debug)]
pub(crate) struct Failure {
    pub(crate) process: Outcome,
    capture: Option<&'static str>,
    retained: bool,
    observations: BTreeSet<&'static str>,
    children: BTreeSet<ChildStatus>,
    child_statuses_truncated: bool,
    actions: ActionDiagnostics,
    rust_diagnostics: RustDiagnostics,
    oom_kill_delta: Option<u64>,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Bazel build failed: primary={}, code={:?}, signal={:?}, os_error={:?}; evidence={:?}; retained={}; observations={:?}; children={:?}; child_statuses_truncated={}; actions={:?}; rust_diagnostics={:?}; cgroup_oom_kill_delta={:?}",
            if self.process.category == "success" {
                "capture"
            } else {
                self.process.category
            },
            self.process.code,
            self.process.signal,
            self.process.os_error,
            self.capture,
            self.retained,
            self.observations,
            self.children,
            self.child_statuses_truncated,
            self.actions,
            self.rust_diagnostics,
            self.oom_kill_delta
        )
    }
}

impl std::error::Error for Failure {}

fn read_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_CAPTURE as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn finished(bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= MAX_CAPTURE, "Bazel event capture budget");
    let mut terminal = None;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let value: Value = day2::json::decode(line)?;
        if value.pointer("/id/buildFinished").is_some() {
            ensure!(terminal.is_none(), "duplicate Bazel build-finished event");
            // Protobuf JSON omits the default numeric zero. The hosted Linux
            // build emits {"name":"SUCCESS"}; absence alone is never success.
            let exit = value
                .pointer("/finished/exitCode")
                .context("Bazel exit status required")?;
            let code = exit.get("code").and_then(Value::as_i64);
            terminal = Some(match (exit.get("name").and_then(Value::as_str), code) {
                (Some("SUCCESS"), None | Some(0)) => 0,
                (Some(name), Some(code)) if name != "SUCCESS" && code != 0 => code,
                _ => anyhow::bail!("inconsistent Bazel build-finished exit status"),
            });
        }
    }
    ensure!(
        terminal == Some(0),
        "Bazel successful build-finished event required"
    );
    Ok(())
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct ChildStatus {
    code: Option<i32>,
    signal: Option<u8>,
    metadata_kill_requested: bool,
}

fn child_statuses(bytes: &[u8]) -> BTreeSet<ChildStatus> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter_map(|line| {
            let line = std::str::from_utf8(line)
                .ok()?
                .strip_suffix('\r')
                .unwrap_or(std::str::from_utf8(line).ok()?);
            let fields = line
                .strip_prefix("RR_CHILD_V1 ")?
                .split(' ')
                .collect::<Vec<_>>();
            if fields.len() != 5 {
                return None;
            }
            let get = |index: usize, key: &str| fields[index].strip_prefix(key);
            let code_present = get(0, "code_present=")?;
            let code = get(1, "code=")?.parse::<i32>().ok()?;
            let signal_present = get(2, "signal_present=")?;
            let signal = get(3, "signal=")?.parse::<u8>().ok()?;
            let requested = get(4, "metadata_kill_requested=")?;
            if !["0", "1"].contains(&code_present)
                || !["0", "1"].contains(&signal_present)
                || !["0", "1"].contains(&requested)
            {
                return None;
            }
            if (code_present == "0" && code != 0)
                || (signal_present == "0" && signal != 0)
                || (signal_present == "1" && !(1..=64).contains(&signal))
            {
                return None;
            }
            Some(ChildStatus {
                code: (code_present == "1").then_some(code),
                signal: (signal_present == "1").then_some(signal),
                metadata_kill_requested: requested == "1",
            })
        })
        .collect()
}

/// Advisory fixed markers only. Never export a diagnostic line, source text,
/// path, argument or environment value, and never attribute a kill or OOM.
fn diagnostic_observations(bytes: &[u8]) -> BTreeSet<&'static str> {
    let text = String::from_utf8_lossy(bytes);
    [
        ("No such file or directory", "missing_path"),
        ("Permission denied", "os_access_refused"),
        ("Operation not permitted", "os_access_refused"),
        ("Read-only file system", "read_only_output"),
        ("sandbox_init", "sandbox_initialization"),
        ("sandbox_apply", "sandbox_initialization"),
        ("download is disabled", "offline_download_refused"),
        ("lockfile is no longer up-to-date", "module_lock_changed"),
        ("no such package", "package_not_found"),
        ("no such target", "target_not_found"),
        ("error[E0432]", "rust_unresolved_import"),
        ("error[E0433]", "rust_unresolved_module"),
        ("error[E0463]", "rust_missing_crate"),
        ("error[E0786]", "rust_invalid_metadata"),
        ("error: linking with", "native_link_failed"),
        ("library not found for", "link_library_not_found"),
    ]
    .into_iter()
    .filter_map(|(marker, observation)| text.contains(marker).then_some(observation))
    .collect()
}

const MAX_RUST_DIAGNOSTICS: usize = 16;
const MAX_DIAGNOSTIC_LINE: usize = 128 * 1024;
const MAX_DIAGNOSTIC_CATALOG: usize = 4 * 1024 * 1024;
const MAX_MACRO_LOCATION_DEPTH: usize = 8;

#[derive(Debug, Serialize)]
struct RustDiagnostic {
    code: String,
    location: Option<RustDiagnosticLocation>,
}

#[derive(Debug, Serialize)]
struct RustDiagnosticLocation {
    source: String,
    line: u32,
    column: u32,
    kind: RustLocationKind,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum RustLocationKind {
    Primary,
    MacroCallsite,
}

#[derive(Debug, Serialize)]
struct RustDiagnostics {
    records: Vec<RustDiagnostic>,
    catalog_available: bool,
    input_truncated: bool,
    oversized_lines: usize,
    malformed_json_lines: usize,
    rejected_diagnostics: usize,
    records_truncated: bool,
    unlocated_diagnostics: usize,
    macro_depth_limited: bool,
}

impl RustDiagnostics {
    fn push(&mut self, code: &str, location: Option<RustDiagnosticLocation>) {
        if self.records.len() == MAX_RUST_DIAGNOSTICS {
            self.records_truncated = true;
            return;
        }
        self.records.push(RustDiagnostic {
            code: code.to_owned(),
            location,
        });
    }
}

// The only public paths come from the checked-in architecture catalog, never
// from compiler-owned strings. A missing/invalid catalog exports no locations.
fn diagnostic_sources(bytes: &[u8]) -> Option<BTreeSet<String>> {
    if bytes.len() > MAX_DIAGNOSTIC_CATALOG {
        return None;
    }
    // This is the same bounded persisted-evidence decoder used by the
    // architecture gate, not the smaller application/worker transport decoder.
    let value: Value = day2::json::decode_evidence(bytes).ok()?;
    if value.get("version")?.as_u64()? != 1 {
        return None;
    }
    let sources = value.get("sources")?.as_array()?;
    if sources.is_empty() || sources.len() > 4096 {
        return None;
    }
    sources
        .iter()
        .map(|source| {
            let source = source.as_str()?;
            (source.len() <= 256
                && source.ends_with(".rs")
                && (source.starts_with("crates/")
                    || source.starts_with("cli/checks/")
                    || source == "build.rs")
                && source.split('/').all(|part| {
                    !part.is_empty()
                        && part != "."
                        && part != ".."
                        && part
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
                }))
            .then(|| source.to_owned())
        })
        .collect()
}

// A macro's primary span can be in the private toolchain. Follow only the
// bounded typed callsite chain, exporting a location solely from this catalog.
// No macro name, definition path, source text or whole expansion is copied.
fn diagnostic_location(
    mut span: &Value,
    allowed: &BTreeSet<String>,
) -> (Option<RustDiagnosticLocation>, bool) {
    for depth in 0..MAX_MACRO_LOCATION_DEPTH {
        let source = span
            .get("file_name")
            .and_then(Value::as_str)
            .and_then(|source| allowed.get(source));
        let number = |key| {
            span.get(key)
                .and_then(Value::as_u64)
                .and_then(|number| u32::try_from(number).ok())
                .filter(|number| *number > 0)
        };
        if let (Some(source), Some(line), Some(column)) =
            (source, number("line_start"), number("column_start"))
        {
            return (
                Some(RustDiagnosticLocation {
                    source: source.clone(),
                    line,
                    column,
                    kind: if depth == 0 {
                        RustLocationKind::Primary
                    } else {
                        RustLocationKind::MacroCallsite
                    },
                }),
                false,
            );
        }
        let Some(callsite) = span.pointer("/expansion/span") else {
            return (None, false);
        };
        span = callsite;
    }
    (None, true)
}

// rules_rust's JSON mode preserves the original rustc diagnostic before its
// rendered-message conversion. Coded errors survive even without an admitted
// location; never serialize messages, rendered output, source text or labels.
fn rust_diagnostics(bytes: &[u8], allowed: &BTreeSet<String>) -> RustDiagnostics {
    let mut result = RustDiagnostics {
        records: Vec::new(),
        catalog_available: !allowed.is_empty(),
        input_truncated: bytes.len() > MAX_CAPTURE,
        oversized_lines: 0,
        malformed_json_lines: 0,
        rejected_diagnostics: 0,
        records_truncated: false,
        unlocated_diagnostics: 0,
        macro_depth_limited: false,
    };
    let bytes = &bytes[..bytes.len().min(MAX_CAPTURE)];
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        if result.input_truncated && !line.ends_with(b"\n") {
            break;
        }
        if !line.starts_with(b"{") {
            continue;
        }
        if line.len() > MAX_DIAGNOSTIC_LINE {
            result.oversized_lines += 1;
            continue;
        }
        let Ok(value) = day2::json::decode::<Value>(line) else {
            result.malformed_json_lines += 1;
            continue;
        };
        if value.get("$message_type").and_then(Value::as_str) != Some("diagnostic")
            || value.get("level").and_then(Value::as_str) != Some("error")
        {
            continue;
        }
        let code = value.pointer("/code/code").and_then(Value::as_str);
        let Some(code) = code else {
            result.rejected_diagnostics += 1;
            continue;
        };
        if code.len() != 5
            || !code.starts_with('E')
            || !code.as_bytes()[1..].iter().all(u8::is_ascii_digit)
        {
            result.rejected_diagnostics += 1;
            continue;
        }
        let mut admitted = false;
        for span in value
            .get("spans")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if span.get("is_primary").and_then(Value::as_bool) != Some(true) {
                continue;
            }
            let (location, limited) = diagnostic_location(span, allowed);
            result.macro_depth_limited |= limited;
            if location.is_some() {
                admitted = true;
                result.push(code, location);
            }
        }
        if !admitted {
            result.unlocated_diagnostics += 1;
            result.push(code, None);
        }
    }
    result
}

#[derive(Debug, Serialize)]
struct FailedAction {
    owner: Option<String>,
    kind: &'static str,
    exit_code: Option<i32>,
}

#[derive(Debug, Serialize)]
struct ActionDiagnostics {
    records: Vec<FailedAction>,
    reported_failures: usize,
    catalog_available: bool,
    parse_complete: bool,
    truncated: bool,
    child_signal_attribution: bool,
}

// Export only owners present in the current public platform target catalog.
// BEP messages, paths, command lines and unknown/external labels stay private.
fn action_diagnostics(bytes: &[u8], allowed: &BTreeSet<String>) -> ActionDiagnostics {
    let mut result = ActionDiagnostics {
        records: Vec::new(),
        reported_failures: 0,
        catalog_available: !allowed.is_empty(),
        parse_complete: bytes.len() <= MAX_CAPTURE,
        truncated: false,
        child_signal_attribution: false,
    };
    if !result.parse_complete {
        return result;
    }
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let Ok(value) = day2::json::decode::<Value>(line) else {
            result.parse_complete = false;
            break;
        };
        let Some(action) = value.get("action").and_then(Value::as_object) else {
            continue;
        };
        match action.get("success") {
            Some(Value::Bool(true)) => continue,
            None | Some(Value::Bool(false)) => {}
            _ => {
                result.parse_complete = false;
                continue;
            }
        }
        let Some(id) = value
            .pointer("/id/actionCompleted")
            .and_then(Value::as_object)
        else {
            result.parse_complete = false;
            continue;
        };
        result.reported_failures += 1;
        if result.records.len() == 8 {
            result.truncated = true;
            continue;
        }
        let owner = id.get("label").and_then(Value::as_str).and_then(|label| {
            allowed
                .get(label.strip_prefix("@@").unwrap_or(label))
                .cloned()
        });
        let kind = match action.get("type").and_then(Value::as_str) {
            Some("Rustc") => "rustc",
            Some("RustcClippy") => "clippy",
            Some("CppCompile") => "c_compile",
            Some("CppLink") => "native_link",
            Some("CargoBuildScriptRun") => "build_script",
            _ => "other",
        };
        let exit_code = action
            .get("exitCode")
            .and_then(Value::as_i64)
            .and_then(|code| i32::try_from(code).ok());
        result.records.push(FailedAction {
            owner,
            kind,
            exit_code,
        });
    }
    result
}

fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)?;
    Ok(())
}

fn memory(directory: &Path) -> serde_json::Value {
    let read = |name: &str| -> Option<String> {
        let mut bytes = Vec::new();
        fs::File::open(directory.join(name))
            .ok()?
            .take(4097)
            .read_to_end(&mut bytes)
            .ok()?;
        (bytes.len() <= 4096)
            .then(|| String::from_utf8(bytes).ok())
            .flatten()
    };
    let number = |name: &str| read(name)?.trim().parse::<u64>().ok();
    let events = read("memory.events");
    let event = |name: &str| {
        events.as_ref()?.lines().find_map(|line| {
            let (key, value) = line.split_once(' ')?;
            (key == name).then(|| value.parse::<u64>().ok()).flatten()
        })
    };
    json!({"limit_bytes":number("memory.max"),"current_bytes":number("memory.current"),"peak_bytes":number("memory.peak"),"oom_events":event("oom"),"oom_kills":event("oom_kill"),"cause_attribution":false})
}

fn memory_delta(before: &Value, after: &Value, key: &str) -> Option<u64> {
    let limit = before["limit_bytes"].as_u64().filter(|limit| *limit > 0)?;
    if after["limit_bytes"].as_u64() != Some(limit) {
        return None;
    }
    after[key].as_u64()?.checked_sub(before[key].as_u64()?)
}

fn report(
    root: &Path,
    process: Outcome,
    events: std::io::Result<Vec<u8>>,
    log: &[u8],
    memory_before: Value,
) -> Result<()> {
    let capture = match &events {
        Err(_) => Some("read"),
        Ok(bytes) if bytes.len() > MAX_CAPTURE => Some("budget"),
        Ok(bytes) if finished(bytes).is_err() => Some("events"),
        Ok(_) => None,
    };
    if process.category == "success" && capture.is_none() {
        return Ok(());
    }
    let memory_after = memory(Path::new("/sys/fs/cgroup"));
    let oom_kill_delta = memory_delta(&memory_before, &memory_after, "oom_kills");
    let catalog = crate::bazel::targets(root)
        .map(|targets| targets.into_iter().map(|target| target.label).collect())
        .unwrap_or_default();
    let mut actions = action_diagnostics(events.as_deref().unwrap_or_default(), &catalog);
    actions.parse_complete &= events.is_ok();
    let sources = read_bounded(&root.join("architecture-rules.json"))
        .ok()
        .and_then(|bytes| diagnostic_sources(&bytes))
        .unwrap_or_default();
    let rust_diagnostics = rust_diagnostics(log, &sources);
    let retain = (|| -> Result<()> {
        let base = root.join("artifacts/bazel/failures");
        fs::create_dir_all(&base)?;
        let mut builder = tempfile::Builder::new();
        builder.prefix("build-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(fs::Permissions::from_mode(0o700));
        }
        let directory = builder.tempdir_in(base)?.keep();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        let bytes = events.as_ref().map(Vec::as_slice).unwrap_or_default();
        let manifest = json!({"format":1,"build_process":process,"capture_problem":capture,"captured_bytes":bytes.len(),"retained_bytes":bytes.len().min(MAX_CAPTURE),"complete":bytes.len() <= MAX_CAPTURE && events.is_ok(),"child_statuses":child_statuses(log),"failed_actions":actions,"diagnostic_observations":diagnostic_observations(log),"rust_diagnostics":rust_diagnostics,"cause_attribution":false,"cgroup_memory_before":memory_before,"cgroup_memory_at_failure":memory_after,"cgroup_memory_event_deltas":{"oom_events":memory_delta(&memory_before,&memory_after,"oom_events"),"oom_kills":oom_kill_delta,"cause_attribution":false},"diagnostic_only_not_a_preparation_or_runtime_receipt":true,"raw_retention":"private job-workspace only; never an Actions artifact input"});
        private_write(
            &directory.join("events.jsonl"),
            &bytes[..bytes.len().min(MAX_CAPTURE)],
        )?;
        private_write(
            &directory.join("stderr.bin"),
            &log[..log.len().min(MAX_CAPTURE)],
        )?;
        private_write(
            &directory.join("outcome.json"),
            &serde_json::to_vec_pretty(&manifest)?,
        )?;
        Ok(())
    })();
    let children = child_statuses(log);
    let child_statuses_truncated = children.len() > 8;
    Err(Failure {
        process,
        capture,
        retained: retain.is_ok(),
        observations: diagnostic_observations(log),
        children: children.into_iter().take(8).collect(),
        child_statuses_truncated,
        actions,
        rust_diagnostics,
        oom_kill_delta,
    }
    .into())
}

fn capture(root: &Path, command: &mut Command, budget: Duration, events: &Path) -> Result<()> {
    let stdout = tempfile::NamedTempFile::new()?;
    let stderr = tempfile::NamedTempFile::new()?;
    command
        .stdout(stdout.as_file().try_clone()?)
        .stderr(stderr.as_file().try_clone()?);
    let memory_before = memory(Path::new("/sys/fs/cgroup"));
    let process = Outcome::observe(command_status_with_budget(root, command, budget));
    let output = read_bounded(stdout.path());
    let errors = read_bounded(stderr.path());
    let events = read_bounded(events);
    let metrics = events.as_deref().ok().and_then(build_metrics);
    let result = report(
        root,
        process,
        events,
        errors.as_deref().unwrap_or_default(),
        memory_before,
    );
    // Free-form compiler/Bazel diagnostics remain private local evidence. The
    // public error exports only the actual numeric outcome, fixed classes and
    // bounded coded-error locations from the reviewed source catalog.
    if result.is_ok() {
        ensure!(output.is_ok() && errors.is_ok(), "Bazel log capture failed");
        // Fixed numeric fields only, never the event object, labels, argv or
        // environment. Advisory metrics cannot admit a failed build or replace
        // its existing completion/capture checks. Keep CLI path stdout intact.
        if let Some(metrics) = metrics
            && let Ok(summary) = serde_json::to_string(&metrics)
        {
            eprintln!("BAZEL_BUILD_METRICS_V1 {summary}");
        }
    }
    result
}

pub(crate) fn run(root: &Path, command: &mut Command, budget: Duration) -> Result<()> {
    let events = tempfile::NamedTempFile::new()?;
    // Keep original structured diagnostics inside the existing private capture.
    // The upstream wrapper otherwise replaces them with free-form rendering.
    command.arg("--@rules_rust//rust/settings:error_format=json");
    command.arg(format!(
        "--build_event_json_file={}",
        events.path().display()
    ));
    capture(root, command, budget, events.path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_metrics_never_export_private_event_fields() -> Result<()> {
        let bytes = serde_json::to_vec(&json!({
            "id":{"buildMetrics":{}},
            "buildMetrics":{
                "timingMetrics":{"wallTimeInMs":"1200","analysisPhaseTimeInMs":200,"executionPhaseTimeInMs":"900"},
                "actionSummary":{
                    "actionsExecuted":"12",
                    "actionData":[{"mnemonic":"Rustc","actionsExecuted":"7","commandLine":"PRIVATE-ARGS"}],
                    "runnerCount":[{"name":"disk cache hit","count":5},{"name":"PRIVATE-RUNNER","count":91}],
                    "actionCacheStatistics":{"hits":3,"misses":2},
                    "environment":"PRIVATE-ENV"
                },
                "privatePath":"PRIVATE-PATH"
            }
        }))?;
        let metrics = build_metrics(&bytes).context("fixed numeric metrics")?;
        assert_eq!(metrics.wall_time_ms, Some(1200));
        assert_eq!(metrics.analysis_time_ms, Some(200));
        assert_eq!(metrics.execution_time_ms, Some(900));
        assert_eq!(metrics.action_requests_including_cache, Some(12));
        assert_eq!(metrics.rustc_requests_including_cache, Some(7));
        assert_eq!(metrics.disk_cache_hit_spawns, Some(5));
        assert_eq!(metrics.local_action_cache_hits, Some(3));
        assert_eq!(metrics.local_action_cache_misses, Some(2));
        let public = serde_json::to_value(&metrics)?;
        assert_eq!(public.as_object().context("numeric object")?.len(), 8);
        assert!(public.as_object().unwrap().values().all(Value::is_u64));
        assert!(!public.to_string().contains("PRIVATE"));
        Ok(())
    }

    #[test]
    fn missing_invalid_and_duplicate_metric_counters_remain_unknown() -> Result<()> {
        let bytes = serde_json::to_vec(&json!({
            "id":{"buildMetrics":{}},
            "buildMetrics":{
                "timingMetrics":{"wallTimeInMs":"18446744073709551616","analysisPhaseTimeInMs":-1,"executionPhaseTimeInMs":1.5},
                "actionSummary":{
                    "actionsExecuted":"PRIVATE",
                    "actionData":[{"mnemonic":"Rustc","actionsExecuted":"7"},{"mnemonic":"Rustc","actionsExecuted":"3"}],
                    "runnerCount":[{"name":"disk cache hit","count":5},{"name":"disk cache hit","count":2}]
                }
            }
        }))?;
        let public = serde_json::to_value(build_metrics(&bytes).context("unknown metrics")?)?;
        assert!(public.as_object().unwrap().values().all(Value::is_null));
        let empty = br#"{"id":{"buildMetrics":{}},"buildMetrics":{}}"#;
        let public = serde_json::to_value(build_metrics(empty).context("omitted metrics")?)?;
        assert!(public.as_object().unwrap().values().all(Value::is_null));
        assert!(build_metrics(&vec![b' '; MAX_CAPTURE + 1]).is_none());
        Ok(())
    }

    #[test]
    fn metrics_neither_supply_completion_nor_replace_a_valid_process_outcome() {
        let event =
            br#"{"id":{"buildMetrics":{}},"buildMetrics":{"timingMetrics":{"wallTimeInMs":"12"}}}"#;
        assert!(build_metrics(event).is_some());
        assert!(finished(event).is_err());
        let mut duplicate = event.to_vec();
        duplicate.push(b'\n');
        duplicate.extend_from_slice(event);
        assert!(build_metrics(&duplicate).is_none());
        let mut complete = success_events();
        complete.extend_from_slice(b"\n");
        complete.extend_from_slice(br#"{"id":{"buildMetrics":{}},"buildMetrics":false}"#);
        assert!(build_metrics(&complete).is_none());
        assert!(finished(&complete).is_ok());
        let mut failed = event.to_vec();
        failed.extend_from_slice(
            br#"
{"id":{"buildFinished":{}},"finished":{"exitCode":{"name":"BUILD_FAILURE","code":1}}}"#,
        );
        assert!(build_metrics(&failed).is_some());
        assert!(finished(&failed).is_err());
        assert!(build_metrics(&success_events()).is_none());
    }

    #[test]
    fn public_diagnostics_export_only_fixed_markers_and_bounded_numeric_children() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut log = b"PRIVATE-SDK Permission denied /PRIVATE/ENV=SECRET\n".to_vec();
        for code in 1..=12 {
            log.extend_from_slice(format!("RR_CHILD_V1 code_present=1 code={code} signal_present=0 signal=0 metadata_kill_requested=0\n").as_bytes());
        }
        let error = report(
            root.path(),
            failed(),
            Ok(success_events()),
            &log,
            Value::Null,
        )
        .unwrap_err();
        let display = error.to_string();
        assert!(display.contains("os_access_refused"));
        assert!(display.contains("child_statuses_truncated=true"));
        assert!(!display.contains("PRIVATE") && !display.contains("SECRET"));
        let failure = error.downcast_ref::<Failure>().unwrap();
        assert_eq!(failure.children.len(), 8);
        assert_eq!(failure.process.code, Some(7));
        Ok(())
    }

    #[test]
    fn unknown_private_diagnostics_do_not_create_a_cause_or_escape_the_allowlist() {
        assert!(diagnostic_observations(b"PRIVATE-SDK PRIVATE-ENV PRIVATE-ARGS").is_empty());
        assert_eq!(
            diagnostic_observations(b"PRIVATE sandbox_apply: Operation not permitted"),
            BTreeSet::from(["os_access_refused", "sandbox_initialization"])
        );
        assert_eq!(
            diagnostic_observations(b"error[E0432]: unresolved import PRIVATE"),
            BTreeSet::from(["rust_unresolved_import"])
        );
    }

    fn coded_diagnostic(source: &str) -> Value {
        json!({
            "$message_type":"diagnostic", "level":"error",
            "code":{"code":"E0308","explanation":"PRIVATE-EXPLANATION"},
            "message":"PRIVATE-MESSAGE", "rendered":"PRIVATE-RENDERED",
            "children":[{"message":"PRIVATE-CHILD"}],
            "spans":[{"file_name":source,"is_primary":true,"line_start":17,"column_start":9,
                "text":[{"text":"PRIVATE-SOURCE"}],"label":"PRIVATE-LABEL",
                "expansion":{"span":{"file_name":"PRIVATE-EXPANSION"}}}]
        })
    }

    #[test]
    fn full_current_architecture_catalog_admits_a_coded_error_location() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let bytes = read_bounded(&root.join("architecture-rules.json"))?;
        let sources = diagnostic_sources(&bytes).context("complete reviewed source catalog")?;
        let source = "crates/xtask/src/build_capture.rs";
        assert!(sources.contains(source));
        let summary = rust_diagnostics(&serde_json::to_vec(&coded_diagnostic(source))?, &sources);
        assert!(summary.catalog_available);
        assert_eq!(summary.records.len(), 1);
        assert_eq!(summary.records[0].location.as_ref().unwrap().source, source);
        assert_eq!(summary.records[0].code, "E0308");
        assert!(diagnostic_sources(&vec![b' '; MAX_DIAGNOSTIC_CATALOG + 1]).is_none());
        Ok(())
    }

    #[test]
    fn coded_errors_export_only_reviewed_locations_and_fixed_fields() -> Result<()> {
        let source = "crates/day2/src/lib.rs";
        let allowed = BTreeSet::from([source.to_owned()]);
        let bytes = serde_json::to_vec(&coded_diagnostic(source))?;
        let public = serde_json::to_value(rust_diagnostics(&bytes, &allowed))?;
        assert_eq!(
            public["records"],
            json!([{"code":"E0308","location":{"source":source,"line":17,"column":9,"kind":"primary"}}])
        );
        assert_eq!(public["rejected_diagnostics"], 0);
        assert!(!public.to_string().contains("PRIVATE"));
        let mut warning = coded_diagnostic(source);
        warning["level"] = json!("warning");
        assert!(
            rust_diagnostics(&serde_json::to_vec(&warning)?, &allowed)
                .records
                .is_empty()
        );
        // No alternate normalizer may turn foreign, generated or absolute
        // compiler locations into a reviewed public source name.
        for foreign in [
            "/PRIVATE/lib.rs",
            "../crates/day2/src/lib.rs",
            "./crates/day2/src/lib.rs",
            "external/PRIVATE.rs",
            "crates/day2/src/PRIVATE.rs",
        ] {
            let summary =
                rust_diagnostics(&serde_json::to_vec(&coded_diagnostic(foreign))?, &allowed);
            assert_eq!(summary.records.len(), 1);
            assert_eq!(summary.records[0].code, "E0308");
            assert!(summary.records[0].location.is_none());
            assert_eq!(summary.unlocated_diagnostics, 1);
            assert!(!serde_json::to_string(&summary)?.contains("PRIVATE"));
        }
        Ok(())
    }

    #[test]
    fn invalid_codes_spans_and_catalogs_fail_closed() -> Result<()> {
        let source = "crates/day2/src/lib.rs";
        let allowed = BTreeSet::from([source.to_owned()]);
        for code in [
            json!("E0308-PRIVATE"),
            json!("E12345"),
            json!("E12x4"),
            json!(null),
            json!(308),
        ] {
            let mut diagnostic = coded_diagnostic(source);
            diagnostic["code"]["code"] = code;
            assert!(
                rust_diagnostics(&serde_json::to_vec(&diagnostic)?, &allowed)
                    .records
                    .is_empty()
            );
        }
        for bad in [
            json!(0),
            json!(-1),
            json!(1.5),
            json!(4294967296_u64),
            json!("PRIVATE"),
        ] {
            for key in ["line_start", "column_start"] {
                let mut diagnostic = coded_diagnostic(source);
                diagnostic["spans"][0][key] = bad.clone();
                let summary = rust_diagnostics(&serde_json::to_vec(&diagnostic)?, &allowed);
                assert_eq!(summary.records.len(), 1);
                assert!(summary.records[0].location.is_none());
            }
        }
        let mut secondary = coded_diagnostic(source);
        secondary["spans"][0]["is_primary"] = json!(false);
        let summary = rust_diagnostics(&serde_json::to_vec(&secondary)?, &allowed);
        assert_eq!(summary.records.len(), 1);
        assert!(summary.records[0].location.is_none());
        let sources = diagnostic_sources(&serde_json::to_vec(
            &json!({"version":1,"sources":[source]}),
        )?)
        .unwrap();
        assert_eq!(sources, allowed);
        for bad in [
            json!({"version":2,"sources":[source]}),
            json!({"version":1,"sources":[source,"/PRIVATE.rs"]}),
            json!({"version":1,"sources":[]}),
        ] {
            assert!(diagnostic_sources(&serde_json::to_vec(&bad)?).is_none());
        }
        let unavailable = rust_diagnostics(
            &serde_json::to_vec(&coded_diagnostic(source))?,
            &BTreeSet::new(),
        );
        assert!(!unavailable.catalog_available);
        assert_eq!(unavailable.records.len(), 1);
        assert_eq!(unavailable.records[0].code, "E0308");
        assert!(unavailable.records[0].location.is_none());
        Ok(())
    }

    #[test]
    fn macro_errors_keep_codes_and_only_admitted_bounded_callsite_locations() -> Result<()> {
        let source = "crates/day2/src/lib.rs";
        let allowed = BTreeSet::from([source.to_owned()]);
        // Observed pinned rustc E0277 shape: the primary span is a toolchain
        // macro definition; only its callsite is a reviewed workspace source.
        let mut diagnostic = coded_diagnostic("/PRIVATE/definition.rs");
        diagnostic["code"]["code"] = json!("E0277");
        diagnostic["spans"][0]["expansion"] = json!({
            "span":{"file_name":source,"is_primary":false,"line_start":3,"column_start":13},
            "macro_decl_name":"PRIVATE-MACRO", "def_site_span":{"file_name":"PRIVATE-DEFINITION"}
        });
        let public = serde_json::to_value(rust_diagnostics(
            &serde_json::to_vec(&diagnostic)?,
            &allowed,
        ))?;
        assert_eq!(
            public["records"],
            json!([{"code":"E0277","location":{"source":source,"line":3,"column":13,"kind":"macro_callsite"}}])
        );
        assert!(!public.to_string().contains("PRIVATE"));
        diagnostic["spans"][0]["expansion"]["span"]["file_name"] =
            json!("../crates/day2/src/lib.rs");
        let public = serde_json::to_value(rust_diagnostics(
            &serde_json::to_vec(&diagnostic)?,
            &allowed,
        ))?;
        assert_eq!(public["records"], json!([{"code":"E0277","location":null}]));
        assert_eq!(public["unlocated_diagnostics"], 1);
        assert!(!public.to_string().contains("PRIVATE"));
        let mut nested = json!({"file_name":source,"line_start":3,"column_start":13});
        for _ in 0..MAX_MACRO_LOCATION_DEPTH {
            nested = json!({"file_name":"PRIVATE-DEFINITION","expansion":{"span":nested}});
        }
        nested["is_primary"] = json!(true);
        diagnostic["spans"][0] = nested;
        let summary = rust_diagnostics(&serde_json::to_vec(&diagnostic)?, &allowed);
        assert!(summary.macro_depth_limited);
        assert!(summary.records[0].location.is_none());
        assert_eq!(summary.records[0].code, "E0277");
        Ok(())
    }

    #[test]
    fn compiler_diagnostic_bounds_are_explicit_and_never_export_partial_json() -> Result<()> {
        let source = "crates/day2/src/lib.rs";
        let allowed = BTreeSet::from([source.to_owned()]);
        let mut line = serde_json::to_vec(&coded_diagnostic(source))?;
        line.push(b'\n');
        let summary = rust_diagnostics(&line.repeat(MAX_RUST_DIAGNOSTICS + 1), &allowed);
        assert_eq!(summary.records.len(), MAX_RUST_DIAGNOSTICS);
        assert!(summary.records_truncated);
        let mut oversized = vec![b' '; MAX_DIAGNOSTIC_LINE + 1];
        oversized[0] = b'{';
        oversized.extend_from_slice(b"\n{broken}\n");
        oversized.extend_from_slice(&line);
        let summary = rust_diagnostics(&oversized, &allowed);
        assert_eq!(summary.oversized_lines, 1);
        assert_eq!(summary.malformed_json_lines, 1);
        assert_eq!(summary.records.len(), 1);
        let summary = rust_diagnostics(&vec![b'{'; MAX_CAPTURE + 1], &allowed);
        assert!(summary.input_truncated);
        assert!(summary.records.is_empty());
        Ok(())
    }

    #[test]
    fn failed_build_retains_safe_diagnostics_without_replacing_primary_outcome() -> Result<()> {
        let root = tempfile::tempdir()?;
        let source = "crates/day2/src/lib.rs";
        fs::write(
            root.path().join("architecture-rules.json"),
            serde_json::to_vec(&json!({"version":1,"sources":[source]}))?,
        )?;
        let log = serde_json::to_vec(&coded_diagnostic(source))?;
        let error = report(
            root.path(),
            failed(),
            Ok(success_events()),
            &log,
            Value::Null,
        )
        .unwrap_err();
        let failure = error
            .downcast_ref::<Failure>()
            .context("original typed failure")?;
        assert_eq!(failure.process.code, Some(7));
        assert_eq!(failure.rust_diagnostics.records.len(), 1);
        assert!(!error.to_string().contains("PRIVATE"));
        let directory = fs::read_dir(root.path().join("artifacts/bazel/failures"))?
            .next()
            .context("retained build directory")??
            .path();
        let outcome: Value = day2::json::decode(&fs::read(directory.join("outcome.json"))?)?;
        assert_eq!(outcome["build_process"]["code"], 7);
        assert_eq!(outcome["rust_diagnostics"]["records"][0]["code"], "E0308");
        assert!(!outcome.to_string().contains("PRIVATE"));
        assert!(
            fs::read(directory.join("stderr.bin"))?
                .windows(b"PRIVATE-RENDERED".len())
                .any(|part| part == b"PRIVATE-RENDERED")
        );
        Ok(())
    }

    #[test]
    fn failed_action_diagnostics_expose_only_current_catalog_owners_and_closed_fields() -> Result<()>
    {
        let allowed = BTreeSet::from(["//crates/day2:unit_lib".into()]);
        let mut bytes = Vec::new();
        for (label, kind, success) in [
            ("@@//crates/day2:unit_lib", "Rustc", false),
            ("//PRIVATE:SECRET", "PRIVATE", false),
            ("//crates/day2:unit_lib", "Rustc", true),
        ] {
            bytes.extend(serde_json::to_vec(&json!({
                "id":{"actionCompleted":{"label":label,"primaryOutput":"/PRIVATE/PATH"}},
                "action":{"success":success,"type":kind,"exitCode":1,
                    "commandLine":["PRIVATE-ARGV"],"stderr":{"uri":"file:///PRIVATE"},
                    "failureDetail":{"message":"PRIVATE-ENV"}}
            }))?);
            bytes.push(b'\n');
        }
        let summary = action_diagnostics(&bytes, &allowed);
        assert_eq!(summary.reported_failures, 2);
        assert_eq!(summary.records.len(), 2);
        assert_eq!(
            summary.records[0].owner.as_deref(),
            Some("//crates/day2:unit_lib")
        );
        assert_eq!(summary.records[0].kind, "rustc");
        assert_eq!(summary.records[0].exit_code, Some(1));
        assert_eq!(summary.records[1].owner, None);
        assert_eq!(summary.records[1].kind, "other");
        assert!(!summary.child_signal_attribution);
        assert!(summary.parse_complete);
        assert!(!serde_json::to_string(&summary)?.contains("PRIVATE"));
        Ok(())
    }

    #[test]
    fn failed_action_diagnostics_preserve_limits_multiplicity_and_inconclusive_inputs() -> Result<()>
    {
        let event = serde_json::to_vec(&json!({
            "id":{"actionCompleted":{"label":"//crates/day2:unit_lib"}},
            "action":{"type":"Rustc","exitCode":1}
        }))?;
        let allowed = BTreeSet::from(["//crates/day2:unit_lib".into()]);
        let mut bytes = Vec::new();
        for _ in 0..10 {
            bytes.extend(&event);
            bytes.push(b'\n');
        }
        let summary = action_diagnostics(&bytes, &allowed);
        assert_eq!(summary.reported_failures, 10);
        assert_eq!(summary.records.len(), 8);
        assert!(summary.truncated);
        assert!(summary.parse_complete);
        bytes.extend(b"malformed PRIVATE");
        assert!(!action_diagnostics(&bytes, &allowed).parse_complete);
        let missing = action_diagnostics(&event, &BTreeSet::new());
        assert!(!missing.catalog_available);
        assert_eq!(missing.records[0].owner, None);
        assert!(!action_diagnostics(&vec![b'x'; MAX_CAPTURE + 1], &allowed).parse_complete);
        Ok(())
    }

    #[test]
    fn memory_event_deltas_never_invent_zero_or_identify_a_killed_child() {
        let before = json!({"limit_bytes":6442450944_u64,"oom_kills":3});
        let after = json!({"limit_bytes":6442450944_u64,"oom_kills":4});
        assert_eq!(memory_delta(&before, &after, "oom_kills"), Some(1));
        assert_eq!(memory_delta(&after, &before, "oom_kills"), None);
        assert_eq!(memory_delta(&Value::Null, &after, "oom_kills"), None);
        assert_eq!(
            memory_delta(
                &before,
                &json!({"limit_bytes":1,"oom_kills":4}),
                "oom_kills"
            ),
            None
        );
        assert_eq!(
            memory_delta(&before, &json!({"limit_bytes":6442450944_u64}), "oom_kills"),
            None
        );
    }

    fn failed() -> Outcome {
        Outcome {
            category: "exit",
            code: Some(7),
            signal: None,
            os_error: None,
        }
    }
    fn success_events() -> Vec<u8> {
        serde_json::to_vec(
            &json!({"id":{"buildFinished":{}},"finished":{"exitCode":{"name":"SUCCESS"}}}),
        )
        .unwrap()
    }
    #[test]
    fn nonzero_is_primary_even_with_valid_or_malformed_events() -> Result<()> {
        for events in [success_events(), b"malformed".to_vec()] {
            let root = tempfile::tempdir()?;
            let error = report(root.path(), failed(), Ok(events), b"", Value::Null).unwrap_err();
            assert_eq!(
                error.downcast_ref::<Failure>().unwrap().process.code,
                Some(7)
            );
        }
        Ok(())
    }
    #[test]
    fn success_requires_one_complete_successful_build_event() {
        assert!(finished(&success_events()).is_ok());
        assert!(finished(b"{}").is_err());
        assert!(finished(b"malformed").is_err());
        let mut duplicate = success_events();
        duplicate.push(b'\n');
        duplicate.extend(success_events());
        assert!(finished(&duplicate).is_err());
    }
    #[test]
    fn optional_child_numeric_status_never_replaces_the_outer_process() -> Result<()> {
        let log = b"RR_CHILD_V1 code_present=0 code=0 signal_present=1 signal=9 metadata_kill_requested=0\nPRIVATE RR_CHILD_V1 code_present=1 code=0 signal_present=0 signal=0 metadata_kill_requested=0\n";
        assert_eq!(child_statuses(log).len(), 1);
        let root = tempfile::tempdir()?;
        let error = report(
            root.path(),
            failed(),
            Ok(success_events()),
            log,
            Value::Null,
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<Failure>().unwrap().process.code,
            Some(7)
        );
        assert!(!error.to_string().contains("PRIVATE"));
        Ok(())
    }
    #[test]
    fn capture_and_retention_errors_stay_secondary() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::write(root.path().join("artifacts"), b"not a directory")?;
        let error = report(
            root.path(),
            failed(),
            Err(std::io::Error::from_raw_os_error(5)),
            b"",
            Value::Null,
        )
        .unwrap_err();
        let failure = error.downcast_ref::<Failure>().unwrap();
        assert_eq!(failure.process.code, Some(7));
        assert_eq!(failure.capture, Some("read"));
        assert!(!failure.retained);
        Ok(())
    }
    #[test]
    fn timeout_does_not_invent_an_original_signal() {
        let outcome = Outcome::observe(Err(CommandStatusError::Timeout));
        assert_eq!(outcome.category, "timeout");
        assert_eq!(outcome.code, None);
        assert_eq!(outcome.signal, None);
    }
    fn fixture_command(mode: &str) -> Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "build_capture::tests::real_child_fixture",
                "--nocapture",
            ])
            .env("DAY2_BAZEL_CAPTURE_FIXTURE", mode);
        Ok(command)
    }

    // A subprocess fixture for the controls below, not a separate control.
    #[test]
    fn real_child_fixture() {
        let Ok(mode) = std::env::var("DAY2_BAZEL_CAPTURE_FIXTURE") else {
            return;
        };
        eprintln!("PRIVATE-COMPILER-OUTPUT");
        if mode == "timeout" {
            std::thread::sleep(Duration::from_secs(10));
        }
        std::process::exit(if mode == "success" { 0 } else { 7 });
    }

    #[test]
    fn real_nonzero_is_primary_when_events_are_malformed() -> Result<()> {
        let root = tempfile::tempdir()?;
        let events = root.path().join("events");
        fs::write(&events, b"malformed")?;
        let error = capture(
            root.path(),
            &mut fixture_command("failure")?,
            Duration::from_secs(3),
            &events,
        )
        .unwrap_err();
        let failure = error
            .downcast_ref::<Failure>()
            .context("typed process outcome")?;
        assert_eq!(failure.process.category, "exit");
        assert_eq!(failure.process.code, Some(7));
        assert_eq!(failure.capture, Some("events"));
        assert!(failure.retained);
        assert!(!error.to_string().contains("PRIVATE"));

        // Even valid success events and useful metrics cannot override the
        // genuine nonzero child. Exercise the same capture/report wiring.
        let events = root.path().join("metric-events");
        let mut bytes = success_events();
        bytes.extend_from_slice(
            br#"
{"id":{"buildMetrics":{}},"buildMetrics":{"timingMetrics":{"wallTimeInMs":"12"}}}"#,
        );
        private_write(&events, &bytes)?;
        let error = capture(
            root.path(),
            &mut fixture_command("failure")?,
            Duration::from_secs(3),
            &events,
        )
        .unwrap_err();
        let failure = error
            .downcast_ref::<Failure>()
            .context("real child outcome")?;
        assert_eq!(failure.process.category, "exit");
        assert_eq!(failure.process.code, Some(7));
        assert_eq!(failure.capture, None);
        Ok(())
    }

    #[test]
    fn real_success_cannot_admit_malformed_events() -> Result<()> {
        let root = tempfile::tempdir()?;
        let events = root.path().join("events");
        fs::write(&events, b"malformed")?;
        let error = capture(
            root.path(),
            &mut fixture_command("success")?,
            Duration::from_secs(3),
            &events,
        )
        .unwrap_err();
        let failure = error
            .downcast_ref::<Failure>()
            .context("typed process outcome")?;
        assert_eq!(failure.process.category, "success");
        assert_eq!(failure.process.code, Some(0));
        assert!(error.to_string().contains("primary=capture"));
        Ok(())
    }

    #[test]
    fn real_timeout_remains_primary_without_an_invented_signal() -> Result<()> {
        let root = tempfile::tempdir()?;
        let events = root.path().join("events");
        fs::write(&events, b"")?;
        let started = std::time::Instant::now();
        let error = capture(
            root.path(),
            &mut fixture_command("timeout")?,
            Duration::from_millis(100),
            &events,
        )
        .unwrap_err();
        let failure = error
            .downcast_ref::<Failure>()
            .context("typed process outcome")?;
        assert_eq!(failure.process.category, "timeout");
        assert_eq!(failure.process.signal, None);
        assert!(started.elapsed() < Duration::from_secs(5));
        Ok(())
    }

    #[test]
    fn real_spawn_failure_retains_errno_without_the_command_path() -> Result<()> {
        let root = tempfile::tempdir()?;
        let error = capture(
            root.path(),
            &mut Command::new(root.path().join("PRIVATE-MISSING")),
            Duration::from_secs(1),
            &root.path().join("events"),
        )
        .unwrap_err();
        let failure = error
            .downcast_ref::<Failure>()
            .context("typed process outcome")?;
        assert_eq!(failure.process.category, "spawn");
        assert!(failure.process.os_error.is_some());
        assert!(!error.to_string().contains("PRIVATE"));
        Ok(())
    }

    #[test]
    fn protobuf_defaults_require_an_explicit_consistent_success_name() {
        for exit in [
            json!({}),
            json!({"code":0}),
            json!({"name":"SUCCESS","code":1}),
            json!({"name":"BUILD_FAILURE","code":0}),
        ] {
            let bytes = serde_json::to_vec(
                &json!({"id":{"buildFinished":{}},"finished":{"exitCode":exit}}),
            )
            .unwrap();
            assert!(finished(&bytes).is_err());
        }
        let explicit = serde_json::to_vec(
            &json!({"id":{"buildFinished":{}},"finished":{"exitCode":{"name":"SUCCESS","code":0}}}),
        )
        .unwrap();
        assert!(finished(&explicit).is_ok());
    }

    #[test]
    fn status_parser_refuses_free_text_and_out_of_range_signals() {
        for line in [
            "RR_CHILD_V1 code_present=0 code=1 signal_present=0 signal=0 metadata_kill_requested=0",
            "RR_CHILD_V1 code_present=0 code=0 signal_present=1 signal=65 metadata_kill_requested=0",
            "RR_CHILD_V1 code_present=1 code=7 signal_present=0 signal=0 metadata_kill_requested=0 PRIVATE",
        ] {
            assert!(child_statuses(line.as_bytes()).is_empty());
        }
    }

    #[test]
    fn bounded_private_evidence_never_claims_complete_oversized_capture() -> Result<()> {
        let root = tempfile::tempdir()?;
        report(
            root.path(),
            failed(),
            Ok(vec![b'x'; MAX_CAPTURE + 1]),
            b"PRIVATE",
            Value::Null,
        )
        .unwrap_err();
        let directory = fs::read_dir(root.path().join("artifacts/bazel/failures"))?
            .next()
            .context("retained failure")??
            .path();
        let manifest: Value = day2::json::decode(&fs::read(directory.join("outcome.json"))?)?;
        assert_eq!(manifest["complete"], false);
        assert_eq!(manifest["retained_bytes"], MAX_CAPTURE);
        assert_eq!(
            fs::metadata(directory.join("events.jsonl"))?.len(),
            MAX_CAPTURE as u64
        );
        assert!(!manifest.to_string().contains("PRIVATE"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(directory.join("events.jsonl"))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&directory)?.permissions().mode() & 0o777,
                0o700
            );
        }
        Ok(())
    }

    #[test]
    fn memory_diagnostics_are_optional_numeric_kernel_facts() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::write(root.path().join("memory.max"), b"6442450944")?;
        fs::write(root.path().join("memory.current"), b"1234")?;
        fs::write(root.path().join("memory.peak"), b"PRIVATE")?;
        fs::write(
            root.path().join("memory.events"),
            b"oom 2\noom_kill 1\nPRIVATE",
        )?;
        let value = memory(root.path());
        assert_eq!(value["limit_bytes"], 6442450944_u64);
        assert_eq!(value["current_bytes"], 1234);
        assert!(value["peak_bytes"].is_null());
        assert_eq!(value["oom_events"], 2);
        assert_eq!(value["oom_kills"], 1);
        assert_eq!(value["cause_attribution"], false);
        assert!(!value.to_string().contains("PRIVATE"));
        Ok(())
    }

    #[test]
    fn successful_complete_build_creates_no_failure_receipt() -> Result<()> {
        let root = tempfile::tempdir()?;
        let process = Outcome {
            category: "success",
            code: Some(0),
            signal: None,
            os_error: None,
        };
        report(root.path(), process, Ok(success_events()), b"", Value::Null)?;
        assert!(!root.path().join("artifacts").exists());
        Ok(())
    }
}
