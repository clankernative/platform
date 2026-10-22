//! Preserve the actual compiler-driver outcome before decoding its evidence.
//! Diagnostics contain fixed numeric fields, never argv or environment values.
use crate::{CommandStatusError, command_status_with_budget};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, io::Read, path::Path, process::Command, time::Duration};

const MAX_CAPTURE: usize = 16 * 1024 * 1024;

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
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Bazel build failed: primary={}, code={:?}, signal={:?}, os_error={:?}; evidence={:?}; retained={}",
            if self.process.category == "success" {
                "capture"
            } else {
                self.process.category
            },
            self.process.code,
            self.process.signal,
            self.process.os_error,
            self.capture,
            self.retained
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
    json!({"limit_bytes":number("memory.max"),"peak_bytes":number("memory.peak"),"oom_events":event("oom"),"oom_kills":event("oom_kill"),"cause_attribution":false})
}

fn report(
    root: &Path,
    process: Outcome,
    events: std::io::Result<Vec<u8>>,
    log: &[u8],
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
        let manifest = json!({"format":1,"build_process":process,"capture_problem":capture,"captured_bytes":bytes.len(),"retained_bytes":bytes.len().min(MAX_CAPTURE),"complete":bytes.len() <= MAX_CAPTURE && events.is_ok(),"child_statuses":child_statuses(log),"cause_attribution":false,"cgroup_memory_at_failure":memory(Path::new("/sys/fs/cgroup")),"diagnostic_only_not_a_preparation_or_runtime_receipt":true,"raw_retention":"private job-workspace only; never an Actions artifact input"});
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
    Err(Failure {
        process,
        capture,
        retained: retain.is_ok(),
    }
    .into())
}

fn capture(root: &Path, command: &mut Command, budget: Duration, events: &Path) -> Result<()> {
    let stdout = tempfile::NamedTempFile::new()?;
    let stderr = tempfile::NamedTempFile::new()?;
    command
        .stdout(stdout.as_file().try_clone()?)
        .stderr(stderr.as_file().try_clone()?);
    let process = Outcome::observe(command_status_with_budget(root, command, budget));
    let output = read_bounded(stdout.path());
    let errors = read_bounded(stderr.path());
    let result = report(
        root,
        process,
        read_bounded(events),
        errors.as_deref().unwrap_or_default(),
    );
    // Free-form compiler/Bazel diagnostics remain private local evidence. The
    // public error exports only the actual numeric outcome and fixed classes.
    if result.is_ok() {
        ensure!(output.is_ok() && errors.is_ok(), "Bazel log capture failed");
    }
    result
}

pub(crate) fn run(root: &Path, command: &mut Command, budget: Duration) -> Result<()> {
    let events = tempfile::NamedTempFile::new()?;
    command.arg(format!(
        "--build_event_json_file={}",
        events.path().display()
    ));
    capture(root, command, budget, events.path())
}

#[cfg(test)]
mod tests {
    use super::*;
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
            let error = report(root.path(), failed(), Ok(events), b"").unwrap_err();
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
        let error = report(root.path(), failed(), Ok(success_events()), log).unwrap_err();
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
        fs::write(root.path().join("memory.peak"), b"PRIVATE")?;
        fs::write(
            root.path().join("memory.events"),
            b"oom 2\noom_kill 1\nPRIVATE",
        )?;
        let value = memory(root.path());
        assert_eq!(value["limit_bytes"], 6442450944_u64);
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
        report(root.path(), process, Ok(success_events()), b"")?;
        assert!(!root.path().join("artifacts").exists());
        Ok(())
    }
}
