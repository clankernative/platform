#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use day2::{properties, worker::Worker};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

fn start() -> Result<Worker> {
    let executable = std::env::current_exe()?;
    let directory = executable
        .parent()
        .and_then(|path| path.parent())
        .context("test binary directory")?;
    Worker::start_with_trusted_launcher(
        &directory.join("day2-sandbox-probe"),
        &directory.join("day2-sandbox"),
    )
}

fn process(worker: &mut Worker) -> Result<PathBuf> {
    let id = String::from_utf8(worker.exchange(b"pid")?)?.parse::<u32>()?;
    let path = PathBuf::from(format!("/proc/{id}"));
    ensure!(path.exists(), "worker did not start");
    Ok(path)
}

#[test]
fn qualified_worker_exchanges_frames_and_drop_reaps_it() -> Result<()> {
    let mut worker = start()?;
    let path = process(&mut worker)?;
    ensure!(worker.exchange(b"qualify")? == day2_sandbox::QUALIFIED);
    for value in ["first", "second", "", "final"] {
        ensure!(worker.exchange(format!("echo {value}").as_bytes())? == value.as_bytes());
    }
    drop(worker);
    ensure!(!path.exists(), "dropped worker was not reaped");
    Ok(())
}

#[test]
fn timeout_eof_oversize_and_bad_input_poison_and_reap_worker() -> Result<()> {
    let mut cases = vec![
        b"spin".to_vec(),
        b"exit".to_vec(),
        b"oversize".to_vec(),
        b"bad\nframe".to_vec(),
    ];
    cases.push(vec![b'x'; 1_048_576]);
    for input in cases {
        let mut worker = start()?;
        let path = process(&mut worker)?;
        let started = Instant::now();
        ensure!(
            worker.exchange(&input).is_err(),
            "invalid exchange unexpectedly succeeded"
        );
        ensure!(
            started.elapsed() < Duration::from_secs(5),
            "worker cleanup exceeded deadline"
        );
        ensure!(
            !path.exists(),
            "failed worker was not reaped before returning"
        );
        ensure!(
            worker.exchange(b"echo must-not-reuse").is_err(),
            "poisoned worker was reused"
        );
    }
    Ok(())
}

#[test]
fn property_worker_uses_qualified_limits_and_keeps_invocation_profile_unchanged() -> Result<()> {
    let executable = std::env::current_exe()?;
    let directory = executable
        .parent()
        .and_then(|path| path.parent())
        .context("test binary directory")?;
    let probe = directory.join("day2-sandbox-probe");
    let launcher = directory.join("day2-sandbox");

    let mut ordinary = Worker::start_with_trusted_launcher(&probe, &launcher)?;
    ensure!(
        ordinary
            .exchange_bounded(
                b"limits",
                properties::MAX_PROPERTY_FRAME,
                Duration::from_secs(3)
            )
            .is_err(),
        "ordinary worker admitted the property frame profile"
    );
    ensure!(
        ordinary
            .exchange_bounded(b"limits", 1_048_576, Duration::from_secs(4))
            .is_err(),
        "ordinary worker admitted a longer timeout"
    );
    ensure!(ordinary.exchange(b"limits")? == b"268435456,5");
    ensure!(ordinary.exchange(b"reserve 314572800")? == b"denied");
    ensure!(
        ordinary.exchange(b"oversize").is_err(),
        "ordinary response limit changed"
    );

    let mut qualified = Worker::start_verification(
        &probe,
        512 * 1024 * 1024,
        Duration::from_secs(30),
        properties::MAX_PROPERTY_FRAME,
    )?;
    ensure!(
        qualified
            .exchange_bounded(
                b"limits",
                properties::MAX_PROPERTY_FRAME,
                Duration::from_secs(31)
            )
            .is_err(),
        "property worker admitted a longer timeout"
    );
    ensure!(qualified.exchange(b"limits")? == b"536870912,30");
    ensure!(qualified.exchange(b"reserve 629145600")? == b"denied");
    let response = qualified.exchange_bounded(
        b"oversize",
        properties::MAX_PROPERTY_FRAME,
        Duration::from_secs(3),
    )?;
    ensure!(
        response.len() == 1_048_577,
        "qualified response frame was truncated"
    );

    let started = Instant::now();
    ensure!(
        qualified
            .exchange_bounded(
                b"spin",
                properties::MAX_PROPERTY_FRAME,
                Duration::from_millis(100),
            )
            .is_err(),
        "qualified evaluation timeout was not enforced"
    );
    ensure!(
        started.elapsed() < Duration::from_secs(3),
        "timeout cleanup exceeded bound"
    );
    Ok(())
}

#[test]
fn missing_launcher_never_falls_back_to_direct_execution() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    ensure!(
        Worker::start_with_trusted_launcher(
            &std::env::current_exe()?,
            &temporary.path().join("absent-launcher")
        )
        .is_err()
    );
    Ok(())
}
