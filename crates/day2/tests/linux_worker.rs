#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use day2::worker::Worker;
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
