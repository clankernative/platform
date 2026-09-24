//! Bounded direct execution for trusted platform tools. No shell, caller-supplied
//! environment, arbitrary executable names or unbounded captured pipes.
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub fn run(command: &mut Command, directory: &Path, log: &Path, timeout: Duration) -> Result<()> {
    supervised(command, directory, log, timeout, None)
}

pub fn run_cancellable(
    command: &mut Command,
    directory: &Path,
    log: &Path,
    timeout: Duration,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<()> {
    supervised(command, directory, log, timeout, Some(cancelled))
}

fn supervised(
    command: &mut Command,
    directory: &Path,
    log: &Path,
    timeout: Duration,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::process::CommandExt;
    let output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(log)?;
    command
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(output)
        .process_group(0);
    let mut child = command.spawn().context("start platform tool")?;
    let pid = rustix::process::Pid::from_raw(child.id() as i32).context("child process group")?;
    let start = Instant::now();
    let outcome = (|| -> Result<_> {
        loop {
            ensure!(
                !cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::SeqCst)),
                "local build cancelled"
            );
            ensure!(
                fs::metadata(log)?.len() <= 8 * 1024 * 1024,
                "tool log budget exceeded"
            );
            if let Some(status) = child.try_wait()? {
                return Ok(status);
            }
            ensure!(start.elapsed() < timeout, "tool deadline exceeded");
            std::thread::sleep(Duration::from_millis(25));
        }
    })();
    // Reap the group on both success and failure, including descendants left by
    // a completed parent. This is supervision of trusted tools, not containment
    // of a hostile process that creates a new session.
    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    let _ = child.kill();
    let _ = child.wait();
    let status =
        outcome.with_context(|| format!("platform tool failed; log: {}", log.display()))?;
    ensure!(
        status.success(),
        "platform tool exited {status}; log: {}",
        log.display()
    );
    Ok(())
}
