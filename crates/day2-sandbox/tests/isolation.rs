#![cfg(target_os = "linux")]

use std::{
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn launcher(worker: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_day2-sandbox"));
    command
        .arg(worker)
        .arg(std::process::id().to_string())
        .arg(day2_sandbox::ADDRESS_SPACE_BYTES.to_string())
        .arg(day2_sandbox::CPU_SECONDS.to_string())
        .env("DAY2_SANDBOX_SECRET", "must-not-be-inherited")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn bounded_wait(child: &mut Child) -> std::io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "sandbox probe exceeded outer deadline",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn real_linux_denials_and_approved_reads_are_enforced() -> anyhow::Result<()> {
    let secret = tempfile::tempdir()?;
    let secret_file = secret.path().join("secret");
    let forbidden_file = secret.path().join("new-file");
    std::fs::write(&secret_file, b"private host bytes")?;
    let inherited = std::fs::File::open(&secret_file)?;
    nix::fcntl::fcntl(
        &inherited,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )?;
    let spawned = launcher(Path::new(env!("CARGO_BIN_EXE_day2-sandbox-probe"))).spawn();
    nix::fcntl::fcntl(
        &inherited,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
    )?;
    let mut child = spawned?;
    {
        let mut input = child.stdin.take().unwrap();
        writeln!(
            input,
            "qualify\nread {}\nwrite {}\necho protocol-ok",
            secret_file.display(),
            forbidden_file.display()
        )?;
    }
    let status = bounded_wait(&mut child)?;
    let output = child.wait_with_output()?;
    anyhow::ensure!(
        status.success(),
        "sandbox qualification failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    anyhow::ensure!(
        output.stdout == [day2_sandbox::QUALIFIED, b"\ndenied\ndenied\nprotocol-ok\n"].concat(),
        "unexpected sandbox output"
    );
    anyhow::ensure!(!forbidden_file.exists(), "sandbox created forbidden file");
    anyhow::ensure!(std::fs::read(secret_file)? == b"private host bytes");
    Ok(())
}

#[test]
fn hard_cpu_limit_terminates_nontermination() -> anyhow::Result<()> {
    use std::os::unix::process::ExitStatusExt;
    let mut child = launcher(Path::new(env!("CARGO_BIN_EXE_day2-sandbox-probe"))).spawn()?;
    let mut input = child.stdin.take().unwrap();
    writeln!(input, "pid\nspin")?;
    drop(input);
    let status = bounded_wait(&mut child)?;
    anyhow::ensure!(
        status.signal() == Some(nix::libc::SIGKILL),
        "CPU hard limit did not terminate worker: {status}"
    );
    let pid = child.id();
    let output = child.wait_with_output()?;
    anyhow::ensure!(
        String::from_utf8(output.stdout)?.trim().parse::<u32>()? == pid,
        "launcher did not replace itself with the worker"
    );
    Ok(())
}

#[test]
fn unexpected_arguments_and_parent_identity_fail_before_execution() -> anyhow::Result<()> {
    let probe = Path::new(env!("CARGO_BIN_EXE_day2-sandbox-probe"));
    let output = launcher(probe).arg("extra-policy").output()?;
    anyhow::ensure!(output.status.code() == Some(77));
    let report = day2_sandbox::RefusalReport::parse(output.stdout.strip_suffix(b"\n").unwrap_or(&output.stdout))
        .ok_or_else(|| anyhow::anyhow!("missing numeric refusal"))?;
    anyhow::ensure!(report.stage == day2_sandbox::RefusalStage::Arguments as u8);
    let output = Command::new(env!("CARGO_BIN_EXE_day2-sandbox"))
        .arg(probe)
        .arg("0")
        .arg(day2_sandbox::ADDRESS_SPACE_BYTES.to_string())
        .arg(day2_sandbox::CPU_SECONDS.to_string())
        .output()?;
    anyhow::ensure!(output.status.code() == Some(77));
    let report = day2_sandbox::RefusalReport::parse(output.stdout.strip_suffix(b"\n").unwrap_or(&output.stdout))
        .ok_or_else(|| anyhow::anyhow!("missing numeric refusal"))?;
    anyhow::ensure!(report.stage == day2_sandbox::RefusalStage::ParentIdentity as u8);
    Ok(())
}

#[test]
fn regular_file_stdio_and_mutable_worker_fail_before_execution() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    let output_file = directory.path().join("not-a-protocol-pipe");
    let output = launcher(Path::new(env!("CARGO_BIN_EXE_day2-sandbox-probe")))
        .stdout(std::fs::File::create(&output_file)?)
        .output()?;
    anyhow::ensure!(output.status.code() == Some(77));
    anyhow::ensure!(std::fs::read(&output_file)?.is_empty());
    let report = day2_sandbox::RefusalReport::parse(output.stderr.strip_suffix(b"\n").unwrap_or(&output.stderr))
        .ok_or_else(|| anyhow::anyhow!("missing numeric descriptor refusal"))?;
    anyhow::ensure!(report.stage == day2_sandbox::RefusalStage::StandardDescriptors as u8);
    let worker = directory.path().join("mutable-worker");
    std::fs::copy(env!("CARGO_BIN_EXE_day2-sandbox-probe"), &worker)?;
    std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o777))?;
    let output = launcher(&worker).output()?;
    anyhow::ensure!(output.status.code() == Some(77));
    let report = day2_sandbox::RefusalReport::parse(output.stdout.strip_suffix(b"\n").unwrap_or(&output.stdout))
        .ok_or_else(|| anyhow::anyhow!("missing numeric refusal"))?;
    anyhow::ensure!(report.stage == day2_sandbox::RefusalStage::WorkerMode as u8);
    Ok(())
}

#[test]
fn missing_worker_and_unreviewed_profile_report_distinct_refusals() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let missing = tempfile::tempdir()?;
    let output = launcher(&missing.path().join("PRIVATE_MISSING_WORKER")).output()?;
    anyhow::ensure!(output.status.code() == Some(77));
    let report = day2_sandbox::RefusalReport::parse(output.stdout.strip_suffix(b"\n").unwrap_or(&output.stdout))
        .ok_or_else(|| anyhow::anyhow!("missing numeric refusal"))?;
    anyhow::ensure!(report.stage == day2_sandbox::RefusalStage::ResolveWorker as u8 && report.errno == Some(2));
    anyhow::ensure!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE"));
    let output = Command::new(env!("CARGO_BIN_EXE_day2-sandbox"))
        .arg(env!("CARGO_BIN_EXE_day2-sandbox-probe"))
        .arg(std::process::id().to_string())
        .arg("1")
        .arg("1")
        .stdout(Stdio::piped())
        .output()?;
    anyhow::ensure!(output.status.code() == Some(77));
    let report = day2_sandbox::RefusalReport::parse(output.stdout.strip_suffix(b"\n").unwrap_or(&output.stdout))
        .ok_or_else(|| anyhow::anyhow!("missing numeric refusal"))?;
    anyhow::ensure!(report.stage == day2_sandbox::RefusalStage::Profile as u8 && report.errno.is_none());
    // Reach the exec handoff only after the ordinary confinement checks. The
    // reported OS error may describe invalid ELF or refused shell fallback;
    // assert the actual numeric evidence, never guess a particular errno.
    let invalid = missing.path().join("PRIVATE_INVALID_EXECUTABLE");
    std::fs::write(&invalid, b"PRIVATE_NOT_A_NATIVE_IMAGE")?;
    std::fs::set_permissions(&invalid, std::fs::Permissions::from_mode(0o500))?;
    let output = launcher(&invalid).output()?;
    anyhow::ensure!(output.status.code() == Some(77));
    let report = day2_sandbox::RefusalReport::parse(output.stdout.strip_suffix(b"\n").unwrap_or(&output.stdout))
        .ok_or_else(|| anyhow::anyhow!("missing numeric confined exec refusal"))?;
    anyhow::ensure!(report.stage == day2_sandbox::RefusalStage::ExecuteWorker as u8 && report.errno.is_some());
    anyhow::ensure!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE") && output.stderr.is_empty());
    Ok(())
}

#[test]
fn parent_death_kills_worker_before_cpu_deadline() -> anyhow::Result<()> {
    let mut parent = Command::new(std::env::current_exe()?)
        .args(["--exact", "parent_fixture", "--nocapture"])
        .env("DAY2_PARENT_FIXTURE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = parent.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if let Ok(line) = line
                && let Some(pid) = line.strip_prefix("WORKER_PID=")
            {
                let _ = sender.send(pid.parse::<i32>());
                break;
            }
        }
    });
    let pid = receiver.recv_timeout(Duration::from_secs(5));
    let _ = parent.kill();
    let _ = parent.wait();
    reader.join().unwrap();
    let pid = pid??;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let status = std::fs::read_to_string(format!("/proc/{pid}/stat"));
        if status
            .as_ref()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            || status.as_ref().is_ok_and(|text| {
                text.rsplit_once(") ")
                    .is_some_and(|(_, state)| state.starts_with('Z'))
            })
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
            anyhow::bail!("worker survived supervisor death");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn parent_fixture() -> anyhow::Result<()> {
    if std::env::var("DAY2_PARENT_FIXTURE").as_deref() != Ok("1") {
        return Ok(());
    }
    let mut child = launcher(Path::new(env!("CARGO_BIN_EXE_day2-sandbox-probe"))).spawn()?;
    let mut input = child.stdin.take().unwrap();
    writeln!(input, "pid")?;
    input.flush()?;
    let mut pid = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut pid)?;
    anyhow::ensure!(pid.trim().parse::<u32>()? == child.id());
    writeln!(input, "spin")?;
    input.flush()?;
    println!("WORKER_PID={}", child.id());
    std::io::stdout().flush()?;
    let mut barrier = String::new();
    std::io::stdin().read_line(&mut barrier)?;
    let _ = child.kill();
    let _ = child.wait();
    anyhow::bail!("parent fixture should be killed before stdin closes")
}
