#![cfg(target_os = "linux")]

use std::{
    io::{BufRead, BufReader, Read, Write},
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

const BUSY_OBSERVATION: &[u8] = b"day2 sandbox waiting for executable writers\n";

/// Own/reap the actual probe and join its bounded stderr reader on every path.
struct BusyProbe {
    child: Child,
    first_line: std::sync::mpsc::Receiver<Vec<u8>>,
    stderr: Option<std::thread::JoinHandle<std::io::Result<Vec<u8>>>>,
}

impl BusyProbe {
    fn start(path: &Path) -> anyhow::Result<Self> {
        let mut child = launcher(path).spawn()?;
        let stderr = child.stderr.take().unwrap();
        let (first, first_line) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::Builder::new()
            .name("sandbox-handoff-observation".into())
            .spawn(move || {
                let mut source = BufReader::new(stderr).take(4096);
                let mut bytes = Vec::new();
                source.read_until(b'\n', &mut bytes)?;
                let _ = first.send(bytes.clone());
                source.read_to_end(&mut bytes)?;
                Ok(bytes)
            });
        let reader = match reader {
            Ok(reader) => reader,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
        };
        Ok(Self {
            child,
            first_line,
            stderr: Some(reader),
        })
    }

    fn await_busy(&mut self) -> anyhow::Result<()> {
        let line = self.first_line.recv_timeout(Duration::from_secs(8))?;
        let status = self.child.try_wait()?;
        anyhow::ensure!(
            line == BUSY_OBSERVATION,
            "not a text-busy handoff: first bounded stderr {:?}; observed child status {status:?}",
            String::from_utf8_lossy(&line)
        );
        anyhow::ensure!(status.is_none(), "handoff already exited");
        Ok(())
    }

    fn finish(&mut self) -> anyhow::Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>)> {
        let status = bounded_wait(&mut self.child)?;
        let mut stdout = Vec::new();
        self.child
            .stdout
            .take()
            .unwrap()
            .take(256)
            .read_to_end(&mut stdout)?;
        let stderr = self.stderr.take().unwrap().join().expect("stderr reader")?;
        Ok((status, stdout, stderr))
    }
}

impl Drop for BusyProbe {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.stderr.take() {
            let _ = reader.join();
        }
    }
}

fn held_executable() -> anyhow::Result<(tempfile::TempDir, tempfile::NamedTempFile)> {
    use std::os::unix::fs::PermissionsExt;
    let probe = Path::new(env!("CARGO_BIN_EXE_day2-sandbox-probe"));
    // The fault image needs the probe's executable mount. A default temporary
    // directory may be mounted noexec, which refuses before the writer check.
    let directory = tempfile::tempdir_in(
        probe
            .parent()
            .ok_or_else(|| anyhow::anyhow!("sandbox probe has no parent directory"))?,
    )?;
    let mut writer = tempfile::NamedTempFile::new_in(directory.path())?;
    writer.write_all(&std::fs::read(probe)?)?;
    writer
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o500))?;
    Ok((directory, writer))
}

#[test]
fn a_released_executable_writer_hands_off_once_in_the_same_confined_process() -> anyhow::Result<()>
{
    let (_directory, writer) = held_executable()?;
    let mut probe = BusyProbe::start(writer.path())?;
    let pid = probe.child.id();
    let mut input = probe.child.stdin.take().unwrap();
    writeln!(input, "qualify\npid\nexit")?;
    drop(input);
    probe.await_busy()?;
    // Release the actual write description only after the child observes the
    // kernel refusal. Keeping the TempPath also keeps the exact image alive.
    let executable = writer.into_temp_path();
    let (status, stdout, stderr) = probe.finish()?;
    anyhow::ensure!(status.success(), "released handoff did not execute");
    anyhow::ensure!(
        stdout
            == [
                day2_sandbox::QUALIFIED,
                b"\n",
                pid.to_string().as_bytes(),
                b"\n"
            ]
            .concat(),
        "handoff did not execute once in the original confined process"
    );
    anyhow::ensure!(stderr == BUSY_OBSERVATION, "unexpected handoff observation");
    drop(executable);
    Ok(())
}

#[test]
fn a_retained_executable_writer_expires_without_executing_the_probe() -> anyhow::Result<()> {
    let (_directory, writer) = held_executable()?;
    let mut probe = BusyProbe::start(writer.path())?;
    let mut input = probe.child.stdin.take().unwrap();
    writeln!(input, "pid\nexit")?;
    drop(input);
    probe.await_busy()?;
    let (status, stdout, stderr) = probe.finish()?;
    anyhow::ensure!(status.code() == Some(77) && stdout.is_empty());
    let stderr = String::from_utf8(stderr)?;
    anyhow::ensure!(
        stderr
            .matches(std::str::from_utf8(BUSY_OBSERVATION)?)
            .count()
            == 1
    );
    anyhow::ensure!(stderr.contains("worker exec handoff deadline expired"));
    drop(writer);
    Ok(())
}

#[test]
fn another_exec_error_never_enters_the_writer_wait() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut writer = tempfile::NamedTempFile::new()?;
    writer.write_all(b"not an executable image")?;
    writer
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o500))?;
    let executable = writer.into_temp_path();
    let output = launcher(&executable).output()?;
    anyhow::ensure!(output.status.code() == Some(77) && output.stdout.is_empty());
    anyhow::ensure!(!String::from_utf8(output.stderr)?.contains("waiting for executable writers"));
    Ok(())
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
    anyhow::ensure!(output.status.code() == Some(77) && output.stdout.is_empty());
    let output = Command::new(env!("CARGO_BIN_EXE_day2-sandbox"))
        .arg(probe)
        .arg("0")
        .output()?;
    anyhow::ensure!(output.status.code() == Some(77) && output.stdout.is_empty());
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
    let worker = directory.path().join("mutable-worker");
    std::fs::copy(env!("CARGO_BIN_EXE_day2-sandbox-probe"), &worker)?;
    std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o777))?;
    let output = launcher(&worker).output()?;
    anyhow::ensure!(output.status.code() == Some(77) && output.stdout.is_empty());
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
