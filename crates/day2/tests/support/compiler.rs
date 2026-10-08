use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

const OUTPUT_LIMIT: u64 = 1024 * 1024;

struct Supervised {
    child: Child,
    stopped: bool,
}

impl Supervised {
    fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        #[cfg(unix)]
        let _ = Command::new("/bin/kill")
            .env_clear()
            .args(["-KILL", &format!("-{}", self.child.id())])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Supervised {
    fn drop(&mut self) {
        self.stop();
    }
}

fn read(mut file: File) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(OUTPUT_LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= OUTPUT_LIMIT,
        "compiler diagnostic byte budget exceeded"
    );
    Ok(bytes)
}

// Compiler bugs must fail the probe, not strand the test runner or its children.
pub fn output(command: &mut Command, budget: Duration) -> Result<Output> {
    let stdout = tempfile::tempfile()?;
    let stderr = tempfile::tempfile()?;
    command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = Supervised {
        child: command.spawn().context("start compiler probe")?,
        stopped: false,
    };
    let started = Instant::now();
    loop {
        ensure!(
            stdout.metadata()?.len() <= OUTPUT_LIMIT && stderr.metadata()?.len() <= OUTPUT_LIMIT,
            "compiler diagnostic byte budget exceeded"
        );
        if let Some(status) = child.child.try_wait()? {
            // A finished leader can leave descendants holding the output files.
            child.stop();
            return Ok(Output {
                status,
                stdout: read(stdout)?,
                stderr: read(stderr)?,
            });
        }
        ensure!(
            started.elapsed() < budget,
            "compiler check timed out after {} seconds",
            budget.as_secs_f64()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
#[test]
fn captures_completed_output() -> Result<()> {
    let result = output(
        Command::new("/bin/echo").arg("checked"),
        Duration::from_secs(5),
    )?;
    assert!(result.status.success());
    assert_eq!(result.stdout, b"checked\n");
    assert!(result.stderr.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn stalled_process_is_terminated() {
    let started = Instant::now();
    let error = output(
        Command::new("/bin/sleep").arg("60"),
        Duration::from_millis(30),
    )
    .unwrap_err();
    assert!(error.to_string().contains("compiler check timed out"));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[cfg(unix)]
#[test]
fn exited_leader_does_not_leave_a_child_running() -> Result<()> {
    use std::{io::Write, os::unix::net::UnixListener};

    let directory = tempfile::tempdir().context("create cleanup fixture directory")?;
    let socket = directory.path().join("child.sock");
    let ready = directory.path().join("ready");
    let listener = UnixListener::bind(&socket)
        .with_context(|| format!("bind cleanup socket {}", socket.display()))?;
    listener
        .set_nonblocking(true)
        .context("set cleanup listener nonblocking")?;
    let result = output(
        Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "support::compiler::exited_leader_fixture",
                "--nocapture",
            ])
            .env("DAY2_COMPILER_CLEANUP_ROLE", "leader")
            .env("DAY2_COMPILER_CLEANUP_SOCKET", &socket)
            .env("DAY2_COMPILER_CLEANUP_READY", &ready),
        Duration::from_secs(10),
    )?;
    assert!(result.status.success());
    let (mut stream, _) = listener.accept().context("accept cleanup descendant")?;
    // macOS can reject SO_RCVTIMEO on an accepted socket whose peer has already
    // exited. A bounded nonblocking read still proves both readiness and EOF.
    stream
        .set_nonblocking(true)
        .context("set cleanup stream nonblocking")?;
    let read_until = |stream: &mut std::os::unix::net::UnixStream, byte: &mut [u8; 1]| {
        let started = Instant::now();
        loop {
            match stream.read(byte) {
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && started.elapsed() < Duration::from_secs(2) =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                result => break result,
            }
        }
    };
    let mut byte = [0];
    assert_eq!(
        read_until(&mut stream, &mut byte).context("read cleanup descendant ready marker")?,
        1
    );
    assert_eq!(byte, [b'R'], "child positive control never connected");
    let closed = read_until(&mut stream, &mut byte);
    if !matches!(closed, Ok(0)) {
        // Release the fixture even when testing a broken supervisor.
        let _ = stream.write_all(b"Q");
        let _ = read_until(&mut stream, &mut byte);
    }
    assert!(
        matches!(closed, Ok(0)),
        "child survived its completed leader: {closed:?}"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn exited_leader_fixture() -> Result<()> {
    use std::{io::Write, os::unix::net::UnixStream};

    let Ok(role) = std::env::var("DAY2_COMPILER_CLEANUP_ROLE") else {
        return Ok(());
    };
    let ready =
        std::env::var_os("DAY2_COMPILER_CLEANUP_READY").context("cleanup fixture ready path")?;
    match role.as_str() {
        "leader" => {
            let mut child = Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "support::compiler::exited_leader_fixture",
                    "--nocapture",
                ])
                .env("DAY2_COMPILER_CLEANUP_ROLE", "descendant")
                .spawn()?;
            let started = Instant::now();
            while !std::path::Path::new(&ready).exists() {
                ensure!(
                    started.elapsed() < Duration::from_secs(5),
                    "child fixture did not start"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            ensure!(
                child.try_wait()?.is_none(),
                "child fixture exited before its leader"
            );
            // Exit without waiting: the supervisor must stop this descendant.
            std::process::exit(0);
        }
        "descendant" => {
            let socket = std::env::var_os("DAY2_COMPILER_CLEANUP_SOCKET")
                .context("cleanup fixture socket path")?;
            let mut stream = UnixStream::connect(socket)?;
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            stream.write_all(b"R")?;
            std::fs::write(ready, b"ready")?;
            let _ = stream.read(&mut [0]);
        }
        _ => anyhow::bail!("unknown cleanup fixture role"),
    }
    Ok(())
}

#[test]
fn oversized_diagnostic_is_rejected() -> Result<()> {
    let file = tempfile::tempfile()?;
    file.set_len(OUTPUT_LIMIT + 1)?;
    assert!(
        read(file)
            .unwrap_err()
            .to_string()
            .contains("compiler diagnostic byte budget exceeded")
    );
    Ok(())
}
