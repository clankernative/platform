//! Host-only executable acceptance probe. Never linked into a Roc application.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod probe {
    use anyhow::{Context, Result, ensure};
    use nix::sys::resource::{Resource, getrlimit};
    use std::io::{BufRead, Write};

    fn denied<T>(result: std::io::Result<T>) -> Result<()> {
        match result {
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(nix::libc::EPERM | nix::libc::EACCES)
                ) =>
            {
                Ok(())
            }
            Err(error) => {
                Err(error).context("operation failed for a reason other than sandbox denial")
            }
            Ok(_) => anyhow::bail!("sandbox allowed a forbidden operation"),
        }
    }

    fn qualify() -> Result<()> {
        ensure!(
            nix::sys::prctl::get_no_new_privs()?,
            "no_new_privs not enforced"
        );
        denied(std::fs::read("/etc/passwd"))?;
        denied(std::fs::read("/proc/self/status"))?;
        denied(std::fs::write(
            format!("/tmp/day2-sandbox-denied-{}", std::process::id()),
            b"forbidden",
        ))?;
        denied(std::net::TcpListener::bind("127.0.0.1:0"))?;
        denied(std::net::UdpSocket::bind("127.0.0.1:0"))?;
        denied(std::os::unix::net::UnixStream::pair())?;
        match std::process::Command::new(std::env::current_exe()?).spawn() {
            Err(error) => denied::<()>(Err(error))?,
            Ok(mut child) => {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("sandbox allowed another process");
            }
        }
        match std::thread::Builder::new().spawn(|| {}) {
            Err(error) => denied::<()>(Err(error))?,
            Ok(thread) => {
                let _ = thread.join();
                anyhow::bail!("sandbox allowed a thread");
            }
        }
        ensure!(
            std::env::var_os("DAY2_SANDBOX_SECRET").is_none(),
            "inherited environment leaked"
        );
        for descriptor in 3..4096 {
            ensure!(
                std::fs::metadata(format!("/proc/self/fd/{descriptor}"))
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
                "inherited descriptor leaked"
            );
        }
        let own_bytes = std::fs::read(std::env::current_exe()?)?;
        ensure!(
            own_bytes.starts_with(b"\x7fELF"),
            "approved executable read failed"
        );
        for (resource, expected) in [
            (Resource::RLIMIT_AS, day2_sandbox::ADDRESS_SPACE_BYTES),
            (Resource::RLIMIT_CPU, day2_sandbox::CPU_SECONDS),
            (Resource::RLIMIT_NOFILE, day2_sandbox::OPEN_FILES),
            (Resource::RLIMIT_NPROC, 0),
            (Resource::RLIMIT_CORE, 0),
            (Resource::RLIMIT_FSIZE, 0),
        ] {
            ensure!(
                getrlimit(resource)? == (expected, expected),
                "worker resource limit missing"
            );
        }
        ensure!(
            Vec::<u8>::new()
                .try_reserve_exact(day2_sandbox::ADDRESS_SPACE_BYTES as usize)
                .is_err(),
            "address-space allocation escaped bound"
        );
        Ok(())
    }

    pub fn run() -> Result<()> {
        let mut output = std::io::stdout().lock();
        for line in std::io::stdin().lock().lines() {
            let line = line?;
            match line.as_str() {
                "qualify" => {
                    qualify()?;
                    output.write_all(day2_sandbox::QUALIFIED)?;
                }
                "pid" => write!(output, "{}", std::process::id())?,
                "spin" => loop {
                    std::hint::spin_loop();
                },
                "oversize" => output.write_all(&vec![b'x'; 1_048_577])?,
                "exit" => return Ok(()),
                _ if line.starts_with("read ") => {
                    denied(std::fs::read(&line[5..]))?;
                    output.write_all(b"denied")?;
                }
                _ if line.starts_with("write ") => {
                    denied(std::fs::write(&line[6..], b"forbidden"))?;
                    output.write_all(b"denied")?;
                }
                _ if line.starts_with("echo ") => output.write_all(line[5..].as_bytes())?,
                _ => anyhow::bail!("unknown host acceptance probe"),
            }
            output.write_all(b"\n")?;
            output.flush()?;
        }
        Ok(())
    }
}

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    match probe::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sandbox acceptance failed: {error:#}");
            std::process::ExitCode::from(78)
        }
    }
    #[cfg(not(target_os = "linux"))]
    std::process::ExitCode::from(77)
}
