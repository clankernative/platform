use anyhow::{Context, Result, ensure};
pub use day2_sandbox::CompilerCache;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub fn quoted_path(path: &Path) -> Result<String> {
    let path = path.canonicalize()?;
    let value = path.to_str().context("non UTF-8 sandbox path")?;
    ensure!(
        !value.contains(['"', '\\', '\n', '\r']),
        "unsupported sandbox path"
    );
    Ok(format!("\"{value}\""))
}

pub fn compiler(root: &Path, stage: &Path, roc: &Path) -> Result<Command> {
    compiler_scoped(root, stage, roc, day2_sandbox::CompilerCache::General)
}

pub fn glue_compiler(
    root: &Path,
    stage: &Path,
    roc: &Path,
    cache: day2_sandbox::CompilerCache,
) -> Result<Command> {
    ensure!(
        cache != day2_sandbox::CompilerCache::General,
        "glue requires a generator-scoped cache"
    );
    compiler_scoped(root, stage, roc, cache)
}

fn compiler_scoped(
    root: &Path,
    stage: &Path,
    roc: &Path,
    cache: day2_sandbox::CompilerCache,
) -> Result<Command> {
    for name in ["home", cache.directory(), "tmp"] {
        fs::create_dir_all(stage.join(name))?;
    }
    fs::create_dir_all(root.join("crates/worker/generated"))?;
    if cfg!(target_os = "linux") {
        let executable = std::env::current_exe()?;
        let launcher = executable
            .parent()
            .context("compiler host executable parent")?
            .join("day2-compiler-sandbox");
        ensure!(
            launcher.is_file(),
            "missing trusted compiler sandbox launcher"
        );
        let mut command = Command::new(launcher);
        command
            .arg(root)
            .arg(stage)
            .arg(roc)
            .arg(std::process::id().to_string())
            .arg(cache.name())
            .arg("--");
        return Ok(command);
    }
    ensure!(
        cfg!(target_os = "macos"),
        "unsupported compiler sandbox host"
    );
    let reads = [
        stage.to_path_buf(),
        root.join("../.toolchains"),
        root.join("tools"),
        root.join("vendor"),
    ];
    let mut exceptions = reads
        .iter()
        .map(|path| Ok(format!("(require-not (subpath {}))", quoted_path(path)?)))
        .collect::<Result<Vec<_>>>()?;
    exceptions.push(format!(
        "(require-not (literal {}))",
        quoted_path(&root.join("sdk/main.roc"))?
    ));
    let executable = quoted_path(roc)?;
    let profile = format!(
        r#"(version 1)(deny default)
        (allow process-exec (literal {executable}))
        (allow file-read*)
        (deny file-read-data (require-all (vnode-type REGULAR-FILE)
            (require-not (subpath "/usr/lib")) (require-not (subpath "/System"))
            {}))
        (allow file-write* (subpath {}) (subpath {}))
        (allow sysctl-read)
        (allow mach-lookup (global-name "com.apple.system.logger"))
        (allow file-write-data (literal "/dev/null"))"#,
        exceptions.join(" "),
        quoted_path(stage)?,
        quoted_path(&root.join("crates/worker/generated"))?
    );
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .args(["-p", &profile])
        .arg(roc)
        .current_dir(root)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("HOME", stage.join("home"))
        .env("TMPDIR", stage.join("tmp"))
        .env("ROC_CACHE_DIR", stage.join(cache.directory()))
        .env("XDG_CACHE_HOME", stage.join(cache.directory()));
    Ok(command)
}

/// Accept only the OS-selected command-line tools or one selected Xcode bundle.
/// The caller canonicalizes before this structural check; no app/SDK path is an
/// input, and selecting a developer installation is not an audit of its bytes.
fn trusted_developer_root(selected: &Path) -> Result<PathBuf> {
    if selected == Path::new("/Library/Developer/CommandLineTools") {
        return Ok(selected.to_owned());
    }
    let contents = selected.parent().context("selected developer contents")?;
    let bundle = contents.parent().context("selected developer bundle")?;
    let name = bundle
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let versioned = name
        .strip_prefix("Xcode_")
        .and_then(|name| name.strip_suffix(".app"))
        .is_some_and(|version| {
            version
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        });
    ensure!(
        selected.file_name() == Some(std::ffi::OsStr::new("Developer"))
            && contents.file_name() == Some(std::ffi::OsStr::new("Contents"))
            && bundle.parent() == Some(Path::new("/Applications"))
            && (name == "Xcode.app" || name == "Xcode-beta.app" || versioned),
        "selected developer installation is outside approved system tool locations"
    );
    Ok(bundle.to_owned())
}

fn selected_developer_root() -> Result<PathBuf> {
    let output = Command::new("/usr/bin/xcode-select")
        .arg("--print-path")
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()
        .context("query the selected system developer installation")?;
    // This trusted fixed OS query emits a path. These are post-capture checks,
    // not a hard output-memory or hostile-tool supervision guarantee.
    ensure!(
        output.status.success() && output.stdout.len() <= 4096 && output.stderr.len() <= 4096,
        "selected system developer query failed or exceeded its path budget"
    );
    let text = std::str::from_utf8(&output.stdout).context("selected developer path encoding")?;
    let path = Path::new(text.trim_end_matches('\n'));
    let selected = path
        .canonicalize()
        .context("resolve the selected system developer installation")?;
    trusted_developer_root(&selected)
}

/// Bazel's trusted platform dependencies run separately from the stricter Roc
/// compiler/worker sandboxes: macOS refuses nested sandbox initialization.
/// Its pinned JVM registers sleep/wake notifications and a no-idle-sleep
/// assertion. The power client permission is broader than those two operations;
/// it is confined to trusted dependency builds, never Roc or app execution.
pub fn build_host(job: &Path, bazel: &Path) -> Result<Command> {
    ensure!(
        cfg!(all(target_os = "macos", target_arch = "aarch64")),
        "isolated host build is only supported on macOS arm64"
    );
    let root = quoted_path(job)?;
    let developer = quoted_path(&selected_developer_root()?)?;
    ensure!(
        bazel.canonicalize()?.starts_with(job.canonicalize()?),
        "Bazel must belong to the private runner snapshot"
    );
    let profile = format!(
        r#"(version 1)(deny default)
        (allow file-read-metadata)
        (allow file-read-data (vnode-type DIRECTORY))
        (allow file-read* (subpath {root}) (subpath "/System") (subpath "/usr/lib")
            (subpath "/usr/share") (subpath "/Library/Developer") (subpath {developer})
            (subpath "/usr/bin") (subpath "/bin") (literal "/dev/null") (literal "/dev/urandom")
            (literal "/private/etc/ssl/openssl.cnf")
            (literal "/Library/Preferences/com.apple.dt.Xcode.plist")
            (subpath "/Library/Apple/System/Library/PrivateFrameworks/MobileDevice.framework")
            (subpath "/Library/Apple/System/Library/PrivateFrameworks/Mercury.framework"))
        (allow file-write* (subpath {root}) (literal "/dev/null"))
        (allow process-fork)
        (allow process-exec (subpath {root}) (subpath "/usr/bin") (subpath "/bin")
            (subpath "/Library/Developer") (subpath {developer}))
        (allow iokit-open (iokit-registry-entry-class "RootDomainUserClient"))
        (allow sysctl-read)
        (allow mach-lookup (global-name "com.apple.system.logger")
            (global-name "com.apple.PowerManagement.control"))"#
    );
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .args(["-p", &profile])
        .arg(bazel)
        .env("OPENSSL_CONF", "/dev/null");
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn developer_root_selects_only_one_system_xcode_or_command_line_tools() -> Result<()> {
        for (selected, expected) in [
            (
                "/Applications/Xcode.app/Contents/Developer",
                "/Applications/Xcode.app",
            ),
            (
                "/Applications/Xcode_16.4.app/Contents/Developer",
                "/Applications/Xcode_16.4.app",
            ),
            (
                "/Applications/Xcode-beta.app/Contents/Developer",
                "/Applications/Xcode-beta.app",
            ),
            (
                "/Library/Developer/CommandLineTools",
                "/Library/Developer/CommandLineTools",
            ),
        ] {
            assert_eq!(
                trusted_developer_root(Path::new(selected))?,
                Path::new(expected)
            );
        }
        Ok(())
    }

    #[test]
    fn developer_root_refuses_home_paths_other_apps_and_malformed_bundle_layouts() {
        for selected in [
            "/Users/operator/Xcode.app/Contents/Developer",
            "/Applications/Other.app/Contents/Developer",
            "/Applications/Xcode_16.4.app/Other/Developer",
            "/Applications/Xcode_16.4.app/Contents/Developer/../private",
            "/Applications/Xcode_secret.app/Contents/Developer",
            "/Library/Developer/CommandLineTools/private",
        ] {
            assert!(
                trusted_developer_root(Path::new(selected)).is_err(),
                "{selected}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "public I/O witness invoked explicitly by the build-host profile test"]
    fn build_host_public_witness() -> Result<()> {
        use std::{
            io::{Read, Write},
            net::{SocketAddr, TcpStream},
            time::Duration,
        };

        let operation = std::env::var("DAY2_TEST_BUILD_HOST_OPERATION")?;
        let target = std::env::var("DAY2_TEST_BUILD_HOST_TARGET")?;
        let expected = std::env::var("DAY2_TEST_BUILD_HOST_EXPECTED")?;
        let result = match operation.as_str() {
            "read" => fs::read(&target).and_then(|bytes| {
                if bytes == b"public read witness" {
                    Ok(())
                } else {
                    Err(std::io::Error::other("public read witness changed"))
                }
            }),
            "write" => fs::write(&target, b"public write witness"),
            "connect" => {
                let address: SocketAddr = target.parse()?;
                ensure!(
                    address.ip().is_loopback() && address.port() != 0,
                    "loopback witness required"
                );
                (|| -> std::io::Result<()> {
                    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
                    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
                    stream.write_all(
                        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                    )?;
                    let mut response = Vec::new();
                    stream.take(4097).read_to_end(&mut response)?;
                    if response.len() <= 4096 && response.ends_with(b"\r\n\r\nOK") {
                        Ok(())
                    } else {
                        Err(std::io::Error::other("public HTTP witness changed"))
                    }
                })()
            }
            _ => anyhow::bail!("unknown public witness operation"),
        };
        match (expected.as_str(), result) {
            ("allowed", Ok(())) => {}
            ("denied", Err(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
            ("denied", Ok(())) => anyhow::bail!("sandbox allowed the public witness operation"),
            (_, Err(error)) => return Err(error).context("public witness operation"),
            _ => anyhow::bail!("unknown public witness expectation"),
        }
        println!("DAY2_PUBLIC_WITNESS:{operation}:{expected}");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn selected_developer_profile_keeps_outside_file_and_network_refusals() -> Result<()> {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            sync::{
                Arc,
                atomic::{AtomicBool, AtomicUsize, Ordering},
            },
            time::{Duration, Instant},
        };
        let temporary = tempfile::tempdir()?;
        let job = temporary.path().join("job");
        fs::create_dir(&job)?;
        let outside = temporary.path().join("outside");
        fs::write(&outside, b"public read witness")?;
        let inside = job.join("inside");
        fs::write(&inside, b"public read witness")?;
        // Apple system executables carry launch constraints that can reject a
        // copied binary before confinement. Use this repository-built Rust
        // harness, with one explicit ignored fixture and only public witnesses.
        let executable = job.join("public-witness");
        fs::copy(std::env::current_exe()?, &executable)?;
        let witness = |operation: &str,
                       target: &std::ffi::OsStr,
                       confined: bool,
                       expected: &str|
         -> Result<()> {
            let mut command = if confined {
                build_host(&job, &executable)?
            } else {
                Command::new(&executable)
            };
            let output = command
                .args([
                    "--exact",
                    "sandbox::tests::build_host_public_witness",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("DAY2_TEST_BUILD_HOST_OPERATION", operation)
                .env("DAY2_TEST_BUILD_HOST_TARGET", target)
                .env("DAY2_TEST_BUILD_HOST_EXPECTED", expected)
                .output()?;
            let stdout = std::str::from_utf8(&output.stdout)?;
            ensure!(
                output.status.success()
                    && output.stdout.len() <= 4096
                    && output.stderr.len() <= 4096
                    && stdout.lines().any(|line| line
                        .ends_with(&format!("DAY2_PUBLIC_WITNESS:{operation}:{expected}")))
                    && stdout.contains("1 passed; 0 failed; 0 ignored;"),
                "public witness {operation}/{expected} did not execute successfully: {}",
                output.status
            );
            Ok(())
        };
        witness("read", outside.as_os_str(), false, "allowed")?;
        witness("read", inside.as_os_str(), true, "allowed")?;
        witness("read", outside.as_os_str(), true, "denied")?;
        let allowed = job.join("allowed-write");
        witness("write", allowed.as_os_str(), true, "allowed")?;
        assert_eq!(fs::read(&allowed)?, b"public write witness");
        let denied = temporary.path().join("denied-write");
        witness("write", denied.as_os_str(), false, "allowed")?;
        assert_eq!(fs::read(&denied)?, b"public write witness");
        fs::remove_file(&denied)?;
        witness("write", denied.as_os_str(), true, "denied")?;
        assert!(!denied.exists());

        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?.to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new(AtomicUsize::new(0));
        let serving = Arc::clone(&stop);
        let connections = Arc::clone(&accepted);
        let server = std::thread::spawn(move || -> std::io::Result<()> {
            let started = Instant::now();
            while !serving.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(20) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
                        stream.set_write_timeout(Some(Duration::from_secs(1)))?;
                        let mut request = Vec::new();
                        while !request.ends_with(b"\r\n\r\n") && request.len() < 4096 {
                            let mut byte = [0_u8; 1];
                            if stream.read(&mut byte)? == 0 {
                                return Err(std::io::Error::other(
                                    "public witness request ended early",
                                ));
                            }
                            request.push(byte[0]);
                        }
                        if !request.ends_with(b"\r\n\r\n") {
                            return Err(std::io::Error::other(
                                "public witness request header budget",
                            ));
                        }
                        stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                        )?;
                        connections.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        });
        let result = (|| -> Result<()> {
            let target = std::ffi::OsStr::new(&address);
            witness("connect", target, false, "allowed")?;
            witness("connect", target, true, "denied")?;
            witness("connect", target, false, "allowed")?;
            Ok(())
        })();
        stop.store(true, Ordering::SeqCst);
        server
            .join()
            .map_err(|_| anyhow::anyhow!("public witness server panicked"))??;
        result?;
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
        Ok(())
    }
}
