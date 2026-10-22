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
            !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit() || b == b'.')
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
            (literal "/private/etc/ssl/openssl.cnf"))
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
    fn selected_developer_profile_keeps_outside_file_and_network_refusals() -> Result<()> {
        use std::{
            io::Write,
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
        let cat = job.join("cat");
        fs::copy("/bin/cat", &cat)?;
        assert!(Command::new(&cat).arg(&outside).status()?.success());
        assert!(build_host(&job, &cat)?.arg(&inside).status()?.success());
        assert!(!build_host(&job, &cat)?.arg(&outside).status()?.success());
        let touch = job.join("touch");
        fs::copy("/usr/bin/touch", &touch)?;
        assert!(
            build_host(&job, &touch)?
                .arg(job.join("allowed-write"))
                .status()?
                .success()
        );
        let denied = temporary.path().join("denied-write");
        assert!(Command::new(&touch).arg(&denied).status()?.success());
        fs::remove_file(&denied)?;
        assert!(!build_host(&job, &touch)?.arg(&denied).status()?.success());
        assert!(!denied.exists());

        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = format!("http://{}/", listener.local_addr()?);
        let stop = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new(AtomicUsize::new(0));
        let serving = Arc::clone(&stop);
        let connections = Arc::clone(&accepted);
        let server = std::thread::spawn(move || -> std::io::Result<()> {
            let started = Instant::now();
            while !serving.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(20) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_write_timeout(Some(Duration::from_secs(1)))?;
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
        let curl = job.join("curl");
        fs::copy("/usr/bin/curl", &curl)?;
        let arguments = [
            "--noproxy",
            "*",
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "3",
            "--output",
            "/dev/null",
            &address,
        ];
        let result = (|| -> Result<()> {
            assert!(Command::new(&curl).args(arguments).status()?.success());
            assert!(!build_host(&job, &curl)?.args(arguments).status()?.success());
            assert!(Command::new(&curl).args(arguments).status()?.success());
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
