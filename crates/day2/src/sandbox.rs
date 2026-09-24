use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, process::Command};

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
    for name in ["home", "cache", "tmp"] {
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
        .env("ROC_CACHE_DIR", stage.join("cache"))
        .env("XDG_CACHE_HOME", stage.join("cache"));
    Ok(command)
}

/// Cargo's trusted platform dependencies run separately from the stricter Roc
/// compiler/worker sandboxes: macOS refuses nested sandbox initialization.
pub fn build_host(job: &Path, cargo: &Path) -> Result<Command> {
    ensure!(
        cfg!(all(target_os = "macos", target_arch = "aarch64")),
        "isolated host build is only supported on macOS arm64"
    );
    let root = quoted_path(job)?;
    ensure!(
        cargo.canonicalize()?.starts_with(job.canonicalize()?),
        "Cargo must belong to the private runner snapshot"
    );
    let profile = format!(
        r#"(version 1)(deny default)
        (allow file-read-metadata)
        (allow file-read-data (vnode-type DIRECTORY))
        (allow file-read* (subpath {root}) (subpath "/System") (subpath "/usr/lib")
            (subpath "/usr/share") (subpath "/Library/Developer") (subpath "/Applications/Xcode.app")
            (subpath "/usr/bin") (subpath "/bin") (literal "/dev/null") (literal "/dev/urandom")
            (literal "/private/etc/ssl/openssl.cnf"))
        (allow file-write* (subpath {root}) (literal "/dev/null"))
        (allow process-fork)
        (allow process-exec (subpath {root}) (subpath "/usr/bin") (subpath "/bin")
            (subpath "/Library/Developer") (subpath "/Applications/Xcode.app"))
        (allow sysctl-read)
        (allow mach-lookup (global-name "com.apple.system.logger"))"#
    );
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .args(["-p", &profile])
        .arg(cargo)
        .env("CARGO_NET_OFFLINE", "true")
        .env("OPENSSL_CONF", "/dev/null");
    Ok(command)
}
