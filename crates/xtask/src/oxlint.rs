//! The pinned JavaScript linter `day2 ci check` runs: the official oxlint
//! release binary for the host target, pinned by its archive and binary
//! identities in `tools/oxlint/<target>.json` and installed beside the Roc
//! toolchain. Bootstrap downloads and verifies it; a check only ever runs the
//! installed bytes after verifying them again, with the one platform config in
//! `tools/oxlint/oxlintrc.json`. An app's own lint configuration, ignore files
//! and nested configs are never read.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

/// The platform's one lint configuration.
pub(crate) const CONFIG: &str = "tools/oxlint/oxlintrc.json";
/// Where bootstrap installs the verified binary, beside the Roc toolchain.
const BINARY: &str = "../.toolchains/oxlint";
const MAX_ARCHIVE_BYTES: u64 = 64 << 20;
const MAX_BINARY_BYTES: u64 = 128 << 20;
/// The files one lint run may name, as a source tree may hold.
const MAX_FILES: usize = 8192;
/// oxlint's JSON report.
const MAX_REPORT_BYTES: u64 = 32 << 20;
const LINT_BUDGET: Duration = Duration::from_secs(600);

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pin {
    version: String,
    target: String,
    archive: String,
    archive_sha256: String,
    archive_bytes: u64,
    binary: String,
    binary_sha256: String,
    binary_bytes: u64,
}

/// This host's pin and the release target it names.
fn host() -> Result<(&'static str, &'static str)> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok(("tools/oxlint/darwin-arm64.json", "aarch64-apple-darwin")),
        ("linux", "x86_64") => Ok(("tools/oxlint/linux-x86_64.json", "x86_64-unknown-linux-gnu")),
        _ => bail!("unsupported oxlint host"),
    }
}

fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl Pin {
    fn load(root: &Path) -> Result<Self> {
        let (path, target) = host()?;
        let path = root.join(path);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file() && metadata.len() <= 4096,
            "oxlint pin must be a bounded regular file"
        );
        Self::parse(&fs::read(path)?, target)
    }

    /// A pin for `target`: the fixed release's archive and binary identities.
    fn parse(bytes: &[u8], target: &str) -> Result<Self> {
        let pin: Self = day2::json::decode(bytes)?;
        let release = format!(
            "https://github.com/oxc-project/oxc/releases/download/apps_v{}/oxlint-{target}.tar.gz",
            pin.version
        );
        ensure!(
            pin.version == "1.80.0"
                && pin.target == target
                && pin.archive == release
                && pin.binary == format!("oxlint-{target}")
                && hex(&pin.archive_sha256)
                && hex(&pin.binary_sha256)
                && (1..=MAX_ARCHIVE_BYTES).contains(&pin.archive_bytes)
                && (1..=MAX_BINARY_BYTES).contains(&pin.binary_bytes),
            "invalid oxlint pin"
        );
        Ok(pin)
    }
}

/// A file's sha256 hex, if it is a regular file of exactly `bytes` bytes.
fn identity(path: &Path, bytes: u64) -> Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() == bytes,
        "pinned oxlint file has the wrong type or size: {}",
        path.display()
    );
    let content = day2_assets::read_regular(path, bytes)?;
    ensure!(content.len() as u64 == bytes, "pinned oxlint file changed");
    Ok(day2::digest(&content)["sha256:".len()..].to_owned())
}

/// The installed binary, verified against the pin before every use.
pub(crate) fn verified(root: &Path) -> Result<PathBuf> {
    let pin = Pin::load(root)?;
    let binary = root.join(BINARY);
    ensure!(
        fs::symlink_metadata(&binary)
            .context("pinned oxlint unavailable; run xtask bootstrap-oxlint")?
            .is_file(),
        "pinned oxlint must be a regular file"
    );
    ensure!(
        identity(&binary, pin.binary_bytes)? == pin.binary_sha256,
        "pinned oxlint digest mismatch"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            fs::metadata(&binary)?.permissions().mode() & 0o111 != 0,
            "pinned oxlint is not executable"
        );
    }
    Ok(binary)
}

/// Download the pinned release archive, verify it and the one binary it
/// holds, and install the binary. An installed binary that verifies is kept.
pub(crate) fn bootstrap(root: &Path) -> Result<()> {
    let root = root.canonicalize()?;
    let pin = Pin::load(&root)?;
    if verified(&root).is_ok() {
        println!(
            "Verified pinned oxlint {}: {}",
            pin.version,
            root.join(BINARY).display()
        );
        return Ok(());
    }
    let destination = root.join(BINARY);
    ensure!(
        fs::symlink_metadata(&destination).is_err(),
        "an unverified oxlint is installed at {}; remove it",
        destination.display()
    );
    let parent = destination.parent().context("toolchain directory")?;
    fs::create_dir_all(parent)?;
    let scratch = tempfile::tempdir_in(parent)?;
    let archive = scratch.path().join("oxlint.tar.gz");
    let mut download = Command::new("/usr/bin/curl");
    download
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args([
            "--fail",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-time",
            "180",
            "--max-filesize",
        ])
        .arg(MAX_ARCHIVE_BYTES.to_string())
        .arg("--output")
        .arg(&archive)
        .arg(&pin.archive);
    super::run(&root, &mut download)?;
    ensure!(
        identity(&archive, pin.archive_bytes)? == pin.archive_sha256,
        "oxlint archive digest mismatch"
    );
    // Only the digest-approved archive reaches the extractor, and only its one
    // named member is extracted.
    let extracted = scratch.path().join("extracted");
    fs::create_dir(&extracted)?;
    let mut extract = Command::new("/usr/bin/tar");
    extract
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg("-xzf")
        .arg(&archive)
        .arg("-C")
        .arg(&extracted)
        .arg(&pin.binary);
    super::run(&root, &mut extract)?;
    let binary = extracted.join(&pin.binary);
    ensure!(
        identity(&binary, pin.binary_bytes)? == pin.binary_sha256,
        "oxlint binary digest mismatch"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))?;
    }
    fs::File::open(&binary)?.sync_all()?;
    // The scratch directory shares the destination's parent: one atomic,
    // no-clobber link publishes the verified bytes.
    fs::hard_link(&binary, &destination)?;
    fs::File::open(parent)?.sync_all()?;
    verified(&root)?;
    println!(
        "Installed pinned oxlint {}: {}",
        pin.version,
        destination.display()
    );
    Ok(())
}

/// One lint finding, by the file's path below the repository.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Finding {
    pub(crate) path: String,
    pub(crate) line: u64,
    pub(crate) rule: String,
    pub(crate) message: String,
}

#[derive(Deserialize)]
struct Report {
    diagnostics: Vec<Diagnostic>,
    number_of_files: u64,
}

#[derive(Deserialize)]
struct Diagnostic {
    message: String,
    code: Option<String>,
    filename: String,
    #[serde(default)]
    labels: Vec<Label>,
}

#[derive(Deserialize)]
struct Label {
    span: Span,
}

#[derive(Deserialize)]
struct Span {
    line: u64,
}

/// Lint `files` (paths below `repository`, each a regular file) with the
/// verified binary and the platform config. Returns every finding.
pub(crate) fn lint(root: &Path, repository: &Path, files: &[String]) -> Result<Vec<Finding>> {
    ensure!(files.len() <= MAX_FILES, "JavaScript lint file budget");
    let root = root.canonicalize()?;
    let repository = repository.canonicalize()?;
    for file in files {
        ensure!(
            !file.is_empty()
                && !file.starts_with('/')
                && file
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != ".."),
            "invalid JavaScript path: {file}"
        );
        // The pinned binary silently skips these names; refuse rather than pass them.
        ensure!(
            !day2::app_javascript::minified(file),
            "minified JavaScript cannot be linted: {file}"
        );
        let mut path = repository.clone();
        for part in file.split('/') {
            path.push(part);
            ensure!(
                !fs::symlink_metadata(&path)?.file_type().is_symlink(),
                "JavaScript paths cannot pass through links: {file}"
            );
        }
        ensure!(
            fs::symlink_metadata(&path)?.is_file(),
            "expected regular JavaScript source: {file}"
        );
    }
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let binary = verified(&root)?;
    let config = root.join(CONFIG);
    ensure!(
        fs::symlink_metadata(&config)?.is_file(),
        "the platform lint config must be a regular file"
    );
    let output = tempfile::tempdir()?;
    let report = output.path().join("report.json");
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .arg("--config")
        .arg(&config)
        .args([
            "--disable-nested-config",
            "--no-ignore",
            "--report-unused-disable-directives-severity=error",
            "--format=json",
            "--threads=2",
            "--",
        ])
        .args(files)
        .stdin(Stdio::null())
        .stdout(fs::File::create_new(&report)?)
        .stderr(Stdio::inherit());
    let status = match super::command_status_with_budget(&repository, &mut command, LINT_BUDGET) {
        Ok(status) => status,
        Err(super::CommandStatusError::Spawn(error) | super::CommandStatusError::Wait(error)) => {
            return Err(error).context("run pinned oxlint");
        }
        Err(super::CommandStatusError::Timeout) => bail!("pinned oxlint exceeded its budget"),
    };
    // 0: no findings; 1: findings. Anything else is a failed tool.
    ensure!(
        matches!(status.code(), Some(0 | 1)),
        "pinned oxlint failed: {status}"
    );
    let decoded: Report =
        serde_json::from_slice(&day2_assets::read_regular(&report, MAX_REPORT_BYTES)?)
            .context("unreadable oxlint report")?;
    ensure!(
        decoded.number_of_files == files.len() as u64
            && (status.code() == Some(0)) == decoded.diagnostics.is_empty(),
        "oxlint did not lint exactly the selected files"
    );
    let mut findings = decoded
        .diagnostics
        .into_iter()
        .map(|diagnostic| {
            let path = diagnostic.filename.trim_start_matches("./").to_owned();
            ensure!(files.contains(&path), "oxlint reported an unselected file");
            Ok(Finding {
                path,
                line: diagnostic.labels.first().map_or(1, |label| label.span.line),
                // Parse errors and unused directives carry no rule code.
                rule: diagnostic.code.unwrap_or_else(|| "oxlint".into()),
                message: diagnostic.message,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    findings.sort_by(|a, b| (&a.path, a.line, &a.rule).cmp(&(&b.path, b.line, &b.rule)));
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DARWIN: &[u8] = include_bytes!("../../../tools/oxlint/darwin-arm64.json");
    const LINUX: &[u8] = include_bytes!("../../../tools/oxlint/linux-x86_64.json");

    #[test]
    fn each_pin_names_only_its_targets_release_asset() -> Result<()> {
        let darwin = Pin::parse(DARWIN, "aarch64-apple-darwin")?;
        let linux = Pin::parse(LINUX, "x86_64-unknown-linux-gnu")?;
        assert_eq!(linux.binary, "oxlint-x86_64-unknown-linux-gnu");
        assert_ne!(darwin.binary_sha256, linux.binary_sha256);
        assert!(Pin::parse(DARWIN, "x86_64-unknown-linux-gnu").is_err());
        let text = std::str::from_utf8(LINUX)?;
        for tampered in [
            text.replace("1.80.0", "1.81.0"),
            text.replace("releases/download", "releases/latest/download"),
            text.replace("\"binary_bytes\": 15860216", "\"binary_bytes\": 0"),
            text.replace(&linux.archive_sha256, "abc"),
            text.replace("\"binary_bytes\"", "\"extra\": 1, \"binary_bytes\""),
        ] {
            assert!(Pin::parse(tampered.as_bytes(), &linux.target).is_err());
        }
        Ok(())
    }

    #[test]
    fn lint_names_only_regular_files_below_the_repository() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let repository = directory.path().join("repository");
        fs::create_dir_all(repository.join("ui"))?;
        fs::write(repository.join("ui/app.js"), "export {};\n")?;
        fs::write(directory.path().join("outside.js"), "export {};\n")?;
        std::os::unix::fs::symlink("app.js", repository.join("ui/link.js"))?;
        std::os::unix::fs::symlink(directory.path(), repository.join("up"))?;
        let root = directory.path();
        assert!(lint(root, &repository, &[]).is_ok_and(|findings| findings.is_empty()));
        for refused in [
            "../outside.js",
            "/ui/app.js",
            "ui//app.js",
            "./ui/app.js",
            "ui/link.js",
            "up/outside.js",
            "ui/missing.js",
            "ui",
            "ui/vendor.min.js",
        ] {
            assert!(
                lint(root, &repository, &[refused.to_owned()]).is_err(),
                "{refused}"
            );
        }
        Ok(())
    }
}
