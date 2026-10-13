//! Source-pinned formatter candidates and separately reviewed binary installation.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;
const BUILD_BUDGET: Duration = Duration::from_secs(3600);
const LINUX_ADDRESS_SPACE_BYTES: u64 = 12 * 1024 * 1024 * 1024;
const LINUX_GROUP_RSS_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const LINUX_DISK_HEADROOM_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const ZIG_SHA256: &str = "b23d70deaa879b5c2d486ed3316f7eaa53e84acf6fc9cc747de152450d401489";
const ZIG_LINUX_SHA256: &str = "70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00";

pub(super) fn pin_path() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("tools/roc-formatter/toolchain.json"),
        ("linux", "x86_64") => Ok("tools/roc-formatter/linux-x86_64.json"),
        _ => anyhow::bail!("unsupported native formatter host"),
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    roc_version: String,
    roc_binary_sha256: String,
    roc_source_archive: String,
    roc_source_archive_sha256: String,
    roc_source_commit: String,
    patch_sha256: String,
    digit_grouping_patch_sha256: String,
    zig_version: String,
    zig_archive: String,
    zig_archive_sha256: String,
    target: String,
    build_args: Vec<String>,
}

fn hexadecimal(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl Pin {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.roc_version.is_empty()
                && self.roc_version.len() <= 128
                && self
                    .roc_version
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte)),
            "invalid formatter version"
        );
        for digest in [
            &self.roc_binary_sha256,
            &self.roc_source_archive_sha256,
            &self.patch_sha256,
            &self.digit_grouping_patch_sha256,
            &self.zig_archive_sha256,
        ] {
            ensure!(hexadecimal(digest, 64), "invalid formatter digest pin");
        }
        ensure!(
            hexadecimal(&self.roc_source_commit, 40),
            "invalid formatter source commit"
        );
        ensure!(
            self.roc_source_archive
                .starts_with("https://github.com/roc-lang/nightlies/releases/download/")
                && !self.roc_source_archive.chars().any(char::is_control),
            "formatter source must be an approved nightly archive"
        );
        let (archive, digest, cpu, jobs) = match self.target.as_str() {
            "aarch64-macos" => (
                "https://ziglang.org/download/0.16.0/zig-aarch64-macos-0.16.0.tar.xz",
                ZIG_SHA256,
                "-Dcpu=apple_m1",
                "-j4",
            ),
            "x86_64-linux" => (
                "https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz",
                ZIG_LINUX_SHA256,
                "-Dcpu=baseline",
                "-j1",
            ),
            _ => anyhow::bail!("unsupported formatter build toolchain"),
        };
        ensure!(
            self.zig_version == "0.16.0"
                && self.zig_archive == archive
                && self.zig_archive_sha256 == digest,
            "unsupported formatter build toolchain"
        );
        let mut expected = vec![
            "build".to_string(),
            "roc".to_string(),
            "-Doptimize=ReleaseFast".to_string(),
            "-Dstrip=true".to_string(),
            cpu.to_string(),
            format!("-Dcompiler-version={}", self.roc_version),
            jobs.to_string(),
        ];
        if self.target == "x86_64-linux" {
            expected.extend(["--summary".into(), "all".into()]);
        }
        ensure!(
            self.build_args == expected,
            "unapproved formatter build recipe"
        );
        Ok(())
    }

    fn binary_url(&self) -> Result<&'static str> {
        self.validate()?;
        match self.target.as_str() {
            "aarch64-macos" => Ok(
                "https://github.com/clankernative/platform/releases/download/roc-formatter-2026-09-12/roc-fmt-day2-aarch64-apple-darwin",
            ),
            "x86_64-linux" => Ok(
                "https://github.com/clankernative/platform/releases/download/roc-formatter-linux-2026-09-12/roc-fmt-day2-x86_64-unknown-linux-gnu",
            ),
            _ => anyhow::bail!("unsupported native formatter release"),
        }
    }

    fn recipe(&self) -> serde_json::Value {
        let mut recipe = serde_json::json!({
            "roc_version": self.roc_version,
            "roc_source_archive": self.roc_source_archive,
            "roc_source_archive_sha256": self.roc_source_archive_sha256,
            "roc_source_commit": self.roc_source_commit,
            "patch_sha256": self.patch_sha256,
            // Both patches are recipe inputs: the binary is not reproducible from
            // the spacing patch alone.
            "digit_grouping_patch_sha256": self.digit_grouping_patch_sha256,
            "zig_version": self.zig_version,
            "zig_archive": self.zig_archive,
            "zig_archive_sha256": self.zig_archive_sha256,
            "target": self.target,
            "build_args": self.build_args,
            "test_args": self.test_args(),
        });
        if self.target == "x86_64-linux" {
            recipe["process_limits"] = serde_json::json!({
                "program": "/usr/bin/prlimit",
                "address_space_bytes_per_process": LINUX_ADDRESS_SPACE_BYTES,
                "core_bytes": 0,
                "sampled_process_group_rss_bytes": LINUX_GROUP_RSS_BYTES,
                "minimum_available_disk_bytes": LINUX_DISK_HEADROOM_BYTES,
                "resource_sampling_ms": 500,
                "sampling_is_not_kernel_process_tree_confinement": true,
            });
        }
        recipe
    }

    fn test_args(&self) -> Vec<String> {
        let mut args = self.build_args.clone();
        args[1] = "run-test-zig-module-fmt".into();
        args
    }
}

fn file_digest(path: &Path, budget: u64) -> Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= budget,
        "invalid or oversized formatter input: {}",
        path.display()
    );
    let mut reader = fs::File::open(path)?.take(budget + 1);
    let mut hash = Sha256::new();
    let mut bytes = [0u8; 64 * 1024];
    let mut total = 0;
    loop {
        let count = reader.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        ensure!(total <= budget, "formatter input byte budget");
        hash.update(&bytes[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn verify(path: &Path, expected: &str, budget: u64) -> Result<()> {
    let actual = file_digest(path, budget)?;
    ensure!(
        actual == expected,
        "formatter digest mismatch: {}; expected {expected}, got {actual}",
        path.display(),
    );
    Ok(())
}

fn installed(path: &Path, expected: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
        Ok(_) => {
            verify(path, expected, MAX_BINARY_BYTES)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                ensure!(
                    fs::metadata(path)?.permissions().mode() & 0o111 != 0,
                    "installed formatter is not executable"
                );
            }
            Ok(true)
        }
    }
}

struct Supervised(Child);

impl Drop for Supervised {
    fn drop(&mut self) {
        // End option parsing before the negative group ID: procps 4.0.4 can
        // otherwise interpret just its first digit (including -1, all PIDs).
        #[cfg(unix)]
        if let Some(mut signal) = group_signal(self.0.id(), "KILL") {
            let _ = signal.status();
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
fn group_signal(group: u32, signal: &str) -> Option<Command> {
    if group <= 1 || group > i32::MAX as u32 {
        return None;
    }
    let mut command = Command::new("/bin/kill");
    command
        .env_clear()
        .args([format!("-{signal}"), "--".into(), format!("-{group}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Some(command)
}

fn command(program: impl AsRef<Path>, scratch: &Path) -> Command {
    let mut command = Command::new(program.as_ref());
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("HOME", scratch.join("home"))
        .env("TMPDIR", scratch.join("tmp"))
        .env("XDG_CACHE_HOME", scratch.join("roc-cache"))
        .env("ROC_CACHE_DIR", scratch.join("roc-cache"))
        .env("ZIG_GLOBAL_CACHE_DIR", scratch.join("zig-cache"))
        .env("GIT_CEILING_DIRECTORIES", scratch)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command
}

fn compiler_command(program: &Path, scratch: &Path, pin: &Pin) -> Command {
    if pin.target == "x86_64-linux" {
        // One scheduled Zig job and a per-process address-space ceiling leave
        // room for the hosted runner. This is not a process-tree memory limit.
        let mut bounded = command("/usr/bin/prlimit", scratch);
        bounded
            .arg(format!("--as={LINUX_ADDRESS_SPACE_BYTES}"))
            .args(["--core=0", "--"])
            .arg(program);
        bounded
    } else {
        command(program, scratch)
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
enum GroupMemory {
    Foreign,
    Resident(u64),
    Unavailable,
}

#[cfg(target_os = "linux")]
fn status_group_rss(status: &str, group: u32) -> Result<GroupMemory> {
    let Some(groups) = status.lines().find_map(|line| line.strip_prefix("NSpgid:")) else {
        return Ok(GroupMemory::Foreign);
    };
    let actual: u32 = groups
        .split_whitespace()
        .next()
        .context("process group missing")?
        .parse()?;
    if actual != group {
        return Ok(GroupMemory::Foreign);
    }
    let Some(rss) = status.lines().find_map(|line| line.strip_prefix("VmRSS:")) else {
        return Ok(if status
            .lines()
            .any(|line| line.starts_with("State:") && line.contains("Z (zombie)"))
        {
            GroupMemory::Resident(0)
        } else {
            GroupMemory::Unavailable
        });
    };
    let mut fields = rss.split_whitespace();
    let kibibytes: u64 = fields.next().context("process RSS missing")?.parse()?;
    ensure!(
        fields.next() == Some("kB") && fields.next().is_none(),
        "unsupported process RSS units"
    );
    Ok(GroupMemory::Resident(
        kibibytes
            .checked_mul(1024)
            .context("process RSS overflow")?,
    ))
}

#[cfg(target_os = "linux")]
fn read_process_status(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(status) => Ok(Some(status)),
        Err(error) if error.raw_os_error() == Some(3)
            || [std::io::ErrorKind::NotFound, std::io::ErrorKind::PermissionDenied]
                .contains(&error.kind()) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn sample_member_rss(group: u32, mut read: impl FnMut() -> Result<Option<String>>) -> Result<Option<u64>> {
    // Linux can release a task's address space before it becomes a zombie.
    // Re-observe that transition, never count a persistently unobserved live
    // member as zero. Three reads allow at most two ten-millisecond delays.
    let mut remaining = 3;
    loop {
        let Some(status) = read()? else { return Ok(None); };
        match status_group_rss(&status, group)? {
            GroupMemory::Foreign => return Ok(None),
            GroupMemory::Resident(bytes) => return Ok(Some(bytes)),
            GroupMemory::Unavailable => {
                remaining -= 1;
                ensure!(remaining > 0, "live formatter process RSS unavailable after bounded recheck: {}",
                    status.lines().find(|line| line.starts_with("State:")).unwrap_or("State: missing"));
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn group_rss(group: u32) -> Result<(u64, bool)> {
    let mut total = 0u64;
    let mut parent_observed = false;
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let path = entry.path().join("status");
        if let Some(rss) = sample_member_rss(group, || read_process_status(&path))
            .with_context(|| format!("formatter process {pid} in group {group}"))?
        {
            total = total
                .checked_add(rss)
                .context("formatter process-group RSS overflow")?;
            parent_observed |= pid == group;
        }
    }
    Ok((total, parent_observed))
}

#[cfg(target_os = "linux")]
fn available_disk(scratch: &Path) -> Result<u64> {
    let output = command("/usr/bin/df", scratch)
        .args(["--output=avail", "-B1"])
        .arg(scratch)
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 4096,
        "formatter disk observation"
    );
    let output = String::from_utf8(output.stdout)?;
    let mut fields = output.split_whitespace();
    ensure!(
        fields.next() == Some("Avail"),
        "unsupported disk observation header"
    );
    let bytes = fields.next().context("available disk missing")?.parse()?;
    ensure!(fields.next().is_none(), "ambiguous disk observation");
    Ok(bytes)
}

fn run(scratch: &Path, phase: &str, command: &mut Command, budget: Duration) -> Result<()> {
    let logs = scratch.join("logs");
    fs::create_dir_all(&logs)?;
    ensure!(
        fs::symlink_metadata(&logs)?.is_dir(),
        "formatter log directory"
    );
    let (log, path) = tempfile::Builder::new()
        .prefix("phase-")
        .suffix(".log")
        .tempfile_in(&logs)?
        .keep()?;
    println!("Formatter: {phase}; retained log {}", path.display());
    #[cfg(target_os = "linux")]
    let (mut telemetry, telemetry_path) = tempfile::Builder::new()
        .prefix("resources-")
        .suffix(".jsonl")
        .tempfile_in(&logs)?
        .keep()?;
    #[cfg(target_os = "linux")]
    {
        let disk = available_disk(scratch)?;
        writeln!(
            telemetry,
            "{}",
            serde_json::json!({"phase":phase,"available_disk_bytes":disk,"elapsed_ms":0})
        )?;
        ensure!(
            disk >= LINUX_DISK_HEADROOM_BYTES,
            "formatter disk headroom below budget: {disk} bytes"
        );
        println!("Formatter resource telemetry: {}", telemetry_path.display());
    }
    let output = log.try_clone()?;
    command.stdout(output.try_clone()?).stderr(output);
    let mut child = Supervised(command.spawn().with_context(|| phase.to_string())?);
    let started = Instant::now();
    let mut progress = Instant::now();
    // One unconditional clock owner keeps native-effect admission explicit on
    // every host. Only Linux samples process resources when this clock expires.
    let mut resources: Instant = Instant::now();
    loop {
        ensure!(
            started.elapsed() <= budget,
            "formatter {phase} time budget exceeded"
        );
        ensure!(
            log.metadata()?.len() <= MAX_LOG_BYTES,
            "formatter {phase} log budget exceeded"
        );
        if let Some(status) = child.0.try_wait()? {
            let length = log.metadata()?.len();
            ensure!(
                length <= MAX_LOG_BYTES,
                "formatter {phase} log budget exceeded"
            );
            let mut reader = fs::File::open(&path)?;
            reader.seek(SeekFrom::Start(length.saturating_sub(16_384)))?;
            let mut tail = Vec::new();
            reader.take(16_384).read_to_end(&mut tail)?;
            println!(
                "Formatter: {phase} completed in {:.1}s: {status}\n{}",
                started.elapsed().as_secs_f64(),
                String::from_utf8_lossy(&tail)
            );
            if !status.success() {
                anyhow::bail!(
                    "formatter {phase} failed: {status}\n{}",
                    String::from_utf8_lossy(&tail)
                );
            }
            return Ok(());
        }
        if resources.elapsed() >= Duration::from_millis(500) {
            #[cfg(target_os = "linux")]
            {
                let (rss, observed) = group_rss(child.0.id())?;
                if !observed {
                    ensure!(
                        child.0.try_wait()?.is_some(),
                        "live formatter process group could not be observed"
                    );
                    continue;
                }
                let disk = available_disk(scratch)?;
                writeln!(
                    telemetry,
                    "{}",
                    serde_json::json!({
                        "phase":phase,"elapsed_ms":started.elapsed().as_millis(),
                        "sampled_group_rss_bytes":rss,"available_disk_bytes":disk,
                    })
                )?;
                ensure!(
                    telemetry.metadata()?.len() <= MAX_LOG_BYTES,
                    "formatter telemetry byte budget"
                );
                ensure!(
                    rss <= LINUX_GROUP_RSS_BYTES,
                    "formatter sampled process-group RSS exceeded budget: {rss} bytes"
                );
                ensure!(
                    disk >= LINUX_DISK_HEADROOM_BYTES,
                    "formatter disk headroom below budget: {disk} bytes"
                );
            }
            resources = Instant::now();
        }
        if progress.elapsed() >= Duration::from_secs(60) {
            println!(
                "Formatter: {phase} still running after {:.1}s; {} log bytes",
                started.elapsed().as_secs_f64(),
                log.metadata()?.len()
            );
            #[cfg(target_os = "linux")]
            if let Ok(memory) = fs::read_to_string("/proc/meminfo") {
                for line in memory.lines().filter(|line| {
                    line.starts_with("MemAvailable:") || line.starts_with("SwapFree:")
                }) {
                    println!("Formatter runner memory: {line}");
                }
            }
            std::io::stdout().flush()?;
            progress = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn download(scratch: &Path, url: &str, digest: &str, output: &Path) -> Result<()> {
    run(
        scratch,
        "download pinned archive",
        command("/usr/bin/curl", scratch)
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
                "268435456",
                "--output",
            ])
            .arg(output)
            .arg(url),
        Duration::from_secs(200),
    )?;
    verify(output, digest, MAX_ARCHIVE_BYTES)
}

fn extract(scratch: &Path, archive: &Path, output: &Path) -> Result<()> {
    fs::create_dir(output)?;
    // Only digest-approved archives reach the native extractor.
    run(
        scratch,
        "extract verified archive",
        command("/usr/bin/tar", scratch)
            .arg("-xf")
            .arg(archive)
            .arg("--strip-components=1")
            .arg("-C")
            .arg(output),
        Duration::from_secs(120),
    )
}

fn publish(binary: &Path, destination: &Path, expected: &str) -> Result<()> {
    verify(binary, expected, MAX_BINARY_BYTES)?;
    ensure!(
        !installed(destination, expected)?,
        "formatter was installed concurrently"
    );
    let parent = destination
        .parent()
        .context("formatter install directory")?;
    let staged = tempfile::NamedTempFile::new_in(parent)?;
    fs::copy(binary, staged.path())?;
    verify(staged.path(), expected, MAX_BINARY_BYTES)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staged
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    staged.as_file().sync_all()?;
    staged.persist_noclobber(destination)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn checked_pin(root: &Path) -> Result<Pin> {
    let tools = root.join("tools/roc-formatter");
    let pin_path = root.join(pin_path()?);
    let metadata = fs::symlink_metadata(&pin_path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 16_384,
        "invalid formatter pin file"
    );
    let pin: Pin = serde_json::from_slice(&fs::read(pin_path)?)?;
    pin.validate()?;
    ensure!(
        (pin.target == "aarch64-macos" && cfg!(all(target_os = "macos", target_arch = "aarch64")))
            || (pin.target == "x86_64-linux"
                && cfg!(all(target_os = "linux", target_arch = "x86_64"))),
        "formatter pin does not match the native host"
    );
    let original = super::native_toolchain::load(root)?;
    ensure!(
        original.semantic_version(root)? == pin.roc_version,
        "formatter must retain the semantic compiler version"
    );
    original.verified_compiler(root)?;
    let patch = tools.join("associated-method-spacing.patch");
    verify(&patch, &pin.patch_sha256, 512 * 1024)?;
    let grouping = tools.join("integer-digit-grouping.patch");
    verify(&grouping, &pin.digit_grouping_patch_sha256, 512 * 1024)?;
    Ok(pin)
}

fn install_reviewed(destination: &Path, candidate: Option<&Path>, expected: &str) -> Result<()> {
    if let Some(candidate) = candidate {
        verify(candidate, expected, MAX_BINARY_BYTES)?;
    }
    if installed(destination, expected)? {
        println!("Verified pinned Roc formatter: {}", destination.display());
        return Ok(());
    }
    let candidate = candidate.context(
        "reviewed formatter binary required: run xtask build-formatter to create an unreviewed candidate, have a maintainer review its evidence and binary pin, then run xtask bootstrap-formatter BINARY; source builds never update pins automatically",
    )?;
    publish(candidate, destination, expected)?;
    println!("Installed pinned Roc formatter: {}", destination.display());
    Ok(())
}

pub fn install(root: &Path, candidate: Option<&Path>) -> Result<()> {
    let root = root.canonicalize()?;
    let pin = checked_pin(&root)?;
    let destination = root.join("../.toolchains/roc-fmt-day2");
    if candidate.is_none() && !installed(&destination, &pin.roc_binary_sha256)? {
        // The public release contains the already-reviewed bytes. Downloading
        // never promotes a source-built candidate or changes the admission pin.
        let scratch = tempfile::tempdir()?;
        for child in ["home", "tmp"] {
            fs::create_dir(scratch.path().join(child))?;
        }
        let binary = scratch.path().join("roc-fmt-day2");
        download(
            scratch.path(),
            pin.binary_url()?,
            &pin.roc_binary_sha256,
            &binary,
        )?;
        return install_reviewed(&destination, Some(&binary), &pin.roc_binary_sha256);
    }
    install_reviewed(&destination, candidate, &pin.roc_binary_sha256)
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Candidate {
    format: u32,
    review_status: String,
    roc_binary_sha256: String,
    recipe_sha256: String,
    recipe: serde_json::Value,
    native_formatter_tests_passed: bool,
    binary_reproducibility: String,
}

fn publish_candidate(root: &Path, binary: &Path, pin: &Pin) -> Result<PathBuf> {
    pin.validate()?;
    let hash = file_digest(binary, MAX_BINARY_BYTES)?;
    let recipe = pin.recipe();
    let manifest = Candidate {
        format: 1,
        review_status: "unreviewed-candidate".into(),
        roc_binary_sha256: hash.clone(),
        recipe_sha256: day2::digest(&serde_json::to_vec(&recipe)?),
        recipe,
        native_formatter_tests_passed: true,
        binary_reproducibility: "not-guaranteed: compiler embeds absolute build paths".into(),
    };
    let manifest = serde_json::to_vec_pretty(&manifest)?;
    let artifacts = root.join("artifacts");
    let candidates = artifacts.join("roc-formatter");
    for directory in [&artifacts, &candidates] {
        if !directory.exists() {
            fs::create_dir(directory)?;
        }
        ensure!(
            fs::symlink_metadata(directory)?.is_dir(),
            "formatter candidate directory must be a real directory"
        );
    }
    let destination = candidates.join(&hash);
    if destination.exists() {
        ensure!(
            fs::symlink_metadata(&destination)?.is_dir(),
            "invalid formatter candidate directory"
        );
        ensure!(
            installed(&destination.join("roc"), &hash)?,
            "formatter candidate binary missing"
        );
        verify(
            &destination.join("manifest.json"),
            &format!("{:x}", Sha256::digest(&manifest)),
            32_768,
        )
        .context("existing formatter candidate has different provenance")?;
        return Ok(destination.join("roc"));
    }
    let stage = tempfile::tempdir_in(&candidates)?;
    publish(binary, &stage.path().join("roc"), &hash)?;
    let mut receipt = tempfile::NamedTempFile::new_in(stage.path())?;
    std::io::Write::write_all(&mut receipt, &manifest)?;
    receipt.as_file().sync_all()?;
    receipt.persist_noclobber(stage.path().join("manifest.json"))?;
    fs::File::open(stage.path())?.sync_all()?;
    fs::rename(stage.path(), &destination)?;
    fs::File::open(&candidates)?.sync_all()?;
    Ok(destination.join("roc"))
}

/// Fixed build root. Reproducibility depends on this path being identical on
/// every machine that rebuilds the formatter, because Zig records it in the
/// binary; changing it changes the output.
const REPRODUCIBLE_BUILD_ROOT: &str = "/tmp/day2-roc-formatter-build";

pub fn build_candidate(root: &Path) -> Result<PathBuf> {
    let root = root.canonicalize()?;
    let pin = checked_pin(&root)?;
    // Applied in this order; the grouping patch is written against the tree the
    // spacing patch produces.
    let patches = [
        root.join("tools/roc-formatter/associated-method-spacing.patch"),
        root.join("tools/roc-formatter/integer-digit-grouping.patch"),
    ];
    // Zig embeds source paths in the binary, so a per-build temporary directory
    // makes the output differ every time and the pin unverifiable. A fixed path
    // keeps those embedded strings constant, so a rebuild from the same inputs
    // reproduces the same bytes. The path is absolute and outside the checkout so
    // it does not vary with where the repository is cloned.
    let scratch = PathBuf::from(REPRODUCIBLE_BUILD_ROOT);
    // Everything except the compiler caches is rebuilt from verified inputs, so it
    // is cleared. The caches are kept: Zig names cache entries by content hash and
    // embeds those paths in the binary, so repopulating a cleared cache lands the
    // same inputs in differently named buckets and changes the output bytes.
    for child in ["home", "tmp", "source", "zig", "logs"] {
        let path = scratch.join(child);
        if fs::symlink_metadata(&path).is_ok() {
            fs::remove_dir_all(&path).context("clear the formatter build root")?;
        }
    }
    for stale in ["source.tar.gz", "zig.tar.xz"] {
        let path = scratch.join(stale);
        if fs::symlink_metadata(&path).is_ok() {
            fs::remove_file(&path).context("clear a stale formatter download")?;
        }
    }
    for child in ["home", "tmp", "roc-cache", "zig-cache"] {
        fs::create_dir_all(scratch.join(child))?;
    }
    let scratch = scratch.as_path();
    let archive = scratch.join("source.tar.gz");
    download(
        scratch,
        &pin.roc_source_archive,
        &pin.roc_source_archive_sha256,
        &archive,
    )?;
    let source = scratch.join("source");
    extract(scratch, &archive, &source)?;
    let commit_file = source.join("NIGHTLY_SOURCE_COMMIT");
    ensure!(
        fs::symlink_metadata(&commit_file)?.is_file() && fs::metadata(&commit_file)?.len() <= 128,
        "invalid nightly source commit file"
    );
    ensure!(
        fs::read_to_string(commit_file)?.trim() == pin.roc_source_commit,
        "formatter source commit mismatch"
    );
    for patch in &patches {
        for check in [true, false] {
            let mut apply = command("/usr/bin/git", scratch);
            apply
                .current_dir(&source)
                .args(["apply", "--whitespace=error"]);
            if check {
                apply.arg("--check");
            }
            apply.arg(patch);
            run(
                scratch,
                "apply verified formatter patch",
                &mut apply,
                Duration::from_secs(30),
            )?;
        }
    }
    let archive = scratch.join("zig.tar.xz");
    download(scratch, &pin.zig_archive, &pin.zig_archive_sha256, &archive)?;
    let zig = scratch.join("zig");
    extract(scratch, &archive, &zig)?;
    let executable = zig.join("zig");
    ensure!(
        fs::symlink_metadata(&executable)?.is_file(),
        "Zig compiler must be a regular file"
    );
    run(
        scratch,
        "test native formatter module",
        compiler_command(&executable, scratch, &pin)
            .current_dir(&source)
            .args(pin.test_args()),
        BUILD_BUDGET,
    )?;
    run(
        scratch,
        "build native formatter",
        compiler_command(&executable, scratch, &pin)
            .current_dir(&source)
            .args(&pin.build_args),
        BUILD_BUDGET,
    )?;
    let candidate = publish_candidate(&root, &source.join("zig-out/bin/roc"), &pin)?;
    println!("Unreviewed formatter candidate: {}", candidate.display());
    println!(
        "Build evidence does not approve this binary; review manifest.json and update the pin separately."
    );
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin() -> Pin {
        let version = "nightly-2026-09-05-b195f5b";
        Pin {
            roc_version: version.into(),
            roc_binary_sha256: "1".repeat(64),
            roc_source_archive: format!(
                "https://github.com/roc-lang/nightlies/releases/download/{version}/source.tar.gz"
            ),
            roc_source_archive_sha256: "2".repeat(64),
            roc_source_commit: "3".repeat(40),
            patch_sha256: "4".repeat(64),
            digit_grouping_patch_sha256: "6".repeat(64),
            zig_version: "0.16.0".into(),
            zig_archive: "https://ziglang.org/download/0.16.0/zig-aarch64-macos-0.16.0.tar.xz"
                .into(),
            zig_archive_sha256: ZIG_SHA256.into(),
            target: "aarch64-macos".into(),
            build_args: [
                "build",
                "roc",
                "-Doptimize=ReleaseFast",
                "-Dstrip=true",
                "-Dcpu=apple_m1",
                &format!("-Dcompiler-version={version}"),
                "-j4",
            ]
            .map(str::to_string)
            .to_vec(),
        }
    }

    #[test]
    fn pins_reject_unknown_recipes_and_unreviewed_toolchains() {
        pin().validate().unwrap();
        for change in [0, 1, 2, 3, 4, 5] {
            let mut pin = pin();
            match change {
                0 => pin.build_args.push("--prefix=/tmp/unreviewed".into()),
                1 => pin.roc_binary_sha256 = "A".repeat(64),
                2 => pin.roc_source_commit = "3".repeat(39),
                3 => pin.roc_source_archive = "http://github.com/source.tar.gz".into(),
                4 => pin.zig_archive_sha256 = "0".repeat(64),
                5 => pin.roc_version = "injected\nversion".into(),
                _ => unreachable!(),
            }
            assert!(pin.validate().is_err());
        }
    }

    #[test]
    fn linux_recipe_rejects_mixed_host_inputs_and_build_flags() {
        let mut linux = pin();
        linux.target = "x86_64-linux".into();
        linux.zig_archive =
            "https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz".into();
        linux.zig_archive_sha256 = ZIG_LINUX_SHA256.into();
        linux.build_args[4] = "-Dcpu=baseline".into();
        linux.build_args[6] = "-j1".into();
        linux.build_args.extend(["--summary".into(), "all".into()]);
        linux.validate().unwrap();
        assert!(
            linux
                .binary_url()
                .unwrap()
                .ends_with("x86_64-unknown-linux-gnu")
        );
        for change in 0..4 {
            let mut wrong = linux.clone();
            match change {
                0 => wrong.target = "aarch64-linux".into(),
                1 => wrong.zig_archive_sha256 = ZIG_SHA256.into(),
                2 => wrong.build_args[4] = "-Dcpu=apple_m1".into(),
                3 => wrong.build_args[6] = "-j4".into(),
                _ => unreachable!(),
            }
            assert!(wrong.validate().is_err());
        }
    }

    #[test]
    fn installation_is_exact_and_never_overwrites_wrong_bytes() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let binary = temporary.path().join("built");
        fs::write(&binary, "verified formatter")?;
        let hash = file_digest(&binary, 128)?;
        let target = temporary.path().join("formatter");
        assert!(!installed(&target, &hash)?);
        publish(&binary, &target, &hash)?;
        assert!(installed(&target, &hash)?);
        fs::write(&target, "unapproved replacement")?;
        assert!(installed(&target, &hash).is_err());
        assert!(publish(&binary, &target, &hash).is_err());
        assert_eq!(fs::read(&target)?, b"unapproved replacement");
        Ok(())
    }

    #[test]
    fn installation_requires_reviewed_bytes_even_when_a_candidate_is_supplied() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let approved = temporary.path().join("approved");
        let other = temporary.path().join("unreviewed");
        let target = temporary.path().join("formatter");
        fs::write(&approved, "reviewed formatter")?;
        fs::write(&other, "other formatter")?;
        let hash = file_digest(&approved, 128)?;
        assert!(install_reviewed(&target, None, &hash).is_err());
        assert!(install_reviewed(&target, Some(&other), &hash).is_err());
        assert!(!target.exists());
        install_reviewed(&target, Some(&approved), &hash)?;
        install_reviewed(&target, None, &hash)?;
        assert!(install_reviewed(&target, Some(&other), &hash).is_err());
        assert_eq!(fs::read(&target)?, b"reviewed formatter");
        Ok(())
    }

    #[test]
    fn candidates_record_actual_bytes_without_installing_or_approving_them() -> Result<()> {
        let root = tempfile::tempdir()?;
        let binary = root.path().join("built");
        fs::write(&binary, "fresh native candidate")?;
        let pin = pin();
        let candidate = publish_candidate(root.path(), &binary, &pin)?;
        let hash = file_digest(&candidate, 128)?;
        assert_ne!(hash, pin.roc_binary_sha256);
        assert_eq!(
            candidate
                .parent()
                .context("candidate directory")?
                .file_name()
                .context("candidate hash")?,
            std::ffi::OsStr::new(&hash)
        );
        let manifest: Candidate =
            serde_json::from_slice(&fs::read(candidate.with_file_name("manifest.json"))?)?;
        assert_eq!(manifest.roc_binary_sha256, hash);
        assert_eq!(manifest.recipe, pin.recipe());
        assert_eq!(
            manifest.recipe_sha256,
            day2::digest(&serde_json::to_vec(&pin.recipe())?)
        );
        assert_eq!(manifest.review_status, "unreviewed-candidate");
        assert!(!root.path().join(".toolchains").exists());
        assert_eq!(publish_candidate(root.path(), &binary, &pin)?, candidate);

        let mut reviewed = pin.clone();
        reviewed.roc_binary_sha256 = hash;
        assert_eq!(
            publish_candidate(root.path(), &binary, &reviewed)?,
            candidate
        );
        let mut changed = pin.clone();
        changed.patch_sha256 = "5".repeat(64);
        assert!(publish_candidate(root.path(), &binary, &changed).is_err());
        assert_eq!(fs::read(&candidate)?, b"fresh native candidate");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_inputs_and_installations_fail_closed() -> Result<()> {
        use std::os::unix::fs::symlink;
        let temporary = tempfile::tempdir()?;
        let binary = temporary.path().join("built");
        fs::write(&binary, "verified formatter")?;
        let hash = file_digest(&binary, 128)?;
        let target = temporary.path().join("formatter");
        symlink(&binary, &target)?;
        assert!(installed(&target, &hash).is_err());
        assert!(publish(&binary, &target, &hash).is_err());
        assert_eq!(fs::read(binary)?, b"verified formatter");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn matching_bytes_without_execute_permission_are_not_a_valid_installation() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir()?;
        let target = temporary.path().join("formatter");
        fs::write(&target, "formatter")?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        let hash = file_digest(&target, 128)?;
        assert!(installed(&target, &hash).is_err());
        Ok(())
    }

    #[test]
    fn build_environment_is_private_and_has_no_inherited_overrides() {
        let scratch = Path::new("/private/formatter-build");
        let command = command("/private/zig", scratch);
        let environment: std::collections::BTreeMap<_, _> = command.get_envs().collect();
        for key in [
            "HOME",
            "TMPDIR",
            "ROC_CACHE_DIR",
            "XDG_CACHE_HOME",
            "ZIG_GLOBAL_CACHE_DIR",
        ] {
            let value = environment[std::ffi::OsStr::new(key)].unwrap();
            assert!(Path::new(value).starts_with(scratch));
        }
        assert_eq!(
            environment[std::ffi::OsStr::new("GIT_CEILING_DIRECTORIES")],
            Some(scratch.as_os_str())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_linux_compiler_process_has_the_recorded_kernel_limits() -> Result<()> {
        let scratch = tempfile::tempdir()?;
        let mut linux = pin();
        linux.target = "x86_64-linux".into();
        let output = compiler_command(Path::new("/usr/bin/cat"), scratch.path(), &linux)
            .arg("/proc/self/limits")
            .output()?;
        ensure!(output.status.success(), "query actual child kernel limits");
        let limits = String::from_utf8(output.stdout)?;
        let address = limits
            .lines()
            .find(|line| line.starts_with("Max address space"))
            .context("address-space limit missing")?;
        let core = limits
            .lines()
            .find(|line| line.starts_with("Max core file size"))
            .context("core limit missing")?;
        assert_eq!(
            address.split_whitespace().collect::<Vec<_>>(),
            [
                "Max",
                "address",
                "space",
                "12884901888",
                "12884901888",
                "bytes"
            ]
        );
        assert_eq!(
            core.split_whitespace().collect::<Vec<_>>(),
            ["Max", "core", "file", "size", "0", "0", "bytes"]
        );
        assert_eq!(
            linux.recipe()["process_limits"]["address_space_bytes_per_process"],
            LINUX_ADDRESS_SPACE_BYTES
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_group_observation_rejects_missing_units_overflow_and_foreign_groups() -> Result<()> {
        let status = "Name:\tzig with spaces)\nNSpgid:\t42\t7\nVmRSS:\t123 kB\n";
        assert_eq!(status_group_rss(status, 42)?, GroupMemory::Resident(123 * 1024));
        assert_eq!(status_group_rss(status, 7)?, GroupMemory::Foreign);
        assert!(status_group_rss("NSpgid:\t42\nVmRSS:\t123 bytes\n", 42).is_err());
        assert!(status_group_rss("NSpgid:\t42\nVmRSS:\t18446744073709551615 kB\n", 42).is_err());
        assert_eq!(status_group_rss("NSpgid:\t42\nState:\tR (running)\n", 42)?, GroupMemory::Unavailable);
        assert_eq!(
            status_group_rss("NSpgid:\t42\nState:\tZ (zombie)\n", 42)?,
            GroupMemory::Resident(0)
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn member_rss_rechecks_teardown_but_rejects_persistent_or_malformed_observations() -> Result<()> {
        let missing = "NSpgid:\t42\nState:\tR (running)\n";
        for (last, expected) in [
            (Some("NSpgid:\t42\nVmRSS:\t123 kB\n"), Some(123 * 1024)),
            (Some("NSpgid:\t42\nState:\tZ (zombie)\n"), Some(0)),
            (None, None),
        ] {
            let mut observations = [Some(missing), last].into_iter();
            assert_eq!(sample_member_rss(42, || Ok(observations.next().unwrap().map(str::to_owned)))?, expected);
        }
        let mut attempts = 0;
        assert!(sample_member_rss(42, || { attempts += 1; Ok(Some(missing.into())) }).is_err());
        assert_eq!(attempts, 3);
        assert!(sample_member_rss(42, || Ok(Some("NSpgid:\t42\nVmRSS:\t123 bytes\n".into()))).is_err());
        assert!(sample_member_rss(42, || anyhow::bail!("read failed")).is_err());
        assert_eq!(sample_member_rss(7, || Ok(Some(missing.into())))?, None);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn group_cleanup_terminates_only_the_owned_child_and_keeps_a_sibling_alive() -> Result<()> {
        let scratch = tempfile::tempdir()?;
        let mut sibling = Supervised(command("/bin/sleep", scratch.path()).arg("30").spawn()?);
        let child = Supervised(command("/bin/sleep", scratch.path()).arg("30").spawn()?);
        let group = child.0.id();
        let mut probe = group_signal(group, "0").context("owned group signal")?;
        assert_eq!(
            probe.get_args().collect::<Vec<_>>(),
            [
                std::ffi::OsStr::new("-0"),
                std::ffi::OsStr::new("--"),
                std::ffi::OsStr::new(&format!("-{group}"))
            ]
        );
        ensure!(
            probe.status()?.success(),
            "owned group must exist before cleanup"
        );
        // The old syntax is observed only with signal zero, never a destructive
        // signal. Record the actual hosted tool's behavior without assuming its
        // version; production cleanup always uses the explicit terminator.
        let old_probe = Command::new("/bin/kill")
            .env_clear()
            .args(["-0", &format!("-{group}")])
            .output()?;
        println!(
            "Signal-zero old syntax: {}; stderr={}",
            old_probe.status,
            String::from_utf8_lossy(&old_probe.stderr)
        );
        println!("Owned formatter group={group}; sibling={}", sibling.0.id());
        drop(child);
        ensure!(
            !group_signal(group, "0")
                .context("owned group probe")?
                .status()?
                .success(),
            "owned child group still exists after cleanup"
        );
        ensure!(
            sibling.0.try_wait()?.is_none(),
            "cleanup terminated an unrelated sibling"
        );
        assert!(group_signal(0, "KILL").is_none());
        assert!(group_signal(1, "KILL").is_none());
        assert!(group_signal(u32::MAX, "KILL").is_none());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resource_observation_measures_the_actual_owned_child_group_and_disk() -> Result<()> {
        let scratch = tempfile::tempdir()?;
        let child = Supervised(command("/usr/bin/sleep", scratch.path()).arg("2").spawn()?);
        let started = Instant::now();
        loop {
            let (rss, observed) = group_rss(child.0.id())?;
            if observed && rss > 0 {
                break;
            }
            ensure!(
                started.elapsed() < Duration::from_secs(1),
                "owned child process observation"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(group_rss(u32::MAX)?, (0, false));
        assert!(available_disk(scratch.path())? > 0);
        Ok(())
    }
}
