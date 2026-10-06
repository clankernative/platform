//! Read-only inspection of a running day2 container, for images with no shell.
//!
//! The runtime image is distroless: it has no shell, no coreutils and no
//! package manager, which is most of why it is small. Qualification and the
//! GKE sandbox probe still need to look inside a running container, so this
//! binary is the one way in. It reads, it never writes, and each operation is
//! fixed: there is no argument that names an arbitrary file or command.
//!
//!   day2-inspect read <path>   one of the cgroup and /proc files below
//!   day2-inspect uname         kernel name, release, version and architecture
//!   day2-inspect tmp-bytes     /tmp capacity, used and available, in bytes
//!   day2-inspect tmp-inodes    /tmp inodes, used and available
//!   day2-inspect tmp-files     "<bytes> <octal mode> <uid>" for each regular
//!                              file directly under /tmp, never names or contents
//!   day2-inspect sandbox       run the worker sandbox qualification
//!   day2-inspect probe <profile>  on a real node: print the kernel and cgroup
//!                              facts, then run day2-serve's own cgroup
//!                              preflight for this runtime profile (JSON) and
//!                              the sandbox qualification
use anyhow::{Context, Result, bail, ensure};
use std::{fs, os::unix::fs::MetadataExt};

/// Everything `read` may print: the container's own cgroup limits and usage,
/// and its view of its cgroup and mounts. Nothing here is secret, and nothing
/// outside this list is reachable.
const READABLE: &[&str] = &[
    "/proc/self/cgroup",
    "/proc/self/mountinfo",
    "/sys/fs/cgroup/cpu.max",
    "/sys/fs/cgroup/cpu.stat",
    "/sys/fs/cgroup/memory.current",
    "/sys/fs/cgroup/memory.events",
    "/sys/fs/cgroup/memory.max",
    "/sys/fs/cgroup/pids.current",
    "/sys/fs/cgroup/pids.events",
    "/sys/fs/cgroup/pids.max",
];

/// Enough for mountinfo in a container; far more than any cgroup file.
const MAX_READ_BYTES: u64 = 1024 * 1024;
/// A runaway /tmp must not turn inspection into an unbounded listing.
const MAX_TMP_FILES: usize = 16_384;

fn read(path: &str) -> Result<()> {
    ensure!(READABLE.contains(&path), "day2-inspect cannot read {path}");
    let text = fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    ensure!(
        text.len() as u64 <= MAX_READ_BYTES,
        "{path} exceeds its read budget"
    );
    print!("{text}");
    Ok(())
}

fn uname() -> Result<()> {
    let field = |name: &str| -> Result<String> {
        Ok(fs::read_to_string(format!("/proc/sys/kernel/{name}"))?
            .trim()
            .to_owned())
    };
    println!(
        "{} {} {} {}",
        field("ostype")?,
        field("osrelease")?,
        field("version")?,
        std::env::consts::ARCH
    );
    Ok(())
}

fn tmp_usage(inodes: bool) -> Result<()> {
    let stat = rustix::fs::statvfs("/tmp").context("statvfs /tmp")?;
    let (total, free, available) = if inodes {
        (stat.f_files, stat.f_ffree, stat.f_favail)
    } else {
        (
            stat.f_blocks * stat.f_frsize,
            stat.f_bfree * stat.f_frsize,
            stat.f_bavail * stat.f_frsize,
        )
    };
    println!("total {total} used {} available {available}", total - free);
    Ok(())
}

fn tmp_files() -> Result<()> {
    let mut count = 0;
    let entries: fs::ReadDir = match fs::read_dir("/tmp") {
        Ok(entries) => entries,
        Err(error) => return Err(error).context("list /tmp"),
    };
    for entry in entries {
        let entry = entry?;
        // Not following symlinks: a link is not a file this container stored.
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_file() {
            continue;
        }
        count += 1;
        ensure!(
            count <= MAX_TMP_FILES,
            "/tmp holds more files than inspection lists"
        );
        println!(
            "{} {:o} {}",
            metadata.len(),
            metadata.mode() & 0o7777,
            metadata.uid()
        );
    }
    Ok(())
}

/// Everything a node needs to serve a day2 app, reported line by line and
/// decided by the same functions `day2-serve` runs at start.
fn probe(profile: &str) -> Result<()> {
    let profile: day2_capabilities::runtime::RuntimeProfile =
        serde_json::from_str(profile).context("runtime profile JSON")?;
    profile.validate()?;
    println!("== day2 node probe ==");
    uname()?;
    for path in [
        "/proc/self/cgroup",
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/cpu.max",
        "/sys/fs/cgroup/pids.max",
    ] {
        println!(
            "{path}: {}",
            fs::read_to_string(path).unwrap_or_default().trim()
        );
    }
    for line in fs::read_to_string("/proc/self/status")?.lines() {
        if ["NoNewPrivs:", "Seccomp:", "Seccomp_filters:"]
            .iter()
            .any(|field| line.starts_with(field))
        {
            println!("{line}");
        }
    }
    let preflight = day2::deployment::container_cgroup_preflight(profile.resources());
    match &preflight {
        Ok(()) => println!("RESULT day2-serve cgroup preflight: pass"),
        Err(error) => println!("RESULT day2-serve cgroup preflight: fail ({error:#})"),
    }
    let sandbox = day2::worker::qualify_sandbox();
    match &sandbox {
        Ok(()) => println!("RESULT sandbox: QUALIFIED"),
        Err(error) => {
            println!("RESULT sandbox: NOT QUALIFIED ({error:#})");
            launcher_diagnosis()?;
        }
    }
    ensure!(
        preflight.is_ok() && sandbox.is_ok(),
        "this node cannot serve a day2 app"
    );
    Ok(())
}

/// Why the launcher refused. The supervisor discards the launcher's stderr,
/// because after the exec it is the app worker's; here the worker is the
/// host-only probe, so the launcher's own refusal is safe to print. This runs
/// the same launcher on the same probe, as this process's child.
fn launcher_diagnosis() -> Result<()> {
    let directory = std::env::current_exe()?
        .canonicalize()?
        .parent()
        .context("inspector installation directory")?
        .to_owned();
    let mut child = std::process::Command::new(directory.join("day2-sandbox"))
        .arg(directory.join("day2-sandbox-probe"))
        .arg(std::process::id().to_string())
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawn the sandbox launcher")?;
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().context("launcher stdin")?;
        let _ = stdin.write_all(b"qualify\n");
    }
    let output = child.wait_with_output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("launcher exit: {}", output.status);
    for line in stderr.lines().take(20) {
        println!("launcher: {line}");
    }
    Ok(())
}

fn run() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["read", path] => read(path),
        ["uname"] => uname(),
        ["tmp-bytes"] => tmp_usage(false),
        ["tmp-inodes"] => tmp_usage(true),
        ["tmp-files"] => tmp_files(),
        ["probe", profile] => probe(profile),
        ["sandbox"] => {
            // The same check day2-serve makes before it starts: the probe
            // installed beside this binary must report a fully enforced sandbox.
            day2::worker::qualify_sandbox()?;
            println!("sandbox: QUALIFIED");
            Ok(())
        }
        _ => bail!(
            "usage: day2-inspect read <path> | uname | tmp-bytes | tmp-inodes | tmp-files | sandbox | probe <profile>"
        ),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("day2-inspect: {error:#}");
        std::process::exit(1);
    }
}
