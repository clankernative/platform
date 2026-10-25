//! Temporary hosted-only observer. No argv, environment, source text or raw
//! process names are retained. The child is the existing test-preparation recipe.
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

#[derive(Clone)]
struct Process {
    pid: u32,
    parent: u32,
    birth: u64,
    kind: &'static str,
    owner: &'static str,
    rss: u64,
    hwm: u64,
    threads: u64,
    jobserver_fifo_visible: bool,
}

impl Process {
    fn json(&self) -> String {
        format!(
            "{{\"pid\":{},\"parent\":{},\"birth_ticks\":{},\"kind\":\"{}\",\"owner\":\"{}\",\"rss_kib\":{},\"hwm_kib\":{},\"threads\":{},\"jobserver_fifo_visible\":{}}}",
            self.pid,
            self.parent,
            self.birth,
            self.kind,
            self.owner,
            self.rss,
            self.hwm,
            self.threads,
            self.jobserver_fifo_visible
        )
    }
}

fn read(path: impl AsRef<Path>, maximum: u64) -> Option<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= maximum)
        .then(|| String::from_utf8(bytes).ok())
        .flatten()
}

fn field(text: &str, name: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next()? == name)
            .then(|| fields.next()?.parse().ok())
            .flatten()
    })
}

fn process(pid: u32) -> Option<Process> {
    use std::os::unix::fs::FileTypeExt;
    let directory = format!("/proc/{pid}");
    let name = read(format!("{directory}/comm"), 64)?;
    let kind = match name.trim() {
        "rustc" => "rustc",
        "java" => "bazel_jvm",
        "ld" | "ld.bfd" => "ld_bfd",
        "ld.lld" | "lld" => "lld",
        "cc" | "gcc" | "collect2" | "clang" => "linker_driver",
        _ => return None,
    };
    let status = read(format!("{directory}/status"), 8192)?;
    let stat = read(format!("{directory}/stat"), 8192)?;
    let birth = stat
        .rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()?;
    let owner = if kind == "rustc" {
        let args = read(format!("{directory}/cmdline"), 65536)?;
        let fields = args.split('\0').collect::<Vec<_>>();
        if fields.contains(&"--test")
            && fields.iter().any(|a| a.ends_with("crates/day2/src/lib.rs"))
        {
            "//crates/day2:unit_lib"
        } else {
            "other_rust_unit"
        }
    } else {
        "not_a_rust_unit"
    };
    Some(Process {
        pid,
        parent: field(&status, "PPid:")?.try_into().ok()?,
        birth,
        kind,
        owner,
        rss: field(&status, "VmRSS:").unwrap_or(0),
        hwm: field(&status, "VmHWM:").unwrap_or(0),
        threads: field(&status, "Threads:").unwrap_or(0),
        jobserver_fifo_visible: fs::metadata(format!(
            "{directory}/root/var/tmp/day2-rustc-jobserver"
        ))
        .is_ok_and(|metadata| metadata.file_type().is_fifo()),
    })
}

fn cgroup() -> String {
    let number = |name| {
        read(format!("/sys/fs/cgroup/{name}"), 4096).and_then(|s| s.trim().parse::<u64>().ok())
    };
    let stat = read("/sys/fs/cgroup/memory.stat", 8192).unwrap_or_default();
    let events = read("/sys/fs/cgroup/memory.events", 4096).unwrap_or_default();
    let numeric = |v: Option<u64>| v.map_or_else(|| "null".into(), |v| v.to_string());
    format!(
        "{{\"current_bytes\":{},\"peak_bytes\":{},\"limit_bytes\":{},\"anon_bytes\":{},\"file_bytes\":{},\"shmem_bytes\":{},\"oom_kills\":{}}}",
        numeric(number("memory.current")),
        numeric(number("memory.peak")),
        numeric(number("memory.max")),
        numeric(field(&stat, "anon")),
        numeric(field(&stat, "file")),
        numeric(field(&stat, "shmem")),
        numeric(field(&events, "oom_kill"))
    )
}

fn run() -> io::Result<i32> {
    let mut output = File::create("/tmp/day2-compile-memory.jsonl")?;
    writeln!(
        output,
        "{{\"event\":\"before\",\"cgroup\":{},\"sample_ms\":500,\"per_process_hwm_is_observed_lower_bound\":true}}",
        cgroup()
    )?;
    output.flush()?;
    let start = Instant::now();
    let mut child = Command::new("build-out/bin/xtask")
        .args(["verify-prepare-part", "tests"])
        .spawn()?;
    let mut peaks = BTreeMap::<(u32, u64), Process>::new();
    let mut previous_largest = None;
    let mut maximum_rss = 0;
    let mut samples = 0;
    let mut records = 0;
    let mut inventory_truncated = false;
    loop {
        let mut current = Vec::new();
        for entry in fs::read_dir("/proc")?.take(1024).flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            if let Some(item) = process(pid) {
                if peaks.len() < 4096 || peaks.contains_key(&(item.pid, item.birth)) {
                    let peak = peaks
                        .entry((item.pid, item.birth))
                        .or_insert_with(|| item.clone());
                    peak.rss = peak.rss.max(item.rss);
                    peak.hwm = peak.hwm.max(item.hwm);
                    peak.threads = peak.threads.max(item.threads);
                } else {
                    inventory_truncated = true;
                }
                current.push(item);
            }
        }
        samples += 1;
        current.sort_by_key(|p| std::cmp::Reverse(p.rss));
        if let Some(largest) = current.first() {
            let identity = (largest.pid, largest.birth);
            if records < 1024
                && (previous_largest != Some(identity) || largest.rss > maximum_rss + 131072)
            {
                records += 1;
                previous_largest = Some(identity);
                maximum_rss = maximum_rss.max(largest.rss);
                writeln!(
                    output,
                    "{{\"event\":\"sample\",\"elapsed_ms\":{},\"cgroup\":{},\"processes\":[{}]}}",
                    start.elapsed().as_millis(),
                    cgroup(),
                    current
                        .iter()
                        .take(16)
                        .map(Process::json)
                        .collect::<Vec<_>>()
                        .join(",")
                )?;
                output.flush()?;
            }
        }
        if let Some(status) = child.try_wait()? {
            let mut ranked = peaks.into_values().collect::<Vec<_>>();
            ranked.sort_by_key(|p| std::cmp::Reverse(p.hwm));
            writeln!(
                output,
                "{{\"event\":\"after\",\"elapsed_ms\":{},\"samples\":{},\"inventory_truncated\":{},\"child_code\":{},\"cgroup\":{},\"process_peaks\":[{}]}}",
                start.elapsed().as_millis(),
                samples,
                inventory_truncated,
                status
                    .code()
                    .map_or_else(|| "null".into(), |v| v.to_string()),
                cgroup(),
                ranked
                    .iter()
                    .take(32)
                    .map(Process::json)
                    .collect::<Vec<_>>()
                    .join(",")
            )?;
            output.flush()?;
            return Ok(status.code().unwrap_or(1));
        }
        if start.elapsed() >= Duration::from_secs(5400) {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(124);
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("numeric compile observer failed: {:?}", error.kind());
            std::process::exit(1);
        }
    }
}
