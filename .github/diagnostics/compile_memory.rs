//! Temporary hosted-only observer. No argv, environment, source text or raw
//! process names are retained. The child runs unchanged complete test compilation and documentation preparation.
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone)]
struct Process {
    pid: u32,
    parent: u32,
    birth: u64,
    kind: &'static str,
    rss: Option<u64>,
    hwm: Option<u64>,
    threads: Option<u64>,
    jobserver_fifo_visible: bool,
    jobserver_open_observed: Option<bool>,
}

impl Process {
    fn json(&self) -> String {
        format!(
            "{{\"pid\":{},\"parent\":{},\"birth_ticks\":{},\"kind\":\"{}\",\"rss_kib\":{},\"hwm_kib\":{},\"threads\":{},\"jobserver_fifo_visible\":{},\"jobserver_open_observed\":{}}}",
            self.pid,
            self.parent,
            self.birth,
            self.kind,
            numeric(self.rss),
            numeric(self.hwm),
            numeric(self.threads),
            self.jobserver_fifo_visible,
            self.jobserver_open_observed
                .map_or("null", |v| if v { "true" } else { "false" })
        )
    }
}

fn numeric(value: Option<u64>) -> String {
    value.map_or_else(|| "null".into(), |number| number.to_string())
}

struct Supervised(Child);
impl Drop for Supervised {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
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
        "ld.bfd" => "ld_bfd",
        "ld" => "linker",
        "ld.lld" | "lld" | "rust-lld" => "lld",
        "mold" => "mold",
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
    let jobserver_open_observed = if kind == "rustc" {
        fs::read_dir(format!("{directory}/fd")).ok().and_then(|fds| {
            let mut complete = true;
            for (index, fd) in fds.take(129).enumerate() {
                if index == 128 { complete = false; break; }
                let Ok(fd) = fd else { complete = false; continue; };
                match fs::read_link(fd.path()) {
                    Ok(target) if target == Path::new("/var/tmp/day2-rustc-jobserver") => return Some(true),
                    Ok(_) => {},
                    Err(_) => complete = false,
                }
            }
            complete.then_some(false)
        })
    } else { None };
    Some(Process {
        pid,
        parent: field(&status, "PPid:")?.try_into().ok()?,
        birth,
        kind,
        rss: field(&status, "VmRSS:"),
        hwm: field(&status, "VmHWM:"),
        threads: field(&status, "Threads:"),
        jobserver_fifo_visible: fs::metadata(format!(
            "{directory}/root/var/tmp/day2-rustc-jobserver"
        ))
        .is_ok_and(|metadata| metadata.file_type().is_fifo()),
        jobserver_open_observed,
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
    use std::os::unix::fs::OpenOptionsExt;
    let mut output = fs::OpenOptions::new().create_new(true).write(true).mode(0o600)
        .open("/tmp/day2-compile-memory.jsonl")?;
    writeln!(
        output,
        "{{\"event\":\"before\",\"cgroup\":{},\"sample_ms\":500,\"per_process_hwm_is_observed_lower_bound\":true}}",
        cgroup()
    )?;
    writeln!(
        output,
        "{{\"event\":\"host_memory\",\"total_kib\":{},\"scope\":\"host_view_not_container_allowance\"}}",
        numeric(read("/proc/meminfo", 4096).and_then(|text| field(&text, "MemTotal:")))
    )?;
    output.flush()?;
    let start = Instant::now();
    let mut child = Supervised(Command::new("build-out/bin/xtask")
        .args(["verify-prepare-part", "tests"])
        .spawn()?);
    let mut peaks = BTreeMap::<(u32, u64), Process>::new();
    let mut previous_largest = None;
    let mut maximum_rss = 0;
    let mut samples = 0;
    let mut records = 0;
    let mut inventory_truncated = false;
    loop {
        let mut current = Vec::new();
        for (index, entry) in fs::read_dir("/proc")?.take(1025).enumerate() {
            if index == 1024 { inventory_truncated = true; break; }
            let entry = match entry { Ok(entry) => entry, Err(_) => { inventory_truncated = true; continue; } };
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
                    if peak.jobserver_open_observed != Some(true) {
                        peak.jobserver_open_observed = item
                            .jobserver_open_observed
                            .or(peak.jobserver_open_observed);
                    }
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
                && (previous_largest != Some(identity) || largest.rss.is_some_and(|rss| rss > maximum_rss + 131072))
            {
                records += 1;
                previous_largest = Some(identity);
                maximum_rss = maximum_rss.max(largest.rss.unwrap_or(0));
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
        if let Some(status) = child.0.try_wait()? {
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
            let _ = child.0.kill();
            let _ = child.0.wait();
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
