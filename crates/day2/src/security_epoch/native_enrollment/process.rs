//! Retained identity, not a renewable permission. Only the kernel packet receiver
//! can construct this owner; numeric PIDs and certificate rows cannot adopt it.

use crate::security_epoch::native_enrollment::protocol::ProcessData;
use crate::security_epoch::{
    namespace_protocol, native_clock::NativeAcquisition, native_namespace as ns,
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use rustix::{
    event::{PollFd, PollFlags},
    fs::{Mode, OFlags},
    net::{KernelPidVisibility, ReceivedPidfdPacket},
};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    marker::PhantomData,
    rc::Rc,
    thread::ThreadId,
};

const NAMESPACES: [&str; 6] = ["time", "time_for_children", "pid", "mnt", "user", "cgroup"];

pub(super) struct SelfSnapshot {
    pub process: crate::security_epoch::NativeProcessObservation,
    pub namespace: crate::security_epoch::NativeNamespaceObservation,
    pub data: ProcessData,
}

impl SelfSnapshot {
    pub(super) fn acquire(code: &Digest, acquisition: &mut NativeAcquisition) -> Result<Self> {
        let process = crate::security_epoch::NativeProcessObservation::acquire(code, acquisition)?;
        let namespace = crate::security_epoch::NativeNamespaceObservation::acquire(acquisition)?;
        let proc = ns::open_root(acquisition)?;
        let root = open_process(&proc, std::process::id(), acquisition)?;
        let data = ProcessData {
            process: std::process::id(),
            start_ticks: start(&root, std::process::id(), acquisition)?,
            code: code.clone(),
            boot: boot(acquisition)?,
            namespaces: namespace
                .data()
                .namespaces
                .iter()
                .map(|(k, v)| (k.clone(), (v.device, v.inode)))
                .collect(),
        };
        Ok(Self {
            process,
            namespace,
            data,
        })
    }

    pub(super) fn check(&mut self, acquisition: &mut NativeAcquisition) -> Result<()> {
        self.process.check(acquisition)?;
        self.namespace.check(acquisition)?;
        Ok(())
    }

    pub(super) fn require_node_init(&mut self, acquisition: &mut NativeAcquisition) -> Result<()> {
        self.check(acquisition)?;
        let root = ns::open_root(acquisition)?;
        let init = open_process(&root, 1, acquisition)?;
        for name in ["time", "time_for_children", "pid", "user"] {
            let file = ns::open_namespace(&init, name, acquisition)?;
            let value = ns::namespace_identity(&file)?;
            ensure!(
                self.data.namespaces.get(name) == Some(&(value.device, value.inode)),
                "native_enrollment_node_init_namespace"
            );
        }
        self.check(acquisition)
    }
}

pub(super) struct MessageProcess {
    pidfd: File,
    proc: File,
    process: File,
    executable: File,
    namespaces: BTreeMap<String, File>,
    data: ProcessData,
    local_process: u32,
    thread: ThreadId,
    refused: bool,
    local: PhantomData<Rc<()>>,
}

impl MessageProcess {
    pub(super) fn receive(
        packet: ReceivedPidfdPacket,
        expected_code: &Digest,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Self> {
        let result = (|| {
            let pid = match packet.credentials.process {
                KernelPidVisibility::Visible(pid) => pid.get(),
                KernelPidVisibility::NotVisible => {
                    anyhow::bail!("native_enrollment_pid_not_visible")
                }
            };
            let pidfd = File::from(packet.process);
            live(&pidfd, acquisition)?;
            let proc = ns::open_root(acquisition)?;
            let process = open_process(&proc, pid, acquisition)?;
            let mut executable = executable(&process, acquisition)?;
            let code = hash(&mut executable, acquisition)?;
            ensure!(code == *expected_code, "native_enrollment_code_mismatch");
            let mut namespaces = BTreeMap::new();
            let mut identities = BTreeMap::new();
            for name in NAMESPACES {
                let fd = ns::open_namespace(&process, name, acquisition)?;
                let value = ns::namespace_identity(&fd)?;
                identities.insert(name.to_owned(), (value.device, value.inode));
                namespaces.insert(name.to_owned(), fd);
            }
            ensure!(
                identities["time"] == identities["time_for_children"],
                "native_enrollment_child_time_namespace"
            );
            let start_ticks = start(&process, pid, acquisition)?;
            let boot = boot(acquisition)?;
            let mut owner = Self {
                pidfd,
                proc,
                process,
                executable,
                namespaces,
                data: ProcessData {
                    process: pid,
                    start_ticks,
                    code,
                    boot,
                    namespaces: identities,
                },
                local_process: std::process::id(),
                thread: std::thread::current().id(),
                refused: false,
                local: PhantomData,
            };
            owner.check_identity(acquisition)?;
            Ok(owner)
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }

    pub(super) fn data(&self) -> &ProcessData {
        &self.data
    }

    /// Re-observes the original retained process in a fresh bounded acquisition.
    /// This does not extend any earlier acquisition or grant a role by itself.
    pub(super) fn check_identity(&mut self, acquisition: &mut NativeAcquisition) -> Result<()> {
        let result = (|| {
            ensure!(!self.refused, "native_enrollment_process_refused");
            ensure!(
                self.local_process == std::process::id()
                    && self.thread == std::thread::current().id(),
                "native_enrollment_process_owner_changed"
            );
            live(&self.pidfd, acquisition)?;
            let proc = ns::open_root(acquisition)?;
            ensure!(
                ns::proc_identity(&proc)? == ns::proc_identity(&self.proc)?,
                "native_enrollment_proc_mount_changed"
            );
            let current = open_process(&proc, self.data.process, acquisition)?;
            ensure!(
                ns::proc_identity(&current)? == ns::proc_identity(&self.process)?,
                "native_enrollment_process_replaced"
            );
            ensure!(
                start(&current, self.data.process, acquisition)? == self.data.start_ticks,
                "native_enrollment_process_start_changed"
            );
            ensure!(
                boot(acquisition)? == self.data.boot,
                "native_enrollment_boot_changed"
            );
            let mut current_executable = executable(&current, acquisition)?;
            ensure!(
                file_identity(&current_executable)? == file_identity(&self.executable)?,
                "native_enrollment_executable_replaced"
            );
            ensure!(
                hash(&mut self.executable, acquisition)? == self.data.code
                    && hash(&mut current_executable, acquisition)? == self.data.code,
                "native_enrollment_executable_changed"
            );
            for name in NAMESPACES {
                let current = ns::open_namespace(&current, name, acquisition)?;
                for fd in [&current, &self.namespaces[name]] {
                    let value = ns::namespace_identity(fd)?;
                    ensure!(
                        (value.device, value.inode) == self.data.namespaces[name],
                        "native_enrollment_namespace_changed"
                    );
                }
            }
            let mut offsets = ns::open_proc(&self.process, "timens_offsets", acquisition)?;
            namespace_protocol::require_zero(&namespace_protocol::offsets(&ns::read_proc(
                &mut offsets,
                1024,
                acquisition,
            )?)?)?;
            live(&self.pidfd, acquisition)?;
            Ok(())
        })();
        if result.is_err() {
            self.refused = true;
            acquisition.refuse();
        }
        result
    }
}

pub(super) fn live(fd: &File, acquisition: &mut NativeAcquisition) -> Result<()> {
    acquisition.remaining()?;
    let mut fds = [PollFd::new(fd, PollFlags::IN)];
    let zero = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    ensure!(
        rustix::event::poll(&mut fds, Some(&zero))? == 0 && fds[0].revents().is_empty(),
        "native_enrollment_process_exited"
    );
    acquisition.remaining()?;
    Ok(())
}

fn open_process(proc: &File, pid: u32, acquisition: &mut NativeAcquisition) -> Result<File> {
    acquisition.remaining()?;
    let fd = File::from(rustix::fs::openat(
        proc,
        pid.to_string(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    ns::require_proc(&fd)?;
    acquisition.remaining()?;
    Ok(fd)
}

fn executable(process: &File, acquisition: &mut NativeAcquisition) -> Result<File> {
    acquisition.remaining()?;
    // Fixed kernel-owned procfs magic link, never a caller path.
    let fd = File::from(rustix::fs::openat(
        process,
        "exe",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    acquisition.remaining()?;
    Ok(fd)
}

fn file_identity(file: &File) -> Result<(u64, u64, u64, i64, i64)> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.len() > 0 && m.len() <= 512 * 1024 * 1024,
        "native_enrollment_executable_bound"
    );
    Ok((m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec()))
}

fn hash(file: &mut File, acquisition: &mut NativeAcquisition) -> Result<Digest> {
    let identity = file_identity(file)?;
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0_u8; 65_536];
    let mut total = 0_u64;
    loop {
        acquisition.remaining()?;
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        ensure!(total <= identity.2, "native_enrollment_executable_changed");
        hasher.update(&buffer[..count]);
    }
    ensure!(
        total == identity.2 && file_identity(file)? == identity,
        "native_enrollment_executable_changed"
    );
    format!("sha256:{}", crate::hex(hasher.finish().as_ref())).try_into()
}

fn start(process: &File, pid: u32, acquisition: &mut NativeAcquisition) -> Result<u64> {
    let mut stat = ns::open_proc(process, "stat", acquisition)?;
    let mut status = ns::open_proc(process, "status", acquisition)?;
    let facts = namespace_protocol::task(
        &ns::read_proc(&mut stat, 16_384, acquisition)?,
        &ns::read_proc(&mut status, 65_536, acquisition)?,
    )?;
    ensure!(
        facts.process == pid && facts.thread == pid,
        "native_enrollment_process_leader"
    );
    Ok(facts.start_ticks)
}

pub(super) fn boot(acquisition: &mut NativeAcquisition) -> Result<String> {
    acquisition.remaining()?;
    let mut file = File::from(rustix::fs::open(
        "/proc/sys/kernel/random/boot_id",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    ns::require_proc(&file)?;
    let bytes = ns::read_proc(&mut file, 37, acquisition)?;
    let value = std::str::from_utf8(&bytes)?
        .strip_suffix('\n')
        .ok_or_else(|| anyhow::anyhow!("native_enrollment_boot_format"))?;
    ensure!(
        value.len() == 36
            && value
                .bytes()
                .enumerate()
                .all(|(i, b)| if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }),
        "native_enrollment_boot_format"
    );
    Ok(value.to_owned())
}
