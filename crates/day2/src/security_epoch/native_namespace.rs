//! Actual retained self-task/namespace observations. This is not a current Pod,
//! image, node initial-time-namespace, role or bootstrap capability. Production
//! runtime-to-Pod admission stays unavailable until its actual issuer qualifies.

use super::{
    namespace_protocol::{self, TaskFacts, TimeOffsets},
    native_clock::NativeAcquisition,
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, marker::PhantomData, rc::Rc, thread::ThreadId};

const NAMESPACES: [&str; 6] = ["time", "time_for_children", "pid", "mnt", "user", "cgroup"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NamespaceIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NamespaceFacts {
    pub task: TaskFacts,
    pub namespaces: BTreeMap<String, NamespaceIdentity>,
    pub offsets: TimeOffsets,
}

pub(crate) struct NativeNamespaceObservation {
    process: u32,
    thread: ThreadId,
    domain: Digest,
    facts: NamespaceFacts,
    #[cfg(target_os = "linux")]
    proc_root: std::fs::File,
    #[cfg(target_os = "linux")]
    process_root: std::fs::File,
    #[cfg(target_os = "linux")]
    task: std::fs::File,
    #[cfg(target_os = "linux")]
    stat: std::fs::File,
    #[cfg(target_os = "linux")]
    status: std::fs::File,
    #[cfg(target_os = "linux")]
    offsets: std::fs::File,
    #[cfg(target_os = "linux")]
    namespaces: BTreeMap<String, std::fs::File>,
    valid: bool,
    local: PhantomData<Rc<()>>,
}

impl NativeNamespaceObservation {
    pub(super) fn acquire(acquisition: &mut NativeAcquisition) -> Result<Self> {
        let result = (|| {
            #[cfg(target_os = "linux")]
            {
                let domain = acquisition.sample()?.domain;
                let process = std::process::id();
                let thread = std::thread::current().id();
                let proc_root = open_root(acquisition)?;
                let task = open_task(&proc_root, acquisition)?;
                let mut stat = open_proc(&task, "stat", acquisition)?;
                let mut status = open_proc(&task, "status", acquisition)?;
                let task_facts = namespace_protocol::task(
                    &read_proc(&mut stat, 16_384, acquisition)?,
                    &read_proc(&mut status, 65_536, acquisition)?,
                )?;
                ensure!(
                    task_facts.process == process,
                    "epoch_native_task_process_changed"
                );
                let mut namespaces = BTreeMap::new();
                let mut identities = BTreeMap::new();
                for name in NAMESPACES {
                    let fd = open_namespace(&task, name, acquisition)?;
                    identities.insert(name.to_owned(), namespace_identity(&fd)?);
                    namespaces.insert(name.to_owned(), fd);
                }
                ensure!(
                    identities["time"] == identities["time_for_children"],
                    "epoch_native_child_timens_changed"
                );
                // timens_offsets is a TGID entry, absent from the per-thread
                // proc directory. Bind its process view to this exact thread's
                // retained time namespace before and after reading it.
                let process_root = open_process(&proc_root, acquisition)?;
                require_process_time_join(&process_root, &identities["time"], acquisition)?;
                let mut offsets = open_proc(&process_root, "timens_offsets", acquisition)?;
                let time_offsets =
                    namespace_protocol::offsets(&read_proc(&mut offsets, 1024, acquisition)?)?;
                namespace_protocol::require_zero(&time_offsets)?;
                require_process_time_join(&process_root, &identities["time"], acquisition)?;
                let mut observed = Self {
                    process,
                    thread,
                    domain,
                    facts: NamespaceFacts {
                        task: task_facts,
                        namespaces: identities,
                        offsets: time_offsets,
                    },
                    proc_root,
                    process_root,
                    task,
                    stat,
                    status,
                    offsets,
                    namespaces,
                    valid: true,
                    local: PhantomData,
                };
                observed.check(acquisition)?;
                Ok(observed)
            }
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("epoch_native_namespace_platform_unsupported")
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }

    pub(super) fn check(&mut self, acquisition: &mut NativeAcquisition) -> Result<()> {
        let result = (|| {
            ensure!(self.valid, "epoch_native_namespace_refused");
            ensure!(
                std::process::id() == self.process && std::thread::current().id() == self.thread,
                "epoch_native_task_changed"
            );
            ensure!(
                acquisition.sample()?.domain == self.domain,
                "epoch_native_namespace_acquisition_changed"
            );
            #[cfg(target_os = "linux")]
            {
                require_proc(&self.proc_root)?;
                require_proc(&self.process_root)?;
                require_proc(&self.task)?;
                // Old descriptors alone cannot establish that the fixed current
                // proc mount and kernel self-task path still join those objects.
                let proc_root = open_root(acquisition)?;
                ensure!(
                    proc_identity(&proc_root)? == proc_identity(&self.proc_root)?,
                    "epoch_native_proc_mount_changed"
                );
                let task = open_task(&proc_root, acquisition)?;
                ensure!(
                    proc_identity(&task)? == proc_identity(&self.task)?,
                    "epoch_native_task_path_changed"
                );
                let process_root = open_process(&proc_root, acquisition)?;
                ensure!(
                    proc_identity(&process_root)? == proc_identity(&self.process_root)?,
                    "epoch_native_process_path_changed"
                );
                require_process_time_join(
                    &process_root,
                    &self.facts.namespaces["time"],
                    acquisition,
                )?;
                let current = namespace_protocol::task(
                    &read_proc(&mut self.stat, 16_384, acquisition)?,
                    &read_proc(&mut self.status, 65_536, acquisition)?,
                )?;
                ensure!(current == self.facts.task, "epoch_native_task_changed");
                for name in NAMESPACES {
                    acquisition.remaining()?;
                    let original = self
                        .namespaces
                        .get(name)
                        .ok_or_else(|| anyhow::anyhow!("epoch_native_namespace_missing"))?;
                    let current = open_namespace(&task, name, acquisition)?;
                    ensure!(
                        namespace_identity(original)? == self.facts.namespaces[name]
                            && namespace_identity(&current)? == self.facts.namespaces[name],
                        "epoch_native_namespace_changed"
                    );
                }
                let offsets =
                    namespace_protocol::offsets(&read_proc(&mut self.offsets, 1024, acquisition)?)?;
                namespace_protocol::require_zero(&offsets)?;
                ensure!(offsets == self.facts.offsets, "epoch_native_timens_changed");
                require_process_time_join(
                    &process_root,
                    &self.facts.namespaces["time"],
                    acquisition,
                )?;
                acquisition.remaining()?;
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("epoch_native_namespace_platform_unsupported")
        })();
        if result.is_err() {
            self.valid = false;
            acquisition.refuse();
        }
        result
    }

    /// Discards original native descriptors and acquisition. Historical DATA
    /// cannot reconstruct this observation or a current runtime binding.
    pub(super) fn into_data(self) -> NamespaceFacts {
        self.facts
    }

    pub(super) fn data(&self) -> &NamespaceFacts {
        &self.facts
    }

    /// Actual complete mapping DATA from this retained self task. File-backed
    /// mappings and permissions do not qualify image or immutable execution.
    pub(super) fn mappings(
        &mut self,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Vec<namespace_protocol::Mapping>> {
        let result = (|| {
            self.check(acquisition)?;
            #[cfg(target_os = "linux")]
            {
                let mut file = open_proc(&self.task, "maps", acquisition)?;
                let value =
                    namespace_protocol::mappings(&read_proc(&mut file, 1_048_576, acquisition)?)?;
                self.check(acquisition)?;
                Ok(value)
            }
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("epoch_native_namespace_platform_unsupported")
        })();
        if result.is_err() {
            self.valid = false;
            acquisition.refuse();
        }
        result
    }
}

#[cfg(target_os = "linux")]
pub(super) fn require_proc(file: &std::fs::File) -> Result<()> {
    ensure!(
        rustix::fs::fstatfs(file)?.f_type == rustix::fs::PROC_SUPER_MAGIC,
        "epoch_native_procfs_required"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn open_root(acquisition: &mut NativeAcquisition) -> Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};
    acquisition.remaining()?;
    let file = std::fs::File::from(rustix::fs::open(
        "/proc",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    require_proc(&file)?;
    acquisition.remaining()?;
    Ok(file)
}

#[cfg(target_os = "linux")]
pub(super) fn open_task(
    root: &std::fs::File,
    acquisition: &mut NativeAcquisition,
) -> Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};
    acquisition.remaining()?;
    // Only this fixed kernel-owned link is followed; no caller path.
    let file = std::fs::File::from(rustix::fs::openat(
        root,
        "thread-self",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    require_proc(&file)?;
    acquisition.remaining()?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn open_process(
    root: &std::fs::File,
    acquisition: &mut NativeAcquisition,
) -> Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};
    acquisition.remaining()?;
    // This fixed kernel-owned link selects our TGID, never a supplied PID.
    let file = std::fs::File::from(rustix::fs::openat(
        root,
        "self",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    require_proc(&file)?;
    acquisition.remaining()?;
    Ok(file)
}

pub(super) fn require_process_time_join_data(
    thread_time: &NamespaceIdentity,
    process_time: &NamespaceIdentity,
    process_children: &NamespaceIdentity,
) -> Result<()> {
    ensure!(
        thread_time.inode != 0 && thread_time == process_time && thread_time == process_children,
        "epoch_native_process_timens_changed"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_process_time_join(
    process_root: &std::fs::File,
    thread_time: &NamespaceIdentity,
    acquisition: &mut NativeAcquisition,
) -> Result<()> {
    let time = open_namespace(process_root, "time", acquisition)?;
    let children = open_namespace(process_root, "time_for_children", acquisition)?;
    require_process_time_join_data(
        thread_time,
        &namespace_identity(&time)?,
        &namespace_identity(&children)?,
    )?;
    acquisition.remaining()?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn proc_identity(file: &std::fs::File) -> Result<(u32, u32, u64, u64)> {
    use rustix::fs::{AtFlags, StatxFlags};
    require_proc(file)?;
    let mask = StatxFlags::INO | StatxFlags::MNT_ID;
    let value = rustix::fs::statx(file, "", AtFlags::EMPTY_PATH, mask)?;
    ensure!(
        value.stx_mask & mask.bits() == mask.bits() && value.stx_ino != 0 && value.stx_mnt_id != 0,
        "epoch_native_proc_identity_required"
    );
    Ok((
        value.stx_dev_major,
        value.stx_dev_minor,
        value.stx_ino,
        value.stx_mnt_id,
    ))
}

#[cfg(target_os = "linux")]
pub(super) fn open_proc(
    task: &std::fs::File,
    name: &str,
    acquisition: &mut NativeAcquisition,
) -> Result<std::fs::File> {
    use anyhow::Context;
    use rustix::fs::{Mode, OFlags};
    ensure!(
        ["stat", "status", "timens_offsets", "maps"].contains(&name),
        "epoch_native_proc_path"
    );
    acquisition.remaining()?;
    let file = std::fs::File::from(
        rustix::fs::openat(
            task,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .with_context(|| format!("epoch_native_proc_open:{name}"))?,
    );
    require_proc(&file)?;
    ensure!(
        file.metadata()?.is_file(),
        "epoch_native_proc_file_required"
    );
    acquisition.remaining()?;
    Ok(file)
}

#[cfg(target_os = "linux")]
pub(super) fn open_namespace(
    task: &std::fs::File,
    name: &str,
    acquisition: &mut NativeAcquisition,
) -> Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};
    ensure!(NAMESPACES.contains(&name), "epoch_native_namespace_path");
    // The exact procfs namespace link intentionally resolves to the kernel
    // namespace object; regular user-controlled links/paths are never accepted.
    acquisition.remaining()?;
    let file = std::fs::File::from(rustix::fs::openat(
        task,
        format!("ns/{name}"),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    acquisition.remaining()?;
    Ok(file)
}

#[cfg(target_os = "linux")]
pub(super) fn namespace_identity(file: &std::fs::File) -> Result<NamespaceIdentity> {
    use std::os::unix::fs::MetadataExt;
    // Linux UAPI NSFS_MAGIC. This checks object filesystem type, not authority
    // or node initial namespace membership. Kernel/proc trust still qualified.
    ensure!(
        rustix::fs::fstatfs(file)?.f_type == 0x6e73_6673,
        "epoch_native_nsfs_required"
    );
    let metadata = file.metadata()?;
    ensure!(metadata.ino() != 0, "epoch_native_namespace_identity");
    Ok(NamespaceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(target_os = "linux")]
pub(super) fn read_proc(
    file: &mut std::fs::File,
    max: usize,
    acquisition: &mut NativeAcquisition,
) -> Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    acquisition.remaining()?;
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take((max + 1) as u64).read_to_end(&mut bytes)?;
    acquisition.remaining()?;
    ensure!(bytes.len() <= max, "epoch_native_proc_bound");
    Ok(bytes)
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::NativeNamespaceObservation;
    use crate::security_epoch::native_clock::NativeAcquisition;

    #[test]
    fn substituted_process_directory_refuses_and_keeps_original_acquisition_refused() {
        let mut acquisition = NativeAcquisition::begin(5).unwrap();
        let mut observation = NativeNamespaceObservation::acquire(&mut acquisition).unwrap();
        let unrelated = tempfile::tempdir().unwrap();
        observation.process_root = std::fs::File::open(unrelated.path()).unwrap();
        let reason = observation.check(&mut acquisition).unwrap_err().to_string();
        assert_eq!(reason, "epoch_native_procfs_required");
        assert!(!observation.valid);
        assert!(acquisition.remaining().is_err());
        assert!(observation.check(&mut acquisition).is_err());
    }
}
