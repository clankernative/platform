//! Host-owned Linux pure-worker confinement. No application-selectable policies.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux;

pub const QUALIFIED: &[u8] = b"day2-linux-sandbox-v1:qualified";
pub const ADDRESS_SPACE_BYTES: u64 = 256 * 1024 * 1024;
pub const CPU_SECONDS: u64 = 5;
pub const QUALIFIED_ADDRESS_SPACE_BYTES: u64 = 512 * 1024 * 1024;
pub const QUALIFIED_CPU_SECONDS: u64 = 30;
pub const OPEN_FILES: u64 = 32;

// TEMPORARY diagnostic source: this branch must never be promoted as a fix.
// The launcher is a fresh, single-threaded process. Only fixed numeric stages
// are retained; this state is not an admission decision or a worker capability.
static REFUSAL_STAGE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum RefusalStage {
    Arguments = 1,
    ParentIdentity,
    Profile,
    ParentDeathSignal,
    ParentRecheck,
    ResolveWorker,
    WorkerMetadata,
    WorkerMode,
    RuntimeLibraries,
    CompileFilter,
    StandardDescriptors,
    CloseDescriptors,
    WorkingDirectory,
    NoNewPrivileges,
    Dumpable,
    AddressSpaceLimit,
    CpuLimit,
    FileDescriptorLimit,
    ProcessLimit,
    CoreLimit,
    FileSizeLimit,
    CreateLandlock,
    WorkerRule,
    RuntimeRule,
    EnforceLandlock,
    EnforceSeccomp,
    ExecuteWorker,
}

pub fn mark_refusal_stage(stage: RefusalStage) {
    REFUSAL_STAGE.store(stage as u8, std::sync::atomic::Ordering::Relaxed);
}

/// A child-reported diagnostic, never proof of the original exit cause.
/// An untrusted child can forge a record; it must still fail the exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefusalReport {
    pub stage: u8,
    pub errno: Option<i32>,
}

impl RefusalReport {
    pub fn from_error(error: &anyhow::Error) -> Self {
        let errno = error.chain().find_map(|cause| {
            if let Some(error) = cause.downcast_ref::<std::io::Error>() {
                return error.raw_os_error();
            }
            #[cfg(target_os = "linux")]
            if let Some(error) = cause.downcast_ref::<nix::errno::Errno>() {
                return Some(*error as i32);
            }
            None
        });
        Self {
            stage: REFUSAL_STAGE.load(std::sync::atomic::Ordering::Relaxed),
            errno,
        }
    }

    pub fn parse(frame: &[u8]) -> Option<Self> {
        if frame.len() > 64 {
            return None;
        }
        let text = std::str::from_utf8(frame).ok()?;
        let fields = text.strip_prefix("day2-launch-refusal-v1 stage=")?;
        let (stage, errno) = fields.split_once(" errno=")?;
        if !stage.bytes().all(|byte| byte.is_ascii_digit())
            || !errno.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let stage: u8 = stage.parse().ok()?;
        let errno: i32 = errno.parse().ok()?;
        if !(1..=RefusalStage::ExecuteWorker as u8).contains(&stage) {
            return None;
        }
        Some(Self { stage, errno: (errno != 0).then_some(errno) })
    }
}

impl std::fmt::Display for RefusalReport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "day2-launch-refusal-v1 stage={} errno={}", self.stage, self.errno.unwrap_or(0))
    }
}

/// Refusing a file-backed protocol descriptor must not write into that file.
#[cfg(target_os = "linux")]
pub fn refusal_stdout_is_pipe() -> bool {
    use nix::sys::stat::{SFlag, fstat};
    fstat(std::io::stdout()).is_ok_and(|stat| {
        SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT == SFlag::S_IFIFO
    })
}

#[cfg(not(target_os = "linux"))]
pub fn refusal_stdout_is_pipe() -> bool {
    false
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LaunchProfile {
    Ordinary,
    QualifiedProperty,
}

#[cfg(any(target_os = "linux", test))]
impl LaunchProfile {
    pub(crate) const fn worker_argument(self) -> Option<&'static str> {
        match self {
            Self::Ordinary => None,
            Self::QualifiedProperty => Some("--day2-qualified-property-v1"),
        }
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn profile_for_limits(
    memory_bytes: u64,
    cpu_seconds: u64,
) -> anyhow::Result<LaunchProfile> {
    match (memory_bytes, cpu_seconds) {
        (ADDRESS_SPACE_BYTES, CPU_SECONDS) => Ok(LaunchProfile::Ordinary),
        (QUALIFIED_ADDRESS_SPACE_BYTES, QUALIFIED_CPU_SECONDS) => {
            Ok(LaunchProfile::QualifiedProperty)
        }
        _ => anyhow::bail!("unreviewed worker resource profile"),
    }
}

#[cfg(target_os = "linux")]
pub use linux::launch;

#[cfg(not(target_os = "linux"))]
pub fn launch(
    _worker: &std::path::Path,
    _parent: u32,
    _memory_bytes: u64,
    _cpu_seconds: u64,
) -> anyhow::Result<()> {
    anyhow::bail!("day2-sandbox requires Linux with enforced Landlock and seccomp")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_records_are_bounded_numeric_and_never_retain_error_text() {
        mark_refusal_stage(RefusalStage::ResolveWorker);
        let error = anyhow::Error::from(std::io::Error::from_raw_os_error(2))
            .context("PRIVATE_PATH PRIVATE_ENV PRIVATE_FRAME");
        let report = RefusalReport::from_error(&error);
        assert_eq!(report.stage, RefusalStage::ResolveWorker as u8);
        assert_eq!(report.errno, Some(2));
        let encoded = report.to_string();
        assert!(encoded.len() <= 64 && !encoded.contains("PRIVATE"));
        assert_eq!(RefusalReport::parse(encoded.as_bytes()), Some(report));
        for invalid in [
            "day2-launch-refusal-v1 stage=0 errno=2",
            "day2-launch-refusal-v1 stage=255 errno=2",
            "day2-launch-refusal-v1 stage=6 errno=-2",
            "day2-launch-refusal-v1 stage=6 errno=2 PRIVATE_ENV",
            "day2-launch-refusal-v1 stage=6 errno=2\nPRIVATE_FRAME",
            "day2-launch-refusal-v1 stage=6 errno=99999999999999999999999999999999999999",
            "PRIVATE_PATH PRIVATE_ENV PRIVATE_FRAME",
        ] {
            assert!(RefusalReport::parse(invalid.as_bytes()).is_none());
        }
    }

    #[test]
    fn permits_only_reviewed_resource_pairs_and_selects_native_argument() {
        assert_eq!(
            profile_for_limits(ADDRESS_SPACE_BYTES, CPU_SECONDS).unwrap(),
            LaunchProfile::Ordinary
        );
        assert_eq!(LaunchProfile::Ordinary.worker_argument(), None);
        assert_eq!(
            profile_for_limits(QUALIFIED_ADDRESS_SPACE_BYTES, QUALIFIED_CPU_SECONDS).unwrap(),
            LaunchProfile::QualifiedProperty
        );
        assert_eq!(
            LaunchProfile::QualifiedProperty.worker_argument(),
            Some("--day2-qualified-property-v1")
        );
        for pair in [
            (ADDRESS_SPACE_BYTES, QUALIFIED_CPU_SECONDS),
            (QUALIFIED_ADDRESS_SPACE_BYTES, CPU_SECONDS),
            (ADDRESS_SPACE_BYTES + 1, CPU_SECONDS),
            (0, 0),
        ] {
            assert!(profile_for_limits(pair.0, pair.1).is_err());
        }
    }
}
