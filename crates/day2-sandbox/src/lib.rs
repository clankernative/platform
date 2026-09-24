//! Host-owned Linux pure-worker confinement. No application-selectable policies.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux;

pub const QUALIFIED: &[u8] = b"day2-linux-sandbox-v1:qualified";
pub const ADDRESS_SPACE_BYTES: u64 = 256 * 1024 * 1024;
pub const CPU_SECONDS: u64 = 5;
pub const OPEN_FILES: u64 = 32;

#[cfg(target_os = "linux")]
pub use linux::launch;

#[cfg(not(target_os = "linux"))]
pub fn launch(_worker: &std::path::Path, _parent: u32) -> anyhow::Result<()> {
    anyhow::bail!("day2-sandbox requires Linux with enforced Landlock and seccomp")
}
