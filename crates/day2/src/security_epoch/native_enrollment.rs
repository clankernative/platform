//! Company-rooted native process enrollment. This supplies process/code role
//! stages, never a human authentication, storage, epoch or business permission.
//!
//! The signing root is operator-owned. Parsed certificates are DATA. A stage
//! additionally owns the original received kernel process handle, current native
//! self observations and the one original five-second acquisition.

#[cfg(target_os = "linux")]
mod birth;
#[cfg(target_os = "linux")]
mod channel;
#[cfg(target_os = "linux")]
mod issuer_peer;
mod owner;
mod policy;
#[cfg(target_os = "linux")]
mod process;
mod protocol;
mod root_kms;
#[cfg(target_os = "linux")]
mod runtime;
#[cfg(target_os = "linux")]
mod runtime_wire;
#[cfg(target_os = "linux")]
mod service;
mod storage_peer;
#[cfg(target_os = "linux")]
mod storage_socket_directory;

pub(crate) use storage_peer::{
    AuthenticatedAppFirstHolder, AuthenticatedControllerFirstHolder,
    AuthenticatedInitialHolderOffer, InitialHolderServer,
};

pub(crate) use day2_capabilities::security_epoch::bootstrap::NativeRole;
pub(crate) use owner::{
    EnrolledOriginalClock, EnrolledProcessRoleOwner, EnrolledRoleStage, SameEnrolledOwner,
};

pub(crate) fn run(issuer: bool) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if issuer { service::run() } else { birth::run() }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = issuer;
        anyhow::bail!("native_enrollment_platform_unsupported")
    }
}

#[cfg(test)]
mod tests;
