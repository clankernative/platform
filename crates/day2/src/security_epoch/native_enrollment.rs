//! Company-rooted native process enrollment. This supplies process/code role
//! stages, never a human authentication, storage, epoch or business permission.
//!
//! The signing root is operator-owned. Parsed certificates are DATA. A stage
//! additionally owns the original received kernel process handle, current native
//! self observations and one original bounded acquisition. Ordinary role work
//! remains five seconds; only the closed first-holder handshake uses ten.

#[cfg(target_os = "linux")]
mod birth;
#[cfg(target_os = "linux")]
mod channel;
#[cfg(any(target_os = "linux", test))]
mod executable_bytes;
#[cfg(any(target_os = "linux", test))]
mod handshake;
#[cfg(test)]
pub(in crate::security_epoch) use handshake::simulation::{
    LifecycleHandshake, LifecycleModelError,
};
pub(in crate::security_epoch) mod issuer_costs;
#[cfg(target_os = "linux")]
mod issuer_peer;
#[cfg(target_os = "linux")]
mod operations;
mod owner;
#[cfg(any(target_os = "linux", test))]
mod peer_idle;
mod policy;
#[cfg(target_os = "linux")]
mod process;
mod protocol;
#[cfg(target_os = "linux")]
mod qualification;
mod root_kms;
#[cfg(target_os = "linux")]
mod runtime;
#[cfg(target_os = "linux")]
mod runtime_reads;
#[cfg(target_os = "linux")]
mod runtime_wire;
#[cfg(target_os = "linux")]
mod service;
mod serving_peer;
#[cfg(target_os = "linux")]
mod serving_peer_native;
mod serving_peer_wire;
mod storage_peer;
#[cfg(target_os = "linux")]
mod storage_peer_native;
mod storage_peer_wire;
#[cfg(target_os = "linux")]
mod storage_socket_directory;

pub(crate) use serving_peer::{
    ControllerServingListener, ControllerServingPeer, ControllerServingRendezvous,
    CurrentServingPeerPhase, ShellServingConnection, ShellServingPeer,
};
pub(crate) use storage_peer::{
    AppHolderPeerContinuity, AuthenticatedAppFirstHolder, AuthenticatedControllerFirstHolder,
    AuthenticatedInitialHolderOffer, ControllerCurrentRendezvous, ControllerHolderPeerContinuity,
    CurrentStoragePeerPhase, InitialHolderConnection, InitialHolderListener, InitialHolderServer,
    PendingAppCurrentPeer, QueuedAppCurrentPeer,
};
pub(crate) use storage_peer_wire::StoragePeerRequest;

/// Closed current-peer request DATA, never storage or serving permission.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StoragePeerPurpose {
    BootstrapCreate,
    BootstrapComplete,
    CurrentServing,
}

pub(crate) use day2_capabilities::security_epoch::bootstrap::NativeRole;
pub(crate) use owner::{
    EnrolledOriginalClock, EnrolledProcessRoleOwner, EnrolledRoleStage, EnrolledStorageStage,
    SameEnrolledOwner,
};
pub(in crate::security_epoch) use protocol::StagePurpose;

pub(crate) fn run(issuer: bool) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if issuer {
            service::run().map_err(|error| error.context("native_enrollment_issuer"))
        } else {
            operations::run()
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = issuer;
        anyhow::bail!("native_enrollment_platform_unsupported")
    }
}

pub(crate) fn qualify(role: &str) -> anyhow::Result<serde_json::Value> {
    #[cfg(target_os = "linux")]
    {
        let role = match role {
            "app_host" => NativeRole::AppHost,
            "security_shell" => NativeRole::SecurityShell,
            "epoch_controller" => NativeRole::EpochController,
            _ => anyhow::bail!("native_qualification_role_required"),
        };
        qualification::run(role)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = role;
        anyhow::bail!("native_enrollment_platform_unsupported")
    }
}

#[cfg(test)]
mod tests;
