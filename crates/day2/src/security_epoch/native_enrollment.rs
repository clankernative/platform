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
mod handshake;
#[cfg(test)]
pub(in crate::security_epoch) use handshake::simulation::{
    LifecycleHandshake, LifecycleModelError, LifecycleProgress, LifecycleReference,
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
mod restore_peer_wire;
mod restore_writer;
pub(in crate::security_epoch) use restore_writer::{ReceiverAction, ReceiverProgress};
mod restored;
pub(crate) use restored::{RestoredArtifactAdmission, RestoredKeeperBirth, RestoredRuntimeBirth};
mod root_kms;
#[cfg(target_os = "linux")]
mod runtime;
#[cfg(target_os = "linux")]
mod runtime_reads;
#[cfg(target_os = "linux")]
mod runtime_wire;
#[cfg(target_os = "linux")]
mod service;
#[cfg(test)]
mod service_source_tests;
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

pub(in crate::security_epoch) use restore_peer_wire::{
    Activation as RestoreWriterActivationData, AdminPeerResult, AuthorityStopData,
    Creator as RestoreCreatorData, LedgerKeys as RestoreLedgerKeysData,
    Projection as RestoreFileProjectionData, Selection as RestoreSelectionData,
};
pub(crate) use serving_peer::{
    ControllerServingListener, ControllerServingPeer, ControllerServingRendezvous,
    CurrentServingPeerPhase, ShellServingConnection, ShellServingPeer,
};
pub(in crate::security_epoch) use storage_peer::RestoredPeerConnection;
pub(crate) use storage_peer::{
    AppHolderPeerContinuity, AuthenticatedAppFirstHolder, AuthenticatedControllerFirstHolder,
    AuthenticatedInitialHolderOffer, ControllerCurrentRendezvous, ControllerHolderPeerContinuity,
    CurrentStoragePeerPhase, InitialHolderConnection, InitialHolderListener, InitialHolderServer,
    PendingAppCurrentPeer, QueuedAppCurrentPeer,
};
pub(crate) use storage_peer_wire::{AdminReadAction, SqliteCohort, StoragePeerRequest};

// Private actual-resource port at the common owning boundary. Only the fixed
// restored-App attempt fills it. It is neither a public parts API nor a role,
// SQL, Current or installation permission. Its history always owns the first
// keeper before the raw main/WAL/SHM anchors can close.
struct RestoredRoleInstallPort {
    history: restored::AcceptedRestoredApp,
    runtime: crate::store::Runtime,
    #[cfg(target_os = "linux")]
    policy: policy::EnrollmentPolicy,
    #[cfg(target_os = "linux")]
    key: std::rc::Rc<protocol::KeyOwner>,
    #[cfg(target_os = "linux")]
    certificate: protocol::IssuerCertificate,
    #[cfg(target_os = "linux")]
    policy_file: std::rc::Rc<std::cell::RefCell<birth::PolicyFileOwner>>,
    #[cfg(target_os = "linux")]
    current: std::rc::Rc<std::cell::RefCell<process::SelfSnapshot>>,
    #[cfg(target_os = "linux")]
    issuer: std::rc::Rc<std::cell::RefCell<issuer_peer::IssuerReceipt>>,
    #[cfg(target_os = "linux")]
    nonce_peer: std::rc::Rc<std::cell::RefCell<issuer_peer::IssuerReceipt>>,
    #[cfg(target_os = "linux")]
    channel: std::rc::Rc<channel::Channel>,
    #[cfg(target_os = "linux")]
    admission: protocol::SignedStage,
    #[cfg(target_os = "linux")]
    original: crate::security_epoch::native_clock::NativeAcquisition,
    #[cfg(target_os = "linux")]
    clock: crate::security_epoch::native_clock::NativeConnectionClock,
}

/// Fixed native transfer input, never a socket/parts API. Only the actual
/// installed owners may fill it after proving their real retirement and fresh
/// same-connection request. The completed cursor and native anchor move once.
struct RestoredCurrentPeerPort<'tail> {
    #[cfg(target_os = "linux")]
    socket: Option<std::rc::Rc<std::fs::File>>,
    #[cfg(target_os = "linux")]
    transcript: Option<handshake::Transcript>,
    #[cfg(target_os = "linux")]
    anchor: Option<RestoredPeerAnchor>,
    #[cfg(target_os = "linux")]
    same: Option<owner::SameEnrolledOwner>,
    #[cfg(target_os = "linux")]
    local: storage_peer_wire::StageStatement,
    #[cfg(target_os = "linux")]
    remote: storage_peer_wire::StageStatement,
    #[cfg(target_os = "linux")]
    binding: day2_capabilities::Digest,
    #[cfg(target_os = "linux")]
    native_refusal: Option<crate::security_epoch::native_clock::NativeOriginalRefusal>,
    #[cfg(target_os = "linux")]
    original: Option<crate::security_epoch::native_clock::NativeAcquisition>,
    #[cfg(target_os = "linux")]
    channel_refusal: std::rc::Rc<std::cell::Cell<bool>>,
    tail: Option<RestoredPeerTail<'tail>>,
    completed: bool,
    local_only: std::marker::PhantomData<std::rc::Rc<()>>,
}

/// Borrowed negative comparison input constructed by Channel from its actual
/// retained resources. It grants nothing and has no public factory or getter.
struct RestoredPeerSource<'source> {
    #[cfg(target_os = "linux")]
    socket: &'source std::rc::Rc<std::fs::File>,
    #[cfg(target_os = "linux")]
    refusal: &'source std::rc::Rc<std::cell::Cell<bool>>,
    local: &'source storage_peer_wire::StageStatement,
    remote: &'source storage_peer_wire::StageStatement,
    binding: &'source day2_capabilities::Digest,
}

/// Keep the complete historical owners alive; only their fresh negative and
/// physical checks may run after retirement. No old positive clock is used.
enum RestoredPeerTail<'tail> {
    App(std::rc::Rc<restored::RestoredAppHistory>),
    Controller {
        peer: &'tail mut owner::RestoredWriterPeer,
        installed: &'tail mut owner::InstalledRestoredAppConfirmation,
    },
}

#[cfg(target_os = "linux")]
enum RestoredPeerAnchor {
    App(Box<process::MessageProcess>),
    Controller(restored::RestoredControllerReceipt),
}

impl RestoredPeerTail<'_> {
    fn check_current(
        &mut self,
        binding: &day2_capabilities::Digest,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut crate::security_epoch::native_clock::NativeAcquisition,
    ) -> anyhow::Result<()> {
        match self {
            Self::App(history) => {
                let selected = history.check_current_transfer(binding);
                let keeper = history.check_current_resources(stage);
                let peer = history.check_current_peer_anchors(stage, acquisition);
                let native = stage.check();
                if selected.is_err() || keeper.is_err() || peer.is_err() || native.is_err() {
                    history.refuse();
                    acquisition.refuse();
                    stage.refuse_serving();
                }
                selected?;
                keeper?;
                peer?;
                native
            }
            Self::Controller { peer, installed } => {
                installed.check_current_tail(peer, binding, stage, acquisition)
            }
        }
    }

    fn check_source(&mut self, source: &RestoredPeerSource<'_>) -> anyhow::Result<()> {
        match self {
            Self::App(history) => history.check_current_source(source),
            Self::Controller { peer, installed } => installed.check_current_source(peer, source),
        }
    }

    fn refuse(&mut self) {
        match self {
            Self::App(history) => history.refuse(),
            Self::Controller { peer, installed } => {
                peer.refuse();
                installed.refuse();
            }
        }
    }
}

impl Drop for RestoredCurrentPeerPort<'_> {
    fn drop(&mut self) {
        if !self.completed {
            #[cfg(target_os = "linux")]
            {
                self.channel_refusal.set(true);
                if let Some(original) = &self.native_refusal {
                    original.refuse();
                }
            }
            if let Some(tail) = &mut self.tail {
                tail.refuse();
            }
        }
    }
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <RestoredCurrentPeerPort<'static> as Ambiguous<_>>::check;
            let _ = <RestoredPeerConnection<'static> as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(Clone);
    assert_not_impl!(Copy);
    assert_not_impl!(Default);
    assert_not_impl!(std::fmt::Debug);
    assert_not_impl!(Send);
    assert_not_impl!(Sync);
    assert_not_impl!(serde::Serialize);
    assert_not_impl!(serde::Deserialize<'static>);
};

/// Closed current-peer request DATA, never storage or serving permission.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StoragePeerPurpose {
    AdminRead,
    BootstrapCreate,
    BootstrapComplete,
    CurrentServing,
}

pub(crate) use day2_capabilities::security_epoch::bootstrap::NativeRole;
pub(in crate::security_epoch) use owner::PendingRestoredEnrollment;
pub(in crate::security_epoch) use owner::{
    ActivatedRestoredAppRole, CapturedRestoredAppRequest, CompletedRestoreIssuer,
    InstalledRestoredAppConfirmation, IssuerRestoreFinishing, IssuerRestorePreparation,
    IssuerRestoreRoleActivating, PreparedRestoreAdmission, PreparedRestoredAppConfirmation,
    ReceiverDurability, ReceiverRendezvous, RestorePreparationData, RestoredAppCurrentPeer,
    RestoredWriterPeer, RetainedControllerNative, RetiredRestoredAppNative,
};
pub(crate) use owner::{
    EnrolledCurrentRequest, EnrolledOriginalClock, EnrolledProcessRoleOwner, EnrolledRoleStage,
    EnrolledStorageStage, FrozenRoleIssuer, NativeConsumerCompletion, NativeConsumerOrigin,
    RestoredAppRequestSettlement, SameEnrolledOwner, UnselectedShellRequest,
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
