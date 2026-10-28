//! Bounded historical observations from the real Controller executor. Nothing
//! accepts these records as a native owner, permission, readiness or replay.
use super::bootstrap_timing::Snapshot as BootstrapSnapshot;
use super::preparation_timing::Summary;
use super::serving_timing::Snapshot as ServingSnapshot;
use crate::security_epoch::{
    bootstrap::{Action, ServingObservation},
    kernel::{Holder, Request, Snapshot},
    seed_core::OriginalSeedCore,
    transport::FailedRequestWindow,
};
use anyhow::{Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy},
};
use serde::Serialize;
use std::io::{Stderr, Write};

pub(super) const PREFIX: &str = "day2-native-controller-evidence ";
const MAX_RECORD_BYTES: usize = 2048;
const MAX_RECORDS: u8 = 12;
const LISTENER_PREFIX: &str = "day2-native-controller-listener ";
const MAX_LISTENER_BYTES: usize = 512;
const SELF_CHECK_PREFIX: &str = "day2-native-controller-self-check ";
const MAX_SELF_CHECK_BYTES: usize = 1024;
// The full redacted original/producer commitments must fit alongside maximal
// existing cost rows. This is a diagnostic byte bound, never a work budget.
const MAX_CURRENT_SELF_CHECK_BYTES: usize = 4096;
const MAX_CURRENT_SELF_CHECK_RECORDS: u16 = 256;

pub(in crate::security_epoch) type Evidence = Recorder<StderrOutput>;

pub(in crate::security_epoch) struct StderrOutput {
    stream: Stderr,
}

pub(in crate::security_epoch) trait RecordOutput {
    fn append(&mut self, record: &[u8]) -> std::io::Result<()>;
}

struct CurrentServingJoin {
    role: ServingRole,
    request: Option<super::super::native_enrollment::EnrolledRequestDiagnosticData>,
    peer: Option<super::super::native_enrollment::PeerRequestDiagnosticData>,
}

struct CurrentAdmissionWork {
    role: ServingRole,
    before: Option<super::super::admission_work::Snapshot>,
    now: Option<super::super::admission_work::Snapshot>,
}

impl RecordOutput for StderrOutput {
    fn append(&mut self, record: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(record)
    }
}

pub(in crate::security_epoch) struct Recorder<W> {
    output: W,
    selection: Option<Digest>,
    incarnation: Option<Digest>,
    first_holder: bool,
    next: usize,
    activated: bool,
    serving: [bool; 2],
    records: u8,
    listener_attempted: bool,
    self_check_exported: u8,
    current_self_check_records: u16,
    current_join_records: u64,
    at: FailurePhase,
    refused: bool,
    export_failed: bool,
    preparation_timing: Option<Summary>,
    bootstrap_timing: Option<BootstrapSnapshot>,
    serving_timing: Option<ServingSnapshot>,
    current_serving_profile: Option<super::super::self_check_profile::CurrentProfile>,
    current_serving_join: Option<CurrentServingJoin>,
    current_admission_work: Option<CurrentAdmissionWork>,
    read_only_observed: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::security_epoch) enum FailurePhase {
    Selection,
    Enrollment,
    Preparation,
    HolderListener,
    FirstHolder,
    CreateReserve,
    CreateDispatch,
    CreateSettle,
    ActivateReserve,
    ActivateDispatch,
    ActivateSettle,
    Activation,
    CounterAdmission,
    ServingListener,
    AppPending,
    AppServing,
    ShellPending,
    ShellAccept,
    ShellServing,
    CounterReadmission,
    Health,
}

/// Fixed diagnostic DATA only. No field carries a path, URL, response body,
/// credential, arbitrary message, measured latency assertion or permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::security_epoch) enum PreparationStep {
    Unknown,
    RoleStage,
    StorageAcquisition,
    StorageProfile,
    ClusterCa,
    TransportSetup,
    MetadataCredential,
    ProjectIdentity,
    ClusterIdentity,
    ControllerIdentity,
    ControllerCredential,
    EpochDatabase,
    KubernetesCredential,
    ClaimBinding,
    VolumeBinding,
    NodeBoot,
    NodeBinding,
    DiskBinding,
    InstanceBinding,
    VolumeDirectory,
    VolumeIdentity,
    BlockDevice,
    VolumeCurrent,
    Seed,
    PrivateDirectory,
    ImageAdmission,
    OriginalPreparation,
    OriginalRetention,
    OriginalRetentionBefore,
    OriginalRetentionOwner,
    OriginalRetentionAfter,
    HolderRoleStage,
    HolderFilePhase,
    HolderListenerBind,
    HolderOwner,
    HolderProjection,
    HolderInterval,
    HolderTransport,
    HolderFinalCheck,
    FirstRole,
    FirstReady,
    FirstFile,
    FirstStart,
    FirstExchange,
    FirstCheck,
    FirstProjection,
    FirstAccept,
    FirstHello,
    FirstPeer,
    FirstOffer,
    FirstConfirm,
    FirstComplete,
    FirstAccepted,
    FirstDurability,
    FirstRetain,
    BootstrapWaitApp,
    BootstrapRole,
    BootstrapCore,
    BootstrapFilePeer,
    BootstrapReady,
    BootstrapFile,
    BootstrapDurability,
    BootstrapPeer,
    BootstrapPeerCheck,
    BootstrapTransport,
    BootstrapNames,
    BootstrapCounterBefore,
    BootstrapSlotBefore,
    BootstrapExecution,
    BootstrapReservePrepare,
    BootstrapReserveSend,
    BootstrapDispatchPrepare,
    BootstrapDispatchRecordSend,
    BootstrapDispatchCounterSend,
    BootstrapSettlePrepare,
    BootstrapSettleSend,
    BootstrapCounterAfter,
    BootstrapSlotAfter,
    BootstrapValidation,
    BootstrapAnnouncement,
    BootstrapRelease,
    BootstrapSnapshotBefore,
    BootstrapSnapshotAfter,
    CounterRoleStage,
    CounterPendingFile,
    CounterPhysicalAcquire,
    CounterStage,
    CounterAdmit,
    CounterPhysicalFinish,
    CounterProviderAcquire,
    CounterMetadataSource,
    CounterIamMint,
    CounterTokenInfo,
    CounterMaterial,
    CounterStagePostcheck,
    CounterOriginalPostcheck,
}

/// Cumulative microseconds from the last successful samples of the SAME
/// original acquisition at fixed boundaries. No clock is read for these fields;
/// absent samples stay absent. Values are historical progress DATA, not exact
/// boundary timestamps, operation durations, remaining time or authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(in crate::security_epoch) struct PreparationProgress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::security_epoch) acquired_us: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::security_epoch) image_us: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::security_epoch) prepared_us: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::security_epoch) last_checked_us: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PreparationErrorCategory {
    ClockExpiredOrRewound,
    AcquisitionRefused,
    TransportUnavailable,
    SocketPollTimeout,
    SocketUnexpectedEvents,
    ChannelClosed,
    ChannelProfileChanged,
    RemoteStageExpired,
    ProcessExited,
    ProcessNotVisible,
    ProcessIdentityChanged,
    #[cfg(target_os = "linux")]
    PacketSocketProfile,
    #[cfg(target_os = "linux")]
    PacketEmptyPayloadBuffer,
    #[cfg(target_os = "linux")]
    PacketClosedOrEmpty,
    #[cfg(target_os = "linux")]
    PacketTruncated,
    #[cfg(target_os = "linux")]
    PacketMalformedAncillary,
    #[cfg(target_os = "linux")]
    PacketUnexpectedAncillary,
    #[cfg(target_os = "linux")]
    PacketMissingProcess,
    #[cfg(target_os = "linux")]
    PacketDuplicateProcess,
    #[cfg(target_os = "linux")]
    PacketSenderUnavailable,
    #[cfg(target_os = "linux")]
    PacketMissingCredentials,
    #[cfg(target_os = "linux")]
    PacketDuplicateCredentials,
    #[cfg(target_os = "linux")]
    PacketMalformedCredentials,
    #[cfg(target_os = "linux")]
    PacketDescriptorNotCloexec,
    ResponseStatusOrBound,
    ResponseBadRequest,
    ResponseUnauthorized,
    ResponseForbidden,
    ResponseNotFound,
    ResponseMethodNotAllowed,
    ResponseRequestTimeout,
    ResponseLengthRequired,
    ResponseRateLimited,
    ResponseServerError,
    ResponseOtherStatus,
    ResponseDeclaredLengthBound,
    ResponseMetadataFlavor,
    AdmissionRejected,
    PermissionDenied,
    NotFound,
    AlreadyExists,
    TimedOut,
    PathResolution,
    Unsupported,
    Io,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(in crate::security_epoch) struct PreparationFailure {
    step: PreparationStep,
    category: PreparationErrorCategory,
    #[serde(skip_serializing_if = "Option::is_none")]
    progress: Option<PreparationProgress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<FailedRequestWindow>,
}

/// Read-only projection of an actual annotated cold-admission failure. These
/// private closed fields cannot carry a provider error, URL, credential or body.
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct CounterAdmissionResponseRefusal {
    producer: CounterAdmissionProducer,
    category: PreparationErrorCategory,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum CounterAdmissionProducer {
    Provider,
    Metadata,
    Mint,
    TokenInfo,
    Material,
    Stage,
    Original,
}

impl CounterAdmissionResponseRefusal {
    pub(crate) fn observe(error: &anyhow::Error) -> Option<Self> {
        let context = error.downcast_ref::<PreparationFailure>()?;
        if context.category == PreparationErrorCategory::Other {
            return None;
        }
        let producer = match context.step {
            PreparationStep::CounterProviderAcquire => CounterAdmissionProducer::Provider,
            PreparationStep::CounterMetadataSource => CounterAdmissionProducer::Metadata,
            PreparationStep::CounterIamMint => CounterAdmissionProducer::Mint,
            PreparationStep::CounterTokenInfo => CounterAdmissionProducer::TokenInfo,
            PreparationStep::CounterMaterial => CounterAdmissionProducer::Material,
            PreparationStep::CounterStagePostcheck => CounterAdmissionProducer::Stage,
            PreparationStep::CounterOriginalPostcheck => CounterAdmissionProducer::Original,
            _ => return None,
        };
        Some(Self {
            producer,
            category: context.category,
        })
    }

    #[cfg(test)]
    pub(crate) fn maximal_fixture() -> Self {
        Self {
            producer: CounterAdmissionProducer::TokenInfo,
            category: PreparationErrorCategory::ResponseDeclaredLengthBound,
        }
    }
}

impl std::fmt::Display for PreparationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native preparation boundary refused")
    }
}

impl PreparationFailure {
    /// Preserve the innermost annotated actual boundary. This only adds error
    /// context; the original error and every existing refusal remain intact.
    pub(in crate::security_epoch) fn at(
        step: PreparationStep,
        error: anyhow::Error,
    ) -> anyhow::Error {
        if error.downcast_ref::<Self>().is_some() {
            return error;
        }
        let context = Self {
            step,
            category: preparation_error_category(&error),
            progress: None,
            request: FailedRequestWindow::observe(&error),
        };
        error.context(context)
    }

    pub(in crate::security_epoch) fn with_progress(
        step: PreparationStep,
        error: anyhow::Error,
        mut progress: PreparationProgress,
    ) -> anyhow::Error {
        let mut context = Self::observe(&error);
        if context.step == PreparationStep::Unknown {
            context.step = step;
        }
        if let Some(inner) = context.progress {
            progress.acquired_us = progress.acquired_us.or(inner.acquired_us);
            progress.image_us = progress.image_us.or(inner.image_us);
            progress.prepared_us = progress.prepared_us.or(inner.prepared_us);
            progress.last_checked_us = inner.last_checked_us.or(progress.last_checked_us);
        }
        context.progress = Some(progress);
        error.context(context)
    }

    fn observe(error: &anyhow::Error) -> Self {
        error.downcast_ref::<Self>().copied().unwrap_or(Self {
            step: PreparationStep::Unknown,
            category: preparation_error_category(error),
            progress: None,
            request: FailedRequestWindow::observe(error),
        })
    }
}

pub(super) fn preparation_error_category(error: &anyhow::Error) -> PreparationErrorCategory {
    use crate::security_epoch::transport::ResponseRefusal as Counter;
    use PreparationErrorCategory as Category;
    if let Some(counter) = error.downcast_ref::<Counter>() {
        return match counter {
            Counter::BadRequest => Category::ResponseBadRequest,
            Counter::Unauthorized => Category::ResponseUnauthorized,
            Counter::Forbidden => Category::ResponseForbidden,
            Counter::NotFound => Category::ResponseNotFound,
            Counter::MethodNotAllowed => Category::ResponseMethodNotAllowed,
            Counter::RequestTimeout => Category::ResponseRequestTimeout,
            Counter::LengthRequired => Category::ResponseLengthRequired,
            Counter::RateLimited => Category::ResponseRateLimited,
            Counter::ServerError => Category::ResponseServerError,
            Counter::OtherStatus => Category::ResponseOtherStatus,
            Counter::DeclaredLengthBound => Category::ResponseDeclaredLengthBound,
            Counter::MetadataFlavor => Category::ResponseMetadataFlavor,
        };
    }
    // Inspect only stored message DATA against a closed list. Never format the
    // error, walk Display causes, or emit an unrecognized string.
    let code = error
        .downcast_ref::<&'static str>()
        .copied()
        .or_else(|| error.downcast_ref::<String>().map(String::as_str));
    match code {
        Some("native_enrollment_socket_poll_timeout") => return Category::SocketPollTimeout,
        Some("native_enrollment_socket_unexpected_events") => {
            return Category::SocketUnexpectedEvents;
        }
        Some("storage_peer_channel_closed" | "storage_peer_idle_channel_closed") => {
            return Category::ChannelClosed;
        }
        Some("storage_peer_channel_cloexec_required" | "storage_peer_listener_cloexec_lost") => {
            return Category::ChannelProfileChanged;
        }
        Some("storage_peer_remote_stage_expired") => return Category::RemoteStageExpired,
        Some("native_enrollment_process_exited") => return Category::ProcessExited,
        Some("native_enrollment_pid_not_visible" | "storage_peer_controller_pid_not_visible") => {
            return Category::ProcessNotVisible;
        }
        Some(
            "native_enrollment_process_owner_changed"
            | "native_enrollment_proc_mount_changed"
            | "native_enrollment_process_replaced"
            | "native_enrollment_process_start_changed"
            | "native_enrollment_boot_changed"
            | "native_enrollment_code_mismatch"
            | "native_enrollment_namespace_changed"
            | "native_enrollment_child_time_namespace"
            | "native_enrollment_process_leader",
        ) => return Category::ProcessIdentityChanged,
        Some(
            "epoch_native_clock_rewind_or_expired"
            | "epoch_native_acquisition_expired"
            | "epoch_native_narrowed_acquisition_expired"
            | "epoch_counter_credential_expired"
            | "epoch_counter_connection_clock_rewind"
            | "native_enrollment_stage_expired",
        ) => return Category::ClockExpiredOrRewound,
        Some(
            "epoch_native_acquisition_refused"
            | "native_enrollment_owner_refused"
            | "epoch_counter_credential_refused",
        ) => {
            return Category::AcquisitionRefused;
        }
        Some(
            "epoch_native_transport_unavailable"
            | "epoch_native_response_unavailable"
            | "epoch_native_metadata_unavailable"
            | "epoch_counter_tokeninfo_unavailable"
            | "epoch_counter_tokeninfo_transport",
        ) => return Category::TransportUnavailable,
        Some(
            "epoch_native_response_status_or_bound"
            | "epoch_native_metadata_status_or_bound"
            | "epoch_counter_tokeninfo_status_or_bound",
        ) => {
            return Category::ResponseStatusOrBound;
        }
        Some(
            "storage_provider_selection_mismatch"
            | "storage_provider_kubernetes_identity"
            | "storage_provider_claim_binding"
            | "storage_provider_volume_binding"
            | "storage_provider_node_binding"
            | "storage_provider_disk_binding"
            | "storage_provider_instance_binding"
            | "storage_provider_attachment_binding"
            | "storage_provider_attachment_missing"
            | "storage_provider_attachment_ambiguous"
            | "storage_native_mount_binding"
            | "storage_native_block_device_mismatch"
            | "storage_native_private_anchor_profile"
            | "epoch_preparation_admitted_schema_mismatch"
            | "epoch_preparation_runtime_selection_mismatch"
            | "epoch_counter_tokeninfo_bound"
            | "epoch_counter_tokeninfo_shape"
            | "epoch_counter_tokeninfo_binding_or_expiry"
            | "native_enrollment_full_selection_changed",
        ) => return Category::AdmissionRejected,
        _ => {}
    }
    let errno = error.downcast_ref::<rustix::io::Errno>().copied();
    // The pinned packet error does not expose its errno through Error::source.
    // Inspect its typed variants directly; never parse or format its Display.
    #[cfg(target_os = "linux")]
    let errno = if let Some(packet) = error.downcast_ref::<rustix::net::RecvPidfdError>() {
        use rustix::net::RecvPidfdError as Packet;
        match packet {
            Packet::Io(errno) => Some(*errno),
            Packet::SocketProfile => return Category::PacketSocketProfile,
            Packet::EmptyPayloadBuffer => return Category::PacketEmptyPayloadBuffer,
            Packet::ClosedOrEmptyPacket => return Category::PacketClosedOrEmpty,
            Packet::Truncated => return Category::PacketTruncated,
            Packet::MalformedAncillary => return Category::PacketMalformedAncillary,
            Packet::UnexpectedAncillary => return Category::PacketUnexpectedAncillary,
            Packet::MissingProcess => return Category::PacketMissingProcess,
            Packet::DuplicateProcess => return Category::PacketDuplicateProcess,
            Packet::SenderUnavailable(_) => return Category::PacketSenderUnavailable,
            Packet::MissingCredentials => return Category::PacketMissingCredentials,
            Packet::DuplicateCredentials => return Category::PacketDuplicateCredentials,
            Packet::MalformedCredentials => return Category::PacketMalformedCredentials,
            Packet::DescriptorNotCloexec => return Category::PacketDescriptorNotCloexec,
            _ => return Category::Other,
        }
    } else {
        errno
    };
    let kind = error
        .downcast_ref::<std::io::Error>()
        .map(std::io::Error::kind)
        .or_else(|| {
            errno.map(|errno| std::io::Error::from_raw_os_error(errno.raw_os_error()).kind())
        });
    match kind {
        Some(std::io::ErrorKind::PermissionDenied) => Category::PermissionDenied,
        Some(std::io::ErrorKind::NotFound) => Category::NotFound,
        Some(std::io::ErrorKind::AlreadyExists) => Category::AlreadyExists,
        Some(std::io::ErrorKind::TimedOut) => Category::TimedOut,
        Some(std::io::ErrorKind::Unsupported) => Category::Unsupported,
        Some(_)
            if errno
                .is_some_and(|e| e == rustix::io::Errno::LOOP || e == rustix::io::Errno::XDEV) =>
        {
            Category::PathResolution
        }
        Some(_) => Category::Io,
        None => Category::Other,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Step {
    CreateReserve,
    CreateDispatch,
    CreateSettle,
    ActivateReserve,
    ActivateDispatch,
    ActivateSettle,
}

const STEPS: [Step; 6] = [
    Step::CreateReserve,
    Step::CreateDispatch,
    Step::CreateSettle,
    Step::ActivateReserve,
    Step::ActivateDispatch,
    Step::ActivateSettle,
];

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::security_epoch) enum ServingRole {
    App,
    Shell,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ReadOnlyFrontier {
    AuthThreeProviderRounds,
}

#[derive(Serialize)]
struct Record<'a> {
    format: &'static str,
    sequence: u8,
    selection: &'a Option<Digest>,
    controller_incarnation: &'a Option<Digest>,
    observation: Observation,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ListenerEvent {
    InitialHolderListenerBound,
}

/// A completed transport-bind observation, never peer or file authority.
/// Only fixed labels and actual historical selection/incarnation commitments.
#[derive(Serialize)]
struct ListenerRecord<'a> {
    format: &'static str,
    event: ListenerEvent,
    selection: &'a Digest,
    controller_incarnation: &'a Digest,
    scheduling_data_only: bool,
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Observation {
    Enrolled,
    FirstHolderDurabilityCompleted {
        seed: Digest,
        holder: Digest,
        #[serde(skip_serializing_if = "Option::is_none")]
        timing: Option<Summary>,
    },
    PreparationReadOnlyObserved {
        frontier: ReadOnlyFrontier,
        completed: bool,
        expected_rounds: u8,
        bootstrap: BootstrapSnapshot,
    },
    BootstrapCompleted {
        step: Step,
        operation: Digest,
        request: Digest,
        snapshot: Digest,
        #[serde(skip_serializing_if = "Option::is_none")]
        bootstrap: Option<BootstrapSnapshot>,
    },
    ActivationCompleted {
        operation: Digest,
        snapshot: Digest,
    },
    FirstServingRelease {
        role: ServingRole,
        binding: Digest,
        snapshot: Digest,
        #[serde(skip_serializing_if = "Option::is_none")]
        serving: Option<Box<ServingSnapshot>>,
    },
    Refused {
        at: FailurePhase,
        #[serde(skip_serializing_if = "Option::is_none")]
        preparation: Option<PreparationFailure>,
        #[serde(skip_serializing_if = "Option::is_none")]
        timing: Option<Summary>,
        #[serde(skip_serializing_if = "Option::is_none")]
        bootstrap: Option<BootstrapSnapshot>,
        #[serde(skip_serializing_if = "Option::is_none")]
        serving: Option<Box<ServingSnapshot>>,
    },
}

impl Evidence {
    pub(super) fn new() -> Self {
        Self::with_writer(StderrOutput {
            stream: std::io::stderr(),
        })
    }
}

impl<W: RecordOutput> Recorder<W> {
    fn with_writer(output: W) -> Self {
        Self {
            output,
            selection: None,
            incarnation: None,
            first_holder: false,
            next: 0,
            activated: false,
            serving: [false; 2],
            records: 0,
            listener_attempted: false,
            self_check_exported: 0,
            current_self_check_records: 0,
            current_join_records: 0,
            at: FailurePhase::Selection,
            refused: false,
            export_failed: false,
            preparation_timing: None,
            bootstrap_timing: None,
            serving_timing: None,
            current_serving_profile: None,
            current_serving_join: None,
            current_admission_work: None,
            read_only_observed: false,
        }
    }

    pub(in crate::security_epoch) fn enter(&mut self, at: FailurePhase) {
        self.at = at;
        self.serving_timing = None;
        self.current_serving_profile = None;
        self.current_serving_join = None;
        self.current_admission_work = None;
    }

    /// Historical snapshots from the real Controller, never native admission.
    /// Duplicate or wrongly phased captures remain unknown until enter clears
    /// the phase. They cannot replace a prior interval with a later baseline.
    pub(super) fn current_admission_work(
        &mut self,
        role: ServingRole,
        before: super::super::admission_work::Snapshot,
        now: super::super::admission_work::Snapshot,
    ) {
        let valid = self.current_admission_work.is_none()
            && matches!(
                (role, self.at),
                (ServingRole::App, FailurePhase::AppServing)
                    | (ServingRole::Shell, FailurePhase::ShellServing)
            );
        self.current_admission_work = Some(CurrentAdmissionWork {
            role,
            before: valid.then_some(before),
            now: valid.then_some(now),
        });
    }

    pub(super) fn serving_timing(&mut self, timing: ServingSnapshot) {
        self.serving_timing = Some(timing);
    }

    pub(super) fn current_serving_profile(
        &mut self,
        profile: Option<super::super::self_check_profile::CurrentProfile>,
    ) {
        self.current_serving_profile = profile;
    }

    pub(super) fn select(
        &mut self,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
    ) -> Result<()> {
        ensure!(
            self.selection.is_none(),
            "native_evidence_selection_already_set"
        );
        self.selection = Some(Digest::of(&(
            "day2-controller-evidence-selection-v1",
            policy,
            store,
        ))?);
        Ok(())
    }

    pub(super) fn enrolled(&mut self, incarnation: Digest) -> Result<()> {
        ensure!(
            self.selection.is_some() && self.incarnation.is_none(),
            "native_evidence_enrollment_order"
        );
        self.incarnation = Some(incarnation);
        self.emit(Observation::Enrolled)
    }

    /// Only the known-successful bind caller invokes this, after its actual
    /// file phase has finished and before it waits or acquires a first-holder
    /// original. Its separate one-record budget cannot spend a main slot.
    pub(super) fn holder_listener_bound(&mut self) -> Result<()> {
        ensure!(
            !self.listener_attempted,
            "native_listener_observation_closed"
        );
        // Consume even an unsuccessful/partial attempt; never emit a second
        // apparent ready line after a failed, uncertain or invalid export.
        self.listener_attempted = true;
        ensure!(
            self.at == FailurePhase::HolderListener
                && !self.refused
                && !self.export_failed
                && !self.read_only_observed
                && !self.first_holder
                && !self.activated
                && self.next == 0
                && self.records == 1
                && self.serving == [false; 2],
            "native_listener_observation_order"
        );
        let record = ListenerRecord {
            format: "day2_native_controller_listener_v1",
            event: ListenerEvent::InitialHolderListenerBound,
            selection: self
                .selection
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("native_listener_selection_missing"))?,
            controller_incarnation: self
                .incarnation
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("native_listener_incarnation_missing"))?,
            scheduling_data_only: true,
        };
        let json = serde_json::to_string(&record)?;
        let line = format!("{LISTENER_PREFIX}{json}\n");
        ensure!(
            line.len() <= MAX_LISTENER_BYTES,
            "native_listener_record_bound"
        );
        if self.output.append(line.as_bytes()).is_err() {
            self.export_failed = true;
            anyhow::bail!("native_evidence_export_failed");
        }
        Ok(())
    }

    pub(super) fn first_holder(&mut self, seed: &OriginalSeedCore, holder: &Holder) -> Result<()> {
        ensure!(
            self.incarnation.is_some() && !self.first_holder && !self.read_only_observed,
            "native_evidence_first_holder_order"
        );
        self.emit(Observation::FirstHolderDurabilityCompleted {
            seed: seed.digest()?,
            holder: Digest::of(&("day2-controller-first-holder-evidence-v1", holder))?,
            timing: self.preparation_timing.clone(),
        })?;
        self.first_holder = true;
        Ok(())
    }

    pub(super) fn preparation_timings(&mut self, timing: Summary) {
        self.preparation_timing = Some(timing);
    }

    pub(super) fn preparation_read_only(&mut self, bootstrap: BootstrapSnapshot) -> Result<()> {
        ensure!(
            self.incarnation.is_some()
                && !self.first_holder
                && !self.read_only_observed
                && self.next == 0,
            "native_evidence_read_only_order"
        );
        ensure!(
            bootstrap.completed_provider_control(),
            "native_evidence_three_provider_rounds_required"
        );
        self.emit(Observation::PreparationReadOnlyObserved {
            frontier: ReadOnlyFrontier::AuthThreeProviderRounds,
            completed: true,
            expected_rounds: 3,
            bootstrap,
        })?;
        self.read_only_observed = true;
        Ok(())
    }

    pub(in crate::security_epoch) fn enter_bootstrap(&mut self, request: &Request, action: Action) {
        let (_, at) = step(request, action);
        self.enter(at);
        // The first-holder record already owns its historical preparation
        // summary. It is not timing evidence about a new Current phase.
        self.preparation_timing = None;
        self.bootstrap_timing = None;
    }

    pub(in crate::security_epoch) fn bootstrap_timing(
        &mut self,
        snapshot: Option<BootstrapSnapshot>,
    ) {
        self.bootstrap_timing = snapshot;
    }

    pub(in crate::security_epoch) fn bootstrap(
        &mut self,
        request: &Request,
        action: Action,
        snapshot: &Snapshot,
    ) -> Result<()> {
        let (step, _) = step(request, action);
        ensure!(
            self.first_holder && STEPS.get(self.next) == Some(&step),
            "native_evidence_bootstrap_order"
        );
        ensure!(
            self.bootstrap_timing
                .as_ref()
                .is_none_or(BootstrapSnapshot::completed_bootstrap_action),
            "native_evidence_bootstrap_timing_incomplete"
        );
        self.emit(Observation::BootstrapCompleted {
            step,
            operation: request.operation().clone(),
            request: request.digest()?,
            snapshot: crate::security_epoch::journal::snapshot_digest(snapshot)?,
            bootstrap: self.bootstrap_timing.clone(),
        })?;
        self.next += 1;
        Ok(())
    }

    pub(in crate::security_epoch) fn activated(
        &mut self,
        request: &Request,
        snapshot: &Digest,
    ) -> Result<()> {
        ensure!(
            self.next == STEPS.len()
                && !self.activated
                && matches!(request, Request::CompleteInitialFirstActivation { .. }),
            "native_evidence_activation_order"
        );
        self.emit(Observation::ActivationCompleted {
            operation: request.operation().clone(),
            snapshot: snapshot.clone(),
        })?;
        self.activated = true;
        Ok(())
    }

    pub(super) fn serving(
        &mut self,
        role: ServingRole,
        observed: ServingObservation,
    ) -> Result<()> {
        ensure!(
            self.activated && !self.refused && !self.export_failed,
            "native_evidence_serving_before_activation_or_closed"
        );
        let index = match role {
            ServingRole::App => 0,
            ServingRole::Shell => 1,
        };
        // Returned only after this actual App/Shell scope's final checks and
        // release. Keep its identity independently of optional cost profiling.
        self.current_serving_join = Some(CurrentServingJoin {
            role,
            request: observed.request,
            peer: observed.peer,
        });
        if !self.serving[index] {
            self.emit(Observation::FirstServingRelease {
                role,
                binding: observed.binding,
                snapshot: observed.snapshot,
                serving: match role {
                    ServingRole::App => self.serving_timing.clone().map(Box::new),
                    ServingRole::Shell => None,
                },
            })?;
            self.serving[index] = true;
        } else {
            // Later actual Current operations still return historical DATA.
            // Do not fabricate another first-release lifecycle observation.
            self.emit_current_self_check(true)?;
        }
        Ok(())
    }

    pub(super) fn refuse(&mut self, error: Option<&anyhow::Error>) -> Result<()> {
        if !self.refused {
            let current = matches!(
                self.at,
                FailurePhase::CreateReserve
                    | FailurePhase::CreateDispatch
                    | FailurePhase::CreateSettle
                    | FailurePhase::ActivateReserve
                    | FailurePhase::ActivateDispatch
                    | FailurePhase::ActivateSettle
            );
            let provider_control = matches!(self.at, FailurePhase::Preparation)
                && !self.first_holder
                && self.next == 0
                && self
                    .bootstrap_timing
                    .as_ref()
                    .is_some_and(BootstrapSnapshot::is_provider_read_only);
            // This closed field reports a failed native boundary, including
            // counter preparation/send/reobservation. It never asserts that a
            // failed bootstrap send had no remote effect or permits a retry.
            let preparation = if matches!(
                self.at,
                FailurePhase::Preparation
                    | FailurePhase::HolderListener
                    | FailurePhase::FirstHolder
                    | FailurePhase::CreateReserve
                    | FailurePhase::CreateDispatch
                    | FailurePhase::CreateSettle
                    | FailurePhase::ActivateReserve
                    | FailurePhase::ActivateDispatch
                    | FailurePhase::ActivateSettle
                    | FailurePhase::CounterAdmission
            ) {
                error.map(PreparationFailure::observe)
            } else {
                None
            };
            self.emit(Observation::Refused {
                at: self.at,
                preparation,
                // This completed preparation DATA remains attributable if a
                // later listener/holder phase refuses before first-holder log.
                timing: if current
                    || provider_control
                    || matches!(self.at, FailurePhase::AppServing)
                {
                    None
                } else {
                    self.preparation_timing.clone()
                },
                bootstrap: if current || provider_control {
                    self.bootstrap_timing.clone()
                } else {
                    None
                },
                serving: if matches!(self.at, FailurePhase::AppServing) {
                    self.serving_timing.clone().map(Box::new)
                } else {
                    None
                },
            })?;
            self.refused = true;
        }
        Ok(())
    }

    fn emit(&mut self, observation: Observation) -> Result<()> {
        ensure!(
            !self.refused && !self.export_failed && self.records < MAX_RECORDS,
            "native_evidence_closed"
        );
        // One profile per fixed bootstrap action, and separately bounded
        // profiles for actual Current App-serving operations.
        // All permission borrows have unwound before diagnostic output.
        self.emit_self_check(&observation)?;
        let record = Record {
            format: "day2_native_controller_evidence_v1",
            sequence: self.records + 1,
            selection: &self.selection,
            controller_incarnation: &self.incarnation,
            observation,
        };
        let json = serde_json::to_string(&record)?;
        ensure!(
            PREFIX.len() + json.len() < MAX_RECORD_BYTES,
            "native_evidence_record_bound"
        );
        let line = format!("{PREFIX}{json}\n");
        // No role/file phase is live at emission. A blocked OS logger can still
        // perturb other executors; no deadline extension or hard time bound.
        if self.output.append(line.as_bytes()).is_err() {
            self.export_failed = true;
            anyhow::bail!("native_evidence_export_failed");
        }
        self.records += 1;
        Ok(())
    }

    fn emit_self_check(&mut self, observation: &Observation) -> Result<()> {
        if matches!(
            observation,
            Observation::FirstServingRelease { .. }
                | Observation::Refused {
                    at: FailurePhase::AppServing,
                    ..
                }
        ) || (matches!(
            observation,
            Observation::Refused {
                at: FailurePhase::ShellServing,
                ..
            }
        ) && self.current_admission_work.is_some())
        {
            return self.emit_current_self_check(matches!(
                observation,
                Observation::FirstServingRelease { .. }
            ));
        }
        let (step, profile) = match observation {
            Observation::BootstrapCompleted {
                step,
                bootstrap: Some(bootstrap),
                ..
            } => (*step, bootstrap.self_check),
            Observation::Refused {
                at,
                bootstrap: Some(bootstrap),
                ..
            } => {
                let step = match at {
                    FailurePhase::CreateReserve => Step::CreateReserve,
                    FailurePhase::CreateDispatch => Step::CreateDispatch,
                    FailurePhase::CreateSettle => Step::CreateSettle,
                    FailurePhase::ActivateReserve => Step::ActivateReserve,
                    FailurePhase::ActivateDispatch => Step::ActivateDispatch,
                    FailurePhase::ActivateSettle => Step::ActivateSettle,
                    _ => return Ok(()),
                };
                (step, bootstrap.self_check)
            }
            _ => return Ok(()),
        };
        let Some(profile) = profile else {
            return Ok(());
        };
        let bit = match step {
            Step::CreateReserve => 1,
            Step::CreateDispatch => 2,
            Step::CreateSettle => 4,
            Step::ActivateReserve => 8,
            Step::ActivateDispatch => 16,
            Step::ActivateSettle => 32,
        };
        if self.self_check_exported & bit != 0 {
            return Ok(());
        }
        #[derive(Serialize)]
        struct ProfileRecord<'a> {
            format: &'static str,
            // Joins the following main evidence record, not a grant/result.
            sequence: u8,
            selection: &'a Option<Digest>,
            controller_incarnation: &'a Option<Digest>,
            step: Step,
            profile: super::super::self_check_profile::Profile,
        }
        let record = ProfileRecord {
            format: "controller_full_check_exclusive_ns_v1",
            sequence: self.records + 1,
            selection: &self.selection,
            controller_incarnation: &self.incarnation,
            step,
            profile,
        };
        let json = serde_json::to_string(&record)?;
        self.append_self_check(&json, MAX_SELF_CHECK_BYTES)?;
        self.self_check_exported |= bit;
        Ok(())
    }

    fn emit_current_self_check(&mut self, completed: bool) -> Result<()> {
        // Consume once. Essential actual-owner/original joins continue after
        // the cost-detail cap; neither capped detail nor missing DATA is zero
        // work or complete capture.
        let profile = self.current_serving_profile.take();
        let join = self.current_serving_join.take();
        let admission = self.current_admission_work.take();
        if profile.is_none() && join.is_none() && admission.is_none() {
            return Ok(());
        }
        let sequence = self
            .current_join_records
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("native_current_diagnostic_sequence_overflow"))?;
        let role = join
            .as_ref()
            .map(|join| join.role)
            .unwrap_or_else(|| match self.at {
                FailurePhase::ShellServing => ServingRole::Shell,
                _ => ServingRole::App,
            });
        let detail = profile.filter(|_| {
            matches!(role, ServingRole::App)
                && self.current_self_check_records < MAX_CURRENT_SELF_CHECK_RECORDS
        });
        #[derive(Serialize)]
        struct CurrentRecord<'a> {
            format: &'static str,
            scope: &'static str,
            sequence: u64,
            lifecycle_sequence: u8,
            completed: bool,
            role: ServingRole,
            selection: &'a Option<Digest>,
            controller_incarnation: &'a Option<Digest>,
            request: Option<&'a super::super::native_clock::EnrolledRequestDiagnosticData>,
            peer: Option<&'a super::super::native_enrollment::PeerRequestDiagnosticData>,
            capture_completeness: &'static str,
            detail_limit: u16,
            detail: Option<super::super::self_check_profile::CurrentProfile>,
        }
        let record = CurrentRecord {
            format: "controller_current_serving_v4",
            scope: match role {
                ServingRole::Shell => "whole_current_shell_serving_operation",
                ServingRole::App => "whole_current_app_serving_operation",
            },
            sequence,
            lifecycle_sequence: self.records,
            completed,
            role,
            selection: &self.selection,
            controller_incarnation: &self.incarnation,
            request: match &join {
                Some(join) => join.request.as_ref(),
                None => self
                    .serving_timing
                    .as_ref()
                    .and_then(ServingSnapshot::request_data),
            },
            peer: match &join {
                Some(join) => join.peer.as_ref(),
                None => self
                    .serving_timing
                    .as_ref()
                    .and_then(ServingSnapshot::peer_data),
            },
            capture_completeness: "unknown",
            detail_limit: MAX_CURRENT_SELF_CHECK_RECORDS,
            detail,
        };
        let json = serde_json::to_string(&record)?;
        #[derive(Serialize)]
        struct WorkRecord<'a> {
            format: &'static str,
            sequence: u64,
            boundary: &'static str,
            completed: bool,
            role: ServingRole,
            selection: &'a Option<Digest>,
            controller_incarnation: &'a Option<Digest>,
            request: Option<&'a super::super::native_clock::EnrolledRequestDiagnosticData>,
            peer: Option<&'a super::super::native_enrollment::PeerRequestDiagnosticData>,
            admission_work: Option<super::super::admission_work::CompactSnapshot<'a>>,
        }
        // Serialize both bounded sidecars before borrowing the output. The
        // same actual Current joins and ordinal are copied, never reconstructed.
        let work_json = admission
            .as_ref()
            .map(|admission| {
                let same_role = matches!(
                    (admission.role, role),
                    (ServingRole::App, ServingRole::App) | (ServingRole::Shell, ServingRole::Shell)
                );
                let encode =
                    |boundary, snapshot: Option<&super::super::admission_work::Snapshot>| {
                        serde_json::to_string(&WorkRecord {
                            format: "controller_current_admission_work_v1",
                            sequence,
                            boundary,
                            completed,
                            role,
                            selection: record.selection,
                            controller_incarnation: record.controller_incarnation,
                            request: record.request,
                            peer: record.peer,
                            admission_work: snapshot
                                .filter(|_| same_role)
                                .map(|value| value.compact_data()),
                        })
                    };
                Ok::<_, serde_json::Error>((
                    encode("before", admission.before.as_ref())?,
                    encode("after", admission.now.as_ref())?,
                ))
            })
            .transpose()?;
        self.append_self_check(&json, MAX_CURRENT_SELF_CHECK_BYTES)?;
        if let Some((before, after)) = work_json {
            self.append_self_check(&before, MAX_CURRENT_SELF_CHECK_BYTES)?;
            self.append_self_check(&after, MAX_CURRENT_SELF_CHECK_BYTES)?;
        }
        self.current_join_records = sequence;
        if detail.is_some() {
            self.current_self_check_records += 1;
        }
        Ok(())
    }

    fn append_self_check(&mut self, json: &str, limit: usize) -> Result<()> {
        ensure!(
            SELF_CHECK_PREFIX.len() + json.len() < limit,
            "native_self_check_record_bound"
        );
        if self
            .output
            .append(format!("{SELF_CHECK_PREFIX}{json}\n").as_bytes())
            .is_err()
        {
            self.export_failed = true;
            anyhow::bail!("native_evidence_export_failed");
        }
        Ok(())
    }
}

fn step(request: &Request, action: Action) -> (Step, FailurePhase) {
    match (request, action) {
        (Request::CreateInitialAuthority { .. }, Action::Reserve) => {
            (Step::CreateReserve, FailurePhase::CreateReserve)
        }
        (Request::CreateInitialAuthority { .. }, Action::Dispatch) => {
            (Step::CreateDispatch, FailurePhase::CreateDispatch)
        }
        (Request::CreateInitialAuthority { .. }, Action::Settle) => {
            (Step::CreateSettle, FailurePhase::CreateSettle)
        }
        (Request::CompleteInitialFirstActivation { .. }, Action::Reserve) => {
            (Step::ActivateReserve, FailurePhase::ActivateReserve)
        }
        (Request::CompleteInitialFirstActivation { .. }, Action::Dispatch) => {
            (Step::ActivateDispatch, FailurePhase::ActivateDispatch)
        }
        (Request::CompleteInitialFirstActivation { .. }, Action::Settle) => {
            (Step::ActivateSettle, FailurePhase::ActivateSettle)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_epoch::{kernel::Versions, seed_core::Incarnations};
    use serde_json::Value;

    impl RecordOutput for Vec<u8> {
        fn append(&mut self, record: &[u8]) -> std::io::Result<()> {
            self.extend_from_slice(record);
            Ok(())
        }
    }

    // DATA-only export controls. These never construct a real enrolled stage,
    // file, provider observation, first holder or serving authority.
    fn fixture() -> (
        Recorder<Vec<u8>>,
        OriginalSeedCore,
        Holder,
        Request,
        Request,
        Snapshot,
    ) {
        let store = crate::security_epoch::tests::selection();
        let policy = crate::security_epoch::control_slot_tests::policy(&store);
        let seed = OriginalSeedCore::new(
            &policy,
            &store,
            Incarnations {
                record: Digest::new(b"record"),
                database: Digest::new(b"database"),
                activation: Digest::new(b"activation"),
            },
        )
        .unwrap();
        let holder = Holder {
            principal: Digest::new(b"private principal"),
            pod_uid: "11234567-89ab-4cde-8fab-0123456789ab".into(),
            process_incarnation: Digest::new(b"App process"),
            ephemeral_key: Digest::new(b"private ephemeral key"),
        };
        let create = Request::CreateInitialAuthority {
            bootstrap: seed.bootstrap().unwrap(),
        };
        let version = "2026-10-20T00:00:00.000001Z".to_owned().try_into().unwrap();
        let complete = Request::CompleteInitialFirstActivation {
            bootstrap: create.bootstrap().clone(),
            operation: Digest::new(b"activation operation"),
            parent_receipt: create.receipt().unwrap().digest().unwrap(),
            before: Versions {
                root: version,
                sentinel: "2026-10-20T00:00:00.000002Z".to_owned().try_into().unwrap(),
            },
            holder: holder.clone(),
        };
        let snapshot = Snapshot {
            root: None,
            sentinel: None,
            create: None,
            activate: None,
        };
        let mut recorder = Recorder::with_writer(Vec::new());
        recorder.select(&policy, &store).unwrap();
        (recorder, seed, holder, create, complete, snapshot)
    }

    fn records(output: &[u8]) -> Vec<Value> {
        std::str::from_utf8(output)
            .unwrap()
            .lines()
            .filter(|line| {
                !line.starts_with(SELF_CHECK_PREFIX) && !line.starts_with(LISTENER_PREFIX)
            })
            .map(|line| {
                assert!(line.len() < MAX_RECORD_BYTES);
                serde_json::from_str(line.strip_prefix(PREFIX).unwrap()).unwrap()
            })
            .collect()
    }

    #[test]
    fn listener_marker_is_closed_bounded_once_and_outside_lifecycle_budget() {
        let (mut recorder, ..) = fixture();
        let incarnation = Digest::new(b"actual Controller commitment DATA fixture");
        recorder.enrolled(incarnation.clone()).unwrap();
        recorder.enter(FailurePhase::HolderListener);
        let before = recorder.output.len();
        recorder.holder_listener_bound().unwrap();
        let line = std::str::from_utf8(&recorder.output[before..]).unwrap();
        assert!(line.len() <= MAX_LISTENER_BYTES && line.ends_with('\n'));
        let row: Value = serde_json::from_str(line.strip_prefix(LISTENER_PREFIX).unwrap()).unwrap();
        assert_eq!(row.as_object().unwrap().len(), 5);
        assert_eq!(row["format"], "day2_native_controller_listener_v1");
        assert_eq!(row["event"], "initial_holder_listener_bound");
        assert_eq!(
            row["selection"],
            serde_json::to_value(&recorder.selection).unwrap()
        );
        assert_eq!(row["controller_incarnation"], incarnation.as_str());
        assert_eq!(row["scheduling_data_only"], true);
        assert_eq!(recorder.records, 1);
        assert_eq!(recorder.self_check_exported, 0);
        assert_eq!(recorder.current_join_records, 0);
        assert!(!recorder.first_holder && !recorder.activated && recorder.serving == [false; 2]);
        let length = recorder.output.len();
        assert!(recorder.holder_listener_bound().is_err());
        assert_eq!(recorder.output.len(), length);
        assert_eq!(records(&recorder.output).len(), 1);
    }

    #[test]
    fn listener_marker_refuses_missing_context_or_wrong_frontier_without_relabel() {
        for case in 0..9 {
            let (mut recorder, ..) = fixture();
            recorder
                .enrolled(Digest::new(b"enrolled commitment DATA"))
                .unwrap();
            recorder.enter(FailurePhase::HolderListener);
            match case {
                0 => recorder.selection = None,
                1 => recorder.incarnation = None,
                2 => recorder.at = FailurePhase::FirstHolder,
                3 => recorder.refused = true,
                4 => recorder.export_failed = true,
                5 => recorder.read_only_observed = true,
                6 => recorder.first_holder = true,
                7 => recorder.activated = true,
                8 => recorder.records = MAX_RECORDS,
                _ => unreachable!(),
            }
            let before = recorder.output.len();
            assert!(recorder.holder_listener_bound().is_err());
            assert!(recorder.listener_attempted);
            assert_eq!(recorder.output.len(), before);
            // Even restoring fixture DATA cannot retry an uncertain attempt.
            recorder.selection = Some(Digest::new(b"later selection DATA"));
            recorder.incarnation = Some(Digest::new(b"later incarnation DATA"));
            recorder.at = FailurePhase::HolderListener;
            assert!(recorder.holder_listener_bound().is_err());
            assert_eq!(recorder.output.len(), before);
        }
    }

    #[test]
    fn listener_marker_partial_export_is_terminal_and_never_reemitted() {
        struct Partial {
            fail: bool,
            attempts: usize,
            bytes: Vec<u8>,
        }
        impl RecordOutput for Partial {
            fn append(&mut self, record: &[u8]) -> std::io::Result<()> {
                self.attempts += 1;
                if self.fail {
                    self.bytes.extend_from_slice(&record[..7]);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "controlled partial export",
                    ));
                }
                self.bytes.extend_from_slice(record);
                Ok(())
            }
        }
        let store = crate::security_epoch::tests::selection();
        let policy = crate::security_epoch::control_slot_tests::policy(&store);
        let mut recorder = Recorder::with_writer(Partial {
            fail: false,
            attempts: 0,
            bytes: Vec::new(),
        });
        recorder.select(&policy, &store).unwrap();
        recorder
            .enrolled(Digest::new(b"enrolled commitment DATA"))
            .unwrap();
        recorder.enter(FailurePhase::HolderListener);
        recorder.output.fail = true;
        assert!(recorder.holder_listener_bound().is_err());
        assert!(recorder.export_failed && recorder.listener_attempted);
        assert_eq!(recorder.records, 1);
        assert_eq!(recorder.output.attempts, 2);
        let before = recorder.output.bytes.len();
        assert!(recorder.holder_listener_bound().is_err());
        assert!(recorder.refuse(None).is_err());
        assert_eq!(recorder.output.attempts, 2);
        assert_eq!(recorder.output.bytes.len(), before);
    }

    fn listener_marker_call_follows_known_bind(source: &str) -> bool {
        let parsed = syn::parse_file(source).unwrap();
        let body = parsed
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(function) if function.sig.ident == "run_inner" => {
                    Some(&function.block)
                }
                _ => None,
            })
            .unwrap();
        let Some(index) = body.stmts.iter().position(|statement| {
            matches!(statement,syn::Stmt::Local(local)
            if matches!(&local.pat,syn::Pat::Ident(name) if name.ident=="holder_listener"))
        }) else {
            return false;
        };
        matches!(&body.stmts[index],syn::Stmt::Local(local)
            if matches!(local.init.as_ref().map(|init|&*init.expr),Some(syn::Expr::Try(attempt))
                if matches!(&*attempt.expr,syn::Expr::Path(path) if path.path.is_ident("result"))))
            && matches!(body.stmts.get(index+1),Some(syn::Stmt::Expr(syn::Expr::Try(attempt),Some(_)))
                if matches!(&*attempt.expr,syn::Expr::MethodCall(call)
                    if call.method=="holder_listener_bound" && call.args.is_empty()
                    && matches!(&*call.receiver,syn::Expr::Path(path) if path.path.is_ident("evidence"))))
            && matches!(body.stmts.get(index+2),Some(syn::Stmt::Expr(syn::Expr::While(wait),_))
                if matches!(&*wait.cond,syn::Expr::Unary(negative) if matches!(negative.op,syn::UnOp::Not(_))
                    && matches!(&*negative.expr,syn::Expr::Try(attempt)
                        if matches!(&*attempt.expr,syn::Expr::MethodCall(call)
                            if call.method=="idle_ready" && call.args.is_empty()
                            && matches!(&*call.receiver,syn::Expr::Path(path) if path.path.is_ident("holder_listener"))))))
    }

    fn listener_bind_finishes_actual_phase_before_return(source: &str) -> bool {
        let parsed = syn::parse_file(source).unwrap();
        parsed.items.iter().any(|item| {
            let syn::Item::Impl(item) = item else { return false; };
            if !matches!(&*item.self_ty,syn::Type::Path(path) if path.path.is_ident("InitialHolderListener")) { return false; }
            item.items.iter().any(|item| {
                let syn::ImplItem::Fn(function) = item else { return false; };
                if function.sig.ident!="bind" { return false; }
                function.block.stmts.iter().any(|statement| {
                    let syn::Stmt::Expr(syn::Expr::Block(block),_) = statement else { return false; };
                    if !block.attrs.iter().any(|attribute| matches!(&attribute.meta,syn::Meta::List(list)
                        if list.path.is_ident("cfg") && list.tokens.to_string()=="target_os = \"linux\"")) { return false; }
                    let Some(index) = block.block.stmts.len().checked_sub(2) else { return false; };
                    matches!(&block.block.stmts[index],syn::Stmt::Expr(syn::Expr::Try(attempt),Some(_))
                        if matches!(&*attempt.expr,syn::Expr::MethodCall(mapped)
                            if mapped.method=="map_err" && mapped.args.len()==1
                            && matches!(&*mapped.receiver,syn::Expr::MethodCall(finish)
                                if finish.method=="finish_checked" && finish.args.is_empty()
                                && matches!(&*finish.receiver,syn::Expr::Path(path) if path.path.is_ident("phase")))))
                        && matches!(&block.block.stmts[index+1],syn::Stmt::Expr(syn::Expr::Call(ok),None)
                            if matches!(&*ok.func,syn::Expr::Path(path) if path.path.is_ident("Ok"))
                            && ok.args.len()==1 && matches!(&ok.args[0],syn::Expr::Struct(value) if value.path.is_ident("Self")))
                })
            })
        })
    }

    #[test]
    fn listener_marker_source_controls_require_completed_bind_before_idle_wait() {
        let source = include_str!("../controller.rs");
        assert!(listener_marker_call_follows_known_bind(source));
        let marker = "evidence.holder_listener_bound()?;";
        let binder = "let mut holder_listener = result?;";
        for changed in [
            source.replacen(marker, "", 1),
            source.replacen(marker, &format!("if false {{ {marker} }}"), 1),
            source.replacen(marker, "foreign.holder_listener_bound()?;", 1),
            source.replacen(binder, "let mut holder_listener = forged_listener();", 1),
            source
                .replacen(marker, "", 1)
                .replacen(binder, &format!("{marker} {binder}"), 1),
            source.replacen(marker, "", 1).replacen(
                "evidence.enter(FailurePhase::FirstHolder);",
                &format!("{marker} evidence.enter(FailurePhase::FirstHolder);"),
                1,
            ),
        ] {
            assert_ne!(source, changed);
            assert!(!listener_marker_call_follows_known_bind(&changed));
        }
        let source = include_str!("../native_enrollment/storage_peer.rs");
        assert!(listener_bind_finishes_actual_phase_before_return(source));
        let finish = "phase.finish_checked().map_err(|error| {\n                PreparationFailure::at(PreparationStep::HolderFinalCheck, error)\n            })?;";
        for changed in [
            source.replacen(finish, "", 1),
            source.replacen(finish, &format!("if false {{ {finish} }}"), 1),
            source.replacen("phase.finish_checked()", "phase.unchecked_finish()", 1),
            source.replacen(finish, "", 1).replacen(
                "phase.check().map_err",
                &format!("{finish} phase.check().map_err"),
                1,
            ),
        ] {
            assert_ne!(source, changed);
            assert!(!listener_bind_finishes_actual_phase_before_return(&changed));
        }
    }

    #[test]
    fn current_profile_is_bounded_phase_local_joined_and_emitted_once_after_refusal() {
        for phase in [
            FailurePhase::AppServing,
            FailurePhase::ShellServing,
            FailurePhase::Preparation,
        ] {
            let (mut recorder, ..) = fixture();
            recorder
                .enrolled(Digest::new(b"actual Controller DATA"))
                .unwrap();
            recorder.enter(phase);
            recorder.current_serving_profile(Some(
                super::super::super::self_check_profile::CurrentProfile::maximal_fixture(),
            ));
            if phase == FailurePhase::AppServing {
                recorder.preparation_timings(
                    super::super::preparation_timing::Timings::maximal_summary_fixture(),
                );
            }
            recorder.refuse(None).unwrap();
            let text = std::str::from_utf8(&recorder.output).unwrap();
            let profiles = text
                .lines()
                .filter_map(|line| line.strip_prefix(SELF_CHECK_PREFIX))
                .collect::<Vec<_>>();
            if phase == FailurePhase::AppServing {
                assert_eq!(profiles.len(), 1);
                assert!(SELF_CHECK_PREFIX.len() + profiles[0].len() < MAX_CURRENT_SELF_CHECK_BYTES);
                let profile: Value = serde_json::from_str(profiles[0]).unwrap();
                assert_eq!(profile["format"], "controller_current_serving_v4");
                assert_eq!(profile["scope"], "whole_current_app_serving_operation");
                assert_eq!(profile["sequence"], 1);
                assert_eq!(profile["lifecycle_sequence"], 1);
                assert_eq!(profile["completed"], false);
                assert_eq!(
                    profile["selection"],
                    serde_json::to_value(&recorder.selection).unwrap()
                );
                assert_eq!(
                    profile["controller_incarnation"],
                    serde_json::to_value(&recorder.incarnation).unwrap()
                );
                assert_eq!(
                    profile["detail"]["profile"]["rows"]
                        .as_array()
                        .unwrap()
                        .len(),
                    16
                );
                assert_eq!(
                    profile["detail"]["physical"]["rows"]
                        .as_array()
                        .unwrap()
                        .len(),
                    4
                );
                assert_eq!(profile["capture_completeness"], "unknown");
                assert!(profile["request"].is_null());
                assert!(
                    profile.get("step").is_none(),
                    "Current is not a bootstrap action"
                );
                assert_eq!(records(&recorder.output)[1]["sequence"], 2);
                assert!(
                    records(&recorder.output)[1]["observation"]
                        .get("timing")
                        .is_none()
                );
            } else {
                assert!(profiles.is_empty());
            }
            let length = recorder.output.len();
            recorder.refuse(None).unwrap();
            assert_eq!(length, recorder.output.len());
            assert!(recorder.refused && !recorder.activated);
        }
        let (mut recorder, ..) = fixture();
        recorder.current_serving_profile(Some(
            super::super::super::self_check_profile::CurrentProfile::maximal_fixture(),
        ));
        recorder.enter(FailurePhase::AppServing);
        assert!(recorder.current_serving_profile.is_none());
    }

    #[test]
    fn serving_steps_and_exclusive_profile_share_one_bounded_refusal_without_stale_slots() {
        let (mut recorder, ..) = fixture();
        recorder
            .enrolled(Digest::new(b"actual Controller DATA"))
            .unwrap();
        recorder.enter(FailurePhase::AppServing);
        recorder.serving_timing(super::super::serving_timing::ServingTiming::maximal_fixture());
        recorder.current_serving_profile(Some(
            super::super::super::self_check_profile::CurrentProfile::maximal_fixture(),
        ));
        recorder.refuse(None).unwrap();
        let ordinary = records(&recorder.output);
        assert_eq!(
            ordinary[1]["observation"]["serving"]["scope"],
            "current_app_serving"
        );
        let text = std::str::from_utf8(&recorder.output).unwrap();
        let numeric = text
            .lines()
            .filter_map(|line| line.strip_prefix(SELF_CHECK_PREFIX))
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(numeric.len(), 1);
        assert_eq!(numeric[0]["sequence"], 1);
        assert_eq!(numeric[0]["lifecycle_sequence"], ordinary[0]["sequence"]);
        assert_eq!(ordinary[1]["sequence"], 2);
        assert_eq!(numeric[0]["completed"], false);
        assert!(recorder.refused && !recorder.activated && recorder.serving == [false; 2]);
        // Phase reset clears both independently retained DATA slots.
        recorder.enter(FailurePhase::ShellServing);
        assert!(recorder.serving_timing.is_none() && recorder.current_serving_profile.is_none());
    }

    #[test]
    fn current_profile_before_physical_work_has_no_fabricated_rows_or_native_success() {
        let (mut recorder, ..) = fixture();
        recorder.enrolled(Digest::new(b"Controller")).unwrap();
        recorder.enter(FailurePhase::AppServing);
        let (result, profile) = crate::security_epoch::self_check_profile::sample_current(|| {
            Err::<(), _>("role refused")
        });
        assert_eq!(result, Err("role refused"));
        recorder.current_serving_profile(profile);
        recorder.refuse(None).unwrap();
        let text = std::str::from_utf8(&recorder.output).unwrap();
        let row: Value = serde_json::from_str(
            text.lines()
                .find_map(|line| line.strip_prefix(SELF_CHECK_PREFIX))
                .unwrap(),
        )
        .unwrap();
        assert!(row["detail"].get("physical").is_none());
        assert_eq!(row["detail"]["profile"]["samples"], 1);
        assert_eq!(
            records(&recorder.output)[1]["observation"]["event"],
            "refused"
        );
        assert!(!recorder.activated && recorder.serving == [false; 2]);
    }

    #[test]
    fn current_profile_export_failure_keeps_the_actual_native_error() {
        struct Fails;
        impl RecordOutput for Fails {
            fn append(&mut self, _: &[u8]) -> std::io::Result<()> {
                Err(std::io::Error::other("private logger refused"))
            }
        }
        let mut recorder = Recorder::with_writer(Fails);
        recorder.enter(FailurePhase::AppServing);
        recorder.current_serving_profile(Some(
            crate::security_epoch::self_check_profile::CurrentProfile::maximal_fixture(),
        ));
        let native = Err(anyhow::anyhow!("private original refusal").context(MustNotDisplay));
        let recorded = recorder.refuse(native.as_ref().err());
        assert!(recorded.is_err() && recorder.export_failed);
        let error = super::super::preserve_native_failure(native, recorded).unwrap_err();
        assert!(error.downcast_ref::<MustNotDisplay>().is_some());
        assert!(!recorder.activated && recorder.serving == [false; 2]);
    }

    #[test]
    fn current_profiles_cap_cost_detail_but_keep_each_actual_identity_join_once() {
        let (mut recorder, ..) = fixture();
        recorder.enrolled(Digest::new(b"Controller")).unwrap();
        for sequence in 1..=MAX_CURRENT_SELF_CHECK_RECORDS + 2 {
            recorder.enter(FailurePhase::AppServing);
            recorder.current_serving_profile(Some(
                crate::security_epoch::self_check_profile::CurrentProfile::maximal_fixture(),
            ));
            recorder.serving_timing(super::super::serving_timing::ServingTiming::maximal_fixture());
            recorder.emit_current_self_check(sequence % 2 == 0).unwrap();
            assert!(recorder.current_serving_profile.is_none());
            let length = recorder.output.len();
            recorder.emit_current_self_check(false).unwrap();
            assert_eq!(recorder.output.len(), length);
        }
        let text = std::str::from_utf8(&recorder.output).unwrap();
        let rows = text
            .lines()
            .filter_map(|line| line.strip_prefix(SELF_CHECK_PREFIX));
        let mut count = 0;
        for row in rows {
            assert!(row.len() + SELF_CHECK_PREFIX.len() < MAX_CURRENT_SELF_CHECK_BYTES);
            let row: Value = serde_json::from_str(row).unwrap();
            count += 1;
            assert_eq!(row["sequence"], count);
            assert_eq!(row["lifecycle_sequence"], 1);
            assert_eq!(row["completed"], count % 2 == 0);
            assert_eq!(
                row["detail"].is_object(),
                count <= MAX_CURRENT_SELF_CHECK_RECORDS
            );
            assert_eq!(row["detail_limit"], MAX_CURRENT_SELF_CHECK_RECORDS);
            assert!(row["request"]["request_original"].is_string());
            assert!(row["request"]["producer_incarnation"].is_string());
            assert!(row["peer"]["exchange_commitment"].is_string());
            assert_eq!(row["capture_completeness"], "unknown");
        }
        assert_eq!(count, MAX_CURRENT_SELF_CHECK_RECORDS + 2);
        assert_eq!(
            recorder.current_self_check_records,
            MAX_CURRENT_SELF_CHECK_RECORDS
        );
        assert_eq!(recorder.current_join_records, u64::from(count));
        assert_eq!(records(&recorder.output).len(), 1);
        assert!(!recorder.refused && !recorder.export_failed && !recorder.activated);
    }

    #[test]
    fn current_identity_sequence_overflow_cannot_emit_a_wrapped_or_repeated_join() {
        let (mut recorder, ..) = fixture();
        recorder.current_join_records = u64::MAX;
        recorder.enter(FailurePhase::AppServing);
        recorder.current_serving_profile(Some(
            crate::security_epoch::self_check_profile::CurrentProfile::maximal_fixture(),
        ));
        let before = recorder.output.len();
        assert!(recorder.emit_current_self_check(true).is_err());
        assert_eq!(recorder.output.len(), before);
        assert_eq!(recorder.current_join_records, u64::MAX);
        assert!(recorder.current_serving_profile.is_none());
        // The consumed sample cannot be re-labelled as a later successful row.
        recorder.emit_current_self_check(true).unwrap();
        assert_eq!(recorder.output.len(), before);
    }

    #[test]
    fn known_scope_with_missing_identity_cannot_adopt_another_timing_join() {
        // Serialization DATA only; no successful native phase is constructed.
        let (mut recorder, ..) = fixture();
        recorder.enter(FailurePhase::AppServing);
        recorder.serving_timing(super::super::serving_timing::ServingTiming::maximal_fixture());
        recorder.current_serving_join = Some(CurrentServingJoin {
            role: ServingRole::Shell,
            request: None,
            peer: None,
        });
        recorder.emit_current_self_check(true).unwrap();
        let line = std::str::from_utf8(&recorder.output).unwrap();
        let row: Value =
            serde_json::from_str(line.strip_prefix(SELF_CHECK_PREFIX).unwrap()).unwrap();
        assert!(row["request"].is_null() && row["peer"].is_null());
        assert_eq!(row["role"], "shell");
        assert_eq!(row["scope"], "whole_current_shell_serving_operation");
        assert!(row["detail"].is_null());
        assert_eq!(row["capture_completeness"], "unknown");
        assert!(recorder.current_serving_join.is_none());
    }

    fn current_work_rows(output: &[u8]) -> Vec<Value> {
        std::str::from_utf8(output)
            .unwrap()
            .lines()
            .filter_map(|line| {
                let json = line.strip_prefix(SELF_CHECK_PREFIX)?;
                let value: Value = serde_json::from_str(json).unwrap();
                (value["format"] == "controller_current_admission_work_v1").then_some(value)
            })
            .collect()
    }

    #[test]
    fn current_ledger_pairs_are_uncapped_joined_bounded_and_once_on_both_role_outcomes() {
        for role in [ServingRole::App, ServingRole::Shell] {
            for completed in [false, true] {
                let (mut recorder, ..) = fixture();
                recorder.activated = true;
                recorder.incarnation = Some(Digest::new(b"actual Controller DATA fixture"));
                recorder.enter(match role {
                    ServingRole::App => FailurePhase::AppServing,
                    ServingRole::Shell => FailurePhase::ShellServing,
                });
                recorder.current_join_records = u64::MAX - 1;
                // Ledger output continues after the optional timing-detail cap.
                recorder.current_self_check_records = MAX_CURRENT_SELF_CHECK_RECORDS;
                recorder.current_admission_work(
                    role,
                    super::super::super::admission_work::Snapshot::maximal_fixture(),
                    super::super::super::admission_work::Snapshot::maximal_fixture(),
                );
                recorder.current_serving_join=Some(CurrentServingJoin {
                    role,
                    request:Some(super::super::super::native_clock::EnrolledRequestDiagnosticData::maximal_fixture()),
                    peer:Some(super::super::super::native_enrollment::PeerRequestDiagnosticData::maximal_fixture()),
                });
                if completed {
                    recorder.emit_current_self_check(true).unwrap();
                } else {
                    recorder
                        .refuse(Some(&anyhow::anyhow!("PRIVATE error must not serialize")))
                        .unwrap();
                }
                let rows = current_work_rows(&recorder.output);
                assert_eq!(rows.len(), 2);
                assert_eq!(rows[0]["boundary"], "before");
                assert_eq!(rows[1]["boundary"], "after");
                for row in &rows {
                    assert_eq!(row["sequence"], u64::MAX);
                    assert_eq!(row["completed"], completed);
                    assert_eq!(row["role"], serde_json::to_value(role).unwrap());
                    assert_eq!(
                        row["controller_incarnation"],
                        serde_json::to_value(&recorder.incarnation).unwrap()
                    );
                    assert!(row["request"]["request_original"].is_string());
                    assert!(row["peer"].is_object());
                    assert_eq!(row["admission_work"]["rows"].as_array().unwrap().len(), 9);
                    assert!(
                        row["admission_work"]["rows"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .all(|row| row[2].as_array().unwrap().len() == 8)
                    );
                }
                let lines = std::str::from_utf8(&recorder.output).unwrap();
                assert!(!lines.contains("PRIVATE"));
                for line in lines
                    .lines()
                    .filter(|line| line.starts_with(SELF_CHECK_PREFIX))
                {
                    assert!(
                        line.len() + 1 <= MAX_CURRENT_SELF_CHECK_BYTES,
                        "maximal complete line exceeds bound"
                    );
                }
                assert!(recorder.current_admission_work.is_none());
                let length = recorder.output.len();
                recorder.emit_current_self_check(false).unwrap();
                assert_eq!(recorder.output.len(), length);
            }
        }
    }

    #[test]
    fn current_ledger_capture_cannot_rebaseline_or_cross_a_phase_or_role() {
        let data = super::super::super::admission_work::Snapshot::maximal_fixture();
        let (mut recorder, ..) = fixture();
        recorder.enter(FailurePhase::AppServing);
        recorder.current_admission_work(ServingRole::App, data.clone(), data.clone());
        recorder.current_admission_work(ServingRole::App, data.clone(), data.clone());
        recorder.emit_current_self_check(false).unwrap();
        assert!(
            current_work_rows(&recorder.output)
                .iter()
                .all(|row| row["admission_work"].is_null())
        );
        recorder.enter(FailurePhase::ShellServing);
        recorder.current_admission_work(ServingRole::App, data.clone(), data.clone());
        recorder.emit_current_self_check(false).unwrap();
        assert!(
            current_work_rows(&recorder.output)
                .iter()
                .all(|row| row["admission_work"].is_null())
        );
        recorder.enter(FailurePhase::AppServing);
        recorder.current_admission_work(ServingRole::App, data.clone(), data);
        recorder.enter(FailurePhase::ShellPending);
        assert!(recorder.current_admission_work.is_none());
        let length = recorder.output.len();
        recorder.emit_current_self_check(false).unwrap();
        assert_eq!(recorder.output.len(), length);
    }

    #[test]
    fn partial_before_or_after_ledger_export_is_terminal_and_preserves_native_failure() {
        struct PartialSidecar {
            bytes: Vec<u8>,
            calls: usize,
            fail_at: usize,
        }
        impl RecordOutput for PartialSidecar {
            fn append(&mut self, record: &[u8]) -> std::io::Result<()> {
                self.calls += 1;
                if self.calls == self.fail_at {
                    self.bytes.extend_from_slice(&record[..10]);
                    return Err(std::io::ErrorKind::BrokenPipe.into());
                }
                self.bytes.extend_from_slice(record);
                Ok(())
            }
        }
        for fail_at in [2, 3] {
            let mut recorder = Recorder::with_writer(PartialSidecar {
                bytes: Vec::new(),
                calls: 0,
                fail_at,
            });
            recorder.activated = true;
            recorder.enter(FailurePhase::AppServing);
            let data = super::super::super::admission_work::Snapshot::maximal_fixture();
            recorder.current_admission_work(ServingRole::App, data.clone(), data);
            recorder.current_serving_join=Some(CurrentServingJoin {
                role:ServingRole::App,
                request:Some(super::super::super::native_clock::EnrolledRequestDiagnosticData::maximal_fixture()),
                peer:Some(super::super::super::native_enrollment::PeerRequestDiagnosticData::maximal_fixture()),
            });
            let native = PreparationFailure::at(
                PreparationStep::DiskBinding,
                anyhow::anyhow!("storage_provider_disk_binding"),
            );
            let exported = recorder.refuse(Some(&native));
            assert!(exported.is_err());
            let error = super::super::preserve_native_failure(Err(native), exported).unwrap_err();
            assert!(error.downcast_ref::<PreparationFailure>().is_some());
            assert!(
                error
                    .chain()
                    .any(|cause| cause.to_string() == "storage_provider_disk_binding")
            );
            assert!(
                recorder.export_failed
                    && recorder.current_admission_work.is_none()
                    && recorder.current_serving_join.is_none()
            );
            let end = recorder
                .output
                .bytes
                .iter()
                .rposition(|byte| *byte == b'\n')
                .unwrap()
                + 1;
            let complete = current_work_rows(&recorder.output.bytes[..end]);
            assert_eq!(complete.len(), fail_at - 2);
            assert!(!complete.iter().any(|row| row["boundary"] == "after"));
            let bytes = recorder.output.bytes.len();
            let calls = recorder.output.calls;
            assert!(recorder.refuse(None).is_err());
            recorder.emit_current_self_check(false).unwrap();
            assert_eq!(
                (recorder.output.bytes.len(), recorder.output.calls),
                (bytes, calls)
            );
        }
    }

    #[test]
    fn controller_ledger_observes_injected_full_check_in_an_isolated_process() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "security_epoch::controller::evidence::tests::controller_ledger_full_check_child",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated Controller ledger control failed"
        );
    }

    #[test]
    #[ignore = "isolated production-ledger control executed by parent"]
    fn controller_ledger_full_check_child() {
        use super::super::super::admission_work::{self, Work};
        admission_work::bind_producer(
            &Digest::new(b"Controller DATA ledger fixture"),
            std::process::id(),
        );
        let baseline = admission_work::snapshot();
        for inject in [false, true, false] {
            let before = admission_work::snapshot();
            if inject {
                let mut full = admission_work::begin(Work::PhysicalAdmission);
                full.finish(true);
            }
            let after = admission_work::snapshot();
            let (mut recorder, ..) = fixture();
            recorder.enter(FailurePhase::AppServing);
            recorder.current_admission_work(ServingRole::App, before, after);
            recorder.emit_current_self_check(true).unwrap();
            let rows = current_work_rows(&recorder.output);
            assert_eq!(rows.len(), 2);
            let a = &rows[0]["admission_work"];
            let b = &rows[1]["admission_work"];
            assert_eq!(a["producer_incarnation"], b["producer_incarnation"]);
            assert!(a["complete"].as_bool().unwrap() && b["complete"].as_bool().unwrap());
            assert!(a["sequence"].as_u64() < b["sequence"].as_u64());
            let zero = (0..9).all(|index| a["rows"][index] == b["rows"][index]);
            assert_eq!(
                zero, !inject,
                "full-check attempt must break warm-zero evidence"
            );
            if inject {
                assert_eq!(
                    b["rows"][3][2][0].as_u64().unwrap(),
                    a["rows"][3][2][0].as_u64().unwrap() + 1
                );
            }
        }
        assert!(
            serde_json::to_value(baseline).unwrap()["complete"]
                .as_bool()
                .unwrap()
        );
    }

    #[test]
    fn exclusive_profiles_are_separately_bounded_joined_and_once_per_action() {
        let (mut recorder, _, _, _, _, _) = fixture();
        recorder.incarnation = Some(Digest::new(b"actual-owner-historical-data-fixture"));
        for step in STEPS {
            let observation = Observation::BootstrapCompleted {
                step,
                operation: Digest::new(b"operation"),
                request: Digest::new(b"request"),
                snapshot: Digest::new(b"snapshot"),
                bootstrap: Some(
                    super::super::bootstrap_timing::BootstrapTiming::maximal_completed_fixture(),
                ),
            };
            recorder.emit_self_check(&observation).unwrap();
            let length = recorder.output.len();
            recorder.emit_self_check(&observation).unwrap();
            assert_eq!(recorder.output.len(), length);
        }
        assert_eq!(recorder.records, 0);
        assert_eq!(recorder.self_check_exported, 63);
        let text = std::str::from_utf8(&recorder.output).unwrap();
        assert_eq!(text.lines().count(), 6);
        for line in text.lines() {
            assert!(line.len() < MAX_SELF_CHECK_BYTES);
            let record: Value =
                serde_json::from_str(line.strip_prefix(SELF_CHECK_PREFIX).unwrap()).unwrap();
            assert_eq!(record["sequence"], 1);
            assert_eq!(
                record["selection"],
                serde_json::to_value(&recorder.selection).unwrap()
            );
            assert_eq!(record["profile"]["rows"].as_array().unwrap().len(), 9);
        }
    }

    #[test]
    fn transcript_has_six_ordered_steps_and_first_real_release_per_role_only() {
        let (mut recorder, seed, holder, create, complete, snapshot) = fixture();
        let incarnation = Digest::new(b"Controller original");
        recorder.enrolled(incarnation.clone()).unwrap();
        recorder.enter(FailurePhase::HolderListener);
        recorder.holder_listener_bound().unwrap();
        recorder.first_holder(&seed, &holder).unwrap();
        for request in [&create, &complete] {
            for action in [Action::Reserve, Action::Dispatch, Action::Settle] {
                recorder.enter_bootstrap(request, action);
                recorder.bootstrap_timing(Some(
                    super::super::bootstrap_timing::BootstrapTiming::maximal_completed_fixture(),
                ));
                recorder.bootstrap(request, action, &snapshot).unwrap();
            }
        }
        let snapshot_digest = crate::security_epoch::journal::snapshot_digest(&snapshot).unwrap();
        recorder.activated(&complete, &snapshot_digest).unwrap();
        for _ in 0..100 {
            for role in [ServingRole::App, ServingRole::Shell] {
                recorder.enter(match role {
                    ServingRole::App => FailurePhase::AppServing,
                    ServingRole::Shell => FailurePhase::ShellServing,
                });
                if matches!(role, ServingRole::App) {
                    let (_, profile) =
                        crate::security_epoch::self_check_profile::sample_current(|| ());
                    recorder.current_serving_profile(profile);
                }
                recorder
                    .serving(
                        role,
                        ServingObservation {
                            binding: Digest::new(b"actual request binding"),
                            snapshot: snapshot_digest.clone(),
                            request: Some(crate::security_epoch::native_enrollment::EnrolledRequestDiagnosticData::maximal_fixture()),
                            peer: Some(crate::security_epoch::native_enrollment::PeerRequestDiagnosticData::maximal_fixture()),
                        },
                    )
                    .unwrap();
            }
        }
        recorder.enter(FailurePhase::ShellServing);
        recorder.refuse(None).unwrap();
        recorder.refuse(None).unwrap();
        let rows = records(&recorder.output);
        assert_eq!(rows.len(), usize::from(MAX_RECORDS));
        let text = std::str::from_utf8(&recorder.output).unwrap();
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with(LISTENER_PREFIX))
                .count(),
            1
        );
        let profiles: Vec<Value> = text
            .lines()
            .filter_map(|line| {
                line.strip_prefix(SELF_CHECK_PREFIX)
                    .map(|row| serde_json::from_str::<Value>(row).unwrap())
            })
            .filter(|profile| profile["format"] == "controller_current_serving_v4")
            .collect();
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with(SELF_CHECK_PREFIX))
                .count(),
            206
        );
        assert_eq!(profiles.len(), 200);
        for (index, profile) in profiles.iter().enumerate() {
            assert_eq!(profile["sequence"], index + 1);
            assert_eq!(profile["completed"], true);
            assert_eq!(
                profile["lifecycle_sequence"],
                match index {
                    0 => 9,
                    1 => 10,
                    _ => 11,
                }
            );
            assert_eq!(profile["controller_incarnation"], incarnation.as_str());
            assert!(profile["request"]["request_original"].is_string());
            assert_eq!(profile["detail"].is_object(), index % 2 == 0);
            assert_eq!(
                profile["role"],
                if index % 2 == 0 { "app" } else { "shell" }
            );
        }
        assert!(
            recorder.output.len()
                <= usize::from(MAX_RECORDS) * MAX_RECORD_BYTES
                    + MAX_LISTENER_BYTES
                    + 200 * MAX_CURRENT_SELF_CHECK_BYTES
        );
        for (index, row) in rows.iter().enumerate() {
            assert_eq!(row["sequence"], index + 1);
            assert_eq!(row["controller_incarnation"], incarnation.as_str());
            assert_eq!(row["format"], "day2_native_controller_evidence_v1");
        }
        let steps = rows
            .iter()
            .filter_map(|row| row["observation"].get("step"))
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            steps,
            serde_json::json!([
                "create_reserve",
                "create_dispatch",
                "create_settle",
                "activate_reserve",
                "activate_dispatch",
                "activate_settle"
            ])
            .as_array()
            .unwrap()
            .clone()
        );
        assert_eq!(rows[9]["observation"]["role"], "app");
        assert_eq!(rows[10]["observation"]["role"], "shell");
        for row in &rows[2..8] {
            let timing = &row["observation"]["bootstrap"];
            assert_eq!(timing["purpose_limit_us"], 60_000_000);
            assert_eq!(timing["elapsed_us"], u32::MAX);
            assert_eq!(timing["last_step"], "bootstrap_release");
            assert_eq!(timing["returned"], true);
            assert_eq!(timing["timing_format"], "operation_count_total_us_v1");
        }
        assert_eq!(
            rows[11]["observation"],
            serde_json::json!({"event":"refused", "at":"shell_serving"})
        );
        assert!(
            recorder
                .serving(
                    ServingRole::App,
                    ServingObservation {
                        binding: Digest::new(b"late"),
                        snapshot: snapshot_digest,
                        request: Some(crate::security_epoch::native_enrollment::EnrolledRequestDiagnosticData::maximal_fixture()),
                        peer: Some(crate::security_epoch::native_enrollment::PeerRequestDiagnosticData::maximal_fixture()),
                    }
                )
                .is_err()
        );
        assert_eq!(records(&recorder.output).len(), 12);
    }

    #[test]
    fn incomplete_or_read_only_timing_cannot_be_exported_as_a_completed_action() {
        for timing in [
            super::super::bootstrap_timing::BootstrapTiming::maximal_fixture(),
            super::super::bootstrap_timing::BootstrapTiming::maximal_provider_fixture(),
        ] {
            let (mut recorder, seed, holder, create, _, snapshot) = fixture();
            recorder.enrolled(Digest::new(b"Controller")).unwrap();
            recorder.first_holder(&seed, &holder).unwrap();
            recorder.enter_bootstrap(&create, Action::Reserve);
            recorder.bootstrap_timing(Some(timing));
            let error = recorder
                .bootstrap(&create, Action::Reserve, &snapshot)
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "native_evidence_bootstrap_timing_incomplete"
            );
            assert_eq!(recorder.next, 0);
            assert_eq!(records(&recorder.output).len(), 2);
        }
    }

    #[test]
    fn incomplete_or_out_of_order_data_cannot_emit_activation_or_serving() {
        let (mut recorder, seed, holder, create, complete, snapshot) = fixture();
        assert!(recorder.first_holder(&seed, &holder).is_err());
        assert!(
            recorder
                .bootstrap(&create, Action::Reserve, &snapshot)
                .is_err()
        );
        assert!(
            recorder
                .activated(&complete, &Digest::new(b"snapshot"))
                .is_err()
        );
        assert!(
            recorder
                .serving(
                    ServingRole::App,
                    ServingObservation {
                        binding: Digest::new(b"binding"),
                        snapshot: Digest::new(b"snapshot"),
                        request: Some(crate::security_epoch::native_enrollment::EnrolledRequestDiagnosticData::maximal_fixture()),
                        peer: Some(crate::security_epoch::native_enrollment::PeerRequestDiagnosticData::maximal_fixture()),
                    }
                )
                .is_err()
        );
        assert!(recorder.output.is_empty());
        recorder.enrolled(Digest::new(b"original")).unwrap();
        recorder.first_holder(&seed, &holder).unwrap();
        assert!(
            recorder
                .bootstrap(&create, Action::Dispatch, &snapshot)
                .is_err()
        );
        assert!(
            recorder
                .bootstrap(&complete, Action::Reserve, &snapshot)
                .is_err()
        );
        recorder
            .bootstrap(&create, Action::Reserve, &snapshot)
            .unwrap();
        assert!(
            recorder
                .bootstrap(&create, Action::Reserve, &snapshot)
                .is_err()
        );
        assert!(
            recorder
                .activated(&complete, &Digest::new(b"snapshot"))
                .is_err()
        );
        recorder.refuse(None).unwrap();
        assert!(
            recorder
                .bootstrap(&create, Action::Dispatch, &snapshot)
                .is_err()
        );
        assert_eq!(records(&recorder.output).len(), 4);
    }

    #[test]
    fn maximal_timing_data_fits_existing_records_and_read_only_observation_cannot_claim_holder() {
        let (mut recorder, seed, holder, ..) = fixture();
        recorder
            .enrolled(Digest::new(b"Controller timing"))
            .unwrap();
        recorder.preparation_timings(
            super::super::preparation_timing::Timings::maximal_summary_fixture(),
        );
        recorder.first_holder(&seed, &holder).unwrap();
        recorder.enter(FailurePhase::Preparation);
        recorder
            .refuse(Some(&PreparationFailure::at(
                PreparationStep::OriginalRetention,
                anyhow::anyhow!("epoch_native_clock_rewind_or_expired"),
            )))
            .unwrap();
        assert_eq!(records(&recorder.output).len(), 3);

        let (mut recorder, seed, holder, ..) = fixture();
        recorder
            .enrolled(Digest::new(b"Controller read-only"))
            .unwrap();
        recorder
            .preparation_read_only(
                super::super::bootstrap_timing::BootstrapTiming::maximal_provider_fixture(),
            )
            .unwrap();
        assert!(recorder.first_holder(&seed, &holder).is_err());
        assert!(
            recorder
                .preparation_read_only(
                    super::super::bootstrap_timing::BootstrapTiming::maximal_provider_fixture(),
                )
                .is_err()
        );
        recorder.enter(FailurePhase::Preparation);
        recorder.refuse(None).unwrap();
        let rows = records(&recorder.output);
        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows[1]["observation"]["event"],
            "preparation_read_only_observed"
        );
        assert_eq!(
            rows[1]["observation"]["frontier"],
            "auth_three_provider_rounds"
        );
        assert_eq!(rows[1]["observation"]["expected_rounds"], 3);
        assert_eq!(
            rows[1]["observation"]["bootstrap"]["provider_rounds"],
            serde_json::json!([3, 3])
        );
        assert_eq!(
            rows[1]["observation"]["bootstrap"]["scope"],
            "provider_read_only_storage_metadata"
        );
        assert!(
            rows.iter()
                .all(|row| row["observation"]["event"] != "first_holder_durability_completed")
        );
    }

    #[test]
    fn refusal_before_selection_is_fixed_metadata_without_positive_milestones() {
        let mut recorder = Recorder::with_writer(Vec::new());
        recorder.refuse(None).unwrap();
        recorder.refuse(None).unwrap();
        let rows = records(&recorder.output);
        assert_eq!(rows.len(), 1);
        assert!(rows[0]["selection"].is_null());
        assert!(rows[0]["controller_incarnation"].is_null());
        assert_eq!(
            rows[0]["observation"],
            serde_json::json!({"event":"refused", "at":"selection"})
        );
    }

    #[test]
    fn exported_bytes_contain_commitments_not_private_selection_or_holder_fields() {
        let (mut recorder, mut seed, holder, _, _, _) = fixture();
        seed.provider_volume_uid = "/private/secret-volume-location".into();
        recorder
            .enrolled(Digest::new(b"private Controller incarnation input"))
            .unwrap();
        recorder.first_holder(&seed, &holder).unwrap();
        let output = std::str::from_utf8(&recorder.output).unwrap();
        for private in [
            "/private/",
            "secret-volume",
            "private Controller",
            "project-seven",
            "epoch@",
            holder.pod_uid.as_str(),
            "ephemeral_key",
            "principal",
        ] {
            assert!(!output.contains(private), "private data leaked: {private}");
        }
        let rows = records(&recorder.output);
        assert_eq!(
            rows[1]["observation"]["seed"],
            seed.digest().unwrap().as_str()
        );
        assert_eq!(
            rows[1]["observation"]["holder"],
            Digest::of(&("day2-controller-first-holder-evidence-v1", &holder))
                .unwrap()
                .as_str()
        );
    }

    struct InterruptedWriter {
        bytes: Vec<u8>,
    }
    impl RecordOutput for InterruptedWriter {
        fn append(&mut self, record: &[u8]) -> std::io::Result<()> {
            self.bytes.extend_from_slice(&record[..10]);
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn failed_partial_export_is_terminal_and_cannot_claim_a_complete_record() {
        let mut recorder = Recorder::with_writer(InterruptedWriter { bytes: Vec::new() });
        assert!(recorder.refuse(None).is_err());
        assert_eq!(recorder.records, 0);
        assert_eq!(recorder.output.bytes.len(), 10);
        assert!(recorder.refuse(None).is_err());
        assert_eq!(recorder.output.bytes.len(), 10);
        assert!(!recorder.output.bytes.contains(&b'\n'));
    }
    #[test]
    fn preparation_categories_accept_only_closed_messages_and_os_kinds() {
        use PreparationErrorCategory as Category;
        for (code, expected) in [
            (
                "native_enrollment_socket_poll_timeout",
                Category::SocketPollTimeout,
            ),
            (
                "native_enrollment_socket_unexpected_events",
                Category::SocketUnexpectedEvents,
            ),
            ("storage_peer_channel_closed", Category::ChannelClosed),
            ("storage_peer_idle_channel_closed", Category::ChannelClosed),
            (
                "storage_peer_channel_cloexec_required",
                Category::ChannelProfileChanged,
            ),
            (
                "storage_peer_listener_cloexec_lost",
                Category::ChannelProfileChanged,
            ),
            (
                "native_enrollment_pid_not_visible",
                Category::ProcessNotVisible,
            ),
            (
                "storage_peer_controller_pid_not_visible",
                Category::ProcessNotVisible,
            ),
            (
                "native_enrollment_code_mismatch",
                Category::ProcessIdentityChanged,
            ),
            (
                "native_enrollment_namespace_changed",
                Category::ProcessIdentityChanged,
            ),
            ("storage_peer_channel_closed /SECRET", Category::Other),
            ("native_enrollment_code_mismatch /SECRET", Category::Other),
            ("native_enrollment_process_exited", Category::ProcessExited),
            (
                "storage_peer_remote_stage_expired",
                Category::RemoteStageExpired,
            ),
            ("storage_peer_remote_stage_expired /SECRET", Category::Other),
            (
                "epoch_native_clock_rewind_or_expired",
                Category::ClockExpiredOrRewound,
            ),
            (
                "native_enrollment_stage_expired",
                Category::ClockExpiredOrRewound,
            ),
            (
                "epoch_counter_credential_expired",
                Category::ClockExpiredOrRewound,
            ),
            (
                "epoch_counter_connection_clock_rewind",
                Category::ClockExpiredOrRewound,
            ),
            (
                "epoch_native_acquisition_refused",
                Category::AcquisitionRefused,
            ),
            (
                "epoch_counter_credential_refused",
                Category::AcquisitionRefused,
            ),
            (
                "epoch_native_transport_unavailable",
                Category::TransportUnavailable,
            ),
            (
                "epoch_counter_tokeninfo_unavailable",
                Category::TransportUnavailable,
            ),
            (
                "epoch_counter_tokeninfo_transport",
                Category::TransportUnavailable,
            ),
            (
                "epoch_native_response_status_or_bound",
                Category::ResponseStatusOrBound,
            ),
            (
                "epoch_counter_tokeninfo_status_or_bound",
                Category::ResponseStatusOrBound,
            ),
            ("epoch_counter_tokeninfo_bound", Category::AdmissionRejected),
            ("epoch_counter_tokeninfo_shape", Category::AdmissionRejected),
            (
                "epoch_counter_tokeninfo_binding_or_expiry",
                Category::AdmissionRejected,
            ),
            ("epoch_counter_tokeninfo_shape /SECRET", Category::Other),
            (
                "epoch_counter_tokeninfo_status_or_bound?access_token=PRIVATE",
                Category::Other,
            ),
            ("storage_provider_disk_binding", Category::AdmissionRejected),
            (
                "epoch_native_clock_rewind_or_expired /SECRET",
                Category::Other,
            ),
        ] {
            assert_eq!(
                preparation_error_category(&anyhow::Error::msg(code)),
                expected
            );
            assert_eq!(
                preparation_error_category(&anyhow::Error::msg(code.to_owned())),
                expected
            );
        }
        for (kind, expected) in [
            (
                std::io::ErrorKind::PermissionDenied,
                Category::PermissionDenied,
            ),
            (std::io::ErrorKind::NotFound, Category::NotFound),
            (std::io::ErrorKind::AlreadyExists, Category::AlreadyExists),
            (std::io::ErrorKind::TimedOut, Category::TimedOut),
        ] {
            let error = anyhow::Error::new(std::io::Error::new(kind, "/SECRET Bearer TOKEN"));
            assert_eq!(preparation_error_category(&error), expected);
        }
        assert_eq!(
            preparation_error_category(&anyhow::Error::new(rustix::io::Errno::LOOP)),
            Category::PathResolution
        );
    }

    #[test]
    fn preparation_context_preserves_original_error_and_innermost_boundary() {
        let error = PreparationFailure::at(
            PreparationStep::ClaimBinding,
            anyhow::Error::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "SECRET",
            )),
        );
        let error = PreparationFailure::at(PreparationStep::StorageAcquisition, error);
        assert_eq!(
            PreparationFailure::observe(&error),
            PreparationFailure {
                step: PreparationStep::ClaimBinding,
                category: PreparationErrorCategory::PermissionDenied,
                progress: None,
                request: None,
            }
        );
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn preparation_progress_keeps_inner_boundary_and_fixed_private_record_bound() {
        let error = PreparationFailure::with_progress(
            PreparationStep::OriginalRetentionBefore,
            anyhow::anyhow!("epoch_native_clock_rewind_or_expired"),
            PreparationProgress {
                last_checked_us: Some(u32::MAX),
                ..PreparationProgress::default()
            },
        );
        let error = PreparationFailure::with_progress(
            PreparationStep::OriginalRetention,
            error,
            PreparationProgress {
                acquired_us: Some(u32::MAX),
                image_us: Some(u32::MAX),
                prepared_us: Some(u32::MAX),
                last_checked_us: Some(1),
            },
        );
        assert_eq!(
            error.downcast_ref::<&'static str>(),
            Some(&"epoch_native_clock_rewind_or_expired")
        );
        let (mut recorder, _, _, _, _, _) = fixture();
        recorder.enrolled(Digest::new(b"Controller")).unwrap();
        recorder.enter(FailurePhase::Preparation);
        recorder.refuse(Some(&error)).unwrap();
        let rows = records(&recorder.output);
        let preparation = &rows[1]["observation"]["preparation"];
        assert_eq!(preparation["step"], "original_retention_before");
        assert_eq!(preparation["category"], "clock_expired_or_rewound");
        assert_eq!(
            preparation["progress"],
            serde_json::json!({
                "acquired_us":u32::MAX, "image_us":u32::MAX,
                "prepared_us":u32::MAX, "last_checked_us":u32::MAX,
            })
        );
        assert_eq!(preparation.as_object().unwrap().len(), 3);
        assert!(
            !String::from_utf8(recorder.output)
                .unwrap()
                .contains("rewind_or_expired")
        );
    }

    #[derive(Debug)]
    struct MustNotDisplay;
    impl std::fmt::Display for MustNotDisplay {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("diagnostics must never format an unknown error")
        }
    }
    impl std::error::Error for MustNotDisplay {}

    #[test]
    fn receive_boundary_categories_preserve_causes_without_exporting_error_text() {
        for (code, category) in [
            ("storage_peer_channel_closed", "channel_closed"),
            (
                "storage_peer_channel_cloexec_required",
                "channel_profile_changed",
            ),
            ("native_enrollment_pid_not_visible", "process_not_visible"),
            (
                "native_enrollment_process_replaced",
                "process_identity_changed",
            ),
            ("storage_peer_channel_closed /SECRET Bearer TOKEN", "other"),
        ] {
            let error = anyhow::Error::msg(code.to_owned()).context(MustNotDisplay);
            let error = PreparationFailure::at(PreparationStep::FirstHello, error);
            let error = PreparationFailure::at(PreparationStep::FirstExchange, error);
            assert_eq!(error.downcast_ref::<String>().unwrap(), code);
            let (mut recorder, _, _, _, _, _) = fixture();
            recorder.enrolled(Digest::new(b"Controller")).unwrap();
            recorder.preparation_timings(
                super::super::preparation_timing::Timings::maximal_summary_fixture(),
            );
            recorder.enter(FailurePhase::FirstHolder);
            recorder.refuse(Some(&error)).unwrap();
            let rows = records(&recorder.output);
            let boundary = &rows[1]["observation"]["preparation"];
            assert_eq!(boundary["step"], "first_hello");
            assert_eq!(boundary["category"], category);
            let exported = String::from_utf8(recorder.output).unwrap();
            for private in [code, "/SECRET", "Bearer", "TOKEN"] {
                assert!(!exported.contains(private));
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn typed_packet_failures_keep_their_closed_category_and_original_cause() {
        use rustix::{io::Errno, net::RecvPidfdError as Packet};
        for (packet, category) in [
            (Packet::SocketProfile, "packet_socket_profile"),
            (Packet::EmptyPayloadBuffer, "packet_empty_payload_buffer"),
            (Packet::ClosedOrEmptyPacket, "packet_closed_or_empty"),
            (Packet::Truncated, "packet_truncated"),
            (Packet::MalformedAncillary, "packet_malformed_ancillary"),
            (Packet::UnexpectedAncillary, "packet_unexpected_ancillary"),
            (Packet::MissingProcess, "packet_missing_process"),
            (Packet::DuplicateProcess, "packet_duplicate_process"),
            (
                Packet::SenderUnavailable(Errno::SRCH),
                "packet_sender_unavailable",
            ),
            (
                Packet::SenderUnavailable(Errno::PERM),
                "packet_sender_unavailable",
            ),
            (Packet::MissingCredentials, "packet_missing_credentials"),
            (Packet::DuplicateCredentials, "packet_duplicate_credentials"),
            (Packet::MalformedCredentials, "packet_malformed_credentials"),
            (
                Packet::DescriptorNotCloexec,
                "packet_descriptor_not_cloexec",
            ),
            (Packet::Io(Errno::ACCESS), "permission_denied"),
            (Packet::Io(Errno::NOENT), "not_found"),
            (Packet::Io(Errno::EXIST), "already_exists"),
            (Packet::Io(Errno::TIMEDOUT), "timed_out"),
            (Packet::Io(Errno::LOOP), "path_resolution"),
            (Packet::Io(Errno::XDEV), "path_resolution"),
            (Packet::Io(Errno::IO), "io"),
        ] {
            let error = anyhow::Error::new(packet).context(MustNotDisplay);
            let error = PreparationFailure::at(PreparationStep::FirstHello, error);
            let error = PreparationFailure::at(PreparationStep::FirstExchange, error);
            assert_eq!(error.downcast_ref::<Packet>(), Some(&packet));
            let (mut recorder, _, _, _, _, _) = fixture();
            recorder.enrolled(Digest::new(b"Controller")).unwrap();
            recorder.preparation_timings(
                super::super::preparation_timing::Timings::maximal_summary_fixture(),
            );
            recorder.enter(FailurePhase::FirstHolder);
            recorder.refuse(Some(&error)).unwrap();
            let rows = records(&recorder.output);
            let boundary = &rows[1]["observation"]["preparation"];
            assert_eq!(boundary["step"], "first_hello");
            assert_eq!(boundary["category"], category);
            let exported = String::from_utf8(recorder.output).unwrap();
            assert!(!exported.contains("PIDFD packet reception failed"));
            assert!(!exported.contains("native_enrollment"));
        }
    }

    #[test]
    fn first_holder_refusals_keep_fixed_inner_boundaries_timings_and_record_bound() {
        for (step, name) in [
            (PreparationStep::FirstRole, "first_role"),
            (PreparationStep::FirstFile, "first_file"),
            (PreparationStep::FirstStart, "first_start"),
            (PreparationStep::FirstExchange, "first_exchange"),
            (PreparationStep::FirstCheck, "first_check"),
            (PreparationStep::FirstProjection, "first_projection"),
            (PreparationStep::FirstAccept, "first_accept"),
            (PreparationStep::FirstHello, "first_hello"),
            (PreparationStep::FirstPeer, "first_peer"),
            (PreparationStep::FirstOffer, "first_offer"),
            (PreparationStep::FirstConfirm, "first_confirm"),
            (PreparationStep::FirstComplete, "first_complete"),
            (PreparationStep::FirstAccepted, "first_accepted"),
            (PreparationStep::FirstDurability, "first_durability"),
            (PreparationStep::FirstRetain, "first_retain"),
        ] {
            let error = PreparationFailure::at(
                step,
                anyhow::anyhow!("native_enrollment_socket_poll_timeout"),
            );
            let error = PreparationFailure::at(PreparationStep::FirstExchange, error);
            assert_eq!(PreparationFailure::observe(&error).step, step);
            assert_eq!(
                error.downcast_ref::<&str>(),
                Some(&"native_enrollment_socket_poll_timeout")
            );
            let (mut recorder, _, _, _, _, _) = fixture();
            recorder.enrolled(Digest::new(b"Controller")).unwrap();
            recorder.preparation_timings(
                super::super::preparation_timing::Timings::maximal_summary_fixture(),
            );
            recorder.enter(FailurePhase::FirstHolder);
            recorder.refuse(Some(&error)).unwrap();
            let rows = records(&recorder.output);
            assert_eq!(rows[1]["observation"]["at"], "first_holder");
            assert_eq!(rows[1]["observation"]["preparation"]["step"], name);
            assert_eq!(
                rows[1]["observation"]["preparation"]["category"],
                "socket_poll_timeout"
            );
            let timing = rows[1]["observation"]["timing"].as_array().unwrap();
            for name in ["first_role", "first_file", "first_exchange"] {
                assert!(timing.iter().any(|row| row[0] == name));
            }
            assert!(
                !String::from_utf8(recorder.output)
                    .unwrap()
                    .contains("native_enrollment_socket")
            );
        }
        let (mut recorder, _, _, _, _, _) = fixture();
        recorder.enrolled(Digest::new(b"Controller")).unwrap();
        recorder.enter(FailurePhase::FirstHolder);
        recorder
            .refuse(Some(&PreparationFailure::at(
                PreparationStep::FirstPeer,
                anyhow::Error::new(MustNotDisplay),
            )))
            .unwrap();
        assert_eq!(
            records(&recorder.output)[1]["observation"]["preparation"]["category"],
            "other"
        );
    }

    #[test]
    fn holder_listener_refusal_keeps_inner_step_category_and_cached_preparation() {
        for (cause, step, name, category) in [
            (
                anyhow::Error::new(rustix::io::Errno::XDEV),
                PreparationStep::HolderTransport,
                "holder_transport",
                "path_resolution",
            ),
            (
                anyhow::anyhow!("epoch_native_acquisition_expired"),
                PreparationStep::HolderFilePhase,
                "holder_file_phase",
                "clock_expired_or_rewound",
            ),
            (
                anyhow::anyhow!("epoch_native_acquisition_expired"),
                PreparationStep::HolderFinalCheck,
                "holder_final_check",
                "clock_expired_or_rewound",
            ),
        ] {
            let error = PreparationFailure::at(step, cause);
            let error = PreparationFailure::at(PreparationStep::HolderListenerBind, error);
            assert_eq!(PreparationFailure::observe(&error).step, step);
            if category == "path_resolution" {
                assert_eq!(
                    error.downcast_ref::<rustix::io::Errno>(),
                    Some(&rustix::io::Errno::XDEV)
                );
            }
            let (mut recorder, _, _, _, _, _) = fixture();
            recorder.enrolled(Digest::new(b"Controller")).unwrap();
            recorder.preparation_timings(
                super::super::preparation_timing::Timings::maximal_summary_fixture(),
            );
            recorder.enter(FailurePhase::HolderListener);
            recorder.refuse(Some(&error)).unwrap();
            let rows = records(&recorder.output);
            assert_eq!(rows[1]["observation"]["at"], "holder_listener");
            assert_eq!(rows[1]["observation"]["preparation"]["step"], name);
            assert_eq!(rows[1]["observation"]["preparation"]["category"], category);
            assert!(rows[1]["observation"]["timing"].is_array());
            let timing = rows[1]["observation"]["timing"].as_array().unwrap();
            for name in ["holder_role", "holder_listener"] {
                assert!(timing.iter().any(|row| row[0] == name));
            }
            for line in recorder
                .output
                .split(|b| *b == b'\n')
                .filter(|s| !s.is_empty())
            {
                assert!(line.len() < MAX_RECORD_BYTES);
            }
            let text = String::from_utf8(recorder.output).unwrap();
            assert!(!text.contains("epoch_native_acquisition_expired"));
            assert!(!text.contains("Cross-device"));
        }
    }

    #[test]
    fn preparation_refusal_is_bounded_fixed_data_and_never_formats_unknown_causes() {
        let (mut recorder, _, _, _, _, _) = fixture();
        recorder.enrolled(Digest::new(b"Controller")).unwrap();
        recorder.enter(FailurePhase::Preparation);
        let error = PreparationFailure::at(
            PreparationStep::MetadataCredential,
            anyhow::Error::new(MustNotDisplay),
        );
        recorder.refuse(Some(&error)).unwrap();
        recorder.refuse(Some(&error)).unwrap();
        let rows = records(&recorder.output);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[1]["observation"],
            serde_json::json!({
                "event":"refused", "at":"preparation",
                "preparation":{"step":"metadata_credential", "category":"other"}
            })
        );
        assert!(
            !String::from_utf8(recorder.output)
                .unwrap()
                .contains("MustNotDisplay")
        );
    }

    #[test]
    fn preparation_details_are_not_exported_for_another_phase_or_as_success() {
        let (mut recorder, _, _, _, _, _) = fixture();
        recorder.enter(FailurePhase::Enrollment);
        let error = PreparationFailure::at(
            PreparationStep::RoleStage,
            anyhow::anyhow!("native_enrollment_stage_expired"),
        );
        recorder.refuse(Some(&error)).unwrap();
        assert_eq!(
            records(&recorder.output)[0]["observation"],
            serde_json::json!({"event":"refused", "at":"enrollment"})
        );
        assert_eq!(recorder.records, 1);
        assert!(!recorder.first_holder && !recorder.activated);
    }
    #[test]
    fn bootstrap_refusal_exports_only_closed_inner_cause_after_unwind_and_stays_terminal() {
        for (phase, name) in [
            (FailurePhase::CreateReserve, "create_reserve"),
            (FailurePhase::CreateDispatch, "create_dispatch"),
            (FailurePhase::CreateSettle, "create_settle"),
            (FailurePhase::ActivateReserve, "activate_reserve"),
            (FailurePhase::ActivateDispatch, "activate_dispatch"),
            (FailurePhase::ActivateSettle, "activate_settle"),
        ] {
            let cause =
                anyhow::anyhow!("epoch_native_clock_rewind_or_expired").context(MustNotDisplay);
            let error = PreparationFailure::at(PreparationStep::BootstrapPeer, cause);
            let error = PreparationFailure::at(PreparationStep::BootstrapFilePeer, error);
            assert_eq!(
                error.downcast_ref::<&str>(),
                Some(&"epoch_native_clock_rewind_or_expired")
            );
            let (mut recorder, _, _, _, _, _) = fixture();
            recorder.enrolled(Digest::new(b"Controller")).unwrap();
            recorder.preparation_timings(
                super::super::preparation_timing::Timings::maximal_summary_fixture(),
            );
            recorder.enter(phase);
            recorder.bootstrap_timing(Some(
                super::super::bootstrap_timing::BootstrapTiming::maximal_fixture(),
            ));
            recorder.refuse(Some(&error)).unwrap();
            let count = recorder.records;
            recorder
                .refuse(Some(&anyhow::Error::new(MustNotDisplay)))
                .unwrap();
            assert_eq!(recorder.records, count);
            let rows = records(&recorder.output);
            assert_eq!(rows.len(), 2);
            let observation = &rows[1]["observation"];
            assert_eq!(observation["at"], name);
            assert_eq!(
                observation["preparation"],
                serde_json::json!({
                    "step":"bootstrap_peer", "category":"clock_expired_or_rewound"
                })
            );
            assert!(observation.get("timing").is_none());
            assert_eq!(observation["bootstrap"]["scope"], "storage_bootstrap");
            assert!(!recorder.first_holder && !recorder.activated);
            let bytes = String::from_utf8(recorder.output).unwrap();
            assert!(!bytes.contains("epoch_native_clock") && !bytes.contains("MustNotDisplay"));
        }
    }

    #[test]
    fn bootstrap_unknown_private_causes_never_become_exported_error_text() {
        let private = "/SECRET/provider/body Bearer TOKEN nonce=private subject=private";
        let cause = anyhow::Error::msg(private).context(MustNotDisplay);
        let error = PreparationFailure::at(PreparationStep::BootstrapReserveSend, cause);
        assert_eq!(error.downcast_ref::<&str>(), Some(&private));
        let (mut recorder, _, _, _, _, _) = fixture();
        recorder.enter(FailurePhase::CreateReserve);
        recorder.refuse(Some(&error)).unwrap();
        let rows = records(&recorder.output);
        assert_eq!(
            rows[0]["observation"]["preparation"],
            serde_json::json!({
                "step":"bootstrap_reserve_send", "category":"other"
            })
        );
        let bytes = String::from_utf8(recorder.output).unwrap();
        for value in [
            private,
            "/SECRET",
            "Bearer",
            "TOKEN",
            "nonce",
            "subject",
            "MustNotDisplay",
        ] {
            assert!(!bytes.contains(value));
        }
    }

    #[test]
    fn failed_request_window_keeps_first_boundary_and_fits_maximal_private_record() {
        for timeout in [false, true] {
            let window = FailedRequestWindow::maximal_fixture(timeout);
            let native = anyhow::Error::new(window)
                .context("epoch_native_transport_unavailable")
                .context(MustNotDisplay);
            let error =
                PreparationFailure::at(PreparationStep::BootstrapDispatchCounterSend, native);
            let error = PreparationFailure::with_progress(
                PreparationStep::BootstrapFile,
                error,
                PreparationProgress {
                    acquired_us: Some(u32::MAX),
                    image_us: Some(u32::MAX),
                    prepared_us: Some(u32::MAX),
                    last_checked_us: Some(u32::MAX),
                },
            );
            assert_eq!(FailedRequestWindow::observe(&error), Some(window));
            let (mut recorder, _, _, _, _, _) = fixture();
            recorder.enrolled(Digest::new(b"Controller")).unwrap();
            recorder.preparation_timings(
                super::super::preparation_timing::Timings::maximal_summary_fixture(),
            );
            recorder.enter(FailurePhase::ActivateDispatch);
            recorder.bootstrap_timing(Some(
                super::super::bootstrap_timing::BootstrapTiming::maximal_fixture(),
            ));
            recorder.records = MAX_RECORDS - 1;
            recorder.refuse(Some(&error)).unwrap();
            let rows = records(&recorder.output);
            let preparation = &rows[1]["observation"]["preparation"];
            assert_eq!(preparation["step"], "bootstrap_dispatch_counter_send");
            assert_eq!(preparation["category"], "transport_unavailable");
            assert_eq!(
                preparation["request"],
                serde_json::json!([u32::MAX, 5_000_000, timeout])
            );
            assert_eq!(rows[1]["sequence"], MAX_RECORDS);
            assert!(recorder.refused && !recorder.activated);
            let bytes = String::from_utf8(recorder.output).unwrap();
            for value in [
                "MustNotDisplay",
                "epoch_native_transport_unavailable",
                "https://",
                "Bearer",
            ] {
                assert!(!bytes.contains(value));
            }
        }
    }

    #[test]
    fn bootstrap_annotations_cannot_export_details_from_other_lifecycle_phases() {
        for phase in [
            FailurePhase::Selection,
            FailurePhase::Enrollment,
            FailurePhase::Activation,
            FailurePhase::ServingListener,
            FailurePhase::AppPending,
            FailurePhase::AppServing,
            FailurePhase::ShellPending,
            FailurePhase::ShellAccept,
            FailurePhase::ShellServing,
            FailurePhase::Health,
        ] {
            let (mut recorder, _, _, _, _, _) = fixture();
            let error = PreparationFailure::at(
                PreparationStep::BootstrapRole,
                anyhow::Error::new(MustNotDisplay),
            );
            recorder.enter(phase);
            recorder.bootstrap_timing(Some(
                super::super::bootstrap_timing::BootstrapTiming::maximal_fixture(),
            ));
            recorder.refuse(Some(&error)).unwrap();
            let rows = records(&recorder.output);
            assert!(rows[0]["observation"].get("preparation").is_none());
            assert!(rows[0]["observation"].get("bootstrap").is_none());
            assert!(recorder.refused && !recorder.activated && !recorder.first_holder);
            assert!(
                !String::from_utf8(recorder.output)
                    .unwrap()
                    .contains("bootstrap_role")
            );
        }
    }

    #[test]
    fn cold_counter_refusal_is_closed_after_activation_and_keeps_original_cause() {
        for step in [
            PreparationStep::CounterRoleStage,
            PreparationStep::CounterPendingFile,
            PreparationStep::CounterPhysicalAcquire,
            PreparationStep::CounterStage,
            PreparationStep::CounterAdmit,
            PreparationStep::CounterPhysicalFinish,
        ] {
            let (mut recorder, seed, holder, create, complete, snapshot) = fixture();
            recorder.enrolled(Digest::new(b"Controller")).unwrap();
            recorder.first_holder(&seed, &holder).unwrap();
            for request in [&create, &complete] {
                for action in [Action::Reserve, Action::Dispatch, Action::Settle] {
                    recorder.bootstrap(request, action, &snapshot).unwrap();
                }
            }
            recorder
                .activated(&complete, &Digest::new(b"snapshot"))
                .unwrap();
            recorder.enter(FailurePhase::CounterAdmission);
            let error = PreparationFailure::at(step, anyhow::Error::new(MustNotDisplay));
            assert!(error.downcast_ref::<MustNotDisplay>().is_some());
            recorder.refuse(Some(&error)).unwrap();
            let rows = records(&recorder.output);
            assert_eq!(rows.len(), 10);
            assert_eq!(rows[8]["observation"]["event"], "activation_completed");
            assert_eq!(
                rows[9]["observation"],
                serde_json::json!({
                    "event":"refused", "at":"counter_admission",
                    "preparation":{"step":step,"category":"other"}
                })
            );
            assert!(recorder.activated && recorder.refused && recorder.serving == [false; 2]);
            let length = recorder.output.len();
            recorder.refuse(Some(&error)).unwrap();
            assert_eq!(recorder.output.len(), length);
            let text = std::str::from_utf8(&recorder.output).unwrap();
            assert!(!text.contains("MustNotDisplay"));
            assert!(text.lines().all(|line| line.len() < MAX_RECORD_BYTES));
        }
        // A more specific original native boundary keeps precedence, while
        // context wrapping never replaces the original error or formats it.
        let inner = PreparationFailure::at(
            PreparationStep::VolumeCurrent,
            anyhow::Error::new(MustNotDisplay),
        );
        let outer = PreparationFailure::at(PreparationStep::CounterPhysicalAcquire, inner);
        assert_eq!(
            PreparationFailure::observe(&outer).step,
            PreparationStep::VolumeCurrent
        );
        assert!(outer.downcast_ref::<MustNotDisplay>().is_some());
    }

    #[test]
    fn counter_http_refusal_exports_only_typed_status_or_declared_bound() {
        use crate::security_epoch::transport::ResponseRefusal as Counter;
        for (refusal, expected) in [
            (Counter::BadRequest, "response_bad_request"),
            (Counter::Unauthorized, "response_unauthorized"),
            (Counter::Forbidden, "response_forbidden"),
            (Counter::NotFound, "response_not_found"),
            (Counter::MethodNotAllowed, "response_method_not_allowed"),
            (Counter::RequestTimeout, "response_request_timeout"),
            (Counter::LengthRequired, "response_length_required"),
            (Counter::RateLimited, "response_rate_limited"),
            (Counter::ServerError, "response_server_error"),
            (Counter::OtherStatus, "response_other_status"),
            (
                Counter::DeclaredLengthBound,
                "response_declared_length_bound",
            ),
            (Counter::MetadataFlavor, "response_metadata_flavor"),
        ] {
            let error = anyhow::Error::new(MustNotDisplay).context(refusal);
            let error = PreparationFailure::at(PreparationStep::CounterTokenInfo, error);
            let error = PreparationFailure::at(PreparationStep::CounterAdmit, error);
            assert!(error.downcast_ref::<MustNotDisplay>().is_some());
            let (mut recorder, ..) = fixture();
            recorder.enrolled(Digest::new(b"Controller")).unwrap();
            recorder.enter(FailurePhase::CounterAdmission);
            recorder.refuse(Some(&error)).unwrap();
            let rows = records(&recorder.output);
            assert_eq!(
                rows[1]["observation"],
                serde_json::json!({
                    "event":"refused","at":"counter_admission",
                    "preparation":{"step":"counter_token_info","category":expected}
                })
            );
            let text = std::str::from_utf8(&recorder.output).unwrap();
            for private in [
                "MustNotDisplay",
                "access_token",
                "https://",
                "Bearer",
                "response body",
            ] {
                assert!(!text.contains(private));
            }
            assert!(recorder.refused && !recorder.activated && recorder.serving == [false; 2]);
        }
        // Matching text is not a typed transport observation.
        let error = anyhow::anyhow!("response_forbidden https://private/?access_token=PRIVATE");
        assert_eq!(
            preparation_error_category(&error),
            PreparationErrorCategory::Other
        );
    }

    #[test]
    fn app_counter_projection_requires_actual_known_cold_context() {
        use crate::security_epoch::transport::ResponseRefusal;
        let maximal = serde_json::to_vec(&CounterAdmissionResponseRefusal::maximal_fixture())
            .unwrap()
            .len();
        for (step, producer) in [
            (PreparationStep::CounterProviderAcquire, "provider"),
            (PreparationStep::CounterMetadataSource, "metadata"),
            (PreparationStep::CounterIamMint, "mint"),
            (PreparationStep::CounterTokenInfo, "token_info"),
            (PreparationStep::CounterMaterial, "material"),
            (PreparationStep::CounterStagePostcheck, "stage"),
            (PreparationStep::CounterOriginalPostcheck, "original"),
        ] {
            let error =
                anyhow::Error::new(MustNotDisplay).context(ResponseRefusal::DeclaredLengthBound);
            let error = PreparationFailure::at(step, error);
            let observed = CounterAdmissionResponseRefusal::observe(&error).unwrap();
            let json = serde_json::to_value(observed).unwrap();
            assert_eq!(
                json,
                serde_json::json!({"producer":producer,"category":"response_declared_length_bound"})
            );
            assert!(serde_json::to_vec(&observed).unwrap().len() <= maximal);
            let unknown = PreparationFailure::at(step, anyhow::Error::new(MustNotDisplay));
            assert!(CounterAdmissionResponseRefusal::observe(&unknown).is_none());
        }
        for step in [
            PreparationStep::Unknown,
            PreparationStep::CounterAdmit,
            PreparationStep::BootstrapTransport,
            PreparationStep::CounterPhysicalAcquire,
        ] {
            let error = anyhow::Error::new(MustNotDisplay).context(ResponseRefusal::Forbidden);
            let error = PreparationFailure::at(step, error);
            assert!(CounterAdmissionResponseRefusal::observe(&error).is_none());
        }
        assert!(
            CounterAdmissionResponseRefusal::observe(&anyhow::anyhow!(
                "counter_token_info response_forbidden https://private/?access_token=PRIVATE"
            ))
            .is_none()
        );
    }

    fn cold_counter_boundaries_follow_activation(source: &str) -> bool {
        fn expression(mut value: &syn::Expr) -> &syn::Expr {
            while let syn::Expr::Block(block) = value {
                let [syn::Stmt::Expr(inner, None)] = block.block.stmts.as_slice() else {
                    break;
                };
                value = inner;
            }
            value
        }
        #[derive(Default)]
        struct Boundaries(Vec<String>);
        impl<'ast> syn::visit::Visit<'ast> for Boundaries {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                syn::visit::visit_expr_method_call(self, call);
                if call.method == "activated" {
                    self.0.push("activated".into());
                } else if call.method == "enter" && call.args.iter().any(|arg| {
                    matches!(arg, syn::Expr::Path(path)
                        if path.path.segments.last().is_some_and(|segment| segment.ident == "CounterAdmission"))
                }) {
                    self.0.push("counter_admission".into());
                } else if call.method == "map_err" {
                    let syn::Expr::MethodCall(boundary) = &*call.receiver else { return; };
                    let Some(syn::Expr::Closure(closure)) = call.args.first() else { return; };
                    let syn::Expr::Call(annotation) = expression(&closure.body) else { return; };
                    let syn::Expr::Path(function) = &*annotation.func else { return; };
                    if function.path.segments.len() != 2
                        || function.path.segments[0].ident != "PreparationFailure"
                        || function.path.segments[1].ident != "at"
                        || annotation.args.len() != 2
                        || !matches!(annotation.args.last(),Some(syn::Expr::Path(path)) if path.path.is_ident("error"))
                    { return; }
                    let Some(syn::Expr::Path(step)) = annotation.args.first() else { return; };
                    if step.path.segments.len() == 2 && step.path.segments[0].ident == "PreparationStep" {
                        let name = step.path.segments[1].ident.to_string();
                        if name.starts_with("Counter") {
                            self.0.push(format!("{}:{name}", boundary.method));
                        }
                    }
                }
            }
        }
        let parsed = syn::parse_file(source).unwrap();
        let function = parsed
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(function) if function.sig.ident == "activate_controller" => {
                    Some(function)
                }
                _ => None,
            })
            .unwrap();
        let mut observed = Boundaries::default();
        syn::visit::Visit::visit_block(&mut observed, &function.block);
        observed.0.iter().map(String::as_str).eq([
            "activated",
            "counter_admission",
            "begin_current_stage:CounterRoleStage",
            "begin_pending_current_controller:CounterPendingFile",
            "acquire:CounterPhysicalAcquire",
            "controller_stage:CounterStage",
            "admit:CounterAdmit",
            "finish_controller_known:CounterPhysicalFinish",
        ])
    }

    #[test]
    fn cold_counter_annotations_cover_actual_calls_without_relabeling_activation() {
        let source = include_str!("../bootstrap.rs");
        assert!(cold_counter_boundaries_follow_activation(source));
        for label in [
            "CounterRoleStage",
            "CounterPendingFile",
            "CounterPhysicalAcquire",
            "CounterStage",
            "CounterAdmit",
            "CounterPhysicalFinish",
        ] {
            assert!(!cold_counter_boundaries_follow_activation(&source.replace(
                &format!("PreparationStep::{label}"),
                "PreparationStep::Unknown"
            )));
        }
        assert!(!cold_counter_boundaries_follow_activation(&source.replace(
            "FailurePhase::CounterAdmission",
            "FailurePhase::Activation"
        )));
        let enter = "evidence.enter(super::controller::evidence::FailurePhase::CounterAdmission);";
        let moved = source.replace(enter, "").replace(
            "let mut counter = super::authenticated_reads::CounterConnectionSlot::new();",
            &format!("{enter}\nlet mut counter = super::authenticated_reads::CounterConnectionSlot::new();"));
        // This is the same pre-admission boundary, after observed activation.
        assert!(cold_counter_boundaries_follow_activation(&moved));
        let late = source.replace(enter, "").replace(
            "Ok((complete, activation, counter))",
            &format!("{enter}\nOk((complete, activation, counter))"),
        );
        assert!(!cold_counter_boundaries_follow_activation(&late));
    }

    #[test]
    fn current_app_serving_diagnostic_fits_fixed_bound_and_never_leaks_to_other_phases() {
        for phase in [
            FailurePhase::AppServing,
            FailurePhase::Preparation,
            FailurePhase::ShellServing,
        ] {
            let (mut recorder, ..) = fixture();
            recorder.enrolled(Digest::new(b"Controller")).unwrap();
            recorder.enter(phase);
            recorder.serving_timing(super::super::serving_timing::ServingTiming::maximal_fixture());
            if matches!(phase, FailurePhase::AppServing) {
                recorder.preparation_timings(
                    super::super::preparation_timing::Timings::maximal_summary_fixture(),
                );
            }
            recorder.refuse(None).unwrap();
            let rows = records(&recorder.output);
            let observation = &rows[1]["observation"];
            if matches!(phase, FailurePhase::AppServing) {
                assert_eq!(observation["serving"]["scope"], "current_app_serving");
                assert_eq!(observation["serving"]["failure"]["step"], "acknowledgement");
                assert_eq!(
                    observation["serving"]["timing"].as_array().unwrap().len(),
                    24
                );
                assert!(observation.get("timing").is_none());
            } else {
                assert!(observation.get("serving").is_none());
            }
            let records = recorder.records;
            recorder.refuse(None).unwrap();
            assert_eq!(recorder.records, records);
            assert!(recorder.refused && !recorder.activated);
        }
        let (mut recorder, ..) = fixture();
        recorder.serving_timing(super::super::serving_timing::ServingTiming::maximal_fixture());
        recorder.enter(FailurePhase::AppServing);
        assert!(
            recorder.serving_timing.is_none(),
            "another attempt cannot inherit timing"
        );
    }

    #[test]
    fn current_trace_replaces_initial_history_and_export_failure_keeps_first_native_cause() {
        let (mut recorder, _, _, create, _, _) = fixture();
        recorder.preparation_timings(
            super::super::preparation_timing::Timings::maximal_summary_fixture(),
        );
        recorder.enter_bootstrap(&create, Action::Reserve);
        assert!(recorder.preparation_timing.is_none() && recorder.bootstrap_timing.is_none());
        recorder.bootstrap_timing(Some(
            super::super::bootstrap_timing::BootstrapTiming::maximal_fixture(),
        ));
        let error = PreparationFailure::at(
            PreparationStep::DiskBinding,
            anyhow::Error::new(FailedRequestWindow::maximal_fixture(true))
                .context("epoch_native_transport_unavailable")
                .context(MustNotDisplay),
        );
        // The native result is retained even when a separate evidence export
        // fails. No telemetry failure can turn it into success or replace it.
        let result = crate::security_epoch::controller::preserve_native_failure(
            Err(error),
            Err(anyhow::anyhow!("native_evidence_export_failed")),
        );
        let error = result.unwrap_err();
        assert_eq!(
            FailedRequestWindow::observe(&error),
            Some(FailedRequestWindow::maximal_fixture(true))
        );
        assert_eq!(
            PreparationFailure::observe(&error).step,
            PreparationStep::DiskBinding
        );
        recorder.refuse(Some(&error)).unwrap();
        let rows = records(&recorder.output);
        assert!(rows[0]["observation"].get("timing").is_none());
        assert_eq!(
            rows[0]["observation"]["bootstrap"]["scope"],
            "storage_bootstrap"
        );
        assert!(recorder.refused && !recorder.activated);
        assert!(
            !String::from_utf8(recorder.output)
                .unwrap()
                .contains("MustNotDisplay")
        );
    }

    #[test]
    fn one_or_two_provider_rounds_cannot_emit_three_round_control_completion() {
        use super::super::{bootstrap_timing::BootstrapTiming, preparation_timing::Operation};
        for rounds in [1, 2, 4] {
            // Export DATA only; no native owner/observation/permission is built.
            let (mut recorder, ..) = fixture();
            recorder.enrolled(Digest::new(b"Controller")).unwrap();
            let trace = BootstrapTiming::provider_read_only();
            trace
                .measure(Operation::VolumeAcquisition, || {
                    for _ in 0..rounds {
                        trace.provider_round(|| Ok(()))?;
                    }
                    Ok(())
                })
                .unwrap();
            assert!(
                recorder
                    .preparation_read_only(trace.snapshot().unwrap())
                    .is_err()
            );
            assert_eq!(records(&recorder.output).len(), 1);
            assert!(!recorder.read_only_observed && !recorder.first_holder && !recorder.activated);
        }
    }
}
