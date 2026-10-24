//! Bounded historical observations from the real Controller executor. Nothing
//! accepts these records as a native owner, permission, readiness or replay.
use super::bootstrap_timing::Snapshot as BootstrapSnapshot;
use super::preparation_timing::Summary;
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
const SELF_CHECK_PREFIX: &str = "day2-native-controller-self-check ";
const MAX_SELF_CHECK_BYTES: usize = 1024;

pub(in crate::security_epoch) type Evidence = Recorder<StderrOutput>;

pub(in crate::security_epoch) struct StderrOutput {
    stream: Stderr,
}

pub(in crate::security_epoch) trait RecordOutput {
    fn append(&mut self, record: &[u8]) -> std::io::Result<()>;
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
    self_check_exported: u8,
    at: FailurePhase,
    refused: bool,
    export_failed: bool,
    preparation_timing: Option<Summary>,
    bootstrap_timing: Option<BootstrapSnapshot>,
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
    ServingListener,
    AppPending,
    AppServing,
    ShellPending,
    ShellAccept,
    ShellServing,
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
enum PreparationErrorCategory {
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

fn preparation_error_category(error: &anyhow::Error) -> PreparationErrorCategory {
    use PreparationErrorCategory as Category;
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
            | "native_enrollment_stage_expired",
        ) => return Category::ClockExpiredOrRewound,
        Some("epoch_native_acquisition_refused" | "native_enrollment_owner_refused") => {
            return Category::AcquisitionRefused;
        }
        Some(
            "epoch_native_transport_unavailable"
            | "epoch_native_response_unavailable"
            | "epoch_native_metadata_unavailable",
        ) => return Category::TransportUnavailable,
        Some("epoch_native_response_status_or_bound" | "epoch_native_metadata_status_or_bound") => {
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
    },
    Refused {
        at: FailurePhase,
        #[serde(skip_serializing_if = "Option::is_none")]
        preparation: Option<PreparationFailure>,
        #[serde(skip_serializing_if = "Option::is_none")]
        timing: Option<Summary>,
        #[serde(skip_serializing_if = "Option::is_none")]
        bootstrap: Option<BootstrapSnapshot>,
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
            self_check_exported: 0,
            at: FailurePhase::Selection,
            refused: false,
            export_failed: false,
            preparation_timing: None,
            bootstrap_timing: None,
            read_only_observed: false,
        }
    }

    pub(in crate::security_epoch) fn enter(&mut self, at: FailurePhase) {
        self.at = at;
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
        if !self.serving[index] {
            self.emit(Observation::FirstServingRelease {
                role,
                binding: observed.binding,
                snapshot: observed.snapshot,
            })?;
            self.serving[index] = true;
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
                timing: if current || provider_control {
                    None
                } else {
                    self.preparation_timing.clone()
                },
                bootstrap: if current || provider_control {
                    self.bootstrap_timing.clone()
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
        // At most one numeric profile for each of the six fixed actions.
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
        ensure!(
            SELF_CHECK_PREFIX.len() + json.len() < MAX_SELF_CHECK_BYTES,
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
        self.self_check_exported |= bit;
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
            .filter(|line| !line.starts_with(SELF_CHECK_PREFIX))
            .map(|line| {
                assert!(line.len() < MAX_RECORD_BYTES);
                serde_json::from_str(line.strip_prefix(PREFIX).unwrap()).unwrap()
            })
            .collect()
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
                recorder
                    .serving(
                        role,
                        ServingObservation {
                            binding: Digest::new(b"actual request binding"),
                            snapshot: snapshot_digest.clone(),
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
        assert!(recorder.output.len() <= usize::from(MAX_RECORDS) * MAX_RECORD_BYTES);
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
                "epoch_native_acquisition_refused",
                Category::AcquisitionRefused,
            ),
            (
                "epoch_native_transport_unavailable",
                Category::TransportUnavailable,
            ),
            (
                "epoch_native_response_status_or_bound",
                Category::ResponseStatusOrBound,
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
