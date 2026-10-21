//! Bounded historical observations from the real Controller executor. Nothing
//! accepts these records as a native owner, permission, readiness or replay.
use super::preparation_timing::Summary;
use crate::security_epoch::{
    bootstrap::{Action, ServingObservation},
    kernel::{Holder, Request, Snapshot},
    seed_core::OriginalSeedCore,
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
    at: FailurePhase,
    refused: bool,
    export_failed: bool,
    preparation_timing: Option<Summary>,
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
    RemoteStageExpired,
    ProcessExited,
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
        Some("storage_peer_remote_stage_expired") => return Category::RemoteStageExpired,
        Some("native_enrollment_process_exited") => return Category::ProcessExited,
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
    let kind = error
        .downcast_ref::<std::io::Error>()
        .map(std::io::Error::kind)
        .or_else(|| {
            error
                .downcast_ref::<rustix::io::Errno>()
                .map(|errno| std::io::Error::from_raw_os_error(errno.raw_os_error()).kind())
        });
    match kind {
        Some(std::io::ErrorKind::PermissionDenied) => Category::PermissionDenied,
        Some(std::io::ErrorKind::NotFound) => Category::NotFound,
        Some(std::io::ErrorKind::AlreadyExists) => Category::AlreadyExists,
        Some(std::io::ErrorKind::TimedOut) => Category::TimedOut,
        Some(std::io::ErrorKind::Unsupported) => Category::Unsupported,
        Some(_)
            if error.downcast_ref::<rustix::io::Errno>().is_some_and(|e| {
                *e == rustix::io::Errno::LOOP || *e == rustix::io::Errno::XDEV
            }) =>
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
        completed: bool,
        timing: Summary,
    },
    BootstrapCompleted {
        step: Step,
        operation: Digest,
        request: Digest,
        snapshot: Digest,
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
            at: FailurePhase::Selection,
            refused: false,
            export_failed: false,
            preparation_timing: None,
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

    pub(super) fn preparation_read_only(&mut self, timing: Summary, completed: bool) -> Result<()> {
        ensure!(
            self.incarnation.is_some()
                && !self.first_holder
                && !self.read_only_observed
                && self.next == 0,
            "native_evidence_read_only_order"
        );
        self.emit(Observation::PreparationReadOnlyObserved { completed, timing })?;
        self.read_only_observed = true;
        Ok(())
    }

    pub(in crate::security_epoch) fn enter_bootstrap(&mut self, request: &Request, action: Action) {
        let (_, at) = step(request, action);
        self.enter(at);
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
        self.emit(Observation::BootstrapCompleted {
            step,
            operation: request.operation().clone(),
            request: request.digest()?,
            snapshot: crate::security_epoch::journal::snapshot_digest(snapshot)?,
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
            let preparation = if matches!(
                self.at,
                FailurePhase::Preparation
                    | FailurePhase::HolderListener
                    | FailurePhase::FirstHolder
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
                timing: self.preparation_timing.clone(),
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
            .map(|line| {
                assert!(line.len() < MAX_RECORD_BYTES);
                serde_json::from_str(line.strip_prefix(PREFIX).unwrap()).unwrap()
            })
            .collect()
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
                super::super::preparation_timing::Timings::maximal_summary_fixture(),
                true,
            )
            .unwrap();
        assert!(recorder.first_holder(&seed, &holder).is_err());
        assert!(
            recorder
                .preparation_read_only(
                    super::super::preparation_timing::Timings::new().summary(),
                    true
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
}
