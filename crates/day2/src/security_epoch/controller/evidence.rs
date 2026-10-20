//! Bounded historical observations from the real Controller executor. Nothing
//! accepts these records as a native owner, permission, readiness or replay.
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
}

#[derive(Clone, Copy, Serialize)]
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
            self.incarnation.is_some() && !self.first_holder,
            "native_evidence_first_holder_order"
        );
        self.emit(Observation::FirstHolderDurabilityCompleted {
            seed: seed.digest()?,
            holder: Digest::of(&("day2-controller-first-holder-evidence-v1", holder))?,
        })?;
        self.first_holder = true;
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

    pub(super) fn refuse(&mut self) -> Result<()> {
        if !self.refused {
            self.emit(Observation::Refused { at: self.at })?;
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
        recorder.refuse().unwrap();
        recorder.refuse().unwrap();
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
        recorder.refuse().unwrap();
        assert!(
            recorder
                .bootstrap(&create, Action::Dispatch, &snapshot)
                .is_err()
        );
        assert_eq!(records(&recorder.output).len(), 4);
    }

    #[test]
    fn refusal_before_selection_is_fixed_metadata_without_positive_milestones() {
        let mut recorder = Recorder::with_writer(Vec::new());
        recorder.refuse().unwrap();
        recorder.refuse().unwrap();
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
        assert!(recorder.refuse().is_err());
        assert_eq!(recorder.records, 0);
        assert_eq!(recorder.output.bytes.len(), 10);
        assert!(recorder.refuse().is_err());
        assert_eq!(recorder.output.bytes.len(), 10);
        assert!(!recorder.output.bytes.contains(&b'\n'));
    }
}
