//! Historical DATA for one actual Current App-serving call. No permission,
//! enforcement clock, deadline, retry or readiness is produced. Nested rows are
//! inclusive and must not be summed. Export happens only after native unwind.
use super::evidence::{PreparationErrorCategory, preparation_error_category};
use crate::security_epoch::{
    native_clock::{self, AcquisitionProgress, EnrolledRequestDiagnosticData},
    native_enrollment::PeerRequestDiagnosticData,
    transport::FailedRequestWindow,
};
use anyhow::Result;
use serde::Serialize;
use std::{cell::RefCell, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub(in crate::security_epoch) enum ServingStep {
    RoleStage,
    PhysicalBegin,
    PhysicalPending,
    PeerPrepare,
    PhysicalAcquire,
    Durability,
    PeerAccept,
    PhysicalCheck,
    RequestBinding,
    ProviderAcquire,
    Names,
    CounterBefore,
    ValidateBefore,
    PhysicalBefore,
    ProviderBefore,
    Announcement,
    Acknowledgement,
    CounterAfter,
    ValidateAfter,
    ProviderAfter,
    PhysicalAfter,
    Snapshot,
    Release,
    Operation,
}

const STEPS: [ServingStep; 24] = [
    ServingStep::RoleStage,
    ServingStep::PhysicalBegin,
    ServingStep::PhysicalPending,
    ServingStep::PeerPrepare,
    ServingStep::PhysicalAcquire,
    ServingStep::Durability,
    ServingStep::PeerAccept,
    ServingStep::PhysicalCheck,
    ServingStep::RequestBinding,
    ServingStep::ProviderAcquire,
    ServingStep::Names,
    ServingStep::CounterBefore,
    ServingStep::ValidateBefore,
    ServingStep::PhysicalBefore,
    ServingStep::ProviderBefore,
    ServingStep::Announcement,
    ServingStep::Acknowledgement,
    ServingStep::CounterAfter,
    ServingStep::ValidateAfter,
    ServingStep::ProviderAfter,
    ServingStep::PhysicalAfter,
    ServingStep::Snapshot,
    ServingStep::Release,
    ServingStep::Operation,
];

#[derive(Clone, Copy)]
struct Measurement(Option<u32>, Option<u32>);

#[derive(Clone, Copy, Debug, Serialize)]
struct ServingFailure {
    step: ServingStep,
    category: PreparationErrorCategory,
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<FailedRequestWindow>,
}

impl std::fmt::Display for ServingFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native current App-serving boundary refused")
    }
}

impl ServingFailure {
    fn at(step: ServingStep, error: anyhow::Error) -> anyhow::Error {
        if error.downcast_ref::<Self>().is_some() {
            return error;
        }
        let failure = Self {
            step,
            category: preparation_error_category(&error),
            request: FailedRequestWindow::observe(&error),
        };
        error.context(failure)
    }
}

#[derive(Clone, Serialize)]
pub(in crate::security_epoch) struct Snapshot {
    scope: &'static str,
    /// Diagnostic caller time includes role acquisition. Missing, rewind or
    /// overflow is inconclusive. This is not the original's enforcement clock.
    caller_elapsed_us: Option<u32>,
    /// Last SUCCESSFUL sample of the actual SAME original, possibly from a
    /// narrowed sibling. Not the failure instant, current validity or remaining
    /// time. Missing when role acquisition did not return its actual stage.
    original_last_checked_us: Option<u32>,
    /// Commitments copied from the actual enrolled original. Absent when the
    /// role/binding was unavailable; elapsed time cannot substitute for it.
    /// Serialized once by the Current identity record, not duplicated into
    /// the separately bounded first-release timing detail.
    #[serde(skip_serializing)]
    request: Option<EnrolledRequestDiagnosticData>,
    #[serde(skip_serializing)]
    peer: Option<PeerRequestDiagnosticData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<ServingFailure>,
    timing_format: &'static str,
    timing: Vec<(u8, Option<u32>, Option<u32>)>,
}

pub(in crate::security_epoch) struct ServingTiming {
    started: Option<Duration>,
    original: RefCell<Option<AcquisitionProgress>>,
    peer: RefCell<Option<PeerRequestDiagnosticData>>,
    timings: RefCell<[Measurement; STEPS.len()]>,
}

impl ServingTiming {
    pub(in crate::security_epoch) fn new() -> Self {
        Self {
            started: native_clock::boottime().ok(),
            original: RefCell::new(None),
            peer: RefCell::new(None),
            timings: RefCell::new([Measurement(Some(0), Some(0)); STEPS.len()]),
        }
    }

    pub(in crate::security_epoch) fn bind_progress(&self, progress: AcquisitionProgress) {
        *self.original.borrow_mut() = Some(progress);
    }

    pub(in crate::security_epoch) fn bind_peer_data(&self, peer: PeerRequestDiagnosticData) {
        *self.peer.borrow_mut() = Some(peer);
    }

    pub(in crate::security_epoch) fn measure<T>(
        &self,
        step: ServingStep,
        call: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.measure_with(step, call, || native_clock::boottime().ok())
    }

    fn measure_with<T>(
        &self,
        step: ServingStep,
        call: impl FnOnce() -> Result<T>,
        mut clock: impl FnMut() -> Option<Duration>,
    ) -> Result<T> {
        let before = clock();
        let result = call();
        let elapsed = before
            .zip(clock())
            .and_then(|(a, b)| b.checked_sub(a))
            .and_then(|duration| u32::try_from(duration.as_micros()).ok());
        let mut timings = self.timings.borrow_mut();
        let measured = &mut timings[step as usize];
        measured.0 = measured.0.and_then(|count| count.checked_add(1));
        measured.1 = measured
            .1
            .zip(elapsed)
            .and_then(|(total, elapsed)| total.checked_add(elapsed));
        result.map_err(|error| ServingFailure::at(step, error))
    }

    pub(in crate::security_epoch) fn snapshot(&self, error: Option<&anyhow::Error>) -> Snapshot {
        self.snapshot_at(error, native_clock::boottime().ok())
    }

    fn snapshot_at(&self, error: Option<&anyhow::Error>, finished: Option<Duration>) -> Snapshot {
        let timings = self.timings.borrow();
        Snapshot {
            scope: "current_app_serving",
            caller_elapsed_us: self
                .started
                .zip(finished)
                .and_then(|(a, b)| b.checked_sub(a))
                .and_then(|duration| u32::try_from(duration.as_micros()).ok()),
            original_last_checked_us: self
                .original
                .borrow()
                .as_ref()
                .and_then(AcquisitionProgress::last_checked_elapsed_micros),
            request: self
                .original
                .borrow()
                .as_ref()
                .and_then(|progress| progress.historical_request_binding_data().ok()),
            peer: self.peer.borrow().clone(),
            failure: error
                .and_then(|error| error.downcast_ref::<ServingFailure>())
                .copied(),
            timing_format: "operation_count_total_us_v1",
            timing: STEPS
                .iter()
                .map(|step| (*step as u8, timings[*step as usize]))
                .filter(|(_, measured)| measured.0 != Some(0))
                .map(|(step, measured)| (step, measured.0, measured.1))
                .collect(),
        }
    }

    #[cfg(test)]
    pub(super) fn maximal_fixture() -> Snapshot {
        Snapshot {
            scope: "current_app_serving",
            caller_elapsed_us: Some(u32::MAX),
            original_last_checked_us: Some(u32::MAX),
            request: Some(EnrolledRequestDiagnosticData::maximal_fixture()),
            peer: Some(PeerRequestDiagnosticData::maximal_fixture()),
            failure: Some(ServingFailure {
                step: ServingStep::Acknowledgement,
                category: PreparationErrorCategory::ClockExpiredOrRewound,
                request: Some(FailedRequestWindow::maximal_fixture(true)),
            }),
            timing_format: "operation_count_total_us_v1",
            timing: STEPS
                .into_iter()
                .map(|step| (step as u8, Some(u32::MAX), Some(u32::MAX)))
                .collect(),
        }
    }
}

impl Snapshot {
    pub(super) fn request_data(&self) -> Option<&EnrolledRequestDiagnosticData> {
        self.request.as_ref()
    }

    pub(super) fn peer_data(&self) -> Option<&PeerRequestDiagnosticData> {
        self.peer.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::cell::Cell;

    #[derive(Debug)]
    struct MustNotDisplay;
    impl std::fmt::Display for MustNotDisplay {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("private context was formatted")
        }
    }
    impl std::error::Error for MustNotDisplay {}

    fn trace() -> ServingTiming {
        ServingTiming {
            started: Some(Duration::from_secs(100)),
            original: RefCell::new(None),
            peer: RefCell::new(None),
            timings: RefCell::new([Measurement(Some(0), Some(0)); STEPS.len()]),
        }
    }

    #[test]
    fn serving_snapshot_copies_actual_original_data_without_checking_or_reviving_it() {
        use crate::security_epoch::{
            native_clock::NativeAcquisition,
            native_enrollment::{NativeRole, StagePurpose},
        };
        use day2_capabilities::Digest;

        // Clock/identity DATA only: no native role, peer or permission is made.
        let mut original = NativeAcquisition::fixture(
            Digest::new(b"actual fixture original domain"),
            std::process::id(),
            Duration::from_secs(100),
            Duration::from_secs(5),
        );
        let progress = original.diagnostic_progress().with_enrollment_data(
            Digest::new(b"actual fixture enrollment"),
            Some(Digest::new(b"actual fixture producer")),
            Some(3),
            Some(7),
            NativeRole::EpochController,
            StagePurpose::CurrentRole,
        );
        let expected =
            serde_json::to_value(progress.historical_request_binding_data().unwrap()).unwrap();
        let trace = trace();
        trace.bind_progress(progress);
        original.refuse();
        for finished in [None, Some(Duration::from_secs(110))] {
            let snapshot = trace.snapshot_at(None, finished);
            assert_eq!(
                serde_json::to_value(snapshot.request_data()).unwrap(),
                expected
            );
            let value = serde_json::to_value(snapshot).unwrap();
            assert!(value.get("request").is_none());
            assert_eq!(value["original_last_checked_us"], 0);
            assert!(original.remaining().is_err());
        }
    }

    #[test]
    fn unannotated_original_is_missing_evidence_even_with_an_elapsed_sample() {
        use crate::security_epoch::native_clock::NativeAcquisition;
        use day2_capabilities::Digest;

        let original = NativeAcquisition::fixture(
            Digest::new(b"unannotated fixture original"),
            std::process::id(),
            Duration::from_secs(100),
            Duration::from_secs(5),
        );
        let trace = trace();
        trace.bind_progress(original.diagnostic_progress());
        let snapshot = trace.snapshot_at(None, Some(Duration::from_secs(101)));
        assert!(snapshot.request_data().is_none());
        let value = serde_json::to_value(snapshot).unwrap();
        assert_eq!(value["original_last_checked_us"], 0);
        assert!(value.get("request").is_none());
    }

    #[test]
    fn serving_trace_preserves_inner_boundary_original_error_and_once_only_callbacks() {
        let trace = trace();
        let calls = Cell::new(0);
        let mut outer = [
            Some(Duration::from_secs(101)),
            Some(Duration::from_secs(104)),
        ]
        .into_iter();
        let error = trace
            .measure_with(
                ServingStep::PhysicalBegin,
                || {
                    let mut inner = [
                        Some(Duration::from_secs(102)),
                        Some(Duration::from_secs(103)),
                    ]
                    .into_iter();
                    trace.measure_with(
                        ServingStep::PeerPrepare,
                        || -> Result<()> {
                            calls.set(calls.get() + 1);
                            Err(anyhow::anyhow!("native_enrollment_stage_expired")
                                .context(MustNotDisplay))
                        },
                        || inner.next().flatten(),
                    )
                },
                || outer.next().flatten(),
            )
            .unwrap_err();
        assert_eq!(calls.get(), 1);
        assert_eq!(
            error.downcast_ref::<&str>(),
            Some(&"native_enrollment_stage_expired")
        );
        assert!(error.downcast_ref::<MustNotDisplay>().is_some());
        let value =
            serde_json::to_value(trace.snapshot_at(Some(&error), Some(Duration::from_secs(106))))
                .unwrap();
        assert_eq!(value["failure"]["step"], "peer_prepare");
        assert_eq!(value["failure"]["category"], "clock_expired_or_rewound");
        assert_eq!(value["caller_elapsed_us"], 6_000_000);
        assert_eq!(value["original_last_checked_us"], Value::Null);
        assert!(value.get("request").is_none());
        assert_eq!(
            value["timing"],
            serde_json::json!([[1, 1, 3_000_000], [3, 1, 1_000_000]])
        );
        let bytes = value.to_string();
        assert!(
            !bytes.contains("MustNotDisplay") && !bytes.contains("native_enrollment_stage_expired")
        );
    }

    #[test]
    fn inconclusive_clocks_cannot_change_native_result_or_invent_original_elapsed() {
        for clocks in [
            [None, None],
            [
                Some(Duration::from_secs(103)),
                Some(Duration::from_secs(102)),
            ],
        ] {
            let trace = trace();
            let mut clocks = clocks.into_iter();
            let calls = Cell::new(0);
            let value = trace
                .measure_with(
                    ServingStep::RoleStage,
                    || -> Result<u32> {
                        calls.set(calls.get() + 1);
                        Ok(7)
                    },
                    || clocks.next().flatten(),
                )
                .unwrap();
            assert_eq!(value, 7);
            assert_eq!(calls.get(), 1);
            let snapshot = serde_json::to_value(trace.snapshot_at(None, None)).unwrap();
            assert_eq!(snapshot["caller_elapsed_us"], Value::Null);
            assert_eq!(snapshot["original_last_checked_us"], Value::Null);
            assert_eq!(snapshot["timing"], serde_json::json!([[0, 1, null]]));
            assert!(snapshot.get("failure").is_none());
        }
    }

    #[test]
    fn unknown_failure_stays_private_and_role_acquisition_refusal_has_no_stage_sample() {
        let trace = trace();
        let private = "/SECRET/provider/body Bearer TOKEN nonce=private";
        let error = trace
            .measure(ServingStep::RoleStage, || -> Result<()> {
                Err(anyhow::Error::msg(private).context(MustNotDisplay))
            })
            .unwrap_err();
        let snapshot = serde_json::to_value(trace.snapshot(Some(&error))).unwrap();
        assert_eq!(snapshot["failure"]["step"], "role_stage");
        assert_eq!(snapshot["failure"]["category"], "other");
        assert_eq!(snapshot["original_last_checked_us"], Value::Null);
        for value in ["SECRET", "Bearer", "TOKEN", "nonce", "MustNotDisplay"] {
            assert!(!snapshot.to_string().contains(value));
        }
    }
}
