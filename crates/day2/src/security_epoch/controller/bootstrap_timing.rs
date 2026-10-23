//! Diagnostic DATA for ONE purpose-bound bootstrap or metadata attempt. It cannot supply
//! a clock, role, file, peer, writer, retry or authority. Measurements spend the
//! original purpose deadline; nested rows are inclusive, never additive.
use super::preparation_timing::{CompactSummary, Operation, Timings};
use anyhow::Result;
use serde::Serialize;
use std::{cell::Cell, rc::Rc, time::Duration};

#[derive(Clone)]
pub(in crate::security_epoch) struct BootstrapTiming {
    timings: Timings,
    state: Option<Rc<Cell<State>>>,
    scope: DiagnosticScope,
    started: Option<Duration>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DiagnosticScope {
    StorageBootstrap,
    ProviderReadOnlyStorageMetadata,
}

#[derive(Clone, Copy)]
struct State {
    at: Operation,
    returned: Option<bool>,
    rounds: [Option<u8>; 2],
}

#[derive(Clone, Serialize)]
pub(in crate::security_epoch) struct Snapshot {
    scope: DiagnosticScope,
    // Nominal closed-purpose ceiling, not a sampled effective clock/permission.
    purpose_limit_us: Option<u32>,
    // This is the LAST MEASURED callback, not the failed statement or overall
    // phase outcome. PreparationFailure remains the native error boundary.
    #[serde(rename = "last_step")]
    at: Operation,
    returned: Option<bool>,
    /// [attempted, fully validated]. None is overflow/inconclusive, not zero.
    provider_rounds: [Option<u8>; 2],
    /// Complete caller action, including role acquisition and acknowledgement.
    /// Missing/rewound/overflowed diagnostic clock is inconclusive, not zero.
    elapsed_us: Option<u32>,
    timing_format: &'static str,
    timing: CompactSummary,
}

fn purpose_limit_us(scope: DiagnosticScope) -> Option<u32> {
    let limit = match scope {
        DiagnosticScope::StorageBootstrap => {
            crate::security_epoch::native_clock::STORAGE_BOOTSTRAP_LIMIT
        }
        DiagnosticScope::ProviderReadOnlyStorageMetadata => {
            crate::security_epoch::native_clock::STORAGE_METADATA_OBSERVATION_LIMIT
        }
    };
    limit.as_micros().try_into().ok()
}

impl BootstrapTiming {
    pub(in crate::security_epoch) fn new() -> Self {
        Self {
            timings: Timings::bootstrap(),
            state: Some(Rc::new(Cell::new(State {
                at: Operation::RoleStage,
                returned: None,
                rounds: [Some(0), Some(0)],
            }))),
            scope: DiagnosticScope::StorageBootstrap,
            started: crate::security_epoch::native_clock::boottime().ok(),
        }
    }

    pub(in crate::security_epoch) fn provider_read_only() -> Self {
        Self {
            scope: DiagnosticScope::ProviderReadOnlyStorageMetadata,
            ..Self::new()
        }
    }

    pub(in crate::security_epoch) fn disabled() -> Self {
        Self {
            timings: Timings::disabled(),
            state: None,
            scope: DiagnosticScope::StorageBootstrap,
            started: None,
        }
    }

    pub(in crate::security_epoch) fn timings(&self) -> Timings {
        self.timings.clone()
    }

    pub(in crate::security_epoch) fn measure<T>(
        &self,
        at: Operation,
        call: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        if let Some(state) = &self.state {
            state.set(State {
                at,
                returned: None,
                ..state.get()
            });
        }
        // Preserve the actual first native result, including its error chain.
        // Missing/reversed metric clocks only make timing DATA inconclusive.
        let result = self.timings.measure(at, call);
        if let Some(state) = &self.state {
            state.set(State {
                returned: Some(result.is_ok()),
                ..state.get()
            });
        }
        result
    }

    pub(in crate::security_epoch) fn provider_round<T>(
        &self,
        call: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let operation = if let Some(state) = &self.state {
            let mut value = state.get();
            value.rounds[0] = value.rounds[0].and_then(|n| n.checked_add(1));
            state.set(value);
            match value.rounds[0] {
                Some(1) => Operation::ProviderRoundOne,
                Some(2) => Operation::ProviderRoundTwo,
                Some(3) => Operation::ProviderRoundThree,
                _ => Operation::ProviderRoundOther,
            }
        } else {
            return call();
        };
        // Nested timing must not replace the enclosing phase's last_step or
        // result. The unchanged actual round runs exactly once, even on error.
        let result = self.timings.measure(operation, call);
        if result.is_ok()
            && let Some(state) = &self.state
        {
            let mut value = state.get();
            value.rounds[1] = value.rounds[1].and_then(|n| n.checked_add(1));
            state.set(value);
        }
        result
    }

    /// Called only after the actual stage/file/port operation has returned and
    /// its permission borrows have unwound. A snapshot cannot reconstruct them.
    pub(in crate::security_epoch) fn snapshot(&self) -> Option<Snapshot> {
        self.state.as_ref()?;
        self.snapshot_at(crate::security_epoch::native_clock::boottime().ok())
    }

    fn snapshot_at(&self, finished: Option<Duration>) -> Option<Snapshot> {
        self.state.as_ref().map(|state| {
            let value = state.get();
            Snapshot {
                scope: self.scope,
                purpose_limit_us: purpose_limit_us(self.scope),
                at: value.at,
                returned: value.returned,
                provider_rounds: value.rounds,
                elapsed_us: self
                    .started
                    .zip(finished)
                    .and_then(|(start, end)| end.checked_sub(start))
                    .and_then(|elapsed| elapsed.as_micros().try_into().ok()),
                timing_format: "operation_count_total_us_v1",
                timing: self.timings.summary().compact(),
            }
        })
    }

    #[cfg(test)]
    pub(super) fn maximal_fixture() -> Snapshot {
        Snapshot {
            scope: DiagnosticScope::StorageBootstrap,
            purpose_limit_us: purpose_limit_us(DiagnosticScope::StorageBootstrap),
            at: Operation::BootstrapAuthentication,
            returned: Some(false),
            provider_rounds: [Some(u8::MAX), Some(u8::MAX)],
            elapsed_us: Some(u32::MAX),
            timing_format: "operation_count_total_us_v1",
            timing: Timings::maximal_bootstrap_fixture().compact(),
        }
    }

    #[cfg(test)]
    pub(super) fn maximal_completed_fixture() -> Snapshot {
        Snapshot {
            at: Operation::BootstrapRelease,
            returned: Some(true),
            ..Self::maximal_fixture()
        }
    }

    #[cfg(test)]
    pub(super) fn maximal_provider_fixture() -> Snapshot {
        Snapshot {
            scope: DiagnosticScope::ProviderReadOnlyStorageMetadata,
            purpose_limit_us: purpose_limit_us(DiagnosticScope::ProviderReadOnlyStorageMetadata),
            at: Operation::VolumeAcquisition,
            returned: Some(true),
            provider_rounds: [Some(3), Some(3)],
            elapsed_us: Some(u32::MAX),
            timing_format: "operation_count_total_us_v1",
            timing: Timings::maximal_bootstrap_fixture().compact(),
        }
    }
}

impl Snapshot {
    pub(in crate::security_epoch) fn completed_bootstrap_action(&self) -> bool {
        self.scope == DiagnosticScope::StorageBootstrap
            && matches!(self.at, Operation::BootstrapRelease)
            && self.returned == Some(true)
    }

    pub(in crate::security_epoch) fn is_provider_read_only(&self) -> bool {
        self.scope == DiagnosticScope::ProviderReadOnlyStorageMetadata
    }

    pub(in crate::security_epoch) fn completed_provider_control(&self) -> bool {
        self.is_provider_read_only()
            && matches!(self.at, Operation::VolumeAcquisition)
            && self.returned == Some(true)
            && self.provider_rounds == [Some(3), Some(3)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_report_their_own_limit_and_complete_elapsed_time_never_becomes_permission() {
        let mut trace = BootstrapTiming::new();
        trace.started = Some(Duration::from_secs(100));
        trace
            .measure(Operation::BootstrapRelease, || Ok(()))
            .unwrap();
        let snapshot = trace
            .snapshot_at(Some(Duration::from_millis(123_999)))
            .unwrap();
        assert!(snapshot.completed_bootstrap_action());
        let json = serde_json::to_value(snapshot).unwrap();
        assert_eq!(json["elapsed_us"], 23_999_000);
        assert_eq!(json["purpose_limit_us"], 60_000_000);
        assert_eq!(json["timing_format"], "operation_count_total_us_v1");
        for end in [None, Some(Duration::from_secs(99)), Some(Duration::MAX)] {
            assert!(serde_json::to_value(trace.snapshot_at(end)).unwrap()["elapsed_us"].is_null());
        }
        let metadata = BootstrapTiming::provider_read_only();
        let json = serde_json::to_value(metadata.snapshot()).unwrap();
        assert_eq!(json["purpose_limit_us"], 10_000_000);
        assert!(!metadata.snapshot().unwrap().completed_bootstrap_action());
    }

    #[test]
    fn each_provider_round_is_recorded_once_without_replacing_the_enclosing_failure() {
        let trace = BootstrapTiming::new();
        let calls = Cell::new(0);
        let result = trace.measure(Operation::BootstrapDurability, || {
            for round in 1..=3 {
                trace.provider_round(|| {
                    calls.set(calls.get() + 1);
                    if round == 3 {
                        anyhow::bail!("original round-three cause");
                    }
                    Ok(())
                })?;
            }
            Ok(())
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "original round-three cause"
        );
        assert_eq!(calls.get(), 3);
        let json = serde_json::to_value(trace.snapshot()).unwrap();
        assert_eq!(json["provider_rounds"], serde_json::json!([3, 2]));
        assert_eq!(json["last_step"], "bootstrap_durability");
        assert_eq!(json["returned"], false);
        for code in [42, 43, 44] {
            let row = json["timing"]
                .as_array()
                .unwrap()
                .iter()
                .find(|x| x[0] == code)
                .unwrap();
            assert_eq!(row[1], 1);
        }
    }

    #[test]
    fn failed_round_two_or_three_is_attempted_but_never_completed() {
        for failed in [2, 3] {
            let trace = BootstrapTiming::new();
            for _ in 1..failed {
                trace.provider_round(|| Ok(())).unwrap();
            }
            let result = trace.measure(Operation::BootstrapDurability, || {
                trace.provider_round(|| Err::<(), _>(anyhow::anyhow!("original native cause")))
            });
            assert_eq!(result.unwrap_err().to_string(), "original native cause");
            let json = serde_json::to_value(trace.snapshot().unwrap()).unwrap();
            assert_eq!(
                json["provider_rounds"],
                serde_json::json!([failed, failed - 1])
            );
            assert_eq!(json["returned"], false);
            assert_eq!(json["scope"], "storage_bootstrap");
        }
    }

    #[test]
    fn unreturned_attempt_and_overflow_are_never_success_or_zero() {
        let trace = BootstrapTiming::new();
        assert_eq!(
            serde_json::to_value(trace.snapshot()).unwrap()["returned"],
            serde_json::Value::Null
        );
        for _ in 0..=u8::MAX {
            trace.provider_round(|| Ok(())).unwrap();
        }
        assert_eq!(
            serde_json::to_value(trace.snapshot()).unwrap()["provider_rounds"],
            serde_json::json!([null, null])
        );
        assert!(BootstrapTiming::disabled().snapshot().is_none());
    }

    #[test]
    fn provider_control_requires_exactly_three_fully_validated_rounds() {
        for rounds in [1, 2, 3, 4] {
            let trace = BootstrapTiming::provider_read_only();
            trace
                .measure(Operation::VolumeAcquisition, || {
                    for _ in 0..rounds {
                        trace.provider_round(|| Ok(()))?;
                    }
                    Ok(())
                })
                .unwrap();
            let snapshot = trace.snapshot().unwrap();
            assert_eq!(snapshot.completed_provider_control(), rounds == 3);
            assert_eq!(
                serde_json::to_value(snapshot).unwrap()["scope"],
                "provider_read_only_storage_metadata"
            );
        }
        assert!(!BootstrapTiming::maximal_fixture().is_provider_read_only());
    }
}
