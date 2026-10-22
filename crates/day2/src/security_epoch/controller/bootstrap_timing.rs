//! Diagnostic DATA for ONE actual Current bootstrap attempt. It cannot supply
//! a clock, role, file, peer, writer, retry or authority. Measurements spend the
//! unchanged original deadline; nested rows are inclusive, never additive.
use super::preparation_timing::{Operation, Summary, Timings};
use anyhow::Result;
use serde::Serialize;
use std::{cell::Cell, rc::Rc};

#[derive(Clone)]
pub(in crate::security_epoch) struct BootstrapTiming {
    timings: Timings,
    state: Option<Rc<Cell<State>>>,
    scope: DiagnosticScope,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DiagnosticScope {
    BootstrapCurrent,
    ProviderReadOnlyCurrent,
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
    // This is the LAST MEASURED callback, not the failed statement or overall
    // phase outcome. PreparationFailure remains the native error boundary.
    #[serde(rename = "last_step")]
    at: Operation,
    returned: Option<bool>,
    /// [attempted, fully validated]. None is overflow/inconclusive, not zero.
    provider_rounds: [Option<u8>; 2],
    timing: Summary,
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
            scope: DiagnosticScope::BootstrapCurrent,
        }
    }

    pub(in crate::security_epoch) fn provider_read_only() -> Self {
        Self {
            scope: DiagnosticScope::ProviderReadOnlyCurrent,
            ..Self::new()
        }
    }

    pub(in crate::security_epoch) fn disabled() -> Self {
        Self {
            timings: Timings::disabled(),
            state: None,
            scope: DiagnosticScope::BootstrapCurrent,
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
        if let Some(state) = &self.state {
            let mut value = state.get();
            value.rounds[0] = value.rounds[0].and_then(|n| n.checked_add(1));
            state.set(value);
        }
        let result = call();
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
        self.state.as_ref().map(|state| {
            let value = state.get();
            Snapshot {
                scope: self.scope,
                at: value.at,
                returned: value.returned,
                provider_rounds: value.rounds,
                timing: self.timings.summary(),
            }
        })
    }

    #[cfg(test)]
    pub(super) fn maximal_fixture() -> Snapshot {
        Snapshot {
            scope: DiagnosticScope::BootstrapCurrent,
            at: Operation::BootstrapAuthentication,
            returned: Some(false),
            provider_rounds: [Some(u8::MAX), Some(u8::MAX)],
            timing: Timings::maximal_bootstrap_fixture(),
        }
    }

    #[cfg(test)]
    pub(super) fn maximal_provider_fixture() -> Snapshot {
        Snapshot {
            scope: DiagnosticScope::ProviderReadOnlyCurrent,
            at: Operation::VolumeAcquisition,
            returned: Some(true),
            provider_rounds: [Some(3), Some(3)],
            timing: Timings::maximal_bootstrap_fixture(),
        }
    }
}

impl Snapshot {
    pub(in crate::security_epoch) fn is_provider_read_only(&self) -> bool {
        self.scope == DiagnosticScope::ProviderReadOnlyCurrent
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
            assert_eq!(json["scope"], "bootstrap_current");
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
                "provider_read_only_current"
            );
        }
        assert!(!BootstrapTiming::maximal_fixture().is_provider_read_only());
    }
}
