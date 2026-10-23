//! Bounded diagnostic DATA, independent of every native acquisition/permission.
//! Timings are inclusive; nested rows MUST NOT be added together. No I/O occurs
//! here except two diagnostic clock reads around an unchanged operation.

use serde::Serialize;
use std::{cell::RefCell, rc::Rc, time::Duration};

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub(in crate::security_epoch) enum Operation {
    RoleStage,
    VolumeAcquisition,
    NativeCheck,
    Image,
    OriginalFile,
    Write,
    Read,
    FileSync,
    DirectorySync,
    RetentionBefore,
    RetentionOwner,
    MetadataToken,
    Project,
    Cluster,
    ControllerIdentity,
    ControllerToken,
    Database,
    Claim,
    Volume,
    Node,
    Disk,
    Instance,
    HolderRole,
    HolderListener,
    FirstRole,
    FirstReady,
    FirstFile,
    FirstExchange,
    BootstrapReady,
    BootstrapAuthentication,
    BootstrapFile,
    BootstrapProjection,
    BootstrapDurability,
    BootstrapPeer,
    BootstrapPeerCheck,
    BootstrapWriter,
    BootstrapCounter,
    BootstrapSlot,
    BootstrapMutation,
    BootstrapValidation,
    BootstrapRelease,
    AuthenticationCheck,
    ProviderRoundOne,
    ProviderRoundTwo,
    ProviderRoundThree,
    ProviderRoundOther,
    BootstrapWriterPhase,
    BootstrapWriterMaterial,
    BootstrapWriterSample,
    BootstrapCounterAfter,
    BootstrapSlotAfter,
    BootstrapExecution,
    BootstrapAnnouncement,
    BootstrapAcknowledgement,
    BootstrapPeerRelease,
    BootstrapPeerFinish,
    BootstrapFirestoreRead,
    BootstrapFirestoreCommit,
    BootstrapFirestoreRollback,
}

const OPERATIONS: [Operation; 59] = [
    Operation::RoleStage,
    Operation::VolumeAcquisition,
    Operation::NativeCheck,
    Operation::Image,
    Operation::OriginalFile,
    Operation::Write,
    Operation::Read,
    Operation::FileSync,
    Operation::DirectorySync,
    Operation::RetentionBefore,
    Operation::RetentionOwner,
    Operation::MetadataToken,
    Operation::Project,
    Operation::Cluster,
    Operation::ControllerIdentity,
    Operation::ControllerToken,
    Operation::Database,
    Operation::Claim,
    Operation::Volume,
    Operation::Node,
    Operation::Disk,
    Operation::Instance,
    Operation::HolderRole,
    Operation::HolderListener,
    Operation::FirstRole,
    Operation::FirstReady,
    Operation::FirstFile,
    Operation::FirstExchange,
    Operation::BootstrapReady,
    Operation::BootstrapAuthentication,
    Operation::BootstrapFile,
    Operation::BootstrapProjection,
    Operation::BootstrapDurability,
    Operation::BootstrapPeer,
    Operation::BootstrapPeerCheck,
    Operation::BootstrapWriter,
    Operation::BootstrapCounter,
    Operation::BootstrapSlot,
    Operation::BootstrapMutation,
    Operation::BootstrapValidation,
    Operation::BootstrapRelease,
    Operation::AuthenticationCheck,
    Operation::ProviderRoundOne,
    Operation::ProviderRoundTwo,
    Operation::ProviderRoundThree,
    Operation::ProviderRoundOther,
    Operation::BootstrapWriterPhase,
    Operation::BootstrapWriterMaterial,
    Operation::BootstrapWriterSample,
    Operation::BootstrapCounterAfter,
    Operation::BootstrapSlotAfter,
    Operation::BootstrapExecution,
    Operation::BootstrapAnnouncement,
    Operation::BootstrapAcknowledgement,
    Operation::BootstrapPeerRelease,
    Operation::BootstrapPeerFinish,
    Operation::BootstrapFirestoreRead,
    Operation::BootstrapFirestoreCommit,
    Operation::BootstrapFirestoreRollback,
];

#[derive(Clone, Copy)]
enum Scope {
    Preparation,
    Bootstrap,
}

impl Scope {
    fn includes(self, operation: Operation) -> bool {
        let bootstrap_only = matches!(
            operation,
            Operation::BootstrapReady
                | Operation::BootstrapAuthentication
                | Operation::BootstrapFile
                | Operation::BootstrapProjection
                | Operation::BootstrapDurability
                | Operation::BootstrapPeer
                | Operation::BootstrapPeerCheck
                | Operation::BootstrapWriter
                | Operation::BootstrapCounter
                | Operation::BootstrapSlot
                | Operation::BootstrapMutation
                | Operation::BootstrapValidation
                | Operation::BootstrapRelease
                | Operation::AuthenticationCheck
                | Operation::ProviderRoundOne
                | Operation::ProviderRoundTwo
                | Operation::ProviderRoundThree
                | Operation::ProviderRoundOther
                | Operation::BootstrapWriterPhase
                | Operation::BootstrapWriterMaterial
                | Operation::BootstrapWriterSample
                | Operation::BootstrapCounterAfter
                | Operation::BootstrapSlotAfter
                | Operation::BootstrapExecution
                | Operation::BootstrapAnnouncement
                | Operation::BootstrapAcknowledgement
                | Operation::BootstrapPeerRelease
                | Operation::BootstrapPeerFinish
                | Operation::BootstrapFirestoreRead
                | Operation::BootstrapFirestoreCommit
                | Operation::BootstrapFirestoreRollback
        );
        match self {
            Self::Preparation => !bootstrap_only,
            Self::Bootstrap => {
                bootstrap_only
                    || matches!(
                        operation,
                        Operation::RoleStage
                            | Operation::VolumeAcquisition
                            | Operation::NativeCheck
                            | Operation::Claim
                            | Operation::Volume
                            | Operation::Node
                            | Operation::Disk
                            | Operation::Instance
                    )
            }
        }
    }
}

/// [call count, inclusive total microseconds, maximum call microseconds].
/// Null is sticky missing/rewound/overflowed measurement, never zero/success.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(in crate::security_epoch) struct Measurement(Option<u32>, Option<u32>, Option<u32>);

impl Measurement {
    const EMPTY: Self = Self(Some(0), Some(0), Some(0));

    fn add(&mut self, elapsed: Option<Duration>) {
        self.0 = self.0.and_then(|n| n.checked_add(1));
        let micros = elapsed.and_then(|d| d.as_micros().try_into().ok());
        self.1 = self.1.zip(micros).and_then(|(a, b)| a.checked_add(b));
        self.2 = self.2.zip(micros).map(|(a, b)| a.max(b));
    }
}

#[derive(Clone, Debug, Serialize)]
pub(in crate::security_epoch) struct Summary(Vec<(Operation, Measurement)>);

/// Fixed operation code, call count, inclusive total microseconds. Compact
/// bootstrap DATA keeps even maximal counters inside the unchanged 2048-byte
/// record ceiling. Preparation's named count/total/max rows remain separate.
#[derive(Clone, Debug, Serialize)]
pub(in crate::security_epoch) struct CompactSummary(Vec<(u8, Option<u32>, Option<u32>)>);

impl Summary {
    pub(super) fn compact(self) -> CompactSummary {
        CompactSummary(
            self.0
                .into_iter()
                .map(|(operation, value)| (operation as u8, value.0, value.1))
                .collect(),
        )
    }
}

/// One explicitly scoped collector for preparation, listener and first holder.
/// Other current/serving phases use disabled(), with no allocation, clock
/// reads, inherited observations or permission.
#[derive(Clone)]
pub(in crate::security_epoch) struct Timings(
    Option<Rc<RefCell<[Measurement; OPERATIONS.len()]>>>,
    Scope,
);

impl Timings {
    pub(in crate::security_epoch) fn new() -> Self {
        Self(
            Some(Rc::new(RefCell::new(
                [Measurement::EMPTY; OPERATIONS.len()],
            ))),
            Scope::Preparation,
        )
    }

    pub(in crate::security_epoch) fn bootstrap() -> Self {
        Self(
            Some(Rc::new(RefCell::new(
                [Measurement::EMPTY; OPERATIONS.len()],
            ))),
            Scope::Bootstrap,
        )
    }

    pub(in crate::security_epoch) fn disabled() -> Self {
        Self(None, Scope::Preparation)
    }

    pub(in crate::security_epoch) fn measure<T>(
        &self,
        operation: Operation,
        call: impl FnOnce() -> T,
    ) -> T {
        self.measure_with(operation, call, || {
            super::super::native_clock::boottime().ok()
        })
    }

    fn measure_with<T>(
        &self,
        operation: Operation,
        call: impl FnOnce() -> T,
        mut clock: impl FnMut() -> Option<Duration>,
    ) -> T {
        let Some(values) = &self.0 else {
            return call();
        };
        if !self.1.includes(operation) {
            return call();
        }
        let before = clock();
        let result = call();
        let elapsed = before.zip(clock()).and_then(|(a, b)| b.checked_sub(a));
        values.borrow_mut()[operation as usize].add(elapsed);
        result
    }

    pub(in crate::security_epoch) fn summary(&self) -> Summary {
        Summary(self.0.as_ref().map_or_else(Vec::new, |values| {
            OPERATIONS
                .iter()
                .copied()
                .zip(*values.borrow())
                .filter(|(operation, value)| self.1.includes(*operation) && value.0 != Some(0))
                .collect()
        }))
    }

    #[cfg(test)]
    pub(super) fn maximal_summary_fixture() -> Summary {
        Summary(
            OPERATIONS
                .into_iter()
                .filter(|operation| Scope::Preparation.includes(*operation))
                .map(|operation| {
                    (
                        operation,
                        Measurement(Some(u32::MAX), Some(u32::MAX), Some(u32::MAX)),
                    )
                })
                .collect(),
        )
    }

    #[cfg(test)]
    pub(super) fn maximal_bootstrap_fixture() -> Summary {
        Summary(
            OPERATIONS
                .into_iter()
                .filter(|operation| Scope::Bootstrap.includes(*operation))
                .map(|operation| {
                    (
                        operation,
                        Measurement(Some(u32::MAX), Some(u32::MAX), Some(u32::MAX)),
                    )
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_round_and_tail_codes_preserve_counts_totals_and_inconclusive_values() {
        for (index, operation) in OPERATIONS.iter().enumerate() {
            assert_eq!(*operation as usize, index);
        }
        let timings = Timings::bootstrap();
        for (operation, micros) in [
            (Operation::ProviderRoundOne, 11),
            (Operation::ProviderRoundTwo, 22),
            (Operation::ProviderRoundThree, 33),
            (Operation::BootstrapAcknowledgement, 44),
        ] {
            let mut times = [Duration::ZERO, Duration::from_micros(micros)].into_iter();
            assert_eq!(timings.measure_with(operation, || 17, || times.next()), 17);
        }
        assert_eq!(
            serde_json::to_value(timings.summary().compact()).unwrap(),
            serde_json::json!([[42, 1, 11], [43, 1, 22], [44, 1, 33], [53, 1, 44]])
        );
        let inconclusive = Summary(vec![(
            Operation::BootstrapFirestoreCommit,
            Measurement(None, None, None),
        )]);
        assert_eq!(
            serde_json::to_value(inconclusive.compact()).unwrap(),
            serde_json::json!([[57, null, null]])
        );
    }

    #[test]
    fn error_outcomes_are_unchanged_and_inclusive_nested_measurements_stay_separate() {
        let timings = Timings::new();
        let mut outside = [
            Some(Duration::from_micros(10)),
            Some(Duration::from_micros(90)),
        ]
        .into_iter();
        let result = timings.measure_with(
            Operation::VolumeAcquisition,
            || {
                let mut inside = [
                    Some(Duration::from_micros(20)),
                    Some(Duration::from_micros(50)),
                ]
                .into_iter();
                timings.measure_with(
                    Operation::Database,
                    || Err::<(), _>("original failure"),
                    || inside.next().unwrap(),
                )
            },
            || outside.next().unwrap(),
        );
        assert_eq!(result, Err("original failure"));
        let values = timings.0.as_ref().unwrap().borrow();
        assert_eq!(
            values[Operation::VolumeAcquisition as usize],
            Measurement(Some(1), Some(80), Some(80))
        );
        assert_eq!(
            values[Operation::Database as usize],
            Measurement(Some(1), Some(30), Some(30))
        );
    }

    #[test]
    fn missing_rewound_and_overflowed_measurements_cannot_turn_into_zero_or_success() {
        let mut value = Measurement::EMPTY;
        value.add(Some(Duration::from_micros(5)));
        value.add(None);
        value.add(Some(Duration::from_micros(2)));
        assert_eq!(value, Measurement(Some(3), None, None));
        let mut value = Measurement::EMPTY;
        value.add(Some(Duration::MAX));
        assert_eq!(value, Measurement(Some(1), None, None));
        let timings = Timings::new();
        let mut samples = [Some(Duration::from_secs(2)), Some(Duration::from_secs(1))].into_iter();
        assert_eq!(
            timings.measure_with(Operation::Image, || 17, || samples.next().unwrap()),
            17
        );
        assert_eq!(
            timings.0.as_ref().unwrap().borrow()[Operation::Image as usize],
            Measurement(Some(1), None, None)
        );
    }

    #[test]
    fn disabled_collector_performs_no_clock_read_and_no_observation() {
        let timings = Timings::disabled();
        assert_eq!(
            timings.measure_with(Operation::Read, || 19, || panic!("clock read")),
            19
        );
        assert_eq!(serde_json::to_string(&timings.summary()).unwrap(), "[]");
    }

    #[test]
    fn holder_role_and_listener_keep_distinct_failed_and_completed_measurements() {
        let timings = Timings::new();
        for (operation, result, micros) in [
            (Operation::HolderRole, Ok(()), 17),
            (
                Operation::HolderListener,
                Err("original final check refused"),
                29,
            ),
        ] {
            let mut clock = [Duration::ZERO, Duration::from_micros(micros)].into_iter();
            assert_eq!(
                timings.measure_with(operation, || result, || clock.next()),
                result
            );
        }
        assert_eq!(
            serde_json::to_value(timings.summary()).unwrap(),
            serde_json::json!([
                ["holder_role", [1, 17, 17]],
                ["holder_listener", [1, 29, 29]],
            ])
        );
    }

    #[test]
    fn first_holder_scopes_preserve_failure_and_remain_independent_data() {
        let timings = Timings::new();
        for operation in [
            Operation::FirstRole,
            Operation::FirstFile,
            Operation::FirstExchange,
        ] {
            let mut clock = [Duration::ZERO, Duration::from_micros(17)].into_iter();
            assert_eq!(
                timings.measure_with(
                    operation,
                    || Err::<(), _>("original failure"),
                    || clock.next()
                ),
                Err("original failure")
            );
        }
        assert_eq!(
            serde_json::to_value(timings.summary()).unwrap(),
            serde_json::json!([
                ["first_role", [1, 17, 17]],
                ["first_file", [1, 17, 17]],
                ["first_exchange", [1, 17, 17]]
            ])
        );
    }
}
