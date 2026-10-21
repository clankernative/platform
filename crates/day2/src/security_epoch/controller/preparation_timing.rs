//! Bounded diagnostic DATA, independent of every native acquisition/permission.
//! Timings are inclusive; nested rows MUST NOT be added together. No I/O occurs
//! here except two diagnostic clock reads around an unchanged operation.

use serde::Serialize;
use std::{cell::RefCell, rc::Rc, time::Duration};

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
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
}

const OPERATIONS: [Operation; 22] = [
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
];

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

/// One explicitly scoped collector. Current/serving phases use disabled(),
/// with no allocation, clock reads, inherited observations or permission.
#[derive(Clone)]
pub(in crate::security_epoch) struct Timings(Option<Rc<RefCell<[Measurement; 22]>>>);

impl Timings {
    pub(in crate::security_epoch) fn new() -> Self {
        Self(Some(Rc::new(RefCell::new([Measurement::EMPTY; 22]))))
    }

    pub(in crate::security_epoch) fn disabled() -> Self {
        Self(None)
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
                .filter(|(_, value)| value.0 != Some(0))
                .collect()
        }))
    }

    #[cfg(test)]
    pub(super) fn maximal_summary_fixture() -> Summary {
        Summary(
            OPERATIONS
                .into_iter()
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
}
