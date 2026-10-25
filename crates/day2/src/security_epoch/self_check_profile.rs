//! Exclusive diagnostic DATA for synchronous Controller work. Bootstrap roots
//! cover one full check; the separately labelled Current root covers one real
//! App-serving operation, including role acquisition. These scopes do not mix.
//! The thread-local slot contains only bounded counters, never native owners,
//! permission or a clock used by admission. Every operation still runs once.
//! Leaf spans still end before their terminal native guards. The outer Current
//! collector returns only historical DATA after the actual callback returns.

use serde::Serialize;
use std::{cell::Cell, marker::PhantomData, rc::Rc, time::Duration};

#[derive(Clone, Copy)]
#[repr(usize)]
pub(super) enum Category {
    Other,
    ExecutableBytes,
    SelfProcess,
    Namespace,
    Policy,
    Peer,
    StorageProfile,
    OriginalFile,
    Volume,
    SelfExecutableBytes,
    IssuerTransport,
    PacketWait,
    ProviderHttp,
    RoleLocal,
    PhysicalLocal,
    ServingLocal,
}

// The wire order is explicit and identical on Mac and Linux, including leaves
// that only the Linux producer can execute.
const CATEGORIES: [Category; 9] = [
    Category::Other,
    Category::ExecutableBytes,
    Category::SelfProcess,
    Category::Namespace,
    Category::Policy,
    Category::Peer,
    Category::StorageProfile,
    Category::OriginalFile,
    Category::Volume,
];

const CURRENT_CATEGORIES: usize = 16;

/// Whole-Current DATA has additional named leaves. Bootstrap measures a
/// different fixed body and does not enable these additional spans.
#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct CurrentRows {
    pub samples: Option<u32>,
    pub rows: [(Option<u32>, Option<u64>); CURRENT_CATEGORIES],
}

impl CurrentRows {
    const EMPTY: Self = Self {
        samples: Some(0),
        rows: [(Some(0), Some(0)); CURRENT_CATEGORIES],
    };

    #[cfg(test)]
    fn maximal_fixture() -> Self {
        Self {
            samples: Some(u32::MAX),
            rows: [(Some(u32::MAX), Some(u64::MAX)); CURRENT_CATEGORIES],
        }
    }
}

/// Per-category [attempts, exclusive nanoseconds]. Missing timing is sticky
/// for the whole sample: a broken diagnostic clock cannot look like zero cost.
#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct Profile {
    pub samples: Option<u32>,
    pub rows: [(Option<u32>, Option<u64>); CATEGORIES.len()],
}

impl Profile {
    pub(super) const EMPTY: Self = Self {
        samples: Some(0),
        rows: [(Some(0), Some(0)); CATEGORIES.len()],
    };

    pub(super) fn add(&mut self, other: Self) {
        self.samples = self
            .samples
            .zip(other.samples)
            .and_then(|(a, b)| a.checked_add(b));
        for (a, b) in self.rows.iter_mut().zip(other.rows) {
            a.0 = a.0.zip(b.0).and_then(|(a, b)| a.checked_add(b));
            a.1 = a.1.zip(b.1).and_then(|(a, b)| a.checked_add(b));
        }
    }

    #[cfg(test)]
    pub(super) fn maximal_fixture() -> Self {
        Self {
            samples: Some(u32::MAX),
            rows: [(Some(u32::MAX), Some(u64::MAX)); CATEGORIES.len()],
        }
    }
}

#[derive(Clone, Copy)]
struct Active {
    profile: CurrentRows,
    current: bool,
    category: Category,
    last: Option<Duration>,
    physical: Option<PhysicalProfile>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(usize)]
pub(super) enum PhysicalStep {
    Durability,
    Peer,
    FinalFile,
    ProviderStage,
}

/// These rows are inclusive microseconds, separate from exclusive leaf ns.
/// A marker identifies a call, never an exact failed statement or root cause.
#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct PhysicalProfile {
    timing_format: &'static str,
    last: PhysicalStep,
    returned: Option<bool>,
    failed: Option<PhysicalStep>,
    rows: [(Option<u32>, Option<u32>); 4],
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct CurrentProfile {
    pub profile: CurrentRows,
    #[serde(skip_serializing_if = "Option::is_none")]
    physical: Option<PhysicalProfile>,
}

impl CurrentProfile {
    #[cfg(test)]
    pub(super) fn maximal_fixture() -> Self {
        Self {
            profile: CurrentRows::maximal_fixture(),
            physical: Some(PhysicalProfile {
                timing_format: "step_count_inclusive_us_v1",
                last: PhysicalStep::ProviderStage,
                returned: Some(false),
                failed: Some(PhysicalStep::ProviderStage),
                rows: [(Some(u32::MAX), Some(u32::MAX)); 4],
            }),
        }
    }
}

impl Active {
    fn boundary(&mut self, now: Option<Duration>) {
        let elapsed = self.last.zip(now).and_then(|(a, b)| b.checked_sub(a));
        self.last = now;
        let elapsed = elapsed.and_then(|d| d.as_nanos().try_into().ok());
        if let Some(elapsed) = elapsed {
            let row = &mut self.profile.rows[self.category as usize];
            row.1 = row.1.and_then(|n| n.checked_add(elapsed));
        } else {
            self.invalidate();
        }
    }

    fn invalidate(&mut self) {
        for row in &mut self.profile.rows {
            row.1 = None;
        }
        if let Some(physical) = &mut self.physical {
            for row in &mut physical.rows {
                row.1 = None;
            }
        }
    }
}

thread_local! {
    static ACTIVE: Cell<Option<Active>> = const { Cell::new(None) };
}

fn clock() -> Option<Duration> {
    super::native_clock::boottime().ok()
}

struct Root(bool);

impl Drop for Root {
    fn drop(&mut self) {
        if self.0 {
            ACTIVE.with(|slot| slot.set(None));
        }
    }
}

/// A closed synchronous diagnostic scope; it returns the ORIGINAL result even
/// on refusal. Nested roots are inconclusive, never reset or steal the parent.
pub(super) fn sample<T>(call: impl FnOnce() -> T) -> (T, Option<Profile>) {
    let (result, collected) = sample_data(call, false);
    (
        result,
        collected.map(|collected| Profile {
            samples: collected.profile.samples,
            rows: std::array::from_fn(|index| collected.profile.rows[index]),
        }),
    )
}

/// Arm exactly once around the actual Current operation, not each nested
/// guard. This grants no role, changes no native check, and never exports I/O.
pub(super) fn sample_current<T>(call: impl FnOnce() -> T) -> (T, Option<CurrentProfile>) {
    sample_data(call, true)
}

fn sample_data<T>(call: impl FnOnce() -> T, current: bool) -> (T, Option<CurrentProfile>) {
    let mut root = Root(ACTIVE.with(|slot| {
        if let Some(mut active) = slot.get() {
            active.invalidate();
            slot.set(Some(active));
            return false;
        }
        let mut profile = CurrentRows::EMPTY;
        profile.samples = Some(1);
        profile.rows[Category::Other as usize].0 = Some(1);
        slot.set(Some(Active {
            profile,
            current,
            category: Category::Other,
            last: clock(),
            physical: None,
        }));
        true
    }));
    let result = call();
    let profile = if root.0 {
        ACTIVE.with(|slot| {
            slot.take().map(|mut active| {
                active.boundary(clock());
                CurrentProfile {
                    profile: active.profile,
                    physical: active.physical,
                }
            })
        })
    } else {
        None
    };
    root.0 = false;
    (result, profile)
}

/// A closed S3 subcall, measured only under an already armed synchronous root.
/// The original result/error is returned unchanged; counters cannot revive it.
pub(super) fn physical<T>(
    step: PhysicalStep,
    call: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let attempt = ACTIVE.with(|slot| {
        let mut active = slot.get()?;
        let timing_known = active.profile.rows.iter().all(|row| row.1.is_some());
        let mut physical = active.physical.unwrap_or(PhysicalProfile {
            timing_format: "step_count_inclusive_us_v1",
            last: step,
            returned: None,
            failed: None,
            rows: [(Some(0), timing_known.then_some(0)); 4],
        });
        physical.last = step;
        physical.returned = None;
        physical.rows[step as usize].0 = physical.rows[step as usize]
            .0
            .and_then(|n| n.checked_add(1));
        let attempt = physical.rows[step as usize].0;
        active.physical = Some(physical);
        slot.set(Some(active));
        Some(attempt)
    });
    let Some(attempt) = attempt else {
        return call();
    };
    let before = clock();
    let result = call();
    let duration = before
        .zip(clock())
        .and_then(|(a, b)| b.checked_sub(a))
        .and_then(|value| u32::try_from(value.as_micros()).ok());
    ACTIVE.with(|slot| {
        if let Some(mut active) = slot.get() {
            if let Some(physical) = &mut active.physical {
                let row = &mut physical.rows[step as usize];
                row.1 = row.1.zip(duration).and_then(|(a, b)| a.checked_add(b));
                // A parent finishing must not overwrite the outcome of the
                // last nested call. Its own failure is recorded separately.
                if physical.last == step && attempt.is_some() && row.0 == attempt {
                    physical.returned = Some(result.is_ok());
                }
                if result.is_err() && physical.failed.is_none() {
                    physical.failed = Some(step);
                }
            }
            slot.set(Some(active));
        }
    });
    result
}

pub(super) struct Guard(Option<Category>, PhantomData<Rc<()>>);

/// Enter a fixed category only inside an actual full-check sample. Disabled
/// leaves allocate nothing and perform no diagnostic clock read. RAII keeps
/// early errors/panics from leaving the category active in a later sample.
pub(super) fn enter(category: Category) -> Guard {
    let previous = ACTIVE.with(|slot| {
        slot.get().and_then(|mut active| {
            if !active.current && category as usize >= CATEGORIES.len() {
                return None;
            }
            active.boundary(clock());
            let previous = active.category;
            active.category = category;
            let count = &mut active.profile.rows[category as usize].0;
            *count = count.and_then(|n| n.checked_add(1));
            slot.set(Some(active));
            Some(previous)
        })
    });
    Guard(previous, PhantomData)
}

/// Issuer receives already contain their actual synchronous packet waits.
/// Other socket polls get a separate leaf rather than double-counting them.
pub(super) fn packet_wait() -> Guard {
    if ACTIVE.with(|slot| {
        slot.get()
            .is_some_and(|active| matches!(active.category, Category::IssuerTransport))
    }) {
        Guard(None, PhantomData)
    } else {
        enter(Category::PacketWait)
    }
}

impl Guard {
    /// Finish diagnostics before a terminal native guard. Error paths may rely
    /// on Drop; finishing twice never charges a later category or clock read.
    pub(super) fn finish(&mut self) {
        if let Some(previous) = self.0.take() {
            ACTIVE.with(|slot| {
                if let Some(mut active) = slot.get() {
                    active.boundary(clock());
                    active.category = previous;
                    slot.set(Some(active));
                }
            });
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_named_leaves_partition_local_work_and_do_not_change_bootstrap_scope() {
        let mut active = Active {
            profile: CurrentRows::EMPTY,
            current: true,
            category: Category::RoleLocal,
            last: Some(Duration::ZERO),
            physical: None,
        };
        active.boundary(Some(Duration::from_nanos(10)));
        active.category = Category::SelfExecutableBytes;
        active.boundary(Some(Duration::from_nanos(70)));
        active.category = Category::IssuerTransport;
        active.boundary(Some(Duration::from_nanos(100)));
        assert_eq!(
            active.profile.rows[Category::RoleLocal as usize].1,
            Some(10)
        );
        assert_eq!(
            active.profile.rows[Category::SelfExecutableBytes as usize].1,
            Some(60)
        );
        assert_eq!(
            active.profile.rows[Category::IssuerTransport as usize].1,
            Some(30)
        );
        assert_eq!(
            active
                .profile
                .rows
                .iter()
                .map(|row| row.1.unwrap())
                .sum::<u64>(),
            100
        );

        let (_, bootstrap) = sample(|| {
            let before = ACTIVE.with(|slot| slot.get().unwrap().last);
            let _disabled = enter(Category::SelfExecutableBytes);
            assert!(ACTIVE.with(|slot| slot.get().unwrap().last == before));
        });
        let bootstrap = bootstrap.unwrap();
        assert_eq!(bootstrap.rows.len(), 9);
        assert_eq!(bootstrap.rows[Category::Other as usize].0, Some(1));
    }

    #[test]
    fn issuer_packet_wait_is_not_relabelled_as_another_peer_or_counted_twice() {
        let (_, current) = sample_current(|| {
            let _issuer = enter(Category::IssuerTransport);
            let _wait = packet_wait();
            assert!(
                ACTIVE
                    .with(|slot| matches!(slot.get().unwrap().category, Category::IssuerTransport))
            );
        });
        let current = current.unwrap();
        assert_eq!(current.profile.rows.len(), 16);
        assert_eq!(
            current.profile.rows[Category::IssuerTransport as usize].0,
            Some(1)
        );
        assert_eq!(
            current.profile.rows[Category::PacketWait as usize].0,
            Some(0)
        );
        let (_, current) = sample_current(|| {
            let _wait = packet_wait();
        });
        assert_eq!(
            current.unwrap().profile.rows[Category::PacketWait as usize].0,
            Some(1)
        );
    }

    #[test]
    fn failed_provider_argument_preserves_nested_failure_and_never_enters_acquisition() {
        let mut acquisition_entered = false;
        let (result, collected) = sample_current(|| {
            let _: () = physical(PhysicalStep::ProviderStage, || {
                physical(PhysicalStep::Durability, || {
                    Err(anyhow::anyhow!("actual durability refusal"))
                })
            })?;
            acquisition_entered = true;
            Ok::<_, anyhow::Error>(())
        });
        assert!(!acquisition_entered);
        assert_eq!(result.unwrap_err().to_string(), "actual durability refusal");
        let physical = collected.unwrap().physical.unwrap();
        assert_eq!(physical.failed, Some(PhysicalStep::Durability));
        assert_eq!(physical.last, PhysicalStep::Durability);
        assert_eq!(physical.returned, Some(false));
        assert_eq!(
            physical.rows[PhysicalStep::ProviderStage as usize].0,
            Some(1)
        );
        assert_eq!(physical.rows[PhysicalStep::Durability as usize].0, Some(1));
        assert_eq!(physical.rows[PhysicalStep::Peer as usize].0, Some(0));
        assert!(ACTIVE.with(|slot| slot.get().is_none()));
    }

    #[test]
    fn failed_outer_stage_preserves_the_last_successful_nested_call_outcome() {
        let (result, collected) = sample_current(|| {
            physical(PhysicalStep::ProviderStage, || {
                physical(PhysicalStep::FinalFile, || Ok(()))?;
                Err::<(), _>(anyhow::anyhow!("outer stage refusal"))
            })
        });
        assert_eq!(result.unwrap_err().to_string(), "outer stage refusal");
        let physical = collected.unwrap().physical.unwrap();
        assert_eq!(physical.last, PhysicalStep::FinalFile);
        assert_eq!(physical.returned, Some(true));
        assert_eq!(physical.failed, Some(PhysicalStep::ProviderStage));
        assert_eq!(physical.rows[PhysicalStep::FinalFile as usize].0, Some(1));
        assert_eq!(
            physical.rows[PhysicalStep::ProviderStage as usize].0,
            Some(1)
        );
        assert!(ACTIVE.with(|slot| slot.get().is_none()));
    }

    #[test]
    fn nested_same_step_keeps_the_last_attempts_outcome() {
        let (result, collected) = sample_current(|| {
            physical(PhysicalStep::ProviderStage, || {
                physical(PhysicalStep::ProviderStage, || Ok(()))?;
                Err::<(), _>(anyhow::anyhow!("outer stage refusal"))
            })
        });
        assert!(result.is_err());
        let physical = collected.unwrap().physical.unwrap();
        assert_eq!(physical.last, PhysicalStep::ProviderStage);
        assert_eq!(physical.returned, Some(true));
        assert_eq!(physical.failed, Some(PhysicalStep::ProviderStage));
        assert_eq!(
            physical.rows[PhysicalStep::ProviderStage as usize].0,
            Some(2)
        );
    }

    #[test]
    fn nested_categories_partition_time_instead_of_double_counting() {
        let mut active = Active {
            profile: CurrentRows::EMPTY,
            current: false,
            category: Category::Peer,
            last: Some(Duration::from_nanos(10)),
            physical: None,
        };
        active.boundary(Some(Duration::from_nanos(20)));
        active.category = Category::ExecutableBytes;
        active.boundary(Some(Duration::from_nanos(50)));
        active.category = Category::Peer;
        active.boundary(Some(Duration::from_nanos(70)));
        assert_eq!(active.profile.rows[Category::Peer as usize].1, Some(30));
        assert_eq!(
            active.profile.rows[Category::ExecutableBytes as usize].1,
            Some(30)
        );
        assert_eq!(
            active
                .profile
                .rows
                .iter()
                .map(|r| r.1.unwrap())
                .sum::<u64>(),
            60
        );
    }

    #[test]
    fn missing_rewound_and_overflowed_costs_never_recover_as_zero() {
        for now in [None, Some(Duration::ZERO), Some(Duration::MAX)] {
            let mut active = Active {
                profile: CurrentRows::EMPTY,
                current: false,
                category: Category::Peer,
                last: Some(Duration::from_secs(1)),
                physical: None,
            };
            active.boundary(now);
            active.boundary(Some(Duration::from_secs(2)));
            assert!(active.profile.rows.iter().all(|r| r.1.is_none()));
        }
        let mut maximum = Profile::maximal_fixture();
        maximum.add(Profile::maximal_fixture());
        assert!(maximum.samples.is_none());
        assert!(maximum.rows.iter().all(|r| r.0.is_none() && r.1.is_none()));
    }

    #[test]
    fn original_error_nested_root_and_panic_do_not_leak_a_scope() {
        let (result, profile) = sample(|| {
            let _guard = enter(Category::Peer);
            let (value, nested) = sample(|| 17);
            assert_eq!(value, 17);
            assert!(nested.is_none());
            Err::<(), _>("original refusal")
        });
        assert_eq!(result, Err("original refusal"));
        assert!(profile.unwrap().rows.iter().all(|r| r.1.is_none()));
        assert!(
            std::panic::catch_unwind(|| sample(|| {
                let _guard = enter(Category::Peer);
                panic!("fixture panic");
            }))
            .is_err()
        );
        assert!(ACTIVE.with(|slot| slot.get().is_none()));
        let (value, profile) = sample(|| 19);
        assert_eq!(value, 19);
        assert_eq!(profile.unwrap().samples, Some(1));
        let _disabled = enter(Category::Policy);
        assert!(ACTIVE.with(|slot| slot.get().is_none()));
    }

    #[test]
    fn explicit_finish_cannot_restore_a_category_twice_after_a_terminal_guard() {
        let (_, profile) = sample(|| {
            let mut guard = enter(Category::Policy);
            guard.finish();
            assert!(guard.0.is_none());
            let _peer = enter(Category::Peer);
            guard.finish();
            drop(guard);
            assert!(ACTIVE.with(|slot| matches!(slot.get().unwrap().category, Category::Peer)));
        });
        assert_eq!(profile.unwrap().rows[Category::Policy as usize].0, Some(1));
    }

    #[test]
    fn current_refusal_keeps_original_error_and_actual_subcall_order() {
        let mut order = Vec::new();
        let (result, collected) = sample_current(|| {
            physical(PhysicalStep::Durability, || {
                order.push(0);
                Ok(())
            })?;
            physical(PhysicalStep::Peer, || {
                order.push(1);
                Err::<(), _>(anyhow::anyhow!("original physical refusal"))
            })?;
            physical(PhysicalStep::FinalFile, || {
                order.push(2);
                Ok(())
            })
        });
        assert_eq!(order, [0, 1]);
        assert_eq!(result.unwrap_err().to_string(), "original physical refusal");
        let collected = collected.unwrap();
        assert_eq!(collected.profile.samples, Some(1));
        let physical = collected.physical.unwrap();
        assert_eq!(physical.last, PhysicalStep::Peer);
        assert_eq!(physical.returned, Some(false));
        assert_eq!(physical.failed, Some(PhysicalStep::Peer));
        assert_eq!(physical.rows[0].0, Some(1));
        assert_eq!(physical.rows[1].0, Some(1));
        assert_eq!(physical.rows[2].0, Some(0));
        assert!(ACTIVE.with(|slot| slot.get().is_none()));
    }

    #[test]
    fn failed_role_before_physical_work_and_unwind_never_fabricate_a_physical_sample() {
        let (result, collected) = sample_current(|| Err::<(), _>("original role refusal"));
        assert_eq!(result, Err("original role refusal"));
        assert!(collected.unwrap().physical.is_none());
        assert!(
            std::panic::catch_unwind(|| sample_current(|| {
                let _ = physical(PhysicalStep::Durability, || -> anyhow::Result<()> {
                    panic!("fixture")
                });
            }))
            .is_err()
        );
        assert!(ACTIVE.with(|slot| slot.get().is_none()));
        let result = physical(PhysicalStep::Peer, || {
            Err::<(), _>(anyhow::anyhow!("disabled refusal"))
        });
        assert_eq!(result.unwrap_err().to_string(), "disabled refusal");
        assert!(ACTIVE.with(|slot| slot.get().is_none()));
    }

    #[test]
    fn nested_root_and_missing_time_never_revive_current_measurements_or_clock() {
        use super::super::native_clock::NativeAcquisition;
        use day2_capabilities::Digest;
        let mut acquisition = NativeAcquisition::fixture(
            Digest::new(b"current-profile"),
            std::process::id(),
            Duration::from_secs(100),
            Duration::from_secs(5),
        );
        acquisition.refuse();
        let (result, collected) = sample_current(|| {
            physical(PhysicalStep::Durability, || {
                let (_, nested) = sample_current(|| 17);
                assert!(nested.is_none());
                acquisition.remaining()
            })
        });
        assert!(result.is_err());
        assert!(acquisition.remaining().is_err());
        let collected = collected.unwrap();
        assert!(collected.profile.rows.iter().all(|row| row.1.is_none()));
        assert!(
            collected
                .physical
                .unwrap()
                .rows
                .iter()
                .all(|row| row.1.is_none())
        );
        for now in [None, Some(Duration::ZERO), Some(Duration::MAX)] {
            let mut active = Active {
                profile: CurrentRows::EMPTY,
                current: false,
                category: Category::Other,
                last: Some(Duration::from_secs(1)),
                physical: CurrentProfile::maximal_fixture().physical,
            };
            active.boundary(now);
            active.boundary(Some(Duration::from_secs(2)));
            assert!(
                active
                    .physical
                    .unwrap()
                    .rows
                    .iter()
                    .all(|row| row.1.is_none())
            );
        }
    }
}
