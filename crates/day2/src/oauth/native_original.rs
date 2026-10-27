//! One non-transferable creator lifetime. The clock supplier owns enrolled
//! common-domain/process/self-task observations; timestamps and SQL rows cannot
//! implement that supplier. NativeAcquisition's five-second clock is separate.

use super::fresh_auth::FreshIntent;
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use std::{marker::PhantomData, rc::Rc, thread::ThreadId, time::Duration};

const ORIGINAL: Duration = Duration::from_secs(300);

/// Private composition seam implemented by the enrolled role adapter. Each
/// sample reborrows the SAME accepted request against the retained enrollment;
/// it may not replace either clock domain or restart either original. No production
/// scalar/trait-object factory or caller-supplied clock implementation exists.
pub(super) trait Clock {
    fn origin(&self) -> Duration;
    fn sample(&mut self) -> Result<Duration>;
}

pub(super) struct Original<C> {
    pub(super) clock: C,
    process: u32,
    thread: ThreadId,
    origin: Duration,
    latest: Duration,
    ceiling: Duration,
    binding: Option<Digest>,
    refused: bool,
    local: PhantomData<Rc<()>>,
}

impl<C: Clock> Original<C> {
    pub(super) fn refuse(&mut self) {
        self.refused = true;
    }

    #[cfg(test)]
    pub(super) fn observation(&self) -> serde_json::Value {
        serde_json::json!({"origin":self.origin,"latest":self.latest,"ceiling":self.ceiling,
            "binding":self.binding,"refused":self.refused,
            "same_executor":self.process == std::process::id() && self.thread == std::thread::current().id()})
    }

    /// Only during the original creator's current Pending transaction, before
    /// its exact committed intent can be bound. The native adapter supplies the
    /// SAME captured clock sampled through the already held enrolled stage.
    pub(super) fn check_capture_sample(&mut self, sample: Result<Duration>) -> Result<()> {
        let result = (|| {
            ensure!(self.binding.is_none(), "native creator already bound");
            self.check_time(sample?)?;
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Call with a clock captured at creator entry BEFORE DB/entropy/RPC. Clock
    /// construction, not this bookkeeping, fixes the original BOOTTIME origin.
    pub(super) fn capture(clock: C) -> Result<Self> {
        let origin = clock.origin();
        let ceiling = origin
            .checked_add(ORIGINAL)
            .ok_or_else(|| anyhow::anyhow!("native original overflow"))?;
        Ok(Self {
            clock,
            process: std::process::id(),
            thread: std::thread::current().id(),
            origin,
            latest: origin,
            ceiling,
            binding: None,
            refused: false,
            local: PhantomData,
        })
    }

    /// Only after the App's actual commit, or before Shell naming entropy/Claim.
    /// The exact FreshIntent covers actor/sub/purpose/challenge/artifact/slot and
    /// the complete committed View digest. Repeated binding is never adoption.
    pub(super) fn bind(&mut self, intent: &FreshIntent, wall: i64) -> Result<()> {
        let result = (|| {
            ensure!(self.binding.is_none(), "native original already bound");
            let at = self.current()?;
            ensure!(
                wall >= intent.created_at() && wall < intent.deadline(),
                "native original intent expired"
            );
            let remaining = Duration::from_secs(u64::try_from(intent.deadline() - wall)?);
            self.ceiling = self.ceiling.min(
                at.checked_add(remaining)
                    .ok_or_else(|| anyhow::anyhow!("native intent overflow"))?,
            );
            self.binding = Some(intent.commitment()?);
            Ok(())
        })();
        if result.is_err() {
            self.refused = true;
        }
        result
    }

    pub(super) fn check(&mut self, intent: &FreshIntent, wall: i64) -> Result<()> {
        let sample = self.clock.sample();
        self.check_sample(intent, wall, sample)
    }

    /// Only the retained clock adapter supplies this sample, while the actual
    /// enrolled stage is borrowed through the consumer's local commit.
    pub(super) fn check_sample(
        &mut self,
        intent: &FreshIntent,
        wall: i64,
        sample: Result<Duration>,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                self.binding.as_ref() == Some(&intent.commitment()?),
                "native original context changed"
            );
            ensure!(
                wall >= intent.created_at() && wall < intent.deadline(),
                "native original intent expired"
            );
            self.check_time(sample?)?;
            Ok(())
        })();
        if result.is_err() {
            self.refused = true;
        }
        result
    }

    /// Provider/registration deadlines only shorten, never extend, either
    /// original. `wall` is a local observation; signed issuer times need their
    /// separately qualified mapping and are NOT accepted as local BOOTTIME.
    pub(super) fn tighten_local(&mut self, deadline: i64, wall: i64) -> Result<()> {
        let result = (|| {
            let at = self.current()?;
            ensure!(deadline > wall, "native original earlier bound expired");
            let remaining = Duration::from_secs(u64::try_from(deadline - wall)?);
            self.ceiling = self.ceiling.min(
                at.checked_add(remaining)
                    .ok_or_else(|| anyhow::anyhow!("native bound overflow"))?,
            );
            Ok(())
        })();
        if result.is_err() {
            self.refused = true;
        }
        result
    }

    fn current(&mut self) -> Result<Duration> {
        let now = self.clock.sample();
        self.check_time(now?)
    }

    fn check_time(&mut self, now: Duration) -> Result<Duration> {
        let result = (|| {
            ensure!(
                !self.refused
                    && self.process == std::process::id()
                    && self.thread == std::thread::current().id(),
                "native original executor unavailable"
            );
            ensure!(
                now >= self.origin && now >= self.latest && now < self.ceiling,
                "native original expired or clock changed"
            );
            self.latest = now;
            Ok(now)
        })();
        if result.is_err() {
            self.refused = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct SimClock {
        origin: Duration,
        now: Rc<Cell<Duration>>,
        fail: Rc<Cell<bool>>,
    }
    impl Clock for SimClock {
        fn origin(&self) -> Duration {
            self.origin
        }
        fn sample(&mut self) -> Result<Duration> {
            ensure!(!self.fail.get(), "scripted current role refusal");
            Ok(self.now.get())
        }
    }
    fn clock(now: &Rc<Cell<Duration>>) -> SimClock {
        SimClock {
            origin: now.get(),
            now: now.clone(),
            fail: Rc::new(Cell::new(false)),
        }
    }
    fn intent() -> FreshIntent {
        FreshIntent::fixture_oauth(
            &crate::iap::Verified {
                email: "alice@example.com".into(),
                subject: "subject".into(),
            },
            "attempt",
            &Digest::new(b"challenge"),
            "https://shell.example.com",
            100,
            400,
        )
        .unwrap()
    }

    #[test]
    fn pending_capture_samples_keep_the_creator_ceiling_and_refuse_bound_reentry() -> Result<()> {
        let now = Rc::new(Cell::new(Duration::from_secs(10)));
        let mut original = Original::capture(clock(&now))?;
        original.check_capture_sample(Ok(Duration::from_secs(309)))?;
        assert!(
            original
                .check_capture_sample(Ok(Duration::from_secs(310)))
                .is_err()
        );
        assert!(original.bind(&intent(), 100).is_err());
        let mut original = Original::capture(clock(&now))?;
        original.bind(&intent(), 100)?;
        assert!(original.check_capture_sample(Ok(now.get())).is_err());
        assert!(original.check(&intent(), 100).is_err());
        Ok(())
    }

    #[test]
    fn independent_creators_and_exact_300_boundary_do_not_renew() -> Result<()> {
        let now = Rc::new(Cell::new(Duration::from_secs(10)));
        let mut app = Original::capture(clock(&now))?;
        now.set(Duration::from_secs(30)); // DB/selection work consumed App time.
        app.bind(&intent(), 100)?;
        let mut shell = Original::capture(clock(&now))?;
        shell.bind(&intent(), 100)?;
        now.set(Duration::from_secs(309));
        app.check(&intent(), 101)?;
        shell.check(&intent(), 101)?;
        now.set(Duration::from_secs(310));
        assert!(app.check(&intent(), 101).is_err());
        shell.check(&intent(), 101)?;
        now.set(Duration::from_secs(330));
        assert!(shell.check(&intent(), 101).is_err());
        now.set(Duration::from_secs(31));
        assert!(app.check(&intent(), 101).is_err());
        Ok(())
    }

    #[test]
    fn earlier_bounds_bind_once_and_clock_failures_are_sticky() -> Result<()> {
        let now = Rc::new(Cell::new(Duration::ZERO));
        let mut original = Original::capture(clock(&now))?;
        original.bind(&intent(), 100)?;
        original.tighten_local(110, 100)?;
        original.tighten_local(300, 100)?;
        now.set(Duration::from_secs(10));
        assert!(original.check(&intent(), 101).is_err());
        let mut original = Original::capture(clock(&now))?;
        original.bind(&intent(), 100)?;
        assert!(original.bind(&intent(), 100).is_err());
        assert!(original.check(&intent(), 100).is_err());
        let clock = clock(&now);
        let fail = clock.fail.clone();
        let mut original = Original::capture(clock)?;
        original.bind(&intent(), 100)?;
        fail.set(true);
        assert!(original.check(&intent(), 100).is_err());
        fail.set(false);
        assert!(original.check(&intent(), 100).is_err());
        Ok(())
    }

    proptest::proptest! {
        #[test]
        fn seeded_rechecks_never_restart_an_expired_or_refused_original(
            schedule in proptest::collection::vec((0u16..351, proptest::bool::ANY), 1..64)
        ) {
            let now = Rc::new(Cell::new(Duration::ZERO));
            let clock = clock(&now);
            let fail = clock.fail.clone();
            let mut original = Original::capture(clock).unwrap();
            original.bind(&intent(), 100).unwrap();
            let mut elapsed = 0u64;
            let mut refused = false;
            for (advance, fail_stage) in schedule {
                elapsed += u64::from(advance);
                now.set(Duration::from_secs(elapsed));
                fail.set(fail_stage);
                refused |= fail_stage || elapsed >= 300;
                proptest::prop_assert_eq!(original.check(&intent(), 100).is_ok(), !refused);
            }
        }
    }
}
