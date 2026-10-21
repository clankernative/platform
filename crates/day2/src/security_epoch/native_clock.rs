//! Process-local acquisition origin. This observes an actual Linux continuous
//! clock; it does not qualify a runtime profile, workload, file or authority.
//! The serving bootstrap context factory remains unavailable.

use super::firestore::{Budget, Sample};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use std::{marker::PhantomData, rc::Rc, time::Duration};

const MAX_ACQUISITION: Duration = Duration::from_secs(5);

/// Only the initial first-holder rendezvous/exchange may spend this original
/// interval. The composed path estimate was about 6.3s; the actual former 5s run refused
/// at 5.001s: 2.003s role, 0.017s Ready, 0.985s file, 1.996s peer. The user
/// selected ten seconds without dropping fresh-content checks. Ordinary acquisitions,
/// including the role-authentication subphase, remain capped at five seconds.
pub(in crate::security_epoch) const INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT: Duration =
    Duration::from_secs(10);

/// One original interval for code, identity, credentials, metadata and epoch I/O.
/// No production scalar/config constructor, clock replacement or renewal exists.
pub(crate) struct NativeAcquisition {
    domain: Digest,
    process: u32,
    origin: Duration,
    latest: Duration,
    deadline: Duration,
    valid: bool,
    local: PhantomData<Rc<()>>,
    #[cfg(test)]
    fixture_time: Option<Duration>,
}

impl NativeAcquisition {
    /// The first clock read precedes entropy and every subsequent observation.
    /// Linux qualification of the selected deployment profile is a separate gate.
    pub(super) fn begin(max_lease_seconds: u32) -> Result<Self> {
        ensure!(
            (1..=60).contains(&max_lease_seconds),
            "epoch_native_acquisition_bound"
        );
        Self::begin_bounded(MAX_ACQUISITION.min(Duration::from_secs(u64::from(max_lease_seconds))))
    }

    pub(super) fn begin_initial_first_holder() -> Result<Self> {
        Self::begin_bounded(INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT)
    }

    fn begin_bounded(limit: Duration) -> Result<Self> {
        let origin = boottime()?;
        let process = std::process::id();
        let mut nonce = [0_u8; 32];
        crate::host_inputs::Entropy::fill(&crate::host_inputs::SecureEntropy, &mut nonce)?;
        let domain = Digest::of(&("day2-native-epoch-acquisition-v1", process, nonce))?;
        let deadline = origin
            .checked_add(limit)
            .ok_or_else(|| anyhow::anyhow!("epoch_native_clock_overflow"))?;
        let mut acquisition = Self {
            domain,
            process,
            origin,
            latest: origin,
            deadline,
            valid: true,
            local: PhantomData,
            #[cfg(test)]
            fixture_time: None,
        };
        acquisition.sample()?;
        Ok(acquisition)
    }

    pub(super) fn sample(&mut self) -> Result<Sample> {
        ensure!(self.valid, "epoch_native_acquisition_refused");
        let result = (|| {
            ensure!(
                std::process::id() == self.process,
                "epoch_native_process_changed"
            );
            #[cfg(test)]
            let now = self.fixture_time.map_or_else(boottime, Ok)?;
            #[cfg(not(test))]
            let now = boottime()?;
            self.observe(now)
        })();
        if result.is_err() {
            self.valid = false;
        }
        result
    }

    fn observe(&mut self, now: Duration) -> Result<Sample> {
        ensure!(self.valid, "epoch_native_acquisition_refused");
        if now < self.latest || now < self.origin || now >= self.deadline {
            self.valid = false;
            anyhow::bail!("epoch_native_clock_rewind_or_expired");
        }
        self.latest = now;
        Ok(Sample {
            domain: self.domain.clone(),
            elapsed: now,
        })
    }

    pub(super) fn remaining(&mut self) -> Result<Duration> {
        let sample = self.sample()?;
        self.deadline
            .checked_sub(sample.elapsed)
            .ok_or_else(|| anyhow::anyhow!("epoch_native_acquisition_expired"))
    }

    /// Historical DATA from the last successful sample of THIS original
    /// interval. Does not read a clock, check validity, issue permission or
    /// change refusal/deadline. An expired check may be later than this value.
    pub(super) fn last_checked_elapsed_micros(&self) -> Option<u32> {
        self.latest
            .checked_sub(self.origin)
            .and_then(|elapsed| elapsed.as_micros().try_into().ok())
    }

    pub(super) fn refuse(&mut self) {
        self.valid = false;
    }

    pub(super) fn budget(&mut self) -> Result<Budget> {
        Budget::from_native_origin(self.sample()?, self.origin, self.deadline)
    }

    /// Interval DATA for a signature, never a constructor or renewal.
    pub(super) fn interval_data(&mut self) -> Result<(Duration, Duration)> {
        self.sample()?;
        Ok((self.origin, self.deadline))
    }

    /// A narrower I/O clock derived from this actual owner, never from stored
    /// DATA. The original domain/origin and spent time are preserved. This
    /// grants no role or provider authority and cannot extend either deadline.
    pub(super) fn narrow(&mut self, max_lease_seconds: u32, ceiling: Duration) -> Result<Self> {
        let result = (|| {
            let sample = self.sample()?;
            ensure!(
                (1..=60).contains(&max_lease_seconds),
                "epoch_native_acquisition_bound"
            );
            let deadline = self
                .origin
                .checked_add(Duration::from_secs(u64::from(max_lease_seconds)))
                .ok_or_else(|| anyhow::anyhow!("epoch_native_clock_overflow"))?
                .min(self.deadline)
                .min(ceiling);
            ensure!(
                sample.elapsed < deadline,
                "epoch_native_narrowed_acquisition_expired"
            );
            let mut child = Self {
                domain: self.domain.clone(),
                process: self.process,
                origin: self.origin,
                latest: sample.elapsed,
                deadline,
                valid: true,
                local: PhantomData,
                #[cfg(test)]
                fixture_time: self.fixture_time,
            };
            child.sample()?;
            Ok(child)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    #[cfg(test)]
    pub(super) fn fixture(domain: Digest, process: u32, origin: Duration, limit: Duration) -> Self {
        Self {
            domain,
            process,
            origin,
            latest: origin,
            deadline: origin + limit,
            valid: true,
            local: PhantomData,
            fixture_time: Some(origin),
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn boottime() -> Result<Duration> {
    let value = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Boottime)?;
    ensure!(
        value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec),
        "epoch_native_clock_value"
    );
    Ok(Duration::new(
        value.tv_sec.try_into()?,
        value.tv_nsec.try_into()?,
    ))
}

#[cfg(not(target_os = "linux"))]
pub(super) fn boottime() -> Result<Duration> {
    anyhow::bail!("epoch_native_clock_platform_unsupported")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_progress_never_samples_renews_or_clears_a_refusal() {
        let mut acquisition = NativeAcquisition::fixture(
            Digest::new(b"clock-progress"),
            std::process::id(),
            Duration::from_secs(100),
            Duration::from_secs(5),
        );
        acquisition
            .observe(Duration::from_micros(102_123_456))
            .unwrap();
        assert_eq!(acquisition.last_checked_elapsed_micros(), Some(2_123_456));
        let original = (acquisition.origin, acquisition.latest, acquisition.deadline);
        assert!(acquisition.observe(Duration::from_secs(105)).is_err());
        assert_eq!(acquisition.last_checked_elapsed_micros(), Some(2_123_456));
        assert_eq!(
            (acquisition.origin, acquisition.latest, acquisition.deadline),
            original
        );
        assert!(acquisition.remaining().is_err());
        assert!(acquisition.observe(Duration::from_secs(103)).is_err());
    }

    #[test]
    fn one_origin_covers_prior_observation_time_and_cannot_renew() {
        let mut acquisition = NativeAcquisition::fixture(
            Digest::new(b"clock"),
            std::process::id(),
            Duration::from_secs(100),
            Duration::from_secs(5),
        );
        let sample = acquisition.observe(Duration::from_millis(104_900)).unwrap();
        assert_eq!(
            acquisition.deadline - sample.elapsed,
            Duration::from_millis(100)
        );
        assert!(acquisition.observe(Duration::from_secs(105)).is_err());
        assert!(acquisition.observe(Duration::from_secs(101)).is_err());
    }

    #[test]
    fn acquisition_refuses_process_change_before_clock_access() {
        let process = std::process::id().wrapping_add(1);
        let mut acquisition = NativeAcquisition::fixture(
            Digest::new(b"clock"),
            process,
            Duration::ZERO,
            Duration::from_secs(5),
        );
        let error = acquisition.sample().err().unwrap().to_string();
        assert!(error.contains("epoch_native_process_changed"));
        acquisition.process = std::process::id();
        assert!(acquisition.sample().is_err());
    }

    #[test]
    fn narrowed_io_keeps_original_domain_origin_and_spent_time() {
        let mut original = NativeAcquisition::fixture(
            Digest::new(b"original"),
            std::process::id(),
            Duration::from_secs(100),
            Duration::from_secs(5),
        );
        original.fixture_time = Some(Duration::from_millis(104_900));
        let mut child = original.narrow(60, Duration::from_millis(104_950)).unwrap();
        assert_eq!(child.domain, original.domain);
        assert_eq!(child.origin, original.origin);
        assert_eq!(child.remaining().unwrap(), Duration::from_millis(50));
        child.fixture_time = Some(Duration::from_millis(104_950));
        assert!(child.remaining().is_err());
        child.fixture_time = Some(Duration::from_millis(104_910));
        assert!(child.remaining().is_err());
        let mut original_bound = original.narrow(60, Duration::from_secs(200)).unwrap();
        assert_eq!(
            original_bound.remaining().unwrap(),
            Duration::from_millis(100)
        );
        assert!(original.narrow(1, Duration::from_secs(200)).is_err());
        assert!(original.remaining().is_err());
    }

    #[test]
    fn initial_handshake_keeps_spent_time_and_ten_second_equality_refusal() {
        assert_eq!(
            INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT,
            Duration::from_secs(10)
        );
        assert_eq!(MAX_ACQUISITION, Duration::from_secs(5));
        let mut original = NativeAcquisition::fixture(
            Digest::new(b"initial-first-holder"),
            std::process::id(),
            Duration::from_secs(100),
            INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT,
        );
        let mut authentication = original.narrow(5, Duration::from_secs(110)).unwrap();
        assert_eq!(authentication.domain, original.domain);
        assert_eq!(authentication.origin, original.origin);
        authentication.fixture_time = Some(Duration::from_secs(102));
        authentication.remaining().unwrap();
        // Model a successful authentication before spending the remaining
        // original peer interval; a refused child is never a fallback route.
        original.fixture_time = Some(Duration::from_millis(106_300));
        let mut peer = original
            .narrow(
                INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT
                    .as_secs()
                    .try_into()
                    .unwrap(),
                Duration::from_secs(110),
            )
            .unwrap();
        assert_eq!(peer.domain, original.domain);
        assert_eq!(peer.origin, original.origin);
        assert_eq!(peer.remaining().unwrap(), Duration::from_millis(3_700));
        peer.fixture_time = Some(Duration::from_secs(110));
        assert!(peer.remaining().is_err());
        peer.fixture_time = Some(Duration::from_secs(107));
        assert!(peer.remaining().is_err());
        original.fixture_time = Some(Duration::from_secs(110));
        assert!(original.narrow(60, Duration::from_secs(120)).is_err());
        original.fixture_time = Some(Duration::from_secs(101));
        assert!(original.remaining().is_err());
    }

    #[test]
    fn initial_file_cap_and_signed_ceiling_only_narrow_the_original_interval() {
        let mut original = NativeAcquisition::fixture(
            Digest::new(b"initial-file-cap"),
            std::process::id(),
            Duration::from_secs(100),
            INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT,
        );
        original.fixture_time = Some(Duration::from_secs(102));
        let mut configured = original.narrow(3, Duration::from_secs(110)).unwrap();
        assert_eq!(configured.remaining().unwrap(), Duration::from_secs(1));
        configured.fixture_time = Some(Duration::from_secs(103));
        assert!(configured.remaining().is_err());
        let mut signed = original.narrow(30, Duration::from_secs(108)).unwrap();
        assert_eq!(signed.remaining().unwrap(), Duration::from_secs(6));
        assert!(original.narrow(0, Duration::from_secs(110)).is_err());
        assert!(original.remaining().is_err());
        let mut original = NativeAcquisition::fixture(
            Digest::new(b"initial-invalid-file-cap"),
            std::process::id(),
            Duration::from_secs(100),
            INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT,
        );
        assert!(original.narrow(61, Duration::from_secs(110)).is_err());
        assert!(original.remaining().is_err());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platform_never_substitutes_instant_or_wall_time() {
        assert!(NativeAcquisition::begin(5).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_native_boottime_acquisition_is_live_and_private() {
        let mut acquisition = NativeAcquisition::begin(5).unwrap();
        let before = acquisition.sample().unwrap();
        let after = acquisition.sample().unwrap();
        assert_eq!(before.domain, after.domain);
        assert!(after.elapsed >= before.elapsed);
        assert!(acquisition.remaining().unwrap() <= MAX_ACQUISITION);
    }
}
