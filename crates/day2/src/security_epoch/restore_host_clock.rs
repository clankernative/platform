//! Actual enrolled-owner-bound observations of trusted host time. This sampler
//! is deliberately UNFENCED: only the future actual outside-archive high-water
//! commit can qualify its interval for approval. It creates no grant or signer.
use crate::security_epoch::{
    CurrentControllerStoragePhase, NativeAcquisition,
    native_enrollment::{EnrolledRoleStage, NativeRole, SameEnrolledOwner},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{Digest, security_epoch::AuthorityScope};
use std::time::Duration;

const MAX_UNCERTAINTY: Duration = Duration::from_secs(1);
// A conservative acceptance bound, not an assertion about a configured NTP
// source. A faster/slower observed host clock refuses instead of widening it.
const MAX_RATE_ERROR_PPM: u128 = 1000;

pub(super) struct UnfencedHostClock {
    acquisition: NativeAcquisition,
    same: SameEnrolledOwner,
    domain: Digest,
    tracker: Tracker,
}

/// Actual Controller observations require its retained physical/file/peer
/// phase at capture AND every later use. The inner clock still shares that
/// phase's real original; another phase or an App clock cannot substitute.
/// This is not a ledger writer, qualified high-water or approval owner.
pub(super) struct UnfencedControllerClock {
    clock: UnfencedHostClock,
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<A> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <UnfencedHostClock as Ambiguous<_>>::check;
            let _ = <UnfencedControllerClock as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(Clone);
    assert_not_impl!(Copy);
    assert_not_impl!(Default);
    assert_not_impl!(std::fmt::Debug);
    assert_not_impl!(serde::Serialize);
    assert_not_impl!(serde::Deserialize<'static>);
    assert_not_impl!(Send);
    assert_not_impl!(Sync);
};

/// Observation DATA only. Neither this interval nor its domain can reconstruct
/// the sampler, prove a durable high-water commit or authorize approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct HostTimeData {
    pub domain: Digest,
    pub lower: Duration,
    pub upper: Duration,
    pub observed_at: Duration,
}

impl UnfencedHostClock {
    pub(super) fn capture(
        stage: &mut EnrolledRoleStage<'_>,
        scope: &AuthorityScope,
    ) -> Result<Self> {
        stage.check_for(scope, NativeRole::AppHost)?;
        Self::capture_checked_current(stage)
    }

    // Only the two fixed native constructors in this module can enter here.
    // Neither an arbitrary role selector nor a public bare-stage factory is
    // introduced. SameEnrolledOwner and the actual original remain shared.
    fn capture_checked_current(stage: &mut EnrolledRoleStage<'_>) -> Result<Self> {
        let mut acquisition = stage.narrow_io_acquisition(5)?;
        let result = (|| {
            let same = stage.capture_same_owner()?;
            let domain = acquisition.identity_domain()?;
            Ok((same, domain))
        })();
        let (same, domain) = match result {
            Ok(values) => values,
            Err(error) => {
                acquisition.refuse();
                return Err(error);
            }
        };
        let mut clock = Self {
            acquisition,
            same,
            domain,
            tracker: Tracker::default(),
        };
        clock.observe(stage)?;
        Ok(clock)
    }

    pub(super) fn observe(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<HostTimeData> {
        let result = (|| {
            // This existing meet checks exact shared original/domain/origin,
            // retained enrolled owner, current purpose and the shorter ceiling.
            self.same
                .meet_current_read_view(stage, &mut self.acquisition)?;
            let before = self.acquisition.sample()?.elapsed;
            let utc = realtime()?;
            let after = self.acquisition.sample()?.elapsed;
            self.same
                .meet_current_read_view(stage, &mut self.acquisition)?;
            let end = self.acquisition.sample()?.elapsed;
            let (lower, upper) = self.tracker.observe(before, utc, after, end)?;
            Ok(HostTimeData {
                domain: self.domain.clone(),
                lower,
                upper,
                observed_at: end,
            })
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(super) fn refuse(&mut self) {
        self.acquisition.refuse();
    }
}

impl UnfencedControllerClock {
    pub(super) fn capture(
        phase: &mut CurrentControllerStoragePhase<'_, '_>,
        scope: &AuthorityScope,
    ) -> Result<Self> {
        let captured = (|| -> Result<Self> {
            let stage = phase.controller_stage()?;
            stage.check_for(scope, NativeRole::EpochController)?;
            let clock = UnfencedHostClock::capture_checked_current(stage)?;
            Ok(Self { clock })
        })();
        // Always run the actual physical postcheck, including when sampling
        // failed. Preserve the original sampling error when both refuse.
        let checked = phase.check();
        let result = (|| {
            let mut value: Self = captured?;
            if let Err(error) = checked {
                value.clock.refuse();
                return Err(error);
            }
            Ok(value)
        })();
        if result.is_err() {
            phase.refuse();
        }
        result
    }

    pub(super) fn observe(
        &mut self,
        phase: &mut CurrentControllerStoragePhase<'_, '_>,
    ) -> Result<HostTimeData> {
        let observed = (|| self.clock.observe(phase.controller_stage()?))();
        let checked = phase.check();
        let result = (|| {
            let value = observed?;
            checked?;
            Ok(value)
        })();
        if result.is_err() {
            self.refuse(phase);
        }
        result
    }

    pub(super) fn refuse(&mut self, phase: &mut CurrentControllerStoragePhase<'_, '_>) {
        self.clock.refuse();
        phase.refuse();
    }
}

#[cfg(target_os = "linux")]
fn realtime() -> Result<Duration> {
    let value = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    ensure!(
        value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec),
        "restore_host_clock_value"
    );
    Ok(Duration::new(
        value.tv_sec.try_into()?,
        value.tv_nsec.try_into()?,
    ))
}

#[cfg(not(target_os = "linux"))]
fn realtime() -> Result<Duration> {
    anyhow::bail!("restore_host_clock_platform_unsupported")
}

#[derive(Default)]
struct Tracker {
    previous: Option<Window>,
    refused: bool,
}

struct Window {
    before: Duration,
    offset_lower: i128,
    offset_upper: i128,
    utc: Duration,
    end: Duration,
}

fn rate_error(span: Duration) -> Result<Duration> {
    let nanos = span
        .as_nanos()
        .checked_mul(MAX_RATE_ERROR_PPM)
        .context("restore_host_clock_overflow")?;
    // Round upward so integer division never understates the permitted range.
    let nanos = nanos
        .checked_add(999_999)
        .context("restore_host_clock_overflow")?
        / 1_000_000;
    Ok(Duration::new(
        (nanos / 1_000_000_000).try_into()?,
        (nanos % 1_000_000_000).try_into()?,
    ))
}

impl Tracker {
    fn observe(
        &mut self,
        before: Duration,
        utc: Duration,
        after: Duration,
        end: Duration,
    ) -> Result<(Duration, Duration)> {
        let result = (|| {
            ensure!(
                !self.refused && before <= after && after <= end,
                "restore_host_clock_refused_or_rewound"
            );
            let width = end
                .checked_sub(before)
                .context("restore_host_clock_rewind")?;
            ensure!(width <= MAX_UNCERTAINTY, "restore_host_clock_uncertain");
            let offset_lower = i128::try_from(utc.as_nanos())? - i128::try_from(after.as_nanos())?;
            let offset_upper = i128::try_from(utc.as_nanos())? - i128::try_from(before.as_nanos())?;
            let (offset_lower, offset_upper) = if let Some(prior) = &self.previous {
                ensure!(
                    before >= prior.end && utc >= prior.utc,
                    "restore_host_clock_rewind"
                );
                // Prior offsets describe its actual read bracket, not the
                // later owner postcheck. Bound the largest possible elapsed
                // interval between the two real UTC reads.
                let error = i128::try_from(rate_error(after - prior.before)?.as_nanos())?;
                let low = offset_lower.max(
                    prior
                        .offset_lower
                        .checked_sub(error)
                        .context("restore_host_clock_overflow")?,
                );
                let high = offset_upper.min(
                    prior
                        .offset_upper
                        .checked_add(error)
                        .context("restore_host_clock_overflow")?,
                );
                ensure!(low <= high, "restore_host_clock_discontinuity");
                (low, high)
            } else {
                (offset_lower, offset_upper)
            };
            let drift = rate_error(width)?;
            let lower = utc
                .checked_add(end - after)
                .and_then(|v| v.checked_sub(drift))
                .context("restore_host_clock_overflow")?;
            let upper = utc
                .checked_add(end - before)
                .and_then(|v| v.checked_add(drift))
                .context("restore_host_clock_overflow")?;
            ensure!(
                upper
                    .checked_sub(lower)
                    .is_some_and(|v| v <= MAX_UNCERTAINTY),
                "restore_host_clock_uncertain"
            );
            self.previous = Some(Window {
                before,
                offset_lower,
                offset_upper,
                utc,
                end,
            });
            Ok((lower, upper))
        })();
        if result.is_err() {
            self.refused = true;
        }
        result
    }
}

#[cfg(test)]
mod tests;
