//! Process-local acquisition origin. This observes an actual Linux continuous
//! clock; it does not qualify a runtime profile, workload, file or authority.
//! The serving bootstrap context factory remains unavailable.

use super::firestore::{Budget, Sample};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use std::{cell::Cell, marker::PhantomData, rc::Rc, time::Duration};

const MAX_ACQUISITION: Duration = Duration::from_secs(5);

/// Only the initial first-holder rendezvous/exchange may spend this original
/// interval. The composed path estimate was about 6.3s; the actual former 5s run refused
/// at 5.001s: 2.003s role, 0.017s Ready, 0.985s file, 1.996s peer. The user
/// selected ten seconds without dropping fresh-content checks. Ordinary acquisitions,
/// including the role-authentication subphase, remain capped at five seconds.
pub(in crate::security_epoch) const INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT: Duration =
    Duration::from_secs(10);

/// User-approved ceiling for EACH original storage-bootstrap action only.
/// The 2026-10-23 run spent 7.718s before writer preparation, then exhausted
/// 10s there after all three provider rounds, before its first counter read.
/// Thirty seconds permits qualification of the unmeasured tail; margin is not
/// established until repeated complete actions finish within 24s. Role and
/// provider authentication still share the SAME original origin+5 deadline.
pub(in crate::security_epoch) const STORAGE_BOOTSTRAP_LIMIT: Duration = Duration::from_secs(30);

/// Read-only metadata diagnostics retain their separate existing ten seconds.
/// They cannot create a file, join the bootstrap peer or install a writer.
pub(in crate::security_epoch) const STORAGE_METADATA_OBSERVATION_LIMIT: Duration =
    Duration::from_secs(10);

#[derive(Clone, Copy, PartialEq, Eq)]
enum AcquisitionScope {
    Current,
    InitialFirstHolder,
    StorageBootstrap,
    StorageMetadataObservation,
}

impl AcquisitionScope {
    fn limit(self) -> Duration {
        match self {
            Self::Current => MAX_ACQUISITION,
            Self::InitialFirstHolder => INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT,
            Self::StorageBootstrap => STORAGE_BOOTSTRAP_LIMIT,
            Self::StorageMetadataObservation => STORAGE_METADATA_OBSERVATION_LIMIT,
        }
    }
}

/// One original interval for code, identity, credentials, metadata and epoch I/O.
/// No production scalar/config constructor, clock replacement or renewal exists.
pub(crate) struct NativeAcquisition {
    scope: AcquisitionScope,
    domain: Digest,
    process: u32,
    origin: Duration,
    observation: Rc<Cell<OriginalObservation>>,
    deadline: Duration,
    valid: bool,
    local: PhantomData<Rc<()>>,
    #[cfg(test)]
    fixture_time: Option<Duration>,
}

// Every actual narrowed view shares this original observation, including the
// enrolled role parent. A parent observation is visible BEFORE the next child
// sample/send, not imported only at a later handoff. Refusal cannot be repaired
// by discarding a child or by a later recovering clock. Deadlines remain per
// view and are never widened; this is not a grant or a scalar clock factory.
#[derive(Clone, Copy)]
struct OriginalObservation {
    latest: Duration,
    refused: bool,
}

impl NativeAcquisition {
    /// The first clock read precedes entropy and every subsequent observation.
    /// Linux qualification of the selected deployment profile is a separate gate.
    pub(super) fn begin(max_lease_seconds: u32) -> Result<Self> {
        ensure!(
            (1..=60).contains(&max_lease_seconds),
            "epoch_native_acquisition_bound"
        );
        Self::begin_bounded(
            AcquisitionScope::Current,
            MAX_ACQUISITION.min(Duration::from_secs(u64::from(max_lease_seconds))),
        )
    }

    pub(super) fn begin_initial_first_holder() -> Result<Self> {
        Self::begin_bounded(
            AcquisitionScope::InitialFirstHolder,
            INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT,
        )
    }

    pub(super) fn begin_storage_bootstrap() -> Result<Self> {
        Self::begin_bounded(AcquisitionScope::StorageBootstrap, STORAGE_BOOTSTRAP_LIMIT)
    }

    pub(super) fn begin_storage_metadata_observation() -> Result<Self> {
        Self::begin_bounded(
            AcquisitionScope::StorageMetadataObservation,
            STORAGE_METADATA_OBSERVATION_LIMIT,
        )
    }

    pub(super) fn require_storage_bootstrap(&mut self) -> Result<()> {
        self.require_scope(AcquisitionScope::StorageBootstrap)
    }

    pub(super) fn require_storage_metadata_observation(&mut self) -> Result<()> {
        self.require_scope(AcquisitionScope::StorageMetadataObservation)
    }

    fn require_scope(&mut self, scope: AcquisitionScope) -> Result<()> {
        let result = (|| {
            ensure!(
                self.scope == scope,
                "epoch_native_acquisition_purpose_changed"
            );
            self.sample().map(|_| ())
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn begin_bounded(scope: AcquisitionScope, limit: Duration) -> Result<Self> {
        ensure!(limit <= scope.limit(), "epoch_native_acquisition_bound");
        let origin = boottime()?;
        let process = std::process::id();
        let mut nonce = [0_u8; 32];
        crate::host_inputs::Entropy::fill(&crate::host_inputs::SecureEntropy, &mut nonce)?;
        let domain = Digest::of(&("day2-native-epoch-acquisition-v1", process, nonce))?;
        let deadline = origin
            .checked_add(limit)
            .ok_or_else(|| anyhow::anyhow!("epoch_native_clock_overflow"))?;
        let mut acquisition = Self {
            scope,
            domain,
            process,
            origin,
            observation: Rc::new(Cell::new(OriginalObservation {
                latest: origin,
                refused: false,
            })),
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
        ensure!(
            self.valid && !self.observation.get().refused,
            "epoch_native_acquisition_refused"
        );
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
            self.refuse();
        }
        result
    }

    fn observe(&mut self, now: Duration) -> Result<Sample> {
        let original = self.observation.get();
        ensure!(
            self.valid && !original.refused,
            "epoch_native_acquisition_refused"
        );
        if now < original.latest || now < self.origin || now >= self.deadline {
            self.refuse();
            anyhow::bail!("epoch_native_clock_rewind_or_expired");
        }
        self.observation.set(OriginalObservation {
            latest: now,
            refused: false,
        });
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

    /// Historical DATA from the last successful sample of this SAME original
    /// interval. Does not read a clock, check validity, issue permission or
    /// change refusal/deadline. An expired check may be later than this value.
    /// Another actual narrowed view may have observed it; it does not establish
    /// this handle's last successful I/O or this handle's current validity.
    pub(super) fn last_checked_elapsed_micros(&self) -> Option<u32> {
        self.observation
            .get()
            .latest
            .checked_sub(self.origin)
            .and_then(|elapsed| elapsed.as_micros().try_into().ok())
    }

    /// Historical DATA only, for the packet decision reducer after actual
    /// native pre/postchecks. Never samples, renews or reconstructs this owner.
    pub(super) fn historical_interval_observation(&self) -> (Digest, Duration, Duration, Duration) {
        (
            self.domain.clone(),
            self.origin,
            self.deadline,
            self.observation.get().latest,
        )
    }

    pub(super) fn refuse(&mut self) {
        self.valid = false;
        self.observation.set(OriginalObservation {
            refused: true,
            ..self.observation.get()
        });
    }

    pub(super) fn budget(&mut self) -> Result<Budget> {
        match self.scope {
            AcquisitionScope::StorageBootstrap => Budget::from_storage_bootstrap(self),
            AcquisitionScope::StorageMetadataObservation => {
                self.refuse();
                anyhow::bail!("epoch_native_metadata_budget_refused")
            }
            AcquisitionScope::Current | AcquisitionScope::InitialFirstHolder => {
                Budget::from_native_origin(self.sample()?, self.origin, self.deadline)
            }
        }
    }

    /// Interval DATA for a signature, never a constructor or renewal.
    pub(super) fn interval_data(&mut self) -> Result<(Duration, Duration)> {
        self.sample()?;
        Ok((self.origin, self.deadline))
    }

    /// Join an actual current-role view into retained read material before
    /// the fixed bootstrap writer consumes it. Both are the SAME original
    /// interval; the retained ceiling may only be shorter. Consume the actual
    /// current child and retain its latest sample, never a caller timestamp or
    /// max that could hide a rewind. This cannot extend a five-second stage.
    pub(super) fn join_current_view(&mut self, current: Self) -> Result<()> {
        self.join_view(current, AcquisitionScope::Current)
    }

    pub(super) fn join_storage_bootstrap_view(&mut self, current: Self) -> Result<()> {
        self.join_view(current, AcquisitionScope::StorageBootstrap)
    }

    pub(super) fn join_storage_metadata_observation_view(&mut self, current: Self) -> Result<()> {
        self.join_view(current, AcquisitionScope::StorageMetadataObservation)
    }

    fn join_view(&mut self, mut current: Self, scope: AcquisitionScope) -> Result<()> {
        let result = (|| {
            ensure!(
                self.valid
                    && current.valid
                    && self.scope == scope
                    && current.scope == scope
                    && Rc::ptr_eq(&self.observation, &current.observation)
                    && self.domain == current.domain
                    && self.process == current.process
                    && self.origin == current.origin
                    && self.deadline <= current.deadline
                    && self.deadline > self.origin
                    && current.deadline > current.origin
                    && current.deadline - current.origin <= scope.limit(),
                "epoch_native_current_read_clock_changed"
            );
            let sample = current.sample()?;
            self.observe(sample.elapsed)?;
            self.sample()?;
            Ok(())
        })();
        if result.is_err() {
            current.refuse();
            self.refuse();
        }
        result
    }

    /// Exchange the two ACTUAL current views. Both retain the shorter ceiling
    /// and the exact last observed sample, never a maximum of timestamp DATA.
    /// This permits a shorter legitimate lease without widening either side.
    pub(super) fn exchange_current_views(&mut self, other: &mut Self) -> Result<()> {
        self.exchange_views(other, AcquisitionScope::Current)
    }

    pub(super) fn exchange_storage_bootstrap_views(&mut self, other: &mut Self) -> Result<()> {
        self.exchange_views(other, AcquisitionScope::StorageBootstrap)
    }

    pub(super) fn exchange_storage_metadata_observation_views(
        &mut self,
        other: &mut Self,
    ) -> Result<()> {
        self.exchange_views(other, AcquisitionScope::StorageMetadataObservation)
    }

    fn exchange_views(&mut self, other: &mut Self, scope: AcquisitionScope) -> Result<()> {
        let result = (|| {
            ensure!(
                self.valid
                    && other.valid
                    && self.scope == scope
                    && other.scope == scope
                    && Rc::ptr_eq(&self.observation, &other.observation)
                    && self.domain == other.domain
                    && self.process == other.process
                    && self.origin == other.origin
                    && self.deadline > self.origin
                    && other.deadline > other.origin
                    && self.deadline - self.origin <= scope.limit()
                    && other.deadline - other.origin <= scope.limit(),
                "epoch_native_current_read_clock_changed"
            );
            let ceiling = self.deadline.min(other.deadline);
            self.deadline = ceiling;
            other.deadline = ceiling;
            let incoming = other.sample()?;
            self.observe(incoming.elapsed)?;
            let outgoing = self.sample()?;
            other.observe(outgoing.elapsed)?;
            let checked = other.sample()?;
            self.observe(checked.elapsed)?;
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
            other.refuse();
        }
        result
    }

    /// Consume this actual successful authentication child, retaining its last
    /// observation before the parent can continue. No scalar DATA can advance
    /// this clock, replace its origin, widen a deadline or revive a refusal.
    pub(super) fn complete_authentication(&mut self, mut child: Self) -> Result<()> {
        let result = (|| {
            ensure!(
                self.valid
                    && child.valid
                    && self.scope == child.scope
                    && Rc::ptr_eq(&self.observation, &child.observation)
                    && child.domain == self.domain
                    && child.process == self.process
                    && child.origin == self.origin
                    && child.deadline <= self.deadline
                    && self.deadline > self.origin
                    && self.deadline - self.origin <= self.scope.limit()
                    && child.deadline > child.origin
                    && child.deadline - child.origin <= MAX_ACQUISITION,
                "epoch_native_authentication_clock_changed"
            );
            let sample = child.sample()?;
            self.observe(sample.elapsed)?;
            self.sample()?;
            Ok(())
        })();
        if result.is_err() {
            child.refuse();
            self.refuse();
        }
        result
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
                scope: self.scope,
                domain: self.domain.clone(),
                process: self.process,
                origin: self.origin,
                observation: Rc::clone(&self.observation),
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

    /// Authentication always consumes the first five seconds of THIS origin;
    /// starting a second authentication child cannot restart that interval.
    pub(super) fn narrow_authentication(&mut self) -> Result<Self> {
        self.narrow(5, self.deadline)
    }

    #[cfg(test)]
    pub(super) fn fixture(domain: Digest, process: u32, origin: Duration, limit: Duration) -> Self {
        Self {
            scope: AcquisitionScope::Current,
            domain,
            process,
            origin,
            observation: Rc::new(Cell::new(OriginalObservation {
                latest: origin,
                refused: false,
            })),
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

    fn storage_fixture(scope: AcquisitionScope) -> NativeAcquisition {
        let mut clock = NativeAcquisition::fixture(
            Digest::new(b"storage-bootstrap-clock"),
            std::process::id(),
            Duration::from_secs(100),
            scope.limit(),
        );
        clock.scope = scope;
        clock
    }

    // DATA-only transport schedule over the real budget/clock arithmetic. No
    // native role, physical file, provider identity or positive permission is
    // constructed. Pre/post times represent work inside a guarded exchange.
    struct BudgetTransport {
        clock: NativeAcquisition,
        pre: Duration,
        post: Duration,
        sends: usize,
        selected: Option<Duration>,
        transport_error: bool,
        post_error: bool,
        omit_post_budget: bool,
        status: u16,
        bytes: usize,
    }

    impl super::super::firestore::Port for BudgetTransport {
        fn sample(&mut self) -> Result<Sample> {
            self.clock.sample()
        }

        fn post(
            &mut self,
            _: &str,
            _: &[u8],
            budget: &mut Budget,
            _: usize,
        ) -> Result<super::super::firestore::EpochReply> {
            self.clock.fixture_time = Some(self.pre);
            let timeout = budget
                .remaining_native(&mut self.clock)?
                .min(Duration::from_secs(5));
            self.selected = Some(timeout);
            self.sends += 1;
            self.clock.fixture_time = Some(self.post);
            let requested = if self.transport_error {
                Err(anyhow::anyhow!("original_model_transport_failure"))
            } else {
                Ok(super::super::firestore::EpochReply {
                    status: self.status,
                    body: vec![0; self.bytes],
                })
            };
            let checked = (|| {
                ensure!(!self.post_error, "model_full_postguard_refused");
                if !self.omit_post_budget {
                    budget.remaining_native(&mut self.clock)?;
                }
                Ok::<(), anyhow::Error>(())
            })();
            let reply = requested?;
            checked?;
            Ok(reply)
        }

        fn refuse(&mut self) {
            self.clock.refuse();
        }
    }

    fn budget_transport() -> (Budget, BudgetTransport, NativeAcquisition) {
        let mut clock = storage_fixture(AcquisitionScope::StorageBootstrap);
        let sample = clock.sample().unwrap();
        let budget =
            Budget::from_native_origin(sample, clock.origin, clock.origin + Duration::from_secs(5))
                .unwrap();
        let sibling = clock.narrow(60, clock.deadline).unwrap();
        (
            budget,
            BudgetTransport {
                clock,
                pre: Duration::from_secs(101),
                post: Duration::from_secs(102),
                sends: 0,
                selected: None,
                transport_error: false,
                post_error: false,
                omit_post_budget: false,
                status: 200,
                bytes: 0,
            },
            sibling,
        )
    }

    #[test]
    fn transport_charges_preguard_work_to_shorter_caller_budget_before_send() {
        for millis in [104_999, 105_000, 106_000] {
            let (mut budget, mut port, mut sibling) = budget_transport();
            port.pre = Duration::from_millis(millis);
            port.post = port.pre;
            // The parent really remains live beyond the caller's five seconds.
            port.clock.fixture_time = Some(port.pre);
            assert!(port.clock.sample().is_ok());
            let result = budget.call(&mut port, "fixed-data-model", &[]);
            if millis < 105_000 {
                assert!(result.is_ok());
                assert_eq!(port.sends, 1);
                assert_eq!(port.selected, Some(Duration::from_millis(1)));
            } else {
                assert!(result.is_err());
                assert_eq!(port.sends, 0);
                assert_eq!(
                    sibling.sample().err().unwrap().to_string(),
                    "epoch_native_acquisition_refused"
                );
            }
            assert_eq!(port.clock.deadline, Duration::from_secs(130));
        }
    }

    #[test]
    fn transport_full_postwork_and_missing_post_budget_cannot_escape_expiry() {
        for omit_post_budget in [false, true] {
            let (mut budget, mut port, mut sibling) = budget_transport();
            port.post = Duration::from_secs(105);
            port.omit_post_budget = omit_post_budget;
            assert!(budget.call(&mut port, "fixed-data-model", &[]).is_err());
            assert_eq!(port.sends, 1);
            // Catching the error and restoring a clock cannot revive either
            // actual narrowed view of the original DATA clock.
            port.clock.fixture_time = Some(Duration::from_secs(102));
            assert!(budget.call(&mut port, "fixed-data-model", &[]).is_err());
            assert_eq!(port.sends, 1);
            assert_eq!(
                sibling.sample().err().unwrap().to_string(),
                "epoch_native_acquisition_refused"
            );
        }
    }

    #[test]
    fn transport_budget_domain_rewind_and_response_contract_failures_refuse_siblings() {
        for fault in [
            "domain",
            "rewind",
            "status",
            "size",
            "request-size",
            "postguard",
        ] {
            let (mut budget, mut port, mut sibling) = budget_transport();
            let mut body = Vec::new();
            match fault {
                "domain" => {
                    budget = Budget::from_native_origin(
                        Sample {
                            domain: Digest::new(b"foreign-data-clock"),
                            elapsed: Duration::from_secs(100),
                        },
                        Duration::from_secs(100),
                        Duration::from_secs(105),
                    )
                    .unwrap()
                }
                "rewind" => {
                    port.clock.fixture_time = Some(Duration::from_secs(102));
                    budget.remaining_native(&mut port.clock).unwrap();
                }
                "status" => port.status = 503,
                "size" => port.bytes = 65_537,
                "request-size" => body = vec![0; 65_537],
                _ => port.post_error = true,
            }
            assert!(
                budget.call(&mut port, "fixed-data-model", &body).is_err(),
                "{fault}"
            );
            assert_eq!(
                port.sends,
                usize::from(matches!(fault, "status" | "size" | "postguard")),
                "{fault}"
            );
            assert!(sibling.sample().is_err(), "{fault}");
        }
    }

    #[test]
    fn attempted_transport_preserves_first_error_over_postguard_refusal() {
        let (mut budget, mut port, mut sibling) = budget_transport();
        port.transport_error = true;
        port.post_error = true;
        assert_eq!(
            budget
                .call(&mut port, "fixed-data-model", &[])
                .unwrap_err()
                .to_string(),
            "original_model_transport_failure"
        );
        assert_eq!(port.sends, 1);
        assert!(sibling.sample().is_err());
    }

    #[test]
    fn both_storage_authentication_children_spend_the_first_original_five_seconds() {
        for scope in [
            AcquisitionScope::StorageBootstrap,
            AcquisitionScope::StorageMetadataObservation,
        ] {
            let mut parent = storage_fixture(scope);
            match scope {
                AcquisitionScope::StorageBootstrap => parent.require_storage_bootstrap().unwrap(),
                AcquisitionScope::StorageMetadataObservation => {
                    parent.require_storage_metadata_observation().unwrap();
                }
                _ => unreachable!(),
            }
            let mut role_authentication = parent.narrow_authentication().unwrap();
            role_authentication.fixture_time = Some(Duration::from_millis(103_063));
            parent.fixture_time = role_authentication.fixture_time;
            parent.complete_authentication(role_authentication).unwrap();
            let mut provider_authentication = parent.narrow_authentication().unwrap();
            assert_eq!(provider_authentication.origin, parent.origin);
            assert_eq!(provider_authentication.deadline, Duration::from_secs(105));
            assert_eq!(
                provider_authentication.remaining().unwrap(),
                Duration::from_millis(1_937)
            );
            provider_authentication.fixture_time = Some(Duration::from_millis(104_255));
            parent.fixture_time = provider_authentication.fixture_time;
            parent
                .complete_authentication(provider_authentication)
                .unwrap();
            // The completed authentication child is gone. Subsequent I/O is
            // derived from THIS actual parent, never by widening that child.
            let mut io = parent.narrow(30, parent.deadline).unwrap();
            io.fixture_time = Some(Duration::from_millis(106_300));
            parent.fixture_time = io.fixture_time;
            match scope {
                AcquisitionScope::StorageBootstrap => {
                    parent.join_storage_bootstrap_view(io).unwrap();
                }
                AcquisitionScope::StorageMetadataObservation => {
                    parent.join_storage_metadata_observation_view(io).unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(
                parent.remaining().unwrap(),
                scope.limit() - Duration::from_millis(6_300)
            );
            assert_eq!(parent.origin, Duration::from_secs(100));
            assert_eq!(parent.deadline, parent.origin + scope.limit());
        }
    }

    #[test]
    fn bootstrap_peer_wait_cannot_defer_provider_authentication_past_original_five_seconds() {
        for elapsed in [Duration::from_secs(5), Duration::from_millis(6_300)] {
            let mut parent = storage_fixture(AcquisitionScope::StorageBootstrap);
            let mut role = parent.narrow_authentication().unwrap();
            role.fixture_time = Some(parent.origin + Duration::from_millis(1_400));
            parent.fixture_time = role.fixture_time;
            parent.complete_authentication(role).unwrap();
            // The bootstrap interval itself is still live. A peer wait is not
            // authentication completion and cannot issue a new five seconds.
            parent.fixture_time = Some(parent.origin + elapsed);
            assert!(parent.remaining().is_ok());
            let error = parent.narrow_authentication().err().unwrap();
            assert_eq!(
                error.to_string(),
                "epoch_native_narrowed_acquisition_expired"
            );
            assert!(parent.remaining().is_err());
        }

        let mut parent = storage_fixture(AcquisitionScope::StorageBootstrap);
        let mut role = parent.narrow_authentication().unwrap();
        role.fixture_time = Some(parent.origin + Duration::from_millis(1_400));
        parent.fixture_time = role.fixture_time;
        parent.complete_authentication(role).unwrap();
        let mut provider = parent.narrow_authentication().unwrap();
        provider.fixture_time = Some(parent.origin + Duration::from_millis(2_300));
        parent.fixture_time = provider.fixture_time;
        parent.complete_authentication(provider).unwrap();
        // Authenticate first, consume that actual successful child, then spend
        // peer/file I/O time on the same original bootstrap parent.
        let mut io = parent.narrow(30, parent.deadline).unwrap();
        io.fixture_time = Some(parent.origin + Duration::from_millis(6_300));
        parent.fixture_time = io.fixture_time;
        parent.join_storage_bootstrap_view(io).unwrap();
        assert_eq!(parent.remaining().unwrap(), Duration::from_millis(23_700));
        parent.fixture_time = Some(parent.origin + STORAGE_BOOTSTRAP_LIMIT);
        assert!(parent.remaining().is_err());
    }

    #[test]
    fn storage_authentication_expiry_or_foreign_kind_permanently_refuses_parent() {
        for scope in [
            AcquisitionScope::StorageBootstrap,
            AcquisitionScope::StorageMetadataObservation,
        ] {
            for changed in ["equality", "foreign_kind", "wider_child", "rewind"] {
                let mut parent = storage_fixture(scope);
                let mut child = parent.narrow_authentication().unwrap();
                child.fixture_time = Some(Duration::from_millis(104_900));
                parent.fixture_time = child.fixture_time;
                match changed {
                    "equality" => child.fixture_time = Some(Duration::from_secs(105)),
                    "foreign_kind" => child.scope = AcquisitionScope::Current,
                    "wider_child" => child.deadline = Duration::from_secs(106),
                    "rewind" => parent.fixture_time = Some(Duration::from_millis(104_800)),
                    _ => unreachable!(),
                }
                assert!(parent.complete_authentication(child).is_err(), "{changed}");
                parent.fixture_time = Some(Duration::from_secs(106));
                assert!(parent.remaining().is_err());
                parent.fixture_time = Some(Duration::from_secs(101));
                assert!(parent.narrow_authentication().is_err());
            }
        }
    }

    #[test]
    fn storage_views_cannot_alias_current_or_each_other_even_with_short_deadlines() {
        for scope in [
            AcquisitionScope::StorageBootstrap,
            AcquisitionScope::StorageMetadataObservation,
        ] {
            let mut original = storage_fixture(scope);
            let mut current_candidate = original.narrow(4, Duration::from_secs(104)).unwrap();
            let child = original.narrow(4, Duration::from_secs(104)).unwrap();
            // Every non-purpose identity and <=5 ceiling is valid. Refusal
            // must be caused by the actual private purpose, not a long clock.
            assert!(current_candidate.join_current_view(child).is_err());
            assert!(original.remaining().is_err());

            let mut parent = storage_fixture(scope);
            let mut child = parent.narrow(4, Duration::from_secs(104)).unwrap();
            child.scope = if scope == AcquisitionScope::StorageBootstrap {
                AcquisitionScope::StorageMetadataObservation
            } else {
                AcquisitionScope::StorageBootstrap
            };
            let result = match scope {
                AcquisitionScope::StorageBootstrap => {
                    parent.exchange_storage_bootstrap_views(&mut child)
                }
                AcquisitionScope::StorageMetadataObservation => {
                    parent.exchange_storage_metadata_observation_views(&mut child)
                }
                _ => unreachable!(),
            };
            assert!(result.is_err());
            assert!(parent.remaining().is_err());
            assert!(child.remaining().is_err());
        }
    }

    #[test]
    fn storage_exchange_retains_shorter_cap_and_shared_latest_observation() {
        for scope in [
            AcquisitionScope::StorageBootstrap,
            AcquisitionScope::StorageMetadataObservation,
        ] {
            let mut parent = storage_fixture(scope);
            let mut other = parent.narrow(8, Duration::from_secs(110)).unwrap();
            parent.fixture_time = Some(Duration::from_millis(106_300));
            other.fixture_time = parent.fixture_time;
            match scope {
                AcquisitionScope::StorageBootstrap => {
                    parent.exchange_storage_bootstrap_views(&mut other).unwrap();
                }
                AcquisitionScope::StorageMetadataObservation => {
                    parent
                        .exchange_storage_metadata_observation_views(&mut other)
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(parent.deadline, Duration::from_secs(108));
            assert_eq!(other.deadline, parent.deadline);
            assert_eq!(parent.remaining().unwrap(), Duration::from_millis(1_700));
            other.fixture_time = Some(Duration::from_millis(106_299));
            assert!(other.remaining().is_err());
            assert!(parent.remaining().is_err());
        }
    }

    #[test]
    fn storage_deadline_and_shorter_caps_refuse_equality_without_recovery() {
        assert_eq!(STORAGE_BOOTSTRAP_LIMIT, Duration::from_secs(30));
        assert_eq!(STORAGE_METADATA_OBSERVATION_LIMIT, Duration::from_secs(10));
        assert_eq!(
            INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT,
            Duration::from_secs(10)
        );
        assert_eq!(MAX_ACQUISITION, Duration::from_secs(5));
        for scope in [
            AcquisitionScope::StorageBootstrap,
            AcquisitionScope::StorageMetadataObservation,
        ] {
            for seconds in [7, scope.limit().as_secs().try_into().unwrap()] {
                let mut parent = storage_fixture(scope);
                let mut child = parent.narrow(seconds, parent.deadline).unwrap();
                let original = (child.domain.clone(), child.origin, child.deadline);
                child.fixture_time = Some(Duration::from_secs(100 + u64::from(seconds)));
                assert!(child.remaining().is_err());
                child.fixture_time = Some(Duration::from_secs(101));
                assert!(child.remaining().is_err());
                assert_eq!((child.domain, child.origin, child.deadline), original);
                assert!(parent.remaining().is_err());
            }
        }
    }

    #[test]
    fn only_bootstrap_spends_thirty_seconds_and_every_original_deadline_is_exclusive() {
        for (scope, seconds) in [
            (AcquisitionScope::Current, 5),
            (AcquisitionScope::InitialFirstHolder, 10),
            (AcquisitionScope::StorageMetadataObservation, 10),
            (AcquisitionScope::StorageBootstrap, 30),
        ] {
            assert_eq!(scope.limit(), Duration::from_secs(seconds));
            let mut clock = storage_fixture(scope);
            let identity = (clock.domain.clone(), clock.origin, clock.deadline);
            clock.fixture_time = Some(clock.deadline - Duration::from_nanos(1));
            assert_eq!(clock.remaining().unwrap(), Duration::from_nanos(1));
            clock.fixture_time = Some(clock.deadline);
            assert!(clock.remaining().is_err());
            clock.fixture_time = Some(clock.origin + Duration::from_secs(1));
            assert!(clock.remaining().is_err());
            assert_eq!((clock.domain, clock.origin, clock.deadline), identity);
        }
        let mut bootstrap = storage_fixture(AcquisitionScope::StorageBootstrap);
        bootstrap.fixture_time = Some(bootstrap.origin + Duration::from_secs(11));
        assert_eq!(bootstrap.remaining().unwrap(), Duration::from_secs(19));
        // A live bootstrap purpose cannot start late provider authentication.
        assert!(bootstrap.narrow_authentication().is_err());
        assert!(bootstrap.remaining().is_err());
    }

    #[test]
    fn storage_scope_requirement_refuses_same_length_wrong_purpose_permanently() {
        let mut initial = storage_fixture(AcquisitionScope::InitialFirstHolder);
        assert!(initial.require_storage_bootstrap().is_err());
        assert!(initial.remaining().is_err());
        let mut actual = storage_fixture(AcquisitionScope::StorageBootstrap);
        assert!(actual.require_storage_metadata_observation().is_err());
        assert!(actual.require_storage_bootstrap().is_err());
        let mut diagnostic = storage_fixture(AcquisitionScope::StorageMetadataObservation);
        assert!(diagnostic.require_storage_bootstrap().is_err());
        assert!(diagnostic.require_storage_metadata_observation().is_err());
    }

    #[test]
    fn storage_epoch_budget_requires_actual_bootstrap_clock_and_retains_spent_time() {
        let mut actual = storage_fixture(AcquisitionScope::StorageBootstrap);
        actual.fixture_time = Some(Duration::from_millis(106_300));
        let mut budget = actual.budget().unwrap();
        assert_eq!(
            budget.remaining_native(&mut actual).unwrap(),
            Duration::from_millis(23_700)
        );
        actual.fixture_time = Some(Duration::from_secs(130));
        assert!(budget.remaining_native(&mut actual).is_err());
        assert!(actual.remaining().is_err());

        let mut diagnostic = storage_fixture(AcquisitionScope::StorageMetadataObservation);
        assert!(diagnostic.budget().is_err());
        assert!(diagnostic.remaining().is_err());

        let mut current = NativeAcquisition::fixture(
            Digest::new(b"ordinary-budget"),
            std::process::id(),
            Duration::from_secs(100),
            Duration::from_secs(5),
        );
        assert!(Budget::from_storage_bootstrap(&mut current).is_err());
        assert!(current.remaining().is_err());
    }

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
        let original = (
            acquisition.origin,
            acquisition.observation.get().latest,
            acquisition.deadline,
        );
        assert!(acquisition.observe(Duration::from_secs(105)).is_err());
        assert_eq!(acquisition.last_checked_elapsed_micros(), Some(2_123_456));
        assert_eq!(
            (
                acquisition.origin,
                acquisition.observation.get().latest,
                acquisition.deadline
            ),
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
    fn bootstrap_read_handoff_preserves_spent_time_and_shorter_original_ceiling() {
        for retained_seconds in [4, 5] {
            let origin = Duration::from_secs(100);
            let mut current = NativeAcquisition::fixture(
                Digest::new(b"same-current"),
                std::process::id(),
                origin,
                Duration::from_secs(5),
            );
            let mut retained = current
                .narrow(
                    retained_seconds.try_into().unwrap(),
                    origin + Duration::from_secs(5),
                )
                .unwrap();
            let now = origin + Duration::from_millis(retained_seconds * 1000 - 100);
            retained.fixture_time = Some(now);
            current.fixture_time = Some(now);
            let expected = (retained.domain.clone(), retained.origin, retained.deadline);
            retained.join_current_view(current).unwrap();
            assert_eq!(
                (retained.domain.clone(), retained.origin, retained.deadline),
                expected
            );
            assert_eq!(retained.remaining().unwrap(), Duration::from_millis(100));
            retained.fixture_time = Some(retained.deadline);
            assert!(retained.remaining().is_err());
            retained.fixture_time = Some(now);
            assert!(retained.remaining().is_err());
        }
    }

    #[test]
    fn bootstrap_read_handoff_refuses_replacement_wider_or_initial_interval() {
        for changed in 0..8 {
            let origin = Duration::from_secs(100);
            let mut retained = NativeAcquisition::fixture(
                Digest::new(b"same-current"),
                std::process::id(),
                origin,
                Duration::from_secs(5),
            );
            let mut current = retained.narrow(5, origin + Duration::from_secs(5)).unwrap();
            match changed {
                0 => current.domain = Digest::new(b"later-stage-same-owner"),
                1 => current.origin += Duration::from_millis(1),
                2 => current.process = current.process.wrapping_add(1),
                3 => current.deadline -= Duration::from_millis(1),
                4 => retained.refuse(),
                5 => current.refuse(),
                6 => current.deadline = origin + INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT,
                7 => retained.deadline = origin,
                _ => unreachable!(),
            }
            assert!(
                retained.join_current_view(current).is_err(),
                "case {changed}"
            );
            retained.fixture_time = Some(origin);
            assert!(retained.remaining().is_err(), "case {changed}");
        }
    }

    #[test]
    fn bootstrap_read_handoff_cannot_mask_current_to_retained_rewind() {
        let origin = Duration::from_secs(100);
        let mut retained = NativeAcquisition::fixture(
            Digest::new(b"same-current"),
            std::process::id(),
            origin,
            Duration::from_secs(5),
        );
        let mut current = retained.narrow(5, origin + Duration::from_secs(5)).unwrap();
        retained.fixture_time = Some(Duration::from_millis(104_000));
        current.fixture_time = Some(Duration::from_millis(104_500));
        assert!(retained.join_current_view(current).is_err());
        assert_eq!(
            retained.observation.get().latest,
            Duration::from_millis(104_500)
        );
        retained.fixture_time = Some(Duration::from_millis(104_750));
        assert!(retained.remaining().is_err());
    }

    #[test]
    fn bootstrap_read_handoff_refuses_equality_in_either_actual_interval() {
        for expire_retained in [false, true] {
            let origin = Duration::from_secs(100);
            let mut retained = NativeAcquisition::fixture(
                Digest::new(b"same-current"),
                std::process::id(),
                origin,
                Duration::from_secs(5),
            );
            let mut current = retained.narrow(5, origin + Duration::from_secs(5)).unwrap();
            retained.fixture_time = Some(if expire_retained {
                retained.deadline
            } else {
                origin
            });
            current.fixture_time = Some(if expire_retained {
                origin
            } else {
                current.deadline
            });
            assert!(retained.join_current_view(current).is_err());
            retained.fixture_time = Some(origin);
            assert!(retained.remaining().is_err());
        }
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
        let mut original_bound = original.narrow(60, Duration::from_secs(200)).unwrap();
        assert_eq!(
            original_bound.remaining().unwrap(),
            Duration::from_millis(100)
        );
        child.fixture_time = Some(Duration::from_millis(104_950));
        assert!(child.remaining().is_err());
        child.fixture_time = Some(Duration::from_millis(104_910));
        assert!(child.remaining().is_err());
        assert!(original_bound.remaining().is_err());
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
        original.scope = AcquisitionScope::InitialFirstHolder;
        let mut authentication = original.narrow(5, Duration::from_secs(110)).unwrap();
        assert_eq!(authentication.domain, original.domain);
        assert_eq!(authentication.origin, original.origin);
        authentication.fixture_time = Some(Duration::from_secs(102));
        original.fixture_time = Some(Duration::from_secs(102));
        original.complete_authentication(authentication).unwrap();
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
        original.scope = AcquisitionScope::InitialFirstHolder;
        original.fixture_time = Some(Duration::from_secs(102));
        let mut configured = original.narrow(3, Duration::from_secs(110)).unwrap();
        assert_eq!(configured.remaining().unwrap(), Duration::from_secs(1));
        let mut signed = original.narrow(30, Duration::from_secs(108)).unwrap();
        assert_eq!(signed.remaining().unwrap(), Duration::from_secs(6));
        configured.fixture_time = Some(Duration::from_secs(103));
        assert!(configured.remaining().is_err());
        assert!(signed.remaining().is_err());
        assert!(original.narrow(0, Duration::from_secs(110)).is_err());
        assert!(original.remaining().is_err());
        let mut original = NativeAcquisition::fixture(
            Digest::new(b"initial-invalid-file-cap"),
            std::process::id(),
            Duration::from_secs(100),
            INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT,
        );
        original.scope = AcquisitionScope::InitialFirstHolder;
        assert!(original.narrow(61, Duration::from_secs(110)).is_err());
        assert!(original.remaining().is_err());
    }

    #[test]
    fn authentication_handoff_keeps_its_last_sample_and_refuses_an_intervening_rewind() {
        for limit in [MAX_ACQUISITION, INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT] {
            for (parent_now, accepted) in [(104_950, true), (104_800, false)] {
                let mut original = NativeAcquisition::fixture(
                    Digest::new(b"authentication-handoff"),
                    std::process::id(),
                    Duration::from_secs(100),
                    limit,
                );
                if limit == INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT {
                    original.scope = AcquisitionScope::InitialFirstHolder;
                }
                let mut child = original.narrow(5, Duration::from_secs(110)).unwrap();
                child.fixture_time = Some(Duration::from_millis(104_900));
                original.fixture_time = Some(Duration::from_millis(parent_now));
                assert_eq!(original.complete_authentication(child).is_ok(), accepted);
                assert_eq!(original.deadline, Duration::from_secs(100) + limit);
                if accepted {
                    assert_eq!(
                        original.observation.get().latest,
                        Duration::from_millis(parent_now)
                    );
                    original.fixture_time = Some(Duration::from_millis(104_925));
                    assert!(original.remaining().is_err());
                }
                assert!(original.remaining().is_err());
            }
        }
    }

    #[test]
    fn failed_or_foreign_authentication_cannot_fall_back_to_a_live_parent() {
        for refusal in [
            "expired_child",
            "expired_parent",
            "refused_child",
            "refused_parent",
            "domain",
            "origin",
            "process",
            "longer_child",
            "parent_ahead",
        ] {
            let mut original = NativeAcquisition::fixture(
                Digest::new(b"authentication-refusal"),
                std::process::id(),
                Duration::from_secs(100),
                INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT,
            );
            original.scope = AcquisitionScope::InitialFirstHolder;
            let mut child = original.narrow(5, Duration::from_secs(110)).unwrap();
            original.fixture_time = Some(Duration::from_secs(106));
            child.fixture_time = Some(Duration::from_secs(104));
            match refusal {
                "expired_child" => child.fixture_time = Some(Duration::from_secs(105)),
                "expired_parent" => original.fixture_time = Some(Duration::from_secs(110)),
                "refused_child" => child.refuse(),
                "refused_parent" => original.refuse(),
                "domain" => child.domain = Digest::new(b"another-original"),
                "origin" => child.origin += Duration::from_millis(1),
                "process" => child.process = child.process.wrapping_add(1),
                "longer_child" => child.deadline = Duration::from_secs(106),
                "parent_ahead" => {
                    original.observe(Duration::from_millis(104_500)).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                original.complete_authentication(child).is_err(),
                "{refusal}"
            );
            // Without the join this parent could remain live until 110. An
            // expired/refused child cannot fall back to it or move time back.
            assert!(original.remaining().is_err());
            original.fixture_time = Some(Duration::from_secs(102));
            assert!(original.remaining().is_err());
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platform_never_substitutes_instant_or_wall_time() {
        assert!(NativeAcquisition::begin(5).is_err());
    }

    #[test]
    fn shared_current_views_keep_spent_time_and_accept_either_shorter_ceiling() {
        for (left, right) in [(1, 5), (5, 1), (3, 5), (5, 3)] {
            let origin = Duration::from_secs(100);
            let mut original = NativeAcquisition::fixture(
                Digest::new(b"same"),
                std::process::id(),
                origin,
                MAX_ACQUISITION,
            );
            let mut a = original.narrow(left, origin + MAX_ACQUISITION).unwrap();
            let mut b = original.narrow(right, origin + MAX_ACQUISITION).unwrap();
            a.fixture_time = Some(origin + Duration::from_millis(500));
            b.fixture_time = a.fixture_time;
            a.exchange_current_views(&mut b).unwrap();
            let ceiling = origin + Duration::from_secs(u64::from(left.min(right)));
            assert_eq!((a.origin, b.origin), (origin, origin));
            assert_eq!((a.deadline, b.deadline), (ceiling, ceiling));
            assert_eq!(a.observation.get().latest, b.observation.get().latest);
            assert_eq!(
                a.remaining().unwrap(),
                Duration::from_secs(u64::from(left.min(right))) - Duration::from_millis(500)
            );
            a.fixture_time = Some(ceiling);
            b.fixture_time = Some(ceiling);
            assert!(a.exchange_current_views(&mut b).is_err());
            a.fixture_time = Some(origin);
            b.fixture_time = Some(origin);
            assert!(a.remaining().is_err());
            assert!(b.remaining().is_err());
        }
    }

    #[test]
    fn shared_views_reject_foreign_refused_and_initial_intervals_permanently() {
        for case in 0..7 {
            let origin = Duration::from_secs(100);
            let mut a = NativeAcquisition::fixture(
                Digest::new(b"same"),
                std::process::id(),
                origin,
                Duration::from_secs(5),
            );
            let mut b = a.narrow(5, origin + Duration::from_secs(5)).unwrap();
            match case {
                0 => b.domain = Digest::new(b"other"),
                1 => b.process = b.process.wrapping_add(1),
                2 => b.origin += Duration::from_secs(1),
                3 => b.refuse(),
                4 => a.refuse(),
                5 => b.deadline = origin + INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT,
                _ => a.deadline = origin,
            }
            assert!(a.exchange_current_views(&mut b).is_err());
            assert!(a.remaining().is_err());
            assert!(b.remaining().is_err());
        }
    }

    #[test]
    fn shared_views_cannot_mask_either_last_sample_with_a_maximum() {
        for later_left in [false, true] {
            let origin = Duration::from_secs(100);
            let mut a = NativeAcquisition::fixture(
                Digest::new(b"same"),
                std::process::id(),
                origin,
                Duration::from_secs(5),
            );
            let mut b = a.narrow(5, origin + Duration::from_secs(5)).unwrap();
            if later_left {
                a.observe(origin + Duration::from_millis(4500)).unwrap();
            } else {
                b.observe(origin + Duration::from_millis(4500)).unwrap();
            }
            a.fixture_time = Some(origin + Duration::from_millis(4250));
            b.fixture_time = a.fixture_time;
            assert!(a.exchange_current_views(&mut b).is_err());
            assert!(a.remaining().is_err());
            assert!(b.remaining().is_err());
        }
    }

    #[test]
    fn three_actual_views_refuse_the_first_rewind_before_send_budget_or_interval() {
        // Pure clock DATA only: no fabricated role, process observation, peer,
        // authenticated owner, successful request or native lifecycle proof.
        for advanced in 0..3 {
            for resumed in 0..3 {
                let origin = Duration::from_secs(100);
                let mut role = NativeAcquisition::fixture(
                    Digest::new(b"one-actual-origin"),
                    std::process::id(),
                    origin,
                    MAX_ACQUISITION,
                );
                let authenticated = role.narrow(5, origin + MAX_ACQUISITION).unwrap();
                let provider = role.narrow(5, origin + MAX_ACQUISITION).unwrap();
                let mut views = [role, authenticated, provider];
                for view in &mut views {
                    view.fixture_time = Some(origin + Duration::from_millis(3800));
                    view.sample().unwrap();
                }
                // ONLY one real view observes 4.000. The others would have
                // accepted 3.900 under the former copied-latest design.
                views[advanced].fixture_time = Some(origin + Duration::from_millis(4000));
                views[advanced].sample().unwrap();
                views[resumed].fixture_time = Some(origin + Duration::from_millis(3900));
                let mut sends = 0;
                let requested: Result<()> = (|| {
                    match resumed {
                        0 => {
                            views[resumed].sample()?;
                        }
                        1 => {
                            views[resumed].budget()?;
                        }
                        _ => {
                            views[resumed].interval_data()?;
                        }
                    }
                    sends += 1;
                    Ok(())
                })();
                assert!(requested.is_err(), "advanced {advanced}, resumed {resumed}");
                assert_eq!(sends, 0);
                for view in &mut views {
                    view.fixture_time = Some(origin + Duration::from_millis(4100));
                    assert!(view.remaining().is_err());
                }
            }
        }
    }

    #[test]
    fn matching_data_cannot_reconstruct_the_private_original_state_at_any_handoff() {
        for handoff in 0..3 {
            let origin = Duration::from_secs(100);
            let mut parent = NativeAcquisition::fixture(
                Digest::new(b"identical-data"),
                std::process::id(),
                origin,
                MAX_ACQUISITION,
            );
            let mut foreign = NativeAcquisition::fixture(
                parent.domain.clone(),
                parent.process,
                parent.origin,
                MAX_ACQUISITION,
            );
            let foreign_state = Rc::clone(&foreign.observation);
            assert!(!Rc::ptr_eq(&parent.observation, &foreign.observation));
            let result = match handoff {
                0 => parent.join_current_view(foreign),
                1 => parent.complete_authentication(foreign),
                _ => parent.exchange_current_views(&mut foreign),
            };
            assert!(result.is_err());
            assert!(parent.remaining().is_err());
            assert!(foreign_state.get().refused);
        }
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
