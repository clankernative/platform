//! Closed restore lease-drain foundation. No genuine approval/complete-stop
//! supplier exists. Controlled tests exercise the same state machine, not native
//! owners. Serializable epoch/fence records and elapsed local time cannot enter.
use anyhow::{Context, Result, ensure};
use day2_capabilities::{Digest, security_epoch::{AuthorityScope, EpochStore}};
use super::{kernel::restore::Intent, restore_approval::{ApprovalRequest, native::{NativeRestoreApproval, ConsumedRestoreApproval}}};
use std::{cell::Cell, marker::PhantomData, rc::Rc};

const MAX_OUTSTANDING: usize = 1024;

/// Exact selection DATA. Matching it never grants stop, restore or writer rights.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Binding {
    pub scope: AuthorityScope,
    pub selection: Digest,
    pub incumbent_root: Digest,
    pub incumbent_holder: Digest,
    pub intent: Digest,
    pub operation: Digest,
    pub binding_generation: u64,
    pub source_epoch: u64,
    pub target_epoch: u64,
    pub target_incarnation: Digest,
}

// Native carries the ACTUAL typed consumed owner, never request/receipt DATA.
// Its origin remains empty in production AND tests until the genuine producer.
enum ApprovalOrigin<'source> {
    Native(ConsumedRestoreApproval<'source>),
    #[cfg(test)]
    UnqualifiedModel,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    Fresh,
    Stopping,
    Waiting,
    Drained,
    Refused,
}

/// No configuration/scalar/record/default constructor, clone, serialization,
/// transfer or renewal. Native input retains its actual short original and the
/// separately checked, signed one-hour approval, without converting UTC scalars.
pub(super) struct Approval<'source> {
    origin: ApprovalOrigin<'source>,
    binding: Binding,
    domain: Digest,
    issued_at: u64,
    expires_at: u64,
    last: Option<(u64, u64)>,
    state: Cell<Disposition>,
    identity: Rc<()>,
    local: PhantomData<Rc<()>>,
}

/// Continuity DATA only. This cannot construct approval, exclusion or a writer;
/// a consuming candidate must still borrow and freshly check the actual Session.
#[derive(Clone)]
pub(super) struct ApprovalIdentity(Rc<()>);
impl ApprovalIdentity {
    pub(super) fn same(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

/// Authenticated common-domain interval DATA from the sealed retained supplier.
/// Its LOWER bound must pass old expiry; its UPPER must stay inside approval.
pub(super) struct Clock {
    binding: Binding,
    domain: Digest,
    lower: u64,
    upper: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Lease,
    FinalPermit,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Identity {
    holder: Digest,
    executor: Digest,
    stage: Digest,
    grant: Digest,
    kind: Kind,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Outstanding {
    identity: Identity,
    expires_upper: u64,
}

// No production variant: a Vec, count, receipt, pidfd or flock cannot construct
// COMPLETE renewal exclusion. A future source must account for in-flight sends,
// every holder/descendant/duplicate/remote right and all final-action permits.
enum StopOrigin {
    #[cfg(test)]
    UnqualifiedModel,
}
pub(super) struct Stopped {
    origin: StopOrigin,
    binding: Binding,
    domain: Digest,
    source: Rc<()>, // continuity only, never authentication
    stop_upper: u64,
    outstanding: Vec<Outstanding>,
}

mod sealed {
    pub trait Source {}
}
/// Only a future retained native source may implement this in production.
/// No default, blanket or production implementation is supplied in this slice.
pub(super) trait Source: sealed::Source {
    fn current(&mut self, approval: &Approval<'_>) -> Result<Clock>;
    /// Atomically exclude new issuance AND renewal, including in-flight sends,
    /// then freeze the complete bounded inventory in one qualified clock domain.
    fn stop(&mut self, approval: &Approval<'_>) -> Result<Stopped>;
    /// Check that the SAME retained source/exclusion remains current; this must
    /// not issue a new cut, resample old deadlines or acquire replacement rights.
    fn check_stopped(&mut self, approval: &Approval<'_>, cut: &Stopped) -> Result<()>;
    /// Terminal local disposition even after expiry, without new IO/permission.
    fn refuse(&mut self);
}

impl<'source> Approval<'source> {
    /// Sole production-shaped entry: consumes Credential's actual typed input.
    /// That type remains uninhabited; this does not implement its producer/CAS.
    /// One-hour signed validity stays inside the native owner. The drain uses
    /// its UNCHANGED short original/domain in nanoseconds, not UTC scalars.
    pub(super) fn consume_native(
        input: NativeRestoreApproval<'source>,
        expected: &ApprovalRequest,
        selected: &EpochStore,
        intent: &Intent,
        binding: Binding,
    ) -> Result<Self> {
        require_native_binding(selected, intent, &binding, expected)?;
        let mut native = input.consume(expected, &binding.operation)?;
        let observed = native.check()?;
        let (domain, origin, deadline) = observed.interval_data();
        let (lower, upper) = observed.observation_data();
        let clock = Clock { binding: binding.clone(), domain: domain.clone(), lower, upper };
        let mut approval = Self {
            origin: ApprovalOrigin::Native(native),
            binding,
            domain: domain.clone(),
            issued_at: origin,
            expires_at: deadline,
            last: None,
            state: Cell::new(Disposition::Fresh),
            identity: Rc::new(()),
            local: PhantomData,
        };
        approval.observe(clock)?;
        Ok(approval)
    }

    fn observe_native(&mut self) -> Result<()> {
        let observation = match &mut self.origin {
            ApprovalOrigin::Native(native) => native.check()?,
            #[cfg(test)]
            ApprovalOrigin::UnqualifiedModel => anyhow::bail!("restore_native_origin_required"),
        };
        let (domain, origin, deadline) = observation.interval_data();
        ensure!(
            domain == &self.domain && origin == self.issued_at && deadline == self.expires_at,
            "restore_native_original_changed"
        );
        let (lower, upper) = observation.observation_data();
        self.observe(Clock { binding: self.binding.clone(), domain: domain.clone(), lower, upper })
    }

    fn refresh(&mut self, source: &mut impl Source) -> Result<()> {
        match &self.origin {
            ApprovalOrigin::Native(_) => {
                self.observe_native()?;
                let result = source.current(self);
                // Mandatory same producer postcheck even on a source failure.
                let post = self.observe_native();
                let clock = result?;
                post?;
                ensure!(clock.binding == self.binding && clock.domain == self.domain,
                    "restore_native_source_clock_domain_changed");
                // The source's scalar bounds cannot replace the actual typed
                // producer observation or freshen the retained original.
                Ok(())
            }
            #[cfg(test)]
            ApprovalOrigin::UnqualifiedModel => {
                let clock = source.current(self)?;
                self.observe(clock)
            }
        }
    }

    fn observe(&mut self, clock: Clock) -> Result<()> {
        ensure!(
            self.state.get() != Disposition::Refused,
            "restore_approval_refused"
        );
        ensure!(
            clock.binding == self.binding && clock.domain == self.domain,
            "restore_fence_binding_or_clock_changed"
        );
        ensure!(
            self.issued_at < self.expires_at
                && self.issued_at <= clock.lower
                && clock.lower <= clock.upper
                && clock.upper < self.expires_at,
            "restore_fence_original_expired_or_invalid"
        );
        ensure!(
            self.last
                .is_none_or(|(lower, upper)| lower <= clock.lower && upper <= clock.upper),
            "restore_fence_clock_rewound"
        );
        self.last = Some((clock.lower, clock.upper));
        Ok(())
    }
    fn refuse(&mut self) {
        self.state.set(Disposition::Refused);
        match &mut self.origin {
            ApprovalOrigin::Native(native) => native.refuse(),
            #[cfg(test)]
            ApprovalOrigin::UnqualifiedModel => {},
        }
    }
}

// Selection DATA checks only. This never constructs approval from an archive,
// caller identity, local timestamp, request hash or stored consumption receipt.
fn require_native_binding(
    selected: &EpochStore,
    intent: &Intent,
    binding: &Binding,
    expected: &ApprovalRequest,
) -> Result<()> {
    selected.validate()?;
    expected.validate()?;
    ensure!(
        expected.target.scope == selected.scope
            && expected.target.authority == selected.authority_key()?
            && expected.target.selection == Digest::of(selected)?
            && expected.full_archive_digest == intent.archive.full_archive_digest
            && expected.target.incarnation == intent.target_incarnation
            && expected.target.artifact == intent.archive.artifact
            && expected.target.schema == intent.archive.schema
            && binding.scope == expected.target.scope
            && binding.selection == expected.target.selection
            && binding.intent == intent.commitment(selected)?
            && binding.operation == intent.operation
            && binding.binding_generation == expected.target.binding_generation
            && binding.source_epoch == intent.archive.security_epoch
            && binding.target_epoch == expected.target.security_epoch
            && binding.source_epoch.checked_add(1) == Some(binding.target_epoch)
            && binding.target_incarnation == expected.target.incarnation,
        "restore_native_target_or_archive_changed"
    );
    Ok(())
}
impl Stopped {
    fn ceiling(&self, approval: &Approval<'_>) -> Result<u64> {
        ensure!(
            self.binding == approval.binding && self.domain == approval.domain,
            "restore_stop_binding_or_clock_changed"
        );
        ensure!(
            self.outstanding.len() <= MAX_OUTSTANDING,
            "restore_stop_inventory_bound"
        );
        let observed = approval.last.context("restore_stop_clock_missing")?;
        ensure!(
            approval.issued_at <= self.stop_upper && self.stop_upper <= observed.1,
            "restore_stop_cut_not_observed"
        );
        let mut previous = None;
        let mut ceiling = self.stop_upper;
        for item in &self.outstanding {
            ensure!(
                previous.is_none_or(|id| id < &item.identity),
                "restore_stop_inventory_duplicate_or_unsorted"
            );
            previous = Some(&item.identity);
            ceiling = ceiling.max(item.expires_upper);
        }
        // Equality cannot fit a fresh observation whose upper bound must be
        // STRICTLY before the one original approval deadline. Never renew it.
        ensure!(
            ceiling < approval.expires_at,
            "restore_original_cannot_cover_drain"
        );
        Ok(ceiling)
    }
}

struct Attempt<'a, 'source, S: Source> {
    approval: &'a mut Approval<'source>,
    source: &'a mut S,
    disarmed: bool,
}
impl<S: Source> Drop for Attempt<'_, '_, S> {
    fn drop(&mut self) {
        if !self.disarmed {
            self.approval.refuse();
            self.source.refuse();
        }
    }
}

/// Historical progress only, never a fence, creator, P3 or new-writer witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WaitStatus {
    Pending { not_before: u64 },
    Drained,
}

/// Retains BOTH original approval and same stop source across every poll. A
/// cached status cannot create this owner or bypass its fresh check.
pub(super) struct Session<'a, 'source, S: Source> {
    approval: &'a mut Approval<'source>,
    source: &'a mut S,
    cut: Stopped,
    ceiling: u64,
}
impl<'a, 'source, S: Source> Session<'a, 'source, S> {
    pub(super) fn begin(approval: &'a mut Approval<'source>, source: &'a mut S) -> Result<Self> {
        let mut guard = Attempt {
            approval: &mut *approval,
            source: &mut *source,
            disarmed: false,
        };
        ensure!(
            guard.approval.state.get() == Disposition::Fresh,
            "restore_approval_already_used"
        );
        ensure!(
            guard.approval.binding.binding_generation > 0
                && guard.approval.binding.source_epoch > 0
                && guard.approval.binding.target_epoch > guard.approval.binding.source_epoch,
            "restore_fence_epoch_binding_invalid"
        );
        guard.approval.refresh(guard.source)?;
        // Known-May boundary BEFORE the possible stop effect. An unknown reply
        // permanently refuses this attempt; no retry or reapplied stop occurs.
        guard.approval.state.set(Disposition::Stopping);
        let result = guard.source.stop(guard.approval);
        let post = guard.approval.refresh(guard.source);
        let cut = result?;
        post?;
        let ceiling = cut.ceiling(guard.approval)?;
        let checked = guard.source.check_stopped(guard.approval, &cut);
        let post = guard.approval.refresh(guard.source);
        checked?;
        post?;
        guard.approval.state.set(Disposition::Waiting);
        guard.disarmed = true;
        drop(guard);
        Ok(Self {
            approval,
            source,
            cut,
            ceiling,
        })
    }
    pub(super) fn poll(&mut self) -> Result<WaitStatus> {
        let cut = &self.cut;
        let ceiling = self.ceiling;
        // A caught panic must poison the SAME still-borrowed session. Session
        // Drop alone is insufficient when the caller retains it after unwind.
        let mut guard = Attempt {
            approval: &mut *self.approval,
            source: &mut *self.source,
            disarmed: false,
        };
        let result = (|| {
            ensure!(
                matches!(
                    guard.approval.state.get(),
                    Disposition::Waiting | Disposition::Drained
                ),
                "restore_fence_session_refused"
            );
            guard.approval.refresh(guard.source)?;
            let checked = guard.source.check_stopped(guard.approval, cut);
            let post = guard.approval.refresh(guard.source);
            checked?;
            post?;
            ensure!(
                cut.ceiling(guard.approval)? == ceiling,
                "restore_stop_inventory_changed"
            );
            let lower = guard.approval.last.context("restore_stop_clock_missing")?.0;
            if lower < ceiling {
                Ok(WaitStatus::Pending {
                    not_before: ceiling,
                })
            } else {
                guard.approval.state.set(Disposition::Drained);
                Ok(WaitStatus::Drained)
            }
        })();
        if result.is_ok() {
            guard.disarmed = true;
        }
        drop(guard);
        result
    }
    /// Call again at the next concrete consuming boundary. A previous Drained
    /// DATA value cannot stand in for this same-original/same-source check.
    pub(super) fn require_drained(&mut self) -> Result<()> {
        let result = self.poll().and_then(|state| {
            ensure!(
                state == WaitStatus::Drained,
                "restore_incumbent_not_drained"
            );
            Ok(())
        });
        if result.is_err() {
            self.approval.refuse();
            self.source.refuse();
        }
        result
    }
    /// No clock sample or permission is issued by this continuity projection.
    pub(super) fn identity(&self) -> ApprovalIdentity {
        ApprovalIdentity(self.approval.identity.clone())
    }
    pub(super) fn require_join(
        &mut self,
        binding: &Binding,
        original: &ApprovalIdentity,
    ) -> Result<()> {
        let result = self.require_drained().and_then(|()| {
            ensure!(
                &self.approval.binding == binding && self.identity().same(original),
                "restore_fence_original_or_target_changed"
            );
            Ok(())
        });
        if result.is_err() {
            self.refuse();
        }
        result
    }
    /// Terminal disposition only; usable after a failed consuming boundary or
    /// caught unwind without new IO, clock acquisition or independent authority.
    pub(super) fn refuse(&mut self) {
        self.approval.refuse();
        self.source.refuse();
    }
}
impl<S: Source> Drop for Session<'_, '_, S> {
    fn drop(&mut self) {
        self.refuse();
    }
}

#[cfg(test)]
pub(super) mod tests;
