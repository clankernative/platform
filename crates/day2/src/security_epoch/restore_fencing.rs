//! Closed restore lease-drain foundation. No production approval/complete-stop
//! supplier exists. Controlled tests exercise the same state machine, not native
//! owners. Serializable epoch/fence records and elapsed local time cannot enter.
use anyhow::{Context,Result,ensure};
use day2_capabilities::{Digest,security_epoch::AuthorityScope};
use std::{cell::Cell,marker::PhantomData,rc::Rc};

const MAX_OUTSTANDING:usize=1024;

/// Exact selection DATA. Matching it never grants stop, restore or writer rights.
#[derive(Clone,Debug,PartialEq,Eq)]
pub(super) struct Binding {
    pub scope:AuthorityScope,
    pub selection:Digest,
    pub incumbent_root:Digest,
    pub incumbent_holder:Digest,
    pub intent:Digest,
    pub target_incarnation:Digest,
}

// Deliberately UNINHABITED in production. Adding a genuine supplier must retain
// its actual authenticated approval/original owner here, not add a DTO variant.
enum ApprovalOrigin {
    #[cfg(test)]
    UnqualifiedModel,
}
#[derive(Clone,Copy,PartialEq,Eq)]
enum Disposition {Fresh,Stopping,Waiting,Drained,Refused}

/// No configuration/scalar/record/default constructor, clone, serialization,
/// transfer or clock renewal. The eventual policy defines its fixed interval.
pub(super) struct Approval {
    origin:ApprovalOrigin,
    binding:Binding,
    domain:Digest,
    issued_at:u64,
    expires_at:u64,
    last:Option<(u64,u64)>,
    state:Cell<Disposition>,
    local:PhantomData<Rc<()>>,
}

/// Authenticated common-domain interval DATA from the sealed retained supplier.
/// Its LOWER bound must pass old expiry; its UPPER must stay inside approval.
pub(super) struct Clock {
    binding:Binding,
    domain:Digest,
    lower:u64,
    upper:u64,
}

#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
enum Kind {Lease,FinalPermit}
#[derive(Clone,Debug,PartialEq,Eq,PartialOrd,Ord)]
struct Identity {holder:Digest,executor:Digest,stage:Digest,grant:Digest,kind:Kind}
#[derive(Clone,Debug,PartialEq,Eq)]
struct Outstanding {identity:Identity,expires_upper:u64}

// No production variant: a Vec, count, receipt, pidfd or flock cannot construct
// COMPLETE renewal exclusion. A future source must account for in-flight sends,
// every holder/descendant/duplicate/remote right and all final-action permits.
enum StopOrigin {
    #[cfg(test)]
    UnqualifiedModel,
}
pub(super) struct Stopped {
    origin:StopOrigin,
    binding:Binding,
    domain:Digest,
    source:Rc<()>, // continuity only, never authentication
    stop_upper:u64,
    outstanding:Vec<Outstanding>,
}

mod sealed {pub(super) trait Source {}}
/// Only a future retained native source may implement this in production.
/// No default, blanket or production implementation is supplied in this slice.
pub(super) trait Source:sealed::Source {
    fn current(&mut self,approval:&Approval)->Result<Clock>;
    /// Atomically exclude new issuance AND renewal, including in-flight sends,
    /// then freeze the complete bounded inventory in one qualified clock domain.
    fn stop(&mut self,approval:&Approval)->Result<Stopped>;
    /// Check that the SAME retained source/exclusion remains current; this must
    /// not issue a new cut, resample old deadlines or acquire replacement rights.
    fn check_stopped(&mut self,approval:&Approval,cut:&Stopped)->Result<()>;
    /// Terminal local disposition even after expiry, without new IO/permission.
    fn refuse(&mut self);
}

impl Approval {
    fn observe(&mut self,clock:Clock)->Result<()> {
        ensure!(self.state.get()!=Disposition::Refused,"restore_approval_refused");
        ensure!(clock.binding==self.binding && clock.domain==self.domain,"restore_fence_binding_or_clock_changed");
        ensure!(self.issued_at<self.expires_at && self.issued_at<=clock.lower
            && clock.lower<=clock.upper && clock.upper<self.expires_at,
            "restore_fence_original_expired_or_invalid");
        ensure!(self.last.is_none_or(|(lower,upper)|lower<=clock.lower && upper<=clock.upper),"restore_fence_clock_rewound");
        self.last=Some((clock.lower,clock.upper));Ok(())
    }
    fn refuse(&self) {self.state.set(Disposition::Refused);}
}
impl Stopped {
    fn ceiling(&self,approval:&Approval)->Result<u64> {
        ensure!(self.binding==approval.binding && self.domain==approval.domain,"restore_stop_binding_or_clock_changed");
        ensure!(self.outstanding.len()<=MAX_OUTSTANDING,"restore_stop_inventory_bound");
        let observed=approval.last.context("restore_stop_clock_missing")?;
        ensure!(approval.issued_at<=self.stop_upper && self.stop_upper<=observed.1,"restore_stop_cut_not_observed");
        let mut previous=None;let mut ceiling=self.stop_upper;
        for item in &self.outstanding {
            ensure!(previous.is_none_or(|id|id<&item.identity),"restore_stop_inventory_duplicate_or_unsorted");
            previous=Some(&item.identity);ceiling=ceiling.max(item.expires_upper);
        }
        // Equality cannot fit a fresh observation whose upper bound must be
        // STRICTLY before the one original approval deadline. Never renew it.
        ensure!(ceiling<approval.expires_at,"restore_original_cannot_cover_drain");
        Ok(ceiling)
    }
}

struct Attempt<'a,S:Source> {approval:&'a mut Approval,source:&'a mut S,disarmed:bool}
impl<S:Source> Drop for Attempt<'_,S> {
    fn drop(&mut self) {if !self.disarmed {self.approval.refuse();self.source.refuse();}}
}

/// Historical progress only, never a fence, creator, P3 or new-writer witness.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) enum WaitStatus {Pending{not_before:u64},Drained}

/// Retains BOTH original approval and same stop source across every poll. A
/// cached status cannot create this owner or bypass its fresh check.
pub(super) struct Session<'a,S:Source> {
    approval:&'a mut Approval,
    source:&'a mut S,
    cut:Stopped,
    ceiling:u64,
}
impl<'a,S:Source> Session<'a,S> {
    pub(super) fn begin(approval:&'a mut Approval,source:&'a mut S)->Result<Self> {
        let mut guard=Attempt{approval:&mut *approval,source:&mut *source,disarmed:false};
        ensure!(guard.approval.state.get()==Disposition::Fresh,"restore_approval_already_used");
        let clock=guard.source.current(guard.approval)?;guard.approval.observe(clock)?;
        // Known-May boundary BEFORE the possible stop effect. An unknown reply
        // permanently refuses this attempt; no retry or reapplied stop occurs.
        guard.approval.state.set(Disposition::Stopping);
        let result=guard.source.stop(guard.approval);
        let post=guard.source.current(guard.approval).and_then(|c|guard.approval.observe(c));
        let cut=result?;post?;
        let ceiling=cut.ceiling(guard.approval)?;
        let checked=guard.source.check_stopped(guard.approval,&cut);
        let post=guard.source.current(guard.approval).and_then(|c|guard.approval.observe(c));
        checked?;post?;
        guard.approval.state.set(Disposition::Waiting);
        guard.disarmed=true;drop(guard);
        Ok(Self {approval,source,cut,ceiling})
    }
    pub(super) fn poll(&mut self)->Result<WaitStatus> {
        let result=(|| {
            ensure!(matches!(self.approval.state.get(),Disposition::Waiting|Disposition::Drained),"restore_fence_session_refused");
            let clock=self.source.current(self.approval)?;self.approval.observe(clock)?;
            let checked=self.source.check_stopped(self.approval,&self.cut);
            let post=self.source.current(self.approval).and_then(|c|self.approval.observe(c));
            checked?;post?;
            ensure!(self.cut.ceiling(self.approval)?==self.ceiling,"restore_stop_inventory_changed");
            let lower=self.approval.last.context("restore_stop_clock_missing")?.0;
            if lower<self.ceiling {Ok(WaitStatus::Pending{not_before:self.ceiling})}
            else {self.approval.state.set(Disposition::Drained);Ok(WaitStatus::Drained)}
        })();
        if result.is_err() {self.approval.refuse();self.source.refuse();}
        result
    }
    /// Call again at the next concrete consuming boundary. A previous Drained
    /// DATA value cannot stand in for this same-original/same-source check.
    pub(super) fn require_drained(&mut self)->Result<()> {
        let result=self.poll().and_then(|state| {ensure!(state==WaitStatus::Drained,"restore_incumbent_not_drained");Ok(())});
        if result.is_err() {self.approval.refuse();self.source.refuse();}
        result
    }
}
impl<S:Source> Drop for Session<'_,S> {
    fn drop(&mut self) {self.approval.refuse();self.source.refuse();}
}

#[cfg(test)]
mod tests;
