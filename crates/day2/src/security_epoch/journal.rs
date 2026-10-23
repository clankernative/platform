//! Opaque initial execution context and consuming counter-dispatch boundary.
//! Production dispatch requires a shared-slot known claim. The local SQLite
//! journal is retained solely as a controlled test fixture.
use super::CurrentStorageBootstrapPhase;
#[cfg(test)]
use super::{firestore, kernel::Outcome};
use super::{
    firestore::{Budget, Port, Sample},
    kernel::{self, Request, Snapshot},
};
use anyhow::{Result, ensure};
use day2_capabilities::{Digest, security_epoch::EpochStore};
#[cfg(test)]
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{cell::RefCell, marker::PhantomData, rc::Rc, time::Duration};

#[cfg(test)]
const SCHEMA: &str = "CREATE TABLE external_epoch_operations (
    authority TEXT NOT NULL,
    stage TEXT NOT NULL CHECK(stage IN ('create','activate')),
    operation TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL,
    request_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('prepared','may_have_been_sent','retryable','observed')),
    dispatch_count INTEGER NOT NULL CHECK(dispatch_count >= 0),
    receipt_json TEXT,
    PRIMARY KEY(authority,stage),
    CHECK((state = 'observed') = (receipt_json IS NOT NULL))
)";

#[cfg(test)]
pub(super) struct Journal<'a> {
    db: &'a mut Connection,
}

fn stage(request: &Request) -> &'static str {
    match request {
        Request::CreateInitialAuthority { .. } => "create",
        Request::CompleteInitialFirstActivation { .. } => "activate",
    }
}

pub(super) fn snapshot_digest(snapshot: &Snapshot) -> Result<Digest> {
    fn value<T: serde::Serialize>(
        value: &Option<kernel::Versioned<T>>,
    ) -> Option<(&T, &kernel::UpdateTime)> {
        value
            .as_ref()
            .map(|versioned| (&versioned.value, &versioned.version))
    }
    Digest::of(&(
        "day2-external-epoch-observation-v1",
        value(&snapshot.root),
        value(&snapshot.sentinel),
        value(&snapshot.create),
        value(&snapshot.activate),
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Purpose {
    Dispatch,
    Reconcile,
}

/// A native context retains the SAME current Controller/file/peer phase and
/// exact authenticated port identity through the consuming claim, send and
/// response checks. The constructor accepts no DTO, flag or replacement clock.
/// Controlled test contexts remain cfg(test) only. It is process/thread local.
pub(crate) struct CurrentBootstrapExecution<'storage, 'role> {
    selection: Digest,
    request: Digest,
    snapshot: Digest,
    stage: &'static str,
    purpose: Purpose,
    domain: Digest,
    floor: Duration,
    deadline: Duration,
    valid: bool,
    native: Option<Rc<RefCell<CurrentStorageBootstrapPhase<'storage, 'role>>>>,
    native_budget: Option<Budget>,
    local: PhantomData<Rc<()>>,
    #[cfg(test)]
    retention: Option<Rc<()>>,
}

impl<'storage, 'role> CurrentBootstrapExecution<'storage, 'role> {
    pub(super) fn native(
        owner: Rc<RefCell<CurrentStorageBootstrapPhase<'storage, 'role>>>,
        selection: &EpochStore,
        request: &Request,
        snapshot: &Snapshot,
        purpose: Purpose,
        port: &mut super::authenticated_reads::ControllerBorrow<'_, 'storage, 'role>,
    ) -> Result<Self> {
        let result = (|| {
            owner.try_borrow_mut()?.check()?;
            ensure!(
                owner.try_borrow()?.request_digest()? == request.digest()?,
                "security_epoch_native_request_changed"
            );
            // Preserve the actual purpose-bound budget, including all role,
            // authentication, file and peer time already spent. Scalar context
            // DATA must not select or renew the bootstrap interval.
            let mut budget = port.budget()?;
            let (sample, deadline) = port.context_interval(&owner, selection)?;
            let domain = sample.domain.clone();
            let floor = sample.elapsed;
            let native_budget = budget.narrow_for_context(sample, deadline)?;
            Ok(Self {
                selection: Digest::of(selection)?,
                request: request.digest()?,
                snapshot: snapshot_digest(snapshot)?,
                stage: stage(request),
                purpose,
                domain,
                floor,
                deadline,
                valid: true,
                native: Some(Rc::clone(&owner)),
                native_budget: Some(native_budget),
                local: PhantomData,
                #[cfg(test)]
                retention: None,
            })
        })();
        if result.is_err() {
            owner.try_borrow_mut()?.refuse();
        }
        result
    }

    pub(super) fn check(
        &mut self,
        selection: &EpochStore,
        request: &Request,
        snapshot: &Snapshot,
        purpose: Purpose,
        port: &mut impl Port,
    ) -> Result<(Sample, Budget)> {
        let result = (|| {
            ensure!(self.valid, "security_epoch_execution_context_refused");
            ensure!(
                self.selection == Digest::of(selection)?
                    && self.request == request.digest()?
                    && self.snapshot == snapshot_digest(snapshot)?
                    && self.stage == stage(request)
                    && self.purpose == purpose,
                "security_epoch_execution_context_mismatch"
            );
            let sample = self.sample(port)?;
            let budget = self.budget_at(&sample)?;
            Ok((sample, budget))
        })();
        if result.is_err() {
            self.refuse();
            port.refuse();
        }
        result
    }

    fn sample(&mut self, port: &mut impl Port) -> Result<Sample> {
        let result = (|| {
            ensure!(self.valid, "security_epoch_execution_context_refused");
            let sample = match &self.native {
                Some(owner) => port.sample_for_context(owner)?,
                None => port.sample()?,
            };
            self.observe_sample(sample)
        })();
        if result.is_err() {
            self.refuse();
            port.refuse();
        }
        result
    }

    /// Time DATA only, after a fixed mutation's same-owner full observation.
    /// This cannot stand in for `check` at a later effect/transfer boundary.
    pub(super) fn clock_sample(&mut self, port: &mut impl Port) -> Result<Sample> {
        let result = (|| {
            ensure!(self.valid, "security_epoch_execution_context_refused");
            let sample = match &self.native {
                Some(owner) => port.clock_for_context(owner)?,
                None => port.decoding_sample()?,
            };
            self.observe_sample(sample)
        })();
        if result.is_err() {
            self.refuse();
            port.refuse();
        }
        result
    }

    fn observe_sample(&mut self, sample: Sample) -> Result<Sample> {
        ensure!(
            sample.domain == self.domain
                && sample.elapsed >= self.floor
                && sample.elapsed < self.deadline,
            "security_epoch_execution_context_expired_or_changed"
        );
        self.floor = sample.elapsed;
        Ok(sample)
    }

    pub(super) fn refuse(&mut self) {
        self.valid = false;
        if let Some(owner) = &self.native
            && let Ok(mut phase) = owner.try_borrow_mut()
        {
            phase.refuse();
        }
    }

    fn budget_at(&mut self, sample: &Sample) -> Result<Budget> {
        let sample = Sample {
            domain: sample.domain.clone(),
            elapsed: sample.elapsed,
        };
        match &mut self.native_budget {
            Some(budget) => budget.narrow_for_context(sample, self.deadline),
            None => Budget::for_context(sample, self.deadline),
        }
    }

    #[cfg(test)]
    pub(super) fn budget(&mut self, port: &mut impl Port) -> Result<Budget> {
        let result = (|| {
            let sample = self.sample(port)?;
            self.budget_at(&sample)
        })();
        if result.is_err() {
            self.refuse();
            port.refuse();
        }
        result
    }

    #[cfg(test)]
    pub(super) fn fixture(
        selection: &EpochStore,
        request: &Request,
        snapshot: &Snapshot,
        purpose: Purpose,
        sample: Sample,
    ) -> Result<Self> {
        Ok(Self {
            selection: Digest::of(selection)?,
            request: request.digest()?,
            snapshot: snapshot_digest(snapshot)?,
            stage: stage(request),
            purpose,
            domain: sample.domain,
            floor: sample.elapsed,
            deadline: sample
                .elapsed
                .checked_add(Duration::from_secs(u64::from(
                    selection.max_lease_seconds.min(5),
                )))
                .ok_or_else(|| anyhow::anyhow!("fixture clock overflow"))?,
            valid: true,
            native: None,
            native_budget: None,
            local: PhantomData,
            retention: None,
        })
    }

    #[cfg(test)]
    pub(super) fn lose_original_creator_fixture(&mut self) {
        // Controlled invalidation, not a producer or native file-loss proof.
        self.valid = false;
    }

    /// Only observes the lifetime of this controlled context. It does not stand
    /// in for a native file, enrollment, provider or first-holder supplier.
    #[cfg(test)]
    pub(super) fn observe_fixture_lifetime(&mut self) -> std::rc::Weak<()> {
        let owner = Rc::new(());
        let observed = Rc::downgrade(&owner);
        self.retention = Some(owner);
        observed
    }
}

#[cfg(test)]
pub(super) struct InitialEpochCreatePermit<'storage, 'role> {
    request: Request,
    context: CurrentBootstrapExecution<'storage, 'role>,
}

#[cfg(test)]
pub(super) struct InitialFirstHolderActivationPermit<'storage, 'role> {
    request: Request,
    context: CurrentBootstrapExecution<'storage, 'role>,
}

/// Serving builds accept only the shared known claim. The two local fixture
/// variants exist exclusively in tests of the underlying counter kernel.
pub(super) enum AuthorizedDispatch<'storage, 'role> {
    #[cfg(test)]
    Create(InitialEpochCreatePermit<'storage, 'role>),
    #[cfg(test)]
    Activate(InitialFirstHolderActivationPermit<'storage, 'role>),
    Shared(Box<super::control_slot_io::KnownClaim<'storage, 'role>>),
}

/// Keep the consuming claim and all of its native owners through the actual
/// request and response checks. A request/budget tuple would drop those owners
/// before entering the transport.
pub(crate) struct PreparedDispatch<'storage, 'role> {
    owner: AuthorizedDispatch<'storage, 'role>,
    request: Request,
    budget: Budget,
}

/// The response still owns the exact execution context. Its native owners
/// cannot be dropped before the fixed response parser and final current check.
pub(crate) struct CounterResponse<'storage, 'role> {
    dispatch: PreparedDispatch<'storage, 'role>,
    bytes: Vec<u8>,
}

impl<'storage, 'role> AuthorizedDispatch<'storage, 'role> {
    fn refuse(&mut self) {
        match self {
            Self::Shared(claim) => claim.refuse(),
            #[cfg(test)]
            Self::Create(permit) => permit.context.refuse(),
            #[cfg(test)]
            Self::Activate(permit) => permit.context.refuse(),
        }
    }

    pub(super) fn prepare(
        self,
        selection: &EpochStore,
        port: &mut impl Port,
    ) -> Result<PreparedDispatch<'storage, 'role>> {
        let (owner, request, budget) = match self {
            Self::Shared(claim) => {
                let (claim, request, budget) = claim.prepare(selection, port)?;
                (Self::Shared(Box::new(claim)), request, budget)
            }
            #[cfg(test)]
            Self::Create(mut permit) => {
                ensure!(
                    permit.context.selection == Digest::of(selection)?,
                    "security_epoch_execution_selection_changed"
                );
                let request = permit.request.clone();
                let budget = permit.context.budget(port)?;
                (Self::Create(permit), request, budget)
            }
            #[cfg(test)]
            Self::Activate(mut permit) => {
                ensure!(
                    permit.context.selection == Digest::of(selection)?,
                    "security_epoch_execution_selection_changed"
                );
                let request = permit.request.clone();
                let budget = permit.context.budget(port)?;
                (Self::Activate(permit), request, budget)
            }
        };
        Ok(PreparedDispatch {
            owner,
            request,
            budget,
        })
    }
}

impl<'storage, 'role> PreparedDispatch<'storage, 'role> {
    pub(super) fn check(&mut self, selection: &EpochStore, port: &mut impl Port) -> Result<()> {
        let result = (|| {
            let (sample, mut current) = match &mut self.owner {
                AuthorizedDispatch::Shared(claim) => claim.check(selection, port)?,
                #[cfg(test)]
                AuthorizedDispatch::Create(permit) => {
                    ensure!(
                        permit.context.selection == Digest::of(selection)?,
                        "security_epoch_execution_selection_changed"
                    );
                    let sample = permit.context.sample(port)?;
                    let budget = permit.context.budget_at(&sample)?;
                    (sample, budget)
                }
                #[cfg(test)]
                AuthorizedDispatch::Activate(permit) => {
                    ensure!(
                        permit.context.selection == Digest::of(selection)?,
                        "security_epoch_execution_selection_changed"
                    );
                    let sample = permit.context.sample(port)?;
                    let budget = permit.context.budget_at(&sample)?;
                    (sample, budget)
                }
            };
            // Retain THIS prepared dispatch's original interval as well as
            // every newly checked claim observation. Never replace it with a
            // later context-only budget.
            self.budget.constrain_to(&mut current, &sample)?;
            Ok(())
        })();
        if result.is_err() {
            self.owner.refuse();
            port.refuse();
        }
        result
    }

    pub(super) fn send(
        mut self,
        selection: &EpochStore,
        port: &mut impl Port,
    ) -> Result<CounterResponse<'storage, 'role>> {
        let names = super::firestore::Names::new(selection, self.request.bootstrap(), None)?;
        let body = super::firestore::commit_body(selection, &self.request)?;
        self.check(selection, port)?;
        let bytes = self.budget.call(port, &names.endpoint("commit"), &body)?;
        self.check(selection, port)?;
        Ok(CounterResponse {
            dispatch: self,
            bytes,
        })
    }
}

impl<'storage, 'role> CounterResponse<'storage, 'role> {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn finish(mut self, selection: &EpochStore, port: &mut impl Port) -> Result<()> {
        self.dispatch.check(selection, port)
    }
}

#[cfg(test)]
impl<'storage, 'role> InitialEpochCreatePermit<'storage, 'role> {
    pub(super) fn send(self, selection: &EpochStore, port: &mut impl Port) -> Result<()> {
        firestore::commit(port, selection, AuthorizedDispatch::Create(self))
    }
}

#[cfg(test)]
impl<'storage, 'role> InitialFirstHolderActivationPermit<'storage, 'role> {
    pub(super) fn send(self, selection: &EpochStore, port: &mut impl Port) -> Result<()> {
        firestore::commit(port, selection, AuthorizedDispatch::Activate(self))
    }
}

#[cfg(test)]
impl<'a> Journal<'a> {
    pub(super) fn create(db: &'a mut Connection) -> Result<Self> {
        // Fresh schema only. No adoption, ALTER, migration or fallback schema.
        db.execute_batch(SCHEMA)?;
        Self::open(db)
    }

    pub(super) fn open(db: &'a mut Connection) -> Result<Self> {
        let schema: String = db.query_row(
            "SELECT sql FROM sqlite_master WHERE name='external_epoch_operations' AND type='table'",
            [],
            |row| row.get(0),
        )?;
        ensure!(schema == SCHEMA, "security_epoch_journal_schema_mismatch");
        Ok(Self { db })
    }

    pub(super) fn accept(&mut self, selection: &EpochStore, request: &Request) -> Result<()> {
        request.validate(selection)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authority = request.bootstrap().authority.as_str();
        let encoded = serde_json::to_string(request)?;
        let existing: Option<(String, String)> = tx.query_row(
            "SELECT request_digest,request_json FROM external_epoch_operations WHERE authority=?1 AND stage=?2",
            params![authority, stage(request)], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        if let Some((digest, stored)) = existing {
            ensure!(
                digest == request.digest()?.as_str() && stored == encoded,
                "security_epoch_candidate_already_accepted"
            );
        } else {
            if let Request::CompleteInitialFirstActivation { bootstrap, .. } = request {
                let create = Request::CreateInitialAuthority {
                    bootstrap: bootstrap.clone(),
                };
                let observed: Option<String> = tx.query_row(
                    "SELECT receipt_json FROM external_epoch_operations WHERE authority=?1 AND stage='create' AND state='observed' AND request_digest=?2",
                    params![authority, create.digest()?.as_str()], |row| row.get(0),
                ).optional()?;
                ensure!(
                    observed.as_deref()
                        == Some(serde_json::to_string(&create.receipt()?)?.as_str()),
                    "security_epoch_create_not_observed"
                );
            }
            tx.execute(
                "INSERT INTO external_epoch_operations(authority,stage,operation,request_digest,request_json,state,dispatch_count) VALUES(?1,?2,?3,?4,?5,'prepared',0)",
                params![authority, stage(request), request.operation().as_str(), request.digest()?.as_str(), encoded],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn claim(&mut self, request: &Request) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE external_epoch_operations SET state='may_have_been_sent',dispatch_count=dispatch_count+1 WHERE authority=?1 AND stage=?2 AND operation=?3 AND request_digest=?4 AND request_json=?5 AND state IN ('prepared','retryable') AND dispatch_count<9223372036854775807",
            params![request.bootstrap().authority.as_str(), stage(request), request.operation().as_str(), request.digest()?.as_str(), serde_json::to_string(request)?],
        )?;
        ensure!(
            changed == 1,
            "security_epoch_dispatch_requires_reconciliation"
        );
        tx.commit()?;
        Ok(())
    }

    pub(super) fn authorize_create<'storage, 'role>(
        &mut self,
        selection: &EpochStore,
        request: &Request,
        snapshot: &Snapshot,
        mut context: CurrentBootstrapExecution<'storage, 'role>,
        port: &mut impl Port,
    ) -> Result<InitialEpochCreatePermit<'storage, 'role>> {
        ensure!(
            matches!(request, Request::CreateInitialAuthority { .. }),
            "security_epoch_wrong_stage"
        );
        context.check(selection, request, snapshot, Purpose::Dispatch, port)?;
        ensure!(
            kernel::reconcile(selection, request, snapshot)? == Outcome::NotApplied,
            "security_epoch_already_applied"
        );
        self.claim(request)?;
        Ok(InitialEpochCreatePermit {
            request: request.clone(),
            context,
        })
    }

    pub(super) fn authorize_activate<'storage, 'role>(
        &mut self,
        selection: &EpochStore,
        request: &Request,
        snapshot: &Snapshot,
        mut context: CurrentBootstrapExecution<'storage, 'role>,
        port: &mut impl Port,
    ) -> Result<InitialFirstHolderActivationPermit<'storage, 'role>> {
        ensure!(
            matches!(request, Request::CompleteInitialFirstActivation { .. }),
            "security_epoch_wrong_stage"
        );
        context.check(selection, request, snapshot, Purpose::Dispatch, port)?;
        ensure!(
            kernel::reconcile(selection, request, snapshot)? == Outcome::NotApplied,
            "security_epoch_already_applied"
        );
        self.claim(request)?;
        Ok(InitialFirstHolderActivationPermit {
            request: request.clone(),
            context,
        })
    }

    /// Reconciliation preserves the permanently occupied authority/stage slot.
    /// NotApplied only arms the SAME request for a separately authorized send;
    /// neither a lost reply nor a fenced/refused holder permits a new candidate.
    pub(super) fn reconcile_attempt<'storage, 'role>(
        &mut self,
        selection: &EpochStore,
        request: &Request,
        snapshot: &Snapshot,
        mut context: CurrentBootstrapExecution<'storage, 'role>,
        port: &mut impl Port,
    ) -> Result<Outcome> {
        context.check(selection, request, snapshot, Purpose::Reconcile, port)?;
        let outcome = kernel::reconcile(selection, request, snapshot)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state: String = tx.query_row(
            "SELECT state FROM external_epoch_operations WHERE authority=?1 AND stage=?2 AND operation=?3 AND request_digest=?4 AND request_json=?5",
            params![request.bootstrap().authority.as_str(), stage(request), request.operation().as_str(), request.digest()?.as_str(), serde_json::to_string(request)?], |row| row.get(0),
        )?;
        let (next, receipt) = match &outcome {
            Outcome::Applied(receipt) => ("observed", Some(serde_json::to_string(receipt)?)),
            Outcome::NotApplied => {
                ensure!(
                    state != "observed",
                    "security_epoch_observed_state_disappeared"
                );
                (
                    if state == "prepared" {
                        "prepared"
                    } else {
                        "retryable"
                    },
                    None,
                )
            }
        };
        // A slow writer acquisition cannot extend a native context's deadline.
        context.sample(port)?;
        tx.execute(
            "UPDATE external_epoch_operations SET state=?3,receipt_json=?4 WHERE authority=?1 AND stage=?2",
            params![request.bootstrap().authority.as_str(), stage(request), next, receipt],
        )?;
        tx.commit()?;
        Ok(outcome)
    }

    #[cfg(test)]
    pub(super) fn state(&self, request: &Request) -> Result<(String, i64)> {
        Ok(self.db.query_row("SELECT state,dispatch_count FROM external_epoch_operations WHERE authority=?1 AND stage=?2", params![request.bootstrap().authority.as_str(), stage(request)], |row| Ok((row.get(0)?, row.get(1)?)))?)
    }
}
