//! Exact-operation acceptance and dispatch fencing in real SQLite. Production
//! placement in a qualified shared control store is deliberately not wired.
//! An app backup/local marker is never a substitute for that outside authority.
use super::{
    firestore::{self, Budget, Port, Sample},
    kernel::{self, Outcome, Request, Snapshot},
};
use anyhow::{Result, ensure};
use day2_capabilities::{Digest, security_epoch::EpochStore};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{marker::PhantomData, rc::Rc, time::Duration};

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

pub(super) struct Journal<'a> {
    db: &'a mut Connection,
}

fn stage(request: &Request) -> &'static str {
    match request {
        Request::CreateInitialAuthority { .. } => "create",
        Request::CompleteInitialFirstActivation { .. } => "activate",
    }
}

fn snapshot_digest(snapshot: &Snapshot) -> Result<Digest> {
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

/// No production constructor exists. A future constructor must acquire the
/// actual current role/code/process/governance/clock/holder/marker observations
/// together. A token, desired policy, parsed snapshot, journal row or test fixture
/// cannot construct this in a serving build. It is process and thread local.
pub(crate) struct CurrentBootstrapExecution {
    selection: Digest,
    request: Digest,
    snapshot: Digest,
    stage: &'static str,
    purpose: Purpose,
    domain: Digest,
    floor: Duration,
    deadline: Duration,
    local: PhantomData<Rc<()>>,
}

impl CurrentBootstrapExecution {
    fn check(
        &mut self,
        selection: &EpochStore,
        request: &Request,
        snapshot: &Snapshot,
        purpose: Purpose,
        port: &mut impl Port,
    ) -> Result<()> {
        ensure!(
            self.selection == Digest::of(selection)?
                && self.request == request.digest()?
                && self.snapshot == snapshot_digest(snapshot)?
                && self.stage == stage(request)
                && self.purpose == purpose,
            "security_epoch_execution_context_mismatch"
        );
        self.sample(port)?;
        Ok(())
    }

    fn sample(&mut self, port: &mut impl Port) -> Result<Sample> {
        let sample = port.sample()?;
        ensure!(
            sample.domain == self.domain
                && sample.elapsed >= self.floor
                && sample.elapsed < self.deadline,
            "security_epoch_execution_context_expired_or_changed"
        );
        self.floor = sample.elapsed;
        Ok(sample)
    }

    fn budget(&mut self, port: &mut impl Port) -> Result<Budget> {
        Budget::for_context(self.sample(port)?, self.deadline)
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
                .checked_add(Duration::from_secs(u64::from(selection.max_lease_seconds.min(5))))
                .ok_or_else(||anyhow::anyhow!("fixture clock overflow"))?,
            local: PhantomData,
        })
    }
}

pub(crate) struct InitialEpochCreatePermit {
    request: Request,
    context: CurrentBootstrapExecution,
}

pub(crate) struct InitialFirstHolderActivationPermit {
    request: Request,
    context: CurrentBootstrapExecution,
}

/// The provider write boundary consumes one of the two already journal-fenced
/// stage handles. Historical Request/Budget values cannot invoke it directly.
pub(super) enum AuthorizedDispatch {
    Create(InitialEpochCreatePermit),
    Activate(InitialFirstHolderActivationPermit),
}

impl AuthorizedDispatch {
    pub(super) fn prepare(
        self,
        selection: &EpochStore,
        port: &mut impl Port,
    ) -> Result<(Request, Budget)> {
        let (request, mut context) = match self {
            Self::Create(permit) => (permit.request, permit.context),
            Self::Activate(permit) => (permit.request, permit.context),
        };
        ensure!(
            context.selection == Digest::of(selection)?,
            "security_epoch_execution_selection_changed"
        );
        Ok((request, context.budget(port)?))
    }
}

impl InitialEpochCreatePermit {
    pub(super) fn send(self, selection: &EpochStore, port: &mut impl Port) -> Result<()> {
        firestore::commit(port, selection, AuthorizedDispatch::Create(self))
    }
}

impl InitialFirstHolderActivationPermit {
    pub(super) fn send(self, selection: &EpochStore, port: &mut impl Port) -> Result<()> {
        firestore::commit(port, selection, AuthorizedDispatch::Activate(self))
    }
}

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

    pub(super) fn authorize_create(
        &mut self,
        selection: &EpochStore,
        request: &Request,
        snapshot: &Snapshot,
        mut context: CurrentBootstrapExecution,
        port: &mut impl Port,
    ) -> Result<InitialEpochCreatePermit> {
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

    pub(super) fn authorize_activate(
        &mut self,
        selection: &EpochStore,
        request: &Request,
        snapshot: &Snapshot,
        mut context: CurrentBootstrapExecution,
        port: &mut impl Port,
    ) -> Result<InitialFirstHolderActivationPermit> {
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
    pub(super) fn reconcile_attempt(
        &mut self,
        selection: &EpochStore,
        request: &Request,
        snapshot: &Snapshot,
        mut context: CurrentBootstrapExecution,
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
