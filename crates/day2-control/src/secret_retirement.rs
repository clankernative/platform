//! Private, durable protected disable of one physical secret version. Roc chooses
//! the next capability; the native journal enforces consumer barriers, authority
//! and exact receipts. This is neither secret destruction nor credential revocation.

use crate::{
    BindingRef, Digest, Name,
    journal::{Journal, OperatorActor, RecoveryMode},
    provider_evidence::{EffectAcknowledgement, RevisionRelation, StateEvidence},
    runtime_secret::{self, ResourceScope, RetirementGuard, SecretVersionKey, VersionState},
};
use anyhow::{Result, ensure};
use durable_temporal::{AdvanceBackend, BackendError, StepOutcome, TemporalAdapter};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};

pub const LEASE_MILLIS: u64 = 20_000;

/// Approval is trusted operator-adapter provenance, not a client-supplied token
/// that grants authority. The journal's current resource policy remains decisive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementPlan {
    pub key: SecretVersionKey,
    pub scope: ResourceScope,
    pub request: Name,
    pub authority_revision: u64,
    pub policy: Digest,
    pub actor: OperatorActor,
    pub approval: Digest,
    pub resources: BindingRef,
    pub durability: BindingRef,
    pub recipe: Digest,
}
impl RetirementPlan {
    pub fn execution_id(&self) -> Result<Digest> {
        Digest::of(&("day2-secret-retirement-v1", &self.key))
    }
    pub fn fingerprint(&self) -> Result<Digest> {
        Digest::of(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetirementPhase {
    WaitingConsumers,
    Eligible,
    WaitingDisabled,
    Disabled,
    Complete,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetirementWait {
    Consumers,
    ProviderRetry,
    Reconciliation,
    DisabledReadback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetirementTerminal {
    Disabled,
    AuthorityLost,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementSnapshot {
    pub id: Digest,
    pub plan: RetirementPlan,
    pub phase: RetirementPhase,
    pub next_step: u64,
    pub revision: u64,
    pub waiting: Option<RetirementWait>,
    pub terminal: Option<RetirementTerminal>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetirementOperation {
    WaitConsumers,
    DisableVersion,
    ObserveDisabled,
    Complete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementStepRequest {
    pub name: Name,
    pub ordinal: u64,
    pub operation: RetirementOperation,
}

pub trait Recipe: Send + Sync + 'static {
    fn revision(&self) -> Result<Digest>;
    fn choose(&self, snapshot: &RetirementSnapshot) -> Result<RetirementStepRequest>;
}

pub trait Capabilities: Send + Sync + 'static {
    /// Verifies immutable adapter/binding identity, not mutable resource authority.
    /// The latter is checked atomically by the runtime-secret journal.
    fn validate(&self, plan: &RetirementPlan) -> Result<()>;
    fn perform(&self, lease: &RetirementLease) -> Result<RetirementEffectResult>;
}

#[derive(Clone, Debug)]
pub struct RetirementLease {
    pub execution: RetirementSnapshot,
    pub step: RetirementStepRequest,
    pub effect: Digest,
    pub epoch: u64,
    pub owner: Name,
    pub until: u64,
    pub recovery: RecoveryMode,
}

#[derive(Clone, Debug)]
pub enum RetirementClaim {
    Acquired(Box<RetirementLease>),
    Busy,
    Terminal(Box<RetirementSnapshot>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementFact {
    pub execution: Digest,
    pub effect: Digest,
    pub plan: Digest,
    pub key: SecretVersionKey,
    pub scope: ResourceScope,
    pub binding: BindingRef,
    pub evidence: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RetirementObserved {
    DisableAcknowledged {
        acknowledgement: EffectAcknowledgement,
    },
    Disabled {
        disabled: bool,
        evidence: StateEvidence,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementObservation {
    pub fact: RetirementFact,
    pub outcome: RetirementObserved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RetirementEffectResult {
    Observed(RetirementObservation),
    RetryNotApplied { fact: RetirementFact },
    ReconciledAbsent { fact: RetirementFact },
    Ambiguous {},
    WaitConsumers {},
    Complete {},
    GuardChanged {},
}

impl RetirementLease {
    pub fn fact(&self, evidence: Digest) -> Result<RetirementFact> {
        ensure!(
            matches!(
                self.step.operation,
                RetirementOperation::DisableVersion | RetirementOperation::ObserveDisabled
            ),
            "internal retirement operation has no provider fact"
        );
        Ok(RetirementFact {
            execution: self.execution.id.clone(),
            effect: self.effect.clone(),
            plan: self.execution.plan.fingerprint()?,
            key: self.execution.plan.key.clone(),
            scope: self.execution.plan.scope.clone(),
            binding: self.execution.plan.resources.clone(),
            evidence,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetirementRejection {
    FencedLease,
    ConflictingCompletion,
    StaleStep,
    InvalidFact,
    UncertainMutation,
}
impl std::fmt::Display for RetirementRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::FencedLease => "retirement lease fenced",
            Self::ConflictingCompletion => "conflicting retirement completion",
            Self::StaleStep => "stale retirement step",
            Self::InvalidFact => "retirement provider fact mismatch",
            Self::UncertainMutation => "retirement mutation requires reconciliation",
        })
    }
}
impl std::error::Error for RetirementRejection {}

pub struct RetirementExecutionHost {
    journal: PathBuf,
    company: Name,
    owner: Name,
    durability: BindingRef,
    capabilities: Arc<dyn Capabilities>,
    recipe: Arc<dyn Recipe>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    snapshot: RetirementSnapshot,
    barrier: RetirementGuard,
    disable: Option<RetirementObservation>,
    readback: Option<RetirementObservation>,
    qualified_frontier: Option<RetirementObservation>,
}

impl RetirementOperation {
    fn name(self) -> &'static str {
        match self {
            Self::WaitConsumers => "wait_consumers",
            Self::DisableVersion => "disable_version",
            Self::ObserveDisabled => "observe_disabled",
            Self::Complete => "complete",
        }
    }
    fn provider(self) -> bool {
        matches!(self, Self::DisableVersion | Self::ObserveDisabled)
    }
}

impl RetirementExecutionHost {
    pub fn new(
        journal: PathBuf,
        company: Name,
        owner: Name,
        durability: BindingRef,
        capabilities: Arc<dyn Capabilities>,
        recipe: Arc<dyn Recipe>,
    ) -> Self {
        Self {
            journal,
            company,
            owner,
            durability,
            capabilities,
            recipe,
        }
    }

    fn validate_scope(&self, plan: &RetirementPlan) -> Result<()> {
        ensure!(
            plan.scope.company == self.company && plan.durability == self.durability,
            "retirement host scope mismatch"
        );
        Ok(())
    }

    fn validate(&self, plan: &RetirementPlan) -> Result<()> {
        self.validate_scope(plan)?;
        ensure!(
            plan.recipe == self.recipe.revision()?,
            "retirement recipe mismatch"
        );
        Ok(())
    }

    pub fn accept(&self, plan: &RetirementPlan) -> Result<Digest> {
        self.validate(plan)?;
        self.capabilities.validate(plan)?;
        Ok(Journal::open(&self.journal)?
            .accept_secret_retirement(plan)?
            .id)
    }

    pub fn inspect(&self, id: &Digest) -> Result<RetirementSnapshot> {
        let journal = Journal::open(&self.journal)?;
        let stored = read(&journal.connection, id)?;
        self.validate_scope(&stored.snapshot.plan)?;
        Ok(stored.snapshot)
    }

    pub fn claim_at(
        &self,
        id: &Digest,
        step: &RetirementStepRequest,
        now: u64,
    ) -> Result<RetirementClaim> {
        let snapshot = self.inspect(id)?;
        if snapshot.terminal.is_some() {
            return Ok(RetirementClaim::Terminal(Box::new(snapshot)));
        }
        self.validate(&snapshot.plan)?;
        Journal::open(&self.journal)?.claim_secret_retirement_step(
            id,
            step,
            self.owner.clone(),
            now,
        )
    }

    pub fn perform_at(&self, lease: &RetirementLease, now: u64) -> Result<RetirementEffectResult> {
        self.validate(&lease.execution.plan)?;
        self.capabilities.validate(&lease.execution.plan)?;
        let mut journal = Journal::open(&self.journal)?;
        let tx = journal
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = read(&tx, &lease.execution.id)?;
        let row = step_row(&tx, &lease.execution.id, lease.step.ordinal)?
            .ok_or(RetirementRejection::FencedLease)?;
        validate_lease(&stored, &row, lease, now)?;
        if row.started {
            return Err(RetirementRejection::FencedLease.into());
        }
        if lease.recovery == RecoveryMode::Execute && guard_changed(&tx, &stored)? {
            tx.commit()?;
            return Ok(RetirementEffectResult::GuardChanged {});
        }
        if lease.step.operation == RetirementOperation::DisableVersion
            && lease.recovery == RecoveryMode::Execute
        {
            runtime_secret::require_disable_in(&tx, &stored.barrier)?;
        }
        tx.execute(
            "UPDATE secret_retirement_steps SET started=1 WHERE id=?1",
            [lease.effect.as_str()],
        )?;
        event(
            &tx,
            &stored,
            "capability_dispatch",
            &(
                &lease.effect,
                &lease.step,
                lease.epoch,
                &lease.owner,
                now,
                lease.recovery == RecoveryMode::Reconcile,
            ),
        )?;
        tx.commit()?;
        match lease.step.operation {
            RetirementOperation::WaitConsumers => Ok(RetirementEffectResult::WaitConsumers {}),
            RetirementOperation::Complete => Ok(RetirementEffectResult::Complete {}),
            _ => match self.capabilities.perform(lease) {
                Ok(
                    RetirementEffectResult::WaitConsumers {}
                    | RetirementEffectResult::Complete {}
                    | RetirementEffectResult::GuardChanged {},
                ) => Err(RetirementRejection::InvalidFact.into()),
                Ok(result) => Ok(result),
                Err(_) => Err(anyhow::anyhow!("retirement provider host fault")),
            },
        }
    }

    pub fn settle_at(
        &self,
        lease: &RetirementLease,
        result: RetirementEffectResult,
        now: u64,
    ) -> Result<StepOutcome> {
        self.validate(&lease.execution.plan)?;
        let snapshot =
            Journal::open(&self.journal)?.settle_secret_retirement_step(lease, &result, now)?;
        Ok(progress(&snapshot))
    }

    pub fn advance_at(&self, id: &Digest, now: u64) -> Result<StepOutcome> {
        self.advance_with_clock(id, || Ok(now))
    }

    pub fn advance_with_clock(
        &self,
        id: &Digest,
        clock: impl Fn() -> Result<u64>,
    ) -> Result<StepOutcome> {
        let snapshot = self.inspect(id)?;
        if snapshot.terminal.is_some() {
            return Ok(progress(&snapshot));
        }
        let step = self.recipe.choose(&snapshot)?;
        let now = clock()?;
        let lease = match self.claim_at(id, &step, now)? {
            RetirementClaim::Acquired(lease) => lease,
            RetirementClaim::Busy => return Ok(StepOutcome::Continue),
            RetirementClaim::Terminal(snapshot) => return Ok(progress(&snapshot)),
        };
        let result = self.perform_at(&lease, clock()?.max(now))?;
        self.settle_at(&lease, result, clock()?.max(now))
    }

    pub async fn dispatch(&self, adapter: &TemporalAdapter) -> Result<usize> {
        self.durability.verify(adapter.binding_configuration())?;
        let ids = Journal::open(&self.journal)?.pending_secret_retirement_dispatches(
            &self.company,
            &self.durability,
            256,
        )?;
        let mut dispatched = 0;
        for id in ids {
            let snapshot = self.inspect(&id)?;
            let receipt = adapter.ensure_started(snapshot.id.as_str()).await?;
            let mut journal = Journal::open(&self.journal)?;
            let tx = journal
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let (workflow, run): (Option<String>, Option<String>) = tx.query_row(
                "SELECT workflow_id,run_id FROM secret_retirement_outbox WHERE execution=?1",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            ensure!(
                workflow
                    .as_ref()
                    .is_none_or(|prior| prior == &receipt.workflow_id),
                "retirement workflow receipt mismatch"
            );
            if workflow.as_ref() == Some(&receipt.workflow_id)
                && run.as_ref() == Some(&receipt.run_id)
            {
                tx.commit()?;
                continue;
            }
            tx.execute(
                "UPDATE secret_retirement_outbox SET workflow_id=?1,run_id=?2 WHERE execution=?3",
                params![receipt.workflow_id, receipt.run_id, id.as_str()],
            )?;
            event(
                &tx,
                &read(&tx, &id)?,
                "workflow_dispatched",
                &(&receipt.workflow_id, &receipt.run_id),
            )?;
            tx.commit()?;
            dispatched += 1;
        }
        Ok(dispatched)
    }
}

impl AdvanceBackend for RetirementExecutionHost {
    fn advance(
        &self,
        execution_id: &str,
        runtime: &durable_temporal::RuntimeConfig,
    ) -> std::result::Result<StepOutcome, BackendError> {
        self.durability
            .verify(runtime)
            .map_err(|_| BackendError::Rejected)?;
        let id = Digest::try_from(execution_id.to_owned()).map_err(|_| BackendError::Rejected)?;
        let journal = Journal::open(&self.journal).map_err(|_| BackendError::Retryable)?;
        let stored = read(&journal.connection, &id).map_err(|_| BackendError::Retryable)?;
        self.validate_scope(&stored.snapshot.plan)
            .map_err(|_| BackendError::Rejected)?;
        self.advance_with_clock(&id, wall_clock)
            .map_err(|_| BackendError::Retryable)
    }
}

fn wall_clock() -> Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}
fn progress(snapshot: &RetirementSnapshot) -> StepOutcome {
    match snapshot.terminal {
        Some(RetirementTerminal::Disabled) => StepOutcome::Succeeded,
        Some(_) => StepOutcome::Failed,
        None => StepOutcome::Continue,
    }
}

impl Journal {
    pub(crate) fn initialize_secret_retirement_schema(&mut self) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS secret_retirement_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL);
            INSERT OR IGNORE INTO secret_retirement_meta VALUES(1,2);")?;
        let version: i64 = tx.query_row(
            "SELECT version FROM secret_retirement_meta WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        if version == 1 {
            for table in [
                "secret_retirements",
                "secret_retirement_steps",
                "secret_retirement_outbox",
                "secret_retirement_events",
            ] {
                let count: i64 =
                    tx.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })?;
                ensure!(
                    count == 0,
                    "legacy retirement evidence requires explicit reviewed migration"
                );
            }
            tx.execute(
                "UPDATE secret_retirement_meta SET version=2 WHERE singleton=1",
                [],
            )?;
        } else {
            ensure!(version == 2, "unsupported secret retirement schema");
        }
        tx.execute_batch("CREATE TABLE IF NOT EXISTS secret_retirements(id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS secret_retirement_outbox(execution TEXT PRIMARY KEY REFERENCES secret_retirements(id),workflow_id TEXT,run_id TEXT);
            CREATE TABLE IF NOT EXISTS secret_retirement_steps(
                id TEXT PRIMARY KEY,execution TEXT NOT NULL REFERENCES secret_retirements(id),ordinal INTEGER NOT NULL CHECK(ordinal>=0),
                request TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN('running','pending','ambiguous','complete')),
                epoch INTEGER NOT NULL CHECK(epoch>0),owner TEXT NOT NULL,lease_until INTEGER NOT NULL,
                result TEXT,recovery INTEGER NOT NULL CHECK(recovery IN(0,1)),started INTEGER NOT NULL CHECK(started IN(0,1)),UNIQUE(execution,ordinal));
            CREATE TABLE IF NOT EXISTS secret_retirement_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,execution TEXT NOT NULL REFERENCES secret_retirements(id),kind TEXT NOT NULL,body TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS secret_retirement_events_no_update BEFORE UPDATE ON secret_retirement_events BEGIN SELECT RAISE(ABORT,'retirement audit is append only');END;
            CREATE TRIGGER IF NOT EXISTS secret_retirement_events_no_delete BEFORE DELETE ON secret_retirement_events BEGIN SELECT RAISE(ABORT,'retirement audit is append only');END;
            CREATE TRIGGER IF NOT EXISTS secret_retirement_events_no_replace BEFORE INSERT ON secret_retirement_events WHEN EXISTS(SELECT 1 FROM secret_retirement_events WHERE sequence=NEW.sequence) BEGIN SELECT RAISE(ABORT,'retirement audit is append only');END;")?;
        tx.commit()?;
        Ok(())
    }

    pub fn accept_secret_retirement(
        &mut self,
        plan: &RetirementPlan,
    ) -> Result<RetirementSnapshot> {
        ensure!(
            plan.authority_revision > 0 && plan.resources.id != plan.durability.id,
            "invalid retirement authority or capability identity"
        );
        i64::try_from(plan.authority_revision)?;
        let id = plan.execution_id()?;
        let fingerprint = plan.fingerprint()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(prior) = tx
            .query_row(
                "SELECT fingerprint FROM secret_retirements WHERE id=?1",
                [id.as_str()],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            ensure!(
                prior == fingerprint.as_str(),
                "physical version already has a different retirement plan"
            );
            return Ok(read(&tx, &id)?.snapshot);
        }
        let barrier = runtime_secret::begin_retirement_in(
            &tx,
            &plan.key,
            &plan.scope,
            &plan.request,
            plan.authority_revision,
            &plan.policy,
            &plan.actor,
        )?;
        ensure!(
            barrier.state == VersionState::Retiring,
            "cannot start retirement for an already disabled version"
        );
        let snapshot = RetirementSnapshot {
            id: id.clone(),
            plan: plan.clone(),
            phase: RetirementPhase::WaitingConsumers,
            next_step: 0,
            revision: 0,
            waiting: Some(RetirementWait::Consumers),
            terminal: None,
        };
        let stored = Stored {
            snapshot: snapshot.clone(),
            barrier,
            disable: None,
            readback: None,
            qualified_frontier: None,
        };
        tx.execute(
            "INSERT INTO secret_retirements VALUES(?1,?2,?3)",
            params![
                id.as_str(),
                fingerprint.as_str(),
                serde_json::to_string(&stored)?
            ],
        )?;
        tx.execute(
            "INSERT INTO secret_retirement_outbox(execution) VALUES(?1)",
            [id.as_str()],
        )?;
        event(&tx, &stored, "accepted", plan)?;
        tx.commit()?;
        Ok(snapshot)
    }

    pub fn secret_retirement(&self, id: &Digest) -> Result<RetirementSnapshot> {
        Ok(read(&self.connection, id)?.snapshot)
    }

    pub fn secret_retirements(
        &self,
        company: &Name,
        durability: &BindingRef,
        limit: u32,
    ) -> Result<Vec<RetirementSnapshot>> {
        ensure!((1..=256).contains(&limit), "retirement page budget");
        let mut statement=self.connection.prepare("SELECT id FROM secret_retirements WHERE json_extract(body,'$.snapshot.plan.scope.company')=?1
            AND json_extract(body,'$.snapshot.plan.durability.id')=?2 AND json_extract(body,'$.snapshot.plan.durability.revision')=?3 ORDER BY id LIMIT ?4")?;
        statement
            .query_map(
                params![
                    company.as_str(),
                    durability.id.as_str(),
                    durability.revision.as_str(),
                    limit
                ],
                |r| r.get::<_, String>(0),
            )?
            .map(|id| {
                let id = Digest::try_from(id?)?;
                let snapshot = read(&self.connection, &id)?.snapshot;
                ensure!(
                    snapshot.plan.scope.company == *company
                        && snapshot.plan.durability == *durability,
                    "retirement listing scope mismatch"
                );
                Ok(snapshot)
            })
            .collect()
    }

    pub fn pending_secret_retirement_dispatches(
        &self,
        company: &Name,
        durability: &BindingRef,
        limit: u32,
    ) -> Result<Vec<Digest>> {
        ensure!((1..=256).contains(&limit), "retirement outbox page budget");
        let mut statement=self.connection.prepare("SELECT w.id FROM secret_retirement_outbox o JOIN secret_retirements w ON w.id=o.execution
            WHERE o.workflow_id IS NULL AND json_extract(w.body,'$.snapshot.terminal') IS NULL
            AND json_extract(w.body,'$.snapshot.plan.scope.company')=?1 AND json_extract(w.body,'$.snapshot.plan.durability.id')=?2
            AND json_extract(w.body,'$.snapshot.plan.durability.revision')=?3 ORDER BY w.id LIMIT ?4")?;
        statement
            .query_map(
                params![
                    company.as_str(),
                    durability.id.as_str(),
                    durability.revision.as_str(),
                    limit
                ],
                |r| r.get::<_, String>(0),
            )?
            .map(|id| Digest::try_from(id?))
            .collect()
    }

    pub fn claim_secret_retirement_step(
        &mut self,
        id: &Digest,
        request: &RetirementStepRequest,
        owner: Name,
        now: u64,
    ) -> Result<RetirementClaim> {
        let until = now
            .checked_add(LEASE_MILLIS)
            .ok_or_else(|| anyhow::anyhow!("retirement lease overflow"))?;
        i64::try_from(until)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut stored = read(&tx, id)?;
        if stored.snapshot.terminal.is_some() {
            return Ok(RetirementClaim::Terminal(Box::new(stored.snapshot)));
        }
        let prior = step_row(&tx, id, stored.snapshot.next_step)?;
        let uncertain = prior.as_ref().is_some_and(|row| {
            row.status == "ambiguous"
                || (row.status == "running"
                    && (row.started || row.recovery == RecoveryMode::Reconcile))
        });
        if !uncertain && guard_changed(&tx, &stored)? {
            refresh_guard(&tx, &mut stored)?;
            if let Some(prior) = prior {
                tx.execute(
                    "UPDATE secret_retirement_steps SET status='complete',result=?1 WHERE id=?2",
                    params![
                        serde_json::to_string(&RetirementEffectResult::GuardChanged {})?,
                        prior.id.as_str()
                    ],
                )?;
                stored.snapshot.next_step = stored
                    .snapshot
                    .next_step
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("retirement ordinal exhausted"))?;
                event(&tx, &stored, "retired_unapplied_step", &prior.id)?;
            }
            save(&tx, &mut stored)?;
            tx.commit()?;
            return Ok(if stored.snapshot.terminal.is_some() {
                RetirementClaim::Terminal(Box::new(stored.snapshot))
            } else {
                RetirementClaim::Busy
            });
        }
        if request.ordinal != stored.snapshot.next_step || !legal(&stored.snapshot, request) {
            return Err(RetirementRejection::StaleStep.into());
        }
        let effect = effect_id(&stored.snapshot, request)?;
        let (epoch, recovery) = match prior {
            None => (1, RecoveryMode::Execute),
            Some(prior) => {
                if prior.request != *request || prior.id != effect {
                    return Err(RetirementRejection::StaleStep.into());
                }
                if prior.status == "running" && prior.until > now {
                    return Ok(RetirementClaim::Busy);
                }
                ensure!(
                    prior.status != "complete",
                    "completed retirement step is current"
                );
                let recovery = if prior.status == "pending"
                    || (prior.status == "running"
                        && !prior.started
                        && prior.recovery == RecoveryMode::Execute)
                {
                    RecoveryMode::Execute
                } else {
                    RecoveryMode::Reconcile
                };
                (
                    prior
                        .epoch
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("retirement lease epoch exhausted"))?,
                    recovery,
                )
            }
        };
        tx.execute("INSERT INTO secret_retirement_steps VALUES(?1,?2,?3,?4,'running',?5,?6,?7,NULL,?8,0)
            ON CONFLICT(id) DO UPDATE SET status='running',epoch=excluded.epoch,owner=excluded.owner,lease_until=excluded.lease_until,recovery=excluded.recovery,started=0",
            params![effect.as_str(),id.as_str(),i64::try_from(request.ordinal)?,serde_json::to_string(request)?,i64::try_from(epoch)?,owner.as_str(),i64::try_from(until)?,recovery==RecoveryMode::Reconcile])?;
        event(
            &tx,
            &stored,
            "claimed",
            &(
                &effect,
                request,
                epoch,
                &owner,
                now,
                until,
                recovery == RecoveryMode::Reconcile,
            ),
        )?;
        let lease = RetirementLease {
            execution: stored.snapshot,
            step: request.clone(),
            effect,
            epoch,
            owner,
            until,
            recovery,
        };
        tx.commit()?;
        Ok(RetirementClaim::Acquired(Box::new(lease)))
    }

    pub fn settle_secret_retirement_step(
        &mut self,
        lease: &RetirementLease,
        result: &RetirementEffectResult,
        now: u64,
    ) -> Result<RetirementSnapshot> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut stored = read(&tx, &lease.execution.id)?;
        let row = step_row(&tx, &lease.execution.id, lease.step.ordinal)?
            .ok_or(RetirementRejection::FencedLease)?;
        let encoded = serde_json::to_string(result)?;
        if row.status == "complete" {
            if row.id != lease.effect
                || row.request != lease.step
                || row.result.as_deref() != Some(encoded.as_str())
                || stored.snapshot.plan != lease.execution.plan
            {
                return Err(RetirementRejection::ConflictingCompletion.into());
            }
            return Ok(stored.snapshot);
        }
        validate_lease(&stored, &row, lease, now)?;
        if !row.started && !matches!(result, RetirementEffectResult::GuardChanged {}) {
            return Err(RetirementRejection::FencedLease.into());
        }
        let mut complete = true;
        match result {
            RetirementEffectResult::GuardChanged {} => {
                ensure!(
                    !row.started && guard_changed(&tx, &stored)?,
                    "dispatched retirement cannot be abandoned as unapplied"
                );
                refresh_guard(&tx, &mut stored)?;
            }
            RetirementEffectResult::WaitConsumers {} => {
                ensure!(
                    lease.step.operation == RetirementOperation::WaitConsumers,
                    "consumer check used for provider step"
                );
                if !authority_current(&tx, &stored.barrier)? {
                    stop(&mut stored);
                } else {
                    let consumers =
                        runtime_secret::retirement_consumers_in(&tx, &stored.barrier.id)?;
                    if consumers.protected() {
                        stored.snapshot.waiting = Some(RetirementWait::Consumers);
                    } else {
                        stored.snapshot.phase = RetirementPhase::Eligible;
                        stored.snapshot.waiting = None;
                    }
                    event(&tx, &stored, "consumers_observed", &consumers)?;
                }
            }
            RetirementEffectResult::Complete {} => {
                ensure!(
                    lease.step.operation == RetirementOperation::Complete
                        && stored.snapshot.phase == RetirementPhase::Disabled,
                    "completion has no disabled readback"
                );
                let disable = stored
                    .disable
                    .as_ref()
                    .ok_or(RetirementRejection::InvalidFact)?;
                let readback = stored
                    .readback
                    .as_ref()
                    .ok_or(RetirementRejection::InvalidFact)?;
                // A completed provider write remains a physical fact even if a
                // qualification was withdrawn after dispatch; it is not safe-retirement authority.
                let current = authority_current(&tx, &stored.barrier)?
                    && !runtime_secret::retirement_consumers_in(&tx, &stored.barrier.id)?
                        .protected();
                runtime_secret::complete_disabled_in(
                    &tx,
                    &stored.barrier,
                    &disable.fact.effect,
                    &Digest::of(readback)?,
                )?;
                if current {
                    stored.snapshot.phase = RetirementPhase::Complete;
                    stored.snapshot.terminal = Some(RetirementTerminal::Disabled);
                    stored.snapshot.waiting = None;
                } else {
                    stop(&mut stored);
                }
            }
            RetirementEffectResult::Observed(observation) => {
                validate_fact(lease, &observation.fact)?;
                match (&observation.outcome, lease.step.operation) {
                    (
                        RetirementObserved::DisableAcknowledged { acknowledgement },
                        RetirementOperation::DisableVersion,
                    ) => {
                        ensure!(
                            acknowledgement.effect == lease.effect,
                            "disable acknowledgement effect mismatch"
                        );
                        stored.disable = Some(observation.clone());
                        stored.snapshot.phase = RetirementPhase::WaitingDisabled;
                        stored.snapshot.waiting = Some(RetirementWait::DisabledReadback);
                    }
                    (
                        RetirementObserved::Disabled { evidence, .. },
                        RetirementOperation::DisableVersion,
                    ) => {
                        if evidence.barrier().is_some() {
                            evidence.require(
                                &stored.snapshot.plan.resources,
                                &Digest::of(&stored.snapshot.plan.key)?,
                                Some(&lease.effect),
                            )?;
                        }
                        // State alone cannot acknowledge this mutation, even if
                        // another actor has already disabled the same version.
                        defer(
                            &tx,
                            &mut stored,
                            lease,
                            "ambiguous",
                            RetirementWait::Reconciliation,
                        )?;
                        complete = false;
                    }
                    (
                        RetirementObserved::Disabled { disabled, evidence },
                        RetirementOperation::ObserveDisabled,
                    ) => {
                        stored.snapshot.waiting = Some(RetirementWait::DisabledReadback);
                        // Weak revisions are audit evidence only. In particular,
                        // a large unqualified sequence cannot move the frontier.
                        if evidence.barrier().is_some()
                            && qualified_state_current(&stored, *disabled, evidence)?
                        {
                            stored.qualified_frontier = Some(observation.clone());
                            if *disabled {
                                stored.readback = Some(observation.clone());
                                stored.snapshot.phase = RetirementPhase::Disabled;
                                stored.snapshot.waiting = None;
                            }
                        }
                    }
                    _ => return Err(RetirementRejection::InvalidFact.into()),
                }
            }
            RetirementEffectResult::RetryNotApplied { fact } => {
                validate_fact(lease, fact)?;
                if lease.recovery == RecoveryMode::Reconcile
                    && lease.step.operation == RetirementOperation::DisableVersion
                {
                    return Err(RetirementRejection::UncertainMutation.into());
                }
                defer(
                    &tx,
                    &mut stored,
                    lease,
                    "pending",
                    RetirementWait::ProviderRetry,
                )?;
                complete = false;
            }
            RetirementEffectResult::ReconciledAbsent { fact } => {
                validate_fact(lease, fact)?;
                ensure!(
                    lease.recovery == RecoveryMode::Reconcile
                        && lease.step.operation == RetirementOperation::DisableVersion,
                    "absence evidence is only for uncertain disable"
                );
                defer(
                    &tx,
                    &mut stored,
                    lease,
                    "pending",
                    RetirementWait::ProviderRetry,
                )?;
                complete = false;
            }
            RetirementEffectResult::Ambiguous {} => {
                ensure!(
                    lease.step.operation.provider(),
                    "internal operation cannot report provider ambiguity"
                );
                defer(
                    &tx,
                    &mut stored,
                    lease,
                    "ambiguous",
                    RetirementWait::Reconciliation,
                )?;
                complete = false;
            }
        }
        if complete {
            tx.execute(
                "UPDATE secret_retirement_steps SET status='complete',result=?1 WHERE id=?2",
                params![encoded, lease.effect.as_str()],
            )?;
            stored.snapshot.next_step = stored
                .snapshot
                .next_step
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("retirement ordinal exhausted"))?;
        }
        // Deferred absence/unknown evidence is also immutable: later retries must
        // be explainable from the audit, not just a mutable pending status.
        event(
            &tx,
            &stored,
            "settled",
            &(&lease.effect, lease.epoch, &lease.owner, now, result),
        )?;
        save(&tx, &mut stored)?;
        tx.commit()?;
        Ok(stored.snapshot)
    }
}

#[derive(Debug)]
struct StepRow {
    id: Digest,
    request: RetirementStepRequest,
    status: String,
    epoch: u64,
    owner: String,
    until: u64,
    result: Option<String>,
    recovery: RecoveryMode,
    started: bool,
}

fn step_row(connection: &Connection, id: &Digest, ordinal: u64) -> Result<Option<StepRow>> {
    type Row = (
        String,
        String,
        String,
        i64,
        String,
        i64,
        Option<String>,
        bool,
        bool,
    );
    let row:Option<Row>=connection.query_row("SELECT id,request,status,epoch,owner,lease_until,result,recovery,started FROM secret_retirement_steps WHERE execution=?1 AND ordinal=?2",
        params![id.as_str(),i64::try_from(ordinal)?],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?))).optional()?;
    row.map(
        |(id, request, status, epoch, owner, until, result, recovery, started)| {
            Ok(StepRow {
                id: id.try_into()?,
                request: serde_json::from_str(&request)?,
                status,
                epoch: u64::try_from(epoch)?,
                owner,
                until: u64::try_from(until)?,
                result,
                recovery: if recovery {
                    RecoveryMode::Reconcile
                } else {
                    RecoveryMode::Execute
                },
                started,
            })
        },
    )
    .transpose()
}

fn read(connection: &Connection, id: &Digest) -> Result<Stored> {
    let (fingerprint, body): (String, String) = connection.query_row(
        "SELECT fingerprint,body FROM secret_retirements WHERE id=?1",
        [id.as_str()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let stored: Stored = serde_json::from_str(&body)?;
    let snapshot = &stored.snapshot;
    ensure!(
        snapshot.id == *id
            && snapshot.plan.execution_id()? == *id
            && snapshot.plan.fingerprint()?.as_str() == fingerprint,
        "retirement execution identity mismatch"
    );
    ensure!(
        stored.barrier.key == snapshot.plan.key
            && stored.barrier.scope == snapshot.plan.scope
            && stored.barrier.authority_revision == snapshot.plan.authority_revision
            && stored.barrier.policy == snapshot.plan.policy
            && stored.barrier.state == VersionState::Retiring,
        "retirement barrier identity mismatch"
    );
    let current = runtime_secret::retirement_in(connection, &stored.barrier.id)?;
    ensure!(
        current.id == stored.barrier.id
            && current.key == stored.barrier.key
            && current.scope == stored.barrier.scope
            && current.authority_revision == stored.barrier.authority_revision
            && current.policy == stored.barrier.policy
            && matches!(
                current.state,
                VersionState::Retiring | VersionState::Disabled
            ),
        "persisted retirement barrier changed"
    );
    let proofs = match snapshot.phase {
        RetirementPhase::WaitingConsumers | RetirementPhase::Eligible => {
            stored.disable.is_none() && stored.readback.is_none() && snapshot.terminal.is_none()
        }
        RetirementPhase::WaitingDisabled => {
            stored.disable.is_some() && stored.readback.is_none() && snapshot.terminal.is_none()
        }
        RetirementPhase::Disabled => {
            stored.disable.is_some() && stored.readback.is_some() && snapshot.terminal.is_none()
        }
        RetirementPhase::Complete => {
            stored.disable.is_some()
                && stored.readback.is_some()
                && snapshot.terminal == Some(RetirementTerminal::Disabled)
                && current.state == VersionState::Disabled
        }
        RetirementPhase::Stopped => snapshot.terminal == Some(RetirementTerminal::AuthorityLost),
    };
    let waiting = match snapshot.phase {
        RetirementPhase::WaitingConsumers => snapshot.waiting == Some(RetirementWait::Consumers),
        RetirementPhase::Eligible => matches!(
            snapshot.waiting,
            None | Some(RetirementWait::ProviderRetry | RetirementWait::Reconciliation)
        ),
        RetirementPhase::WaitingDisabled => matches!(
            snapshot.waiting,
            Some(
                RetirementWait::DisabledReadback
                    | RetirementWait::ProviderRetry
                    | RetirementWait::Reconciliation
            )
        ),
        RetirementPhase::Disabled | RetirementPhase::Complete | RetirementPhase::Stopped => {
            snapshot.waiting.is_none()
        }
    };
    ensure!(proofs && waiting, "retirement phase proof mismatch");
    if let Some(disable) = &stored.disable {
        let RetirementObserved::DisableAcknowledged { acknowledgement } = &disable.outcome else {
            anyhow::bail!("retirement disable has no exact acknowledgement");
        };
        ensure!(
            acknowledgement.effect == disable.fact.effect,
            "persisted disable acknowledgement effect mismatch"
        );
        validate_stored_observation(
            connection,
            &stored,
            disable,
            RetirementOperation::DisableVersion,
        )?;
    }
    if let Some(frontier) = &stored.qualified_frontier {
        let RetirementObserved::Disabled { disabled, evidence } = &frontier.outcome else {
            anyhow::bail!("retirement frontier is not state evidence");
        };
        ensure!(
            evidence.barrier().is_some() && qualified_state_current(&stored, *disabled, evidence)?,
            "retirement frontier lacks qualified evidence"
        );
        validate_stored_observation(
            connection,
            &stored,
            frontier,
            RetirementOperation::ObserveDisabled,
        )?;
    }
    if let Some(readback) = &stored.readback {
        ensure!(
            matches!(
                readback.outcome,
                RetirementObserved::Disabled { disabled: true, .. }
            ) && Some(readback) == stored.qualified_frontier.as_ref(),
            "retirement disabled proof mismatch"
        );
    }
    let completed: i64 = connection.query_row(
        "SELECT count(*) FROM secret_retirement_steps WHERE execution=?1 AND status='complete'",
        [id.as_str()],
        |r| r.get(0),
    )?;
    ensure!(
        u64::try_from(completed)? == snapshot.next_step,
        "retirement logical progress mismatch"
    );
    Ok(stored)
}

fn qualified_state_current(
    stored: &Stored,
    disabled: bool,
    evidence: &StateEvidence,
) -> Result<bool> {
    let acknowledged = stored
        .disable
        .as_ref()
        .ok_or(RetirementRejection::InvalidFact)?;
    let RetirementObserved::DisableAcknowledged { acknowledgement } = &acknowledged.outcome else {
        return Err(RetirementRejection::InvalidFact.into());
    };
    evidence.require(
        &stored.snapshot.plan.resources,
        &Digest::of(&stored.snapshot.plan.key)?,
        Some(&acknowledgement.effect),
    )?;
    match evidence.revision().relation(&acknowledgement.revision) {
        RevisionRelation::Older => return Ok(false),
        RevisionRelation::Incomparable => return Err(RetirementRejection::InvalidFact.into()),
        RevisionRelation::Same | RevisionRelation::Newer => {}
    }
    if let Some(frontier) = &stored.qualified_frontier {
        let RetirementObserved::Disabled {
            disabled: prior_disabled,
            evidence: prior,
        } = &frontier.outcome
        else {
            return Err(RetirementRejection::InvalidFact.into());
        };
        match evidence.revision().relation(prior.revision()) {
            RevisionRelation::Older => return Ok(false),
            RevisionRelation::Incomparable => return Err(RetirementRejection::InvalidFact.into()),
            RevisionRelation::Same if disabled != *prior_disabled => {
                return Err(RetirementRejection::InvalidFact.into());
            }
            RevisionRelation::Same | RevisionRelation::Newer => {}
        }
    }
    Ok(true)
}

fn validate_stored_observation(
    connection: &Connection,
    stored: &Stored,
    observation: &RetirementObservation,
    operation: RetirementOperation,
) -> Result<()> {
    let (request, status, result): (String, String, String) = connection.query_row(
        "SELECT request,status,result FROM secret_retirement_steps WHERE id=?1 AND execution=?2",
        params![
            observation.fact.effect.as_str(),
            stored.snapshot.id.as_str()
        ],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let request: RetirementStepRequest = serde_json::from_str(&request)?;
    let expected = RetirementEffectResult::Observed(observation.clone());
    ensure!(
        status == "complete"
            && serde_json::from_str::<RetirementEffectResult>(&result)? == expected
            && request.operation == operation
            && request.name.as_str() == operation.name()
            && effect_id(&stored.snapshot, &request)? == observation.fact.effect,
        "retirement receipt is not durably completed"
    );
    let fact = &observation.fact;
    ensure!(
        fact.execution == stored.snapshot.id
            && fact.plan == stored.snapshot.plan.fingerprint()?
            && fact.key == stored.snapshot.plan.key
            && fact.scope == stored.snapshot.plan.scope
            && fact.binding == stored.snapshot.plan.resources,
        "retirement receipt identity mismatch"
    );
    Ok(())
}

fn effect_id(snapshot: &RetirementSnapshot, request: &RetirementStepRequest) -> Result<Digest> {
    Digest::of(&(
        "day2-secret-retirement-step-v1",
        &snapshot.id,
        &snapshot.plan.recipe,
        &request.name,
        request.ordinal,
    ))
}

fn legal(snapshot: &RetirementSnapshot, request: &RetirementStepRequest) -> bool {
    request.name.as_str() == request.operation.name()
        && matches!(
            (snapshot.phase, request.operation),
            (
                RetirementPhase::WaitingConsumers,
                RetirementOperation::WaitConsumers
            ) | (
                RetirementPhase::Eligible,
                RetirementOperation::DisableVersion
            ) | (
                RetirementPhase::WaitingDisabled,
                RetirementOperation::ObserveDisabled
            ) | (RetirementPhase::Disabled, RetirementOperation::Complete)
        )
}

fn validate_lease(stored: &Stored, row: &StepRow, lease: &RetirementLease, now: u64) -> Result<()> {
    if stored.snapshot != lease.execution
        || row.id != lease.effect
        || row.request != lease.step
        || row.status != "running"
        || row.epoch != lease.epoch
        || row.owner != lease.owner.as_str()
        || row.until != lease.until
        || row.recovery != lease.recovery
        || now >= lease.until
        || lease.step.ordinal != stored.snapshot.next_step
        || !legal(&stored.snapshot, &lease.step)
        || effect_id(&stored.snapshot, &lease.step)? != lease.effect
    {
        return Err(RetirementRejection::FencedLease.into());
    }
    Ok(())
}

fn validate_fact(lease: &RetirementLease, fact: &RetirementFact) -> Result<()> {
    if lease.fact(fact.evidence.clone())? != *fact {
        return Err(RetirementRejection::InvalidFact.into());
    }
    Ok(())
}

fn authority_current(connection: &Connection, barrier: &RetirementGuard) -> Result<bool> {
    match runtime_secret::require_retirement_authority_in(connection, barrier) {
        Ok(()) => Ok(true),
        Err(error)
            if matches!(
                error.downcast_ref::<runtime_secret::RuntimeSecretRejection>(),
                Some(runtime_secret::RuntimeSecretRejection::AuthorityChanged)
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn guard_changed(connection: &Connection, stored: &Stored) -> Result<bool> {
    if matches!(
        stored.snapshot.phase,
        RetirementPhase::WaitingConsumers | RetirementPhase::Eligible
    ) {
        if !authority_current(connection, &stored.barrier)? {
            return Ok(true);
        }
        if stored.snapshot.phase == RetirementPhase::Eligible
            && runtime_secret::retirement_consumers_in(connection, &stored.barrier.id)?.protected()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn refresh_guard(connection: &Connection, stored: &mut Stored) -> Result<()> {
    if !authority_current(connection, &stored.barrier)? {
        stop(stored);
    } else {
        stored.snapshot.phase = RetirementPhase::WaitingConsumers;
        stored.snapshot.waiting = Some(RetirementWait::Consumers);
    }
    Ok(())
}

fn stop(stored: &mut Stored) {
    stored.snapshot.phase = RetirementPhase::Stopped;
    stored.snapshot.terminal = Some(RetirementTerminal::AuthorityLost);
    stored.snapshot.waiting = None;
}

fn defer(
    tx: &Transaction<'_>,
    stored: &mut Stored,
    lease: &RetirementLease,
    status: &str,
    waiting: RetirementWait,
) -> Result<()> {
    tx.execute(
        "UPDATE secret_retirement_steps SET status=?1 WHERE id=?2",
        params![status, lease.effect.as_str()],
    )?;
    stored.snapshot.waiting = Some(waiting);
    Ok(())
}

fn save(tx: &Transaction<'_>, stored: &mut Stored) -> Result<()> {
    stored.snapshot.revision = stored
        .snapshot
        .revision
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("retirement revision exhausted"))?;
    i64::try_from(stored.snapshot.revision)?;
    i64::try_from(stored.snapshot.next_step)?;
    tx.execute(
        "UPDATE secret_retirements SET body=?1 WHERE id=?2",
        params![serde_json::to_string(stored)?, stored.snapshot.id.as_str()],
    )?;
    Ok(())
}

fn event(tx: &Transaction<'_>, stored: &Stored, kind: &str, body: &impl Serialize) -> Result<()> {
    let plan = &stored.snapshot.plan;
    let value = serde_json::json!({"scope":plan.scope,"actor":plan.actor,"request":plan.request,"approval":plan.approval,
        "resource":plan.key,"authority_revision":plan.authority_revision,"policy":plan.policy,"execution":stored.snapshot.id,"phase":stored.snapshot.phase,"body":body});
    tx.execute(
        "INSERT INTO secret_retirement_events(execution,kind,body) VALUES(?1,?2,?3)",
        params![
            stored.snapshot.id.as_str(),
            kind,
            serde_json::to_string(&value)?
        ],
    )?;
    Ok(())
}
