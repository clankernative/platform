//! Durable atomic release capabilities. The pinned Roc recipe selects operations;
//! native code validates their authority, predecessor facts and exact receipts.
//! Provider I/O never runs inside a SQLite transaction. These contracts currently
//! have synthetic adapters, not qualified cloud provisioning or deployment.

use crate::journal::{Journal, RecoveryMode};
use crate::provider_evidence::{DeploymentIncarnation, RevisionRelation, StateEvidence};
use crate::release::{self, ApprovedRelease, ReadyRelease, ReleaseAuthority, ReleaseNotReady};
use crate::release::{ActivationReceipt, ReleaseApproval, ReleaseTarget, SecretObservation};
use crate::{BindingRef, Digest, Name};
use anyhow::{Result, ensure};
use durable_temporal::{AdvanceBackend, BackendError, StepOutcome, TemporalAdapter};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};

pub const LEASE_MILLIS: u64 = 20_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseExecutionPlan {
    pub release: Digest,
    pub recipe: Digest,
    pub durability: BindingRef,
    pub resources: BindingRef,
    pub deployment: BindingRef,
}
impl ReleaseExecutionPlan {
    pub fn execution_id(&self) -> Result<Digest> {
        Digest::of(&("day2-release-workflow-v1", &self.release))
    }

    pub fn fingerprint(&self) -> Result<Digest> {
        Digest::of(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleasePhase {
    Accepted,
    WaitingSecret,
    SecretReady,
    WaitingDeployment,
    DeploymentReady,
    Active,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseWait {
    SecretMetadata,
    SecretDisabled,
    SecretAccess,
    SecretProjection,
    Deployment,
    ProviderRetry,
    Reconciliation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseTerminal {
    Activated,
    AuthorityLost,
    Intervention,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSnapshot {
    pub id: Digest,
    pub plan: ReleaseExecutionPlan,
    pub target: ReleaseTarget,
    pub phase: ReleasePhase,
    pub next_step: u64,
    pub revision: u64,
    pub waiting: Option<ReleaseWait>,
    pub terminal: Option<ReleaseTerminal>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseOperation {
    PrepareDependency,
    ObserveSecret,
    PrepareDeployment,
    ObserveDeployment,
    Activate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepRequest {
    pub name: Name,
    pub ordinal: u64,
    pub operation: ReleaseOperation,
}

pub trait Recipe: Send + Sync + 'static {
    fn revision(&self) -> Result<Digest>;
    fn choose(&self, snapshot: &ReleaseSnapshot) -> Result<StepRequest>;
}

pub trait Capabilities: Send + Sync + 'static {
    fn validate(&self, plan: &ReleaseExecutionPlan, approval: &ReleaseApproval) -> Result<()>;
    fn perform(&self, lease: &ReleaseLease) -> Result<ReleaseEffectResult>;
}

#[derive(Clone, Debug)]
pub struct ReleaseLease {
    pub execution: ReleaseSnapshot,
    pub step: StepRequest,
    pub effect: Digest,
    pub epoch: u64,
    pub owner: Name,
    pub until: u64,
    pub recovery: RecoveryMode,
    pub approval: ReleaseApproval,
    pub readiness: Option<Digest>,
}

#[derive(Clone, Debug)]
pub enum ReleaseClaim {
    Acquired(Box<ReleaseLease>),
    Busy,
    Terminal(Box<ReleaseSnapshot>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseProviderFact {
    pub execution: Digest,
    pub effect: Digest,
    pub plan: Digest,
    pub release: Digest,
    pub target: ReleaseTarget,
    pub artifact: Digest,
    pub secret: crate::release::ImmutableSecretRef,
    pub binding: BindingRef,
    pub resource: Digest,
    pub readiness: Option<Digest>,
    pub evidence: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReleaseObserved {
    DependencyPrepared {},
    Secret {
        metadata: Option<SecretObservation>,
    },
    DeploymentPrepared {
        incarnation: DeploymentIncarnation,
    },
    Deployment {
        ready: bool,
        evidence: StateEvidence,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseObservation {
    pub fact: ReleaseProviderFact,
    pub outcome: ReleaseObserved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReleaseEffectResult {
    Observed(Box<ReleaseObservation>),
    RetryNotApplied {},
    ReconciledAbsent { fact: Box<ReleaseProviderFact> },
    Ambiguous {},
    Activate {},
    GuardChanged {},
}

impl ReleaseLease {
    /// Stable resource identity is execution + resource family, not poll/attempt.
    /// A repeat prepare cannot silently allocate a different dependency/deployment.
    pub fn fact(&self, evidence: Digest) -> Result<ReleaseProviderFact> {
        let (family, binding) = match self.step.operation {
            ReleaseOperation::PrepareDependency | ReleaseOperation::ObserveSecret => {
                ("dependency", self.execution.plan.resources.clone())
            }
            ReleaseOperation::PrepareDeployment | ReleaseOperation::ObserveDeployment => {
                ("deployment", self.execution.plan.deployment.clone())
            }
            ReleaseOperation::Activate => anyhow::bail!("activation has no provider capability"),
        };
        Ok(ReleaseProviderFact {
            execution: self.execution.id.clone(),
            effect: self.effect.clone(),
            plan: self.execution.plan.fingerprint()?,
            release: self.execution.plan.release.clone(),
            target: self.execution.target.clone(),
            artifact: self.approval.artifact.clone(),
            secret: self.approval.secret.clone(),
            binding,
            resource: Digest::of(&("day2-release-resource-v1", &self.execution.id, family))?,
            readiness: if family == "deployment" {
                self.readiness.clone()
            } else {
                None
            },
            evidence,
        })
    }
}

pub struct ReleaseExecutionHost {
    journal: PathBuf,
    company: Name,
    owner: Name,
    durability: BindingRef,
    capabilities: Arc<dyn Capabilities>,
    recipe: Arc<dyn Recipe>,
}

impl ReleaseExecutionHost {
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

    fn validate_scope(
        &self,
        plan: &ReleaseExecutionPlan,
        approval: &ReleaseApproval,
    ) -> Result<()> {
        ensure!(
            approval.target.company == self.company,
            "release host company mismatch"
        );
        ensure!(
            plan.durability == self.durability,
            "release durable binding mismatch"
        );
        Ok(())
    }

    fn validate(&self, plan: &ReleaseExecutionPlan, approval: &ReleaseApproval) -> Result<()> {
        self.validate_scope(plan, approval)?;
        ensure!(
            plan.recipe == self.recipe.revision()?,
            "release recipe identity mismatch"
        );
        Ok(())
    }

    pub fn accept(&self, plan: &ReleaseExecutionPlan) -> Result<Digest> {
        let mut journal = Journal::open(&self.journal)?;
        let approval = release::read_approval(&journal.connection, &plan.release)?.approval;
        self.validate(plan, &approval)?;
        self.capabilities.validate(plan, &approval)?;
        Ok(journal.accept_release_execution(plan)?.id)
    }

    pub fn inspect(&self, id: &Digest) -> Result<ReleaseSnapshot> {
        let journal = Journal::open(&self.journal)?;
        let stored = read_execution(&journal.connection, id)?;
        self.validate_scope(&stored.snapshot.plan, &stored.approval)?;
        Ok(stored.snapshot)
    }

    pub fn claim_at(&self, id: &Digest, request: &StepRequest, now: u64) -> Result<ReleaseClaim> {
        let snapshot = self.inspect(id)?;
        if snapshot.terminal.is_some() {
            return Ok(ReleaseClaim::Terminal(Box::new(snapshot)));
        }
        ensure!(
            snapshot.plan.recipe == self.recipe.revision()?,
            "release recipe identity mismatch"
        );
        // The driver evaluated the pinned recipe. The journal independently
        // checks the requested operation's predecessor facts and logical ordinal.
        Journal::open(&self.journal)?.claim_release_step(id, request, self.owner.clone(), now)
    }

    pub fn perform(&self, lease: &ReleaseLease) -> Result<ReleaseEffectResult> {
        self.perform_at(lease, wall_clock()?)
    }

    pub fn perform_at(&self, lease: &ReleaseLease, now: u64) -> Result<ReleaseEffectResult> {
        self.perform_checked(lease, Some(now))
    }

    fn perform_checked(
        &self,
        lease: &ReleaseLease,
        now: Option<u64>,
    ) -> Result<ReleaseEffectResult> {
        self.validate(&lease.execution.plan, &lease.approval)?;
        self.capabilities
            .validate(&lease.execution.plan, &lease.approval)?;
        let mut journal = Journal::open(&self.journal)?;
        let tx = day2::write_queue::immediate(&mut journal.connection)?;
        let stored = read_execution(&tx, &lease.execution.id)?;
        let row = step_row(&tx, &lease.execution.id, lease.step.ordinal)?
            .ok_or(ReleaseRejection::FencedLease)?;
        validate_lease(&stored, &row, lease, now)?;
        if row.started {
            return Err(ReleaseRejection::FencedLease.into());
        }
        // Reconciliation must remain possible after revocation: it observes an
        // already uncertain mutation, rather than authorizing another mutation.
        if lease.recovery == RecoveryMode::Execute && guards_changed(&tx, &stored)? {
            tx.commit()?;
            return Ok(ReleaseEffectResult::GuardChanged {});
        }
        tx.execute(
            "UPDATE release_steps SET started=1 WHERE id=?1",
            [lease.effect.as_str()],
        )?;
        workflow_event(
            &tx,
            &stored,
            "workflow_provider_dispatch",
            &(
                &lease.effect,
                lease.epoch,
                lease.recovery == RecoveryMode::Reconcile,
            ),
        )?;
        tx.commit()?;
        if lease.step.operation == ReleaseOperation::Activate {
            return Ok(ReleaseEffectResult::Activate {});
        }
        match self.capabilities.perform(lease) {
            Ok(ReleaseEffectResult::Activate {} | ReleaseEffectResult::GuardChanged {}) => {
                Err(ReleaseRejection::InvalidFact.into())
            }
            Ok(result) => Ok(result),
            Err(_) => {
                let _=journal.connection.execute("INSERT INTO release_events(target,kind,body) VALUES(?1,'workflow_host_fault',?2)",
                    params![serde_json::to_string(&stored.snapshot.target)?,serde_json::to_string(&(&stored.snapshot.id,"provider"))?]);
                Err(anyhow::anyhow!("release provider host fault"))
            }
        }
    }

    pub fn settle_at(
        &self,
        lease: &ReleaseLease,
        result: ReleaseEffectResult,
        now: u64,
    ) -> Result<StepOutcome> {
        // Receipt settlement does not require current Git approval: exact scope
        // and implementation pins are checked, then the journal drains/rejects it.
        self.validate(&lease.execution.plan, &lease.approval)?;
        let snapshot = Journal::open(&self.journal)?.settle_release_step(lease, &result, now)?;
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
        let request = self.recipe.choose(&snapshot)?;
        let now = clock()?;
        let lease = match self.claim_at(id, &request, now)? {
            ReleaseClaim::Acquired(lease) => lease,
            ReleaseClaim::Busy => return Ok(StepOutcome::Continue),
            ReleaseClaim::Terminal(snapshot) => return Ok(progress(&snapshot)),
        };
        let result = self.perform_at(&lease, clock()?.max(now))?;
        self.settle_at(&lease, result, clock()?.max(now))
    }

    pub async fn dispatch(&self, adapter: &TemporalAdapter) -> Result<usize> {
        self.durability.verify(adapter.binding_configuration())?;
        let ids = Journal::open(&self.journal)?.pending_release_dispatches(
            &self.company,
            &self.durability,
            256,
        )?;
        let mut count = 0;
        for id in ids {
            let snapshot = self.inspect(&id)?;
            let receipt = adapter.ensure_started(snapshot.id.as_str()).await?;
            let mut journal = Journal::open(&self.journal)?;
            let tx = day2::write_queue::immediate(&mut journal.connection)?;
            let (prior, run): (Option<String>, Option<String>) = tx.query_row(
                "SELECT workflow_id,run_id FROM release_workflow_outbox WHERE execution=?1",
                [snapshot.id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            ensure!(
                prior
                    .as_ref()
                    .is_none_or(|prior| prior == &receipt.workflow_id),
                "release workflow receipt mismatch"
            );
            if prior.as_ref() == Some(&receipt.workflow_id) && run.as_ref() == Some(&receipt.run_id)
            {
                tx.commit()?;
                continue;
            }
            tx.execute(
                "UPDATE release_workflow_outbox SET workflow_id=?1,run_id=?2 WHERE execution=?3",
                params![receipt.workflow_id, receipt.run_id, snapshot.id.as_str()],
            )?;
            let stored = read_execution(&tx, &snapshot.id)?;
            workflow_event(
                &tx,
                &stored,
                "workflow_dispatched",
                &(&receipt.workflow_id, &receipt.run_id),
            )?;
            tx.commit()?;
            count += 1;
        }
        Ok(count)
    }
}

impl AdvanceBackend for ReleaseExecutionHost {
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
        let stored =
            read_execution(&journal.connection, &id).map_err(|_| BackendError::Retryable)?;
        if stored.approval.target.company != self.company
            || stored.snapshot.plan.durability != self.durability
        {
            return Err(BackendError::Rejected);
        }
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

fn progress(snapshot: &ReleaseSnapshot) -> StepOutcome {
    match snapshot.terminal {
        Some(ReleaseTerminal::Activated) => StepOutcome::Succeeded,
        Some(_) => StepOutcome::Failed,
        None => StepOutcome::Continue,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseRejection {
    FencedLease,
    ConflictingCompletion,
    StaleStep,
    InvalidFact,
    UncertainMutation,
}
impl std::fmt::Display for ReleaseRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::FencedLease => "release lease fenced",
            Self::ConflictingCompletion => "conflicting release completion",
            Self::StaleStep => "stale release step",
            Self::InvalidFact => "release provider fact identity mismatch",
            Self::UncertainMutation => "release mutation requires explicit reconciliation",
        })
    }
}
impl std::error::Error for ReleaseRejection {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredExecution {
    snapshot: ReleaseSnapshot,
    approval: ReleaseApproval,
    readiness: Option<Digest>,
    dependency: Option<ReleaseProviderFact>,
    deployment: Option<ReleaseProviderFact>,
    incarnation: Option<DeploymentIncarnation>,
    readback: Option<ReleaseProviderFact>,
    activation: Option<ActivationReceipt>,
}

impl ReleaseOperation {
    fn name(self) -> &'static str {
        match self {
            Self::PrepareDependency => "prepare_dependency",
            Self::ObserveSecret => "observe_secret",
            Self::PrepareDeployment => "prepare_deployment",
            Self::ObserveDeployment => "observe_deployment",
            Self::Activate => "activate",
        }
    }

    fn mutation(self) -> bool {
        matches!(self, Self::PrepareDependency | Self::PrepareDeployment)
    }
}

impl Journal {
    pub fn release_deployment_fact(&self, release: &Digest) -> Result<Option<ReleaseProviderFact>> {
        runtime_deployment_fact(&self.connection, release)
    }

    pub(crate) fn initialize_release_execution_schema(&mut self) -> Result<()> {
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS release_execution_meta(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL);
            INSERT OR IGNORE INTO release_execution_meta VALUES(1,2);",
        )?;
        let version: i64 = tx.query_row(
            "SELECT version FROM release_execution_meta WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        if version == 1 {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='release_workflows')",
                [], |row| row.get(0),
            )?;
            if exists {
                let occupied: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM release_workflows)",
                    [],
                    |row| row.get(0),
                )?;
                ensure!(
                    !occupied,
                    "legacy release execution evidence requires explicit reviewed migration"
                );
            }
            tx.execute(
                "UPDATE release_execution_meta SET version=2 WHERE singleton=1",
                [],
            )?;
        } else {
            ensure!(version == 2, "unsupported release execution schema");
        }
        tx.execute_batch("CREATE TABLE IF NOT EXISTS release_workflows(
            id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS release_workflow_outbox(
            execution TEXT PRIMARY KEY REFERENCES release_workflows(id), workflow_id TEXT,run_id TEXT);
            CREATE TABLE IF NOT EXISTS release_steps(
            id TEXT PRIMARY KEY,execution TEXT NOT NULL REFERENCES release_workflows(id),
            ordinal INTEGER NOT NULL CHECK(ordinal>=0), request TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('running','pending','ambiguous','complete')),
            epoch INTEGER NOT NULL CHECK(epoch>0),owner TEXT NOT NULL,lease_until INTEGER NOT NULL,
            result TEXT, recovery INTEGER NOT NULL CHECK(recovery IN (0,1)),
            started INTEGER NOT NULL CHECK(started IN (0,1)), UNIQUE(execution,ordinal));")?;
        tx.commit()?;
        Ok(())
    }

    pub fn accept_release_execution(
        &mut self,
        plan: &ReleaseExecutionPlan,
    ) -> Result<ReleaseSnapshot> {
        let id = plan.execution_id()?;
        let fingerprint = plan.fingerprint()?;
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        if let Some(prior) = tx
            .query_row(
                "SELECT fingerprint FROM release_workflows WHERE id=?1",
                [id.as_str()],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            ensure!(
                prior == fingerprint.as_str(),
                "release execution binding cannot change"
            );
            return Ok(read_execution(&tx, &id)?.snapshot);
        }
        let approval = release::current_approval(&tx, &plan.release)?.approval;
        ensure!(
            plan.resources == approval.secret.binding,
            "resource capability differs from approved secret binding"
        );
        ensure!(
            plan.resources.id != plan.deployment.id
                && plan.resources.id != plan.durability.id
                && plan.deployment.id != plan.durability.id,
            "release capability identities must be distinct"
        );
        let snapshot = ReleaseSnapshot {
            id: id.clone(),
            plan: plan.clone(),
            target: approval.target.clone(),
            phase: ReleasePhase::Accepted,
            next_step: 0,
            revision: 0,
            waiting: None,
            terminal: None,
        };
        let stored = StoredExecution {
            snapshot: snapshot.clone(),
            approval,
            readiness: None,
            dependency: None,
            deployment: None,
            incarnation: None,
            readback: None,
            activation: None,
        };
        tx.execute(
            "INSERT INTO release_workflows VALUES(?1,?2,?3)",
            params![
                id.as_str(),
                fingerprint.as_str(),
                serde_json::to_string(&stored)?
            ],
        )?;
        tx.execute(
            "INSERT INTO release_workflow_outbox(execution) VALUES(?1)",
            [id.as_str()],
        )?;
        workflow_event(&tx, &stored, "workflow_accepted", plan)?;
        tx.commit()?;
        Ok(snapshot)
    }

    pub fn release_execution(&self, id: &Digest) -> Result<ReleaseSnapshot> {
        Ok(read_execution(&self.connection, id)?.snapshot)
    }

    pub fn release_execution_approval(&self, id: &Digest) -> Result<ReleaseApproval> {
        Ok(read_execution(&self.connection, id)?.approval)
    }

    pub fn pending_release_dispatches(
        &self,
        company: &Name,
        durability: &BindingRef,
        limit: u32,
    ) -> Result<Vec<Digest>> {
        ensure!((1..=256).contains(&limit), "release outbox page budget");
        let mut stmt=self.connection.prepare("SELECT w.id FROM release_workflow_outbox o
            JOIN release_workflows w ON w.id=o.execution WHERE o.workflow_id IS NULL
            AND json_extract(w.body,'$.snapshot.terminal') IS NULL
            AND json_extract(w.body,'$.snapshot.target.company')=?1
            AND json_extract(w.body,'$.snapshot.plan.durability.id')=?2
            AND json_extract(w.body,'$.snapshot.plan.durability.revision')=?3 ORDER BY w.id LIMIT ?4")?;
        stmt.query_map(
            params![
                company.as_str(),
                durability.id.as_str(),
                durability.revision.as_str(),
                limit
            ],
            |r| r.get::<_, String>(0),
        )?
        .map(|row| Digest::try_from(row?))
        .collect()
    }

    pub fn release_executions(
        &self,
        company: &Name,
        durability: &BindingRef,
        limit: u32,
    ) -> Result<Vec<ReleaseSnapshot>> {
        ensure!((1..=256).contains(&limit), "release execution page budget");
        let mut stmt = self.connection.prepare(
            "SELECT id FROM release_workflows
            WHERE json_extract(body,'$.snapshot.target.company')=?1
            AND json_extract(body,'$.snapshot.plan.durability.id')=?2
            AND json_extract(body,'$.snapshot.plan.durability.revision')=?3 ORDER BY id LIMIT ?4",
        )?;
        stmt.query_map(
            params![
                company.as_str(),
                durability.id.as_str(),
                durability.revision.as_str(),
                limit
            ],
            |r| r.get::<_, String>(0),
        )?
        .map(|row| {
            let id = Digest::try_from(row?)?;
            let stored = read_execution(&self.connection, &id)?;
            ensure!(
                stored.snapshot.target.company == *company
                    && stored.snapshot.plan.durability == *durability,
                "listed release execution scope mismatch"
            );
            Ok(stored.snapshot)
        })
        .collect()
    }

    pub fn claim_release_step(
        &mut self,
        id: &Digest,
        step: &StepRequest,
        owner: Name,
        now: u64,
    ) -> Result<ReleaseClaim> {
        let until = now
            .checked_add(LEASE_MILLIS)
            .ok_or_else(|| anyhow::anyhow!("release lease overflow"))?;
        i64::try_from(until)?;
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        let mut stored = read_execution(&tx, id)?;
        if stored.snapshot.terminal.is_some() {
            return Ok(ReleaseClaim::Terminal(Box::new(stored.snapshot)));
        }
        let prior = step_row(&tx, id, stored.snapshot.next_step)?;
        let uncertain = prior.as_ref().is_some_and(|row| {
            row.status == "ambiguous"
                || (row.status == "running"
                    && (row.started || row.recovery == RecoveryMode::Reconcile))
        });
        if !uncertain && refresh_guards(&tx, &mut stored)? {
            if let Some(prior) = &prior {
                tx.execute(
                    "UPDATE release_steps SET status='complete',result=?1 WHERE id=?2",
                    params![
                        serde_json::to_string(&ReleaseEffectResult::GuardChanged {})?,
                        prior.id.as_str()
                    ],
                )?;
                stored.snapshot.next_step = stored
                    .snapshot
                    .next_step
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("release ordinal exhausted"))?;
                workflow_event(&tx, &stored, "workflow_retired_unapplied_step", &prior.id)?;
            }
            save_execution(&tx, &mut stored)?;
            tx.commit()?;
            return Ok(if stored.snapshot.terminal.is_some() {
                ReleaseClaim::Terminal(Box::new(stored.snapshot))
            } else {
                ReleaseClaim::Busy
            });
        }
        if step.ordinal != stored.snapshot.next_step || !legal_step(&stored, step) {
            return Err(ReleaseRejection::StaleStep.into());
        }
        let effect = Digest::of(&(
            "day2-release-step-v1",
            id,
            &stored.snapshot.plan.recipe,
            &step.name,
            step.ordinal,
        ))?;
        let (epoch, recovery) = match prior {
            Some(prior) => {
                if prior.request != *step || prior.id != effect {
                    return Err(ReleaseRejection::StaleStep.into());
                }
                if prior.status == "running" && prior.until > now {
                    return Ok(ReleaseClaim::Busy);
                }
                ensure!(
                    prior.status != "complete",
                    "completed release step is still current"
                );
                (
                    prior
                        .epoch
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("release lease epoch exhausted"))?,
                    if prior.status == "pending"
                        || (prior.status == "running"
                            && !prior.started
                            && prior.recovery == RecoveryMode::Execute)
                    {
                        RecoveryMode::Execute
                    } else {
                        RecoveryMode::Reconcile
                    },
                )
            }
            None => (1, RecoveryMode::Execute),
        };
        tx.execute("INSERT INTO release_steps VALUES(?1,?2,?3,?4,'running',?5,?6,?7,NULL,?8,0)
            ON CONFLICT(id) DO UPDATE SET status='running',epoch=excluded.epoch,
            owner=excluded.owner,lease_until=excluded.lease_until,recovery=excluded.recovery,started=0",
            params![effect.as_str(),id.as_str(),i64::try_from(step.ordinal)?,serde_json::to_string(step)?,
                i64::try_from(epoch)?,owner.as_str(),i64::try_from(until)?,recovery==RecoveryMode::Reconcile])?;
        workflow_event(
            &tx,
            &stored,
            "workflow_claimed",
            &(
                &effect,
                step,
                epoch,
                &owner,
                until,
                recovery == RecoveryMode::Reconcile,
            ),
        )?;
        let lease = ReleaseLease {
            execution: stored.snapshot,
            step: step.clone(),
            effect,
            epoch,
            owner,
            until,
            recovery,
            approval: stored.approval,
            readiness: stored.readiness,
        };
        tx.commit()?;
        Ok(ReleaseClaim::Acquired(Box::new(lease)))
    }

    pub fn settle_release_step(
        &mut self,
        lease: &ReleaseLease,
        result: &ReleaseEffectResult,
        now: u64,
    ) -> Result<ReleaseSnapshot> {
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        let mut stored = read_execution(&tx, &lease.execution.id)?;
        let row = step_row(&tx, &lease.execution.id, lease.step.ordinal)?
            .ok_or(ReleaseRejection::FencedLease)?;
        let encoded = serde_json::to_string(result)?;
        if row.status == "complete" {
            if row.id != lease.effect
                || row.result.as_deref() != Some(encoded.as_str())
                || row.request != lease.step
                || stored.snapshot.plan != lease.execution.plan
                || stored.approval != lease.approval
            {
                return Err(ReleaseRejection::ConflictingCompletion.into());
            }
            return Ok(stored.snapshot);
        }
        validate_lease(&stored, &row, lease, Some(now))?;
        if !matches!(result, ReleaseEffectResult::GuardChanged {}) && !row.started {
            return Err(ReleaseRejection::FencedLease.into());
        }
        match result {
            ReleaseEffectResult::GuardChanged {} => {
                ensure!(
                    !row.started,
                    "dispatched effect cannot be abandoned as unapplied"
                );
                ensure!(
                    refresh_guards(&tx, &mut stored)?,
                    "guard refusal has no changed guard"
                );
                complete_step(&tx, &mut stored, lease, &encoded)?;
            }
            ReleaseEffectResult::RetryNotApplied {} => {
                if lease.recovery == RecoveryMode::Reconcile && lease.step.operation.mutation() {
                    return Err(ReleaseRejection::UncertainMutation.into());
                }
                defer_step(
                    &tx,
                    &mut stored,
                    lease,
                    "pending",
                    ReleaseWait::ProviderRetry,
                )?;
            }
            ReleaseEffectResult::ReconciledAbsent { fact } => {
                validate_fact(lease, fact)?;
                ensure!(
                    lease.recovery == RecoveryMode::Reconcile && lease.step.operation.mutation(),
                    "absence proof is only for uncertain mutations"
                );
                defer_step(
                    &tx,
                    &mut stored,
                    lease,
                    "pending",
                    ReleaseWait::ProviderRetry,
                )?;
            }
            ReleaseEffectResult::Ambiguous {} => {
                defer_step(
                    &tx,
                    &mut stored,
                    lease,
                    "ambiguous",
                    ReleaseWait::Reconciliation,
                )?;
            }
            ReleaseEffectResult::Observed(observation) => {
                validate_fact(lease, &observation.fact)?;
                validate_observation_kind(lease, observation)?;
                if approval_current(&tx, &stored)? {
                    apply_observation(&tx, &mut stored, lease, observation)?;
                }
                complete_step(&tx, &mut stored, lease, &encoded)?;
                if !approval_current(&tx, &stored)? {
                    stop(&tx, &mut stored, ReleaseTerminal::AuthorityLost)?;
                }
            }
            ReleaseEffectResult::Activate {} => {
                ensure!(
                    lease.step.operation == ReleaseOperation::Activate,
                    "activation used for a provider step"
                );
                if !refresh_guards(&tx, &mut stored)? {
                    ensure!(
                        stored
                            .readback
                            .as_ref()
                            .is_some_and(|fact| fact.readiness == stored.readiness),
                        "deployment has no exact current readback"
                    );
                    let ready = ReadyRelease {
                        id: stored
                            .readiness
                            .clone()
                            .ok_or_else(|| anyhow::anyhow!("missing release readiness"))?,
                        release: stored.snapshot.plan.release.clone(),
                    };
                    stored.activation = Some(Journal::activate_release_in(&tx, &ready)?);
                    stored.snapshot.phase = ReleasePhase::Active;
                    stored.snapshot.terminal = Some(ReleaseTerminal::Activated);
                    stored.snapshot.waiting = None;
                }
                complete_step(&tx, &mut stored, lease, &encoded)?;
            }
        }
        if matches!(
            result,
            ReleaseEffectResult::RetryNotApplied {}
                | ReleaseEffectResult::ReconciledAbsent { .. }
                | ReleaseEffectResult::Ambiguous {}
        ) {
            // A later Execute needs the exact evidence that made retry safe,
            // not merely a mutable status saying the effect is pending again.
            workflow_event(
                &tx,
                &stored,
                "workflow_settlement",
                &(&lease.effect, result),
            )?;
        }
        save_execution(&tx, &mut stored)?;
        tx.commit()?;
        Ok(stored.snapshot)
    }
}

/// Resource-lifecycle guards read the same validated deployment record as the
/// release host. An activation pointer alone is not a provider drain proof.
pub(crate) fn runtime_deployment_fact(
    connection: &Connection,
    release: &Digest,
) -> Result<Option<ReleaseProviderFact>> {
    let id = Digest::of(&("day2-release-workflow-v1", release))?;
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM release_workflows WHERE id=?1)",
        [id.as_str()],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    Ok(read_execution(connection, &id)?.deployment)
}

#[derive(Debug)]
struct StepRow {
    id: Digest,
    request: StepRequest,
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
    let row: Option<Row> = connection
        .query_row(
            "SELECT id,request,status,epoch,owner,lease_until,result,recovery,started
        FROM release_steps WHERE execution=?1 AND ordinal=?2",
            params![id.as_str(), i64::try_from(ordinal)?],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                ))
            },
        )
        .optional()?;
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

fn read_execution(connection: &Connection, id: &Digest) -> Result<StoredExecution> {
    let (fingerprint, body): (String, String) = connection.query_row(
        "SELECT fingerprint,body FROM release_workflows WHERE id=?1",
        [id.as_str()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let stored: StoredExecution = serde_json::from_str(&body)?;
    ensure!(
        stored.snapshot.id == *id
            && stored.snapshot.plan.execution_id()? == *id
            && stored.snapshot.plan.fingerprint()?.as_str() == fingerprint,
        "release execution identity mismatch"
    );
    let approval = release::read_approval(connection, &stored.snapshot.plan.release)?.approval;
    ensure!(
        approval == stored.approval && approval.target == stored.snapshot.target,
        "release execution approval mismatch"
    );
    validate_stored_state(connection, &stored)?;
    Ok(stored)
}

fn validate_stored_state(connection: &Connection, stored: &StoredExecution) -> Result<()> {
    ensure!(
        stored.deployment.is_some() == stored.incarnation.is_some(),
        "deployment incarnation receipt missing or premature"
    );
    if let Some(incarnation) = &stored.incarnation {
        incarnation.validate()?;
    }
    let snapshot = &stored.snapshot;
    let active = snapshot.phase == ReleasePhase::Active;
    let stopped = snapshot.phase == ReleasePhase::Stopped;
    ensure!(
        active == (snapshot.terminal == Some(ReleaseTerminal::Activated)),
        "release active terminal mismatch"
    );
    ensure!(
        stopped
            == matches!(
                snapshot.terminal,
                Some(ReleaseTerminal::AuthorityLost | ReleaseTerminal::Intervention)
            ),
        "release stopped terminal mismatch"
    );
    ensure!(
        active == stored.activation.is_some(),
        "release activation receipt missing or premature"
    );
    if active || stopped {
        ensure!(
            snapshot.waiting.is_none(),
            "terminal release is also waiting"
        );
    }
    let needs_readiness = matches!(
        snapshot.phase,
        ReleasePhase::SecretReady
            | ReleasePhase::WaitingDeployment
            | ReleasePhase::DeploymentReady
            | ReleasePhase::Active
    );
    let needs_deployment = matches!(
        snapshot.phase,
        ReleasePhase::WaitingDeployment | ReleasePhase::DeploymentReady | ReleasePhase::Active
    );
    let needs_readback = matches!(
        snapshot.phase,
        ReleasePhase::DeploymentReady | ReleasePhase::Active
    );
    if !stopped {
        ensure!(
            (snapshot.phase != ReleasePhase::Accepted) == stored.dependency.is_some(),
            "release dependency phase mismatch"
        );
        ensure!(
            needs_readiness == stored.readiness.is_some(),
            "release readiness phase mismatch"
        );
        ensure!(
            needs_deployment == stored.deployment.is_some(),
            "release deployment phase mismatch"
        );
        ensure!(
            needs_readback == stored.readback.is_some(),
            "release readback phase mismatch"
        );
        if matches!(
            snapshot.phase,
            ReleasePhase::WaitingSecret | ReleasePhase::WaitingDeployment
        ) {
            ensure!(
                snapshot.waiting.is_some(),
                "release waiting phase lacks reason"
            );
        }
    }
    if let Some(readiness) = &stored.readiness {
        let body: String = connection.query_row(
            "SELECT body FROM release_readiness WHERE id=?1 AND release=?2",
            params![readiness.as_str(), snapshot.plan.release.as_str()],
            |r| r.get(0),
        )?;
        let proof: release::StoredReady = serde_json::from_str(&body)?;
        ensure!(
            proof.release == snapshot.plan.release
                && Digest::of(&("day2-release-readiness-v1", &proof))? == *readiness,
            "stored release readiness receipt mismatch"
        );
    }
    for (fact, family, binding, operation) in [
        (
            &stored.dependency,
            "dependency",
            &snapshot.plan.resources,
            ReleaseOperation::PrepareDependency,
        ),
        (
            &stored.deployment,
            "deployment",
            &snapshot.plan.deployment,
            ReleaseOperation::PrepareDeployment,
        ),
        (
            &stored.readback,
            "deployment",
            &snapshot.plan.deployment,
            ReleaseOperation::ObserveDeployment,
        ),
    ] {
        if let Some(fact) = fact {
            ensure!(
                fact.execution == snapshot.id
                    && fact.plan == snapshot.plan.fingerprint()?
                    && fact.release == snapshot.plan.release
                    && fact.target == snapshot.target
                    && fact.artifact == stored.approval.artifact
                    && fact.secret == stored.approval.secret
                    && &fact.binding == binding
                    && fact.resource
                        == Digest::of(&("day2-release-resource-v1", &snapshot.id, family))?
                    && fact.readiness
                        == if family == "dependency" {
                            None
                        } else {
                            stored.readiness.clone()
                        },
                "stored provider fact binding mismatch"
            );
            let (request, result): (String, String) = connection.query_row(
                "SELECT request,result FROM release_steps
                WHERE id=?1 AND execution=?2 AND status='complete'",
                params![fact.effect.as_str(), snapshot.id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let request: StepRequest = serde_json::from_str(&request)?;
            let result: ReleaseEffectResult = serde_json::from_str(&result)?;
            ensure!(
                request.operation == operation
                    && matches!(&result,ReleaseEffectResult::Observed(observation)
                if observation.fact==*fact),
                "stored provider fact has no completed step receipt"
            );
            if let ReleaseEffectResult::Observed(observation) = &result {
                match &observation.outcome {
                    ReleaseObserved::DeploymentPrepared { incarnation } => ensure!(
                        Some(incarnation) == stored.incarnation.as_ref(),
                        "stored deployment incarnation differs from preparation receipt"
                    ),
                    ReleaseObserved::Deployment { ready, evidence } => {
                        ensure!(
                            *ready,
                            "stored deployment readiness lacks positive readback"
                        );
                        let prepared = stored
                            .deployment
                            .as_ref()
                            .ok_or(ReleaseRejection::InvalidFact)?;
                        evidence.require(
                            &prepared.binding,
                            &prepared.resource,
                            Some(&prepared.effect),
                        )?;
                    }
                    _ => {}
                }
            }
        }
    }
    if let Some(activation) = &stored.activation {
        let body: String = connection.query_row(
            "SELECT body FROM release_activations WHERE release=?1",
            [snapshot.plan.release.as_str()],
            |r| r.get(0),
        )?;
        let receipt: ActivationReceipt = serde_json::from_str(&body)?;
        ensure!(
            activation == &receipt
                && receipt.release == snapshot.plan.release
                && receipt.target == snapshot.target
                && receipt.artifact == stored.approval.artifact
                && receipt.secret == stored.approval.secret
                && Some(&receipt.readiness) == stored.readiness.as_ref(),
            "workflow activation authority receipt mismatch"
        );
    }
    Ok(())
}

fn save_execution(connection: &Connection, stored: &mut StoredExecution) -> Result<()> {
    stored.snapshot.revision = stored
        .snapshot
        .revision
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("release revision exhausted"))?;
    connection.execute(
        "UPDATE release_workflows SET body=?1 WHERE id=?2",
        params![serde_json::to_string(stored)?, stored.snapshot.id.as_str()],
    )?;
    Ok(())
}

fn workflow_event<T: Serialize>(
    connection: &Connection,
    stored: &StoredExecution,
    kind: &str,
    body: &T,
) -> Result<()> {
    release::release_event(
        connection,
        &stored.snapshot.target,
        kind,
        &(&stored.snapshot.id, body),
    )
}

fn legal_step(stored: &StoredExecution, step: &StepRequest) -> bool {
    step.name.as_str() == step.operation.name()
        && matches!(
            (stored.snapshot.phase, step.operation),
            (ReleasePhase::Accepted, ReleaseOperation::PrepareDependency)
                | (ReleasePhase::WaitingSecret, ReleaseOperation::ObserveSecret)
                | (
                    ReleasePhase::SecretReady,
                    ReleaseOperation::PrepareDeployment
                )
                | (
                    ReleasePhase::WaitingDeployment,
                    ReleaseOperation::ObserveDeployment
                )
                | (ReleasePhase::DeploymentReady, ReleaseOperation::Activate)
        )
}

fn validate_lease(
    stored: &StoredExecution,
    row: &StepRow,
    lease: &ReleaseLease,
    now: Option<u64>,
) -> Result<()> {
    if row.status != "running"
        || row.id != lease.effect
        || row.request != lease.step
        || row.epoch != lease.epoch
        || row.owner != lease.owner.as_str()
        || row.until != lease.until
        || now.is_some_and(|now| now >= row.until)
        || stored.snapshot.id != lease.execution.id
        || stored.snapshot.plan != lease.execution.plan
        || stored.snapshot.next_step != lease.step.ordinal
        || stored.approval != lease.approval
        || stored.readiness != lease.readiness
        || row.recovery != lease.recovery
    {
        return Err(ReleaseRejection::FencedLease.into());
    }
    Ok(())
}

fn validate_fact(lease: &ReleaseLease, fact: &ReleaseProviderFact) -> Result<()> {
    if lease.fact(fact.evidence.clone())? != *fact {
        return Err(ReleaseRejection::InvalidFact.into());
    }
    Ok(())
}

fn approval_current(connection: &Connection, stored: &StoredExecution) -> Result<bool> {
    let approved = release::read_approval(connection, &stored.snapshot.plan.release)?;
    let status: String = connection.query_row(
        "SELECT status FROM release_status WHERE id=?1",
        [stored.snapshot.plan.release.as_str()],
        |r| r.get(0),
    )?;
    if status != "approved" {
        return Ok(false);
    }
    let target = serde_json::to_string(&stored.snapshot.target)?;
    let (generation, desired): (i64, Option<String>) = connection.query_row(
        "SELECT generation,desired FROM release_slots WHERE target=?1",
        [target],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if u64::try_from(generation)? != approved.generation
        || desired.as_deref() != Some(stored.snapshot.plan.release.as_str())
    {
        return Ok(false);
    }
    let authority = release::read_observation::<ReleaseAuthority>(
        connection,
        &stored.snapshot.target,
        "authority",
        "current",
    )?;
    if !authority.is_some_and(|(revision, authority)| {
        revision == approved.authority_revision
            && authority.source == approved.approval.git.source
            && authority.policy == approved.approval.git.policy
    }) {
        return Ok(false);
    }
    let cancelled: bool = connection.query_row(
        "SELECT cancel_requested FROM executions WHERE id=?1",
        [stored.approval.build_execution.as_str()],
        |r| r.get(0),
    )?;
    if cancelled {
        return Ok(false);
    }
    match release::current_approval(connection, &stored.snapshot.plan.release) {
        Ok(_) => {}
        Err(error)
            if error.downcast_ref::<crate::runtime_secret::RuntimeSecretRejection>()
                == Some(&crate::runtime_secret::RuntimeSecretRejection::VersionUnavailable) =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error),
    }
    Ok(true)
}

fn readiness_current(connection: &Connection, stored: &StoredExecution) -> Result<bool> {
    if let Some(prepared) = &stored.deployment
        && Some(crate::runtime_secret::deployment_incarnation_in(
            connection, prepared,
        )?) != stored.incarnation
    {
        return Ok(false);
    }
    let Some(id) = &stored.readiness else {
        return Ok(false);
    };
    let body: String = connection.query_row(
        "SELECT body FROM release_readiness WHERE id=?1",
        [id.as_str()],
        |r| r.get(0),
    )?;
    let proof: release::StoredReady = serde_json::from_str(&body)?;
    ensure!(
        Digest::of(&("day2-release-readiness-v1", &proof))? == *id,
        "release readiness identity mismatch"
    );
    match release::ready_secret(connection, &stored.approval) {
        Ok((revision, observation)) => {
            Ok(revision == proof.secret_revision
                && Digest::of(&observation)? == proof.secret_evidence)
        }
        Err(error) if error.downcast_ref::<ReleaseNotReady>().is_some() => Ok(false),
        Err(error) => Err(error),
    }
}

fn guards_changed(connection: &Connection, stored: &StoredExecution) -> Result<bool> {
    if !approval_current(connection, stored)? {
        return Ok(true);
    }
    Ok(matches!(
        stored.snapshot.phase,
        ReleasePhase::SecretReady | ReleasePhase::WaitingDeployment | ReleasePhase::DeploymentReady
    ) && !readiness_current(connection, stored)?)
}

fn refresh_guards(connection: &Connection, stored: &mut StoredExecution) -> Result<bool> {
    if !approval_current(connection, stored)? {
        stop(connection, stored, ReleaseTerminal::AuthorityLost)?;
        return Ok(true);
    }
    if matches!(
        stored.snapshot.phase,
        ReleasePhase::SecretReady | ReleasePhase::WaitingDeployment | ReleasePhase::DeploymentReady
    ) && !readiness_current(connection, stored)?
    {
        stored.snapshot.phase = ReleasePhase::WaitingSecret;
        stored.snapshot.waiting = Some(ReleaseWait::SecretMetadata);
        stored.readiness = None;
        stored.deployment = None;
        stored.incarnation = None;
        stored.readback = None;
        workflow_event(
            connection,
            stored,
            "workflow_readiness_invalidated",
            &stored.snapshot.next_step,
        )?;
        return Ok(true);
    }
    Ok(false)
}

fn stop(
    connection: &Connection,
    stored: &mut StoredExecution,
    reason: ReleaseTerminal,
) -> Result<()> {
    stored.snapshot.phase = ReleasePhase::Stopped;
    stored.snapshot.terminal = Some(reason);
    stored.snapshot.waiting = None;
    workflow_event(connection, stored, "workflow_stopped", &reason)
}

fn defer_step(
    connection: &Connection,
    stored: &mut StoredExecution,
    lease: &ReleaseLease,
    status: &str,
    waiting: ReleaseWait,
) -> Result<()> {
    connection.execute(
        "UPDATE release_steps SET status=?1,lease_until=0 WHERE id=?2",
        params![status, lease.effect.as_str()],
    )?;
    stored.snapshot.waiting = Some(waiting);
    workflow_event(
        connection,
        stored,
        "workflow_deferred",
        &(&lease.effect, status),
    )
}

fn complete_step(
    connection: &Connection,
    stored: &mut StoredExecution,
    lease: &ReleaseLease,
    result: &str,
) -> Result<()> {
    connection.execute(
        "UPDATE release_steps SET status='complete',result=?1 WHERE id=?2",
        params![result, lease.effect.as_str()],
    )?;
    stored.snapshot.next_step = stored
        .snapshot
        .next_step
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("release step budget exhausted"))?;
    workflow_event(
        connection,
        stored,
        "workflow_completed_step",
        &(&lease.effect, result, &stored.snapshot),
    )
}

fn validate_observation_kind(lease: &ReleaseLease, observation: &ReleaseObservation) -> Result<()> {
    if let ReleaseObserved::Secret {
        metadata: Some(metadata),
    } = &observation.outcome
        && metadata.reference != lease.approval.secret
    {
        return Err(ReleaseRejection::InvalidFact.into());
    }
    if !matches!(
        (lease.step.operation, &observation.outcome),
        (
            ReleaseOperation::PrepareDependency,
            ReleaseObserved::DependencyPrepared {}
        ) | (
            ReleaseOperation::ObserveSecret,
            ReleaseObserved::Secret { .. }
        ) | (
            ReleaseOperation::PrepareDeployment,
            ReleaseObserved::DeploymentPrepared { .. }
        ) | (
            ReleaseOperation::ObserveDeployment,
            ReleaseObserved::Deployment { .. }
        )
    ) {
        return Err(ReleaseRejection::InvalidFact.into());
    }
    Ok(())
}

fn apply_observation(
    connection: &Transaction<'_>,
    stored: &mut StoredExecution,
    lease: &ReleaseLease,
    observation: &ReleaseObservation,
) -> Result<()> {
    stored.snapshot.waiting = None;
    match (lease.step.operation, &observation.outcome) {
        (ReleaseOperation::PrepareDependency, ReleaseObserved::DependencyPrepared {}) => {
            stored.dependency = Some(observation.fact.clone());
            stored.snapshot.phase = ReleasePhase::WaitingSecret;
            stored.snapshot.waiting = Some(ReleaseWait::SecretMetadata);
        }
        (ReleaseOperation::ObserveSecret, ReleaseObserved::Secret { metadata }) => {
            ensure!(
                stored.dependency.is_some(),
                "secret observation lacks prepared dependency"
            );
            if let Some(metadata) = metadata {
                if metadata.reference != stored.approval.secret {
                    return Err(ReleaseRejection::InvalidFact.into());
                }
                if metadata.provider_state.barrier().is_none() {
                    stored.snapshot.phase = ReleasePhase::WaitingSecret;
                    stored.snapshot.waiting = Some(ReleaseWait::SecretMetadata);
                    return Ok(());
                }
                metadata.provider_state.require(
                    &metadata.reference.binding,
                    &Digest::of(&metadata.reference)?,
                    None,
                )?;
                let key = release::secret_key(&metadata.reference)?;
                let current = release::read_observation::<SecretObservation>(
                    connection,
                    &stored.snapshot.target,
                    "secret",
                    &key,
                )?;
                let revision = current.as_ref().map_or(0, |(revision, _)| *revision);
                let newer = current.as_ref().is_none_or(|(_, prior)| {
                    metadata
                        .provider_state
                        .revision()
                        .relation(prior.provider_state.revision())
                        == RevisionRelation::Newer
                });
                if newer {
                    release::observe(
                        connection,
                        &stored.snapshot.target,
                        "secret",
                        &key,
                        &Name::try_from(format!(
                            "step-{}",
                            lease.effect.as_str().trim_start_matches("sha256:")
                        ))?,
                        revision,
                        metadata,
                    )?;
                    release::clear_secret_uncertainty(
                        connection,
                        &stored.snapshot.target,
                        &key,
                        metadata,
                    )?;
                } else if current.as_ref().is_some_and(|(_, prior)| {
                    metadata
                        .provider_state
                        .revision()
                        .relation(prior.provider_state.revision())
                        == RevisionRelation::Same
                        && prior.same_state(metadata)
                }) {
                    // Re-reading an unchanged provider revision is valid evidence,
                    // but does not invent a newer local metadata revision.
                } else {
                    if current.as_ref().is_some_and(|(_, prior)| {
                        matches!(
                            metadata
                                .provider_state
                                .revision()
                                .relation(prior.provider_state.revision()),
                            RevisionRelation::Incomparable | RevisionRelation::Same
                        )
                    }) {
                        let incomparable = current.as_ref().is_some_and(|(_, prior)| {
                            metadata
                                .provider_state
                                .revision()
                                .relation(prior.provider_state.revision())
                                == RevisionRelation::Incomparable
                        });
                        release::mark_secret_uncertain(
                            connection,
                            &stored.snapshot.target,
                            &key,
                            metadata,
                            incomparable,
                        )?;
                    }
                    stored.snapshot.phase = ReleasePhase::WaitingSecret;
                    stored.snapshot.waiting = Some(ReleaseWait::SecretMetadata);
                    return Ok(());
                }
                match Journal::prepare_release_in(
                    connection,
                    &ApprovedRelease {
                        id: stored.snapshot.plan.release.clone(),
                    },
                ) {
                    Ok(ready) => {
                        stored.readiness = Some(ready.id);
                        stored.snapshot.phase = ReleasePhase::SecretReady;
                    }
                    Err(error) if error.downcast_ref::<ReleaseNotReady>().is_some() => {
                        stored.snapshot.phase = ReleasePhase::WaitingSecret;
                        stored.snapshot.waiting =
                            Some(match error.downcast_ref::<ReleaseNotReady>().unwrap() {
                                ReleaseNotReady::AwaitingSecretMetadata => {
                                    ReleaseWait::SecretMetadata
                                }
                                ReleaseNotReady::SecretDisabled => ReleaseWait::SecretDisabled,
                                ReleaseNotReady::SecretAccessDenied => ReleaseWait::SecretAccess,
                                ReleaseNotReady::SecretProjectionUnavailable => {
                                    ReleaseWait::SecretProjection
                                }
                            });
                    }
                    Err(error) => return Err(error),
                }
            } else {
                stored.snapshot.phase = ReleasePhase::WaitingSecret;
                stored.snapshot.waiting = Some(ReleaseWait::SecretMetadata);
            }
        }
        (
            ReleaseOperation::PrepareDeployment,
            ReleaseObserved::DeploymentPrepared { incarnation },
        ) => {
            ensure!(
                stored.dependency.is_some() && stored.readiness.is_some(),
                "deployment missing dependency readiness"
            );
            incarnation.validate()?;
            crate::runtime_secret::record_deployment_incarnation_in(
                connection,
                &observation.fact,
                incarnation,
            )?;
            stored.deployment = Some(observation.fact.clone());
            stored.incarnation = Some(incarnation.clone());
            stored.readback = None;
            stored.snapshot.phase = ReleasePhase::WaitingDeployment;
            stored.snapshot.waiting = Some(ReleaseWait::Deployment);
        }
        (ReleaseOperation::ObserveDeployment, ReleaseObserved::Deployment { ready, evidence }) => {
            ensure!(
                stored
                    .deployment
                    .as_ref()
                    .is_some_and(|prepared| prepared.resource == observation.fact.resource
                        && prepared.readiness == observation.fact.readiness),
                "deployment readback lacks exact preparation"
            );
            if evidence.barrier().is_none() {
                stored.snapshot.phase = ReleasePhase::WaitingDeployment;
                stored.snapshot.waiting = Some(ReleaseWait::Deployment);
                return Ok(());
            }
            let prepared = stored.deployment.as_ref().expect("checked preparation");
            evidence.require(
                &prepared.binding,
                &prepared.resource,
                Some(&prepared.effect),
            )?;
            ensure!(
                Some(crate::runtime_secret::deployment_incarnation_in(
                    connection, prepared
                )?) == stored.incarnation,
                "deployment incarnation changed before readback"
            );
            if *ready {
                stored.readback = Some(observation.fact.clone());
                stored.snapshot.phase = ReleasePhase::DeploymentReady;
            } else {
                stored.snapshot.phase = ReleasePhase::WaitingDeployment;
                stored.snapshot.waiting = Some(ReleaseWait::Deployment);
            }
        }
        _ => return Err(ReleaseRejection::InvalidFact.into()),
    }
    Ok(())
}
