use crate::{
    BuildPlan, Digest, Name,
    kernel::{self, EffectKind, Observation, State},
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};

pub struct Journal {
    pub(crate) connection: Connection,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OperatorActor(String);
impl OperatorActor {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for OperatorActor {
    type Error = anyhow::Error;
    fn try_from(actor: String) -> Result<Self> {
        ensure!(
            !actor.trim().is_empty() && actor.len() <= 254 && !actor.chars().any(char::is_control),
            "invalid acceptance actor"
        );
        Ok(Self(actor))
    }
}
impl From<OperatorActor> for String {
    fn from(actor: OperatorActor) -> Self {
        actor.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AcceptanceProvenance {
    PlatformHost,
    Operator { actor: OperatorActor },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceReceipt {
    fingerprint: Digest,
    provenance: AcceptanceProvenance,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Execution {
    pub id: Digest,
    pub plan: BuildPlan,
    pub state: State,
    pub revision: u64,
    pub cancel_requested: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryMode {
    Execute,
    Reconcile,
}

#[derive(Clone, Debug)]
pub struct Lease {
    pub execution: Execution,
    pub effect: Digest,
    pub kind: EffectKind,
    pub epoch: u64,
    pub owner: Name,
    pub until: u64,
    pub recovery: RecoveryMode,
}

#[derive(Clone, Debug)]
pub enum Claim {
    Acquired(Box<Lease>),
    Busy,
    Terminal(State),
}

#[derive(Clone, Copy, Debug)]
pub enum RetryDisposition {
    NotApplied,
    Ambiguous,
}

/// Closed, redacted commit refusals. The live driver and simulator can distinguish
/// expected fencing from a storage failure without exposing arbitrary error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionRejection {
    FencedLease,
    ConflictingCompletion,
    UncertainPublication,
}

impl std::fmt::Display for CompletionRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::FencedLease => "expired or fenced effect lease",
            Self::ConflictingCompletion => "conflicting effect completion",
            Self::UncertainPublication => "uncertain publication requires reconciliation",
        })
    }
}

impl std::error::Error for CompletionRejection {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostFault {
    JournalRead,
    CapabilityBinding,
    Clock,
    Claim,
    Capability,
    Completion,
}

impl std::fmt::Display for HostFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::JournalRead => "host_journal_read",
            Self::CapabilityBinding => "host_capability_binding",
            Self::Clock => "host_clock",
            Self::Claim => "host_claim",
            Self::Capability => "host_capability",
            Self::Completion => "host_completion",
        })
    }
}

impl std::error::Error for HostFault {}

impl Journal {
    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;
            CREATE TABLE IF NOT EXISTS control_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL);
            INSERT OR IGNORE INTO control_meta VALUES(1,2);")?;
        let version: i64 = connection.query_row(
            "SELECT version FROM control_meta WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        ensure!(version == 2, "unsupported control journal version");
        connection.execute_batch("BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS executions (
                id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, plan TEXT NOT NULL, state TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision>=0), cancel_requested INTEGER NOT NULL CHECK(cancel_requested IN (0,1)));
            CREATE TABLE IF NOT EXISTS outbox (
                execution TEXT PRIMARY KEY REFERENCES executions(id), workflow_id TEXT, run_id TEXT);
            CREATE TABLE IF NOT EXISTS execution_acceptance (
                execution TEXT PRIMARY KEY REFERENCES executions(id), provenance TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS effects (
                id TEXT PRIMARY KEY, execution TEXT NOT NULL REFERENCES executions(id), kind TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending','running','ambiguous','complete')),
                epoch INTEGER NOT NULL CHECK(epoch>=0), owner TEXT NOT NULL, lease_until INTEGER NOT NULL,
                observation TEXT, recovery INTEGER NOT NULL CHECK(recovery IN (0,1)), UNIQUE(execution,kind));
            CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, execution TEXT NOT NULL REFERENCES executions(id),
                kind TEXT NOT NULL, body TEXT NOT NULL);
            COMMIT;")?;
        let mut journal = Self { connection };
        journal.initialize_release_schema()?;
        journal.initialize_release_execution_schema()?;
        journal.initialize_runtime_secret_schema()?;
        journal.initialize_secret_retirement_schema()?;
        Ok(journal)
    }

    pub fn accept(&mut self, plan: &BuildPlan) -> Result<Execution> {
        self.accept_with_provenance(plan, AcceptanceProvenance::PlatformHost)
    }

    pub fn accept_as(&mut self, plan: &BuildPlan, actor: &str) -> Result<Execution> {
        self.accept_with_provenance(
            plan,
            AcceptanceProvenance::Operator {
                actor: OperatorActor::try_from(actor.to_owned())?,
            },
        )
    }

    fn accept_with_provenance(
        &mut self,
        plan: &BuildPlan,
        provenance: AcceptanceProvenance,
    ) -> Result<Execution> {
        plan.validate()?;
        let id = plan.execution_id()?;
        let fingerprint = plan.fingerprint()?;
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        let prior: Option<String> = tx
            .query_row(
                "SELECT fingerprint FROM executions WHERE id=?1",
                [id.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(prior) = prior {
            ensure!(
                prior == fingerprint.as_str(),
                "idempotency key reused with different pinned inputs"
            );
            let stored = read_acceptance(&tx, &id, &fingerprint)?;
            ensure!(
                stored == provenance,
                "idempotency key reused by a different acceptance actor"
            );
        } else {
            tx.execute(
                "INSERT INTO executions VALUES(?1,?2,?3,?4,0,0)",
                params![
                    id.as_str(),
                    fingerprint.as_str(),
                    serde_json::to_string(plan)?,
                    serde_json::to_string(&State::Accepted)?
                ],
            )?;
            tx.execute(
                "INSERT INTO execution_acceptance(execution,provenance) VALUES(?1,?2)",
                params![id.as_str(), serde_json::to_string(&provenance)?],
            )?;
            tx.execute("INSERT INTO outbox(execution) VALUES(?1)", [id.as_str()])?;
            event(
                &tx,
                &id,
                "accepted",
                &AcceptanceReceipt {
                    fingerprint,
                    provenance,
                },
            )?;
        }
        tx.commit()?;
        self.get(&id)
    }

    pub fn get(&self, id: &Digest) -> Result<Execution> {
        read_execution(&self.connection, id)
    }

    pub fn accepted_by(&self, id: &Digest) -> Result<AcceptanceProvenance> {
        let execution = self.get(id)?;
        read_acceptance(&self.connection, id, &execution.plan.fingerprint()?)
    }

    pub fn pending_dispatches(&self, limit: u32) -> Result<Vec<Digest>> {
        ensure!(limit > 0 && limit <= 256, "outbox page budget");
        let mut statement = self.connection.prepare(
            "SELECT execution FROM outbox WHERE workflow_id IS NULL ORDER BY execution LIMIT ?1",
        )?;
        statement
            .query_map([limit], |r| r.get::<_, String>(0))?
            .map(|r| Digest::try_from(r?))
            .collect()
    }

    pub fn pending_for(
        &self,
        company: &Name,
        durability: &crate::BindingRef,
        limit: u32,
    ) -> Result<Vec<Digest>> {
        ensure!(limit > 0 && limit <= 256, "outbox page budget");
        let mut statement = self.connection.prepare(
            "SELECT o.execution FROM outbox o JOIN executions e ON e.id=o.execution
            WHERE o.workflow_id IS NULL AND json_extract(e.plan,'$.company')=?1
            AND json_extract(e.plan,'$.profile.durability.id')=?2
            AND json_extract(e.plan,'$.profile.durability.revision')=?3
            AND json_extract(e.state,'$.state') IN ('accepted','source_ready','verified','verification_failed')
            ORDER BY o.execution LIMIT ?4",
        )?;
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
            .map(|r| Digest::try_from(r?))
            .collect()
    }

    pub fn dispatched(&mut self, id: &Digest, workflow: &str, run: &str) -> Result<()> {
        ensure!(
            !workflow.is_empty() && workflow.len() <= 256 && !run.is_empty() && run.len() <= 128,
            "invalid Temporal receipt"
        );
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        let prior: (Option<String>, Option<String>) = tx.query_row(
            "SELECT workflow_id,run_id FROM outbox WHERE execution=?1",
            [id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if let Some(prior_workflow) = prior.0 {
            ensure!(prior_workflow == workflow, "workflow affinity changed");
        } else {
            tx.execute(
                "UPDATE outbox SET workflow_id=?2,run_id=?3 WHERE execution=?1",
                params![id.as_str(), workflow, run],
            )?;
            event(&tx, id, "dispatched", &(workflow, run))?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn request_cancel(&mut self, id: &Digest) -> Result<()> {
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        let execution = read_execution(&tx, id)?;
        if execution.state.next_effect().is_some() && !execution.cancel_requested {
            tx.execute(
                "UPDATE executions SET cancel_requested=1,revision=revision+1 WHERE id=?1",
                [id.as_str()],
            )?;
            event(&tx, id, "cancel_requested", &())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn claim(&mut self, id: &Digest, owner: Name, now: u64, duration: u64) -> Result<Claim> {
        ensure!(
            duration > 0 && duration <= 3_600_000,
            "lease duration outside budget"
        );
        let until = now.checked_add(duration).context("lease overflow")?;
        ensure!(until <= i64::MAX as u64, "lease timestamp overflow");
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        let mut execution = read_execution(&tx, id)?;
        let Some(kind) = execution.state.next_effect() else {
            return Ok(Claim::Terminal(execution.state));
        };
        let effect = kernel::effect_id(&execution.plan, kind)?;
        let prior: Option<(String, i64, i64)> = tx
            .query_row(
                "SELECT status,epoch,lease_until FROM effects WHERE id=?1",
                [effect.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        // Lease expiry does not prove that a provider mutation failed. Reconcile
        // the stable effect ID before permitting another mutation.
        let (epoch, recovery) = match prior {
            Some((status, epoch, expiry)) => {
                let epoch = u64::try_from(epoch)?;
                let expiry = u64::try_from(expiry)?;
                ensure!(status != "complete", "journal effect/state mismatch");
                if status == "running" && expiry > now {
                    return Ok(Claim::Busy);
                }
                (
                    epoch.checked_add(1).context("lease epoch overflow")?,
                    if status == "pending" {
                        RecoveryMode::Execute
                    } else {
                        RecoveryMode::Reconcile
                    },
                )
            }
            None => (1, RecoveryMode::Execute),
        };
        // Cancellation cannot erase an effect whose external outcome is still unknown.
        if execution.cancel_requested && recovery == RecoveryMode::Execute {
            execution.state = State::Cancelled;
            tx.execute(
                "UPDATE executions SET state=?2,revision=revision+1 WHERE id=?1",
                params![id.as_str(), serde_json::to_string(&execution.state)?],
            )?;
            event(&tx, id, "cancelled", &())?;
            tx.commit()?;
            return Ok(Claim::Terminal(State::Cancelled));
        }
        tx.execute("INSERT INTO effects(id,execution,kind,status,epoch,owner,lease_until,recovery) VALUES(?1,?2,?3,'running',?4,?5,?6,?7)
            ON CONFLICT(id) DO UPDATE SET status='running',epoch=excluded.epoch,owner=excluded.owner,lease_until=excluded.lease_until,recovery=excluded.recovery",
            params![effect.as_str(), id.as_str(), serde_json::to_string(&kind)?, i64::try_from(epoch)?, owner.as_str(), i64::try_from(until)?, recovery == RecoveryMode::Reconcile])?;
        event(
            &tx,
            id,
            "claimed",
            &(&effect, epoch, recovery == RecoveryMode::Reconcile),
        )?;
        tx.commit()?;
        Ok(Claim::Acquired(Box::new(Lease {
            execution,
            effect,
            kind,
            epoch,
            owner,
            until,
            recovery,
        })))
    }

    pub fn complete(
        &mut self,
        lease: &Lease,
        observation: &Observation,
        now: u64,
    ) -> Result<State> {
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        let id = &lease.execution.id;
        let execution = read_execution(&tx, id)?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT observation FROM effects WHERE id=?1 AND status='complete'",
                [lease.effect.as_str()],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        if let Some(previous) = previous {
            if previous != serde_json::to_string(observation)? {
                return Err(CompletionRejection::ConflictingCompletion.into());
            }
            return Ok(execution.state);
        }
        validate_lease(&tx, lease, now)?;
        if lease.kind == EffectKind::PublishCheck
            && lease.recovery == RecoveryMode::Reconcile
            && !matches!(observation, Observation::Published { .. })
        {
            return Err(CompletionRejection::UncertainPublication.into());
        }
        ensure!(
            execution.plan == lease.execution.plan,
            "execution input mutation"
        );
        ensure!(
            execution.state.next_effect() == Some(lease.kind),
            "stale effect kind"
        );
        let mut next = execution.state.observe(&execution.plan, observation)?;
        if execution.cancel_requested && next.next_effect().is_some() {
            next = State::Cancelled;
        }
        tx.execute(
            "UPDATE effects SET status='complete',observation=?2 WHERE id=?1",
            params![lease.effect.as_str(), serde_json::to_string(observation)?],
        )?;
        tx.execute(
            "UPDATE executions SET state=?2,revision=revision+1 WHERE id=?1",
            params![id.as_str(), serde_json::to_string(&next)?],
        )?;
        event(&tx, id, "completed", &(&lease.effect, observation, &next))?;
        tx.commit()?;
        Ok(next)
    }

    pub fn defer(&mut self, lease: &Lease, disposition: RetryDisposition, now: u64) -> Result<()> {
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        validate_lease(&tx, lease, now)?;
        // Only an adapter's definitive non-application observation may authorize another mutation.
        if lease.recovery == RecoveryMode::Reconcile
            && matches!(disposition, RetryDisposition::NotApplied)
            && lease.kind == EffectKind::PublishCheck
        {
            return Err(CompletionRejection::UncertainPublication.into());
        }
        let status = match disposition {
            RetryDisposition::NotApplied => "pending",
            RetryDisposition::Ambiguous => "ambiguous",
        };
        tx.execute(
            "UPDATE effects SET status=?2,lease_until=0 WHERE id=?1",
            params![lease.effect.as_str(), status],
        )?;
        event(
            &tx,
            &lease.execution.id,
            "deferred",
            &(&lease.effect, status),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn event_count(&self, id: &Digest) -> Result<u64> {
        Ok(u64::try_from(self.connection.query_row(
            "SELECT count(*) FROM events WHERE execution=?1",
            [id.as_str()],
            |r| r.get::<_, i64>(0),
        )?)?)
    }

    /// At most one diagnostic per fixed fault code and execution. This records
    /// operator-visible context without raw provider errors or unbounded retry spam.
    pub fn record_fault(&mut self, id: &Digest, code: HostFault) -> Result<()> {
        let tx = day2::write_queue::immediate(&mut self.connection)?;
        read_execution(&tx, id)?;
        let prior: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE execution=?1 AND kind='host_fault' AND body=?2)",
            params![id.as_str(), serde_json::to_string(&code)?], |row| row.get(0),
        )?;
        if !prior {
            event(&tx, id, "host_fault", &code)?;
        }
        tx.commit()?;
        Ok(())
    }
}

fn read_acceptance(
    connection: &Connection,
    id: &Digest,
    fingerprint: &Digest,
) -> Result<AcceptanceProvenance> {
    let raw: Option<String> = connection
        .query_row(
            "SELECT provenance FROM execution_acceptance WHERE execution=?1",
            [id.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    let provenance: AcceptanceProvenance =
        serde_json::from_str(&raw.context("legacy execution has no acceptance provenance")?)?;
    let (count, body): (i64, String) = connection.query_row("SELECT COUNT(*), COALESCE(MIN(body),'') FROM events WHERE execution=?1 AND kind='accepted'", [id.as_str()], |row| Ok((row.get(0)?,row.get(1)?)))?;
    ensure!(count == 1, "acceptance event unavailable");
    let receipt: AcceptanceReceipt = serde_json::from_str(&body)?;
    ensure!(
        receipt.fingerprint == *fingerprint && receipt.provenance == provenance,
        "acceptance provenance receipt mismatch"
    );
    Ok(provenance)
}

fn read_execution(connection: &Connection, id: &Digest) -> Result<Execution> {
    let (plan, state, revision, cancel_requested, fingerprint): (
        String,
        String,
        i64,
        bool,
        String,
    ) = connection.query_row(
        "SELECT plan,state,revision,cancel_requested,fingerprint FROM executions WHERE id=?1",
        [id.as_str()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )?;
    let plan: BuildPlan = serde_json::from_str(&plan)?;
    plan.validate()?;
    ensure!(plan.execution_id()? == *id, "corrupt execution identity");
    ensure!(
        plan.fingerprint()?.as_str() == fingerprint,
        "corrupt pinned execution inputs"
    );
    Ok(Execution {
        id: id.clone(),
        plan,
        state: serde_json::from_str(&state)?,
        revision: u64::try_from(revision)?,
        cancel_requested,
    })
}

fn validate_lease(connection: &Connection, lease: &Lease, now: u64) -> Result<()> {
    let valid: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM effects WHERE id=?1 AND execution=?2 AND status='running' AND epoch=?3 AND owner=?4 AND lease_until>?5 AND kind=?6 AND recovery=?7)",
        params![lease.effect.as_str(), lease.execution.id.as_str(), i64::try_from(lease.epoch)?, lease.owner.as_str(), i64::try_from(now)?, serde_json::to_string(&lease.kind)?, lease.recovery == RecoveryMode::Reconcile], |r| r.get(0))?;
    if !valid {
        return Err(CompletionRejection::FencedLease.into());
    }
    Ok(())
}

fn event<T: Serialize>(connection: &Connection, id: &Digest, kind: &str, value: &T) -> Result<()> {
    connection.execute(
        "INSERT INTO events(execution,kind,body) VALUES(?1,?2,?3)",
        params![id.as_str(), kind, serde_json::to_string(value)?],
    )?;
    Ok(())
}
