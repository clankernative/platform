//! Protected local-operator resolution of blocked invocations.
use crate::{
    authority_state::LocalOperator,
    store::{self, Runtime},
};
use anyhow::{Context as _, Result, ensure};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub request_id: String,
    pub invocation: String,
    pub expected_artifact: String,
    pub expected_revision: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub invocation: String,
    pub resolution: String,
    pub revision: u64,
    pub successor: Option<String>,
    pub evidence: EvidenceSummary,
    pub children: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceSummary {
    pub never_admitted: u32,
    pub known_result: u32,
    pub unknown_outcome: u32,
}

pub(crate) fn upgrade(connection: &rusqlite::Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS day2_recoveries(
            request_id TEXT PRIMARY KEY,
            invocation TEXT NOT NULL REFERENCES day2_invocations(id),
            revision INTEGER NOT NULL CHECK(revision>0),
            operator TEXT NOT NULL, reason TEXT NOT NULL,
            resolution TEXT NOT NULL CHECK(resolution IN ('abandoned','reissued','readmitted')),
            successor TEXT REFERENCES day2_invocations(id), evidence TEXT NOT NULL,
            authority_epoch TEXT NOT NULL, authority_revision INTEGER NOT NULL CHECK(authority_revision>0),
            policy TEXT NOT NULL, payload TEXT NOT NULL, at_ms INTEGER NOT NULL, receipt TEXT NOT NULL,
            UNIQUE(invocation,revision)
        ) STRICT;
        CREATE INDEX IF NOT EXISTS day2_recoveries_latest ON day2_recoveries(invocation,revision DESC);
        CREATE TRIGGER IF NOT EXISTS day2_recoveries_no_update
        BEFORE UPDATE ON day2_recoveries BEGIN SELECT RAISE(ABORT,'append_only_recovery'); END;
        CREATE TRIGGER IF NOT EXISTS day2_recoveries_no_delete
        BEFORE DELETE ON day2_recoveries BEGIN SELECT RAISE(ABORT,'append_only_recovery'); END;",
    )?;
    Ok(())
}

pub fn abandon(runtime: &Runtime, operator: &LocalOperator, request: &Request) -> Result<Receipt> {
    resolve(runtime, operator, request, Resolution::Abandoned)
}

pub fn reissue(runtime: &Runtime, operator: &LocalOperator, request: &Request) -> Result<Receipt> {
    resolve(runtime, operator, request, Resolution::Reissued)
}

pub fn readmit(runtime: &Runtime, operator: &LocalOperator, request: &Request) -> Result<Receipt> {
    resolve(runtime, operator, request, Resolution::Readmitted)
}

#[derive(Clone, Copy)]
enum Resolution {
    Abandoned,
    Reissued,
    Readmitted,
}

impl Resolution {
    fn as_str(self) -> &'static str {
        match self {
            Self::Abandoned => "abandoned",
            Self::Reissued => "reissued",
            Self::Readmitted => "readmitted",
        }
    }

    fn is_terminal(self) -> bool {
        !matches!(self, Self::Readmitted)
    }
}

fn resolve(
    runtime: &Runtime,
    operator: &LocalOperator,
    request: &Request,
    resolution: Resolution,
) -> Result<Receipt> {
    ensure!(
        !request.request_id.trim().is_empty() && request.request_id.len() <= 128,
        "invalid_recovery_request_id"
    );
    ensure!(
        !request.reason.trim().is_empty()
            && request.reason.len() <= 200
            && !request.reason.chars().any(char::is_control),
        "invalid_recovery_reason"
    );
    let payload = serde_json::to_string(&(request, operator.name(), resolution.as_str()))?;
    let mut database = store::open(runtime.db())?;
    let tx = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
    runtime.check_binding(&tx)?;
    if let Some((stored, receipt)) = tx
        .query_row(
            "SELECT payload,receipt FROM day2_recoveries WHERE request_id=?1",
            [&request.request_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
    {
        ensure!(stored == payload, "recovery_request_conflict");
        return Ok(serde_json::from_str(&receipt)?);
    }

    let (revision, terminal): (i64, bool) = tx.query_row(
        "SELECT COUNT(*),COALESCE(MAX(resolution IN ('abandoned','reissued')),0)
         FROM day2_recoveries WHERE invocation=?1",
        [&request.invocation],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    ensure!(!terminal, "recovery_already_resolved");
    ensure!(
        u64::try_from(revision)? == request.expected_revision,
        "recovery_revision_conflict"
    );
    let (artifact, status): (String, String) = tx
        .query_row(
            "SELECT artifact,status FROM day2_invocations WHERE id=?1",
            [&request.invocation],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .context(crate::error::Failure::NotFound)?;
    ensure!(
        artifact == request.expected_artifact,
        crate::error::Failure::ArtifactBindingChanged
    );
    if !matches!(resolution, Resolution::Abandoned) {
        ensure!(
            artifact == runtime.artifact().id(),
            crate::error::Failure::ArtifactBindingChanged
        );
    }
    ensure!(status == "pending", "recovery_requires_blocked_invocation");
    ensure!(
        crate::authority_state::is_blocked(&tx, &request.invocation)?,
        "recovery_requires_blocked_invocation"
    );

    let revision = revision
        .checked_add(1)
        .context("recovery_revision_overflow")?;
    let evidence = classify_effects(&tx, &request.invocation)?;
    let children = children_in(&tx, &request.invocation)?;
    let mut successor = None;
    let active_authority = crate::authority_state::current(&tx)?;
    let has_pin: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_invocation_authority WHERE invocation=?1)",
        [&request.invocation],
        |row| row.get(0),
    )?;
    let mut stamp = if has_pin {
        crate::authority_state::invocation_stamp(&tx, &request.invocation)?
    } else {
        active_authority.stamp.clone()
    };
    let mut policy = active_authority.policy()?.clone();
    if matches!(resolution, Resolution::Reissued) {
        ensure!(
            evidence == EvidenceSummary::default()
                && !has_committed_decision(&tx, &request.invocation)?
                && children.is_empty(),
            "recovery_reissue_requires_uncommitted_invocation"
        );
        successor = Some(admit_successor(runtime, &tx, &request.invocation)?);
    } else if matches!(resolution, Resolution::Readmitted) {
        let (operation, actor, input): (String, String, String) = tx.query_row(
            "SELECT operation,actor,input FROM day2_invocations WHERE id=?1",
            [&request.invocation],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let active = crate::authority_state::authorize_in(&tx, runtime, &operation, &actor)?;
        stamp = active.stamp.clone();
        policy = active.policy()?.clone();
        let definition = runtime.artifact().route(&operation)?;
        let value: serde_json::Value = serde_json::from_str(&input)?;
        runtime.artifact().contract().schema.inputs[&definition.input_type]
            .validate_input(&value)?;
        let unknown = unknown_non_idempotent_effects(&tx, &request.invocation)?;
        ensure!(
            unknown.is_empty(),
            "recovery_readmit_requires_known_outcomes: {}",
            unknown.join(",")
        );
        refresh_command_child_policy(&tx, runtime, &request.invocation, &policy)?;
        ensure_readmitted_resources(&tx, &request.invocation, &operation, &active)?;
        let old_reason: String = tx.query_row(
            "SELECT reason FROM day2_authority_blocks WHERE invocation=?1",
            [&request.invocation],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT INTO day2_authority_block_history(invocation,revision,reason,at_ms) VALUES(?1,?2,?3,?4)",
            params![request.invocation, revision, old_reason, crate::resource_admin::now_ms()?],
        )?;
        crate::authority_state::pin_readmitted_invocation(&tx, &request.invocation, &stamp)?;
        tx.execute(
            "DELETE FROM day2_authority_blocks WHERE invocation=?1",
            [&request.invocation],
        )?;
    }

    let resolution_text = resolution.as_str();
    let now_ms = crate::resource_admin::now_ms()?;
    let evidence_json = serde_json::to_string(&evidence)?;
    let receipt = Receipt {
        invocation: request.invocation.clone(),
        resolution: resolution_text.into(),
        revision: u64::try_from(revision)?,
        successor: successor.clone(),
        evidence: evidence.clone(),
        children,
    };
    if resolution.is_terminal() {
        let error = if matches!(resolution, Resolution::Reissued) {
            "invocation_reissued"
        } else {
            "invocation_abandoned"
        };
        let outcome = crate::protocol::Outcome {
            status: "failure".into(),
            result: serde_json::json!({}),
            error: error.into(),
        };
        tx.execute(
            "UPDATE day2_invocations SET status='failure',outcome=?1 WHERE id=?2 AND status='pending'",
            params![serde_json::to_string(&outcome)?, request.invocation],
        )?;
    }
    tx.execute(
        "INSERT INTO day2_recoveries(request_id,invocation,revision,operator,reason,resolution,successor,evidence,authority_epoch,authority_revision,policy,payload,at_ms,receipt)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![request.request_id, request.invocation, revision, operator.name(), request.reason,
            resolution_text, successor, evidence_json, stamp.epoch, i64::try_from(stamp.revision)?,
            serde_json::to_string(&policy)?, payload, now_ms, serde_json::to_string(&receipt)?],
    )?;
    crate::audit::record_recovery(
        &tx,
        runtime,
        operator.name(),
        &request.invocation,
        resolution_text,
        &request.reason,
        now_ms,
    )?;
    tx.commit()?;
    Ok(receipt)
}

fn ensure_readmitted_resources(
    connection: &Transaction<'_>,
    invocation: &str,
    operation: &str,
    authority: &crate::authority_state::ActiveAuthority,
) -> Result<()> {
    crate::resources::capture_root_budgets(connection, invocation, operation, authority)?;
    let has_seed: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_id_seeds WHERE invocation=?1)",
        [invocation],
        |row| row.get(0),
    )?;
    if !has_seed {
        let parent: String = connection.query_row(
            "SELECT parent FROM day2_command_requests WHERE id=?1
             UNION ALL SELECT parent FROM day2_deferrals WHERE id=?1 LIMIT 1",
            [invocation],
            |row| row.get(0),
        )?;
        let parent_seed: Vec<u8> = connection.query_row(
            "SELECT seed FROM day2_id_seeds WHERE invocation=?1",
            [&parent],
            |row| row.get(0),
        )?;
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(parent_seed);
        hash.update(invocation.as_bytes());
        connection.execute(
            "INSERT INTO day2_id_seeds VALUES(?1,?2)",
            params![invocation, hash.finalize().to_vec()],
        )?;
    }
    Ok(())
}

fn refresh_command_child_policy(
    connection: &Transaction<'_>,
    runtime: &Runtime,
    invocation: &str,
    policy: &crate::authority::Policy,
) -> Result<()> {
    let target: Option<(String, String, i64)> = connection
        .query_row(
            "SELECT model,target,version FROM day2_command_requests WHERE id=?1",
            [invocation],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((model, target, version)) = target {
        let row = store::get(
            connection,
            &model,
            &runtime.artifact().contract().schema.models[&model],
            crate::identity::parse_public_or_legacy(&target)?,
        )?;
        ensure!(row.version == version, crate::error::Failure::Conflict);
        connection.execute(
            "UPDATE day2_command_requests SET policy=?1 WHERE id=?2",
            params![serde_json::to_string(policy)?, invocation],
        )?;
    }
    Ok(())
}

fn classify_effects(
    connection: &rusqlite::Connection,
    invocation: &str,
) -> Result<EvidenceSummary> {
    let mut summary = EvidenceSummary::default();
    let mut statement = connection.prepare(
        "SELECT e.observation,COUNT(a.identity),SUM(CASE WHEN a.observation IS NOT NULL THEN 1 ELSE 0 END)
         FROM day2_external_effects e LEFT JOIN day2_external_attempts a ON a.effect=e.identity
         WHERE e.invocation=?1 GROUP BY e.identity,e.observation ORDER BY e.ordinal",
    )?;
    let rows = statement.query_map([invocation], |row| {
        Ok((
            row.get::<_, Option<String>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;
    for row in rows {
        let (effect_result, attempts, settled) = row?;
        if effect_result.is_some() || settled > 0 {
            summary.known_result += 1;
        } else if attempts == 0 {
            summary.never_admitted += 1;
        } else {
            summary.unknown_outcome += 1;
        }
    }
    Ok(summary)
}

fn unknown_non_idempotent_effects(
    connection: &rusqlite::Connection,
    invocation: &str,
) -> Result<Vec<String>> {
    let mut statement = connection.prepare(
        "SELECT e.identity,e.instruction FROM day2_external_effects e
         WHERE e.invocation=?1 AND e.observation IS NULL
           AND EXISTS(SELECT 1 FROM day2_external_attempts a WHERE a.effect=e.identity AND a.observation IS NULL)
         ORDER BY e.ordinal",
    )?;
    let rows = statement.query_map([invocation], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut refused = Vec::new();
    for row in rows {
        let (identity, instruction) = row?;
        let instruction: crate::protocol::Instruction = serde_json::from_str(&instruction)?;
        if !crate::capabilities::retries_are_idempotent_instruction(&instruction) {
            refused.push(identity);
        }
    }
    Ok(refused)
}

fn children_in(connection: &rusqlite::Connection, invocation: &str) -> Result<Vec<String>> {
    let mut statement = connection.prepare(
        "SELECT id FROM day2_command_requests WHERE parent=?1 UNION ALL SELECT id FROM day2_deferrals WHERE parent=?1 ORDER BY 1",
    )?;
    Ok(statement
        .query_map([invocation], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

/// A pending invocation's decision commits in the same transaction that writes
/// its execution journal row (`store.rs`, `execution::begin`); local commands
/// commit decision and completion together and are never left pending. So the
/// row's existence is exactly "a decision committed", independent of trace shape.
fn has_committed_decision(connection: &rusqlite::Connection, invocation: &str) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_execution WHERE invocation=?1)",
        [invocation],
        |row| row.get(0),
    )?)
}

fn admit_successor(
    runtime: &Runtime,
    connection: &Transaction<'_>,
    old_id: &str,
) -> Result<String> {
    let (operation, actor, input): (String, String, String) = connection.query_row(
        "SELECT operation,actor,input FROM day2_invocations WHERE id=?1",
        [old_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let definition = runtime.artifact().route(&operation)?;
    let input_value: serde_json::Value = serde_json::from_str(&input)?;
    runtime.artifact().contract().schema.inputs[&definition.input_type]
        .validate_input(&input_value)?;
    let active = crate::authority_state::authorize_in(connection, runtime, &operation, &actor)?;
    let id = format!(
        "rcv_{}",
        &crate::digest(format!("{}\n{}", runtime.scope(), old_id).as_bytes())[7..]
    );
    let existing: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_invocations WHERE id=?1)",
        [&id],
        |row| row.get(0),
    )?;
    ensure!(!existing, "recovery_successor_identity_conflict");
    let now = crate::resource_admin::now_ms()?.div_euclid(1000);
    connection.execute(
        "INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status,trigger) VALUES(?1,?2,?3,?4,?5,?6,'pending','recovery')",
        params![id, operation, actor, input, runtime.artifact().id(), now],
    )?;
    crate::authority_state::pin_invocation(connection, &id, &active.stamp)?;
    // The successor continues the original work, so it stays within the old
    // invocation's root and its root-wide budgets. The recovery row records
    // that it is a successor; the root records whose work it belongs to.
    crate::resources::inherit_root(connection, &id, old_id)?;
    crate::resources::capture_root_budgets(connection, &id, &operation, &active)?;
    use sha2::{Digest, Sha256};
    let seed = Sha256::digest(format!("{}\n{}\n{}", runtime.scope(), old_id, id).as_bytes());
    connection.execute(
        "INSERT INTO day2_id_seeds VALUES(?1,?2)",
        params![id, seed.as_slice()],
    )?;
    crate::audit::record_attempt(
        connection,
        runtime,
        crate::audit::Attempt {
            kind: crate::audit::AttemptKind::Admission,
            trigger: crate::audit::Trigger::Recovery,
            identity: &id,
            actor: &actor,
            initiator: &actor,
            operation: &operation,
            outcome: crate::audit::AttemptOutcome::Accepted,
            reason: None,
            at_ms: now.checked_mul(1000).context("audit_clock")?,
        },
    )?;
    Ok(id)
}
