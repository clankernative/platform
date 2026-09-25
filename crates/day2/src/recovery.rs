//! Protected local-operator resolution of blocked invocations.
use crate::{
    authority_state::LocalOperator,
    store::{self, Runtime},
};
use anyhow::{Context as _, Result, ensure};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub request_id: String,
    pub invocation: String,
    pub expected_artifact: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub invocation: String,
    pub resolution: String,
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
            invocation TEXT NOT NULL UNIQUE REFERENCES day2_invocations(id),
            operator TEXT NOT NULL, reason TEXT NOT NULL,
            resolution TEXT NOT NULL CHECK(resolution IN ('abandoned','reissued')),
            successor TEXT REFERENCES day2_invocations(id), evidence TEXT NOT NULL,
            payload TEXT NOT NULL, at_ms INTEGER NOT NULL
        ) STRICT;
        CREATE TRIGGER IF NOT EXISTS day2_recoveries_no_update
        BEFORE UPDATE ON day2_recoveries BEGIN SELECT RAISE(ABORT,'append_only_recovery'); END;
        CREATE TRIGGER IF NOT EXISTS day2_recoveries_no_delete
        BEFORE DELETE ON day2_recoveries BEGIN SELECT RAISE(ABORT,'append_only_recovery'); END;",
    )?;
    Ok(())
}

pub fn abandon(runtime: &Runtime, operator: &LocalOperator, request: &Request) -> Result<Receipt> {
    resolve(runtime, operator, request, false)
}

pub fn reissue(runtime: &Runtime, operator: &LocalOperator, request: &Request) -> Result<Receipt> {
    resolve(runtime, operator, request, true)
}

fn resolve(
    runtime: &Runtime,
    operator: &LocalOperator,
    request: &Request,
    reissue: bool,
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
    let payload = serde_json::to_string(&(request, operator.name(), reissue))?;
    let mut database = store::open(runtime.db())?;
    let tx = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
    runtime.check_binding(&tx)?;
    let prior: Option<(String, String)> = tx
        .query_row(
            "SELECT payload,evidence FROM day2_recoveries WHERE request_id=?1",
            [&request.request_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((stored, evidence)) = prior {
        ensure!(stored == payload, "recovery_request_conflict");
        let (successor, resolution): (Option<String>, String) = tx.query_row(
            "SELECT successor,resolution FROM day2_recoveries WHERE request_id=?1",
            [&request.request_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let receipt = Receipt {
            invocation: request.invocation.clone(),
            resolution,
            successor,
            evidence: serde_json::from_str(&evidence)?,
            children: children_in(&tx, &request.invocation)?,
        };
        return Ok(receipt);
    }
    let resolved: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_recoveries WHERE invocation=?1)",
        [&request.invocation],
        |row| row.get(0),
    )?;
    ensure!(!resolved, "recovery_already_resolved");
    let (artifact, status): (String, String) = tx
        .query_row(
            "SELECT artifact,status FROM day2_invocations WHERE id=?1",
            [&request.invocation],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .context(crate::error::Failure::NotFound)?;
    ensure!(
        artifact == request.expected_artifact && artifact == runtime.artifact().id(),
        crate::error::Failure::ArtifactBindingChanged
    );
    ensure!(status == "pending", "recovery_requires_blocked_invocation");
    ensure!(
        crate::authority_state::is_blocked(&tx, &request.invocation)?,
        "recovery_requires_blocked_invocation"
    );

    let evidence = classify_effects(&tx, &request.invocation)?;
    let children = children_in(&tx, &request.invocation)?;
    let successor = if reissue {
        ensure!(
            evidence == EvidenceSummary::default()
                && !has_committed_decision(&tx, &request.invocation)?
                && children.is_empty(),
            "recovery_reissue_requires_uncommitted_invocation"
        );
        Some(admit_successor(runtime, &tx, &request.invocation)?)
    } else {
        None
    };
    let resolution = if reissue { "reissued" } else { "abandoned" };
    let error = if reissue {
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
    let evidence_json = serde_json::to_string(&evidence)?;
    let now_ms = crate::resource_admin::now_ms()?;
    tx.execute("INSERT INTO day2_recoveries(request_id,invocation,operator,reason,resolution,successor,evidence,payload,at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![request.request_id, request.invocation, operator.name(), request.reason, resolution, successor, evidence_json, payload, now_ms])?;
    crate::audit::record_recovery(
        &tx,
        runtime,
        operator.name(),
        &request.invocation,
        resolution,
        &request.reason,
        now_ms,
    )?;
    tx.commit()?;
    Ok(Receipt {
        invocation: request.invocation.clone(),
        resolution: resolution.into(),
        successor,
        evidence,
        children,
    })
}

fn classify_effects(
    connection: &rusqlite::Connection,
    invocation: &str,
) -> Result<EvidenceSummary> {
    let mut summary = EvidenceSummary::default();
    let mut statement = connection.prepare("SELECT e.identity,e.observation,COUNT(a.identity),SUM(CASE WHEN a.observation IS NOT NULL THEN 1 ELSE 0 END) FROM day2_external_effects e LEFT JOIN day2_external_attempts a ON a.effect=e.identity WHERE e.invocation=?1 GROUP BY e.identity,e.observation ORDER BY e.ordinal")?;
    let rows = statement.query_map([invocation], |row| {
        Ok((
            row.get::<_, Option<String>>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
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

fn children_in(connection: &rusqlite::Connection, invocation: &str) -> Result<Vec<String>> {
    let mut statement = connection.prepare("SELECT id FROM day2_command_requests WHERE parent=?1 UNION ALL SELECT id FROM day2_deferrals WHERE parent=?1 ORDER BY 1")?;
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
    connection: &rusqlite::Transaction<'_>,
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
    connection.execute("INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status,trigger) VALUES(?1,?2,?3,?4,?5,?6,'pending','recovery')", params![id,operation,actor,input,runtime.artifact().id(),now])?;
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
