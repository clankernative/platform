//! Local-operator resolution of invocations blocked by an authority change.
//!
//! A block is permanent: the invocation stays pending, never runs a business
//! phase again, and only settles evidence for external attempts admitted before
//! the block. Abandoning one makes that end explicit. It finishes the invocation
//! as a failure, refuses any dispatch permit that has not started, and records
//! what is known about its external effects. Nothing is retried or rolled back,
//! and business rows are never edited.
use crate::{authority_state::LocalOperator, error::Failure, protocol::Outcome, store::Runtime};
use anyhow::{Context as _, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// The operator's idempotency key. Repeating it with the same request
    /// returns the original receipt; with a different one it is refused.
    pub request_id: String,
    pub invocation: String,
    /// The artifact that admitted the invocation, as the operator inspected it.
    pub expected_artifact: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub invocation: String,
    pub evidence: EvidenceSummary,
    /// Command requests the invocation made. Abandoning never cascades to them.
    pub children: Vec<String>,
}

/// What is known about each external effect the invocation claimed.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSummary {
    /// No attempt was admitted: the provider was never called.
    pub never_admitted: u32,
    /// The effect's result was recorded and its usage is known.
    pub known_result: u32,
    /// An attempt was admitted and the effect is unresolved, or its usage is
    /// unknown: the provider may or may not have committed it. Abandoning
    /// releases no budget; reconcile it with the provider.
    pub unknown_outcome: u32,
}

const TABLE: &str = "CREATE TABLE IF NOT EXISTS day2_abandonments(
    request_id TEXT PRIMARY KEY,
    invocation TEXT NOT NULL UNIQUE REFERENCES day2_invocations(id),
    operator TEXT NOT NULL, reason TEXT NOT NULL, evidence TEXT NOT NULL,
    authority_epoch TEXT NOT NULL, authority_revision INTEGER NOT NULL CHECK(authority_revision>0),
    policy TEXT NOT NULL, payload TEXT NOT NULL, at_ms INTEGER NOT NULL, receipt TEXT NOT NULL
) STRICT";

/// Abandonments are append-only. The triggers are created with the table and
/// checked on every initialization, like the authority journal's.
pub(crate) fn upgrade(connection: &Connection) -> Result<()> {
    let existed: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='day2_abandonments')",
        [],
        |row| row.get(0),
    )?;
    connection.execute_batch(TABLE)?;
    for (suffix, action) in [
        ("no_update", "BEFORE UPDATE ON day2_abandonments"),
        ("no_delete", "BEFORE DELETE ON day2_abandonments"),
        (
            "no_replace",
            "BEFORE INSERT ON day2_abandonments WHEN EXISTS(SELECT 1 FROM day2_abandonments \
             WHERE request_id=NEW.request_id OR invocation=NEW.invocation)",
        ),
    ] {
        let name = format!("day2_abandonments_{suffix}");
        let sql = format!(
            "CREATE TRIGGER {name} {action} BEGIN SELECT RAISE(ABORT,'append_only_abandonment'); END"
        );
        if !existed {
            connection.execute_batch(&sql)?;
        }
        crate::audit::validate_trigger(connection, &name, &sql)?;
    }
    Ok(())
}

/// Finish a blocked invocation as a failure (`invocation_abandoned`).
///
/// The invocation may belong to an earlier artifact. Its block row stays, and
/// every later read, execution or duplicate request reports the abandonment. A
/// provider result that arrives late is still recorded as evidence and never
/// runs completion.
pub fn abandon(runtime: &Runtime, operator: &LocalOperator, request: &Request) -> Result<Receipt> {
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
    let payload = serde_json::to_string(&(request, operator.name()))?;
    let at_ms = runtime.host().now_ms()?;
    runtime.sql_write(|tx| {
        runtime.check_binding(tx)?;
        let active = crate::authority_state::current(tx)?;
        ensure!(
            runtime.operators()?.contains(operator.name())
                || active.policy()?.admins.contains(operator.name()),
            "recovery_operator_required"
        );
        if let Some((stored, receipt)) = tx
            .query_row(
                "SELECT payload,receipt FROM day2_abandonments WHERE request_id=?1",
                [&request.request_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            ensure!(stored == payload, "recovery_request_conflict");
            return crate::json::decode(receipt.as_bytes());
        }
        ensure!(!abandoned(tx, &request.invocation)?, "recovery_already_resolved");
        let (artifact, operation, status): (String, String, String) = tx
            .query_row(
                "SELECT artifact,operation,status FROM day2_invocations WHERE id=?1",
                [&request.invocation],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .context(Failure::NotFound)?;
        ensure!(artifact == request.expected_artifact, Failure::ArtifactBindingChanged);
        ensure!(
            status == "pending" && crate::authority_state::is_blocked(tx, &request.invocation)?,
            "recovery_requires_blocked_invocation"
        );
        let receipt = Receipt {
            invocation: request.invocation.clone(),
            evidence: classify_effects(tx, &request.invocation)?,
            children: children_in(tx, &request.invocation)?,
        };
        ensure!(
            tx.execute(
                "UPDATE day2_invocations SET status='failure',outcome=?1 WHERE id=?2 AND status='pending'",
                params![serde_json::to_string(&abandoned_outcome())?, request.invocation],
            )? == 1,
            "recovery_requires_blocked_invocation"
        );
        // The operator acts under the active authority; record it with its policy.
        tx.execute(
            "INSERT INTO day2_abandonments(request_id,invocation,operator,reason,evidence,
             authority_epoch,authority_revision,policy,payload,at_ms,receipt)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                request.request_id,
                request.invocation,
                operator.name(),
                request.reason,
                serde_json::to_string(&receipt.evidence)?,
                active.stamp.epoch,
                i64::try_from(active.stamp.revision)?,
                serde_json::to_string(active.policy()?)?,
                payload,
                at_ms,
                serde_json::to_string(&receipt)?
            ],
        )?;
        crate::audit::record_abandonment(
            tx,
            runtime,
            crate::audit::Abandonment {
                operator: operator.name(),
                invocation: &request.invocation,
                operation: &operation,
                artifact: &artifact,
                at_ms,
            },
        )?;
        Ok(receipt)
    })
}

/// The outcome an abandoned invocation finishes with, and that every read,
/// execution and duplicate request of it reports.
pub(crate) fn abandoned_outcome() -> Outcome {
    Outcome {
        status: "failure".into(),
        result: serde_json::json!({}),
        error: Failure::InvocationAbandoned.code().into(),
    }
}

pub(crate) fn abandoned(connection: &Connection, invocation: &str) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_abandonments WHERE invocation=?1)",
        [invocation],
        |row| row.get(0),
    )?)
}

/// Whether the effect belongs to an abandoned invocation. A dispatch permit for
/// it must not start a provider call.
pub(crate) fn effect_abandoned(connection: &Connection, effect: &str) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_abandonments a
         JOIN day2_external_effects e ON e.invocation=a.invocation WHERE e.identity=?1)",
        [effect],
        |row| row.get(0),
    )?)
}

/// An attempt's reservation shares its identity. A recorded effect result is
/// still not known if its usage is: an adapter error alone is not evidence of
/// a final provider outcome. A recorded attempt error with no effect result is
/// a retry the effect still waits on (such as an undelivered app send).
fn classify_effects(connection: &Connection, invocation: &str) -> Result<EvidenceSummary> {
    let mut summary = EvidenceSummary::default();
    let mut statement = connection.prepare(
        "SELECT e.observation IS NOT NULL,
            EXISTS(SELECT 1 FROM day2_external_attempts a WHERE a.effect=e.identity),
            EXISTS(SELECT 1 FROM day2_external_attempts a JOIN day2_budget_unknown u ON u.id=a.identity
                   WHERE a.effect=e.identity)
         FROM day2_external_effects e WHERE e.invocation=?1 ORDER BY e.ordinal",
    )?;
    let rows = statement.query_map([invocation], |row| {
        Ok((
            row.get::<_, bool>(0)?,
            row.get::<_, bool>(1)?,
            row.get::<_, bool>(2)?,
        ))
    })?;
    for row in rows {
        let count = match row? {
            (_, false, _) => &mut summary.never_admitted,
            (true, true, false) => &mut summary.known_result,
            _ => &mut summary.unknown_outcome,
        };
        *count = count.checked_add(1).context("recovery_evidence_overflow")?;
    }
    Ok(summary)
}

fn children_in(connection: &Connection, invocation: &str) -> Result<Vec<String>> {
    let mut statement = connection
        .prepare("SELECT id FROM day2_command_requests WHERE parent=?1 ORDER BY ordinal")?;
    Ok(statement
        .query_map([invocation], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each effect shape, built on the runtime's own schema.
    #[test]
    fn evidence_counts_only_recorded_results_with_known_usage_as_known() -> Result<()> {
        let mut connection = Connection::open_in_memory()?;
        let db = connection.transaction()?;
        db.execute_batch(
            "CREATE TABLE day2_invocations(id TEXT PRIMARY KEY) STRICT;
             INSERT INTO day2_invocations VALUES('blocked');",
        )?;
        crate::execution::upgrade(&db)?;
        crate::budget::upgrade(&db)?;
        let effect = |ordinal: i64, observation: Option<&str>| -> Result<()> {
            db.execute(
                "INSERT INTO day2_external_effects(identity,invocation,ordinal,instruction,observation)
                 VALUES(?1,'blocked',?2,'{}',?3)",
                params![format!("effect-{ordinal}"), ordinal, observation],
            )?;
            Ok(())
        };
        let attempt = |ordinal: i64, name: &str, observation: Option<&str>| -> Result<()> {
            db.execute(
                "INSERT INTO day2_external_attempts(identity,effect,ordinal,authority_epoch,authority_revision,observation)
                 VALUES(?1,?2,1,'epoch',1,?3)",
                params![name, format!("effect-{ordinal}"), observation],
            )?;
            Ok(())
        };
        // Claimed, never admitted.
        effect(0, None)?;
        // Admitted, no result yet.
        effect(1, None)?;
        attempt(1, "a1", None)?;
        // Delivery errors recorded on attempts while the effect waits for a retry.
        effect(2, None)?;
        attempt(2, "a2", Some("{\"error\":\"undelivered\"}"))?;
        // Resolved with known usage.
        effect(3, Some("{}"))?;
        attempt(3, "a3", Some("{}"))?;
        // Resolved, but the adapter could not say what the provider did.
        effect(4, Some("{\"error\":\"adapter\"}"))?;
        attempt(4, "a4", Some("{\"error\":\"adapter\"}"))?;
        db.execute(
            "INSERT INTO day2_budget_reservations VALUES('a4','ledger','fingerprint','{}','{}')",
            [],
        )?;
        db.execute("INSERT INTO day2_budget_unknown VALUES('a4')", [])?;
        assert_eq!(
            classify_effects(&db, "blocked")?,
            EvidenceSummary {
                never_admitted: 1,
                known_result: 1,
                unknown_outcome: 3
            }
        );
        Ok(())
    }
}
