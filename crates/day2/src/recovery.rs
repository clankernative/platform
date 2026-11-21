//! Local-operator resolution of pending invocations that will never finish.
//!
//! Two kinds qualify, and the operator states which one they found:
//! - Blocked by an authority change. A block is permanent: the invocation stays
//!   pending, never runs a business phase again, and only settles evidence for
//!   external attempts admitted before the block.
//! - An orphaned request. A direct request admitted a query or a page load, and
//!   the serving process stopped before finishing it, for example when
//!   maintenance stopped the app mid-request. Only that request was running it:
//!   the scheduler never resumes it, and its random identity is never repeated.
//!   A migration ends the ones it finds itself ([`abandon_orphaned_requests`]),
//!   since it holds the store against every server; an operator may also end
//!   one explicitly.
//!
//! Abandoning one makes that end explicit. It finishes the invocation as a
//! failure, refuses any dispatch permit that has not started, and records what
//! is known about its external effects. Nothing is retried or rolled back, and
//! business rows are never edited.
use crate::{authority_state::LocalOperator, error::Failure, protocol::Outcome, store::Runtime};
use anyhow::{Context as _, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The most invocations one call abandons: a reviewed handful, never a sweep.
pub const MAX_REQUESTS: usize = 16;

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
    /// Why the operator says it will never finish.
    pub cause: Cause,
}

impl Request {
    /// The checks that need no store, so a list can be refused before an app
    /// is stopped for it.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.request_id.trim().is_empty() && self.request_id.len() <= 128,
            "invalid_recovery_request_id"
        );
        ensure!(
            !self.invocation.trim().is_empty() && self.invocation.len() <= 512,
            "invalid_recovery_invocation"
        );
        ensure!(
            !self.reason.trim().is_empty()
                && self.reason.len() <= 200
                && !self.reason.chars().any(char::is_control),
            "invalid_recovery_reason"
        );
        Ok(())
    }
}

/// A list one call abandons: 1 to [`MAX_REQUESTS`] valid requests, each
/// `request_id` and each invocation once.
pub fn validate(requests: &[Request]) -> Result<()> {
    ensure!(
        (1..=MAX_REQUESTS).contains(&requests.len()),
        "recovery_requests_count"
    );
    let mut keys = BTreeSet::new();
    let mut invocations = BTreeSet::new();
    for request in requests {
        request.validate()?;
        ensure!(
            keys.insert(request.request_id.as_str())
                && invocations.insert(request.invocation.as_str()),
            "recovery_request_duplicate"
        );
    }
    Ok(())
}

/// Why a pending invocation will never finish.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Cause {
    /// An authority change blocked it.
    Blocked,
    /// A direct request for work the scheduler never resumes, whose serving
    /// process stopped before finishing it.
    OrphanedRequest,
}

impl Cause {
    /// The wire name, as requests and receipts carry it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::OrphanedRequest => "orphaned_request",
        }
    }

    /// The refusal when the invocation is not what the operator said.
    fn refusal(self) -> &'static str {
        match self {
            Self::Blocked => "recovery_requires_blocked_invocation",
            Self::OrphanedRequest => "recovery_requires_orphaned_request",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub invocation: String,
    pub cause: Cause,
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

/// Finish each listed invocation as a failure (`invocation_abandoned`), all or
/// nothing: one refusal leaves every listed invocation as it was.
///
/// An invocation may belong to an earlier artifact. A block row stays, and every
/// later read, execution or duplicate request reports the abandonment. A
/// provider result that arrives late is still recorded as evidence and never
/// runs completion.
///
/// An orphaned request must be pending, unblocked, admitted by a direct request
/// (`trigger` `request`), and of an operation the scheduler never resumes in
/// this store ([`crate::invocations::scheduled_operations`]): a query or a page
/// load in an ordinary non-rolling store. A rolling store drains every kind, so
/// nothing there is orphaned. The decision holds the store's recovery
/// exclusion, which no `day2-serve` can hold beside it: no runtime holds the
/// invocation, and the request that admitted it has ended.
pub fn abandon(
    runtime: &Runtime,
    operator: &LocalOperator,
    requests: &[Request],
) -> Result<Vec<Receipt>> {
    validate(requests)?;
    let payloads = requests
        .iter()
        .map(|request| serde_json::to_string(&(request, operator.name())))
        .collect::<serde_json::Result<Vec<_>>>()?;
    // A recorded request returns its receipt without a new decision, so
    // repeating one needs no exclusion.
    let recorded = runtime.sql_read(|db| {
        let mut recorded = BTreeSet::new();
        for request in requests {
            if db
                .query_row(
                    "SELECT 1 FROM day2_abandonments WHERE request_id=?1",
                    [&request.request_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some()
            {
                recorded.insert(request.request_id.clone());
            }
        }
        Ok(recorded)
    })?;
    let _exclusion = if requests.iter().any(|request| {
        request.cause == Cause::OrphanedRequest && !recorded.contains(&request.request_id)
    }) {
        Some(
            crate::deployment::recovery_exclusion(runtime, operator)
                .context("recovery_requires_exclusive_store")?,
        )
    } else {
        None
    };
    let scheduled = crate::invocations::scheduled_operations(runtime);
    let at_ms = runtime.host().now_ms()?;
    runtime.sql_write(|tx| {
        runtime.check_binding(tx)?;
        let active = crate::authority_state::current(tx)?;
        ensure!(
            runtime.operators()?.contains(operator.name())
                || active.policy()?.admins.contains(operator.name()),
            "recovery_operator_required"
        );
        let decision = Decision {
            runtime,
            operator,
            active: &active,
            scheduled: &scheduled,
            at_ms,
        };
        let mut receipts = Vec::with_capacity(requests.len());
        for (request, payload) in requests.iter().zip(&payloads) {
            receipts.push(decision.abandon(tx, request, payload)?);
        }
        Ok(receipts)
    })
}

/// Who abandons the orphaned requests a migration finds: the migration itself,
/// not an operator.
pub const MIGRATION_OPERATOR: &str = "day2-migration";

/// Why a migration abandoned an orphaned request, as its row records.
const MIGRATION_REASON: &str =
    "no server held the store when a migration began, so nothing will finish this request";

/// Abandon, in the migration's own transaction, every orphaned request in a
/// store the migration holds against every server: each pending, unblocked
/// invocation that a direct request admitted, of an operation the scheduler
/// never resumes. They record [`Cause::OrphanedRequest`] under
/// [`MIGRATION_OPERATOR`], with a `request_id` of `migration:` and the
/// invocation id. An orphaned request is the one kind of pending work that is
/// provably over without an operator: nothing runs it again, and the request
/// that admitted it has ended. Otherwise each one, though harmless, would refuse
/// every migration until an operator abandoned it.
///
/// Blocked work stays for an operator to judge. Work the scheduler finishes
/// must still drain first: the migration's drain check then refuses the store,
/// and these abandonments roll back with it. A rolling store, which drains
/// every kind, and native storage, whose serving lock does not exclude
/// servers, have none.
pub(crate) fn abandon_orphaned_requests(
    tx: &Connection,
    runtime: &Runtime,
    _exclusion: &crate::deployment::MigrationExclusion,
    at_ms: i64,
) -> Result<Vec<Receipt>> {
    if runtime.rolling() || !crate::deployment::ordinary_store(runtime)? {
        return Ok(Vec::new());
    }
    let scheduled = crate::invocations::scheduled_operations(runtime);
    let requested = {
        let mut statement = tx.prepare(
            "SELECT id,artifact,operation FROM day2_invocations
             WHERE status='pending' AND trigger=?1 ORDER BY id",
        )?;
        statement
            .query_map([crate::audit::Trigger::Request.as_str()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<rusqlite::Result<Vec<(String, String, String)>>>()?
    };
    let mut orphaned = Vec::new();
    for (invocation, artifact, operation) in requested {
        if !scheduled.contains(&operation) && !crate::authority_state::is_blocked(tx, &invocation)?
        {
            orphaned.push(Request {
                request_id: format!("migration:{invocation}"),
                invocation,
                expected_artifact: artifact,
                reason: MIGRATION_REASON.into(),
                cause: Cause::OrphanedRequest,
            });
        }
    }
    if orphaned.is_empty() {
        return Ok(Vec::new());
    }
    let operator = LocalOperator::assert_local(MIGRATION_OPERATOR)?;
    let active = crate::authority_state::current(tx)?;
    let decision = Decision {
        runtime,
        operator: &operator,
        active: &active,
        scheduled: &scheduled,
        at_ms,
    };
    orphaned
        .iter()
        .map(|request| {
            decision.abandon(
                tx,
                request,
                &serde_json::to_string(&(request, operator.name()))?,
            )
        })
        .collect()
}

/// What every item of one call is decided under.
struct Decision<'a> {
    runtime: &'a Runtime,
    operator: &'a LocalOperator,
    active: &'a crate::authority_state::ActiveAuthority,
    /// The operations this store's scheduler resumes.
    scheduled: &'a [String],
    at_ms: i64,
}

impl Decision<'_> {
    /// Whether a pending invocation of `operation` is one only its request ran.
    fn unscheduled(&self, operation: &str) -> bool {
        !self.runtime.rolling() && !self.scheduled.iter().any(|name| name == operation)
    }

    fn abandon(&self, tx: &Connection, request: &Request, payload: &str) -> Result<Receipt> {
        let (runtime, operator, active, at_ms) =
            (self.runtime, self.operator, self.active, self.at_ms);
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
        ensure!(
            !abandoned(tx, &request.invocation)?,
            "recovery_already_resolved"
        );
        let (artifact, operation, status, trigger): (String, String, String, String) = tx
            .query_row(
                "SELECT artifact,operation,status,trigger FROM day2_invocations WHERE id=?1",
                [&request.invocation],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?
            .context(Failure::NotFound)?;
        ensure!(
            artifact == request.expected_artifact,
            Failure::ArtifactBindingChanged
        );
        let blocked = crate::authority_state::is_blocked(tx, &request.invocation)?;
        let qualifies = status == "pending"
            && match request.cause {
                Cause::Blocked => blocked,
                // A blocked request is abandoned as blocked, which keeps the cause exact.
                Cause::OrphanedRequest => {
                    !blocked
                        && trigger == crate::audit::Trigger::Request.as_str()
                        && self.unscheduled(&operation)
                }
            };
        ensure!(qualifies, request.cause.refusal());
        let receipt = Receipt {
            invocation: request.invocation.clone(),
            cause: request.cause,
            evidence: classify_effects(tx, &request.invocation)?,
            children: children_in(tx, &request.invocation)?,
        };
        ensure!(
        tx.execute(
            "UPDATE day2_invocations SET status='failure',outcome=?1 WHERE id=?2 AND status='pending'",
            params![serde_json::to_string(&abandoned_outcome())?, request.invocation],
        )? == 1,
        request.cause.refusal()
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
    }
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
