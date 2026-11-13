//! How the invocation journal stores traces, and its compaction.
//!
//! Every invocation keeps its accepted input and a full trace: each storage
//! observation, the authority policy it ran under and its outcome. That is what
//! lets a pending command resume by replay.
//!
//! The policy is most of a trace — the whole access policy, every operation — and
//! it is the same for every invocation under one authority revision. A stored
//! trace therefore names its policy by digest, and `day2_trace_policies` holds each
//! distinct policy once. Reading a stored trace resolves the digest and checks the
//! bytes against it, so a trace still binds exactly the policy it ran under and a
//! changed or missing policy row fails closed. A trace read out of the store, for
//! replay, inspection or evidence, carries the resolved policy and is
//! self-contained again.
//!
//! A completed invocation needs almost none of it. What remains in use is its
//! receipt: a retry under the same idempotency key must be recognised and answered
//! with the original outcome, and only while the authority it ran under is still
//! the active one. So after a window, compaction replaces the input and trace of a
//! completed invocation with a digest of each part those checks compare, and keeps
//! the outcome column. The provider responses its external effects recorded are
//! replaced by their digest too: they were the input to resuming the effects
//! phase, which a completed invocation never does again. Retries and status reads
//! keep working; the full trace is gone. Pending invocations, including blocked
//! ones, are never touched.
//!
//! Rows are never deleted: every completed invocation has an append-only audit
//! row that references it, and the audit record is kept by design.
use crate::{
    authority_state::AuthorityStamp,
    protocol::{ExecutionGuard, Outcome, Request, Row, Trace},
};
use anyhow::{Context as _, Result, ensure};
use rusqlite::{Connection, OptionalExtension as _, params};
use serde::{Deserialize, Serialize};

/// Hours a completed invocation keeps its full trace when the instance does not
/// say otherwise. Long enough to debug yesterday's failure; short enough that a
/// busy app's journal stays a small part of its database.
pub const DEFAULT_TRACE_HOURS: u32 = 72;

/// The operator's choice, declared per app in the instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Hours after acceptance that a completed invocation keeps its full trace.
    pub trace_hours: u32,
}

impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=24 * 366).contains(&self.trace_hours),
            "journal trace_hours must be between 1 and 8784"
        );
        Ok(())
    }
}

/// What a compacted invocation keeps in place of its input and trace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    pub format: u32,
    /// Digest of the accepted canonical input, compared by an idempotent retry.
    pub input: String,
    /// Digest of the authority policy the invocation ran under. Absent for
    /// invocations whose trace carried no guard, which could not be reused before
    /// compaction either.
    pub policy: Option<String>,
}

impl Receipt {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        let receipt: Self = serde_json::from_str(raw).context("invalid_invocation_receipt")?;
        ensure!(receipt.format == 1, "invalid_invocation_receipt");
        Ok(receipt)
    }
}

pub(crate) fn policy_digest(policy: &crate::authority::Policy) -> Result<String> {
    // Policies are built from ordered maps and sets, so their serialisation is
    // deterministic and equal policies have equal digests.
    Ok(crate::digest(&serde_json::to_vec(policy)?))
}

/// Each distinct authority policy a stored trace ran under, keyed by the digest
/// of its canonical serialisation, which is also the digest a receipt keeps.
/// There is at most one row per policy the app has ever run under, and nothing
/// removes one: any pending trace may name any of them.
///
/// The digest is the integrity check. Every read compares the row's bytes with
/// the digest the trace names, so an edited, replaced or missing row fails closed
/// wherever it is used. The table is one schema object on purpose — no key
/// index, no guard triggers — because security admission charges each object on
/// every full-schema scan, under a fixed budget the restore path already spends
/// most of. It stays an ordinary rowid table, which restore snapshots require.
/// Without an index a lookup scans the table, which holds one row per policy;
/// the digest is the first column, so only the matching row's policy is read.
const POLICIES_DDL: &str = "CREATE TABLE day2_trace_policies(
    digest TEXT NOT NULL CHECK(length(digest)=71 AND substr(digest,1,7)='sha256:'),
    policy TEXT NOT NULL) STRICT";

/// A trace as `day2_invocations.trace` and `day2_execution.trace` hold it: the
/// guard's policy is the digest of a `day2_trace_policies` row.
#[derive(Serialize)]
struct StoringTrace<'a> {
    format: u32,
    artifact: &'a str,
    scope: &'a str,
    request: &'a Request,
    outcome: &'a Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    guard: Option<StoringGuard<'a>>,
}

#[derive(Serialize)]
struct StoringGuard<'a> {
    policy: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    authority: Option<&'a AuthorityStamp>,
    precondition_row: Option<&'a Row>,
    error: &'a str,
}

/// The owned reading of [`StoringTrace`]. A trace with an embedded policy is not
/// one of these, and is refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredTrace {
    format: u32,
    artifact: String,
    scope: String,
    request: Request,
    outcome: Outcome,
    #[serde(default)]
    guard: Option<StoredGuard>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredGuard {
    policy: String,
    #[serde(default)]
    authority: Option<AuthorityStamp>,
    precondition_row: Option<Row>,
    error: String,
}

/// The stored form of `trace`, recording its policy once in `day2_trace_policies`.
/// Deterministic: equal traces have equal stored forms, which the effects phase
/// relies on to compare a journal entry with the one it advances.
pub(crate) fn store_trace(connection: &Connection, trace: &Trace) -> Result<String> {
    let policy = trace
        .guard
        .as_ref()
        .map(|guard| store_policy(connection, &guard.policy))
        .transpose()?;
    let guard = trace
        .guard
        .as_ref()
        .zip(policy.as_deref())
        .map(|(guard, policy)| StoringGuard {
            policy,
            authority: guard.authority.as_ref(),
            precondition_row: guard.precondition_row.as_ref(),
            error: &guard.error,
        });
    Ok(serde_json::to_string(&StoringTrace {
        format: trace.format,
        artifact: &trace.artifact,
        scope: &trace.scope,
        request: &trace.request,
        outcome: &trace.outcome,
        guard,
    })?)
}

/// A stored trace with its policy resolved and checked against its digest.
pub(crate) fn load_trace(connection: &Connection, raw: &str) -> Result<Trace> {
    let stored: StoredTrace = serde_json::from_str(raw).context("invalid_invocation_trace")?;
    let guard = match stored.guard {
        Some(guard) => Some(ExecutionGuard {
            policy: load_policy(connection, &guard.policy)?,
            authority: guard.authority,
            precondition_row: guard.precondition_row,
            error: guard.error,
        }),
        None => None,
    };
    Ok(Trace {
        format: stored.format,
        artifact: stored.artifact,
        scope: stored.scope,
        request: stored.request,
        outcome: stored.outcome,
        guard,
    })
}

fn store_policy(connection: &Connection, policy: &crate::authority::Policy) -> Result<String> {
    let canonical = serde_json::to_string(policy)?;
    let digest = crate::digest(canonical.as_bytes());
    // An existing row is not re-read here: every read checks its bytes against
    // the digest, so a changed row fails closed wherever it is used.
    let present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_trace_policies WHERE digest=?1)",
        [&digest],
        |row| row.get(0),
    )?;
    if !present {
        connection.execute(
            "INSERT INTO day2_trace_policies(digest,policy) VALUES(?1,?2)",
            params![digest, canonical],
        )?;
    }
    Ok(digest)
}

fn load_policy(connection: &Connection, digest: &str) -> Result<crate::authority::Policy> {
    let canonical: String = connection
        .query_row(
            "SELECT policy FROM day2_trace_policies WHERE digest=?1",
            [digest],
            |row| row.get(0),
        )
        .optional()?
        .context("trace_policy_missing")?;
    ensure!(
        crate::digest(canonical.as_bytes()) == digest,
        "trace_policy_digest_mismatch"
    );
    let policy: crate::authority::Policy =
        serde_json::from_str(&canonical).context("invalid_trace_policy")?;
    // Receipts compare the active policy by this same digest, so the stored bytes
    // must be the canonical serialisation and not merely some encoding of it.
    ensure!(
        policy_digest(&policy)? == digest,
        "trace_policy_digest_mismatch"
    );
    Ok(policy)
}

/// What a compacted external effect, or one of its attempts, keeps in place of
/// the provider's response. Never NULL: an effect without an observation is one
/// whose outcome is still unknown, and the scheduler and delegated sends read it
/// that way. Not an `Observation` either, so a reader that needs the response
/// fails closed rather than replaying something else.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactedObservation {
    compacted: String,
}

fn compacted_observation(raw: &str) -> Result<Option<String>> {
    if serde_json::from_str::<CompactedObservation>(raw).is_ok() {
        return Ok(None);
    }
    Ok(Some(serde_json::to_string(&CompactedObservation {
        compacted: crate::digest(raw.as_bytes()),
    })?))
}

/// Replace the recorded provider responses of a completed invocation's external
/// effects and their attempts with digests. The rows, identities and the fact
/// that each settled all stay: resource accounting cites the attempts.
fn compact_effects(connection: &Connection, id: &str) -> Result<()> {
    let effects: Vec<(String, Option<String>)> = connection
        .prepare("SELECT identity,observation FROM day2_external_effects WHERE invocation=?1")?
        .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (effect, observation) in effects {
        if let Some(compacted) = observation
            .as_deref()
            .map(compacted_observation)
            .transpose()?
            .flatten()
        {
            connection.execute(
                "UPDATE day2_external_effects SET observation=?2
                 WHERE identity=?1 AND observation IS NOT NULL",
                params![effect, compacted],
            )?;
        }
        let attempts: Vec<(String, String)> = connection
            .prepare(
                "SELECT identity,observation FROM day2_external_attempts
                 WHERE effect=?1 AND observation IS NOT NULL",
            )?
            .query_map([&effect], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (attempt, observation) in attempts {
            if let Some(compacted) = compacted_observation(&observation)? {
                connection.execute(
                    "UPDATE day2_external_attempts SET observation=?2
                     WHERE identity=?1 AND observation IS NOT NULL",
                    params![attempt, compacted],
                )?;
            }
        }
    }
    Ok(())
}

/// Host schema 11: traces name their policy by digest, and completed invocations
/// compacted before this schema lose their recorded provider responses as well.
///
/// Every stored trace is rewritten here, in the upgrade transaction, so the
/// runtime reads a single stored form. Pending invocations would never age out of
/// an embedded copy — a blocked one stays pending indefinitely — so waiting for
/// compaction would have meant reading both forms for good. A trace already in
/// the stored form is left as it is, which makes a repeated upgrade a no-op; one
/// in neither form is left too, and fails closed where it is read, as before.
pub(crate) fn upgrade(db: &Connection) -> Result<()> {
    if !table_exists(db, "day2_trace_policies")? {
        db.execute_batch(POLICIES_DDL)?;
    }
    let ids: Vec<String> = db
        .prepare("SELECT id FROM day2_invocations WHERE trace IS NOT NULL")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for id in ids {
        let raw: String = db.query_row(
            "SELECT trace FROM day2_invocations WHERE id=?1",
            [&id],
            |row| row.get(0),
        )?;
        if let Some(stored) = stored_from_embedded(db, &raw)? {
            db.execute(
                "UPDATE day2_invocations SET trace=?2 WHERE id=?1",
                params![id, stored],
            )?;
        }
    }
    if table_exists(db, "day2_execution")? {
        let ids: Vec<String> = db
            .prepare("SELECT invocation FROM day2_execution WHERE trace!=''")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for id in ids {
            let raw: String = db.query_row(
                "SELECT trace FROM day2_execution WHERE invocation=?1",
                [&id],
                |row| row.get(0),
            )?;
            if let Some(stored) = stored_from_embedded(db, &raw)? {
                db.execute(
                    "UPDATE day2_execution SET trace=?2 WHERE invocation=?1",
                    params![id, stored],
                )?;
            }
        }
    }
    if table_exists(db, "day2_external_effects")? && table_exists(db, "day2_external_attempts")? {
        let compacted: Vec<String> = db
            .prepare(
                "SELECT DISTINCT e.invocation FROM day2_external_effects e
                 JOIN day2_invocations i ON i.id=e.invocation
                 WHERE i.status IN ('success','failure') AND i.trace IS NULL
                 AND i.receipt IS NOT NULL",
            )?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for id in compacted {
            compact_effects(db, &id)?;
        }
    }
    Ok(())
}

/// The stored form of a trace written with its policy embedded, or None when
/// there is nothing to rewrite.
fn stored_from_embedded(db: &Connection, raw: &str) -> Result<Option<String>> {
    if serde_json::from_str::<StoredTrace>(raw).is_ok() {
        return Ok(None);
    }
    match serde_json::from_str::<Trace>(raw) {
        Ok(trace) => store_trace(db, &trace).map(Some),
        Err(_) => Ok(None),
    }
}

fn table_exists(db: &Connection, name: &str) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [name],
        |row| row.get(0),
    )?)
}

/// Whether a stored input, possibly compacted, is the input a retry presents.
pub(crate) fn same_input(stored: &str, receipt: Option<&str>, canonical: &str) -> Result<bool> {
    match receipt {
        Some(raw) if stored.is_empty() => {
            Ok(Receipt::parse(raw)?.input == crate::digest(canonical.as_bytes()))
        }
        _ => Ok(stored == canonical),
    }
}

/// Compact up to `batch` completed invocations accepted before `now - trace_hours`.
/// Returns how many were compacted; fewer than `batch` means none are left.
pub fn compact(runtime: &crate::store::Runtime, now: i64, batch: usize) -> Result<usize> {
    let policy = crate::artifact::Instance::load(runtime.instance_path())?
        .apps
        .get(runtime.app())
        .and_then(|binding| binding.journal);
    let hours = policy.map_or(DEFAULT_TRACE_HOURS, |policy| policy.trace_hours);
    let cutoff = now - i64::from(hours) * 3_600;
    runtime.sql_write(|tx| compact_in(tx, cutoff, batch))
}

#[cfg(test)]
pub(crate) fn compact_before(db: &std::path::Path, cutoff: i64, batch: usize) -> Result<usize> {
    let mut connection = crate::store::open(db)?;
    let tx = crate::write_queue::immediate(&mut connection)?;
    let count = compact_in(&tx, cutoff, batch)?;
    tx.commit()?;
    Ok(count)
}

// The transaction's owner commits and settles the actual SQL unit. No
// connection or transaction may survive into the next compaction batch.
fn compact_in(tx: &rusqlite::Connection, cutoff: i64, batch: usize) -> Result<usize> {
    let rows: Vec<(String, String, String, Option<String>)> = tx
        .prepare(
            "SELECT id,input,trace,outcome FROM day2_invocations
             WHERE status IN ('success','failure') AND trace IS NOT NULL AND now < ?1
             ORDER BY now LIMIT ?2",
        )?
        .query_map(rusqlite::params![cutoff, batch as i64], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut verified = std::collections::BTreeSet::new();
    for (id, input, raw, outcome) in &rows {
        let trace: StoredTrace = serde_json::from_str(raw).context("invalid_invocation_trace")?;
        let receipt = Receipt {
            format: 1,
            input: crate::digest(input.as_bytes()),
            policy: reusable_policy(tx, id, &trace, outcome.as_deref(), &mut verified)?,
        };
        ensure!(
            tx.execute(
                "UPDATE day2_invocations SET input='',trace=NULL,receipt=?2
                 WHERE id=?1 AND status IN ('success','failure') AND trace IS NOT NULL",
                rusqlite::params![id, serde_json::to_string(&receipt)?],
            )? == 1,
            "journal_compaction_conflict"
        );
        // Effectful commands keep a second copy of the trace for their completion
        // phase; once complete it is replay evidence only.
        tx.execute(
            "UPDATE day2_execution SET trace='' WHERE invocation=?1 AND phase='complete'",
            [id],
        )?;
        // Preparation rows and observation payloads are the input to preparing a
        // pending invocation, which a completed one never does again; its receipt
        // answers retries. The attempt rows stay, as resource accounting cites them.
        tx.execute("DELETE FROM day2_preparation WHERE invocation=?1", [id])?;
        tx.execute(
            "UPDATE day2_observation_attempts SET observation=NULL
             WHERE invocation=?1 AND observation IS NOT NULL",
            [id],
        )?;
        // Provider responses were the input to resuming the effects phase. The
        // completion copy of the trace that cited them is gone already.
        compact_effects(tx, id)?;
    }
    Ok(rows.len())
}

/// The digest a receipt keeps for the authority check, when the trace passes
/// every check that reuse makes on a full trace apart from the active policy and
/// stamp, which are compared at reuse time. Otherwise none: the invocation could
/// not have been reused before compaction and cannot be after it.
///
/// The stored trace already names its policy by that digest. The policy row is
/// still resolved and checked, once per batch, so compaction never turns a
/// reference to a changed or missing policy into a receipt.
fn reusable_policy(
    connection: &rusqlite::Connection,
    id: &str,
    trace: &StoredTrace,
    outcome: Option<&str>,
    verified: &mut std::collections::BTreeSet<String>,
) -> Result<Option<String>> {
    let Some(guard) = trace.guard.as_ref() else {
        return Ok(None);
    };
    if !verified.contains(&guard.policy) {
        load_policy(connection, &guard.policy)?;
        verified.insert(guard.policy.clone());
    }
    if trace.format != 2 {
        return Ok(None);
    }
    let Ok(stamp) = crate::authority_state::invocation_stamp(connection, id) else {
        return Ok(None);
    };
    let recorded = outcome
        .map(serde_json::from_str::<crate::protocol::Outcome>)
        .transpose()?;
    if guard.authority.as_ref() != Some(&stamp) || recorded.as_ref() != Some(&trace.outcome) {
        return Ok(None);
    }
    Ok(Some(guard.policy.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_window_is_bounded() {
        assert!(Policy { trace_hours: 0 }.validate().is_err());
        assert!(Policy { trace_hours: 1 }.validate().is_ok());
        assert!(
            Policy {
                trace_hours: 24 * 366
            }
            .validate()
            .is_ok()
        );
        assert!(
            Policy {
                trace_hours: 24 * 366 + 1
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn compacted_input_is_compared_by_digest() -> Result<()> {
        let receipt = serde_json::to_string(&Receipt {
            format: 1,
            input: crate::digest(br#"{"a":1}"#),
            policy: None,
        })?;
        assert!(same_input("", Some(&receipt), r#"{"a":1}"#)?);
        assert!(!same_input("", Some(&receipt), r#"{"a":2}"#)?);
        assert!(same_input(r#"{"a":2}"#, None, r#"{"a":2}"#)?);
        assert!(Receipt::parse(r#"{"format":2,"input":"x","policy":null}"#).is_err());
        Ok(())
    }
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod storage_tests;
