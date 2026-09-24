//! Compaction of the invocation journal.
//!
//! Every invocation keeps its accepted input and a full trace: each storage
//! observation, the authority policy it ran under and its outcome. That is what
//! lets a pending command resume by replay, and it is roughly seventeen kilobytes
//! per command — most of an app database under steady traffic, and more than the
//! business data by two orders of magnitude.
//!
//! A completed invocation needs almost none of it. What remains in use is its
//! receipt: a retry under the same idempotency key must be recognised and answered
//! with the original outcome, and only while the authority it ran under is still
//! the active one. So after a window, compaction replaces the input and trace of a
//! completed invocation with a digest of each part those checks compare, and keeps
//! the outcome column. Retries and status reads keep working; the full trace is
//! gone. Pending invocations, including blocked ones, are never touched.
//!
//! Rows are never deleted: every completed invocation has an append-only audit
//! row that references it, and the audit record is kept by design.
use crate::protocol::Trace;
use anyhow::{Context as _, Result, ensure};
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
    compact_before(runtime.db(), now - i64::from(hours) * 3_600, batch)
}

pub(crate) fn compact_before(db: &std::path::Path, cutoff: i64, batch: usize) -> Result<usize> {
    let mut connection = crate::store::open(db)?;
    let tx = crate::write_queue::immediate(&mut connection)?;
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
    for (id, input, raw, outcome) in &rows {
        let trace: Trace = serde_json::from_str(raw).context("invalid_invocation_trace")?;
        let receipt = Receipt {
            format: 1,
            input: crate::digest(input.as_bytes()),
            policy: reusable_policy(&tx, id, &trace, outcome.as_deref())?,
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
    }
    tx.commit()?;
    Ok(rows.len())
}

/// The digest a receipt keeps for the authority check, when the trace passes
/// every check that reuse makes on a full trace apart from the active policy and
/// stamp, which are compared at reuse time. Otherwise none: the invocation could
/// not have been reused before compaction and cannot be after it.
fn reusable_policy(
    connection: &rusqlite::Connection,
    id: &str,
    trace: &Trace,
    outcome: Option<&str>,
) -> Result<Option<String>> {
    let Some(guard) = trace.guard.as_ref().filter(|_| trace.format == 2) else {
        return Ok(None);
    };
    let Ok(stamp) = crate::authority_state::invocation_stamp(connection, id) else {
        return Ok(None);
    };
    let recorded = outcome
        .map(serde_json::from_str::<crate::protocol::Outcome>)
        .transpose()?;
    if guard.authority.as_ref() != Some(&stamp) || recorded.as_ref() != Some(&trace.outcome) {
        return Ok(None);
    }
    policy_digest(&guard.policy).map(Some)
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
