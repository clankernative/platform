//! Operator retention: the only thing in this platform that removes anything.
//!
//! Applications cannot delete. `Tx.soft_delete` marks a row and `Tx.restore`
//! brings it back; no instruction an application can issue takes a row out of
//! the database, and no capability it can invoke destroys an object. That is
//! the stance in [`docs/DELETION.md`], and it has one deliberate exception:
//! removal is an operator's decision, expressed here.
//!
//! Three things make this safe to be the exception.
//!
//! It is declared in the instance, which is the operator's file — an artifact
//! cannot ask to be swept, and an application cannot see that it will be.
//!
//! It removes only what was already deleted, and only after the declared window
//! has passed. A live row is not eligible under any policy, which is why the
//! eligibility predicate is written once, used by both the plan and the sweep,
//! and tested against a policy that would remove everything if it could.
//!
//! It removes exactly what the operator reviewed. `sweep` is handed the plan
//! `plan` produced, recomputes it, and refuses on any difference. A row deleted
//! between reading the plan and running the sweep is not swept — it waits for
//! the next one, which is the harmless direction for the mistake to fall.
use crate::{artifact::Instance, store::open};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Seconds in a day, spelled out because the window is declared in days and
/// compared in seconds.
const DAY: i64 = 86_400;

/// Which rows a sweep may touch, written once.
///
/// `deleted_at != 0` is the whole of the safety property: a row nobody deleted
/// is not eligible under any policy. It lives in one string rather than in each
/// statement so the count an operator reads, the records written and the rows
/// destroyed cannot disagree about what "eligible" means — three copies of a
/// predicate are three chances for one of them to lose its first clause.
const ELIGIBLE: &str = "deleted_at != 0 AND deleted_at <= ?1";

/// What an operator declares about one model.
///
/// Per model rather than per app: "remove closed tickets after a year" and
/// "keep the audit of who closed them" are different decisions, and a
/// whole-app window would force the shorter one on everything.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Days a row stays after it was deleted.
    ///
    /// At least one. Zero would mean removal at the moment of deletion, which
    /// is a hard delete wearing a policy's clothes — the window is the thing
    /// that makes deletion recoverable, so a window of nothing is refused
    /// rather than honoured.
    pub after_days: u32,
    /// Why this policy exists, recorded with every row it removes.
    ///
    /// Required because the reason is the only part of a removal that cannot be
    /// reconstructed afterwards. The row is gone; what is left is that someone
    /// decided it should be, and why.
    pub reason: String,
}

impl Rule {
    pub fn validate(&self, model: &str) -> Result<()> {
        day2_contracts::names::identifier(model)?;
        ensure!(
            self.after_days >= 1,
            "retention_window_must_outlast_the_deletion"
        );
        ensure!(
            (1..=200).contains(&self.reason.trim().len()),
            "retention_rule_requires_a_reason"
        );
        Ok(())
    }

    /// The instant on or before which a deletion is old enough to remove.
    fn cutoff(&self, now: i64) -> Result<i64> {
        i64::from(self.after_days)
            .checked_mul(DAY)
            .and_then(|window| now.checked_sub(window))
            .context("retention_window_overflow")
    }
}

/// What a sweep would remove, per model.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelPlan {
    pub model: String,
    pub after_days: u32,
    pub eligible: i64,
    /// The deletion instants at the ends of the eligible set, so an operator
    /// reading a plan can see what age of record they are about to destroy
    /// without querying the database themselves.
    pub oldest_deleted_at: Option<i64>,
    pub newest_deleted_at: Option<i64>,
}

/// What a sweep would do, and the thing a sweep is checked against.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub app: String,
    pub at: i64,
    pub models: Vec<ModelPlan>,
}

/// What a sweep did.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Swept {
    pub app: String,
    pub at: i64,
    pub removed: i64,
    pub models: Vec<ModelPlan>,
}

/// What a sweep would remove if it ran now.
pub fn plan(instance: &Path, app: &str, operator: &str, now: i64) -> Result<Plan> {
    let rules = declared(instance, app, operator)?;
    let runtime = crate::store::Runtime::load(instance, app)?;
    let connection = open(runtime.db())?;
    planned(&connection, app, &rules, now)
}

/// The plan itself, over a connection. Separate from the operator wrapper above
/// so the safety properties are tested against the code that enforces them
/// rather than through an instance file that could be wired up wrong.
fn planned(connection: &Connection, app: &str, rules: &[(String, Rule)], now: i64) -> Result<Plan> {
    let mut models = Vec::new();
    for (model, rule) in rules {
        models.push(eligible(connection, model, rule, now)?);
    }
    Ok(Plan {
        app: app.to_owned(),
        at: now,
        models,
    })
}

/// Remove what the operator reviewed, or nothing.
pub fn sweep(
    instance: &Path,
    app: &str,
    operator: &str,
    now: i64,
    reviewed: &Plan,
) -> Result<Swept> {
    let rules = declared(instance, app, operator)?;
    let runtime = crate::store::Runtime::load(instance, app)?;
    let mut connection = open(runtime.db())?;
    let transaction = crate::write_queue::immediate(&mut connection)?;
    runtime.check_binding(&transaction)?;
    crate::audit::upgrade(&transaction)?;

    let identities = runtime
        .artifact()
        .contract()
        .schema
        .models
        .iter()
        .map(|(name, record)| (name.clone(), record.identity.clone()))
        .collect();
    let swept = perform(
        &transaction,
        app,
        &rules,
        &identities,
        operator,
        now,
        reviewed,
    )?;
    transaction.commit()?;
    Ok(swept)
}

/// The sweep itself, over an open transaction.
fn perform(
    connection: &Connection,
    app: &str,
    rules: &[(String, Rule)],
    identities: &std::collections::BTreeMap<
        String,
        Option<day2_contracts::identity::ModelIdentity>,
    >,
    operator: &str,
    now: i64,
    reviewed: &Plan,
) -> Result<Swept> {
    // Recomputed inside the transaction that does the removing, and compared
    // against what the operator saw. Anything that changed in between — a row
    // deleted, a row restored, a clock moved — means the plan on the screen is
    // not the plan about to run, and the answer to that is to show it again.
    let current = planned(connection, app, rules, now)?;
    ensure!(&current == reviewed, "retention_plan_changed");
    let mut removed = 0;
    for (model, rule) in rules {
        let identity = identities.get(model.as_str()).and_then(Option::as_ref);
        removed += remove(connection, model, identity, rule, operator, now)?;
    }
    Ok(Swept {
        app: app.to_owned(),
        at: now,
        removed,
        models: current.models,
    })
}

/// The operator's declaration for this app, checked to be theirs to make.
fn declared(instance: &Path, app: &str, operator: &str) -> Result<Vec<(String, Rule)>> {
    ensure!(
        crate::resource_admin::is_administrator(instance, operator)?,
        "installation_admin_required"
    );
    let loaded = Instance::load(instance)?;
    let binding = loaded.apps.get(app).context("unknown_app")?;
    Ok(binding
        .retention
        .iter()
        .map(|(model, rule)| (model.clone(), rule.clone()))
        .collect())
}

/// Rows a rule covers: deleted, and deleted long enough ago.
///
/// Both the plan an operator reads and the sweep that runs are built from
/// `ELIGIBLE`, so they cannot disagree about which rows are in scope.
fn eligible(connection: &Connection, model: &str, rule: &Rule, now: i64) -> Result<ModelPlan> {
    let cutoff = rule.cutoff(now)?;
    let table = day2_contracts::names::identifier(model).map(|()| model)?;
    let (eligible, oldest, newest) = connection.query_row(
        &format!(
            "SELECT count(*), min(deleted_at), max(deleted_at) FROM \"{table}\" WHERE {ELIGIBLE}"
        ),
        [cutoff],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    Ok(ModelPlan {
        model: model.to_owned(),
        after_days: rule.after_days,
        eligible,
        oldest_deleted_at: oldest,
        newest_deleted_at: newest,
    })
}

/// Record every removal, then remove.
///
/// In that order and in one transaction: the record of what was destroyed is
/// the only thing that outlives it, so a removal that committed without its
/// entry would be indistinguishable from a row that never existed. The counts
/// are compared afterwards because the two statements select independently —
/// if they ever disagreed, the difference would be a row destroyed without a
/// record, and the whole transaction is refused rather than reconciled.
///
/// The identity is carried in so the recorded id is the one people use. A
/// UUID model stores raw bytes; writing those to the record would leave an
/// operator holding sixteen bytes of hex where the application, the audit log
/// and every screen say `lnk_...`.
fn remove(
    connection: &Connection,
    model: &str,
    identity: Option<&day2_contracts::identity::ModelIdentity>,
    rule: &Rule,
    operator: &str,
    now: i64,
) -> Result<i64> {
    let cutoff = rule.cutoff(now)?;
    let table = day2_contracts::names::identifier(model).map(|()| model)?;
    let doomed: Vec<(rusqlite::types::Value, i64, i64)> = connection
        .prepare(&format!(
            "SELECT id,created_at,deleted_at FROM \"{table}\" WHERE {ELIGIBLE} ORDER BY id"
        ))?
        .query_map([cutoff], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (id, created_at, deleted_at) in &doomed {
        connection.execute(
            "INSERT INTO day2_retention_removals(at,operator,model,record_id,created_at,deleted_at,after_days,reason)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                now,
                operator,
                model,
                readable(id, identity)?,
                created_at,
                deleted_at,
                rule.after_days,
                rule.reason.trim()
            ],
        )?;
    }
    let removed = connection.execute(
        &format!("DELETE FROM \"{table}\" WHERE {ELIGIBLE}"),
        [cutoff],
    )?;
    ensure!(doomed.len() == removed, "retention_record_count_differs");
    Ok(i64::try_from(removed)?)
}

/// A stored id in the form the rest of the platform shows it.
fn readable(
    id: &rusqlite::types::Value,
    identity: Option<&day2_contracts::identity::ModelIdentity>,
) -> Result<String> {
    Ok(match (id, identity) {
        (rusqlite::types::Value::Integer(value), _) => value.to_string(),
        (rusqlite::types::Value::Blob(bytes), Some(identity)) => {
            let bytes: [u8; 16] = bytes.as_slice().try_into().context("row_id_width")?;
            crate::identity::Id::from_uuid(&identity.prefix, bytes)?.to_string()
        }
        _ => anyhow::bail!("unsupported_row_id"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::collections::BTreeMap;

    /// One model, four rows: live, deleted today, deleted long ago, and a
    /// second deleted long ago so a count can be wrong in both directions.
    fn fixture() -> Result<Connection> {
        let mut connection = Connection::open_in_memory()?;
        connection.execute_batch(crate::store::PLATFORM_DDL)?;
        let transaction = connection.transaction()?;
        crate::audit::upgrade(&transaction)?;
        transaction.commit()?;
        connection.execute_batch(
            "INSERT OR REPLACE INTO day2_meta VALUES('scope','installation/test/support');",
        )?;
        connection.execute_batch(
            "CREATE TABLE tickets(id INTEGER PRIMARY KEY, version INTEGER NOT NULL,
                created_at INTEGER NOT NULL, title TEXT NOT NULL,
                deleted_at INTEGER NOT NULL DEFAULT 0 CHECK(deleted_at >= 0)) STRICT;
             INSERT INTO tickets VALUES(1,1,100,'live',0);
             INSERT INTO tickets VALUES(2,2,100,'deleted today',1_000_000);
             INSERT INTO tickets VALUES(3,2,100,'deleted long ago',100_000);
             INSERT INTO tickets VALUES(4,2,100,'deleted longer ago',50_000);",
        )?;
        Ok(connection)
    }

    fn rules(after_days: u32) -> Vec<(String, Rule)> {
        vec![(
            "tickets".to_string(),
            Rule {
                after_days,
                reason: "closed tickets are kept for the support window".into(),
            },
        )]
    }

    fn live(connection: &Connection) -> Result<Vec<i64>> {
        Ok(connection
            .prepare("SELECT id FROM tickets ORDER BY id")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// A live row is not eligible under any policy.
    ///
    /// The one invariant everything else rests on. A retention sweep is the only
    /// thing in the platform that destroys anything, so the question "could this
    /// take a row nobody deleted?" has to have a testable answer, and the test
    /// has to be run against a policy that would take everything if it could —
    /// a one-day window against rows deleted long ago, with the live row sitting
    /// in the same table.
    #[test]
    fn a_row_nobody_deleted_is_never_eligible_however_the_policy_is_written() -> Result<()> {
        let connection = fixture()?;
        let now = 1_000_000;
        for after_days in [1, 7, 365, u32::from(u16::MAX)] {
            let plan = planned(&connection, "support", &rules(after_days), now)?;
            assert_eq!(plan.models.len(), 1);
            let swept = perform(
                &connection,
                "support",
                &rules(after_days),
                &BTreeMap::new(),
                "operator",
                now,
                &plan,
            )?;
            assert_eq!(swept.removed, plan.models[0].eligible);
            assert!(
                live(&connection)?.contains(&1),
                "the live row was removed under a {after_days}-day policy"
            );
        }
        Ok(())
    }

    /// The window is the whole of the protection, so it is measured, not assumed.
    #[test]
    fn a_deletion_inside_the_window_waits_and_one_outside_it_goes() -> Result<()> {
        let connection = fixture()?;
        // Rows 3 and 4 were deleted more than ten days before now; row 2 today.
        let now = 1_000_000;
        let plan = planned(&connection, "support", &rules(10), now)?;
        assert_eq!(plan.models[0].eligible, 2);
        assert_eq!(plan.models[0].oldest_deleted_at, Some(50_000));
        assert_eq!(plan.models[0].newest_deleted_at, Some(100_000));

        let swept = perform(
            &connection,
            "support",
            &rules(10),
            &BTreeMap::new(),
            "operator",
            now,
            &plan,
        )?;
        assert_eq!(swept.removed, 2);
        assert_eq!(
            live(&connection)?,
            vec![1, 2],
            "the live row and the recent deletion did not both survive"
        );

        // And a second sweep takes nothing, because nothing else is old enough.
        let again = planned(&connection, "support", &rules(10), now)?;
        assert_eq!(again.models[0].eligible, 0);
        assert_eq!(
            perform(
                &connection,
                "support",
                &rules(10),
                &BTreeMap::new(),
                "operator",
                now,
                &again
            )?
            .removed,
            0
        );
        Ok(())
    }

    /// A sweep removes what the operator reviewed, or nothing.
    ///
    /// The window between reading a plan and running it is where an operator's
    /// judgement can be invalidated without them seeing it. Refusing is the only
    /// answer that keeps "I read what this would remove" true.
    #[test]
    fn a_sweep_refuses_a_plan_that_no_longer_describes_what_would_happen() -> Result<()> {
        let connection = fixture()?;
        let now = 1_000_000;
        let reviewed = planned(&connection, "support", &rules(10), now)?;

        // Another row is deleted after the operator read the plan.
        connection.execute("UPDATE tickets SET deleted_at=60_000 WHERE id=1", [])?;
        let error = perform(
            &connection,
            "support",
            &rules(10),
            &BTreeMap::new(),
            "operator",
            now,
            &reviewed,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "retention_plan_changed");
        assert_eq!(
            live(&connection)?,
            vec![1, 2, 3, 4],
            "a refused sweep still removed something"
        );

        // A plan read against a different clock is a different plan, too.
        let error = perform(
            &connection,
            "support",
            &rules(10),
            &BTreeMap::new(),
            "operator",
            now + DAY,
            &reviewed,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "retention_plan_changed");
        Ok(())
    }

    /// What outlives the row is the record that it existed and was removed.
    #[test]
    fn every_removal_leaves_an_entry_that_cannot_be_edited_or_dropped() -> Result<()> {
        let connection = fixture()?;
        let now = 1_000_000;
        let plan = planned(&connection, "support", &rules(10), now)?;
        perform(
            &connection,
            "support",
            &rules(10),
            &BTreeMap::new(),
            "operator",
            now,
            &plan,
        )?;

        let mut statement = connection.prepare(
            "SELECT model,record_id,created_at,deleted_at,after_days,operator,reason
             FROM day2_retention_removals ORDER BY record_id",
        )?;
        let entries: Vec<(String, String, i64, i64, i64, String, String)> = statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "tickets");
        assert_eq!(entries[0].1, "3");
        assert_eq!(
            entries[0].3, 100_000,
            "the deletion instant is not recorded"
        );
        assert_eq!(entries[0].4, 10);
        assert_eq!(entries[0].5, "operator");
        assert!(entries[0].6.starts_with("closed tickets"));

        // And it reaches the one feed an operator reads, beside invocations and
        // web requests. A removal that could only be found by knowing which
        // table to query is a removal most people would never find.
        let stream: Vec<(String, String, String, String)> = connection
            .prepare(
                "SELECT kind,identity,outcome,reason FROM day2_audit_events
                 WHERE kind='retention' ORDER BY sequence",
            )?
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        assert_eq!(stream.len(), 2, "removals missing from the audit stream");
        assert_eq!(stream[0].2, "removed");
        assert!(
            stream.iter().any(|entry| entry.3 == "tickets:3"),
            "the stream does not say which record: {stream:?}"
        );

        // The record is not a record if it can be changed afterwards.
        for statement in [
            "UPDATE day2_retention_removals SET operator='someone else'",
            "DELETE FROM day2_retention_removals",
        ] {
            let refusal = connection.execute_batch(statement).unwrap_err().to_string();
            assert!(
                refusal.contains("append_only_audit"),
                "{statement} was permitted: {refusal}"
            );
        }
        Ok(())
    }

    /// A window of nothing is a hard delete wearing a policy's clothes.
    #[test]
    fn a_rule_is_refused_unless_it_leaves_a_window_and_says_why() {
        let good = Rule {
            after_days: 1,
            reason: "legal hold expiry".into(),
        };
        assert!(good.validate("tickets").is_ok());
        assert!(
            Rule {
                after_days: 0,
                ..good.clone()
            }
            .validate("tickets")
            .is_err()
        );
        assert!(
            Rule {
                reason: "   ".into(),
                ..good.clone()
            }
            .validate("tickets")
            .is_err()
        );
        assert!(good.validate("day2_invocations").is_err());
        assert!(good.validate("tickets; DROP TABLE tickets").is_err());
    }
}
