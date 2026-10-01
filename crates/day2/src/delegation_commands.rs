//! Durable acceptance and receipt lookup. The inbox and the ordinary invocation
//! are inserted under one SQLite writer lock; no business executor lives here.
use crate::{
    delegation::{Call, Purpose},
    delegation_wire::{Query, VerifiedQuery},
    store::{self, Runtime},
};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub const RETRY_HORIZON_SECONDS: i64 = 3_600;
const RECEIPT_RETENTION_SECONDS: i64 = 86_400;
const MAX_RECEIPTS: i64 = 10_000;
pub const ROOT_CALL_ALLOWANCE: u32 = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub first_at: i64,
    pub incarnation: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InheritedOrigin {
    pub root: String,
    pub principal: String,
    pub subject_digest: String,
    pub actor: String,
}

pub(crate) struct Admission {
    pub origin: InheritedOrigin,
    budget: u32,
    inbox: Option<Inbox>,
}

struct Inbox {
    id: String,
    fingerprint: String,
    source: String,
    actor: String,
    operation: String,
    contract: String,
    accepted_at: i64,
    first_at: i64,
}

#[cfg(test)]
impl Admission {
    pub(crate) fn query_for_test(
        root: &str,
        actor: &str,
        subject_digest: &str,
        budget: u32,
    ) -> Self {
        Self {
            origin: InheritedOrigin {
                root: root.into(),
                principal: actor.into(),
                subject_digest: subject_digest.into(),
                actor: actor.into(),
            },
            budget,
            inbox: None,
        }
    }
}

pub(crate) fn upgrade(connection: &Connection) -> Result<()> {
    connection.execute_batch("CREATE TABLE IF NOT EXISTS day2_app_outgoing(
        identity TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, delivery TEXT NOT NULL,
        invocation TEXT NOT NULL REFERENCES day2_invocations(id)) STRICT;
        CREATE TABLE IF NOT EXISTS day2_app_inbox(
        id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, source TEXT NOT NULL,
        actor TEXT NOT NULL, operation TEXT NOT NULL, contract TEXT NOT NULL,
        invocation TEXT NOT NULL UNIQUE REFERENCES day2_invocations(id), accepted_at INTEGER NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS day2_inherited_origins(
        invocation TEXT PRIMARY KEY REFERENCES day2_invocations(id), evidence TEXT NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS day2_app_root_allowances(
        invocation TEXT PRIMARY KEY REFERENCES day2_invocations(id), allowance INTEGER NOT NULL, spent INTEGER NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS day2_app_call_allowances(
        identity TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, allowance INTEGER NOT NULL,
        invocation TEXT NOT NULL REFERENCES day2_invocations(id), allocated_at INTEGER NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS day2_app_restore_fence(
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), not_before INTEGER NOT NULL) STRICT;
        CREATE INDEX IF NOT EXISTS day2_app_call_expiry ON day2_app_call_allowances(allocated_at);
        CREATE INDEX IF NOT EXISTS day2_app_receipt_expiry ON day2_app_inbox(accepted_at);")?;
    Ok(())
}

pub(crate) fn invalidate_restored(connection: &Connection) -> Result<()> {
    restore_fence_in(connection, now_seconds()?)
}

fn now_seconds() -> Result<i64> {
    Ok(i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    )?)
}

fn compact_in(connection: &Connection, at: i64) -> Result<()> {
    let expired = at.saturating_sub(RETRY_HORIZON_SECONDS + 60);
    // Live uncertain source work never expires. Supported restore and policy
    // revocation permanently block it before these records can be removed.
    connection.execute("DELETE FROM day2_app_call_allowances WHERE allocated_at<?1 AND invocation IN (SELECT id FROM day2_invocations WHERE status!='pending' UNION SELECT invocation FROM day2_authority_blocks)", [expired])?;
    connection.execute("DELETE FROM day2_app_outgoing WHERE json_extract(delivery,'$.first_at')<?1 AND invocation IN (SELECT id FROM day2_invocations WHERE status!='pending' UNION SELECT invocation FROM day2_authority_blocks)", [expired])?;
    connection.execute("DELETE FROM day2_app_inbox WHERE accepted_at<?1 AND invocation IN (SELECT id FROM day2_invocations WHERE status!='pending' UNION SELECT invocation FROM day2_authority_blocks)", [at.saturating_sub(RECEIPT_RETENTION_SECONDS)])?;
    Ok(())
}

fn restore_fence_in(connection: &Connection, at: i64) -> Result<()> {
    upgrade(connection)?;
    connection.execute("INSERT INTO day2_app_restore_fence VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET not_before=max(not_before,excluded.not_before)", [at])?;
    Ok(())
}

fn outgoing_identity(call: &Call) -> Result<String> {
    Ok(crate::digest(&serde_json::to_vec(&(
        &call.source_epoch,
        &call.origin,
        &call.step,
        &call.app,
    ))?))
}

/// Reserve disjoint subtrees under the writer lock. A child cannot copy its
/// parent's allowance across diamond branches; retries reuse their reservation.
pub fn prepare_budget(runtime: &Runtime, call: &Call) -> Result<u32> {
    let identity = crate::digest(&serde_json::to_vec(&(
        &call.source_epoch,
        &call.origin,
        &call.step,
        call.purpose,
        &call.app,
    ))?);
    let fingerprint = crate::digest(&serde_json::to_vec(call)?);
    let mut connection = store::open(runtime.db())?;
    let tx = crate::write_queue::immediate(&mut connection)?;
    runtime.check_binding(&tx)?;
    let operation: String = tx.query_row(
        "SELECT operation FROM day2_invocations WHERE id=?1 AND actor=?2 AND status='pending'",
        params![call.origin, call.actor],
        |row| row.get(0),
    )?;
    crate::authority_state::require_invocation_in(
        &tx,
        runtime,
        &call.origin,
        &operation,
        &call.actor,
    )?;
    let root = crate::resources::root_in(&tx, &call.origin)?;
    let child = allocate_in(&tx, &root, &identity, &fingerprint)?;
    tx.commit()?;
    Ok(child)
}

fn allocate_in(
    connection: &Connection,
    root: &str,
    identity: &str,
    fingerprint: &str,
) -> Result<u32> {
    if let Some((recorded, allowance)) = connection
        .query_row(
            "SELECT fingerprint,allowance FROM day2_app_call_allowances WHERE identity=?1",
            [identity],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?)),
        )
        .optional()?
    {
        ensure!(recorded == fingerprint, "app_call_allowance_conflict");
        return Ok(allowance);
    }
    let at = now_seconds()?;
    compact_in(connection, at)?;
    let count: i64 =
        connection.query_row("SELECT count(*) FROM day2_app_call_allowances", [], |row| {
            row.get(0)
        })?;
    ensure!(count < MAX_RECEIPTS, "app_call_ledger_capacity");
    connection.execute(
        "INSERT OR IGNORE INTO day2_app_root_allowances VALUES(?1,?2,0)",
        params![root, ROOT_CALL_ALLOWANCE],
    )?;
    let (allowance, spent): (u32, u32) = connection.query_row(
        "SELECT allowance,spent FROM day2_app_root_allowances WHERE invocation=?1",
        [root],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    ensure!(
        allowance <= ROOT_CALL_ALLOWANCE,
        "app_call_allowance_changed"
    );
    let child = allowance.saturating_sub(4) / 4;
    let charge = child + 1;
    ensure!(
        spent
            .checked_add(charge)
            .is_some_and(|next| next <= allowance),
        "app_root_call_budget_exhausted"
    );
    connection.execute(
        "UPDATE day2_app_root_allowances SET spent=spent+?1 WHERE invocation=?2",
        params![charge, root],
    )?;
    connection.execute(
        "INSERT INTO day2_app_call_allowances VALUES(?1,?2,?3,?4,?5)",
        params![identity, fingerprint, child, root, at],
    )?;
    Ok(child)
}

pub fn require_budget(runtime: &Runtime, call: &Call, allowance: u32) -> Result<()> {
    ensure!(
        prepare_budget(runtime, call)? == allowance,
        "app_call_allowance_changed"
    );
    Ok(())
}

/// Persist the original target before any network send. A later attempt can
/// authenticate a new serving host but cannot create a fresh acceptance there
/// if the original inbox was lost.
pub fn prepare_delivery(
    runtime: &Runtime,
    call: &Call,
    incarnation: &str,
    at: i64,
) -> Result<Delivery> {
    ensure!(
        call.purpose == Purpose::Send && !call.source_epoch.is_empty() && !call.step.is_empty(),
        "invalid_app_send_identity"
    );
    let identity = outgoing_identity(call)?;
    let fingerprint = crate::digest(&serde_json::to_vec(call)?);
    let mut connection = store::open(runtime.db())?;
    let tx = crate::write_queue::immediate(&mut connection)?;
    runtime.check_binding(&tx)?;
    ensure!(
        crate::authority_state::current(&tx)?.stamp.epoch == call.source_epoch,
        "app_send_epoch_changed"
    );
    let existing: Option<(String, String)> = tx
        .query_row(
            "SELECT fingerprint,delivery FROM day2_app_outgoing WHERE identity=?1",
            [&identity],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let delivery = if let Some((recorded, delivery)) = existing {
        ensure!(recorded == fingerprint, "app_send_identity_conflict");
        crate::json::decode::<Delivery>(delivery.as_bytes())?
    } else {
        compact_in(&tx, at)?;
        let count: i64 = tx.query_row("SELECT count(*) FROM day2_app_outgoing", [], |row| {
            row.get(0)
        })?;
        ensure!(count < MAX_RECEIPTS, "app_outgoing_capacity");
        let delivery = Delivery {
            first_at: at,
            incarnation: incarnation.to_owned(),
        };
        tx.execute(
            "INSERT INTO day2_app_outgoing VALUES(?1,?2,?3,?4)",
            params![
                identity,
                fingerprint,
                serde_json::to_string(&delivery)?,
                call.origin
            ],
        )?;
        delivery
    };
    tx.commit()?;
    Ok(delivery)
}

/// The platform issuer checks the rollback-sensitive source ledger as well as
/// the invocation and grant. A signed workload cannot substitute a target fence.
pub fn require_delivery(runtime: &Runtime, call: &Call, delivery: &Delivery) -> Result<()> {
    let connection = store::open(runtime.db())?;
    let recorded: (String, String) = connection.query_row(
        "SELECT fingerprint,delivery FROM day2_app_outgoing WHERE identity=?1",
        [outgoing_identity(call)?],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    ensure!(
        recorded.0 == crate::digest(&serde_json::to_vec(call)?)
            && crate::json::decode::<Delivery>(recorded.1.as_bytes())? == *delivery,
        "app_send_identity_conflict"
    );
    Ok(())
}

fn receipt_id(query: &Query) -> Result<String> {
    Ok(format!(
        "rcp_{}",
        &crate::digest(&serde_json::to_vec(&(
            &query.source,
            &query.source_epoch,
            &query.origin,
            &query.step,
            &query.target
        ))?)[7..]
    ))
}

pub(crate) fn admission(verified: &VerifiedQuery, at: i64) -> Result<Admission> {
    let query = verified.query();
    let claims = verified.origin()?;
    let origin = InheritedOrigin {
        root: claims.root.clone(),
        principal: claims.principal.clone(),
        subject_digest: claims.subject_digest.clone(),
        actor: claims.actor.clone(),
    };
    let inbox = if query.purpose == Purpose::Send {
        let delivery = query
            .delivery
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("app_send_delivery_missing"))?;
        ensure!(
            delivery.first_at <= at
                && at
                    < delivery
                        .first_at
                        .checked_add(RETRY_HORIZON_SECONDS)
                        .ok_or_else(|| anyhow::anyhow!("app_send_horizon"))?
                && !query.source_epoch.is_empty(),
            "app_send_horizon"
        );
        let contract = query
            .contract_digest
            .clone()
            .ok_or_else(|| anyhow::anyhow!("delegated_contract_missing"))?;
        let fingerprint = crate::digest(&serde_json::to_vec(&(
            &query.source,
            &query.target,
            &query.operation,
            &query.schema_digest,
            &contract,
            &query.input,
            &query.actor,
            &query.chain,
            query.now,
            delivery,
            &origin,
        ))?);
        Some(Inbox {
            id: receipt_id(query)?,
            fingerprint,
            source: query.source.runtime_scope(),
            actor: query.actor.clone(),
            operation: query.operation.clone(),
            contract,
            accepted_at: at,
            first_at: delivery.first_at,
        })
    } else {
        None
    };
    ensure!(
        query.budget <= ROOT_CALL_ALLOWANCE,
        "app_call_allowance_changed"
    );
    Ok(Admission {
        origin,
        budget: query.budget,
        inbox,
    })
}

/// Called only inside ordinary receiver admission, after current authorization.
/// Historical receipts survive artifact changes and never transfer old work to
/// a new invocation. Conflicting reuse fails under the same writer lock.
pub(crate) fn reused_in(connection: &Connection, admission: &Admission) -> Result<bool> {
    let Some(inbox) = &admission.inbox else {
        return Ok(false);
    };
    compact_in(connection, inbox.accepted_at)?;
    let existing: Option<String> = connection
        .query_row(
            "SELECT fingerprint FROM day2_app_inbox WHERE id=?1",
            [&inbox.id],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing) = existing {
        ensure!(existing == inbox.fingerprint, "app_send_identity_conflict");
        return Ok(true);
    }
    let restored: Option<i64> = connection
        .query_row(
            "SELECT not_before FROM day2_app_restore_fence WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    ensure!(
        restored.is_none_or(|cutoff| inbox.first_at > cutoff),
        "app_send_before_restore_fence"
    );
    let count: i64 =
        connection.query_row("SELECT count(*) FROM day2_app_inbox", [], |row| row.get(0))?;
    ensure!(count < MAX_RECEIPTS, "app_inbox_capacity");
    Ok(false)
}

pub(crate) fn record_in(
    connection: &Connection,
    invocation: &str,
    admission: &Admission,
) -> Result<()> {
    let evidence = serde_json::to_string(&admission.origin)?;
    connection.execute(
        "INSERT OR IGNORE INTO day2_inherited_origins VALUES(?1,?2)",
        params![invocation, evidence],
    )?;
    let recorded: String = connection.query_row(
        "SELECT evidence FROM day2_inherited_origins WHERE invocation=?1",
        [invocation],
        |row| row.get(0),
    )?;
    ensure!(recorded == evidence, "delegated_origin_changed");
    connection.execute(
        "INSERT OR IGNORE INTO day2_app_root_allowances VALUES(?1,?2,0)",
        params![invocation, admission.budget],
    )?;
    let allowance: u32 = connection.query_row(
        "SELECT allowance FROM day2_app_root_allowances WHERE invocation=?1",
        [invocation],
        |row| row.get(0),
    )?;
    ensure!(allowance == admission.budget, "app_call_allowance_changed");
    if let Some(inbox) = &admission.inbox {
        connection.execute(
            "INSERT INTO day2_app_inbox VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                inbox.id,
                inbox.fingerprint,
                inbox.source,
                inbox.actor,
                inbox.operation,
                inbox.contract,
                invocation,
                inbox.accepted_at
            ],
        )?;
    }
    Ok(())
}

pub fn accept(
    callee: &Runtime,
    verified: &VerifiedQuery,
    current_incarnation: &str,
    at: i64,
) -> Result<String> {
    let query = verified.query();
    ensure!(
        query.purpose == Purpose::Send && query.target.runtime_scope() == callee.scope(),
        "app_send_target_changed"
    );
    crate::delegation::require_contract(
        callee,
        &query.operation,
        &query.schema_digest,
        query.contract_digest.as_deref(),
        "command",
    )?;
    let admission = admission(verified, at)?;
    let receipt = admission
        .inbox
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("app_send_receipt_missing"))?;
    let chain = crate::delegation::extend(&query.chain, &query.source.app, &query.target.app)?;
    // This is only an early hint. The writer-transaction admission repeats the
    // lookup and checks the original fence before inserting a missing inbox.
    let invocation = format!("dlg_{}", &receipt.id[4..]);
    let authenticated = format!("app:{}", query.source.app);
    callee.accept_remote(
        &query.operation,
        &invocation,
        &query.input,
        query.now,
        store::Cause::delegated(&query.actor, &chain, &authenticated).remote(&admission),
        query
            .delivery
            .as_ref()
            .is_some_and(|delivery| delivery.incarnation == current_incarnation),
    )?;
    Ok(json!({"id":receipt.id,"status":"accepted"}).to_string())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusInput {
    id: String,
}

pub fn status(callee: &Runtime, verified: &VerifiedQuery) -> Result<String> {
    let query = verified.query();
    ensure!(
        query.purpose == Purpose::Status && query.target.runtime_scope() == callee.scope(),
        "app_status_target_changed"
    );
    let input: StatusInput = crate::json::decode(&serde_json::to_vec(&query.input)?)?;
    ensure!(
        input.id.len() == 68
            && input.id.starts_with("rcp_")
            && input.id[4..].bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid_app_receipt"
    );
    let mut connection = store::open(callee.db())?;
    let tx = connection.transaction()?;
    callee.check_binding(&tx)?;
    crate::authority_state::authorize_in(&tx, callee, &query.operation, &query.actor)?;
    let row: Option<(String, String)> = tx.query_row("SELECT i.invocation,v.status FROM day2_app_inbox i JOIN day2_invocations v ON v.id=i.invocation WHERE i.id=?1 AND i.source=?2 AND i.actor=?3 AND i.operation=?4 AND i.contract=?5", params![input.id, query.source.runtime_scope(), query.actor, query.operation, query.contract_digest.as_deref().unwrap_or("")], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
    let state = if let Some((id, status)) = row {
        if crate::authority_state::is_blocked(&tx, &id)? {
            "blocked"
        } else {
            match status.as_str() {
                "success" => "success",
                "failure" => "refused",
                _ => "pending",
            }
        }
    } else {
        "unknown"
    };
    tx.commit()?;
    Ok(json!({"id":input.id,"status":state}).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::sync::{Arc, Barrier};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]
        #[test]
        fn diamond_subtrees_conserve_root_credit_and_retries_do_not_spend(schedule in prop::collection::vec((any::<u8>(), 0_u8..8), 1..128)) {
            let directory = tempfile::tempdir().unwrap();
            let mut connection = database(&directory.path().join("budgets.sqlite")).unwrap();
            connection.execute("INSERT INTO day2_invocations(id) VALUES('root')", []).unwrap();
            connection.execute("INSERT INTO day2_app_root_allowances VALUES('root',256,0)", []).unwrap();
            let mut nodes = vec!["root".to_owned()];
            let mut calls = std::collections::BTreeSet::new();
            for (selector, slot) in schedule {
                let parent = nodes[usize::from(selector) % nodes.len()].clone();
                let identity = format!("{parent}-{slot}");
                let before: i64 = connection.query_row("SELECT sum(allowance-spent) FROM day2_app_root_allowances", [], |row| row.get(0)).unwrap();
                {
                    let tx = crate::write_queue::immediate(&mut connection).unwrap();
                    if let Ok(child) = allocate_in(&tx, &parent, &identity, "same-intent") {
                        if calls.insert(identity.clone()) {
                            tx.execute("INSERT INTO day2_invocations(id) VALUES(?1)", [&identity]).unwrap();
                            tx.execute("INSERT INTO day2_app_root_allowances VALUES(?1,?2,0)", params![identity, child]).unwrap();
                            nodes.push(identity.clone());
                        }
                        tx.commit().unwrap();
                    }
                }
                let remaining: i64 = connection.query_row("SELECT sum(allowance-spent) FROM day2_app_root_allowances", [], |row| row.get(0)).unwrap();
                prop_assert!(remaining <= before);
                prop_assert_eq!(remaining + i64::try_from(calls.len()).unwrap(), 256);
                prop_assert!(calls.len() <= 256);
                if calls.contains(&identity) {
                    prop_assert!(allocate_in(&connection, &parent, &identity, "substituted-intent").is_err());
                }
            }
        }
    }

    fn database(path: &std::path::Path) -> Result<Connection> {
        let connection = store::open(path)?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS day2_invocations(id TEXT PRIMARY KEY,status TEXT NOT NULL DEFAULT 'pending') STRICT;
            CREATE TABLE IF NOT EXISTS day2_authority_blocks(invocation TEXT PRIMARY KEY,reason TEXT NOT NULL) STRICT;",
        )?;
        upgrade(&connection)?;
        Ok(connection)
    }

    fn request(fingerprint: &str) -> Admission {
        Admission {
            budget: 63,
            origin: InheritedOrigin {
                root: "human-root".into(),
                principal: "alice@example.com".into(),
                subject_digest: crate::digest(b"subject"),
                actor: "alice@example.com".into(),
            },
            inbox: Some(Inbox {
                id: "receipt".into(),
                fingerprint: fingerprint.into(),
                source: "alpha/test/desk".into(),
                actor: "alice@example.com".into(),
                operation: "stock.reserve".into(),
                contract: crate::digest(b"contract"),
                accepted_at: 100,
                first_at: 100,
            }),
        }
    }

    #[test]
    fn acceptance_and_origin_are_atomic_and_conflicting_reuse_is_refused() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut connection = database(&directory.path().join("receiver.sqlite"))?;
        {
            let tx = crate::write_queue::immediate(&mut connection)?;
            tx.execute("INSERT INTO day2_invocations(id) VALUES('accepted')", [])?;
            record_in(&tx, "accepted", &request("original"))?;
            // Crash before commit must leave neither the inbox nor invocation.
        }
        assert_eq!(
            connection.query_row("SELECT count(*) FROM day2_invocations", [], |row| row
                .get::<_, i64>(0))?,
            0
        );
        assert!(!reused_in(&connection, &request("original"))?);
        let tx = crate::write_queue::immediate(&mut connection)?;
        tx.execute("INSERT INTO day2_invocations(id) VALUES('accepted')", [])?;
        record_in(&tx, "accepted", &request("original"))?;
        tx.commit()?;
        drop(connection);
        let reopened = database(&directory.path().join("receiver.sqlite"))?;
        assert!(reused_in(&reopened, &request("original"))?);
        assert!(reused_in(&reopened, &request("substituted-payload")).is_err());
        assert_eq!(
            reopened.query_row("SELECT count(*) FROM day2_inherited_origins", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        Ok(())
    }

    #[test]
    fn concurrent_connections_accept_one_invocation() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("receiver.sqlite");
        database(&path)?;
        let barrier = Arc::new(Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|index| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || -> Result<bool> {
                    let mut connection = store::open(&path)?;
                    barrier.wait();
                    let tx = crate::write_queue::immediate(&mut connection)?;
                    if reused_in(&tx, &request("original"))? {
                        return Ok(false);
                    }
                    let invocation = format!("invocation-{index}");
                    tx.execute("INSERT INTO day2_invocations(id) VALUES(?1)", [&invocation])?;
                    record_in(&tx, &invocation, &request("original"))?;
                    tx.commit()?;
                    Ok(true)
                })
            })
            .collect();
        let mut accepted = 0;
        for worker in workers {
            accepted += usize::from(worker.join().expect("inbox worker")?);
        }
        assert_eq!(accepted, 1);
        let connection = database(&path)?;
        assert_eq!(
            connection.query_row("SELECT count(*) FROM day2_invocations", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        Ok(())
    }

    #[test]
    fn restore_keeps_known_receipts_but_never_recreates_a_missing_old_acceptance() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut connection = database(&directory.path().join("receiver.sqlite"))?;
        let original = request("original");
        let tx = crate::write_queue::immediate(&mut connection)?;
        tx.execute("INSERT INTO day2_invocations(id) VALUES('accepted')", [])?;
        record_in(&tx, "accepted", &original)?;
        tx.commit()?;
        let tx = crate::write_queue::immediate(&mut connection)?;
        restore_fence_in(&tx, 100)?;
        tx.commit()?;
        assert!(reused_in(&connection, &original)?);
        let mut lost = request("missing-old");
        lost.inbox.as_mut().unwrap().id = "missing".into();
        assert!(reused_in(&connection, &lost).is_err());
        lost.inbox.as_mut().unwrap().first_at = 101;
        assert!(!reused_in(&connection, &lost)?);
        drop(connection);
        let reopened = database(&directory.path().join("receiver.sqlite"))?;
        lost.inbox.as_mut().unwrap().first_at = 100;
        assert!(reused_in(&reopened, &lost).is_err());
        Ok(())
    }

    #[test]
    fn expiry_reclaims_terminal_records_and_preserves_live_uncertainty() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut connection = database(&directory.path().join("expiry.sqlite"))?;
        let tx = crate::write_queue::immediate(&mut connection)?;
        for (id, status) in [
            ("done", "success"),
            ("live", "pending"),
            ("blocked", "pending"),
        ] {
            tx.execute(
                "INSERT INTO day2_invocations VALUES(?1,?2)",
                params![id, status],
            )?;
            tx.execute(
                "INSERT INTO day2_app_outgoing VALUES(?1,'intent',?2,?1)",
                params![
                    id,
                    serde_json::to_string(&Delivery {
                        first_at: 1,
                        incarnation: "original".into()
                    })?
                ],
            )?;
            tx.execute(
                "INSERT INTO day2_app_call_allowances VALUES(?1,'intent',63,?1,1)",
                [id],
            )?;
            let mut admission = request(id);
            admission.inbox.as_mut().unwrap().id = id.into();
            record_in(&tx, id, &admission)?;
        }
        tx.execute(
            "INSERT INTO day2_authority_blocks VALUES('blocked','revoked')",
            [],
        )?;
        compact_in(&tx, RECEIPT_RETENTION_SECONDS + 101)?;
        for table in [
            "day2_app_outgoing",
            "day2_app_call_allowances",
            "day2_app_inbox",
        ] {
            assert_eq!(
                tx.query_row(&format!("SELECT invocation FROM {table}"), [], |row| row
                    .get::<_, String>(
                    0
                ))?,
                "live"
            );
        }
        assert_eq!(
            tx.query_row("SELECT count(*) FROM day2_invocations", [], |row| row
                .get::<_, i64>(0))?,
            3,
            "business history is never erased by transport compaction"
        );
        tx.commit()?;
        Ok(())
    }
}
