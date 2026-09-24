//! Durable capability accounting. Admission reserves every applicable account in
//! the caller's authority transaction. Unknown outcomes retain their reservation.
//! Monetary units are integers; only an adapter with a qualified bound may claim
//! that its quote bounds an external invoice.
//!
//! Installation limits use centrally committed, fixed allocations. Allocating
//! first and importing second can strand capacity after a crash, but cannot spend
//! it twice. This deliberately does not claim cross-database ACID admission.

use crate::error::Failure;
use anyhow::{Context, Result, ensure};
use day2_capabilities::resources::{BudgetDefinition, BudgetLimits, BudgetScope};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consumption {
    pub calls: u64,
    /// Full request plus response bytes, before output truncation.
    pub bytes: u64,
    pub cost_microunits: u64,
    /// Outstanding physical attempts. A terminal settlement releases this gauge.
    pub concurrency: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetContext {
    pub app: String,
    pub actor: String,
    pub connection: String,
    /// The accepted root, shared by all child commands; never caller supplied.
    pub invocation_root: String,
    /// Trusted dispatch time, not a client timestamp.
    pub now: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationRequest {
    /// Immutable physical attempt ID. A new network attempt needs a new ID.
    pub id: String,
    /// Digest binding authority, grant, instruction, input and logical request.
    pub binding: String,
    pub context: BudgetContext,
    pub budgets: BTreeMap<String, BudgetDefinition>,
    pub quote: Consumption,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub id: String,
    pub ledger_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum Settlement {
    Known { actual: Consumption },
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettlementReceipt {
    pub reservation: Reservation,
    pub settled: bool,
    pub overrun: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetUsage {
    pub budget_id: String,
    pub window_start: i64,
    pub scope: String,
    pub subject: String,
    pub unit: String,
    pub limit: u64,
    pub used: u64,
    pub reserved: u64,
    pub frozen: bool,
    pub revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Charge {
    account: String,
    unit: String,
    reserved: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerStatus {
    pub ledger_id: String,
    pub frozen_after_restore: bool,
    pub frozen_after_overrun: bool,
    pub accounts: Vec<BudgetUsage>,
    pub outstanding_attempts: u64,
    pub known_usage: Consumption,
    pub overruns: Vec<OverrunEvidence>,
    #[serde(default)]
    pub unknown_usage: Vec<UnknownUsage>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownUsage {
    pub reservation: Reservation,
    pub quote: Consumption,
    /// Bounded provider correlation metadata, never request/response payloads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exchanges: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverrunEvidence {
    pub reservation: String,
    pub quote: Consumption,
    pub actual: Consumption,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverrunResolution {
    pub id: String,
    pub ledger_id: String,
    pub reservations: BTreeSet<String>,
    pub reason: String,
    /// Operator-supplied reference to reviewed adapter repair/reconciliation
    /// evidence. The ledger records this assertion; it cannot verify an invoice.
    pub proof: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverrunResolutionReceipt {
    pub id: String,
    pub ledger_id: String,
    pub operator: String,
    pub reservations: BTreeSet<String>,
    pub reason: String,
    pub proof: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageReconciliation {
    pub id: String,
    pub ledger_id: String,
    pub reservation: String,
    pub actual: Consumption,
    pub reason: String,
    /// Explicit operator assertion referencing terminal provider usage evidence.
    /// The platform records this assertion; it cannot verify an external invoice.
    pub proof: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageReconciliationReceipt {
    pub request: UsageReconciliation,
    pub operator: String,
    pub settlement: SettlementReceipt,
}

const UNITS: [&str; 4] = ["calls", "bytes", "cost_microunits", "concurrency"];

#[path = "budget_reduction.rs"]
mod reduction;
pub use reduction::*;

fn amount(value: &Consumption, unit: &str) -> u64 {
    match unit {
        "calls" => value.calls,
        "bytes" => value.bytes,
        "cost_microunits" => value.cost_microunits,
        "concurrency" => value.concurrency,
        _ => unreachable!("reviewed unit"),
    }
}

fn limit(value: &BudgetLimits, unit: &str) -> Option<u64> {
    match unit {
        "calls" => value.calls,
        "bytes" => value.bytes,
        "cost_microunits" => value.cost_microunits,
        "concurrency" => value.concurrency,
        _ => unreachable!("reviewed unit"),
    }
}

fn integer(value: u64) -> Result<i64> {
    i64::try_from(value).context("budget_integer_overflow")
}

fn checked_add(left: u64, right: u64) -> Result<u64> {
    let result = left.checked_add(right).context("budget_integer_overflow")?;
    integer(result)?;
    Ok(result)
}

fn require_transaction(connection: &Connection) -> Result<()> {
    ensure!(!connection.is_autocommit(), "budget_requires_transaction");
    Ok(())
}

/// Internal savepoints prevent partial multi-account mutation even if the caller
/// catches an admission failure and commits other work in its outer transaction.
fn atomic<T>(connection: &Connection, body: impl FnOnce() -> Result<T>) -> Result<T> {
    require_transaction(connection)?;
    connection.execute_batch("SAVEPOINT day2_budget_atomic")?;
    match body() {
        Ok(value) => {
            connection.execute_batch("RELEASE day2_budget_atomic")?;
            Ok(value)
        }
        Err(error) => {
            connection
                .execute_batch("ROLLBACK TO day2_budget_atomic; RELEASE day2_budget_atomic")?;
            Err(error)
        }
    }
}

pub(crate) fn upgrade(connection: &Connection) -> Result<()> {
    upgrade_with_lineage(connection, None)
}

/// Authority bootstrap supplies its host-generated lineage, deterministic in a
/// simulation and unique for each real installation. Later revisions preserve it.
pub(crate) fn initialize_in(connection: &Connection, authority_lineage: &str) -> Result<()> {
    upgrade_with_lineage(connection, Some(authority_lineage))
}

fn upgrade_with_lineage(connection: &Connection, lineage: Option<&str>) -> Result<()> {
    require_transaction(connection)?;
    let mut tables = connection.prepare("SELECT name FROM sqlite_master WHERE type='table'")?;
    let existing_tables: BTreeSet<String> = tables
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS day2_budget_meta(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),ledger_id TEXT NOT NULL,
            restored INTEGER NOT NULL CHECK(restored IN (0,1))) STRICT;
        CREATE TABLE IF NOT EXISTS day2_budget_definitions(
            id TEXT PRIMARY KEY,scope TEXT NOT NULL,period_seconds INTEGER NOT NULL CHECK(period_seconds>0)) STRICT;
        CREATE TABLE IF NOT EXISTS day2_budget_accounts(
            id TEXT PRIMARY KEY,budget_id TEXT NOT NULL,window_start INTEGER NOT NULL,
            scope TEXT NOT NULL,subject TEXT NOT NULL,unit TEXT NOT NULL,
            limit_amount INTEGER NOT NULL CHECK(limit_amount>=0),
            used INTEGER NOT NULL CHECK(used>=0),held INTEGER NOT NULL CHECK(held>=0),
            frozen INTEGER NOT NULL CHECK(frozen IN (0,1)),revision INTEGER NOT NULL CHECK(revision>0),
            UNIQUE(budget_id,window_start,scope,subject,unit)) STRICT;
        CREATE TABLE IF NOT EXISTS day2_budget_reservations(
            id TEXT PRIMARY KEY,ledger_id TEXT NOT NULL,fingerprint TEXT NOT NULL,
            request TEXT NOT NULL,charges TEXT NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS day2_budget_settlements(
            id TEXT PRIMARY KEY REFERENCES day2_budget_reservations(id),actual TEXT NOT NULL,
            receipt TEXT NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS day2_budget_unknown(
            id TEXT PRIMARY KEY REFERENCES day2_budget_reservations(id)) STRICT;
        CREATE TABLE IF NOT EXISTS day2_budget_overruns(
            id TEXT PRIMARY KEY REFERENCES day2_budget_reservations(id),actual TEXT NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS day2_budget_overrun_acknowledgments(
            id TEXT PRIMARY KEY REFERENCES day2_budget_overruns(id),resolution TEXT NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS day2_budget_overrun_resolutions(
            id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,receipt TEXT NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS day2_budget_usage_reconciliations(
            id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,receipt TEXT NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS day2_budget_allocations(
            allocation_id TEXT PRIMARY KEY,budget_id TEXT NOT NULL,window_start INTEGER NOT NULL,
            ledger_id TEXT NOT NULL,receipt TEXT NOT NULL) STRICT;
        CREATE INDEX IF NOT EXISTS day2_budget_allocation_lookup ON day2_budget_allocations(budget_id,window_start,ledger_id);
        CREATE TABLE IF NOT EXISTS day2_budget_definition_state(
            id TEXT PRIMARY KEY,revision INTEGER NOT NULL,definition TEXT NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS day2_budget_allocator(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),allocator_id TEXT NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS day2_budget_recovery(
            old_ledger_id TEXT PRIMARY KEY,new_ledger_id TEXT NOT NULL UNIQUE) STRICT;
        CREATE TABLE IF NOT EXISTS day2_budget_recovery_receipts(
            id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL) STRICT;",
    )?;
    let exists: bool =
        connection.query_row("SELECT EXISTS(SELECT 1 FROM day2_budget_meta)", [], |row| {
            row.get(0)
        })?;
    if !exists {
        let id = if let Some(lineage) = lineage {
            crate::digest(&serde_json::to_vec(&("day2-budget-ledger-v1", lineage))?)
        } else {
            let mut entropy = [0_u8; 32];
            getrandom::fill(&mut entropy)
                .map_err(|error| anyhow::anyhow!("budget_entropy: {error}"))?;
            crate::digest(&entropy)
        };
        connection.execute(
            "INSERT INTO day2_budget_meta(singleton,ledger_id,restored) VALUES(1,?1,0)",
            [id],
        )?;
    }
    for table in [
        "day2_budget_definitions",
        "day2_budget_reservations",
        "day2_budget_settlements",
        "day2_budget_unknown",
        "day2_budget_overruns",
        "day2_budget_overrun_acknowledgments",
        "day2_budget_overrun_resolutions",
        "day2_budget_usage_reconciliations",
        "day2_budget_allocations",
        "day2_budget_allocator",
        "day2_budget_recovery",
        "day2_budget_recovery_receipts",
    ] {
        immutable_table(connection, table, !existing_tables.contains(table))?;
    }
    reduction::upgrade_local(connection)?;
    Ok(())
}

fn immutable_table(connection: &Connection, table: &str, create_missing: bool) -> Result<()> {
    for (suffix, action) in [("update", "UPDATE"), ("delete", "DELETE")] {
        let name = format!("{table}_no_{suffix}");
        let sql = format!(
            "CREATE TRIGGER {name} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'append_only_budget'); END"
        );
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='trigger' AND name=?1)",
            [&name],
            |row| row.get(0),
        )?;
        ensure!(exists || create_missing, "budget_immutable_trigger_missing");
        if !exists {
            connection.execute_batch(&sql)?;
        }
        crate::audit::validate_trigger(connection, &name, &sql)?;
    }
    // SQLite REPLACE can bypass delete triggers when recursive_triggers is off.
    let key = match table {
        "day2_budget_allocations" => "allocation_id",
        "day2_budget_allocator" => "singleton",
        "day2_budget_recovery" => "old_ledger_id",
        _ => "id",
    };
    let name = format!("{table}_no_replace");
    let sql = format!(
        "CREATE TRIGGER {name} BEFORE INSERT ON {table} WHEN EXISTS(SELECT 1 FROM {table} WHERE {key}=NEW.{key}) BEGIN SELECT RAISE(ABORT,'append_only_budget'); END"
    );
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='trigger' AND name=?1)",
        [&name],
        |row| row.get(0),
    )?;
    ensure!(exists || create_missing, "budget_immutable_trigger_missing");
    if !exists {
        connection.execute_batch(&sql)?;
    }
    crate::audit::validate_trigger(connection, &name, &sql)?;
    Ok(())
}

fn ledger(connection: &Connection) -> Result<(String, bool)> {
    connection
        .query_row(
            "SELECT ledger_id,restored FROM day2_budget_meta WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("budget_ledger_uninitialized")
}

fn scope_name(scope: &BudgetScope) -> &'static str {
    match scope {
        BudgetScope::Installation => "installation",
        BudgetScope::App => "app",
        BudgetScope::Actor => "actor",
        BudgetScope::Connection => "connection",
        BudgetScope::InvocationRoot => "invocation_root",
    }
}

fn subject(scope: &BudgetScope, context: &BudgetContext) -> String {
    match scope {
        BudgetScope::Installation => "allocation".into(),
        BudgetScope::App => context.app.clone(),
        BudgetScope::Actor => context.actor.clone(),
        BudgetScope::Connection => context.connection.clone(),
        BudgetScope::InvocationRoot => context.invocation_root.clone(),
    }
}

fn window(definition: &BudgetDefinition, now: i64) -> Result<i64> {
    let period = integer(definition.period_seconds)?;
    ensure!(period > 0 && now >= 0, "invalid_budget_period");
    Ok(now - now.rem_euclid(period))
}

/// Fixed allocations in other app databases cannot be recalled by updating this
/// app's snapshot. An established installation ceiling is therefore monotonic.
/// Reducing it requires a separately reviewed pool transition; neither a new
/// revision nor a new time window silently reclaims old allocated capacity.
fn reject_installation_reduction(old: &BudgetDefinition, new: &BudgetDefinition) -> Result<()> {
    if matches!(old.scope, BudgetScope::Installation) {
        for unit in UNITS {
            if let Some(previous) = limit(&old.limits, unit) {
                ensure!(
                    limit(&new.limits, unit).is_some_and(|next| next >= previous),
                    "budget_installation_reduction_requires_new_pool"
                );
            }
        }
    }
    Ok(())
}

fn validate_request(request: &ReservationRequest) -> Result<()> {
    for value in [
        &request.id,
        &request.binding,
        &request.context.app,
        &request.context.actor,
        &request.context.connection,
        &request.context.invocation_root,
    ] {
        ensure!(
            !value.is_empty() && value.len() <= 4096,
            "invalid_budget_identity"
        );
    }
    for unit in UNITS {
        integer(amount(&request.quote, unit))?;
    }
    for (id, definition) in &request.budgets {
        ensure!(
            !id.is_empty() && id.len() <= 128 && definition.revision > 0,
            "invalid_budget_definition"
        );
        integer(definition.revision)?;
        window(definition, request.context.now)?;
        let mut supplied = false;
        for unit in UNITS {
            if let Some(value) = limit(&definition.limits, unit) {
                ensure!(value > 0, "invalid_budget_limit");
                integer(value)?;
                supplied = true;
            }
        }
        ensure!(supplied, "empty_budget_limits");
    }
    Ok(())
}

pub fn reserve_in(connection: &Connection, request: &ReservationRequest) -> Result<Reservation> {
    atomic(connection, || {
        validate_request(request)?;
        let (ledger_id, restored) = ledger(connection)?;
        ensure!(
            !restored,
            anyhow::Error::new(Failure::BudgetUnavailable)
                .context("budget_restore_reconciliation_required")
        );
        let mut identity = request.clone();
        // Re-reading the same immutable attempt later never moves its charges to
        // a fresh period. The first trusted dispatch time stays in the stored row.
        identity.context.now = 0;
        let fingerprint = crate::digest(&serde_json::to_vec(&identity)?);
        let existing: Option<(String, String)> = connection
            .query_row(
                "SELECT fingerprint,ledger_id FROM day2_budget_reservations WHERE id=?1",
                [&request.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let reservation = Reservation {
            id: request.id.clone(),
            ledger_id,
        };
        if let Some((recorded, epoch)) = existing {
            ensure!(
                recorded == fingerprint && epoch == reservation.ledger_id,
                "budget_idempotency_conflict"
            );
            return Ok(reservation);
        }
        let overrun = frozen_overrun_in(connection)?;
        ensure!(
            !overrun,
            anyhow::Error::new(Failure::BudgetUnavailable)
                .context("budget_account_frozen_after_overrun")
        );
        sync_definitions_in(connection, &request.budgets)?;
        let mut charges = Vec::new();
        for (id, definition) in &request.budgets {
            let scope = scope_name(&definition.scope);
            let period = integer(definition.period_seconds)?;
            let existing: Option<(String, i64)> = connection
                .query_row(
                    "SELECT scope,period_seconds FROM day2_budget_definitions WHERE id=?1",
                    [id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((old_scope, old_period)) = existing {
                ensure!(
                    old_scope == scope && old_period == period,
                    "budget_account_shape_changed"
                );
            } else {
                connection.execute(
                    "INSERT INTO day2_budget_definitions VALUES(?1,?2,?3)",
                    params![id, scope, period],
                )?;
            }
            let window_start = window(definition, request.context.now)?;
            let subject = subject(&definition.scope, &request.context);
            for unit in UNITS {
                let Some(global_limit) = limit(&definition.limits, unit) else {
                    continue;
                };
                let local_limit = if matches!(definition.scope, BudgetScope::Installation) {
                    allocation_limit_in(connection, id, window_start, &reservation.ledger_id, unit)?
                        .min(global_limit)
                } else {
                    global_limit
                };
                // Outstanding attempts and a root's child work do not gain fresh
                // capacity merely by surviving a wall-clock period boundary.
                let account_window = if unit == "concurrency"
                    || matches!(definition.scope, BudgetScope::InvocationRoot)
                {
                    0
                } else {
                    window_start
                };
                let account = crate::digest(&serde_json::to_vec(&(
                    id,
                    account_window,
                    scope,
                    &subject,
                    unit,
                ))?);
                let existing: Option<(i64, i64, bool, i64)> = connection
                    .query_row(
                        "SELECT used,held,frozen,revision FROM day2_budget_accounts WHERE id=?1",
                        [&account],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .optional()?;
                let (used, held, frozen, revision) =
                    existing.unwrap_or((0, 0, false, integer(definition.revision)?));
                ensure!(
                    !frozen,
                    anyhow::Error::new(Failure::BudgetUnavailable)
                        .context(format!("budget_account_frozen:{id}:{unit}"))
                );
                ensure!(
                    revision <= integer(definition.revision)?,
                    "budget_revision_stale"
                );
                let requested = amount(&request.quote, unit);
                let total = checked_add(
                    checked_add(u64::try_from(used)?, u64::try_from(held)?)?,
                    requested,
                )?;
                ensure!(
                    total <= local_limit,
                    anyhow::Error::new(Failure::BudgetExhausted)
                        .context(format!("budget_exhausted:{id}:{unit}"))
                );
                if existing.is_some() {
                    connection.execute("UPDATE day2_budget_accounts SET limit_amount=?2,held=held+?3,revision=?4 WHERE id=?1",
                        params![account,integer(local_limit)?,integer(requested)?,integer(definition.revision)?])?;
                } else {
                    connection.execute(
                        "INSERT INTO day2_budget_accounts VALUES(?1,?2,?3,?4,?5,?6,?7,0,?8,0,?9)",
                        params![
                            account,
                            id,
                            account_window,
                            scope,
                            subject,
                            unit,
                            integer(local_limit)?,
                            integer(requested)?,
                            integer(definition.revision)?
                        ],
                    )?;
                }
                charges.push(Charge {
                    account,
                    unit: unit.into(),
                    reserved: requested,
                });
            }
        }
        connection.execute(
            "INSERT INTO day2_budget_reservations VALUES(?1,?2,?3,?4,?5)",
            params![
                request.id,
                reservation.ledger_id,
                fingerprint,
                serde_json::to_string(request)?,
                serde_json::to_string(&charges)?
            ],
        )?;
        Ok(reservation)
    })
}

fn allocation_limit_in(
    connection: &Connection,
    budget_id: &str,
    window_start: i64,
    ledger_id: &str,
    unit: &str,
) -> Result<u64> {
    let mut statement = connection.prepare("SELECT receipt FROM day2_budget_allocations WHERE budget_id=?1 AND ledger_id=?2 AND (window_start=?3 OR ?4='concurrency') ORDER BY allocation_id")?;
    let mut total = 0;
    let mut found = false;
    for encoded in statement
        .query_map(params![budget_id, ledger_id, window_start, unit], |row| {
            row.get::<_, String>(0)
        })?
    {
        let allocation: AllocationReceipt = crate::json::decode(encoded?.as_bytes())?;
        ensure!(
            allocation.ledger_id == ledger_id,
            "budget_allocation_ledger_mismatch"
        );
        if let Some(value) = limit(&allocation.limits, unit) {
            total = checked_add(total, value)?;
            found = true;
        }
    }
    ensure!(
        found,
        anyhow::Error::new(Failure::BudgetUnavailable).context(format!(
            "budget_installation_allocation_required:{budget_id}:{unit}"
        ))
    );
    reduction::remaining_local_capacity(connection, budget_id, window_start, ledger_id, unit, total)
}

/// Called by authority activation in its transaction. Quota revisions update the
/// cap, never the used/held balances. Accounting identity and period are stable.
pub fn sync_definitions_in(
    connection: &Connection,
    definitions: &BTreeMap<String, BudgetDefinition>,
) -> Result<()> {
    atomic(connection, || {
        for (id, definition) in definitions {
            definition.validate()?;
            let scope = scope_name(&definition.scope);
            let period = integer(definition.period_seconds)?;
            let old_shape: Option<(String, i64)> = connection
                .query_row(
                    "SELECT scope,period_seconds FROM day2_budget_definitions WHERE id=?1",
                    [id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((old_scope, old_period)) = old_shape {
                ensure!(
                    old_scope == scope && old_period == period,
                    "budget_account_shape_changed"
                );
            } else {
                connection.execute(
                    "INSERT INTO day2_budget_definitions VALUES(?1,?2,?3)",
                    params![id, scope, period],
                )?;
            }
            let encoded = serde_json::to_string(definition)?;
            let old: Option<(i64, String)> = connection
                .query_row(
                    "SELECT revision,definition FROM day2_budget_definition_state WHERE id=?1",
                    [id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((revision, old)) = &old {
                ensure!(
                    *revision <= integer(definition.revision)?,
                    "budget_revision_stale"
                );
                ensure!(
                    *revision != integer(definition.revision)? || *old == encoded,
                    "budget_revision_conflict"
                );
                reduction::validate_local_definition(
                    connection,
                    id,
                    &crate::json::decode::<BudgetDefinition>(old.as_bytes())?,
                    definition,
                )?;
            }
            // A restored/newly activated app can already contain an imported
            // allocation without a prior local definition-state row. The
            // immutable receipt supplies the old company ceiling in that case.
            if matches!(definition.scope, BudgetScope::Installation) {
                let mut allocations = connection
                    .prepare("SELECT receipt FROM day2_budget_allocations WHERE budget_id=?1")?;
                for encoded in allocations.query_map([id], |row| row.get::<_, String>(0))? {
                    let receipt: AllocationReceipt = crate::json::decode(encoded?.as_bytes())?;
                    reduction::validate_local_definition(
                        connection,
                        id,
                        &receipt.definition,
                        definition,
                    )?;
                }
            }
            connection.execute("INSERT INTO day2_budget_definition_state VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,definition=excluded.definition",params![id,integer(definition.revision)?,encoded])?;
            for unit in UNITS {
                if let Some(cap) = limit(&definition.limits, unit) {
                    // Installation capacity can only increase by an allocation
                    // import/reservation, not a company quota edit alone.
                    let sql = if matches!(definition.scope, BudgetScope::Installation) {
                        "UPDATE day2_budget_accounts SET limit_amount=MIN(limit_amount,?3),revision=?4 WHERE budget_id=?1 AND unit=?2 AND (unit='concurrency' OR window_start>=?5)"
                    } else {
                        "UPDATE day2_budget_accounts SET limit_amount=?3,revision=?4 WHERE budget_id=?1 AND unit=?2"
                    };
                    if matches!(definition.scope, BudgetScope::Installation) {
                        connection.execute(
                            sql,
                            params![
                                id,
                                unit,
                                integer(cap)?,
                                integer(definition.revision)?,
                                reduction::definition_effective_window(connection, id, definition)?
                            ],
                        )?;
                    } else {
                        connection.execute(
                            sql,
                            params![id, unit, integer(cap)?, integer(definition.revision)?],
                        )?;
                    }
                }
            }
        }
        Ok(())
    })
}

pub fn settle_in(
    connection: &Connection,
    reservation: &Reservation,
    outcome: &Settlement,
) -> Result<SettlementReceipt> {
    atomic(connection, || {
        let (ledger_id, restored) = ledger(connection)?;
        ensure!(
            !restored,
            anyhow::Error::new(Failure::BudgetUnavailable)
                .context("budget_restore_reconciliation_required")
        );
        ensure!(ledger_id == reservation.ledger_id, "budget_ledger_mismatch");
        let (charges, request): (String, String) = connection
            .query_row(
                "SELECT charges,request FROM day2_budget_reservations WHERE id=?1 AND ledger_id=?2",
                params![reservation.id, reservation.ledger_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .context("budget_reservation_missing")?;
        let existing: Option<(String, String)> = connection
            .query_row(
                "SELECT actual,receipt FROM day2_budget_settlements WHERE id=?1",
                [&reservation.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let actual = match outcome {
            Settlement::Known { actual } => {
                let mut actual = actual.clone();
                actual.concurrency = 0;
                for unit in UNITS {
                    integer(amount(&actual, unit))?;
                }
                actual
            }
            Settlement::Unknown => {
                if let Some((_, receipt)) = existing {
                    return crate::json::decode(receipt.as_bytes());
                }
                let known: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM day2_budget_unknown WHERE id=?1)",
                    [&reservation.id],
                    |row| row.get(0),
                )?;
                if !known {
                    connection.execute(
                        "INSERT INTO day2_budget_unknown VALUES(?1)",
                        [&reservation.id],
                    )?;
                }
                return Ok(SettlementReceipt {
                    reservation: reservation.clone(),
                    settled: false,
                    overrun: false,
                });
            }
        };
        if let Some((recorded, receipt)) = existing {
            ensure!(
                crate::json::decode::<Consumption>(recorded.as_bytes())? == actual,
                "budget_settlement_conflict"
            );
            return crate::json::decode(receipt.as_bytes());
        }
        let charges: Vec<Charge> = crate::json::decode(charges.as_bytes())?;
        let request: ReservationRequest = crate::json::decode(request.as_bytes())?;
        let mut overrun = actual.calls > request.quote.calls
            || actual.bytes > request.quote.bytes
            || actual.cost_microunits > request.quote.cost_microunits;
        for charge in charges {
            let (used, held): (i64, i64) = connection.query_row(
                "SELECT used,held FROM day2_budget_accounts WHERE id=?1",
                [&charge.account],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let actual_units = amount(&actual, &charge.unit);
            let next_used = checked_add(u64::try_from(used)?, actual_units)?;
            let next_held = u64::try_from(held)?
                .checked_sub(charge.reserved)
                .context("budget_hold_corrupt")?;
            // A quota reduction can put already admitted usage above the new
            // cap. That blocks future admission but is not an adapter overrun.
            let exceeded = actual_units > charge.reserved;
            overrun |= exceeded;
            connection.execute(
                "UPDATE day2_budget_accounts SET used=?2,held=?3,frozen=MAX(frozen,?4) WHERE id=?1",
                params![
                    charge.account,
                    integer(next_used)?,
                    integer(next_held)?,
                    exceeded
                ],
            )?;
        }
        let receipt = SettlementReceipt {
            reservation: reservation.clone(),
            settled: true,
            overrun,
        };
        if overrun {
            connection.execute(
                "INSERT INTO day2_budget_overruns VALUES(?1,?2)",
                params![reservation.id, serde_json::to_string(&actual)?],
            )?;
        }
        connection.execute(
            "INSERT INTO day2_budget_settlements VALUES(?1,?2,?3)",
            params![
                reservation.id,
                serde_json::to_string(&actual)?,
                serde_json::to_string(&receipt)?
            ],
        )?;
        Ok(receipt)
    })
}

/// Reconciles accounting only. It cannot create a provider result, retry an
/// effect, resume an invocation, or authorize its business completion.
pub fn reconcile_usage_in(
    connection: &Connection,
    operator: &crate::authority_state::LocalOperator,
    request: &UsageReconciliation,
) -> Result<UsageReconciliationReceipt> {
    atomic(connection, || {
        ensure!(
            !request.id.is_empty()
                && request.id.len() <= 256
                && !request.reason.trim().is_empty()
                && request.reason.len() <= 4096
                && !request.proof.trim().is_empty()
                && request.proof.len() <= 4096,
            "budget_usage_reconciliation_evidence_required"
        );
        ensure!(
            request.actual.concurrency == 0,
            "budget_usage_reconciliation_requires_terminal_outcome"
        );
        let fingerprint = crate::digest(&serde_json::to_vec(request)?);
        let existing: Option<(String, String)> = connection
            .query_row(
                "SELECT fingerprint,receipt FROM day2_budget_usage_reconciliations WHERE id=?1",
                [&request.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((existing, raw)) = existing {
            ensure!(
                existing == fingerprint,
                "budget_usage_reconciliation_conflict"
            );
            return crate::json::decode(raw.as_bytes());
        }
        let unknown: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM day2_budget_unknown WHERE id=?1)",
            [&request.reservation],
            |row| row.get(0),
        )?;
        ensure!(unknown, "budget_usage_reconciliation_requires_unknown");
        let settled: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM day2_budget_settlements WHERE id=?1)",
            [&request.reservation],
            |row| row.get(0),
        )?;
        ensure!(!settled, "budget_usage_already_settled");
        let settlement = settle_in(
            connection,
            &Reservation {
                id: request.reservation.clone(),
                ledger_id: request.ledger_id.clone(),
            },
            &Settlement::Known {
                actual: request.actual.clone(),
            },
        )?;
        let receipt = UsageReconciliationReceipt {
            request: request.clone(),
            operator: operator.name().into(),
            settlement,
        };
        connection.execute(
            "INSERT INTO day2_budget_usage_reconciliations VALUES(?1,?2,?3)",
            params![request.id, fingerprint, serde_json::to_string(&receipt)?],
        )?;
        Ok(receipt)
    })
}

/// Read inside the same transaction as the administrator's authorization check.
pub fn inspect_in(connection: &Connection) -> Result<LedgerStatus> {
    require_transaction(connection)?;
    let (ledger_id, frozen_after_restore) = ledger(connection)?;
    let overruns = overruns_in(connection)?;
    let frozen_after_overrun = !overruns.is_empty();
    let mut statement = connection.prepare("SELECT budget_id,window_start,scope,subject,unit,limit_amount,used,held,frozen,revision FROM day2_budget_accounts ORDER BY budget_id,window_start,scope,subject,unit")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, bool>(8)?,
            row.get::<_, i64>(9)?,
        ))
    })?;
    let mut accounts = Vec::new();
    for row in rows {
        let (budget_id, window_start, scope, subject, unit, cap, used, held, frozen, revision) =
            row?;
        accounts.push(BudgetUsage {
            budget_id,
            window_start,
            scope,
            subject,
            unit,
            limit: u64::try_from(cap)?,
            used: u64::try_from(used)?,
            reserved: u64::try_from(held)?,
            frozen,
            revision: u64::try_from(revision)?,
        });
    }
    let outstanding: i64 = connection.query_row("SELECT COUNT(*) FROM day2_budget_reservations r WHERE NOT EXISTS(SELECT 1 FROM day2_budget_settlements s WHERE s.id=r.id)", [], |row| row.get(0))?;
    let mut statement =
        connection.prepare("SELECT actual FROM day2_budget_settlements ORDER BY id")?;
    let mut known_usage = Consumption::default();
    for row in statement.query_map([], |row| row.get::<_, String>(0))? {
        let actual: Consumption = crate::json::decode(row?.as_bytes())?;
        known_usage.calls = checked_add(known_usage.calls, actual.calls)?;
        known_usage.bytes = checked_add(known_usage.bytes, actual.bytes)?;
        known_usage.cost_microunits =
            checked_add(known_usage.cost_microunits, actual.cost_microunits)?;
    }
    let mut unknown_usage = Vec::new();
    let has_correlations: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='day2_resource_correlations')", [], |row| row.get(0))?;
    let mut statement = connection.prepare("SELECT r.id,r.ledger_id,r.request FROM day2_budget_reservations r JOIN day2_budget_unknown u ON u.id=r.id WHERE NOT EXISTS(SELECT 1 FROM day2_budget_settlements s WHERE s.id=r.id) ORDER BY r.id")?;
    for row in statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })? {
        let (id, ledger_id, raw) = row?;
        let request: ReservationRequest = crate::json::decode(raw.as_bytes())?;
        let mut exchanges = Vec::new();
        if has_correlations {
            let raw: Option<String> = connection
                .query_row(
                    "SELECT exchanges FROM day2_resource_correlations WHERE attempt=?1",
                    [&id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(raw) = raw {
                ensure!(raw.len() <= 2048, "budget_provider_correlation_byte_limit");
                let recorded: Vec<crate::integrations::ExchangeCorrelation> =
                    crate::json::decode(raw.as_bytes())?;
                ensure!(
                    recorded.len() <= 2,
                    "budget_provider_correlation_count_limit"
                );
                for exchange in recorded {
                    ensure!(
                        exchange
                            .request_id
                            .as_ref()
                            .is_none_or(|value| value.len() <= 128)
                            && exchange
                                .statement_handle
                                .as_ref()
                                .is_none_or(|value| value.len() <= 128),
                        "budget_provider_correlation_identifier_limit"
                    );
                    exchanges.push(serde_json::to_value(exchange)?);
                }
            }
        }
        unknown_usage.push(UnknownUsage {
            reservation: Reservation { id, ledger_id },
            quote: request.quote,
            exchanges,
        });
    }
    Ok(LedgerStatus {
        ledger_id,
        frozen_after_restore,
        frozen_after_overrun,
        accounts,
        outstanding_attempts: u64::try_from(outstanding)?,
        known_usage,
        overruns,
        unknown_usage,
    })
}

fn frozen_overrun_in(connection: &Connection) -> Result<bool> {
    Ok(connection.query_row("SELECT EXISTS(SELECT 1 FROM day2_budget_overruns o WHERE NOT EXISTS(SELECT 1 FROM day2_budget_overrun_acknowledgments a WHERE a.id=o.id))",[],|row|row.get(0))?)
}

fn overruns_in(connection: &Connection) -> Result<Vec<OverrunEvidence>> {
    let mut statement=connection.prepare("SELECT o.id,o.actual,r.request FROM day2_budget_overruns o JOIN day2_budget_reservations r ON r.id=o.id WHERE NOT EXISTS(SELECT 1 FROM day2_budget_overrun_acknowledgments a WHERE a.id=o.id) ORDER BY o.id")?;
    let mut result = Vec::new();
    for row in statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })? {
        let (reservation, actual, request) = row?;
        let request: ReservationRequest = crate::json::decode(request.as_bytes())?;
        result.push(OverrunEvidence {
            reservation,
            quote: request.quote,
            actual: crate::json::decode(actual.as_bytes())?,
        });
    }
    Ok(result)
}

/// A deliberate trusted operator assertion after reviewing adapter repair or
/// reconciliation evidence. It acknowledges exactly the displayed event set;
/// an additional overrun invalidates a pending approval. No balances are reset.
pub fn resolve_overruns_in(
    connection: &Connection,
    operator: &crate::authority_state::LocalOperator,
    request: &OverrunResolution,
) -> Result<OverrunResolutionReceipt> {
    atomic(connection, || {
        ensure!(
            !request.id.is_empty()
                && request.id.len() <= 256
                && !request.reason.trim().is_empty()
                && request.reason.len() <= 4096
                && !request.proof.trim().is_empty()
                && request.proof.len() <= 4096
                && !request.reservations.is_empty(),
            "invalid_budget_overrun_resolution"
        );
        let fingerprint = crate::digest(&serde_json::to_vec(&(operator.name(), request))?);
        let existing: Option<(String, String)> = connection
            .query_row(
                "SELECT fingerprint,receipt FROM day2_budget_overrun_resolutions WHERE id=?1",
                [&request.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((old, receipt)) = existing {
            ensure!(old == fingerprint, "budget_overrun_resolution_conflict");
            return crate::json::decode(receipt.as_bytes());
        }
        let (ledger_id, restored) = ledger(connection)?;
        ensure!(
            ledger_id == request.ledger_id && !restored,
            "budget_overrun_resolution_ledger_mismatch"
        );
        let pending: BTreeSet<_> = overruns_in(connection)?
            .into_iter()
            .map(|evidence| evidence.reservation)
            .collect();
        ensure!(
            pending == request.reservations,
            "budget_overrun_evidence_changed"
        );
        let receipt = OverrunResolutionReceipt {
            id: request.id.clone(),
            ledger_id,
            operator: operator.name().into(),
            reservations: request.reservations.clone(),
            reason: request.reason.clone(),
            proof: request.proof.clone(),
        };
        connection.execute(
            "INSERT INTO day2_budget_overrun_resolutions VALUES(?1,?2,?3)",
            params![request.id, fingerprint, serde_json::to_string(&receipt)?],
        )?;
        for id in &request.reservations {
            connection.execute(
                "INSERT INTO day2_budget_overrun_acknowledgments VALUES(?1,?2)",
                params![id, request.id],
            )?;
        }
        // The complete pending set was acknowledged. A later settlement creates
        // a new event and freezes again; caps still compare full used+held units.
        connection.execute("UPDATE day2_budget_accounts SET frozen=0", [])?;
        Ok(receipt)
    })
}

/// A copied ledger cannot prove what the original spent after the snapshot.
/// Keep usage and outstanding holds intact and disable all future admission.
/// There is intentionally no reset/unfreeze API that would resurrect capacity.
pub fn invalidate_restored(connection: &Connection) -> Result<()> {
    require_transaction(connection)?;
    upgrade(connection)?;
    connection.execute(
        "UPDATE day2_budget_meta SET restored=1 WHERE singleton=1",
        [],
    )?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationRequest {
    pub id: String,
    pub budget_id: String,
    pub definition: BudgetDefinition,
    pub window_start: i64,
    pub ledger_id: String,
    pub limits: BudgetLimits,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationReceipt {
    pub allocator_id: String,
    pub allocation_id: String,
    pub budget_id: String,
    pub window_start: i64,
    pub ledger_id: String,
    pub definition: BudgetDefinition,
    pub limits: BudgetLimits,
}

/// A trusted operator-owned company allocator. Apps never choose this path.
pub struct Allocator {
    connection: Connection,
}

impl Allocator {
    pub fn open(path: &Path, _operator: &crate::authority_state::LocalOperator) -> Result<Self> {
        ensure!(path.is_file(), "budget_allocator_missing_recovery_required");
        let connection = crate::store::open(path)?;
        let valid: bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='day2_company_budget_meta')",[],|row|row.get(0))?;
        ensure!(valid, "budget_allocator_invalid");
        immutable_table(&connection, "day2_company_budget_allocations", false)?;
        reduction::upgrade_allocator(&connection)?;
        let allocator = Self { connection };
        allocator.id()?;
        Ok(allocator)
    }

    /// Only initial provisioning may create a company ledger. A missing ledger
    /// at an established installation is a recovery incident, never a reset.
    /// The installation must persist/pin the returned id separately from this DB.
    pub fn create(path: &Path, _operator: &crate::authority_state::LocalOperator) -> Result<Self> {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .context("budget_allocator_already_exists")?;
        let mut connection = crate::store::open(path)?;
        let tx = crate::write_queue::immediate(&mut connection)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS day2_company_budget_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),id TEXT NOT NULL) STRICT;
            CREATE TABLE IF NOT EXISTS day2_company_budget_accounts(id TEXT NOT NULL,window_start INTEGER NOT NULL,unit TEXT NOT NULL,period_seconds INTEGER NOT NULL,revision INTEGER NOT NULL,limit_amount INTEGER NOT NULL,allocated INTEGER NOT NULL CHECK(allocated>=0),PRIMARY KEY(id,window_start,unit)) STRICT;
            CREATE TABLE IF NOT EXISTS day2_company_budget_definitions(id TEXT PRIMARY KEY,definition TEXT NOT NULL) STRICT;
            CREATE TABLE IF NOT EXISTS day2_company_budget_allocations(id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,receipt TEXT NOT NULL) STRICT;")?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM day2_company_budget_meta)",
            [],
            |row| row.get(0),
        )?;
        if !exists {
            let mut entropy = [0_u8; 32];
            getrandom::fill(&mut entropy)
                .map_err(|error| anyhow::anyhow!("budget_entropy: {error}"))?;
            tx.execute(
                "INSERT INTO day2_company_budget_meta(singleton,id) VALUES(1,?1)",
                [crate::digest(&entropy)],
            )?;
        }
        immutable_table(&tx, "day2_company_budget_allocations", true)?;
        reduction::upgrade_allocator(&tx)?;
        tx.commit()?;
        Ok(Self { connection })
    }

    pub fn id(&self) -> Result<String> {
        self.connection
            .query_row(
                "SELECT id FROM day2_company_budget_meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .context("budget_allocator_invalid")
    }

    pub fn receipt(&self, allocation_id: &str) -> Result<Option<AllocationReceipt>> {
        let encoded: Option<String> = self
            .connection
            .query_row(
                "SELECT receipt FROM day2_company_budget_allocations WHERE id=?1",
                [allocation_id],
                |row| row.get(0),
            )
            .optional()?;
        encoded
            .map(|value| crate::json::decode(value.as_bytes()))
            .transpose()
    }

    pub fn open_expected(
        path: &Path,
        operator: &crate::authority_state::LocalOperator,
        expected_id: &str,
    ) -> Result<Self> {
        let allocator = Self::open(path, operator)?;
        ensure!(
            allocator.id()? == expected_id,
            "budget_allocator_identity_mismatch"
        );
        Ok(allocator)
    }

    /// Capacity is spent on allocation, not on later usage reports. Allocations
    /// are immutable and never automatically returned from an app or a backup.
    pub fn allocate(
        &mut self,
        request: &AllocationRequest,
        _operator: &crate::authority_state::LocalOperator,
    ) -> Result<AllocationReceipt> {
        let tx = crate::write_queue::immediate(&mut self.connection)?;
        request.definition.validate()?;
        ensure!(
            matches!(request.definition.scope, BudgetScope::Installation),
            "budget_allocation_requires_installation_scope"
        );
        ensure!(
            window(&request.definition, request.window_start)? == request.window_start,
            "invalid_budget_allocation_window"
        );
        ensure!(
            !request.id.is_empty()
                && !request.ledger_id.is_empty()
                && !request.budget_id.is_empty(),
            "invalid_budget_allocation_identity"
        );
        ensure!(request.definition.revision > 0, "invalid_budget_definition");
        let fingerprint = crate::digest(&serde_json::to_vec(request)?);
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT fingerprint,receipt FROM day2_company_budget_allocations WHERE id=?1",
                [&request.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((recorded, receipt)) = existing {
            ensure!(recorded == fingerprint, "budget_allocation_conflict");
            return crate::json::decode(receipt.as_bytes());
        }
        reduction::allow_allocation(&tx, &request.budget_id, request.window_start)?;
        let old: Option<String> = tx
            .query_row(
                "SELECT definition FROM day2_company_budget_definitions WHERE id=?1",
                [&request.budget_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            let old: BudgetDefinition = crate::json::decode(old.as_bytes())?;
            ensure!(
                old.scope == request.definition.scope
                    && old.period_seconds == request.definition.period_seconds,
                "budget_account_shape_changed"
            );
            ensure!(
                old.revision <= request.definition.revision,
                "budget_revision_stale"
            );
            ensure!(
                old.revision != request.definition.revision || old == request.definition,
                "budget_revision_conflict"
            );
            reject_installation_reduction(&old, &request.definition)?;
        }
        tx.execute("INSERT INTO day2_company_budget_definitions VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET definition=excluded.definition",params![request.budget_id,serde_json::to_string(&request.definition)?])?;
        let allocator_id: String = tx.query_row(
            "SELECT id FROM day2_company_budget_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let mut supplied = false;
        for unit in UNITS {
            let requested = limit(&request.limits, unit);
            let global = limit(&request.definition.limits, unit);
            ensure!(
                requested.is_none() || global.is_some(),
                "budget_allocation_unit_unbounded"
            );
            let Some(requested) = requested else { continue };
            ensure!(requested > 0, "invalid_budget_limit");
            supplied = true;
            let global = global.unwrap();
            let account_window = if unit == "concurrency" {
                0
            } else {
                request.window_start
            };
            let row: Option<(i64,i64,i64)> = tx.query_row("SELECT allocated,period_seconds,revision FROM day2_company_budget_accounts WHERE id=?1 AND window_start=?2 AND unit=?3", params![request.budget_id,account_window,unit], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
            let period = integer(request.definition.period_seconds)?;
            // Validate period across windows too: a quota edit cannot rotate the
            // accounting identity by changing its window width.
            let incompatible: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM day2_company_budget_accounts WHERE id=?1 AND period_seconds<>?2)", params![request.budget_id,period], |row| row.get(0))?;
            ensure!(!incompatible, "budget_account_shape_changed");
            let (allocated, _, revision) =
                row.unwrap_or((0, period, integer(request.definition.revision)?));
            ensure!(
                revision <= integer(request.definition.revision)?,
                "budget_revision_stale"
            );
            let next = checked_add(u64::try_from(allocated)?, requested)?;
            ensure!(
                next <= global,
                anyhow::Error::new(Failure::BudgetExhausted)
                    .context("budget_company_pool_exhausted")
            );
            if row.is_some() {
                tx.execute("UPDATE day2_company_budget_accounts SET allocated=?4,limit_amount=?5,revision=?6 WHERE id=?1 AND window_start=?2 AND unit=?3", params![request.budget_id,account_window,unit,integer(next)?,integer(global)?,integer(request.definition.revision)?])?;
            } else {
                tx.execute(
                    "INSERT INTO day2_company_budget_accounts VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![
                        request.budget_id,
                        account_window,
                        unit,
                        period,
                        integer(request.definition.revision)?,
                        integer(global)?,
                        integer(next)?
                    ],
                )?;
            }
        }
        ensure!(supplied, "empty_budget_limits");
        let receipt = AllocationReceipt {
            allocator_id,
            allocation_id: request.id.clone(),
            budget_id: request.budget_id.clone(),
            window_start: request.window_start,
            ledger_id: request.ledger_id.clone(),
            definition: request.definition.clone(),
            limits: request.limits.clone(),
        };
        tx.execute(
            "INSERT INTO day2_company_budget_allocations VALUES(?1,?2,?3)",
            params![request.id, fingerprint, serde_json::to_string(&receipt)?],
        )?;
        tx.commit()?;
        Ok(receipt)
    }

    pub fn inspect(&self) -> Result<Vec<BudgetUsage>> {
        let mut statement = self.connection.prepare("SELECT id,window_start,unit,limit_amount,allocated,revision FROM day2_company_budget_accounts ORDER BY id,window_start,unit")?;
        let mut result = Vec::new();
        for row in statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })? {
            let (budget_id, window_start, unit, cap, allocated, revision) = row?;
            result.push(BudgetUsage {
                budget_id,
                window_start,
                scope: "installation".into(),
                subject: "fixed_allocations".into(),
                unit,
                limit: u64::try_from(cap)?,
                used: 0,
                reserved: u64::try_from(allocated)?,
                frozen: false,
                revision: u64::try_from(revision)?,
            });
        }
        Ok(result)
    }
}

/// Import verifies a committed allocation in the operator-selected allocator;
/// trusting a caller-supplied receipt alone would permit forged company capacity.
pub fn install_allocation_in(
    connection: &Connection,
    allocator: &Allocator,
    receipt: &AllocationReceipt,
    _operator: &crate::authority_state::LocalOperator,
) -> Result<()> {
    atomic(connection, || {
        let (ledger_id, restored) = ledger(connection)?;
        ensure!(
            !restored && ledger_id == receipt.ledger_id,
            "budget_allocation_ledger_mismatch"
        );
        let recorded = verify_allocation_in(connection, allocator, receipt)?;
        let existing: Option<String> = connection
            .query_row(
                "SELECT receipt FROM day2_budget_allocations WHERE allocation_id=?1",
                [&receipt.allocation_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            ensure!(existing == recorded, "budget_allocation_conflict");
            return Ok(());
        }
        connection.execute(
            "INSERT INTO day2_budget_allocations VALUES(?1,?2,?3,?4,?5)",
            params![
                receipt.allocation_id,
                receipt.budget_id,
                receipt.window_start,
                receipt.ledger_id,
                recorded
            ],
        )?;
        Ok(())
    })
}

fn verify_allocation_in(
    connection: &Connection,
    allocator: &Allocator,
    receipt: &AllocationReceipt,
) -> Result<String> {
    let recorded: String = allocator
        .connection
        .query_row(
            "SELECT receipt FROM day2_company_budget_allocations WHERE id=?1",
            [&receipt.allocation_id],
            |row| row.get(0),
        )
        .optional()?
        .context("budget_allocation_missing")?;
    ensure!(
        crate::json::decode::<AllocationReceipt>(recorded.as_bytes())? == *receipt,
        "budget_allocation_conflict"
    );
    ensure!(
        allocator.id()? == receipt.allocator_id,
        "budget_allocator_identity_mismatch"
    );
    let pinned: Option<String> = connection
        .query_row(
            "SELECT allocator_id FROM day2_budget_allocator WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(pinned) = pinned {
        ensure!(
            pinned == receipt.allocator_id,
            "budget_allocator_identity_mismatch"
        );
    } else {
        connection.execute(
            "INSERT INTO day2_budget_allocator VALUES(1,?1)",
            [&receipt.allocator_id],
        )?;
    }
    Ok(recorded)
}

/// Allocate a new ledger identity while leaving the restored ledger disabled.
/// The returned identity is the target of fresh central allocations; no old
/// allocation is transferred or returned to the company pool.
pub fn prepare_restore_recovery_in(
    connection: &Connection,
    _operator: &crate::authority_state::LocalOperator,
) -> Result<String> {
    atomic(connection, || {
        let (old, restored) = ledger(connection)?;
        if !restored {
            let completed: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM day2_budget_recovery_receipts WHERE id=?1)",
                [&old],
                |row| row.get(0),
            )?;
            ensure!(completed, "budget_not_restored");
            return Ok(old);
        }
        let existing: Option<String> = connection
            .query_row(
                "SELECT new_ledger_id FROM day2_budget_recovery WHERE old_ledger_id=?1",
                [&old],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            return Ok(existing);
        }
        let mut entropy = [0_u8; 32];
        getrandom::fill(&mut entropy)
            .map_err(|error| anyhow::anyhow!("budget_entropy: {error}"))?;
        let new = crate::digest(&entropy);
        connection.execute(
            "INSERT INTO day2_budget_recovery VALUES(?1,?2)",
            params![old, new],
        )?;
        Ok(new)
    })
}

/// Explicit recovery buys fresh company capacity and carries every old balance
/// and unknown hold forward. It does not assert that old effects never happened.
/// Empty allocations only work for a ledger that never held company allocations.
/// Overrun freezes remain; this API cannot erase an adapter-bound violation.
pub fn recover_restored_in(
    connection: &Connection,
    allocator: Option<&Allocator>,
    receipts: &[AllocationReceipt],
    _operator: &crate::authority_state::LocalOperator,
) -> Result<String> {
    atomic(connection, || {
        let (old, restored) = ledger(connection)?;
        let normalized: BTreeMap<_, _> = receipts
            .iter()
            .map(|receipt| (&receipt.allocation_id, receipt))
            .collect();
        ensure!(
            normalized.len() == receipts.len(),
            "budget_recovery_duplicate_allocation"
        );
        let fingerprint = crate::digest(&serde_json::to_vec(&normalized)?);
        if !restored {
            let existing: String = connection
                .query_row(
                    "SELECT fingerprint FROM day2_budget_recovery_receipts WHERE id=?1",
                    [&old],
                    |row| row.get(0),
                )
                .optional()?
                .context("budget_not_restored")?;
            ensure!(existing == fingerprint, "budget_recovery_conflict");
            return Ok(old);
        }
        let new: String = connection
            .query_row(
                "SELECT new_ledger_id FROM day2_budget_recovery WHERE old_ledger_id=?1",
                [&old],
                |row| row.get(0),
            )
            .optional()?
            .context("budget_recovery_not_prepared")?;
        let had_allocations: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM day2_budget_allocations)",
            [],
            |row| row.get(0),
        )?;
        ensure!(
            !had_allocations || !receipts.is_empty(),
            "budget_restore_fresh_allocation_required"
        );
        for receipt in receipts {
            ensure!(
                receipt.ledger_id == new,
                "budget_allocation_ledger_mismatch"
            );
            let recorded = verify_allocation_in(
                connection,
                allocator.context("budget_allocator_required")?,
                receipt,
            )?;
            connection.execute(
                "INSERT INTO day2_budget_allocations VALUES(?1,?2,?3,?4,?5)",
                params![
                    receipt.allocation_id,
                    receipt.budget_id,
                    receipt.window_start,
                    receipt.ledger_id,
                    recorded
                ],
            )?;
        }
        // Every installed company budget must receive fresh backing. Existing
        // balances stay unchanged; reservations below them remain impossible.
        let mut statement = connection
            .prepare("SELECT DISTINCT budget_id FROM day2_budget_allocations WHERE ledger_id=?1")?;
        for id in statement.query_map([&old], |row| row.get::<_, String>(0))? {
            let id = id?;
            ensure!(
                receipts.iter().any(|receipt| receipt.budget_id == id),
                "budget_restore_fresh_allocation_required:{id}"
            );
        }
        connection.execute(
            "UPDATE day2_budget_meta SET ledger_id=?1,restored=0 WHERE singleton=1",
            [&new],
        )?;
        connection.execute(
            "INSERT INTO day2_budget_recovery_receipts VALUES(?1,?2)",
            params![new, fingerprint],
        )?;
        Ok(new)
    })
}

#[cfg(test)]
#[path = "budget_tests.rs"]
mod tests;
