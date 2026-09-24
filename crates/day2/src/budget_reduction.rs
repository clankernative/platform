//! Explicit return of unused fixed capacity. Local fences commit before the
//! allocator credits a return. A crash can delay availability, never duplicate it.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityReturn {
    pub ledger_id: String,
    /// Concurrency is a persistent gauge and always uses window zero.
    pub window_start: i64,
    pub unit: String,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolReductionRequest {
    pub id: String,
    pub budget_id: String,
    pub expected: BudgetDefinition,
    pub definition: BudgetDefinition,
    pub effective_window: i64,
    /// Explicit amounts being returned, not new app caps. Empty means that the
    /// lower ceiling already covers all outstanding fixed allocations.
    pub returns: Vec<CapacityReturn>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolReduction {
    pub allocator_id: String,
    pub request: PoolReductionRequest,
    pub operator: String,
    pub allocations: Vec<AllocationReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityReturnReceipt {
    pub id: String,
    pub reduction_id: String,
    pub proposal_digest: String,
    pub allocator_id: String,
    pub budget_id: String,
    pub ledger_id: String,
    pub returns: Vec<CapacityReturn>,
    pub operator: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolReductionDecision {
    pub proposal: PoolReduction,
    pub completed: bool,
    pub operator: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolReductionStatus {
    pub proposal: PoolReduction,
    pub acknowledged_ledgers: BTreeSet<String>,
    pub decision: Option<PoolReductionDecision>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolOverview {
    pub allocator_id: String,
    pub definitions: BTreeMap<String, BudgetDefinition>,
    pub accounts: Vec<BudgetUsage>,
    pub allocations: Vec<AllocationReceipt>,
    pub returns: Vec<CapacityReturnReceipt>,
    pub reductions: Vec<PoolReductionStatus>,
}

fn create_tables(connection: &Connection, tables: &[(&str, &str)]) -> Result<()> {
    for (name, columns) in tables {
        let existed: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [name],
            |row| row.get(0),
        )?;
        connection.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {name}({columns}) STRICT"
        ))?;
        immutable_table(connection, name, !existed)?;
    }
    Ok(())
}

fn check_schema_version(connection: &Connection, meta: &str, tables: &[&str]) -> Result<()> {
    let column: bool = connection.query_row(&format!("SELECT EXISTS(SELECT 1 FROM pragma_table_info('{meta}') WHERE name='pool_return_version')"), [], |row| row.get(0))?;
    if !column {
        connection.execute_batch(&format!("ALTER TABLE {meta} ADD COLUMN pool_return_version INTEGER NOT NULL DEFAULT 0 CHECK(pool_return_version IN (0,1))"))?;
    }
    let version: i64 = connection.query_row(
        &format!("SELECT pool_return_version FROM {meta} WHERE singleton=1"),
        [],
        |row| row.get(0),
    )?;
    if version == 1 {
        for table in tables {
            let exists: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                [table],
                |row| row.get(0),
            )?;
            ensure!(exists, "budget_pool_fence_table_missing");
        }
    }
    Ok(())
}

/// These are SQL guards, not host callbacks: a connection opened by an older
/// runtime must obey a return committed by a newer operator. Once installed,
/// missing or modified guards are corruption rather than an upgrade opportunity.
fn admission_guards(
    connection: &Connection,
    meta: &str,
    guards: Vec<(String, String)>,
) -> Result<()> {
    let column: bool = connection.query_row(&format!("SELECT EXISTS(SELECT 1 FROM pragma_table_info('{meta}') WHERE name='capacity_guard_version')"), [], |row| row.get(0))?;
    if !column {
        connection.execute_batch(&format!("ALTER TABLE {meta} ADD COLUMN capacity_guard_version INTEGER NOT NULL DEFAULT 0 CHECK(capacity_guard_version IN (0,1))"))?;
    }
    let installed: bool = connection.query_row(
        &format!("SELECT capacity_guard_version=1 FROM {meta} WHERE singleton=1"),
        [],
        |row| row.get(0),
    )?;
    for (name, sql) in guards {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='trigger' AND name=?1)",
            [&name],
            |row| row.get(0),
        )?;
        ensure!(exists || !installed, "budget_capacity_trigger_missing");
        if !exists {
            connection.execute_batch(&sql)?;
        }
        crate::audit::validate_trigger(connection, &name, &sql)?;
    }
    connection.execute(
        &format!("UPDATE {meta} SET capacity_guard_version=1 WHERE singleton=1"),
        [],
    )?;
    Ok(())
}

fn local_admission_guard_sql() -> Vec<(String, String)> {
    // Match allocation_limit_in exactly, including persistent concurrency and
    // the current ledger after explicit restore recovery. Only built-in SQLite
    // functions are used, so trusted_schema=OFF and older connections work.
    let capacity = "(
        COALESCE((SELECT SUM(json_extract(a.receipt,'$.limits.' || NEW.unit))
            FROM day2_budget_allocations a
            WHERE a.budget_id=NEW.budget_id
              AND a.ledger_id=(SELECT ledger_id FROM day2_budget_meta WHERE singleton=1)
              AND (a.window_start=NEW.window_start OR NEW.unit='concurrency')),0)
        - COALESCE((SELECT SUM(json_extract(item.value,'$.amount'))
            FROM day2_budget_capacity_returns r, json_each(r.receipt,'$.returns') item
            WHERE r.budget_id=NEW.budget_id
              AND r.ledger_id=(SELECT ledger_id FROM day2_budget_meta WHERE singleton=1)
              AND json_extract(item.value,'$.unit')=NEW.unit
              AND (json_extract(item.value,'$.window_start')=NEW.window_start OR NEW.unit='concurrency')),0)
        )";
    // Settlement only reduces held and records the full actual usage, including
    // overruns. It must not be rejected for putting used above retained capacity.
    [
        ("insert", "INSERT", "NEW.scope='installation'", "1"),
        (
            "update",
            "UPDATE",
            "NEW.scope='installation' AND (NEW.limit_amount>OLD.limit_amount OR NEW.held>OLD.held)",
            "NEW.held>OLD.held",
        ),
    ]
    .into_iter()
    .map(|(suffix, action, when, holds_increase)| {
        let name = format!("day2_budget_accounts_capacity_{suffix}");
        let sql = format!(
            "CREATE TRIGGER {name} BEFORE {action} ON day2_budget_accounts
                WHEN {when}
                BEGIN SELECT CASE WHEN NEW.limit_amount>{capacity}
                    OR ({holds_increase} AND NEW.held>{capacity}-NEW.used)
                    THEN RAISE(ABORT,'budget_returned_capacity_exceeded') END; END"
        );
        (name, sql)
    })
    .collect()
}

/// A return receipt is useful only while its admission fence is still installed.
/// Acknowledgment must inspect existing proof, never install or repair that proof.
fn verify_local_admission_guards(connection: &Connection) -> Result<()> {
    let column: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('day2_budget_meta') WHERE name='capacity_guard_version')",
        [],
        |row| row.get(0),
    )?;
    ensure!(column, "budget_capacity_guards_not_installed");
    let installed: bool = connection.query_row(
        "SELECT capacity_guard_version=1 FROM day2_budget_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    ensure!(installed, "budget_capacity_guards_not_installed");
    for (name, sql) in local_admission_guard_sql() {
        crate::audit::validate_trigger(connection, &name, &sql)?;
    }
    Ok(())
}

fn allocator_admission_guards(connection: &Connection) -> Result<()> {
    let pending = "EXISTS(SELECT 1 FROM day2_company_budget_reductions r
        WHERE r.budget_id=NEW.id AND NOT EXISTS(
            SELECT 1 FROM day2_company_budget_reduction_decisions d WHERE d.id=r.id))";
    let historical = "NEW.unit<>'concurrency' AND EXISTS(
        SELECT 1 FROM day2_company_budget_reduction_decisions d
        WHERE json_extract(d.receipt,'$.completed')=1
          AND json_extract(d.receipt,'$.proposal.request.budget_id')=NEW.id
          AND json_extract(d.receipt,'$.proposal.request.effective_window')>NEW.window_start)";
    let mut guards: Vec<_> = [("insert", "INSERT", "1"),
        ("update", "UPDATE", "NEW.allocated>OLD.allocated OR NEW.limit_amount>OLD.limit_amount")]
        .into_iter().map(|(suffix, action, when)| {
            let name = format!("day2_company_budget_accounts_capacity_{suffix}");
            let sql = format!("CREATE TRIGGER {name} BEFORE {action} ON day2_company_budget_accounts
                WHEN {when}
                BEGIN
                    SELECT CASE WHEN {pending} THEN RAISE(ABORT,'budget_pool_reduction_pending') END;
                    SELECT CASE WHEN {historical} THEN RAISE(ABORT,'budget_pool_historical_window_closed') END;
                    SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM day2_company_budget_definitions d
                        WHERE d.id=NEW.id AND NEW.limit_amount>=0
                          AND NEW.limit_amount<=json_extract(d.definition,'$.limits.' || NEW.unit)
                          AND NEW.allocated<=NEW.limit_amount
                          AND NEW.revision=json_extract(d.definition,'$.revision')
                          AND NEW.period_seconds=json_extract(d.definition,'$.period_seconds'))
                        THEN RAISE(ABORT,'budget_company_capacity_exceeded') END;
                END");
            (name, sql)
        }).collect();
    // The pre-reduction allocator writes this state before updating accounts.
    // It cannot roll the definition back and then pass the capacity guard.
    for (suffix, action) in [("insert", "INSERT"), ("update", "UPDATE")] {
        let name = format!("day2_company_budget_definitions_version_{suffix}");
        let sql = format!("CREATE TRIGGER {name} BEFORE {action} ON day2_company_budget_definitions
            WHEN EXISTS(SELECT 1 FROM day2_company_budget_definitions d WHERE d.id=NEW.id AND (
                json_extract(NEW.definition,'$.revision')<json_extract(d.definition,'$.revision')
                OR (json_extract(NEW.definition,'$.revision')=json_extract(d.definition,'$.revision') AND NEW.definition<>d.definition)
                OR json_extract(NEW.definition,'$.scope')<>json_extract(d.definition,'$.scope')
                OR json_extract(NEW.definition,'$.period_seconds')<>json_extract(d.definition,'$.period_seconds')))
            BEGIN SELECT RAISE(ABORT,'budget_company_definition_conflict'); END");
        guards.push((name, sql));
    }
    let name = "day2_company_budget_definitions_no_delete".to_owned();
    guards.push((name.clone(), format!("CREATE TRIGGER {name} BEFORE DELETE ON day2_company_budget_definitions BEGIN SELECT RAISE(ABORT,'budget_company_definition_conflict'); END")));
    let name = "day2_company_budget_allocations_admission".to_owned();
    guards.push((name.clone(), format!("CREATE TRIGGER {name} BEFORE INSERT ON day2_company_budget_allocations
        BEGIN
            SELECT CASE WHEN EXISTS(SELECT 1 FROM day2_company_budget_reductions r
                WHERE r.budget_id=json_extract(NEW.receipt,'$.budget_id') AND NOT EXISTS(
                    SELECT 1 FROM day2_company_budget_reduction_decisions d WHERE d.id=r.id))
                THEN RAISE(ABORT,'budget_pool_reduction_pending') END;
            SELECT CASE WHEN EXISTS(SELECT 1 FROM day2_company_budget_reduction_decisions d
                WHERE json_extract(d.receipt,'$.completed')=1
                  AND json_extract(d.receipt,'$.proposal.request.budget_id')=json_extract(NEW.receipt,'$.budget_id')
                  AND json_extract(d.receipt,'$.proposal.request.effective_window')>json_extract(NEW.receipt,'$.window_start'))
                THEN RAISE(ABORT,'budget_pool_historical_window_closed') END;
        END")));
    admission_guards(connection, "day2_company_budget_meta", guards)
}

pub(super) fn upgrade_local(connection: &Connection) -> Result<()> {
    check_schema_version(
        connection,
        "day2_budget_meta",
        &["day2_budget_capacity_returns", "day2_budget_pool_proofs"],
    )?;
    create_tables(
        connection,
        &[
            (
                "day2_budget_capacity_returns",
                "id TEXT PRIMARY KEY,reduction_id TEXT NOT NULL,ledger_id TEXT NOT NULL,budget_id TEXT NOT NULL,receipt TEXT NOT NULL",
            ),
            (
                "day2_budget_pool_proofs",
                "id TEXT PRIMARY KEY,budget_id TEXT NOT NULL,receipt TEXT NOT NULL",
            ),
        ],
    )?;
    admission_guards(connection, "day2_budget_meta", local_admission_guard_sql())?;
    connection.execute(
        "UPDATE day2_budget_meta SET pool_return_version=1 WHERE singleton=1",
        [],
    )?;
    Ok(())
}

pub(super) fn upgrade_allocator(connection: &Connection) -> Result<()> {
    connection.execute_batch("SAVEPOINT day2_pool_upgrade")?;
    let result = (|| -> Result<()> {
        check_schema_version(
            connection,
            "day2_company_budget_meta",
            &[
                "day2_company_budget_reductions",
                "day2_company_budget_returns",
                "day2_company_budget_reduction_decisions",
            ],
        )?;
        create_tables(
            connection,
            &[
                (
                    "day2_company_budget_reductions",
                    "id TEXT PRIMARY KEY,budget_id TEXT NOT NULL,fingerprint TEXT NOT NULL,proposal TEXT NOT NULL",
                ),
                (
                    "day2_company_budget_returns",
                    "id TEXT PRIMARY KEY,reduction_id TEXT NOT NULL,ledger_id TEXT NOT NULL,receipt TEXT NOT NULL",
                ),
                (
                    "day2_company_budget_reduction_decisions",
                    "id TEXT PRIMARY KEY,receipt TEXT NOT NULL",
                ),
            ],
        )?;
        allocator_admission_guards(connection)?;
        connection.execute(
            "UPDATE day2_company_budget_meta SET pool_return_version=1 WHERE singleton=1",
            [],
        )?;
        Ok(())
    })();
    if result.is_ok() {
        connection.execute_batch("RELEASE day2_pool_upgrade")?;
    } else {
        connection.execute_batch("ROLLBACK TO day2_pool_upgrade; RELEASE day2_pool_upgrade")?;
    }
    result
}

fn read_values<T: serde::de::DeserializeOwned>(
    connection: &Connection,
    sql: &str,
) -> Result<Vec<T>> {
    let mut statement = connection.prepare(sql)?;
    statement
        .query_map([], |row| row.get::<_, String>(0))?
        .map(|row| crate::json::decode(row?.as_bytes()))
        .collect()
}

fn proposal_in(connection: &Connection, id: &str) -> Result<PoolReduction> {
    let raw: String = connection
        .query_row(
            "SELECT proposal FROM day2_company_budget_reductions WHERE id=?1",
            [id],
            |row| row.get(0),
        )
        .optional()?
        .context("budget_pool_reduction_missing")?;
    crate::json::decode(raw.as_bytes())
}

fn decision_in(connection: &Connection, id: &str) -> Result<Option<PoolReductionDecision>> {
    let raw: Option<String> = connection
        .query_row(
            "SELECT receipt FROM day2_company_budget_reduction_decisions WHERE id=?1",
            [id],
            |row| row.get(0),
        )
        .optional()?;
    raw.map(|raw| crate::json::decode(raw.as_bytes()))
        .transpose()
}

pub(super) fn allow_allocation(connection: &Connection, budget: &str, at: i64) -> Result<()> {
    let pending: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM day2_company_budget_reductions r WHERE budget_id=?1 AND NOT EXISTS(SELECT 1 FROM day2_company_budget_reduction_decisions d WHERE d.id=r.id))", [budget], |row| row.get(0))?;
    ensure!(!pending, "budget_pool_reduction_pending");
    for decision in read_values::<PoolReductionDecision>(
        connection,
        "SELECT receipt FROM day2_company_budget_reduction_decisions",
    )? {
        if decision.completed && decision.proposal.request.budget_id == budget {
            ensure!(
                at >= decision.proposal.request.effective_window,
                "budget_pool_historical_window_closed"
            );
        }
    }
    Ok(())
}

pub(super) fn remaining_local_capacity(
    connection: &Connection,
    budget: &str,
    at: i64,
    ledger: &str,
    unit: &str,
    total: u64,
) -> Result<u64> {
    let mut statement = connection.prepare(
        "SELECT receipt FROM day2_budget_capacity_returns WHERE budget_id=?1 AND ledger_id=?2",
    )?;
    let mut returned = 0;
    for raw in statement.query_map(params![budget, ledger], |row| row.get::<_, String>(0))? {
        let receipt: CapacityReturnReceipt = crate::json::decode(raw?.as_bytes())?;
        for item in receipt.returns {
            if item.unit == unit && (unit == "concurrency" || item.window_start == at) {
                returned = checked_add(returned, item.amount)?;
            }
        }
    }
    total
        .checked_sub(returned)
        .context("budget_pool_return_exceeds_imported_capacity")
}

pub(super) fn validate_local_definition(
    connection: &Connection,
    id: &str,
    old: &BudgetDefinition,
    new: &BudgetDefinition,
) -> Result<()> {
    if reject_installation_reduction(old, new).is_ok() {
        return Ok(());
    }
    let mut statement =
        connection.prepare("SELECT receipt FROM day2_budget_pool_proofs WHERE budget_id=?1")?;
    for raw in statement.query_map([id], |row| row.get::<_, String>(0))? {
        let proof: PoolReductionDecision = crate::json::decode(raw?.as_bytes())?;
        let approved = &proof.proposal.request.definition;
        if proof.completed
            && old.revision < approved.revision
            && approved.revision <= new.revision
            && approved.scope == new.scope
            && approved.period_seconds == new.period_seconds
            && (approved.revision != new.revision || approved == new)
            && reject_installation_reduction(approved, new).is_ok()
        {
            return Ok(());
        }
    }
    anyhow::bail!("budget_pool_reduction_proof_required")
}

pub(super) fn definition_effective_window(
    connection: &Connection,
    id: &str,
    new: &BudgetDefinition,
) -> Result<i64> {
    let mut effective = 0;
    let mut statement =
        connection.prepare("SELECT receipt FROM day2_budget_pool_proofs WHERE budget_id=?1")?;
    for raw in statement.query_map([id], |row| row.get::<_, String>(0))? {
        let proof: PoolReductionDecision = crate::json::decode(raw?.as_bytes())?;
        if proof.completed && proof.proposal.request.definition.revision <= new.revision {
            effective = effective.max(proof.proposal.request.effective_window);
        }
    }
    Ok(effective)
}

fn key(item: &CapacityReturn) -> (&str, i64, &str) {
    (&item.ledger_id, item.window_start, &item.unit)
}

impl Allocator {
    /// A read transaction gives a consistent review of allocations and returns.
    pub fn overview(&mut self) -> Result<PoolOverview> {
        let tx = self.connection.transaction()?;
        let mut definitions = BTreeMap::new();
        let mut statement =
            tx.prepare("SELECT id,definition FROM day2_company_budget_definitions ORDER BY id")?;
        for row in statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })? {
            let (id, raw) = row?;
            definitions.insert(id, crate::json::decode(raw.as_bytes())?);
        }
        drop(statement);
        let allocations = read_values(
            &tx,
            "SELECT receipt FROM day2_company_budget_allocations ORDER BY id",
        )?;
        let returns = read_values(
            &tx,
            "SELECT receipt FROM day2_company_budget_returns ORDER BY id",
        )?;
        let mut reductions = Vec::new();
        for proposal in read_values::<PoolReduction>(
            &tx,
            "SELECT proposal FROM day2_company_budget_reductions ORDER BY id",
        )? {
            reductions.push(status_in(&tx, proposal)?);
        }
        let allocator_id = tx.query_row("SELECT id FROM day2_company_budget_meta", [], |row| {
            row.get(0)
        })?;
        // Same implementation as inspect, kept under this snapshot transaction.
        let mut statement = tx.prepare("SELECT id,window_start,unit,limit_amount,allocated,revision FROM day2_company_budget_accounts ORDER BY id,window_start,unit")?;
        let mut accounts = Vec::new();
        for row in statement.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })? {
            let (budget_id, window_start, unit, cap, allocated, revision) = row?;
            let frozen = reductions
                .iter()
                .any(|r| r.proposal.request.budget_id == budget_id && r.decision.is_none());
            accounts.push(BudgetUsage {
                budget_id,
                window_start,
                scope: "installation".into(),
                subject: "fixed_allocations".into(),
                unit,
                limit: u64::try_from(cap)?,
                used: 0,
                reserved: u64::try_from(allocated)?,
                frozen,
                revision: u64::try_from(revision)?,
            });
        }
        drop(statement);
        tx.commit()?;
        Ok(PoolOverview {
            allocator_id,
            definitions,
            accounts,
            allocations,
            returns,
            reductions,
        })
    }

    pub fn reduction(&self, id: &str) -> Result<PoolReductionStatus> {
        status_in(&self.connection, proposal_in(&self.connection, id)?)
    }

    /// A proposal freezes new allocations, not app spending. Only the explicit
    /// subsequent app-local return transaction fences that app's unused capacity.
    pub fn propose_reduction(
        &mut self,
        request: &PoolReductionRequest,
        operator: &crate::authority_state::LocalOperator,
    ) -> Result<PoolReduction> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let fingerprint = crate::digest(&serde_json::to_vec(request)?);
        let old: Option<(String, String)> = tx
            .query_row(
                "SELECT fingerprint,proposal FROM day2_company_budget_reductions WHERE id=?1",
                [&request.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((old, raw)) = old {
            ensure!(old == fingerprint, "budget_pool_reduction_conflict");
            return crate::json::decode(raw.as_bytes());
        }
        ensure!(
            !request.id.is_empty()
                && request.id.len() <= 256
                && !request.reason.trim().is_empty()
                && request.reason.len() <= 4096,
            "budget_pool_reduction_identity_required"
        );
        request.definition.validate()?;
        request.expected.validate()?;
        integer(request.definition.revision)?;
        ensure!(
            request.definition.scope == BudgetScope::Installation
                && request.expected.scope == BudgetScope::Installation
                && request.expected.period_seconds == request.definition.period_seconds,
            "budget_account_shape_changed"
        );
        ensure!(
            request.definition.revision > request.expected.revision,
            "budget_revision_stale"
        );
        ensure!(
            window(&request.definition, request.effective_window)? == request.effective_window,
            "invalid_budget_allocation_window"
        );
        let mut reduced = false;
        for unit in UNITS {
            let (old, new) = (
                limit(&request.expected.limits, unit),
                limit(&request.definition.limits, unit),
            );
            ensure!(
                old.is_some() == new.is_some(),
                "budget_pool_reduction_meter_changed"
            );
            if let (Some(old), Some(new)) = (old, new) {
                ensure!(new <= old, "budget_pool_reduction_must_not_increase");
                reduced |= new < old;
            }
        }
        ensure!(reduced, "budget_pool_reduction_required");
        allow_allocation(&tx, &request.budget_id, request.effective_window)?;
        let current: String = tx
            .query_row(
                "SELECT definition FROM day2_company_budget_definitions WHERE id=?1",
                [&request.budget_id],
                |row| row.get(0),
            )
            .optional()?
            .context("budget_company_definition_missing")?;
        ensure!(
            crate::json::decode::<BudgetDefinition>(current.as_bytes())? == request.expected,
            "budget_pool_definition_changed"
        );
        let allocations: Vec<AllocationReceipt> = read_values::<AllocationReceipt>(
            &tx,
            "SELECT receipt FROM day2_company_budget_allocations ORDER BY id",
        )?
        .into_iter()
        .filter(|a| a.budget_id == request.budget_id)
        .collect();
        let mut available: BTreeMap<(String, i64, String), u64> = BTreeMap::new();
        for allocation in &allocations {
            for unit in UNITS {
                if let Some(value) = limit(&allocation.limits, unit) {
                    let key = (
                        allocation.ledger_id.clone(),
                        if unit == "concurrency" {
                            0
                        } else {
                            allocation.window_start
                        },
                        unit.to_owned(),
                    );
                    let total = available.entry(key).or_default();
                    *total = checked_add(*total, value)?;
                }
            }
        }
        for receipt in read_values::<CapacityReturnReceipt>(
            &tx,
            "SELECT receipt FROM day2_company_budget_returns",
        )? {
            if receipt.budget_id == request.budget_id {
                for item in receipt.returns {
                    let total = available
                        .get_mut(&(item.ledger_id, item.window_start, item.unit))
                        .context("budget_pool_return_corrupt")?;
                    *total = total
                        .checked_sub(item.amount)
                        .context("budget_pool_return_corrupt")?;
                }
            }
        }
        let mut seen = BTreeSet::new();
        for item in &request.returns {
            ensure!(seen.insert(key(item)), "budget_pool_duplicate_return");
            ensure!(
                item.amount > 0 && UNITS.contains(&item.unit.as_str()),
                "budget_pool_invalid_return"
            );
            ensure!(
                if item.unit == "concurrency" {
                    item.window_start == 0
                } else {
                    item.window_start >= request.effective_window
                        && window(&request.definition, item.window_start)? == item.window_start
                },
                "budget_pool_historical_return_forbidden"
            );
            let total = available
                .get_mut(&(item.ledger_id.clone(), item.window_start, item.unit.clone()))
                .context("budget_pool_return_unallocated")?;
            *total = total
                .checked_sub(item.amount)
                .context("budget_pool_return_exceeds_allocation")?;
        }
        let mut remaining: BTreeMap<(i64, String), u64> = BTreeMap::new();
        for ((_, at, unit), value) in available {
            if unit == "concurrency" || at >= request.effective_window {
                let total = remaining.entry((at, unit)).or_default();
                *total = checked_add(*total, value)?;
            }
        }
        for ((_, unit), value) in remaining {
            ensure!(
                value
                    <= limit(&request.definition.limits, &unit)
                        .context("budget_pool_invalid_unit")?,
                "budget_pool_returns_insufficient"
            );
        }
        let proposal = PoolReduction {
            allocator_id: tx.query_row("SELECT id FROM day2_company_budget_meta", [], |row| {
                row.get(0)
            })?,
            request: request.clone(),
            operator: operator.name().into(),
            allocations,
        };
        tx.execute(
            "INSERT INTO day2_company_budget_reductions VALUES(?1,?2,?3,?4)",
            params![
                request.id,
                request.budget_id,
                fingerprint,
                serde_json::to_string(&proposal)?
            ],
        )?;
        tx.commit()?;
        Ok(proposal)
    }

    /// Reads a committed local fence directly. A caller-provided JSON receipt
    /// cannot manufacture a return of live app capacity.
    pub fn acknowledge_return(
        &mut self,
        app: &Connection,
        reduction_id: &str,
        ledger_id: &str,
        _operator: &crate::authority_state::LocalOperator,
    ) -> Result<CapacityReturnReceipt> {
        ensure!(app.is_autocommit(), "budget_pool_return_must_be_committed");
        verify_local_admission_guards(app)?;
        immutable_table(app, "day2_budget_capacity_returns", false)?;
        let id = return_id(reduction_id, ledger_id)?;
        let raw: String = app
            .query_row(
                "SELECT receipt FROM day2_budget_capacity_returns WHERE id=?1",
                [&id],
                |row| row.get(0),
            )
            .optional()?
            .context("budget_pool_local_return_missing")?;
        let receipt: CapacityReturnReceipt = crate::json::decode(raw.as_bytes())?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let proposal = proposal_in(&tx, reduction_id)?;
        validate_return_receipt(&proposal, ledger_id, &receipt)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT receipt FROM day2_company_budget_returns WHERE id=?1",
                [&id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            ensure!(existing == raw, "budget_pool_return_conflict");
            return Ok(receipt);
        }
        // A cancellation retains returned capacity as available under the old
        // ceiling. Late acknowledgments remain safe and recover crash-stranding.
        for item in &receipt.returns {
            let changed = tx.execute("UPDATE day2_company_budget_accounts SET allocated=allocated-?4 WHERE id=?1 AND window_start=?2 AND unit=?3 AND allocated>=?4",params![receipt.budget_id,item.window_start,item.unit,integer(item.amount)?])?;
            ensure!(changed == 1, "budget_pool_return_corrupt");
        }
        tx.execute(
            "INSERT INTO day2_company_budget_returns VALUES(?1,?2,?3,?4)",
            params![id, reduction_id, ledger_id, raw],
        )?;
        tx.commit()?;
        Ok(receipt)
    }

    pub fn decide_reduction(
        &mut self,
        id: &str,
        complete: bool,
        operator: &crate::authority_state::LocalOperator,
    ) -> Result<PoolReductionDecision> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(receipt) = decision_in(&tx, id)? {
            ensure!(
                receipt.completed == complete,
                "budget_pool_decision_conflict"
            );
            return Ok(receipt);
        }
        let proposal = proposal_in(&tx, id)?;
        let request = &proposal.request;
        if complete {
            let status = status_in(&tx, proposal.clone())?;
            ensure!(
                request
                    .returns
                    .iter()
                    .all(|item| status.acknowledged_ledgers.contains(&item.ledger_id)),
                "budget_pool_returns_unacknowledged"
            );
            let mut statement = tx.prepare(
                "SELECT window_start,unit,allocated FROM day2_company_budget_accounts WHERE id=?1",
            )?;
            for row in statement.query_map([&request.budget_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })? {
                let (at, unit, allocated) = row?;
                if unit == "concurrency" || at >= request.effective_window {
                    ensure!(
                        u64::try_from(allocated)?
                            <= limit(&request.definition.limits, &unit)
                                .context("budget_pool_invalid_unit")?,
                        "budget_pool_returns_insufficient"
                    );
                }
            }
            drop(statement);
            for unit in UNITS {
                if let Some(cap) = limit(&request.definition.limits, unit) {
                    tx.execute("UPDATE day2_company_budget_accounts SET limit_amount=?3,revision=?4 WHERE id=?1 AND unit=?2 AND (window_start>=?5 OR unit='concurrency')",params![request.budget_id,unit,integer(cap)?,integer(request.definition.revision)?,request.effective_window])?;
                }
            }
            tx.execute(
                "UPDATE day2_company_budget_definitions SET definition=?2 WHERE id=?1",
                params![
                    request.budget_id,
                    serde_json::to_string(&request.definition)?
                ],
            )?;
        }
        let receipt = PoolReductionDecision {
            proposal,
            completed: complete,
            operator: operator.name().into(),
        };
        tx.execute(
            "INSERT INTO day2_company_budget_reduction_decisions VALUES(?1,?2)",
            params![id, serde_json::to_string(&receipt)?],
        )?;
        tx.commit()?;
        Ok(receipt)
    }
}

fn status_in(connection: &Connection, proposal: PoolReduction) -> Result<PoolReductionStatus> {
    let mut statement = connection
        .prepare("SELECT ledger_id FROM day2_company_budget_returns WHERE reduction_id=?1")?;
    let acknowledged_ledgers = statement
        .query_map([&proposal.request.id], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let decision = decision_in(connection, &proposal.request.id)?;
    Ok(PoolReductionStatus {
        proposal,
        acknowledged_ledgers,
        decision,
    })
}

fn return_id(reduction: &str, ledger: &str) -> Result<String> {
    Ok(crate::digest(&serde_json::to_vec(&(
        "day2-pool-return-v1",
        reduction,
        ledger,
    ))?))
}

fn validate_return_receipt(
    proposal: &PoolReduction,
    ledger: &str,
    receipt: &CapacityReturnReceipt,
) -> Result<()> {
    let returns: Vec<_> = proposal
        .request
        .returns
        .iter()
        .filter(|item| item.ledger_id == ledger)
        .cloned()
        .collect();
    ensure!(
        !returns.is_empty()
            && receipt.id == return_id(&proposal.request.id, ledger)?
            && receipt.reduction_id == proposal.request.id
            && receipt.proposal_digest == crate::digest(&serde_json::to_vec(proposal)?)
            && receipt.allocator_id == proposal.allocator_id
            && receipt.budget_id == proposal.request.budget_id
            && receipt.ledger_id == ledger
            && receipt.returns == returns,
        "budget_pool_return_conflict"
    );
    Ok(())
}

/// Atomically retires only explicitly reviewed, unused local capacity. Importing
/// all committed source allocations first makes delayed original imports safe.
pub fn return_capacity_in(
    connection: &Connection,
    allocator: &Allocator,
    reduction_id: &str,
    operator: &crate::authority_state::LocalOperator,
) -> Result<CapacityReturnReceipt> {
    atomic(connection, || {
        upgrade_local(connection)?;
        let (ledger_id, restored) = ledger(connection)?;
        ensure!(!restored, "budget_restore_reconciliation_required");
        let proposal = proposal_in(&allocator.connection, reduction_id)?;
        let id = return_id(reduction_id, &ledger_id)?;
        let existing: Option<String> = connection
            .query_row(
                "SELECT receipt FROM day2_budget_capacity_returns WHERE id=?1",
                [&id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(raw) = existing {
            let receipt = crate::json::decode(raw.as_bytes())?;
            validate_return_receipt(&proposal, &ledger_id, &receipt)?;
            return Ok(receipt);
        }
        ensure!(
            decision_in(&allocator.connection, reduction_id)?.is_none(),
            "budget_pool_reduction_already_decided"
        );
        let returns: Vec<_> = proposal
            .request
            .returns
            .iter()
            .filter(|item| item.ledger_id == ledger_id)
            .cloned()
            .collect();
        ensure!(
            !returns.is_empty(),
            "budget_pool_no_reviewed_return_for_app"
        );
        for allocation in proposal
            .allocations
            .iter()
            .filter(|a| a.ledger_id == ledger_id)
        {
            install_allocation_in(connection, allocator, allocation, operator)?;
        }
        for item in &returns {
            let total = allocation_limit_in(
                connection,
                &proposal.request.budget_id,
                item.window_start,
                &ledger_id,
                &item.unit,
            )?;
            let remaining = total
                .checked_sub(item.amount)
                .context("budget_pool_return_exceeds_allocation")?;
            let liability:i64=connection.query_row("SELECT COALESCE(SUM(used+held),0) FROM day2_budget_accounts WHERE budget_id=?1 AND scope='installation' AND window_start=?2 AND unit=?3",params![proposal.request.budget_id,item.window_start,item.unit],|row|row.get(0))?;
            ensure!(
                u64::try_from(liability)? <= remaining,
                "budget_pool_return_would_remove_liability"
            );
            connection.execute("UPDATE day2_budget_accounts SET limit_amount=MIN(limit_amount,?4) WHERE budget_id=?1 AND scope='installation' AND window_start=?2 AND unit=?3",params![proposal.request.budget_id,item.window_start,item.unit,integer(remaining)?])?;
        }
        let receipt = CapacityReturnReceipt {
            id,
            reduction_id: reduction_id.into(),
            proposal_digest: crate::digest(&serde_json::to_vec(&proposal)?),
            allocator_id: proposal.allocator_id,
            budget_id: proposal.request.budget_id,
            ledger_id,
            returns,
            operator: operator.name().into(),
        };
        connection.execute(
            "INSERT INTO day2_budget_capacity_returns VALUES(?1,?2,?3,?4,?5)",
            params![
                receipt.id,
                receipt.reduction_id,
                receipt.ledger_id,
                receipt.budget_id,
                serde_json::to_string(&receipt)?
            ],
        )?;
        Ok(receipt)
    })
}

/// Proof import verifies the central immutable decision, rather than trusting
/// an authoring catalog to claim that other apps returned their allocations.
pub fn install_pool_reduction_in(
    connection: &Connection,
    allocator: &Allocator,
    id: &str,
    _operator: &crate::authority_state::LocalOperator,
) -> Result<PoolReductionDecision> {
    atomic(connection, || {
        upgrade_local(connection)?;
        let receipt =
            decision_in(&allocator.connection, id)?.context("budget_pool_reduction_pending")?;
        ensure!(receipt.completed, "budget_pool_reduction_cancelled");
        let allocator_id = allocator.id()?;
        ensure!(
            receipt.proposal.allocator_id == allocator_id,
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
            ensure!(pinned == allocator_id, "budget_allocator_identity_mismatch");
        } else {
            connection.execute(
                "INSERT INTO day2_budget_allocator VALUES(1,?1)",
                [&allocator_id],
            )?;
        }
        let raw = serde_json::to_string(&receipt)?;
        let existing: Option<String> = connection
            .query_row(
                "SELECT receipt FROM day2_budget_pool_proofs WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            ensure!(existing == raw, "budget_pool_reduction_conflict");
        } else {
            connection.execute(
                "INSERT INTO day2_budget_pool_proofs VALUES(?1,?2,?3)",
                params![id, receipt.proposal.request.budget_id, raw],
            )?;
        }
        Ok(receipt)
    })
}
