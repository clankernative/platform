use super::*;
use rusqlite::TransactionBehavior;

fn database() -> Result<Connection> {
    let mut connection = Connection::open_in_memory()?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    upgrade(&tx)?;
    tx.commit()?;
    Ok(connection)
}

#[test]
fn reviewed_unknown_usage_reconciliation_is_exact_and_never_changes_known_history() -> Result<()> {
    let mut db = database()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let budgets = BTreeMap::from([("app".into(), definition(BudgetScope::App, 10))]);
    let mut attempt = request("physical-unknown", budgets.clone());
    attempt.quote.calls = 4;
    let reservation = reserve(&mut db, &attempt)?;
    let request = UsageReconciliation {
        id: "reconcile-one".into(),
        ledger_id: reservation.ledger_id.clone(),
        reservation: reservation.id.clone(),
        actual: Consumption {
            calls: 2,
            bytes: 50,
            ..Consumption::default()
        },
        reason: "Provider reports a terminal outcome".into(),
        proof: "provider-request/terminal-receipt-4821".into(),
    };
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert!(
        reconcile_usage_in(&tx, &operator, &request)
            .unwrap_err()
            .to_string()
            .contains("requires_unknown")
    );
    settle_in(&tx, &reservation, &Settlement::Unknown)?;
    tx.commit()?;
    assert_eq!(inspect(&mut db)?.unknown_usage.len(), 1);
    // Standalone budget databases have no resource journal. When present, only
    // its bounded typed correlation fields are exposed for operator review.
    db.execute_batch("CREATE TABLE day2_resource_correlations(attempt TEXT PRIMARY KEY,exchanges TEXT NOT NULL) STRICT")?;
    db.execute("INSERT INTO day2_resource_correlations VALUES(?1,?2)",params![reservation.id,r#"[{"phase":"operation","http_status":500,"request_id":"req_4821","statement_handle":null}]"#])?;
    assert_eq!(
        inspect(&mut db)?.unknown_usage[0].exchanges[0]["request_id"],
        "req_4821"
    );
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut missing = request.clone();
    missing.proof.clear();
    assert!(reconcile_usage_in(&tx, &operator, &missing).is_err());
    let receipt = reconcile_usage_in(&tx, &operator, &request)?;
    assert_eq!(receipt.operator, "operator");
    assert!(!receipt.settlement.overrun);
    assert_eq!(reconcile_usage_in(&tx, &operator, &request)?, receipt);
    let mut changed = request.clone();
    changed.actual.calls = 1;
    assert!(
        reconcile_usage_in(&tx, &operator, &changed)
            .unwrap_err()
            .to_string()
            .contains("conflict")
    );
    changed.id = "different-review".into();
    assert!(
        reconcile_usage_in(&tx, &operator, &changed)
            .unwrap_err()
            .to_string()
            .contains("already_settled")
    );
    // The original uncertainty record remains immutable evidence.
    assert_eq!(
        tx.query_row("SELECT COUNT(*) FROM day2_budget_unknown", [], |row| row
            .get::<_, i64>(0))?,
        1
    );
    assert!(
        tx.execute("DELETE FROM day2_budget_usage_reconciliations", [])
            .is_err()
    );
    tx.commit()?;
    let usage = inspect(&mut db)?;
    assert_eq!((usage.accounts[0].used, usage.accounts[0].reserved), (2, 0));
    assert!(usage.unknown_usage.is_empty());
    assert_eq!(usage.outstanding_attempts, 0);
    Ok(())
}

#[test]
fn reconciled_overrun_still_freezes_admission_and_restore_cannot_assert_old_usage() -> Result<()> {
    let mut db = database()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let budgets = BTreeMap::from([("app".into(), definition(BudgetScope::App, 10))]);
    let reservation = reserve(&mut db, &request("unknown", budgets.clone()))?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    settle_in(&tx, &reservation, &Settlement::Unknown)?;
    let reconciliation = UsageReconciliation {
        id: "review-overrun".into(),
        ledger_id: reservation.ledger_id.clone(),
        reservation: reservation.id.clone(),
        actual: Consumption {
            calls: 2,
            bytes: 100,
            ..Consumption::default()
        },
        reason: "Confirmed full provider usage".into(),
        proof: "provider-invoice-line/7".into(),
    };
    let receipt = reconcile_usage_in(&tx, &operator, &reconciliation)?;
    assert!(receipt.settlement.overrun);
    tx.commit()?;
    assert!(inspect(&mut db)?.frozen_after_overrun);
    assert!(reserve(&mut db, &request("blocked", budgets.clone())).is_err());
    let mut other = database()?;
    let old = reserve(&mut other, &request("old-unknown", budgets))?;
    let tx = other.transaction_with_behavior(TransactionBehavior::Immediate)?;
    settle_in(&tx, &old, &Settlement::Unknown)?;
    invalidate_restored(&tx)?;
    let copied = UsageReconciliation {
        id: "copied".into(),
        ledger_id: old.ledger_id,
        reservation: old.id,
        ..reconciliation
    };
    assert!(
        reconcile_usage_in(&tx, &operator, &copied)
            .unwrap_err()
            .to_string()
            .contains("restore_reconciliation_required")
    );
    tx.commit()?;
    assert_eq!(inspect(&mut other)?.accounts[0].reserved, 1);
    Ok(())
}

fn definition(scope: BudgetScope, calls: u64) -> BudgetDefinition {
    BudgetDefinition {
        revision: 1,
        scope,
        period_seconds: 60,
        limits: BudgetLimits {
            calls: Some(calls),
            ..BudgetLimits::default()
        },
    }
}

fn request(id: &str, budgets: BTreeMap<String, BudgetDefinition>) -> ReservationRequest {
    ReservationRequest {
        id: id.into(),
        binding: "authority+resource+input".into(),
        context: BudgetContext {
            app: "app".into(),
            actor: "alice".into(),
            connection: "physical-mailbox".into(),
            invocation_root: "root".into(),
            now: 100,
        },
        budgets,
        quote: Consumption {
            calls: 1,
            bytes: 100,
            cost_microunits: 0,
            concurrency: 1,
        },
    }
}

fn reserve(connection: &mut Connection, request: &ReservationRequest) -> Result<Reservation> {
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = reserve_in(&tx, request)?;
    tx.commit()?;
    Ok(result)
}

fn known(
    connection: &mut Connection,
    reservation: &Reservation,
    actual: Consumption,
) -> Result<SettlementReceipt> {
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = settle_in(&tx, reservation, &Settlement::Known { actual })?;
    tx.commit()?;
    Ok(result)
}

fn inspect(connection: &mut Connection) -> Result<LedgerStatus> {
    let tx = connection.transaction()?;
    let result = inspect_in(&tx)?;
    tx.commit()?;
    Ok(result)
}

#[test]
fn admission_requires_transaction_and_rolls_back_all_accounts_on_failure() -> Result<()> {
    let mut connection = database()?;
    let first = request(
        "first",
        BTreeMap::from([("z-limited".into(), definition(BudgetScope::App, 1))]),
    );
    assert!(
        reserve_in(&connection, &first)
            .unwrap_err()
            .to_string()
            .contains("requires_transaction")
    );
    reserve(&mut connection, &first)?;
    let blocked = request(
        "blocked",
        BTreeMap::from([
            ("a-roomy".into(), definition(BudgetScope::App, 10)),
            ("z-limited".into(), definition(BudgetScope::App, 1)),
        ]),
    );
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert!(
        reserve_in(&tx, &blocked)
            .unwrap_err()
            .to_string()
            .contains("exhausted")
    );
    // Catching the error and committing unrelated work cannot leave a partial hold.
    tx.execute_batch("CREATE TABLE unrelated(value INTEGER); INSERT INTO unrelated VALUES(1)")?;
    tx.commit()?;
    let status = inspect(&mut connection)?;
    assert_eq!(status.accounts.len(), 1);
    assert_eq!(status.accounts[0].reserved, 1);
    assert_eq!(status.outstanding_attempts, 1);
    Ok(())
}

#[test]
fn immutable_attempt_is_idempotent_and_keeps_its_first_window() -> Result<()> {
    let mut connection = database()?;
    let mut change = request(
        "attempt",
        BTreeMap::from([("app".into(), definition(BudgetScope::App, 2))]),
    );
    let original = reserve(&mut connection, &change)?;
    change.context.now = 300;
    assert_eq!(reserve(&mut connection, &change)?, original);
    let status = inspect(&mut connection)?;
    assert_eq!(status.accounts.len(), 1);
    assert_eq!(status.accounts[0].window_start, 60);
    assert_eq!(status.accounts[0].reserved, 1);
    change.binding = "substituted-input".into();
    assert!(
        reserve(&mut connection, &change)
            .unwrap_err()
            .to_string()
            .contains("idempotency_conflict")
    );
    Ok(())
}

#[test]
fn unknown_holds_then_one_immutable_settlement_releases_unused_quote() -> Result<()> {
    let mut connection = database()?;
    let mut def = definition(BudgetScope::App, 10);
    def.limits.bytes = Some(200);
    def.limits.concurrency = Some(1);
    let first = request("attempt", BTreeMap::from([("budget".into(), def.clone())]));
    let reservation = reserve(&mut connection, &first)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert!(!settle_in(&tx, &reservation, &Settlement::Unknown)?.settled);
    assert!(!settle_in(&tx, &reservation, &Settlement::Unknown)?.settled);
    tx.commit()?;
    let mut next = request("next", first.budgets.clone());
    next.context.now = 200;
    assert!(
        reserve(&mut connection, &next)
            .unwrap_err()
            .to_string()
            .contains("concurrency")
    );
    let actual = Consumption {
        calls: 1,
        bytes: 25,
        ..Consumption::default()
    };
    let receipt = known(&mut connection, &reservation, actual.clone())?;
    assert_eq!(known(&mut connection, &reservation, actual)?, receipt);
    assert!(
        known(
            &mut connection,
            &reservation,
            Consumption {
                calls: 1,
                bytes: 26,
                ..Consumption::default()
            }
        )
        .unwrap_err()
        .to_string()
        .contains("settlement_conflict")
    );
    reserve(&mut connection, &next)?;
    let status = inspect(&mut connection)?;
    assert_eq!(status.known_usage.bytes, 25);
    assert_eq!(status.known_usage.calls, 1);
    assert_eq!(
        status
            .accounts
            .iter()
            .find(|a| a.unit == "bytes" && a.window_start == 60)
            .unwrap()
            .reserved,
        0
    );
    Ok(())
}

#[test]
fn overrun_records_full_cost_and_freezes_admission() -> Result<()> {
    let mut connection = database()?;
    let mut def = definition(BudgetScope::App, 100);
    def.limits.cost_microunits = Some(100);
    let mut first = request(
        "paid-attempt",
        BTreeMap::from([("paid".into(), def.clone())]),
    );
    first.quote.cost_microunits = 80;
    let reservation = reserve(&mut connection, &first)?;
    let receipt = known(
        &mut connection,
        &reservation,
        Consumption {
            calls: 1,
            cost_microunits: 130,
            ..Consumption::default()
        },
    )?;
    assert!(receipt.overrun);
    let status = inspect(&mut connection)?;
    let cost = status
        .accounts
        .iter()
        .find(|a| a.unit == "cost_microunits")
        .unwrap();
    assert_eq!((cost.used, cost.reserved, cost.frozen), (130, 0, true));
    let mut next = request("next", first.budgets);
    next.budgets.get_mut("paid").unwrap().revision = 2;
    next.budgets.get_mut("paid").unwrap().limits.cost_microunits = Some(1_000);
    assert!(
        reserve(&mut connection, &next)
            .unwrap_err()
            .to_string()
            .contains("frozen")
    );
    Ok(())
}

#[test]
fn quota_changes_preserve_usage_and_cannot_change_period_or_scope() -> Result<()> {
    let mut connection = database()?;
    let first = request(
        "first",
        BTreeMap::from([("stable".into(), definition(BudgetScope::App, 1))]),
    );
    let reservation = reserve(&mut connection, &first)?;
    known(
        &mut connection,
        &reservation,
        Consumption {
            calls: 1,
            ..Consumption::default()
        },
    )?;
    let mut next = request("next", first.budgets.clone());
    next.budgets.get_mut("stable").unwrap().revision = 2;
    next.budgets.get_mut("stable").unwrap().limits.calls = Some(2);
    reserve(&mut connection, &next)?;
    let status = inspect(&mut connection)?;
    assert_eq!(
        (
            status.accounts[0].used,
            status.accounts[0].reserved,
            status.accounts[0].limit
        ),
        (1, 1, 2)
    );
    next.id = "changed-period".into();
    next.context.now = 300;
    next.budgets.get_mut("stable").unwrap().period_seconds = 120;
    assert!(
        reserve(&mut connection, &next)
            .unwrap_err()
            .to_string()
            .contains("shape_changed")
    );
    next.budgets.get_mut("stable").unwrap().period_seconds = 60;
    next.budgets.get_mut("stable").unwrap().scope = BudgetScope::Actor;
    assert!(
        reserve(&mut connection, &next)
            .unwrap_err()
            .to_string()
            .contains("shape_changed")
    );
    Ok(())
}

#[test]
fn admitted_usage_settling_after_a_quota_reduction_is_not_an_adapter_overrun() -> Result<()> {
    let mut connection = database()?;
    let mut first = request(
        "already-admitted",
        BTreeMap::from([("stable".into(), definition(BudgetScope::App, 100))]),
    );
    first.quote.calls = 80;
    let reservation = reserve(&mut connection, &first)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    settle_in(&tx, &reservation, &Settlement::Unknown)?;
    let mut lower = first.budgets.clone();
    lower.get_mut("stable").unwrap().revision = 2;
    lower.get_mut("stable").unwrap().limits.calls = Some(60);
    sync_definitions_in(&tx, &lower)?;
    tx.commit()?;
    let pending = inspect(&mut connection)?;
    assert_eq!(
        (pending.accounts[0].reserved, pending.accounts[0].limit),
        (80, 60)
    );
    let receipt = known(
        &mut connection,
        &reservation,
        Consumption {
            calls: 80,
            ..Consumption::default()
        },
    )?;
    assert!(!receipt.overrun);
    let status = inspect(&mut connection)?;
    assert_eq!(
        (status.accounts[0].used, status.accounts[0].reserved),
        (80, 0)
    );
    assert_eq!(status.known_usage.calls, 80);
    assert!(!status.frozen_after_overrun);
    assert!(!status.accounts[0].frozen);
    assert!(status.overruns.is_empty());
    assert!(
        reserve(&mut connection, &request("new-work", lower))
            .unwrap_err()
            .to_string()
            .contains("exhausted")
    );
    Ok(())
}

#[test]
fn root_children_share_limits_even_across_time_windows() -> Result<()> {
    let mut connection = database()?;
    let first = request(
        "parent-attempt",
        BTreeMap::from([(
            "root-cap".into(),
            definition(BudgetScope::InvocationRoot, 1),
        )]),
    );
    let reservation = reserve(&mut connection, &first)?;
    known(
        &mut connection,
        &reservation,
        Consumption {
            calls: 1,
            ..Consumption::default()
        },
    )?;
    let mut child = request("child-attempt", first.budgets.clone());
    child.context.now = 500;
    assert!(
        reserve(&mut connection, &child)
            .unwrap_err()
            .to_string()
            .contains("exhausted")
    );
    child.context.invocation_root = "another-root".into();
    reserve(&mut connection, &child)?;
    Ok(())
}

#[test]
fn actor_and_physical_connection_accounts_do_not_depend_on_grant_binding() -> Result<()> {
    let mut connection = database()?;
    let first = request(
        "first",
        BTreeMap::from([
            ("actor".into(), definition(BudgetScope::Actor, 1)),
            ("connection".into(), definition(BudgetScope::Connection, 1)),
        ]),
    );
    reserve(&mut connection, &first)?;
    let mut next = request("second", first.budgets);
    next.binding = "new-resource-handle-same-provider".into();
    next.context.actor = "bob".into();
    assert!(
        reserve(&mut connection, &next)
            .unwrap_err()
            .to_string()
            .contains("connection")
    );
    // The failed connection admission also rolls back the new actor account.
    assert_eq!(inspect(&mut connection)?.accounts.len(), 2);
    Ok(())
}

#[test]
fn restore_keeps_usage_and_unknown_holds_but_fences_all_attempts() -> Result<()> {
    let mut connection = database()?;
    let first = request(
        "unknown",
        BTreeMap::from([("app".into(), definition(BudgetScope::App, 10))]),
    );
    let reservation = reserve(&mut connection, &first)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    settle_in(&tx, &reservation, &Settlement::Unknown)?;
    invalidate_restored(&tx)?;
    tx.commit()?;
    let status = inspect(&mut connection)?;
    assert!(status.frozen_after_restore);
    assert_eq!(status.accounts[0].reserved, 1);
    assert!(
        reserve(&mut connection, &first)
            .unwrap_err()
            .to_string()
            .contains("reconciliation_required")
    );
    assert!(
        known(&mut connection, &reservation, Consumption::default())
            .unwrap_err()
            .to_string()
            .contains("reconciliation_required")
    );
    Ok(())
}

#[test]
fn no_budget_still_accounts_actual_physical_calls_and_bytes() -> Result<()> {
    let mut connection = database()?;
    let attempt = reserve(
        &mut connection,
        &request("unlimited-local", BTreeMap::new()),
    )?;
    known(
        &mut connection,
        &attempt,
        Consumption {
            calls: 1,
            bytes: 79,
            ..Consumption::default()
        },
    )?;
    let status = inspect(&mut connection)?;
    assert!(status.accounts.is_empty());
    assert_eq!(
        status.known_usage,
        Consumption {
            calls: 1,
            bytes: 79,
            ..Consumption::default()
        }
    );
    Ok(())
}

#[test]
fn concurrent_writers_cannot_both_take_the_last_unit() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("budget.sqlite");
    let mut connection = crate::store::open(&path)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    upgrade(&tx)?;
    tx.commit()?;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|index| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || -> Result<bool> {
                let mut connection = crate::store::open(&path)?;
                barrier.wait();
                let request = request(
                    &format!("attempt-{index}"),
                    BTreeMap::from([("last".into(), definition(BudgetScope::App, 1))]),
                );
                match reserve(&mut connection, &request) {
                    Ok(_) => Ok(true),
                    Err(error) if error.to_string().contains("exhausted") => Ok(false),
                    Err(error) => Err(error),
                }
            })
        })
        .collect();
    let mut accepted = 0;
    for worker in workers {
        if worker.join().unwrap()? {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 1);
    assert_eq!(inspect(&mut connection)?.accounts[0].reserved, 1);
    Ok(())
}

#[test]
fn reservations_and_settlements_reject_sql_replace() -> Result<()> {
    let mut connection = database()?;
    let reservation = reserve(&mut connection, &request("attempt", BTreeMap::new()))?;
    known(
        &mut connection,
        &reservation,
        Consumption {
            calls: 1,
            ..Consumption::default()
        },
    )?;
    for table in ["day2_budget_reservations", "day2_budget_settlements"] {
        assert!(
            connection
                .execute(
                    &format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table}"),
                    []
                )
                .is_err()
        );
        assert!(
            connection
                .execute(&format!("DELETE FROM {table}"), [])
                .is_err()
        );
    }
    Ok(())
}

fn allocation(id: &str, ledger_id: &str, calls: u64, company_limit: u64) -> AllocationRequest {
    AllocationRequest {
        id: id.into(),
        budget_id: "company".into(),
        definition: definition(BudgetScope::Installation, company_limit),
        window_start: 60,
        ledger_id: ledger_id.into(),
        limits: BudgetLimits {
            calls: Some(calls),
            ..BudgetLimits::default()
        },
    }
}

fn install(
    connection: &mut Connection,
    allocator: &Allocator,
    receipt: &AllocationReceipt,
    operator: &crate::authority_state::LocalOperator,
) -> Result<()> {
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    install_allocation_in(&tx, allocator, receipt, operator)?;
    tx.commit()?;
    Ok(())
}

fn reduction_request(
    id: &str,
    old: u64,
    new: u64,
    returns: &[(&str, u64)],
) -> PoolReductionRequest {
    let expected = definition(BudgetScope::Installation, old);
    let mut next = definition(BudgetScope::Installation, new);
    next.revision = 2;
    PoolReductionRequest {
        id: id.into(),
        budget_id: "company".into(),
        expected,
        definition: next,
        effective_window: 60,
        reason: "Review and return unused app capacity".into(),
        returns: returns
            .iter()
            .map(|(ledger, amount)| CapacityReturn {
                ledger_id: (*ledger).into(),
                window_start: 60,
                unit: "calls".into(),
                amount: *amount,
            })
            .collect(),
    }
}

fn commit_return(
    db: &mut Connection,
    allocator: &Allocator,
    id: &str,
    operator: &crate::authority_state::LocalOperator,
) -> Result<CapacityReturnReceipt> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = return_capacity_in(&tx, allocator, id, operator)?;
    tx.commit()?;
    Ok(result)
}

#[test]
fn coordinated_reduction_fences_two_live_apps_before_lowering_company_cap() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let mut allocator = Allocator::create(&directory.path().join("company.sqlite"), &operator)?;
    let mut first = database()?;
    let mut second = database()?;
    let first_id = inspect(&mut first)?.ledger_id;
    let second_id = inspect(&mut second)?.ledger_id;
    for (id, ledger, db) in [("a", &first_id, &mut first), ("b", &second_id, &mut second)] {
        let receipt = allocator.allocate(&allocation(id, ledger, 10, 20), &operator)?;
        install(db, &allocator, &receipt, &operator)?;
    }
    let budgets = BTreeMap::from([("company".into(), definition(BudgetScope::Installation, 20))]);
    let known_attempt = reserve(&mut first, &request("known", budgets.clone()))?;
    known(
        &mut first,
        &known_attempt,
        Consumption {
            calls: 1,
            bytes: 100,
            ..Consumption::default()
        },
    )?;
    let unknown = reserve(&mut first, &request("unknown", budgets.clone()))?;
    let tx = first.transaction_with_behavior(TransactionBehavior::Immediate)?;
    settle_in(&tx, &unknown, &Settlement::Unknown)?;
    tx.commit()?;
    let change = reduction_request("reduce", 20, 10, &[(&first_id, 6), (&second_id, 4)]);
    let proposal = allocator.propose_reduction(&change, &operator)?;
    assert_eq!(allocator.propose_reduction(&change, &operator)?, proposal);
    assert!(
        allocator
            .allocate(&allocation("blocked-new", &first_id, 1, 20), &operator)
            .unwrap_err()
            .to_string()
            .contains("reduction_pending")
    );
    assert!(
        allocator
            .decide_reduction("reduce", true, &operator)
            .unwrap_err()
            .to_string()
            .contains("unacknowledged")
    );
    let first_return = commit_return(&mut first, &allocator, "reduce", &operator)?;
    assert_eq!(
        commit_return(&mut first, &allocator, "reduce", &operator)?,
        first_return
    );
    // Local fence commits before the central credit: a crash cannot spend twice.
    assert_eq!(allocator.inspect()?[0].reserved, 20);
    let mut too_much = request("fenced", budgets.clone());
    too_much.quote.calls = 3;
    assert!(reserve(&mut first, &too_much).is_err());
    allocator.acknowledge_return(&first, "reduce", &first_id, &operator)?;
    allocator.acknowledge_return(&first, "reduce", &first_id, &operator)?;
    assert_eq!(allocator.inspect()?[0].reserved, 14);
    commit_return(&mut second, &allocator, "reduce", &operator)?;
    allocator.acknowledge_return(&second, "reduce", &second_id, &operator)?;
    let completion = allocator.decide_reduction("reduce", true, &operator)?;
    assert_eq!(
        allocator.decide_reduction("reduce", true, &operator)?,
        completion
    );
    let pool = allocator.inspect()?;
    assert_eq!((pool[0].limit, pool[0].reserved), (10, 10));
    let state = inspect(&mut first)?;
    assert_eq!(
        (
            state.accounts[0].used,
            state.accounts[0].reserved,
            state.accounts[0].limit
        ),
        (1, 1, 4)
    );
    assert_eq!(state.outstanding_attempts, 1);
    // An unchanged active grant remains fenced by its reduced local capacity.
    let mut fits = request("fits", budgets);
    fits.quote.calls = 2;
    reserve(&mut first, &fits)?;
    Ok(())
}

#[test]
fn delayed_allocation_import_and_cached_receipt_cannot_resurrect_returned_capacity() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let mut allocator = Allocator::create(&directory.path().join("company.sqlite"), &operator)?;
    let mut db = database()?;
    let ledger = inspect(&mut db)?.ledger_id;
    let first = allocator.allocate(&allocation("imported", &ledger, 6, 10), &operator)?;
    let delayed_request = allocation("not-imported", &ledger, 4, 10);
    let delayed = allocator.allocate(&delayed_request, &operator)?;
    install(&mut db, &allocator, &first, &operator)?;
    let change = reduction_request("trim", 10, 3, &[(&ledger, 7)]);
    allocator.propose_reduction(&change, &operator)?;
    commit_return(&mut db, &allocator, "trim", &operator)?;
    // Fence imported both allocations and subtracted seven, before central ack.
    assert_eq!(allocator.allocate(&delayed_request, &operator)?, delayed);
    install(&mut db, &allocator, &delayed, &operator)?;
    install(&mut db, &allocator, &first, &operator)?;
    let budgets = BTreeMap::from([("company".into(), definition(BudgetScope::Installation, 10))]);
    let mut work = request("large", budgets.clone());
    work.quote.calls = 4;
    assert!(reserve(&mut db, &work).is_err());
    work.id = "small".into();
    work.quote.calls = 3;
    reserve(&mut db, &work)?;
    allocator.acknowledge_return(&db, "trim", &ledger, &operator)?;
    allocator.decide_reduction("trim", true, &operator)?;
    assert!(install(&mut db, &allocator, &delayed, &operator).is_ok());
    assert_eq!(inspect(&mut db)?.accounts[0].limit, 3);
    Ok(())
}

#[test]
fn lower_definition_needs_verified_completion_and_keeps_historical_caps() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let mut allocator = Allocator::create(&directory.path().join("company.sqlite"), &operator)?;
    let mut db = database()?;
    let ledger = inspect(&mut db)?.ledger_id;
    let mut historical = allocation("historical", &ledger, 10, 10);
    historical.window_start = 0;
    let old = allocator.allocate(&historical, &operator)?;
    install(&mut db, &allocator, &old, &operator)?;
    let current = allocator.allocate(&allocation("current", &ledger, 5, 10), &operator)?;
    install(&mut db, &allocator, &current, &operator)?;
    let budgets = BTreeMap::from([("company".into(), definition(BudgetScope::Installation, 10))]);
    let mut past = request("past", budgets);
    past.context.now = 1;
    past.quote.calls = 8;
    reserve(&mut db, &past)?;
    let change = reduction_request("lower", 10, 5, &[]);
    allocator.propose_reduction(&change, &operator)?;
    let next = BTreeMap::from([("company".into(), change.definition.clone())]);
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert!(
        sync_definitions_in(&tx, &next)
            .unwrap_err()
            .to_string()
            .contains("proof_required")
    );
    assert!(install_pool_reduction_in(&tx, &allocator, "lower", &operator).is_err());
    tx.commit()?;
    allocator.decide_reduction("lower", true, &operator)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    install_pool_reduction_in(&tx, &allocator, "lower", &operator)?;
    sync_definitions_in(&tx, &next)?;
    tx.commit()?;
    let usage = inspect(&mut db)?;
    assert_eq!(
        (
            usage.accounts[0].window_start,
            usage.accounts[0].limit,
            usage.accounts[0].reserved
        ),
        (0, 10, 8)
    );
    let pool = allocator.inspect()?;
    assert_eq!((pool[0].limit, pool[0].reserved), (10, 10));
    assert_eq!((pool[1].limit, pool[1].reserved), (5, 5));
    historical.id = "late-past-allocation".into();
    historical.definition = change.definition;
    assert!(
        allocator
            .allocate(&historical, &operator)
            .unwrap_err()
            .to_string()
            .contains("historical_window_closed")
    );
    Ok(())
}

#[test]
fn returns_preserve_unknown_holds_and_rollback_all_units_when_one_is_unsafe() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let mut allocator = Allocator::create(&directory.path().join("company.sqlite"), &operator)?;
    let mut db = database()?;
    let ledger = inspect(&mut db)?.ledger_id;
    let mut allocation = allocation("allocation", &ledger, 10, 10);
    allocation.definition.limits.concurrency = Some(2);
    allocation.limits.concurrency = Some(2);
    let receipt = allocator.allocate(&allocation, &operator)?;
    install(&mut db, &allocator, &receipt, &operator)?;
    let budgets = BTreeMap::from([("company".into(), allocation.definition.clone())]);
    let mut running = request("running", budgets.clone());
    running.quote.concurrency = 2;
    let reservation = reserve(&mut db, &running)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    settle_in(&tx, &reservation, &Settlement::Unknown)?;
    tx.commit()?;
    let mut change = reduction_request("unsafe", 10, 5, &[(&ledger, 5)]);
    change.expected = allocation.definition.clone();
    change.definition.limits.concurrency = Some(1);
    change.returns.push(CapacityReturn {
        ledger_id: ledger.clone(),
        window_start: 0,
        unit: "concurrency".into(),
        amount: 1,
    });
    allocator.propose_reduction(&change, &operator)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert!(
        return_capacity_in(&tx, &allocator, "unsafe", &operator)
            .unwrap_err()
            .to_string()
            .contains("remove_liability")
    );
    tx.commit()?;
    assert!(
        allocator
            .acknowledge_return(&db, "unsafe", &ledger, &operator)
            .is_err()
    );
    assert_eq!(
        inspect(&mut db)?
            .accounts
            .iter()
            .find(|a| a.unit == "calls")
            .unwrap()
            .limit,
        10
    );
    // A clock window boundary cannot refresh a persistent concurrency gauge.
    let mut future = request("future", budgets);
    future.context.now = 180;
    assert!(reserve(&mut db, &future).is_err());
    Ok(())
}

#[test]
fn cancelled_reduction_recovers_committed_returns_after_crash_without_resurrection() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("company.sqlite");
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let mut allocator = Allocator::create(&path, &operator)?;
    let mut db = database()?;
    let ledger = inspect(&mut db)?.ledger_id;
    let original = allocator.allocate(&allocation("allocation", &ledger, 10, 10), &operator)?;
    install(&mut db, &allocator, &original, &operator)?;
    allocator.propose_reduction(
        &reduction_request("cancel", 10, 5, &[(&ledger, 5)]),
        &operator,
    )?;
    commit_return(&mut db, &allocator, "cancel", &operator)?;
    drop(allocator);
    let mut allocator = Allocator::open(&path, &operator)?;
    allocator.decide_reduction("cancel", false, &operator)?;
    assert_eq!(allocator.inspect()?[0].reserved, 10);
    assert!(
        allocator
            .allocate(&allocation("too-early", &ledger, 5, 10), &operator)
            .is_err()
    );
    // Late ack is still verifiable after cancellation; returned capacity is
    // available under the original ceiling, not lost or silently reinstalled.
    allocator.acknowledge_return(&db, "cancel", &ledger, &operator)?;
    assert_eq!(allocator.inspect()?[0].reserved, 5);
    let fresh = allocator.allocate(
        &allocation("explicit-replenishment", &ledger, 5, 10),
        &operator,
    )?;
    install(&mut db, &allocator, &fresh, &operator)?;
    install(&mut db, &allocator, &original, &operator)?;
    let budgets = BTreeMap::from([("company".into(), definition(BudgetScope::Installation, 10))]);
    let mut request = request("ten", budgets);
    request.quote.calls = 10;
    reserve(&mut db, &request)?;
    assert_eq!(inspect(&mut db)?.accounts[0].limit, 10);
    Ok(())
}

#[test]
fn restore_does_not_reuse_returned_company_capacity_or_erase_liability() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let mut allocator = Allocator::create(&directory.path().join("company.sqlite"), &operator)?;
    let mut db = database()?;
    let old_ledger = inspect(&mut db)?.ledger_id;
    let old = allocator.allocate(&allocation("old", &old_ledger, 10, 10), &operator)?;
    install(&mut db, &allocator, &old, &operator)?;
    let budgets = BTreeMap::from([("company".into(), definition(BudgetScope::Installation, 10))]);
    reserve(&mut db, &request("held", budgets.clone()))?;
    allocator.propose_reduction(
        &reduction_request("reduce", 10, 6, &[(&old_ledger, 6)]),
        &operator,
    )?;
    commit_return(&mut db, &allocator, "reduce", &operator)?;
    allocator.acknowledge_return(&db, "reduce", &old_ledger, &operator)?;
    allocator.decide_reduction("reduce", true, &operator)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    invalidate_restored(&tx)?;
    let new_ledger = prepare_restore_recovery_in(&tx, &operator)?;
    tx.commit()?;
    assert!(reserve(&mut db, &request("restored", budgets.clone())).is_err());
    assert!(install(&mut db, &allocator, &old, &operator).is_err());
    let mut fresh = allocation("recovery", &new_ledger, 2, 6);
    fresh.definition.revision = 2;
    let receipt = allocator.allocate(&fresh, &operator)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    recover_restored_in(&tx, Some(&allocator), &[receipt], &operator)?;
    tx.commit()?;
    assert_eq!(inspect(&mut db)?.accounts[0].reserved, 1);
    let mut work = request("fresh", budgets);
    work.quote.calls = 2;
    assert!(reserve(&mut db, &work).is_err());
    assert_eq!(allocator.inspect()?[0].reserved, 6);
    Ok(())
}

#[test]
fn activated_pool_fence_schema_cannot_be_silently_recreated_after_loss() -> Result<()> {
    let mut db = database()?;
    db.execute_batch("DROP TABLE day2_budget_capacity_returns")?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert!(
        upgrade(&tx)
            .unwrap_err()
            .to_string()
            .contains("fence_table_missing")
    );
    tx.rollback()?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("company.sqlite");
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let allocator = Allocator::create(&path, &operator)?;
    allocator
        .connection
        .execute_batch("DROP TABLE day2_company_budget_returns")?;
    drop(allocator);
    assert!(Allocator::open(&path, &operator).is_err());
    Ok(())
}

#[test]
fn old_host_sql_cannot_spend_returned_capacity_in_existing_or_future_accounts() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let mut allocator = Allocator::create(&directory.path().join("company.sqlite"), &operator)?;
    let path = directory.path().join("app.sqlite");
    let mut db = crate::store::open(&path)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    upgrade(&tx)?;
    tx.commit()?;
    let ledger = inspect(&mut db)?.ledger_id;
    let current = allocator.allocate(&allocation("current", &ledger, 10, 30), &operator)?;
    let mut future_request = allocation("future", &ledger, 10, 30);
    future_request.window_start = 120;
    let future = allocator.allocate(&future_request, &operator)?;
    install(&mut db, &allocator, &current, &operator)?;
    install(&mut db, &allocator, &future, &operator)?;
    let budgets = BTreeMap::from([("company".into(), current.definition.clone())]);
    let mut running = request("running", budgets.clone());
    running.quote.calls = 2;
    let reservation = reserve(&mut db, &running)?;
    let account: String =
        db.query_row("SELECT id FROM day2_budget_accounts", [], |row| row.get(0))?;

    // This connection and cached statements outlive the new operator's return.
    // Execute the exact pre-reduction reserve SQL, with its original full sum.
    let old_host = crate::store::open(&path)?;
    let mut old_update = old_host.prepare(
        "UPDATE day2_budget_accounts SET limit_amount=?2,held=held+?3,revision=?4 WHERE id=?1",
    )?;
    let mut old_insert = old_host
        .prepare("INSERT INTO day2_budget_accounts VALUES(?1,?2,?3,?4,?5,?6,?7,0,?8,0,?9)")?;
    let mut change = reduction_request("return", 30, 6, &[(&ledger, 6)]);
    change.returns.push(CapacityReturn {
        ledger_id: ledger.clone(),
        window_start: 120,
        unit: "calls".into(),
        amount: 6,
    });
    allocator.propose_reduction(&change, &operator)?;
    commit_return(&mut db, &allocator, "return", &operator)?;
    for (cap, additional) in [(10, 3), (10, 0), (4, 3)] {
        let error = old_update
            .execute(params![account, cap, additional, 1])
            .unwrap_err();
        assert!(
            error.to_string().contains("returned_capacity_exceeded"),
            "{error}"
        );
    }
    // A future allocation with no account yet must be fenced too. Returned
    // capacity cannot be restored by creating an account at the next boundary.
    for (cap, held) in [(10, 1), (4, 5)] {
        let error = old_insert
            .execute(params![
                "old-future",
                "company",
                120,
                "installation",
                "allocation",
                "calls",
                cap,
                held,
                1
            ])
            .unwrap_err();
        assert!(
            error.to_string().contains("returned_capacity_exceeded"),
            "{error}"
        );
    }
    assert_eq!(inspect(&mut db)?.accounts[0].reserved, 2);
    allocator.acknowledge_return(&db, "return", &ledger, &operator)?;
    allocator.decide_reduction("return", true, &operator)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    install_pool_reduction_in(&tx, &allocator, "return", &operator)?;
    tx.commit()?;
    future_request.id = "fresh-capacity".into();
    future_request.definition = change.definition.clone();
    future_request.limits.calls = Some(2);
    let fresh = allocator.allocate(&future_request, &operator)?;
    install(&mut db, &allocator, &fresh, &operator)?;
    // Cached imports do not change the sum; fresh centrally charged capacity does.
    install(&mut db, &allocator, &future, &operator)?;
    let mut future_work = request("new-future", budgets);
    future_work.context.now = 121;
    future_work.quote.calls = 6;
    reserve(&mut db, &future_work)?;
    assert!(
        old_insert
            .execute(params![
                "old-missing-window",
                "company",
                180,
                "installation",
                "allocation",
                "calls",
                10,
                1,
                1
            ])
            .is_err()
    );
    // Full observed usage survives a return, even beyond its retained capacity.
    let settled = known(
        &mut db,
        &reservation,
        Consumption {
            calls: 7,
            ..Consumption::default()
        },
    )?;
    assert!(settled.overrun);
    let usage = inspect(&mut db)?;
    let current_usage = usage
        .accounts
        .iter()
        .find(|a| a.window_start == 60)
        .unwrap();
    assert_eq!(
        (
            current_usage.limit,
            current_usage.used,
            current_usage.reserved
        ),
        (4, 7, 0)
    );
    assert!(usage.frozen_after_overrun);
    Ok(())
}

#[test]
fn old_host_sql_cannot_refresh_returned_concurrency_at_a_window_boundary() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let mut allocator = Allocator::create(&directory.path().join("company.sqlite"), &operator)?;
    let path = directory.path().join("app.sqlite");
    let mut db = crate::store::open(&path)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    upgrade(&tx)?;
    tx.commit()?;
    let ledger = inspect(&mut db)?.ledger_id;
    let mut initial = allocation("current", &ledger, 10, 10);
    initial.definition.limits.concurrency = Some(6);
    initial.limits.concurrency = Some(3);
    let current = allocator.allocate(&initial, &operator)?;
    initial.id = "future".into();
    initial.window_start = 120;
    let future = allocator.allocate(&initial, &operator)?;
    install(&mut db, &allocator, &current, &operator)?;
    install(&mut db, &allocator, &future, &operator)?;
    let budgets = BTreeMap::from([("company".into(), initial.definition.clone())]);
    let reservation = reserve(&mut db, &request("running", budgets.clone()))?;
    let old_host = crate::store::open(&path)?;
    let mut change = reduction_request("trim", 10, 10, &[]);
    change.expected = initial.definition.clone();
    change.definition.limits.concurrency = Some(2);
    change.returns.push(CapacityReturn {
        ledger_id: ledger.clone(),
        window_start: 0,
        unit: "concurrency".into(),
        amount: 4,
    });
    allocator.propose_reduction(&change, &operator)?;
    commit_return(&mut db, &allocator, "trim", &operator)?;
    let account: String = db.query_row(
        "SELECT id FROM day2_budget_accounts WHERE unit='concurrency'",
        [],
        |row| row.get(0),
    )?;
    assert!(old_host.execute("UPDATE day2_budget_accounts SET limit_amount=?2,held=held+?3,revision=?4 WHERE id=?1",params![account,6,2,1]).unwrap_err().to_string().contains("returned_capacity_exceeded"));
    let mut future_work = request("future-work", budgets);
    future_work.context.now = 121;
    reserve(&mut db, &future_work)?;
    future_work.id = "excess".into();
    assert!(reserve(&mut db, &future_work).is_err());
    known(&mut db, &reservation, Consumption::default())?;
    assert_eq!(
        inspect(&mut db)?
            .accounts
            .iter()
            .find(|a| a.unit == "concurrency")
            .unwrap()
            .reserved,
        1
    );
    Ok(())
}

#[test]
fn old_allocator_sql_obeys_pending_freeze_and_completed_ceiling() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("company.sqlite");
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let mut allocator = Allocator::create(&path, &operator)?;
    let initial = allocator.allocate(&allocation("initial", "app", 4, 10), &operator)?;
    let old_host = crate::store::open(&path)?;
    let change = reduction_request("reduce", 10, 6, &[]);
    allocator.propose_reduction(&change, &operator)?;
    let mut extra = initial.clone();
    extra.allocation_id = "old-allocation".into();
    extra.limits.calls = Some(1);
    assert!(
        old_host
            .execute(
                "INSERT INTO day2_company_budget_allocations VALUES(?1,?2,?3)",
                params![
                    extra.allocation_id,
                    "old-fingerprint",
                    serde_json::to_string(&extra)?
                ]
            )
            .unwrap_err()
            .to_string()
            .contains("reduction_pending")
    );
    assert!(old_host.execute("UPDATE day2_company_budget_accounts SET allocated=?4,limit_amount=?5,revision=?6 WHERE id=?1 AND window_start=?2 AND unit=?3",params!["company",60,"calls",5,10,1]).unwrap_err().to_string().contains("reduction_pending"));
    allocator.decide_reduction("reduce", true, &operator)?;
    // Even bypassing the old host's own revision check cannot restore the old
    // definition, increase an existing account, or create a future old-cap row.
    let old_definition = serde_json::to_string(&initial.definition)?;
    assert!(old_host.execute("INSERT INTO day2_company_budget_definitions VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET definition=excluded.definition",params!["company",old_definition]).unwrap_err().to_string().contains("definition_conflict"));
    for old_sql in [
        "UPDATE day2_company_budget_accounts SET allocated=7,limit_amount=10,revision=1 WHERE id='company' AND window_start=60 AND unit='calls'",
        "INSERT INTO day2_company_budget_accounts VALUES('company',120,'calls',60,1,10,7)",
    ] {
        assert!(
            old_host
                .execute(old_sql, [])
                .unwrap_err()
                .to_string()
                .contains("company_capacity_exceeded")
        );
    }
    extra.window_start = 0;
    assert!(
        old_host
            .execute(
                "INSERT INTO day2_company_budget_allocations VALUES(?1,?2,?3)",
                params![
                    extra.allocation_id,
                    "old-fingerprint",
                    serde_json::to_string(&extra)?
                ]
            )
            .unwrap_err()
            .to_string()
            .contains("historical_window_closed")
    );
    // Explicit later increases with a new definition are still supported.
    let mut replenishment = allocation("replenishment", "app", 5, 12);
    replenishment.definition.revision = 3;
    allocator.allocate(&replenishment, &operator)?;
    assert_eq!(
        (
            allocator.inspect()?[0].limit,
            allocator.inspect()?[0].reserved
        ),
        (12, 9)
    );
    Ok(())
}

#[test]
fn direct_return_acknowledgment_requires_installed_unchanged_local_guards() -> Result<()> {
    for mutation in [
        "DROP TRIGGER day2_budget_accounts_capacity_insert",
        "DROP TRIGGER day2_budget_accounts_capacity_update; CREATE TRIGGER day2_budget_accounts_capacity_update BEFORE UPDATE ON day2_budget_accounts BEGIN SELECT 1; END",
        "UPDATE day2_budget_meta SET capacity_guard_version=0",
        "ALTER TABLE day2_budget_meta DROP COLUMN capacity_guard_version",
    ] {
        let directory = tempfile::tempdir()?;
        let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
        let mut allocator = Allocator::create(&directory.path().join("company.sqlite"), &operator)?;
        let mut app = database()?;
        let ledger = inspect(&mut app)?.ledger_id;
        let allocation = allocator.allocate(&allocation("initial", &ledger, 10, 10), &operator)?;
        install(&mut app, &allocator, &allocation, &operator)?;
        allocator.propose_reduction(
            &reduction_request("return", 10, 6, &[(&ledger, 4)]),
            &operator,
        )?;
        commit_return(&mut app, &allocator, "return", &operator)?;
        app.execute_batch(mutation)?;
        let schema = || -> Result<Vec<(String, String)>> {
            let mut statement = app.prepare(
                "SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name",
            )?;
            Ok(statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?)
        };
        let before = schema()?;
        let changes_before = app.total_changes();
        for _ in 0..2 {
            assert!(
                allocator
                    .acknowledge_return(&app, "return", &ledger, &operator)
                    .is_err()
            );
        }
        // Neither credit capacity nor silently create/repair an unproven fence.
        assert_eq!(schema()?, before);
        assert_eq!(app.total_changes(), changes_before);
        assert_eq!(allocator.inspect()?[0].reserved, 10);
        assert!(
            allocator
                .reduction("return")?
                .acknowledged_ledgers
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn established_capacity_guards_reject_missing_or_changed_sql() -> Result<()> {
    for change in [
        "DROP TRIGGER day2_budget_accounts_capacity_insert",
        "DROP TRIGGER day2_budget_accounts_capacity_update; CREATE TRIGGER day2_budget_accounts_capacity_update BEFORE UPDATE ON day2_budget_accounts BEGIN SELECT 1; END",
    ] {
        let mut db = database()?;
        db.execute_batch(change)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(upgrade(&tx).is_err());
        tx.rollback()?;
    }
    for change in [
        "DROP TRIGGER day2_company_budget_accounts_capacity_insert",
        "DROP TRIGGER day2_company_budget_allocations_admission; CREATE TRIGGER day2_company_budget_allocations_admission BEFORE INSERT ON day2_company_budget_allocations BEGIN SELECT 1; END",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("company.sqlite");
        let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
        let allocator = Allocator::create(&path, &operator)?;
        allocator.connection.execute_batch(change)?;
        drop(allocator);
        assert!(Allocator::open(&path, &operator).is_err());
    }
    Ok(())
}

#[test]
fn company_allocations_are_durable_additive_and_cannot_be_imported_twice() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("company.sqlite");
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    assert!(Allocator::open(&path, &operator).is_err());
    let mut allocator = Allocator::create(&path, &operator)?;
    let mut first_db = database()?;
    let mut second_db = database()?;
    let first_id = inspect(&mut first_db)?.ledger_id;
    let second_id = inspect(&mut second_db)?.ledger_id;
    let first_request = allocation("first-allocation", &first_id, 3, 5);
    let first = allocator.allocate(&first_request, &operator)?;
    assert_eq!(allocator.allocate(&first_request, &operator)?, first);
    assert!(
        allocator
            .allocate(&allocation("second-app", &second_id, 3, 5), &operator)
            .unwrap_err()
            .to_string()
            .contains("pool_exhausted")
    );
    // Capacity remains allocated even before any app import or provider use.
    assert_eq!(allocator.inspect()?[0].reserved, 3);
    install(&mut first_db, &allocator, &first, &operator)?;
    install(&mut first_db, &allocator, &first, &operator)?;
    assert!(install(&mut second_db, &allocator, &first, &operator).is_err());
    let topup = allocator.allocate(&allocation("topup", &first_id, 2, 5), &operator)?;
    install(&mut first_db, &allocator, &topup, &operator)?;
    let budgets = BTreeMap::from([("company".into(), definition(BudgetScope::Installation, 5))]);
    let mut one = request("physical-one", budgets.clone());
    one.quote.calls = 4;
    reserve(&mut first_db, &one)?;
    let mut two = request("physical-two", budgets);
    two.quote.calls = 2;
    assert!(
        reserve(&mut first_db, &two)
            .unwrap_err()
            .to_string()
            .contains("exhausted")
    );
    assert_eq!(allocator.inspect()?[0].reserved, 5);
    assert_eq!(inspect(&mut first_db)?.accounts[0].reserved, 4);
    Ok(())
}

#[test]
fn company_revision_changes_preserve_allocations_and_reject_stale_limits() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let mut allocator = Allocator::create(&directory.path().join("company.sqlite"), &operator)?;
    allocator.allocate(&allocation("first", "ledger-one", 3, 5), &operator)?;
    let mut raised = allocation("raise", "ledger-two", 4, 8);
    raised.definition.revision = 2;
    allocator.allocate(&raised, &operator)?;
    assert_eq!(allocator.inspect()?[0].reserved, 7);
    assert_eq!(allocator.inspect()?[0].limit, 8);
    let mut stale = allocation("stale", "ledger-three", 1, 100);
    stale.window_start = 120;
    assert!(
        allocator
            .allocate(&stale, &operator)
            .unwrap_err()
            .to_string()
            .contains("revision_stale")
    );
    stale.definition.revision = 2;
    assert!(
        allocator
            .allocate(&stale, &operator)
            .unwrap_err()
            .to_string()
            .contains("revision_conflict")
    );
    stale.definition = raised.definition;
    stale.definition.revision = 3;
    stale.definition.period_seconds = 120;
    assert!(
        allocator
            .allocate(&stale, &operator)
            .unwrap_err()
            .to_string()
            .contains("shape_changed")
    );
    Ok(())
}

#[test]
fn installation_ceiling_reduction_cannot_leave_two_apps_with_excess_capacity() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let mut allocator = Allocator::create(&directory.path().join("company.sqlite"), &operator)?;
    let mut apps = [database()?, database()?];
    let original = BTreeMap::from([("company".into(), definition(BudgetScope::Installation, 100))]);
    for (index, app) in apps.iter_mut().enumerate() {
        let ledger_id = inspect(app)?.ledger_id;
        let receipt = allocator.allocate(
            &allocation(&format!("app-{index}"), &ledger_id, 50, 100),
            &operator,
        )?;
        install(app, &allocator, &receipt, &operator)?;
        // One app has already activated; the other has only imported capacity.
        if index == 0 {
            let tx = app.transaction_with_behavior(TransactionBehavior::Immediate)?;
            sync_definitions_in(&tx, &original)?;
            tx.commit()?;
        }
    }
    let mut lower = original.clone();
    lower.get_mut("company").unwrap().revision = 2;
    lower.get_mut("company").unwrap().limits.calls = Some(60);
    for app in &mut apps {
        let tx = app.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(
            sync_definitions_in(&tx, &lower)
                .unwrap_err()
                .to_string()
                .contains("pool_reduction_proof_required")
        );
        // Caught rejection cannot leak a partial definition update.
        tx.commit()?;
        let mut work = request("original-capacity", original.clone());
        work.quote.calls = 50;
        reserve(app, &work)?;
        assert_eq!(inspect(app)?.accounts[0].limit, 50);
    }
    let mut next_window = allocation("lower-next-window", "third-ledger", 1, 60);
    next_window.window_start = 120;
    next_window.definition.revision = 2;
    assert!(
        allocator
            .allocate(&next_window, &operator)
            .unwrap_err()
            .to_string()
            .contains("installation_reduction_requires_new_pool")
    );
    assert_eq!(allocator.inspect()?.len(), 1);
    assert_eq!(
        (
            allocator.inspect()?[0].limit,
            allocator.inspect()?[0].reserved
        ),
        (100, 100)
    );
    // Removing then re-adding a dimension cannot bypass monotonic ceilings.
    next_window.id = "remove-call-limit".into();
    next_window.definition.limits.calls = None;
    next_window.definition.limits.bytes = Some(100);
    next_window.limits.calls = None;
    next_window.limits.bytes = Some(1);
    assert!(
        allocator
            .allocate(&next_window, &operator)
            .unwrap_err()
            .to_string()
            .contains("installation_reduction_requires_new_pool")
    );
    Ok(())
}

#[test]
fn allocator_identity_pin_rejects_replacement_and_forged_receipt() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let path = directory.path().join("company.sqlite");
    let mut allocator = Allocator::create(&path, &operator)?;
    let id = allocator.id()?;
    assert_eq!(Allocator::open_expected(&path, &operator, &id)?.id()?, id);
    assert!(Allocator::open_expected(&path, &operator, "wrong-id").is_err());
    let mut connection = database()?;
    let ledger_id = inspect(&mut connection)?.ledger_id;
    let receipt = allocator.allocate(&allocation("first", &ledger_id, 2, 10), &operator)?;
    let mut forged = receipt.clone();
    forged.limits.calls = Some(1000);
    assert!(install(&mut connection, &allocator, &forged, &operator).is_err());
    install(&mut connection, &allocator, &receipt, &operator)?;
    let mut replacement =
        Allocator::create(&directory.path().join("replacement.sqlite"), &operator)?;
    let replacement_receipt =
        replacement.allocate(&allocation("replacement", &ledger_id, 2, 10), &operator)?;
    assert!(
        install(
            &mut connection,
            &replacement,
            &replacement_receipt,
            &operator
        )
        .unwrap_err()
        .to_string()
        .contains("identity_mismatch")
    );
    Ok(())
}

#[test]
fn company_multidimensional_allocation_failure_leaves_no_partial_capacity() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let mut allocator = Allocator::create(&directory.path().join("company.sqlite"), &operator)?;
    let mut request = allocation("too-many-bytes", "ledger", 2, 10);
    request.definition.limits.bytes = Some(10);
    request.limits.bytes = Some(11);
    assert!(allocator.allocate(&request, &operator).is_err());
    assert!(allocator.inspect()?.is_empty());
    Ok(())
}

#[test]
fn company_concurrency_allocation_does_not_reset_each_period() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let mut allocator = Allocator::create(&directory.path().join("company.sqlite"), &operator)?;
    let mut first = allocation("first", "ledger-one", 1, 10);
    first.definition.limits.concurrency = Some(2);
    first.limits.concurrency = Some(1);
    allocator.allocate(&first, &operator)?;
    first.id = "second-period".into();
    first.ledger_id = "ledger-two".into();
    first.window_start = 120;
    allocator.allocate(&first, &operator)?;
    first.id = "third-period".into();
    first.ledger_id = "ledger-one".into();
    first.window_start = 180;
    assert!(
        allocator
            .allocate(&first, &operator)
            .unwrap_err()
            .to_string()
            .contains("pool_exhausted")
    );
    let accounts = allocator.inspect()?;
    let concurrency: Vec<_> = accounts
        .iter()
        .filter(|account| account.unit == "concurrency")
        .collect();
    assert_eq!(concurrency.len(), 1);
    assert_eq!(
        (
            concurrency[0].window_start,
            concurrency[0].limit,
            concurrency[0].reserved
        ),
        (0, 2, 2)
    );
    assert!(!accounts.iter().any(|account| account.window_start == 180));
    Ok(())
}

#[test]
fn recovery_requires_fresh_company_capacity_and_retains_old_unknown_holds() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let mut allocator = Allocator::create(&directory.path().join("company.sqlite"), &operator)?;
    let mut connection = database()?;
    let old_ledger = inspect(&mut connection)?.ledger_id;
    let receipt = allocator.allocate(&allocation("old-capacity", &old_ledger, 3, 10), &operator)?;
    install(&mut connection, &allocator, &receipt, &operator)?;
    let first = request(
        "pre-restore-unknown",
        BTreeMap::from([("company".into(), definition(BudgetScope::Installation, 10))]),
    );
    let old_attempt = reserve(&mut connection, &first)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    settle_in(&tx, &old_attempt, &Settlement::Unknown)?;
    invalidate_restored(&tx)?;
    let new_ledger = prepare_restore_recovery_in(&tx, &operator)?;
    assert_eq!(prepare_restore_recovery_in(&tx, &operator)?, new_ledger);
    assert!(recover_restored_in(&tx, Some(&allocator), &[], &operator).is_err());
    tx.commit()?;
    let fresh = allocator.allocate(&allocation("new-capacity", &new_ledger, 3, 10), &operator)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert_eq!(
        recover_restored_in(&tx, Some(&allocator), &[fresh], &operator)?,
        new_ledger
    );
    tx.commit()?;
    let status = inspect(&mut connection)?;
    assert!(!status.frozen_after_restore);
    assert_eq!(status.ledger_id, new_ledger);
    assert_eq!(status.accounts[0].reserved, 1);
    assert_eq!(status.outstanding_attempts, 1);
    assert_eq!(allocator.inspect()?[0].reserved, 6);
    assert!(
        known(&mut connection, &old_attempt, Consumption::default())
            .unwrap_err()
            .to_string()
            .contains("ledger_mismatch")
    );
    let mut next = request("post-restore", first.budgets);
    next.quote.calls = 3;
    assert!(
        reserve(&mut connection, &next)
            .unwrap_err()
            .to_string()
            .contains("exhausted")
    );
    next.quote.calls = 2;
    reserve(&mut connection, &next)?;
    Ok(())
}

#[test]
fn local_recovery_and_cap_update_do_not_erase_pre_restore_usage() -> Result<()> {
    let mut connection = database()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let first = request(
        "first",
        BTreeMap::from([("app".into(), definition(BudgetScope::App, 1))]),
    );
    let attempt = reserve(&mut connection, &first)?;
    known(
        &mut connection,
        &attempt,
        Consumption {
            calls: 1,
            ..Consumption::default()
        },
    )?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    invalidate_restored(&tx)?;
    prepare_restore_recovery_in(&tx, &operator)?;
    let recovered = recover_restored_in(&tx, None, &[], &operator)?;
    assert_eq!(prepare_restore_recovery_in(&tx, &operator)?, recovered);
    assert_eq!(recover_restored_in(&tx, None, &[], &operator)?, recovered);
    tx.commit()?;
    assert!(reserve(&mut connection, &request("new", first.budgets.clone())).is_err());
    let mut raised = first.budgets;
    raised.get_mut("app").unwrap().revision = 2;
    raised.get_mut("app").unwrap().limits.calls = Some(3);
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    sync_definitions_in(&tx, &raised)?;
    tx.commit()?;
    let account = &inspect(&mut connection)?.accounts[0];
    assert_eq!((account.limit, account.used, account.reserved), (3, 1, 0));
    Ok(())
}

#[test]
fn typed_denials_hide_account_names_and_overrun_remains_frozen_next_period() -> Result<()> {
    let mut connection = database()?;
    let first = request(
        "first",
        BTreeMap::from([("private-account".into(), definition(BudgetScope::App, 1))]),
    );
    let attempt = reserve(&mut connection, &first)?;
    let error = reserve(&mut connection, &request("second", first.budgets.clone())).unwrap_err();
    assert_eq!(crate::error::observation_code(&error), "budget_exhausted");
    known(
        &mut connection,
        &attempt,
        Consumption {
            calls: 2,
            ..Consumption::default()
        },
    )?;
    let mut later = request("later", first.budgets);
    later.context.now = 500;
    let error = reserve(&mut connection, &later).unwrap_err();
    assert_eq!(crate::error::observation_code(&error), "budget_unavailable");
    assert!(inspect(&mut connection)?.frozen_after_overrun);
    Ok(())
}

#[test]
fn authority_lineage_initializes_replayable_but_distinct_ledgers() -> Result<()> {
    let ids: Vec<_> = ["host-lineage-a", "host-lineage-a", "host-lineage-b"]
        .iter()
        .map(|lineage| -> Result<String> {
            let mut connection = Connection::open_in_memory()?;
            let tx = connection.transaction()?;
            initialize_in(&tx, lineage)?;
            let id = inspect_in(&tx)?.ledger_id;
            tx.commit()?;
            Ok(id)
        })
        .collect::<Result<_>>()?;
    assert_eq!(ids[0], ids[1]);
    assert_ne!(ids[0], ids[2]);
    Ok(())
}

#[test]
fn reviewed_overrun_resolution_is_exact_and_never_acknowledges_unseen_events() -> Result<()> {
    let mut connection = database()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let budgets = BTreeMap::from([("app".into(), definition(BudgetScope::App, 10))]);
    let a = reserve(&mut connection, &request("a", budgets.clone()))?;
    let b = reserve(&mut connection, &request("b", budgets.clone()))?;
    let c = reserve(&mut connection, &request("c", budgets.clone()))?;
    known(
        &mut connection,
        &a,
        Consumption {
            calls: 2,
            ..Consumption::default()
        },
    )?;
    let mut approval = OverrunResolution {
        id: "review".into(),
        ledger_id: a.ledger_id.clone(),
        reservations: BTreeSet::from(["a".into()]),
        reason: "Reviewed adapter quote discrepancy".into(),
        proof: "repair-review/123".into(),
    };
    known(
        &mut connection,
        &b,
        Consumption {
            calls: 2,
            ..Consumption::default()
        },
    )?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert!(
        resolve_overruns_in(&tx, &operator, &approval)
            .unwrap_err()
            .to_string()
            .contains("evidence_changed")
    );
    assert!(inspect_in(&tx)?.frozen_after_overrun);
    approval.reservations.insert("b".into());
    let receipt = resolve_overruns_in(&tx, &operator, &approval)?;
    let status = inspect_in(&tx)?;
    assert_eq!(status.known_usage.calls, 4);
    assert_eq!(
        (status.accounts[0].used, status.accounts[0].reserved),
        (4, 1)
    );
    assert!(!status.frozen_after_overrun);
    tx.commit()?;
    known(
        &mut connection,
        &c,
        Consumption {
            calls: 2,
            ..Consumption::default()
        },
    )?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert_eq!(resolve_overruns_in(&tx, &operator, &approval)?, receipt);
    assert!(inspect_in(&tx)?.frozen_after_overrun);
    assert_eq!(inspect_in(&tx)?.overruns[0].reservation, "c");
    tx.commit()?;
    assert!(reserve(&mut connection, &request("d", budgets)).is_err());
    Ok(())
}

#[test]
fn overrun_acknowledgment_requires_proof_and_does_not_raise_the_cap() -> Result<()> {
    let mut connection = database()?;
    let operator = crate::authority_state::LocalOperator::assert_local("operator")?;
    let budgets = BTreeMap::from([("app".into(), definition(BudgetScope::App, 1))]);
    let attempt = reserve(&mut connection, &request("overrun", budgets.clone()))?;
    known(
        &mut connection,
        &attempt,
        Consumption {
            calls: 2,
            ..Consumption::default()
        },
    )?;
    let mut approval = OverrunResolution {
        id: "review".into(),
        ledger_id: attempt.ledger_id,
        reservations: BTreeSet::from(["overrun".into()]),
        reason: "Adapter repaired".into(),
        proof: String::new(),
    };
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert!(resolve_overruns_in(&tx, &operator, &approval).is_err());
    approval.proof = "repair-review/456".into();
    resolve_overruns_in(&tx, &operator, &approval)?;
    tx.commit()?;
    let status = inspect(&mut connection)?;
    assert!(!status.frozen_after_overrun);
    assert_eq!((status.accounts[0].limit, status.accounts[0].used), (1, 2));
    assert!(
        reserve(&mut connection, &request("next", budgets))
            .unwrap_err()
            .to_string()
            .contains("exhausted")
    );
    Ok(())
}

#[test]
fn missing_immutability_guard_is_not_silently_recreated() -> Result<()> {
    let mut connection = database()?;
    connection.execute_batch("DROP TRIGGER day2_budget_reservations_no_update")?;
    let tx = connection.transaction()?;
    assert!(
        upgrade(&tx)
            .unwrap_err()
            .to_string()
            .contains("trigger_missing")
    );
    Ok(())
}
