use anyhow::{Context, Result};
use day2::{automation, store::Runtime};
use day2_ops::{
    backup,
    local_dev::{Options, Session},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn artifact() -> Result<PathBuf> {
    std::env::var_os("DAY2_TEST_REPORTS_ARTIFACT")
        .map(PathBuf::from)
        .context("run xtask verify-reports")
}

fn options(source: &Path, directory: &Path) -> Options {
    Options {
        source: source.to_string_lossy().into_owned(),
        directory: directory.to_string_lossy().into_owned(),
        action: "start".into(),
        example: "".into(),
        generated: 0,
        seed: "42".into(),
        actor: "alice@example.test".into(),
        port: "0".into(),
        watch: "on".into(),
        reset: false,
        backup: "".into(),
        detach: false,
        data_requested: false,
    }
}

fn call(session: &mut Session, action: &str, input: Value) -> Result<Value> {
    session.effect(automation::Request {
        protocol: 1,
        action: action.into(),
        input: input.to_string(),
    })
}

fn setup() -> Result<(tempfile::TempDir, PathBuf, Options)> {
    // macOS Unix sockets have a short path limit; keep the managed test root short.
    let directory = tempfile::Builder::new()
        .prefix("d2dev-")
        .tempdir_in("/tmp")?;
    let source = directory.path().join("app");
    fs::create_dir(&source)?;
    fs::write(source.join("App.roc"), "App :: [].{}\n")?;
    let platform = directory.path().join("platform");
    fs::create_dir(&platform)?;
    let options = options(&source, &directory.path().join("dev"));
    Ok((directory, platform, options))
}

fn budget_status(runtime: &Runtime) -> Result<day2::budget::LedgerStatus> {
    let mut db = rusqlite::Connection::open(runtime.db())?;
    let tx = db.transaction()?;
    day2::budget::inspect_in(&tx)
}

#[test]
fn native_session_preserves_data_and_port_recovers_failed_candidate_and_stops_cleanly() -> Result<()>
{
    let (_directory, platform, mut options) = setup()?;
    options.example = "demo".into();
    options.data_requested = true;
    let mut session = Session::resolve(&platform, options.clone())?;
    assert_eq!(
        call(&mut session, "local-prepare", json!({}))?["running"],
        false
    );
    call(&mut session, "local-open", json!({"artifact":artifact()?}))?;
    assert!(call(&mut session, "local-activate", json!({})).is_err());
    call(&mut session, "local-campaign", json!({}))?;
    automation::run(
        &automation::runner()?,
        &["exercise", "demo", "0"],
        |request| session.effect(request),
    )?;
    call(&mut session, "local-properties", json!({}))?;
    call(&mut session, "local-activate", json!({}))?;
    let first = call(&mut session, "local-status", json!({}))?;
    assert_eq!(first["actor"], options.actor);
    assert_eq!(first["state"], "ready");
    let contracts_path = PathBuf::from(
        first["contracts"]["path"]
            .as_str()
            .context("contracts path")?,
    );
    let contracts_bytes = fs::read(&contracts_path)?;
    assert_eq!(first["contracts"]["artifact"], first["artifact"]);
    assert_eq!(
        first["contracts"]["sha256"],
        day2::digest(&contracts_bytes)[7..]
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&contracts_bytes)?["artifact"],
        first["artifact"]
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(&contracts_path)?.permissions().mode() & 0o777,
        0o600
    );
    let instance = PathBuf::from(first["instance"].as_str().context("instance")?);
    let runtime = Runtime::load(&instance, "app")?;
    let snapshot = runtime.inspect()?;
    assert_eq!(snapshot["reports"].as_array().context("reports")?.len(), 2);
    for row in snapshot["reports"].as_array().context("reports")? {
        let data: Value = serde_json::from_str(row["data"].as_str().context("data")?)?;
        assert_eq!(data["owner"], options.actor);
        assert_eq!(data["ready"], true);
    }
    // A bad candidate never changes the selected instance. Recovery serves the
    // same database and port, without replaying seed commands.
    call(&mut session, "local-pause", json!({}))?;
    call(&mut session, "local-snapshot", json!({}))?;
    assert!(
        call(
            &mut session,
            "local-migrate",
            json!({"artifact":"/missing-candidate"})
        )
        .is_err()
    );
    call(&mut session, "local-recover", json!({}))?;
    let recovered = call(&mut session, "local-status", json!({}))?;
    assert_eq!(recovered["port"], first["port"]);
    assert_eq!(recovered["instance"], first["instance"]);
    assert_eq!(runtime.inspect()?, snapshot);
    call(&mut session, "local-pause", json!({}))?;
    call(&mut session, "local-snapshot", json!({}))?;
    call(
        &mut session,
        "local-migrate",
        json!({"artifact":artifact()?}),
    )?;
    assert!(call(&mut session, "local-activate", json!({})).is_err());
    call(&mut session, "local-properties", json!({}))?;
    call(&mut session, "local-activate", json!({}))?;
    let next = call(&mut session, "local-status", json!({}))?;
    assert_eq!(next["port"], first["port"]);
    assert_ne!(next["instance"], first["instance"]);
    assert_eq!(
        Runtime::load(
            Path::new(next["instance"].as_str().context("instance")?),
            "app"
        )?
        .inspect()?,
        snapshot
    );
    call(&mut session, "local-shutdown", json!({}))?;
    drop(session);
    options.example.clear();
    options.data_requested = false;
    let mut resumed = Session::resolve(&platform, options.clone())?;
    call(&mut resumed, "local-prepare", json!({}))?;
    assert_eq!(
        call(&mut resumed, "local-open", json!({"artifact":artifact()?}))?["fresh"],
        false
    );
    call(&mut resumed, "local-snapshot", json!({}))?;
    call(
        &mut resumed,
        "local-migrate",
        json!({"artifact":artifact()?}),
    )?;
    call(&mut resumed, "local-properties", json!({}))?;
    call(&mut resumed, "local-activate", json!({}))?;
    let current = call(&mut resumed, "local-status", json!({}))?;
    assert_eq!(current["port"], first["port"]);
    assert_eq!(
        Runtime::load(
            Path::new(current["instance"].as_str().context("instance")?),
            "app"
        )?
        .inspect()?,
        snapshot
    );
    let stopper = std::thread::spawn(move || -> Result<Value> {
        options.action = "stop".into();
        let mut client = Session::resolve(&platform, options)?;
        call(&mut client, "local-stop", json!({}))
    });
    assert_eq!(
        call(&mut resumed, "local-wait", json!({}))?["stopped"],
        true
    );
    call(&mut resumed, "local-shutdown", json!({}))?;
    drop(resumed);
    assert_eq!(stopper.join().expect("stop thread")?["stopping"], true);
    Ok(())
}

#[test]
fn contract_export_failure_removes_stale_file_and_does_not_block_serving() -> Result<()> {
    let (_directory, platform, options) = setup()?;
    let artifact = artifact()?;
    let mut session = Session::resolve(&platform, options)?;
    call(&mut session, "local-prepare", json!({}))?;
    call(&mut session, "local-open", json!({"artifact":artifact}))?;
    call(&mut session, "local-properties", json!({}))?;
    let contracts_path = Path::new(&session.options.directory).join("app-contracts.json");
    fs::write(&contracts_path, b"stale contract")?;
    let metadata_path = artifact.join("artifact.json");
    let original_metadata = fs::read(&metadata_path)?;
    fs::write(&metadata_path, b"invalid artifact")?;
    call(&mut session, "local-activate", json!({}))?;
    fs::write(&metadata_path, original_metadata)?;
    let status = call(&mut session, "local-status", json!({}))?;
    assert_eq!(status["state"], "ready");
    assert_eq!(status["contracts"]["artifact"], status["artifact"]);
    assert!(status["contracts"]["error"].is_string());
    assert!(!contracts_path.exists());
    call(&mut session, "local-shutdown", json!({}))?;
    Ok(())
}

#[test]
fn backup_data_is_imported_into_clean_local_authority_without_pending_commands() -> Result<()> {
    let (directory, platform, mut options) = setup()?;
    let original =
        day2::development::create(&artifact()?, &directory.path().join("original"), None)?;
    original.invoke(
        "reports.submit",
        "developer",
        "pending-import",
        &json!({"title":"Backup report","text":"Imported data"}),
        1_700_000_000,
        day2::store::Fault::None,
    )?;
    let expected = original.inspect()?;
    let bundle = directory.path().join("backup");
    let manifest = backup::take(original.instance_path(), "app", &bundle)?;
    options.backup = bundle.to_string_lossy().into_owned();
    options.data_requested = true;
    let mut session = Session::resolve(&platform, options)?;
    call(&mut session, "local-prepare", json!({}))?;
    call(&mut session, "local-open", json!({"artifact":artifact()?}))?;
    call(&mut session, "local-import", json!({}))?;
    call(&mut session, "local-properties", json!({}))?;
    call(&mut session, "local-activate", json!({}))?;
    let status = call(&mut session, "local-status", json!({}))?;
    let runtime = Runtime::load(
        Path::new(status["instance"].as_str().context("instance")?),
        "app",
    )?;
    assert_eq!(runtime.inspect()?, expected);
    let listed = runtime.invoke(
        "reports.list",
        "alice@example.test",
        "local-read",
        &json!({"after":"","limit":10}),
        1_700_000_001,
        day2::store::Fault::None,
    )?;
    assert_eq!(listed.status, "success");
    assert!(
        runtime
            .invoke(
                "reports.list",
                "developer",
                "old-authority",
                &json!({"after":"","limit":10}),
                1_700_000_001,
                day2::store::Fault::None
            )
            .is_err()
    );
    let db = rusqlite::Connection::open(runtime.db())?;
    let pending: i64 = db.query_row(
        "SELECT COUNT(*) FROM day2_invocations WHERE status='pending'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(pending, 0);
    assert_eq!(backup::verify(&bundle)?.database, manifest.database);
    call(&mut session, "local-shutdown", json!({}))?;
    Ok(())
}

#[test]
fn rebuild_recovers_local_resources_and_retains_accounting_but_rejects_company_capacity()
-> Result<()> {
    use day2::budget::{self, BudgetContext, Consumption, ReservationRequest, Settlement};
    use day2_capabilities::resources::{BudgetDefinition, BudgetLimits, BudgetScope};
    let (directory, platform, options) = setup()?;
    let actor = options.actor.clone();
    let mut session = Session::resolve(&platform, options)?;
    call(&mut session, "local-prepare", json!({}))?;
    call(&mut session, "local-open", json!({"artifact":artifact()?}))?;
    call(&mut session, "local-properties", json!({}))?;
    call(&mut session, "local-activate", json!({}))?;
    let first = call(&mut session, "local-status", json!({}))?;
    call(&mut session, "local-pause", json!({}))?;
    let original = Runtime::load(
        Path::new(first["instance"].as_str().context("instance")?),
        "app",
    )?;
    let mut db = rusqlite::Connection::open(original.db())?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let definition = BudgetDefinition {
        revision: 1,
        scope: BudgetScope::App,
        period_seconds: 3600,
        limits: BudgetLimits {
            calls: Some(10),
            bytes: Some(100),
            cost_microunits: Some(100),
            concurrency: Some(2),
        },
    };
    let request = |id: &str| ReservationRequest {
        id: id.into(),
        binding: day2::digest(id.as_bytes()),
        context: BudgetContext {
            app: original.scope().into(),
            actor: actor.clone(),
            connection: "local-test".into(),
            invocation_root: id.into(),
            now: 100,
        },
        budgets: std::collections::BTreeMap::from([("retained".into(), definition.clone())]),
        quote: Consumption {
            calls: 1,
            bytes: 8,
            cost_microunits: 3,
            concurrency: 1,
        },
    };
    let completed = budget::reserve_in(&tx, &request("completed-before-rebuild"))?;
    budget::settle_in(
        &tx,
        &completed,
        &Settlement::Known {
            actual: Consumption {
                calls: 1,
                bytes: 4,
                cost_microunits: 1,
                concurrency: 1,
            },
        },
    )?;
    let unknown = budget::reserve_in(&tx, &request("unknown-before-rebuild"))?;
    budget::settle_in(&tx, &unknown, &Settlement::Unknown)?;
    let before = budget::inspect_in(&tx)?;
    assert!(before.accounts.iter().any(|account| account.used > 0));
    assert!(before.accounts.iter().any(|account| account.reserved > 0));
    assert_eq!(before.outstanding_attempts, 1);
    tx.commit()?;
    call(&mut session, "local-snapshot", json!({}))?;
    call(
        &mut session,
        "local-migrate",
        json!({"artifact":artifact()?}),
    )?;
    call(&mut session, "local-properties", json!({}))?;
    call(&mut session, "local-activate", json!({}))?;
    let next = call(&mut session, "local-status", json!({}))?;
    call(&mut session, "local-pause", json!({}))?;
    let rebuilt = Runtime::load(
        Path::new(next["instance"].as_str().context("instance")?),
        "app",
    )?;
    let mut db = rusqlite::Connection::open(rebuilt.db())?;
    let active = day2::authority_state::current(&db)?;
    assert!(!active.document.resources.is_empty());
    let after = budget_status(&rebuilt)?;
    assert_ne!(after.ledger_id, before.ledger_id);
    assert!(!after.frozen_after_restore);
    assert_eq!(after.accounts, before.accounts);
    assert_eq!(after.known_usage, before.known_usage);
    assert_eq!(after.outstanding_attempts, before.outstanding_attempts);
    assert_eq!(budget_status(&original)?, before);
    // Exercise both the preparation reader and the actual child notification
    // after cutover. Inspecting existing rows alone misses lost resource grants.
    rebuilt.invoke(
        "reports.submit",
        &actor,
        "provider-after-rebuild",
        &json!({"title":"After rebuild","text":"Resource authority still works"}),
        1000,
        day2::store::Fault::None,
    )?;
    let completed = day2::invocations::drain(&rebuilt, 30)?;
    assert!(completed.iter().any(
        |invocation| invocation.operation == "reports.notify" && invocation.status == "success"
    ));
    assert!(
        completed
            .iter()
            .all(|invocation| invocation.status == "success")
    );
    let provider = rusqlite::Connection::open(rebuilt.db().with_file_name("notifications.sqlite"))?;
    let encoded: String = provider.query_row(
        "SELECT state FROM notification_world WHERE id=1",
        [],
        |row| row.get(0),
    )?;
    let notifications: day2::capabilities::NotificationWorld = serde_json::from_str(&encoded)?;
    assert_eq!(notifications.messages.len(), 1);
    assert!(
        notifications
            .messages
            .values()
            .all(|message| message.actor == actor)
    );
    // A custom active cap must never disappear merely because the checkpoint
    // omits authoring files. Refuse the cutover, then prove the incumbent still
    // meters its next provider attempt under that cap.
    let operator = day2::authority_state::LocalOperator::assert_local("local-test")?;
    let mut metered = active.document.clone();
    metered.resources.budgets.insert(
        "cutover-cap".into(),
        BudgetDefinition {
            revision: 1,
            scope: BudgetScope::App,
            period_seconds: 31_536_000,
            limits: BudgetLimits {
                calls: Some(1),
                ..Default::default()
            },
        },
    );
    for grant in metered
        .resources
        .operations
        .values_mut()
        .flat_map(|slots| slots.values_mut())
    {
        grant
            .budgets
            .push(day2_capabilities::resources::VersionRef {
                id: "cutover-cap".into(),
                revision: 1,
            });
    }
    day2::authority_state::apply(
        &rebuilt,
        &operator,
        &day2::authority_state::ApplyAuthority {
            request_id: "custom-local-cap".into(),
            expected: Some(active.stamp.clone()),
            document: metered.clone(),
        },
    )?;
    call(&mut session, "local-snapshot", json!({}))?;
    let failed = call(
        &mut session,
        "local-migrate",
        json!({"artifact":artifact()?}),
    )
    .unwrap_err();
    assert!(
        failed
            .to_string()
            .contains("local_custom_resource_authority_requires_explicit_activation"),
        "{failed:#}"
    );
    assert_eq!(day2::authority_state::current(&db)?.document, metered);
    call(&mut session, "local-recover", json!({}))?;
    assert_eq!(
        call(&mut session, "local-status", json!({}))?["instance"],
        next["instance"]
    );
    call(&mut session, "local-pause", json!({}))?;
    rebuilt.invoke(
        "reports.submit",
        &actor,
        "metered-after-rejected-cutover",
        &json!({"title":"Still metered","text":"Custom authority remains active"}),
        1001,
        day2::store::Fault::None,
    )?;
    let limited = day2::invocations::drain(&rebuilt, 30).unwrap_err();
    assert!(
        limited
            .chain()
            .any(|cause| cause.to_string() == "budget_exhausted"),
        "{limited:#}"
    );
    let metered_usage = budget_status(&rebuilt)?;
    assert!(
        metered_usage
            .accounts
            .iter()
            .any(|account| account.budget_id == "cutover-cap"
                && account.used + account.reserved == 1)
    );
    let encoded: String = provider.query_row(
        "SELECT state FROM notification_world WHERE id=1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        serde_json::from_str::<day2::capabilities::NotificationWorld>(&encoded)?
            .messages
            .len(),
        1
    );
    let expected = day2::authority_state::current(&db)?.stamp;
    day2::authority_state::apply(
        &rebuilt,
        &operator,
        &day2::authority_state::ApplyAuthority {
            request_id: "restore-explicit-local-fixture".into(),
            expected: Some(expected),
            document: active.document,
        },
    )?;
    // Installing any company-backed capacity makes automatic local checkpoint
    // recovery inappropriate, even if the new local fixture would omit its grant.
    let mut allocator =
        budget::Allocator::create(&directory.path().join("company.sqlite"), &operator)?;
    let ledger = budget_status(&rebuilt)?;
    let company = BudgetDefinition {
        revision: 1,
        scope: BudgetScope::Installation,
        period_seconds: 3600,
        limits: BudgetLimits {
            calls: Some(10),
            ..Default::default()
        },
    };
    let allocation = allocator.allocate(
        &budget::AllocationRequest {
            id: "company-for-original".into(),
            budget_id: "company".into(),
            definition: company,
            window_start: 0,
            ledger_id: ledger.ledger_id.clone(),
            limits: BudgetLimits {
                calls: Some(5),
                ..Default::default()
            },
        },
        &operator,
    )?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    budget::install_allocation_in(&tx, &allocator, &allocation, &operator)?;
    tx.commit()?;
    let retained = budget_status(&rebuilt)?;
    call(&mut session, "local-snapshot", json!({}))?;
    let failed = call(
        &mut session,
        "local-migrate",
        json!({"artifact":artifact()?}),
    )
    .unwrap_err();
    assert!(
        failed
            .to_string()
            .contains("budget_restore_fresh_allocation_required"),
        "{failed:#}"
    );
    assert_eq!(budget_status(&rebuilt)?, retained);
    call(&mut session, "local-recover", json!({}))?;
    assert_eq!(
        call(&mut session, "local-status", json!({}))?["instance"],
        next["instance"]
    );
    call(&mut session, "local-shutdown", json!({}))?;
    Ok(())
}
