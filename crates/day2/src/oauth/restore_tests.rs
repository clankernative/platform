//! Real SQLite/crypto adapters and an independent expected denial cut. These
//! fixtures never construct a native owner, passkey approval or writer.
use super::*;
use crate::oauth::{connect, custody, exchange, inbound, profiles, store};
use rusqlite::TransactionBehavior;
use std::path::Path;

pub(in crate::oauth) fn database(path: &Path) -> Result<Connection> {
    let db = Connection::open(path)?;
    db.pragma_update(None, "foreign_keys", true)?;
    db.execute_batch(crate::store::PLATFORM_DDL)?;
    db.execute(
        "INSERT INTO day2_meta VALUES('scope','company/canary/calendar')",
        [],
    )?;
    db.execute(
        "INSERT INTO day2_meta VALUES('schema',?1)",
        [Digest::new(b"schema").as_str()],
    )?;
    crate::oauth::usage::install(&db)?;
    inbound::install_schema(&db)?;
    Ok(db)
}

fn intent(id: &str) -> connect::ConnectIntent {
    connect::ConnectIntent {
        attempt: id.into(),
        slot: format!("slot_{id}"),
        expected_generation: None,
        expected_epoch: 1,
        proposed_generation: 1,
        owner: "human_1".into(),
        profile: "google_calendar_v1".into(),
        registration: "registration_1".into(),
        callback: "callback_1".into(),
        consent: "consent_1".into(),
        expires_at: 100,
    }
}

fn seed(db: &mut Connection) -> Result<()> {
    assert!(connect::begin(db, &intent("pending"), 1)?);
    assert!(connect::begin(db, &intent("sent"), 1)?);
    assert!(connect::claim_callback(
        db,
        "sent",
        "retained_code",
        2,
        |_| Ok(())
    )?);
    let _may = connect::authorize_and_commit_exchange(db, "sent", 3)?.unwrap();
    for (index, state) in [
        "ready",
        "may_have_been_sent",
        "uncertain",
        "replacement_committed",
    ]
    .into_iter()
    .enumerate()
    {
        let slot = format!("refresh_slot_{index}");
        db.execute("INSERT INTO oauth_connection_slots VALUES(?1,1,1,1,'profile','account','affinity','active')",[&slot])?;
        db.execute("INSERT INTO oauth_refresh_attempts VALUES(?1,?2,1,1,1,'profile','account','affinity',?3,?4,?5)",
            params![format!("refresh_{index}"),slot,state,if index==3 {Some(2)} else {None},if index==3 {Some("known_receipt")} else {None}])?;
    }
    inbound::record_grant(db, "old_grant", &inbound::tests::ceiling(), 1)?;
    Ok(())
}

fn cut(db: &mut Connection, profile: &Profile, seed: u64) -> Result<usize> {
    let mut tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let before = Snapshot::capture(&tx, profile)?;
    let cut = crate::security_epoch::restore_cut::fixture(before.digest().clone(), seed)?;
    let count = close_in(&mut tx, before, &cut, profile)?;
    tx.commit()?;
    Ok(count)
}

pub(in crate::oauth) fn apply_for_storage(db: &mut Connection, seed: u64) -> Result<usize> {
    let scope: String = db.query_row(
        "SELECT value FROM main.day2_meta WHERE key='scope'",
        [],
        |r| r.get(0),
    )?;
    let schema: String = db.query_row(
        "SELECT value FROM main.day2_meta WHERE key='schema'",
        [],
        |r| r.get(0),
    )?;
    let profile = Profile::prepare()?;
    let mut tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let before = Snapshot::capture(&tx, &profile)?;
    let cut = crate::security_epoch::restore_cut::fixture_for_storage(
        before.digest().clone(),
        seed,
        &scope,
        schema.try_into()?,
    )?;
    let count = close_in(&mut tx, before, &cut, &profile)?;
    tx.commit()?;
    Ok(count)
}

type ConnectHistory = Vec<(String, String, Option<String>)>;
type RefreshHistory = Vec<(String, String, Option<i64>, Option<String>)>;

fn histories(db: &Connection) -> Result<(ConnectHistory, RefreshHistory)> {
    let mut q = db.prepare(
        "SELECT attempt,state,code_ref FROM main.oauth_connect_attempts ORDER BY attempt",
    )?;
    let connects = q
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut q=db.prepare("SELECT attempt,state,next_version,receipt FROM main.oauth_refresh_attempts ORDER BY attempt")?;
    let refresh = q
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok((connects, refresh))
}

#[test]
fn complete_cut_preserves_unknown_and_known_histories_and_reopens_as_denial() -> Result<()> {
    let profile = Profile::prepare()?;
    for seed_number in [3, 17, 81] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("app.sqlite");
        let mut db = database(&path)?;
        seed(&mut db)?;
        let history = histories(&db)?;
        assert_eq!(cut(&mut db, &profile, seed_number)?, 7); // 2 connect + 4 refresh + 1 grant.
        drop(db);
        for _ in 0..2 {
            let mut db = Connection::open(&path)?;
            db.pragma_update(None, "foreign_keys", true)?;
            assert_eq!(histories(&db)?, history);
            assert_eq!(db.query_row("SELECT count(*) FROM main.oauth_connection_slots WHERE status='reauth_required' AND security_epoch=2 AND generation=1 AND token_version=1",[],|r|r.get::<_,i64>(0))?,4);
            assert_eq!(
                db.query_row(
                    "SELECT status,epoch FROM main.oauth_inbound_grants WHERE id='old_grant'",
                    [],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                )?,
                ("revoked".into(), 2)
            );
            assert!(store::authorize_and_commit_dispatch(&mut db, "refresh_0").is_err());
            assert!(
                connect::claim_callback(&mut db, "pending", "late_code", 5, |_| panic!(
                    "closed callback entered custody"
                ))
                .is_err()
            );
            assert!(
                connect::await_account_approval(
                    &mut db,
                    "sent",
                    "account",
                    "scope",
                    5,
                    |_| panic!("closed response entered custody")
                )
                .is_err()
            );
            assert!(connect::begin(&mut db, &intent("pending"), 5).is_err());
            assert!(require_open(&db, Kind::Inbound, "old_grant").is_err());
            assert!(require_no_history(&db).is_err());
            assert!(
                db.execute("DELETE FROM main.oauth_restore_closed", [])
                    .is_err()
            );
            assert!(
                db.execute("UPDATE main.oauth_restore_cuts SET inventory=inventory", [])
                    .is_err()
            );
            assert_eq!(histories(&db)?, history);
        }
    }
    Ok(())
}

#[test]
fn late_prepared_code_and_tokens_cannot_publish_or_decrypt_after_cut() -> Result<()> {
    crate::oauth::effects::scope(crate::oauth::simulation::World::new(9721), || {
        let dir = tempfile::tempdir()?;
        let mut db = database(&dir.path().join("app.sqlite"))?;
        let profile = Profile::prepare()?;
        let fixture = profiles::tests::external_fixture();
        let key = profiles::tests::exchange_key();
        let authorization = exchange::prepare_authorization(
            fixture.input(),
            &key,
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
        )?;
        let binding = authorization.parts().2.clone();
        assert!(authorization.begin(&mut db, 1)?);
        let code = custody::prepare_code(&key, &fixture.intent, &binding, "fixture_code")?;
        let raw=br#"{"access_token":"fixture_access","refresh_token":"fixture_refresh","token_type":"Bearer","expires_in":300,"scope":"calendar.read"}"#;
        let tokens = fixture
            .reviewed
            .validate_token_response(raw, &fixture.permission)?;
        let held =
            custody::prepare_tokens(&key, &fixture.intent, "account_1", &binding, tokens, 2)?;
        let before: Vec<u8> = db.query_row(
            "SELECT ciphertext FROM main.oauth_private_verifiers",
            [],
            |r| r.get(0),
        )?;
        cut(&mut db, &profile, 19)?;
        let tx = db.transaction()?;
        assert!(custody::publish_code(&tx, code).is_err());
        assert!(custody::publish_tokens(&tx, held).is_err());
        assert!(custody::load_verifier(&tx, &key, &fixture.intent, &binding).is_err());
        assert_eq!(
            tx.query_row("SELECT count(*) FROM main.oauth_private_codes", [], |r| r
                .get::<_, i64>(
                0
            ))?,
            0
        );
        assert_eq!(
            tx.query_row("SELECT count(*) FROM main.oauth_private_tokens", [], |r| {
                r.get::<_, i64>(0)
            })?,
            0
        );
        assert_eq!(
            tx.query_row(
                "SELECT ciphertext FROM main.oauth_private_verifiers",
                [],
                |r| r.get::<_, Vec<u8>>(0)
            )?,
            before
        );
        tx.commit()?;
        Ok(())
    })
}

#[test]
fn old_slot_cannot_be_adopted_but_fresh_scope_still_needs_new_authorization() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut db = database(&dir.path().join("app.sqlite"))?;
    let profile = Profile::prepare()?;
    seed(&mut db)?;
    cut(&mut db, &profile, 20)?;
    let mut adoption = intent("new_attempt");
    adoption.slot = "refresh_slot_0".into();
    assert!(!connect::begin(&mut db, &adoption, 5)?);
    adoption.expected_generation = Some(1);
    adoption.proposed_generation = 2;
    adoption.expected_epoch = 2;
    assert!(!connect::begin(&mut db, &adoption, 5)?); // No implicit restored-slot replacement profile.
    let fresh = intent("new_scoped_authorization");
    assert!(connect::begin(&mut db, &fresh, 5)?); // Navigation only, never a provider or native permit.
    assert_eq!(
        connect::state(&db, &fresh.attempt)?,
        Some(connect::ConnectState::AwaitingProviderAuthorization)
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM main.oauth_connection_slots WHERE status='active'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    Ok(())
}

#[test]
fn changed_row_or_identity_inventory_refuses_without_repair() -> Result<()> {
    for mutation in 0..4 {
        let dir = tempfile::tempdir()?;
        let mut db = database(&dir.path().join("app.sqlite"))?;
        let profile = Profile::prepare()?;
        seed(&mut db)?;
        let mut tx = db.transaction()?;
        let before = Snapshot::capture(&tx, &profile)?;
        let cut = crate::security_epoch::restore_cut::fixture(before.digest().clone(), 21)?;
        match mutation {
            0 => {
                tx.execute("UPDATE main.oauth_connection_slots SET affinity='changed' WHERE slot='refresh_slot_0'",[])?;
            }
            1 => {
                tx.execute("UPDATE main.oauth_connect_attempts SET consent='changed' WHERE attempt='pending'",[])?;
            }
            2 => {
                tx.execute(
                    "UPDATE main.day2_meta SET value='foreign/scope/app' WHERE key='scope'",
                    [],
                )?;
            }
            _ => {
                tx.execute("INSERT INTO main.oauth_connect_attempts SELECT 'new_identity',slot,expected_generation,expected_epoch,proposed_generation,owner,profile,registration,callback,consent,expires_at,state,code_ref,account,scope_evidence FROM main.oauth_connect_attempts WHERE attempt='pending'",[])?;
            }
        }
        assert!(close_in(&mut tx, before, &cut, &profile).is_err());
        assert_eq!(
            tx.query_row("SELECT count(*) FROM main.oauth_restore_cuts", [], |r| r
                .get::<_, i64>(0))?,
            0
        );
        tx.rollback()?;
    }
    Ok(())
}

#[test]
fn late_failure_rolls_back_cut_and_all_local_revocations_even_if_caller_catches_it() -> Result<()> {
    for failure in ["slot", "inbound"] {
        let dir = tempfile::tempdir()?;
        let mut db = database(&dir.path().join("app.sqlite"))?;
        let profile = Profile::prepare()?;
        seed(&mut db)?;
        let before_history = histories(&db)?;
        // Valid but exhausted inputs are refused, never clamped or wrapped.
        let table = if failure == "slot" {
            "oauth_connection_slots"
        } else {
            "oauth_inbound_grants"
        };
        let column = if failure == "slot" {
            "security_epoch"
        } else {
            "epoch"
        };
        db.execute(
            &format!("UPDATE {table} SET {column}=9223372036854775807"),
            [],
        )?;
        let mut tx = db.transaction()?;
        let snapshot = Snapshot::capture(&tx, &profile)?;
        let cut = crate::security_epoch::restore_cut::fixture(snapshot.digest().clone(), 22)?;
        assert!(close_in(&mut tx, snapshot, &cut, &profile).is_err());
        tx.commit()?; // Catching the failure must not persist a prefix.
        assert_eq!(
            db.query_row("SELECT count(*) FROM main.oauth_restore_cuts", [], |r| r
                .get::<_, i64>(0))?,
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM main.oauth_restore_closed", [], |r| {
                r.get::<_, i64>(0)
            })?,
            0
        );
        assert_eq!(histories(&db)?, before_history);
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM main.oauth_connection_slots WHERE status='active'",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            4
        );
    }
    Ok(())
}

#[test]
fn missing_partial_shadow_and_unknown_units_refuse_before_any_cut() -> Result<()> {
    for mutation in 0..6 {
        let dir = tempfile::tempdir()?;
        let mut db = database(&dir.path().join("app.sqlite"))?;
        let profile = Profile::prepare()?;
        match mutation {
            0 => db.execute_batch("CREATE TEMP TABLE oauth_connect_attempts(untrusted TEXT)")?,
            1 => db.execute_batch("CREATE TABLE oauth_unreviewed_callback(untrusted TEXT)")?,
            2 => db.execute_batch("DROP TABLE oauth_use_handles")?,
            3 => db.execute_batch("CREATE TEMP TABLE day2_meta(key TEXT,value TEXT)")?,
            4 => db.execute_batch("ATTACH ':memory:' AS foreign_state")?,
            _ => {db.execute("INSERT INTO oauth_connect_attempts(attempt,slot,expected_generation,expected_epoch,proposed_generation,owner,profile,registration,callback,consent,expires_at,state) VALUES(?1,'slot',NULL,1,1,'human','profile','registration','callback','consent',100,'awaiting_provider_authorization')",["invalid\noriginal"])?;}
        }
        let tx = db.transaction()?;
        assert!(Snapshot::capture(&tx, &profile).is_err());
        assert_eq!(
            tx.query_row("SELECT count(*) FROM main.oauth_restore_cuts", [], |r| r
                .get::<_, i64>(0))?,
            0
        );
        tx.rollback()?;
    }
    Ok(())
}

#[test]
fn ordinary_restore_allows_only_empty_current_cut_metadata() -> Result<()> {
    let mut db = Connection::open_in_memory()?;
    {
        let tx = db.transaction()?;
        require_no_history(&tx)?;
        tx.commit()?;
    }
    install(&db)?;
    {
        let tx = db.transaction()?;
        require_no_history(&tx)?;
        tx.commit()?;
    }
    db.execute("DELETE FROM oauth_restore_schema_version", [])?;
    let tx = db.transaction()?;
    assert!(require_no_history(&tx).is_err());
    tx.rollback()?;
    Ok(())
}

#[test]
fn ordinary_preflight_refuses_retained_oauth_after_selection_removal_and_readonly_reopen()
-> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("archive.sqlite");
    let mut db = database(&path)?;
    {
        let tx = db.transaction()?;
        crate::store::require_no_managed_credential_restore_state(&tx)?;
        tx.commit()?;
    }
    seed(&mut db)?;
    let original = histories(&db)?;
    // No credential family or desired OAuth selection participates in this
    // actual ordinary preflight. Empty restore-cut tables cannot hide history.
    drop(db);
    for _ in 0..2 {
        let mut db =
            Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let tx = db.transaction()?;
        assert!(crate::store::require_no_managed_credential_restore_state(&tx).is_err());
        assert_eq!(histories(&tx)?, original);
        assert_eq!(
            tx.query_row("SELECT count(*) FROM main.oauth_restore_cuts", [], |r| r
                .get::<_, i64>(0))?,
            0
        );
        tx.rollback()?;
    }
    Ok(())
}

#[test]
fn ordinary_preflight_preserves_the_callers_actual_progress_hook_on_success_and_refusal()
-> Result<()> {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    };
    for occupied in [false, true] {
        let directory = tempfile::tempdir()?;
        let mut db = database(&directory.path().join("archive.sqlite"))?;
        if occupied {
            seed(&mut db)?;
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let interrupt = Arc::new(AtomicBool::new(false));
        let counter = calls.clone();
        let stop = interrupt.clone();
        db.progress_handler(
            1,
            Some(move || {
                counter.fetch_add(1, SeqCst);
                stop.load(SeqCst)
            }),
        )?;
        let tx = db.transaction()?;
        assert_eq!(
            crate::store::require_no_managed_credential_restore_state(&tx).is_err(),
            occupied
        );
        tx.rollback()?;
        let before = calls.load(SeqCst);
        let _:i64=db.query_row("WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<100) SELECT sum(i) FROM n",[],|r|r.get(0))?;
        assert!(
            calls.load(SeqCst) > before,
            "preflight replaced the caller's hook"
        );
        interrupt.store(true, SeqCst);
        assert!(
            db.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))
                .is_err()
        );
        db.progress_handler(0, None::<fn() -> bool>)?;
    }
    Ok(())
}

const CHILD: &str = "oauth::restore::tests::restore_cut_process_child";

#[test]
fn actual_process_loss_before_and_after_outer_commit_has_one_replayable_cut() -> Result<()> {
    for stage in 0..3 {
        let directory = tempfile::tempdir()?;
        let output = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                CHILD,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("G1_RESTORE_CUT_ROOT", directory.path())
            .env("G1_RESTORE_CUT_STAGE", stage.to_string())
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(70 + stage),
            "child did not reach its controlled loss point"
        );
        for _ in 0..2 {
            let db = Connection::open(directory.path().join("app.sqlite"))?;
            let applied = stage == 2; // Independent expected durable boundary.
            assert_eq!(
                db.query_row("SELECT count(*) FROM main.oauth_restore_cuts", [], |r| r
                    .get::<_, i64>(0))?,
                i64::from(applied)
            );
            assert_eq!(
                db.query_row("SELECT count(*) FROM main.oauth_restore_closed", [], |r| {
                    r.get::<_, i64>(0)
                })?,
                if applied { 7 } else { 0 }
            );
            assert_eq!(db.query_row("SELECT count(*) FROM main.oauth_connection_slots WHERE status=?1 AND security_epoch=?2",params![if applied {"reauth_required"} else {"active"},if applied {2} else {1}],|r|r.get::<_,i64>(0))?,4);
            assert_eq!(
                db.query_row(
                    "SELECT state,code_ref FROM main.oauth_connect_attempts WHERE attempt='sent'",
                    [],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                )?,
                ("exchange_may_have_been_sent".into(), "retained_code".into())
            );
            assert_eq!(
                db.query_row(
                    "SELECT receipt FROM main.oauth_refresh_attempts WHERE attempt='refresh_3'",
                    [],
                    |r| r.get::<_, String>(0)
                )?,
                "known_receipt"
            );
        }
    }
    Ok(())
}

#[test]
#[ignore = "singleton subprocess invoked by the mandatory process-loss parent"]
fn restore_cut_process_child() -> Result<()> {
    let root = std::path::PathBuf::from(
        std::env::var_os("G1_RESTORE_CUT_ROOT")
            .ok_or_else(|| anyhow::anyhow!("owned child root required"))?,
    );
    let stage: i32 = std::env::var("G1_RESTORE_CUT_STAGE")?.parse()?;
    assert!((0..3).contains(&stage));
    let mut db = database(&root.join("app.sqlite"))?;
    seed(&mut db)?;
    let profile = Profile::prepare()?;
    let mut tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let before = Snapshot::capture(&tx, &profile)?;
    let cut = crate::security_epoch::restore_cut::fixture(before.digest().clone(), 101)?;
    if stage == 0 {
        std::process::exit(70);
    }
    close_in(&mut tx, before, &cut, &profile)?;
    if stage == 1 {
        std::process::exit(71);
    }
    tx.commit()?;
    std::process::exit(72)
}

#[test]
fn actual_continuation_gates_cannot_drop_retarget_duplicate_or_delay_the_cut_check() -> Result<()> {
    use quote::ToTokens as _;
    use syn::visit::Visit;
    struct Calls(usize);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = call.func.as_ref()
                && path
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == "require_open")
            {
                self.0 += 1;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    fn body(source: &str, name: &str, owner: Option<&str>) -> Result<syn::Block> {
        let syntax = syn::parse_file(source)?;
        let mut selected = Vec::new();
        for item in syntax.items {
            match item {
                syn::Item::Fn(function) if owner.is_none() && function.sig.ident == name => {
                    selected.push(*function.block)
                }
                syn::Item::Impl(implementation)
                    if owner.is_some_and(|owner| {
                        implementation.self_ty.to_token_stream().to_string() == owner
                    }) =>
                {
                    for item in implementation.items {
                        if let syn::ImplItem::Fn(function) = item
                            && function.sig.ident == name
                        {
                            selected.push(function.block);
                        }
                    }
                }
                _ => {}
            }
        }
        ensure!(selected.len() == 1, "actual_cut_gate_selector_count");
        Ok(selected.remove(0))
    }
    fn accepts(block: &syn::Block, prefix: &str, guard: &str, count: usize) -> Result<bool> {
        let expected: syn::Block = syn::parse_str(&format!("{{{prefix}{guard}}}"))?;
        let prefix: Vec<_> = expected
            .stmts
            .iter()
            .map(|s| s.to_token_stream().to_string())
            .collect();
        let actual: Vec<_> = block
            .stmts
            .iter()
            .take(prefix.len())
            .map(|s| s.to_token_stream().to_string())
            .collect();
        let mut calls = Calls(0);
        calls.visit_block(block);
        Ok(actual == prefix && calls.0 == count)
    }
    let connect = include_str!("connect.rs");
    let custody = include_str!("custody.rs");
    let exchange = include_str!("exchange.rs");
    let refresh = include_str!("store.rs");
    let fresh = include_str!("fresh_owner.rs");
    let management = include_str!("management/app.rs");
    let usage = include_str!("usage.rs");
    let inbound = include_str!("inbound.rs");
    let mut specs = Vec::new();
    for name in ["begin_in", "slot_matches"] {
        specs.push((connect, name, None, "", "Connect", "tx", "&intent.attempt"));
    }
    specs.push((connect, "activate_in", None, "", "Connect", "tx", "attempt"));
    specs.push((
        connect,
        "activate_mapped_in",
        None,
        "",
        "Connect",
        "tx",
        "verified.attempt()",
    ));
    specs.push((
        connect,
        "pending_approval",
        None,
        "",
        "Connect",
        "db",
        "attempt",
    ));
    specs.push((connect,"claim_callback",None,"identifier(attempt)?;identifier(code_ref)?;let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;","Connect","&tx","attempt"));
    specs.push((connect,"authorize_and_commit_exchange",None,"identifier(attempt)?;let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;","Connect","&tx","attempt"));
    specs.push((connect,"await_account_approval",None,"identifier(attempt)?;identifier(account)?;identifier(scope_evidence)?;let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;","Connect","&tx","attempt"));
    specs.push((connect,"quarantine_external_bound",None,"let intent=verified.intent();let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;","Connect","&tx","&intent.attempt"));
    specs.push((
        exchange,
        "load_binding",
        None,
        "",
        "Connect",
        "db",
        "attempt",
    ));
    specs.push((
        exchange,
        "authorize_in",
        None,
        "",
        "Connect",
        "tx",
        "&input.intent.attempt",
    ));
    for name in [
        "claim_refresh_in",
        "checked_dispatch_in",
        "commit_replacement_in",
    ] {
        specs.push((refresh, name, None, "", "Refresh", "tx", "attempt"));
    }
    for name in [
        "claim",
        "publish",
        "consume_in_current_app_transaction",
        "terminal_history",
    ] {
        specs.push((
            fresh,
            name,
            None,
            "",
            "Fresh",
            "db",
            "intent.commitment()?.as_str()",
        ));
    }
    for name in ["code_exists", "verifier_exists"] {
        specs.push((custody, name, None, "", "Connect", "tx", "&intent.attempt"));
    }
    for name in ["load_code", "load_verifier", "load_bundle"] {
        specs.push((custody, name, None, "", "Connect", "db", "&intent.attempt"));
    }
    for name in [
        "publish_code",
        "publish_verifier",
        "publish_tokens",
        "replace_tokens",
        "publish_external_quarantine",
    ] {
        specs.push((
            custody,
            name,
            None,
            "",
            "Connect",
            "tx",
            "&prepared.attempt",
        ));
    }
    specs.push((
        custody,
        "quarantine_row",
        None,
        "",
        "Connect",
        "db",
        "attempt",
    ));
    specs.push((usage, "load", None, "", "Use", "db", "reference"));
    specs.push((inbound, "active_grant", None, "", "Inbound", "db", "id"));
    specs.push((inbound, "record_grant", None, "", "Inbound", "db", "id"));
    for (name, id) in [("load", "id"), ("check_in", "&view.id")] {
        specs.push((
            management,
            name,
            Some("Manager"),
            "",
            "Management",
            "db",
            id,
        ));
    }
    assert_eq!(specs.len(), 34);
    for (source, name, owner, prefix, kind, db, id) in specs {
        let root = if owner.is_some() {
            "crate::oauth::restore"
        } else {
            "super::restore"
        };
        let guard = format!("{root}::require_open({db},{root}::Kind::{kind},{id})?;");
        let block = body(source, name, owner)?;
        let count = if kind == "Use" { 2 } else { 1 };
        assert!(accepts(&block, prefix, &guard, count)?, "{name}");
        if kind == "Use" {
            let decoded: syn::Stmt =
                syn::parse_str("let claims:Claims=crate::json::decode(encoded.as_bytes())?;")?;
            let positions: Vec<_> = block
                .stmts
                .iter()
                .enumerate()
                .filter(|(_, statement)| {
                    statement.to_token_stream().to_string() == decoded.to_token_stream().to_string()
                })
                .map(|(i, _)| i)
                .collect();
            assert_eq!(positions.len(), 1);
            let check: syn::Stmt = syn::parse_str(
                "super::restore::require_open(db,super::restore::Kind::UseBinding,claim_identity(&claims)?.as_str())?;",
            )?;
            assert_eq!(
                block.stmts[positions[0] + 1].to_token_stream().to_string(),
                check.to_token_stream().to_string()
            );
            let mut omitted = block.clone();
            omitted.stmts.remove(positions[0] + 1);
            assert!(!accepts(&omitted, prefix, &guard, count)?);
        }
        let expected: syn::Block = syn::parse_str(&format!("{{{prefix}{guard}}}"))?;
        let index = expected.stmts.len() - 1;
        let mut deleted = block.clone();
        deleted.stmts.remove(index);
        assert!(!accepts(&deleted, prefix, &guard, count)?, "deleted {name}");
        let mut delayed = block.clone();
        let check = delayed.stmts.remove(index);
        delayed.stmts.push(check);
        assert!(!accepts(&delayed, prefix, &guard, count)?, "delayed {name}");
        let mut duplicate = block.clone();
        duplicate.stmts.insert(index, expected.stmts[index].clone());
        assert!(
            !accepts(&duplicate, prefix, &guard, count)?,
            "duplicate {name}"
        );
        let mut wrong = block.clone();
        wrong.stmts[index] = syn::parse_str(&guard.replace(id, "\"different_original\""))?;
        assert!(
            !accepts(&wrong, prefix, &guard, count)?,
            "retargeted {name}"
        );
    }
    Ok(())
}
