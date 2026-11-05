//! Real SQLite/crypto adapters and an independent expected denial cut. These
//! fixtures never construct a native owner, passkey approval or writer.
use super::*;
use crate::oauth::{connect, custody, exchange, inbound, profiles, store};
use rusqlite::TransactionBehavior;
use std::path::Path;

fn database(path: &Path) -> Result<Connection> {
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
    for mutation in 0..5 {
        let dir = tempfile::tempdir()?;
        let mut db = database(&dir.path().join("app.sqlite"))?;
        let profile = Profile::prepare()?;
        match mutation {
            0 => db.execute_batch("CREATE TEMP TABLE oauth_connect_attempts(untrusted TEXT)")?,
            1 => db.execute_batch("CREATE TABLE oauth_unreviewed_callback(untrusted TEXT)")?,
            2 => db.execute_batch("DROP TABLE oauth_use_handles")?,
            3 => db.execute_batch("CREATE TEMP TABLE day2_meta(key TEXT,value TEXT)")?,
            _ => db.execute_batch("ATTACH ':memory:' AS foreign_state")?,
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
fn actual_continuation_gates_cannot_drop_retarget_duplicate_or_delay_the_cut_check() -> Result<()> {
    use quote::ToTokens as _;
    use syn::visit::Visit;
    struct Calls(usize);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path)=call.func.as_ref()
                && path.path.segments.last().is_some_and(|part|part.ident=="require_open") {
                self.0+=1;
            }
            syn::visit::visit_expr_call(self,call);
        }
    }
    fn body(source:&str,name:&str,owner:Option<&str>)->Result<syn::Block> {
        let syntax=syn::parse_file(source)?;
        let mut selected=Vec::new();
        for item in syntax.items {
            match item {
                syn::Item::Fn(function) if owner.is_none() && function.sig.ident==name => selected.push(*function.block),
                syn::Item::Impl(implementation) if owner.is_some_and(|owner|implementation.self_ty.to_token_stream().to_string()==owner) => {
                    for item in implementation.items {
                        if let syn::ImplItem::Fn(function)=item && function.sig.ident==name {selected.push(function.block);}
                    }
                }
                _=>{}
            }
        }
        ensure!(selected.len()==1,"actual_cut_gate_selector_count");
        Ok(selected.remove(0))
    }
    fn accepts(block:&syn::Block,prefix:&str,guard:&str)->Result<bool> {
        let expected:syn::Block=syn::parse_str(&format!("{{{prefix}{guard}}}"))?;
        let prefix:Vec<_>=expected.stmts.iter().map(|s|s.to_token_stream().to_string()).collect();
        let actual:Vec<_>=block.stmts.iter().take(prefix.len()).map(|s|s.to_token_stream().to_string()).collect();
        let mut calls=Calls(0);calls.visit_block(block);
        Ok(actual==prefix && calls.0==1)
    }
    let connect=include_str!("connect.rs");let custody=include_str!("custody.rs");
    let exchange=include_str!("exchange.rs");let refresh=include_str!("store.rs");
    let fresh=include_str!("fresh_owner.rs");let management=include_str!("management/app.rs");
    let usage=include_str!("usage.rs");let inbound=include_str!("inbound.rs");
    let mut specs=Vec::new();
    for name in ["begin_in","slot_matches"] {specs.push((connect,name,None,"","Connect","tx","&intent.attempt"));}
    specs.push((connect,"activate_in",None,"","Connect","tx","attempt"));
    specs.push((connect,"activate_mapped_in",None,"","Connect","tx","verified.attempt()"));
    specs.push((connect,"pending_approval",None,"","Connect","db","attempt"));
    specs.push((connect,"claim_callback",None,"identifier(attempt)?;identifier(code_ref)?;let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;","Connect","&tx","attempt"));
    specs.push((connect,"authorize_and_commit_exchange",None,"identifier(attempt)?;let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;","Connect","&tx","attempt"));
    specs.push((connect,"await_account_approval",None,"identifier(attempt)?;identifier(account)?;identifier(scope_evidence)?;let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;","Connect","&tx","attempt"));
    specs.push((connect,"quarantine_external_bound",None,"let intent=verified.intent();let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;","Connect","&tx","&intent.attempt"));
    specs.push((exchange,"load_binding",None,"","Connect","db","attempt"));
    specs.push((exchange,"authorize_in",None,"","Connect","tx","&input.intent.attempt"));
    for name in ["claim_refresh_in","checked_dispatch_in","commit_replacement_in"] {specs.push((refresh,name,None,"","Refresh","tx","attempt"));}
    for name in ["claim","publish","consume_in_current_app_transaction","terminal_history"] {specs.push((fresh,name,None,"","Fresh","db","intent.commitment()?.as_str()"));}
    for name in ["code_exists","verifier_exists"] {specs.push((custody,name,None,"","Connect","tx","&intent.attempt"));}
    for name in ["load_code","load_verifier","load_bundle"] {specs.push((custody,name,None,"","Connect","db","&intent.attempt"));}
    for name in ["publish_code","publish_verifier","publish_tokens","replace_tokens","publish_external_quarantine"] {specs.push((custody,name,None,"","Connect","tx","&prepared.attempt"));}
    specs.push((custody,"quarantine_row",None,"","Connect","db","attempt"));
    specs.push((usage,"load",None,"","Use","db","reference"));
    specs.push((inbound,"active_grant",None,"","Inbound","db","id"));
    specs.push((inbound,"record_grant",None,"","Inbound","db","id"));
    for (name,id) in [("load","id"),("check_in","&view.id")] {specs.push((management,name,Some("Manager"),"","Management","db",id));}
    assert_eq!(specs.len(),34);
    for (source,name,owner,prefix,kind,db,id) in specs {
        let root=if owner.is_some(){"crate::oauth::restore"}else{"super::restore"};
        let guard=format!("{root}::require_open({db},{root}::Kind::{kind},{id})?;");
        let block=body(source,name,owner)?;
        assert!(accepts(&block,prefix,&guard)?,"{name}");
        let expected:syn::Block=syn::parse_str(&format!("{{{prefix}{guard}}}"))?;
        let index=expected.stmts.len()-1;
        let mut deleted=block.clone();deleted.stmts.remove(index);
        assert!(!accepts(&deleted,prefix,&guard)?,"deleted {name}");
        let mut delayed=block.clone();let check=delayed.stmts.remove(index);delayed.stmts.push(check);
        assert!(!accepts(&delayed,prefix,&guard)?,"delayed {name}");
        let mut duplicate=block.clone();duplicate.stmts.insert(index,expected.stmts[index].clone());
        assert!(!accepts(&duplicate,prefix,&guard)?,"duplicate {name}");
        let mut wrong=block.clone();wrong.stmts[index]=syn::parse_str(&guard.replace(id,"\"different_original\""))?;
        assert!(!accepts(&wrong,prefix,&guard)?,"retargeted {name}");
    }
    Ok(())
}
