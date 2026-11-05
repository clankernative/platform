//! Real SQLite/crypto adapters and an independent expected denial cut. These
//! fixtures never construct a native owner, passkey approval or writer.
use super::*;
use crate::oauth::{connect, custody, exchange, inbound, profiles, store};
use rusqlite::TransactionBehavior;
use std::path::Path;

fn database(path: &Path) -> Result<Connection> {
    let db=Connection::open(path)?;
    db.pragma_update(None,"foreign_keys",true)?;
    db.execute_batch(crate::store::PLATFORM_DDL)?;
    db.execute("INSERT INTO day2_meta VALUES('scope','company/canary/calendar')",[])?;
    db.execute("INSERT INTO day2_meta VALUES('schema',?1)",[Digest::new(b"schema").as_str()])?;
    crate::oauth::usage::install(&db)?;
    inbound::install_schema(&db)?;
    Ok(db)
}

fn intent(id: &str) -> connect::ConnectIntent {
    connect::ConnectIntent {attempt:id.into(),slot:format!("slot_{id}"),expected_generation:None,
        expected_epoch:1,proposed_generation:1,owner:"human_1".into(),profile:"google_calendar_v1".into(),
        registration:"registration_1".into(),callback:"callback_1".into(),consent:"consent_1".into(),expires_at:100}
}

fn seed(db: &mut Connection) -> Result<()> {
    assert!(connect::begin(db,&intent("pending"),1)?);
    assert!(connect::begin(db,&intent("sent"),1)?);
    assert!(connect::claim_callback(db,"sent","retained_code",2,|_|Ok(()))?);
    let _may=connect::authorize_and_commit_exchange(db,"sent",3)?.unwrap();
    for (index,state) in ["ready","may_have_been_sent","uncertain","replacement_committed"].into_iter().enumerate() {
        let slot=format!("refresh_slot_{index}");
        db.execute("INSERT INTO oauth_connection_slots VALUES(?1,1,1,1,'profile','account','affinity','active')",[&slot])?;
        db.execute("INSERT INTO oauth_refresh_attempts VALUES(?1,?2,1,1,1,'profile','account','affinity',?3,?4,?5)",
            params![format!("refresh_{index}"),slot,state,if index==3 {Some(2)} else {None},if index==3 {Some("known_receipt")} else {None}])?;
    }
    inbound::record_grant(db,"old_grant",&inbound::tests::ceiling(),1)?;
    Ok(())
}

fn cut(db: &mut Connection, profile: &Profile, seed: u64) -> Result<usize> {
    let mut tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let before=Snapshot::capture(&tx,profile)?;
    let cut=crate::security_epoch::restore_cut::fixture(before.digest().clone(),seed)?;
    let count=close_in(&mut tx,before,&cut,profile)?;
    tx.commit()?;
    Ok(count)
}

type ConnectHistory=Vec<(String,String,Option<String>)>;
type RefreshHistory=Vec<(String,String,Option<i64>,Option<String>)>;

fn histories(db: &Connection) -> Result<(ConnectHistory,RefreshHistory)> {
    let mut q=db.prepare("SELECT attempt,state,code_ref FROM main.oauth_connect_attempts ORDER BY attempt")?;
    let connects=q.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
    let mut q=db.prepare("SELECT attempt,state,next_version,receipt FROM main.oauth_refresh_attempts ORDER BY attempt")?;
    let refresh=q.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok((connects,refresh))
}

#[test]
fn complete_cut_preserves_unknown_and_known_histories_and_reopens_as_denial() -> Result<()> {
    let profile=Profile::prepare()?;
    for seed_number in [3,17,81] {
        let dir=tempfile::tempdir()?;let path=dir.path().join("app.sqlite");
        let mut db=database(&path)?;seed(&mut db)?;let history=histories(&db)?;
        assert_eq!(cut(&mut db,&profile,seed_number)?,7); // 2 connect + 4 refresh + 1 grant.
        drop(db);
        for _ in 0..2 {
            let mut db=Connection::open(&path)?;db.pragma_update(None,"foreign_keys",true)?;
            assert_eq!(histories(&db)?,history);
            assert_eq!(db.query_row("SELECT count(*) FROM main.oauth_connection_slots WHERE status='reauth_required' AND security_epoch=2 AND generation=1 AND token_version=1",[],|r|r.get::<_,i64>(0))?,4);
            assert_eq!(db.query_row("SELECT status,epoch FROM main.oauth_inbound_grants WHERE id='old_grant'",[],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?)))?,("revoked".into(),2));
            assert!(store::authorize_and_commit_dispatch(&mut db,"refresh_0").is_err());
            assert!(connect::claim_callback(&mut db,"pending","late_code",5,|_|panic!("closed callback entered custody")).is_err());
            assert!(connect::await_account_approval(&mut db,"sent","account","scope",5,|_|panic!("closed response entered custody")).is_err());
            assert!(connect::begin(&mut db,&intent("pending"),5).is_err());
            assert!(require_open(&db,Kind::Inbound,"old_grant").is_err());
            assert!(require_no_history(&db).is_err());
            assert!(db.execute("DELETE FROM main.oauth_restore_closed",[]).is_err());
            assert!(db.execute("UPDATE main.oauth_restore_cuts SET inventory=inventory",[]).is_err());
            assert_eq!(histories(&db)?,history);
        }
    }
    Ok(())
}

#[test]
fn late_prepared_code_and_tokens_cannot_publish_or_decrypt_after_cut() -> Result<()> {
    crate::oauth::effects::scope(crate::oauth::simulation::World::new(9721),|| {
        let dir=tempfile::tempdir()?;let mut db=database(&dir.path().join("app.sqlite"))?;
        let profile=Profile::prepare()?;
        let fixture=profiles::tests::external_fixture();
        let key=profiles::tests::exchange_key();
        let authorization=exchange::prepare_authorization(fixture.input(),&key,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")?;
        let binding=authorization.parts().2.clone();
        assert!(authorization.begin(&mut db,1)?);
        let code=custody::prepare_code(&key,&fixture.intent,&binding,"fixture_code")?;
        let raw=br#"{"access_token":"fixture_access","refresh_token":"fixture_refresh","token_type":"Bearer","expires_in":300,"scope":"calendar.read"}"#;
        let tokens=fixture.reviewed.validate_token_response(raw,&fixture.permission)?;
        let held=custody::prepare_tokens(&key,&fixture.intent,"account_1",&binding,tokens,2)?;
        let before:Vec<u8>=db.query_row("SELECT ciphertext FROM main.oauth_private_verifiers",[],|r|r.get(0))?;
        cut(&mut db,&profile,19)?;
        let tx=db.transaction()?;
        assert!(custody::publish_code(&tx,code).is_err());
        assert!(custody::publish_tokens(&tx,held).is_err());
        assert!(custody::load_verifier(&tx,&key,&fixture.intent,&binding).is_err());
        assert_eq!(tx.query_row("SELECT count(*) FROM main.oauth_private_codes",[],|r|r.get::<_,i64>(0))?,0);
        assert_eq!(tx.query_row("SELECT count(*) FROM main.oauth_private_tokens",[],|r|r.get::<_,i64>(0))?,0);
        assert_eq!(tx.query_row("SELECT ciphertext FROM main.oauth_private_verifiers",[],|r|r.get::<_,Vec<u8>>(0))?,before);
        tx.commit()?;
        Ok(())
    })
}

#[test]
fn old_slot_cannot_be_adopted_but_fresh_scope_still_needs_new_authorization() -> Result<()> {
    let dir=tempfile::tempdir()?;let mut db=database(&dir.path().join("app.sqlite"))?;
    let profile=Profile::prepare()?;seed(&mut db)?;cut(&mut db,&profile,20)?;
    let mut adoption=intent("new_attempt");adoption.slot="refresh_slot_0".into();
    assert!(!connect::begin(&mut db,&adoption,5)?);
    adoption.expected_generation=Some(1);adoption.proposed_generation=2;adoption.expected_epoch=2;
    assert!(!connect::begin(&mut db,&adoption,5)?); // No implicit restored-slot replacement profile.
    let fresh=intent("new_scoped_authorization");
    assert!(connect::begin(&mut db,&fresh,5)?); // Navigation only, never a provider or native permit.
    assert_eq!(connect::state(&db,&fresh.attempt)?,Some(connect::ConnectState::AwaitingProviderAuthorization));
    assert_eq!(db.query_row("SELECT count(*) FROM main.oauth_connection_slots WHERE status='active'",[],|r|r.get::<_,i64>(0))?,0);
    Ok(())
}

#[test]
fn changed_row_or_identity_inventory_refuses_without_repair() -> Result<()> {
    for mutation in 0..4 {
        let dir=tempfile::tempdir()?;let mut db=database(&dir.path().join("app.sqlite"))?;
        let profile=Profile::prepare()?;seed(&mut db)?;
        let mut tx=db.transaction()?;let before=Snapshot::capture(&tx,&profile)?;
        let cut=crate::security_epoch::restore_cut::fixture(before.digest().clone(),21)?;
        match mutation {
            0=>{tx.execute("UPDATE main.oauth_connection_slots SET affinity='changed' WHERE slot='refresh_slot_0'",[])?;}
            1=>{tx.execute("UPDATE main.oauth_connect_attempts SET consent='changed' WHERE attempt='pending'",[])?;}
            2=>{tx.execute("UPDATE main.day2_meta SET value='foreign/scope/app' WHERE key='scope'",[])?;}
            _=>{tx.execute("INSERT INTO main.oauth_connect_attempts SELECT 'new_identity',slot,expected_generation,expected_epoch,proposed_generation,owner,profile,registration,callback,consent,expires_at,state,code_ref,account,scope_evidence FROM main.oauth_connect_attempts WHERE attempt='pending'",[])?;}
        }
        assert!(close_in(&mut tx,before,&cut,&profile).is_err());
        assert_eq!(tx.query_row("SELECT count(*) FROM main.oauth_restore_cuts",[],|r|r.get::<_,i64>(0))?,0);
        tx.rollback()?;
    }
    Ok(())
}

#[test]
fn late_failure_rolls_back_cut_and_all_local_revocations_even_if_caller_catches_it() -> Result<()> {
    for failure in ["slot", "inbound"] {
        let dir=tempfile::tempdir()?;let mut db=database(&dir.path().join("app.sqlite"))?;
        let profile=Profile::prepare()?;seed(&mut db)?;let before_history=histories(&db)?;
        // Valid but exhausted inputs are refused, never clamped or wrapped.
        let table=if failure=="slot" {"oauth_connection_slots"} else {"oauth_inbound_grants"};
        let column=if failure=="slot" {"security_epoch"} else {"epoch"};
        db.execute(&format!("UPDATE {table} SET {column}=9223372036854775807"),[])?;
        let mut tx=db.transaction()?;let snapshot=Snapshot::capture(&tx,&profile)?;
        let cut=crate::security_epoch::restore_cut::fixture(snapshot.digest().clone(),22)?;
        assert!(close_in(&mut tx,snapshot,&cut,&profile).is_err());
        tx.commit()?; // Catching the failure must not persist a prefix.
        assert_eq!(db.query_row("SELECT count(*) FROM main.oauth_restore_cuts",[],|r|r.get::<_,i64>(0))?,0);
        assert_eq!(db.query_row("SELECT count(*) FROM main.oauth_restore_closed",[],|r|r.get::<_,i64>(0))?,0);
        assert_eq!(histories(&db)?,before_history);
        assert_eq!(db.query_row("SELECT count(*) FROM main.oauth_connection_slots WHERE status='active'",[],|r|r.get::<_,i64>(0))?,4);
    }
    Ok(())
}

#[test]
fn missing_partial_shadow_and_unknown_units_refuse_before_any_cut() -> Result<()> {
    for mutation in 0..5 {
        let dir=tempfile::tempdir()?;let mut db=database(&dir.path().join("app.sqlite"))?;
        let profile=Profile::prepare()?;
        match mutation {
            0=>db.execute_batch("CREATE TEMP TABLE oauth_connect_attempts(untrusted TEXT)")?,
            1=>db.execute_batch("CREATE TABLE oauth_unreviewed_callback(untrusted TEXT)")?,
            2=>db.execute_batch("DROP TABLE oauth_use_handles")?,
            3=>db.execute_batch("CREATE TEMP TABLE day2_meta(key TEXT,value TEXT)")?,
            _=>db.execute_batch("ATTACH ':memory:' AS foreign_state")?,
        }
        let tx=db.transaction()?;assert!(Snapshot::capture(&tx,&profile).is_err());
        assert_eq!(tx.query_row("SELECT count(*) FROM main.oauth_restore_cuts",[],|r|r.get::<_,i64>(0))?,0);
        tx.rollback()?;
    }
    Ok(())
}

#[test]
fn ordinary_restore_allows_only_empty_current_cut_metadata() -> Result<()> {
    let mut db=Connection::open_in_memory()?;
    {let tx=db.transaction()?;require_no_history(&tx)?;tx.commit()?;}
    install(&db)?;
    {let tx=db.transaction()?;require_no_history(&tx)?;tx.commit()?;}
    db.execute("DELETE FROM oauth_restore_schema_version",[])?;
    let tx=db.transaction()?;assert!(require_no_history(&tx).is_err());tx.rollback()?;
    Ok(())
}
