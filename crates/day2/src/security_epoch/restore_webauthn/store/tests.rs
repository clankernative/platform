use super::*;
use crate::security_epoch::restore_webauthn::tests::{Fixture, fixture};
use std::cell::RefCell;

mod attempts;
mod process;

type Hook = Box<dyn FnMut(Cut) -> Result<()>>;
thread_local! { static HOOK: RefCell<Option<Hook>> = const {RefCell::new(None)}; }

pub(super) fn checkpoint(cut: Cut) -> Result<()> {
    HOOK.with(|hook| match hook.borrow_mut().as_mut() {
        Some(hook) => hook(cut),
        None => Ok(()),
    })
}

struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        HOOK.with(|hook| *hook.borrow_mut() = None);
    }
}

fn inject(hook: impl FnMut(Cut) -> Result<()> + 'static) -> Reset {
    HOOK.with(|active| {
        assert!(active.borrow().is_none());
        *active.borrow_mut() = Some(Box::new(hook));
    });
    Reset
}

fn prepare(db: &mut Connection, f: &Fixture) -> Digest {
    db.execute_batch(DDL).unwrap();
    db.execute(
        "INSERT INTO main.restore_passkey_keys VALUES(?1,?2,1,0,1)",
        params![
            &f.key.record.credential_id,
            f.key.binding().unwrap().as_str()
        ],
    )
    .unwrap();
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let id = issue(&tx, &f.key, &f.challenge, 1000, 1300).unwrap();
    tx.commit().unwrap();
    id
}

#[test]
fn executor_completion_rechecks_the_new_counter_and_exact_verified_row_after_reopen() -> Result<()>
{
    let mut f = fixture();
    let directory = tempfile::tempdir()?;
    let path = directory.path().canonicalize()?.join("execution.sqlite");
    let mut db = Connection::open(&path)?;
    let approval = prepare(&mut db, &f);
    complete(
        &mut db,
        &f.key,
        &approval,
        &f.challenge.request,
        1100,
        &f.assertion(1, 0x0d),
    )?;
    // The SAME administrator/key now authenticates execution. Its successful
    // approval already advanced the version/counter; that old value must not
    // be required by the new executor completion.
    f.challenge.request = Digest::of(&(
        "day2-restore-executor-assertion-v1",
        Digest::new(b"complete signed approval"),
        Digest::new(b"one actual operation"),
    ))?;
    f.challenge.nonce = [79; 32];
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let id = issue(&tx, &f.key, &f.challenge, 1100, 1400)?;
    assert!(verified_snapshot(&tx, &f.key, &f.challenge, 2).is_err());
    tx.commit()?;
    complete(
        &mut db,
        &f.key,
        &id,
        &f.challenge.request,
        1200,
        &f.assertion(2, 0x0d),
    )?;
    let tx = db.transaction()?;
    let expected = verified_snapshot(&tx, &f.key, &f.challenge, 2)?;
    assert_eq!(expected.0, 3);
    tx.commit()?;
    drop(db);
    let mut db = Connection::open(&path)?;
    let tx = db.transaction()?;
    assert_eq!(verified_snapshot(&tx, &f.key, &f.challenge, 2)?, expected);
    assert!(verified_snapshot(&tx, &f.key, &f.challenge, 1).is_err());
    tx.commit()?;
    // Independent expectation: every listed persistent transition invalidates
    // the saved completion. Each actual transaction is rolled back only to
    // reset this fixture, never to promise production rollback after delivery.
    let foreign = Digest::new(b"foreign binding").as_str().to_owned();
    for mutation in [
        "UPDATE restore_passkey_keys SET enabled=0".to_owned(),
        "UPDATE restore_passkey_keys SET version=version+1".to_owned(),
        "UPDATE restore_passkey_keys SET counter=counter+1".to_owned(),
        format!("UPDATE restore_passkey_keys SET binding='{foreign}'"),
        "UPDATE restore_passkey_challenges SET state='claimed' WHERE state='verified'".to_owned(),
        format!("UPDATE restore_passkey_challenges SET request='{foreign}'"),
        format!("UPDATE restore_passkey_challenges SET binding='{foreign}'"),
        "UPDATE restore_passkey_challenges SET nonce=zeroblob(32)".to_owned(),
        "UPDATE restore_passkey_challenges SET key_version=key_version+1".to_owned(),
        "UPDATE restore_passkey_challenges SET counter=counter+1".to_owned(),
        "UPDATE restore_passkey_challenges SET created_at=created_at+1,expires_at=expires_at+1"
            .to_owned(),
        "DELETE FROM restore_passkey_challenges".to_owned(),
    ] {
        let tx = db.transaction()?;
        tx.execute_batch(&mutation)?;
        let actual = verified_snapshot(&tx, &f.key, &f.challenge, 2);
        assert!(actual.is_err() || actual.as_ref().is_ok_and(|value| value != &expected));
        tx.rollback()?;
    }
    // A denied assertion leaves a claimed tombstone, never a completed row.
    f.challenge.nonce = [83; 32];
    let tx = db.transaction()?;
    let denied = issue(&tx, &f.key, &f.challenge, 1200, 1500)?;
    tx.commit()?;
    assert!(
        complete(
            &mut db,
            &f.key,
            &denied,
            &f.challenge.request,
            1300,
            &f.assertion(3, 0x09)
        )
        .is_err()
    );
    let tx = db.transaction()?;
    assert!(verified_snapshot(&tx, &f.key, &f.challenge, 3).is_err());
    tx.commit()?;
    Ok(())
}

fn observed(db: &Connection) -> (String, i64, u32) {
    for table in [
        "main.restore_passkey_keys",
        "main.restore_passkey_challenges",
    ] {
        let count: i64 = db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "complete fixture snapshot required");
    }
    db.query_row("SELECT c.state,k.version,k.counter FROM main.restore_passkey_challenges c CROSS JOIN main.restore_passkey_keys k",[],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap()
}

type SchemaRow = (String, String, String, Option<String>);

fn schema_snapshot(db: &Connection) -> Result<Vec<SchemaRow>> {
    let mut query =
        db.prepare("SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name")?;
    let rows = query.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

#[test]
fn existing_schema_admission_survives_real_reopen_without_changing_rows() -> Result<()> {
    let f = fixture();
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("authentication.sqlite");
    let mut db = Connection::open(&path)?;
    prepare(&mut db, &f);
    db.pragma_update(None, "journal_mode", "WAL")?;
    let before = observed(&db);
    let schema = schema_snapshot(&db)?;
    require_existing_schema(&db)?;
    assert!(db.is_autocommit());
    assert_eq!(observed(&db), before);
    assert_eq!(schema_snapshot(&db)?, schema);
    drop(db);
    let reopened = Connection::open(&path)?;
    require_existing_schema(&reopened)?;
    assert!(reopened.is_autocommit());
    assert_eq!(observed(&reopened), before);
    assert_eq!(schema_snapshot(&reopened)?, schema);
    Ok(())
}

#[test]
fn existing_schema_admission_never_initializes_missing_or_partial_schema() -> Result<()> {
    for ddl in ["", DDL.split_once(';').unwrap().0] {
        let db = Connection::open_in_memory()?;
        db.execute_batch(ddl)?;
        let before = schema_snapshot(&db)?;
        assert!(require_existing_schema(&db).is_err());
        assert!(db.is_autocommit());
        assert_eq!(schema_snapshot(&db)?, before);
    }
    Ok(())
}

#[test]
fn existing_schema_admission_refuses_extra_objects_without_repair() -> Result<()> {
    for extra in [
        "CREATE TABLE unexpected(value INTEGER)",
        "CREATE VIEW unexpected AS SELECT * FROM restore_passkey_keys",
        "CREATE INDEX unexpected ON restore_passkey_keys(counter)",
        "CREATE TRIGGER unexpected AFTER INSERT ON restore_passkey_keys BEGIN
             UPDATE restore_passkey_keys SET enabled=0; END",
    ] {
        let db = Connection::open_in_memory()?;
        db.execute_batch(DDL)?;
        require_existing_schema(&db)?;
        db.execute_batch(extra)?;
        let before = schema_snapshot(&db)?;
        assert!(require_existing_schema(&db).is_err(), "{extra}");
        assert!(db.is_autocommit());
        assert_eq!(schema_snapshot(&db)?, before);
    }
    Ok(())
}

#[test]
fn existing_schema_admission_refuses_changed_constraints_and_table_shapes() -> Result<()> {
    for changed in [
        DDL.replace("counter BETWEEN 0 AND 4294967295", "counter>=0"),
        DDL.replace("version>0", "version>=0"),
        DDL.replace(") STRICT", ")"),
        DDL.replace("nonce BLOB NOT NULL", "nonce TEXT NOT NULL"),
        DDL.replace("PRIMARY KEY", "UNIQUE"),
    ] {
        assert_ne!(changed, DDL);
        let db = Connection::open_in_memory()?;
        db.execute_batch(&changed)?;
        let before = schema_snapshot(&db)?;
        assert!(require_existing_schema(&db).is_err());
        assert!(db.is_autocommit());
        assert_eq!(schema_snapshot(&db)?, before);
    }
    Ok(())
}

#[test]
fn existing_schema_admission_cannot_use_a_temp_shadow_for_a_missing_main_table() -> Result<()> {
    let db = Connection::open_in_memory()?;
    db.execute_batch(&DDL.replace("main.", "temp."))?;
    assert!(require_existing_schema(&db).is_err());
    assert!(schema_snapshot(&db)?.is_empty());
    // Four canonical tables and their four implicit primary-key indexes exist
    // only in TEMP; none may replace the missing main catalog.
    assert_eq!(
        db.query_row("SELECT count(*) FROM temp.sqlite_schema", [], |r| r
            .get::<_, i64>(0))?,
        8
    );
    Ok(())
}

#[test]
fn existing_schema_admission_refuses_a_callers_active_transaction_without_closing_it() -> Result<()>
{
    let db = Connection::open_in_memory()?;
    db.execute_batch(DDL)?;
    db.execute_batch("BEGIN")?;
    assert!(require_existing_schema(&db).is_err());
    assert!(!db.is_autocommit());
    db.execute_batch("ROLLBACK")?;
    require_existing_schema(&db)
}

#[test]
fn counterless_completion_is_durable_and_cannot_replay_after_reopen() {
    let f = fixture();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("outside-restore.sqlite");
    let mut db = Connection::open(&path).unwrap();
    let id = prepare(&mut db, &f);
    let assertion = f.assertion(0, 0x0d);
    assert_eq!(
        complete(&mut db, &f.key, &id, &f.challenge.request, 1001, &assertion)
            .unwrap()
            .counter,
        0
    );
    assert_eq!(observed(&db), ("verified".into(), 2, 0));
    drop(db);
    let mut reopened = Connection::open(path).unwrap();
    assert!(
        complete(
            &mut reopened,
            &f.key,
            &id,
            &f.challenge.request,
            1002,
            &assertion
        )
        .is_err()
    );
    assert_eq!(observed(&reopened), ("verified".into(), 2, 0));
    let tx = reopened.transaction().unwrap();
    assert!(issue(&tx, &f.key, &f.challenge, 1002, 1300).is_err());
    tx.rollback().unwrap();
}

#[test]
fn bad_signature_expiry_and_rewind_burn_the_claim_before_refusal() {
    for fault in 0..3 {
        let f = fixture();
        let root = tempfile::tempdir().unwrap();
        let mut db = Connection::open(root.path().join("outside-restore.sqlite")).unwrap();
        let id = prepare(&mut db, &f);
        let mut assertion = f.assertion(1, 0x0d);
        let at = match fault {
            0 => {
                assertion.signature[10] ^= 1;
                1001
            }
            1 => 1300,
            2 => 999,
            _ => unreachable!(),
        };
        assert!(complete(&mut db, &f.key, &id, &f.challenge.request, at, &assertion).is_err());
        assert_eq!(observed(&db), ("claimed".into(), 1, 0));
        // A valid replacement assertion and repaired scalar time cannot revive
        // the same durable challenge, even through a newly opened transaction.
        assert!(
            complete(
                &mut db,
                &f.key,
                &id,
                &f.challenge.request,
                1002,
                &f.assertion(1, 0x0d)
            )
            .is_err()
        );
        assert_eq!(observed(&db), ("claimed".into(), 1, 0));
    }
}

#[test]
fn wrong_request_or_stale_current_enrollment_cannot_claim() {
    let f = fixture();
    let root = tempfile::tempdir().unwrap();
    let mut db = Connection::open(root.path().join("outside-restore.sqlite")).unwrap();
    let id = prepare(&mut db, &f);
    assert!(
        complete(
            &mut db,
            &f.key,
            &id,
            &Digest::new(b"wrong restore request"),
            1001,
            &f.assertion(1, 0x0d)
        )
        .is_err()
    );
    assert_eq!(observed(&db), ("pending".into(), 1, 0));
    db.execute("UPDATE main.restore_passkey_keys SET enabled=0", [])
        .unwrap();
    assert!(
        complete(
            &mut db,
            &f.key,
            &id,
            &f.challenge.request,
            1001,
            &f.assertion(1, 0x0d)
        )
        .is_err()
    );
    assert_eq!(observed(&db), ("pending".into(), 1, 0));
}

#[test]
fn key_removal_registry_binding_change_and_equal_value_aba_after_signature_refuse() {
    for fault in 0..4 {
        let f = fixture();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("outside-restore.sqlite");
        let mut db = Connection::open(&path).unwrap();
        let id = prepare(&mut db, &f);
        let _reset = inject(move |cut| {
            if cut == Cut::AfterSignature {
                let peer = Connection::open(&path)?;
                match fault {
                    0 => {
                        peer.execute("DELETE FROM main.restore_passkey_keys", [])?;
                    }
                    1 => {
                        peer.execute("UPDATE main.restore_passkey_keys SET enabled=0", [])?;
                    }
                    2 => {
                        peer.execute(
                            "UPDATE main.restore_passkey_keys SET binding=?1",
                            [Digest::new(b"new selected registry binding").as_str()],
                        )?;
                    }
                    3 => {
                        peer.execute("UPDATE main.restore_passkey_keys SET version=version+1", [])?;
                    }
                    _ => unreachable!(),
                }
            }
            Ok(())
        });
        assert!(
            complete(
                &mut db,
                &f.key,
                &id,
                &f.challenge.request,
                1001,
                &f.assertion(1, 0x0d)
            )
            .is_err()
        );
        let state: String = db
            .query_row(
                "SELECT state FROM main.restore_passkey_challenges",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "claimed");
        let changed_counter: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM main.restore_passkey_keys WHERE counter<>0)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!changed_counter);
    }
}

#[test]
fn independent_error_cut_model_matches_durable_counter_and_completion_rows() {
    // Expected outcomes come from the explicit commit boundaries, never from
    // the returned error or implementation reconciliation. Every injected cut
    // returns Err, including an already committed final transaction.
    for cut in [
        Cut::AfterClaim,
        Cut::AfterSignature,
        Cut::AfterCounter,
        Cut::BeforeCommit,
        Cut::AfterCommit,
    ] {
        let f = fixture();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("outside-restore.sqlite");
        let mut db = Connection::open(&path).unwrap();
        let id = prepare(&mut db, &f);
        let _reset = inject(move |at| {
            ensure!(at != cut, "controlled cut");
            Ok(())
        });
        assert!(
            complete(
                &mut db,
                &f.key,
                &id,
                &f.challenge.request,
                1001,
                &f.assertion(7, 0x0d)
            )
            .is_err()
        );
        drop(db);
        let mut reopened = Connection::open(path).unwrap();
        let expected = if cut == Cut::AfterCommit {
            ("verified".into(), 2, 7)
        } else {
            ("claimed".into(), 1, 0)
        };
        assert_eq!(observed(&reopened), expected);
        assert!(
            complete(
                &mut reopened,
                &f.key,
                &id,
                &f.challenge.request,
                1002,
                &f.assertion(8, 0x0d)
            )
            .is_err()
        );
        assert_eq!(observed(&reopened), expected);
    }
}

#[test]
fn two_valid_counterless_assertions_racing_one_challenge_have_one_winner() {
    let f = fixture();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("outside-restore.sqlite");
    let mut db = Connection::open(&path).unwrap();
    let id = prepare(&mut db, &f);
    drop(db);
    let start = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let record = f.key.record.clone();
        let request = f.challenge.request.clone();
        let assertion = f.assertion(0, 0x0d);
        let id = id.clone();
        let path = path.clone();
        let start = start.clone();
        workers.push(std::thread::spawn(move || {
            // Only authenticator INPUT crosses threads. Construct the test-only
            // key inside its thread; genuine native key owners stay !Send.
            let key = TrustedKey {
                record,
                source: super::super::KeySource::Fixture,
            };
            let mut db = Connection::open(path).unwrap();
            db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
            start.wait();
            complete(&mut db, &key, &id, &request, 1001, &assertion).is_ok()
        }));
    }
    let successes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .filter(|won| *won)
        .count();
    assert_eq!(successes, 1);
    assert_eq!(
        observed(&Connection::open(path).unwrap()),
        ("verified".into(), 2, 0)
    );
}

#[test]
fn issue_rejects_invalid_lifetimes_and_never_updates_an_existing_challenge() {
    let f = fixture();
    let root = tempfile::tempdir().unwrap();
    let mut db = Connection::open(root.path().join("outside-restore.sqlite")).unwrap();
    let id = prepare(&mut db, &f);
    for (begin, end) in [(-1, 1), (1, 1), (2, 1), (1, 302), (i64::MAX, i64::MIN)] {
        let tx = db.transaction().unwrap();
        assert!(issue(&tx, &f.key, &f.challenge, begin, end).is_err());
        tx.rollback().unwrap();
    }
    assert_eq!(observed(&db), ("pending".into(), 1, 0));
    assert!(
        complete(
            &mut db,
            &f.key,
            &id,
            &f.challenge.request,
            1299,
            &f.assertion(1, 0x0d)
        )
        .is_ok()
    );
}

#[test]
fn memory_or_nondurable_ledger_cannot_issue_or_complete() {
    let f = fixture();
    let mut memory = Connection::open_in_memory().unwrap();
    memory.execute_batch(DDL).unwrap();
    memory
        .execute(
            "INSERT INTO main.restore_passkey_keys VALUES(?1,?2,1,0,1)",
            params![
                &f.key.record.credential_id,
                f.key.binding().unwrap().as_str()
            ],
        )
        .unwrap();
    let tx = memory.transaction().unwrap();
    assert!(issue(&tx, &f.key, &f.challenge, 1000, 1300).is_err());
    tx.rollback().unwrap();
    let root = tempfile::tempdir().unwrap();
    let mut db = Connection::open(root.path().join("outside-restore.sqlite")).unwrap();
    let id = prepare(&mut db, &f);
    db.pragma_update(None, "synchronous", "OFF").unwrap();
    assert!(
        complete(
            &mut db,
            &f.key,
            &id,
            &f.challenge.request,
            1001,
            &f.assertion(1, 0x0d)
        )
        .is_err()
    );
    assert_eq!(observed(&db), ("pending".into(), 1, 0));
}

#[test]
fn temp_shadows_cannot_substitute_the_key_or_discard_a_durable_claim() {
    for revoked in [false, true] {
        let f = fixture();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("outside-restore.sqlite");
        let mut db = Connection::open(&path).unwrap();
        let id = prepare(&mut db, &f);
        db.execute_batch(&DDL.replace("main.", "temp.")).unwrap();
        db.execute_batch("INSERT INTO temp.restore_passkey_keys SELECT * FROM main.restore_passkey_keys;
                          INSERT INTO temp.restore_passkey_challenges SELECT * FROM main.restore_passkey_challenges;").unwrap();
        if revoked {
            db.execute("UPDATE main.restore_passkey_keys SET enabled=0", [])
                .unwrap();
        }
        let result = complete(
            &mut db,
            &f.key,
            &id,
            &f.challenge.request,
            1001,
            &f.assertion(0, 0x0d),
        );
        assert_eq!(result.is_ok(), !revoked);
        let expected = if revoked {
            ("pending".into(), 1, 0)
        } else {
            ("verified".into(), 2, 0)
        };
        assert_eq!(observed(&db), expected);
        let temporary:(String,i64,u32)=db.query_row("SELECT c.state,k.version,k.counter FROM temp.restore_passkey_challenges c CROSS JOIN temp.restore_passkey_keys k",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(temporary, ("pending".into(), 1, 0));
        drop(db);
        let mut reopened = Connection::open(path).unwrap();
        assert_eq!(observed(&reopened), expected);
        assert!(
            complete(
                &mut reopened,
                &f.key,
                &id,
                &f.challenge.request,
                1002,
                &f.assertion(0, 0x0d)
            )
            .is_err()
        );
        assert_eq!(observed(&reopened), expected);
    }
}

#[test]
fn absent_main_ledger_never_falls_back_to_an_attached_database() {
    let f = fixture();
    let root = tempfile::tempdir().unwrap();
    let decoy_path = root.path().join("attached.sqlite");
    let mut decoy = Connection::open(&decoy_path).unwrap();
    let id = prepare(&mut decoy, &f);
    drop(decoy);
    let mut db = Connection::open(root.path().join("uninitialized-main.sqlite")).unwrap();
    db.execute(
        "ATTACH DATABASE ?1 AS decoy",
        [decoy_path.to_str().unwrap()],
    )
    .unwrap();
    assert!(
        complete(
            &mut db,
            &f.key,
            &id,
            &f.challenge.request,
            1001,
            &f.assertion(0, 0x0d)
        )
        .is_err()
    );
    let tx = db.transaction().unwrap();
    assert!(issue(&tx, &f.key, &f.challenge, 1000, 1300).is_err());
    tx.rollback().unwrap();
    drop(db);
    assert_eq!(
        observed(&Connection::open(decoy_path).unwrap()),
        ("pending".into(), 1, 0)
    );
}
