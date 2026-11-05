use super::*;
use crate::security_epoch::restore_webauthn::tests::{Fixture, fixture};
use std::cell::RefCell;

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
        "INSERT INTO restore_passkey_keys VALUES(?1,?2,1,0,1)",
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

fn observed(db: &Connection) -> (String, i64, u32) {
    db.query_row("SELECT c.state,k.version,k.counter FROM restore_passkey_challenges c CROSS JOIN restore_passkey_keys k",[],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap()
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
    db.execute("UPDATE restore_passkey_keys SET enabled=0", [])
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
fn key_removal_policy_change_and_equal_value_aba_after_signature_refuse() {
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
                        peer.execute("DELETE FROM restore_passkey_keys", [])?;
                    }
                    1 => {
                        peer.execute("UPDATE restore_passkey_keys SET enabled=0", [])?;
                    }
                    2 => {
                        peer.execute(
                            "UPDATE restore_passkey_keys SET binding=?1",
                            [Digest::new(b"new current admin policy").as_str()],
                        )?;
                    }
                    3 => {
                        peer.execute("UPDATE restore_passkey_keys SET version=version+1", [])?;
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
            .query_row("SELECT state FROM restore_passkey_challenges", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(state, "claimed");
        let changed_counter: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM restore_passkey_keys WHERE counter<>0)",
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
        let key = TrustedKey {
            record: f.key.record.clone(),
            source: super::super::KeySource::Fixture,
        };
        let request = f.challenge.request.clone();
        let assertion = f.assertion(0, 0x0d);
        let id = id.clone();
        let path = path.clone();
        let start = start.clone();
        workers.push(std::thread::spawn(move || {
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
            "INSERT INTO restore_passkey_keys VALUES(?1,?2,1,0,1)",
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
