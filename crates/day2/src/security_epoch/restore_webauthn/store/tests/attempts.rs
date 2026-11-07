//! Grant-keyed durable refusal DATA, exercised through real SQLite and the real
//! assertion verifier. Fixture keys do not create a native execution owner.
use super::*;
use crate::security_epoch::restore_approval::signed::SignedApprovalRecord;
use rusqlite::OptionalExtension as _;

pub(super) fn execution_fixture(
    db: &mut Connection,
    f: &mut Fixture,
) -> Result<(SignedApprovalRecord, Digest, (i64, Digest))> {
    let signed = super::super::signing::tests::statement(f)?;
    let operation = Digest::new(b"one accepting restore operation");
    f.challenge.request = crate::security_epoch::restore_webauthn::execution_request(&signed, &operation)?;
    f.challenge.nonce = [89; 32];
    let id = prepare(db, f);
    complete(db, &f.key, &id, &f.challenge.request, 1100, &f.assertion(7, 0x0d))?;
    let tx = db.transaction()?;
    let completion = verified_snapshot(&tx, &f.key, &f.challenge, 7)?;
    tx.commit()?;
    Ok((signed, operation, completion))
}

pub(super) fn fresh_execution(
    db: &mut Connection,
    f: &mut Fixture,
    signed: &SignedApprovalRecord,
    operation: &Digest,
) -> Result<(i64, Digest)> {
    f.challenge.request = crate::security_epoch::restore_webauthn::execution_request(signed, operation)?;
    f.challenge.nonce = [90; 32];
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let id = issue(&tx, &f.key, &f.challenge, 1100, 1400)?;
    tx.commit()?;
    complete(db, &f.key, &id, &f.challenge.request, 1200, &f.assertion(8, 0x0d))?;
    let tx = db.transaction()?;
    let completion = verified_snapshot(&tx, &f.key, &f.challenge, 8)?;
    tx.commit()?;
    Ok(completion)
}

#[derive(Clone, Copy, Debug)]
enum Step { Mark, RollBack, Check, Reopen, Foreign, Remove, Replace }

#[derive(Default)]
struct Model { spent: bool, invalid: bool }

impl Model {
    fn step(&mut self, step: Step) -> bool {
        match step {
            Step::Reopen => true,
            Step::Remove | Step::Replace => { self.invalid = true; true }
            Step::Mark if !self.invalid && !self.spent => { self.spent = true; true }
            Step::RollBack => !self.invalid && !self.spent,
            Step::Check => !self.invalid && self.spent,
            _ => false,
        }
    }
}

fn run_history(steps: &[Step]) -> Result<Vec<(bool, bool)>> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("outside-restore.sqlite");
    let mut db = Connection::open(&path)?;
    let mut f = fixture();
    let (signed, operation, completion) = execution_fixture(&mut db, &mut f)?;
    let mut model = Model::default();
    let mut observed = Vec::new();
    for (index, step) in steps.iter().copied().enumerate() {
        let expected = model.step(step);
        let result: Result<()> = match step {
            Step::Reopen => { drop(db); db = Connection::open(&path)?; Ok(()) }
            Step::Remove => db.execute("UPDATE main.restore_passkey_keys SET enabled=0", []).map(|_| ()).map_err(Into::into),
            Step::Replace => db.execute("UPDATE main.restore_passkey_keys SET version=version+1", []).map(|_| ()).map_err(Into::into),
            _ => (|| {
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let mut selected = signed.clone();
                if matches!(step, Step::Foreign) {
                    selected.statement.request.full_archive_digest = Digest::new(b"foreign archive");
                }
                if matches!(step, Step::Check) {
                    check_may_execute(&tx, &f.key, &f.challenge, &selected, &operation, (7, completion.0, &completion.1))?;
                } else {
                    mark_may_execute(&tx, &f.key, &f.challenge, &selected, &operation, (7, completion.0, &completion.1))?;
                }
                if matches!(step, Step::RollBack) { tx.rollback()?; } else { tx.commit()?; }
                Ok(())
            })(),
        };
        assert_eq!(result.is_ok(), expected, "step {index}: {steps:?}");
        let saved: Option<String> = db.query_row("SELECT grant_id FROM main.restore_approval_execution_attempts", [], |row| row.get(0)).optional()?;
        assert_eq!(saved.as_deref(), model.spent.then_some(signed.statement.request.grant_id.as_str()), "step {index}: {steps:?}");
        observed.push((result.is_ok(), saved.is_some()));
    }
    Ok(observed)
}

#[test]
fn execution_attempt_generated_histories_match_independent_durable_refusal_and_replay() -> Result<()> {
    for steps in [
        [Step::Remove,Step::Mark,Step::Check,Step::Reopen,Step::Mark],
        [Step::Replace,Step::Mark,Step::Check,Step::Reopen,Step::Mark],
        [Step::Foreign,Step::RollBack,Step::Reopen,Step::Mark,Step::Check],
    ] {
        assert_eq!(run_history(&steps)?, run_history(&steps)?);
    }
    let choices = [Step::Mark,Step::RollBack,Step::Check,Step::Reopen,Step::Foreign,Step::Remove,Step::Replace];
    for seed in [1_u64, 19, 709, 3089] {
        let mut state = seed;
        let mut history = vec![Step::Check,Step::RollBack,Step::Reopen,Step::Mark,Step::Reopen,Step::Check,Step::Mark];
        for _ in 0..25 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            history.push(choices[(state >> 32) as usize % choices.len()]);
        }
        assert_eq!(run_history(&history)?, run_history(&history)?, "seed {seed}");
    }
    Ok(())
}

#[test]
fn new_verified_login_and_operation_cannot_reuse_a_spent_grant() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("outside-restore.sqlite");
    let mut db = Connection::open(&path)?;
    let mut f = fixture();
    let (signed, operation, completion) = execution_fixture(&mut db, &mut f)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    mark_may_execute(&tx, &f.key, &f.challenge, &signed, &operation, (7, completion.0, &completion.1))?;
    tx.commit()?;
    drop(db);
    let mut db = Connection::open(&path)?;
    let next_operation = Digest::new(b"new authenticated operation after unknown send");
    let next = fresh_execution(&mut db, &mut f, &signed, &next_operation)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert!(mark_may_execute(&tx, &f.key, &f.challenge, &signed, &next_operation, (8, next.0, &next.1)).is_err());
    assert!(check_may_execute(&tx, &f.key, &f.challenge, &signed, &next_operation, (8, next.0, &next.1)).is_err());
    tx.commit()?;
    assert_eq!(db.query_row("SELECT operation FROM main.restore_approval_execution_attempts", [], |row| row.get::<_,String>(0))?, operation.as_str());
    Ok(())
}

#[test]
fn exact_execution_marker_and_every_completion_binding_are_required() -> Result<()> {
    for cut in 0..8 {
        let root = tempfile::tempdir()?;
        let mut db = Connection::open(root.path().join("auth.sqlite"))?;
        let mut f = fixture();
        let (signed, operation, completion) = execution_fixture(&mut db, &mut f)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        mark_may_execute(&tx, &f.key, &f.challenge, &signed, &operation, (7, completion.0, &completion.1))?;
        tx.commit()?;
        let mut changed = signed.clone();
        let mut current_operation = operation.clone();
        let mut version = completion.0;
        let mut snapshot = completion.1.clone();
        match cut {
            0 => changed.statement.request.full_archive_digest = Digest::new(b"other archive"),
            1 => changed.statement.request.target.security_epoch += 1,
            2 => changed.statement.request.executor.subject = "another executor".into(),
            3 => current_operation = Digest::new(b"other operation"),
            4 => f.challenge.nonce = [91; 32],
            5 => version += 1,
            6 => snapshot = Digest::new(b"other verified completion"),
            _ => { db.execute("UPDATE main.restore_approval_execution_attempts SET completion_digest=?1", [Digest::new(b"rewritten marker").as_str()])?; }
        }
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(check_may_execute(&tx, &f.key, &f.challenge, &changed, &current_operation, (7, version, &snapshot)).is_err(), "cut {cut}");
        tx.commit()?;
        assert_eq!(db.query_row("SELECT count(*) FROM main.restore_approval_execution_attempts", [], |row| row.get::<_,i64>(0))?, 1);
    }
    Ok(())
}

#[test]
fn independent_connections_cannot_claim_the_same_grant_twice() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("auth.sqlite");
    let mut first = Connection::open(&path)?;
    let mut f = fixture();
    let (signed, operation, completion) = execution_fixture(&mut first, &mut f)?;
    let mut second = Connection::open(&path)?;
    second.busy_timeout(std::time::Duration::ZERO)?;
    let tx = first.transaction_with_behavior(TransactionBehavior::Immediate)?;
    mark_may_execute(&tx, &f.key, &f.challenge, &signed, &operation, (7, completion.0, &completion.1))?;
    assert!(second.transaction_with_behavior(TransactionBehavior::Immediate).is_err());
    tx.commit()?;
    let tx = second.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert!(mark_may_execute(&tx, &f.key, &f.challenge, &signed, &operation, (7, completion.0, &completion.1)).is_err());
    tx.commit()?;
    Ok(())
}
