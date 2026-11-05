//! Ordinary SQLite is an interpreter for conditional writes only. It is NOT an
//! approval verifier or native source. Expectations below do not call reconcile.
use super::*;
use crate::security_epoch::kernel::restore::approval_use as kernel;

pub(super) fn plan(selected: &EpochStore, before: &Snapshot, seed: u64) -> Result<(Current, kernel::Plan)> {
    let intent = intent(selected, seed);
    let current = current(selected, &intent, before);
    let request = Request::new(selected, intent, &current, 1000, before)?;
    let reserve = request.prepare(selected, &current, 1000, before, None)?;
    Ok((
        current.clone(),
        kernel::Plan::new(reserve, selected, &current, 1000, before, None, None)?,
    ))
}

fn use_name(selected: &EpochStore, plan: &kernel::Plan) -> Result<String> {
    Ok(format!(
        "approval-use/{}",
        plan.approval_use.key(selected)?.as_str()
    ))
}

fn apply(
    provider: &mut Provider,
    selected: &EpochStore,
    current: &Current,
    plan: &kernel::Plan,
    cut: usize,
) -> Result<()> {
    let ledger = Provider::ledger_name(&plan.reservation);
    let use_key = use_name(selected, plan)?;
    plan.revalidate(
        selected,
        current,
        1000,
        &provider.snapshot()?,
        provider.read(&ledger)?.as_ref(),
        provider.read(&use_key)?.as_ref(),
    )?;
    ensure!(cut != 0, "controlled_cut");
    let tx = provider
        .db
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    // All four observed versions, including immutable history, are conditions
    // in the same transaction. Equal-value rewrites are not the same snapshot.
    for row in initial_rows(&plan.reservation.before)? {
        let seen: (String, i64) = tx.query_row(
            "SELECT body,version FROM records WHERE name=?1",
            [&row.name],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            seen == (serde_json::to_string(&row.body)?, row.version),
            "controlled_read_conflict"
        );
    }
    let values = [
        (
            "root".to_owned(),
            serde_json::to_string(&plan.reservation.advance.root)?,
            true,
        ),
        (
            "sentinel".to_owned(),
            serde_json::to_string(&plan.reservation.advance.sentinel)?,
            true,
        ),
        (
            Provider::advance_name(selected, &plan.reservation)?,
            serde_json::to_string(&plan.reservation.advance.receipt)?,
            false,
        ),
        (
            ledger,
            serde_json::to_string(&plan.reservation.receipt)?,
            false,
        ),
        (use_key, serde_json::to_string(&plan.approval_use)?, false),
    ];
    for (index, (name, body, update)) in values.into_iter().enumerate() {
        if update {
            ensure!(
                tx.execute(
                    "UPDATE records SET body=?1,version=3 WHERE name=?2 AND version=2",
                    params![body, name]
                )? == 1,
                "controlled_write_conflict"
            );
        } else {
            tx.execute("INSERT INTO records VALUES(?1,?2,3)", params![name, body])?;
        }
        ensure!(cut != index + 1, "controlled_cut");
    }
    tx.commit()?;
    ensure!(cut != 6, "controlled_unknown_commit");
    Ok(())
}

#[test]
fn all_five_record_cuts_reopen_against_an_independent_commit_oracle_twice() -> Result<()> {
    for seed in 0..8 {
        let (selected, before) = initial();
        let (current, plan) = plan(&selected, &before, seed)?;
        let mut replays = Vec::new();
        for _ in 0..2 {
            let mut observations = Vec::new();
            for cut in 0..=7 {
                let dir = tempfile::tempdir()?;
                let path = dir.path().join("external.sqlite");
                let mut provider = Provider::open(&path, &before)?;
                let result = apply(&mut provider, &selected, &current, &plan, cut);
                assert_eq!(result.is_ok(), cut == 7);
                provider.reopen(&path)?;
                let committed = cut >= 6;
                let snapshot = provider.snapshot()?;
                let use_row: Option<Versioned<kernel::UseRecord>> =
                    provider.read(&use_name(&selected, &plan)?)?;
                assert_eq!(provider.rows()?.len(), if committed { 7 } else { 4 });
                assert_eq!(
                    snapshot.root.as_ref().unwrap().value.epoch.value(),
                    if committed { 2 } else { 1 }
                );
                assert_eq!(use_row.is_some(), committed);
                let outcome = kernel::reconcile(
                    &selected,
                    &plan,
                    &snapshot,
                    provider
                        .read(&Provider::advance_name(&selected, &plan.reservation)?)?
                        .as_ref(),
                    provider
                        .read(&Provider::ledger_name(&plan.reservation))?
                        .as_ref(),
                    use_row.as_ref(),
                )?;
                assert_eq!(matches!(outcome, Outcome::Applied(_)), committed);
                assert_eq!(matches!(outcome, Outcome::NotApplied), !committed);
                if committed {
                    // A historical Applied cannot authorize another send, even
                    // when its request and approval DATA are perfectly equal.
                    assert!(apply(&mut provider, &selected, &current, &plan, 7).is_err());
                }
                observations.push((snapshot, provider.rows()?));
            }
            replays.push(observations);
        }
        assert_eq!(replays[0], replays[1]);
    }
    Ok(())
}

#[test]
fn grant_key_is_independent_of_operation_and_occupied_use_refuses_before_writes() -> Result<()> {
    let (selected, before) = initial();
    let (current, first) = plan(&selected, &before, 1)?;
    let mut other_intent = first.reservation.receipt.request.intent.clone();
    other_intent.operation = Digest::new(b"different-operation");
    let mut other_current = super::current(&selected, &other_intent, &before);
    other_current.grant.approval = current.grant.approval.clone();
    let request = Request::new(&selected, other_intent, &other_current, 1000, &before)?;
    let reserve = request.prepare(&selected, &other_current, 1000, &before, None)?;
    let other = kernel::Plan::new(
        reserve,
        &selected,
        &other_current,
        1000,
        &before,
        None,
        None,
    )?;
    assert_eq!(
        first.approval_use.key(&selected)?,
        other.approval_use.key(&selected)?
    );
    let occupied = Versioned {
        value: first.approval_use.clone(),
        version: version(3),
    };
    assert!(
        other
            .revalidate(
                &selected,
                &other_current,
                1000,
                &before,
                None,
                Some(&occupied)
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn exact_hour_does_not_extend_the_existing_five_second_current_observation() -> Result<()> {
    let (selected, before) = initial();
    let (current, plan) = plan(&selected, &before, 4)?;
    assert_eq!(
        current.grant.approval.expires_at - current.grant.approval.approved_at,
        3600
    );
    assert!(
        plan.revalidate(&selected, &current, 1005, &before, None, None)
            .is_err()
    );
    let mut fresh = current.clone();
    fresh.observed_at = 4599;
    fresh.ready_until = 4600;
    plan.revalidate(&selected, &fresh, 4599, &before, None, None)?;
    assert!(
        plan.revalidate(&selected, &fresh, 4600, &before, None, None)
            .is_err()
    );
    for delta in [-1, 1] {
        let mut changed = current.clone();
        changed.grant.approval.expires_at += delta;
        assert!(
            Request::new(
                &selected,
                plan.reservation.receipt.request.intent.clone(),
                &changed,
                1000,
                &before
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn signed_target_archive_custody_and_executor_are_compared_as_complete_values() -> Result<()> {
    let (selected, before) = initial();
    let (_, base) = plan(&selected, &before, 9)?;
    for cut in 0..11 {
        let intent = base.reservation.receipt.request.intent.clone();
        let mut current = super::current(&selected, &intent, &before);
        match cut {
            0 => {
                current.grant.approval.full_archive_digest = Digest::new(b"different-full-archive")
            }
            1 => current.grant.approval.target.scope.app = "foreign".to_owned().try_into()?,
            2 => current.grant.approval.target.binding_generation += 1,
            3 => current.grant.approval.target.authority = Digest::new(b"foreign-authority"),
            4 => current.grant.approval.target.selection = Digest::new(b"foreign-selection"),
            5 => current.grant.approval.target.incarnation = Digest::new(b"foreign-target"),
            6 => current.grant.approval.target.security_epoch += 1,
            7 => current.grant.approval.target.artifact = Digest::new(b"foreign-artifact"),
            8 => current.grant.approval.target.schema = Digest::new(b"foreign-schema"),
            9 => current.grant.approval.executor.subject = "reassigned-email-subject".into(),
            _ => current.grant.approval.custody.revision = Digest::new(b"other-vault"),
        }
        // Updating an unrelated intent digest must not hide a mismatched field.
        current.grant.intent = intent.commitment(&selected)?;
        assert!(Request::new(&selected, intent.clone(), &current, 1000, &before).is_err());
    }
    Ok(())
}
