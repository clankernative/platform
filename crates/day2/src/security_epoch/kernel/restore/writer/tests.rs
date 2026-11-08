//! Portable protocol/ordinary SQLite tests. Neither the model nor a reopened
//! provider record constructs an enrolled role, consumed approval or writer.
use super::*;
use crate::security_epoch::kernel::restore::tests::{current, initial, intent, version};
use rusqlite::{Connection, TransactionBehavior, params};
use serde_json::{Value, json};
use std::collections::BTreeMap;

mod history;

#[test]
fn may_snapshot_is_one_exact_predecessor_or_one_atomic_planned_pair() -> Result<()> {
    let f = fixture(901, true)?;
    let plan = f
        .request
        .prepare(&f.selected, &f.authority, 1002, &f.before, None)?;
    let before = &f.before.settled.snapshot;
    plan.require_may_snapshot_data(before)?;
    let mut after = before.clone();
    after.root = Some(Versioned {
        value: plan.root.clone(),
        version: version(5),
    });
    after.sentinel = Some(Versioned {
        value: plan.sentinel.clone(),
        version: version(5),
    });
    plan.require_may_snapshot_data(&after)?;

    let mut cuts = Vec::new();
    let mut changed = after.clone();
    changed.root = before.root.clone();
    cuts.push(changed);
    let mut changed = after.clone();
    changed.sentinel = before.sentinel.clone();
    cuts.push(changed);
    let mut changed = after.clone();
    changed.root = None;
    cuts.push(changed);
    let mut changed = after.clone();
    changed.sentinel = None;
    cuts.push(changed);
    let mut changed = after.clone();
    changed.root.as_mut().unwrap().version = version(6);
    cuts.push(changed);
    let mut changed = after.clone();
    changed.root.as_mut().unwrap().version = version(3);
    changed.sentinel.as_mut().unwrap().version = version(3);
    cuts.push(changed);
    let mut changed = after.clone();
    changed.root.as_mut().unwrap().version = version(2);
    changed.sentinel.as_mut().unwrap().version = version(2);
    cuts.push(changed);
    let mut changed = after.clone();
    changed.root.as_mut().unwrap().version =
        "2026-11-04T00:00:00.0000030Z".to_owned().try_into()?;
    changed.sentinel.as_mut().unwrap().version = changed.root.as_ref().unwrap().version.clone();
    cuts.push(changed);
    let mut changed = after.clone();
    changed.create.as_mut().unwrap().version = version(6);
    cuts.push(changed);
    let mut changed = after.clone();
    changed.activate.as_mut().unwrap().version = version(6);
    cuts.push(changed);
    let foreign = fixture(902, true)?;
    let foreign_plan = foreign.request.prepare(
        &foreign.selected,
        &foreign.authority,
        1002,
        &foreign.before,
        None,
    )?;
    let mut changed = after.clone();
    changed.root.as_mut().unwrap().value = foreign_plan.root;
    cuts.push(changed);
    let mut changed = after;
    changed.sentinel.as_mut().unwrap().value = foreign_plan.sentinel;
    cuts.push(changed);
    for (index, changed) in cuts.iter().enumerate() {
        assert!(
            plan.require_may_snapshot_data(changed).is_err(),
            "coherent snapshot cut {index}"
        );
    }
    // This equality predicate does not turn a possible send into its strict
    // acknowledged result: without the actual receipt, reconciliation is not
    // Applied even when the planned root/sentinel already appear.
    let mut observed = f.before.clone();
    observed.settled.snapshot = after_for_test(&plan);
    assert_eq!(
        reconcile(&f.selected, &f.request, &plan, &observed, None)?,
        Outcome::Conflict
    );
    for version in [
        version(2),
        "2026-11-04T00:00:00.0000030Z".to_owned().try_into()?,
    ] {
        observed.settled.snapshot.root.as_mut().unwrap().version = version.clone();
        observed.settled.snapshot.sentinel.as_mut().unwrap().version = version.clone();
        let receipt = Versioned {
            value: plan.receipt.clone(),
            version,
        };
        assert_eq!(
            reconcile(&f.selected, &f.request, &plan, &observed, Some(&receipt))?,
            Outcome::Conflict
        );
    }

    Ok(())
}

fn after_for_test(plan: &Plan) -> crate::security_epoch::kernel::Snapshot {
    let mut snapshot = plan.before.settled.snapshot.clone();
    snapshot.root = Some(Versioned {
        value: plan.root.clone(),
        version: version(5),
    });
    snapshot.sentinel = Some(Versioned {
        value: plan.sentinel.clone(),
        version: version(5),
    });
    snapshot
}

#[cfg(unix)]
mod process;

pub(in crate::security_epoch) struct Fixture {
    pub(in crate::security_epoch) selected: EpochStore,
    pub(in crate::security_epoch) authority: Current,
    pub(in crate::security_epoch) request: Request,
    pub(in crate::security_epoch) before: State,
}

pub(in crate::security_epoch) fn fixture(seed: u64, completed: bool) -> Result<Fixture> {
    let (selected, source) = initial();
    let intent = intent(&selected, seed);
    let authority = current(&selected, &intent, &source);
    let reservation =
        super::super::Request::new(&selected, intent.clone(), &authority, 1000, &source)?
            .prepare(&selected, &authority, 1000, &source, None)?;
    let reservation = approval_use::Plan::new(
        reservation,
        &selected,
        &authority,
        1000,
        &source,
        None,
        None,
    )?;
    let mut snapshot = source;
    snapshot.root = Some(Versioned {
        value: reservation.reservation.advance.root.clone(),
        version: version(3),
    });
    snapshot.sentinel = Some(Versioned {
        value: reservation.reservation.advance.sentinel.clone(),
        version: version(3),
    });
    let settled = completion::State {
        snapshot,
        advance: Versioned {
            value: reservation.reservation.advance.receipt.clone(),
            version: version(3),
        },
        reservation: Versioned {
            value: reservation.reservation.receipt.clone(),
            version: version(3),
        },
    };
    let disposition = if completed {
        completion::Disposition::Completed {
            report: completion::TargetReport {
                intent: intent.commitment(&selected)?,
                archive: intent.archive.image.clone(),
                target_incarnation: intent.target_incarnation.clone(),
                target_epoch: 2,
                image: Digest::of(&("actually-reset-fixture-image", seed))?,
                schema: intent.archive.schema.clone(),
                artifact: intent.archive.artifact.clone(),
                reset_observation: Digest::of(&("reset-fixture-observation", seed))?,
            },
        }
    } else {
        completion::Disposition::Refused {
            reason: completion::Refusal::OperatorCancelled,
        }
    };
    let completion_request = completion::Request::new(
        &selected,
        &reservation.reservation,
        &settled,
        &authority,
        1001,
        disposition,
    )?;
    let completion_plan =
        completion_request.prepare(&selected, &authority, 1001, &settled, None)?;
    let before = State {
        settled,
        terminal: Versioned {
            value: completion_plan.receipt.clone(),
            version: version(4),
        },
        consumed: Versioned {
            value: reservation.approval_use.clone(),
            version: version(3),
        },
    };
    let input = Input {
        reservation,
        completion_request,
        completion_plan,
        before: before.clone(),
        holder: Holder {
            principal: Digest::new(b"new-app-principal"),
            pod_uid: "21234567-89ab-4cde-8fab-0123456789ab".into(),
            process_incarnation: Digest::of(&("new-process", seed))?,
            ephemeral_key: Digest::of(&("new-key", seed))?,
        },
    };
    // Keep even refused fixtures available to negative constructor tests.
    let request = Request {
        input,
        authorization: authority.clone(),
        prepared_at: 1002,
    };
    Ok(Fixture {
        selected,
        authority,
        request,
        before,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    value: Value,
    token: u32,
}
type Rows = BTreeMap<String, Row>;

fn rows(state: &State) -> Result<Rows> {
    let s = &state.settled;
    let mut result = Rows::new();
    for (name, value, token) in [
        (
            "root",
            serde_json::to_value(&s.snapshot.root.as_ref().unwrap().value)?,
            3,
        ),
        (
            "sentinel",
            serde_json::to_value(&s.snapshot.sentinel.as_ref().unwrap().value)?,
            3,
        ),
        (
            "create",
            serde_json::to_value(&s.snapshot.create.as_ref().unwrap().value)?,
            1,
        ),
        (
            "activate",
            serde_json::to_value(&s.snapshot.activate.as_ref().unwrap().value)?,
            2,
        ),
        ("advance", serde_json::to_value(&s.advance.value)?, 3),
        (
            "reservation",
            serde_json::to_value(&s.reservation.value)?,
            3,
        ),
        ("terminal", serde_json::to_value(&state.terminal.value)?, 4),
        ("consumed", serde_json::to_value(&state.consumed.value)?, 3),
    ] {
        result.insert(name.to_owned(), Row { value, token });
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Cut {
    BeforeCompare,
    AfterCompare,
    AfterRoot,
    BeforeCommit,
    AfterCommit,
    Complete,
}

struct Provider {
    db: Connection,
}

impl Provider {
    fn open(path: &std::path::Path, before: &State) -> Result<Self> {
        let existed = path.exists();
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS records (name TEXT PRIMARY KEY, body TEXT NOT NULL, token INTEGER NOT NULL);")?;
        let count: i64 = db.query_row("SELECT count(*) FROM records", [], |r| r.get(0))?;
        if count == 0 && !existed {
            for (name, row) in rows(before)? {
                db.execute(
                    "INSERT INTO records VALUES (?1,?2,?3)",
                    params![name, serde_json::to_string(&row.value)?, row.token],
                )?;
            }
        }
        let count: i64 = db.query_row("SELECT count(*) FROM records", [], |r| r.get(0))?;
        ensure!(
            (8..=9).contains(&count),
            "writer_provider_existing_history_incomplete"
        );
        Ok(Self { db })
    }

    fn read(db: &Connection) -> Result<Rows> {
        let mut query = db.prepare("SELECT name,body,token FROM records ORDER BY name")?;
        let mut rows = query.query([])?;
        let mut result = Rows::new();
        while let Some(row) = rows.next()? {
            let body: String = row.get(1)?;
            result.insert(
                row.get(0)?,
                Row {
                    value: crate::json::decode(body.as_bytes())?,
                    token: row.get(2)?,
                },
            );
        }
        Ok(result)
    }

    fn send(
        &mut self,
        f: &Fixture,
        plan: &Plan,
        at: i64,
        mut checkpoint: impl FnMut(Cut) -> Result<()>,
    ) -> Result<()> {
        checkpoint(Cut::BeforeCompare)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure!(
            Self::read(&tx)? == rows(&plan.before)?,
            "writer_provider_conditional_conflict"
        );
        plan.revalidate(&f.selected, &f.request, &f.authority, at, &f.before, None)?;
        checkpoint(Cut::AfterCompare)?;
        tx.execute(
            "UPDATE records SET body=?1,token=5 WHERE name='root'",
            [serde_json::to_string(&plan.root)?],
        )?;
        checkpoint(Cut::AfterRoot)?;
        tx.execute(
            "UPDATE records SET body=?1,token=5 WHERE name='sentinel'",
            [serde_json::to_string(&plan.sentinel)?],
        )?;
        tx.execute(
            "INSERT INTO records VALUES ('writer',?1,5)",
            [serde_json::to_string(&plan.receipt)?],
        )?;
        checkpoint(Cut::BeforeCommit)?;
        tx.commit()?;
        checkpoint(Cut::AfterCommit)?;
        checkpoint(Cut::Complete)
    }
}

fn applied(f: &Fixture, p: &Plan) -> State {
    let mut s = f.before.clone();
    s.settled.snapshot.root = Some(Versioned {
        value: p.root.clone(),
        version: version(5),
    });
    s.settled.snapshot.sentinel = Some(Versioned {
        value: p.sentinel.clone(),
        version: version(5),
    });
    s
}

#[test]
fn restored_writer_is_distinct_from_initial_activation_and_captures_grant_use() -> Result<()> {
    let f = fixture(1, true)?;
    let p = f
        .request
        .prepare(&f.selected, &f.authority, 1002, &f.before, None)?;
    assert_eq!(rows(&p.before)?.len(), 8);
    assert_eq!(p.root.epoch.value(), 2);
    let Phase::RestoredFirstHolder { restoration } = &p.root.phase else {
        panic!("restored phase required");
    };
    assert_eq!(restoration.report.image, p.receipt.restoration.report.image);
    assert_eq!(restoration.consumed, Digest::of(&f.before.consumed.value)?);
    assert_eq!(p.sentinel.phase, p.root.phase);
    assert_ne!(restoration.report.image, restoration.report.archive);
    let s = applied(&f, &p);
    let receipt = Versioned {
        value: p.receipt.clone(),
        version: version(5),
    };
    assert!(matches!(
        reconcile(&f.selected, &f.request, &p, &s, Some(&receipt))?,
        Outcome::Applied(_)
    ));
    let genesis = &s.settled.snapshot.create.as_ref().unwrap().value.request;
    assert!(
        crate::security_epoch::kernel::reconcile(&f.selected, genesis, &s.settled.snapshot)
            .is_err()
    );
    Ok(())
}

#[test]
fn writer_constructor_validates_completed_reset_and_exact_current_authority() -> Result<()> {
    let f = fixture(70, true)?;
    let request = Request::new(&f.selected, f.request.input, &f.authority, 1002)?;
    request.prepare(&f.selected, &f.authority, 1002, &f.before, None)?;
    let f = fixture(71, false)?;
    assert!(Request::new(&f.selected, f.request.input, &f.authority, 1002).is_err());
    let mut f = fixture(72, true)?;
    f.authority.enabled = false;
    assert!(Request::new(&f.selected, f.request.input, &f.authority, 1002).is_err());
    Ok(())
}

#[test]
fn every_captured_version_and_terminal_grant_or_holder_substitution_refuses() -> Result<()> {
    for field in 0..8 {
        let f = fixture(2, true)?;
        let mut s = f.before.clone();
        let token = match field {
            0 => &mut s.settled.snapshot.root.as_mut().unwrap().version,
            1 => &mut s.settled.snapshot.sentinel.as_mut().unwrap().version,
            2 => &mut s.settled.snapshot.create.as_mut().unwrap().version,
            3 => &mut s.settled.snapshot.activate.as_mut().unwrap().version,
            4 => &mut s.settled.advance.version,
            5 => &mut s.settled.reservation.version,
            6 => &mut s.terminal.version,
            _ => &mut s.consumed.version,
        };
        *token = version(90);
        assert!(
            f.request
                .prepare(&f.selected, &f.authority, 1002, &s, None)
                .is_err()
        );
    }
    let mut f = fixture(3, true)?;
    let foreign = fixture(4, true)?;
    f.before.consumed.value = foreign.before.consumed.value.clone();
    f.request.input.before = f.before.clone();
    assert!(
        f.request
            .prepare(&f.selected, &f.authority, 1002, &f.before, None)
            .is_err()
    );
    let f = fixture(5, false)?;
    assert!(
        f.request
            .prepare(&f.selected, &f.authority, 1002, &f.before, None)
            .is_err()
    );
    let mut f = fixture(6, true)?;
    let Phase::ActiveFirstHolder { completion } = &f
        .request
        .input
        .reservation
        .reservation
        .before
        .root
        .as_ref()
        .unwrap()
        .value
        .phase
    else {
        unreachable!()
    };
    f.request.input.holder.process_incarnation = completion.holder.process_incarnation.clone();
    assert!(
        f.request
            .prepare(&f.selected, &f.authority, 1002, &f.before, None)
            .is_err()
    );
    Ok(())
}

#[test]
fn current_revocation_exact_keys_and_equality_expiry_remain_mandatory() -> Result<()> {
    let f = fixture(7, true)?;
    for change in 0..6 {
        let mut current = f.authority.clone();
        let at = match change {
            0 => {
                current.enabled = false;
                1002
            }
            1 => {
                current.available_keys.clear();
                1002
            }
            2 => {
                current.target.security_epoch += 1;
                1002
            }
            3 => {
                current.custody.revision = Digest::new(b"rotated-custody");
                1002
            }
            4 => current.ready_until,
            _ => 1001,
        };
        assert!(
            f.request
                .prepare(&f.selected, &current, at, &f.before, None)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn closed_restored_phase_rejects_arrays_mixed_fields_and_nested_duplicates() -> Result<()> {
    let f = fixture(8, true)?;
    let p = f
        .request
        .prepare(&f.selected, &f.authority, 1002, &f.before, None)?;
    let raw = serde_json::to_string(&p.root.phase)?;
    let decoded: Phase = crate::json::decode(raw.as_bytes())?;
    assert_eq!(decoded, p.root.phase);
    let mut value = serde_json::to_value(&p.root.phase)?;
    value["fence"] = json!({});
    assert!(serde_json::from_value::<Phase>(value).is_err());
    assert!(
        serde_json::from_value::<Phase>(json!(["restored_first_holder", p.receipt.restoration]))
            .is_err()
    );
    let duplicate = raw.replacen("\"operation\":", "\"operation\":\"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"operation\":", 1);
    assert_ne!(raw, duplicate);
    assert!(serde_json::from_str::<Phase>(&duplicate).is_err());
    assert!(crate::json::decode::<Phase>(duplicate.as_bytes()).is_err());
    Ok(())
}

#[test]
fn sqlite_compares_every_record_and_never_adopts_partial_or_reopened_activation() -> Result<()> {
    for rewrite in [
        "root",
        "sentinel",
        "create",
        "activate",
        "advance",
        "reservation",
        "terminal",
        "consumed",
    ] {
        let f = fixture(10, true)?;
        let p = f
            .request
            .prepare(&f.selected, &f.authority, 1002, &f.before, None)?;
        let dir = tempfile::tempdir()?;
        let mut db = Provider::open(&dir.path().join("provider.sqlite"), &f.before)?;
        db.db
            .execute("UPDATE records SET token=90 WHERE name=?1", [rewrite])?;
        let before = Provider::read(&db.db)?;
        assert!(db.send(&f, &p, 1002, |_| Ok(())).is_err());
        assert_eq!(Provider::read(&db.db)?, before);
    }
    for cut in [
        Cut::BeforeCompare,
        Cut::AfterCompare,
        Cut::AfterRoot,
        Cut::BeforeCommit,
        Cut::AfterCommit,
    ] {
        let f = fixture(11, true)?;
        let p = f
            .request
            .prepare(&f.selected, &f.authority, 1002, &f.before, None)?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("provider.sqlite");
        let mut db = Provider::open(&path, &f.before)?;
        assert!(
            db.send(&f, &p, 1002, |actual| {
                ensure!(actual != cut, "controlled_completion_unknown");
                Ok(())
            })
            .is_err()
        );
        drop(db);
        let mut reopened = Provider::open(&path, &f.before)?;
        let r = Provider::read(&reopened.db)?;
        assert_eq!(r.contains_key("writer"), cut == Cut::AfterCommit);
        if cut == Cut::AfterCommit {
            assert!(reopened.send(&f, &p, 1002, |_| Ok(())).is_err());
            assert_eq!(Provider::read(&reopened.db)?, r);
        } else {
            assert_eq!(r, rows(&f.before)?);
        }
    }
    Ok(())
}
