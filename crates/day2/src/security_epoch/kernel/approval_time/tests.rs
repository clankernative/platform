use super::*;
use crate::security_epoch::kernel::{Holder, Request, Versions};
use rusqlite::{Connection, OptionalExtension, params};

fn version(value: u64) -> UpdateTime {
    format!("2026-11-05T00:00:00.{value:06}Z")
        .try_into()
        .unwrap()
}

fn fixture() -> (EpochStore, Snapshot, Versioned<Floor>) {
    let selected = crate::security_epoch::tests::selection();
    let create = crate::security_epoch::tests::create();
    let activate = Request::CompleteInitialFirstActivation {
        bootstrap: create.bootstrap().clone(),
        operation: Digest::new(b"time-fixture-activation"),
        parent_receipt: create.receipt().unwrap().digest().unwrap(),
        before: Versions {
            root: version(1),
            sentinel: version(1),
        },
        holder: Holder {
            principal: Digest::new(b"time-fixture-app"),
            pod_uid: "11234567-89ab-4cde-8fab-0123456789ab".into(),
            process_incarnation: Digest::new(b"time-fixture-process"),
            ephemeral_key: Digest::new(b"time-fixture-key"),
        },
    };
    let (root, sentinel) = activate.records().unwrap();
    let before = Snapshot {
        root: Some(Versioned {
            value: root,
            version: version(2),
        }),
        sentinel: Some(Versioned {
            value: sentinel,
            version: version(2),
        }),
        create: Some(Versioned {
            value: create.receipt().unwrap(),
            version: version(1),
        }),
        activate: Some(Versioned {
            value: activate.receipt().unwrap(),
            version: version(2),
        }),
    };
    let floor = Versioned {
        value: Floor {
            format: Format::Day2RestoreTimeFloorV1,
            authority: selected.authority_key().unwrap(),
            upper: utc(100_000_000_000),
            operation: Digest::new(b"explicit-fixture-install-not-a-production-initializer"),
        },
        version: version(3),
    };
    (selected, before, floor)
}

fn utc(nanos: u128) -> Utc {
    Utc {
        seconds: (nanos / 1_000_000_000).try_into().unwrap(),
        nanos: (nanos % 1_000_000_000).try_into().unwrap(),
    }
}

fn interval(lower: u128, upper: u128) -> Interval {
    Interval {
        domain: Digest::new(b"actual-source-domain-is-still-required"),
        lower: utc(lower),
        upper: utc(upper),
    }
}

#[test]
fn strict_interval_advances_to_upper_and_never_repairs_overlap() -> Result<()> {
    let (selected, before, floor) = fixture();
    for (lower, upper, accepted) in [
        (100_000_000_000, 100_000_000_000, true),
        (100_000_000_000, 101_000_000_000, true),
        (100_000_000_001, 100_000_000_002, true),
        (99_999_999_999, 100_000_000_001, false),
        (99_000_000_000, 99_500_000_000, false),
        (100_000_000_001, 100_000_000_000, false),
        (100_000_000_000, 101_000_000_001, false),
    ] {
        let result = Plan::prepare(
            &selected,
            &before,
            Some(&floor),
            Digest::new(b"operation"),
            interval(lower, upper),
        );
        assert_eq!(result.is_ok(), accepted, "{lower}..{upper}");
        if let Ok(plan) = result {
            assert_eq!(plan.after.upper, utc(upper));
            plan.revalidate(&selected, &before, Some(&floor), None)?;
        }
    }
    assert!(
        Plan::prepare(
            &selected,
            &before,
            None,
            Digest::new(b"operation"),
            interval(100_000_000_000, 100_000_000_001)
        )
        .is_err()
    );
    assert!(
        Plan::prepare(
            &selected,
            &before,
            Some(&floor),
            floor.value.operation.clone(),
            interval(100_000_000_000, 100_000_000_001)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn stable_floor_key_survives_rotation_and_rejects_another_world() -> Result<()> {
    let (selected, before, floor) = fixture();
    let mut rotated = selected.clone();
    rotated.key_set = Digest::new(b"rotated-key-set");
    rotated.max_lease_seconds = 4;
    let day2_capabilities::security_epoch::EpochProvider::FirestoreNativeV1 {
        project,
        database,
        iam_source,
        ..
    } = &mut rotated.provider;
    *project = "renamed-selector".to_owned().try_into()?;
    *database = "another-selector".to_owned().try_into()?;
    let day2_capabilities::security_epoch::EpochIam::GkeWorkloadIdentityV1 {
        service_account,
        service_account_uid,
    } = iam_source;
    *service_account = "rotated@renamed-selector.iam.gserviceaccount.com".into();
    *service_account_uid = "100000000000000000008".to_owned().try_into()?;
    assert_eq!(key(&selected)?, key(&rotated)?);
    floor.value.validate(&rotated)?;
    let mut foreign = selected.clone();
    foreign.scope.app = "other".to_owned().try_into()?;
    assert_ne!(key(&selected)?, key(&foreign)?);
    assert!(floor.value.validate(&foreign).is_err());
    assert!(
        Plan::prepare(
            &foreign,
            &before,
            Some(&floor),
            Digest::new(b"op"),
            interval(101_000_000_000, 101_000_000_001)
        )
        .is_err()
    );
    let mut repaired_domain = interval(99_000_000_000, 99_000_000_001);
    repaired_domain.domain = Digest::new(b"reboot-does-not-reset-the-floor");
    assert!(
        Plan::prepare(
            &selected,
            &before,
            Some(&floor),
            Digest::new(b"op"),
            repaired_domain
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn receipt_selector_binds_authority_and_operation_in_a_separate_namespace() -> Result<()> {
    let (selected, before, floor) = fixture();
    let first = Plan::prepare(
        &selected,
        &before,
        Some(&floor),
        Digest::new(b"first"),
        interval(101_000_000_000, 101_000_000_001),
    )?;
    let second = Plan::prepare(
        &selected,
        &before,
        Some(&floor),
        Digest::new(b"second"),
        interval(101_000_000_000, 101_000_000_001),
    )?;
    assert_ne!(first.receipt.key(&selected)?, key(&selected)?);
    assert_ne!(
        first.receipt.key(&selected)?,
        second.receipt.key(&selected)?
    );
    let mut foreign = selected.clone();
    foreign.scope.app = "other".to_owned().try_into()?;
    assert!(first.receipt.key(&foreign).is_err());
    Ok(())
}

#[test]
fn every_read_version_and_closed_plan_binding_is_required() -> Result<()> {
    let (selected, before, floor) = fixture();
    let plan = Plan::prepare(
        &selected,
        &before,
        Some(&floor),
        Digest::new(b"op"),
        interval(101_000_000_000, 101_000_000_001),
    )?;
    for which in 0..4 {
        let mut changed = before.clone();
        match which {
            0 => changed.root.as_mut().unwrap().version = version(9),
            1 => changed.sentinel.as_mut().unwrap().version = version(9),
            2 => changed.create.as_mut().unwrap().version = version(9),
            _ => changed.activate.as_mut().unwrap().version = version(9),
        }
        assert!(
            plan.revalidate(&selected, &changed, Some(&floor), None)
                .is_err()
        );
        assert!(reconcile(&plan, &selected, &changed, Some(&floor), None).is_err());
    }
    let mut changed = floor.clone();
    changed.version = version(9);
    assert!(
        plan.revalidate(&selected, &before, Some(&changed), None)
            .is_err()
    );
    let used = Versioned {
        value: plan.receipt.clone(),
        version: version(9),
    };
    assert!(
        plan.revalidate(&selected, &before, Some(&floor), Some(&used))
            .is_err()
    );
    for which in 0..4 {
        let mut forged = plan.clone();
        match which {
            0 => forged.after.upper = utc(102_000_000_000),
            1 => forged.receipt.authority = Digest::new(b"foreign"),
            2 => forged.receipt.before_version = version(9),
            _ => forged.after.operation = Digest::new(b"foreign-operation"),
        }
        assert!(
            forged
                .revalidate(&selected, &before, Some(&floor), None)
                .is_err()
        );
    }
    let mut missing = before.clone();
    missing.create = None;
    assert!(
        Plan::prepare(
            &selected,
            &missing,
            Some(&floor),
            Digest::new(b"op"),
            interval(101_000_000_000, 101_000_000_001)
        )
        .is_err()
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Cut {
    Before,
    AfterFloor,
    BeforeCommit,
    LostReply,
    Known,
}

/// Independent conditional provider: compares stored versions and create-only
/// keys in a real SQLite transaction. It does not call the kernel's predicates.
fn send(db: &mut Connection, plan: &Plan, cut: Cut) -> Result<()> {
    let tx = db.transaction()?;
    if matches!(cut, Cut::Before) {
        anyhow::bail!("fixture_before_send");
    }
    let conditions = [
        ("root", &plan.before.root.as_ref().unwrap().version),
        ("sentinel", &plan.before.sentinel.as_ref().unwrap().version),
        ("create", &plan.before.create.as_ref().unwrap().version),
        ("activate", &plan.before.activate.as_ref().unwrap().version),
        ("floor", &plan.prior.version),
    ];
    for (name, expected) in conditions {
        let seen: i64 = tx.query_row("SELECT version FROM records WHERE name=?1", [name], |r| {
            r.get(0)
        })?;
        let expected = expected
            .0
            .rsplit('.')
            .next()
            .unwrap()
            .trim_end_matches('Z')
            .parse::<i64>()?;
        ensure!(seen == expected, "fixture_conflict");
    }
    let seen: i64 = tx.query_row("SELECT version FROM records WHERE name='floor'", [], |r| {
        r.get(0)
    })?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM receipts WHERE operation=?1)",
        [plan.receipt.operation.as_str()],
        |r| r.get(0),
    )?;
    ensure!(!exists, "fixture_receipt_exists");
    tx.execute(
        "UPDATE records SET body=?1,version=version+1 WHERE name='floor' AND version=?2",
        params![serde_json::to_string(&plan.after)?, seen],
    )?;
    if matches!(cut, Cut::AfterFloor) {
        anyhow::bail!("fixture_after_floor");
    }
    tx.execute(
        "INSERT INTO receipts VALUES(?1,?2,?3)",
        params![
            plan.receipt.operation.as_str(),
            serde_json::to_string(&plan.receipt)?,
            seen + 1
        ],
    )?;
    if matches!(cut, Cut::BeforeCommit) {
        anyhow::bail!("fixture_before_commit");
    }
    tx.commit()?;
    if matches!(cut, Cut::LostReply) {
        anyhow::bail!("fixture_lost_reply");
    }
    Ok(())
}

fn read(
    db: &Connection,
    operation: &Digest,
) -> Result<(Versioned<Floor>, Option<Versioned<Receipt>>)> {
    let (body, revision): (String, u64) = db.query_row(
        "SELECT body,version FROM records WHERE name='floor'",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let floor = Versioned {
        value: crate::json::decode(body.as_bytes())?,
        version: version(revision),
    };
    let receipt: Option<(String, u64)> = db
        .query_row(
            "SELECT body,version FROM receipts WHERE operation=?1",
            [operation.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok((
        floor,
        receipt
            .map(|(body, revision)| -> Result<_> {
                Ok(Versioned {
                    value: crate::json::decode(body.as_bytes())?,
                    version: version(revision),
                })
            })
            .transpose()?,
    ))
}

fn install_fixture(db: &Connection, before: &Snapshot, floor: &Versioned<Floor>) -> Result<()> {
    db.execute_batch("CREATE TABLE records(name TEXT PRIMARY KEY,body TEXT NOT NULL,version INTEGER NOT NULL);CREATE TABLE receipts(operation TEXT PRIMARY KEY,body TEXT NOT NULL,version INTEGER NOT NULL);")?;
    for (name, body, revision) in [
        (
            "root",
            serde_json::to_string(&before.root.as_ref().unwrap().value)?,
            2,
        ),
        (
            "sentinel",
            serde_json::to_string(&before.sentinel.as_ref().unwrap().value)?,
            2,
        ),
        (
            "create",
            serde_json::to_string(&before.create.as_ref().unwrap().value)?,
            1,
        ),
        (
            "activate",
            serde_json::to_string(&before.activate.as_ref().unwrap().value)?,
            2,
        ),
        ("floor", serde_json::to_string(&floor.value)?, 3),
    ] {
        db.execute(
            "INSERT INTO records VALUES(?1,?2,?3)",
            params![name, body, revision],
        )?;
    }
    Ok(())
}

#[test]
fn conditional_floor_and_receipt_are_atomic_across_reopen_and_lost_reply() -> Result<()> {
    for cut in [
        Cut::Before,
        Cut::AfterFloor,
        Cut::BeforeCommit,
        Cut::LostReply,
        Cut::Known,
    ] {
        let (selected, before, floor) = fixture();
        let plan = Plan::prepare(
            &selected,
            &before,
            Some(&floor),
            Digest::new(b"atomic-op"),
            interval(101_000_000_000, 101_000_000_001),
        )?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("external-time.sqlite");
        let mut db = Connection::open(&path)?;
        install_fixture(&db, &before, &floor)?;
        assert_eq!(send(&mut db, &plan, cut).is_ok(), matches!(cut, Cut::Known));
        drop(db);
        for _ in 0..2 {
            let db = Connection::open(&path)?;
            let (actual, receipt) = read(&db, &plan.receipt.operation)?;
            let expected = if matches!(cut, Cut::LostReply | Cut::Known) {
                Outcome::Applied
            } else {
                Outcome::NotApplied
            };
            assert_eq!(
                reconcile(&plan, &selected, &before, Some(&actual), receipt.as_ref())?,
                expected,
                "{cut:?}"
            );
            assert_eq!(
                actual.value.upper,
                if matches!(cut, Cut::LostReply | Cut::Known) {
                    utc(101_000_000_001)
                } else {
                    utc(100_000_000_000)
                }
            );
        }
    }
    Ok(())
}

#[test]
fn stale_concurrent_floor_cannot_win_or_turn_another_receipt_into_success() -> Result<()> {
    let (selected, before, floor) = fixture();
    let first = Plan::prepare(
        &selected,
        &before,
        Some(&floor),
        Digest::new(b"first"),
        interval(101_000_000_000, 101_000_000_001),
    )?;
    let second = Plan::prepare(
        &selected,
        &before,
        Some(&floor),
        Digest::new(b"second"),
        interval(102_000_000_000, 102_000_000_001),
    )?;
    let mut db = Connection::open_in_memory()?;
    install_fixture(&db, &before, &floor)?;
    send(&mut db, &first, Cut::Known)?;
    assert!(send(&mut db, &second, Cut::Known).is_err());
    let (actual, receipt) = read(&db, &second.receipt.operation)?;
    assert_eq!(
        reconcile(&second, &selected, &before, Some(&actual), receipt.as_ref())?,
        Outcome::Conflict
    );
    let first_receipt = read(&db, &first.receipt.operation)?.1;
    assert_eq!(
        reconcile(
            &second,
            &selected,
            &before,
            Some(&actual),
            first_receipt.as_ref()
        )?,
        Outcome::Conflict
    );
    Ok(())
}

#[test]
fn malformed_time_and_floor_wire_cannot_become_a_plan() -> Result<()> {
    let (selected, before, floor) = fixture();
    for bad in [
        Utc {
            seconds: u64::MAX,
            nanos: 0,
        },
        Utc {
            seconds: 100,
            nanos: 1_000_000_000,
        },
    ] {
        assert!(
            Plan::prepare(
                &selected,
                &before,
                Some(&floor),
                Digest::new(b"op"),
                Interval {
                    domain: Digest::new(b"d"),
                    lower: bad.clone(),
                    upper: bad
                }
            )
            .is_err()
        );
    }
    let mut foreign = floor.clone();
    foreign.value.format = Format::Day2RestoreTimeReceiptV1;
    assert!(
        Plan::prepare(
            &selected,
            &before,
            Some(&foreign),
            Digest::new(b"op"),
            interval(101_000_000_000, 101_000_000_001)
        )
        .is_err()
    );
    let wire = serde_json::to_string(&floor.value)?;
    let duplicate = wire.replacen("{", "{\"upper\":{\"seconds\":100,\"nanos\":0},", 1);
    assert!(crate::json::decode::<Floor>(duplicate.as_bytes()).is_err());
    Ok(())
}

#[test]
fn provider_checks_every_version_after_an_earlier_successful_revalidation() -> Result<()> {
    for name in ["root", "sentinel", "create", "activate", "floor"] {
        let (selected, before, floor) = fixture();
        let plan = Plan::prepare(
            &selected,
            &before,
            Some(&floor),
            Digest::new(b"race-op"),
            interval(101_000_000_000, 101_000_000_001),
        )?;
        plan.revalidate(&selected, &before, Some(&floor), None)?;
        let mut db = Connection::open_in_memory()?;
        install_fixture(&db, &before, &floor)?;
        db.execute("UPDATE records SET version=version+1 WHERE name=?1", [name])?;
        assert!(send(&mut db, &plan, Cut::Known).is_err(), "{name}");
        let (actual, receipt) = read(&db, &plan.receipt.operation)?;
        assert_eq!(actual.value, floor.value);
        assert!(receipt.is_none());
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Action {
    lower_delta: i64,
    width: u32,
    cut: Cut,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trace {
    format: u32,
    source: Digest,
    seed: u64,
    actions: Vec<Action>,
}

fn source() -> Result<Digest> {
    Digest::of(&(
        "day2-restore-time-floor-campaign-v1",
        include_str!("../approval_time.rs"),
        include_str!("tests.rs"),
    ))
}

fn replay(trace: &Trace) -> Result<()> {
    ensure!(
        trace.format == 1 && trace.source == source()? && trace.actions.len() == 64,
        "fixture_trace_binding"
    );
    let (selected, before, floor) = fixture();
    let mut db = Connection::open_in_memory()?;
    install_fixture(&db, &before, &floor)?;
    // The reference model uses integer time and durable step counts; it never
    // calls Plan, interval validation, reconciliation or the provider predicates.
    let mut model_floor = 100_000_000_000_i128;
    let mut commits = 0_u64;
    for (step, action) in trace.actions.iter().enumerate() {
        ensure!(
            (-1_000_000_000..=2_000_000_000).contains(&action.lower_delta)
                && action.width <= 1_000_000_001,
            "fixture_trace_action"
        );
        let lower = model_floor + i128::from(action.lower_delta);
        let upper = lower + i128::from(action.width);
        let valid = lower >= model_floor && action.width <= 1_000_000_000;
        let operation = Digest::of(&("generated-time-operation", trace.seed, step))?;
        let (observed, _) = read(&db, &operation)?;
        let plan = Plan::prepare(
            &selected,
            &before,
            Some(&observed),
            operation.clone(),
            interval(lower.try_into()?, upper.try_into()?),
        );
        ensure!(
            plan.is_ok() == valid,
            "fixture_model_acceptance seed={} step={step}",
            trace.seed
        );
        let applied = valid && matches!(action.cut, Cut::Known | Cut::LostReply);
        if let Ok(plan) = plan {
            let result = send(&mut db, &plan, action.cut);
            ensure!(
                result.is_ok() == matches!(action.cut, Cut::Known),
                "fixture_model_reply"
            );
            let (actual, receipt) = read(&db, &operation)?;
            let expected = if applied {
                Outcome::Applied
            } else {
                Outcome::NotApplied
            };
            ensure!(
                reconcile(&plan, &selected, &before, Some(&actual), receipt.as_ref())? == expected,
                "fixture_model_readback"
            );
        }
        if applied {
            model_floor = upper;
            commits += 1;
        }
        let (actual, _) = read(&db, &operation)?;
        ensure!(
            actual.value.upper == utc(model_floor.try_into()?)
                && actual.version == version(3 + commits),
            "fixture_model_durable_state"
        );
        let actual_receipts: u64 =
            db.query_row("SELECT count(*) FROM receipts", [], |r| r.get(0))?;
        ensure!(actual_receipts == commits, "fixture_model_receipt_count");
    }
    Ok(())
}

#[test]
fn seeded_histories_replay_against_an_independent_durable_time_model() -> Result<()> {
    for seed in 1..=64_u64 {
        let mut state = seed;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut actions = Vec::new();
        for _ in 0..64 {
            let lower_delta = [-1_000_000_000, -1, 0, 1, 2_000_000_000][(next() % 5) as usize];
            let width = [0, 1, 500_000_000, 1_000_000_000, 1_000_000_001][(next() % 5) as usize];
            let cut = [
                Cut::Before,
                Cut::AfterFloor,
                Cut::BeforeCommit,
                Cut::LostReply,
                Cut::Known,
            ][(next() % 5) as usize];
            actions.push(Action {
                lower_delta,
                width,
                cut,
            });
        }
        let trace = Trace {
            format: 1,
            source: source()?,
            seed,
            actions,
        };
        let bytes = serde_json::to_vec(&trace)?;
        let loaded: Trace = crate::json::decode(&bytes)?;
        let result = replay(&loaded).and_then(|()| replay(&loaded));
        if result.is_err() {
            let mut file = tempfile::Builder::new()
                .prefix("day2-restore-time-floor-failure-")
                .suffix(".json")
                .tempfile()?;
            std::io::Write::write_all(file.as_file_mut(), &bytes)?;
            let (_, path) = file.keep()?;
            anyhow::bail!(
                "restore_time_floor_counterexample_saved: {}",
                path.display()
            );
        }
    }
    Ok(())
}

#[test]
fn retained_trace_replay_requires_current_source_and_a_complete_bounded_schedule() -> Result<()> {
    let mut trace = Trace {
        format: 1,
        source: source()?,
        seed: 7,
        actions: vec![
            Action {
                lower_delta: 1,
                width: 1,
                cut: Cut::LostReply
            };
            64
        ],
    };
    replay(&trace)?;
    trace.source = Digest::new(b"another-source");
    assert!(replay(&trace).is_err());
    trace.source = source()?;
    trace.actions.pop();
    assert!(replay(&trace).is_err());
    trace.actions.push(Action {
        lower_delta: 1,
        width: 1_000_000_002,
        cut: Cut::Known,
    });
    assert!(replay(&trace).is_err());
    // This optional input adds a retained counterexample replay; it never skips
    // the normal campaign or any validation above. Only controlled test DATA.
    if let Some(path) = std::env::var_os("DAY2_RESTORE_TIME_FLOOR_REPLAY") {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(65_537)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 65_536, "fixture_trace_bound");
        let loaded: Trace = crate::json::decode(&bytes)?;
        replay(&loaded)?;
    }
    Ok(())
}
