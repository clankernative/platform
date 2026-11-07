//! Real SQLite journal controls and an independent durable-state model. Fixture
//! keys/time/signatures are DATA; no native completed/signing owner is created.
use super::*;
use crate::security_epoch::{
    restore_approval,
    restore_webauthn::tests::{Fixture, fixture},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use rusqlite::{Connection, OptionalExtension};

pub(in crate::security_epoch::restore_webauthn::store) fn statement(
    f: &mut Fixture,
) -> Result<SignedApprovalRecord> {
    let mut request = restore_approval::fixture_request_data()?;
    request.approved_at = 1100;
    request.expires_at = 4700;
    f.challenge.request = request.intent().commitment()?;
    let pair = Ed25519KeyPair::from_seed_unchecked(&[29; 32]).unwrap();
    let selected=day2_capabilities::restore_signing::KeySelection {
        version:"projects/fixture/locations/global/keyRings/restore/cryptoKeys/approval/cryptoKeyVersions/7".to_owned().try_into()?,
        public_key:pair.public_key().as_ref().try_into()?,
    };
    let statement = ApprovalStatement {
        request,
        approver: restore_approval::AdminIdentity {
            email: "admin@example.org".into(),
            subject: "fixture-subject".into(),
        },
        registry: f.key.record.registry.clone(),
        credential: Digest::new(&f.key.record.credential_id),
        assertion: Digest::new(b"fixture-real-assertion-data"),
        signing_key: selected.commitment()?,
    };
    let frame = serde_json::to_vec(&("day2-restore-approval-grant-ed25519-v1", &statement))?;
    Ok(SignedApprovalRecord {
        statement,
        signature: URL_SAFE_NO_PAD.encode(pair.sign(&frame).as_ref()),
    })
}

fn initialize(db: &mut Connection, f: &Fixture) -> Result<Digest> {
    db.execute_batch(super::super::DDL)?;
    db.execute(
        "INSERT INTO main.restore_passkey_keys VALUES(?1,?2,1,0,1)",
        params![&f.key.record.credential_id, f.key.binding()?.as_str()],
    )?;
    let tx = db.transaction()?;
    let id = super::super::issue(&tx, &f.key, &f.challenge, 1000, 1300)?;
    tx.commit()?;
    Ok(id)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Verify,
    Prepare,
    May,
    Check,
    Publish,
    ForeignPrepare,
    ForeignMay,
    ForeignPublish,
    Reopen,
    Remove,
    Rewrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Journal {
    Prepared,
    May,
    Published,
}

#[derive(Debug)]
struct Model {
    verified: bool,
    version: i64,
    enabled: bool,
    journal: Option<Journal>,
}

impl Model {
    fn apply(&mut self, step: Step) -> bool {
        match step {
            Step::Reopen => true,
            Step::Remove => {
                self.enabled = false;
                true
            }
            Step::Rewrite => {
                self.version += 1;
                true
            }
            Step::Verify if !self.verified && self.version == 1 && self.enabled => {
                self.verified = true;
                self.version = 2;
                true
            }
            Step::Prepare
                if self.verified && self.version == 2 && self.enabled && self.journal.is_none() =>
            {
                self.journal = Some(Journal::Prepared);
                true
            }
            Step::May
                if self.enabled && self.version == 2 && self.journal == Some(Journal::Prepared) =>
            {
                self.journal = Some(Journal::May);
                true
            }
            Step::Check
                if self.enabled && self.version == 2 && self.journal == Some(Journal::May) =>
            {
                true
            }
            Step::Publish
                if self.enabled && self.version == 2 && self.journal == Some(Journal::May) =>
            {
                self.journal = Some(Journal::Published);
                true
            }
            _ => false,
        }
    }
}

fn execute(
    db: &mut Connection,
    f: &Fixture,
    id: &Digest,
    record: &SignedApprovalRecord,
    step: Step,
) -> Result<()> {
    match step {
        Step::Verify => {
            super::super::complete(
                db,
                &f.key,
                id,
                &f.challenge.request,
                1001,
                &f.assertion(0, 0x0d),
            )?;
            Ok(())
        }
        Step::Remove => {
            db.execute("UPDATE main.restore_passkey_keys SET enabled=0", [])?;
            Ok(())
        }
        Step::Rewrite => {
            db.execute("UPDATE main.restore_passkey_keys SET version=version+1", [])?;
            Ok(())
        }
        Step::Reopen => Ok(()),
        _ => {
            let tx = db.transaction()?;
            let mut changed = record.clone();
            changed.statement.request.target.artifact = Digest::new(b"another-world");
            match step {
                Step::Prepare => prepare_signing(&tx, &f.key, id, &record.statement, 0)?,
                Step::May => mark_may_sign(&tx, &f.key, id, &record.statement)?,
                Step::Check => check_may_sign(&tx, &f.key, id, &record.statement)?,
                Step::Publish => record_publication(&tx, &f.key, id, record)?,
                Step::ForeignPrepare => prepare_signing(&tx, &f.key, id, &changed.statement, 0)?,
                Step::ForeignMay => mark_may_sign(&tx, &f.key, id, &changed.statement)?,
                Step::ForeignPublish => record_publication(&tx, &f.key, id, &changed)?,
                _ => unreachable!(),
            }
            tx.commit()?;
            Ok(())
        }
    }
}

fn check(db: &Connection, model: &Model) -> Result<()> {
    let (version, counter, enabled): (i64, u32, bool) = db.query_row(
        "SELECT version,counter,enabled FROM main.restore_passkey_keys",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    assert_eq!(
        (version, counter, enabled),
        (model.version, 0, model.enabled)
    );
    let challenge: String = db.query_row(
        "SELECT state FROM main.restore_passkey_challenges",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        challenge,
        if model.verified {
            "verified"
        } else {
            "pending"
        }
    );
    let row:Option<(String,bool,i64,i64)>=db.query_row("SELECT state,signed_record IS NOT NULL,approved_at,expires_at FROM main.restore_approval_issuance",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let expected = model.journal.map(|s| {
        (
            match s {
                Journal::Prepared => "prepared",
                Journal::May => "may_sign",
                Journal::Published => "published",
            }
            .to_owned(),
            s == Journal::Published,
            1100,
            4700,
        )
    });
    assert_eq!(row, expected);
    Ok(())
}

fn history(steps: &[Step]) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("auth.sqlite");
    let mut db = Connection::open(&path)?;
    let mut f = fixture();
    let record = statement(&mut f)?;
    let id = initialize(&mut db, &f)?;
    let mut model = Model {
        verified: false,
        version: 1,
        enabled: true,
        journal: None,
    };
    for (index, step) in steps.iter().copied().enumerate() {
        let expected = model.apply(step);
        let result = if step == Step::Reopen {
            drop(db);
            db = Connection::open(&path)?;
            Ok(())
        } else {
            execute(&mut db, &f, &id, &record, step)
        };
        assert_eq!(
            result.is_ok(),
            expected,
            "prefix={:?}, model={model:?}",
            &steps[..=index]
        );
        assert!(db.is_autocommit());
        check(&db, &model)?;
    }
    Ok(())
}

#[test]
fn signing_journal_advances_once_and_preserves_frozen_times_across_real_reopen() -> Result<()> {
    history(&[
        Step::Prepare,
        Step::May,
        Step::Verify,
        Step::Reopen,
        Step::Prepare,
        Step::Prepare,
        Step::May,
        Step::Reopen,
        Step::May,
        Step::Check,
        Step::Publish,
        Step::Reopen,
        Step::Publish,
        Step::Verify,
    ])
}

#[test]
fn signing_journal_refuses_key_removal_aba_and_foreign_statement_at_every_stage() -> Result<()> {
    for prefix in [
        vec![Step::Verify],
        vec![Step::Verify, Step::Prepare],
        vec![Step::Verify, Step::Prepare, Step::May],
    ] {
        for fault in [Step::Remove, Step::Rewrite] {
            let mut steps = prefix.clone();
            steps.extend([
                fault,
                Step::Prepare,
                Step::May,
                Step::Check,
                Step::Publish,
                Step::Reopen,
            ]);
            history(&steps)?;
        }
    }
    history(&[
        Step::Verify,
        Step::ForeignPrepare,
        Step::Prepare,
        Step::ForeignMay,
        Step::May,
        Step::ForeignPublish,
        Step::Check,
        Step::Publish,
    ])
}

#[test]
fn signing_journal_seeded_replayable_histories_match_independent_model() -> Result<()> {
    let actions = [
        Step::Verify,
        Step::Prepare,
        Step::May,
        Step::Check,
        Step::Publish,
        Step::ForeignPrepare,
        Step::ForeignMay,
        Step::ForeignPublish,
        Step::Reopen,
        Step::Remove,
        Step::Rewrite,
    ];
    for seed in 0..32u64 {
        let mut state = seed + 1;
        let mut steps = vec![Step::Verify, Step::Prepare];
        for _ in 0..40 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            steps.push(actions[(state as usize) % actions.len()]);
        }
        history(&steps).map_err(|error| error.context(format!("signing-history-seed-{seed}")))?;
    }
    Ok(())
}
