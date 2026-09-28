//! Durable single-flight refresh kernel. The caller supplies verified eligibility
//! and a custody write that participates in the *same* SQLite transaction.
//! Provider transport must consume the permit after the dispatch fence commits.

use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshEligibility {
    pub slot: String,
    pub generation: i64,
    pub base_version: i64,
    pub security_epoch: i64,
    pub profile: String,
    pub account: String,
    pub affinity: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshState {
    Ready,
    MayHaveBeenSent,
    Uncertain,
    ReplacementCommitted { next_version: i64, receipt: String },
    PublicationRejected,
    ReauthRequired,
}

/// This value cannot be cloned, serialized or reconstructed after a crash. Its
/// private fields bind one dispatch to the exact claimed token generation.
pub struct RefreshDispatchPermit {
    attempt: String,
    eligibility: RefreshEligibility,
}

impl RefreshDispatchPermit {
    pub fn attempt(&self) -> &str {
        &self.attempt
    }

    /// Transport owns this value. The durable fence already exists when called.
    pub fn send<T>(self, transport: impl FnOnce(&RefreshEligibility) -> T) -> T {
        transport(&self.eligibility)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplacementReceipt {
    pub attempt: String,
    pub next_version: i64,
    pub receipt: String,
}

pub fn install_schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS oauth_schema_version (
            version INTEGER PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS oauth_connection_slots (
            slot TEXT PRIMARY KEY,
            generation INTEGER NOT NULL CHECK(generation > 0),
            token_version INTEGER NOT NULL CHECK(token_version > 0),
            security_epoch INTEGER NOT NULL CHECK(security_epoch > 0),
            profile TEXT NOT NULL,
            account TEXT NOT NULL,
            affinity TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('active', 'reauth_required', 'disabled'))
        );
        CREATE TABLE IF NOT EXISTS oauth_refresh_attempts (
            attempt TEXT PRIMARY KEY,
            slot TEXT NOT NULL REFERENCES oauth_connection_slots(slot),
            generation INTEGER NOT NULL,
            base_version INTEGER NOT NULL,
            security_epoch INTEGER NOT NULL,
            profile TEXT NOT NULL,
            account TEXT NOT NULL,
            affinity TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN (
                'ready', 'may_have_been_sent', 'uncertain', 'replacement_committed',
                'publication_rejected', 'reauth_required'
            )),
            next_version INTEGER,
            receipt TEXT,
            CHECK((state = 'replacement_committed') = (next_version IS NOT NULL AND receipt IS NOT NULL)),
            UNIQUE(slot, generation, base_version)
        );",
    )?;
    let mut versions = db.prepare("SELECT version FROM oauth_schema_version")?;
    let known = versions
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        known.is_empty() || known == [1],
        "unsupported OAuth schema version"
    );
    if known.is_empty() {
        db.execute("INSERT INTO oauth_schema_version VALUES (1)", [])?;
    }
    Ok(())
}

/// A caller must establish eligibility from current identity, slot and custody
/// evidence. This kernel repeats the durable version/fence checks under SQLite.
pub fn claim_refresh(
    db: &mut Connection,
    attempt: &str,
    expected: &RefreshEligibility,
) -> Result<bool> {
    validate_id(attempt)?;
    validate_eligibility(expected)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current: Option<(i64, i64, i64, String, String, String, String)> = tx
        .query_row(
            "SELECT generation, token_version, security_epoch, profile, account, affinity, status
         FROM oauth_connection_slots WHERE slot = ?1",
            [&expected.slot],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    let eligible = current.is_some_and(
        |(generation, version, epoch, profile, account, affinity, status)| {
            generation == expected.generation
                && version == expected.base_version
                && epoch == expected.security_epoch
                && profile == expected.profile
                && account == expected.account
                && affinity == expected.affinity
                && status == "active"
        },
    );
    if !eligible {
        return Ok(false);
    }
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO oauth_refresh_attempts
         (attempt, slot, generation, base_version, security_epoch, profile, account, affinity, state)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'ready')",
        params![
            attempt,
            expected.slot,
            expected.generation,
            expected.base_version,
            expected.security_epoch,
            expected.profile,
            expected.account,
            expected.affinity
        ],
    )?;
    tx.commit()?;
    Ok(inserted == 1)
}

/// A known committed CAS is the only source of a process-local dispatch permit.
pub fn authorize_and_commit_dispatch(
    db: &mut Connection,
    attempt: &str,
) -> Result<Option<RefreshDispatchPermit>> {
    validate_id(attempt)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row = tx.query_row(
        "SELECT a.slot, a.generation, a.base_version, a.security_epoch, a.profile, a.account, a.affinity
         FROM oauth_refresh_attempts a JOIN oauth_connection_slots s ON s.slot = a.slot
         WHERE a.attempt = ?1 AND a.state = 'ready' AND s.status = 'active'
           AND s.generation = a.generation AND s.token_version = a.base_version
           AND s.security_epoch = a.security_epoch AND s.profile = a.profile AND s.account = a.account
           AND s.affinity = a.affinity",
        [attempt],
        |row| Ok(RefreshEligibility {
            slot: row.get(0)?, generation: row.get(1)?, base_version: row.get(2)?,
            security_epoch: row.get(3)?, profile: row.get(4)?, account: row.get(5)?,
            affinity: row.get(6)?,
        }),
    ).optional()?;
    let Some(eligibility) = row else {
        return Ok(None);
    };
    let changed = tx.execute(
        "UPDATE oauth_refresh_attempts SET state = 'may_have_been_sent'
         WHERE attempt = ?1 AND state = 'ready'",
        [attempt],
    )?;
    ensure!(changed == 1, "refresh dispatch fence lost");
    tx.commit()?;
    Ok(Some(RefreshDispatchPermit {
        attempt: attempt.to_owned(),
        eligibility,
    }))
}

/// Recovery never reconstructs a permit. A crash after fencing but before the
/// socket send is deliberately indistinguishable from a sent request.
pub fn mark_uncertain(db: &Connection, attempt: &str) -> Result<bool> {
    validate_id(attempt)?;
    Ok(db.execute(
        "UPDATE oauth_refresh_attempts SET state = 'uncertain'
         WHERE attempt = ?1 AND state = 'may_have_been_sent'",
        [attempt],
    )? == 1)
}

/// A definitive, profile-classified invalid-grant response blocks future use
/// only if this attempt still owns the active base version. A stale rejection
/// cannot disable a successor connection.
pub fn mark_definitive_rejection(db: &mut Connection, attempt: &str) -> Result<bool> {
    validate_id(attempt)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<RefreshEligibility> = tx
        .query_row(
            "SELECT slot, generation, base_version, security_epoch, profile, account, affinity
         FROM oauth_refresh_attempts WHERE attempt = ?1
           AND state IN ('may_have_been_sent', 'uncertain')",
            [attempt],
            |row| {
                Ok(RefreshEligibility {
                    slot: row.get(0)?,
                    generation: row.get(1)?,
                    base_version: row.get(2)?,
                    security_epoch: row.get(3)?,
                    profile: row.get(4)?,
                    account: row.get(5)?,
                    affinity: row.get(6)?,
                })
            },
        )
        .optional()?;
    let Some(expected) = row else {
        return Ok(false);
    };
    let changed = tx.execute(
        "UPDATE oauth_connection_slots SET status = 'reauth_required'
         WHERE slot = ?1 AND generation = ?2 AND token_version = ?3
           AND security_epoch = ?4 AND profile = ?5 AND account = ?6
           AND affinity = ?7 AND status = 'active'",
        params![
            expected.slot,
            expected.generation,
            expected.base_version,
            expected.security_epoch,
            expected.profile,
            expected.account,
            expected.affinity
        ],
    )?;
    tx.execute(
        "UPDATE oauth_refresh_attempts SET state = ?2 WHERE attempt = ?1",
        params![
            attempt,
            if changed == 1 {
                "reauth_required"
            } else {
                "publication_rejected"
            }
        ],
    )?;
    tx.commit()?;
    Ok(changed == 1)
}

/// `custody_write` stores only encrypted material in the caller's reserved
/// private vault tables. Its error rolls back both the version and receipt.
pub fn commit_replacement(
    db: &mut Connection,
    attempt: &str,
    next_version: i64,
    receipt: &str,
    custody_write: impl FnOnce(&Transaction<'_>) -> Result<()>,
) -> Result<Option<ReplacementReceipt>> {
    validate_id(attempt)?;
    validate_id(receipt)?;
    ensure!(next_version > 1, "invalid replacement token version");
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(RefreshEligibility, String)> = tx
        .query_row(
            "SELECT slot, generation, base_version, security_epoch, profile, account, affinity, state
         FROM oauth_refresh_attempts WHERE attempt = ?1",
            [attempt],
            |row| {
                Ok((
                    RefreshEligibility {
                        slot: row.get(0)?,
                        generation: row.get(1)?,
                        base_version: row.get(2)?,
                        security_epoch: row.get(3)?,
                        profile: row.get(4)?,
                        account: row.get(5)?,
                        affinity: row.get(6)?,
                    },
                    row.get(7)?,
                ))
            },
        )
        .optional()?;
    let Some((expected, state)) = row else {
        return Ok(None);
    };
    if state != "may_have_been_sent" && state != "uncertain" {
        return Ok(None);
    }
    ensure!(
        next_version == expected.base_version + 1,
        "replacement version mismatch"
    );
    let current: Option<(i64, i64, i64, String, String, String, String)> = tx
        .query_row(
            "SELECT generation, token_version, security_epoch, profile, account, affinity, status
         FROM oauth_connection_slots WHERE slot = ?1",
            [&expected.slot],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    if !current.is_some_and(
        |(generation, version, epoch, profile, account, affinity, status)| {
            generation == expected.generation
                && version == expected.base_version
                && epoch == expected.security_epoch
                && profile == expected.profile
                && account == expected.account
                && affinity == expected.affinity
                && status == "active"
        },
    ) {
        tx.execute(
            "UPDATE oauth_refresh_attempts SET state = 'publication_rejected'
             WHERE attempt = ?1",
            [attempt],
        )?;
        tx.commit()?;
        return Ok(None);
    }
    custody_write(&tx)?;
    let changed = tx.execute(
        "UPDATE oauth_connection_slots SET token_version = ?2
         WHERE slot = ?1 AND generation = ?3 AND token_version = ?4 AND security_epoch = ?5
           AND profile = ?6 AND account = ?7 AND affinity = ?8 AND status = 'active'",
        params![
            expected.slot,
            next_version,
            expected.generation,
            expected.base_version,
            expected.security_epoch,
            expected.profile,
            expected.account,
            expected.affinity
        ],
    )?;
    ensure!(changed == 1, "replacement publication fence lost");
    tx.execute(
        "UPDATE oauth_refresh_attempts SET state = 'replacement_committed', next_version = ?2,
         receipt = ?3 WHERE attempt = ?1 AND state IN ('may_have_been_sent', 'uncertain')",
        params![attempt, next_version, receipt],
    )?;
    tx.commit()?;
    Ok(Some(ReplacementReceipt {
        attempt: attempt.to_owned(),
        next_version,
        receipt: receipt.to_owned(),
    }))
}

pub fn refresh_state(db: &Connection, attempt: &str) -> Result<Option<RefreshState>> {
    validate_id(attempt)?;
    let row: Option<(String, Option<i64>, Option<String>)> = db
        .query_row(
            "SELECT state, next_version, receipt FROM oauth_refresh_attempts WHERE attempt = ?1",
            [attempt],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    row.map(|(state, next, receipt)| match state.as_str() {
        "ready" => Ok(RefreshState::Ready),
        "may_have_been_sent" => Ok(RefreshState::MayHaveBeenSent),
        "uncertain" => Ok(RefreshState::Uncertain),
        "replacement_committed" => Ok(RefreshState::ReplacementCommitted {
            next_version: next.ok_or_else(|| anyhow::anyhow!("missing committed version"))?,
            receipt: receipt.ok_or_else(|| anyhow::anyhow!("missing committed receipt"))?,
        }),
        "publication_rejected" => Ok(RefreshState::PublicationRejected),
        "reauth_required" => Ok(RefreshState::ReauthRequired),
        _ => anyhow::bail!("unknown refresh state"),
    })
    .transpose()
}

pub fn disable_slot(db: &mut Connection, slot: &str, expected_epoch: i64) -> Result<bool> {
    validate_id(slot)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let changed = tx.execute(
        "UPDATE oauth_connection_slots SET status = 'disabled', security_epoch = security_epoch + 1
         WHERE slot = ?1 AND security_epoch = ?2 AND status = 'active'",
        params![slot, expected_epoch],
    )?;
    if changed == 1 {
        tx.execute(
            "UPDATE oauth_refresh_attempts SET state = 'publication_rejected'
             WHERE slot = ?1 AND state IN ('ready', 'may_have_been_sent', 'uncertain')",
            [slot],
        )?;
    }
    tx.commit()?;
    Ok(changed == 1)
}

fn validate_eligibility(value: &RefreshEligibility) -> Result<()> {
    validate_id(&value.slot)?;
    validate_id(&value.profile)?;
    validate_id(&value.account)?;
    validate_id(&value.affinity)?;
    ensure!(
        value.generation > 0 && value.base_version > 0 && value.security_epoch > 0,
        "invalid refresh fence"
    );
    Ok(())
}

fn validate_id(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 160
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-:/".contains(&byte)),
        "invalid private OAuth identifier"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::{BufRead, Write};
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    fn eligibility() -> RefreshEligibility {
        RefreshEligibility {
            slot: "installation.env.app.calendar.human_1".into(),
            generation: 7,
            base_version: 1,
            security_epoch: 4,
            profile: "google_calendar_v1".into(),
            account: "google_subject_1".into(),
            affinity: "affinity_v1".into(),
        }
    }

    fn setup(db: &Connection) {
        db.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
            .unwrap();
        install_schema(db).unwrap();
        let expected = eligibility();
        db.execute(
            "INSERT INTO oauth_connection_slots
             (slot, generation, token_version, security_epoch, profile, account, affinity, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active')",
            params![
                expected.slot,
                expected.generation,
                expected.base_version,
                expected.security_epoch,
                expected.profile,
                expected.account,
                expected.affinity
            ],
        )
        .unwrap();
    }

    fn version(db: &Connection) -> i64 {
        db.query_row(
            "SELECT token_version FROM oauth_connection_slots",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }

    #[test]
    fn fence_survives_reopen_and_only_committed_receipt_recovers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("app.sqlite");
        let mut host_a = Connection::open(&path).unwrap();
        setup(&host_a);
        assert!(claim_refresh(&mut host_a, "attempt_1", &eligibility()).unwrap());
        let mut host_b = Connection::open(&path).unwrap();
        host_b.execute_batch("PRAGMA foreign_keys = ON").unwrap();
        assert!(!claim_refresh(&mut host_b, "attempt_2", &eligibility()).unwrap());
        let permit = authorize_and_commit_dispatch(&mut host_a, "attempt_1")
            .unwrap()
            .unwrap();
        assert_eq!(permit.attempt(), "attempt_1");
        assert_eq!(
            permit.send(|bound| bound.account.clone()),
            "google_subject_1"
        );
        drop(host_a);
        let mut reopened = Connection::open(&path).unwrap();
        reopened.execute_batch("PRAGMA foreign_keys = ON").unwrap();
        assert!(
            authorize_and_commit_dispatch(&mut reopened, "attempt_1")
                .unwrap()
                .is_none()
        );
        assert!(mark_uncertain(&reopened, "attempt_1").unwrap());
        assert_eq!(
            refresh_state(&reopened, "attempt_1").unwrap(),
            Some(RefreshState::Uncertain)
        );
        let receipt = commit_replacement(&mut reopened, "attempt_1", 2, "receipt_1", |tx| {
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS private_test_vault
                (slot TEXT, version INTEGER, encrypted BLOB, PRIMARY KEY(slot, version))",
            )?;
            tx.execute(
                "INSERT INTO private_test_vault VALUES (?1, 2, ?2)",
                params![eligibility().slot, b"encrypted-fixture".as_slice()],
            )?;
            Ok(())
        })
        .unwrap()
        .unwrap();
        assert_eq!(receipt.next_version, 2);
        assert_eq!(version(&reopened), 2);
        assert_eq!(
            refresh_state(&reopened, "attempt_1").unwrap(),
            Some(RefreshState::ReplacementCommitted {
                next_version: 2,
                receipt: "receipt_1".into()
            })
        );
        assert!(
            commit_replacement(&mut reopened, "attempt_1", 2, "receipt_2", |_| Ok(()))
                .unwrap()
                .is_none()
        );
        assert!(!claim_refresh(&mut host_b, "attempt_3", &eligibility()).unwrap());
    }

    #[test]
    fn custody_failure_rolls_back_and_disconnect_fences_late_publication() {
        let mut db = Connection::open_in_memory().unwrap();
        setup(&db);
        assert!(claim_refresh(&mut db, "attempt_1", &eligibility()).unwrap());
        authorize_and_commit_dispatch(&mut db, "attempt_1")
            .unwrap()
            .unwrap()
            .send(|_| ());
        assert!(
            commit_replacement(&mut db, "attempt_1", 2, "receipt_1", |_| {
                anyhow::bail!("test custody failure")
            })
            .is_err()
        );
        assert_eq!(version(&db), 1);
        assert_eq!(
            refresh_state(&db, "attempt_1").unwrap(),
            Some(RefreshState::MayHaveBeenSent)
        );
        assert!(disable_slot(&mut db, &eligibility().slot, 4).unwrap());
        assert!(!disable_slot(&mut db, &eligibility().slot, 4).unwrap());
        assert_eq!(
            refresh_state(&db, "attempt_1").unwrap(),
            Some(RefreshState::PublicationRejected)
        );
        assert!(
            commit_replacement(&mut db, "attempt_1", 2, "receipt_1", |_| Ok(()))
                .unwrap()
                .is_none()
        );
        assert_eq!(version(&db), 1);
    }

    #[test]
    fn two_sqlite_hosts_cannot_claim_one_token_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("race.sqlite");
        setup(&Connection::open(&path).unwrap());
        let barrier = Arc::new(Barrier::new(2));
        let results = std::thread::scope(|scope| {
            let jobs = (1..=2)
                .map(|ordinal| {
                    let path = path.clone();
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        let mut db = Connection::open(path).unwrap();
                        db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
                        barrier.wait();
                        claim_refresh(&mut db, &format!("attempt_{ordinal}"), &eligibility())
                            .unwrap()
                    })
                })
                .collect::<Vec<_>>();
            jobs.into_iter()
                .map(|job| job.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.into_iter().filter(|claimed| *claimed).count(), 1);
    }

    #[test]
    fn successor_generation_can_refresh_its_own_first_version() {
        let mut db = Connection::open_in_memory().unwrap();
        setup(&db);
        assert!(claim_refresh(&mut db, "old_attempt", &eligibility()).unwrap());
        let mut successor = eligibility();
        successor.generation += 1;
        successor.account = "successor_account".into();
        successor.affinity = "successor_affinity".into();
        db.execute(
            "UPDATE oauth_connection_slots SET generation = ?2, token_version = 1,
             account = ?3, affinity = ?4 WHERE slot = ?1",
            params![
                successor.slot,
                successor.generation,
                successor.account,
                successor.affinity
            ],
        )
        .unwrap();
        assert!(claim_refresh(&mut db, "new_attempt", &successor).unwrap());
        assert!(
            authorize_and_commit_dispatch(&mut db, "old_attempt")
                .unwrap()
                .is_none()
        );
        assert!(
            authorize_and_commit_dispatch(&mut db, "new_attempt")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn changed_affinity_blocks_claim_and_dispatch() {
        let mut db = Connection::open_in_memory().unwrap();
        setup(&db);
        let mut changed = eligibility();
        changed.affinity = "different_consent_or_registration".into();
        assert!(!claim_refresh(&mut db, "wrong_attempt", &changed).unwrap());
        assert!(claim_refresh(&mut db, "old_attempt", &eligibility()).unwrap());
        db.execute(
            "UPDATE oauth_connection_slots SET affinity = ?1",
            [&changed.affinity],
        )
        .unwrap();
        assert!(
            authorize_and_commit_dispatch(&mut db, "old_attempt")
                .unwrap()
                .is_none()
        );
        assert!(!claim_refresh(&mut db, "new_attempt", &changed).unwrap());
    }

    #[test]
    fn unknown_schema_version_fails_closed() {
        let db = Connection::open_in_memory().unwrap();
        install_schema(&db).unwrap();
        db.execute("UPDATE oauth_schema_version SET version = 2", [])
            .unwrap();
        assert!(install_schema(&db).is_err());
    }

    #[test]
    fn definitive_rejection_cannot_disable_replaced_or_revoked_slot() {
        let mut active = Connection::open_in_memory().unwrap();
        setup(&active);
        claim_refresh(&mut active, "attempt_1", &eligibility()).unwrap();
        authorize_and_commit_dispatch(&mut active, "attempt_1")
            .unwrap()
            .unwrap()
            .send(|_| ());
        assert!(mark_definitive_rejection(&mut active, "attempt_1").unwrap());
        assert_eq!(
            refresh_state(&active, "attempt_1").unwrap(),
            Some(RefreshState::ReauthRequired)
        );
        assert!(!claim_refresh(&mut active, "attempt_2", &eligibility()).unwrap());

        let mut revoked = Connection::open_in_memory().unwrap();
        setup(&revoked);
        claim_refresh(&mut revoked, "attempt_1", &eligibility()).unwrap();
        authorize_and_commit_dispatch(&mut revoked, "attempt_1")
            .unwrap()
            .unwrap()
            .send(|_| ());
        disable_slot(&mut revoked, &eligibility().slot, 4).unwrap();
        assert!(!mark_definitive_rejection(&mut revoked, "attempt_1").unwrap());
        assert_eq!(
            refresh_state(&revoked, "attempt_1").unwrap(),
            Some(RefreshState::PublicationRejected)
        );

        let mut replaced = Connection::open_in_memory().unwrap();
        setup(&replaced);
        claim_refresh(&mut replaced, "attempt_1", &eligibility()).unwrap();
        authorize_and_commit_dispatch(&mut replaced, "attempt_1")
            .unwrap()
            .unwrap()
            .send(|_| ());
        replaced
            .execute(
                "UPDATE oauth_connection_slots SET generation = 8, token_version = 1,
            account = 'successor_account'",
                [],
            )
            .unwrap();
        assert!(!mark_definitive_rejection(&mut replaced, "attempt_1").unwrap());
        let (status, account): (String, String) = replaced
            .query_row(
                "SELECT status, account FROM oauth_connection_slots",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (status, account),
            ("active".into(), "successor_account".into())
        );
        assert_eq!(
            refresh_state(&replaced, "attempt_1").unwrap(),
            Some(RefreshState::PublicationRejected)
        );
    }

    #[test]
    fn subprocess_fence_crash_reopens_uncertain() {
        const CHILD_PATH: &str = "DAY2_OAUTH_CRASH_TEST_DB";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            let mut db = Connection::open(path).unwrap();
            assert!(claim_refresh(&mut db, "attempt_1", &eligibility()).unwrap());
            let _permit = authorize_and_commit_dispatch(&mut db, "attempt_1")
                .unwrap()
                .unwrap();
            println!("OAUTH_FENCE_COMMITTED");
            std::io::stdout().flush().unwrap();
            loop {
                std::thread::park();
            }
        }

        let dir = tempdir().unwrap();
        let path = dir.path().join("crash.sqlite");
        setup(&Connection::open(&path).unwrap());
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("oauth::store::tests::subprocess_fence_crash_reopens_uncertain")
            .arg("--nocapture")
            .env(CHILD_PATH, &path)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut seen_fence = false;
        for line in std::io::BufReader::new(stdout).lines() {
            if line.unwrap().contains("OAUTH_FENCE_COMMITTED") {
                seen_fence = true;
                break;
            }
        }
        assert!(seen_fence, "child did not commit the dispatch fence");
        child.kill().unwrap();
        child.wait().unwrap();
        let mut reopened = Connection::open(&path).unwrap();
        assert_eq!(
            refresh_state(&reopened, "attempt_1").unwrap(),
            Some(RefreshState::MayHaveBeenSent)
        );
        assert!(
            authorize_and_commit_dispatch(&mut reopened, "attempt_1")
                .unwrap()
                .is_none()
        );
        assert!(mark_uncertain(&reopened, "attempt_1").unwrap());
        assert!(!claim_refresh(&mut reopened, "attempt_2", &eligibility()).unwrap());
    }

    #[derive(Clone, Copy, Debug)]
    enum Step {
        Claim,
        Fence,
        Uncertain,
        Commit,
        Disconnect,
        Reject,
    }

    /// Independent small oracle: it does not call the SQL transition functions.
    #[derive(Clone, Copy, Debug)]
    struct Model {
        state: Option<u8>,
        active: bool,
        version: i64,
    }

    impl Model {
        fn step(&mut self, action: Step) -> bool {
            match action {
                Step::Claim if self.state.is_none() && self.active && self.version == 1 => {
                    self.state = Some(0);
                    true
                }
                Step::Fence if self.state == Some(0) && self.active => {
                    self.state = Some(1);
                    true
                }
                Step::Uncertain if self.state == Some(1) => {
                    self.state = Some(2);
                    true
                }
                Step::Commit if matches!(self.state, Some(1 | 2)) && self.active => {
                    self.state = Some(3);
                    self.version = 2;
                    true
                }
                Step::Disconnect if self.active => {
                    self.active = false;
                    if matches!(self.state, Some(0..=2)) {
                        self.state = Some(4);
                    }
                    true
                }
                Step::Reject if matches!(self.state, Some(1 | 2)) && self.active => {
                    self.active = false;
                    self.state = Some(5);
                    true
                }
                _ => false,
            }
        }

        fn observed(&self) -> Option<RefreshState> {
            match self.state {
                None => None,
                Some(0) => Some(RefreshState::Ready),
                Some(1) => Some(RefreshState::MayHaveBeenSent),
                Some(2) => Some(RefreshState::Uncertain),
                Some(3) => Some(RefreshState::ReplacementCommitted {
                    next_version: 2,
                    receipt: "receipt_1".into(),
                }),
                Some(4) => Some(RefreshState::PublicationRejected),
                Some(5) => Some(RefreshState::ReauthRequired),
                _ => unreachable!(),
            }
        }
    }

    proptest! {
        #[test]
        fn sqlite_matches_independent_oracle(schedule in proptest::collection::vec(0u8..6, 0..30)) {
            let mut db = Connection::open_in_memory().unwrap();
            setup(&db);
            let mut model = Model { state: None, active: true, version: 1 };
            for choice in schedule {
                let action = match choice {
                    0 => Step::Claim, 1 => Step::Fence, 2 => Step::Uncertain,
                    3 => Step::Commit, 4 => Step::Disconnect, _ => Step::Reject,
                };
                let predicted = model.step(action);
                let actual = match action {
                    Step::Claim => claim_refresh(&mut db, "attempt_1", &eligibility()).unwrap(),
                    Step::Fence => authorize_and_commit_dispatch(&mut db, "attempt_1").unwrap()
                        .map(|permit| { permit.send(|_| ()); true }).unwrap_or(false),
                    Step::Uncertain => mark_uncertain(&db, "attempt_1").unwrap(),
                    Step::Commit => commit_replacement(&mut db, "attempt_1", 2, "receipt_1", |_| Ok(())).unwrap().is_some(),
                    Step::Disconnect => disable_slot(&mut db, &eligibility().slot, 4).unwrap(),
                    Step::Reject => mark_definitive_rejection(&mut db, "attempt_1").unwrap(),
                };
                prop_assert_eq!(actual, predicted);
                prop_assert_eq!(refresh_state(&db, "attempt_1").unwrap(), model.observed());
                prop_assert_eq!(version(&db), model.version);
            }
        }
    }
}
