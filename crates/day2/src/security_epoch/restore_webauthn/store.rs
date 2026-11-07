//! Durable challenge transitions behind the closed trusted-key input. No path,
//! global database, production installer or native authority factory is added.
//! The fixed native producer supplies its actual outside-restore connection and
//! fences every complete unit with that connection's real native file owner.
use super::{Assertion, AssertionFacts, Challenge, TrustedKey, verify};
use anyhow::{Context, Result, ensure};
use day2_capabilities::Digest;
use rusqlite::{Connection, Transaction, TransactionBehavior, params};

const MAX_CEREMONY_SECONDS: i64 = 300;

mod signing;
pub(super) use signing::{check_may_sign, mark_may_sign, prepare_signing, record_publication};

/// The one schema for the independently owned instance authentication store.
/// Only the fixture installs it today. Existing-store admission derives its
/// complete expected catalog from these same declarations, without installing
/// or repairing anything. It is never installed in a restored app database.
const DDL: &str = "
    CREATE TABLE main.restore_passkey_keys (
        credential BLOB PRIMARY KEY,
        binding TEXT NOT NULL CHECK(length(binding)=71),
        version INTEGER NOT NULL CHECK(version>0),
        counter INTEGER NOT NULL CHECK(counter BETWEEN 0 AND 4294967295),
        enabled INTEGER NOT NULL CHECK(enabled IN (0,1))
    ) STRICT;
    CREATE TABLE main.restore_passkey_challenges (
        id TEXT PRIMARY KEY CHECK(length(id)=71),
        request TEXT NOT NULL CHECK(length(request)=71),
        binding TEXT NOT NULL CHECK(length(binding)=71),
        nonce BLOB NOT NULL CHECK(length(nonce)=32),
        key_version INTEGER NOT NULL CHECK(key_version>0),
        counter INTEGER NOT NULL CHECK(counter BETWEEN 0 AND 4294967295),
        created_at INTEGER NOT NULL CHECK(created_at>=0),
        expires_at INTEGER NOT NULL CHECK(expires_at>created_at AND expires_at-created_at<=300),
        state TEXT NOT NULL CHECK(state IN ('pending','claimed','verified'))
    ) STRICT;
    CREATE TABLE main.restore_approval_issuance (
        grant_id TEXT PRIMARY KEY CHECK(length(grant_id)=71),
        challenge_id TEXT NOT NULL CHECK(length(challenge_id)=71),
        statement TEXT NOT NULL CHECK(length(statement)<=16384),
        statement_digest TEXT NOT NULL CHECK(length(statement_digest)=71),
        key_version INTEGER NOT NULL CHECK(key_version>0),
        counter INTEGER NOT NULL CHECK(counter BETWEEN 0 AND 4294967295),
        approved_at INTEGER NOT NULL CHECK(approved_at>=0),
        expires_at INTEGER NOT NULL CHECK(expires_at-approved_at=3600),
        state TEXT NOT NULL CHECK(state IN ('prepared','may_sign','published')),
        signed_record TEXT,
        CHECK((state='published' AND signed_record IS NOT NULL) OR
              (state!='published' AND signed_record IS NULL))
    ) STRICT;
    CREATE TABLE main.restore_approval_execution_attempts (
        grant_id TEXT PRIMARY KEY CHECK(length(grant_id)=71),
        signed_digest TEXT NOT NULL CHECK(length(signed_digest)=71),
        operation TEXT NOT NULL CHECK(length(operation)=71),
        challenge_id TEXT NOT NULL CHECK(length(challenge_id)=71),
        binding TEXT NOT NULL CHECK(length(binding)=71),
        key_version INTEGER NOT NULL CHECK(key_version>0),
        counter INTEGER NOT NULL CHECK(counter BETWEEN 0 AND 4294967295),
        completion_digest TEXT NOT NULL CHECK(length(completion_digest)=71)
    ) STRICT;";

/// SQL shape admission only. The caller must retain its actual native file
/// owner and bracket this complete read unit with the same original's checks.
/// Success supplies no placement, durability, key trust or approval authority.
pub(in crate::security_epoch) fn require_existing_schema(db: &Connection) -> Result<()> {
    ensure!(
        db.is_autocommit(),
        "restore_passkey_schema_transaction_open"
    );
    let mut expected = Vec::new();
    for statement in DDL.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        let declaration = statement
            .strip_prefix("CREATE TABLE main.")
            .context("restore_passkey_schema_declaration")?;
        let (name, _) = declaration
            .split_once('(')
            .context("restore_passkey_schema_declaration")?;
        let name = name.trim();
        expected.push((
            "table".to_owned(),
            name.to_owned(),
            name.to_owned(),
            Some(format!("CREATE TABLE {declaration}")),
        ));
        // Each canonical table has one non-integer PRIMARY KEY. SQLite
        // creates exactly this internal index; no other index is admitted.
        expected.push((
            "index".to_owned(),
            format!("sqlite_autoindex_{name}_1"),
            name.to_owned(),
            None,
        ));
    }
    expected.sort();

    let tx = db.unchecked_transaction()?;
    let actual = {
        // One row beyond the complete expected catalog makes extra objects
        // refuse. Bounded projections cannot turn a longer name/SQL into an
        // accepted canonical value: every expected value is shorter than its
        // projection bound and equality is complete.
        let mut query = tx.prepare(
            "SELECT substr(type,1,16),substr(name,1,129),substr(tbl_name,1,129),
                    rootpage,substr(sql,1,4097)
             FROM main.sqlite_schema ORDER BY type,name LIMIT ?1",
        )?;
        let rows = query.query_map([i64::try_from(expected.len() + 1)?], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;
        let mut actual = Vec::new();
        for row in rows {
            let (kind, name, table, page, sql) = row?;
            ensure!(page > 0, "restore_passkey_schema_root_missing");
            actual.push((kind, name, table, sql));
        }
        actual
    };
    ensure!(actual == expected, "restore_passkey_schema_changed");
    tx.commit()?;
    Ok(())
}

pub(super) fn challenge_id(challenge: &Challenge) -> Result<Digest> {
    Digest::of(&("day2-restore-passkey-challenge-id-v1", challenge.encoded()?))
}

fn current(tx: &Transaction<'_>, key: &TrustedKey) -> Result<(i64, u32)> {
    key.check_sqlite(tx)?;
    key.validate()?;
    // PRAGMAs refuse non-durable storage; they do not attest its actual FD,
    // filesystem/profile or outside-restore placement. The native owner must.
    let mode: String = tx.query_row("PRAGMA main.journal_mode", [], |row| row.get(0))?;
    let synchronous: i64 = tx.query_row("PRAGMA main.synchronous", [], |row| row.get(0))?;
    ensure!(
        matches!(mode.as_str(), "delete" | "truncate" | "persist" | "wal")
            && matches!(synchronous, 2 | 3),
        "restore_passkey_store_not_durable"
    );
    let (binding, version, counter, enabled): (String, i64, u32, i64) = tx.query_row(
        "SELECT binding,version,counter,enabled FROM main.restore_passkey_keys
         WHERE credential=?1 AND length(binding)=71",
        [&key.record.credential_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    ensure!(
        enabled == 1 && version > 0 && binding == key.binding()?.as_str(),
        "restore_passkey_registry_changed"
    );
    Ok((version, counter))
}

/// Create-only pending challenge DATA in the caller's actual transaction. Its
/// commit and current-owner postchecks are required before showing a challenge.
/// No upsert, reuse, resurrection or completion from historical rows exists.
pub(super) fn issue(
    tx: &Transaction<'_>,
    key: &TrustedKey,
    challenge: &Challenge,
    created_at: i64,
    expires_at: i64,
) -> Result<Digest> {
    let result = (|| -> Result<Digest> {
        ensure!(
            challenge.enrollment == key.binding()?,
            "restore_passkey_challenge_binding_changed"
        );
        ensure!(
            created_at >= 0
                && expires_at
                    .checked_sub(created_at)
                    .is_some_and(|span| (1..=MAX_CEREMONY_SECONDS).contains(&span)),
            "restore_passkey_ceremony_lifetime"
        );
        let (version, counter) = current(tx, key)?;
        let id = challenge_id(challenge)?;
        ensure!(
            tx.execute(
                "INSERT INTO main.restore_passkey_challenges
             (id,request,binding,nonce,key_version,counter,created_at,expires_at,state)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'pending')",
                params![
                    id.as_str(),
                    challenge.request.as_str(),
                    challenge.enrollment.as_str(),
                    challenge.nonce.as_slice(),
                    version,
                    counter,
                    created_at,
                    expires_at
                ],
            )? == 1,
            "restore_passkey_challenge_not_created"
        );
        Ok(id)
    })();
    result.context("restore_passkey_challenge_issue_refused")
}

struct Claimed {
    challenge: Challenge,
    key_version: i64,
    counter: u32,
    created_at: i64,
    expires_at: i64,
}

/// Claim before signature verification. This first transaction commits a
/// tombstone even when later verification fails or the process dies. A replay
/// cannot reconstruct this in-memory continuation from the persisted row.
fn claim(db: &mut Connection, key: &TrustedKey, id: &Digest, expected: &Digest) -> Result<Claimed> {
    key.check_sqlite(db)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (version, counter) = current(&tx, key)?;
    let (request, binding, nonce, key_version, saved_counter, created_at, expires_at): (
        String,
        String,
        Vec<u8>,
        i64,
        u32,
        i64,
        i64,
    ) = tx.query_row(
        "SELECT request,binding,nonce,key_version,counter,created_at,expires_at
         FROM main.restore_passkey_challenges WHERE id=?1 AND state='pending'
         AND length(request)=71 AND length(binding)=71 AND length(nonce)=32",
        [id.as_str()],
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
    )?;
    let challenge = Challenge {
        request: request.try_into()?,
        nonce: nonce
            .try_into()
            .map_err(|_| anyhow::anyhow!("restore_passkey_nonce_shape"))?,
        enrollment: binding.try_into()?,
    };
    ensure!(
        challenge.request == *expected
            && challenge.enrollment == key.binding()?
            && challenge_id(&challenge)? == *id
            && key_version == version
            && saved_counter == counter,
        "restore_passkey_pending_binding_changed"
    );
    ensure!(
        tx.execute(
            "UPDATE main.restore_passkey_challenges SET state='claimed' WHERE id=?1 AND state='pending'",
            [id.as_str()]
        )? == 1,
        "restore_passkey_challenge_already_used"
    );
    key.check_sqlite(&tx)?;
    let committed = tx.commit();
    let checked = key.check_sqlite(db);
    committed?;
    checked?;
    Ok(Claimed {
        challenge,
        key_version,
        counter,
        created_at,
        expires_at,
    })
}

/// The only public completion path owns both real commits. The supplied time is
/// observation DATA: the future native producer must use its actual qualified
/// clock and preserve the same original across these steps and final signing.
/// A successful return is still DATA, never VerifiedApproval or a serving owner.
pub(super) fn complete(
    db: &mut Connection,
    key: &TrustedKey,
    id: &Digest,
    expected_request: &Digest,
    at: i64,
    assertion: &Assertion,
) -> Result<AssertionFacts> {
    let result = (|| -> Result<AssertionFacts> {
        let claimed = claim(db, key, id, expected_request)?;
        checkpoint(Cut::AfterClaim)?;
        ensure!(
            claimed.created_at >= 0
                && claimed.created_at <= at
                && at < claimed.expires_at
                && claimed
                    .expires_at
                    .checked_sub(claimed.created_at)
                    .is_some_and(|span| (1..=MAX_CEREMONY_SECONDS).contains(&span)),
            "restore_passkey_ceremony_expired_or_clock_rewound"
        );
        let facts = verify(
            key,
            &claimed.challenge,
            expected_request,
            claimed.counter,
            assertion,
        )?;
        checkpoint(Cut::AfterSignature)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (version, counter) = current(&tx, key)?;
        ensure!(
            version == claimed.key_version && counter == claimed.counter,
            "restore_passkey_counter_snapshot_changed"
        );
        let next = version
            .checked_add(1)
            .context("restore_passkey_version_exhausted")?;
        ensure!(
            tx.execute(
                "UPDATE main.restore_passkey_keys SET version=?1,counter=?2
             WHERE credential=?3 AND binding=?4 AND enabled=1 AND version=?5 AND counter=?6",
                params![
                    next,
                    facts.counter,
                    &key.record.credential_id,
                    key.binding()?.as_str(),
                    version,
                    counter
                ],
            )? == 1,
            "restore_passkey_counter_write_conflict"
        );
        checkpoint(Cut::AfterCounter)?;
        ensure!(tx.execute(
            "UPDATE main.restore_passkey_challenges SET state='verified'
             WHERE id=?1 AND state='claimed' AND key_version=?2 AND counter=?3 AND binding=?4 AND request=?5
             AND nonce=?6 AND created_at=?7 AND expires_at=?8",
            params![id.as_str(),version,counter,claimed.challenge.enrollment.as_str(),expected_request.as_str(),claimed.challenge.nonce.as_slice(),claimed.created_at,claimed.expires_at],
        )?==1, "restore_passkey_completion_conflict");
        checkpoint(Cut::BeforeCommit)?;
        key.check_sqlite(&tx)?;
        let committed = tx.commit();
        let checked = key.check_sqlite(db);
        committed?;
        checked?;
        checkpoint(Cut::AfterCommit)?;
        Ok(facts)
    })();
    result.context("restore_passkey_completion_refused")
}

/// Snapshot DATA for the fixed execution completion. The native caller must
/// own this entire SQL unit and retain the returned version/counter commitment
/// only after its actual commit and file/native postchecks have succeeded.
pub(super) fn verified_snapshot(
    tx: &Transaction<'_>,
    key: &TrustedKey<'_>,
    challenge: &Challenge,
    completed_counter: u32,
) -> Result<(i64, Digest)> {
    let (version, counter) = current(tx, key)?;
    let id = challenge_id(challenge)?;
    let (saved_version, saved_counter, created_at, expires_at): (i64, u32, i64, i64) = tx
        .query_row(
            "SELECT key_version,counter,created_at,expires_at FROM main.restore_passkey_challenges
         WHERE id=?1 AND state='verified' AND request=?2 AND binding=?3 AND nonce=?4",
            params![
                id.as_str(),
                challenge.request.as_str(),
                key.binding()?.as_str(),
                challenge.nonce.as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    ensure!(
        challenge.enrollment == key.binding()?
            && counter == completed_counter
            && saved_version.checked_add(1) == Some(version)
            && created_at >= 0
            && expires_at
                .checked_sub(created_at)
                .is_some_and(|span| (1..=MAX_CEREMONY_SECONDS).contains(&span)),
        "restore_executor_completion_changed"
    );
    let snapshot = Digest::of(&(
        "day2-restore-executor-completion-v1",
        &id,
        &challenge.request,
        &challenge.enrollment,
        &challenge.nonce,
        saved_version,
        saved_counter,
        created_at,
        expires_at,
        version,
        counter,
    ))?;
    key.check_sqlite(tx)?;
    Ok((version, snapshot))
}

fn execution_attempt_binding(
    tx: &Transaction<'_>,
    key: &TrustedKey<'_>,
    challenge: &Challenge,
    signed: &crate::security_epoch::restore_approval::signed::SignedApprovalRecord,
    operation: &Digest,
    completed: (u32, i64, &Digest),
) -> Result<(Digest, Digest)> {
    ensure!(
        challenge.request == super::execution_request(signed, operation)?,
        "restore_execution_attempt_request_changed"
    );
    let current = verified_snapshot(tx, key, challenge, completed.0)?;
    ensure!(
        current.0 == completed.1 && &current.1 == completed.2,
        "restore_execution_attempt_completion_changed"
    );
    Ok((
        challenge_id(challenge)?,
        Digest::of(&("day2-restore-execution-attempt-v1", signed))?,
    ))
}

/// Create-only, grant-keyed May DATA in the caller's actual authentication
/// transaction. The native caller must commit and complete ALL same-owner
/// postchecks before any reservation send. A row cannot reconstruct that owner.
/// New challenges, logins and operations never create a second use of a grant.
pub(super) fn mark_may_execute(
    tx: &Transaction<'_>,
    key: &TrustedKey<'_>,
    challenge: &Challenge,
    signed: &crate::security_epoch::restore_approval::signed::SignedApprovalRecord,
    operation: &Digest,
    completed: (u32, i64, &Digest),
) -> Result<()> {
    let (id, signed_digest) =
        execution_attempt_binding(tx, key, challenge, signed, operation, completed)?;
    let inserted = tx.execute(
        "INSERT INTO main.restore_approval_execution_attempts
         (grant_id,signed_digest,operation,challenge_id,binding,key_version,counter,completion_digest)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![signed.statement.request.grant_id.as_str(),signed_digest.as_str(),
            operation.as_str(),id.as_str(),key.binding()?.as_str(),completed.1,
            completed.0,completed.2.as_str()],
    );
    let checked = key.check_sqlite(tx);
    let inserted = inserted?;
    checked?;
    ensure!(inserted == 1, "restore_execution_attempt_not_created");
    Ok(())
}

/// Exact historical marker equality, not recovery or permission. There is no
/// deletion, reset, retry adoption, clock renewal or row-to-native factory.
pub(super) fn check_may_execute(
    tx: &Transaction<'_>,
    key: &TrustedKey<'_>,
    challenge: &Challenge,
    signed: &crate::security_epoch::restore_approval::signed::SignedApprovalRecord,
    operation: &Digest,
    completed: (u32, i64, &Digest),
) -> Result<()> {
    let (id, signed_digest) =
        execution_attempt_binding(tx, key, challenge, signed, operation, completed)?;
    let present = tx.query_row(
        "SELECT count(*) FROM main.restore_approval_execution_attempts
         WHERE grant_id=?1 AND signed_digest=?2 AND operation=?3 AND challenge_id=?4
           AND binding=?5 AND key_version=?6 AND counter=?7 AND completion_digest=?8",
        params![
            signed.statement.request.grant_id.as_str(),
            signed_digest.as_str(),
            operation.as_str(),
            id.as_str(),
            key.binding()?.as_str(),
            completed.1,
            completed.0,
            completed.2.as_str()
        ],
        |row| row.get::<_, i64>(0),
    );
    let checked = key.check_sqlite(tx);
    let present = present?;
    checked?;
    ensure!(present == 1, "restore_execution_attempt_changed");
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Cut {
    AfterClaim,
    AfterSignature,
    AfterCounter,
    BeforeCommit,
    AfterCommit,
}

fn checkpoint(cut: Cut) -> Result<()> {
    #[cfg(test)]
    return tests::checkpoint(cut);
    #[cfg(not(test))]
    {
        let _ = cut;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
