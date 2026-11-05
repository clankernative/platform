//! Durable challenge transitions behind the closed trusted-key input. No path,
//! global database, production installer or native authority factory is added.
//! A future native owner must supply its actual outside-restore SQL connection.
use super::{Assertion, AssertionFacts, Challenge, TrustedKey, verify};
use anyhow::{Context, Result, ensure};
use day2_capabilities::Digest;
use rusqlite::{Connection, Transaction, TransactionBehavior, params};

const MAX_CEREMONY_SECONDS: i64 = 300;

/// Schema for the independently owned instance authentication store. Only the
/// fixture installs it today. It is never installed in a restored app database.
const DDL: &str = "
    CREATE TABLE restore_passkey_keys (
        credential BLOB PRIMARY KEY,
        binding TEXT NOT NULL CHECK(length(binding)=71),
        version INTEGER NOT NULL CHECK(version>0),
        counter INTEGER NOT NULL CHECK(counter BETWEEN 0 AND 4294967295),
        enabled INTEGER NOT NULL CHECK(enabled IN (0,1))
    ) STRICT;
    CREATE TABLE restore_passkey_challenges (
        id TEXT PRIMARY KEY CHECK(length(id)=71),
        request TEXT NOT NULL CHECK(length(request)=71),
        binding TEXT NOT NULL CHECK(length(binding)=71),
        nonce BLOB NOT NULL CHECK(length(nonce)=32),
        key_version INTEGER NOT NULL CHECK(key_version>0),
        counter INTEGER NOT NULL CHECK(counter BETWEEN 0 AND 4294967295),
        created_at INTEGER NOT NULL CHECK(created_at>=0),
        expires_at INTEGER NOT NULL CHECK(expires_at>created_at AND expires_at-created_at<=300),
        state TEXT NOT NULL CHECK(state IN ('pending','claimed','verified'))
    ) STRICT;";

fn challenge_id(challenge: &Challenge) -> Result<Digest> {
    Digest::of(&("day2-restore-passkey-challenge-id-v1", challenge.encoded()?))
}

fn current(tx: &Transaction<'_>, key: &TrustedKey) -> Result<(i64, u32)> {
    key.validate()?;
    // PRAGMAs refuse non-durable storage; they do not attest its actual FD,
    // filesystem/profile or outside-restore placement. The native owner must.
    let mode: String = tx.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let synchronous: i64 = tx.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    ensure!(
        matches!(mode.as_str(), "delete" | "truncate" | "persist" | "wal")
            && matches!(synchronous, 2 | 3),
        "restore_passkey_store_not_durable"
    );
    let (binding, version, counter, enabled): (String, i64, u32, i64) = tx.query_row(
        "SELECT binding,version,counter,enabled FROM restore_passkey_keys
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
                "INSERT INTO restore_passkey_challenges
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
    result.map_err(|_| anyhow::anyhow!("restore_passkey_challenge_issue_refused"))
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
         FROM restore_passkey_challenges WHERE id=?1 AND state='pending'
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
            "UPDATE restore_passkey_challenges SET state='claimed' WHERE id=?1 AND state='pending'",
            [id.as_str()]
        )? == 1,
        "restore_passkey_challenge_already_used"
    );
    tx.commit()?;
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
                "UPDATE restore_passkey_keys SET version=?1,counter=?2
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
            "UPDATE restore_passkey_challenges SET state='verified'
             WHERE id=?1 AND state='claimed' AND key_version=?2 AND counter=?3 AND binding=?4 AND request=?5
             AND nonce=?6 AND created_at=?7 AND expires_at=?8",
            params![id.as_str(),version,counter,claimed.challenge.enrollment.as_str(),expected_request.as_str(),claimed.challenge.nonce.as_slice(),claimed.created_at,claimed.expires_at],
        )?==1, "restore_passkey_completion_conflict");
        checkpoint(Cut::BeforeCommit)?;
        tx.commit()?;
        checkpoint(Cut::AfterCommit)?;
        Ok(facts)
    })();
    result.map_err(|_| anyhow::anyhow!("restore_passkey_completion_refused"))
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
