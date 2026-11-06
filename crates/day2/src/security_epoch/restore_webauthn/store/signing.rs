//! Fixed one-attempt signing journal under the actual authentication SQL unit.
//! Rows are DATA, never a recovered UV continuation or signing/native owner.
use super::{TrustedKey, current};
use crate::security_epoch::restore_approval::signed::{ApprovalStatement, SignedApprovalRecord};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use rusqlite::{Transaction, params};

fn statement_data(statement: &ApprovalStatement) -> Result<(String, Digest)> {
    statement.signature_input_data()?;
    let bytes = serde_json::to_string(statement)?;
    ensure!(bytes.len() <= 16_384, "restore_issuance_statement_bound");
    Ok((
        bytes,
        Digest::of(&("day2-restore-approval-issuance-v1", statement))?,
    ))
}

/// Create only after the exact challenge's known verification/counter commit.
/// The caller must still retain its actual completed owner and qualified time;
/// this function cannot construct either from the rows it inspects.
pub(in crate::security_epoch::restore_webauthn) fn prepare_signing(
    tx: &Transaction<'_>,
    key: &TrustedKey<'_>,
    challenge: &Digest,
    statement: &ApprovalStatement,
    verified_counter: u32,
) -> Result<()> {
    let (version, counter) = current(tx, key)?;
    ensure!(
        counter == verified_counter,
        "restore_issuance_counter_changed"
    );
    let (body, digest) = statement_data(statement)?;
    ensure!(tx.execute(
        "INSERT INTO main.restore_approval_issuance
         (grant_id,challenge_id,statement,statement_digest,key_version,counter,approved_at,expires_at,state,signed_record)
         SELECT ?1,c.id,?2,?3,?9,?10,?4,?5,'prepared',NULL
         FROM main.restore_passkey_challenges c
         WHERE c.id=?6 AND c.state='verified' AND c.request=?7
           AND c.binding=?8 AND c.key_version+1=?9",
        params![statement.request.grant_id.as_str(),body,digest.as_str(),
            statement.request.approved_at,statement.request.expires_at,challenge.as_str(),
            statement.request.intent().commitment()?.as_str(),key.binding()?.as_str(),version,verified_counter],
    )?==1,"restore_issuance_verified_challenge_required");
    key.check_sqlite(tx)
}

/// This known commit precedes the FIRST signing RPC. No replay/reset or
/// historical-row continuation exists after a process loss or ambiguous send.
pub(in crate::security_epoch::restore_webauthn) fn mark_may_sign(
    tx: &Transaction<'_>,
    key: &TrustedKey<'_>,
    challenge: &Digest,
    statement: &ApprovalStatement,
) -> Result<()> {
    check_journal(tx, key, challenge, statement, "prepared")?;
    let (body, digest) = statement_data(statement)?;
    ensure!(
        tx.execute(
            "UPDATE main.restore_approval_issuance SET state='may_sign'
         WHERE grant_id=?1 AND challenge_id=?2 AND statement=?3 AND statement_digest=?4
           AND approved_at=?5 AND expires_at=?6 AND state='prepared' AND signed_record IS NULL",
            params![
                statement.request.grant_id.as_str(),
                challenge.as_str(),
                body,
                digest.as_str(),
                statement.request.approved_at,
                statement.request.expires_at
            ],
        )? == 1,
        "restore_issuance_sign_attempt_spent_or_changed"
    );
    key.check_sqlite(tx)
}

/// Bookkeeping follows the actual external create-only publication/readback.
/// Neither this row nor an error after its commit proves delivery or rollback.
pub(in crate::security_epoch::restore_webauthn) fn record_publication(
    tx: &Transaction<'_>,
    key: &TrustedKey<'_>,
    challenge: &Digest,
    record: &SignedApprovalRecord,
) -> Result<()> {
    let statement = &record.statement;
    check_journal(tx, key, challenge, statement, "may_sign")?;
    let (body, digest) = statement_data(statement)?;
    let signed = String::from_utf8(record.encode()?)?;
    ensure!(
        tx.execute(
            "UPDATE main.restore_approval_issuance SET state='published',signed_record=?1
         WHERE grant_id=?2 AND challenge_id=?3 AND statement=?4 AND statement_digest=?5
           AND approved_at=?6 AND expires_at=?7 AND state='may_sign' AND signed_record IS NULL",
            params![
                signed,
                statement.request.grant_id.as_str(),
                challenge.as_str(),
                body,
                digest.as_str(),
                statement.request.approved_at,
                statement.request.expires_at
            ],
        )? == 1,
        "restore_issuance_publication_spent_or_changed"
    );
    key.check_sqlite(tx)
}

fn check_journal(
    tx: &Transaction<'_>,
    key: &TrustedKey<'_>,
    challenge: &Digest,
    statement: &ApprovalStatement,
    state: &str,
) -> Result<()> {
    let (version, counter) = current(tx, key)?;
    let (body, digest) = statement_data(statement)?;
    ensure!(
        tx.query_row(
            "SELECT count(*) FROM main.restore_approval_issuance
         WHERE grant_id=?1 AND challenge_id=?2 AND statement=?3 AND statement_digest=?4
           AND approved_at=?5 AND expires_at=?6 AND state=?7 AND signed_record IS NULL
           AND key_version=?8 AND counter=?9",
            params![
                statement.request.grant_id.as_str(),
                challenge.as_str(),
                body,
                digest.as_str(),
                statement.request.approved_at,
                statement.request.expires_at,
                state,
                version,
                counter
            ],
            |row| row.get::<_, i64>(0),
        )? == 1,
        "restore_issuance_journal_or_key_changed"
    );
    key.check_sqlite(tx)
}

pub(in crate::security_epoch::restore_webauthn) fn check_may_sign(
    tx: &Transaction<'_>,
    key: &TrustedKey<'_>,
    challenge: &Digest,
    statement: &ApprovalStatement,
) -> Result<()> {
    check_journal(tx, key, challenge, statement, "may_sign")
}

#[cfg(test)]
mod tests;
