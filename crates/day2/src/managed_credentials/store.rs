//! Private SQLite transitions for managed lineages and human delivery.
//! Staging accepts the caller's existing app transaction. A pending result has
//! no secret or permit. The caller's coordinator owns the product commit.

use super::crypto::{
    KeyLease, MaterialIdentity, PreparedMaterial, decrypt_for_human, prepare_managed,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    credentials::{ManagementSnapshot, Namespace},
    oauth::GrantCeiling,
};
use getrandom::fill;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

pub(crate) fn install_schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS day2_credential_schema_version (
            version INTEGER PRIMARY KEY
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_lineages (
            id TEXT PRIMARY KEY,
            namespace TEXT NOT NULL,
            namespace_json TEXT NOT NULL,
            family TEXT NOT NULL,
            family_contract TEXT NOT NULL,
            principal TEXT NOT NULL,
            creator TEXT NOT NULL,
            label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 128),
            recipient TEXT NOT NULL,
            session TEXT NOT NULL,
            grant_json TEXT NOT NULL,
            grant_digest TEXT NOT NULL,
            grant_valid_until INTEGER NOT NULL,
            security_epoch INTEGER NOT NULL CHECK(security_epoch > 0),
            state TEXT NOT NULL CHECK(state IN ('active', 'revoked')),
            head TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision > 0)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_versions (
            id TEXT PRIMARY KEY,
            lineage TEXT NOT NULL REFERENCES day2_credential_lineages(id),
            predecessor TEXT UNIQUE REFERENCES day2_credential_versions(id),
            selector TEXT NOT NULL UNIQUE,
            verifier BLOB NOT NULL CHECK(length(verifier) = 32),
            verifier_key_version TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
            security_epoch INTEGER NOT NULL CHECK(security_epoch > 0),
            grant_digest TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('active', 'superseded', 'revoked'))
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_material (
            version TEXT PRIMARY KEY REFERENCES day2_credential_versions(id),
            identity_json TEXT NOT NULL,
            material_revision INTEGER NOT NULL CHECK(material_revision > 0),
            envelope_revision INTEGER NOT NULL CHECK(envelope_revision > 0),
            encryption_key_version TEXT NOT NULL,
            nonce BLOB NOT NULL CHECK(length(nonce) = 12),
            ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 32 AND 512)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_deliveries (
            version TEXT PRIMARY KEY REFERENCES day2_credential_versions(id),
            recipient TEXT NOT NULL,
            session TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('available', 'closed')),
            closed_reason TEXT NOT NULL DEFAULT ''
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_receipts (
            namespace TEXT NOT NULL,
            invocation TEXT NOT NULL,
            instruction_slot INTEGER NOT NULL CHECK(instruction_slot >= 0),
            family_contract TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('issue', 'rotate', 'revoke')),
            lineage TEXT NOT NULL REFERENCES day2_credential_lineages(id),
            version TEXT REFERENCES day2_credential_versions(id),
            PRIMARY KEY(namespace, invocation, instruction_slot)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_reveals (
            attempt TEXT PRIMARY KEY,
            version TEXT NOT NULL REFERENCES day2_credential_versions(id),
            recipient TEXT NOT NULL,
            session TEXT NOT NULL,
            authorized_at INTEGER NOT NULL
        ) STRICT;
        CREATE INDEX IF NOT EXISTS day2_credential_visible_creator
            ON day2_credential_lineages(namespace, family, creator, id);
        CREATE INDEX IF NOT EXISTS day2_credential_visible_principal
            ON day2_credential_lineages(namespace, family, principal, id);",
    )?;
    let mut statement = db.prepare("SELECT version FROM day2_credential_schema_version")?;
    let versions = statement
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        versions.is_empty() || versions == [1],
        "unsupported credential schema version"
    );
    if versions.is_empty() {
        db.execute("INSERT INTO day2_credential_schema_version VALUES (1)", [])?;
    }
    Ok(())
}

/// All fields are immutable accepted-invocation evidence supplied by the host.
/// The host must establish direct interactive authorization before preparation.
pub(crate) struct IssueIntent {
    pub namespace: Namespace,
    pub family: String,
    pub family_contract: Digest,
    pub invocation: String,
    pub instruction_slot: u32,
    pub principal: String,
    pub creator: String,
    pub recipient: String,
    pub session: String,
    pub label: String,
    pub ceiling: GrantCeiling,
    pub issued_at: i64,
    pub expires_at: i64,
    pub grant_valid_until: i64,
    pub reveal_until: i64,
    pub security_epoch: u64,
}

pub(crate) struct PreparedIssue {
    intent: IssueIntent,
    lineage: String,
    version: String,
    material: PreparedMaterial,
    request_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PublicReceipt {
    pub lineage: String,
    pub version: Option<String>,
}

/// This value remains pending until the containing product transaction commits.
pub(crate) struct PendingIssue(PublicReceipt);

impl PendingIssue {
    pub fn public_identity(&self) -> &PublicReceipt {
        &self.0
    }
}

pub(crate) fn prepare_issue(lease: &KeyLease, intent: IssueIntent) -> Result<PreparedIssue> {
    intent.namespace.validate()?;
    intent.ceiling.verify()?;
    for id in [
        &intent.family,
        &intent.invocation,
        &intent.principal,
        &intent.creator,
        &intent.recipient,
        &intent.session,
    ] {
        validate_id(id)?;
    }
    ensure!(
        !intent.label.trim().is_empty()
            && intent.label.len() <= 128
            && !intent.label.chars().any(char::is_control),
        "invalid credential label"
    );
    ensure!(
        intent.issued_at < intent.expires_at
            && intent.expires_at <= intent.grant_valid_until
            && intent.issued_at < intent.reveal_until
            && intent.reveal_until <= intent.expires_at
            && intent.security_epoch > 0,
        "invalid credential time or epoch bounds"
    );
    ensure!(
        intent.ceiling.subject == intent.principal,
        "credential principal and grant subject mismatch"
    );
    let lineage = random_id()?;
    let version = random_id()?;
    let identity = MaterialIdentity {
        namespace: intent.namespace.clone(),
        family: intent.family.clone(),
        lineage: lineage.clone(),
        version: version.clone(),
        recipient: intent.recipient.clone(),
        security_epoch: intent.security_epoch,
        material_revision: 1,
    };
    let material = prepare_managed(lease, identity)?;
    let request_digest = Digest::of(&(
        "credential-issue-intent-v1",
        (
            &intent.namespace,
            &intent.family,
            &intent.family_contract,
            &intent.invocation,
            intent.instruction_slot,
            &intent.principal,
            &intent.creator,
            &intent.recipient,
        ),
        (
            &intent.session,
            &intent.label,
            &intent.ceiling.digest,
            intent.issued_at,
            intent.expires_at,
            intent.grant_valid_until,
            intent.reveal_until,
            intent.security_epoch,
        ),
    ))?;
    Ok(PreparedIssue {
        intent,
        lineage,
        version,
        material,
        request_digest,
    })
}

/// Stage alongside ordinary product rows. Same accepted invocation and intent
/// returns the original public identity; changed intent is a hard conflict.
pub(crate) fn stage_issue(tx: &Transaction<'_>, prepared: PreparedIssue) -> Result<PendingIssue> {
    let issue = &prepared.intent;
    let namespace = namespace_key(&issue.namespace)?;
    ensure!(
        prepared.material.identity.namespace == issue.namespace
            && prepared.material.identity.family == issue.family,
        "credential material namespace or family mismatch"
    );
    if let Some(ReceiptRow {
        contract,
        digest,
        action,
        lineage,
        version,
    }) = receipt(tx, &namespace, &issue.invocation, issue.instruction_slot)?
    {
        ensure!(
            contract == issue.family_contract.as_str()
                && digest == prepared.request_digest.as_str()
                && action == "issue",
            "credential issuance identity reused with changed intent"
        );
        return Ok(PendingIssue(PublicReceipt { lineage, version }));
    }
    let grant_json = serde_json::to_string(&issue.ceiling)?;
    tx.execute(
        "INSERT INTO day2_credential_lineages
         (id, namespace, namespace_json, family, family_contract, principal, creator, label, recipient, session,
          grant_json, grant_digest, grant_valid_until, security_epoch, state, head, revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 'active', ?15, 1)",
        params![
            prepared.lineage,
            namespace,
            serde_json::to_string(&issue.namespace)?,
            issue.family,
            issue.family_contract.as_str(),
            issue.principal,
            issue.creator,
            issue.label,
            issue.recipient,
            issue.session,
            grant_json,
            issue.ceiling.digest.as_str(),
            issue.grant_valid_until,
            i64::try_from(issue.security_epoch)?,
            prepared.version
        ],
    )?;
    insert_version(
        tx,
        VersionWrite {
            lineage: &prepared.lineage,
            version: &prepared.version,
            predecessor: None,
            material: &prepared.material,
            issued_at: issue.issued_at,
            expires_at: issue.expires_at,
            security_epoch: issue.security_epoch,
            grant_digest: issue.ceiling.digest.as_str(),
            recipient: &issue.recipient,
            session: &issue.session,
            reveal_until: issue.reveal_until,
        },
    )?;
    tx.execute(
        "INSERT INTO day2_credential_receipts
         (namespace, invocation, instruction_slot, family_contract, request_digest, action, lineage, version)
         VALUES (?1, ?2, ?3, ?4, ?5, 'issue', ?6, ?7)",
        params![namespace, issue.invocation, issue.instruction_slot, issue.family_contract.as_str(),
            prepared.request_digest.as_str(), prepared.lineage, prepared.version],
    )?;
    Ok(PendingIssue(PublicReceipt {
        lineage: prepared.lineage,
        version: Some(prepared.version),
    }))
}

struct VersionWrite<'a> {
    lineage: &'a str,
    version: &'a str,
    predecessor: Option<&'a str>,
    material: &'a PreparedMaterial,
    issued_at: i64,
    expires_at: i64,
    security_epoch: u64,
    grant_digest: &'a str,
    recipient: &'a str,
    session: &'a str,
    reveal_until: i64,
}

fn insert_version(tx: &Transaction<'_>, write: VersionWrite<'_>) -> Result<()> {
    let VersionWrite {
        lineage,
        version,
        predecessor,
        material,
        issued_at,
        expires_at,
        security_epoch,
        grant_digest,
        recipient,
        session,
        reveal_until,
    } = write;
    ensure!(
        material.identity.lineage == lineage
            && material.identity.version == version
            && material.identity.security_epoch == security_epoch
            && material.identity.recipient == recipient,
        "credential material binding mismatch"
    );
    tx.execute(
        "INSERT INTO day2_credential_versions
         (id, lineage, predecessor, selector, verifier, verifier_key_version, issued_at,
          expires_at, security_epoch, grant_digest, state)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'active')",
        params![
            version,
            lineage,
            predecessor,
            material.selector,
            material.verifier.as_slice(),
            material.verifier_version,
            issued_at,
            expires_at,
            i64::try_from(security_epoch)?,
            grant_digest
        ],
    )?;
    tx.execute(
        "INSERT INTO day2_credential_material
         (version, identity_json, material_revision, envelope_revision, encryption_key_version, nonce, ciphertext)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![version, serde_json::to_string(&material.identity)?,
            i64::try_from(material.identity.material_revision)?,
            i64::try_from(material.envelope_revision)?,
            material.encryption_version, material.nonce.as_slice(), material.ciphertext],
    )?;
    tx.execute(
        "INSERT INTO day2_credential_deliveries (version, recipient, session, expires_at, state)
         VALUES (?1, ?2, ?3, ?4, 'available')",
        params![version, recipient, session, reveal_until],
    )?;
    Ok(())
}

pub(crate) enum RotationResult {
    Rotated(PendingIssue),
    Conflict,
}

pub(crate) struct RotationIntent<'a> {
    pub invocation: &'a str,
    pub instruction_slot: u32,
    pub recipient: &'a str,
    pub session: &'a str,
    pub issued_at: i64,
    pub expires_at: i64,
    pub reveal_until: i64,
}

/// The key lease is resolved before SQLite; local material generation runs
/// inside the transaction. Authorization, fresh interaction and current
/// instance policy must be checked by the host before this transition.
pub(crate) fn stage_rotation(
    tx: &Transaction<'_>,
    lease: &KeyLease,
    expected: &ManagementSnapshot,
    intent: RotationIntent<'_>,
) -> Result<RotationResult> {
    let RotationIntent {
        invocation,
        instruction_slot,
        recipient,
        session,
        issued_at,
        expires_at,
        reveal_until,
    } = intent;
    validate_id(invocation)?;
    validate_id(recipient)?;
    validate_id(session)?;
    let namespace = namespace_key(&expected.lineage.namespace)?;
    let (
        family_contract,
        grant_json,
        grant_digest,
        grant_valid_until,
        epoch,
        state,
        head,
        revision,
    ): (String, String, String, i64, i64, String, String, i64) = tx
        .query_row(
            "SELECT family_contract, grant_json, grant_digest,
                grant_valid_until, security_epoch, state, head, revision
         FROM day2_credential_lineages WHERE id = ?1 AND namespace = ?2 AND family = ?3",
            params![
                expected.lineage.id,
                namespace,
                expected.lineage.family.as_str()
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .context("credential lineage is unavailable")?;
    let request_digest = Digest::of(&(
        "credential-rotation-intent-v1",
        &namespace,
        &expected.lineage.id,
        &expected.head.id,
        expected.revision,
        recipient,
        session,
        issued_at,
        expires_at,
        reveal_until,
    ))?;
    if let Some(ReceiptRow {
        contract,
        digest,
        action,
        lineage,
        version,
    }) = receipt(tx, &namespace, invocation, instruction_slot)?
    {
        ensure!(
            contract == family_contract && digest == request_digest.as_str() && action == "rotate",
            "credential rotation identity reused with changed intent"
        );
        return Ok(RotationResult::Rotated(PendingIssue(PublicReceipt {
            lineage,
            version,
        })));
    }
    if state != "active"
        || head != expected.head.id
        || revision != i64::try_from(expected.revision)?
        || expected.head.lineage != expected.lineage
        || issued_at >= grant_valid_until
    {
        return Ok(RotationResult::Conflict);
    }
    ensure!(
        issued_at < expires_at
            && expires_at <= grant_valid_until
            && issued_at < reveal_until
            && reveal_until <= expires_at,
        "invalid rotation time bounds"
    );
    let ceiling: GrantCeiling = serde_json::from_str(&grant_json)?;
    ceiling.verify()?;
    ensure!(
        ceiling.digest.as_str() == grant_digest,
        "stored credential grant mismatch"
    );
    let next = random_id()?;
    let identity = MaterialIdentity {
        namespace: expected.lineage.namespace.clone(),
        family: expected.lineage.family.as_str().to_owned(),
        lineage: expected.lineage.id.clone(),
        version: next.clone(),
        recipient: recipient.to_owned(),
        security_epoch: u64::try_from(epoch)?,
        material_revision: 1,
    };
    let material = prepare_managed(lease, identity)?;
    let changed = tx.execute(
        "UPDATE day2_credential_lineages SET head = ?1, revision = revision + 1,
         recipient = ?2, session = ?3 WHERE id = ?4 AND state = 'active'
         AND head = ?5 AND revision = ?6",
        params![
            next,
            recipient,
            session,
            expected.lineage.id,
            head,
            revision
        ],
    )?;
    if changed != 1 {
        return Ok(RotationResult::Conflict);
    }
    tx.execute("UPDATE day2_credential_versions SET state = 'superseded' WHERE id = ?1 AND state = 'active'",
        [&head])?;
    tx.execute(
        "UPDATE day2_credential_deliveries SET state = 'closed', closed_reason = 'rotation'
                WHERE version = ?1 AND state = 'available'",
        [&head],
    )?;
    insert_version(
        tx,
        VersionWrite {
            lineage: &expected.lineage.id,
            version: &next,
            predecessor: Some(&head),
            material: &material,
            issued_at,
            expires_at,
            security_epoch: u64::try_from(epoch)?,
            grant_digest: &grant_digest,
            recipient,
            session,
            reveal_until,
        },
    )?;
    tx.execute(
        "INSERT INTO day2_credential_receipts
         (namespace, invocation, instruction_slot, family_contract, request_digest, action, lineage, version)
         VALUES (?1, ?2, ?3, ?4, ?5, 'rotate', ?6, ?7)",
        params![namespace, invocation, instruction_slot, family_contract,
            request_digest.as_str(), expected.lineage.id, next],
    )?;
    Ok(RotationResult::Rotated(PendingIssue(PublicReceipt {
        lineage: expected.lineage.id.clone(),
        version: Some(next),
    })))
}

pub(crate) fn stage_revoke(
    tx: &Transaction<'_>,
    namespace: &Namespace,
    lineage: &str,
) -> Result<bool> {
    validate_id(lineage)?;
    let namespace = namespace_key(namespace)?;
    let changed = tx.execute(
        "UPDATE day2_credential_lineages SET state = 'revoked', revision = revision + 1
         WHERE id = ?1 AND namespace = ?2 AND state = 'active'",
        params![lineage, namespace],
    )?;
    if changed == 1 {
        tx.execute(
            "UPDATE day2_credential_versions SET state = 'revoked' WHERE lineage = ?1",
            [lineage],
        )?;
        tx.execute(
            "UPDATE day2_credential_deliveries SET state = 'closed', closed_reason = 'revoked'
                    WHERE version IN (SELECT id FROM day2_credential_versions WHERE lineage = ?1)
                    AND state = 'available'",
            [lineage],
        )?;
    }
    Ok(changed == 1)
}

pub(crate) struct VerifiedHumanPost {
    pub namespace: Namespace,
    pub version: String,
    pub recipient: String,
    pub session: String,
    pub attempt: String,
    pub now: i64,
    pub security_epoch: u64,
}

/// Process-local, non-clone, non-serializable authorization for this exact
/// response. A historical receipt cannot construct or recover this value.
pub(crate) struct HumanRevealPermit {
    identity: MaterialIdentity,
    envelope_revision: u64,
    encryption_version: String,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl HumanRevealPermit {
    pub fn into_response_body(self, lease: &KeyLease) -> Result<String> {
        decrypt_for_human(
            lease,
            &self.identity,
            &self.identity,
            self.envelope_revision,
            &self.encryption_version,
            self.nonce,
            &self.ciphertext,
        )
    }
}

/// A private security-origin handler supplies a verified current POST. The
/// authorization commit is the cutoff: closure first denies; authorization
/// first may finish its already-authorized response.
pub(crate) fn authorize_reveal(
    db: &mut Connection,
    post: VerifiedHumanPost,
) -> Result<Option<HumanRevealPermit>> {
    for id in [&post.version, &post.recipient, &post.session, &post.attempt] {
        validate_id(id)?;
    }
    let expected_namespace_key = namespace_key(&post.namespace)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    struct RevealRow {
        identity_json: String,
        namespace_json: String,
        family: String,
        lineage: String,
        material_revision: i64,
        envelope_revision: i64,
        encryption_version: String,
        epoch: i64,
        recipient: String,
        session: String,
        expires_at: i64,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    }
    let row: Option<RevealRow> = tx
        .query_row(
            "SELECT m.identity_json, l.namespace_json, l.family, l.id, m.material_revision,
                m.envelope_revision, m.encryption_key_version, l.security_epoch,
                d.recipient, d.session, d.expires_at, m.nonce, m.ciphertext
         FROM day2_credential_deliveries d
         JOIN day2_credential_versions v ON v.id = d.version
         JOIN day2_credential_lineages l ON l.id = v.lineage
         JOIN day2_credential_material m ON m.version = v.id
         WHERE d.version = ?1 AND l.namespace = ?2 AND l.head = v.id
           AND l.state = 'active' AND v.state = 'active' AND d.state = 'available'
           AND v.security_epoch = l.security_epoch AND v.grant_digest = l.grant_digest
           AND d.recipient = l.recipient AND d.session = l.session",
            params![post.version, expected_namespace_key],
            |row| {
                Ok(RevealRow {
                    identity_json: row.get(0)?,
                    namespace_json: row.get(1)?,
                    family: row.get(2)?,
                    lineage: row.get(3)?,
                    material_revision: row.get(4)?,
                    envelope_revision: row.get(5)?,
                    encryption_version: row.get(6)?,
                    epoch: row.get(7)?,
                    recipient: row.get(8)?,
                    session: row.get(9)?,
                    expires_at: row.get(10)?,
                    nonce: row.get(11)?,
                    ciphertext: row.get(12)?,
                })
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    if u64::try_from(row.epoch)? != post.security_epoch
        || row.recipient != post.recipient
        || row.session != post.session
        || post.now >= row.expires_at
    {
        return Ok(None);
    }
    let stored_namespace: Namespace = serde_json::from_str(&row.namespace_json)?;
    ensure!(
        stored_namespace == post.namespace,
        "stored credential namespace mismatch"
    );
    let expected_identity = MaterialIdentity {
        namespace: stored_namespace,
        family: row.family,
        lineage: row.lineage,
        version: post.version.clone(),
        recipient: row.recipient.clone(),
        security_epoch: u64::try_from(row.epoch)?,
        material_revision: u64::try_from(row.material_revision)?,
    };
    let stored_identity: MaterialIdentity = serde_json::from_str(&row.identity_json)?;
    ensure!(
        stored_identity == expected_identity,
        "stored delivery identity mismatch"
    );
    let nonce: [u8; 12] = row
        .nonce
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid material nonce"))?;
    tx.execute(
        "INSERT INTO day2_credential_reveals
                (attempt, version, recipient, session, authorized_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            post.attempt,
            post.version,
            row.recipient,
            row.session,
            post.now
        ],
    )?;
    tx.commit()?;
    Ok(Some(HumanRevealPermit {
        identity: expected_identity,
        envelope_revision: u64::try_from(row.envelope_revision)?,
        encryption_version: row.encryption_version,
        nonce,
        ciphertext: row.ciphertext,
    }))
}

pub(crate) fn close_delivery(tx: &Transaction<'_>, version: &str, reason: &str) -> Result<bool> {
    validate_id(version)?;
    ensure!(
        matches!(
            reason,
            "acknowledged" | "expired" | "session_end" | "epoch_advance"
        ),
        "invalid delivery closure reason"
    );
    Ok(tx.execute(
        "UPDATE day2_credential_deliveries SET state = 'closed', closed_reason = ?2
                   WHERE version = ?1 AND state = 'available'",
        params![version, reason],
    )? == 1)
}

struct ReceiptRow {
    contract: String,
    digest: String,
    action: String,
    lineage: String,
    version: Option<String>,
}

fn receipt(
    tx: &Transaction<'_>,
    namespace: &str,
    invocation: &str,
    slot: u32,
) -> Result<Option<ReceiptRow>> {
    Ok(tx.query_row(
        "SELECT family_contract, request_digest, action, lineage, version
         FROM day2_credential_receipts WHERE namespace = ?1 AND invocation = ?2 AND instruction_slot = ?3",
        params![namespace, invocation, slot],
        |row| Ok(ReceiptRow { contract: row.get(0)?, digest: row.get(1)?,
            action: row.get(2)?, lineage: row.get(3)?, version: row.get(4)? }),
    ).optional()?)
}

fn namespace_key(namespace: &Namespace) -> Result<String> {
    namespace.validate()?;
    Ok(Digest::of(&("credential-namespace-v1", namespace))?
        .as_str()
        .to_owned())
}

fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    fill(&mut bytes).map_err(|_| anyhow::anyhow!("credential entropy unavailable"))?;
    Ok(format!(
        "c_{}",
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
    ))
}

fn validate_id(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 160
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b)),
        "invalid credential identifier"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use day2_capabilities::{
        BindingRef, Name,
        credentials::{LineageRef, ManagementState, VersionRef},
        oauth::{
            AuthorityAction, AuthorityNode, OperationAuthorityContract, OperationKind,
            ResourceAudienceRef,
        },
    };
    use proptest::prelude::*;
    use std::collections::{BTreeMap, BTreeSet};
    use tempfile::TempDir;

    fn name(value: &str) -> Name {
        Name::try_from(value.to_owned()).unwrap()
    }

    fn lease() -> KeyLease {
        KeyLease::new(
            &[3u8; 32],
            &[4u8; 32],
            "verify-v1".into(),
            "encrypt-v1".into(),
        )
        .unwrap()
    }

    fn namespace() -> Namespace {
        Namespace {
            installation: name("wonderly"),
            environment: name("dev"),
            app: name("transcriber"),
            binding_generation: 2,
        }
    }

    fn ceiling() -> GrantCeiling {
        let operation = OperationAuthorityContract::derive(
            "SubmitTranscription".into(),
            1,
            Digest::of(&"submit-v1").unwrap(),
            OperationKind::Command,
            AuthorityNode {
                actions: BTreeSet::from([AuthorityAction::LocalData {
                    category: "transcription".into(),
                    policy: Digest::of(&"own").unwrap(),
                    write: true,
                }]),
                children: BTreeMap::new(),
            },
        )
        .unwrap();
        GrantCeiling::derive(
            BindingRef::pin(name("client"), &"client-v1").unwrap(),
            "client-1".into(),
            ResourceAudienceRef(BindingRef::pin(name("transcriber-api"), &"api-v1").unwrap()),
            BTreeMap::from([("SubmitTranscription".into(), operation)]),
        )
        .unwrap()
    }

    fn issue(invocation: &str) -> IssueIntent {
        IssueIntent {
            namespace: namespace(),
            family: "transcription-client".into(),
            family_contract: Digest::of(&"family-v1").unwrap(),
            invocation: invocation.into(),
            instruction_slot: 0,
            principal: "client-1".into(),
            creator: "issuer/human-1".into(),
            recipient: "issuer/human-1".into(),
            session: "session-1".into(),
            label: "Studio transcription".into(),
            ceiling: ceiling(),
            issued_at: 1_000,
            expires_at: 2_000,
            grant_valid_until: 3_000,
            reveal_until: 1_300,
            security_epoch: 7,
        }
    }

    fn database() -> Result<(TempDir, Connection)> {
        let dir = tempfile::tempdir()?;
        let db = Connection::open(dir.path().join("app.sqlite"))?;
        install_schema(&db)?;
        Ok((dir, db))
    }

    fn committed_issue(db: &mut Connection) -> Result<PublicReceipt> {
        let prepared = prepare_issue(&lease(), issue("invocation-1"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let receipt = stage_issue(&tx, prepared)?.public_identity().clone();
        tx.commit()?;
        Ok(receipt)
    }

    fn post(version: &str, attempt: &str) -> VerifiedHumanPost {
        VerifiedHumanPost {
            namespace: namespace(),
            version: version.into(),
            recipient: "issuer/human-1".into(),
            session: "session-1".into(),
            attempt: attempt.into(),
            now: 1_100,
            security_epoch: 7,
        }
    }

    fn snapshot(receipt: &PublicReceipt) -> ManagementSnapshot {
        let lineage = LineageRef {
            namespace: namespace(),
            family: name("transcription-client"),
            id: receipt.lineage.clone(),
        };
        ManagementSnapshot {
            head: VersionRef {
                lineage: lineage.clone(),
                id: receipt.version.clone().unwrap(),
            },
            lineage,
            revision: 1,
            state: ManagementState::Active,
        }
    }

    #[test]
    fn issue_rolls_back_with_product_write_and_retries_recover_same_receipt() -> Result<()> {
        let (_dir, mut db) = database()?;
        db.execute_batch("CREATE TABLE product_registration (credential TEXT NOT NULL)")?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pending = stage_issue(&tx, prepare_issue(&lease(), issue("invocation-1"))?)?;
        tx.execute(
            "INSERT INTO product_registration VALUES (?1)",
            [&pending.public_identity().lineage],
        )?;
        tx.rollback()?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM day2_credential_lineages", [], |r| r
                .get::<_, i64>(
                0
            ))?,
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM product_registration", [], |r| r
                .get::<_, i64>(0))?,
            0
        );

        let committed = committed_issue(&mut db)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let retried = stage_issue(&tx, prepare_issue(&lease(), issue("invocation-1"))?)?;
        assert_eq!(retried.public_identity(), &committed);
        tx.commit()?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM day2_credential_versions", [], |r| r
                .get::<_, i64>(
                0
            ))?,
            1
        );
        let mut changed = issue("invocation-1");
        changed.label = "Changed intent".into();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(stage_issue(&tx, prepare_issue(&lease(), changed)?).is_err());
        Ok(())
    }

    #[test]
    fn stale_rotation_cannot_create_a_second_successor_and_revoke_is_terminal() -> Result<()> {
        let (_dir, mut db) = database()?;
        let first = committed_issue(&mut db)?;
        let expected = snapshot(&first);
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rotated = match stage_rotation(
            &tx,
            &lease(),
            &expected,
            RotationIntent {
                invocation: "rotation-1",
                instruction_slot: 0,
                recipient: "issuer/human-1",
                session: "session-1",
                issued_at: 1_200,
                expires_at: 2_100,
                reveal_until: 1_400,
            },
        )? {
            RotationResult::Rotated(pending) => pending.public_identity().clone(),
            RotationResult::Conflict => anyhow::bail!("first rotation conflicted"),
        };
        tx.commit()?;
        assert_eq!(rotated.lineage, first.lineage);
        assert_ne!(rotated.version, first.version);
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(matches!(
            stage_rotation(
                &tx,
                &lease(),
                &expected,
                RotationIntent {
                    invocation: "rotation-2",
                    instruction_slot: 0,
                    recipient: "issuer/human-1",
                    session: "session-1",
                    issued_at: 1_200,
                    expires_at: 2_100,
                    reveal_until: 1_400
                }
            )?,
            RotationResult::Conflict
        ));
        tx.commit()?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM day2_credential_versions", [], |r| r
                .get::<_, i64>(
                0
            ))?,
            2
        );
        assert!(
            authorize_reveal(
                &mut db,
                post(first.version.as_ref().unwrap(), "old-attempt")
            )?
            .is_none()
        );
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(stage_revoke(&tx, &namespace(), &first.lineage)?);
        tx.commit()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(!stage_revoke(&tx, &namespace(), &first.lineage)?);
        tx.commit()?;
        assert!(
            authorize_reveal(
                &mut db,
                post(rotated.version.as_ref().unwrap(), "after-revoke")
            )?
            .is_none()
        );
        Ok(())
    }

    #[test]
    fn reveal_commit_is_the_precise_closure_cutoff() -> Result<()> {
        let (_dir, mut db) = database()?;
        let first = committed_issue(&mut db)?;
        let version = first.version.as_ref().unwrap();
        let wrong = VerifiedHumanPost {
            recipient: "issuer/other".into(),
            ..post(version, "wrong")
        };
        assert!(authorize_reveal(&mut db, wrong)?.is_none());
        let permit = authorize_reveal(&mut db, post(version, "allowed"))?.unwrap();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(close_delivery(&tx, version, "acknowledged")?);
        tx.commit()?;
        assert!(authorize_reveal(&mut db, post(version, "too-late"))?.is_none());
        let token = permit.into_response_body(&lease())?;
        assert_eq!(
            super::super::crypto::token_selector(&token)?,
            db.query_row(
                "SELECT selector FROM day2_credential_versions WHERE id = ?1",
                [version],
                |r| r.get::<_, String>(0)
            )?
        );
        assert!(!format!("{first:?}").contains(&token));
        Ok(())
    }

    #[test]
    fn private_state_survives_reopen_without_public_secret_projection() -> Result<()> {
        let (dir, mut db) = database()?;
        let first = committed_issue(&mut db)?;
        drop(db);
        let mut reopened = Connection::open(dir.path().join("app.sqlite"))?;
        install_schema(&reopened)?;
        let permit = authorize_reveal(
            &mut reopened,
            post(first.version.as_ref().unwrap(), "reopened"),
        )?
        .unwrap();
        let token = permit.into_response_body(&lease())?;
        let public = format!("{first:?}");
        assert!(!public.contains(&token));
        Ok(())
    }

    #[test]
    fn reveal_rejects_foreign_namespace_and_substituted_material_identity() -> Result<()> {
        let (_dir, mut db) = database()?;
        let first = committed_issue(&mut db)?;
        let version = first.version.as_ref().unwrap();
        let mut foreign = post(version, "foreign");
        foreign.namespace.app = name("another-app");
        assert!(authorize_reveal(&mut db, foreign)?.is_none());
        let identity_json: String = db.query_row(
            "SELECT identity_json FROM day2_credential_material WHERE version = ?1",
            [version],
            |row| row.get(0),
        )?;
        let mut identity: MaterialIdentity = serde_json::from_str(&identity_json)?;
        identity.lineage = "different-lineage".into();
        db.execute(
            "UPDATE day2_credential_material SET identity_json = ?2 WHERE version = ?1",
            params![version, serde_json::to_string(&identity)?],
        )?;
        assert!(authorize_reveal(&mut db, post(version, "substituted")).is_err());
        Ok(())
    }

    /// Independent abstract state: no SQL or production transition helper is
    /// called to compute expected outcomes. Each schedule runs on real SQLite.
    fn run_state_schedule(actions: &[u8]) -> Result<()> {
        struct Model {
            active: bool,
            delivery_open: bool,
            head: PublicReceipt,
            revision: u64,
        }
        let (_dir, mut db) = database()?;
        let initial = committed_issue(&mut db)?;
        let mut model = Model {
            active: true,
            delivery_open: true,
            head: initial.clone(),
            revision: 1,
        };
        for (index, action) in actions.iter().enumerate() {
            match action % 5 {
                0 | 1 => {
                    let expected = if action % 5 == 0 {
                        let mut current = snapshot(&model.head);
                        current.revision = model.revision;
                        current
                    } else {
                        snapshot(&initial)
                    };
                    let should_rotate = model.active
                        && expected.revision == model.revision
                        && expected.head.id == model.head.version.as_ref().unwrap().as_str();
                    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                    let result = stage_rotation(
                        &tx,
                        &lease(),
                        &expected,
                        RotationIntent {
                            invocation: &format!("rotation-{index}"),
                            instruction_slot: 0,
                            recipient: "issuer/human-1",
                            session: "session-1",
                            issued_at: 1_100,
                            expires_at: 2_000,
                            reveal_until: 1_300,
                        },
                    )?;
                    match result {
                        RotationResult::Rotated(pending) => {
                            ensure!(should_rotate, "model rejected an accepted rotation");
                            model.head = pending.public_identity().clone();
                            model.revision += 1;
                            model.delivery_open = true;
                        }
                        RotationResult::Conflict => {
                            ensure!(!should_rotate, "model accepted a rejected rotation");
                        }
                    }
                    tx.commit()?;
                }
                2 => {
                    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                    let changed = stage_revoke(&tx, &namespace(), &model.head.lineage)?;
                    ensure!(changed == model.active, "model and revocation differ");
                    if changed {
                        model.active = false;
                        model.delivery_open = false;
                        model.revision += 1;
                    }
                    tx.commit()?;
                }
                3 => {
                    let found = authorize_reveal(
                        &mut db,
                        post(
                            model.head.version.as_ref().unwrap(),
                            &format!("reveal-{index}"),
                        ),
                    )?
                    .is_some();
                    ensure!(
                        found == (model.active && model.delivery_open),
                        "model and reveal eligibility differ"
                    );
                }
                _ => {
                    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                    let closed =
                        close_delivery(&tx, model.head.version.as_ref().unwrap(), "acknowledged")?;
                    ensure!(
                        closed == model.delivery_open,
                        "model and delivery closure differ"
                    );
                    model.delivery_open = false;
                    tx.commit()?;
                }
            }
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn sqlite_lineage_transitions_match_independent_model(actions in prop::collection::vec(0u8..5, 0..24)) {
            run_state_schedule(&actions).unwrap();
        }
    }
}
