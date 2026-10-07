//! OAuth material in reserved per-app SQLite tables. Encryption uses the
//! credential track's admitted key lease; no key or raw token enters SQLite.

use super::account::ProviderAccount;
use super::connect::ConnectIntent;
use super::exchange::ExchangeBinding;
use super::profiles::ValidatedTokenResponse;
use crate::managed_credentials::crypto::KeyLease;
use crate::oauth::effects::fill;
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::oauth::ProviderCallbackRef;
use day2_capabilities::{BindingRef, Digest};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, Serialize)]
enum MaterialPurpose {
    AuthorizationCode,
    PkceVerifier,
    ConnectionTokens,
    ExternalApprovalIdentity,
}

#[derive(Serialize)]
struct MaterialIdentity<'a> {
    purpose: MaterialPurpose,
    attempt: &'a str,
    slot: &'a str,
    generation: i64,
    security_epoch: i64,
    profile: &'a BindingRef,
    registration: &'a BindingRef,
    callback: &'a ProviderCallbackRef,
    custody: &'a BindingRef,
    account: Option<&'a str>,
}

fn identity<'a>(
    purpose: MaterialPurpose,
    intent: &'a ConnectIntent,
    binding: &'a ExchangeBinding,
    account: Option<&'a str>,
) -> MaterialIdentity<'a> {
    MaterialIdentity {
        purpose,
        attempt: &intent.attempt,
        slot: &intent.slot,
        generation: intent.proposed_generation,
        security_epoch: intent.expected_epoch,
        profile: &binding.profile,
        registration: &binding.registration,
        callback: &binding.callback,
        custody: &binding.custody,
        account,
    }
}

fn aad(key: &KeyLease, identity: &MaterialIdentity<'_>) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&(
        "oauth-private-material-aes256gcm-v1",
        identity,
        &key.encryption_version,
    ))?)
}

struct EncryptedMaterial {
    identity_digest: Digest,
    key_version: String,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

fn encrypt(
    key: &KeyLease,
    identity: &MaterialIdentity<'_>,
    plaintext: &[u8],
) -> Result<EncryptedMaterial> {
    ensure!(
        !plaintext.is_empty() && plaintext.len() <= 32 * 1024,
        "invalid private OAuth material size"
    );
    let identity_digest = Digest::of(&("oauth-private-material-identity-v1", identity))?;
    let (nonce, ciphertext) = key.seal_oauth(&aad(key, identity)?, plaintext)?;
    Ok(EncryptedMaterial {
        identity_digest,
        key_version: key.encryption_version.clone(),
        nonce,
        ciphertext,
    })
}

pub(super) fn pkce_challenge(verifier: &str) -> Result<String> {
    ensure!(
        (43..=128).contains(&verifier.len())
            && verifier
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) }),
        "invalid private PKCE verifier"
    );
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())))
}

pub(super) struct PreparedCode {
    attempt: String,
    reference: String,
    material: EncryptedMaterial,
}

pub(super) fn prepare_code(
    key: &KeyLease,
    intent: &ConnectIntent,
    binding: &ExchangeBinding,
    code: &str,
) -> Result<PreparedCode> {
    ensure!(
        !code.is_empty() && code.len() <= 8192,
        "invalid authorization code size"
    );
    let material = encrypt(
        key,
        &identity(MaterialPurpose::AuthorizationCode, intent, binding, None),
        code.as_bytes(),
    )?;
    Ok(PreparedCode {
        attempt: intent.attempt.clone(),
        reference: binding.code_ref.clone(),
        material,
    })
}

pub(super) fn publish_code(tx: &Transaction<'_>, prepared: PreparedCode) -> Result<()> {
    tx.execute(
        "INSERT INTO oauth_private_codes
         (reference, attempt, identity_digest, key_version, nonce, ciphertext)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            prepared.reference,
            prepared.attempt,
            prepared.material.identity_digest.as_str(),
            prepared.material.key_version,
            prepared.material.nonce.as_slice(),
            prepared.material.ciphertext,
        ],
    )?;
    Ok(())
}

pub(super) fn code_exists(
    tx: &Transaction<'_>,
    intent: &ConnectIntent,
    binding: &ExchangeBinding,
) -> Result<bool> {
    let expected = Digest::of(&(
        "oauth-private-material-identity-v1",
        identity(MaterialPurpose::AuthorizationCode, intent, binding, None),
    ))?;
    let stored: Option<(String, Vec<u8>, Vec<u8>)> = tx
        .query_row(
            "SELECT identity_digest, nonce, ciphertext FROM oauth_private_codes
         WHERE reference = ?1 AND attempt = ?2",
            params![binding.code_ref, intent.attempt],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    Ok(stored.is_some_and(|(digest, nonce, ciphertext)| {
        digest == expected.as_str() && nonce.len() == 12 && ciphertext.len() >= 16
    }))
}

pub(super) fn load_code(
    db: &Connection,
    key: &KeyLease,
    intent: &ConnectIntent,
    binding: &ExchangeBinding,
) -> Result<String> {
    let (digest, version, nonce, ciphertext): (String, String, Vec<u8>, Vec<u8>) = db.query_row(
        "SELECT identity_digest, key_version, nonce, ciphertext
         FROM oauth_private_codes WHERE reference = ?1 AND attempt = ?2",
        params![binding.code_ref, intent.attempt],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let expected = identity(MaterialPurpose::AuthorizationCode, intent, binding, None);
    ensure!(
        digest == Digest::of(&("oauth-private-material-identity-v1", &expected))?.as_str()
            && version == key.encryption_version,
        "private code identity or key version mismatch"
    );
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid private code nonce"))?;
    let bytes = key.open_oauth(&aad(key, &expected)?, nonce, &ciphertext)?;
    String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("invalid private code material"))
}

pub(super) fn delete_code(
    tx: &Transaction<'_>,
    intent: &ConnectIntent,
    binding: &ExchangeBinding,
) -> Result<()> {
    let deleted = tx.execute(
        "DELETE FROM oauth_private_codes WHERE reference = ?1 AND attempt = ?2",
        params![binding.code_ref, intent.attempt],
    )?;
    ensure!(
        deleted == 1,
        "private authorization code missing at settlement"
    );
    Ok(())
}

pub(super) fn delete_attempt_material(tx: &Transaction<'_>, attempt: &str) -> Result<()> {
    tx.execute(
        "DELETE FROM oauth_external_quarantine WHERE attempt = ?1",
        [attempt],
    )?;
    tx.execute(
        "DELETE FROM oauth_private_codes WHERE attempt = ?1",
        [attempt],
    )?;
    tx.execute(
        "DELETE FROM oauth_private_verifiers WHERE attempt = ?1",
        [attempt],
    )?;
    Ok(())
}

pub(super) struct PreparedVerifier {
    attempt: String,
    reference: String,
    material: EncryptedMaterial,
}

pub(super) fn prepare_verifier(
    key: &KeyLease,
    intent: &ConnectIntent,
    binding: &ExchangeBinding,
    verifier: &str,
) -> Result<PreparedVerifier> {
    ensure!(
        pkce_challenge(verifier)? == binding.code_challenge,
        "PKCE challenge does not match private verifier"
    );
    let material = encrypt(
        key,
        &identity(MaterialPurpose::PkceVerifier, intent, binding, None),
        verifier.as_bytes(),
    )?;
    Ok(PreparedVerifier {
        attempt: intent.attempt.clone(),
        reference: binding.verifier_ref.clone(),
        material,
    })
}

pub(super) fn publish_verifier(tx: &Transaction<'_>, prepared: &PreparedVerifier) -> Result<()> {
    tx.execute(
        "INSERT INTO oauth_private_verifiers
         (reference, attempt, identity_digest, key_version, nonce, ciphertext)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            prepared.reference,
            prepared.attempt,
            prepared.material.identity_digest.as_str(),
            prepared.material.key_version,
            prepared.material.nonce.as_slice(),
            &prepared.material.ciphertext,
        ],
    )?;
    Ok(())
}

pub(super) fn verifier_exists(
    tx: &Transaction<'_>,
    intent: &ConnectIntent,
    binding: &ExchangeBinding,
) -> Result<bool> {
    let expected = Digest::of(&(
        "oauth-private-material-identity-v1",
        identity(MaterialPurpose::PkceVerifier, intent, binding, None),
    ))?;
    let stored: Option<(String, Vec<u8>, Vec<u8>)> = tx
        .query_row(
            "SELECT identity_digest, nonce, ciphertext FROM oauth_private_verifiers
             WHERE reference = ?1 AND attempt = ?2",
            params![binding.verifier_ref, intent.attempt],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    Ok(stored.is_some_and(|(digest, nonce, ciphertext)| {
        digest == expected.as_str() && nonce.len() == 12 && ciphertext.len() >= 16
    }))
}

/// The reviewed transport resolves this reference after the dispatch fence.
/// The expected AAD comes from the sealed permit, not from stored metadata.
pub(super) fn load_verifier(
    db: &Connection,
    key: &KeyLease,
    intent: &ConnectIntent,
    binding: &ExchangeBinding,
) -> Result<String> {
    let (digest, version, nonce, ciphertext): (String, String, Vec<u8>, Vec<u8>) = db.query_row(
        "SELECT identity_digest, key_version, nonce, ciphertext
         FROM oauth_private_verifiers WHERE reference = ?1 AND attempt = ?2",
        params![binding.verifier_ref, intent.attempt],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let expected = identity(MaterialPurpose::PkceVerifier, intent, binding, None);
    ensure!(
        digest == Digest::of(&("oauth-private-material-identity-v1", &expected))?.as_str()
            && version == key.encryption_version,
        "private PKCE identity or key version mismatch"
    );
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid private PKCE nonce"))?;
    let bytes = key.open_oauth(&aad(key, &expected)?, nonce, &ciphertext)?;
    let verifier =
        String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("invalid private PKCE material"))?;
    ensure!(
        pkce_challenge(&verifier)? == binding.code_challenge,
        "private PKCE challenge mismatch"
    );
    Ok(verifier)
}

pub(super) fn delete_verifier(
    tx: &Transaction<'_>,
    intent: &ConnectIntent,
    binding: &ExchangeBinding,
) -> Result<()> {
    let deleted = tx.execute(
        "DELETE FROM oauth_private_verifiers WHERE reference = ?1 AND attempt = ?2",
        params![binding.verifier_ref, intent.attempt],
    )?;
    ensure!(deleted == 1, "private PKCE verifier missing at settlement");
    Ok(())
}

pub(super) struct PreparedTokenMaterial {
    slot: String,
    generation: i64,
    account: String,
    reference: String,
    material: EncryptedMaterial,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenBundle {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
}

pub(super) fn prepare_tokens(
    key: &KeyLease,
    intent: &ConnectIntent,
    account: &str,
    binding: &ExchangeBinding,
    tokens: ValidatedTokenResponse,
) -> Result<PreparedTokenMaterial> {
    let (access_token, refresh_token, expires_in) = tokens.into_private_tokens();
    let bundle = TokenBundle {
        access_token,
        refresh_token,
        expires_in,
    };
    let mut plaintext = serde_json::to_vec(&bundle)?;
    let material = encrypt(
        key,
        &identity(
            MaterialPurpose::ConnectionTokens,
            intent,
            binding,
            Some(account),
        ),
        &plaintext,
    );
    plaintext.fill(0);
    Ok(PreparedTokenMaterial {
        slot: intent.slot.clone(),
        generation: intent.proposed_generation,
        account: account.to_owned(),
        reference: binding.token_slot_ref.clone(),
        material: material?,
    })
}

pub(super) fn publish_tokens(tx: &Transaction<'_>, prepared: PreparedTokenMaterial) -> Result<()> {
    tx.execute(
        "INSERT INTO oauth_private_tokens
         (reference, slot, generation, account, identity_digest, key_version, nonce, ciphertext)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            prepared.reference,
            prepared.slot,
            prepared.generation,
            prepared.account,
            prepared.material.identity_digest.as_str(),
            prepared.material.key_version,
            prepared.material.nonce.as_slice(),
            prepared.material.ciphertext,
        ],
    )?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingExternalIdentity {
    pub observed: ProviderAccount,
    pub challenge: Digest,
    pub quarantined_at: i64,
}

pub(super) struct PreparedExternalQuarantine {
    attempt: String,
    scope_evidence: String,
    token: PreparedTokenMaterial,
    identity: EncryptedMaterial,
    challenge: Digest,
    quarantined_at: i64,
}

impl PreparedExternalQuarantine {
    pub(super) fn quarantined_at(&self) -> i64 {
        self.quarantined_at
    }
}

pub(super) fn prepare_external_quarantine(
    key: &KeyLease,
    intent: &ConnectIntent,
    account_scope: (&str, &str),
    observed: &ProviderAccount,
    binding: &ExchangeBinding,
    tokens: ValidatedTokenResponse,
    now: i64,
) -> Result<PreparedExternalQuarantine> {
    let (account, scope_evidence) = account_scope;
    ensure!(
        now >= 0 && now < intent.expires_at,
        "invalid external approval lifetime"
    );
    let mut random = [0u8; 32];
    fill(&mut random).map_err(|_| anyhow::anyhow!("approval challenge entropy unavailable"))?;
    let challenge = Digest::of(&(
        "oauth-external-approval-challenge-v1",
        &intent.attempt,
        account,
        scope_evidence,
        intent.proposed_generation,
        now,
        random,
    ))?;
    random.fill(0);
    let pending = PendingExternalIdentity {
        observed: observed.clone(),
        challenge: challenge.clone(),
        quarantined_at: now,
    };
    let mut plaintext = serde_json::to_vec(&pending)?;
    let identity = encrypt(
        key,
        &identity(
            MaterialPurpose::ExternalApprovalIdentity,
            intent,
            binding,
            Some(account),
        ),
        &plaintext,
    );
    plaintext.fill(0);
    Ok(PreparedExternalQuarantine {
        attempt: intent.attempt.clone(),
        scope_evidence: scope_evidence.to_owned(),
        token: prepare_tokens(key, intent, account, binding, tokens)?,
        identity: identity?,
        challenge,
        quarantined_at: now,
    })
}

pub(super) fn publish_external_quarantine(
    tx: &Transaction<'_>,
    prepared: PreparedExternalQuarantine,
) -> Result<()> {
    tx.execute(
        "INSERT INTO oauth_external_quarantine
         (attempt, slot, generation, account, scope_evidence, challenge, quarantined_at,
          token_reference, token_identity_digest, token_key_version, token_nonce, token_ciphertext,
          identity_digest, identity_key_version, identity_nonce, identity_ciphertext)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            prepared.attempt,
            prepared.token.slot,
            prepared.token.generation,
            prepared.token.account,
            prepared.scope_evidence,
            prepared.challenge.as_str(),
            prepared.quarantined_at,
            prepared.token.reference,
            prepared.token.material.identity_digest.as_str(),
            prepared.token.material.key_version,
            prepared.token.material.nonce.as_slice(),
            prepared.token.material.ciphertext,
            prepared.identity.identity_digest.as_str(),
            prepared.identity.key_version,
            prepared.identity.nonce.as_slice(),
            prepared.identity.ciphertext,
        ],
    )?;
    Ok(())
}

struct QuarantineRow {
    slot: String,
    generation: i64,
    account: String,
    scope_evidence: String,
    challenge: String,
    quarantined_at: i64,
    token_reference: String,
    token_identity_digest: String,
    token_key_version: String,
    token_nonce: Vec<u8>,
    token_ciphertext: Vec<u8>,
    identity_digest: String,
    identity_key_version: String,
    identity_nonce: Vec<u8>,
    identity_ciphertext: Vec<u8>,
}

fn quarantine_row(db: &Connection, attempt: &str) -> Result<Option<QuarantineRow>> {
    Ok(db
        .query_row(
            "SELECT slot, generation, account, scope_evidence, challenge, quarantined_at,
                token_reference, token_identity_digest, token_key_version, token_nonce,
                token_ciphertext, identity_digest, identity_key_version, identity_nonce,
                identity_ciphertext
         FROM oauth_external_quarantine WHERE attempt = ?1",
            [attempt],
            |row| {
                Ok(QuarantineRow {
                    slot: row.get(0)?,
                    generation: row.get(1)?,
                    account: row.get(2)?,
                    scope_evidence: row.get(3)?,
                    challenge: row.get(4)?,
                    quarantined_at: row.get(5)?,
                    token_reference: row.get(6)?,
                    token_identity_digest: row.get(7)?,
                    token_key_version: row.get(8)?,
                    token_nonce: row.get(9)?,
                    token_ciphertext: row.get(10)?,
                    identity_digest: row.get(11)?,
                    identity_key_version: row.get(12)?,
                    identity_nonce: row.get(13)?,
                    identity_ciphertext: row.get(14)?,
                })
            },
        )
        .optional()?)
}

fn validate_external_identity(
    row: &QuarantineRow,
    key: &KeyLease,
    intent: &ConnectIntent,
    binding: &ExchangeBinding,
    account: &str,
    scope_evidence: &str,
) -> Result<PendingExternalIdentity> {
    ensure!(
        row.slot == intent.slot
            && row.generation == intent.proposed_generation
            && row.account == account
            && row.scope_evidence == scope_evidence
            && row.quarantined_at >= 0
            && row.quarantined_at < intent.expires_at,
        "external approval quarantine identity mismatch"
    );
    let expected = identity(
        MaterialPurpose::ExternalApprovalIdentity,
        intent,
        binding,
        Some(account),
    );
    ensure!(
        row.identity_digest
            == Digest::of(&("oauth-private-material-identity-v1", &expected))?.as_str()
            && row.identity_key_version == key.encryption_version,
        "external approval identity or key version mismatch"
    );
    let nonce: [u8; 12] = row
        .identity_nonce
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid external approval nonce"))?;
    let mut plaintext = key.open_oauth(&aad(key, &expected)?, nonce, &row.identity_ciphertext)?;
    let pending: PendingExternalIdentity = serde_json::from_slice(&plaintext)
        .map_err(|_| anyhow::anyhow!("invalid external approval identity"))?;
    plaintext.fill(0);
    ensure!(
        pending.challenge.as_str() == row.challenge
            && pending.quarantined_at == row.quarantined_at
            && super::account::provider_account_digest(&pending.observed)?.as_str() == account,
        "external approval identity does not match quarantine"
    );
    Ok(pending)
}

pub(super) fn load_pending_external_identity(
    db: &Connection,
    key: &KeyLease,
    intent: &ConnectIntent,
    binding: &ExchangeBinding,
    account: &str,
    scope_evidence: &str,
) -> Result<Option<PendingExternalIdentity>> {
    quarantine_row(db, &intent.attempt)?
        .map(|row| validate_external_identity(&row, key, intent, binding, account, scope_evidence))
        .transpose()
}

pub(super) fn commit_external_quarantine(
    tx: &Transaction<'_>,
    key: &KeyLease,
    intent: &ConnectIntent,
    binding: &ExchangeBinding,
    account: &str,
    scope_evidence: &str,
    challenge: &Digest,
) -> Result<()> {
    let row = quarantine_row(tx, &intent.attempt)?
        .ok_or_else(|| anyhow::anyhow!("external approval quarantine missing"))?;
    let pending = validate_external_identity(&row, key, intent, binding, account, scope_evidence)?;
    ensure!(
        pending.challenge == *challenge,
        "external approval challenge changed"
    );
    let expected = identity(
        MaterialPurpose::ConnectionTokens,
        intent,
        binding,
        Some(account),
    );
    ensure!(
        row.token_reference == binding.token_slot_ref
            && row.token_identity_digest
                == Digest::of(&("oauth-private-material-identity-v1", &expected))?.as_str()
            && row.token_key_version == key.encryption_version,
        "quarantined token identity or key version mismatch"
    );
    let nonce: [u8; 12] = row
        .token_nonce
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid quarantined token nonce"))?;
    let mut plaintext = key.open_oauth(&aad(key, &expected)?, nonce, &row.token_ciphertext)?;
    let token: TokenBundle = serde_json::from_slice(&plaintext)
        .map_err(|_| anyhow::anyhow!("invalid quarantined token bundle"))?;
    plaintext.fill(0);
    let valid = !token.access_token.is_empty();
    let mut access = token.access_token.into_bytes();
    access.fill(0);
    if let Some(refresh) = token.refresh_token {
        let mut refresh = refresh.into_bytes();
        refresh.fill(0);
    }
    ensure!(valid, "empty quarantined access token");
    tx.execute(
        "INSERT INTO oauth_private_tokens
         (reference, slot, generation, account, identity_digest, key_version, nonce, ciphertext)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            row.token_reference,
            row.slot,
            row.generation,
            row.account,
            row.token_identity_digest,
            row.token_key_version,
            row.token_nonce,
            row.token_ciphertext,
        ],
    )?;
    let deleted = tx.execute(
        "DELETE FROM oauth_external_quarantine WHERE attempt = ?1 AND challenge = ?2",
        params![intent.attempt, challenge.as_str()],
    )?;
    ensure!(deleted == 1, "external approval quarantine lost");
    Ok(())
}

pub(super) fn install_schema(db: &Connection) -> Result<()> {
    super::schema::admit(db, install_schema_in)
}

fn install_schema_in(db: &Connection) -> Result<()> {
    let ddl = "CREATE TABLE IF NOT EXISTS oauth_custody_schema_version (
            version INTEGER PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS oauth_private_verifiers (
            reference TEXT PRIMARY KEY,
            attempt TEXT NOT NULL REFERENCES oauth_connect_attempts(attempt),
            identity_digest TEXT NOT NULL,
            key_version TEXT NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS oauth_private_codes (
            reference TEXT PRIMARY KEY,
            attempt TEXT NOT NULL REFERENCES oauth_connect_attempts(attempt),
            identity_digest TEXT NOT NULL,
            key_version TEXT NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS oauth_private_tokens (
            reference TEXT PRIMARY KEY,
            slot TEXT NOT NULL,
            generation INTEGER NOT NULL CHECK(generation > 0),
            account TEXT NOT NULL,
            identity_digest TEXT NOT NULL,
            key_version TEXT NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            UNIQUE(slot, generation)
        );
        CREATE TABLE IF NOT EXISTS oauth_external_quarantine (
            attempt TEXT PRIMARY KEY REFERENCES oauth_connect_attempts(attempt),
            slot TEXT NOT NULL,
            generation INTEGER NOT NULL CHECK(generation > 0),
            account TEXT NOT NULL,
            scope_evidence TEXT NOT NULL,
            challenge TEXT NOT NULL UNIQUE,
            quarantined_at INTEGER NOT NULL,
            token_reference TEXT NOT NULL,
            token_identity_digest TEXT NOT NULL,
            token_key_version TEXT NOT NULL,
            token_nonce BLOB NOT NULL,
            token_ciphertext BLOB NOT NULL,
            identity_digest TEXT NOT NULL,
            identity_key_version TEXT NOT NULL,
            identity_nonce BLOB NOT NULL,
            identity_ciphertext BLOB NOT NULL
        );";
    super::schema::install_current(db, "oauth_custody_schema_version", 3, ddl, &[
        super::schema::Invariant { table: "oauth_private_verifiers", predicate:
            "length(reference) > 0 AND length(attempt) > 0 AND length(identity_digest) > 0 AND length(key_version) > 0 AND
             typeof(nonce) = 'blob' AND length(nonce) = 12 AND typeof(ciphertext) = 'blob' AND length(ciphertext) BETWEEN 16 AND 32784" },
        super::schema::Invariant { table: "oauth_private_codes", predicate:
            "length(reference) > 0 AND length(attempt) > 0 AND length(identity_digest) > 0 AND length(key_version) > 0 AND
             typeof(nonce) = 'blob' AND length(nonce) = 12 AND typeof(ciphertext) = 'blob' AND length(ciphertext) BETWEEN 16 AND 32784" },
        super::schema::Invariant { table: "oauth_private_tokens", predicate:
            "length(reference) > 0 AND length(slot) > 0 AND generation > 0 AND length(account) > 0 AND
             length(identity_digest) > 0 AND length(key_version) > 0 AND
             typeof(nonce) = 'blob' AND length(nonce) = 12 AND typeof(ciphertext) = 'blob' AND length(ciphertext) BETWEEN 16 AND 32784" },
        super::schema::Invariant { table: "oauth_external_quarantine", predicate:
            "length(attempt) > 0 AND length(slot) > 0 AND generation > 0 AND length(account) > 0 AND length(scope_evidence) > 0 AND
             length(challenge) > 0 AND length(token_reference) > 0 AND length(token_identity_digest) > 0 AND length(token_key_version) > 0 AND
             length(identity_digest) > 0 AND length(identity_key_version) > 0 AND
             typeof(token_nonce) = 'blob' AND length(token_nonce) = 12 AND typeof(token_ciphertext) = 'blob' AND length(token_ciphertext) BETWEEN 16 AND 32784 AND
             typeof(identity_nonce) = 'blob' AND length(identity_nonce) = 12 AND typeof(identity_ciphertext) = 'blob' AND length(identity_ciphertext) BETWEEN 16 AND 32784" },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custody_schema_reopens_current_and_refuses_other_versions() {
        for version in [1, 2, 99] {
            let db = Connection::open_in_memory().unwrap();
            super::super::connect::install_schema(&db).unwrap();
            super::super::connect::install_schema(&db).unwrap();
            db.execute(
                "UPDATE oauth_custody_schema_version SET version=?1",
                [version],
            )
            .unwrap();
            assert!(super::super::connect::install_schema(&db).is_err());
            assert_eq!(
                db.query_row(
                    "SELECT version FROM oauth_custody_schema_version",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
                version
            );
        }
    }
}
