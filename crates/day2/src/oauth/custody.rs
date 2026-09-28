//! OAuth material in reserved per-app SQLite tables. Encryption uses the
//! credential track's admitted key lease; no key or raw token enters SQLite.

use super::account::VerifiedMappedAccount;
use super::connect::ConnectIntent;
use super::exchange::ExchangeBinding;
use super::profiles::ValidatedTokenResponse;
use crate::managed_credentials::crypto::KeyLease;
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
    verified: &VerifiedMappedAccount,
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
            verified.intent(),
            binding,
            Some(verified.account()),
        ),
        &plaintext,
    );
    plaintext.fill(0);
    Ok(PreparedTokenMaterial {
        slot: verified.intent().slot.clone(),
        generation: verified.intent().proposed_generation,
        account: verified.account().to_owned(),
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

pub(super) fn install_schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS oauth_custody_schema_version (
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
        );",
    )?;
    let mut versions = db.prepare("SELECT version FROM oauth_custody_schema_version")?;
    let known = versions
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        known.is_empty() || known == [1],
        "unsupported OAuth custody schema version"
    );
    if known.is_empty() {
        db.execute("INSERT INTO oauth_custody_schema_version VALUES (1)", [])?;
    }
    Ok(())
}
