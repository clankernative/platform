//! Private managed-token format and authenticated delivery envelope.
//! Key bytes are supplied by an admitted, exact-version key lease. This module
//! never derives cryptographic entropy from replay or invocation identifiers.

use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::{credentials::Namespace, oauth::GrantCeiling};
use ring::{aead, hmac};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const PREFIX: &str = "d2c1";
const SECRET_BYTES: usize = 32;
const SELECTOR_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const MAX_TOKEN_BYTES: usize = 128;

/// Distinct key versions are part of material identity. A provider must check
/// current readiness and purpose before constructing this value.
pub(crate) struct KeyLease {
    verifier: VerifierLease,
    encryption_key: aead::LessSafeKey,
    pub verifier_version: String,
    pub encryption_version: String,
}

/// Authentication has no encryption key or decryption capability.
pub(crate) struct VerifierLease {
    key: hmac::Key,
    pub verifier_version: String,
}

/// Maintenance borrows encryption authority only, never a verifier or a human
/// response permit. The selected maintenance adapter supplies exact key bytes.
pub(super) struct RewrapKey {
    key: aead::LessSafeKey,
    version: String,
}

impl RewrapKey {
    pub(super) fn new(bytes: &[u8; 32], version: String) -> Result<Self> {
        validate_id(&version)?;
        let key = aead::UnboundKey::new(&aead::AES_256_GCM, bytes)
            .map_err(|_| anyhow::anyhow!("invalid encryption key"))?;
        Ok(Self {
            key: aead::LessSafeKey::new(key),
            version,
        })
    }
}

/// Historical encrypted DATA selected by the maintenance owner, not authority.
pub(super) struct RewrapSource<'a> {
    pub identity: &'a MaterialIdentity,
    pub selector: &'a str,
    pub envelope_revision: u64,
    pub encryption_version: &'a str,
    pub nonce: [u8; NONCE_BYTES],
    pub ciphertext: &'a [u8],
}

/// This contains no plaintext, verifier, new material identity or renewed time.
/// Only the owning maintenance transition may publish it with its exact CAS.
pub(super) struct RewrappedEnvelope {
    pub envelope_revision: u64,
    pub encryption_version: String,
    pub nonce: [u8; NONCE_BYTES],
    pub ciphertext: Vec<u8>,
}

/// Authenticate the independently expected identity, then reseal the SAME
/// canonical token. No plaintext getter or callback leaves this closed body.
/// Provider key acquisition and this fresh nonce precede the writer transaction.
pub(super) fn prepare_rewrap(
    previous: &RewrapKey,
    replacement: &RewrapKey,
    expected: &MaterialIdentity,
    source: RewrapSource<'_>,
) -> Result<RewrappedEnvelope> {
    ensure!(
        expected == source.identity
            && source.encryption_version == previous.version
            && previous.version != replacement.version,
        "credential rewrap identity or key selection changed"
    );
    ensure!(
        (32..=512).contains(&source.ciphertext.len()),
        "invalid protected credential envelope size"
    );
    let envelope_revision = source
        .envelope_revision
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("credential envelope revision exhausted"))?;
    // Zeroizing owns the in-place plaintext on every error and success path.
    let mut buffer = Zeroizing::new(source.ciphertext.to_vec());
    let plaintext = previous
        .key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(source.nonce),
            aead::Aad::from(expected.aad(source.envelope_revision, &previous.version)?),
            &mut buffer,
        )
        .map_err(|_| anyhow::anyhow!("credential rewrap authentication failed"))?;
    let (selector, _secret) = parse_token(
        std::str::from_utf8(plaintext)
            .map_err(|_| anyhow::anyhow!("invalid protected credential material"))?,
    )?;
    ensure!(
        selector == source.selector,
        "credential rewrap selector changed"
    );
    let length = plaintext.len();
    buffer.truncate(length);
    let mut nonce = [0; NONCE_BYTES];
    super::effects::fill_secret(&mut nonce)?;
    replacement
        .key
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(expected.aad(envelope_revision, &replacement.version)?),
            &mut *buffer,
        )
        .map_err(|_| anyhow::anyhow!("credential rewrap encryption failed"))?;
    Ok(RewrappedEnvelope {
        envelope_revision,
        encryption_version: replacement.version.clone(),
        nonce,
        // Only ciphertext escapes the zeroizing workspace.
        ciphertext: buffer.to_vec(),
    })
}

impl VerifierLease {
    pub(crate) fn new(key: &[u8], verifier_version: String) -> Result<Self> {
        validate_id(&verifier_version)?;
        ensure!(key.len() >= 32, "invalid verifier key length");
        Ok(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, key),
            verifier_version,
        })
    }
}

impl AsRef<VerifierLease> for VerifierLease {
    fn as_ref(&self) -> &VerifierLease {
        self
    }
}

impl AsRef<VerifierLease> for KeyLease {
    fn as_ref(&self) -> &VerifierLease {
        &self.verifier
    }
}

impl KeyLease {
    pub fn new(
        verifier_key: &[u8],
        encryption_key: &[u8; 32],
        verifier_version: String,
        encryption_version: String,
    ) -> Result<Self> {
        validate_id(&verifier_version)?;
        validate_id(&encryption_version)?;
        ensure!(verifier_key.len() >= 32, "invalid verifier key length");
        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, encryption_key)
            .map_err(|_| anyhow::anyhow!("invalid encryption key"))?;
        Ok(Self {
            verifier: VerifierLease::new(verifier_key, verifier_version.clone())?,
            encryption_key: aead::LessSafeKey::new(unbound),
            verifier_version,
            encryption_version,
        })
    }

    /// OAuth custody uses the same admitted encryption lease with a separate
    /// authenticated-data domain. The caller prepares material before SQLite.
    pub(crate) fn seal_oauth(&self, aad: &[u8], plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>)> {
        ensure!(!aad.is_empty(), "missing OAuth custody identity");
        let mut nonce = [0u8; 12];
        crate::oauth::effects::fill(&mut nonce)?;
        let mut ciphertext = plaintext.to_vec();
        self.encryption_key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                &mut ciphertext,
            )
            .map_err(|_| anyhow::anyhow!("OAuth custody encryption failed"))?;
        Ok((nonce, ciphertext))
    }

    pub(crate) fn open_oauth(
        &self,
        aad: &[u8],
        nonce: [u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        ensure!(!aad.is_empty(), "missing OAuth custody identity");
        let mut buffer = ciphertext.to_vec();
        let plaintext = self
            .encryption_key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                &mut buffer,
            )
            .map_err(|_| anyhow::anyhow!("OAuth custody authentication failed"))?;
        let plaintext = plaintext.to_vec();
        buffer.fill(0);
        Ok(plaintext)
    }
}

/// Expected identity comes from authorized current state, not the ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MaterialIdentity {
    pub namespace: Namespace,
    pub family: String,
    pub lineage: String,
    pub version: String,
    pub recipient: String,
    pub security_epoch: u64,
    pub material_revision: u64,
    /// Immutable effective grant of THIS version, authenticated by both the
    /// verifier and encrypted envelope; never reconstructed from today's head.
    pub grant: GrantCeiling,
}

impl MaterialIdentity {
    fn validate(&self) -> Result<()> {
        self.namespace.validate()?;
        for id in [&self.family, &self.lineage, &self.version] {
            validate_id(id)?;
        }
        crate::authority::valid_actor(&self.recipient)?;
        ensure!(
            self.security_epoch > 0 && self.material_revision > 0,
            "invalid material identity revision"
        );
        ensure!(
            self.grant.roots.len() <= 64,
            "credential material grant budget"
        );
        self.grant.verify()?;
        Ok(())
    }

    fn aad(&self, envelope_revision: u64, encryption_version: &str) -> Result<Vec<u8>> {
        self.validate()?;
        ensure!(envelope_revision > 0, "invalid envelope revision");
        validate_id(encryption_version)?;
        Ok(serde_json::to_vec(&(
            "day2-managed-material-aes256gcm-v1",
            self,
            envelope_revision,
            encryption_version,
        ))?)
    }
}

/// This type has no Debug, Clone or Serialize path into journals or app results.
pub(crate) struct PreparedMaterial {
    pub selector: String,
    pub verifier: [u8; 32],
    pub verifier_version: String,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_BYTES],
    pub identity: MaterialIdentity,
    pub envelope_revision: u64,
    pub encryption_version: String,
}

/// Private entropy and encryption happen before the product transaction. The
/// resulting material is not eligible for any sink until the transaction commits.
pub(crate) fn prepare_managed(
    lease: &KeyLease,
    identity: MaterialIdentity,
) -> Result<PreparedMaterial> {
    identity.validate()?;
    let mut selector_bytes = [0u8; SELECTOR_BYTES];
    let mut secret_bytes = [0u8; SECRET_BYTES];
    let mut nonce = [0u8; NONCE_BYTES];
    super::effects::fill_secret(&mut selector_bytes)?;
    super::effects::fill_secret(&mut secret_bytes)?;
    super::effects::fill_secret(&mut nonce)?;
    let selector = URL_SAFE_NO_PAD.encode(selector_bytes);
    let token = format!(
        "{PREFIX}.{selector}.{}",
        URL_SAFE_NO_PAD.encode(secret_bytes)
    );
    let verifier = verifier(lease, &identity, &selector, &secret_bytes)?;
    let envelope_revision = 1;
    let aad = identity.aad(envelope_revision, &lease.encryption_version)?;
    let mut ciphertext = token.into_bytes();
    lease
        .encryption_key
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad),
            &mut ciphertext,
        )
        .map_err(|_| anyhow::anyhow!("credential encryption failed"))?;
    secret_bytes.fill(0);
    Ok(PreparedMaterial {
        selector,
        verifier,
        verifier_version: lease.verifier_version.clone(),
        ciphertext,
        nonce,
        identity,
        envelope_revision,
        encryption_version: lease.encryption_version.clone(),
    })
}

pub(crate) fn token_selector(token: &str) -> Result<String> {
    let (selector, _) = parse_token(token)?;
    Ok(selector)
}

/// Exact expected identity and the stored verifier must come from a current,
/// accepted lineage/version. This cryptographic check is not authorization.
pub(crate) fn verify_managed(
    lease: &impl AsRef<VerifierLease>,
    identity: &MaterialIdentity,
    expected_selector: &str,
    expected_verifier: &[u8],
    verifier_version: &str,
    token: &str,
) -> Result<bool> {
    let lease = lease.as_ref();
    ensure!(expected_verifier.len() == 32, "invalid stored verifier");
    ensure!(
        verifier_version == lease.verifier_version,
        "credential verifier key version mismatch"
    );
    let (selector, secret) = parse_token(token)?;
    if selector != expected_selector {
        return Ok(false);
    }
    let message = verifier_message(identity, &selector, &secret)?;
    Ok(hmac::verify(&lease.key, &message, expected_verifier).is_ok())
}

/// Only a role-specific, consuming sink should call this after a known-commit
/// reveal authorization. The envelope's identity is compared with an independent
/// state selection before decryption.
pub(crate) fn decrypt_for_human(
    lease: &KeyLease,
    expected: &MaterialIdentity,
    stored_identity: &MaterialIdentity,
    envelope_revision: u64,
    encryption_version: &str,
    nonce: [u8; NONCE_BYTES],
    ciphertext: &[u8],
) -> Result<String> {
    ensure!(
        expected == stored_identity,
        "credential material identity mismatch"
    );
    ensure!(
        encryption_version == lease.encryption_version,
        "credential encryption key version mismatch"
    );
    let aad = expected.aad(envelope_revision, encryption_version)?;
    let mut buffer = ciphertext.to_vec();
    let plaintext = lease
        .encryption_key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad),
            &mut buffer,
        )
        .map_err(|_| anyhow::anyhow!("credential authentication failed"))?;
    let token = std::str::from_utf8(plaintext)
        .map_err(|_| anyhow::anyhow!("invalid protected credential material"))?
        .to_owned();
    parse_token(&token)?;
    buffer.fill(0);
    Ok(token)
}

fn verifier(
    lease: &KeyLease,
    identity: &MaterialIdentity,
    selector: &str,
    secret: &[u8; SECRET_BYTES],
) -> Result<[u8; 32]> {
    let message = verifier_message(identity, selector, secret)?;
    let tag = hmac::sign(&lease.verifier.key, &message);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(tag.as_ref());
    Ok(digest)
}

fn verifier_message(
    identity: &MaterialIdentity,
    selector: &str,
    secret: &[u8; SECRET_BYTES],
) -> Result<Vec<u8>> {
    identity.validate()?;
    Ok(serde_json::to_vec(&(
        "day2-managed-verifier-v1",
        identity,
        selector,
        secret,
    ))?)
}

fn parse_token(token: &str) -> Result<(String, Zeroizing<[u8; SECRET_BYTES]>)> {
    ensure!(token.len() <= MAX_TOKEN_BYTES, "invalid credential format");
    let mut parts = token.split('.');
    let (Some(PREFIX), Some(selector), Some(secret), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        anyhow::bail!("invalid credential format");
    };
    let selector_bytes = URL_SAFE_NO_PAD
        .decode(selector)
        .map_err(|_| anyhow::anyhow!("invalid credential format"))?;
    let secret_bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(secret)
            .map_err(|_| anyhow::anyhow!("invalid credential format"))?,
    );
    ensure!(
        selector_bytes.len() == SELECTOR_BYTES && secret_bytes.len() == SECRET_BYTES,
        "invalid credential format"
    );
    ensure!(
        URL_SAFE_NO_PAD.encode(&selector_bytes) == selector
            && Zeroizing::new(URL_SAFE_NO_PAD.encode(&*secret_bytes)).as_str() == secret,
        "noncanonical credential format"
    );
    let mut bytes = Zeroizing::new([0u8; SECRET_BYTES]);
    bytes.copy_from_slice(&secret_bytes);
    Ok((selector.to_owned(), bytes))
}

fn validate_id(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 160
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b)),
        "invalid private credential identifier"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use day2_capabilities::Name;

    fn identity() -> MaterialIdentity {
        use day2_capabilities::{
            BindingRef, Digest,
            oauth::{
                AuthorityNode, OperationAuthorityContract, OperationKind, ResourceAudienceRef,
            },
        };
        let binding = BindingRef::pin(
            Name::try_from("identity-client".to_owned()).unwrap(),
            &"identity-client",
        )
        .unwrap();
        let operation = OperationAuthorityContract::derive(
            "ReadIdentity".into(),
            1,
            Digest::new(b"identity-contract"),
            OperationKind::Query,
            AuthorityNode {
                actions: Default::default(),
                children: Default::default(),
            },
        )
        .unwrap();
        let grant = GrantCeiling::derive(
            binding.clone(),
            "client-1".into(),
            ResourceAudienceRef(binding),
            std::collections::BTreeMap::from([("ReadIdentity".into(), operation)]),
        )
        .unwrap();
        MaterialIdentity {
            namespace: Namespace {
                installation: Name::try_from("wonderly".to_owned()).unwrap(),
                environment: Name::try_from("dev".to_owned()).unwrap(),
                app: Name::try_from("transcriber".to_owned()).unwrap(),
                binding_generation: 1,
            },
            family: "transcription-client".into(),
            lineage: "lineage-1".into(),
            version: "version-1".into(),
            recipient: "issuer/subject-1".into(),
            security_epoch: 7,
            material_revision: 1,
            grant,
        }
    }

    fn lease() -> KeyLease {
        KeyLease::new(
            &[7u8; 32],
            &[9u8; 32],
            "verifier-v1".into(),
            "encrypt-v1".into(),
        )
        .unwrap()
    }

    fn rewrap_source(material: &PreparedMaterial) -> RewrapSource<'_> {
        RewrapSource {
            identity: &material.identity,
            selector: &material.selector,
            envelope_revision: material.envelope_revision,
            encryption_version: &material.encryption_version,
            nonce: material.nonce,
            ciphertext: &material.ciphertext,
        }
    }

    #[test]
    fn rewrap_preserves_exact_token_and_verifier_without_a_plaintext_result() -> Result<()> {
        let identity = identity();
        let material = prepare_managed(&lease(), identity.clone())?;
        let old_token = decrypt_for_human(
            &lease(),
            &identity,
            &identity,
            1,
            "encrypt-v1",
            material.nonce,
            &material.ciphertext,
        )?;
        let next = KeyLease::new(
            &[7; 32],
            &[11; 32],
            "verifier-v1".into(),
            "encrypt-v2".into(),
        )?;
        let envelope = prepare_rewrap(
            &RewrapKey::new(&[9; 32], "encrypt-v1".into())?,
            &RewrapKey::new(&[11; 32], "encrypt-v2".into())?,
            &identity,
            rewrap_source(&material),
        )?;
        assert_eq!(envelope.envelope_revision, 2);
        assert_eq!(envelope.encryption_version, "encrypt-v2");
        let token = decrypt_for_human(
            &next,
            &identity,
            &identity,
            envelope.envelope_revision,
            &envelope.encryption_version,
            envelope.nonce,
            &envelope.ciphertext,
        )?;
        assert_eq!(token, old_token);
        assert!(verify_managed(
            &lease(),
            &identity,
            &material.selector,
            &material.verifier,
            &material.verifier_version,
            &token,
        )?);
        assert!(
            decrypt_for_human(
                &next,
                &identity,
                &identity,
                1,
                "encrypt-v2",
                envelope.nonce,
                &envelope.ciphertext,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn rewrap_rejects_substitution_bad_aead_and_revision_exhaustion() -> Result<()> {
        let identity = identity();
        let material = prepare_managed(&lease(), identity.clone())?;
        let previous = RewrapKey::new(&[9; 32], "encrypt-v1".into())?;
        let next = RewrapKey::new(&[11; 32], "encrypt-v2".into())?;
        let mut foreign = identity.clone();
        foreign.security_epoch += 1;
        assert!(prepare_rewrap(&previous, &next, &foreign, rewrap_source(&material)).is_err());
        assert!(prepare_rewrap(&previous, &previous, &identity, rewrap_source(&material)).is_err());
        assert!(
            prepare_rewrap(
                &RewrapKey::new(&[9; 32], "wrong-version".into())?,
                &next,
                &identity,
                rewrap_source(&material),
            )
            .is_err()
        );
        assert!(
            prepare_rewrap(
                &RewrapKey::new(&[12; 32], "encrypt-v1".into())?,
                &next,
                &identity,
                rewrap_source(&material),
            )
            .is_err()
        );
        let mut ciphertext = material.ciphertext.clone();
        ciphertext[0] ^= 1;
        assert!(
            prepare_rewrap(
                &previous,
                &next,
                &identity,
                RewrapSource {
                    ciphertext: &ciphertext,
                    ..rewrap_source(&material)
                }
            )
            .is_err()
        );
        assert!(
            prepare_rewrap(
                &previous,
                &next,
                &identity,
                RewrapSource {
                    selector: "foreign-selector",
                    ..rewrap_source(&material)
                }
            )
            .is_err()
        );
        assert!(
            prepare_rewrap(
                &previous,
                &next,
                &identity,
                RewrapSource {
                    envelope_revision: u64::MAX,
                    ..rewrap_source(&material)
                }
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn rewrap_does_not_restamp_an_authenticated_foreign_payload_format() -> Result<()> {
        let identity = identity();
        let material = prepare_managed(&lease(), identity.clone())?;
        let mut nonce = [0; NONCE_BYTES];
        super::super::effects::fill_secret(&mut nonce)?;
        let mut ciphertext = b"foreign-payload-format-not-a-managed-token".to_vec();
        lease()
            .encryption_key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(identity.aad(1, "encrypt-v1")?),
                &mut ciphertext,
            )
            .map_err(|_| anyhow::anyhow!("fixture encryption failed"))?;
        assert!(
            prepare_rewrap(
                &RewrapKey::new(&[9; 32], "encrypt-v1".into())?,
                &RewrapKey::new(&[11; 32], "encrypt-v2".into())?,
                &identity,
                RewrapSource {
                    nonce,
                    ciphertext: &ciphertext,
                    ..rewrap_source(&material)
                },
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn changing_a_version_grant_cannot_retarget_its_verifier_or_envelope() -> Result<()> {
        let original = identity();
        let material = prepare_managed(&lease(), original.clone())?;
        let token = decrypt_for_human(
            &lease(),
            &original,
            &original,
            material.envelope_revision,
            &material.encryption_version,
            material.nonce,
            &material.ciphertext,
        )?;
        let mut changed = original.clone();
        changed.grant = GrantCeiling::derive(
            original.grant.client,
            "different-subject".into(),
            original.grant.audience,
            original.grant.roots,
        )?;
        assert!(!verify_managed(
            &lease(),
            &changed,
            &material.selector,
            &material.verifier,
            &material.verifier_version,
            &token
        )?);
        // Even a caller substituting both JSON identities cannot make the
        // original ciphertext authenticate the altered grant.
        assert!(
            decrypt_for_human(
                &lease(),
                &changed,
                &changed,
                material.envelope_revision,
                &material.encryption_version,
                material.nonce,
                &material.ciphertext
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn material_binds_all_identity_fields_and_exact_keys() {
        let identity = identity();
        let material = prepare_managed(&lease(), identity.clone()).unwrap();
        let token = decrypt_for_human(
            &lease(),
            &identity,
            &material.identity,
            material.envelope_revision,
            &material.encryption_version,
            material.nonce,
            &material.ciphertext,
        )
        .unwrap();
        assert_eq!(token_selector(&token).unwrap(), material.selector);
        assert!(
            verify_managed(
                &lease(),
                &identity,
                &material.selector,
                &material.verifier,
                &material.verifier_version,
                &token
            )
            .unwrap()
        );
        let mut wrong = identity.clone();
        wrong.lineage = "another-lineage".into();
        assert!(
            !verify_managed(
                &lease(),
                &wrong,
                &material.selector,
                &material.verifier,
                &material.verifier_version,
                &token
            )
            .unwrap()
        );
        assert!(
            verify_managed(
                &lease(),
                &identity,
                &material.selector,
                &material.verifier,
                "other-verifier",
                &token,
            )
            .is_err()
        );
        assert!(
            decrypt_for_human(
                &lease(),
                &wrong,
                &material.identity,
                material.envelope_revision,
                &material.encryption_version,
                material.nonce,
                &material.ciphertext
            )
            .is_err()
        );
        assert!(
            decrypt_for_human(
                &lease(),
                &identity,
                &material.identity,
                material.envelope_revision + 1,
                &material.encryption_version,
                material.nonce,
                &material.ciphertext
            )
            .is_err()
        );
        assert!(
            decrypt_for_human(
                &lease(),
                &identity,
                &material.identity,
                material.envelope_revision,
                "encrypt-v2",
                material.nonce,
                &material.ciphertext
            )
            .is_err()
        );
        let mut corrupt = material.ciphertext.clone();
        corrupt[0] ^= 1;
        assert!(
            decrypt_for_human(
                &lease(),
                &identity,
                &material.identity,
                material.envelope_revision,
                &material.encryption_version,
                material.nonce,
                &corrupt
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_malformed_tokens_without_exposing_secret() {
        for token in ["", "d2c1", "d2c1.x.y", "d2c1.x.y.z", "d2c0.x.y", "d2c1.!.!"] {
            assert!(token_selector(token).is_err());
        }
    }
}
