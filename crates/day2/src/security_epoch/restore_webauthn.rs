//! Closed ES256 assertion profile for restore approval. Successful verification
//! returns DATA, not approval, current authority, delivery or a native owner.
//! The only production key origin borrows a real native registry-read owner.
//! Signing, durable grant consumption and post-fence approval remain separate.
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::Digest;
use ring::{
    digest::{SHA256, digest},
    signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey},
};
use serde::Deserialize;

const MAX_CLIENT_DATA: usize = 4096;
const MAX_CREDENTIAL_ID: usize = 1023;
const USER_PRESENT: u8 = 0x01;
const USER_VERIFIED: u8 = 0x04;
const BACKUP_ELIGIBLE: u8 = 0x08;
const BACKED_UP: u8 = 0x10;
const SUPPORTED_FLAGS: u8 = USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE | BACKED_UP;

/// Exact admitted registry selection, not a browser-supplied key. A future
/// registry owner must retain current admin membership and this exact version.
/// Private fields and a scoped native registry source prevent scalar minting.
pub(super) struct TrustedKey<'owner> {
    record: KeyRecord,
    source: KeySource<'owner>,
}

enum KeySource<'owner> {
    Registry(registry::Origin<'owner>),
    #[cfg(test)]
    Fixture,
}

#[derive(Clone, PartialEq, Eq)]
struct KeyRecord {
    admin: Digest,
    registry: Digest,
    revision: u64,
    credential_id: Vec<u8>,
    user_handle: Vec<u8>,
    public_key: Vec<u8>,
    rp_id: String,
    origin: String,
    backup_eligible: bool,
}

impl TrustedKey<'_> {
    fn validate(&self) -> Result<()> {
        // The source is not a bool, public trait, deserializable proof or
        // production default. Reading record DATA never supplies that source.
        match &self.source {
            KeySource::Registry(source) => source.check_local()?,
            #[cfg(test)]
            KeySource::Fixture => (),
        }
        let row = &self.record;
        ensure!(
            row.revision > 0
                && (1..=MAX_CREDENTIAL_ID).contains(&row.credential_id.len())
                && (1..=64).contains(&row.user_handle.len())
                && row.public_key.len() == 65
                && row.public_key[0] == 4,
            "restore_passkey_invalid_enrollment"
        );
        let origin = url::Url::parse(&row.origin)
            .map_err(|_| anyhow::anyhow!("restore_passkey_invalid_origin"))?;
        ensure!(
            origin.scheme() == "https"
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.path() == "/"
                && origin.origin().ascii_serialization() == row.origin
                && origin.host_str() == Some(row.rp_id.as_str())
                && matches!(origin.host(), Some(url::Host::Domain(_))),
            "restore_passkey_invalid_origin_or_rp"
        );
        Ok(())
    }

    fn binding(&self) -> Result<Digest> {
        self.validate()?;
        self.record.binding_data()
    }
}

impl KeyRecord {
    // Commitment DATA only. Only the scoped source validates current authority.
    fn binding_data(&self) -> Result<Digest> {
        let row = self;
        Digest::of(&(
            "day2-restore-passkey-enrollment-v1",
            &row.admin,
            &row.registry,
            row.revision,
            &row.credential_id,
            &row.user_handle,
            &row.public_key,
            &row.rp_id,
            &row.origin,
            row.backup_eligible,
        ))
    }
}

/// Server-owned request DATA. Registry capture obtains actual entropy under
/// its current native owner. This is not a durable grant or approval.
/// The exact request digest includes archive, target, epoch and executor.
#[derive(Clone)]
pub(super) struct Challenge {
    request: Digest,
    nonce: [u8; 32],
    enrollment: Digest,
}

impl Challenge {
    fn encoded(&self) -> Result<String> {
        let bytes = serde_json::to_vec(&(
            "day2-restore-webauthn-challenge-v1",
            &self.request,
            &self.nonce,
            &self.enrollment,
        ))?;
        Ok(URL_SAFE_NO_PAD.encode(digest(&SHA256, &bytes)))
    }
}

/// Bounded decoded transport DATA only. These bytes do not select a trusted key.
#[derive(Clone)]
pub(super) struct Assertion {
    credential_id: Vec<u8>,
    client_data_json: Vec<u8>,
    authenticator_data: Vec<u8>,
    signature: Vec<u8>,
    user_handle: Option<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(default, rename = "crossOrigin")]
    cross_origin: bool,
}

/// Signature/counter facts only. The durable challenge and counter transition
/// must commit atomically before a future owner can act on these observations.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct AssertionFacts {
    counter: u32,
    backed_up: bool,
}

/// Closed rejection of untrusted assertion bytes. Native/source failures and
/// server challenge/enrollment mismatches deliberately never use this type.
#[derive(Debug)]
enum AssertionDenied {
    ShapeOrIdentity,
    ClientData,
    ClientBinding,
    RelyingParty,
    UserVerification,
    Counter,
}

impl std::fmt::Display for AssertionDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ShapeOrIdentity => "restore_passkey_assertion_shape_or_identity",
            Self::ClientData => "restore_passkey_invalid_client_data",
            Self::ClientBinding => "restore_passkey_client_binding_changed",
            Self::RelyingParty => "restore_passkey_rp_changed",
            Self::UserVerification => "restore_passkey_flags_or_verification_changed",
            Self::Counter => "restore_passkey_counter_not_advanced",
        })
    }
}

impl std::error::Error for AssertionDenied {}

pub(super) fn verify(
    key: &TrustedKey<'_>,
    challenge: &Challenge,
    expected_request: &Digest,
    stored_counter: u32,
    assertion: &Assertion,
) -> Result<AssertionFacts> {
    ensure!(
        challenge.request == *expected_request && challenge.enrollment == key.binding()?,
        "restore_passkey_challenge_binding_changed"
    );
    let row = &key.record;
    ensure!(
        assertion.credential_id == row.credential_id
            && assertion
                .user_handle
                .as_ref()
                .is_none_or(|handle| handle == &row.user_handle)
            && (1..=MAX_CLIENT_DATA).contains(&assertion.client_data_json.len())
            && assertion.authenticator_data.len() == 37
            && (8..=72).contains(&assertion.signature.len()),
        AssertionDenied::ShapeOrIdentity
    );
    let value: serde_json::Value = crate::json::decode(&assertion.client_data_json)
        .map_err(|_| anyhow::anyhow!(AssertionDenied::ClientData))?;
    ensure!(value.is_object(), AssertionDenied::ClientData);
    let client: ClientData =
        serde_json::from_value(value).map_err(|_| anyhow::anyhow!(AssertionDenied::ClientData))?;
    ensure!(
        client.kind == "webauthn.get"
            && client.challenge == challenge.encoded()?
            && client.origin == row.origin
            && !client.cross_origin,
        AssertionDenied::ClientBinding
    );
    let auth = &assertion.authenticator_data;
    ensure!(
        &auth[..32] == digest(&SHA256, row.rp_id.as_bytes()).as_ref(),
        AssertionDenied::RelyingParty
    );
    let flags = auth[32];
    let backup_eligible = flags & BACKUP_ELIGIBLE != 0;
    let backed_up = flags & BACKED_UP != 0;
    ensure!(
        flags & (USER_PRESENT | USER_VERIFIED) == USER_PRESENT | USER_VERIFIED
            && flags & !SUPPORTED_FLAGS == 0
            && backup_eligible == row.backup_eligible
            && (!backed_up || backup_eligible),
        AssertionDenied::UserVerification
    );
    let counter = u32::from_be_bytes(auth[33..37].try_into()?);
    // Synced passkeys may have no counter. The durable one-use challenge is
    // their replay barrier. A positive counter can never be reset or repeated.
    ensure!(
        (stored_counter == 0 && counter == 0) || counter > stored_counter,
        AssertionDenied::Counter
    );
    let mut signed = Vec::with_capacity(69);
    signed.extend_from_slice(auth);
    signed.extend_from_slice(digest(&SHA256, &assertion.client_data_json).as_ref());
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &row.public_key)
        .verify(&signed, &assertion.signature)
        // Ring does not distinguish a bad signature from an invalid configured
        // curve point. Keep that ambiguous cryptographic failure terminal.
        .map_err(|_| anyhow::anyhow!("restore_passkey_signature_invalid"))?;
    Ok(AssertionFacts { counter, backed_up })
}

mod registry;
pub(super) use registry::ControllerCeremony;
mod store;
#[cfg(test)]
mod tests;
