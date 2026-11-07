//! Closed wire DATA for exact-purpose approval signatures. Neither parsing nor
//! signature verification constructs VerifiedApproval, current registry trust,
//! a qualified UTC clock, durable single use or a native execution owner.
use super::{AdminIdentity, ApprovalRequest};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::Digest;
use ring::signature;
use serde::{Deserialize, Serialize};

const MAX_RECORD_BYTES: usize = 16_384;
const DOMAIN: &str = "day2-restore-approval-grant-ed25519-v1";

/// Signature input DATA. The actual producer must select the approver/key from
/// current reviewed config, freeze time at actual completion and retain every
/// owner through durable publication. A caller cannot do that by filling fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovalStatement {
    pub request: ApprovalRequest,
    pub approver: AdminIdentity,
    pub registry: Digest,
    pub credential: Digest,
    pub assertion: Digest,
    pub signing_key: Digest,
}

impl ApprovalStatement {
    pub(crate) fn validate(&self) -> Result<()> {
        self.request.validate()?;
        self.approver.validate()
    }

    /// Fixed algorithm and purpose; no arbitrary domain, payload or signer API.
    /// These bytes are not permission for any key or provider to sign them.
    pub(crate) fn signature_input_data(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(&(DOMAIN, self))?;
        ensure!(
            bytes.len() <= MAX_RECORD_BYTES,
            "restore_approval_signature_input_bound"
        );
        Ok(bytes)
    }
}

/// Untrusted transport DATA, including its key reference and fixed timestamps.
/// Single-use enforcement belongs to the actual external conditional consumer;
/// an intact signature, decoded record or historical receipt cannot supply it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedApprovalRecord {
    pub statement: ApprovalStatement,
    pub signature: String,
}

/// Public-key identity DATA only. An attacker can compute this same digest;
/// actual trust must come from the retained producer/consumer key source.
pub(crate) fn signing_key_id_data(public_key: &[u8; 32]) -> Result<Digest> {
    Digest::of(&("day2-restore-approval-ed25519-key-v1", public_key))
}

impl SignedApprovalRecord {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_RECORD_BYTES,
            "restore_approval_signed_record_bound"
        );
        let record: Self = crate::json::decode(bytes)
            .map_err(|_| anyhow::anyhow!("restore_approval_signed_record_encoding"))?;
        record.statement.signature_input_data()?;
        record.signature_bytes()?;
        Ok(record)
    }

    fn signature_bytes(&self) -> Result<Vec<u8>> {
        ensure!(
            self.signature.len() == 86,
            "restore_approval_signature_encoding"
        );
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| anyhow::anyhow!("restore_approval_signature_encoding"))?;
        ensure!(
            bytes.len() == 64 && URL_SAFE_NO_PAD.encode(&bytes) == self.signature,
            "restore_approval_signature_encoding"
        );
        Ok(bytes)
    }

    /// Checks cryptographic DATA against an exact expected statement and key.
    /// It authenticates neither argument. No accepting owner is returned, and
    /// this cannot replace current registry, clock, executor or single-use checks.
    pub(crate) fn verify_signature_data(
        &self,
        expected: &ApprovalStatement,
        public_key: &[u8; 32],
    ) -> Result<()> {
        self.statement.validate()?;
        expected.validate()?;
        ensure!(
            &self.statement == expected,
            "restore_approval_signed_statement_changed"
        );
        ensure!(
            expected.signing_key == signing_key_id_data(public_key)?,
            "restore_approval_signing_key_changed"
        );
        signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
            .verify(
                &self.statement.signature_input_data()?,
                &self.signature_bytes()?,
            )
            .map_err(|_| anyhow::anyhow!("restore_approval_signature_refused"))
    }
}

#[cfg(test)]
mod tests;
