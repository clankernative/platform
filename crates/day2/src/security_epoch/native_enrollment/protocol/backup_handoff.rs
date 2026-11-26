//! Fixed pending/recipient/ACK comparison DATA. This module owns no socket,
//! process, native original, source, completion page or upload permission.
//! Successful decoding/signature comparison never constructs those owners.
use super::{EnrollmentPolicy, IssuerCertificate, decode_key, verify};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};

// The largest complete typed packet is the pending statement (fixed 368-byte
// envelope encoded in 491 URL-safe bytes). The maximal fixture pins this bound;
// this does not increase the existing native packet/rights or serving limits.
const MAX_DATA_BYTES: usize = 1024;
const PENDING_PURPOSE: &str = "scheduled-backup-pending-completion-v1";
const COMPARISON_PURPOSE: &str = "scheduled-backup-recipient-comparison-v1";

/// Owned public bytes only. They must ultimately come from the actual retained
/// FreshPage; this DATA constructor is NOT proof that a caller created a page.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(in crate::security_epoch::native_enrollment) struct EnvelopeData(String);

impl EnvelopeData {
    pub(in crate::security_epoch::native_enrollment) fn from_bytes_data(
        bytes: [u8; day2_completion_page::FRAME_BYTES],
    ) -> Self {
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }
}

impl TryFrom<String> for EnvelopeData {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        let mut bytes = [0; day2_completion_page::FRAME_BYTES];
        ensure!(
            value.len() == 491
                && URL_SAFE_NO_PAD.decode_slice(&value, &mut bytes).ok() == Some(bytes.len())
                && URL_SAFE_NO_PAD.encode(bytes) == value,
            "backup_completion_envelope_data"
        );
        Ok(Self(value))
    }
}

impl From<EnvelopeData> for String {
    fn from(value: EnvelopeData) -> Self {
        value.0
    }
}

/// The actual creator's pending-only statement. It does not predict Known or
/// attest any later post. The complete envelope already binds the intent,
/// image, destination, connection, nonces, operation and original commitment.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct PendingData {
    pub issuer: Digest,
    pub policy: Digest,
    pub controller_key: String,
    pub envelope: EnvelopeData,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct SignedPendingData {
    pub data: PendingData,
    pub signature: String,
}

impl SignedPendingData {
    /// Comparison only. Expected key/envelope must be derived by the actual
    /// retained creator/receiver path, never selected from this same packet.
    pub(in crate::security_epoch::native_enrollment) fn verify_data(
        &self,
        policy: &EnrollmentPolicy,
        held_certificate: &IssuerCertificate,
        expected_key: &str,
        expected_envelope: &EnvelopeData,
    ) -> Result<()> {
        held_certificate.verify(policy)?;
        ensure!(policy.scheduled_backup.is_some(), "backup_requester_disabled");
        decode_key(expected_key)?;
        ensure!(
            self.data.issuer == held_certificate.digest()?
                && self.data.policy == policy.digest()?
                && self.data.controller_key == expected_key
                && &self.data.envelope == expected_envelope,
            "backup_pending_data_changed"
        );
        verify(expected_key, PENDING_PURPOSE, &self.data, &self.signature)
    }

    pub(in crate::security_epoch::native_enrollment) fn digest_data(&self) -> Result<Digest> {
        Digest::of(&("day2-backup-pending-completion-data-v1", self))
    }
}

/// Signed comparison for the frozen Pending-transfer set, not for the later
/// reply's actor. The request commitment is the actual fixed courier request;
/// the same retained receiver must also keep its real connector/message files.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct RecipientData {
    pub issuer: Digest,
    pub policy: Digest,
    pub pending: Digest,
    pub courier_request: Digest,
    pub receiver_challenge: Digest,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct SignedRecipientData {
    pub data: RecipientData,
    pub signature: String,
}

impl SignedRecipientData {
    /// The caller passes the SAME actual Controller-held certificate cohort,
    /// not a certificate selected by this reply or merely the configured root.
    /// No native owner, creator proof or upload disposition is returned.
    pub(in crate::security_epoch::native_enrollment) fn verify_data(
        &self,
        policy: &EnrollmentPolicy,
        held_certificate: &IssuerCertificate,
        pending: &SignedPendingData,
        expected: (&PendingData, &Digest, &Digest),
    ) -> Result<()> {
        let (expected_pending, expected_request, expected_challenge) = expected;
        pending.verify_data(
            policy,
            held_certificate,
            &expected_pending.controller_key,
            &expected_pending.envelope,
        )?;
        ensure!(
            pending.data == *expected_pending
                && self.data.issuer == held_certificate.digest()?
                && pending.data.issuer == self.data.issuer
                && self.data.policy == policy.digest()?
                && pending.data.policy == self.data.policy
                && self.data.pending == pending.digest_data()?
                && &self.data.courier_request == expected_request
                && &self.data.receiver_challenge == expected_challenge,
            "backup_recipient_comparison_changed"
        );
        verify(
            &held_certificate.data.public_key,
            COMPARISON_PURPOSE,
            &self.data,
            &self.signature,
        )
    }

    pub(in crate::security_epoch::native_enrollment) fn digest_data(&self) -> Result<Digest> {
        Digest::of(&("day2-backup-recipient-comparison-data-v1", self))
    }
}

/// Fixed same-action ACK DATA. The real Controller must authenticate its
/// actual Job message before final posts/retirement/CAS. A matching value or
/// digest alone can neither perform those checks nor acknowledge future work.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct ReceiverAckData {
    pub pending: Digest,
    pub comparison: Digest,
    pub courier_request: Digest,
    pub receiver_challenge: Digest,
}

impl ReceiverAckData {
    pub(in crate::security_epoch::native_enrollment) fn require_exact_data(
        &self,
        pending: &SignedPendingData,
        comparison: &SignedRecipientData,
    ) -> Result<()> {
        ensure!(
            self.pending == pending.digest_data()?
                && self.comparison == comparison.digest_data()?
                && self.pending == comparison.data.pending
                && self.courier_request == comparison.data.courier_request
                && self.receiver_challenge == comparison.data.receiver_challenge,
            "backup_receiver_ack_data_changed"
        );
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) enum PacketData {
    Pending { pending: SignedPendingData },
    Comparison { comparison: SignedRecipientData },
    Ack { ack: ReceiverAckData },
}

impl PacketData {
    pub(in crate::security_epoch::native_enrollment) fn encode_data(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        ensure!(bytes.len() <= MAX_DATA_BYTES, "backup_handoff_data_bound");
        Ok(bytes)
    }
}

/// Bounded DATA decoding only; signature/expected-resource comparisons remain
/// mandatory and separate. Foreign decoder messages are never retained.
pub(in crate::security_epoch::native_enrollment) fn decode_data(bytes: &[u8]) -> Result<PacketData> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_DATA_BYTES,
        "backup_handoff_data_bound"
    );
    let value: serde_json::Value = crate::json::decode(bytes)
        .map_err(|_| anyhow::anyhow!("backup_handoff_data_wire"))?;
    ensure!(value.is_object(), "backup_handoff_data_map");
    let records: &[&str] = match value.get("kind").and_then(serde_json::Value::as_str) {
        Some("pending") => &["/pending", "/pending/data"],
        Some("comparison") => &["/comparison", "/comparison/data"],
        Some("ack") => &["/ack"],
        _ => anyhow::bail!("backup_handoff_data_kind"),
    };
    ensure!(
        records.iter().all(|path| value.pointer(path).is_some_and(serde_json::Value::is_object)),
        "backup_handoff_data_map"
    );
    serde_json::from_value(value).map_err(|_| anyhow::anyhow!("backup_handoff_data_wire"))
}

#[cfg(test)]
mod tests;
