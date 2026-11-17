//! Bounded, domain-separated protected-restore packet DATA. Decoding, a valid
//! signature, or a connection digest never supplies native admission. The fixed
//! channel must independently retain the actual admitted peer and sender handles.

use super::super::{protocol::StagePurpose, storage_peer_wire::OriginalInterval};
use super::{MAX_ASSERTION_BYTES, MAX_INPUT_BYTES, ProtectedRestoreReply, ProtectedRestoreRequest};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};

// The maximal DATA packet is tested with all fields and a 32 KiB payload.
// Base64 keeps the bounded outer decoder below its normal JSON node budget;
// serializing Vec<u8> as a JSON array would exceed it at this admitted size.
// This bound does not change protocol::MAX_PACKET for existing serving traffic.
pub(in crate::security_epoch::native_enrollment) const MAX_PACKET_BYTES: usize = 48 * 1024;
const SIGNATURE_BYTES: usize = 64;
const SIGNATURE_TEXT_BYTES: usize = 86;
pub(super) const SIGNING_DOMAIN: &str = "day2-protected-restore-packet-v1";

#[derive(Serialize, Deserialize)]
enum Format {
    #[serde(rename = "day2_protected_restore_packet_v1")]
    V1,
}

/// All fields remain untrusted DATA. No method returns a native peer, turn,
/// original, permission or authenticated session, including after verification.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct UnverifiedPacket {
    data: Data,
    signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct Data {
    format: Format,
    connection: Digest,
    // Commitment to the actual connection's selected enrollment, not a new
    // certificate or an identity accepted merely because it appears here.
    sender: Digest,
    sequence: u64,
    // Fresh sender request DATA, not the historical admission interval or a
    // receiver clock. The actual signer must match this to its own original.
    original: OriginalInterval,
    body: Body,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Body {
    BeginApproval { input: String },
    Approve { id: Digest, assertion: String },
    BeginExecution { id: Digest },
    Authenticate { id: Digest, assertion: String },
    Abandon { id: Digest },
    ApprovalPrompt { id: Digest, prompt: String },
    ApprovalRecorded { commitment: Digest },
    ExecutionPrompt { id: Digest, prompt: String },
    Abandoned {},
    Refused {},
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Direction {
    Request,
    Reply,
}

impl Body {
    fn direction(&self) -> Direction {
        match self {
            Self::BeginApproval { .. }
            | Self::Approve { .. }
            | Self::BeginExecution { .. }
            | Self::Authenticate { .. }
            | Self::Abandon { .. } => Direction::Request,
            Self::ApprovalPrompt { .. }
            | Self::ApprovalRecorded { .. }
            | Self::ExecutionPrompt { .. }
            | Self::Abandoned {}
            | Self::Refused {} => Direction::Reply,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::BeginApproval { input } => {
                decode_bytes(input, MAX_INPUT_BYTES)?;
            }
            Self::Approve { assertion, .. } | Self::Authenticate { assertion, .. } => {
                decode_bytes(assertion, MAX_ASSERTION_BYTES)?;
            }
            Self::ApprovalPrompt { prompt, .. } | Self::ExecutionPrompt { prompt, .. } => {
                decode_bytes(prompt, MAX_INPUT_BYTES)?;
            }
            Self::BeginExecution { .. }
            | Self::Abandon { .. }
            | Self::ApprovalRecorded { .. }
            | Self::Abandoned {}
            | Self::Refused {} => {}
        }
        Ok(())
    }
}

fn decode_bytes(encoded: &str, limit: usize) -> Result<Vec<u8>> {
    // Check text length before allocating decoded storage. For the fixed
    // profile limits this expression cannot overflow.
    ensure!(
        !encoded.is_empty() && encoded.len() <= (limit * 8).div_ceil(6),
        "protected_restore_wire_payload_bound"
    );
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| anyhow::anyhow!("protected_restore_wire_payload_encoding"))?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= limit && URL_SAFE_NO_PAD.encode(&bytes) == encoded,
        "protected_restore_wire_payload_encoding"
    );
    Ok(bytes)
}

pub(super) fn signature_shape(signature: &str) -> Result<()> {
    ensure!(
        signature.len() == SIGNATURE_TEXT_BYTES,
        "protected_restore_wire_signature_shape"
    );
    let bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| anyhow::anyhow!("protected_restore_wire_signature_shape"))?;
    ensure!(
        bytes.len() == SIGNATURE_BYTES && URL_SAFE_NO_PAD.encode(&bytes) == signature,
        "protected_restore_wire_signature_shape"
    );
    Ok(())
}

impl Data {
    /// Authenticated only after verify_data and the actual retained sender
    /// checks. This immutable DATA cannot sample or construct a local clock.
    pub(super) fn original(&self) -> &OriginalInterval {
        &self.original
    }

    /// Cursor DATA only, distinct from the serving/storage protocols. The
    /// actual native receiver still validates every signed field and sender.
    pub(in crate::security_epoch::native_enrollment) fn frame(
        &self,
    ) -> super::super::handshake::Frame {
        use super::super::handshake::{Frame, Protocol, Step};
        Frame {
            protocol: Protocol::ProtectedRestoreCommand,
            step: match self.body.direction() {
                Direction::Request => Step::Hello,
                Direction::Reply => Step::Complete,
            },
            sequence: Some(self.sequence),
        }
    }

    /// Structural DATA validation only: no time sample, common-clock proof,
    /// native admission or replay permission follows from this predicate.
    fn validate(&self) -> Result<()> {
        ensure!(
            self.original.purpose == StagePurpose::CurrentRole
                && self.original.deadline_ns > self.original.origin_ns
                && u128::from(self.original.deadline_ns - self.original.origin_ns)
                    <= StagePurpose::CurrentRole.limit().as_nanos(),
            "protected_restore_wire_original_shape"
        );
        self.body.validate()
    }

    /// Bind every actual field and payload byte while leaving the existing
    /// enrollment signature framing below its unchanged 8 KiB limit.
    pub(super) fn commitment(&self) -> Result<Digest> {
        Digest::of(&(SIGNING_DOMAIN, self))
    }

    /// Exact local signer identity, direction and fresh original DATA. The
    /// caller must obtain the interval from its actual checked local stage,
    /// never the historical admission. Receiver admission, common-clock
    /// qualification, current expiry and replay checks remain independent.
    pub(super) fn require_sender(
        &self,
        sender: &Digest,
        original: &OriginalInterval,
        direction: Direction,
    ) -> Result<()> {
        ensure!(
            self.original == *original,
            "protected_restore_wire_sender_original_changed"
        );
        self.require_binding(&self.connection, sender, self.sequence, direction)
    }

    pub(super) fn request(
        connection: Digest,
        sender: Digest,
        sequence: u64,
        original: OriginalInterval,
        request: ProtectedRestoreRequest,
    ) -> Result<Self> {
        request.validate_data()?;
        let body = match request {
            ProtectedRestoreRequest::BeginApproval { input } => Body::BeginApproval {
                input: URL_SAFE_NO_PAD.encode(input),
            },
            ProtectedRestoreRequest::Approve { id, assertion } => Body::Approve {
                id,
                assertion: URL_SAFE_NO_PAD.encode(assertion),
            },
            ProtectedRestoreRequest::BeginExecution { id } => Body::BeginExecution { id },
            ProtectedRestoreRequest::Authenticate { id, assertion } => Body::Authenticate {
                id,
                assertion: URL_SAFE_NO_PAD.encode(assertion),
            },
            ProtectedRestoreRequest::Abandon { id } => Body::Abandon { id },
        };
        let data = Self {
            format: Format::V1,
            connection,
            sender,
            sequence,
            original,
            body,
        };
        data.validate()?;
        Ok(data)
    }

    pub(super) fn reply(
        connection: Digest,
        sender: Digest,
        sequence: u64,
        original: OriginalInterval,
        reply: ProtectedRestoreReply,
    ) -> Result<Self> {
        reply.validate_data()?;
        let body = match reply {
            ProtectedRestoreReply::ApprovalPrompt { id, prompt } => Body::ApprovalPrompt {
                id,
                prompt: URL_SAFE_NO_PAD.encode(prompt),
            },
            ProtectedRestoreReply::ApprovalRecorded { commitment } => {
                Body::ApprovalRecorded { commitment }
            }
            ProtectedRestoreReply::ExecutionPrompt { id, prompt } => Body::ExecutionPrompt {
                id,
                prompt: URL_SAFE_NO_PAD.encode(prompt),
            },
            ProtectedRestoreReply::Abandoned => Body::Abandoned {},
            ProtectedRestoreReply::Refused => Body::Refused {},
        };
        let data = Self {
            format: Format::V1,
            connection,
            sender,
            sequence,
            original,
            body,
        };
        data.validate()?;
        Ok(data)
    }

    /// Selection DATA only. The actual native channel must supply the expected
    /// bindings from its retained peer, not by copying fields from this packet.
    pub(super) fn require_binding(
        &self,
        connection: &Digest,
        sender: &Digest,
        sequence: u64,
        direction: Direction,
    ) -> Result<()> {
        ensure!(
            self.connection == *connection
                && self.sender == *sender
                && self.sequence == sequence
                && self.body.direction() == direction,
            "protected_restore_wire_binding_changed"
        );
        self.validate()
    }

    pub(super) fn into_request(self) -> Result<ProtectedRestoreRequest> {
        Ok(match self.body {
            Body::BeginApproval { input } => ProtectedRestoreRequest::BeginApproval {
                input: decode_bytes(&input, MAX_INPUT_BYTES)?,
            },
            Body::Approve { id, assertion } => ProtectedRestoreRequest::Approve {
                id,
                assertion: decode_bytes(&assertion, MAX_ASSERTION_BYTES)?,
            },
            Body::BeginExecution { id } => ProtectedRestoreRequest::BeginExecution { id },
            Body::Authenticate { id, assertion } => ProtectedRestoreRequest::Authenticate {
                id,
                assertion: decode_bytes(&assertion, MAX_ASSERTION_BYTES)?,
            },
            Body::Abandon { id } => ProtectedRestoreRequest::Abandon { id },
            _ => anyhow::bail!("protected_restore_wire_request_required"),
        })
    }

    pub(super) fn into_reply(self) -> Result<ProtectedRestoreReply> {
        Ok(match self.body {
            Body::ApprovalPrompt { id, prompt } => ProtectedRestoreReply::ApprovalPrompt {
                id,
                prompt: decode_bytes(&prompt, MAX_INPUT_BYTES)?,
            },
            Body::ApprovalRecorded { commitment } => {
                ProtectedRestoreReply::ApprovalRecorded { commitment }
            }
            Body::ExecutionPrompt { id, prompt } => ProtectedRestoreReply::ExecutionPrompt {
                id,
                prompt: decode_bytes(&prompt, MAX_INPUT_BYTES)?,
            },
            Body::Abandoned {} => ProtectedRestoreReply::Abandoned,
            Body::Refused {} => ProtectedRestoreReply::Refused,
            _ => anyhow::bail!("protected_restore_wire_reply_required"),
        })
    }
}

impl UnverifiedPacket {
    /// Unverified cursor DATA only, never sender authentication or completion.
    pub(in crate::security_epoch::native_enrollment) fn frame(
        &self,
    ) -> super::super::handshake::Frame {
        self.data.frame()
    }

    /// Formatting DATA for the fixed future sender. Accepting these inputs is
    /// not a signature or native authority proof. The actual supplier must use
    /// its retained enrolled key and SIGNING_DOMAIN, then verify both on receive.
    pub(in crate::security_epoch::native_enrollment) fn encode(
        data: Data,
        signature: String,
    ) -> Result<Vec<u8>> {
        data.validate()?;
        signature_shape(&signature)?;
        let bytes = serde_json::to_vec(&Self { data, signature })?;
        ensure!(
            bytes.len() <= MAX_PACKET_BYTES,
            "protected_restore_wire_packet_bound"
        );
        Ok(bytes)
    }

    pub(in crate::security_epoch::native_enrollment) fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_PACKET_BYTES,
            "protected_restore_wire_packet_bound"
        );
        let value: serde_json::Value = crate::json::decode(bytes)
            .map_err(|_| anyhow::anyhow!("protected_restore_wire_packet_encoding"))?;
        Self::from_value(value)
    }

    // Serde's derived struct deserializer can also accept sequences. This
    // profile has exactly object-shaped envelopes, data and tagged bodies;
    // require that shape before conversion can normalize an array into fields.
    fn from_value(value: serde_json::Value) -> Result<Self> {
        ensure!(
            value.is_object()
                && value.get("data").is_some_and(serde_json::Value::is_object)
                && value
                    .get("data")
                    .and_then(|data| data.get("original"))
                    .is_some_and(serde_json::Value::is_object)
                && value
                    .get("data")
                    .and_then(|data| data.get("format"))
                    .is_some_and(serde_json::Value::is_string)
                && value
                    .get("data")
                    .and_then(|data| data.get("body"))
                    .is_some_and(serde_json::Value::is_object),
            "protected_restore_wire_object_required"
        );
        let packet: Self = serde_json::from_value(value)
            .map_err(|_| anyhow::anyhow!("protected_restore_wire_packet_encoding"))?;
        signature_shape(&packet.signature)?;
        packet.data.validate()?;
        Ok(packet)
    }

    /// Pure signature verification still yields only DATA. It does not check
    /// process liveness, sender handles, role, current policy or any original.
    pub(super) fn verify_data(self, public_key: &str) -> Result<Data> {
        super::super::protocol::verify(
            public_key,
            SIGNING_DOMAIN,
            &self.data.commitment()?,
            &self.signature,
        )?;
        Ok(self.data)
    }
}

#[cfg(test)]
mod tests;
