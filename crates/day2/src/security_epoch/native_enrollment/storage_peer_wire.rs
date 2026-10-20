//! Purpose-bound initial-holder wire DATA. None of these values can adopt a
//! native stage, process handle, prepared file, first holder or writer.

use super::{
    NativeRole,
    policy::{EnrollmentPolicy, decode_key},
    protocol::{self, IssuerCertificate, ProcessData, SignedStage},
};
use crate::security_epoch::PreparedFileProjection;
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct OriginalInterval {
    pub domain: Digest,
    pub origin_ns: u64,
    pub deadline_ns: u64,
}

impl OriginalInterval {
    pub(super) fn validate(&self, now: Duration, issuer_deadline_ns: u64) -> Result<()> {
        let origin = Duration::from_nanos(self.origin_ns);
        let deadline = Duration::from_nanos(self.deadline_ns);
        ensure!(
            origin <= now
                && now < deadline
                && deadline > origin
                && deadline - origin <= Duration::from_secs(5)
                && self.deadline_ns <= issuer_deadline_ns,
            "storage_peer_original_interval"
        );
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct StageStatement {
    pub certificate: IssuerCertificate,
    pub stage: SignedStage,
    pub original: OriginalInterval,
}

impl StageStatement {
    pub(in crate::security_epoch::native_enrollment) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-initial-holder-stage-v1", self))
    }

    /// Validate DATA against the actual message process and local issuer. The
    /// native caller must retain/recheck those owners and the original clock;
    /// this helper itself returns no peer or current permission.
    pub(in crate::security_epoch::native_enrollment) fn validate(
        &self,
        policy: &EnrollmentPolicy,
        local_issuer: &IssuerCertificate,
        expected_role: NativeRole,
        message_process: &ProcessData,
        now: Duration,
    ) -> Result<()> {
        ensure!(
            self.stage.data.process == *message_process,
            "storage_peer_message_process_changed"
        );
        self.validate_sender(
            policy,
            local_issuer,
            expected_role,
            message_process.process,
            now,
        )
    }

    /// Controller observations belong to the actual trusted issuer: the App
    /// has no ptrace/containerd privilege over that privileged process. The
    /// native caller additionally owns the received sender pidfd, verifies the
    /// fresh transcript/key possession and retains the same live issuer.
    pub(in crate::security_epoch::native_enrollment) fn validate_attested_controller(
        &self,
        policy: &EnrollmentPolicy,
        local_issuer: &IssuerCertificate,
        kernel_process: u32,
        now: Duration,
    ) -> Result<()> {
        self.validate_sender(
            policy,
            local_issuer,
            NativeRole::EpochController,
            kernel_process,
            now,
        )
    }

    fn validate_sender(
        &self,
        policy: &EnrollmentPolicy,
        local_issuer: &IssuerCertificate,
        expected_role: NativeRole,
        kernel_process: u32,
        now: Duration,
    ) -> Result<()> {
        self.certificate.verify(policy)?;
        ensure!(
            self.certificate == *local_issuer
                && self.stage.data.issuer == self.certificate.digest()?
                && self.stage.data.policy == policy.digest()?
                && self.stage.data.role == expected_role
                && self.stage.data.process.process == kernel_process
                && self.stage.data.process.code == *policy.code(expected_role),
            "storage_peer_role_issuer_process"
        );
        decode_key(&self.stage.data.public_key)?;
        let origin = Duration::from_nanos(self.stage.data.origin_ns);
        let deadline = Duration::from_nanos(self.stage.data.deadline_ns);
        ensure!(
            origin <= now
                && now < deadline
                && deadline > origin
                && deadline - origin <= Duration::from_secs(5),
            "storage_peer_signed_stage_interval"
        );
        ensure!(
            self.original.origin_ns <= self.stage.data.origin_ns,
            "storage_peer_original_origin_changed"
        );
        self.original.validate(now, self.stage.data.deadline_ns)?;
        protocol::verify(
            &self.certificate.data.public_key,
            "role-stage",
            &self.stage.data,
            &self.stage.signature,
        )
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct Exchange {
    pub app_stage: Digest,
    pub controller_stage: Digest,
    pub app_nonce: Digest,
    pub controller_nonce: Digest,
    pub projection: Digest,
}

impl Exchange {
    pub(super) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-initial-holder-exchange-v1", self))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) enum Body {
    Hello {
        app: Box<StageStatement>,
        nonce: Digest,
    },
    Offer {
        controller: Box<StageStatement>,
        exchange: Exchange,
        projection: Box<PreparedFileProjection>,
    },
    Confirm {
        exchange: Digest,
        projection: Digest,
    },
    Complete {
        exchange: Digest,
    },
    Accepted {
        exchange: Digest,
    },
}

impl Body {
    pub(in crate::security_epoch::native_enrollment) fn sender_role(&self) -> NativeRole {
        match self {
            Self::Hello { .. } | Self::Confirm { .. } | Self::Accepted { .. } => {
                NativeRole::AppHost
            }
            Self::Offer { .. } | Self::Complete { .. } => NativeRole::EpochController,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct Message {
    pub sender: Digest,
    pub body: Body,
    pub signature: String,
}

impl Message {
    pub(super) fn verify(&self, statement: &StageStatement) -> Result<()> {
        ensure!(
            self.sender == statement.digest()?
                && self.body.sender_role() == statement.stage.data.role,
            "storage_peer_message_sender"
        );
        protocol::verify(
            &statement.stage.data.public_key,
            "initial-storage-message",
            &(&self.sender, &self.body),
            &self.signature,
        )
    }
}

/// The fixed boundary rejects struct-as-sequence JSON as well as duplicate,
/// unknown and oversized fields. Namespace identities alone intentionally use
/// typed two-element tuples; no native owner is decoded from this DATA.
pub(super) fn decode(bytes: &[u8]) -> Result<Message> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= protocol::MAX_PACKET,
        "storage_peer_packet_bound"
    );
    let value: serde_json::Value = crate::json::decode(bytes)?;
    require_object(&value, "")?;
    require_object(&value, "/body")?;
    match value
        .pointer("/body/step")
        .and_then(serde_json::Value::as_str)
    {
        Some("hello") => require_stage_objects(&value, "/body/app")?,
        Some("offer") => {
            require_stage_objects(&value, "/body/controller")?;
            for path in [
                "/body/exchange",
                "/body/projection",
                "/body/projection/core",
                "/body/projection/core/scope",
                "/body/projection/core/incarnations",
                "/body/projection/marker",
                "/body/projection/identity",
            ] {
                require_object(&value, path)?;
            }
        }
        Some("confirm" | "complete" | "accepted") => {}
        _ => anyhow::bail!("storage_peer_step"),
    }
    Ok(serde_json::from_value(value)?)
}

fn require_object(value: &serde_json::Value, path: &str) -> Result<()> {
    ensure!(
        value
            .pointer(path)
            .is_some_and(serde_json::Value::is_object),
        "storage_peer_record_object_required"
    );
    Ok(())
}

fn require_stage_objects(value: &serde_json::Value, prefix: &str) -> Result<()> {
    for suffix in [
        "",
        "/certificate",
        "/certificate/data",
        "/certificate/data/process",
        "/certificate/data/process/namespaces",
        "/certificate/data/provisioner",
        "/certificate/data/provisioner/namespaces",
        "/stage",
        "/stage/data",
        "/stage/data/process",
        "/stage/data/process/namespaces",
        "/stage/data/runtime",
        "/stage/data/runtime/container",
        "/original",
    ] {
        require_object(value, &format!("{prefix}{suffix}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
