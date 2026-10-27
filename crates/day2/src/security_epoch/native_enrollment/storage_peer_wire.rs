//! Purpose-bound initial-holder wire DATA. None of these values can adopt a
//! native stage, process handle, prepared file, first holder or writer.

use super::{
    NativeRole, StoragePeerPurpose,
    policy::{EnrollmentPolicy, decode_key},
    protocol::{self, IssuerCertificate, ProcessData, SignedStage, StagePurpose},
};
use crate::security_epoch::PreparedFileProjection;
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct OriginalInterval {
    pub purpose: StagePurpose,
    pub domain: Digest,
    pub origin_ns: u64,
    pub deadline_ns: u64,
}

impl OriginalInterval {
    pub(super) fn validate_request(&self, now: Duration, purpose: StagePurpose) -> Result<()> {
        let origin = Duration::from_nanos(self.origin_ns);
        let deadline = Duration::from_nanos(self.deadline_ns);
        ensure!(
            self.purpose == purpose
                && purpose != StagePurpose::StorageMetadataObservation
                && origin <= now
                && now < deadline
                && deadline > origin
                && deadline - origin <= purpose.limit(),
            "storage_peer_original_interval"
        );
        Ok(())
    }

    pub(super) fn require_later_request(&self, previous: &Self) -> Result<()> {
        ensure!(
            self.domain != previous.domain && self.origin_ns > previous.origin_ns,
            "storage_peer_new_request_required"
        );
        Ok(())
    }

    /// Interval DATA continuity, never replay permission. Only an actual
    /// retained peer can authenticate another exchange on this original, with
    /// its next sequence, fresh nonces, signed binding and fresh counters.
    /// A callback cannot restart the original or increase its earlier ceiling.
    pub(super) fn require_request_continuity(&self, previous: &Self) -> Result<()> {
        if self.domain != previous.domain {
            return self.require_later_request(previous);
        }
        ensure!(
            self.purpose == previous.purpose
                && self.origin_ns == previous.origin_ns
                && self.deadline_ns > self.origin_ns
                && self.deadline_ns <= previous.deadline_ns,
            "storage_peer_request_original_changed"
        );
        Ok(())
    }

    pub(super) fn validate(
        &self,
        now: Duration,
        issuer_deadline_ns: u64,
        purpose: StagePurpose,
    ) -> Result<()> {
        self.validate_request(now, purpose)?;
        ensure!(
            self.deadline_ns <= issuer_deadline_ns,
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
    /// Historical candidate DATA only. Native callers retain the actual
    /// authenticated sender/channel; these hashes cannot recreate that owner.
    pub(super) fn app_holder(&self) -> Result<crate::security_epoch::kernel::Holder> {
        ensure!(
            self.stage.data.role == NativeRole::AppHost,
            "storage_peer_app_holder_role"
        );
        let data = &self.stage.data;
        let holder = crate::security_epoch::kernel::Holder {
            principal: Digest::of(&(
                "day2-enrolled-app-principal-v1",
                &data.policy,
                &data.runtime.container.pod_uid,
            ))?,
            pod_uid: data.runtime.container.pod_uid.clone(),
            process_incarnation: Digest::of(&(
                "day2-enrolled-app-process-v1",
                &data.process,
                &data.runtime,
            ))?,
            ephemeral_key: Digest::new(&decode_key(&data.public_key)?),
        };
        holder.validate()?;
        Ok(holder)
    }

    /// DATA replay check only. The actual retained peer and signed request
    /// transcript remain mandatory; this cannot admit a new connection.
    pub(super) fn require_new_request(&self, previous: &OriginalInterval) -> Result<()> {
        self.original.require_later_request(previous)
    }

    pub(super) fn require_request_continuity(&self, previous: &OriginalInterval) -> Result<()> {
        self.original.require_request_continuity(previous)
    }

    /// Stable admission identity, never request permission by itself.
    pub(super) fn same_enrollment(&self, other: &Self) -> bool {
        self.certificate == other.certificate
            && self.stage.data.issuer == other.stage.data.issuer
            && self.stage.data.policy == other.stage.data.policy
            && self.stage.data.role == other.stage.data.role
            && self.stage.data.public_key == other.stage.data.public_key
            && self.stage.data.process == other.stage.data.process
            && self.stage.data.runtime == other.stage.data.runtime
    }

    pub(in crate::security_epoch::native_enrollment) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-initial-holder-stage-v1", self))
    }

    /// Historical identity plus fresh request DATA. Only a caller retaining
    /// the actual admitted native peer may use this instead of cold validate.
    /// The message signature binds this interval, purpose and exchange; the
    /// old issuer grant's deadline is never reinterpreted or extended.
    pub(super) fn validate_request(
        &self,
        admitted: &Self,
        now: Duration,
        purpose: StagePurpose,
    ) -> Result<()> {
        ensure!(
            self.same_enrollment(admitted),
            "storage_peer_admission_changed"
        );
        purpose.require_role(self.stage.data.role)?;
        self.original.validate_request(now, purpose)?;
        protocol::verify(
            &self.certificate.data.public_key,
            "role-stage",
            &self.stage.data,
            &self.stage.signature,
        )
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
        purpose: StagePurpose,
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
            purpose,
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
        purpose: StagePurpose,
    ) -> Result<()> {
        self.validate_sender(
            policy,
            local_issuer,
            NativeRole::EpochController,
            kernel_process,
            now,
            purpose,
        )
    }

    fn validate_sender(
        &self,
        policy: &EnrollmentPolicy,
        local_issuer: &IssuerCertificate,
        expected_role: NativeRole,
        kernel_process: u32,
        now: Duration,
        purpose: StagePurpose,
    ) -> Result<()> {
        ensure!(
            purpose != StagePurpose::StorageMetadataObservation,
            "storage_peer_metadata_purpose_refused"
        );
        purpose.require_role(expected_role)?;
        self.certificate.verify(policy)?;
        ensure!(
            self.certificate == *local_issuer
                && self.stage.data.issuer == self.certificate.digest()?
                && self.stage.data.policy == policy.digest()?
                && self.stage.data.role == expected_role
                && self.stage.data.purpose == purpose
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
                && deadline - origin <= purpose.limit(),
            "storage_peer_signed_stage_interval"
        );
        ensure!(
            self.original.origin_ns <= self.stage.data.origin_ns,
            "storage_peer_original_origin_changed"
        );
        self.original
            .validate(now, self.stage.data.deadline_ns, purpose)?;
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
    /// DATA-only continuity with the already authenticated readiness packet.
    /// This neither authenticates a sender nor constructs a native owner.
    pub(super) fn require_initial_ready(
        &self,
        ready: &StageStatement,
        nonce: &Digest,
        offered: &StageStatement,
    ) -> Result<()> {
        ensure!(
            offered == ready
                && self.controller_stage == ready.digest()?
                && self.controller_nonce == *nonce,
            "storage_peer_ready_stage_or_nonce_changed"
        );
        Ok(())
    }

    pub(super) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-initial-holder-exchange-v1", self))
    }
}

/// A closed request binding is DATA. It creates neither a current peer phase
/// nor a file, P3, epoch, writer or consumer permission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoragePeerRequest {
    pub purpose: StoragePeerPurpose,
    pub binding: Digest,
}

impl StoragePeerPurpose {
    pub(in crate::security_epoch) fn stage_purpose(self) -> StagePurpose {
        match self {
            Self::BootstrapCreate | Self::BootstrapComplete => StagePurpose::StorageBootstrap,
            Self::CurrentServing => StagePurpose::CurrentRole,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CurrentExchange {
    pub initial: Digest,
    pub sequence: u64,
    pub request: StoragePeerRequest,
    pub app_stage: Digest,
    pub controller_stage: Digest,
    pub app_nonce: Digest,
    pub controller_nonce: Digest,
}

impl CurrentExchange {
    pub(super) fn require_begin_ready(
        &self,
        ready: &StageStatement,
        nonce: &Digest,
        offered: &StageStatement,
    ) -> Result<()> {
        ensure!(
            offered == ready
                && ready.original.purpose == self.request.purpose.stage_purpose()
                && self.controller_stage == ready.digest()?
                && self.controller_nonce == *nonce,
            "storage_peer_current_ready_stage_or_nonce_changed"
        );
        Ok(())
    }

    pub(super) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-current-storage-peer-exchange-v1", self))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) enum Body {
    InitialReady {
        controller: Box<StageStatement>,
        nonce: Digest,
    },
    Hello {
        app: Box<StageStatement>,
        nonce: Digest,
        controller_nonce: Digest,
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
    CurrentBeginReady {
        controller: Box<StageStatement>,
        initial: Digest,
        sequence: u64,
        nonce: Digest,
    },
    CurrentHello {
        app: Box<StageStatement>,
        initial: Digest,
        sequence: u64,
        request: StoragePeerRequest,
        nonce: Digest,
        controller_nonce: Digest,
    },
    CurrentOffer {
        controller: Box<StageStatement>,
        exchange: CurrentExchange,
    },
    CurrentAck {
        exchange: Digest,
    },
    CurrentReady {
        exchange: Digest,
    },
    CurrentResult {
        exchange: Digest,
    },
    CurrentConsumed {
        exchange: Digest,
    },
    CurrentReleased {
        exchange: Digest,
    },
}

#[derive(Clone, Copy)]
pub(super) enum CompletionKind {
    Result,
    Consumed,
    Released,
}

impl Body {
    #[cfg(target_os = "linux")]
    pub(super) fn frame(&self) -> super::handshake::Frame {
        use super::handshake::{Frame, Protocol, Step};
        let (protocol, step, sequence) = match self {
            Self::InitialReady { .. } => (Protocol::InitialStorage, Step::BeginReady, None),
            Self::Hello { .. } => (Protocol::InitialStorage, Step::Hello, None),
            Self::Offer { .. } => (Protocol::InitialStorage, Step::Offer, None),
            Self::Confirm { .. } => (Protocol::InitialStorage, Step::Confirm, None),
            Self::Complete { .. } => (Protocol::InitialStorage, Step::Complete, None),
            Self::Accepted { .. } => (Protocol::InitialStorage, Step::Accepted, None),
            Self::CurrentBeginReady { sequence, .. } => {
                (Protocol::CurrentStorage, Step::BeginReady, Some(*sequence))
            }
            Self::CurrentHello { sequence, .. } => {
                (Protocol::CurrentStorage, Step::Hello, Some(*sequence))
            }
            Self::CurrentOffer { exchange, .. } => (
                Protocol::CurrentStorage,
                Step::Offer,
                Some(exchange.sequence),
            ),
            Self::CurrentAck { .. } => (Protocol::CurrentStorage, Step::Ack, None),
            Self::CurrentReady { .. } => (Protocol::CurrentStorage, Step::Ready, None),
            Self::CurrentResult { .. } => (Protocol::CurrentStorage, Step::Known, None),
            Self::CurrentConsumed { .. } => (Protocol::CurrentStorage, Step::Consumed, None),
            Self::CurrentReleased { .. } => (Protocol::CurrentStorage, Step::Released, None),
        };
        Frame {
            protocol,
            step,
            sequence,
        }
    }

    /// Validate purpose DATA against the native caller's expected purpose.
    /// Completion signatures bind the exact stage statement and exchange;
    /// metadata-observation grants never enter this peer protocol.
    pub(super) fn require_stage_purpose(&self, expected: StagePurpose) -> Result<()> {
        let current = || -> Result<()> {
            ensure!(
                matches!(
                    expected,
                    StagePurpose::CurrentRole | StagePurpose::StorageBootstrap
                ),
                "storage_peer_stage_purpose"
            );
            Ok(())
        };
        match self {
            Self::InitialReady { controller, .. } | Self::Offer { controller, .. } => ensure!(
                expected == StagePurpose::InitialFirstHolder
                    && controller.original.purpose == expected,
                "storage_peer_stage_purpose"
            ),
            Self::Hello { app, .. } => ensure!(
                expected == StagePurpose::InitialFirstHolder && app.original.purpose == expected,
                "storage_peer_stage_purpose"
            ),
            Self::Confirm { .. } | Self::Complete { .. } | Self::Accepted { .. } => ensure!(
                expected == StagePurpose::InitialFirstHolder,
                "storage_peer_stage_purpose"
            ),
            Self::CurrentHello { app, request, .. } => {
                current()?;
                ensure!(
                    request.purpose.stage_purpose() == expected && app.original.purpose == expected,
                    "storage_peer_stage_purpose"
                );
            }
            Self::CurrentOffer {
                controller,
                exchange,
            } => {
                current()?;
                ensure!(
                    exchange.request.purpose.stage_purpose() == expected
                        && controller.original.purpose == expected,
                    "storage_peer_stage_purpose"
                );
            }
            Self::CurrentBeginReady { controller, .. } => {
                current()?;
                ensure!(
                    controller.original.purpose == expected,
                    "storage_peer_stage_purpose"
                );
            }
            Self::CurrentAck { .. }
            | Self::CurrentReady { .. }
            | Self::CurrentResult { .. }
            | Self::CurrentConsumed { .. }
            | Self::CurrentReleased { .. } => current()?,
        }
        Ok(())
    }

    pub(super) fn matches_completion(&self, expected: &Digest, kind: CompletionKind) -> bool {
        match (self, kind) {
            (Self::CurrentResult { exchange }, CompletionKind::Result)
            | (Self::CurrentConsumed { exchange }, CompletionKind::Consumed)
            | (Self::CurrentReleased { exchange }, CompletionKind::Released) => {
                exchange == expected
            }
            _ => false,
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn sender_role(&self) -> NativeRole {
        match self {
            Self::Hello { .. }
            | Self::Confirm { .. }
            | Self::Accepted { .. }
            | Self::CurrentHello { .. }
            | Self::CurrentAck { .. }
            | Self::CurrentConsumed { .. } => NativeRole::AppHost,
            Self::InitialReady { .. }
            | Self::Offer { .. }
            | Self::Complete { .. }
            | Self::CurrentBeginReady { .. }
            | Self::CurrentOffer { .. }
            | Self::CurrentReady { .. }
            | Self::CurrentResult { .. }
            | Self::CurrentReleased { .. } => NativeRole::EpochController,
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
    /// Closed current-request selection DATA. Actual sender, signature and
    /// original-role validation remain mandatory in the native receiver.
    pub(super) fn current_hello(
        &self,
        initial: &Digest,
        sequence: u64,
        controller_nonce: &Digest,
        expected: Option<&StoragePeerRequest>,
    ) -> Result<(&StageStatement, &Digest, &StoragePeerRequest)> {
        match &self.body {
            Body::CurrentHello {
                app,
                initial: selected,
                sequence: number,
                request,
                nonce,
                controller_nonce: echoed,
            } => {
                self.body.require_stage_purpose(app.original.purpose)?;
                ensure!(
                    selected == initial
                        && *number == sequence
                        && echoed == controller_nonce
                        && expected.map_or_else(
                            || request.purpose == StoragePeerPurpose::CurrentServing,
                            |expected| request == expected,
                        ),
                    "storage_peer_current_request_changed"
                );
                Ok((app, nonce, request))
            }
            _ => anyhow::bail!("storage_peer_expected_current_hello"),
        }
    }

    /// Checked wire DATA only. The real receiver still authenticates the
    /// signature, actual sender handles, current role and both native clocks.
    pub(super) fn initial_hello(
        &self,
        expected_controller_nonce: &Digest,
    ) -> Result<(&StageStatement, &Digest)> {
        match &self.body {
            Body::Hello {
                app,
                nonce,
                controller_nonce,
            } => {
                ensure!(
                    controller_nonce == expected_controller_nonce,
                    "storage_peer_ready_nonce_changed"
                );
                Ok((app, nonce))
            }
            _ => anyhow::bail!("storage_peer_expected_hello"),
        }
    }

    pub(super) fn verify(&self, statement: &StageStatement) -> Result<()> {
        self.body
            .require_stage_purpose(statement.original.purpose)?;
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

/// Closed verification/observation ordering. The statement is public DATA;
/// the native caller alone supplies the actual final sender observation.
/// No native owner or successful observation is cached or constructed here.
pub(super) fn verify_message_then_observe<Owner>(
    owner: &mut Owner,
    message: &Message,
    statement: impl FnOnce(&Owner) -> &StageStatement,
    observe: impl FnOnce(&mut Owner) -> Result<()>,
) -> Result<()> {
    message.verify(statement(owner))?;
    observe(owner)
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
        Some("initial_ready" | "current_begin_ready") => {
            require_stage_objects(&value, "/body/controller")?
        }
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
        Some("current_hello") => {
            require_stage_objects(&value, "/body/app")?;
            require_object(&value, "/body/request")?;
        }
        Some("current_offer") => {
            require_stage_objects(&value, "/body/controller")?;
            require_object(&value, "/body/exchange")?;
            require_object(&value, "/body/exchange/request")?;
        }
        Some(
            "confirm" | "complete" | "accepted" | "current_ack" | "current_ready"
            | "current_result" | "current_consumed" | "current_released",
        ) => {}
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
