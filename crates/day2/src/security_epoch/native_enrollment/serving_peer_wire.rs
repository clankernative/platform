//! Closed Shell/Controller role-channel DATA. No file, epoch or writer permit.

use super::{
    NativeRole,
    policy::{EnrollmentPolicy, decode_key},
    protocol::{self, IssuerCertificate, ProcessData, SignedStage, StagePurpose},
    storage_peer_wire::OriginalInterval,
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub(super) const DOMAIN: &str = "shell-controller-serving-message";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Statement {
    pub certificate: IssuerCertificate,
    pub stage: SignedStage,
    pub original: OriginalInterval,
}

impl Statement {
    pub(super) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-shell-controller-serving-statement-v1", self))
    }

    pub(super) fn grant(&self) -> Result<Digest> {
        Digest::of(&("day2-shell-controller-serving-grant-v1", &self.stage))
    }

    pub(super) fn same_enrollment(&self, other: &Self) -> bool {
        self.certificate == other.certificate
            && self.stage.data.issuer == other.stage.data.issuer
            && self.stage.data.policy == other.stage.data.policy
            && self.stage.data.role == other.stage.data.role
            && self.stage.data.public_key == other.stage.data.public_key
            && self.stage.data.process == other.stage.data.process
            && self.stage.data.runtime == other.stage.data.runtime
    }

    pub(super) fn require_fresh(&self, previous: &Self) -> Result<()> {
        ensure!(
            self.same_enrollment(previous)
                && self.grant()? != previous.grant()?
                && self.stage.data.origin_ns > previous.stage.data.origin_ns,
            "serving_peer_fresh_role_grant_required"
        );
        Ok(())
    }

    pub(super) fn validate(
        &self,
        policy: &EnrollmentPolicy,
        issuer: &IssuerCertificate,
        role: NativeRole,
        pid: u32,
        observed: Option<&ProcessData>,
        now: Duration,
    ) -> Result<()> {
        ensure!(
            matches!(
                role,
                NativeRole::SecurityShell | NativeRole::EpochController
            ),
            "serving_peer_closed_role"
        );
        self.certificate.verify(policy)?;
        ensure!(
            self.certificate == *issuer
                && self.stage.data.issuer == issuer.digest()?
                && self.stage.data.policy == policy.digest()?
                && self.stage.data.role == role
                && self.stage.data.purpose == StagePurpose::CurrentRole
                && self.stage.data.process.process == pid
                && self.stage.data.process.code == *policy.code(role)
                && observed.is_none_or(|actual| self.stage.data.process == *actual),
            "serving_peer_issuer_role_or_process_changed"
        );
        decode_key(&self.stage.data.public_key)?;
        let origin = Duration::from_nanos(self.stage.data.origin_ns);
        let deadline = Duration::from_nanos(self.stage.data.deadline_ns);
        ensure!(
            origin <= now
                && now < deadline
                && deadline > origin
                && deadline - origin <= Duration::from_secs(5)
                && self.original.origin_ns <= self.stage.data.origin_ns,
            "serving_peer_signed_interval"
        );
        self.original
            .validate(now, self.stage.data.deadline_ns, StagePurpose::CurrentRole)?;
        protocol::verify(
            &issuer.data.public_key,
            "role-stage",
            &self.stage.data,
            &self.stage.signature,
        )
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Exchange {
    pub initial: Option<Digest>,
    pub sequence: u64,
    pub binding: Option<Digest>,
    pub shell_stage: Digest,
    pub controller_stage: Digest,
    pub shell_nonce: Digest,
    pub controller_nonce: Digest,
}

impl Exchange {
    pub(super) fn require_begin_ready(
        &self,
        ready: &Statement,
        nonce: &Digest,
        offered: &Statement,
    ) -> Result<()> {
        ensure!(
            offered == ready
                && self.controller_stage == ready.digest()?
                && self.controller_nonce == *nonce,
            "serving_peer_ready_statement_or_nonce_changed"
        );
        Ok(())
    }

    pub(super) fn digest(&self) -> Result<Digest> {
        ensure!(
            (self.sequence == 0 && self.initial.is_none() && self.binding.is_none())
                || (self.sequence > 0 && self.initial.is_some() && self.binding.is_some()),
            "serving_peer_exchange_shape"
        );
        Digest::of(&("day2-shell-controller-serving-exchange-v1", self))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Body {
    InitialBeginReady {
        controller: Box<Statement>,
        nonce: Digest,
    },
    CurrentBeginReady {
        controller: Box<Statement>,
        initial: Digest,
        sequence: u64,
        nonce: Digest,
    },
    Hello {
        shell: Box<Statement>,
        nonce: Digest,
        controller_nonce: Digest,
    },
    Offer {
        controller: Box<Statement>,
        exchange: Exchange,
    },
    Confirm {
        exchange: Digest,
    },
    Ready {
        exchange: Digest,
    },
    CurrentHello {
        shell: Box<Statement>,
        initial: Digest,
        sequence: u64,
        binding: Digest,
        nonce: Digest,
        controller_nonce: Digest,
    },
    CurrentOffer {
        controller: Box<Statement>,
        exchange: Exchange,
    },
    CurrentConfirm {
        exchange: Digest,
    },
    CurrentReady {
        exchange: Digest,
    },
    Known {
        exchange: Digest,
    },
    Consumed {
        exchange: Digest,
    },
    Released {
        exchange: Digest,
    },
}

impl Body {
    #[cfg(target_os = "linux")]
    pub(super) fn frame(&self) -> super::handshake::Frame {
        use super::handshake::{Frame, Protocol, Step};
        let (protocol, step, sequence) = match self {
            Self::InitialBeginReady { .. } => (Protocol::InitialServing, Step::BeginReady, None),
            Self::Hello { .. } => (Protocol::InitialServing, Step::Hello, None),
            Self::Offer { .. } => (Protocol::InitialServing, Step::Offer, None),
            Self::Confirm { .. } => (Protocol::InitialServing, Step::Confirm, None),
            Self::Ready { .. } => (Protocol::InitialServing, Step::Ready, None),
            Self::CurrentBeginReady { sequence, .. } => {
                (Protocol::CurrentServing, Step::BeginReady, Some(*sequence))
            }
            Self::CurrentHello { sequence, .. } => {
                (Protocol::CurrentServing, Step::Hello, Some(*sequence))
            }
            Self::CurrentOffer { exchange, .. } => (
                Protocol::CurrentServing,
                Step::Offer,
                Some(exchange.sequence),
            ),
            Self::CurrentConfirm { .. } => (Protocol::CurrentServing, Step::Confirm, None),
            Self::CurrentReady { .. } => (Protocol::CurrentServing, Step::Ready, None),
            Self::Known { .. } => (Protocol::CurrentServing, Step::Known, None),
            Self::Consumed { .. } => (Protocol::CurrentServing, Step::Consumed, None),
            Self::Released { .. } => (Protocol::CurrentServing, Step::Released, None),
        };
        Frame {
            protocol,
            step,
            sequence,
        }
    }

    pub(super) fn role(&self) -> NativeRole {
        match self {
            Self::Hello { .. }
            | Self::Confirm { .. }
            | Self::CurrentHello { .. }
            | Self::CurrentConfirm { .. }
            | Self::Consumed { .. } => NativeRole::SecurityShell,
            _ => NativeRole::EpochController,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Message {
    pub sender: Digest,
    pub body: Body,
    pub signature: String,
}

impl Message {
    pub(super) fn hello(
        &self,
        initial: Option<&Digest>,
        sequence: u64,
        controller_nonce: &Digest,
    ) -> Result<(&Statement, &Digest, Option<&Digest>)> {
        match &self.body {
            Body::Hello {
                shell,
                nonce,
                controller_nonce: echoed,
            } if initial.is_none() && sequence == 0 && echoed == controller_nonce => {
                Ok((shell, nonce, None))
            }
            Body::CurrentHello {
                shell,
                initial: selected,
                sequence: number,
                binding,
                nonce,
                controller_nonce: echoed,
            } if Some(selected) == initial && *number == sequence && echoed == controller_nonce => {
                Ok((shell, nonce, Some(binding)))
            }
            _ => anyhow::bail!("serving_peer_hello_order_or_sequence"),
        }
    }

    pub(super) fn verify(&self, statement: &Statement) -> Result<()> {
        ensure!(
            self.sender == statement.digest()? && self.body.role() == statement.stage.data.role,
            "serving_peer_message_sender"
        );
        protocol::verify(
            &statement.stage.data.public_key,
            DOMAIN,
            &(&self.sender, &self.body),
            &self.signature,
        )
    }
}

pub(super) fn decode(bytes: &[u8]) -> Result<Message> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= protocol::MAX_PACKET,
        "serving_peer_packet_bound"
    );
    let value: serde_json::Value = crate::json::decode(bytes)?;
    object(&value, "")?;
    object(&value, "/body")?;
    match value
        .pointer("/body/step")
        .and_then(serde_json::Value::as_str)
    {
        Some("hello" | "current_hello") => stage_objects(&value, "/body/shell")?,
        Some("initial_begin_ready" | "current_begin_ready") => {
            stage_objects(&value, "/body/controller")?
        }
        Some("offer" | "current_offer") => {
            stage_objects(&value, "/body/controller")?;
            object(&value, "/body/exchange")?;
        }
        Some(
            "confirm" | "ready" | "current_confirm" | "current_ready" | "known" | "consumed"
            | "released",
        ) => {}
        _ => anyhow::bail!("serving_peer_step"),
    }
    Ok(serde_json::from_value(value)?)
}

fn object(value: &serde_json::Value, path: &str) -> Result<()> {
    ensure!(
        value
            .pointer(path)
            .is_some_and(serde_json::Value::is_object),
        "serving_peer_record_object_required"
    );
    Ok(())
}

fn stage_objects(value: &serde_json::Value, prefix: &str) -> Result<()> {
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
        object(value, &format!("{prefix}{suffix}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
