//! Separate protected-restore connection transcript DATA. These signatures do
//! not admit a native peer: the actual enrolled stage, original, issuer and
//! per-message kernel sender must also be checked by the fixed native receiver.

use super::super::{
    NativeRole,
    protocol::{self, StagePurpose},
    serving_peer_wire::Statement,
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};

pub(super) const DOMAIN: &str = "day2-protected-restore-admission-v1";
pub(super) const MAX_PACKET_BYTES: usize = protocol::MAX_PACKET;

#[derive(Serialize, Deserialize)]
enum Format {
    #[serde(rename = "day2_protected_restore_admission_v1")]
    V1,
}

/// The ordinary enrollment statement is DATA shared with the existing native
/// validators, not a serving connection or serving-purpose signature. The
/// commitment and every signature in this module have a separate purpose.
pub(super) fn enrollment(statement: &Statement) -> Result<Digest> {
    Digest::of(&("day2-protected-restore-enrollment-v1", statement))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConnectionData {
    shell: Digest,
    controller: Digest,
    shell_nonce: Digest,
    controller_nonce: Digest,
}

impl ConnectionData {
    /// Comparison DATA only. Native admission must independently validate both
    /// statements and fresh nonces against the same actual channel attempt.
    pub(super) fn bind(
        shell: &Statement,
        controller: &Statement,
        shell_nonce: Digest,
        controller_nonce: Digest,
    ) -> Result<Self> {
        ensure!(
            shell.stage.data.role == NativeRole::SecurityShell
                && controller.stage.data.role == NativeRole::EpochController
                && shell.original.purpose == StagePurpose::CurrentRole
                && controller.original.purpose == StagePurpose::CurrentRole
                && shell.certificate == controller.certificate
                && shell.stage.data.issuer == controller.stage.data.issuer
                && shell.stage.data.policy == controller.stage.data.policy,
            "protected_restore_admission_connection_shape"
        );
        Ok(Self {
            shell: enrollment(shell)?,
            controller: enrollment(controller)?,
            shell_nonce,
            controller_nonce,
        })
    }

    pub(super) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-protected-restore-connection-v1", self))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Body {
    ControllerHello {
        controller: Box<Statement>,
        nonce: Digest,
    },
    ShellProof {
        shell: Box<Statement>,
        connection: ConnectionData,
    },
    ControllerAccept {
        connection: ConnectionData,
    },
    ShellConfirm {
        connection: ConnectionData,
    },
}

impl Body {
    fn role(&self) -> NativeRole {
        match self {
            Self::ControllerHello { .. } | Self::ControllerAccept { .. } => {
                NativeRole::EpochController
            }
            Self::ShellProof { .. } | Self::ShellConfirm { .. } => NativeRole::SecurityShell,
        }
    }

    fn require_sender(&self, sender: &Digest) -> Result<()> {
        let expected = match self {
            Self::ControllerHello { controller, .. } => enrollment(controller)?,
            Self::ShellProof { shell, connection } => {
                let shell = enrollment(shell)?;
                ensure!(
                    shell == connection.shell,
                    "protected_restore_admission_shell_changed"
                );
                shell
            }
            Self::ControllerAccept { connection } => connection.controller.clone(),
            Self::ShellConfirm { connection } => connection.shell.clone(),
        };
        ensure!(
            *sender == expected,
            "protected_restore_admission_sender_changed"
        );
        Ok(())
    }

    /// Fixed signer input from the actual local native statement. This checks
    /// only message DATA; the stage owns all role/original/key observations.
    pub(super) fn commitment_for(&self, statement: &Statement) -> Result<Digest> {
        ensure!(
            self.role() == statement.stage.data.role,
            "protected_restore_admission_signer_role"
        );
        Packet::commitment(&enrollment(statement)?, self)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Packet {
    format: Format,
    sender: Digest,
    pub(super) body: Body,
    signature: String,
}

impl Packet {
    pub(super) fn commitment(sender: &Digest, body: &Body) -> Result<Digest> {
        body.require_sender(sender)?;
        Digest::of(&(DOMAIN, &Format::V1, sender, body))
    }

    /// Encodes already signed DATA; possession of these bytes supplies no
    /// native stage, original, sender receipt or authenticated connection.
    pub(super) fn encode(sender: Digest, body: Body, signature: String) -> Result<Vec<u8>> {
        body.require_sender(&sender)?;
        super::wire::signature_shape(&signature)?;
        let bytes = serde_json::to_vec(&Self {
            format: Format::V1,
            sender,
            body,
            signature,
        })?;
        ensure!(
            bytes.len() <= MAX_PACKET_BYTES,
            "protected_restore_admission_packet_bound"
        );
        Ok(bytes)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_PACKET_BYTES,
            "protected_restore_admission_packet_bound"
        );
        let value: serde_json::Value = crate::json::decode(bytes)
            .map_err(|_| anyhow::anyhow!("protected_restore_admission_packet_encoding"))?;
        Self::from_value(value)
    }

    fn from_value(value: serde_json::Value) -> Result<Self> {
        object(&value, "")?;
        object(&value, "/body")?;
        ensure!(
            value
                .get("format")
                .is_some_and(serde_json::Value::is_string),
            "protected_restore_admission_format"
        );
        match value
            .pointer("/body/step")
            .and_then(serde_json::Value::as_str)
        {
            Some("controller_hello") => statement_objects(&value, "/body/controller")?,
            Some("shell_proof") => {
                statement_objects(&value, "/body/shell")?;
                object(&value, "/body/connection")?;
            }
            Some("controller_accept" | "shell_confirm") => object(&value, "/body/connection")?,
            _ => anyhow::bail!("protected_restore_admission_step"),
        }
        let packet: Self = serde_json::from_value(value)
            .map_err(|_| anyhow::anyhow!("protected_restore_admission_packet_encoding"))?;
        super::wire::signature_shape(&packet.signature)?;
        packet.body.require_sender(&packet.sender)?;
        Ok(packet)
    }

    /// Signature/role comparison only. The caller must supply the actual
    /// native-validated statement, not adopt the packet's parsed statement.
    pub(super) fn verify_data(&self, statement: &Statement) -> Result<()> {
        ensure!(
            self.sender == enrollment(statement)?
                && self.body.role() == statement.stage.data.role
                && statement.original.purpose == StagePurpose::CurrentRole,
            "protected_restore_admission_role_or_enrollment_changed"
        );
        protocol::verify(
            &statement.stage.data.public_key,
            DOMAIN,
            &Self::commitment(&self.sender, &self.body)?,
            &self.signature,
        )
    }

    pub(super) fn require_hello(&self, expected: &Statement, nonce: &Digest) -> Result<()> {
        ensure!(
            matches!(&self.body, Body::ControllerHello { controller, nonce: actual }
                if **controller == *expected && actual == nonce),
            "protected_restore_admission_hello_changed"
        );
        Ok(())
    }

    pub(super) fn require_proof(
        &self,
        expected: &Statement,
        connection: &ConnectionData,
    ) -> Result<()> {
        ensure!(
            matches!(&self.body, Body::ShellProof { shell, connection: actual }
                if **shell == *expected && actual == connection),
            "protected_restore_admission_proof_changed"
        );
        Ok(())
    }

    pub(super) fn require_accept(&self, connection: &ConnectionData) -> Result<()> {
        ensure!(
            matches!(&self.body, Body::ControllerAccept { connection: actual } if actual == connection),
            "protected_restore_admission_accept_changed"
        );
        Ok(())
    }

    pub(super) fn require_confirm(&self, connection: &ConnectionData) -> Result<()> {
        ensure!(
            matches!(&self.body, Body::ShellConfirm { connection: actual } if actual == connection),
            "protected_restore_admission_confirm_changed"
        );
        Ok(())
    }
}

fn object(value: &serde_json::Value, path: &str) -> Result<()> {
    ensure!(
        value
            .pointer(path)
            .is_some_and(serde_json::Value::is_object),
        "protected_restore_admission_object_required"
    );
    Ok(())
}

fn statement_objects(value: &serde_json::Value, prefix: &str) -> Result<()> {
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
