//! Separate protected-restore connection transcript DATA. These signatures do
//! not admit a native peer: the actual enrolled stage, original, issuer and
//! per-message kernel sender must also be checked by the fixed native receiver.

use super::super::{
    NativeRole,
    protocol::{self, StagePurpose},
    serving_peer_wire::Statement,
    storage_peer_wire::OriginalInterval,
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};

pub(super) const DOMAIN: &str = "day2-protected-restore-admission-v1";
pub(in crate::security_epoch::native_enrollment) const MAX_PACKET_BYTES: usize =
    protocol::MAX_PACKET;

#[derive(Serialize, Deserialize)]
enum Format {
    #[serde(rename = "day2_protected_restore_admission_v1")]
    V1,
}

/// The ordinary enrollment statement is DATA shared with the existing native
/// validators, not a serving connection or serving-purpose signature. The
/// attested enrollment stays stable when the SAME actual original is narrowed.
/// Initial originals remain explicit in the signed bodies and connection below;
/// fresh command originals are separately signed in every command packet.
pub(in crate::security_epoch::native_enrollment) fn enrollment(
    statement: &Statement,
) -> Result<Digest> {
    Digest::of(&(
        "day2-protected-restore-enrollment-v1",
        &statement.certificate,
        &statement.stage,
    ))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct ConnectionData {
    shell: Digest,
    controller: Digest,
    // Exact FIRST signed intervals, not the current reduced native clock.
    // Later narrowing cannot change or reconstruct this connection attempt.
    shell_original: OriginalInterval,
    controller_original: OriginalInterval,
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
            shell_original: shell.original.clone(),
            controller_original: controller.original.clone(),
            shell_nonce,
            controller_nonce,
        })
    }

    pub(super) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-protected-restore-connection-v1", self))
    }

    /// Exact initial comparison only, after native sender, signature and
    /// common-clock validation. The remote Shell nonce is signed DATA; the
    /// Controller nonce must be this actual attempt's fresh local nonce.
    pub(super) fn require_initial(
        &self,
        shell: &Statement,
        controller: &Statement,
        controller_nonce: &Digest,
    ) -> Result<()> {
        ensure!(
            *self
                == Self::bind(
                    shell,
                    controller,
                    self.shell_nonce.clone(),
                    controller_nonce.clone()
                )?,
            "protected_restore_admission_connection_changed"
        );
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) enum Body {
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
    /// Order DATA only. Native sender, signature, original and common-clock
    /// checks remain mandatory; this frame cannot create an admitted peer.
    pub(in crate::security_epoch::native_enrollment) fn frame(
        &self,
    ) -> super::super::handshake::Frame {
        use super::super::handshake::{Frame, Protocol, Step};
        Frame {
            protocol: Protocol::ProtectedRestoreAdmission,
            step: match self {
                Self::ControllerHello { .. } => Step::Hello,
                Self::ShellProof { .. } => Step::Bind,
                Self::ControllerAccept { .. } => Step::Grant,
                Self::ShellConfirm { .. } => Step::Confirm,
            },
            sequence: None,
        }
    }

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
                let expected = enrollment(shell)?;
                ensure!(
                    expected == connection.shell && shell.original == connection.shell_original,
                    "protected_restore_admission_shell_changed"
                );
                expected
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
        self.require_statement(statement)?;
        Packet::commitment(&enrollment(statement)?, self)
    }

    fn require_statement(&self, statement: &Statement) -> Result<()> {
        let exact = match self {
            Self::ControllerHello { controller, .. } => controller.as_ref() == statement,
            Self::ShellProof { shell, .. } => shell.as_ref() == statement,
            Self::ControllerAccept { connection } => same_original_with_reduced_deadline(
                &statement.original,
                &connection.controller_original,
            ),
            Self::ShellConfirm { connection } => {
                same_original_with_reduced_deadline(&statement.original, &connection.shell_original)
            }
        };
        ensure!(exact, "protected_restore_admission_statement_changed");
        Ok(())
    }
}

/// Continuity DATA only. The native caller must still retain/check the actual
/// saved request and common clock; equal scalar fields never recreate them.
fn same_original_with_reduced_deadline(
    actual: &OriginalInterval,
    saved: &OriginalInterval,
) -> bool {
    actual.purpose == StagePurpose::CurrentRole
        && actual.purpose == saved.purpose
        && actual.domain == saved.domain
        && actual.origin_ns == saved.origin_ns
        && actual.deadline_ns > actual.origin_ns
        && actual.deadline_ns <= saved.deadline_ns
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct Packet {
    format: Format,
    sender: Digest,
    pub(in crate::security_epoch::native_enrollment) body: Body,
    signature: String,
}

impl Packet {
    pub(super) fn commitment(sender: &Digest, body: &Body) -> Result<Digest> {
        body.require_sender(sender)?;
        Digest::of(&(DOMAIN, &Format::V1, sender, body))
    }

    /// Encodes already signed DATA; possession of these bytes supplies no
    /// native stage, original, sender receipt or authenticated connection.
    pub(in crate::security_epoch::native_enrollment) fn encode(
        sender: Digest,
        body: Body,
        signature: String,
    ) -> Result<Vec<u8>> {
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

    pub(in crate::security_epoch::native_enrollment) fn decode(bytes: &[u8]) -> Result<Self> {
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
                connection_objects(&value)?;
            }
            Some("controller_accept" | "shell_confirm") => connection_objects(&value)?,
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
        self.body.require_statement(statement)?;
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

fn connection_objects(value: &serde_json::Value) -> Result<()> {
    for path in [
        "/body/connection",
        "/body/connection/shell_original",
        "/body/connection/controller_original",
    ] {
        object(value, path)?;
    }
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

#[cfg(test)]
pub(super) fn fixture_statement_data(role: NativeRole) -> Statement {
    tests::fixture_statement_data(role)
}
