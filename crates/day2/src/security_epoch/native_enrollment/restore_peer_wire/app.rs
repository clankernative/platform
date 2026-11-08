//! Signed restore-process DATA, distinct from an ordinary role statement.
//! Neither validation nor a holder projection supplies native peer/P3/keeper
//! ownership. The receiver must still retain its actual message process.
use super::{Selection, StageStatement, map_only};
use crate::security_epoch::native_enrollment::{
    NativeRole,
    policy::{EnrollmentPolicy, decode_key},
    protocol::{
        IssuerCertificate, ProcessData, SignedRestoreAdmission, SignedRestoreAuthorization,
    },
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct RestoreOriginal {
    pub domain: Digest,
    pub origin_ns: u64,
    pub deadline_ns: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch::native_enrollment) struct RestoreAppStatement {
    #[serde(deserialize_with = "map_only")]
    pub certificate: IssuerCertificate,
    #[serde(deserialize_with = "map_only")]
    pub authorization: SignedRestoreAuthorization,
    #[serde(deserialize_with = "map_only")]
    pub admission: SignedRestoreAdmission,
    #[serde(deserialize_with = "map_only")]
    pub original: RestoreOriginal,
}

impl RestoreAppStatement {
    pub(in crate::security_epoch::native_enrollment) fn require_selection(
        &self,
        selection: &Selection,
    ) -> Result<()> {
        let authorized = &self.authorization.statement.data;
        ensure!(
            authorized.operation == selection.operation
                && authorized.approval == selection.approval_request
                && authorized.intent == selection.intent
                && authorized.full_archive == selection.full_archive
                && authorized.target == selection.target,
            "restore_peer_app_selection_changed"
        );
        Ok(())
    }

    pub(in crate::security_epoch::native_enrollment) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-restored-app-statement-v1", self))
    }

    /// Actual native callers compare the retained SCM message process and
    /// establish the common clock namespace BEFORE supplying their fresh now.
    /// Parsed process numbers, times or success here cannot adopt that handle.
    pub(in crate::security_epoch::native_enrollment) fn validate(
        &self,
        policy: &EnrollmentPolicy,
        issuer: &IssuerCertificate,
        message: &ProcessData,
        now: Duration,
    ) -> Result<()> {
        ensure!(&self.certificate == issuer, "restore_peer_issuer_changed");
        self.admission
            .verify_data(policy, issuer, &self.authorization, now)?;
        let admitted = &self.admission.statement;
        ensure!(
            admitted.process == *message
                && self.original.domain == admitted.receiver_clock
                && self.original.origin_ns == admitted.receiver_origin_ns
                && self.original.origin_ns < self.original.deadline_ns
                && self.original.deadline_ns <= admitted.effective_deadline_ns
                && u128::from(self.original.origin_ns) <= now.as_nanos()
                && now.as_nanos() < u128::from(self.original.deadline_ns),
            "restore_peer_original_or_process_changed"
        );
        require_runtime_selection(
            policy,
            NativeRole::AppHost,
            &admitted.process,
            &admitted.runtime,
        )
    }

    /// Match the exact Controller that the issuer authorized; its ordinary
    /// role is never copied onto this new App or treated as the App's owner.
    pub(in crate::security_epoch::native_enrollment) fn require_controller(
        &self,
        controller: &StageStatement,
    ) -> Result<()> {
        ensure!(
            controller.certificate == self.certificate
                && controller.stage.data.role == NativeRole::EpochController
                && controller.original.purpose == super::StagePurpose::CurrentRole
                && controller.digest()? == self.authorization.statement.data.controller,
            "restore_peer_controller_changed"
        );
        Ok(())
    }

    /// Historical issuer identity plus this fresh restore's exact Controller
    /// request DATA. Only a native receipt may supply actual sender provenance;
    /// this helper itself grants no connection, file, P3, writer or Current.
    pub(in crate::security_epoch::native_enrollment) fn validate_controller_data(
        &self,
        policy: &EnrollmentPolicy,
        statement: &StageStatement,
        sender: u32,
        now: Duration,
    ) -> Result<()> {
        self.admission
            .verify_data(policy, &self.certificate, &self.authorization, now)?;
        self.require_controller(statement)?;
        let authorized = &self.authorization.statement.data;
        ensure!(
            statement.stage.data.process.process == sender
                && statement.original.domain == authorized.parent_clock
                && statement.original.origin_ns == authorized.parent_origin_ns
                && statement.original.deadline_ns <= authorized.parent_deadline_ns,
            "restore_peer_controller_original_changed"
        );
        statement.validate_issued_request_data(
            policy,
            &self.certificate,
            NativeRole::EpochController,
            now,
        )?;
        require_runtime_selection(
            policy,
            NativeRole::EpochController,
            &statement.stage.data.process,
            &statement.stage.data.runtime,
        )
    }

    /// Historical kernel request input only. This is never accepted as a
    /// candidate: the actual native App and keeper/P3 stay borrowed by it.
    pub(in crate::security_epoch::native_enrollment) fn holder_data(
        &self,
    ) -> Result<crate::security_epoch::kernel::Holder> {
        let data = &self.admission.statement;
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
}

pub(in crate::security_epoch::native_enrollment) fn require_runtime_selection(
    policy: &EnrollmentPolicy,
    role: NativeRole,
    process: &ProcessData,
    runtime: &crate::security_epoch::native_enrollment::protocol::RuntimeBinding,
) -> Result<()> {
    ensure!(
        matches!(role, NativeRole::AppHost | NativeRole::EpochController),
        "restore_peer_runtime_role"
    );
    let workload = policy.workload(role);
    let container = &runtime.container;
    ensure!(
        runtime.node_uid == policy.runtime.node_uid
            && runtime.boot == process.boot
            && container.node_name == policy.runtime.node_name
            && container.container_name == workload.container.name
            && container.image == workload.container.image
            && !container.pod_uid.is_empty()
            && container.pod_uid.len() <= 253
            && pod_name(&container.pod_name)
            && container
                .container_id
                .strip_prefix("containerd://")
                .is_some_and(|id| id.len() == 64
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())),
        "restore_peer_runtime_changed"
    );
    Ok(())
}

// Metadata syntax only. The genuine issuer already joined the actual Pod
// through its ReplicaSet/Deployment or StatefulSet owner. A Pod name is not
// a workload name or an authorization prefix.
fn pod_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}
