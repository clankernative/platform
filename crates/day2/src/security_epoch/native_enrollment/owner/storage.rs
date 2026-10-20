//! Purpose-closed storage statements from the actual retained enrolled key and
//! ORIGINAL stage. DATA cannot provide a replacement stage clock or key.

use super::EnrolledRoleStage;
use crate::security_epoch::native_clock::NativeAcquisition;
use crate::security_epoch::native_enrollment::{
    NativeRole,
    process::MessageProcess,
    runtime,
    storage_peer::wire::{Body, Message, OriginalInterval, StageStatement},
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;

impl EnrolledRoleStage<'_> {
    pub(in crate::security_epoch::native_enrollment) fn begin_initial_holder_attempt(
        &mut self,
    ) -> Result<()> {
        let result = (|| {
            self.check()?;
            ensure!(
                self.owner.role == NativeRole::AppHost,
                "storage_peer_app_role_required"
            );
            ensure!(
                !self.owner.initial_holder_attempted,
                "storage_peer_initial_attempt_already_started"
            );
            // Before connection, nonce generation or any packet. No code resets
            // this gate on failure, success, expiry or a replacement stage.
            self.owner.initial_holder_attempted = true;
            Ok(())
        })();
        if result.is_err() {
            self.owner.refused = true;
            self.acquisition.refuse();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn storage_statement(
        &mut self,
    ) -> Result<StageStatement> {
        let result = (|| {
            self.check()?;
            ensure!(
                matches!(
                    self.owner.role,
                    NativeRole::EpochController | NativeRole::AppHost
                ),
                "storage_peer_shell_role_refused"
            );
            let (origin, deadline) = self.acquisition.interval_data()?;
            let sample = self.acquisition.sample()?;
            let statement = StageStatement {
                certificate: self.owner.certificate.clone(),
                stage: self.current_grant.clone(),
                original: OriginalInterval {
                    domain: sample.domain,
                    origin_ns: origin.as_nanos().try_into()?,
                    deadline_ns: deadline.min(self.deadline).as_nanos().try_into()?,
                },
            };
            self.check()?;
            Ok(statement)
        })();
        if result.is_err() {
            self.owner.refused = true;
            self.acquisition.refuse();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn sign_storage_message(
        &mut self,
        body: Body,
    ) -> Result<Message> {
        let result = (|| {
            self.check()?;
            ensure!(
                body.sender_role() == self.owner.role,
                "storage_peer_local_sender_role"
            );
            let sender = self.storage_statement()?.digest()?;
            let signature = self
                .owner
                .key
                .sign("initial-storage-message", &(&sender, &body))?;
            self.check()?;
            Ok(Message {
                sender,
                body,
                signature,
            })
        })();
        if result.is_err() {
            self.owner.refused = true;
            self.acquisition.refuse();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn check_storage_acquisition(
        &mut self,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            self.check()?;
            let current = self.acquisition.sample()?;
            let child = acquisition.sample()?;
            let (origin, deadline) = self.acquisition.interval_data()?;
            let (child_origin, child_deadline) = acquisition.interval_data()?;
            ensure!(
                child.domain == current.domain
                    && child_origin == origin
                    && child_deadline <= deadline.min(self.deadline),
                "storage_peer_original_stage_replaced"
            );
            self.check()
        })();
        if result.is_err() {
            self.owner.refused = true;
            self.acquisition.refuse();
            acquisition.refuse();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn storage_peer_role(
        &mut self,
    ) -> Result<NativeRole> {
        self.check()?;
        match self.owner.role {
            NativeRole::EpochController => Ok(NativeRole::AppHost),
            NativeRole::AppHost => Ok(NativeRole::EpochController),
            NativeRole::SecurityShell => anyhow::bail!("storage_peer_shell_role_refused"),
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn storage_peer_code(
        &mut self,
    ) -> Result<Digest> {
        self.check()?;
        let expected = match self.owner.role {
            NativeRole::EpochController => NativeRole::AppHost,
            NativeRole::AppHost => NativeRole::EpochController,
            NativeRole::SecurityShell => anyhow::bail!("storage_peer_shell_role_refused"),
        };
        Ok(self.owner.policy.code(expected).clone())
    }

    pub(in crate::security_epoch::native_enrollment) fn check_storage_controller_statement(
        &mut self,
        statement: &StageStatement,
        kernel_process: u32,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            self.check_storage_acquisition(acquisition)?;
            ensure!(
                self.owner.role == NativeRole::AppHost,
                "storage_peer_controller_receipt_role"
            );
            statement.validate_attested_controller(
                &self.owner.policy,
                &self.owner.certificate,
                kernel_process,
                acquisition.sample()?.elapsed,
            )?;
            runtime::require_common(&statement.stage.data.process, &self.owner.self_data)?;
            let runtime = &statement.stage.data.runtime;
            let selected = self.owner.policy.workload(NativeRole::EpochController);
            ensure!(
                runtime.node_uid == self.owner.policy.runtime.node_uid
                    && runtime.boot == statement.stage.data.process.boot
                    && runtime.container.node_name == self.owner.policy.runtime.node_name
                    && runtime.container.container_name == selected.container.name.as_str()
                    && runtime.container.image == selected.container.image,
                "storage_peer_runtime_selection"
            );
            self.check_storage_acquisition(acquisition)
        })();
        if result.is_err() {
            self.owner.refused = true;
            self.acquisition.refuse();
            acquisition.refuse();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn check_storage_peer(
        &mut self,
        statement: &StageStatement,
        process: &mut MessageProcess,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            self.check_storage_acquisition(acquisition)?;
            let role = match self.owner.role {
                NativeRole::EpochController => NativeRole::AppHost,
                NativeRole::AppHost => NativeRole::EpochController,
                NativeRole::SecurityShell => anyhow::bail!("storage_peer_shell_role_refused"),
            };
            process.check_identity(acquisition)?;
            statement.validate(
                &self.owner.policy,
                &self.owner.certificate,
                role,
                process.data(),
                acquisition.sample()?.elapsed,
            )?;
            runtime::require_common(process.data(), &self.owner.self_data)?;
            // The ACTUAL retained same-generation issuer joined this exact
            // process to its runtime when issuing this signed <=5s stage. The
            // receiver retains/rechecks that issuer and this message's pidfd;
            // no parsed grant alone supplies a native peer. App/Shell must not
            // receive containerd access merely to authenticate this endpoint.
            let runtime = &statement.stage.data.runtime;
            let selected = self.owner.policy.workload(role);
            ensure!(
                runtime.node_uid == self.owner.policy.runtime.node_uid
                    && runtime.boot == process.data().boot
                    && runtime.container.node_name == self.owner.policy.runtime.node_name
                    && runtime.container.container_name == selected.container.name.as_str()
                    && runtime.container.image == selected.container.image,
                "storage_peer_runtime_selection"
            );
            process.check_identity(acquisition)?;
            self.check_storage_acquisition(acquisition)
        })();
        if result.is_err() {
            self.owner.refused = true;
            self.acquisition.refuse();
            acquisition.refuse();
        }
        result
    }
}
