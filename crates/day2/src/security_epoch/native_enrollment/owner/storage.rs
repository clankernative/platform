//! Purpose-closed statements from the actual retained key and ORIGINAL stage.
//! Parsed DATA cannot replace a stage clock, process handle or key owner.

use super::EnrolledRoleStage;
use crate::security_epoch::native_clock::NativeAcquisition;
use crate::security_epoch::native_enrollment::{
    NativeRole,
    protocol::ProcessData,
    storage_peer_wire::{Body, Message, StageStatement},
};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::{runtime, storage_peer_wire::OriginalInterval};
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
            // One-way refusal gate BEFORE connection, naming or packet I/O.
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
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("storage_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
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
            }
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
        let expected = self.storage_peer_role()?;
        Ok(self.owner.policy.code(expected).clone())
    }

    /// The private receiver retains/checks the ACTUAL privileged sender pidfd;
    /// issuer observations replace App-side privileged proc/containerd reads.
    /// This validator alone returns no native peer or storage authority.
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
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("storage_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                runtime::require_common(&statement.stage.data.process, &self.owner.self_data)?;
                self.check_storage_runtime_selection(statement, NativeRole::EpochController)?;
                self.check_storage_acquisition(acquisition)
            }
        })();
        if result.is_err() {
            self.owner.refused = true;
            self.acquisition.refuse();
            acquisition.refuse();
        }
        result
    }

    /// The caller holds the actual MessageProcess and checks its original
    /// pidfd/code/namespaces around this DATA comparison, never a caller PID.
    pub(in crate::security_epoch::native_enrollment) fn check_storage_app_statement(
        &mut self,
        statement: &StageStatement,
        observed: &ProcessData,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            self.check_storage_acquisition(acquisition)?;
            ensure!(
                self.owner.role == NativeRole::EpochController,
                "storage_peer_app_receipt_role"
            );
            statement.validate(
                &self.owner.policy,
                &self.owner.certificate,
                NativeRole::AppHost,
                observed,
                acquisition.sample()?.elapsed,
            )?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("storage_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                runtime::require_common(observed, &self.owner.self_data)?;
                self.check_storage_runtime_selection(statement, NativeRole::AppHost)?;
                self.check_storage_acquisition(acquisition)
            }
        })();
        if result.is_err() {
            self.owner.refused = true;
            self.acquisition.refuse();
            acquisition.refuse();
        }
        result
    }

    fn check_storage_runtime_selection(
        &mut self,
        statement: &StageStatement,
        role: NativeRole,
    ) -> Result<()> {
        let runtime = &statement.stage.data.runtime;
        let selected = self.owner.policy.workload(role);
        ensure!(
            runtime.node_uid == self.owner.policy.runtime.node_uid
                && runtime.boot == statement.stage.data.process.boot
                && runtime.container.node_name == self.owner.policy.runtime.node_name
                && runtime.container.container_name == selected.container.name.as_str()
                && runtime.container.image == selected.container.image,
            "storage_peer_runtime_selection"
        );
        Ok(())
    }
}
