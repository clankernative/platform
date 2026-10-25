//! Purpose-closed statements from the actual retained key and ORIGINAL stage.
//! Parsed DATA cannot replace a stage clock, process handle or key owner.

use super::{EnrolledStorageStage, StagePurpose};
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

impl EnrolledStorageStage<'_, '_> {
    pub(in crate::security_epoch::native_enrollment) fn begin_initial_holder_attempt(
        &mut self,
    ) -> Result<()> {
        let result = (|| {
            self.stage.require_purpose(StagePurpose::CurrentRole)?;
            ensure!(
                self.stage.owner.role == NativeRole::AppHost,
                "storage_peer_app_role_required"
            );
            ensure!(
                !self.stage.owner.initial_holder_attempted,
                "storage_peer_initial_attempt_already_started"
            );
            // One-way refusal gate BEFORE connection, naming or packet I/O.
            self.stage.owner.initial_holder_attempted = true;
            Ok(())
        })();
        if result.is_err() {
            self.stage.owner.refused.set(true);
            self.stage.acquisition.refuse();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn storage_statement(
        &mut self,
    ) -> Result<StageStatement> {
        let result = (|| {
            self.require_storage_peer_purpose()?;
            let statement = self.storage_statement_data()?;
            self.stage.check()?;
            Ok(statement)
        })();
        if result.is_err() {
            self.stage.owner.refused.set(true);
            self.stage.acquisition.refuse();
        }
        result
    }

    // Private DATA assembly within a checked operation. This never leaves the
    // facade or returns a permission; standalone statements and signing retain
    // full pre/post native checks around their actual consuming boundary.
    fn storage_statement_data(&mut self) -> Result<StageStatement> {
        ensure!(
            matches!(
                self.stage.owner.role,
                NativeRole::EpochController | NativeRole::AppHost
            ),
            "storage_peer_shell_role_refused"
        );
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("storage_peer_platform_unsupported");
        #[cfg(target_os = "linux")]
        {
            let (origin, deadline) = self.stage.acquisition.interval_data()?;
            let sample = self.stage.acquisition.sample()?;
            Ok(StageStatement {
                certificate: self.stage.owner.certificate.clone(),
                stage: self.stage.current_grant.clone(),
                original: OriginalInterval {
                    domain: sample.domain,
                    origin_ns: origin.as_nanos().try_into()?,
                    deadline_ns: deadline.min(self.stage.deadline).as_nanos().try_into()?,
                },
            })
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn sign_storage_message(
        &mut self,
        body: Body,
    ) -> Result<Message> {
        let result = (|| {
            self.require_storage_peer_purpose()?;
            body.require_stage_purpose(self.stage.purpose)?;
            ensure!(
                body.sender_role() == self.stage.owner.role,
                "storage_peer_local_sender_role"
            );
            let sender = self.storage_statement_data()?.digest()?;
            // The same full native check remains immediately before the key
            // operation, followed by the original full post-signing check.
            self.stage.check()?;
            let signature = self
                .stage
                .owner
                .key
                .sign("initial-storage-message", &(&sender, &body))?;
            self.stage.check()?;
            Ok(Message {
                sender,
                body,
                signature,
            })
        })();
        if result.is_err() {
            self.stage.owner.refused.set(true);
            self.stage.acquisition.refuse();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn check_storage_acquisition(
        &mut self,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            self.require_storage_peer_purpose()?;
            if self.stage.purpose == super::StagePurpose::StorageBootstrap {
                acquisition.require_storage_bootstrap()?;
            }
            let current = self.stage.acquisition.sample()?;
            let child = acquisition.sample()?;
            let (origin, deadline) = self.stage.acquisition.interval_data()?;
            let (child_origin, child_deadline) = acquisition.interval_data()?;
            ensure!(
                child.domain == current.domain
                    && child_origin == origin
                    && child_deadline <= deadline.min(self.stage.deadline),
                "storage_peer_original_stage_replaced"
            );
            self.stage.check()
        })();
        if result.is_err() {
            self.stage.owner.refused.set(true);
            self.stage.acquisition.refuse();
            acquisition.refuse();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn storage_peer_role(
        &mut self,
    ) -> Result<NativeRole> {
        self.require_storage_peer_purpose()?;
        match self.stage.owner.role {
            NativeRole::EpochController => Ok(NativeRole::AppHost),
            NativeRole::AppHost => Ok(NativeRole::EpochController),
            NativeRole::SecurityShell => anyhow::bail!("storage_peer_shell_role_refused"),
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn storage_peer_code(
        &mut self,
    ) -> Result<Digest> {
        let expected = self.storage_peer_role()?;
        Ok(self.stage.owner.policy.code(expected).clone())
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
                self.stage.owner.role == NativeRole::AppHost,
                "storage_peer_controller_receipt_role"
            );
            statement.validate_attested_controller(
                &self.stage.owner.policy,
                &self.stage.owner.certificate,
                kernel_process,
                acquisition.sample()?.elapsed,
                self.stage.purpose,
            )?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("storage_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                runtime::require_common(
                    &statement.stage.data.process,
                    &self.stage.owner.self_data,
                )?;
                self.check_storage_runtime_selection(statement, NativeRole::EpochController)?;
                self.check_storage_acquisition(acquisition)
            }
        })();
        if result.is_err() {
            self.stage.owner.refused.set(true);
            self.stage.acquisition.refuse();
            acquisition.refuse();
        }
        result
    }

    /// Validate DATA from the caller's retained actual MessageProcess. Before a
    /// Peer escapes, its closed factory must freshly check that owner's original
    /// pidfd/code/namespaces after this comparison; a caller PID cannot adopt it.
    pub(in crate::security_epoch::native_enrollment) fn check_storage_app_statement(
        &mut self,
        statement: &StageStatement,
        observed: &ProcessData,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            self.check_storage_acquisition(acquisition)?;
            ensure!(
                self.stage.owner.role == NativeRole::EpochController,
                "storage_peer_app_receipt_role"
            );
            statement.validate(
                &self.stage.owner.policy,
                &self.stage.owner.certificate,
                NativeRole::AppHost,
                observed,
                acquisition.sample()?.elapsed,
                self.stage.purpose,
            )?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("storage_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                runtime::require_common(observed, &self.stage.owner.self_data)?;
                self.check_storage_runtime_selection(statement, NativeRole::AppHost)?;
                self.check_storage_acquisition(acquisition)
            }
        })();
        if result.is_err() {
            self.stage.owner.refused.set(true);
            self.stage.acquisition.refuse();
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
        let selected = self.stage.owner.policy.workload(role);
        ensure!(
            runtime.node_uid == self.stage.owner.policy.runtime.node_uid
                && runtime.boot == statement.stage.data.process.boot
                && runtime.container.node_name == self.stage.owner.policy.runtime.node_name
                && runtime.container.container_name == selected.container.name.as_str()
                && runtime.container.image == selected.container.image,
            "storage_peer_runtime_selection"
        );
        Ok(())
    }

    fn require_storage_peer_purpose(&mut self) -> Result<()> {
        let result = (|| {
            ensure!(
                matches!(
                    self.stage.purpose,
                    super::StagePurpose::CurrentRole
                        | super::StagePurpose::AppServing
                        | super::StagePurpose::InitialFirstHolder
                        | super::StagePurpose::StorageBootstrap
                ),
                "storage_peer_stage_purpose_refused"
            );
            self.stage.check()
        })();
        if result.is_err() {
            self.stage.owner.refused.set(true);
            self.stage.acquisition.refuse();
        }
        result
    }
}
