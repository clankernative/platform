//! Private serving-channel hooks on the actual enrolled thread/key/stage.

use super::EnrolledRoleStage;
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::{runtime, storage_peer_wire::OriginalInterval};
use crate::security_epoch::{
    native_clock::NativeAcquisition,
    native_enrollment::{
        NativeRole,
        protocol::ProcessData,
        serving_peer_wire::{Body, DOMAIN, Message, Statement},
    },
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;

impl EnrolledRoleStage<'_> {
    pub(in crate::security_epoch::native_enrollment) fn begin_serving_attempt(
        &mut self,
        role: NativeRole,
    ) -> Result<()> {
        let result = (|| {
            self.check()?;
            ensure!(
                self.owner.role == role
                    && matches!(
                        role,
                        NativeRole::SecurityShell | NativeRole::EpochController
                    )
                    && !self.owner.serving_attempted,
                "serving_peer_connection_already_attempted_or_wrong_role"
            );
            self.owner.serving_attempted = true;
            Ok(())
        })();
        if result.is_err() {
            self.refuse_serving();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn serving_role(
        &mut self,
    ) -> Result<NativeRole> {
        self.require_purpose(super::StagePurpose::CurrentRole)?;
        ensure!(
            matches!(
                self.owner.role,
                NativeRole::SecurityShell | NativeRole::EpochController
            ),
            "serving_peer_closed_role"
        );
        Ok(self.owner.role)
    }

    pub(in crate::security_epoch::native_enrollment) fn serving_peer_role(
        &mut self,
    ) -> Result<NativeRole> {
        Ok(match self.serving_role()? {
            NativeRole::SecurityShell => NativeRole::EpochController,
            NativeRole::EpochController => NativeRole::SecurityShell,
            NativeRole::AppHost => unreachable!(),
        })
    }

    pub(in crate::security_epoch::native_enrollment) fn serving_peer_code(
        &mut self,
    ) -> Result<Digest> {
        let role = self.serving_peer_role()?;
        Ok(self.owner.policy.code(role).clone())
    }

    pub(in crate::security_epoch::native_enrollment) fn serving_statement(
        &mut self,
    ) -> Result<Statement> {
        let result = (|| {
            self.serving_role()?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("serving_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let (origin, deadline) = self.acquisition.as_mut().interval_data()?;
                let statement = Statement {
                    certificate: self.owner.certificate.clone(),
                    stage: self.owner.admission.clone(),
                    original: OriginalInterval {
                        purpose: self.purpose,
                        domain: self.acquisition.as_mut().sample()?.domain,
                        origin_ns: origin.as_nanos().try_into()?,
                        deadline_ns: deadline.min(self.deadline).as_nanos().try_into()?,
                    },
                };
                self.check()?;
                Ok(statement)
            }
        })();
        if result.is_err() {
            self.refuse_serving();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn sign_serving_message(
        &mut self,
        body: Body,
    ) -> Result<Message> {
        let result = (|| {
            ensure!(
                body.role() == self.serving_role()?,
                "serving_peer_local_sender_role"
            );
            let sender = self.serving_statement()?.digest()?;
            let signature = self.owner.key.sign(DOMAIN, &(&sender, &body))?;
            self.check()?;
            Ok(Message {
                sender,
                body,
                signature,
            })
        })();
        if result.is_err() {
            self.refuse_serving();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn check_serving_acquisition(
        &mut self,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        // This shared original-clock guard has no App-specific role conversion.
        self.require_purpose(super::StagePurpose::CurrentRole)?;
        self.storage()?.check_storage_acquisition(acquisition)
    }

    pub(in crate::security_epoch::native_enrollment) fn check_serving_statement(
        &mut self,
        statement: &Statement,
        kernel_process: u32,
        observed: Option<&ProcessData>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            self.check_serving_acquisition(acquisition)?;
            let role = self.serving_peer_role()?;
            ensure!(
                observed.is_some() == (role == NativeRole::SecurityShell),
                "serving_peer_sender_provenance"
            );
            statement.validate(
                &self.owner.policy,
                &self.owner.certificate,
                role,
                kernel_process,
                observed,
                acquisition.sample()?.elapsed,
            )?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("serving_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                runtime::require_common(&statement.stage.data.process, &self.owner.self_data)?;
                let runtime = &statement.stage.data.runtime;
                let selected = self.owner.policy.workload(role);
                ensure!(
                    runtime.node_uid == self.owner.policy.runtime.node_uid
                        && runtime.boot == statement.stage.data.process.boot
                        && runtime.container.node_name == self.owner.policy.runtime.node_name
                        && runtime.container.container_name == selected.container.name.as_str()
                        && runtime.container.image == selected.container.image,
                    "serving_peer_runtime_selection"
                );
                self.check_serving_acquisition(acquisition)
            }
        })();
        if result.is_err() {
            self.refuse_serving();
            acquisition.refuse();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn check_serving_controller_statement(
        &mut self,
        statement: &Statement,
        pid: u32,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        self.check_serving_statement(statement, pid, None, acquisition)
    }

    /// Validate request DATA only after its caller checks the actual admitted
    /// peer. No signature or historical statement supplies that native owner.
    pub(in crate::security_epoch::native_enrollment) fn check_admitted_serving_statement(
        &mut self,
        statement: &Statement,
        admitted: &Statement,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            self.check_serving_acquisition(acquisition)?;
            ensure!(
                statement.stage.data.role == self.serving_peer_role()?,
                "serving_peer_request_role_changed"
            );
            statement.validate_request(admitted, acquisition.sample()?.elapsed)?;
            self.check_serving_acquisition(acquisition)
        })();
        if result.is_err() {
            self.refuse_serving();
            acquisition.refuse();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn check_serving_shell_statement(
        &mut self,
        statement: &Statement,
        observed: &ProcessData,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        self.check_serving_statement(statement, observed.process, Some(observed), acquisition)
    }

    pub(in crate::security_epoch::native_enrollment) fn refuse_serving(&mut self) {
        self.owner.refused = true;
        self.acquisition.as_mut().refuse();
    }
}
