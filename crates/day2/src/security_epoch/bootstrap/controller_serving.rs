//! Fixed Controller-side active App serving operation. No callback can execute
//! inside the Controller. The signed peer result is released only while the
//! SAME current physical/first-holder and provider observations remain owned.
use super::{ActiveControllerStorageContinuity, check_active_snapshot, request_names};
use crate::security_epoch::{AuthenticatedReads, native_enrollment::EnrolledRoleStage};
use anyhow::{Result, ensure};
use day2_capabilities::security_epoch::bootstrap::NativeRole;

impl ActiveControllerStorageContinuity {
    pub(in crate::security_epoch) fn app_pending(&mut self) -> Result<bool> {
        ensure!(self.valid, "active_controller_storage_refused");
        self.storage.app_pending()
    }

    pub(in crate::security_epoch) fn serve_app_current(
        &mut self,
        stage: EnrolledRoleStage<'_>,
    ) -> Result<()> {
        ensure!(self.valid, "active_controller_storage_refused");
        self.valid = false;
        let result = (|| {
            let mut physical = self.storage.begin_current_app(stage)?;
            // Authenticated request selection is DATA. This can only be the
            // original App enrollment and a fresh current-serving transcript.
            let _binding = physical.app_request()?.binding.clone();
            let mut reads = AuthenticatedReads::acquire(
                &self.policy,
                &self.store,
                NativeRole::EpochController,
                physical.controller_stage()?,
            )?
            .retain_current()?;
            let names = request_names(&self.store, &self.completion)?;
            let mut observed = reads.read(physical.controller_stage()?, &self.store, &names)?;
            check_active_snapshot(
                &self.store,
                &self.completion,
                &self.activation,
                observed.snapshot(),
            )?;
            physical.check()?;
            reads.check_observation(physical.controller_stage()?, &mut observed)?;
            physical.announce_app_known()?;
            physical.await_app_consumed()?;
            // The actual App has now recorded its consumer and original
            // postchecks. Reobserve the fixed counter before final release.
            observed = reads.read(physical.controller_stage()?, &self.store, &names)?;
            check_active_snapshot(
                &self.store,
                &self.completion,
                &self.activation,
                observed.snapshot(),
            )?;
            reads.check_observation(physical.controller_stage()?, &mut observed)?;
            physical.check()?;
            physical.finish_app_known()
        })();
        if result.is_ok() {
            self.valid = true;
        } else {
            self.storage.refuse();
        }
        result
    }
}
