//! Fixed Controller-side active App serving operation. No callback can execute
//! inside the Controller. The signed peer result is released only while the
//! SAME current physical/first-holder and provider observations remain owned.
use super::{
    ActiveControllerStorageContinuity, ServingObservation, check_active_snapshot, request_names,
};
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
    ) -> Result<ServingObservation> {
        ensure!(self.valid, "active_controller_storage_refused");
        self.valid = false;
        let result = (|| {
            let mut physical = self.storage.begin_current_app(stage)?;
            // Authenticated request selection is DATA. This can only be the
            // original App enrollment and a fresh current-serving transcript.
            let binding = physical.app_request()?.binding.clone();
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
            let snapshot = super::super::journal::snapshot_digest(observed.snapshot())?;
            physical.finish_app_known()?;
            Ok(ServingObservation { binding, snapshot })
        })();
        if result.is_ok() {
            self.valid = true;
        } else {
            self.storage.refuse();
        }
        result
    }
}

impl ActiveControllerStorageContinuity {
    /// The Shell's actual role channel remains borrowed alongside the SAME
    /// physical file/provider scope. Original App liveness is retained here;
    /// it is never interpreted as a fresh App role or Shell database identity.
    pub(in crate::security_epoch) fn serve_shell_current(
        &mut self,
        stage: EnrolledRoleStage<'_>,
        peer: &mut crate::security_epoch::native_enrollment::ControllerServingPeer,
    ) -> Result<ServingObservation> {
        ensure!(self.valid, "active_controller_storage_refused");
        self.valid = false;
        let result = (|| {
            let mut physical = self.storage.begin_current_controller(stage)?;
            let mut shell = peer.accept_current(physical.controller_stage()?)?;
            let binding = shell.request_binding().clone();
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
            shell.check(physical.controller_stage()?)?;
            shell.announce_known(physical.controller_stage()?)?;
            shell.await_consumed(physical.controller_stage()?)?;
            observed = reads.read(physical.controller_stage()?, &self.store, &names)?;
            check_active_snapshot(
                &self.store,
                &self.completion,
                &self.activation,
                observed.snapshot(),
            )?;
            reads.check_observation(physical.controller_stage()?, &mut observed)?;
            physical.check()?;
            shell.check(physical.controller_stage()?)?;
            shell.release(physical.controller_stage()?)?;
            shell.finish_checked(physical.controller_stage()?)?;
            let snapshot = super::super::journal::snapshot_digest(observed.snapshot())?;
            physical.finish_controller_known()?;
            Ok(ServingObservation { binding, snapshot })
        })();
        if result.is_ok() {
            self.valid = true;
        } else {
            self.storage.refuse();
            peer.refuse();
        }
        result
    }
}
