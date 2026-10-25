//! Fixed Controller-side active App serving operation. No callback can execute
//! inside the Controller. The signed peer result is released only while the
//! SAME current physical/first-holder and provider observations remain owned.
use super::{
    ActiveControllerStorageContinuity, ServingObservation, check_active_snapshot, request_names,
};
use crate::security_epoch::controller::serving_timing::{ServingStep, ServingTiming};
use crate::security_epoch::self_check_profile::{self, Category, PhysicalStep};
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
        trace: &ServingTiming,
    ) -> Result<ServingObservation> {
        let _profile = self_check_profile::enter(Category::ServingLocal);
        ensure!(self.valid, "active_controller_storage_refused");
        self.valid = false;
        let result = (|| {
            let mut physical = trace.measure(ServingStep::PhysicalBegin, || {
                let _profile = self_check_profile::enter(Category::PhysicalLocal);
                self.storage.begin_current_app(stage, trace)
            })?;
            // Authenticated request selection is DATA. This can only be the
            // original App enrollment and a fresh current-serving transcript.
            let binding = trace.measure(ServingStep::RequestBinding, || {
                Ok(physical.app_request()?.binding.clone())
            })?;
            let mut reads = trace.measure(ServingStep::ProviderAcquire, || {
                AuthenticatedReads::acquire(
                    &self.policy,
                    &self.store,
                    NativeRole::EpochController,
                    self_check_profile::physical(PhysicalStep::ProviderStage, || {
                        physical.controller_stage()
                    })?,
                )?
                .retain_current()
            })?;
            let names = trace.measure(ServingStep::Names, || {
                request_names(&self.store, &self.completion)
            })?;
            let mut observed = trace.measure(ServingStep::CounterBefore, || {
                reads.read(physical.controller_stage()?, &self.store, &names)
            })?;
            trace.measure(ServingStep::ValidateBefore, || {
                check_active_snapshot(
                    &self.store,
                    &self.completion,
                    &self.activation,
                    observed.snapshot(),
                )
            })?;
            trace.measure(ServingStep::PhysicalBefore, || physical.check())?;
            trace.measure(ServingStep::ProviderBefore, || {
                reads.check_observation(physical.controller_stage()?, &mut observed)
            })?;
            trace.measure(ServingStep::Announcement, || physical.announce_app_known())?;
            trace.measure(ServingStep::Acknowledgement, || {
                physical.await_app_consumed()
            })?;
            // The actual App has now recorded its consumer and original
            // postchecks. Reobserve the fixed counter before final release.
            observed = trace.measure(ServingStep::CounterAfter, || {
                reads.read(physical.controller_stage()?, &self.store, &names)
            })?;
            trace.measure(ServingStep::ValidateAfter, || {
                check_active_snapshot(
                    &self.store,
                    &self.completion,
                    &self.activation,
                    observed.snapshot(),
                )
            })?;
            trace.measure(ServingStep::ProviderAfter, || {
                reads.check_observation(physical.controller_stage()?, &mut observed)
            })?;
            trace.measure(ServingStep::PhysicalAfter, || physical.check())?;
            let snapshot = trace.measure(ServingStep::Snapshot, || {
                super::super::journal::snapshot_digest(observed.snapshot())
            })?;
            trace.measure(ServingStep::Release, || physical.finish_app_known())?;
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
        mut stage: EnrolledRoleStage<'_>,
        peer: &mut crate::security_epoch::native_enrollment::ControllerServingPeer,
    ) -> Result<ServingObservation> {
        ensure!(self.valid, "active_controller_storage_refused");
        self.valid = false;
        let result = (|| {
            let pending = self.storage.begin_pending_current_controller()?;
            let rendezvous = peer.prepare_current(&mut stage)?;
            let mut physical = pending.acquire(stage)?;
            let mut shell = rendezvous.accept_current(physical.controller_stage()?)?;
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
