//! Same active App owner through the fixed serving acquisition and consumer.
use super::{
    ActiveAppStorageContinuity, CurrentAppServingPhase, ServingDisposition, check_active_snapshot,
    request_names,
};
use crate::security_epoch::{
    AuthenticatedReads,
    native_enrollment::{EnrolledRoleStage, StoragePeerPurpose, StoragePeerRequest},
    serving::CurrentServingPhase,
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
impl ActiveAppStorageContinuity {
    pub(in crate::security_epoch) async fn with_serving_async<'role, T>(
        &mut self,
        stage: &mut EnrolledRoleStage<'role>,
        binding: Digest,
        purpose: crate::security_epoch::serving::ScopePurpose,
        operation: impl AsyncFnOnce(
            &mut dyn CurrentServingPhase,
            &mut EnrolledRoleStage<'role>,
        ) -> Result<T>,
    ) -> crate::security_epoch::serving::ScopeOutcome<T> {
        match self.begin_serving(stage, binding, purpose) {
            Ok(scope) => scope.run_async(stage, operation).await,
            Err(error) => crate::security_epoch::serving::ScopeOutcome::Refused(error),
        }
    }

    fn begin_serving<'storage>(
        &'storage mut self,
        stage: &mut EnrolledRoleStage<'_>,
        binding: Digest,
        purpose: crate::security_epoch::serving::ScopePurpose,
    ) -> Result<CurrentAppServingPhase<'storage>> {
        ensure!(self.valid, "active_app_storage_refused");
        self.valid = false;
        let seed = self.storage.bootstrap_core()?;
        let request = StoragePeerRequest {
            purpose: StoragePeerPurpose::CurrentServing,
            binding: Digest::of(&(
                "day2-current-active-app-storage-v1",
                self.completion.digest()?,
                binding,
            ))?,
        };
        let evidence = crate::security_epoch::serving::ConsumerScopeEvidence::app(
            Digest::of(&(
                "day2-controller-evidence-selection-v1",
                &self.policy,
                &self.store,
            ))?,
            stage.incarnation_data()?,
            request.binding.clone(),
            purpose,
        );
        let mut physical = self.storage.begin_current(stage, request)?;
        physical.await_known(stage)?;
        let mut reads = AuthenticatedReads::acquire(
            &self.policy,
            &self.store,
            day2_capabilities::security_epoch::bootstrap::NativeRole::AppHost,
            stage,
        )?
        .retain_current()?;
        let names = request_names(&self.store, &self.completion)?;
        let observed = reads.read(stage, &self.store, &names)?;
        check_active_snapshot(
            &self.store,
            &self.completion,
            &self.activation,
            observed.snapshot(),
        )?;
        physical.check(stage)?;
        Ok(CurrentAppServingPhase {
            physical,
            reads,
            observed,
            selection: self.store.clone(),
            completion: self.completion.clone(),
            activation: self.activation.clone(),
            seed,
            policy: self.policy.clone(),
            continuation: &mut self.valid,
            disposition: ServingDisposition::Unarmed,
            purpose,
            evidence,
        })
    }

    pub(in crate::security_epoch) fn with_serving<'role, T>(
        &mut self,
        stage: &mut EnrolledRoleStage<'role>,
        binding: Digest,
        purpose: crate::security_epoch::serving::ScopePurpose,
        operation: impl FnOnce(&mut dyn CurrentServingPhase, &mut EnrolledRoleStage<'role>) -> Result<T>,
    ) -> crate::security_epoch::serving::ScopeOutcome<T> {
        match self.begin_serving(stage, binding, purpose) {
            Ok(scope) => scope.run(stage, operation),
            Err(error) => crate::security_epoch::serving::ScopeOutcome::Refused(error),
        }
    }
}
impl<'storage> CurrentAppServingPhase<'storage> {
    pub(in crate::security_epoch) fn reobserve(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        let result = (|| {
            // Check the old observation BEFORE replacing DATA: an expired
            // read/authentication origin cannot be renewed by a fresh reply.
            self.check(stage)?;
            let names = request_names(&self.selection, &self.completion)?;
            let observed = self.reads.read(stage, &self.selection, &names)?;
            check_active_snapshot(
                &self.selection,
                &self.completion,
                &self.activation,
                observed.snapshot(),
            )?;
            self.observed = observed;
            self.check(stage)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn check(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                !*self.continuation && self.disposition != ServingDisposition::Refused,
                "native_serving_scope_refused"
            );
            self.physical.check(stage)?;
            self.reads.check_observation(stage, &mut self.observed)?;
            super::check_active_snapshot(
                &self.selection,
                &self.completion,
                &self.activation,
                self.observed.snapshot(),
            )?;
            self.physical.check(stage)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn admit_runtime_database(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        metadata: &crate::store::InitialStoreMetadata,
        db: &rusqlite::Connection,
    ) -> Result<()> {
        let result = (|| {
            self.check(stage)?;
            ensure!(
                matches!(
                    self.purpose,
                    crate::security_epoch::serving::ScopePurpose::Runtime(
                        crate::security_epoch::serving::RuntimeServingUse::InitialStorage
                    )
                ),
                "native_runtime_initial_admission_purpose_required"
            );
            metadata.require_native_selection(
                &self.selection,
                &self.completion.bootstrap().manifest.artifact,
                &self.policy,
            )?;
            crate::security_epoch::preparation_image::require_existing_selection(
                db,
                &self.seed,
                &self.selection,
            )?;
            self.check(stage)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn check_runtime_selection(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        metadata: &crate::store::InitialStoreMetadata,
    ) -> Result<()> {
        let result = (|| {
            self.check(stage)?;
            ensure!(
                matches!(
                    self.purpose,
                    crate::security_epoch::serving::ScopePurpose::Runtime(
                        crate::security_epoch::serving::RuntimeServingUse::InitialStorage
                    )
                ),
                "native_runtime_initial_admission_purpose_required"
            );
            metadata.require_native_selection(
                &self.selection,
                &self.completion.bootstrap().manifest.artifact,
                &self.policy,
            )?;
            self.check(stage)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn arm(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        self.check(stage)?;
        if self.disposition != ServingDisposition::Unarmed {
            self.refuse();
            anyhow::bail!("native_serving_attempt_already_armed");
        }
        self.disposition = ServingDisposition::Armed;
        self.check(stage)
    }

    pub(in crate::security_epoch) fn finish_known(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        self.check(stage)?;
        if !matches!(
            self.disposition,
            ServingDisposition::Unarmed | ServingDisposition::Armed
        ) {
            self.refuse();
            anyhow::bail!("native_serving_result_already_recorded");
        }
        self.disposition = ServingDisposition::Known;
        self.check(stage)
    }

    pub(in crate::security_epoch) fn finish_excluded(&mut self) -> Result<()> {
        if self.disposition != ServingDisposition::Unarmed {
            self.refuse();
            anyhow::bail!("native_serving_exclusion_after_attempt");
        }
        self.disposition = ServingDisposition::Excluded;
        Ok(())
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.disposition = ServingDisposition::Refused;
        *self.continuation = false;
        self.physical.refuse();
        self.reads.refuse();
    }

    fn finish_scope(mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.check(stage)?;
        ensure!(
            matches!(
                self.disposition,
                ServingDisposition::Known | ServingDisposition::Excluded
            ),
            "native_serving_unknown_result"
        );
        let names = super::request_names(&self.selection, &self.completion)?;
        let observed = self.reads.read(stage, &self.selection, &names)?;
        super::check_active_snapshot(
            &self.selection,
            &self.completion,
            &self.activation,
            observed.snapshot(),
        )?;
        self.observed = observed;
        self.check(stage)?;
        // The exact final coherent provider observation is historical DATA.
        // No completion is exported until the actual peer ACK and postcheck.
        self.evidence
            .snapshot(crate::security_epoch::journal::snapshot_digest(
                self.observed.snapshot(),
            )?);
        let known = self.disposition == ServingDisposition::Known;
        self.physical.finish_checked(stage)?;
        stage.check()?;
        *self.continuation = true;
        if known {
            self.evidence
                .record(crate::security_epoch::serving::ConsumerScopeResult::Completed);
        }
        Ok(())
    }

    pub(super) fn run<'role, T>(
        mut self,
        stage: &mut EnrolledRoleStage<'role>,
        operation: impl FnOnce(&mut dyn CurrentServingPhase, &mut EnrolledRoleStage<'role>) -> Result<T>,
    ) -> crate::security_epoch::serving::ScopeOutcome<T> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check(stage)?;
            operation(
                &mut crate::security_epoch::serving::borrow_current(&mut self),
                stage,
            )
        }));
        self.finish_result(stage, result)
    }

    pub(super) async fn run_async<'role, T>(
        mut self,
        stage: &mut EnrolledRoleStage<'role>,
        operation: impl AsyncFnOnce(
            &mut dyn CurrentServingPhase,
            &mut EnrolledRoleStage<'role>,
        ) -> Result<T>,
    ) -> crate::security_epoch::serving::ScopeOutcome<T> {
        use futures_util::FutureExt;
        let result = std::panic::AssertUnwindSafe(async {
            self.check(stage)?;
            operation(
                &mut crate::security_epoch::serving::borrow_current(&mut self),
                stage,
            )
            .await
        })
        .catch_unwind()
        .await;
        self.finish_result(stage, result)
    }

    fn finish_result<T>(
        mut self,
        stage: &mut EnrolledRoleStage<'_>,
        result: std::thread::Result<Result<T>>,
    ) -> crate::security_epoch::serving::ScopeOutcome<T> {
        match result {
            Ok(Ok(value)) if self.disposition == ServingDisposition::Known => {
                let evidence = self.evidence.clone();
                match self.finish_scope(stage) {
                    Ok(()) => crate::security_epoch::serving::ScopeOutcome::Known(value),
                    Err(error) => {
                        evidence.record(
                            crate::security_epoch::serving::ConsumerScopeResult::FinalScopeRefused,
                        );
                        crate::security_epoch::serving::ScopeOutcome::Refused(error)
                    }
                }
            }
            Ok(Err(error)) if self.disposition == ServingDisposition::Excluded => {
                let evidence = self.evidence.clone();
                match self.finish_scope(stage) {
                    Ok(()) => crate::security_epoch::serving::ScopeOutcome::Excluded(error),
                    Err(cause) => {
                        evidence.record(
                            crate::security_epoch::serving::ConsumerScopeResult::FinalScopeRefused,
                        );
                        crate::security_epoch::serving::ScopeOutcome::Refused(error.context(cause))
                    }
                }
            }
            Ok(Err(error)) => {
                self.refuse();
                self.evidence
                    .record(crate::security_epoch::serving::ConsumerScopeResult::OperationRefused);
                crate::security_epoch::serving::ScopeOutcome::Refused(error)
            }
            Ok(Ok(_)) => {
                self.refuse();
                self.evidence
                    .record(crate::security_epoch::serving::ConsumerScopeResult::Unsettled);
                crate::security_epoch::serving::ScopeOutcome::Refused(anyhow::anyhow!(
                    "native_serving_result_not_settled"
                ))
            }
            Err(payload) => {
                self.refuse();
                self.evidence
                    .record(crate::security_epoch::serving::ConsumerScopeResult::Panicked);
                std::panic::resume_unwind(payload)
            }
        }
    }
}
