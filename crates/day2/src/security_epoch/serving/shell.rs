//! A genuine Shell role channel composed with the Controller's SAME physical
//! and current epoch scope. The Shell receives no App database identity.
use super::{CurrentServingPhase, CurrentShellServingPhase, ScopeOutcome, sealed};
use crate::security_epoch::{
    bootstrap::ServingDisposition,
    native_enrollment::{EnrolledRoleStage, ShellServingPeer},
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;

pub(super) fn with_current<'role, T>(
    peer: &mut ShellServingPeer,
    stage: &mut EnrolledRoleStage<'role>,
    binding: Digest,
    operation: impl FnOnce(&mut dyn CurrentServingPhase, &mut EnrolledRoleStage<'role>) -> Result<T>,
) -> ScopeOutcome<T> {
    let result = (|| {
        let mut phase = peer.begin_current(stage, binding)?;
        // The Controller retains current file/P3 and epoch observations until
        // the actual consumer's original postchecks and final acknowledgement.
        phase.await_known(stage)?;
        Ok(CurrentShellServingPhase {
            peer: phase,
            disposition: ServingDisposition::Unarmed,
        })
    })();
    match result {
        Ok(scope) => scope.run(stage, operation),
        Err(error) => ScopeOutcome::Refused(error),
    }
}

impl CurrentShellServingPhase<'_> {
    fn check(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        let result = (|| {
            ensure!(
                self.disposition != ServingDisposition::Refused,
                "native_shell_serving_refused"
            );
            self.peer.check(stage)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn refuse(&mut self) {
        self.disposition = ServingDisposition::Refused;
        self.peer.refuse();
    }

    fn finish_scope(mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.check(stage)?;
        ensure!(
            matches!(
                self.disposition,
                ServingDisposition::Known | ServingDisposition::Excluded
            ),
            "native_shell_serving_unknown_result"
        );
        self.peer.finish_checked(stage)
    }

    fn run<'role, T>(
        mut self,
        stage: &mut EnrolledRoleStage<'role>,
        operation: impl FnOnce(&mut dyn CurrentServingPhase, &mut EnrolledRoleStage<'role>) -> Result<T>,
    ) -> ScopeOutcome<T> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check(stage)?;
            operation(&mut ShellBorrow { owner: &mut self }, stage)
        }));
        match result {
            Ok(Ok(value)) if self.disposition == ServingDisposition::Known => {
                match self.finish_scope(stage) {
                    Ok(()) => ScopeOutcome::Known(value),
                    Err(error) => ScopeOutcome::Refused(error),
                }
            }
            Ok(Err(error)) if self.disposition == ServingDisposition::Excluded => {
                match self.finish_scope(stage) {
                    Ok(()) => ScopeOutcome::Excluded(error),
                    Err(cause) => ScopeOutcome::Refused(error.context(cause)),
                }
            }
            Ok(Err(error)) => {
                self.refuse();
                ScopeOutcome::Refused(error)
            }
            Ok(Ok(_)) => {
                self.refuse();
                ScopeOutcome::Refused(anyhow::anyhow!("native_shell_serving_result_not_settled"))
            }
            Err(payload) => {
                self.refuse();
                std::panic::resume_unwind(payload)
            }
        }
    }
}

struct ShellBorrow<'phase, 'peer> {
    owner: &'phase mut CurrentShellServingPhase<'peer>,
}
impl sealed::NativeServingOwner for ShellBorrow<'_, '_> {}
impl CurrentServingPhase for ShellBorrow<'_, '_> {
    fn check(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.owner.check(stage)
    }

    fn arm(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.owner.check(stage)?;
        if self.owner.disposition != ServingDisposition::Unarmed {
            self.owner.refuse();
            anyhow::bail!("native_shell_serving_already_armed");
        }
        self.owner.disposition = ServingDisposition::Armed;
        self.owner.check(stage)
    }

    fn finish_known(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.owner.check(stage)?;
        if !matches!(
            self.owner.disposition,
            ServingDisposition::Unarmed | ServingDisposition::Armed
        ) {
            self.owner.refuse();
            anyhow::bail!("native_shell_serving_result_already_recorded");
        }
        self.owner.disposition = ServingDisposition::Known;
        self.owner.check(stage)
    }

    fn finish_excluded(&mut self) -> Result<()> {
        if self.owner.disposition != ServingDisposition::Unarmed {
            self.owner.refuse();
            anyhow::bail!("native_shell_serving_exclusion_after_attempt");
        }
        self.owner.disposition = ServingDisposition::Excluded;
        Ok(())
    }

    fn check_runtime_selection(
        &mut self,
        _stage: &mut EnrolledRoleStage<'_>,
        _metadata: &crate::store::InitialStoreMetadata,
    ) -> Result<()> {
        self.owner.refuse();
        anyhow::bail!("native_shell_has_no_database_identity")
    }

    fn admit_runtime_database(
        &mut self,
        _stage: &mut EnrolledRoleStage<'_>,
        _metadata: &crate::store::InitialStoreMetadata,
        _db: &rusqlite::Connection,
    ) -> Result<()> {
        self.owner.refuse();
        anyhow::bail!("native_shell_has_no_database_identity")
    }

    fn refuse(&mut self) {
        self.owner.refuse();
    }
}
