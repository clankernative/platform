//! Current accepting-policy source; claimed principals still require genuine
//! passkey/executor authentication in the exact-purpose approval producer.
use super::super::ActiveControllerStorageContinuity;
use super::{ControllerAdminReadLoan, EnrolledRoleStage};
use crate::{
    security_epoch::controller::serving_timing::ServingTiming,
    store::{ControllerAdminData, InitialStoreMetadata},
};
use anyhow::{Context as _, Result, ensure};
use day2_capabilities::Digest;

mod authentication_store;
pub(crate) use authentication_store::FencedReadUnit;
pub(in crate::security_epoch) use authentication_store::{
    CompletedCeremony, FencedRegistryLoan, FencedRestoreContinuation, RestoreAuthenticationAction,
    RestoreWriteLoan,
};

/// Fields drop in declaration order: SQLite closes before the actual native
/// loan unwinds. No transaction, Connection, descriptor or native owner getter.
/// Claimed principals are DATA; the producer must authenticate both separately.
pub(crate) struct ControllerAdminReader<'metadata, 'storage, 'role> {
    sqlite: crate::store::ControllerAdminSqlite,
    loan: ControllerAdminReadLoan<'storage, 'role>,
    metadata: &'metadata InitialStoreMetadata,
    selected: AdminSelection,
}

/// A real accepting reader with its original captured BEFORE any reader work.
/// This does not authenticate the executor, consume approval or admit a writer.
/// The fixed execution-ceremony child consumes it; no reader/stage getter exists.
pub(in crate::security_epoch) struct RestoreExecutionReader<'metadata, 'storage, 'role> {
    reader: ControllerAdminReader<'metadata, 'storage, 'role>,
    original: crate::security_epoch::restore_original::RestoreOriginalGuard,
    record: crate::security_epoch::restore_approval::signed::SignedApprovalRecord,
    operation: Digest,
}

// Selection DATA only, not a permission or authentication proof.
struct AdminSelection {
    operation: Digest,
    approver: String,
    executor: String,
    authority: crate::authority_state::AuthorityStamp,
}

/// Snapshot DATA for the closed registry selector. It cannot construct a key
/// source: verification still borrows this same actual native reader.
pub(crate) struct ControllerRegistryData {
    pub(crate) selector: std::path::PathBuf,
    pub(crate) instance: Digest,
    pub(crate) scope: String,
    pub(crate) app: String,
    pub(crate) artifact: String,
    pub(crate) authority: crate::authority_state::AuthorityStamp,
    pub(crate) operation: Digest,
    pub(crate) approver: String,
    pub(crate) executor: String,
}

impl AdminSelection {
    fn capture(
        data: &ControllerAdminData,
        operation: &Digest,
        approver: &str,
        executor: &str,
    ) -> Result<Option<Self>> {
        for actor in [approver, executor] {
            crate::authority::valid_actor(actor)
                .map_err(|_| anyhow::anyhow!("controller_admin_actor_shape"))?;
        }
        ensure!(
            !data.authority.epoch.is_empty() && data.authority.revision > 0,
            "controller_admin_authority_missing"
        );
        if !data.members.contains(approver) || !data.members.contains(executor) {
            return Ok(None);
        }
        let selected = Self {
            operation: operation.clone(),
            approver: approver.to_owned(),
            executor: executor.to_owned(),
            authority: data.authority.clone(),
        };
        selected.check(data)?;
        Ok(Some(selected))
    }

    fn check(&self, data: &ControllerAdminData) -> Result<()> {
        ensure!(
            !self.authority.epoch.is_empty()
                && self.authority.revision > 0
                && data.authority == self.authority
                && data.members.contains(&self.approver)
                && data.members.contains(&self.executor),
            "controller_admin_selection_changed_or_denied"
        );
        Ok(())
    }
}

impl ActiveControllerStorageContinuity {
    /// Fixed accepting source: actual active continuity and same fresh role
    /// original, authenticated App exclusion, then the retained SQL reader.
    /// Principals are ordered approver/executor DATA, never authentication.
    pub(in crate::security_epoch) fn begin_accepting_admin_reader<'metadata, 'storage, 'role>(
        &'storage mut self,
        metadata: &'metadata crate::store::InitialStoreMetadata,
        stage: EnrolledRoleStage<'role>,
        operation: &Digest,
        principals: [&str; 2],
        trace: &'storage ServingTiming,
    ) -> Result<Option<ControllerAdminReader<'metadata, 'storage, 'role>>> {
        let loan = self.begin_admin_read(stage, operation, trace)?;
        ControllerAdminReader::capture(metadata, loan, operation, principals[0], principals[1])
    }
}

impl ActiveControllerStorageContinuity {
    /// Signature/identity fields are still untrusted DATA at this entry. Both
    /// current principals are selected by the actual accepting reader; the
    /// separate fixed execution ceremony authenticates the executor afterwards.
    pub(in crate::security_epoch) fn begin_restore_execution_reader<'metadata, 'storage, 'role>(
        &'storage mut self,
        metadata: &'metadata crate::store::InitialStoreMetadata,
        mut stage: EnrolledRoleStage<'role>,
        record: &crate::security_epoch::restore_approval::signed::SignedApprovalRecord,
        operation: &Digest,
        trace: &'storage ServingTiming,
    ) -> Result<Option<RestoreExecutionReader<'metadata, 'storage, 'role>>> {
        // Complete bounded wire shape only; signature and current trust are
        // verified later under this same genuine accepting owner.
        record.encode()?;
        let mut original = crate::security_epoch::restore_original::RestoreOriginalGuard::capture(
            &mut stage,
            &self.policy,
            &self.store,
            record.statement.request.clone(),
            operation.clone(),
        )?;
        let intent = record.statement.request.intent();
        let Some(mut reader) = self.begin_accepting_admin_reader(
            metadata,
            stage,
            &intent.commitment()?,
            [&record.statement.approver.email, &intent.executor.email],
            trace,
        )?
        else {
            return Ok(None);
        };
        reader.check_execution_original(&mut original, record, operation)?;
        Ok(Some(RestoreExecutionReader {
            reader,
            original,
            record: record.clone(),
            operation: operation.clone(),
        }))
    }
}

impl<'metadata, 'storage, 'role> ControllerAdminReader<'metadata, 'storage, 'role> {
    // Fixed mutual check, not an owner/stage/SQL getter. The captured guard
    // meets only the physical phase already held by this exact reader.
    fn check_execution_original(
        &mut self,
        original: &mut crate::security_epoch::restore_original::RestoreOriginalGuard,
        record: &crate::security_epoch::restore_approval::signed::SignedApprovalRecord,
        operation: &Digest,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            self.check_registry_local()?;
            original.check_join(
                self.loan
                    .physical
                    .as_mut()
                    .context("restore_execution_reader_closed")?
                    .controller_stage()?,
                &record.statement.request,
                operation,
            )?;
            Ok(())
        })();
        let checked = self.check_registry_local();
        if requested.is_err() || checked.is_err() {
            original.refuse();
            self.refuse();
        }
        requested?;
        checked
    }

    /// Actual loan by value, never a historical admin projection or Runtime.
    /// The loan must precede the FIRST SQLite activation of this reader.
    fn capture(
        metadata: &'metadata InitialStoreMetadata,
        mut loan: ControllerAdminReadLoan<'storage, 'role>,
        operation: &Digest,
        approver: &str,
        executor: &str,
    ) -> Result<Option<ControllerAdminReader<'metadata, 'storage, 'role>>> {
        let requested = (|| {
            loan.check_action(metadata, operation)?;
            let mut sqlite = crate::store::ControllerAdminSqlite::open(&mut loan)?;
            let data = sqlite.read(&mut loan, metadata)?;
            let selected = AdminSelection::capture(&data, operation, approver, executor)?;
            loan.check_action(metadata, operation)?;
            Ok((sqlite, selected))
        })();
        let (mut sqlite, selected) = match requested {
            Ok(values) => values,
            Err(error) => {
                loan.refuse();
                return Err(error);
            }
        };
        let Some(selected) = selected else {
            // A known initial policy denial is DATA, just as in member().
            // It escapes only after actual close and known peer settlement.
            let closed = sqlite.close(&mut loan);
            let checked = loan.check_local();
            if closed.is_err() || checked.is_err() {
                loan.refuse();
            }
            closed?;
            checked?;
            loan.finish_checked()?;
            return Ok(None);
        };
        Ok(Some(ControllerAdminReader {
            sqlite,
            loan,
            metadata,
            selected,
        }))
    }
}

impl ControllerAdminReader<'_, '_, '_> {
    /// Full current policy/metadata observation outside any SQL unit owned by
    /// the authentication store. No native owner or permission is returned.
    pub(crate) fn registry_data(&mut self) -> Result<ControllerRegistryData> {
        let operation = self.selected.operation.clone();
        let approver = self.selected.approver.clone();
        let executor = self.selected.executor.clone();
        self.check(self.metadata, &operation, &approver, &executor)?;
        let (selector, instance) = self.metadata.restore_registry_selector_data();
        let value = ControllerRegistryData {
            selector,
            instance,
            scope: self.metadata.scope().to_owned(),
            app: self.metadata.app().to_owned(),
            artifact: self.metadata.artifact().id().to_owned(),
            authority: self.selected.authority.clone(),
            operation,
            approver,
            executor,
        };
        self.check_registry_local()?;
        Ok(value)
    }

    /// SQL-safe retained-resource check for the short closed TrustedKey loan.
    /// No provider/configuration read, policy SQL, new stage or clock is added.
    pub(crate) fn check_registry_local(&mut self) -> Result<()> {
        self.loan.check_local()?;
        let requested = self.sqlite.check_handles();
        let checked = self.loan.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(crate) fn check(
        &mut self,
        metadata: &InitialStoreMetadata,
        operation: &Digest,
        approver: &str,
        executor: &str,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                std::ptr::eq(self.metadata, metadata)
                    && self.selected.operation == *operation
                    && self.selected.approver == approver
                    && self.selected.executor == executor,
                "controller_admin_reader_binding_changed"
            );
            self.loan.check_action(metadata, operation)?;
            let data = self.sqlite.read(&mut self.loan, metadata)?;
            self.selected.check(&data)?;
            self.loan.check_action(metadata, operation)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Last current-policy check, actual SQL close, actual local postcheck,
    /// then known peer/counter settlement. No approval/permission is returned.
    pub(crate) fn finish_checked(mut self) -> Result<()> {
        let operation = self.selected.operation.clone();
        let approver = self.selected.approver.clone();
        let executor = self.selected.executor.clone();
        let requested = self.check(self.metadata, &operation, &approver, &executor);
        let closed = self.sqlite.close(&mut self.loan);
        let checked = self.loan.check_local();
        if requested.is_err() || closed.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        closed?;
        checked?;
        self.loan.finish_checked()
    }

    pub(crate) fn refuse(&mut self) {
        self.loan.refuse();
    }
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <ControllerAdminReader<'static, 'static, 'static> as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(Clone);
    assert_not_impl!(Copy);
    assert_not_impl!(Default);
    assert_not_impl!(std::fmt::Debug);
    assert_not_impl!(Send);
    assert_not_impl!(Sync);
    assert_not_impl!(serde::Serialize);
    assert_not_impl!(serde::Deserialize<'static>);
    macro_rules! closed_execution_reader {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <RestoreExecutionReader<'static, 'static, 'static> as Ambiguous<_>>::check;
        }};
    }
    closed_execution_reader!(Clone);
    closed_execution_reader!(Copy);
    closed_execution_reader!(Default);
    closed_execution_reader!(std::fmt::Debug);
    closed_execution_reader!(Send);
    closed_execution_reader!(Sync);
    closed_execution_reader!(serde::Serialize);
    closed_execution_reader!(serde::Deserialize<'static>);
};

#[cfg(test)]
mod tests;
