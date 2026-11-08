//! One retained native stop/fenced-write owner. DATA plans and a peer ACK
//! cannot construct it; the sole construction path must finish actual known
//! grant-use/root-fence send/readback and the complete real peer/issuer stop.
use super::super::super::super::super::ControllerAdminReadLoan;
use super::super::super::super::ControllerAdminReader;
use super::super::super::RestoreAuthenticationAction;
use super::{
    AuthenticatedRestoreExecution, ExecutionCompletion, RestoreOriginalGuard, SignedApprovalRecord,
    approval_window,
};
use crate::security_epoch::{
    kernel::{self, restore::approval_use},
    native_enrollment::{AuthorityStopData, FrozenRoleIssuer},
    restore_original::RestoreObservation,
};
use anyhow::{Context as _, Result, ensure};
use day2_capabilities::Digest;
use std::{cell::Cell, rc::Rc};

impl<'metadata, 'storage, 'role> AuthenticatedRestoreExecution<'metadata, 'storage, 'role> {
    /// Consume the actual authenticated executor and retain its same original
    /// through known reservation, complete stop and writer handoff. This source
    /// interface refuses until those accepting operations are implemented.
    pub(in crate::security_epoch) fn stop_for_restore(
        mut self,
        _intent: &kernel::restore::Intent,
    ) -> Result<FencedRestoreContinuation<'metadata, 'storage, 'role>> {
        self.refuse();
        anyhow::bail!("native_restore_stop_supplier_unavailable")
    }
}

/// A closed borrow of the actual authenticated executor's fields, keeping its
/// native source separately borrowable. No factory accepts replacement fields
/// or returns a source, stage, clock, descriptor or callback permission.
pub(in crate::security_epoch) struct ExecutionSourceLoan<'borrow, 'metadata, 'storage, 'role> {
    action: &'borrow mut RestoreAuthenticationAction<'metadata, 'storage, 'role>,
    original: &'borrow mut RestoreOriginalGuard,
    completion: &'borrow mut ExecutionCompletion,
    record: &'borrow SignedApprovalRecord,
    operation: &'borrow Digest,
    time_operation: &'borrow Digest,
    refused: &'borrow mut bool,
}

impl AuthenticatedRestoreExecution<'_, '_, '_> {
    pub(super) fn check_source(&mut self) -> Result<RestoreObservation> {
        ExecutionSourceLoan {
            action: &mut self.action,
            original: &mut self.original,
            completion: &mut self.completion,
            record: &self.record,
            operation: &self.operation,
            time_operation: &self.time_operation,
            refused: &mut self.refused,
        }
        .check(&mut self.source)
    }
}

impl AuthenticatedRestoreExecution<'_, '_, '_> {
    /// One native acquisition of the whole exact archive key set, before the
    /// Fenced CAS. The actual executor owns the material across the handoff.
    pub(in crate::security_epoch) fn retain_historical_keys(
        &mut self,
        intent: &kernel::restore::Intent,
    ) -> Result<()> {
        let requested = (|| {
            ensure!(
                self.historical_keys.is_none(),
                "restore_keys_already_retained"
            );
            let mut loan = ExecutionSourceLoan {
                action: &mut self.action,
                original: &mut self.original,
                completion: &mut self.completion,
                record: &self.record,
                operation: &self.operation,
                time_operation: &self.time_operation,
                refused: &mut self.refused,
            };
            let keys = self.source.retain_historical_keys(&mut loan, intent)?;
            loan.check(&mut self.source)?;
            self.historical_keys = Some(keys);
            Ok(())
        })();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }

    /// This supplies no list/permission to a caller. Current authority and the
    /// unchanged original are checked before the actual retained material.
    pub(in crate::security_epoch) fn require_historical_keys(
        &mut self,
        intent: &kernel::restore::Intent,
    ) -> Result<()> {
        let requested = (|| {
            self.check()?;
            self.historical_keys
                .as_mut()
                .context("restore_keys_not_retained")?
                .require(intent, &self.record, &self.operation)
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked.map(|_| ())
    }
}

impl ExecutionSourceLoan<'_, '_, '_, '_> {
    pub(in crate::security_epoch) fn request_commitment_data(&self) -> Result<Digest> {
        self.record.statement.request.commitment()
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        *self.refused = true;
        self.original.refuse();
        self.action.refuse();
    }

    /// Selection DATA from the actual reader's admitted metadata, with the
    /// exact signed archive/target/operation and unchanged custody. No key or
    /// provider authority is returned by resolving this configuration.
    pub(in crate::security_epoch) fn historical_key_data(
        &mut self,
        selected: &day2_capabilities::security_epoch::EpochStore,
        policy: &day2_capabilities::security_epoch::bootstrap::InitialBootstrapPolicy,
        intent: &kernel::restore::Intent,
    ) -> Result<Vec<crate::artifact::SecurityKeySelection>> {
        let requested = (|| {
            let request = &self.record.statement.request;
            intent.commitment(selected)?;
            ensure!(
                intent.operation == *self.operation
                    && intent.archive.full_archive_digest == request.full_archive_digest
                    && intent.target_incarnation == request.target.incarnation
                    && intent.archive.artifact == request.target.artifact
                    && intent.archive.schema == request.target.schema
                    && request.target.selection == Digest::of(selected)?
                    && request.target.authority == selected.authority_key()?
                    && request.target.scope == selected.scope
                    && request.target.security_epoch == 2
                    && intent
                        .archive
                        .required_keys
                        .iter()
                        .filter(|key| key.purpose == kernel::restore::KeyPurpose::CustodyEncryption)
                        .all(|key| key.binding == request.custody),
                "restore_keys_approval_binding_changed"
            );
            let instance = self.action.reader.metadata.require_native_selection(
                selected,
                &request.target.artifact,
                policy,
            )?;
            ensure!(
                instance.security_key_set(selected.scope.app.as_str())? == selected.key_set,
                "restore_keys_current_key_set_changed"
            );
            instance.security_key_selections(selected.scope.app.as_str())
        })();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }

    pub(in crate::security_epoch) fn check(
        &mut self,
        source: &mut crate::security_epoch::storage_authority::NativeApprovalSource,
    ) -> Result<RestoreObservation> {
        let requested = (|| {
            ensure!(!*self.refused, "restore_executor_refused");
            self.action
                .check_execution_original(self.original, self.record, self.operation)?;
            self.completion.check_current(
                &mut self.action.reader,
                (
                    self.action
                        .sqlite
                        .as_mut()
                        .context("restore_auth_sqlite_closed")?,
                    &mut self.action.files,
                ),
                self.record,
                self.operation,
            )?;
            source.require_qualified(self.time_operation)?;
            let time = source.current_time(self.action)?;
            approval_window(self.record, &time)?;
            Ok(())
        })();
        // The same original's postcheck still runs on a primary failure.
        // The first failure remains primary; no Source operation can reset it.
        let checked =
            self.action
                .check_execution_original(self.original, self.record, self.operation);
        if requested.is_err() || checked.is_err() {
            *self.refused = true;
            self.original.refuse();
            self.action.refuse();
        }
        requested?;
        checked
    }
}

pub(in crate::security_epoch) struct FencedRestoreContinuation<'metadata, 'storage, 'role> {
    auth: AuthenticatedRestoreExecution<'metadata, 'storage, 'role>,
    issuer: FrozenRoleIssuer,
    plan: approval_use::Plan,
    observed: kernel::Snapshot,
    stopped: AuthorityStopData,
    writer_borrowed: Cell<bool>,
    refused: Rc<Cell<bool>>,
}

/// Exclusive, one-use loan. Parent keeps this exact borrow across creation,
/// SQL reset, P3, writer and activation. It has no descriptor/role/HTTP getter.
pub(in crate::security_epoch) struct RestoreWriteLoan<'borrow, 'metadata, 'storage, 'role> {
    owner: &'borrow mut FencedRestoreContinuation<'metadata, 'storage, 'role>,
    _lost: LostRestoreLoan,
}

// A negative-only, nongeneric Drop owner. A lost loan irreversibly refuses
// the exact still-retained continuation, including after its last good check.
struct LostRestoreLoan {
    refused: Rc<Cell<bool>>,
}

impl Drop for LostRestoreLoan {
    fn drop(&mut self) {
        self.refused.set(true);
    }
}

/// Fixed post-fence policy loan, created only while borrowing the actual
/// known-CAS owner. The Active reader's freshness path is not reused or widened.
pub(crate) struct FencedReadUnit<'borrow, 'storage, 'role> {
    loan: &'borrow mut ControllerAdminReadLoan<'storage, 'role>,
    metadata: &'borrow crate::store::InitialStoreMetadata,
    expected: &'borrow kernel::Snapshot,
}

impl FencedReadUnit<'_, '_, '_> {
    pub(crate) fn check_current(&mut self) -> Result<()> {
        let requested = (|| {
            self.loan.disposition.require_closed()?;
            self.loan.check_local()?;
            self.metadata.require_native_selection(
                &self.loan.selection,
                &self.loan.policy.runtime_profile.app_artifact,
                &self.loan.policy,
            )?;
            let physical = self
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let names = crate::security_epoch::bootstrap::request_names(
                &self.loan.selection,
                &self.loan.completion,
            )?;
            let mut observed =
                self.loan
                    .reads
                    .read(physical.controller_stage()?, &self.loan.selection, &names)?;
            ensure!(
                observed.snapshot() == self.expected
                    && matches!(
                        &observed
                            .snapshot()
                            .root
                            .as_ref()
                            .context("native_restore_fenced_root_missing")?
                            .value
                            .phase,
                        kernel::Phase::Fenced { .. }
                    ),
                "native_restore_fenced_registry_changed"
            );
            self.loan
                .reads
                .check_observation(physical.controller_stage()?, &mut observed)?;
            self.loan.check_local()
        })();
        let checked = self.loan.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(crate) fn check_metadata(
        &mut self,
        metadata: &crate::store::InitialStoreMetadata,
    ) -> Result<()> {
        if !std::ptr::eq(self.metadata, metadata) {
            self.refuse();
            anyhow::bail!("native_restore_fenced_metadata_substituted");
        }
        self.check_current()
    }

    pub(crate) fn check_local(&mut self) -> Result<()> {
        self.loan.check_local()
    }
    pub(crate) fn check_database(&mut self, db: &rusqlite::Connection) -> Result<()> {
        self.loan.check_database(db)
    }
    pub(crate) fn begin_retained_sql(&mut self, db: &rusqlite::Connection) -> Result<()> {
        self.loan.begin_retained_sql(db)
    }
    pub(crate) fn end_retained_sql(
        &mut self,
        db: &rusqlite::Connection,
        completed: &Result<()>,
    ) -> Result<()> {
        self.loan.end_retained_sql(db, completed)
    }
    pub(crate) fn end_sql(&mut self, completed: &Result<()>) -> Result<()> {
        self.loan.end_sql(completed)
    }
    pub(crate) fn refuse(&mut self) {
        self.loan.refuse();
    }
}

pub(in crate::security_epoch) struct FencedRegistryLoan<'borrow, 'metadata, 'storage, 'role> {
    reader: &'borrow mut ControllerAdminReader<'metadata, 'storage, 'role>,
    expected: &'borrow kernel::Snapshot,
}

impl FencedRegistryLoan<'_, '_, '_, '_> {
    pub(in crate::security_epoch) fn registry_data(
        &mut self,
    ) -> Result<crate::security_epoch::ControllerRegistryData> {
        let requested: Result<crate::security_epoch::ControllerRegistryData> = (|| {
            let reader = &mut *self.reader;
            let mut unit = FencedReadUnit {
                loan: &mut reader.loan,
                metadata: reader.metadata,
                expected: self.expected,
            };
            let data = reader.sqlite.read_fenced(&mut unit, reader.metadata)?;
            reader.selected.check(&data)?;
            let (selector, instance) = reader.metadata.restore_registry_selector_data();
            Ok(crate::security_epoch::ControllerRegistryData {
                selector,
                instance,
                scope: reader.metadata.scope().to_owned(),
                app: reader.metadata.app().to_owned(),
                artifact: reader.metadata.artifact().id().to_owned(),
                authority: reader.selected.authority.clone(),
                operation: reader.selected.operation.clone(),
                approver: reader.selected.approver.clone(),
                executor: reader.selected.executor.clone(),
            })
        })();
        let checked = self.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let data = requested?;
        checked?;
        Ok(data)
    }

    pub(in crate::security_epoch) fn check_local(&mut self) -> Result<()> {
        self.reader.check_registry_local()
    }
    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.reader.refuse();
    }
}

impl<'metadata, 'storage, 'role> FencedRestoreContinuation<'metadata, 'storage, 'role> {
    pub(in crate::security_epoch) fn borrow_write(
        &mut self,
    ) -> Result<RestoreWriteLoan<'_, 'metadata, 'storage, 'role>> {
        if self.writer_borrowed.replace(true) {
            self.refuse();
            anyhow::bail!("native_restore_writer_loan_spent");
        }
        self.check_current()?;
        let lost = LostRestoreLoan {
            refused: Rc::clone(&self.refused),
        };
        Ok(RestoreWriteLoan {
            owner: self,
            _lost: lost,
        })
    }

    // Pessimistic refusal is set before any real checker. If an unwind is
    // caught while this same loan survives, no success tail ran to restore
    // availability. This needs no generic destructor or reconstructed guard.
    fn check_local(&mut self) -> Result<()> {
        if self.refused.get() {
            self.refuse();
            anyhow::bail!("native_restore_continuation_refused");
        }
        self.refused.set(true);
        let result = self.check_local_inner();
        if result.is_ok() {
            self.refused.set(false);
        } else {
            self.refuse();
        }
        result
    }

    fn check_current(&mut self) -> Result<RestoreObservation> {
        if self.refused.get() {
            self.refuse();
            anyhow::bail!("native_restore_continuation_refused");
        }
        self.refused.set(true);
        let result = self.check_current_inner();
        if result.is_ok() {
            self.refused.set(false);
        } else {
            self.refuse();
        }
        result
    }

    fn check_local_inner(&mut self) -> Result<()> {
        let requested = (|| {
            self.auth.action.check_local()?;
            self.auth
                .historical_keys
                .as_mut()
                .context("restore_keys_not_retained")?
                .check_retained(&self.auth.record, &self.auth.operation)?;
            let physical = self
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let observed = self.auth.original.check_join(
                physical.controller_stage()?,
                &self.auth.record.statement.request,
                &self.auth.operation,
            )?;
            self.issuer
                .check(&mut physical.controller_stage()?.storage()?)?;
            let (domain, origin, deadline) = observed.interval_data();
            ensure!(
                origin < deadline
                    && observed.observation_data().1 < deadline
                    && !domain.as_str().is_empty(),
                "native_restore_original_changed"
            );
            self.auth.action.check_local()
        })();
        let checked = self.auth.action.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    fn check_current_inner(&mut self) -> Result<RestoreObservation> {
        let requested = (|| {
            self.check_local_inner()?;
            super::super::super::require_outside_unit(
                self.auth
                    .action
                    .sqlite
                    .as_ref()
                    .context("restore_auth_sqlite_closed")?,
            )?;
            // This is a separate fixed fenced-policy read. The old Active-only
            // Action/Reader check and terminal route are never widened.
            let reader = &mut self.auth.action.reader;
            let mut loan = FencedRegistryLoan {
                reader,
                expected: &self.observed,
            };
            self.auth.completion.check_fenced(
                &mut loan,
                (
                    self.auth
                        .action
                        .sqlite
                        .as_mut()
                        .context("restore_auth_sqlite_closed")?,
                    &mut self.auth.action.files,
                ),
                &self.auth.record,
                &self.auth.operation,
            )?;
            self.auth
                .source
                .require_qualified(&self.auth.time_operation)?;
            let physical = self
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let time = self.auth.source.current_fenced_time(physical)?;
            approval_window(&self.auth.record, &time)?;
            let names = crate::security_epoch::bootstrap::request_names(
                &self.auth.action.reader.loan.selection,
                &self.auth.action.reader.loan.completion,
            )?;
            let mut fresh = self.auth.action.reader.loan.reads.read(
                physical.controller_stage()?,
                &self.auth.action.reader.loan.selection,
                &names,
            )?;
            ensure!(
                fresh.snapshot() == &self.observed
                    && self.stopped.root == Digest::of(&self.plan.reservation.advance.root)?
                    && self
                        .observed
                        .root
                        .as_ref()
                        .is_some_and(|r| r.value == self.plan.reservation.advance.root)
                    && self
                        .observed
                        .sentinel
                        .as_ref()
                        .is_some_and(|r| r.value == self.plan.reservation.advance.sentinel),
                "native_restore_fenced_readset_changed"
            );
            self.auth
                .action
                .reader
                .loan
                .reads
                .check_observation(physical.controller_stage()?, &mut fresh)?;
            physical.require_restore_stopped(&self.stopped)?;
            self.auth.original.check_join(
                physical.controller_stage()?,
                &self.auth.record.statement.request,
                &self.auth.operation,
            )
        })();
        let checked = self.check_local_inner();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let observed = requested?;
        checked?;
        Ok(observed)
    }

    fn refuse(&mut self) {
        self.refused.set(true);
        self.auth.refuse();
        self.issuer.refuse();
    }
}

impl RestoreWriteLoan<'_, '_, '_, '_> {
    /// Bind the actual retained plan/approval and namespace generation before
    /// the first source read or creator effect. Neither caller DATA nor root
    /// identity is a substitute for this same-original owner check.
    pub(in crate::security_epoch) fn require_staging_input(
        &mut self,
        _intent: &kernel::restore::Intent,
        _namespace: &day2_capabilities::credentials::Namespace,
    ) -> Result<()> {
        self.refuse();
        anyhow::bail!("native_restore_staging_input_supplier_unavailable")
    }

    /// Admission precedes Parent construction and its first mkdir/create.
    /// The accepting implementation must bind the target from this actual
    /// owner's Fenced plan, never from a caller flag or a directory identity.
    pub(in crate::security_epoch) fn admit_creator_root(
        &mut self,
        _held_root: &std::fs::File,
    ) -> Result<crate::security_epoch::storage_authority::RestoreCreatorRoot> {
        self.refuse();
        anyhow::bail!("native_restore_creator_root_supplier_unavailable")
    }

    /// The report and file are inputs, not completion or P3 authority. The
    /// fixed implementation must verify the actual retained creator and same
    /// reservation, perform one known settlement and check the whole readback.
    pub(in crate::security_epoch) fn settle_target(
        &mut self,
        _held_creator: &std::fs::File,
        _report: &kernel::restore::completion::TargetReport,
    ) -> Result<kernel::restore::completion::Receipt> {
        self.refuse();
        anyhow::bail!("native_restore_target_settlement_unavailable")
    }

    /// Admit the genuine new holder/P3 and update this same retained owner's
    /// phase only after its known conditional write, strong complete read and
    /// mandatory postchecks. A holder or historical receipt supplies no grant.
    pub(in crate::security_epoch) fn activate_writer(
        &mut self,
        _held_creator: &std::fs::File,
        _holder: &kernel::Holder,
    ) -> Result<kernel::restore::writer::Receipt> {
        self.refuse();
        anyhow::bail!("native_restore_writer_transition_unavailable")
    }

    pub(in crate::security_epoch) fn check_current(&mut self) -> Result<RestoreObservation> {
        self.owner.check_current()
    }
    pub(in crate::security_epoch) fn check_local(&mut self) -> Result<()> {
        self.owner.check_local()
    }
    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.owner.refuse();
    }
}

// The loan is permanently spent before it can escape borrow_write; its
// nongeneric lost-loan owner also refuses the retained continuation on Drop.
// Full owner abandonment drops its real
// OriginalGuard, issuer and CounterUseGuard; the old active continuation was
// pessimistically false before acquisition and is never restored here.

// Compiler controls complement the exact owning-module API inventory. None of
// these retained owners/loans is reconstructible, transferable or serializable.
const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <LostRestoreLoan as Ambiguous<_>>::check;
            let _ = <crate::security_epoch::storage_authority::RestoreCreatorRoot as Ambiguous<
                _,
            >>::check;

            let _ = <ExecutionSourceLoan<'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <crate::security_epoch::storage_authority::HistoricalKeyAvailability as Ambiguous<_>>::check;
            let _ =
                <ExecutionSourceLoan<'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <FencedRestoreContinuation<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoreWriteLoan<'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <FencedReadUnit<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <FencedRegistryLoan<'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
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
};

#[cfg(test)]
mod tests {
    use super::LostRestoreLoan;
    use anyhow::Result;
    use quote::ToTokens as _;
    use std::{cell::Cell, rc::Rc};

    fn source_method(source: &str, owner: &str, name: &str) -> Result<syn::Block> {
        let mut found = Vec::new();
        for item in syn::parse_file(source)?.items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            let syn::Type::Path(path) = &*item.self_ty else {
                continue;
            };
            if !path
                .path
                .segments
                .last()
                .is_some_and(|part| part.ident == owner)
            {
                continue;
            }
            for member in item.items {
                if let syn::ImplItem::Fn(method) = member
                    && method.sig.ident == name
                {
                    found.push(method.block);
                }
            }
        }
        anyhow::ensure!(found.len() == 1, "one actual owning method required");
        Ok(found.remove(0))
    }

    fn source_loan_wiring(parent: &str, leaf: &str) -> Result<bool> {
        let delegate = source_method(parent, "AuthenticatedRestoreExecution", "check")?;
        let expected_delegate: syn::Block = syn::parse_quote!({ self.check_source() });
        if delegate.to_token_stream().to_string() != expected_delegate.to_token_stream().to_string()
        {
            return Ok(false);
        }
        let borrow = source_method(leaf, "AuthenticatedRestoreExecution", "check_source")?;
        let expected_borrow: syn::Block = syn::parse_quote!({
            ExecutionSourceLoan {
                action: &mut self.action,
                original: &mut self.original,
                completion: &mut self.completion,
                record: &self.record,
                operation: &self.operation,
                time_operation: &self.time_operation,
                refused: &mut self.refused,
            }
            .check(&mut self.source)
        });
        if borrow.to_token_stream().to_string() != expected_borrow.to_token_stream().to_string() {
            return Ok(false);
        }
        #[derive(Default)]
        struct Calls(Vec<String>);
        impl<'ast> syn::visit::Visit<'ast> for Calls {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                self.0.push(call.method.to_string());
                syn::visit::visit_expr_method_call(self, call);
            }
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if let syn::Expr::Path(path) = &*call.func
                    && let Some(name) = path.path.get_ident()
                {
                    self.0.push(name.to_string());
                }
                syn::visit::visit_expr_call(self, call);
            }
        }
        let body = source_method(leaf, "ExecutionSourceLoan", "check")?;
        // The mandatory postcheck is a direct top-level call, including when
        // requested already failed; a closure gated on requested is not equal.
        let Some(syn::Stmt::Local(checked)) = body.stmts.get(1) else {
            return Ok(false);
        };
        let syn::Pat::Ident(binding) = &checked.pat else {
            return Ok(false);
        };
        let Some(initializer) = &checked.init else {
            return Ok(false);
        };
        let syn::Expr::MethodCall(call) = &*initializer.expr else {
            return Ok(false);
        };
        let arguments: Vec<_> = call
            .args
            .iter()
            .map(|argument| argument.to_token_stream().to_string())
            .collect();
        if binding.ident != "checked"
            || initializer.diverge.is_some()
            || call.method != "check_execution_original"
            || call.receiver.to_token_stream().to_string() != "self . action"
            || arguments != ["self . original", "self . record", "self . operation"]
        {
            return Ok(false);
        }
        let Some(syn::Stmt::Local(requested)) = body.stmts.first() else {
            return Ok(false);
        };
        let Some(initializer) = &requested.init else {
            return Ok(false);
        };
        let syn::Expr::Call(call) = &*initializer.expr else {
            return Ok(false);
        };
        // The production immediately-invoked closure is parenthesized in
        // syn; inspect that actual callee before checking its closure body.
        let syn::Expr::Paren(callee) = &*call.func else {
            return Ok(false);
        };
        let syn::Expr::Closure(closure) = &*callee.expr else {
            return Ok(false);
        };
        let syn::Expr::Block(requested) = &*closure.body else {
            return Ok(false);
        };
        let Some(syn::Stmt::Macro(guard)) = requested.block.stmts.first() else {
            return Ok(false);
        };
        if !guard.mac.path.is_ident("ensure") {
            return Ok(false);
        }
        use syn::parse::Parser as _;
        let arguments = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
            .parse2(guard.mac.tokens.clone())?;
        let expected: syn::Expr = syn::parse_quote!(!*self.refused);
        let code: syn::Expr = syn::parse_quote!("restore_executor_refused");
        if arguments.len() != 2
            || arguments
                .first()
                .map(|argument| argument.to_token_stream().to_string())
                != Some(expected.to_token_stream().to_string())
            || arguments
                .last()
                .map(|argument| argument.to_token_stream().to_string())
                != Some(code.to_token_stream().to_string())
        {
            return Ok(false);
        }
        let mut calls = Calls::default();
        syn::visit::Visit::visit_block(&mut calls, &body);
        let relevant = [
            "check_execution_original",
            "check_current",
            "require_qualified",
            "current_time",
            "approval_window",
            "is_err",
            "refuse",
        ];
        let flow: Vec<_> = calls
            .0
            .iter()
            .filter(|name| relevant.contains(&name.as_str()))
            .map(String::as_str)
            .collect();
        if flow
            != [
                "check_execution_original",
                "check_current",
                "require_qualified",
                "current_time",
                "approval_window",
                "check_execution_original",
                "is_err",
                "is_err",
                "refuse",
                "refuse",
            ]
        {
            return Ok(false);
        }
        if calls.0.iter().any(|name| {
            ["begin", "capture", "narrow", "authenticate", "clone"].contains(&name.as_str())
        }) || body.stmts.len() != 5
        {
            return Ok(false);
        }
        let refusal: syn::Stmt = syn::parse_quote! {
            if requested.is_err() || checked.is_err() {
                *self.refused = true;
                self.original.refuse();
                self.action.refuse();
            }
        };
        let primary: syn::Stmt = syn::parse_quote! { requested?; };
        let post = syn::Stmt::Expr(syn::parse_quote! { checked }, None);
        Ok(
            body.stmts[2].to_token_stream().to_string() == refusal.to_token_stream().to_string()
                && body.stmts[3].to_token_stream().to_string()
                    == primary.to_token_stream().to_string()
                && body.stmts[4].to_token_stream().to_string()
                    == post.to_token_stream().to_string(),
        )
    }

    #[test]
    fn actual_executor_borrows_its_own_fields_and_source_with_original_postcheck() -> Result<()> {
        let parent = include_str!("../consumer.rs");
        let leaf = include_str!("stop.rs");
        assert!(source_loan_wiring(parent, leaf)?);
        let duplicate = parent.replacen(
            "self.check_source()",
            "self.check_source()?; self.check_source()",
            1,
        );
        assert_ne!(parent, duplicate);
        assert!(!source_loan_wiring(&duplicate, leaf)?);
        let mut conditional = syn::parse_file(leaf)?;
        let mut replacements = 0;
        for item in &mut conditional.items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            let syn::Type::Path(path) = &*item.self_ty else {
                continue;
            };
            if !path
                .path
                .segments
                .last()
                .is_some_and(|part| part.ident == "ExecutionSourceLoan")
            {
                continue;
            }
            for member in &mut item.items {
                let syn::ImplItem::Fn(method) = member else {
                    continue;
                };
                if method.sig.ident != "check" {
                    continue;
                }
                method.block.stmts[1] = syn::parse_quote! {
                    let checked = (|| {
                        requested.as_ref().map_err(|_| anyhow::anyhow!("skip"))?;
                        self.action.check_execution_original(self.original, self.record, self.operation)
                    })();
                };
                replacements += 1;
            }
        }
        assert_eq!(replacements, 1, "actual unconditional production postcheck");
        assert!(!source_loan_wiring(
            parent,
            &conditional.to_token_stream().to_string()
        )?);
        let wrong_borrow = leaf.replacen("refused: &mut self.refused,", "refused: &mut false,", 1);
        assert_ne!(leaf, wrong_borrow, "actual source-loan constructor target");
        assert!(!source_loan_wiring(parent, &wrong_borrow)?);
        // Mutate the actual check body, not the first matching text elsewhere
        // in this owning module. New fixed methods may contain the same guards.
        for cut in 0..6 {
            let mut changed = syn::parse_file(leaf)?;
            let mut targets = 0;
            for item in &mut changed.items {
                let syn::Item::Impl(item) = item else {
                    continue;
                };
                if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|part| part.ident == "ExecutionSourceLoan"))
                {
                    continue;
                }
                for member in &mut item.items {
                    let syn::ImplItem::Fn(method) = member else {
                        continue;
                    };
                    if method.sig.ident != "check" {
                        continue;
                    }
                    targets += 1;
                    let body = &mut method.block;
                    match cut {
                        0..=2 => {
                            let syn::Stmt::Local(local) = &mut body.stmts[0] else {
                                unreachable!()
                            };
                            let syn::Expr::Call(call) = &mut *local.init.as_mut().unwrap().expr
                            else {
                                unreachable!()
                            };
                            let syn::Expr::Paren(callee) = &mut *call.func else {
                                unreachable!()
                            };
                            let syn::Expr::Closure(closure) = &mut *callee.expr else {
                                unreachable!()
                            };
                            let syn::Expr::Block(requested) = &mut *closure.body else {
                                unreachable!()
                            };
                            if cut == 0 {
                                requested.block.stmts[0] = syn::parse_quote! { ensure!(true, "restore_executor_refused"); };
                            } else {
                                let target: syn::Stmt = if cut == 1 {
                                    syn::parse_quote! { source.require_qualified(self.time_operation)?; }
                                } else {
                                    syn::parse_quote! { approval_window(self.record, &time)?; }
                                };
                                let before = requested.block.stmts.len();
                                requested.block.stmts.retain(|stmt| {
                                    stmt.to_token_stream().to_string()
                                        != target.to_token_stream().to_string()
                                });
                                assert_eq!(
                                    requested.block.stmts.len() + 1,
                                    before,
                                    "one actual required check"
                                );
                            }
                        }
                        3 => {
                            body.stmts[2] = syn::parse_quote! {
                                if requested.is_err() {
                                    *self.refused = true;
                                    self.original.refuse();
                                    self.action.refuse();
                                }
                            }
                        }
                        4 => {
                            let syn::Stmt::Expr(syn::Expr::If(refusal), _) = &mut body.stmts[2]
                            else {
                                unreachable!()
                            };
                            let target: syn::Stmt = syn::parse_quote! { self.original.refuse(); };
                            let before = refusal.then_branch.stmts.len();
                            refusal.then_branch.stmts.retain(|stmt| {
                                stmt.to_token_stream().to_string()
                                    != target.to_token_stream().to_string()
                            });
                            assert_eq!(
                                refusal.then_branch.stmts.len() + 1,
                                before,
                                "one actual original refusal"
                            );
                        }
                        5 => {
                            body.stmts[3] = syn::parse_quote! { checked?; };
                            body.stmts[4] = syn::Stmt::Expr(
                                syn::parse_quote! { requested.map(|_| unreachable!()) },
                                None,
                            );
                        }
                        _ => unreachable!(),
                    }
                }
            }
            assert_eq!(targets, 1, "one actual execution-source checker");
            assert!(
                !source_loan_wiring(parent, &changed.to_token_stream().to_string())?,
                "actual checker mutation {cut}"
            );
        }
        Ok(())
    }

    #[test]
    fn actual_negative_loan_owner_refuses_after_last_good_check_or_unwind() {
        for unwind in [false, true] {
            let refused = Rc::new(Cell::new(false));
            let lost = LostRestoreLoan {
                refused: Rc::clone(&refused),
            };
            // A preceding successful checker cannot settle the loan itself.
            refused.set(true);
            refused.set(false);
            if unwind {
                let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _lost = lost;
                    panic!("lost restore-loan fixture");
                }));
                assert!(caught.is_err());
            } else {
                drop(lost);
            }
            assert!(refused.get());
        }
    }

    fn retained_refusal_boundary(source: &str) -> Result<bool> {
        let file = syn::parse_file(source)?;
        let owner = file.items.iter().find_map(|item| match item {
            syn::Item::Impl(item) if item.trait_.is_none()
                && matches!(item.self_ty.as_ref(), syn::Type::Path(t) if t.path.segments.last().is_some_and(|s|s.ident=="FencedRestoreContinuation")) => Some(item),
            _ => None,
        }).unwrap();
        for (method, inner) in [
            ("check_local", "check_local_inner"),
            ("check_current", "check_current_inner"),
        ] {
            let actual = owner
                .items
                .iter()
                .find_map(|item| match item {
                    syn::ImplItem::Fn(f) if f.sig.ident == method => Some(&f.block),
                    _ => None,
                })
                .unwrap();
            let inner = syn::Ident::new(inner, proc_macro2::Span::call_site());
            let expected: syn::Block = syn::parse_quote!({
                if self.refused.get() {
                    self.refuse();
                    anyhow::bail!("native_restore_continuation_refused");
                }
                self.refused.set(true);
                let result = self.#inner();
                if result.is_ok() {
                    self.refused.set(false);
                } else {
                    self.refuse();
                }
                result
            });
            if actual.to_token_stream().to_string() != expected.to_token_stream().to_string() {
                return Ok(false);
            }
        }
        let loan = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item) if item.ident == "RestoreWriteLoan" => Some(item),
                _ => None,
            })
            .unwrap();
        if !loan.fields.iter().any(|f| {
            f.ident.as_ref().is_some_and(|i| i == "_lost")
                && f.ty.to_token_stream().to_string() == "LostRestoreLoan"
        }) {
            return Ok(false);
        }
        let borrow = owner
            .items
            .iter()
            .find_map(|item| match item {
                syn::ImplItem::Fn(f) if f.sig.ident == "borrow_write" => Some(&f.block),
                _ => None,
            })
            .unwrap();
        let expected: syn::Block = syn::parse_quote!({
            if self.writer_borrowed.replace(true) {
                self.refuse();
                anyhow::bail!("native_restore_writer_loan_spent");
            }
            self.check_current()?;
            let lost = LostRestoreLoan {
                refused: Rc::clone(&self.refused),
            };
            Ok(RestoreWriteLoan {
                owner: self,
                _lost: lost,
            })
        });
        if borrow.to_token_stream().to_string() != expected.to_token_stream().to_string() {
            return Ok(false);
        }
        Ok(true)
    }

    #[test]
    fn actual_continuation_spends_before_every_checker_and_carries_lost_loan_refusal() -> Result<()>
    {
        let source = include_str!("stop.rs");
        assert!(retained_refusal_boundary(source)?);
        for (old, new) in [
            ("if self.refused.get() {", "if false {"),
            (
                "self.refused.set(true);\n        let result = self.check_local_inner();",
                "let result = self.check_local_inner();",
            ),
            (
                "self.refused.set(true);\n        let result = self.check_current_inner();",
                "let result = self.check_current_inner();",
            ),
            ("if result.is_ok() {", "if true {"),
            (
                "writer_borrowed.replace(true)",
                "writer_borrowed.replace(false)",
            ),
            ("_lost: LostRestoreLoan", "_lost: bool"),
            ("_lost: lost", "_lost: false"),
        ] {
            let mutant = source.replacen(old, new, 1);
            assert_ne!(source, mutant, "actual production refusal target");
            assert!(!retained_refusal_boundary(&mutant)?);
        }
        Ok(())
    }
}
