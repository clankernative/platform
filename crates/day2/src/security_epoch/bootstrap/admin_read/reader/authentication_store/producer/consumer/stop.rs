//! One retained native stop/fenced-write owner. DATA plans and a peer ACK
//! cannot construct it; the sole construction path must finish actual known
//! grant-use/root-fence send/readback and the complete real peer/issuer stop.
use super::super::super::super::super::ControllerAdminReadLoan;
use super::super::super::super::ControllerAdminReader;
use super::{AuthenticatedRestoreExecution, approval_window};
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
            let _ = <crate::security_epoch::storage_authority::RestoreCreatorRoot as Ambiguous<_>>::check;
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
