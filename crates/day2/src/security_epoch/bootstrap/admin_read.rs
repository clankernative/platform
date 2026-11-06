//! Authenticated SQL quiescence, distinct from complete old-rights fencing.
//! A membership proof borrows this actual loan; it cannot survive release or
//! authenticate a claimed identity. No signing/grant authority is created here.
use super::{
    ActiveAppStorageContinuity, ActiveControllerStorageContinuity, Digest, EnrolledRoleStage,
    EpochStore, InitialBootstrapPolicy, Request, check_active_snapshot, request_names,
};
use crate::security_epoch::{
    CurrentControllerStoragePhase,
    authenticated_reads::CounterRequest,
    controller::serving_timing::ServingTiming,
    native_enrollment::{NativeRole, StoragePeerPurpose},
};
use anyhow::{Context, Result, ensure};
use std::{marker::PhantomData, rc::Rc};

mod reader;

pub(crate) struct ControllerAdminReadLoan<'storage, 'role> {
    physical: Option<CurrentControllerStoragePhase<'storage, 'role>>,
    reads: CounterRequest<'storage>,
    observed: super::super::EpochObservation,
    policy: InitialBootstrapPolicy,
    selection: EpochStore,
    completion: Request,
    activation: Digest,
    operation: Digest,
    identity: Rc<()>,
    continuation: &'storage mut bool,
    trace: &'storage ServingTiming,
    disposition: ReadDisposition,
    reader: Option<*const rusqlite::Connection>,
}

/// Current policy membership only, NOT authentication of email/subject. The
/// accepting caller still verifies its actual passkey/executor and signed target.
pub(crate) struct CurrentAdminMembership<'loan, 'storage, 'role> {
    loan: &'loan mut ControllerAdminReadLoan<'storage, 'role>,
    metadata: &'loan crate::store::InitialStoreMetadata,
    actor: String,
    authority: crate::authority_state::AuthorityStamp,
    operation: Digest,
    identity: Rc<()>,
    local: PhantomData<Rc<()>>,
}

fn validate_actor(actor: &str) -> Result<()> {
    crate::authority::valid_actor(actor)
        .map_err(|_| anyhow::anyhow!("controller_admin_actor_shape"))
}

fn binding(completion: &Request, operation: &Digest) -> Result<Digest> {
    Digest::of(&(
        "day2-current-admin-read-v1",
        completion.digest()?,
        operation,
    ))
}

impl ActiveAppStorageContinuity {
    /// Fixed App operation; no consumer/SQL callback can enter while held.
    pub(in crate::security_epoch) fn admin_read(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        operation: &Digest,
    ) -> Result<()> {
        ensure!(self.valid, "active_app_storage_refused");
        self.valid = false;
        let result = (|| {
            let mut reads =
                self.counter
                    .request(stage, &self.policy, &self.store, NativeRole::AppHost)?;
            let mut physical = self
                .storage
                .begin_admin_read(stage, binding(&self.completion, operation)?)?;
            physical.await_known(stage)?;
            let names = request_names(&self.store, &self.completion)?;
            let mut observed = reads.read(stage, &self.store, &names)?;
            check_active_snapshot(
                &self.store,
                &self.completion,
                &self.activation,
                observed.snapshot(),
            )?;
            reads.check_observation(stage, &mut observed)?;
            physical.check(stage)?;
            reads.finish(stage)?;
            physical.finish_checked(stage)
        })();
        if result.is_ok() {
            self.valid = true;
        } else {
            self.storage.refuse();
            self.counter.refuse();
        }
        result
    }
}

impl ActiveControllerStorageContinuity {
    /// This is a pre-fence active-root path, never a post-fence writer source.
    pub(in crate::security_epoch) fn begin_admin_read<'storage, 'role>(
        &'storage mut self,
        stage: EnrolledRoleStage<'role>,
        operation: &Digest,
        trace: &'storage ServingTiming,
    ) -> Result<ControllerAdminReadLoan<'storage, 'role>> {
        ensure!(self.valid, "active_controller_storage_refused");
        self.valid = false;
        let (mut physical, mut reads) = self.storage.begin_app_admin_read(
            stage,
            &self.policy,
            &self.store,
            &mut self.counter,
            &binding(&self.completion, operation)?,
        )?;
        ensure!(
            physical.app_request()?.purpose() == StoragePeerPurpose::AdminRead,
            "controller_admin_purpose_required"
        );
        let names = request_names(&self.store, &self.completion)?;
        let mut observed = reads.read(physical.controller_stage()?, &self.store, &names)?;
        check_active_snapshot(
            &self.store,
            &self.completion,
            &self.activation,
            observed.snapshot(),
        )?;
        reads.check_observation(physical.controller_stage()?, &mut observed)?;
        let mut loan = ControllerAdminReadLoan {
            physical: Some(physical),
            reads,
            observed,
            policy: self.policy.clone(),
            selection: self.store.clone(),
            completion: self.completion.clone(),
            activation: self.activation.clone(),
            operation: operation.clone(),
            identity: Rc::new(()),
            continuation: &mut self.valid,
            trace,
            disposition: ReadDisposition::new(),
            reader: None,
        };
        loan.check_local()?;
        Ok(loan)
    }
}

impl<'storage, 'role> ControllerAdminReadLoan<'storage, 'role> {
    /// Bind accepting work before any SQLite activation. The operation is DATA,
    /// compared with the authenticated request held by this actual loan.
    pub(crate) fn check_action(
        &mut self,
        metadata: &crate::store::InitialStoreMetadata,
        operation: &Digest,
    ) -> Result<()> {
        if self.operation != *operation {
            self.refuse();
            anyhow::bail!("controller_admin_operation_changed");
        }
        self.check_metadata(metadata)
    }

    /// SQL-safe handle/original checks. No provider RPC or new stage is acquired.
    pub(crate) fn check_local(&mut self) -> Result<()> {
        let result = (|| {
            self.disposition.check()?;
            let physical = self
                .physical
                .as_mut()
                .context("controller_admin_loan_closed")?;
            ensure!(
                physical.app_request()?.purpose() == StoragePeerPurpose::AdminRead,
                "controller_admin_purpose_required"
            );
            physical.check()
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// The fixed adapter closes this unit only after Connection::close. This
    /// local disposition grants no role or SQL permission by itself.
    pub(crate) fn begin_sql(&mut self) -> Result<()> {
        self.check_local()?;
        self.disposition.begin_sql().inspect_err(|_| self.refuse())
    }

    pub(crate) fn end_sql(&mut self, closed: &Result<()>) -> Result<()> {
        if let Err(error) = self.disposition.end_sql(closed.is_ok()) {
            self.refuse();
            return Err(error);
        }
        self.check_local()
    }

    /// A retained accepting reader closes each transaction, but keeps its
    /// actual MAIN/WAL/SHM connection until the whole action has settled. Only
    /// this fixed adapter uses this boundary; no SQL or callback escapes it.
    pub(crate) fn end_retained_sql(
        &mut self,
        db: &rusqlite::Connection,
        completed: &Result<()>,
    ) -> Result<()> {
        let closed = (|| {
            ensure!(
                self.reader == Some(std::ptr::from_ref(db)),
                "controller_admin_reader_substituted"
            );
            ensure!(
                db.is_autocommit(),
                "controller_admin_transaction_not_closed"
            );
            self.check_database(db)?;
            ensure!(completed.is_ok(), "controller_admin_sql_completion_unknown");
            Ok(())
        })();
        let ended = self.disposition.end_retained_sql(closed.is_ok());
        if closed.is_err() || ended.is_err() {
            self.refuse();
        }
        closed?;
        ended?;
        self.check_local()
    }

    pub(crate) fn begin_retained_sql(&mut self, db: &rusqlite::Connection) -> Result<()> {
        let result = (|| {
            self.check_local()?;
            self.disposition.require_reader_closed_unit()?;
            ensure!(
                self.reader == Some(std::ptr::from_ref(db)) && db.is_autocommit(),
                "controller_admin_reader_substituted_or_unit_open"
            );
            self.disposition.begin_retained_sql()
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Bind the actual stable boxed connection, before any configuration or
    /// transaction. Pointer equality is only a substitution check; it supplies
    /// no authority and is never returned or dereferenced.
    pub(crate) fn retain_reader(&mut self, db: &rusqlite::Connection) -> Result<()> {
        let result = (|| {
            self.check_local()?;
            ensure!(
                self.reader.is_none(),
                "controller_admin_reader_already_open"
            );
            self.check_opened_database(db)?;
            self.disposition.retain_reader()?;
            self.reader = Some(std::ptr::from_ref(db));
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Consume and close the SAME actual connection. A Result/boolean supplied
    /// by a caller cannot mark a retained reader closed or release its peer.
    pub(crate) fn close_reader(&mut self, db: Box<rusqlite::Connection>) -> Result<()> {
        let requested = (|| {
            self.disposition.require_reader_closed_unit()?;
            ensure!(
                self.reader == Some(std::ptr::from_ref(db.as_ref())),
                "controller_admin_reader_substituted"
            );
            ensure!(
                db.is_autocommit(),
                "controller_admin_transaction_not_closed"
            );
            self.check_database(&db)
        })();
        let closed = match (*db).close() {
            Ok(()) => Ok(()),
            Err((db, _)) => {
                drop(db);
                Err(anyhow::anyhow!("controller_admin_sql_close_refused"))
            }
        };
        let checked = self.check_local();
        if requested.is_err() || closed.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        closed?;
        checked?;
        self.disposition.close_reader()?;
        self.reader = None;
        Ok(())
    }

    fn refresh(&mut self) -> Result<()> {
        let result = (|| {
            self.disposition.require_closed()?;
            self.check_local()?;
            let physical = self
                .physical
                .as_mut()
                .context("controller_admin_loan_closed")?;
            let names = request_names(&self.selection, &self.completion)?;
            let mut observed =
                self.reads
                    .read(physical.controller_stage()?, &self.selection, &names)?;
            check_active_snapshot(
                &self.selection,
                &self.completion,
                &self.activation,
                observed.snapshot(),
            )?;
            self.reads
                .check_observation(physical.controller_stage()?, &mut observed)?;
            self.observed = observed;
            self.check_local()
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(crate) fn check_metadata(
        &mut self,
        metadata: &crate::store::InitialStoreMetadata,
    ) -> Result<()> {
        let result = (|| {
            self.refresh()?;
            let requested = metadata
                .require_native_selection(
                    &self.selection,
                    &self.policy.runtime_profile.app_artifact,
                    &self.policy,
                )
                .map_err(|_| anyhow::anyhow!("controller_admin_metadata_changed"));
            let checked = self.check_local();
            requested?;
            checked
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(crate) fn check_database(&mut self, db: &rusqlite::Connection) -> Result<()> {
        self.check_local()?;
        let requested = self
            .physical
            .as_mut()
            .context("controller_admin_loan_closed")?
            .check_admin_database(db);
        let checked = self.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(crate) fn check_opened_database(&mut self, db: &rusqlite::Connection) -> Result<()> {
        self.check_local()?;
        let requested = self
            .physical
            .as_mut()
            .context("controller_admin_loan_closed")?
            .check_opened_admin_database(db);
        let checked = self.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(crate) fn member<'loan>(
        &'loan mut self,
        metadata: &'loan crate::store::InitialStoreMetadata,
        actor: &str,
    ) -> Result<Option<CurrentAdminMembership<'loan, 'storage, 'role>>> {
        if let Err(error) = validate_actor(actor) {
            self.refuse();
            return Err(error);
        }
        let data = metadata.controller_admin_data(self)?;
        if !data.members.contains(actor) {
            return Ok(None);
        }
        Ok(Some(CurrentAdminMembership {
            operation: self.operation.clone(),
            identity: Rc::clone(&self.identity),
            loan: self,
            metadata,
            actor: actor.to_owned(),
            authority: data.authority,
            local: PhantomData,
        }))
    }

    /// Only after the admin-dependent action and its postchecks. Consuming
    /// this owner makes every borrowed membership unusable at compile time.
    pub(crate) fn finish_checked(mut self) -> Result<()> {
        // Never start final peer/counter settlement while any Controller
        // reader or transaction remains held, even if all SQL units committed.
        if let Err(error) = self.disposition.require_released() {
            self.refuse();
            return Err(error);
        }
        self.refresh()?;
        let physical = self
            .physical
            .as_mut()
            .context("controller_admin_loan_closed")?;
        let names = request_names(&self.selection, &self.completion)?;
        let mut observed = physical.announce_and_read_app_consumed(
            &mut self.reads,
            &self.selection,
            &names,
            self.trace,
        )?;
        check_active_snapshot(
            &self.selection,
            &self.completion,
            &self.activation,
            observed.snapshot(),
        )?;
        self.reads
            .check_observation(physical.controller_stage()?, &mut observed)?;
        self.reads.finish(physical.controller_stage()?)?;
        self.physical
            .take()
            .context("controller_admin_loan_closed")?
            .finish_app_known()?;
        self.disposition.finish()?;
        *self.continuation = true;
        Ok(())
    }

    pub(crate) fn refuse(&mut self) {
        self.disposition.refuse();
        *self.continuation = false;
        if let Some(physical) = &mut self.physical {
            physical.refuse();
        }
        self.reads.refuse();
    }
}

// No custom generic destructor. The actual CounterUseGuard already refuses
// its original/connection on unfinished Drop. Physical and active continuations
// are pessimistically false before acquisition and only the known final path
// restores them. Abandonment therefore cannot publish Ready, even after the
// read transaction has closed. See the production-wiring/drop regressions.

impl CurrentAdminMembership<'_, '_, '_> {
    pub(crate) fn check(
        &mut self,
        metadata: &crate::store::InitialStoreMetadata,
        actor: &str,
        operation: &Digest,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                std::ptr::eq(self.metadata, metadata)
                    && self.actor == actor
                    && self.operation == *operation
                    && self.loan.operation == *operation
                    && Rc::ptr_eq(&self.identity, &self.loan.identity),
                "controller_admin_member_binding_changed"
            );
            // Keep the exact authority stamp in the proof without exporting it
            // as a reusable grant. App SQL is excluded throughout this borrow.
            ensure!(
                !self.authority.epoch.is_empty(),
                "controller_admin_authority_missing"
            );
            self.loan.check_metadata(metadata)
        })();
        if result.is_err() {
            self.loan.refuse();
        }
        result
    }
}

const _: () = {
    macro_rules! assert_not_impl {
        ($owner:ty, $bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <$owner as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(ControllerAdminReadLoan<'static, 'static>, Clone);
    assert_not_impl!(ControllerAdminReadLoan<'static, 'static>, Copy);
    assert_not_impl!(ControllerAdminReadLoan<'static, 'static>, Default);
    assert_not_impl!(ControllerAdminReadLoan<'static, 'static>, std::fmt::Debug);
    assert_not_impl!(ControllerAdminReadLoan<'static, 'static>, Send);
    assert_not_impl!(ControllerAdminReadLoan<'static, 'static>, Sync);
    assert_not_impl!(ControllerAdminReadLoan<'static, 'static>, serde::Serialize);
    assert_not_impl!(
        ControllerAdminReadLoan<'static, 'static>,
        serde::Deserialize<'static>
    );
    assert_not_impl!(CurrentAdminMembership<'static, 'static, 'static>, Clone);
    assert_not_impl!(CurrentAdminMembership<'static, 'static, 'static>, Copy);
    assert_not_impl!(CurrentAdminMembership<'static, 'static, 'static>, Default);
    assert_not_impl!(
        CurrentAdminMembership<'static, 'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(CurrentAdminMembership<'static, 'static, 'static>, Send);
    assert_not_impl!(CurrentAdminMembership<'static, 'static, 'static>, Sync);
    assert_not_impl!(
        CurrentAdminMembership<'static, 'static, 'static>,
        serde::Serialize
    );
    assert_not_impl!(
        CurrentAdminMembership<'static, 'static, 'static>,
        serde::Deserialize<'static>
    );
};

// Local exclusion/terminality only, never native admission. The real native
// owners remain fields of ControllerAdminReadLoan and every call still checks
// them. This reducer also lets the model exercise actual SQL-lifetime decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadPhase {
    Reading,
    Sql,
    Reader,
    ReaderSql,
    Refused,
    Finished,
}
struct ReadDisposition {
    phase: ReadPhase,
}
impl ReadDisposition {
    fn new() -> Self {
        Self {
            phase: ReadPhase::Reading,
        }
    }
    fn check(&self) -> Result<()> {
        ensure!(
            matches!(
                self.phase,
                ReadPhase::Reading | ReadPhase::Sql | ReadPhase::Reader | ReadPhase::ReaderSql
            ),
            "controller_admin_loan_refused"
        );
        Ok(())
    }
    fn require_closed(&self) -> Result<()> {
        ensure!(
            matches!(self.phase, ReadPhase::Reading | ReadPhase::Reader),
            "controller_admin_sql_not_closed"
        );
        Ok(())
    }
    fn begin_sql(&mut self) -> Result<()> {
        if self.phase != ReadPhase::Reading {
            self.refuse();
            anyhow::bail!("controller_admin_sql_already_open_or_reader_held");
        }
        self.phase = ReadPhase::Sql;
        Ok(())
    }
    fn end_sql(&mut self, known: bool) -> Result<()> {
        if self.phase != ReadPhase::Sql || !known {
            self.refuse();
            anyhow::bail!("controller_admin_sql_close_unknown");
        }
        self.phase = ReadPhase::Reading;
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        if let Err(error) = self.require_released() {
            self.refuse();
            return Err(error);
        }
        self.phase = ReadPhase::Finished;
        Ok(())
    }
    fn refuse(&mut self) {
        self.phase = ReadPhase::Refused;
    }

    fn require_released(&self) -> Result<()> {
        ensure!(
            self.phase == ReadPhase::Reading,
            "controller_admin_reader_not_closed"
        );
        Ok(())
    }

    fn retain_reader(&mut self) -> Result<()> {
        self.require_released()?;
        self.phase = ReadPhase::Reader;
        Ok(())
    }

    fn require_reader_closed_unit(&self) -> Result<()> {
        ensure!(
            self.phase == ReadPhase::Reader,
            "controller_admin_reader_unit_not_closed"
        );
        Ok(())
    }

    fn end_retained_sql(&mut self, known: bool) -> Result<()> {
        if self.phase != ReadPhase::ReaderSql || !known {
            self.refuse();
            anyhow::bail!("controller_admin_reader_sql_completion_unknown");
        }
        self.phase = ReadPhase::Reader;
        Ok(())
    }

    fn begin_retained_sql(&mut self) -> Result<()> {
        if self.phase != ReadPhase::Reader {
            self.refuse();
            anyhow::bail!("controller_admin_reader_sql_already_open_or_missing");
        }
        self.phase = ReadPhase::ReaderSql;
        Ok(())
    }

    fn close_reader(&mut self) -> Result<()> {
        self.require_reader_closed_unit()?;
        self.phase = ReadPhase::Reading;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
