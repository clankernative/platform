//! Action-scoped accepting reader, never an authenticated identity or approval.
//! Its actual loan excludes App SQL until every Controller connection/auxiliary
//! handle closes and the counter/peer exchange settles on the same original.
use super::{
    ControllerAdminData, ControllerAdminReadLoan, DATABASE, InitialStoreMetadata,
    configure_connection, open_readonly, opened_files, project,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::Digest;
use rusqlite::Connection;
use std::{
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    path::Path,
};

/// Fields drop in declaration order: SQLite closes before the actual native
/// loan unwinds. No transaction, Connection, descriptor or native owner getter.
/// Claimed principals are DATA; the producer must authenticate both separately.
pub(crate) struct ControllerAdminReader<'metadata, 'storage, 'role> {
    sqlite: ReaderConnection,
    loan: ControllerAdminReadLoan<'storage, 'role>,
    metadata: &'metadata InitialStoreMetadata,
    selected: AdminSelection,
}

// Mechanical resource custody only. It cannot supply a native read loan.
struct ReaderConnection {
    connection: Option<Box<Connection>>,
    files: Option<opened_files::Handles>,
}

// Selection DATA only, not a permission or authentication proof.
struct AdminSelection {
    operation: Digest,
    approver: String,
    executor: String,
    authority: crate::authority_state::AuthorityStamp,
}

impl AdminSelection {
    fn capture(
        data: &ControllerAdminData,
        operation: &Digest,
        approver: &str,
        executor: &str,
    ) -> Result<Self> {
        for actor in [approver, executor] {
            crate::authority::valid_actor(actor)
                .map_err(|_| anyhow::anyhow!("controller_admin_actor_shape"))?;
        }
        let selected = Self {
            operation: operation.clone(),
            approver: approver.to_owned(),
            executor: executor.to_owned(),
            authority: data.authority.clone(),
        };
        selected.check(data)?;
        Ok(selected)
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

impl ReaderConnection {
    fn open(loan: &mut ControllerAdminReadLoan<'_, '_>) -> Result<Self> {
        loan.check_local()?;
        let opened = open_readonly(Path::new(DATABASE));
        let checked = loan.check_local();
        let mut connection = Box::new(opened?);
        checked?;
        loan.retain_reader(&connection)?;
        let configured = (|| {
            configure_connection(&mut connection)
                .map_err(|_| anyhow::anyhow!("controller_admin_sql_configuration_refused"))?;
            connection
                .pragma_update(None, "query_only", true)
                .map_err(|_| anyhow::anyhow!("controller_admin_sql_configuration_refused"))
        })();
        let checked = loan.check_local();
        configured?;
        checked?;
        Ok(Self {
            connection: Some(connection),
            files: None,
        })
    }

    fn check_handles(&self) -> Result<()> {
        let connection = self
            .connection
            .as_ref()
            .context("controller_admin_reader_closed")?;
        ensure!(
            connection.is_autocommit(),
            "controller_admin_transaction_not_closed"
        );
        if let Some(files) = &self.files {
            ensure!(
                opened_files::held(connection)? == *files,
                "controller_admin_reader_handles_changed"
            );
        }
        Ok(())
    }

    fn read(
        &mut self,
        loan: &mut ControllerAdminReadLoan<'_, '_>,
        metadata: &InitialStoreMetadata,
    ) -> Result<ControllerAdminData> {
        loan.check_metadata(metadata)?;
        self.check_handles()?;
        loan.begin_sql()?;
        let requested = catch_unwind(AssertUnwindSafe(|| {
            let db = self
                .connection
                .as_mut()
                .context("controller_admin_reader_closed")?;
            let tx = db
                .transaction()
                .map_err(|_| anyhow::anyhow!("controller_admin_sql_begin_refused"))?;
            let actual = opened_files::snapshot(&tx)?;
            if let Some(retained) = &self.files {
                ensure!(
                    actual == *retained,
                    "controller_admin_reader_handles_changed"
                );
            }
            loan.check_database(&tx)?;
            // Only this fixed current-policy projection runs in the unit.
            let data = project(&tx, metadata)
                .map_err(|_| anyhow::anyhow!("controller_admin_authority_refused"))?;
            ensure!(
                opened_files::snapshot(&tx)? == actual,
                "controller_admin_reader_handles_changed"
            );
            loan.check_database(&tx)?;
            tx.commit()
                .map_err(|_| anyhow::anyhow!("controller_admin_sql_commit_refused"))?;
            if self.files.is_none() {
                self.files = Some(actual);
            }
            Ok::<_, anyhow::Error>(data)
        }));
        // The transaction is gone, including on unwind. Keep all actual
        // SQLite-owned auxiliary descriptors until the whole action finishes.
        let completed = match &requested {
            Ok(Ok(_)) => Ok(()),
            _ => Err(anyhow::anyhow!("controller_admin_sql_unit_failed")),
        };
        let ended = match self.connection.as_ref() {
            Some(db) => loan.end_retained_sql(db, &completed),
            None => loan.end_sql(&Err(anyhow::anyhow!("controller_admin_reader_closed"))),
        };
        let handles = self.check_handles();
        // No provider/configuration I/O occurs inside the transaction.
        let checked = loan.check_metadata(metadata);
        let result = match requested {
            Ok(Err(error)) => Err(error),
            Ok(Ok(data)) => ended.and(handles).and(checked).map(|()| data),
            Err(panic) => {
                loan.refuse();
                resume_unwind(panic)
            }
        };
        if result.is_err() {
            loan.refuse();
        }
        result
    }

    fn close(&mut self, loan: &mut ControllerAdminReadLoan<'_, '_>) -> Result<()> {
        let connection = self
            .connection
            .take()
            .context("controller_admin_reader_closed")?;
        loan.close_reader(connection)
    }
}

impl InitialStoreMetadata {
    /// Actual loan by value, never a historical admin projection or Runtime.
    /// The loan must precede the FIRST SQLite activation of this reader.
    pub(crate) fn accept_admin_reader<'metadata, 'storage, 'role>(
        &'metadata self,
        mut loan: ControllerAdminReadLoan<'storage, 'role>,
        operation: &Digest,
        approver: &str,
        executor: &str,
    ) -> Result<ControllerAdminReader<'metadata, 'storage, 'role>> {
        let requested = (|| {
            loan.check_action(self, operation)?;
            let mut sqlite = ReaderConnection::open(&mut loan)?;
            let data = sqlite.read(&mut loan, self)?;
            let selected = AdminSelection::capture(&data, operation, approver, executor)?;
            loan.check_action(self, operation)?;
            Ok((sqlite, selected))
        })();
        let (sqlite, selected) = match requested {
            Ok(values) => values,
            Err(error) => {
                loan.refuse();
                return Err(error);
            }
        };
        Ok(ControllerAdminReader {
            sqlite,
            loan,
            metadata: self,
            selected,
        })
    }
}

impl ControllerAdminReader<'_, '_, '_> {
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
};

#[cfg(test)]
mod tests;
