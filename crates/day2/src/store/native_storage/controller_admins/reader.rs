//! Actual Controller SQLite connection and auxiliary-handle custody. Native
//! admission and accepting principal selection remain with the retained loan.
use super::{
    ControllerAdminData, ControllerAdminReadLoan, DATABASE, InitialStoreMetadata,
    configure_connection, open_readonly, opened_files, project,
};
use anyhow::{Context, Result, ensure};
use rusqlite::Connection;
use std::{
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    path::Path,
};

// Mechanical resource custody only. It cannot supply a native read loan.
pub(crate) struct ControllerAdminSqlite {
    connection: Option<Box<Connection>>,
    files: Option<opened_files::Handles>,
}

impl ControllerAdminSqlite {
    pub(crate) fn open(loan: &mut ControllerAdminReadLoan<'_, '_>) -> Result<Self> {
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

    pub(crate) fn check_handles(&self) -> Result<()> {
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

    pub(crate) fn read_fenced(
        &mut self,
        loan: &mut crate::security_epoch::FencedReadUnit<'_, '_, '_>,
        metadata: &InitialStoreMetadata,
    ) -> Result<ControllerAdminData> {
        self.read_unit(ReadLoan::Fenced(loan), metadata)
    }

    pub(crate) fn read_reserving(
        &mut self,
        loan: &mut crate::security_epoch::ReservationReadUnit<'_, '_, '_>,
        metadata: &InitialStoreMetadata,
    ) -> Result<ControllerAdminData> {
        self.read_unit(ReadLoan::Reserving(loan), metadata)
    }

    pub(crate) fn read(
        &mut self,
        loan: &mut ControllerAdminReadLoan<'_, '_>,
        metadata: &InitialStoreMetadata,
    ) -> Result<ControllerAdminData> {
        self.read_unit(ReadLoan::Active(loan), metadata)
    }

    fn read_unit(
        &mut self,
        mut loan: ReadLoan<'_, '_, '_, '_>,
        metadata: &InitialStoreMetadata,
    ) -> Result<ControllerAdminData> {
        loan.check_metadata(metadata)?;
        self.check_handles()?;
        loan.begin_retained_sql(
            self.connection
                .as_ref()
                .context("controller_admin_reader_closed")?,
        )?;
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

    pub(crate) fn close(&mut self, loan: &mut ControllerAdminReadLoan<'_, '_>) -> Result<()> {
        let connection = self
            .connection
            .take()
            .context("controller_admin_reader_closed")?;
        loan.close_reader(connection)
    }
}

// The same fixed projection/SQL/handle unit serves distinct actual loans.
// No flag broadens Active admission and no generic callback or owner escapes.
enum ReadLoan<'borrow, 'fenced, 'storage, 'role> {
    Active(&'borrow mut ControllerAdminReadLoan<'storage, 'role>),
    Fenced(&'borrow mut crate::security_epoch::FencedReadUnit<'fenced, 'storage, 'role>),
    Reserving(&'borrow mut crate::security_epoch::ReservationReadUnit<'fenced, 'storage, 'role>),
}

impl ReadLoan<'_, '_, '_, '_> {
    fn check_metadata(&mut self, metadata: &InitialStoreMetadata) -> Result<()> {
        match self {
            Self::Active(loan) => loan.check_metadata(metadata),
            Self::Fenced(loan) => loan.check_metadata(metadata),
            Self::Reserving(loan) => loan.check_metadata(metadata),
        }
    }
    fn begin_retained_sql(&mut self, db: &Connection) -> Result<()> {
        match self {
            Self::Active(loan) => loan.begin_retained_sql(db),
            Self::Fenced(loan) => loan.begin_retained_sql(db),
            Self::Reserving(loan) => loan.begin_retained_sql(db),
        }
    }
    fn check_database(&mut self, db: &Connection) -> Result<()> {
        match self {
            Self::Active(loan) => loan.check_database(db),
            Self::Fenced(loan) => loan.check_database(db),
            Self::Reserving(loan) => loan.check_database(db),
        }
    }
    fn end_retained_sql(&mut self, db: &Connection, completed: &Result<()>) -> Result<()> {
        match self {
            Self::Active(loan) => loan.end_retained_sql(db, completed),
            Self::Fenced(loan) => loan.end_retained_sql(db, completed),
            Self::Reserving(loan) => loan.end_retained_sql(db, completed),
        }
    }
    fn end_sql(&mut self, completed: &Result<()>) -> Result<()> {
        match self {
            Self::Active(loan) => loan.end_sql(completed),
            Self::Fenced(loan) => loan.end_sql(completed),
            Self::Reserving(loan) => loan.end_sql(completed),
        }
    }
    fn refuse(&mut self) {
        match self {
            Self::Active(loan) => loan.refuse(),
            Self::Fenced(loan) => loan.refuse(),
            Self::Reserving(loan) => loan.refuse(),
        }
    }
}

#[cfg(test)]
mod tests;
