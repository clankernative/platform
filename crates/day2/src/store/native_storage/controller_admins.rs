//! Fixed read-only projection. Values returned here are historical DATA; the
//! accepting membership proof is constructed only under the still-borrowed loan.
use super::{
    DATABASE, InitialStoreMetadata, check_storage_binding, configure_connection, opened_files,
};
use crate::security_epoch::ControllerAdminReadLoan;
use crate::security_epoch::native_enrollment::SqliteCohort;
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags};
use std::{
    collections::BTreeSet,
    fs::File,
    os::unix::fs::MetadataExt,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    path::Path,
};

mod reader;
pub(crate) use reader::ControllerAdminSqlite;

pub(crate) struct ControllerAdminData {
    pub(crate) members: BTreeSet<String>,
    pub(crate) authority: crate::authority_state::AuthorityStamp,
}

/// Only compares already-opened resources. This returns no file/role or loan.
pub(crate) fn check_controller_sqlite_files(
    db: &Connection,
    original: &File,
    cohort: &SqliteCohort,
) -> Result<()> {
    let actual =
        opened_files::held(db).map_err(|_| anyhow::anyhow!("controller_admin_files_refused"))?;
    let retained = original.metadata()?;
    ensure!(
        retained.is_file()
            && retained.nlink() == 1
            && (actual.main.device, actual.main.inode) == (retained.dev(), retained.ino()),
        "controller_admin_main_not_original"
    );
    ensure!(
        &opened_files::cohort(&actual)? == cohort,
        "controller_admin_cohort_changed"
    );
    Ok(())
}

fn open_readonly(path: &Path) -> Result<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| anyhow::anyhow!("controller_admin_sql_open_refused"))
}

fn current_authority(db: &Connection) -> Result<crate::authority_state::ActiveAuthority> {
    crate::authority_state::current(db)
        .map_err(|_| anyhow::anyhow!("controller_admin_authority_refused"))
}

fn project(db: &Connection, metadata: &InitialStoreMetadata) -> Result<ControllerAdminData> {
    check_storage_binding(db, metadata.artifact(), metadata.scope())?;
    let active = current_authority(db)?;
    ensure!(
        active.artifact_id == metadata.artifact().id(),
        "controller_admin_artifact_changed"
    );
    active.document.validate(metadata.artifact())?;
    ensure!(
        active.document.enabled,
        "controller_admin_application_disabled"
    );
    Ok(ControllerAdminData {
        members: active.policy()?.admins.clone(),
        authority: active.stamp,
    })
}

impl InitialStoreMetadata {
    /// Fixed reader under an actual authenticated admin loan. Native/SQL errors
    /// and unknown close permanently refuse; a known non-member is ordinary DATA.
    pub(crate) fn controller_admin_data(
        &self,
        loan: &mut ControllerAdminReadLoan<'_, '_>,
    ) -> Result<ControllerAdminData> {
        loan.check_metadata(self)?;
        loan.begin_sql()?;
        let mut connection = None;
        let requested = catch_unwind(AssertUnwindSafe(|| {
            let opened = open_readonly(Path::new(DATABASE));
            let post = loan.check_local();
            connection = Some(opened?);
            post?;
            let db = connection.as_mut().context("controller_admin_sql_closed")?;
            configure_connection(db)
                .map_err(|_| anyhow::anyhow!("controller_admin_sql_configuration_refused"))?;
            db.pragma_update(None, "query_only", true)
                .map_err(|_| anyhow::anyhow!("controller_admin_sql_configuration_refused"))?;
            loan.check_local()?;
            let tx = db
                .transaction()
                .map_err(|_| anyhow::anyhow!("controller_admin_sql_begin_refused"))?;
            let held = opened_files::snapshot(&tx)
                .map_err(|_| anyhow::anyhow!("controller_admin_files_refused"))?;
            loan.check_database(&tx)?;
            let data = project(&tx, self)
                .map_err(|_| anyhow::anyhow!("controller_admin_authority_refused"))?;
            ensure!(
                opened_files::snapshot(&tx)
                    .map_err(|_| anyhow::anyhow!("controller_admin_files_refused"))?
                    == held,
                "controller_admin_local_fds_changed"
            );
            loan.check_database(&tx)?;
            tx.commit()
                .map_err(|_| anyhow::anyhow!("controller_admin_sql_commit_refused"))?;
            loan.check_local()?;
            Ok::<_, anyhow::Error>(data)
        }));
        // No creator/auxiliary MAIN descriptor is dropped while this SQL unit
        // is live. The physical owner and peer stay held beyond this close.
        let closed = match connection.take().map(Connection::close).transpose() {
            Ok(_) => Ok(()),
            Err((db, _)) => {
                drop(db);
                Err(anyhow::anyhow!("controller_admin_sql_close_refused"))
            }
        };
        // Provider/instance reobservation occurs only AFTER SQL transaction and
        // connection close, including on errors. Preserve the primary Result.
        let ended = loan.end_sql(&closed);
        let checked = loan.check_metadata(self);
        let result = match requested {
            Ok(Err(error)) => Err(error),
            Ok(Ok(data)) => closed.and(ended).and(checked).map(|()| data),
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Result<(
        tempfile::TempDir,
        std::path::PathBuf,
        Connection,
        File,
        SqliteCohort,
    )> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().canonicalize()?.join("reader.sqlite");
        let mut keeper = Connection::open(&path)?;
        keeper.pragma_update(None, "journal_mode", "WAL")?;
        keeper.execute_batch("CREATE TABLE data(value INTEGER); INSERT INTO data VALUES(1)")?;
        let original = File::open(&path)?;
        let tx = keeper.transaction()?;
        let files = opened_files::snapshot(&tx)?;
        let cohort = opened_files::cohort(&files)?;
        tx.rollback()?;
        Ok((directory, path, keeper, original, cohort))
    }

    #[test]
    fn actual_reader_requires_creator_main_wal_and_shm_but_not_foreign_fd_numbers() -> Result<()> {
        let (_directory, path, mut keeper, original, cohort) = fixture()?;
        let mut reader = open_readonly(&path)?;
        configure_connection(&mut reader)?;
        reader.pragma_update(None, "query_only", true)?;
        let tx = reader.transaction()?;
        let local = opened_files::snapshot(&tx)?;
        let creator = {
            let tx = keeper.transaction()?;
            let files = opened_files::snapshot(&tx)?;
            tx.rollback()?;
            files
        };
        assert_ne!(local.main.fd, creator.main.fd);
        assert!(opened_files::cohort(&local)? == cohort);
        check_controller_sqlite_files(&tx, &original, &cohort)?;
        assert!(tx.execute("INSERT INTO data VALUES(2)", []).is_err());
        assert_eq!(
            tx.query_row("SELECT value FROM data", [], |row| row.get::<_, i64>(0))?,
            1
        );
        let unused = [
            local.main.inode,
            local.journal.unwrap().inode,
            local.shm.unwrap().inode,
        ]
        .into_iter()
        .max()
        .unwrap()
        .checked_add(1)
        .unwrap();
        for changed in [
            SqliteCohort::from_identities(
                (local.main.device ^ 1, 10),
                (local.main.device ^ 1, 11),
                (local.main.device ^ 1, 12),
            )?,
            SqliteCohort::from_identities(
                (local.main.device, local.main.inode),
                (local.main.device, unused),
                (local.main.device, unused + 1),
            )?,
        ] {
            assert!(check_controller_sqlite_files(&tx, &original, &changed).is_err());
        }
        let other = tempfile::tempfile()?;
        assert!(check_controller_sqlite_files(&tx, &other, &cohort).is_err());
        assert!(
            opened_files::snapshot(&tx)? == local,
            "local FD identity stays stable through the complete unit"
        );
        tx.commit()?;
        reader.close().map_err(|(_, error)| error)?;
        assert!(
            original.metadata()?.is_file(),
            "creator descriptor outlives SQL close"
        );
        Ok(())
    }

    #[test]
    fn reader_refuses_missing_symlink_and_non_wal_files_without_creating_database() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().canonicalize()?.join("missing.sqlite");
        assert!(open_readonly(&path).is_err());
        assert!(!path.exists());
        let (_fixture, actual, _keeper, _original, _cohort) = fixture()?;
        std::os::unix::fs::symlink(&actual, &path)?;
        assert!(open_readonly(&path).is_err());
        let non_wal = directory.path().canonicalize()?.join("non-wal.sqlite");
        let writer = Connection::open(&non_wal)?;
        writer.execute_batch("CREATE TABLE data(value INTEGER)")?;
        writer.close().map_err(|(_, error)| error)?;
        let mut db = open_readonly(&non_wal)?;
        let tx = db.transaction()?;
        let files = opened_files::snapshot(&tx)?;
        assert!(opened_files::cohort(&files).is_err());
        tx.rollback()?;
        Ok(())
    }

    #[test]
    fn malformed_authority_and_actor_errors_are_static_allowlisted_codes() -> Result<()> {
        let marker = "private-authority-marker";
        let db = Connection::open_in_memory()?;
        db.execute_batch("CREATE TABLE day2_authority(singleton INTEGER, epoch TEXT, revision INTEGER, document TEXT, artifact_id TEXT, artifact_path TEXT)")?;
        db.execute(
            "INSERT INTO day2_authority VALUES(1,?1,1,?2,'artifact','path')",
            [
                format!("sha256:{}", "a".repeat(64)),
                format!("{{\"{marker}\":"),
            ],
        )?;
        let Err(original) = crate::authority_state::current(&db) else {
            anyhow::bail!("actual authority decoder must reject");
        };
        let Err(error) = current_authority(&db) else {
            anyhow::bail!("closed projection must refuse");
        };
        assert_eq!(error.to_string(), "controller_admin_authority_refused");
        assert!(!format!("{error:#}").contains(marker));
        assert!(
            original.to_string().len() > 1,
            "the real decoder was reached"
        );
        Ok(())
    }
}
