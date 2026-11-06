use super::*;
use std::collections::BTreeSet;

fn fixture() -> Result<(
    tempfile::TempDir,
    std::path::PathBuf,
    Connection,
    ControllerAdminSqlite,
)> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().canonicalize()?.join("reader.sqlite");
    let keeper = Connection::open(&path)?;
    keeper.pragma_update(None, "journal_mode", "WAL")?;
    keeper.execute_batch("CREATE TABLE current_admin(actor TEXT PRIMARY KEY); INSERT INTO current_admin VALUES('approver@example.test'),('executor@example.test')")?;
    let mut connection = Box::new(open_readonly(&path)?);
    configure_connection(&mut connection)?;
    connection.pragma_update(None, "query_only", true)?;
    let tx = connection.transaction()?;
    let files = opened_files::snapshot(&tx)?;
    tx.commit()?;
    Ok((
        directory,
        path,
        keeper,
        ControllerAdminSqlite {
            connection: Some(connection),
            files: Some(files),
        },
    ))
}

#[test]
fn actual_connection_retains_all_auxiliary_handles_between_closed_units() -> Result<()> {
    let (_directory, _path, keeper, mut reader) = fixture()?;
    for _ in 0..4 {
        reader.check_handles()?;
        let tx = reader.connection.as_mut().unwrap().transaction()?;
        let actual: BTreeSet<String> = tx
            .prepare("SELECT actor FROM current_admin")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        assert_eq!(
            actual,
            BTreeSet::from([
                "approver@example.test".into(),
                "executor@example.test".into()
            ])
        );
        assert!(tx.execute("DELETE FROM current_admin", []).is_err());
        tx.commit()?;
        reader.check_handles()?;
        assert!(reader.connection.as_ref().unwrap().is_autocommit());
    }
    // A new real transaction sees a later writer; no old read snapshot is held
    // over external work. This fixture does NOT model native writer exclusion.
    keeper.execute(
        "DELETE FROM current_admin WHERE actor=?1",
        ["approver@example.test"],
    )?;
    let tx = reader.connection.as_mut().unwrap().transaction()?;
    assert_eq!(
        tx.query_row("SELECT count(*) FROM current_admin", [], |row| row
            .get::<_, i64>(0))?,
        1
    );
    tx.rollback()?;
    reader.check_handles()?;
    Ok(())
}

#[test]
fn same_cohort_second_connection_is_not_the_retained_reader() -> Result<()> {
    let (_directory, path, _keeper, mut reader) = fixture()?;
    let mut substituted = Box::new(open_readonly(&path)?);
    let tx = substituted.transaction()?;
    let files = opened_files::snapshot(&tx)?;
    assert!(opened_files::cohort(&files)? == opened_files::cohort(reader.files.as_ref().unwrap())?);
    tx.rollback()?;
    // Keep the original open: foreign descriptor numbers cannot accidentally
    // be reused by this negative control's new connection.
    let _original = reader.connection.replace(substituted).unwrap();
    assert!(reader.check_handles().is_err());
    Ok(())
}

#[test]
fn open_transaction_and_replaced_auxiliary_handles_refuse() -> Result<()> {
    let (_directory, path, _keeper, reader) = fixture()?;
    let db = reader.connection.as_ref().unwrap();
    db.execute_batch("BEGIN")?;
    assert!(reader.check_handles().is_err());
    db.execute_batch("ROLLBACK")?;
    reader.check_handles()?;
    let mut files = opened_files::held(db)?;
    files.journal.as_mut().unwrap().inode ^= 1;
    let changed = ControllerAdminSqlite {
        connection: reader.connection,
        files: Some(files),
    };
    assert!(changed.check_handles().is_err());
    assert!(path.exists());
    Ok(())
}
