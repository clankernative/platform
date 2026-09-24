//! Durable invalidation belongs to the business transaction, not its caller or
//! the HTTP process. Readers never advance this revision through audit writes.
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension};

pub(crate) fn upgrade(db: &Connection) -> Result<()> {
    ensure!(
        !db.is_autocommit(),
        "live schema upgrade requires transaction"
    );
    let version: Option<String> = db
        .query_row(
            "SELECT value FROM day2_meta WHERE key='live_schema'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match version.as_deref() {
        None => {
            db.execute_batch("CREATE TABLE day2_live_revision(id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL CHECK(revision>=0)) STRICT;
                INSERT INTO day2_live_revision VALUES(1,0);
                INSERT INTO day2_meta VALUES('live_schema','1');")?;
        }
        Some("1") => {
            revision(db)?;
        }
        Some(_) => anyhow::bail!("unknown_live_schema"),
    }
    Ok(())
}

pub(crate) fn changed(db: &Connection) -> Result<()> {
    ensure!(
        !db.is_autocommit(),
        "live change requires business transaction"
    );
    ensure!(db.execute("UPDATE day2_live_revision SET revision=revision+1 WHERE id=1 AND revision<9223372036854775807", [])? == 1,
        "live_revision_unavailable");
    Ok(())
}

pub(crate) fn revision(db: &Connection) -> Result<i64> {
    let revision = db.query_row(
        "SELECT revision FROM day2_live_revision WHERE id=1",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    ensure!(revision >= 0, "invalid_live_revision");
    Ok(revision)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalidation_is_atomic_durable_and_read_only() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("live.sqlite");
        let mut writer = Connection::open(&path)?;
        writer.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE day2_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL) STRICT;")?;
        let tx = writer.transaction()?;
        upgrade(&tx)?;
        tx.commit()?;
        let reader = Connection::open(&path)?;
        assert_eq!(revision(&reader)?, 0);
        assert!(changed(&writer).is_err());
        let tx = writer.transaction()?;
        changed(&tx)?;
        assert_eq!(revision(&reader)?, 0);
        tx.rollback()?;
        assert_eq!(revision(&reader)?, 0);
        let tx = writer.transaction()?;
        changed(&tx)?;
        changed(&tx)?;
        tx.commit()?;
        assert_eq!(revision(&reader)?, 2);
        drop(writer);
        assert_eq!(revision(&Connection::open(&path)?)?, 2);
        assert_eq!(revision(&reader)?, 2);
        Ok(())
    }
}
