//! Additive, transactional invariant upgrades for private OAuth tables. Triggers
//! protect existing databases as well as new ones, without rebuilding referenced
//! tables or turning off foreign keys. Invalid restored rows fail closed.

use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension};

pub(super) struct Invariant {
    pub table: &'static str,
    pub predicate: &'static str,
}

pub(super) fn upgrade(
    db: &Connection,
    version_table: &'static str,
    supported: &[i64],
    current: i64,
    ddl: &str,
    invariants: &[Invariant],
) -> Result<()> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(ddl)?;
    let tx = db.unchecked_transaction()?;
    ensure!(
        shape(&tx, "table_info", version_table)? == shape(&expected, "table_info", version_table)?,
        "unsupported OAuth version table shape"
    );
    let mut statement = tx.prepare(&format!("SELECT version FROM {version_table}"))?;
    let versions = statement
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    ensure!(
        versions.is_empty() || (versions.len() == 1 && supported.contains(&versions[0])),
        "unsupported OAuth schema version"
    );
    for invariant in invariants {
        let Invariant { table, predicate } = invariant;
        for pragma in ["table_info", "foreign_key_list"] {
            ensure!(
                shape(&tx, pragma, table)? == shape(&expected, pragma, table)?,
                "unsupported OAuth table shape in {table}"
            );
        }
        ensure!(
            indexes(&tx, table)? == indexes(&expected, table)?,
            "unsupported OAuth index shape in {table}"
        );
        let mut foreign_keys = tx.prepare(&format!("PRAGMA foreign_key_check({table})"))?;
        ensure!(
            foreign_keys.query([])?.next()?.is_none(),
            "orphaned durable OAuth state in {table}"
        );
        drop(foreign_keys);
        let mut columns = tx.prepare(&format!("PRAGMA table_info({table})"))?;
        let types = columns
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, i64>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(columns);
        let mut shape = Vec::new();
        for (column, kind, required, primary_key) in types {
            ensure!(
                !column.is_empty()
                    && column
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "invalid OAuth schema column"
            );
            let storage = match kind.as_str() {
                "TEXT" => "text",
                "INTEGER" => "integer",
                "BLOB" => "blob",
                _ => anyhow::bail!("unsupported OAuth column type"),
            };
            let check = format!("typeof({column}) = '{storage}'");
            shape.push(if required || primary_key > 0 {
                check
            } else {
                format!("({column} IS NULL OR {check})")
            });
        }
        let predicate = format!("({predicate}) AND {}", shape.join(" AND "));
        let invalid: bool = tx.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE NOT COALESCE(({predicate}), 0))"),
            [],
            |row| row.get(0),
        )?;
        ensure!(!invalid, "invalid durable OAuth state in {table}");
        // Predicates use row column names and the fixed reviewed table selection.
        for operation in ["INSERT", "UPDATE"] {
            let name = format!("{table}_shape_{operation}_v{current}");
            let sql = format!(
                "CREATE TRIGGER {name}
                 AFTER {operation} ON {table}
                 WHEN EXISTS(SELECT 1 FROM {table} WHERE rowid = NEW.rowid AND NOT COALESCE(({predicate}), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END"
            );
            let installed: Option<String> = tx
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                    [&name],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(installed) = installed {
                ensure!(
                    installed == sql,
                    "unsupported OAuth invariant guard in {table}"
                );
            } else {
                tx.execute_batch(&sql)?;
            }
        }
    }
    if versions.is_empty() {
        tx.execute(
            &format!("INSERT INTO {version_table} VALUES (?1)"),
            [current],
        )?;
    } else if versions[0] != current {
        tx.execute(
            &format!("UPDATE {version_table} SET version = ?1"),
            [current],
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn shape(db: &Connection, pragma: &str, table: &str) -> Result<Vec<Vec<rusqlite::types::Value>>> {
    let mut statement = db.prepare(&format!("PRAGMA {pragma}({table})"))?;
    let count = statement.column_count();
    Ok(statement
        .query_map([], |row| (0..count).map(|index| row.get(index)).collect())?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

type IndexShape = (Vec<Vec<rusqlite::types::Value>>, Option<String>);

fn indexes(db: &Connection, table: &str) -> Result<Vec<IndexShape>> {
    let mut statement = db.prepare(&format!("PRAGMA index_list({table})"))?;
    let names = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, bool>(2)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut result = Vec::new();
    for (name, unique) in names {
        if !unique {
            continue;
        }
        ensure!(
            name.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
            "invalid OAuth index name"
        );
        let sql: Option<String> = db.query_row(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name=?1",
            [&name],
            |row| row.get(0),
        )?;
        // Autoindexes have no SQL. Explicit partial uniqueness retains its
        // reviewed predicate as well as the indexed columns.
        result.push((shape(db, "index_xinfo", &name)?, sql));
    }
    result.sort_by_key(|entry| format!("{entry:?}"));
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY_REFRESH: &str = "
        CREATE TABLE oauth_schema_version(version INTEGER PRIMARY KEY);
        INSERT INTO oauth_schema_version VALUES(1);
        CREATE TABLE oauth_connection_slots(slot TEXT PRIMARY KEY, generation INTEGER NOT NULL,
            token_version INTEGER NOT NULL, security_epoch INTEGER NOT NULL, profile TEXT NOT NULL,
            account TEXT NOT NULL, affinity TEXT NOT NULL, status TEXT NOT NULL);
        CREATE TABLE oauth_refresh_attempts(attempt TEXT PRIMARY KEY, slot TEXT NOT NULL REFERENCES oauth_connection_slots(slot),
            generation INTEGER NOT NULL, base_version INTEGER NOT NULL, security_epoch INTEGER NOT NULL,
            profile TEXT NOT NULL, account TEXT NOT NULL, affinity TEXT NOT NULL, state TEXT NOT NULL,
            next_version INTEGER, receipt TEXT,
            CHECK((state = 'replacement_committed') = (next_version IS NOT NULL AND receipt IS NOT NULL)),
            UNIQUE(slot, generation, base_version));
        INSERT INTO oauth_connection_slots VALUES('slot',1,1,1,'profile','account','affinity','active');
        INSERT INTO oauth_refresh_attempts VALUES('attempt','slot',1,1,1,'profile','account','affinity','ready',NULL,NULL);";

    const LEGACY_CONNECT: &str = "
        CREATE TABLE oauth_connect_schema_version(version INTEGER PRIMARY KEY);
        INSERT INTO oauth_connect_schema_version VALUES(1);
        CREATE TABLE oauth_connect_attempts(attempt TEXT PRIMARY KEY, slot TEXT NOT NULL, expected_generation INTEGER,
            expected_epoch INTEGER NOT NULL, proposed_generation INTEGER NOT NULL, owner TEXT NOT NULL,
            profile TEXT NOT NULL, registration TEXT NOT NULL, callback TEXT NOT NULL, consent TEXT NOT NULL,
            expires_at INTEGER NOT NULL, state TEXT NOT NULL, code_ref TEXT, account TEXT, scope_evidence TEXT,
            CHECK((state IN ('exchange_ready','exchange_may_have_been_sent','exchange_uncertain')) = (code_ref IS NOT NULL)),
            CHECK((state IN ('awaiting_account_approval','activated')) = (account IS NOT NULL AND scope_evidence IS NOT NULL)));
        INSERT INTO oauth_connect_attempts VALUES('attempt','slot',NULL,1,1,'human','profile','registration','callback','consent',100,
            'awaiting_provider_authorization',NULL,NULL,NULL);";

    #[test]
    fn valid_legacy_rows_upgrade_atomically_and_keep_identity() -> Result<()> {
        for legacy in [LEGACY_REFRESH, LEGACY_CONNECT] {
            let db = Connection::open_in_memory()?;
            db.execute_batch(legacy)?;
            super::super::connect::install_schema(&db)?;
            assert_eq!(
                db.query_row("SELECT version FROM oauth_schema_version", [], |row| row
                    .get::<_, i64>(0))?,
                2
            );
            assert_eq!(
                db.query_row(
                    "SELECT version FROM oauth_connect_schema_version",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                2
            );
            super::super::connect::install_schema(&db)?;
            for sql in [
                "UPDATE oauth_refresh_attempts SET receipt = 'half' WHERE state = 'ready'",
                "UPDATE oauth_refresh_attempts SET next_version = 2 WHERE state = 'ready'",
                "UPDATE oauth_connection_slots SET generation = 1.5",
                "UPDATE oauth_connect_attempts SET account = 'half' WHERE state = 'awaiting_provider_authorization'",
                "UPDATE oauth_connect_attempts SET scope_evidence = 'half' WHERE state = 'awaiting_provider_authorization'",
                "UPDATE oauth_connect_attempts SET proposed_generation = 9",
            ] {
                // Tables not populated in a particular legacy fixture simply
                // have no candidate; test only its populated target.
                let target =
                    if sql.contains("oauth_refresh") || sql.contains("oauth_connection_slots") {
                        "oauth_refresh_attempts"
                    } else {
                        "oauth_connect_attempts"
                    };
                let populated: i64 =
                    db.query_row(&format!("SELECT count(*) FROM {target}"), [], |row| {
                        row.get(0)
                    })?;
                if populated > 0 {
                    assert!(db.execute_batch(sql).is_err(), "{sql}");
                }
            }
            assert!(db.is_autocommit());
        }
        Ok(())
    }

    #[test]
    fn malformed_legacy_state_cannot_be_stamped_current() -> Result<()> {
        for (legacy, corrupt, version_table) in [
            (
                LEGACY_REFRESH,
                "UPDATE oauth_refresh_attempts SET receipt='half'",
                "oauth_schema_version",
            ),
            (
                LEGACY_CONNECT,
                "UPDATE oauth_connect_attempts SET account='half'",
                "oauth_connect_schema_version",
            ),
        ] {
            let db = Connection::open_in_memory()?;
            db.execute_batch(legacy)?;
            db.execute_batch(corrupt)?;
            assert!(super::super::connect::install_schema(&db).is_err());
            assert_eq!(
                db.query_row(&format!("SELECT version FROM {version_table}"), [], |row| {
                    row.get::<_, i64>(0)
                })?,
                1
            );
            let guards: i64 = db.query_row("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'oauth_%shape_%' AND tbl_name = ?1", [if version_table == "oauth_schema_version" { "oauth_refresh_attempts" } else { "oauth_connect_attempts" }], |row| row.get(0))?;
            assert_eq!(guards, 0);
            assert!(db.is_autocommit());
        }
        Ok(())
    }

    #[test]
    fn ciphertext_shape_and_receipt_versions_are_enforced_on_new_writes() -> Result<()> {
        let db = Connection::open_in_memory()?;
        db.execute_batch(LEGACY_REFRESH)?;
        super::super::connect::install_schema(&db)?;
        assert!(db.execute_batch("UPDATE oauth_refresh_attempts SET state='replacement_committed', next_version=99, receipt='receipt'").is_err());
        db.execute_batch("UPDATE oauth_refresh_attempts SET state='replacement_committed', next_version=2, receipt='receipt'")?;
        assert!(db.execute_batch("INSERT INTO oauth_private_tokens VALUES('ref','slot',1,'account','identity','key',zeroblob(11),zeroblob(16))").is_err());
        assert!(db.execute_batch("INSERT INTO oauth_private_tokens VALUES('ref','slot',1,'account','identity','key',zeroblob(12),zeroblob(15))").is_err());
        db.execute_batch("INSERT INTO oauth_private_tokens VALUES('ref','slot',1,'account','identity','key',zeroblob(12),zeroblob(16))")?;
        assert!(
            db.execute_batch("UPDATE oauth_private_tokens SET nonce='not_a_blob!'")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn restored_schema_substitution_and_orphaned_rows_fail_closed() -> Result<()> {
        for legacy in [
            LEGACY_REFRESH.replace("profile TEXT NOT NULL", "profile BLOB NOT NULL"),
            LEGACY_REFRESH.replace(
                "UNIQUE(slot, generation, base_version)",
                "CHECK(generation > 0)",
            ),
            LEGACY_REFRESH.replace("REFERENCES oauth_connection_slots(slot)", ""),
            LEGACY_REFRESH.replace("version INTEGER PRIMARY KEY", "version INTEGER"),
        ] {
            let db = Connection::open_in_memory()?;
            db.execute_batch(&legacy)?;
            assert!(super::super::store::install_schema(&db).is_err());
            assert_eq!(
                db.query_row("SELECT version FROM oauth_schema_version", [], |row| row
                    .get::<_, i64>(0))?,
                1
            );
        }
        let db = Connection::open_in_memory()?;
        db.execute_batch(LEGACY_REFRESH)?;
        db.execute_batch("PRAGMA foreign_keys=OFF; DELETE FROM oauth_connection_slots;")?;
        assert!(super::super::store::install_schema(&db).is_err());
        let db = Connection::open_in_memory()?;
        super::super::store::install_schema(&db)?;
        db.execute_batch("DROP TRIGGER oauth_refresh_attempts_shape_INSERT_v2;
            CREATE TRIGGER oauth_refresh_attempts_shape_INSERT_v2 AFTER INSERT ON oauth_refresh_attempts BEGIN SELECT 1; END;")?;
        assert!(super::super::store::install_schema(&db).is_err());
        Ok(())
    }

    #[test]
    fn upgraded_guards_survive_reopen_and_preserve_atomic_rollback() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("legacy.sqlite");
        let db = Connection::open(&path)?;
        db.execute_batch(LEGACY_REFRESH)?;
        super::super::connect::install_schema(&db)?;
        drop(db);
        let mut db = Connection::open(&path)?;
        super::super::connect::install_schema(&db)?;
        {
            let tx = db.transaction()?;
            tx.execute(
                "UPDATE oauth_connection_slots SET account='replacement'",
                [],
            )?;
            assert!(
                tx.execute("UPDATE oauth_refresh_attempts SET receipt='half'", [])
                    .is_err()
            );
            // The host drops a failed transaction; the preceding custody/slot
            // update cannot be published on its own.
        }
        assert_eq!(
            db.query_row("SELECT account FROM oauth_connection_slots", [], |row| {
                row.get::<_, String>(0)
            })?,
            "account"
        );
        assert!(db.execute_batch("INSERT INTO oauth_refresh_attempts VALUES('new','slot',1,2,1,'profile','account','affinity','ready',NULL,'half')").is_err());
        Ok(())
    }
}
