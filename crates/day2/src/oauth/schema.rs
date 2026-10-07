//! Additive, transactional invariant upgrades for private OAuth tables. Triggers
//! protect existing databases as well as new ones, without rebuilding referenced
//! tables or turning off foreign keys. Invalid restored rows fail closed.

use anyhow::{Context, Result, ensure};
use rusqlite::Connection;
use std::cell::RefCell;

/// Admission is deliberately finite even for a restored database with no useful
/// indexes. Nested installers debit the same budget, including metadata reads.
const ADMISSION_STEPS: usize = 1_000_000;
const ADMISSION_ROWS: usize = 16_384;
const ADMISSION_BYTES: usize = 8 * 1_048_576;

struct Budget {
    connection: usize,
    steps: usize,
    rows: usize,
    bytes: usize,
    exhausted: bool,
}

thread_local! {
    static ADMISSION: RefCell<Option<Budget>> = const { RefCell::new(None) };
}

/// Own only this admission's thread counter, raw hook and savepoint. Runtime
/// hooks belong to store::open and must survive ordinary refusal and unwind.
struct AdmissionScope<'a> {
    db: &'a Connection,
    raw_hook: bool,
    savepoint: bool,
}

impl AdmissionScope<'_> {
    fn clear_budget(&mut self) -> Result<bool> {
        let exhausted = ADMISSION.with(|active| {
            active
                .borrow_mut()
                .take()
                .is_some_and(|budget| budget.exhausted)
        });
        if self.raw_hook {
            self.db.progress_handler(0, None::<fn() -> bool>)?;
            self.raw_hook = false;
        }
        Ok(exhausted)
    }
}

impl Drop for AdmissionScope<'_> {
    fn drop(&mut self) {
        // On panic, clear our exhausted counter before cleanup SQL. Never
        // replace/reset the permanent runtime callback or its lifetime cap.
        ADMISSION.with(|active| {
            active.borrow_mut().take();
        });
        if self.raw_hook {
            let _ = self.db.progress_handler(0, None::<fn() -> bool>);
        }
        if self.savepoint && !self.db.is_autocommit() {
            let _ = self.db.execute_batch(
                "ROLLBACK TO day2_identity_admission; RELEASE day2_identity_admission",
            );
        }
    }
}

/// The existing connection runtime callback also calls this function; admission
/// never replaces that callback or resets its separate lifetime work counter.
pub(crate) fn admission_step(steps: usize) -> bool {
    ADMISSION.with(|active| {
        let mut active = active.borrow_mut();
        let Some(budget) = active.as_mut() else {
            return false;
        };
        if steps >= budget.steps {
            budget.exhausted = true;
            budget.steps = 0;
        } else {
            budget.steps -= steps;
        }
        budget.exhausted
    })
}

/// Charge SQLite values before allocating owned strings/blobs or decoded JSON.
pub(crate) fn materialize(row: &rusqlite::Row<'_>) -> Result<()> {
    let mut bytes = 0usize;
    for index in 0..row.as_ref().column_count() {
        bytes = bytes.saturating_add(match row.get_ref(index)? {
            rusqlite::types::ValueRef::Text(value) | rusqlite::types::ValueRef::Blob(value) => {
                value.len()
            }
            _ => 8,
        });
    }
    ADMISSION.with(|active| {
        let mut active = active.borrow_mut();
        let budget = active
            .as_mut()
            .context("identity materialization outside admission")?;
        if budget.exhausted || budget.rows == 0 || bytes > budget.bytes {
            budget.exhausted = true;
            anyhow::bail!("identity admission materialization budget exhausted");
        }
        budget.rows -= 1;
        budget.bytes -= bytes;
        Ok(())
    })
}

/// Raw SQLite adapters explicitly grant ownership of their progress callback:
/// this installs/removes a temporary hook, and cannot preserve an unknown hook.
/// Production connections use `admit_with_runtime_hook` instead.
pub(crate) fn admit<T>(
    db: &Connection,
    admission: impl FnOnce(&Connection) -> Result<T>,
) -> Result<T> {
    admit_inner(
        db,
        false,
        ADMISSION_STEPS,
        ADMISSION_ROWS,
        ADMISSION_BYTES,
        admission,
    )
}

pub(crate) fn admit_with_runtime_hook<T>(
    db: &Connection,
    admission: impl FnOnce(&Connection) -> Result<T>,
) -> Result<T> {
    admit_inner(
        db,
        true,
        ADMISSION_STEPS,
        ADMISSION_ROWS,
        ADMISSION_BYTES,
        admission,
    )
}

#[cfg(test)]
pub(crate) fn admit_with_limits<T>(
    db: &Connection,
    steps: usize,
    rows: usize,
    bytes: usize,
    admission: impl FnOnce(&Connection) -> Result<T>,
) -> Result<T> {
    admit_inner(db, false, steps, rows, bytes, admission)
}

fn admit_inner<T>(
    db: &Connection,
    runtime_hook: bool,
    steps: usize,
    rows: usize,
    bytes: usize,
    admission: impl FnOnce(&Connection) -> Result<T>,
) -> Result<T> {
    let connection = std::ptr::from_ref(db) as usize;
    let nested = ADMISSION.with(|active| active.borrow().as_ref().map(|budget| budget.connection));
    if let Some(owner) = nested {
        ensure!(
            owner == connection,
            "nested identity admission changed connection"
        );
        return admission(db);
    }
    // SQLite cannot change this pragma inside a caller transaction. Never turn
    // it off for migration, and refuse a transaction that started without it.
    db.pragma_update(None, "foreign_keys", true)?;
    ensure!(
        db.pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))?,
        "identity admission requires foreign keys"
    );
    ADMISSION.with(|active| {
        *active.borrow_mut() = Some(Budget {
            connection,
            steps,
            rows,
            bytes,
            exhausted: false,
        })
    });
    let mut scope = AdmissionScope {
        db,
        raw_hook: !runtime_hook,
        savepoint: false,
    };
    if !runtime_hook {
        db.progress_handler(1, Some(|| admission_step(1)))?;
    }
    let result = (|| {
        db.execute_batch("SAVEPOINT day2_identity_admission")?;
        scope.savepoint = true;
        admission(db)
    })();
    // Remove the exhausted admission counter before cleanup SQL. SQLite may
    // roll back an entire caller transaction on INTERRUPT during a write; a
    // savepoint preserves caller ownership for ordinary admission failures.
    let exhausted = scope.clear_budget()?;
    let result = if exhausted {
        result.and_then(|_| anyhow::bail!("identity admission budget exhausted"))
    } else {
        result
    };
    match result {
        Ok(value) => {
            db.execute_batch("RELEASE day2_identity_admission")?;
            scope.savepoint = false;
            Ok(value)
        }
        Err(error) => {
            if scope.savepoint && !db.is_autocommit() {
                // An interrupted transaction can already have been rolled back
                // by SQLite. Otherwise unwind only this admission savepoint.
                db.execute_batch(
                    "ROLLBACK TO day2_identity_admission; RELEASE day2_identity_admission",
                )?;
            }
            scope.savepoint = false;
            if exhausted {
                Err(error.context("identity admission VM-step budget exhausted"))
            } else {
                Err(error)
            }
        }
    }
}

pub(crate) struct Invariant<'a> {
    pub table: &'static str,
    pub predicate: &'a str,
}

pub(crate) fn upgrade(
    db: &Connection,
    version_table: &'static str,
    supported: &[i64],
    current: i64,
    ddl: &str,
    invariants: &[Invariant<'_>],
) -> Result<()> {
    admit(db, |db| {
        upgrade_in(db, version_table, supported, current, ddl, invariants)
    })
}

fn upgrade_in(
    db: &Connection,
    version_table: &'static str,
    supported: &[i64],
    current: i64,
    ddl: &str,
    invariants: &[Invariant<'_>],
) -> Result<()> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(ddl)?;
    ensure!(
        shape(db, "table_xinfo", version_table)? == shape(&expected, "table_xinfo", version_table)?,
        "unsupported OAuth version table shape"
    );
    let mut statement = db.prepare(&format!("SELECT version FROM {version_table}"))?;
    let mut versions = Vec::new();
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        materialize(row)?;
        versions.push(row.get::<_, i64>(0)?);
        ensure!(versions.len() <= 1, "unsupported OAuth schema version");
    }
    drop(rows);
    drop(statement);
    ensure!(
        versions.is_empty() || (versions.len() == 1 && supported.contains(&versions[0])),
        "unsupported OAuth schema version"
    );
    for invariant in invariants {
        let Invariant { table, predicate } = invariant;
        for pragma in ["table_xinfo", "foreign_key_list"] {
            ensure!(
                shape(db, pragma, table)? == shape(&expected, pragma, table)?,
                "unsupported OAuth table shape in {table}"
            );
        }
        ensure!(
            indexes(db, table)? == indexes(&expected, table)?,
            "unsupported OAuth index shape in {table}"
        );
        bounded_rows(db, table)?;
        let mut foreign_keys = db.prepare(&format!("PRAGMA foreign_key_check({table})"))?;
        ensure!(
            foreign_keys.query([])?.next()?.is_none(),
            "orphaned durable OAuth state in {table}"
        );
        drop(foreign_keys);
        let mut columns = db.prepare(&format!("PRAGMA table_info({table})"))?;
        let mut types = Vec::new();
        let mut rows = columns.query([])?;
        while let Some(row) = rows.next()? {
            materialize(row)?;
            types.push((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, i64>(5)?,
            ));
        }
        drop(rows);
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
        let invalid: bool = db.query_row(
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
            let installed = schema_sql(db, "trigger", &name)?;
            if let Some(installed) = installed {
                ensure!(
                    installed == sql,
                    "unsupported OAuth invariant guard in {table}"
                );
            } else {
                ensure!(
                    versions != [current],
                    "missing OAuth invariant guard in {table}"
                );
                db.execute_batch(&sql)?;
            }
        }
    }
    if versions.is_empty() {
        db.execute(
            &format!("INSERT INTO {version_table} VALUES (?1)"),
            [current],
        )?;
    } else if versions[0] != current {
        db.execute(
            &format!("UPDATE {version_table} SET version = ?1"),
            [current],
        )?;
    }
    Ok(())
}

fn shape(db: &Connection, pragma: &str, table: &str) -> Result<Vec<Vec<rusqlite::types::Value>>> {
    schema_identifier(table)?;
    ensure!(
        matches!(pragma, "table_xinfo" | "foreign_key_list" | "index_xinfo"),
        "unsupported identity shape pragma"
    );
    let mut statement = db.prepare(&format!("PRAGMA {pragma}({table})"))?;
    let count = statement.column_count();
    let mut rows = statement.query([])?;
    let mut result = Vec::new();
    while let Some(row) = rows.next()? {
        materialize(row)?;
        result.push(
            (0..count)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<_>>>()?,
        );
    }
    Ok(result)
}

type IndexShape = (Vec<Vec<rusqlite::types::Value>>, Option<String>);
type CredentialIndexShape = (String, bool, String, bool, IndexShape);

fn indexes(db: &Connection, table: &str) -> Result<Vec<IndexShape>> {
    schema_identifier(table)?;
    let mut statement = db.prepare(&format!("PRAGMA index_list({table})"))?;
    let mut names = Vec::new();
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        materialize(row)?;
        names.push((row.get::<_, String>(1)?, row.get::<_, bool>(2)?));
    }
    drop(rows);
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
        let sql = schema_sql(db, "index", &name)?;
        // Autoindexes have no SQL. Explicit partial uniqueness retains its
        // reviewed predicate as well as the indexed columns.
        result.push((shape(db, "index_xinfo", &name)?, sql));
    }
    result.sort_by_key(|entry| format!("{entry:?}"));
    Ok(result)
}

/// Credential v1 has one exact authored STRICT layout. Compare SQL as well as
/// pragma metadata: CHECK clauses and STRICT can disappear without changing
/// table_xinfo. SQL normalization removes whitespace only outside literals.
pub(crate) fn exact_layout(db: &Connection, expected: &Connection, table: &str) -> Result<()> {
    for pragma in ["table_xinfo", "foreign_key_list"] {
        ensure!(
            shape(db, pragma, table)? == shape(expected, pragma, table)?,
            "unsupported credential table shape in {table}"
        );
    }
    ensure!(
        schema_sql(db, "table", table)?.map(|sql| normalize_sql(&sql))
            == schema_sql(expected, "table", table)?.map(|sql| normalize_sql(&sql)),
        "unsupported credential table constraints in {table}"
    );
    ensure!(
        all_indexes(db, table)? == all_indexes(expected, table)?,
        "unsupported credential index shape in {table}"
    );
    bounded_rows(db, table)?;
    let mut statement = db.prepare(&format!("PRAGMA foreign_key_check({table})"))?;
    ensure!(
        statement.query([])?.next()?.is_none(),
        "orphaned durable credential state in {table}"
    );
    Ok(())
}

/// Bound values before SQLite's JSON/string predicates or decoded host values
/// inspect them. VM instructions alone do not bound one enormous text operand.
pub(crate) fn bounded_rows(db: &Connection, table: &str) -> Result<()> {
    schema_identifier(table)?;
    let mut statement = db.prepare(&format!("SELECT * FROM {table}"))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        materialize(row)?;
    }
    Ok(())
}

pub(crate) fn schema_sql(db: &Connection, kind: &str, name: &str) -> Result<Option<String>> {
    let mut statement = db.prepare("SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2")?;
    let mut rows = statement.query([kind, name])?;
    match rows.next()? {
        Some(row) => {
            materialize(row)?;
            Ok(row.get(0)?)
        }
        None => Ok(None),
    }
}

fn all_indexes(db: &Connection, table: &str) -> Result<Vec<CredentialIndexShape>> {
    schema_identifier(table)?;
    let mut statement = db.prepare(&format!("PRAGMA index_list({table})"))?;
    let mut rows = statement.query([])?;
    let mut names = Vec::new();
    while let Some(row) = rows.next()? {
        materialize(row)?;
        names.push((
            row.get::<_, String>(1)?,
            row.get::<_, bool>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, bool>(4)?,
        ));
    }
    drop(rows);
    let mut result = Vec::new();
    for (name, unique, origin, partial) in names {
        ensure!(
            name.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
            "invalid credential index name"
        );
        let sql = schema_sql(db, "index", &name)?.map(|sql| normalize_sql(&sql));
        result.push((
            name.clone(),
            unique,
            origin,
            partial,
            (shape(db, "index_xinfo", &name)?, sql),
        ));
    }
    result.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(result)
}

fn schema_identifier(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 160
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
        "invalid identity schema identifier"
    );
    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    let mut quoted = false;
    sql.chars()
        .filter(|character| {
            if *character == '\'' {
                quoted = !quoted;
            }
            quoted || !character.is_ascii_whitespace()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCAN: &str = "WITH RECURSIVE work(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM work WHERE n<500) SELECT sum(n) FROM work";

    #[test]
    fn cumulative_nested_budget_interrupts_and_removes_only_owned_hook() -> Result<()> {
        let db = Connection::open_in_memory()?;
        let mut first_finished = false;
        let error = admit_with_limits(&db, 15_000, 100, 1024, |db| {
            db.query_row(SCAN, [], |row| row.get::<_, i64>(0))?;
            first_finished = true;
            admit(db, |db| {
                db.query_row(SCAN, [], |row| row.get::<_, i64>(0))?;
                Ok(())
            })
        })
        .unwrap_err();
        assert!(first_finished);
        assert!(format!("{error:#}").contains("VM-step budget exhausted"));
        assert!(db.is_autocommit());
        assert_eq!(db.query_row(SCAN, [], |row| row.get::<_, i64>(0))?, 125_250);
        Ok(())
    }

    #[test]
    fn admission_materialization_refuses_before_owned_value_allocation() -> Result<()> {
        let db = Connection::open_in_memory()?;
        db.execute_batch(
            "CREATE TABLE imported(value TEXT); INSERT INTO imported VALUES(hex(zeroblob(2048)))",
        )?;
        let error = admit_with_limits(&db, 20_000, 100, 1024, |db| bounded_rows(db, "imported"))
            .unwrap_err();
        assert!(format!("{error:#}").contains("materialization budget"));
        assert_eq!(
            db.query_row("SELECT length(value) FROM imported", [], |row| row
                .get::<_, i64>(0))?,
            4096
        );
        let error =
            admit_with_limits(&db, 20_000, 0, 8192, |db| bounded_rows(db, "imported")).unwrap_err();
        assert!(format!("{error:#}").contains("materialization budget"));
        Ok(())
    }

    #[test]
    fn nested_admission_cannot_publish_on_another_connection() -> Result<()> {
        let first = Connection::open_in_memory()?;
        let second = Connection::open_in_memory()?;
        assert!(
            admit(&first, |_| admit(&second, |db| {
                db.execute_batch("CREATE TABLE escaped(value INTEGER)")?;
                Ok(())
            }))
            .is_err()
        );
        assert_eq!(
            second.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='escaped'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        Ok(())
    }

    #[test]
    fn budget_exhaustion_rolls_back_upgrade_and_never_restamps_version() -> Result<()> {
        let db = Connection::open_in_memory()?;
        db.execute_batch(LEGACY_REFRESH)?;
        let error = admit_with_limits(&db, 12_000, 16_384, 8 * 1_048_576, |db| {
            super::super::store::install_schema(db)?;
            db.query_row(SCAN, [], |row| row.get::<_, i64>(0))?;
            db.query_row(SCAN, [], |row| row.get::<_, i64>(0))?;
            Ok(())
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("VM-step budget exhausted"));
        assert_eq!(
            db.query_row("SELECT version FROM oauth_schema_version", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='trigger'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        super::super::store::install_schema(&db)?;
        Ok(())
    }

    #[test]
    fn ordinary_failure_preserves_caller_savepoint_and_success_is_uncommitted() -> Result<()> {
        let mut db = Connection::open_in_memory()?;
        db.pragma_update(None, "foreign_keys", true)?;
        db.execute_batch("CREATE TABLE caller(value INTEGER)")?;
        let tx = db.transaction()?;
        tx.execute("INSERT INTO caller VALUES(7)", [])?;
        assert!(
            admit(&tx, |db| -> Result<()> {
                db.execute_batch("CREATE TABLE incomplete(value INTEGER)")?;
                anyhow::bail!("fixture refusal")
            })
            .is_err()
        );
        assert!(!tx.is_autocommit());
        assert_eq!(
            tx.query_row("SELECT value FROM caller", [], |row| row.get::<_, i64>(0))?,
            7
        );
        assert_eq!(
            tx.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='incomplete'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        super::super::connect::install_schema(&tx)?;
        assert!(!tx.is_autocommit());
        tx.rollback()?;
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='oauth_schema_version'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        Ok(())
    }

    #[test]
    fn admission_unwind_cleans_owned_scope_and_preserves_caller_transaction() -> Result<()> {
        let mut db = Connection::open_in_memory()?;
        db.pragma_update(None, "foreign_keys", true)?;
        db.execute_batch("CREATE TABLE caller(value INTEGER)")?;
        let tx = db.transaction()?;
        tx.execute("INSERT INTO caller VALUES(7)", [])?;
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = admit(&tx, |db| -> Result<()> {
                db.execute_batch(
                    "CREATE TABLE incomplete(value INTEGER); INSERT INTO caller VALUES(8)",
                )?;
                panic!("trusted admission fixture panic")
            });
        }));
        assert!(panic.is_err());
        assert!(!tx.is_autocommit());
        assert_eq!(
            tx.query_row("SELECT count(*) FROM caller", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        assert_eq!(
            tx.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='incomplete'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        // A new owner on this worker thread gets a fresh admission, and the
        // temporary callback no longer debits the unwound scope.
        admit(&tx, super::super::connect::install_schema)?;
        assert_eq!(tx.query_row(SCAN, [], |row| row.get::<_, i64>(0))?, 125_250);
        tx.rollback()?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM caller", [], |row| row
                .get::<_, i64>(0))?,
            0
        );
        Ok(())
    }

    #[test]
    fn swallowed_budget_errors_cannot_complete_admission() -> Result<()> {
        let db = Connection::open_in_memory()?;
        db.execute_batch(
            "CREATE TABLE imported(value TEXT); INSERT INTO imported VALUES('bounded')",
        )?;
        assert!(
            admit_with_limits(&db, 100, 100, 1024, |db| {
                assert!(db.query_row(SCAN, [], |row| row.get::<_, i64>(0)).is_err());
                Ok(())
            })
            .is_err()
        );
        assert!(
            admit_with_limits(&db, 20_000, 0, 1024, |db| {
                assert!(bounded_rows(db, "imported").is_err());
                Ok(())
            })
            .is_err()
        );
        assert!(db.is_autocommit());
        admit(&db, |db| bounded_rows(db, "imported"))?;
        Ok(())
    }

    #[test]
    fn current_version_with_missing_guard_is_not_a_supported_upgrade() -> Result<()> {
        let db = Connection::open_in_memory()?;
        super::super::connect::install_schema(&db)?;
        db.execute_batch("DROP TRIGGER oauth_refresh_attempts_shape_UPDATE_v2")?;
        assert!(super::super::connect::install_schema(&db).is_err());
        assert_eq!(db.query_row("SELECT count(*) FROM sqlite_master WHERE name='oauth_refresh_attempts_shape_UPDATE_v2'",[],|row| row.get::<_,i64>(0))?,0);
        Ok(())
    }

    #[test]
    fn permanent_runtime_hook_survives_move_success_failure_and_nested_admission() -> Result<()> {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let db = Connection::open_in_memory()?;
        let ticks = Arc::new(AtomicUsize::new(0));
        let captured = ticks.clone();
        db.progress_handler(
            1,
            Some(move || {
                captured.fetch_add(1, Ordering::Relaxed);
                admission_step(1)
            }),
        )?;
        db.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))?;
        let before = ticks.load(Ordering::Relaxed);
        fn moved(db: Connection) -> Connection {
            db
        }
        let db = moved(db); // Connection moves do not change the callback's state.
        admit_with_runtime_hook(&db, |db| admit(db, super::super::connect::install_schema))?;
        let after_success = ticks.load(Ordering::Relaxed);
        assert!(after_success > before);
        assert!(
            admit_with_runtime_hook(&db, |_| -> Result<()> { anyhow::bail!("fixture refusal") })
                .is_err()
        );
        let after_failure = ticks.load(Ordering::Relaxed);
        assert!(after_failure > after_success);
        db.query_row(SCAN, [], |row| row.get::<_, i64>(0))?;
        assert!(ticks.load(Ordering::Relaxed) > after_failure);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = admit_with_runtime_hook(&db, |db| -> Result<()> {
                db.execute_batch("CREATE TABLE incomplete(value INTEGER)")?;
                panic!("trusted runtime admission fixture panic")
            });
        }));
        assert!(panic.is_err());
        assert!(db.is_autocommit());
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='incomplete'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        let after_unwind = ticks.load(Ordering::Relaxed);
        admit_with_runtime_hook(&db, |db| {
            db.query_row(SCAN, [], |row| row.get::<_, i64>(0))?;
            Ok(())
        })?;
        assert!(ticks.load(Ordering::Relaxed) > after_unwind);
        db.progress_handler(0, None::<fn() -> bool>)?;
        Ok(())
    }

    #[test]
    fn actual_runtime_connection_keeps_its_lifetime_work_cap_after_admission() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let db = crate::store::open(&directory.path().join("runtime.sqlite"))?;
        admit_with_runtime_hook(&db, super::super::connect::install_schema)?;
        let error=db.query_row(
            "WITH RECURSIVE work(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM work WHERE n<1000000) SELECT sum(n) FROM work",
            [],|row| row.get::<_,i64>(0),
        ).unwrap_err();
        assert!(
            matches!(error,rusqlite::Error::SqliteFailure(code,_) if code.code==rusqlite::ErrorCode::OperationInterrupted)
        );
        // A connection that exhausted its lifetime cap is discarded, rather
        // than replacing the callback to continue work after the refusal.
        drop(db);
        Ok(())
    }

    #[test]
    fn sqlite_write_interrupt_can_abort_the_entire_caller_transaction() -> Result<()> {
        let mut db = Connection::open_in_memory()?;
        db.pragma_update(None, "foreign_keys", true)?;
        db.execute_batch("CREATE TABLE caller(value INTEGER)")?;
        let tx = db.transaction()?;
        tx.execute("INSERT INTO caller VALUES(7)", [])?;
        let error=admit_with_limits(&tx,1000,100,1024,|db| {
            db.execute_batch("WITH RECURSIVE work(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM work WHERE n<10000) INSERT INTO caller SELECT n FROM work")?;
            Ok(())
        }).unwrap_err();
        assert!(format!("{error:#}").contains("VM-step budget exhausted"));
        assert!(
            tx.is_autocommit(),
            "SQLite has aborted the caller transaction; the caller must not continue it"
        );
        drop(tx);
        assert_eq!(
            db.query_row("SELECT count(*) FROM caller", [], |row| row
                .get::<_, i64>(0))?,
            0
        );
        Ok(())
    }

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
            LEGACY_REFRESH.replace(
                "version INTEGER PRIMARY KEY",
                "version INTEGER PRIMARY KEY, hidden INTEGER GENERATED ALWAYS AS (version + 1)",
            ).replace("INSERT INTO oauth_schema_version VALUES(1)", "INSERT INTO oauth_schema_version(version) VALUES(1)"),
            LEGACY_REFRESH.replace(
                "next_version INTEGER, receipt TEXT,",
                "next_version INTEGER, receipt TEXT, hidden INTEGER GENERATED ALWAYS AS (generation + 1),",
            ),
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
    fn legacy_binding_tables_validate_shape_and_guard_json_objects() -> Result<()> {
        for prefix in ["callback", "exchange"] {
            let table = format!("oauth_{prefix}_bindings");
            let version = format!("oauth_{prefix}_schema_version");
            let legacy = format!(
                "{LEGACY_CONNECT}
                 CREATE TABLE {version}(version INTEGER PRIMARY KEY);
                 INSERT INTO {version} VALUES(1);
                 CREATE TABLE {table}(attempt TEXT PRIMARY KEY REFERENCES oauth_connect_attempts(attempt), binding TEXT NOT NULL);
                 INSERT INTO {table} VALUES('attempt', '{{}}');"
            );
            let db = Connection::open_in_memory()?;
            db.execute_batch(&legacy)?;
            super::super::connect::install_schema(&db)?;
            assert_eq!(
                db.query_row(&format!("SELECT version FROM {version}"), [], |row| row
                    .get::<_, i64>(0))?,
                2
            );
            super::super::connect::install_schema(&db)?;
            for binding in ["", "broken", "null", "[]", "1"] {
                assert!(
                    db.execute(&format!("UPDATE {table} SET binding = ?1"), [binding])
                        .is_err()
                );
            }
            assert!(
                db.execute(
                    &format!("INSERT INTO {table} VALUES('missing-parent', '{{}}')"),
                    []
                )
                .is_err()
            );
            for corrupt in [
                legacy.replace("'{}'", "'null'"),
                legacy.replace("binding TEXT NOT NULL", "binding BLOB NOT NULL"),
                legacy.replace("REFERENCES oauth_connect_attempts(attempt)", ""),
                legacy.replace(
                    &format!("CREATE TABLE {version}(version INTEGER PRIMARY KEY)"),
                    &format!("CREATE TABLE {version}(version INTEGER)"),
                ),
            ] {
                let restored = Connection::open_in_memory()?;
                restored.execute_batch(&corrupt)?;
                assert!(super::super::connect::install_schema(&restored).is_err());
                assert_eq!(
                    restored.query_row(&format!("SELECT version FROM {version}"), [], |row| row
                        .get::<_, i64>(0))?,
                    1
                );
            }
        }
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
