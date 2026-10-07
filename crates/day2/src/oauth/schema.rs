//! Current-only, bounded admission for private identity tables. Entirely absent
//! schema units are created atomically; existing units must already be complete
//! and current. Invalid restored state is refused without repair.

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
    // it off for admission, and refuse a transaction that started without it.
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

pub(crate) fn install_current(
    db: &Connection,
    version_table: &'static str,
    current: i64,
    ddl: &str,
    invariants: &[Invariant<'_>],
) -> Result<()> {
    admit(db, |db| {
        install_current_in(db, version_table, current, ddl, invariants)
    })
}

fn install_current_in(
    db: &Connection,
    version_table: &'static str,
    current: i64,
    ddl: &str,
    invariants: &[Invariant<'_>],
) -> Result<()> {
    schema_identifier(version_table)?;
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(ddl)?;
    let mut guards = Vec::new();
    let mut checks = Vec::new();
    for invariant in invariants {
        let Invariant { table, predicate } = invariant;
        schema_identifier(table)?;
        let mut columns = expected.prepare(&format!("PRAGMA table_info({table})"))?;
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
        ensure!(!types.is_empty(), "missing current identity table");
        let mut storage_shape = Vec::new();
        for (column, kind, required, primary_key) in types {
            schema_identifier(&column)?;
            let storage = match kind.as_str() {
                "TEXT" => "text",
                "INTEGER" => "integer",
                "BLOB" => "blob",
                _ => anyhow::bail!("unsupported OAuth column type"),
            };
            let check = format!("typeof({column}) = '{storage}'");
            storage_shape.push(if required || primary_key > 0 {
                check
            } else {
                format!("({column} IS NULL OR {check})")
            });
        }
        let predicate = format!("({predicate}) AND {}", storage_shape.join(" AND "));
        for operation in ["INSERT", "UPDATE"] {
            let name = format!("{table}_shape_{operation}_v{current}");
            let sql = format!(
                "CREATE TRIGGER {name}
                 AFTER {operation} ON {table}
                 WHEN EXISTS(SELECT 1 FROM {table} WHERE rowid = NEW.rowid AND NOT COALESCE(({predicate}), 0))
                 BEGIN SELECT RAISE(ABORT, 'invalid durable OAuth state'); END"
            );
            expected.execute_batch(&sql)?;
            guards.push((name, sql));
        }
        checks.push((*table, predicate));
    }
    // Derive the unit from its actual authored installer, never from a second
    // schema catalog. All input metadata is debited before name classification.
    let mut objects = Vec::new();
    let mut statement = expected.prepare("SELECT type,name,tbl_name FROM sqlite_master")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        materialize(row)?;
        objects.push((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ));
    }
    drop(rows);
    drop(statement);
    let mut fresh = true;
    let mut statement = db.prepare("SELECT type,name,tbl_name FROM sqlite_master")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        materialize(row)?;
        let kind = row.get_ref(0)?.as_str()?;
        let name = row.get_ref(1)?.as_str()?;
        let table = row.get_ref(2)?.as_str()?;
        let owned = objects.iter().any(|(expected_kind, expected_name, _)| {
            name.eq_ignore_ascii_case(expected_name)
                || (expected_kind == "table"
                    && (table.eq_ignore_ascii_case(expected_name)
                        || name
                            .get(..expected_name.len() + "_shape_".len())
                            .is_some_and(|prefix| {
                                prefix.eq_ignore_ascii_case(&format!("{expected_name}_shape_"))
                            })))
        });
        if !owned {
            continue;
        }
        fresh = false;
        ensure!(
            objects
                .iter()
                .any(|object| object.0 == kind && object.1 == name && object.2 == table),
            "unsupported current identity schema object {name}"
        );
    }
    drop(rows);
    drop(statement);
    if fresh {
        db.execute_batch(ddl)?;
        for (_, sql) in &guards {
            db.execute_batch(sql)?;
        }
        db.execute(&format!("INSERT INTO {version_table} VALUES (?1)"), [current])?;
    }
    // This branch is validation only for every existing unit, including an
    // empty/old version table or missing guards. Never repair or restamp it.
    exact_layout(db, &expected, version_table)?;
    let mut statement = db.prepare(&format!("SELECT version FROM {version_table}"))?;
    let mut versions = Vec::new();
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        materialize(row)?;
        versions.push(row.get::<_, i64>(0)?);
        ensure!(
            versions.len() <= 1,
            "unsupported OAuth schema version in {version_table}"
        );
    }
    drop(rows);
    drop(statement);
    ensure!(
        versions == [current],
        "unsupported OAuth schema version in {version_table}"
    );
    for (table, predicate) in checks {
        exact_layout(db, &expected, table)?;
        let invalid: bool = db.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE NOT COALESCE(({predicate}), 0))"),
            [],
            |row| row.get(0),
        )?;
        ensure!(!invalid, "invalid durable OAuth state in {table}");
    }
    for (name, sql) in guards {
        ensure!(
            schema_sql(db, "trigger", &name)?.as_deref() == Some(sql.as_str()),
            "missing or unsupported OAuth invariant guard {name}"
        );
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

/// Each current schema unit has one exact authored layout. Compare SQL as well as
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
    fn budget_exhaustion_rolls_back_fresh_creation_without_publishing_a_marker() -> Result<()> {
        let db = Connection::open_in_memory()?;
        let error = admit_with_limits(&db, 12_000, 16_384, 8 * 1_048_576, |db| {
            super::super::store::install_schema(db)?;
            db.query_row(SCAN, [], |row| row.get::<_, i64>(0))?;
            db.query_row(SCAN, [], |row| row.get::<_, i64>(0))?;
            Ok(())
        }).unwrap_err();
        assert!(format!("{error:#}").contains("VM-step budget exhausted"));
        assert_eq!(db.query_row("SELECT count(*) FROM sqlite_master WHERE name GLOB 'oauth_*'", [], |row| row.get::<_, i64>(0))?, 0);
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
    fn current_version_with_missing_guard_is_refused_without_repair() -> Result<()> {
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

    type SchemaObject = (String, String, String, Option<String>);
    type TableRows = (String, Vec<Vec<rusqlite::types::Value>>);

    #[derive(Debug, PartialEq)]
    struct Snapshot {
        objects: Vec<SchemaObject>,
        tables: Vec<TableRows>,
    }

    fn snapshot(db: &Connection) -> Result<Snapshot> {
        let objects = db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?
            .collect::<rusqlite::Result<Vec<SchemaObject>>>()?;
        let mut tables = Vec::new();
        for (kind, name, _, _) in &objects {
            if kind != "table" { continue; }
            let quoted = name.replace('"', "\"\"");
            let mut statement = db.prepare(&format!("SELECT * FROM \"{quoted}\" ORDER BY rowid"))?;
            let count = statement.column_count();
            let values = statement.query_map([], |row| (0..count).map(|index| row.get(index)).collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>())?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            tables.push((name.clone(), values));
        }
        Ok(Snapshot { objects, tables })
    }

    fn current_connect() -> Result<Connection> {
        let db = Connection::open_in_memory()?;
        super::super::connect::install_schema(&db)?;
        db.execute_batch("INSERT INTO oauth_connection_slots VALUES('slot',1,1,1,'profile','account','affinity','active');
            INSERT INTO oauth_refresh_attempts VALUES('attempt','slot',1,1,1,'profile','account','affinity','ready',NULL,NULL);
            INSERT INTO oauth_connect_attempts VALUES('connect','slot',NULL,1,1,'human','profile','registration','callback','consent',100,'awaiting_provider_authorization',NULL,NULL,NULL)")?;
        Ok(db)
    }

    fn corrupt_current_snapshot(db: &Connection, sql: &str) -> Result<()> {
        let guards = db.prepare("SELECT name,sql FROM sqlite_master WHERE type='trigger'")?
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        db.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON")?;
        for (name, _) in &guards {
            db.execute_batch(&format!("DROP TRIGGER {name}"))?;
        }
        db.execute_batch(sql)?;
        for (_, guard) in guards {
            db.execute_batch(&guard)?;
        }
        db.execute_batch("PRAGMA ignore_check_constraints=OFF; PRAGMA foreign_keys=ON")?;
        Ok(())
    }

    #[test]
    fn current_rows_reopen_without_identity_or_schema_mutation() -> Result<()> {
        let db = current_connect()?;
        let before = snapshot(&db)?;
        super::super::connect::install_schema(&db)?;
        assert_eq!(snapshot(&db)?, before);
        assert_eq!(db.query_row("SELECT version FROM oauth_schema_version", [], |row| row.get::<_, i64>(0))?, 2);
        assert_eq!(db.query_row("SELECT version FROM oauth_connect_schema_version", [], |row| row.get::<_, i64>(0))?, 2);
        super::super::connect::install_schema(&db)?;
        for sql in [
            "UPDATE oauth_refresh_attempts SET receipt='half' WHERE state='ready'",
            "UPDATE oauth_refresh_attempts SET next_version=2 WHERE state='ready'",
            "UPDATE oauth_connection_slots SET generation=1.5",
            "UPDATE oauth_connect_attempts SET account='half' WHERE state='awaiting_provider_authorization'",
            "UPDATE oauth_connect_attempts SET scope_evidence='half' WHERE state='awaiting_provider_authorization'",
            "UPDATE oauth_connect_attempts SET proposed_generation=9",
        ] {
            assert!(db.execute_batch(sql).is_err(), "{sql}");
        }
        assert!(db.is_autocommit());
        Ok(())
    }

    #[test]
    fn malformed_current_state_is_refused_without_repair() -> Result<()> {
        for corrupt in [
            "UPDATE oauth_refresh_attempts SET receipt='half'",
            "UPDATE oauth_connect_attempts SET account='half'",
            "DELETE FROM oauth_connection_slots",
        ] {
            let db = current_connect()?;
            corrupt_current_snapshot(&db, corrupt)?;
            let before = snapshot(&db)?;
            let error = super::super::connect::install_schema(&db).unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains("invalid durable OAuth state") || message.contains("orphaned durable credential state"), "{corrupt}: {message}");
            assert_eq!(snapshot(&db)?, before);
            assert_eq!(db.query_row("SELECT version FROM oauth_schema_version", [], |row| row.get::<_, i64>(0))?, 2);
            assert_eq!(db.query_row("SELECT version FROM oauth_connect_schema_version", [], |row| row.get::<_, i64>(0))?, 2);
            assert!(db.is_autocommit());
        }
        Ok(())
    }

    #[test]
    fn ciphertext_shape_and_receipt_versions_are_enforced_on_new_writes() -> Result<()> {
        let db = current_connect()?;
        assert!(db.execute_batch("UPDATE oauth_refresh_attempts SET state='replacement_committed',next_version=99,receipt='receipt'").is_err());
        db.execute_batch("UPDATE oauth_refresh_attempts SET state='replacement_committed',next_version=2,receipt='receipt'")?;
        assert!(db.execute_batch("INSERT INTO oauth_private_tokens VALUES('ref','slot',1,'account','identity','key',zeroblob(11),zeroblob(16))").is_err());
        assert!(db.execute_batch("INSERT INTO oauth_private_tokens VALUES('ref','slot',1,'account','identity','key',zeroblob(12),zeroblob(15))").is_err());
        db.execute_batch("INSERT INTO oauth_private_tokens VALUES('ref','slot',1,'account','identity','key',zeroblob(12),zeroblob(16))")?;
        assert!(db.execute_batch("UPDATE oauth_private_tokens SET nonce='not_a_blob!'").is_err());
        Ok(())
    }

    #[test]
    fn existing_units_require_one_current_marker_and_complete_objects() -> Result<()> {
        for (corrupt, refusal, owner) in [
            ("UPDATE oauth_schema_version SET version=1", "schema version", "oauth_schema_version"),
            ("UPDATE oauth_schema_version SET version=99", "schema version", "oauth_schema_version"),
            ("DELETE FROM oauth_schema_version", "schema version", "oauth_schema_version"),
            ("INSERT INTO oauth_schema_version VALUES(1)", "schema version", "oauth_schema_version"),
            ("DROP TABLE oauth_refresh_attempts", "table shape", "oauth_refresh_attempts"),
            ("DROP TRIGGER oauth_refresh_attempts_shape_INSERT_v2", "invariant guard", "oauth_refresh_attempts"),
            ("DROP TRIGGER oauth_refresh_attempts_shape_INSERT_v2; CREATE TRIGGER oauth_refresh_attempts_shape_INSERT_v2 AFTER INSERT ON oauth_refresh_attempts BEGIN SELECT 1; END", "invariant guard", "oauth_refresh_attempts"),
            ("CREATE TRIGGER unexpected AFTER INSERT ON oauth_refresh_attempts BEGIN SELECT 1; END", "schema object", "unexpected"),
            ("CREATE TABLE unrelated(value INTEGER); CREATE TRIGGER oauth_refresh_attempts_shape_INSERT_v1 AFTER INSERT ON unrelated BEGIN SELECT 1; END", "schema object", "oauth_refresh_attempts_shape_INSERT_v1"),
            ("DROP TABLE oauth_callback_bindings", "table shape", "oauth_callback_bindings"),
            ("DELETE FROM oauth_callback_schema_version", "schema version", "oauth_callback_schema_version"),
            ("UPDATE oauth_callback_schema_version SET version=1", "schema version", "oauth_callback_schema_version"),
        ] {
            let db = current_connect()?;
            db.execute_batch(corrupt)?;
            let before = snapshot(&db)?;
            let error = super::super::connect::install_schema(&db).unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains(refusal) && message.contains(owner), "{corrupt}: {message}");
            assert_eq!(snapshot(&db)?, before, "repaired {corrupt}");
        }
        // A lone owner object is partial, not an empty unit to complete.
        for ddl in [
            "CREATE TABLE oauth_schema_version(version INTEGER PRIMARY KEY)",
            "CREATE TABLE oauth_callback_schema_version(version INTEGER PRIMARY KEY)",
            "CREATE TABLE oauth_connect_attempts(attempt TEXT PRIMARY KEY)",
            "CREATE VIEW OAUTH_SCHEMA_VERSION AS SELECT 2 AS version",
        ] {
            let db = Connection::open_in_memory()?;
            db.execute_batch(ddl)?;
            let before = snapshot(&db)?;
            assert!(super::super::connect::install_schema(&db).is_err(), "accepted {ddl}");
            assert_eq!(snapshot(&db)?, before, "completed {ddl}");
        }
        Ok(())
    }

    #[test]
    fn every_current_unit_refuses_old_empty_and_multiple_markers() -> Result<()> {
        let source = current_connect()?;
        super::super::inbound::install_schema(&source)?;
        let versions = source.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%schema_version' ORDER BY name")?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(versions.len(), 6);
        for table in versions {
            for operation in ["old", "empty", "multiple"] {
                let db = current_connect()?;
                super::super::inbound::install_schema(&db)?;
                let current: i64 = db.query_row(&format!("SELECT version FROM {table}"), [], |row| row.get(0))?;
                match operation {
                    "old" => { db.execute(&format!("UPDATE {table} SET version=?1"), [current - 1])?; },
                    "empty" => { db.execute(&format!("DELETE FROM {table}"), [])?; },
                    "multiple" => { db.execute(&format!("INSERT INTO {table} VALUES(?1)"), [current + 1])?; },
                    _ => unreachable!(),
                }
                let before = snapshot(&db)?;
                let error = admit(&db, |db| {
                    super::super::connect::install_schema(db)?;
                    super::super::inbound::install_schema(db)
                }).unwrap_err();
                let message = format!("{error:#}");
                assert!(message.contains("schema version") && message.contains(table.as_str()), "{table} {operation}: {message}");
                assert_eq!(snapshot(&db)?, before);
            }
        }
        Ok(())
    }

    #[test]
    fn current_layout_substitutions_reach_shape_refusal() -> Result<()> {
        for (table, old, new, refusal) in [
            ("oauth_connection_slots", "profile TEXT NOT NULL", "profile BLOB NOT NULL", "table shape"),
            ("oauth_refresh_attempts", "UNIQUE(slot, generation, base_version)", "CHECK(generation > 0)", "table constraints"),
            ("oauth_refresh_attempts", "REFERENCES oauth_connection_slots(slot)", "", "table shape"),
            ("oauth_schema_version", "version INTEGER PRIMARY KEY", "version INTEGER", "table shape"),
            ("oauth_schema_version", "version INTEGER PRIMARY KEY", "version INTEGER PRIMARY KEY, hidden INTEGER GENERATED ALWAYS AS (version + 1)", "table shape"),
            ("oauth_refresh_attempts", "next_version INTEGER,", "next_version INTEGER, hidden INTEGER GENERATED ALWAYS AS (generation + 1),", "table shape"),
            ("oauth_callback_bindings", "binding TEXT NOT NULL", "binding BLOB NOT NULL", "table shape"),
            ("oauth_exchange_bindings", "REFERENCES oauth_connect_attempts(attempt)", "", "table shape"),
        ] {
            let db = current_connect()?;
            let definition = admit(&db, |db| schema_sql(db, "table", table))?.context("current fixture table")?;
            assert!(definition.contains(old), "missing mutation operand: {old}");
            db.execute_batch("PRAGMA foreign_keys=OFF")?;
            db.execute_batch(&format!("DROP TABLE {table}; {}", definition.replace(old, new)))?;
            if table == "oauth_schema_version" {
                db.execute("INSERT INTO oauth_schema_version(version) VALUES(2)", [])?;
            }
            let before = snapshot(&db)?;
            let error = super::super::connect::install_schema(&db).unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains(refusal) && message.contains(table), "{table}: {message}");
            assert_eq!(snapshot(&db)?, before);
        }
        Ok(())
    }

    #[test]
    fn current_binding_tables_validate_shape_and_guard_json_objects() -> Result<()> {
        for table in ["oauth_callback_bindings", "oauth_exchange_bindings"] {
            let db = current_connect()?;
            db.execute(&format!("INSERT INTO {table} VALUES('connect','{{}}')"), [])?;
            super::super::connect::install_schema(&db)?;
            for binding in ["", "broken", "null", "[]", "1"] {
                assert!(db.execute(&format!("UPDATE {table} SET binding=?1"), [binding]).is_err());
            }
            assert!(db.execute(&format!("INSERT INTO {table} VALUES('missing-parent','{{}}')"), []).is_err());
            corrupt_current_snapshot(&db, &format!("UPDATE {table} SET binding='null'"))?;
            let before = snapshot(&db)?;
            let error = super::super::connect::install_schema(&db).unwrap_err();
            assert!(format!("{error:#}").contains("invalid durable OAuth state"), "{table}: {error:#}");
            assert_eq!(snapshot(&db)?, before);
        }
        Ok(())
    }

    #[test]
    fn current_guards_survive_reopen_and_preserve_atomic_rollback() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("current.sqlite");
        let db = Connection::open(&path)?;
        super::super::connect::install_schema(&db)?;
        db.execute_batch("INSERT INTO oauth_connection_slots VALUES('slot',1,1,1,'profile','account','affinity','active');
            INSERT INTO oauth_refresh_attempts VALUES('attempt','slot',1,1,1,'profile','account','affinity','ready',NULL,NULL)")?;
        drop(db);
        let mut db = Connection::open(&path)?;
        super::super::connect::install_schema(&db)?;
        {
            let tx = db.transaction()?;
            tx.execute("UPDATE oauth_connection_slots SET account='replacement'", [])?;
            assert!(tx.execute("UPDATE oauth_refresh_attempts SET receipt='half'", []).is_err());
        }
        assert_eq!(db.query_row("SELECT account FROM oauth_connection_slots", [], |row| row.get::<_, String>(0))?, "account");
        assert!(db.execute_batch("INSERT INTO oauth_refresh_attempts VALUES('new','slot',1,2,1,'profile','account','affinity','ready',NULL,'half')").is_err());
        Ok(())
    }
}
