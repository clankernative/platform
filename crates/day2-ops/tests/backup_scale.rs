use anyhow::{Context, Result};
use day2::{development, identity, store::Runtime};
use day2_ops::backup;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::path::PathBuf;

fn rows(runtime: &Runtime) -> Result<Vec<Value>> {
    let connection = Connection::open(runtime.db())?;
    let mut statement = connection.prepare(
        "SELECT hex(id),version,created_at,title,text,owner,ready,hex(bytes),hex(lines) FROM reports ORDER BY id",
    )?;
    Ok(statement
        .query_map([], |row| {
            Ok(json!([
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, bool>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
            ]))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

#[test]
fn complete_backup_and_restore_do_not_inherit_the_property_snapshot_row_budget() -> Result<()> {
    let artifact = std::env::var_os("DAY2_TEST_REPORTS_ARTIFACT")
        .map(PathBuf::from)
        .context("run xtask verify or set DAY2_TEST_REPORTS_ARTIFACT")?;
    let scratch = tempfile::tempdir()?;
    let runtime = development::create(&artifact, &scratch.path().join("original"), None)?;
    let identity = runtime.artifact().contract().schema.models["reports"]
        .identity
        .as_ref()
        .context("Reports identity")?;
    let count = day2::properties::MAX_ROWS_PER_MODEL as u64 + 64;
    let mut connection = Connection::open(runtime.db())?;
    let transaction = connection.transaction()?;
    for ordinal in 1..=count {
        let id = identity::generate(&[23; 32], 200_000, &identity.key, ordinal)?;
        transaction.execute(
            "INSERT INTO reports(id,version,created_at,title,text,owner,ready,announced,bytes,lines) VALUES(?1,1,200000,?2,?3,'developer',1,0,?4,?5)",
            params![
                id.as_slice(),
                format!("Report {ordinal}"),
                format!("Content {ordinal}"),
                (8 + ordinal.to_string().len() as u64).to_be_bytes().as_slice(),
                1_u64.to_be_bytes().as_slice(),
            ],
        )?;
    }
    transaction.commit()?;
    assert!(
        runtime
            .inspect()
            .unwrap_err()
            .to_string()
            .contains("inspection_limit")
    );
    runtime.validate_storage()?;
    let expected = rows(&runtime)?;
    assert_eq!(expected.len(), count as usize);
    let snapshot = scratch.path().join("backup");
    backup::take(runtime.instance_path(), "app", &snapshot)?;
    let restored_path = backup::restore(&snapshot, &scratch.path().join("restored"))?;
    let restored = Runtime::load(&restored_path, "app")?;
    restored.validate_storage()?;
    assert_eq!(rows(&restored)?, expected);
    assert!(
        restored
            .inspect()
            .unwrap_err()
            .to_string()
            .contains("inspection_limit")
    );

    // Corruption beyond the property budget must still prevent a new backup.
    let last_id: Vec<u8> = connection.query_row(
        "SELECT id FROM reports ORDER BY id DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    connection.execute(
        "UPDATE reports SET title=?1 WHERE id=?2",
        params!["x".repeat(16_385), last_id],
    )?;
    assert!(runtime.validate_storage().is_err());
    let invalid = scratch.path().join("invalid-backup");
    assert!(backup::take(runtime.instance_path(), "app", &invalid).is_err());
    assert!(!invalid.join("backup.json").exists());
    Ok(())
}
