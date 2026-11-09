//! Owner-authorized business tables in a fresh SQLite database, never a page copy.
use crate::{
    authority_state::AuthorityStamp,
    error::Failure,
    owners::{self, Permission},
    store::Runtime,
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, params, types::Value};

mod image;
use serde::Serialize;
use zeroize::Zeroizing;

pub const PATH: &str = "/api/app-sqlite";
pub const MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Serialize)]
pub struct Metadata {
    pub protocol: u32,
    pub kind: &'static str,
    pub scope: String,
    pub actor: String,
    pub authority: AuthorityStamp,
    pub artifact: String,
    pub maximum_bytes: usize,
}

pub(crate) fn install(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE day2_sensitive_access_events(sequence INTEGER PRIMARY KEY,request_id TEXT NOT NULL,scope TEXT NOT NULL,actor TEXT NOT NULL,authority TEXT NOT NULL,action TEXT NOT NULL,state TEXT NOT NULL) STRICT;
        CREATE TRIGGER day2_sensitive_access_no_update BEFORE UPDATE ON day2_sensitive_access_events BEGIN SELECT RAISE(ABORT,'append_only_sensitive_audit'); END;
        CREATE TRIGGER day2_sensitive_access_no_delete BEFORE DELETE ON day2_sensitive_access_events BEGIN SELECT RAISE(ABORT,'append_only_sensitive_audit'); END;
        CREATE TRIGGER day2_sensitive_access_no_replace BEFORE INSERT ON day2_sensitive_access_events WHEN EXISTS(SELECT 1 FROM day2_sensitive_access_events WHERE sequence=NEW.sequence) BEGIN SELECT RAISE(ABORT,'append_only_sensitive_audit'); END;")?;
    Ok(())
}

fn guards(db: &Connection) -> Result<()> {
    for (suffix, operation) in [
        ("no_update", "BEFORE UPDATE ON day2_sensitive_access_events"),
        ("no_delete", "BEFORE DELETE ON day2_sensitive_access_events"),
        (
            "no_replace",
            "BEFORE INSERT ON day2_sensitive_access_events WHEN EXISTS(SELECT 1 FROM day2_sensitive_access_events WHERE sequence=NEW.sequence)",
        ),
    ] {
        let name = format!("day2_sensitive_access_{suffix}");
        crate::audit::validate_trigger(
            db,
            &name,
            &format!(
                "CREATE TRIGGER {name} {operation} BEGIN SELECT RAISE(ABORT,'append_only_sensitive_audit'); END"
            ),
        )?;
    }
    Ok(())
}

pub fn metadata(runtime: &Runtime, actor: &str) -> Result<Metadata> {
    runtime.sql_read(|db| {
        let authority = owners::authorize_in(db, runtime, actor, Permission::SqliteDownload)?;
        guards(db)?;
        Ok(Metadata {
            protocol: 1,
            kind: "app-sqlite",
            scope: runtime.scope().into(),
            actor: actor.into(),
            authority,
            artifact: runtime.artifact().id().into(),
            maximum_bytes: MAX_BYTES,
        })
    })
}

fn audit(
    db: &Connection,
    runtime: &Runtime,
    actor: &str,
    stamp: &AuthorityStamp,
    id: &str,
    state: &str,
) -> Result<()> {
    guards(db)?;
    db.execute("INSERT INTO day2_sensitive_access_events(request_id,scope,actor,authority,action,state) VALUES(?1,?2,?3,?4,'sqlite.download',?5)",params![id,runtime.scope(),actor,serde_json::to_string(stamp)?,state])?;
    Ok(())
}

pub fn download(
    runtime: &Runtime,
    actor: &str,
    expected: &AuthorityStamp,
    request_id: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    crate::app_secrets::validate_request(request_id)?;
    runtime.sql_write(|db| {
        ensure!(
            &owners::authorize_in(db, runtime, actor, Permission::SqliteDownload)? == expected,
            Failure::AuthorityPolicyChanged
        );
        guards(db)?;
        let used: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM day2_sensitive_access_events WHERE request_id=?1)",
            [request_id],
            |row| row.get(0),
        )?;
        ensure!(!used, Failure::IdempotencyKeyConflict);
        audit(db, runtime, actor, expected, request_id, "admitted")
    })?;
    let schema = &runtime.artifact().contract().schema;
    let image = image::Image::new(schema)?;
    let templates = image.templates().clone();
    let captured = runtime.sql_read(|source| {
        ensure!(
            &owners::authorize_in(source, runtime, actor, Permission::SqliteDownload)? == expected,
            Failure::AuthorityPolicyChanged
        );
        let mut captured = Vec::new();
        let mut count = 0usize;
        let mut total = 0usize;
        for (table, model) in &schema.models {
            let (kind, definition): (String, String) = source.query_row(
                "SELECT type,sql FROM main.sqlite_schema WHERE name=?1",
                [table],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let mut words = definition.split_whitespace();
            ensure!(
                kind == "table"
                    && words
                        .next()
                        .is_some_and(|w| w.eq_ignore_ascii_case("CREATE"))
                    && words
                        .next()
                        .is_some_and(|w| w.eq_ignore_ascii_case("TABLE")),
                "sqlite_export_requires_ordinary_model_table"
            );
            ensure!(
                image::shape(source, table)? == templates[table].shape,
                "sqlite_export_model_shape_changed"
            );
            let columns = ["id", "version", "created_at", "deleted_at"]
                .into_iter()
                .chain(model.fields.keys().map(String::as_str))
                .map(|name| format!("\"{name}\""))
                .collect::<Vec<_>>();
            let names = columns.join(",");
            let mut read =
                source.prepare(&format!("SELECT {names} FROM main.\"{table}\" ORDER BY id"))?;
            let mut captured_rows = Vec::new();
            let mut rows = read.query([])?;
            while let Some(row) = rows.next()? {
                count += 1;
                ensure!(count <= 100_000, "sqlite_export_row_budget");
                let mut values = Vec::with_capacity(columns.len());
                for column in 0..columns.len() {
                    // Bound a value before allocating its owned representation.
                    let raw = row.get_ref(column)?;
                    let length = match raw {
                        rusqlite::types::ValueRef::Text(s) | rusqlite::types::ValueRef::Blob(s) => {
                            s.len()
                        }
                        _ => 8,
                    };
                    total = total
                        .checked_add(length)
                        .context("sqlite_export_byte_budget")?;
                    ensure!(total <= MAX_BYTES, "sqlite_export_byte_budget");
                    values.push(Value::try_from(raw)?);
                }
                captured_rows.push(values);
            }
            captured.push(image::TableRows {
                table: table.clone(),
                rows: captured_rows,
            });
        }
        Ok(captured)
    })?;
    let bytes = image.finish(captured)?;
    // A fresh database has no copied sessions, provider material, history tables,
    // freelist pages or framework schema. Only admitted model columns entered it.
    runtime.sql_write(|db| {
        ensure!(
            &owners::authorize_in(db, runtime, actor, Permission::SqliteDownload)? == expected,
            Failure::AuthorityPolicyChanged
        );
        audit(db, runtime, actor, expected, request_id, "prepared")
    })?;
    Ok(bytes)
}
