//! Fresh private output only. This type never accepts a source connection or path.
use super::MAX_BYTES;
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, types::Value};
use std::{
    collections::BTreeMap,
    io::{Read as _, Seek as _},
    os::unix::fs::PermissionsExt as _,
};
use tempfile::{NamedTempFile, TempDir};
use zeroize::Zeroizing;

type Shape = Vec<(String, String, bool, i64, i64)>;

#[derive(Clone)]
pub(super) struct Template {
    columns: Vec<String>,
    pub shape: Shape,
}

pub(super) struct TableRows {
    pub table: String,
    pub rows: Vec<Vec<Value>>,
}

pub(super) fn shape(db: &Connection, table: &str) -> Result<Shape> {
    Ok(db.prepare(r#"SELECT name,type,"notnull",pk,hidden FROM pragma_table_xinfo(?1,'main') ORDER BY cid"#)?.query_map([table],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))?.collect::<rusqlite::Result<_>>()?)
}

pub(super) struct Image {
    connection: Connection,
    file: NamedTempFile,
    _directory: TempDir,
    templates: BTreeMap<String, Template>,
}

impl Image {
    pub fn new(schema: &crate::schema::Schema) -> Result<Self> {
        // Private mode-0700 directory and exclusively created mode-0600 file.
        // Only this fresh target is opened; neither path nor connection is input.
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let file = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o600))
            .tempfile_in(directory.path())?;
        let connection = Connection::open(file.path())?;
        connection.execute_batch("PRAGMA page_size=4096; PRAGMA max_page_count=4096; PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY;")?;
        for ddl in schema.ddl_with_tables(&BTreeMap::new(), false)? {
            connection.execute_batch(&ddl)?;
        }
        let templates = schema
            .models
            .iter()
            .map(|(table, model)| {
                let columns = ["id", "version", "created_at", "deleted_at"]
                    .into_iter()
                    .chain(model.fields.keys().map(String::as_str))
                    .map(|name| format!("\"{name}\""))
                    .collect();
                Ok((
                    table.clone(),
                    Template {
                        columns,
                        shape: shape(&connection, table)?,
                    },
                ))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            connection,
            file,
            _directory: directory,
            templates,
        })
    }

    pub fn templates(&self) -> &BTreeMap<String, Template> {
        &self.templates
    }

    pub fn finish(mut self, tables: Vec<TableRows>) -> Result<Zeroizing<Vec<u8>>> {
        let transaction = self.connection.transaction()?;
        let mut count = 0usize;
        let mut total = 0usize;
        for table in tables {
            let template = self
                .templates
                .get(&table.table)
                .context("unknown_export_model")?;
            let columns = template.columns.join(",");
            let placeholders = (1..=template.columns.len())
                .map(|i| format!("?{i}"))
                .collect::<Vec<_>>()
                .join(",");
            let mut insert = transaction.prepare(&format!(
                "INSERT INTO \"{}\" ({columns}) VALUES({placeholders})",
                table.table
            ))?;
            for row in table.rows {
                count += 1;
                ensure!(count <= 100_000, "sqlite_export_row_budget");
                ensure!(
                    row.len() == template.columns.len(),
                    "sqlite_export_row_shape"
                );
                for value in &row {
                    let size = match value {
                        Value::Text(s) => s.len(),
                        Value::Blob(s) => s.len(),
                        _ => 8,
                    };
                    total = total
                        .checked_add(size)
                        .context("sqlite_export_byte_budget")?;
                    ensure!(total <= MAX_BYTES, "sqlite_export_byte_budget");
                }
                insert.execute(rusqlite::params_from_iter(row))?;
            }
        }
        transaction.commit()?;
        ensure!(
            self.connection
                .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))?
                == "ok",
            "sqlite_export_integrity"
        );
        ensure!(
            self.connection
                .prepare("PRAGMA foreign_key_check")?
                .query([])?
                .next()?
                .is_none(),
            "sqlite_export_foreign_keys"
        );
        let Self {
            connection,
            mut file,
            _directory,
            templates: _,
        } = self;
        connection.close().map_err(|(_, error)| error)?;
        let output: &mut std::fs::File = file.as_file_mut();
        ensure!(
            output.metadata()?.len() <= MAX_BYTES as u64,
            "sqlite_export_byte_budget"
        );
        output.rewind()?;
        let mut bytes = Zeroizing::new(Vec::new());
        output
            .take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MAX_BYTES && bytes.starts_with(b"SQLite format 3\0"),
            "sqlite_export_image"
        );
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema(models: serde_json::Value) -> crate::schema::Schema {
        serde_json::from_value(serde_json::json!({"models":models,"inputs":{},"foreign_keys":[]}))
            .unwrap()
    }

    #[test]
    fn fresh_image_is_private_and_empty_tables_have_a_valid_sqlite_header() {
        let image = Image::new(&schema(
            serde_json::json!({"items":{"fields":{"marker":"boolean"}}}),
        ))
        .unwrap();
        assert_eq!(
            image
                .file
                .as_file()
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            image
                ._directory
                .path()
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(
            image
                .finish(vec![])
                .unwrap()
                .starts_with(b"SQLite format 3\0")
        );
    }

    #[test]
    fn fresh_image_rejects_forged_models_shapes_and_row_and_byte_overflow() {
        let schema = schema(serde_json::json!({"items":{"fields":{"marker":"boolean"}}}));
        assert!(
            Image::new(&schema)
                .unwrap()
                .finish(vec![TableRows {
                    table: "day2_meta".into(),
                    rows: vec![]
                }])
                .is_err()
        );
        assert!(
            Image::new(&schema)
                .unwrap()
                .finish(vec![TableRows {
                    table: "items".into(),
                    rows: vec![vec![Value::Integer(1)]]
                }])
                .is_err()
        );
        let row = vec![
            Value::Blob(vec![b'x'; MAX_BYTES + 1]),
            Value::Integer(1),
            Value::Integer(1),
            Value::Integer(0),
            Value::Integer(0),
        ];
        let error = Image::new(&schema)
            .unwrap()
            .finish(vec![TableRows {
                table: "items".into(),
                rows: vec![row],
            }])
            .err()
            .unwrap();
        assert!(error.to_string().contains("byte_budget"));
        let rows = (1..=100_001)
            .map(|id| {
                vec![
                    Value::Integer(id),
                    Value::Integer(1),
                    Value::Integer(1),
                    Value::Integer(0),
                    Value::Integer(0),
                ]
            })
            .collect();
        let error = Image::new(&schema)
            .unwrap()
            .finish(vec![TableRows {
                table: "items".into(),
                rows,
            }])
            .err()
            .unwrap();
        assert!(error.to_string().contains("row_budget"));
    }
}
