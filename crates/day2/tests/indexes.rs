use anyhow::Result;
use day2::schema::Schema;
use rusqlite::{Connection, Error, ffi};
use serde_json::json;

fn schema() -> Result<Schema> {
    Ok(serde_json::from_value(json!({
        "models": {"entries": {"roc_type":"Models.Entry", "fields": {
            "account":"text", "name":"text", "email":"text", "deleted":"boolean", "alias":"optional_text"
        }}},
        "inputs": {}, "foreign_keys": [],
        "indexes": [
            {"model":"entries", "name":"by_account_name", "fields":["account","name"], "unique":true},
            {"model":"entries", "name":"by_alias", "fields":["alias"], "unique":true},
            {"model":"entries", "name":"by_deleted", "fields":["deleted"], "unique":false},
            {"model":"entries", "name":"by_email", "fields":["email"], "unique":true}
        ]
    }))?)
}

fn unique(error: Error) {
    assert!(
        matches!(error, Error::SqliteFailure(code, _) if code.extended_code == ffi::SQLITE_CONSTRAINT_UNIQUE)
    );
}

#[test]
fn sqlite_enforces_single_compound_and_update_uniqueness_with_nulls_distinct() -> Result<()> {
    let schema = schema()?;
    let connection = Connection::open_in_memory()?;
    for ddl in schema.ddl()? {
        connection.execute_batch(&ddl)?;
    }
    connection.execute_batch(
        "INSERT INTO entries(id,version,created_at,account,name,email,deleted) VALUES
            (1,1,0,'a','home','one@example.test',0),
            (2,1,0,'b','home','two@example.test',0);",
    )?;
    // Different accounts can use the same name. NULL aliases are distinct,
    // while every non-null unique key is enforced without an app precheck.
    for sql in [
        "INSERT INTO entries(id,version,created_at,account,name,email,deleted) VALUES(3,1,0,'a','home','three@example.test',0)",
        "INSERT INTO entries(id,version,created_at,account,name,email,deleted) VALUES(3,1,0,'c','other','one@example.test',0)",
        "UPDATE entries SET account='a' WHERE id=2",
    ] {
        unique(connection.execute(sql, []).unwrap_err());
    }
    assert_eq!(
        connection.query_row("SELECT account FROM entries WHERE id=2", [], |row| row
            .get::<_, String>(
            0
        ))?,
        "b"
    );
    connection.execute("UPDATE entries SET alias='shared' WHERE id=1", [])?;
    unique(
        connection
            .execute("UPDATE entries SET alias='shared' WHERE id=2", [])
            .unwrap_err(),
    );
    connection.execute("UPDATE entries SET deleted=1 WHERE id=2", [])?;
    unique(connection.execute("INSERT INTO entries(id,version,created_at,account,name,email,deleted) VALUES(3,1,0,'b','home','three@example.test',0)", []).unwrap_err());
    let indexed_columns = connection.prepare("SELECT name FROM pragma_index_info('day2_decl_entries_by_account_name') ORDER BY seqno")?
        .query_map([], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(indexed_columns, ["account", "name"]);
    let non_unique_columns = connection
        .prepare(
            "SELECT name FROM pragma_index_info('day2_decl_entries_by_deleted') ORDER BY seqno",
        )?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(non_unique_columns, ["deleted", "id"]);
    Ok(())
}

#[test]
fn declared_indexes_reject_unknown_ambiguous_or_unbounded_keys() -> Result<()> {
    let original = schema()?;
    for mutation in [
        "model",
        "field",
        "empty",
        "duplicate_field",
        "unsorted",
        "duplicate_index",
        "wide",
        "reserved",
        "metadata",
    ] {
        let mut schema = original.clone();
        match mutation {
            "model" => schema.indexes[0].model = "missing".into(),
            "field" => schema.indexes[0].fields = vec!["missing".into()],
            "empty" => schema.indexes[0].fields.clear(),
            "duplicate_field" => schema.indexes[0].fields = vec!["name".into(), "name".into()],
            "unsorted" => schema.indexes[0].fields.reverse(),
            "duplicate_index" => schema.indexes.push(schema.indexes[0].clone()),
            "wide" => {
                schema.indexes[0].fields = (0..9).map(|number| format!("field_{number}")).collect()
            }
            "reserved" => schema.indexes[0].name = "sqlite_reserved".into(),
            "metadata" => schema.indexes[0].fields = vec!["id".into()],
            _ => unreachable!(),
        }
        assert!(schema.ddl().is_err(), "{mutation}");
    }
    Ok(())
}

#[test]
fn old_schemas_keep_their_serialized_shape_and_digest() -> Result<()> {
    let mut original = schema()?;
    original.indexes.clear();
    let encoded = serde_json::to_value(&original)?;
    assert!(encoded.get("indexes").is_none());
    let decoded: Schema = serde_json::from_value(encoded)?;
    assert!(decoded.indexes.is_empty());
    assert_eq!(decoded.hash()?, original.hash()?);
    Ok(())
}

#[test]
fn generated_sql_index_names_cannot_alias_across_models() -> Result<()> {
    let mut schema = schema()?;
    let mut other = schema.models["entries"].clone();
    other.roc_type = Some("Models.Other".into());
    schema.models.insert("entries_a".into(), other);
    let mut first = schema.indexes[0].clone();
    first.name = "a_b".into();
    let mut second = first.clone();
    second.model = "entries_a".into();
    second.name = "b".into();
    schema.indexes = vec![first, second];
    assert!(
        schema
            .ddl()
            .unwrap_err()
            .to_string()
            .contains("generated SQL index name collision")
    );
    Ok(())
}
