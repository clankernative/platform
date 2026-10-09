//! Executable text rules shared by construction, admission, and projections.
use crate::{
    output_schema::Type,
    schema::{Kind, Record, Schema},
};
use anyhow::{Context, Result, ensure};
use day2_contracts::text::TextRule;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub type Catalog = BTreeMap<String, TextRule>;

pub fn record(domains: &Catalog, record: &Record, value: &Value) -> Result<()> {
    for (field, kind) in &record.fields {
        if let Kind::StandardText { domain } = kind {
            let text = value
                .get(field)
                .and_then(Value::as_str)
                .context(crate::error::Failure::InvalidDomainValue)?;
            ensure!(
                domains
                    .get(domain)
                    .context("unregistered text domain")?
                    .accepts(text),
                crate::error::Failure::InvalidDomainValue
            );
        }
    }
    Ok(())
}

/// Activation checks existing rows against the target rules, inside the same
/// transaction that guards the artifact transition. Stream complete columns;
/// verification's bounded snapshot is not a substitute for checking live data.
pub fn validate_storage(
    connection: &rusqlite::Connection,
    schema: &Schema,
    domains: &Catalog,
) -> Result<()> {
    for (model, record) in &schema.models {
        for (field, kind) in &record.fields {
            if let Kind::StandardText { domain } = kind {
                let rule = domains.get(domain).context("unregistered text domain")?;
                let mut query =
                    connection.prepare(&format!("SELECT \"{field}\" FROM \"{model}\""))?;
                let mut rows = query.query([])?;
                while let Some(row) = rows.next()? {
                    ensure!(
                        rule.accepts(&row.get::<_, String>(0)?),
                        "existing data violates target domain: {model}.{field}"
                    );
                }
            }
        }
    }
    Ok(())
}

pub fn output(domains: &Catalog, shape: &Type, value: &Value) -> Result<()> {
    match shape {
        Type::StandardText { domain } => ensure!(
            domains
                .get(domain)
                .context("unregistered output domain")?
                .accepts(
                    value
                        .as_str()
                        .context(crate::error::Failure::InvalidDomainValue)?
                ),
            crate::error::Failure::InvalidDomainValue
        ),
        Type::Record(fields) => {
            for (name, field) in fields {
                output(domains, field, &value[name])?;
            }
        }
        Type::IdPage(item) | Type::CollectionPage(item) => {
            for value in value["items"].as_array().context("invalid page")? {
                output(domains, item, value)?;
            }
        }
        Type::List(item) => {
            for value in value.as_array().context("invalid list")? {
                output(domains, item, value)?;
            }
        }
        _ => (),
    }
    Ok(())
}

pub fn annotate(domains: &Catalog, schema: &mut Value) -> Result<()> {
    if let Some(domain) = schema.get("x-day2-standard-domain").and_then(Value::as_str) {
        let rule = domains.get(domain).context("unregistered schema domain")?;
        schema["maxLength"] = json!(rule.maximum_bytes);
        schema["x-day2-max-utf8-bytes"] = json!(rule.maximum_bytes);
        schema["x-day2-nonblank"] = json!(rule.nonblank);
        schema["x-day2-domain-description"] = json!(rule.description);
        if rule.nonblank {
            schema["minLength"] = json!(1);
        }
    }
    if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
        for field in properties.values_mut() {
            annotate(domains, field)?;
        }
    }
    if let Some(items) = schema.get_mut("items") {
        annotate(domains, items)?;
    }
    Ok(())
}

pub fn module(schema: &Schema, admission: bool) -> Result<String> {
    let mut imports = BTreeSet::new();
    for tag in schema.domains.values() {
        imports.extend(crate::output_schema::annotation_imports(tag)?);
    }
    let mut source = String::from("import pf.Text\nimport SchemaSource\n");
    for module in imports {
        source.push_str(&format!("import {module}\n"));
    }
    source.push_str("Domains :: [].{\n");
    for (name, tag) in &schema.domains {
        source.push_str(&format!("    {name} : Str -> Try(Text({tag}), Str)\n    {name} = |value| Text.{}from_spec(SchemaSource.domains.{name}, value)\n", if admission { "admission_" } else { "" }));
    }
    for (name, tag) in &schema.domains {
        source.push_str(&format!(
            "    {} : Str -> Try(Text({tag}), Str)\n    {} = {name}\n",
            decoder(tag),
            decoder(tag)
        ));
    }
    source.push_str("}\n");
    Ok(source)
}

pub fn decoder(tag: &str) -> String {
    format!(
        "decode_{}",
        tag.bytes()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tightening_rules_checks_live_rows_beyond_verification_snapshot_bounds() -> Result<()> {
        let connection = rusqlite::Connection::open_in_memory()?;
        connection.execute_batch("CREATE TABLE reports (title TEXT NOT NULL)")?;
        for _ in 0..300 {
            connection.execute("INSERT INTO reports VALUES ('valid')", [])?;
        }
        connection.execute("INSERT INTO reports VALUES (?1)", ["é".repeat(101)])?;
        let schema = Schema {
            models: BTreeMap::from([(
                "reports".into(),
                Record {
                    roc_type: Some("Models.Report".into()),
                    identity: None,
                    fields: BTreeMap::from([(
                        "title".into(),
                        Kind::StandardText {
                            domain: "Title".into(),
                        },
                    )]),
                },
            )]),
            inputs: BTreeMap::new(),
            domains: BTreeMap::from([("title".into(), "Title".into())]),
            foreign_keys: vec![],
            rollups: Vec::new(),
            indexes: vec![],
        };
        let mut domains = Catalog::from([(
            "Title".into(),
            TextRule {
                maximum_bytes: 200,
                nonblank: true,
                description: "Report title".into(),
            },
        )]);
        assert!(validate_storage(&connection, &schema, &domains).is_err());
        domains.get_mut("Title").unwrap().maximum_bytes = 202;
        validate_storage(&connection, &schema, &domains)?;
        Ok(())
    }
}
