//! Shared field annotation and example validation. Current apps derive these
//! views from their required App.definition contract; decoding optional inventories
//! below is retained only for historical artifact formats.
use crate::{artifact::Operation, operation_catalog, output_schema, schema::Schema};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub type Catalog = BTreeMap<String, Documentation>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub path: String,
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Documentation {
    pub operation: String,
    pub input_type: String,
    pub output_type: String,
    pub summary: String,
    pub description: String,
    pub response_description: String,
    pub inputs: Vec<Field>,
    pub outputs: Vec<Field>,
    pub request_example: String,
    pub response_example: String,
    pub deprecated: bool,
}

pub fn decode(
    raw: &[u8],
    operations: &[Operation],
    schema: &Schema,
    outputs: &output_schema::Catalog,
) -> Result<Catalog> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        entries: Vec<Documentation>,
        error: String,
    }
    ensure!(raw.len() <= 262_144, "API documentation byte budget");
    let envelope: Envelope = serde_json::from_slice(raw).context("invalid ApiDocs.all metadata")?;
    ensure!(
        envelope.error.is_empty(),
        "ApiDocs examples failed: {}",
        envelope.error
    );
    let mut catalog = Catalog::new();
    for entry in envelope.entries {
        ensure!(
            catalog.insert(entry.operation.clone(), entry).is_none(),
            "duplicate API documentation operation"
        );
    }
    validate(&catalog, operations, schema, outputs)?;
    Ok(catalog)
}

pub fn validate(
    catalog: &Catalog,
    operations: &[Operation],
    schema: &Schema,
    outputs: &output_schema::Catalog,
) -> Result<()> {
    ensure!(
        catalog.len() <= 128 && serde_json::to_vec(catalog)?.len() <= 262_144,
        "API documentation budget"
    );
    for (name, docs) in catalog {
        let op = operations
            .iter()
            .find(|op| &op.name == name && matches!(op.kind.as_str(), "command" | "query"))
            .with_context(|| {
                format!("documentation requires a registered public operation: {name}")
            })?;
        ensure!(
            docs.operation == *name
                && docs.input_type == op.input_type
                && docs.output_type == op.output_type,
            "documentation handle differs from registered operation: {name}"
        );
        ensure!(
            !docs.summary.trim().is_empty() && docs.summary.len() <= 120,
            "documentation summary budget: {name}"
        );
        ensure!(
            docs.description.len() <= 4096 && docs.response_description.len() <= 4096,
            "documentation description budget: {name}"
        );
        let record = schema
            .inputs
            .get(&op.input_type)
            .context("documentation input contract missing")?;
        let output = outputs
            .get(&op.output_type)
            .context("documentation output contract missing")?;
        let mut input_schema = operation_catalog::record_schema(record);
        let mut output_schema = operation_catalog::output_schema(&output.shape);
        annotate(&mut input_schema, &docs.inputs)
            .with_context(|| format!("input documentation for {name}"))?;
        annotate(&mut output_schema, &docs.outputs)
            .with_context(|| format!("output documentation for {name}"))?;
        if !docs.request_example.is_empty() {
            ensure!(
                docs.request_example.len() <= 65_536,
                "request example byte budget"
            );
            let example: Value = serde_json::from_str(&docs.request_example)
                .context("invalid request example JSON")?;
            record
                .validate_input(&example)
                .with_context(|| format!("request example does not match {name}"))?;
        }
        if !docs.response_example.is_empty() {
            let example: Value = serde_json::from_str(&docs.response_example)
                .context("invalid response example JSON")?;
            output
                .shape
                .validate_value(&example)
                .with_context(|| format!("response example does not match {name}"))?;
        }
    }
    Ok(())
}

pub fn annotate(schema: &mut Value, fields: &[Field]) -> Result<()> {
    ensure!(fields.len() <= 128, "documentation field count budget");
    let mut names = BTreeSet::new();
    for field in fields {
        ensure!(
            names.insert(&field.path),
            "duplicate documentation field: {}",
            field.path
        );
        ensure!(
            !field.path.is_empty()
                && field.path.len() <= 256
                && !field.description.trim().is_empty()
                && field.description.len() <= 4096,
            "documentation field budget"
        );
        let mut target = &mut *schema;
        for part in field.path.split('.') {
            let (name, array) = part
                .strip_suffix("[]")
                .map_or((part, false), |name| (name, true));
            crate::schema::identifier(name)?;
            target = target
                .get_mut("properties")
                .and_then(|properties| properties.get_mut(name))
                .with_context(|| format!("unknown documentation field: {}", field.path))?;
            if array {
                // A nominal collection documents its values, so `[]` resolves through
                // the wrapper's payload rather than a top-level items schema.
                let collection = target
                    .get("x-day2-collection")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                target = match collection.as_deref() {
                    Some("map") => target
                        .pointer_mut("/properties/entries/items/properties/value")
                        .with_context(|| format!("map value schema missing: {}", field.path))?,
                    Some("set") => target
                        .pointer_mut("/properties/members/items")
                        .with_context(|| format!("set member schema missing: {}", field.path))?,
                    _ => target.get_mut("items").with_context(|| {
                        format!("documentation field is not a collection: {}", field.path)
                    })?,
                };
            }
        }
        // Preserve derived wire constraints separately when an app supplies meaning.
        if let Some(derived) = target.get("description").cloned() {
            target["x-day2-wire-description"] = derived;
        }
        target["description"] = Value::String(field.description.clone());
    }
    Ok(())
}

/// Illustrative data, never a claim about records that exist in an installation.
pub fn example(schema: &Value) -> Value {
    if let Some(value) = schema.get("const") {
        return value.clone();
    }
    if let Some(value) = schema["examples"]
        .as_array()
        .and_then(|values| values.first())
    {
        return value.clone();
    }
    if let Some(value) = schema["enum"].as_array().and_then(|values| values.first()) {
        return value.clone();
    }
    if let Some(value) = schema["oneOf"].as_array().and_then(|values| values.first()) {
        return example(value);
    }
    match schema["type"].as_str() {
        Some("object") => Value::Object(
            schema["properties"]
                .as_object()
                .map(|fields| {
                    fields
                        .iter()
                        .map(|(name, schema)| (name.clone(), example(schema)))
                        .collect()
                })
                .unwrap_or_default(),
        ),
        Some("array") => serde_json::json!([example(&schema["items"])]),
        Some("integer" | "number") => serde_json::json!(1),
        Some("boolean") => serde_json::json!(false),
        Some("string") => serde_json::json!("string"),
        _ => Value::Null,
    }
}
