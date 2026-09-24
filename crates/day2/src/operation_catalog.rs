//! Single admitted operation catalog for HTTP dispatch, OpenAPI, docs and MCP.
//! Transports project this catalog; none independently infer app intent or schemas.
use crate::{
    artifact::{Artifact, Operation},
    operation_metadata,
    output_schema::Type,
    schema::{Kind, Record},
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub struct Endpoint {
    pub operation: Operation,
    pub input_schema: Value,
    pub output_schema: Value,
    pub summary: String,
    pub description: String,
    pub execution_description: &'static str,
    pub response_description: String,
    pub request_example: Value,
    pub response_example: Value,
    pub response_example_source: &'static str,
    pub deprecated: bool,
    pub metadata: Option<operation_metadata::Entry>,
}

impl Endpoint {
    pub fn method(&self) -> &'static str {
        if self.operation.kind == "query" {
            "GET"
        } else {
            "POST"
        }
    }

    pub fn path(&self) -> String {
        format!("{}{}", crate::openapi::API_PREFIX, self.operation.name)
    }
}

pub struct Catalog {
    pub endpoints: BTreeMap<String, Endpoint>,
}

impl Catalog {
    pub fn from_artifact(artifact: &Artifact) -> Result<Self> {
        ensure!(
            artifact.format >= 10,
            "API requires current typed operation contracts"
        );
        crate::output_schema::validate_api(&artifact.outputs)?;
        let (docs_catalog, metadata_catalog) = if let Some(definition) = &artifact.app_contract {
            definition.validate(artifact)?;
            (definition.documentation(), definition.intents())
        } else {
            ensure!(
                artifact.format < 12,
                "complete application contract required"
            );
            (
                artifact.api_docs.clone(),
                artifact.operation_metadata.clone(),
            )
        };
        crate::api_docs::validate(
            &artifact.api_docs,
            &artifact.operations,
            &artifact.schema,
            &artifact.outputs,
        )?;
        operation_metadata::validate(
            &artifact.operation_metadata,
            &artifact.operations,
            &artifact.schema,
            &artifact.outputs,
        )?;
        let mut endpoints = BTreeMap::new();
        for operation in &artifact.operations {
            if artifact.internal_command(&operation.name) {
                continue;
            }
            ensure!(
                matches!(operation.kind.as_str(), "command" | "query"),
                "unsupported public operation kind"
            );
            ensure!(
                operation.name.len() <= 80
                    && operation.name.contains('.')
                    && operation
                        .name
                        .split('.')
                        .all(|name| crate::schema::identifier(name).is_ok()),
                "invalid public operation name"
            );
            ensure!(
                artifact.schema.inputs.contains_key(&operation.input_type),
                "API input contract missing"
            );
            ensure!(
                artifact.outputs.contains_key(&operation.output_type),
                "API output contract missing"
            );
            let input = &artifact.schema.inputs[&operation.input_type];
            let docs = docs_catalog.get(&operation.name);
            let metadata = metadata_catalog.get(&operation.name);
            let mut input_shape = record_schema(input);
            let mut output_shape = output_schema(&artifact.outputs[&operation.output_type].shape);
            let inputs = fields(
                docs.map(|docs| docs.inputs.as_slice()),
                metadata.map(|entry| entry.inputs.as_slice()),
            );
            let outputs = fields(
                docs.map(|docs| docs.outputs.as_slice()),
                metadata.map(|entry| entry.outputs.as_slice()),
            );
            crate::api_docs::annotate(&mut input_shape, &inputs)?;
            crate::api_docs::annotate(&mut output_shape, &outputs)?;
            if let Some(definition) = &artifact.app_contract {
                crate::domain::annotate(&definition.domains, &mut input_shape)?;
                crate::domain::annotate(&definition.domains, &mut output_shape)?;
            }
            let request_example = docs
                .filter(|docs| !docs.request_example.is_empty())
                .map(|docs| {
                    serde_json::from_str(&docs.request_example).expect("admitted request example")
                })
                .unwrap_or_else(|| input_example(input));
            let response_example = docs
                .filter(|docs| !docs.response_example.is_empty())
                .map(|docs| {
                    serde_json::from_str(&docs.response_example).expect("admitted response example")
                })
                .unwrap_or_else(|| crate::api_docs::example(&output_shape));
            let execution_description = if operation.kind == "query" {
                "Read-only preparation followed by a local query. Every declared input field is required; page defaults do not apply."
            } else {
                "Transactional command. Supply a stable idempotency key and reuse it with the same input when retrying an uncertain response. A different input or operation with the same key conflicts. Success completes this command's contract; accepted child commands have separate outcomes. External delivery may return durable acceptance and an invocation status URL."
            };
            let summary = metadata
                .map(|entry| entry.title.clone())
                .or_else(|| docs.map(|docs| docs.summary.clone()))
                .unwrap_or_else(|| operation.name.clone());
            let mut description = metadata
                .map(describe)
                .or_else(|| {
                    docs.filter(|docs| !docs.description.is_empty())
                        .map(|docs| docs.description.clone())
                })
                .unwrap_or_default();
            if !description.is_empty() {
                description.push_str("\n\n");
            }
            description.push_str(execution_description);
            if let Some(definition) = artifact
                .app_contract
                .as_ref()
                .and_then(|definition| definition.operations.get(&operation.name))
            {
                let execution = &definition.execution;
                if !execution.model.is_empty() {
                    description.push_str(&format!("\nThe host requires {} to equal the current revision of the {} row identified by {}. A stale revision fails with conflict, independently of installation policy.", execution.version_field, execution.model, execution.id_field));
                }
                for code in &definition.errors {
                    let error = &artifact
                        .app_contract
                        .as_ref()
                        .expect("checked definition")
                        .errors[code];
                    description.push_str(&format!(
                        "\n{}: {} Recovery: {}",
                        error.code, error.description, error.recovery
                    ));
                }
            }
            if docs.is_some_and(|docs| docs.deprecated) {
                description.push_str("\nDeprecated operation.");
            }
            let response_description = metadata
                .map(|entry| entry.usage.result.clone())
                .or_else(|| {
                    docs.filter(|docs| !docs.response_description.is_empty())
                        .map(|docs| docs.response_description.clone())
                })
                .unwrap_or_else(|| "Successful result.".into());
            let endpoint = Endpoint {
                operation: operation.clone(),
                input_schema: input_shape,
                output_schema: output_shape,
                summary,
                description,
                execution_description,
                response_description,
                request_example,
                response_example,
                response_example_source: if docs
                    .is_some_and(|docs| !docs.response_example.is_empty())
                {
                    "app-authored"
                } else {
                    "generated"
                },
                deprecated: docs.is_some_and(|docs| docs.deprecated),
                metadata: metadata.cloned(),
            };
            ensure!(
                endpoints.insert(operation.name.clone(), endpoint).is_none(),
                "duplicate public operation"
            );
        }
        ensure!(!endpoints.is_empty(), "public operations required");
        Ok(Self { endpoints })
    }
}

fn fields(
    legacy: Option<&[crate::api_docs::Field]>,
    metadata: Option<&[crate::api_docs::Field]>,
) -> Vec<crate::api_docs::Field> {
    legacy
        .unwrap_or_default()
        .iter()
        .chain(metadata.unwrap_or_default())
        .map(|field| (field.path.clone(), field.clone()))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}

fn describe(entry: &operation_metadata::Entry) -> String {
    let mut description = entry.usage.purpose.clone();
    for (label, values) in [
        ("Use when", &entry.usage.use_when),
        ("Avoid when", &entry.usage.avoid_when),
        ("Preconditions", &entry.usage.preconditions),
        ("Effects", &entry.usage.effects),
    ] {
        if !values.is_empty() {
            description.push_str(&format!("\n\n{label}:\n"));
            description.push_str(
                &values
                    .iter()
                    .map(|value| format!("- {value}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        }
    }
    description.push_str(&format!("\n\nReturns: {}", entry.usage.result));
    for source in &entry.input_sources {
        description.push_str(&format!(
            "\nInput {}: use {} from {}.",
            source.input, source.output, source.source.operation
        ));
    }
    for next in &entry.follow_ups {
        description.push_str(&format!(
            "\nFollow up with {}: {}",
            next.target.operation, next.when
        ));
    }
    description
}

fn string_schema() -> Value {
    json!({"type":"string","x-day2-max-utf8-bytes":16384,"description":"At most 16384 UTF-8 bytes."})
}
pub fn input_schema(kind: &Kind) -> Value {
    match kind {
        Kind::ModelReference { prefix, .. } => crate::identity::json_schema(prefix),
        Kind::IdCursor => {
            json!({"type":"string","maxLength":90,"description":"Use an empty string to start. Otherwise pass next_after unchanged; the host checks its model prefix.","examples":[""]})
        }
        Kind::Integer => {
            json!({"type":"integer","format":"int64","minimum":i64::MIN,"maximum":i64::MAX,"examples":[1]})
        }
        Kind::Unsigned(unsigned) => unsigned.schema(),
        Kind::RowVersion => crate::numeric::row_version_schema(),
        Kind::Text => string_schema(),
        Kind::Boolean => json!({"type":"boolean","examples":[false]}),
        Kind::TextDomain { roc_type } => {
            let mut schema = string_schema();
            schema["description"] = json!(format!(
                "{roc_type}: a domain-validated string, at most 16384 UTF-8 bytes. Additional application validation runs at execution."
            ));
            schema
        }
        Kind::StandardText { domain } => {
            let mut schema = string_schema();
            schema["x-day2-standard-domain"] = json!(domain);
            schema
        }
        Kind::Reference { target } => {
            json!({"type":"string","pattern":"^[1-9][0-9]*$","maxLength":19,"x-day2-maximum":"9223372036854775807",
            "description":format!("Canonical positive decimal ID referring to {target}, at most 9223372036854775807. Encoded as a string to preserve precision."),"examples":["1"]})
        }
        Kind::Cursor => {
            json!({"type":"string","pattern":"^(0|[1-9][0-9]*)$","maxLength":19,"x-day2-maximum":"9223372036854775807",
            "description":"Canonical nonnegative decimal cursor, at most 9223372036854775807. Use 0 to start; use next_after for the next page.","examples":["0"]})
        }
        Kind::PageSize => json!({"type":"integer","minimum":1,"maximum":100,"examples":[20]}),
        Kind::WebUrl => {
            json!({"type":"string","format":"uri","pattern":"^https://","x-day2-max-utf8-bytes":2048,
            "description":"HTTPS URL with a host and no credentials, whitespace, controls or backslashes; at most 2048 UTF-8 bytes.","examples":["https://example.com/"]})
        }
        Kind::OptionalText => {
            json!({"oneOf":[{"type":"string","const":"None"},{"type":"object","required":["Some"],"additionalProperties":false,"properties":{"Some":string_schema()}}],
            "description":"Roc optional text uses the string None or an object with one Some string field. The field itself is required."})
        }
        Kind::InputShape { shape, .. } => crate::input_shape::json_schema(shape),
    }
}
pub fn record_schema(record: &Record) -> Value {
    let mut schema = json!({"type":"object","required":record.fields.keys().collect::<Vec<_>>(),"additionalProperties":false,
        "properties":record.fields.iter().map(|(name,kind)|(name.clone(),input_schema(kind))).collect::<BTreeMap<_,_>>()});
    if record
        .fields
        .values()
        .any(|kind| matches!(kind, Kind::InputShape { .. }))
    {
        schema["x-day2-max-input-depth"] = json!(crate::input_shape::MAX_DEPTH);
        schema["x-day2-max-input-value-nodes"] = json!(crate::input_shape::MAX_VALUE_NODES);
        schema["x-day2-max-input-json-bytes"] = json!(crate::input_shape::MAX_JSON_BYTES);
    }
    schema
}
pub fn output_schema(shape: &Type) -> Value {
    match shape {
        Type::ModelReference { prefix, .. } => crate::identity::json_schema(prefix),
        Type::IdCursor => input_schema(&Kind::IdCursor),
        Type::String => string_schema(),
        Type::OptionalText => input_schema(&Kind::OptionalText),
        Type::StandardText { domain } => {
            let mut schema = string_schema();
            schema["x-day2-standard-domain"] = json!(domain);
            schema
        }
        Type::Integer => input_schema(&Kind::Integer),
        Type::Unsigned(unsigned) => unsigned.schema(),
        Type::RowVersion => crate::numeric::row_version_schema(),
        Type::Boolean => input_schema(&Kind::Boolean),
        Type::Cursor => input_schema(&Kind::Cursor),
        Type::PageSize => input_schema(&Kind::PageSize),
        Type::Record(fields) => {
            json!({"type":"object","required":fields.keys().collect::<Vec<_>>(),"additionalProperties":false,
            "properties":fields.iter().map(|(name,kind)|(name.clone(),output_schema(kind))).collect::<BTreeMap<_,_>>()})
        }
        // The nominal wrappers publish their structural payload, so a client sees
        // the exact shape it receives. Uniqueness and ordering are documented as
        // guarantees rather than left for the caller to infer.
        Type::Map(value) => json!({
            "type":"object","required":["entries"],"additionalProperties":false,
            "description":"Entries have unique nonblank keys and are ordered by key.",
            "x-day2-collection":"map",
            "properties":{"entries":{"type":"array","items":{
                "type":"object","required":["key","value"],"additionalProperties":false,
                "properties":{"key":string_schema(),"value":output_schema(value)}}}}
        }),
        Type::Set => json!({
            "type":"object","required":["members"],"additionalProperties":false,
            "description":"Members are unique, nonblank and ordered.",
            "x-day2-collection":"set",
            "properties":{"members":{"type":"array","uniqueItems":true,"items":string_schema()}}
        }),
        Type::IdPage(item) | Type::CollectionPage(item) => {
            json!({"type":"object","required":["items","has_more","next_after"],"additionalProperties":false,
            "description":"At most 100 items. Pass next_after unchanged as the next request's after cursor when has_more is true.",
            "properties":{"items":{"type":"array","maxItems":100,"items":output_schema(item)},"has_more":{"type":"boolean"},"next_after":input_schema(if matches!(shape, Type::IdPage(_)) { &Kind::IdCursor } else { &Kind::Cursor })}})
        }
        Type::List(item) => {
            json!({"type":"array","maxItems":crate::output_schema::MAX_LIST_ITEMS,"items":output_schema(item)})
        }
    }
}
pub fn input_example(record: &Record) -> Value {
    Value::Object(
        record
            .fields
            .iter()
            .map(|(name, kind)| {
                (
                    name.clone(),
                    match kind {
                        Kind::Integer | Kind::RowVersion => json!(1),
                        Kind::Unsigned(_) => json!(0),
                        Kind::PageSize => json!(20),
                        Kind::Cursor => json!("0"),
                        Kind::Reference { .. } => json!("1"),
                        Kind::Boolean => json!(false),
                        Kind::OptionalText => json!("None"),
                        Kind::WebUrl => json!("https://example.com/"),
                        Kind::ModelReference { prefix, .. } => {
                            json!(crate::identity::example(prefix))
                        }
                        Kind::IdCursor => json!(""),
                        Kind::InputShape { shape, .. } => crate::input_shape::example(shape),
                        _ => json!("example"),
                    },
                )
            })
            .collect(),
    )
}
