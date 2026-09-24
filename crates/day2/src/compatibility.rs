//! Conservative compatibility report over admitted contracts, independent of
//! generated codec keys and transport envelopes. No source files are discovered.
use crate::{
    artifact::{Artifact, LoadedArtifact},
    operation_catalog::Catalog,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, Serialize)]
pub struct Change {
    pub subject: String,
    pub kind: String,
    pub requires_transition: bool,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub previous: String,
    pub next: String,
    pub requires_transition: bool,
    pub changes: Vec<Change>,
}

fn wire(mut value: Value) -> Value {
    match &mut value {
        Value::Object(fields) => {
            for name in [
                "title",
                "description",
                "examples",
                "x-day2-domain-description",
            ] {
                fields.remove(name);
            }
            for (name, field) in fields.iter_mut() {
                if [
                    "properties",
                    "patternProperties",
                    "$defs",
                    "definitions",
                    "dependentSchemas",
                ]
                .contains(&name.as_str())
                {
                    // These objects map application names to schemas. A field
                    // called `title` or `description` is still part of the wire.
                    if let Some(schemas) = field.as_object_mut() {
                        for schema in schemas.values_mut() {
                            *schema = wire(schema.take());
                        }
                    }
                } else {
                    *field = wire(field.take());
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                *item = wire(item.take());
            }
        }
        _ => (),
    }
    value
}

fn internal_contracts(artifact: &Artifact) -> Result<Value> {
    let mut commands = serde_json::Map::new();
    for operation in &artifact.operations {
        if !artifact.internal_command(&operation.name) {
            continue;
        }
        let definition = &artifact
            .app_contract
            .as_ref()
            .context("command contract")?
            .operations[&operation.name];
        let input =
            crate::operation_catalog::record_schema(&artifact.schema.inputs[&operation.input_type]);
        commands.insert(operation.name.clone(),json!({"input":wire(input),"output":artifact.outputs[&operation.output_type].shape,"execution":definition.execution,"errors":definition.errors}));
    }
    Ok(Value::Object(commands))
}

pub fn compare(previous: &LoadedArtifact, next: &LoadedArtifact) -> Result<Report> {
    let changes = compare_contracts(previous.contract(), next.contract())?;
    Ok(Report {
        previous: previous.id().to_owned(),
        next: next.id().to_owned(),
        requires_transition: changes.iter().any(|change| change.requires_transition),
        changes,
    })
}

/// Pure comparison of editable contract candidates; this does not admit an artifact.
pub fn compare_contracts(previous: &Artifact, next: &Artifact) -> Result<Vec<Change>> {
    ensure!(
        previous.namespace == next.namespace,
        "compare artifacts from the same application"
    );
    let old = Catalog::from_artifact(previous)?;
    let new = Catalog::from_artifact(next)?;
    let mut changes = vec![];
    let mut add = |subject: &str, kind: &str, requires_transition: bool| {
        changes.push(Change {
            subject: subject.into(),
            kind: kind.into(),
            requires_transition,
        })
    };
    for (name, before) in &old.endpoints {
        let Some(after) = new.endpoints.get(name) else {
            add(name, "removed operation (including renames)", true);
            continue;
        };
        for (kind, before, after) in [
            (
                "operation kind changed",
                json!(before.operation.kind),
                json!(after.operation.kind),
            ),
            (
                "input shape or constraints changed",
                wire(before.input_schema.clone()),
                wire(after.input_schema.clone()),
            ),
            (
                "result shape or constraints changed",
                wire(before.output_schema.clone()),
                wire(after.output_schema.clone()),
            ),
        ] {
            if before != after {
                add(name, kind, true);
            }
        }
        if before.description != after.description
            || before.summary != after.summary
            || before.request_example != after.request_example
            || before.response_example != after.response_example
            || before.deprecated != after.deprecated
        {
            add(name, "descriptions, examples, or lifecycle changed", false);
        }
        let definition = |artifact: &Artifact| {
            artifact
                .app_contract
                .as_ref()
                .and_then(|definition| definition.operations.get(name))
                .map(|op| json!({"execution":op.execution,"errors":op.errors}))
        };
        if definition(previous) != definition(next) {
            add(
                name,
                "execution requirements or declared failures changed",
                true,
            );
        }
    }
    for name in new.endpoints.keys() {
        if !old.endpoints.contains_key(name) {
            add(name, "added operation", false);
        }
    }
    if previous.schema.models != next.schema.models
        || previous.schema.foreign_keys != next.schema.foreign_keys
        || previous.identities != next.identities
    {
        add(
            "storage",
            "storage shape or identity history changed; review migration",
            true,
        );
    }
    let domains = |artifact: &Artifact| {
        wire(json!(
            artifact
                .app_contract
                .as_ref()
                .map(|definition| &definition.domains)
        ))
    };
    if domains(previous) != domains(next) {
        add(
            "domains",
            "text domain constraints changed; review existing data",
            true,
        );
    }
    if internal_contracts(previous)? != internal_contracts(next)? {
        add(
            "internal_commands",
            "internal command contracts changed; drain pending invocations",
            true,
        );
    }
    Ok(changes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalization_preserves_constraints_and_nominal_identity() {
        let a = json!({"type":"string","description":"Old prose","x-day2-standard-domain":"Title","x-day2-max-utf8-bytes":200});
        let mut b = a.clone();
        b["description"] = json!("New prose");
        assert_eq!(wire(a.clone()), wire(b.clone()));
        b["x-day2-max-utf8-bytes"] = json!(201);
        assert_ne!(wire(a.clone()), wire(b.clone()));
        b["x-day2-max-utf8-bytes"] = json!(200);
        b["x-day2-standard-domain"] = json!("Document");
        assert_ne!(wire(a), wire(b));
    }

    #[test]
    fn annotation_names_are_preserved_when_they_are_application_fields() {
        let original = json!({"type":"object", "title":"Display heading", "properties":{
            "title":{"type":"string", "description":"A title"},
            "description":{"type":"string"},
            "examples":{"type":"array", "items":{"type":"object", "properties":{
                "title":{"type":"boolean"}
            }}}
        }});
        let normalized = wire(original.clone());
        assert!(normalized.get("title").is_none());
        assert_eq!(normalized["properties"]["title"], json!({"type":"string"}));
        assert_eq!(
            normalized["properties"]["description"],
            json!({"type":"string"})
        );
        assert_eq!(
            normalized["properties"]["examples"]["items"]["properties"]["title"],
            json!({"type":"boolean"})
        );
        let mut changed = original;
        changed["properties"]["title"]["type"] = json!("boolean");
        assert_ne!(normalized, wire(changed));
    }
}
