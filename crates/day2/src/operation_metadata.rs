//! Structured app intent and checked links between public operation contracts.
use crate::{artifact::Operation, operation_catalog, output_schema, schema::Schema};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub type Catalog = BTreeMap<String, Entry>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub purpose: String,
    pub use_when: Vec<String>,
    pub avoid_when: Vec<String>,
    pub preconditions: Vec<String>,
    pub effects: Vec<String>,
    pub result: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub operation: String,
    pub input_type: String,
    pub output_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputSource {
    pub input: String,
    pub source: Target,
    pub output: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FollowUp {
    pub target: Target,
    pub when: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub target: Target,
    pub title: String,
    pub usage: Usage,
    #[serde(default)]
    pub inputs: Vec<crate::api_docs::Field>,
    #[serde(default)]
    pub outputs: Vec<crate::api_docs::Field>,
    pub input_sources: Vec<InputSource>,
    pub follow_ups: Vec<FollowUp>,
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
        entries: Vec<Entry>,
        error: String,
    }
    ensure!(raw.len() <= 262_144, "operation contract byte budget");
    let envelope: Envelope =
        serde_json::from_slice(raw).context("invalid ApiContract.all metadata")?;
    ensure!(
        envelope.error.is_empty(),
        "ApiContract failed: {}",
        envelope.error
    );
    let mut catalog = Catalog::new();
    for entry in envelope.entries {
        ensure!(
            catalog
                .insert(entry.target.operation.clone(), entry)
                .is_none(),
            "duplicate operation contract operation"
        );
    }
    ensure!(
        !catalog.is_empty(),
        "ApiContract must describe every public operation"
    );
    validate(&catalog, operations, schema, outputs)?;
    Ok(catalog)
}

fn target<'a>(target: &Target, operations: &'a [Operation]) -> Result<&'a Operation> {
    operations
        .iter()
        .find(|operation| {
            operation.name == target.operation
                && matches!(operation.kind.as_str(), "command" | "query")
                && operation.input_type == target.input_type
                && operation.output_type == target.output_type
        })
        .with_context(|| {
            format!(
                "operation handle must match a registered public operation: {}",
                target.operation
            )
        })
}

fn prose(value: &str, max: usize) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= max,
        "operation text budget"
    );
    Ok(())
}

pub fn validate(
    catalog: &Catalog,
    operations: &[Operation],
    schema: &Schema,
    outputs: &output_schema::Catalog,
) -> Result<()> {
    // Existing apps get a mechanically derived server. Once an app opts into
    // semantic contracts, a newly declared operation cannot silently lack intent.
    if catalog.is_empty() {
        return Ok(());
    }
    ensure!(
        catalog.len() <= 128 && serde_json::to_vec(catalog)?.len() <= 262_144,
        "operation contract budget"
    );
    let public: BTreeSet<_> = operations
        .iter()
        .filter(|operation| matches!(operation.kind.as_str(), "command" | "query"))
        .map(|operation| &operation.name)
        .collect();
    ensure!(
        public == catalog.keys().collect(),
        "ApiContract must describe every public operation"
    );
    for (name, entry) in catalog {
        let operation = target(&entry.target, operations)?;
        ensure!(
            name == &operation.name,
            "operation contract key differs from handle"
        );
        prose(&entry.title, 120)?;
        prose(&entry.usage.purpose, 1024)?;
        prose(&entry.usage.result, 1024)?;
        ensure!(
            !entry.usage.use_when.is_empty(),
            "operation use_when required"
        );
        ensure!(
            operation.kind != "command" || !entry.usage.effects.is_empty(),
            "command effects required"
        );
        ensure!(
            operation.kind != "query" || entry.usage.effects.is_empty(),
            "queries cannot declare write effects"
        );
        for list in [
            &entry.usage.use_when,
            &entry.usage.avoid_when,
            &entry.usage.preconditions,
            &entry.usage.effects,
        ] {
            ensure!(list.len() <= 16, "operation usage list budget");
            for value in list {
                prose(value, 1024)?;
            }
        }
        let input = operation_catalog::record_schema(
            schema
                .inputs
                .get(&operation.input_type)
                .context("operation input missing")?,
        );
        crate::api_docs::annotate(&mut input.clone(), &entry.inputs)?;
        let mut output = operation_catalog::output_schema(
            &outputs
                .get(&operation.output_type)
                .context("operation output missing")?
                .shape,
        );
        crate::api_docs::annotate(&mut output, &entry.outputs)?;
        ensure!(
            entry.input_sources.len() <= 64 && entry.follow_ups.len() <= 16,
            "operation relationship budget"
        );
        let mut sources = BTreeSet::new();
        for source in &entry.input_sources {
            target(&source.source, operations)?;
            ensure!(
                sources.insert((&source.input, &source.source.operation, &source.output)),
                "duplicate operation input source"
            );
            // Input paths cannot traverse collections: a source item supplies one
            // concrete input, not an implicit fan-out or executable workflow.
            ensure!(
                !source.input.contains("[]"),
                "operation input source must identify one input"
            );
            let output = operation_catalog::output_schema(
                &outputs
                    .get(&source.source.output_type)
                    .context("operation source output missing")?
                    .shape,
            );
            let destination = field(&input, &source.input)?;
            let origin = field(&output, &source.output)?;
            ensure!(
                destination == origin,
                "operation input source wire contracts differ: {name}.{}",
                source.input
            );
        }
        let mut next = BTreeSet::new();
        for follow in &entry.follow_ups {
            target(&follow.target, operations)?;
            prose(&follow.when, 1024)?;
            ensure!(
                next.insert(&follow.target.operation),
                "duplicate operation follow-up"
            );
        }
    }
    Ok(())
}

fn field<'a>(schema: &'a Value, path: &str) -> Result<&'a Value> {
    prose(path, 256)?;
    let mut value = schema;
    for part in path.split('.') {
        let (name, array) = part
            .strip_suffix("[]")
            .map_or((part, false), |name| (name, true));
        day2_contracts::names::identifier(name)?;
        value = value
            .get("properties")
            .and_then(|fields| fields.get(name))
            .with_context(|| format!("unknown operation field path: {path}"))?;
        if array {
            value = value
                .get("items")
                .context("operation field is not a collection")?;
        }
    }
    Ok(value)
}
