//! The complete application definition. New builds never discover metadata files.
use crate::{
    api_docs,
    artifact::Artifact,
    operation_metadata, output_schema, registry,
    schema::{Kind, Record, Schema},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Effect {
    #[serde(default)]
    pub command: String,
    pub kind: String,
    pub model: String,
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    #[serde(default)]
    pub internal: bool,
    pub model: String,
    pub id_field: String,
    pub version_field: String,
    pub effects: Vec<Effect>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub intent: operation_metadata::Entry,
    pub request_example: String,
    pub response_example: String,
    pub deprecated: bool,
    pub execution: Execution,
    pub errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_all_rows: Vec<String>,
}

impl Operation {
    fn validate_required_all_rows(&self, schema: &Schema) -> Result<()> {
        ensure!(
            self.required_all_rows.len() <= 64,
            "unfiltered read requirement budget"
        );
        let mut seen = BTreeSet::new();
        for model in &self.required_all_rows {
            ensure!(
                schema.models.contains_key(model),
                "unknown unfiltered read model"
            );
            ensure!(seen.insert(model), "duplicate unfiltered read requirement");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    pub code: String,
    pub description: String,
    pub recovery: String,
    pub operation: operation_metadata::Target,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_operations: Vec<operation_metadata::Target>,
}

impl Failure {
    pub fn targets(&self) -> impl Iterator<Item = &operation_metadata::Target> {
        std::iter::once(&self.operation).chain(&self.additional_operations)
    }

    pub fn verification_key(&self, target: &operation_metadata::Target) -> String {
        if self.additional_operations.is_empty() {
            self.code.clone()
        } else {
            format!("{}@{}", self.code, target.operation)
        }
    }

    fn validate_targets(
        &self,
        operations: &[crate::artifact::Operation],
        contracts: &BTreeMap<String, Operation>,
    ) -> Result<()> {
        ensure!(
            self.additional_operations.len() < 256,
            "application error verification case budget"
        );
        let mut seen = BTreeSet::new();
        for target in self.targets() {
            ensure!(
                seen.insert(&target.operation),
                "duplicate application failure verification target"
            );
            let operation = operations
                .iter()
                .find(|operation| operation.name == target.operation)
                .context("failure verification requires a registered operation")?;
            ensure!(
                operation.input_type == target.input_type
                    && operation.output_type == target.output_type,
                "failure verification callback type mismatch"
            );
            ensure!(
                contracts
                    .get(&operation.name)
                    .is_some_and(|operation| operation.errors.contains(&self.code)),
                "application failure requires a matching operation contract and scenario"
            );
        }
        Ok(())
    }
}

fn validate_error_declarations(
    operations: &BTreeMap<String, Operation>,
    errors: &BTreeMap<String, Failure>,
) -> Result<()> {
    for (name, definition) in operations {
        let declared: BTreeSet<_> = definition.errors.iter().collect();
        ensure!(
            declared.len() == definition.errors.len()
                && declared.iter().all(|code| errors
                    .get(*code)
                    .is_some_and(|error| error.targets().any(|target| &target.operation == name))),
            "undeclared, duplicate or unverified operation failure"
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Presentation {
    pub stylesheet: String,
    pub script: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    pub operations: BTreeMap<String, Operation>,
    pub presentation: Presentation,
    pub identities: String,
    pub invariants: BTreeMap<String, String>,
    pub domains: crate::domain::Catalog,
    pub errors: BTreeMap<String, Failure>,
}

pub fn decode(raw: &[u8]) -> Result<Definition> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RawDefinition {
        operations: Vec<Operation>,
        presentation: Presentation,
        identities: String,
        invariants: Vec<Invariant>,
        domains: Vec<Domain>,
        errors: Vec<Failure>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Invariant {
        model: String,
        description: String,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Domain {
        name: String,
        rules: crate::domain::TextRule,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        definition: RawDefinition,
        error: String,
    }
    ensure!(raw.len() <= 1_048_576, "application contract byte budget");
    let Envelope { definition, error } =
        serde_json::from_slice(raw).context("invalid App.definition contract")?;
    ensure!(error.is_empty(), "application contract failed: {error}");
    let mut operations = BTreeMap::new();
    for operation in definition.operations {
        ensure!(
            operations
                .insert(operation.intent.target.operation.clone(), operation)
                .is_none(),
            "duplicate operation contract"
        );
    }
    let mut invariants = BTreeMap::new();
    for check in definition.invariants {
        ensure!(
            invariants.insert(check.model, check.description).is_none(),
            "duplicate model verification obligation"
        );
    }
    let mut domains = BTreeMap::new();
    for domain in definition.domains {
        ensure!(
            domains.insert(domain.name, domain.rules).is_none(),
            "duplicate domain contract"
        );
    }
    let mut errors = BTreeMap::new();
    for error in definition.errors {
        ensure!(
            errors.insert(error.code.clone(), error).is_none(),
            "duplicate application failure"
        );
    }
    Ok(Definition {
        operations,
        presentation: definition.presentation,
        identities: definition.identities,
        invariants,
        domains,
        errors,
    })
}

impl Definition {
    pub fn intents(&self) -> operation_metadata::Catalog {
        self.operations
            .iter()
            .map(|(name, operation)| (name.clone(), operation.intent.clone()))
            .collect()
    }

    pub fn documentation(&self) -> api_docs::Catalog {
        self.operations
            .iter()
            .map(|(name, operation)| {
                let intent = &operation.intent;
                (
                    name.clone(),
                    api_docs::Documentation {
                        operation: name.clone(),
                        input_type: intent.target.input_type.clone(),
                        output_type: intent.target.output_type.clone(),
                        summary: intent.title.clone(),
                        description: intent.usage.purpose.clone(),
                        response_description: intent.usage.result.clone(),
                        inputs: intent.inputs.clone(),
                        outputs: intent.outputs.clone(),
                        request_example: operation.request_example.clone(),
                        response_example: operation.response_example.clone(),
                        deprecated: operation.deprecated,
                    },
                )
            })
            .collect()
    }

    pub fn validate(&self, artifact: &Artifact) -> Result<()> {
        let expected_errors = artifact
            .declarations
            .errors
            .iter()
            .map(|name| format!("app:{}.{}", artifact.namespace, name))
            .collect::<BTreeSet<_>>();
        ensure!(
            self.errors.keys().cloned().collect::<BTreeSet<_>>() == expected_errors,
            "application failures must match checked definitions"
        );
        for (code, error) in &self.errors {
            ensure!(code == &error.code, "application failure key mismatch");
            text(&error.description, 1024)?;
            text(&error.recovery, 1024)?;
            error.validate_targets(&artifact.operations, &self.operations)?;
        }
        ensure!(
            self.domains.keys().collect::<BTreeSet<_>>()
                == artifact.schema.domains.values().collect(),
            "domain contracts must match checked nominal registrations"
        );
        for rules in self.domains.values() {
            rules.validate()?;
        }
        for output in artifact.outputs.values() {
            // Validate type reachability even when an example's collection is empty.
            crate::domain::annotate(
                &self.domains,
                &mut crate::operation_catalog::output_schema(&output.shape),
            )?;
        }
        for record in artifact
            .schema
            .models
            .values()
            .chain(artifact.schema.inputs.values())
        {
            ensure!(
                record
                    .fields
                    .values()
                    .all(|kind| !matches!(kind, Kind::TextDomain { .. })),
                "current applications require executable standard text domains"
            );
        }
        ensure!(
            self.invariants.keys().collect::<BTreeSet<_>>()
                == artifact.schema.models.keys().collect(),
            "every persistent model requires a verification obligation"
        );
        ensure!(
            artifact.properties.iter().collect::<BTreeSet<_>>() == self.invariants.keys().collect(),
            "model verification manifest mismatch"
        );
        ensure!(
            artifact
                .pages
                .iter()
                .map(|page| &page.name)
                .collect::<BTreeSet<_>>()
                == artifact.declarations.pages.iter().collect(),
            "named page manifest mismatch"
        );
        for description in self.invariants.values() {
            text(description, 1024)?;
        }
        ensure!(
            self.identities == crate::identity::REGISTRY_FILE,
            "App.definition.storage must bind the committed model identity ledger"
        );
        ensure!(
            serde_json::to_vec(self)?.len() <= 1_048_576,
            "application contract byte budget"
        );
        let expected = artifact
            .operations
            .iter()
            .map(|op| &op.name)
            .collect::<BTreeSet<_>>();
        ensure!(
            !expected.is_empty() && expected == self.operations.keys().collect(),
            "every operation requires a complete contract"
        );
        operation_metadata::validate(
            &self.intents(),
            &artifact.operations,
            &artifact.schema,
            &artifact.outputs,
        )?;
        api_docs::validate(
            &self.documentation(),
            &artifact.operations,
            &artifact.schema,
            &artifact.outputs,
        )?;
        validate_error_declarations(&self.operations, &self.errors)?;
        for (name, definition) in &self.operations {
            let operation = artifact
                .operations
                .iter()
                .find(|op| &op.name == name)
                .context("operation missing")?;
            let input = &artifact.schema.inputs[&operation.input_type];
            require_fields(
                &definition.intent.inputs,
                &crate::operation_catalog::record_schema(input),
            )?;
            require_fields(
                &definition.intent.outputs,
                &crate::operation_catalog::output_schema(
                    &artifact.outputs[&operation.output_type].shape,
                ),
            )?;
            ensure!(
                !definition.request_example.is_empty() && !definition.response_example.is_empty(),
                "typed input and output examples are required: {name}"
            );
            crate::domain::record(
                &self.domains,
                input,
                &serde_json::from_str(&definition.request_example)?,
            )?;
            crate::domain::output(
                &self.domains,
                &artifact.outputs[&operation.output_type].shape,
                &serde_json::from_str(&definition.response_example)?,
            )?;
            definition.execution.validate(artifact, operation, input)?;
            definition.validate_required_all_rows(&artifact.schema)?;
        }
        for (path, media) in [
            (&self.presentation.stylesheet, "text/css; charset=utf-8"),
            (&self.presentation.script, "text/javascript; charset=utf-8"),
        ] {
            if !path.is_empty() {
                ensure!(
                    artifact
                        .web_resources
                        .get(path)
                        .is_some_and(|resource| resource.media_type == media),
                    "declared presentation resource is missing or has the wrong type: {path}"
                );
            }
        }
        Ok(())
    }
}

impl Execution {
    pub fn target(
        &self,
        input: &serde_json::Value,
    ) -> Result<Option<crate::authority::EditTarget>> {
        if self.model.is_empty() {
            return Ok(None);
        }
        let id = input
            .get(&self.id_field)
            .and_then(serde_json::Value::as_str)
            .context("invalid_edit_precondition")?;
        let version = input
            .get(&self.version_field)
            .and_then(serde_json::Value::as_i64)
            .context("invalid_edit_precondition")?;
        ensure!(
            version > 0 && version < i64::MAX,
            "invalid_edit_precondition"
        );
        Ok(Some(crate::authority::EditTarget {
            model: self.model.clone(),
            id: crate::identity::parse_public_or_legacy(id)?,
            version,
        }))
    }

    fn validate(
        &self,
        artifact: &Artifact,
        operation: &crate::artifact::Operation,
        input: &Record,
    ) -> Result<()> {
        if operation.kind == "query" {
            ensure!(
                self == &Self::default(),
                "queries cannot declare write execution"
            );
            return Ok(());
        }
        if self.model.is_empty() {
            ensure!(
                self.id_field.is_empty() && self.version_field.is_empty(),
                "incomplete command precondition"
            );
        } else {
            ensure!(
                matches!(input.fields.get(&self.id_field), Some(Kind::ModelReference {target, ..}) if target == &self.model),
                "edit precondition must use a reference to its model"
            );
            ensure!(
                matches!(
                    input.fields.get(&self.version_field),
                    Some(Kind::RowVersion)
                ),
                "edit precondition requires RowVersion"
            );
        }
        ensure!(self.effects.len() <= 64, "command effect budget");
        let mut seen = BTreeSet::new();
        for effect in &self.effects {
            let logical_kind = if effect.kind == "update_created" {
                "update"
            } else {
                effect.kind.as_str()
            };
            ensure!(
                seen.insert((logical_kind, &effect.model, &effect.command)),
                "duplicate command effect"
            );
            if effect.kind == "external" {
                ensure!(
                    effect.model.is_empty()
                        && effect.fields.is_empty()
                        && crate::capabilities::WRITES.contains(&effect.command.as_str()),
                    "unknown external capability"
                );
                continue;
            }
            if effect.kind == "request" {
                ensure!(
                    effect.model.is_empty()
                        && effect.fields.is_empty()
                        && artifact
                            .operations
                            .iter()
                            .any(|operation| operation.kind == "command"
                                && operation.name == effect.command),
                    "invalid command request effect"
                );
                continue;
            }
            ensure!(
                effect.command.is_empty(),
                "unexpected command effect target"
            );
            let model = artifact
                .schema
                .models
                .get(&effect.model)
                .context("unknown effect model")?;
            match effect.kind.as_str() {
                "create" => ensure!(effect.fields.is_empty(), "invalid create effect"),
                // Field-less by construction: soft deletion changes no field.
                "soft_delete" => ensure!(effect.fields.is_empty(), "invalid soft_delete effect"),
                "update" | "update_created" => {
                    ensure!(!effect.fields.is_empty(), "update fields required");
                    let fields: BTreeSet<_> = effect.fields.iter().collect();
                    ensure!(
                        fields.len() == effect.fields.len()
                            && fields.iter().all(|field| model.fields.contains_key(*field)),
                        "unknown or duplicate update field"
                    );
                }
                _ => anyhow::bail!("unknown command effect"),
            }
        }
        Ok(())
    }
}

fn text(value: &str, maximum: usize) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= maximum,
        "required application description is empty or oversized"
    );
    Ok(())
}

fn require_fields(fields: &[api_docs::Field], schema: &serde_json::Value) -> Result<()> {
    fn visit(schema: &serde_json::Value, prefix: &str, paths: &mut BTreeSet<String>) {
        if schema.get("x-day2-collection").is_some() {
            paths.insert(format!("{prefix}[]"));
            return;
        }
        if let Some(properties) = schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
        {
            for (name, field) in properties {
                let path = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}.{name}")
                };
                paths.insert(path.clone());
                visit(field, &path, paths);
            }
        }
        if let Some(items) = schema.get("items") {
            visit(items, &format!("{prefix}[]"), paths);
        }
        if schema.get("properties").is_none()
            && schema.get("items").is_none()
            && prefix.ends_with("[]")
        {
            paths.insert(prefix.to_owned());
        }
    }
    let mut expected = BTreeSet::new();
    visit(schema, "", &mut expected);
    ensure!(
        expected == fields.iter().map(|field| field.path.clone()).collect(),
        "descriptions must cover exactly every input/output field"
    );
    Ok(())
}

fn input_docs(record: &Record) -> String {
    format!(
        "{{ {} }}",
        record
            .fields
            .iter()
            .map(|(name, kind)| {
                let docs = match kind {
                    Kind::InputShape { shape, .. } => nested_docs(shape),
                    _ => "Str".into(),
                };
                format!("{name} : {docs}")
            })
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn output_docs(shape: &output_schema::Type) -> String {
    use output_schema::Type;
    match shape {
        Type::Record(fields) => format!(
            "{{ {} }}",
            fields
                .iter()
                .map(|(name, shape)| format!("{name} : {}", nested_docs(shape)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Type::CollectionPage(item) | Type::IdPage(item) => format!(
            "{{ items : {{ description : Str, each : {} }}, has_more : Str, next_after : Str }}",
            output_docs(item)
        ),
        Type::List(item) => format!("{{ description : Str, each : {} }}", output_docs(item)),
        // A nominal collection documents its values, not the list-of-pairs it is
        // represented by: entries, key and value are the wrapper's business.
        Type::Map(value) => format!("{{ description : Str, each : {} }}", output_docs(value)),
        Type::Set => "{ description : Str, each : Str }".into(),
        _ => "Str".into(),
    }
}

fn nested_docs(shape: &output_schema::Type) -> String {
    match shape {
        output_schema::Type::Record(_)
        | output_schema::Type::CollectionPage(_)
        | output_schema::Type::IdPage(_) => {
            format!("{{ description : Str, fields : {} }}", output_docs(shape))
        }
        _ => output_docs(shape),
    }
}

fn fields_expression(shape: &serde_json::Value, accessor: &str) -> String {
    fn visit(shape: &serde_json::Value, path: &str, accessor: &str, fields: &mut Vec<String>) {
        if shape.get("properties").is_none() && shape.get("items").is_none() && path.ends_with("[]")
        {
            fields.push(format!("{{ path: \"{path}\", description: {accessor} }}"));
        }
        if let Some(properties) = shape
            .get("properties")
            .and_then(serde_json::Value::as_object)
        {
            for (key, value) in properties {
                let path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                let access = format!("{accessor}.{key}");
                // A nominal collection documents itself and its values only.
                if value.get("x-day2-collection").is_some() {
                    fields.push(format!(
                        "{{ path: \"{path}\", description: {access}.description }}"
                    ));
                    fields.push(format!(
                        "{{ path: \"{path}[]\", description: {access}.each }}"
                    ));
                    continue;
                }
                let nested = value.get("properties").is_some();
                let array = value.get("items").is_some();
                fields.push(format!(
                    "{{ path: \"{path}\", description: {access}{} }}",
                    if nested || array { ".description" } else { "" }
                ));
                if nested {
                    visit(value, &path, &format!("{access}.fields"), fields);
                }
                if let Some(item) = value.get("items") {
                    visit(
                        item,
                        &format!("{path}[]"),
                        &format!("{access}.each"),
                        fields,
                    );
                }
            }
        }
    }
    let mut fields = Vec::new();
    visit(shape, "", accessor, &mut fields);
    format!("[{}]", fields.join(", "))
}

pub fn modules(
    catalog: &registry::Catalog,
    schema: &Schema,
    outputs: &output_schema::Catalog,
    imports: &str,
    admission: bool,
) -> Result<BTreeMap<String, String>> {
    let prefix = if admission { "admission_" } else { "" };
    let input_type = |key: &str| schema.inputs[key].input_type();
    let mut operation_types = Vec::new();
    let mut bindings = BTreeMap::new();
    let mut metadata = Vec::new();
    let mut verification = String::from(
        "    verify : AppContract.Product, Api.VerificationRequest -> Try(Str, Str)\n    verify = |product, request| {\n",
    );
    let mut source = format!(
        "{imports}import pf.Api\nimport pf.Product\nimport pf.Example\nimport pf.CommandBinding\nimport pf.QueryBinding\nimport AppContract\nimport Commands\nimport Reads\nRegistry :: [].{{\n"
    );
    for (kind, wrapper, definitions, handle) in [
        ("command", "CommandDef", &catalog.commands, "Commands"),
        ("query", "QueryDef", &catalog.queries, "Reads"),
    ] {
        let mut bound = Vec::new();
        for (name, operation) in definitions {
            let input = &schema.inputs[&operation.input];
            let output = &outputs[&operation.output];
            operation_types.push(format!(
                "{name} : Api.{wrapper}({}, {}, {}, {})",
                input_type(&operation.input)?,
                output.roc_type,
                input_docs(input),
                if matches!(
                    output.shape,
                    output_schema::Type::Record(_)
                        | output_schema::Type::CollectionPage(_)
                        | output_schema::Type::IdPage(_)
                        | output_schema::Type::List(_)
                ) {
                    output_docs(&output.shape)
                } else {
                    "{}".into()
                }
            ));
            bound.push(format!(
                "{}Binding.{prefix}bind({handle}.{name}, product.operations.{name}.{prefix}{kind}_program())",
                if kind == "command" {
                    "Command"
                } else {
                    "Query"
                }
            ));
            metadata.push(format!("contract_{name}(product)?"));
            verification.push_str(&format!("        if request.operation == {handle}.{name}.name() {{\n            checks = product.operations.{name}.verification()\n            if request.action == \"input\" {{\n                value = (checks.input)(request.snapshot, request.seed)?\n                encoded = Inputs.{}.encode(value)\n                _ = Inputs.{}.decode(encoded)?\n                return Ok(encoded)\n            }}\n            if request.action == \"check\" {{\n                output = Outputs.decode_{}(request.output)?\n                passed = (checks.check)(request.before, output, request.snapshot)?\n                if !passed {{ return Err(\"operation verification failed\") }}\n                return Ok(\"true\")\n            }}\n        }}\n", operation.input, operation.input, operation.output));
            let execution = if kind == "command" {
                format!(
                    "execution = product.operations.{name}.execution()\n        execution_metadata = {{ internal: execution.internal, model: execution.model, id_field: execution.id_field, version_field: execution.version_field, effects: execution.effects }}"
                )
            } else {
                "execution_metadata : Api.ExecutionMetadata\n        execution_metadata = { internal: Bool.False, model: \"\", id_field: \"\", version_field: \"\", effects: [] }".into()
            };
            let inputs = fields_expression(
                &crate::operation_catalog::record_schema(input),
                "contract.inputs",
            );
            let out = fields_expression(
                &crate::operation_catalog::output_schema(&output.shape),
                "contract.outputs",
            );
            source.push_str(&format!("    contract_{name} : AppContract.Product -> Try(Api.Metadata, Str)\n    contract_{name} = |product| {{\n        contract = product.operations.{name}.contract()\n        example = (contract.example)({{}})?\n        request_example = Inputs.{}.encode(example.input)\n        _ = Inputs.{}.decode(request_example)?\n        {execution}\n        Ok({{ intent: {{ target: Api.{}({handle}.{name}), title: contract.title, usage: contract.usage, inputs: {inputs}, outputs: {out}, input_sources: contract.input_sources, follow_ups: contract.follow_ups }}, request_example, response_example: Outputs.{}.encode(example.output), deprecated: contract.deprecated, execution: execution_metadata, required_all_rows: product.operations.{name}.required_all_rows() }})\n    }}\n", operation.input, operation.input, if kind == "command" { "write" } else { "read" }, operation.output));
        }
        bindings.insert(kind, bound.join(", "));
    }
    for name in &catalog.errors {
        verification.push_str(&format!("        if request.action == \"error-input\" {{\n            scenarios = (product.errors.{name}.verification)({{}})\n            matching = scenarios.keep_if(|scenario| request.operation == \"${{Errors.{name}.code()}}@${{scenario.operation.operation}}\" or (scenarios.len() == 1 and request.operation == Errors.{name}.code()))\n            match matching {{\n                [scenario] => return (scenario.input)(request.snapshot, request.seed)\n                [] => {{}}\n                _ => return Err(\"duplicate application failure verification target\")\n            }}\n        }}\n"));
    }
    verification.push_str("        Err(\"unknown verification obligation\")\n    }\n");
    source.push_str(&verification);
    source.push_str(&format!("    definition : AppContract.Product -> Try(Api.Definition, Str)\n    definition = |product| Ok({{ operations: [{}], presentation: product.presentation, identities: product.storage.identities }})\n", metadata.join(", ")));
    source.push_str(&format!("    {prefix}step : AppContract.Product, Str -> Str\n    {prefix}step = |product, raw| {{\n        if raw == \"app-contract\" {{\n            result = definition(product)\n            empty : Api.Definition\n            empty = {{ operations: [], presentation: product.presentation, identities: product.storage.identities }}\n            return match result {{\n                Ok(value) => Json.to_str({{ definition: value, error: \"\" }})\n                Err(error) => Json.to_str({{ definition: empty, error }})\n            }}\n        }}\n        if raw == \"examples\" {{ return Example.encode(product.examples) }}\n        Product.{prefix}step({{ namespace: product.namespace, commands: [{}], queries: [{}], pages: product.pages, properties: product.properties }}, raw)\n    }}\n}}\n", bindings["command"], bindings["query"]));
    source = source.replacen("        if raw == \"app-contract\"", "        if raw.starts_with(\"verify:\") {\n            parsed : Try(Api.VerificationRequest, _)\n            parsed = Json.parse(raw.drop_prefix(\"verify:\"))\n            result = parsed.map_err(|_| \"invalid verification request\").and_then(|request| verify(product, request))\n            return match result {\n                Ok(value) => Json.to_str({ value, error: \"\" })\n                Err(error) => Json.to_str({ value: \"\", error })\n            }\n        }\n        if raw == \"app-contract\"", 1);
    let pages = catalog
        .pages
        .iter()
        .map(|name| format!("PageBinding.named(\"{name}\", product.pages.{name})"))
        .collect::<Vec<_>>()
        .join(", ");
    let schedules = catalog
        .schedules
        .iter()
        .map(|name| format!("ScheduleBinding.named(\"{name}\", product.schedules.{name})"))
        .collect::<Vec<_>>()
        .join(", ");
    let ingress = catalog
        .ingress
        .iter()
        .map(|name| format!("IngressBinding.named(\"{name}\", product.ingress.{name})"))
        .collect::<Vec<_>>()
        .join(", ");
    let properties = schema
        .models
        .keys()
        .map(|name| {
            format!(
                "Property.invariant(\"{name}\", product.properties.{name}.check(), |passed| passed)"
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    source = source.replace(
        "import pf.Api\n",
        "import pf.Api\nimport pf.PageBinding\nimport pf.Property\nimport Errors\n",
    );
    source = source.replace(
        "execution: execution_metadata",
        "execution: execution_metadata, errors: contract.errors.map(|failure| failure.code())",
    );
    // The generator edits its own output by string replacement, and `str::replace`
    // reports nothing when it matches nothing. A reformatting of the pushed literal
    // above would silently drop `schedules` and `ingress` from every generated
    // contract — which is how a binding an application declared stops reaching the
    // manifest without anything saying so. Asserting the match turns that into a
    // named failure here instead of a missing field at the Roc compiler, or worse,
    // silence.
    let contract_fields = "pages: product.pages, properties: product.properties";
    ensure!(
        source.matches(contract_fields).count() == 1,
        "the generated Product.Contract literal changed shape; the schedules and \
         ingress substitution no longer matches it"
    );
    source = source.replacen(
        contract_fields,
        &format!(
            "pages: [{pages}], properties: [{properties}], schedules: [{schedules}], ingress: [{ingress}]"
        ),
        1,
    );
    if !catalog.schedules.is_empty() {
        source = source.replace(
            "import pf.PageBinding\n",
            "import pf.PageBinding\nimport pf.ScheduleBinding\n",
        );
    }
    if !catalog.ingress.is_empty() {
        source = source.replace(
            "import pf.PageBinding\n",
            "import pf.PageBinding\nimport pf.IngressBinding\n",
        );
    }
    let invariants = schema
        .models
        .keys()
        .map(|name| {
            format!("{{ model: \"{name}\", description: product.properties.{name}.description() }}")
        })
        .collect::<Vec<_>>()
        .join(", ");
    source = source.replace(
        "identities: product.storage.identities",
        &format!("identities: product.storage.identities, invariants: [{invariants}]"),
    );
    let page_type = format!(
        "{{ {} }}",
        catalog
            .pages
            .iter()
            .map(|name| format!("{name} : PageBinding"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let ingress_type = format!(
        "{{ {} }}",
        catalog
            .ingress
            .iter()
            .map(|name| format!("{name} : IngressBinding"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let schedule_type = format!(
        "{{ {} }}",
        catalog
            .schedules
            .iter()
            .map(|name| format!("{name} : ScheduleBinding"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let property_type = format!(
        "{{ {} }}",
        schema
            .models
            .iter()
            .map(|(name, model)| format!(
                "{name} : Api.ModelCheck({})",
                model.roc_type.as_deref().expect("checked model")
            ))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let tables = format!(
        "{{ {} }}",
        schema
            .models
            .iter()
            .map(|(name, record)| format!(
                "{name} : List({})",
                record.roc_type.as_deref().expect("checked model")
            ))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let schedule_import = if catalog.schedules.is_empty() {
        ""
    } else {
        "import pf.ScheduleBinding\n"
    };
    let ingress_import = if catalog.ingress.is_empty() {
        ""
    } else {
        "import pf.IngressBinding\n"
    };
    let schedule_field = if catalog.schedules.is_empty() {
        String::new()
    } else {
        ", schedules : List(ScheduleBinding)".to_owned()
    };
    let ingress_field = if catalog.ingress.is_empty() {
        String::new()
    } else {
        ", ingress : List(IngressBinding)".to_owned()
    };
    let contract = format!(
        "{imports}import pf.Api\nimport pf.PageBinding\nimport pf.Property\nimport pf.Example\n{schedule_import}{ingress_import}AppContract :: [].{{\n    Product : {{ namespace : Str, storage : {{ schema : ({tables} -> {tables}), identities : Str }}, operations : {{ {} }}, pages : List(PageBinding), properties : List(Property), examples : List(Example), presentation : Api.Presentation{schedule_field}{ingress_field} }}\n}}\n",
        operation_types.join(", ")
    );
    for (name, operation) in catalog.commands.iter().chain(catalog.queries.iter()) {
        let start = source
            .find(&format!("    contract_{name} ="))
            .context("contract generator")?;
        let at = start
            + source[start..]
                .find("input_sources: contract.input_sources")
                .context("contract links generator")?;
        source.replace_range(
            at..at + "input_sources: contract.input_sources".len(),
            &format!(
                "input_sources: (contract.input_sources)(Inputs.{}).map(|link| link.metadata())",
                operation.input
            ),
        );
    }
    let domains = schema
        .domains
        .iter()
        .map(|(name, tag)| {
            format!("{{ name: \"{tag}\", rules: product.storage.domains.{name}.metadata() }}")
        })
        .collect::<Vec<_>>()
        .join(", ");
    source = source.replace(
        "identities: product.storage.identities",
        &format!("domains: [{domains}], identities: product.storage.identities"),
    );
    let errors = catalog
        .errors
        .iter()
        .map(|name| format!("Api.error_metadata(Errors.{name}.code(), product.errors.{name})?"))
        .collect::<Vec<_>>()
        .join(", ");
    source = source.replace(
        "identities: product.storage.identities",
        &format!("errors: [{errors}], identities: product.storage.identities"),
    );
    // A rejected metadata callback must still be encoded as an error response;
    // do not evaluate its fallible examples again in the empty response value.
    let empty_at = source
        .find("empty = {")
        .context("empty contract response generator")?;
    let error_fields = format!("errors: [{errors}]");
    let error_at = empty_at
        + source[empty_at..]
            .find(&error_fields)
            .context("empty contract errors generator")?;
    source.replace_range(error_at..error_at + error_fields.len(), "errors: []");
    let domain_type = format!(
        "{{ {} }}",
        schema
            .domains
            .iter()
            .map(|(name, tag)| format!("{name} : TextSpec({tag})"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let mut contract = contract
        .replace("import pf.Api\n", "import pf.Api\nimport pf.TextSpec\n")
        .replace(
            "identities : Str }",
            &format!("identities : Str, domains : {domain_type} }}"),
        )
        .replace("pages : List(PageBinding)", &format!("pages : {page_type}"))
        .replace(
            "schedules : List(ScheduleBinding)",
            &format!("schedules : {schedule_type}"),
        )
        .replace(
            "ingress : List(IngressBinding)",
            &format!("ingress : {ingress_type}"),
        )
        .replace(
            "properties : List(Property)",
            &format!("properties : {property_type}"),
        );
    if !schema.indexes.is_empty() {
        contract = contract.replace("import pf.Api\n", "import pf.Api\nimport pf.Index\n");
        let mut models = BTreeMap::<&str, Vec<String>>::new();
        for index in &schema.indexes {
            let fields = index
                .fields
                .iter()
                .map(|field| format!("{field} : Index.Field"))
                .collect::<Vec<_>>()
                .join(", ");
            models.entry(&index.model).or_default().push(format!(
                "{} : [{}(List({{ {fields} }}))]",
                index.name,
                if index.unique { "Unique" } else { "NonUnique" }
            ));
        }
        let indexes = models
            .into_iter()
            .map(|(model, keys)| format!("{model} : {{ {} }}", keys.join(", ")))
            .collect::<Vec<_>>()
            .join(", ");
        contract = contract.replace(
            "identities : Str, domains :",
            &format!("identities : Str, indexes : {{ {indexes} }}, domains :"),
        );
    }
    for tag in schema.domains.values() {
        for module in output_schema::annotation_imports(tag)? {
            if !contract.contains(&format!("import {module}\n")) {
                contract = format!("import {module}\n{contract}");
            }
        }
    }
    let error_type = format!(
        "{{ {} }}",
        catalog
            .errors
            .iter()
            .map(|name| format!("{name} : Api.ErrorDef"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    contract = contract.replace(
        "examples : List(Example)",
        &format!("errors : {error_type}, examples : List(Example)"),
    );
    source = source.replace("result = parsed.map_err(|_| \"invalid verification request\").and_then(|request| verify(product, request))", "result : Try(Str, Str)\n            result = match parsed {\n                Ok(request) => verify(product, request)\n                Err(_) => Err(\"invalid verification request\")\n            }");
    let mut failures = String::from("import pf.Failure\nimport AppIdentity\nErrors :: [].{\n");
    for name in &catalog.errors {
        failures.push_str(&format!("    {name} : Failure\n    {name} = Failure.{}define(AppIdentity.namespace.concat(\".{name}\"))\n", if admission { "admission_" } else { "" }));
    }
    failures.push_str("}\n");
    Ok(BTreeMap::from([
        ("AppContract.roc".into(), contract),
        ("Registry.roc".into(), source),
        (
            "Selectors.roc".into(),
            selectors(catalog, schema, outputs, admission)?,
        ),
        ("Errors.roc".into(), failures),
    ]))
}

pub fn field_type(kind: &Kind, schema: &Schema) -> Result<String> {
    Ok(match kind {
        Kind::Reference { target } | Kind::ModelReference { target, .. } => format!(
            "Ref({})",
            schema.models[target]
                .roc_type
                .as_deref()
                .context("nominal reference required")?
        ),
        Kind::TextDomain { roc_type } => roc_type.clone(),
        Kind::StandardText { domain } => format!("Text({domain})"),
        Kind::WebUrl => "WebUrl".into(),
        Kind::RowVersion => "RowVersion".into(),
        Kind::Cursor | Kind::IdCursor => "Cursor".into(),
        Kind::PageSize => "PageSize".into(),
        _ => kind.wire_type(false).into(),
    })
}

fn selector_field_imports(kind: &Kind, schema: &Schema) -> Result<BTreeSet<String>> {
    let mut imports = BTreeSet::new();
    let (wrapper, nominal) = match kind {
        Kind::Reference { target } | Kind::ModelReference { target, .. } => (
            Some("Ref"),
            Some(
                schema
                    .models
                    .get(target)
                    .and_then(|model| model.roc_type.as_deref())
                    .context("nominal reference required")?,
            ),
        ),
        Kind::TextDomain { roc_type } => (None, Some(roc_type.as_str())),
        Kind::StandardText { domain } => (Some("Text"), Some(domain.as_str())),
        Kind::WebUrl => (Some("WebUrl"), None),
        Kind::RowVersion => (Some("RowVersion"), None),
        Kind::Cursor | Kind::IdCursor => (Some("Cursor"), None),
        Kind::PageSize => (Some("PageSize"), None),
        // Optional text is a closed built-in union, not a pair of modules.
        Kind::Integer | Kind::Unsigned(_) | Kind::Text | Kind::Boolean | Kind::OptionalText => {
            (None, None)
        }
        // Structured inputs were built only from builtins until nominal collections
        // existed, so their annotations now have to contribute imports too.
        Kind::InputShape { roc_type, .. } => {
            imports.extend(
                output_schema::annotation_imports(roc_type)?
                    .into_iter()
                    .map(str::to_owned),
            );
            (None, None)
        }
    };
    if let Some(wrapper) = wrapper {
        imports.insert(wrapper.to_owned());
    }
    if let Some(nominal) = nominal {
        crate::schema::roc_type_name(nominal)?;
        imports.extend(
            output_schema::annotation_imports(nominal)?
                .into_iter()
                .map(str::to_owned),
        );
    }
    Ok(imports)
}

fn selectors(
    catalog: &registry::Catalog,
    schema: &Schema,
    outputs: &output_schema::Catalog,
    admission: bool,
) -> Result<String> {
    let mut entries = BTreeMap::new();
    let mut imports = BTreeSet::new();
    for (name, record) in &schema.models {
        let root = record.roc_type.as_deref().context("nominal model")?;
        imports.extend(
            output_schema::annotation_imports(root)?
                .into_iter()
                .map(str::to_owned),
        );
        for (field, kind) in &record.fields {
            imports.extend(selector_field_imports(kind, schema)?);
            entries.insert(
                format!("{name}_{field}"),
                (root.to_string(), field_type(kind, schema)?, field.clone()),
            );
        }
    }
    fn output_fields(
        shape: &output_schema::Type,
        prefix: &str,
        path: &str,
        root: &str,
        entries: &mut BTreeMap<String, (String, String, String)>,
        imports: &mut BTreeSet<String>,
    ) -> Result<()> {
        let record = match shape {
            output_schema::Type::IdPage(item) | output_schema::Type::CollectionPage(item) => {
                let join = |field: &str| {
                    if path.is_empty() {
                        field.to_string()
                    } else {
                        format!("{path}.{field}")
                    }
                };
                entries.insert(
                    format!("{prefix}_has_more"),
                    (root.into(), "Bool".into(), join("has_more")),
                );
                entries.insert(
                    format!("{prefix}_next_after"),
                    (root.into(), "Cursor".into(), join("next_after")),
                );
                imports.insert("Cursor".into());
                output_fields(
                    item,
                    &format!("{prefix}_items"),
                    &join("items[]"),
                    root,
                    entries,
                    imports,
                )?;
                return Ok(());
            }
            output_schema::Type::Record(fields) => fields,
            _ => return Ok(()),
        };
        for (field, shape) in record {
            let path = if path.is_empty() {
                field.clone()
            } else {
                format!("{path}.{field}")
            };
            let prefix = format!("{prefix}_{field}");
            let annotation = shape.annotation();
            imports.extend(
                output_schema::annotation_imports(&annotation)?
                    .into_iter()
                    .map(str::to_owned),
            );
            entries.insert(prefix.clone(), (root.into(), annotation, path.clone()));
            output_fields(shape, &prefix, &path, root, entries, imports)?;
        }
        Ok(())
    }
    for (name, op) in catalog.commands.iter().chain(catalog.queries.iter()) {
        let input = &schema.inputs[&op.input];
        let input_root = input.input_type()?;
        imports.extend(
            output_schema::annotation_imports(input_root)?
                .into_iter()
                .map(str::to_owned),
        );
        for (field, kind) in &input.fields {
            imports.extend(selector_field_imports(kind, schema)?);
            entries.insert(
                format!("{name}_input_{field}"),
                (
                    input_root.to_owned(),
                    field_type(kind, schema)?,
                    field.clone(),
                ),
            );
        }
        let output = &outputs[&op.output];
        imports.extend(
            output_schema::annotation_imports(&output.roc_type)?
                .into_iter()
                .map(str::to_owned),
        );
        output_fields(
            &output.shape,
            &format!("{name}_output"),
            "",
            &output.roc_type,
            &mut entries,
            &mut imports,
        )?;
    }
    let mut source = String::from("import pf.Path\n");
    for module in imports {
        source.push_str(&format!(
            "import {}{module}\n",
            if [
                "Ref",
                "RowVersion",
                "Cursor",
                "PageSize",
                "CollectionPage",
                "WebUrl",
                "Text",
                "TextMap",
                "TextSet"
            ]
            .contains(&module.as_str())
            {
                "pf."
            } else {
                ""
            }
        ));
    }
    source.push_str("Selectors :: [].{\n");
    for (name, (root, value, path)) in entries {
        source.push_str(&format!(
            "    {name} : Path({root}, {value})\n    {name} = Path.{}define(\"{path}\")\n",
            if admission { "admission_" } else { "" }
        ));
    }
    source.push_str("}\n");
    Ok(source)
}

pub fn storage_module(schema: &Schema) -> Result<String> {
    let mut imports = BTreeSet::new();
    let mut fields = Vec::new();
    for (name, model) in &schema.models {
        let roc_type = model
            .roc_type
            .as_deref()
            .context("nominal storage model required")?;
        imports.extend(output_schema::annotation_imports(roc_type)?);
        fields.push(format!("{name} : List({roc_type})"));
    }
    Ok(format!(
        "{}\nStorageContract :: [].{{\n    Tables : {{ {} }}\n}}\n",
        imports
            .into_iter()
            .map(|module| format!("import {module}\n"))
            .collect::<String>(),
        fields.join(", ")
    ))
}

#[cfg(test)]
mod selector_tests {
    use super::*;

    #[test]
    fn required_all_rows_metadata_defaults_empty_and_preserves_existing_wire() -> Result<()> {
        let (_, _, contracts) = shared_failure_fixture()?;
        for operation in contracts.values() {
            assert!(operation.required_all_rows.is_empty());
            let wire = serde_json::to_value(operation)?;
            assert!(wire.get("required_all_rows").is_none());
            let decoded: Operation = serde_json::from_value(wire.clone())?;
            assert_eq!(serde_json::to_value(decoded)?, wire);
        }
        Ok(())
    }

    #[test]
    fn required_all_rows_admission_checks_known_distinct_bounded_models() -> Result<()> {
        let (_, mut schema, _) = fixture();
        let (_, _, contracts) = shared_failure_fixture()?;
        let mut operation = contracts["create"].clone();
        operation.validate_required_all_rows(&schema)?;
        operation.required_all_rows = vec!["rows".into()];
        operation.validate_required_all_rows(&schema)?;
        for (requirements, message) in [
            (vec!["unknown".into()], "unknown unfiltered read model"),
            (vec!["".into()], "unknown unfiltered read model"),
            (
                vec!["rows".into(), "rows".into()],
                "duplicate unfiltered read requirement",
            ),
        ] {
            operation.required_all_rows = requirements;
            assert_eq!(
                operation
                    .validate_required_all_rows(&schema)
                    .unwrap_err()
                    .to_string(),
                message
            );
        }
        let row = schema.models["rows"].clone();
        operation.required_all_rows = (0..64).map(|index| format!("rows_{index}")).collect();
        for name in &operation.required_all_rows {
            schema.models.insert(name.clone(), row.clone());
        }
        operation.validate_required_all_rows(&schema)?;
        operation.required_all_rows.push("rows".into());
        assert_eq!(
            operation
                .validate_required_all_rows(&schema)
                .unwrap_err()
                .to_string(),
            "unfiltered read requirement budget"
        );
        Ok(())
    }

    #[test]
    fn required_all_rows_generation_covers_command_and_query_without_replacing_errors() -> Result<()>
    {
        let (mut catalog, schema, outputs) = fixture();
        catalog
            .queries
            .insert("preview".into(), catalog.commands["update"].clone());
        for admission in [false, true] {
            let generated = modules(&catalog, &schema, &outputs, "", admission)?;
            for operation in ["update", "preview"] {
                let metadata = generated["Registry.roc"]
                    .lines()
                    .find(|line| {
                        line.contains(&format!(
                            "required_all_rows: product.operations.{operation}.required_all_rows()"
                        ))
                    })
                    .context("operation read requirements missing")?;
                assert!(metadata.contains("errors: contract.errors.map(|failure| failure.code())"));
            }
        }
        Ok(())
    }

    #[test]
    fn created_updates_require_explicit_fields_and_exclude_ambiguous_update_bounds() -> Result<()> {
        let (_, schema, _) = fixture();
        let operation = crate::artifact::Operation {
            name: "update".into(),
            kind: "command".into(),
            input_type: "update".into(),
            output_type: "result".into(),
        };
        let artifact: Artifact = serde_json::from_value(serde_json::json!({
            "format":13,"roc_version":"test","worker_digest":"test","schema_digest":"test",
            "schema":schema,"operations":[operation],"sources":{},"admission":"test"
        }))?;
        let effect = Effect {
            kind: "update_created".into(),
            model: "rows".into(),
            fields: vec!["note".into()],
            command: String::new(),
        };
        let execution = Execution {
            effects: vec![effect.clone()],
            ..Execution::default()
        };
        execution.validate(&artifact, &operation, &artifact.schema.inputs["update"])?;
        for fields in [
            vec![],
            vec!["unknown".into()],
            vec!["note".into(), "note".into()],
        ] {
            let invalid = Execution {
                effects: vec![Effect {
                    fields,
                    ..effect.clone()
                }],
                ..execution.clone()
            };
            assert!(
                invalid
                    .validate(&artifact, &operation, &artifact.schema.inputs["update"])
                    .is_err()
            );
        }
        for kinds in [
            ["update_created", "update_created"],
            ["update", "update_created"],
            ["update_created", "update"],
        ] {
            let invalid = Execution {
                effects: kinds
                    .map(|kind| Effect {
                        kind: kind.into(),
                        ..effect.clone()
                    })
                    .into(),
                ..execution.clone()
            };
            assert_eq!(
                invalid
                    .validate(&artifact, &operation, &artifact.schema.inputs["update"])
                    .unwrap_err()
                    .to_string(),
                "duplicate command effect"
            );
        }
        let query = crate::artifact::Operation {
            kind: "query".into(),
            ..operation.clone()
        };
        assert!(
            execution
                .validate(&artifact, &query, &artifact.schema.inputs["update"])
                .is_err()
        );
        Ok(())
    }

    fn shared_failure_fixture() -> Result<(
        Failure,
        Vec<crate::artifact::Operation>,
        BTreeMap<String, Operation>,
    )> {
        let operations: Vec<crate::artifact::Operation> = ["create", "preview"]
            .map(|name| crate::artifact::Operation {
                name: name.into(),
                kind: if name == "create" { "command" } else { "query" }.into(),
                input_type: format!("{name}_input"),
                output_type: "result".into(),
            })
            .into();
        let mut contracts = BTreeMap::new();
        for operation in &operations {
            contracts.insert(operation.name.clone(), serde_json::from_value(serde_json::json!({
                "intent": {"target":{"operation":operation.name,"input_type":operation.input_type,"output_type":operation.output_type},
                    "title":"Example", "usage":{"purpose":"Example", "use_when":[], "avoid_when":[], "preconditions":[], "effects":[], "result":"Example"},
                    "inputs":[], "outputs":[], "input_sources":[], "follow_ups":[]},
                "request_example":"{}", "response_example":"{}", "deprecated":false,
                "execution":{"internal":false,"model":"","id_field":"","version_field":"","effects":[]},
                "errors":["app:example.invalid_input"]
            }))?);
        }
        let failure = Failure {
            code: "app:example.invalid_input".into(),
            description: "Invalid business input.".into(),
            recovery: "Correct the input.".into(),
            operation: operation_metadata::Target {
                operation: "create".into(),
                input_type: "create_input".into(),
                output_type: "result".into(),
            },
            additional_operations: vec![operation_metadata::Target {
                operation: "preview".into(),
                input_type: "preview_input".into(),
                output_type: "result".into(),
            }],
        };
        Ok((failure, operations, contracts))
    }

    #[test]
    fn shared_errors_require_exact_typed_cases_for_every_declaring_operation() -> Result<()> {
        let (failure, operations, contracts) = shared_failure_fixture()?;
        failure.validate_targets(&operations, &contracts)?;
        validate_error_declarations(
            &contracts,
            &BTreeMap::from([(failure.code.clone(), failure.clone())]),
        )?;
        let keys: Vec<_> = failure
            .targets()
            .map(|target| failure.verification_key(target))
            .collect();
        assert_eq!(
            keys,
            [
                "app:example.invalid_input@create",
                "app:example.invalid_input@preview"
            ]
        );
        for mutation in [
            "missing",
            "duplicate",
            "unknown",
            "wrong_input",
            "wrong_output",
        ] {
            let mut changed = failure.clone();
            match mutation {
                "missing" => changed.additional_operations.clear(),
                "duplicate" => changed
                    .additional_operations
                    .push(changed.operation.clone()),
                "unknown" => changed.additional_operations[0].operation = "unknown".into(),
                "wrong_input" => {
                    changed.additional_operations[0].input_type = "create_input".into()
                }
                "wrong_output" => changed.additional_operations[0].output_type = "other".into(),
                _ => unreachable!(),
            }
            let admitted = changed
                .validate_targets(&operations, &contracts)
                .and_then(|_| {
                    validate_error_declarations(
                        &contracts,
                        &BTreeMap::from([(changed.code.clone(), changed)]),
                    )
                });
            assert!(admitted.is_err(), "{mutation} verification case");
        }
        let mut unlisted = contracts.clone();
        unlisted.get_mut("preview").unwrap().errors.clear();
        assert!(failure.validate_targets(&operations, &unlisted).is_err());
        let mut duplicate = contracts.clone();
        duplicate
            .get_mut("create")
            .unwrap()
            .errors
            .push(failure.code.clone());
        assert!(
            validate_error_declarations(
                &duplicate,
                &BTreeMap::from([(failure.code.clone(), failure)])
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn singleton_error_metadata_and_verification_keys_remain_compatible() -> Result<()> {
        let wire = serde_json::json!({"code":"app:example.invalid_input", "description":"Invalid.", "recovery":"Correct it.",
            "operation":{"operation":"create","input_type":"input","output_type":"output"}});
        let failure: Failure = serde_json::from_value(wire.clone())?;
        assert_eq!(failure.targets().count(), 1);
        assert_eq!(
            failure.verification_key(&failure.operation),
            "app:example.invalid_input"
        );
        assert_eq!(serde_json::to_value(failure)?, wire);
        Ok(())
    }

    #[test]
    fn error_dispatch_selects_operation_and_code_and_empty_metadata_stays_fallible() -> Result<()> {
        let (mut catalog, schema, outputs) = fixture();
        catalog.errors.push("invalid_input".into());
        for admission in [false, true] {
            let generated = modules(&catalog, &schema, &outputs, "", admission)?;
            let registry = &generated["Registry.roc"];
            assert!(registry.contains("request.operation == \"${Errors.invalid_input.code()}@${scenario.operation.operation}\""));
            assert!(registry.contains(
                "scenarios.len() == 1 and request.operation == Errors.invalid_input.code()"
            ));
            assert!(registry.contains(
                "Api.error_metadata(Errors.invalid_input.code(), product.errors.invalid_input)?"
            ));
            let empty = registry
                .lines()
                .find(|line| line.contains("empty = {"))
                .unwrap();
            assert!(empty.contains("errors: []"));
            assert!(!empty.contains("error_metadata"));
        }
        Ok(())
    }

    #[test]
    fn structured_input_docs_require_descriptions_for_nested_records_and_items() -> Result<()> {
        use output_schema::Type;
        let shape = Type::List(Box::new(Type::Record(BTreeMap::from([
            ("key".into(), Type::String),
            ("value".into(), Type::String),
        ]))));
        let nested = Type::Record(BTreeMap::from([("enabled".into(), Type::Boolean)]));
        let input = Record {
            fields: BTreeMap::from([
                (
                    "attributes".into(),
                    Kind::InputShape {
                        roc_type: shape.annotation(),
                        shape,
                    },
                ),
                (
                    "settings".into(),
                    Kind::InputShape {
                        roc_type: nested.annotation(),
                        shape: nested,
                    },
                ),
                ("reason".into(), Kind::Text),
            ]),
            roc_type: Some("Requests.Update".into()),
            identity: None,
        };
        assert_eq!(
            input_docs(&input),
            "{ attributes : { description : Str, each : { key : Str, value : Str } }, reason : Str, settings : { description : Str, fields : { enabled : Str } } }"
        );
        let schema = crate::operation_catalog::record_schema(&input);
        let expression = fields_expression(&schema, "contract.inputs");
        for accessor in [
            "attributes.description",
            "attributes.each.key",
            "attributes.each.value",
            "reason",
            "settings.description",
            "settings.fields.enabled",
        ] {
            assert!(expression.contains(&format!("description: contract.inputs.{accessor} }}")));
        }
        let described = [
            "attributes",
            "attributes[].key",
            "attributes[].value",
            "reason",
            "settings",
            "settings.enabled",
        ]
        .map(|path| api_docs::Field {
            path: path.into(),
            description: "Documented.".into(),
        });
        require_fields(&described, &schema)?;
        assert!(require_fields(&described[..5], &schema).is_err());
        Ok(())
    }

    fn fixture() -> (registry::Catalog, Schema, output_schema::Catalog) {
        let catalog = registry::Catalog {
            unified: true,
            commands: BTreeMap::from([(
                "update".into(),
                registry::Operation {
                    input: "update".into(),
                    output: "result".into(),
                },
            )]),
            ..registry::Catalog::default()
        };
        let schema = Schema {
            models: BTreeMap::from([(
                "rows".into(),
                Record {
                    fields: BTreeMap::from([("note".into(), Kind::OptionalText)]),
                    roc_type: Some("Models.Row".into()),
                    identity: None,
                },
            )]),
            inputs: BTreeMap::from([(
                "update".into(),
                Record {
                    fields: BTreeMap::from([
                        ("note".into(), Kind::OptionalText),
                        (
                            "row".into(),
                            Kind::ModelReference {
                                target: "rows".into(),
                                prefix: "row".into(),
                            },
                        ),
                        ("version".into(), Kind::RowVersion),
                    ]),
                    roc_type: Some("Requests.Update".into()),
                    identity: None,
                },
            )]),
            foreign_keys: vec![],
            indexes: vec![],
            domains: BTreeMap::new(),
        };
        let outputs = BTreeMap::from([(
            "result".into(),
            output_schema::Contract {
                roc_type: "Views.Result".into(),
                shape: output_schema::Type::Record(BTreeMap::from([(
                    "page".into(),
                    output_schema::Type::IdPage(Box::new(output_schema::Type::Record(
                        BTreeMap::from([
                            (
                                "row".into(),
                                output_schema::Type::ModelReference {
                                    roc_type: "Models.Row".into(),
                                    prefix: "row".into(),
                                },
                            ),
                            (
                                "title".into(),
                                output_schema::Type::StandardText {
                                    domain: "Labels.Title".into(),
                                },
                            ),
                        ]),
                    ))),
                )])),
            },
        )]);
        (catalog, schema, outputs)
    }

    #[test]
    fn optional_model_and_input_selectors_generate_without_union_imports() -> Result<()> {
        let (catalog, schema, outputs) = fixture();
        for admission in [false, true] {
            let generated = modules(&catalog, &schema, &outputs, "", admission)?;
            let source = &generated["Selectors.roc"];
            assert!(source.contains("rows_note : Path(Models.Row, [None, Some(Str)])"));
            assert!(
                source.contains("update_input_note : Path(Requests.Update, [None, Some(Str)])")
            );
            let constructor = if admission {
                "admission_define"
            } else {
                "define"
            };
            assert!(source.contains(&format!("rows_note = Path.{constructor}(\"note\")")));
            assert!(source.contains(&format!("update_input_note = Path.{constructor}(\"note\")")));
            for module in [
                "Models",
                "Requests",
                "Views",
                "Labels",
                "pf.Ref",
                "pf.Text",
                "pf.RowVersion",
                "pf.CollectionPage",
                "pf.Cursor",
            ] {
                assert!(
                    source.contains(&format!("import {module}\n")),
                    "missing {module}"
                );
            }
            assert!(!source.contains("import None\n"));
            assert!(!source.contains("import Some\n"));
            assert!(source.contains(
                "update_output_page_items_title : Path(Views.Result, Text(Labels.Title))"
            ));
        }
        Ok(())
    }

    #[test]
    fn typed_selector_imports_do_not_broaden_output_annotation_admission() {
        let (catalog, schema, outputs) = fixture();
        assert!(
            output_schema::annotation_imports("[None, Some(Str)]")
                .unwrap()
                .is_empty()
        );
        let mut supported = outputs.clone();
        supported.insert(
            "result".into(),
            output_schema::Contract {
                roc_type: "[None, Some(Str)]".into(),
                shape: output_schema::Type::OptionalText,
            },
        );
        for admission in [false, true] {
            let source = selectors(&catalog, &schema, &supported, admission).unwrap();
            assert!(!source.contains("import None\n"));
            assert!(!source.contains("import Some\n"));
        }
        // Import extraction is not a type/shape proof. Arbitrary unions are
        // rejected by output metadata extraction; checked_contract rejects a
        // catalog whose annotation/shape pair differs from that compiler proof.
        for malicious in [
            "Views.Result\nimport Evil",
            "Views.Result -> Str",
            "[None, Some(Str)]\nimport Evil",
            "[None, Some(Str)] -> Str",
            "Json",
            "Output",
            "Outputs",
        ] {
            let mut forged = outputs.clone();
            forged.get_mut("result").unwrap().roc_type = malicious.into();
            for admission in [false, true] {
                assert!(selectors(&catalog, &schema, &forged, admission).is_err());
            }
        }
        for malicious in ["Title\nimport Evil", "[None, Some(Str)]", "Text(Title)"] {
            let mut forged = schema.clone();
            forged.inputs.get_mut("update").unwrap().fields.insert(
                "note".into(),
                Kind::TextDomain {
                    roc_type: malicious.into(),
                },
            );
            for admission in [false, true] {
                assert!(selectors(&catalog, &forged, &outputs, admission).is_err());
            }
        }
    }

    /// Read `Product.Contract`'s field names from the SDK, which is the only place
    /// that defines them.
    fn product_contract_fields() -> Vec<String> {
        let source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/runtime/Product.roc"),
        )
        .expect("the SDK defines Product");
        let body = source
            .split_once("Contract : {")
            .expect("Product declares a Contract")
            .1
            .split_once('}')
            .expect("the Contract record closes")
            .0;
        let fields: Vec<String> = body
            .lines()
            .filter_map(|line| line.split_once(':'))
            .map(|(name, _)| name.trim().to_owned())
            .filter(|name| !name.is_empty())
            .collect();
        assert!(
            fields.len() >= 7 && fields.contains(&"schedules".to_owned()),
            "Contract fields were not parsed: {fields:?}"
        );
        fields
    }

    /// The record literal passed to `Product.step`, by balanced braces.
    fn contract_literals(generated: &str) -> Vec<String> {
        let mut found = Vec::new();
        for marker in ["Product.step({", "Product.admission_step({"] {
            let mut rest = generated;
            while let Some(at) = rest.find(marker) {
                let open = at + marker.len() - 1;
                let mut depth = 0;
                let mut end = open;
                for (offset, character) in rest[open..].char_indices() {
                    match character {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                end = open + offset;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                found.push(rest[open..=end].to_owned());
                rest = &rest[end..];
            }
        }
        found
    }

    /// A field added to `Product.Contract` must reach every place that builds one.
    ///
    /// This has broken twice — once for `schedules`, once for `ingress` — and both
    /// times the compiler did catch it, at the end of a full build, as a missing
    /// field in generated Roc that names no cause. Three separate sites construct a
    /// contract: two generators and one hand-written test fixture, and one of the
    /// generators builds its literal by string replacement, which reports nothing
    /// when it matches nothing.
    ///
    /// So this enumerates from `Product.roc` — the only definition of the field
    /// list — rather than from any remembered copy of it, and checks the generated
    /// output rather than the generator's source text, so a site that stops being
    /// reached is caught as well as one that is misspelled.
    #[test]
    fn a_field_added_to_the_product_contract_reaches_every_site_that_builds_one() -> Result<()> {
        let fields = product_contract_fields();
        let (catalog, schema, outputs) = fixture();
        let mut inspected = 0;
        for admission in [false, true] {
            let generated = modules(&catalog, &schema, &outputs, "", admission)?;
            let registry_only = catalog.modules(&schema, &outputs, admission)?;
            for source in generated.values().chain(registry_only.values()) {
                for literal in contract_literals(source) {
                    inspected += 1;
                    for field in &fields {
                        assert!(
                            literal.contains(&format!("{field}:")),
                            "a generated Product.Contract omits {field}: {literal}"
                        );
                    }
                }
            }
        }
        // The hand-written fixture in the page SDK test is the third site, and the
        // one with no generator to keep it honest.
        let page_sdk = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/page_sdk.rs"),
        )?;
        let fixture_literal = page_sdk
            .lines()
            .find(|line| line.contains("product = {{ namespace:"))
            .context("the page SDK fixture builds a Product.Contract")?;
        inspected += 1;
        for field in &fields {
            assert!(
                fixture_literal.contains(&format!("{field}:")),
                "the page SDK contract fixture omits {field}"
            );
        }
        // A gate that found no literal would pass for exactly the case it exists to
        // catch: a site that stopped being generated at all.
        assert!(
            inspected >= 3,
            "only {inspected} contract literals were inspected"
        );
        Ok(())
    }
}
