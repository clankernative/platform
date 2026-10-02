use anyhow::{Context, Result, ensure};
use day2::{
    artifact::{Artifact, LoadedArtifact, Page},
    output_schema::Type,
    schema::{Kind, Record},
};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, fs, path::Path};

const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_WORKER_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CHECKED_TYPES_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EXPORT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Export<'a> {
    schema_version: u32,
    app: &'a str,
    routes: Vec<RouteExport>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RouteExport {
    name: String,
    operation: String,
    path: String,
    template: String,
    live: bool,
    input_schema: Value,
    query_defaults: Map<String, Value>,
    output_schema: Value,
    template_context_schema: Value,
    example: Example,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Example {
    input: Value,
    output: Value,
    template_context: Value,
}

pub fn export_file(artifact_directory: &Path, output: Option<&Path>) -> Result<()> {
    let metadata = fs::symlink_metadata(artifact_directory)?;
    ensure!(
        metadata.file_type().is_dir(),
        "artifact path must be a directory"
    );
    let artifact_directory = artifact_directory.canonicalize()?;
    for (file, maximum, label) in [
        ("artifact.json", MAX_ARTIFACT_BYTES, "artifact"),
        ("worker", MAX_WORKER_BYTES, "worker"),
        (
            "checked-types.json",
            MAX_CHECKED_TYPES_BYTES,
            "checked types",
        ),
    ] {
        let path = artifact_directory.join(file);
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.file_type().is_file() && metadata.len() <= maximum,
            "page contract {label} file type or byte budget invalid"
        );
    }
    if let Some(path) = output {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let destination = parent
            .canonicalize()?
            .join(path.file_name().context("output filename required")?);
        ensure!(
            !destination.starts_with(&artifact_directory),
            "page contract output must not overwrite artifact contents"
        );
        if let Ok(metadata) = fs::symlink_metadata(&destination) {
            ensure!(
                metadata.file_type().is_file(),
                "output path must be a regular file"
            );
        }
    }
    let artifact = LoadedArtifact::load(&artifact_directory)?;
    let document = export(&artifact.contract())?;
    let bytes = serde_json::to_vec_pretty(&document)?;
    ensure!(
        bytes.len() <= MAX_EXPORT_BYTES,
        "page contract export byte budget exceeded"
    );
    if let Some(path) = output {
        fs::write(path, bytes)?;
    } else {
        println!("{}", String::from_utf8(bytes)?);
    }
    Ok(())
}

fn export(artifact: &Artifact) -> Result<Export<'_>> {
    ensure!(
        artifact.format >= 7,
        "page contracts require explicit admitted routes"
    );
    let definition = artifact
        .app_contract
        .as_ref()
        .context("page contract export requires the admitted app contract")?;
    let routes = day2::routing::Catalog::from_artifact(artifact)?;
    let mut pages = artifact.pages.iter().collect::<Vec<_>>();
    pages.sort_by(|left, right| left.name.cmp(&right.name));
    let mut exported = Vec::with_capacity(pages.len());
    for page in pages {
        exported.push(export_page(artifact, definition, &routes, page)?);
    }
    Ok(Export {
        schema_version: 1,
        app: &artifact.namespace,
        routes: exported,
    })
}

fn export_page(
    artifact: &Artifact,
    definition: &day2::app_contract::Definition,
    routes: &day2::routing::Catalog,
    page: &Page,
) -> Result<RouteExport> {
    let operation = artifact
        .operations
        .iter()
        .find(|operation| operation.name == page.operation && operation.kind == "query")
        .with_context(|| format!("route {} has no registered query", page.name))?;
    let input = artifact
        .schema
        .inputs
        .get(&operation.input_type)
        .context("page query input schema missing")?;
    let output = artifact
        .outputs
        .get(&operation.output_type)
        .context("page query output schema missing")?;
    let contract = definition
        .operations
        .get(&operation.name)
        .with_context(|| format!("page query contract missing: {}", operation.name))?;
    ensure!(
        contract.intent.target.input_type == operation.input_type
            && contract.intent.target.output_type == operation.output_type,
        "page query contract handles differ from admitted operation"
    );
    ensure!(
        !contract.request_example.is_empty() && !contract.response_example.is_empty(),
        "page query requires typed input and output examples"
    );
    let example_input: Value = serde_json::from_str(&contract.request_example)
        .context("invalid page query example input")?;
    let example_output: Value = serde_json::from_str(&contract.response_example)
        .context("invalid page query example output")?;
    input
        .validate_input(&example_input)
        .context("page query example input does not match its contract")?;
    output
        .shape
        .validate_value(&example_output)
        .context("page query example output does not match its contract")?;
    let mut input_schema = record_schema(input)?;
    day2::api_docs::annotate(&mut input_schema, &contract.intent.inputs)?;
    let mut output_schema = day2::operation_catalog::output_schema(&output.shape);
    day2::api_docs::annotate(&mut output_schema, &contract.intent.outputs)?;
    add_output_kinds(&mut output_schema, &output.shape)?;
    let template_context_schema = template_context_schema(&page.name, output_schema.clone());
    let mut context_fields = Map::new();
    context_fields.insert(page.name.clone(), example_output.clone());
    context_fields.insert("company".into(), json!({"name":"Example Company"}));
    let route = routes.route(&page.name)?;
    ensure!(
        route.path == page.path,
        "compiled route path differs from admitted page"
    );
    Ok(RouteExport {
        name: page.name.clone(),
        operation: page.operation.clone(),
        path: page.path.clone(),
        template: format!("ui/{}", page.template),
        live: page.live,
        input_schema,
        query_defaults: route.defaults.clone(),
        output_schema,
        template_context_schema,
        example: Example {
            input: example_input,
            output: example_output,
            template_context: Value::Object(context_fields),
        },
    })
}

fn template_context_schema(page_name: &str, output_schema: Value) -> Value {
    let mut properties = Map::new();
    properties.insert(page_name.to_owned(), output_schema);
    properties.insert(
        "company".into(),
        json!({
            "kind":"record",
            "type":"object",
            "required":["name"],
            "additionalProperties":false,
            "properties":{"name":{"kind":"string","type":"string","description":"Instance branding; supplied outside the app artifact."}}
        }),
    );
    json!({
        "kind":"record",
        "type":"object",
        "required":[page_name,"company"],
        "additionalProperties":false,
        "properties":properties
    })
}

fn record_schema(record: &Record) -> Result<Value> {
    let properties = record
        .fields
        .iter()
        .map(|(name, kind)| Ok((name.clone(), input_kind_schema(kind)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(json!({
        "kind": "record",
        "type": "object",
        "required": record.fields.keys().collect::<Vec<_>>(),
        "additionalProperties": false,
        "properties": properties,
    }))
}

fn input_kind_schema(kind: &Kind) -> Result<Value> {
    let mut schema = day2::operation_catalog::input_schema(kind);
    match kind {
        Kind::Integer => schema["kind"] = json!("integer"),
        Kind::Unsigned(unsigned) => {
            schema["kind"] = json!("unsigned_integer");
            schema["rocType"] = json!(unsigned.roc_type());
        }
        Kind::RowVersion => schema["kind"] = json!("row_version"),
        Kind::Text | Kind::TextDomain { .. } | Kind::StandardText { .. } | Kind::WebUrl => {
            schema["kind"] = json!("string")
        }
        Kind::Boolean => schema["kind"] = json!("boolean"),
        Kind::OptionalText => schema["kind"] = json!("option"),
        Kind::Reference { target } => {
            schema["kind"] = json!("ref");
            schema["target"] = json!(target);
        }
        Kind::ModelReference { target, prefix } => {
            schema["kind"] = json!("ref");
            schema["target"] = json!(target);
            schema["prefix"] = json!(prefix);
        }
        Kind::Cursor => schema["kind"] = json!("cursor"),
        Kind::IdCursor => schema["kind"] = json!("id_cursor"),
        Kind::PageSize => schema["kind"] = json!("page_size"),
        Kind::InputShape { shape, .. } => {
            schema["kind"] = json!("structured");
            add_output_kinds(&mut schema, shape)?;
        }
    }
    Ok(schema)
}

fn add_output_kinds(schema: &mut Value, shape: &Type) -> Result<()> {
    match shape {
        Type::String => schema["kind"] = json!("string"),
        Type::OptionalText => schema["kind"] = json!("option"),
        Type::StandardText { domain } => {
            schema["kind"] = json!("string");
            schema["domain"] = json!(domain);
        }
        Type::Integer => schema["kind"] = json!("integer"),
        Type::Unsigned(unsigned) => {
            schema["kind"] = json!("unsigned_integer");
            schema["rocType"] = json!(unsigned.roc_type());
        }
        Type::RowVersion => schema["kind"] = json!("row_version"),
        Type::ModelReference { roc_type, prefix } => {
            schema["kind"] = json!("ref");
            schema["target"] = json!(roc_type);
            schema["prefix"] = json!(prefix);
        }
        Type::Boolean => schema["kind"] = json!("boolean"),
        Type::Record(fields) => {
            schema["kind"] = json!("record");
            let properties = schema
                .get_mut("properties")
                .and_then(Value::as_object_mut)
                .context("record output schema properties missing")?;
            ensure!(
                properties.len() == fields.len(),
                "record output schema field mismatch"
            );
            for (name, field) in fields {
                let property = properties
                    .get_mut(name)
                    .with_context(|| format!("output schema field missing: {name}"))?;
                add_output_kinds(property, field)?;
            }
        }
        Type::List(item) => {
            schema["kind"] = json!("list");
            let item_schema = schema
                .get_mut("items")
                .context("list output schema item missing")?;
            add_output_kinds(item_schema, item)?;
        }
        Type::Map(item) => {
            schema["kind"] = json!("map");
            let item_schema = schema
                .pointer_mut("/properties/entries/items/properties/value")
                .context("map output schema value missing")?;
            add_output_kinds(item_schema, item)?;
        }
        Type::Set => schema["kind"] = json!("set"),
        Type::CollectionPage(item) | Type::IdPage(item) => {
            schema["kind"] = json!("collection_page");
            let item_schema = schema
                .pointer_mut("/properties/items/items")
                .context("collection page output schema item missing")?;
            add_output_kinds(item_schema, item)?;
            schema["properties"]["has_more"]["kind"] = json!("boolean");
            schema["properties"]["next_after"]["kind"] =
                json!(if matches!(shape, Type::IdPage(_)) {
                    "id_cursor"
                } else {
                    "cursor"
                });
        }
        Type::Cursor => schema["kind"] = json!("cursor"),
        Type::IdCursor => schema["kind"] = json!("id_cursor"),
        Type::PageSize => schema["kind"] = json!("page_size"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn output_kinds_preserve_typed_scalars_and_nested_list_shapes() -> Result<()> {
        let shape = Type::Record(BTreeMap::from([
            ("revision".into(), Type::RowVersion),
            (
                "projects".into(),
                Type::CollectionPage(Box::new(Type::Record(BTreeMap::from([
                    (
                        "id".into(),
                        Type::ModelReference {
                            roc_type: "Models.Project".into(),
                            prefix: "prj".into(),
                        },
                    ),
                    ("name".into(), Type::String),
                ])))),
            ),
        ]));
        let mut schema = day2::operation_catalog::output_schema(&shape);
        add_output_kinds(&mut schema, &shape)?;
        assert_eq!(schema["properties"]["revision"]["kind"], "row_version");
        assert_eq!(
            schema["properties"]["projects"]["properties"]["items"]["items"]["properties"]["id"]["kind"],
            "ref"
        );
        assert_eq!(
            schema["properties"]["projects"]["properties"]["items"]["items"]["properties"]["id"]["target"],
            "Models.Project"
        );
        Ok(())
    }

    #[test]
    fn export_projects_admitted_routes_defaults_descriptions_and_examples() -> Result<()> {
        let schema = day2::schema::Schema {
            models: BTreeMap::new(),
            inputs: BTreeMap::from([(
                "Input".into(),
                Record {
                    fields: BTreeMap::from([(
                        "limit".into(),
                        Kind::Unsigned(day2::numeric::Unsigned::U64),
                    )]),
                    roc_type: Some("Input".into()),
                    identity: None,
                },
            )]),
            foreign_keys: Vec::new(),
            indexes: Vec::new(),
            rollups: Vec::new(),
            domains: BTreeMap::new(),
        };
        let intent = day2::operation_metadata::Entry {
            target: day2::operation_metadata::Target {
                operation: "gallery.list".into(),
                input_type: "Input".into(),
                output_type: "Output".into(),
            },
            title: "List items".into(),
            usage: day2::operation_metadata::Usage {
                purpose: "List items.".into(),
                use_when: Vec::new(),
                avoid_when: Vec::new(),
                preconditions: Vec::new(),
                effects: Vec::new(),
                result: "Items.".into(),
            },
            inputs: vec![day2::api_docs::Field {
                path: "limit".into(),
                description: "Maximum items.".into(),
            }],
            outputs: vec![day2::api_docs::Field {
                path: "title".into(),
                description: "Display title.".into(),
            }],
            input_sources: Vec::new(),
            follow_ups: Vec::new(),
        };
        let contract = day2::app_contract::Operation {
            intent,
            request_example: r#"{"limit":2}"#.into(),
            response_example: r#"{"title":"Example"}"#.into(),
            deprecated: false,
            export_version: 0,
            execution: Default::default(),
            credential_access: Default::default(),
            errors: Vec::new(),
            required_all_rows: Vec::new(),
        };
        let artifact = Artifact {
            format: day2::artifact::CURRENT_FORMAT,
            app_contract: Some(day2::app_contract::Definition {
                operations: BTreeMap::from([("gallery.list".into(), contract)]),
                presentation: day2::app_contract::Presentation {
                    stylesheet: String::new(),
                    script: String::new(),
                },
                identities: String::new(),
                invariants: BTreeMap::new(),
                domains: BTreeMap::new(),
                errors: BTreeMap::new(),
            }),
            export_manifest: None,
            imports: None,
            namespace: "gallery".into(),
            declarations: day2::registry::Catalog::default(),
            credential_declarations: Vec::new(),
            credential_manifest: Vec::new(),
            connection_declarations: Vec::new(),
            checked_types_digest: String::new(),
            roc_version: String::new(),
            worker_digest: String::new(),
            schema_digest: schema.hash()?,
            schema,
            identities: day2::identity::Registry::default(),
            operations: vec![day2::artifact::Operation {
                name: "gallery.list".into(),
                kind: "query".into(),
                input_type: "Input".into(),
                output_type: "Output".into(),
            }],
            properties: Vec::new(),
            pages: vec![Page {
                name: "home".into(),
                title: "Home".into(),
                operation: "gallery.list".into(),
                defaults: r#"{"limit":1}"#.into(),
                path: "/".into(),
                template: "pages/home.html".into(),
                input_type: "Input".into(),
                output_type: "Output".into(),
                live: true,
                live_refresh_ms: 0,
            }],
            schedules: Vec::new(),
            ingress: Vec::new(),
            redirects: Vec::new(),
            assets: Default::default(),
            web_resources: Default::default(),
            outputs: BTreeMap::from([(
                "Output".into(),
                day2::output_schema::Contract {
                    shape: Type::Record(BTreeMap::from([("title".into(), Type::String)])),
                    roc_type: "Output".into(),
                },
            )]),
            templates: Default::default(),
            api_docs: BTreeMap::new(),
            operation_metadata: BTreeMap::new(),
            sources: BTreeMap::new(),
            admission: "local-spike-only".into(),
        };
        let serialized = serde_json::to_value(export(&artifact)?)?;
        assert_eq!(serialized["schemaVersion"], 1);
        assert_eq!(serialized["routes"][0]["operation"], "gallery.list");
        assert_eq!(serialized["routes"][0]["template"], "ui/pages/home.html");
        assert_eq!(serialized["routes"][0]["queryDefaults"]["limit"], 1);
        assert_eq!(
            serialized["routes"][0]["inputSchema"]["properties"]["limit"]["description"],
            "Maximum items."
        );
        assert_eq!(
            serialized["routes"][0]["outputSchema"]["properties"]["title"]["description"],
            "Display title."
        );
        assert_eq!(serialized["routes"][0]["example"]["input"]["limit"], 2);
        assert_eq!(
            serialized["routes"][0]["example"]["output"]["title"],
            "Example"
        );
        assert_eq!(
            serialized["routes"][0]["example"]["templateContext"]["home"]["title"],
            "Example"
        );
        assert_eq!(
            serialized["routes"][0]["templateContextSchema"]["properties"]["company"]["kind"],
            "record"
        );
        Ok(())
    }

    #[test]
    fn record_schema_orders_fields_and_keeps_refs_distinct() -> Result<()> {
        let record = Record {
            fields: BTreeMap::from([
                (
                    "project".into(),
                    Kind::Reference {
                        target: "Models.Project".into(),
                    },
                ),
                ("theme".into(), Kind::Unsigned(day2::numeric::Unsigned::U64)),
            ]),
            roc_type: Some("Input".into()),
            identity: None,
        };
        let schema = record_schema(&record)?;
        assert_eq!(schema["required"][0], "project");
        assert_eq!(schema["properties"]["project"]["kind"], "ref");
        assert_eq!(schema["properties"]["project"]["target"], "Models.Project");
        assert_eq!(schema["properties"]["theme"]["kind"], "unsigned_integer");
        Ok(())
    }
}
