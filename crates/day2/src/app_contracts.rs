use crate::{
    artifact::{Artifact, LoadedArtifact, Page},
    output_schema::Type,
    schema::{Kind, Record},
};
use anyhow::{Context, Result, ensure};
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
    kind: &'static str,
    app: &'a str,
    artifact: String,
    queries: BTreeMap<String, QueryExport>,
    commands: BTreeMap<String, CommandExport>,
    forms: Vec<FormExport>,
    schedules: BTreeMap<String, ScheduleExport>,
    redirects: BTreeMap<String, RedirectExport>,
    view_types: BTreeMap<String, ViewTypeExport>,
    routes: BTreeMap<String, RouteExport>,
    template_context: TemplateContextExport,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QueryExport {
    title: String,
    purpose: String,
    input_schema: Value,
    output_schema: Value,
    view_type: Option<String>,
    example: Example,
    routes: Vec<String>,
    api: ApiExport,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommandExport {
    title: String,
    purpose: String,
    use_when: Vec<String>,
    avoid_when: Vec<String>,
    preconditions: Vec<String>,
    effects: Vec<String>,
    result: String,
    input_schema: Value,
    output_schema: Value,
    errors: Vec<ErrorExport>,
    example: Example,
    internal: bool,
    api: Option<ApiExport>,
    edit: Option<EditExport>,
}

#[derive(Serialize)]
struct ErrorExport {
    name: String,
    description: String,
    recovery: String,
}

#[derive(Serialize)]
struct ApiExport {
    method: &'static str,
    path: String,
}

#[derive(Serialize)]
struct EditExport {
    model: String,
    id_field: String,
    version_field: String,
}

#[derive(Serialize)]
struct FormExport {
    template: String,
    command: String,
    fields: Vec<FormFieldExport>,
}

#[derive(Serialize)]
struct FormFieldExport {
    name: String,
    control: &'static str,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    input_type: Option<String>,
}

#[derive(Serialize)]
struct ScheduleExport {
    command: String,
    cadence: Value,
    missed: String,
    #[serde(rename = "catchUpBound")]
    catch_up_bound: u64,
}

#[derive(Serialize)]
struct RedirectExport {
    path: String,
    command: String,
}

#[derive(Serialize)]
struct ViewTypeExport {
    queries: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RouteExport {
    path: String,
    template: String,
    query: String,
    live: bool,
    query_defaults: Map<String, Value>,
    context_key: String,
}

#[derive(Serialize)]
struct TemplateContextExport {
    shared: BTreeMap<String, Value>,
}

#[derive(Serialize)]
struct Example {
    input: Value,
    output: Value,
}

pub fn export_file(artifact_directory: &Path, output: Option<&Path>) -> Result<()> {
    let bytes = export_bytes(artifact_directory)?;
    if let Some(path) = output {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let destination = parent
            .canonicalize()?
            .join(path.file_name().context("output filename required")?);
        let artifact_directory = artifact_directory.canonicalize()?;
        ensure!(
            !destination.starts_with(&artifact_directory),
            "app contract output must not overwrite artifact contents"
        );
        if let Ok(metadata) = fs::symlink_metadata(&destination) {
            ensure!(
                metadata.file_type().is_file(),
                "output path must be a regular file"
            );
        }
        fs::write(path, bytes)?;
    } else {
        println!("{}", String::from_utf8(bytes)?);
    }
    Ok(())
}

pub fn export_bytes(artifact_directory: &Path) -> Result<Vec<u8>> {
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
            "app contract {label} file type or byte budget invalid"
        );
    }
    let artifact = LoadedArtifact::load(&artifact_directory)?;
    let document = export(artifact.id(), artifact.contract(), &artifact_directory)?;
    let bytes = serde_json::to_vec_pretty(&document)?;
    ensure!(
        bytes.len() <= MAX_EXPORT_BYTES,
        "app contract export byte budget exceeded"
    );
    Ok(bytes)
}

fn export<'a>(
    artifact_id: &str,
    artifact: &'a Artifact,
    artifact_directory: &Path,
) -> Result<Export<'a>> {
    ensure!(
        artifact.format >= 7,
        "app contracts require explicit admitted routes"
    );
    let definition = artifact
        .app_contract
        .as_ref()
        .context("app contract export requires the admitted app contract")?;
    let route_catalog = crate::routing::Catalog::from_artifact(artifact)?;
    let mut queries = BTreeMap::<String, QueryExport>::new();
    let mut routes = BTreeMap::new();
    for page in &artifact.pages {
        let route = export_route(page, &route_catalog)?;
        let query = export_query(artifact, definition, page)?;
        if let Some(existing) = queries.get_mut(&page.operation) {
            ensure!(
                existing.input_schema == query.input_schema
                    && existing.output_schema == query.output_schema
                    && existing.example.input == query.example.input
                    && existing.example.output == query.example.output
                    && existing.title == query.title
                    && existing.purpose == query.purpose,
                "routes sharing query {} have inconsistent contracts",
                page.operation
            );
            existing.routes.push(page.name.clone());
        } else {
            queries.insert(page.operation.clone(), query);
        }
        routes.insert(page.name.clone(), route);
    }
    for query in queries.values_mut() {
        query.routes.sort();
    }
    let commands = export_commands(artifact, definition)?;
    let forms = export_forms(artifact, artifact_directory)?;
    let schedules = artifact
        .schedules
        .iter()
        .map(|schedule| (schedule.name.clone(), export_schedule(schedule)))
        .collect();
    let redirects = artifact
        .redirects
        .iter()
        .map(|redirect| {
            (
                redirect.name.clone(),
                RedirectExport {
                    path: redirect.path.clone(),
                    command: redirect.operation.clone(),
                },
            )
        })
        .collect();
    Ok(Export {
        schema_version: 1,
        kind: "clanker-app-contracts",
        app: &artifact.namespace,
        artifact: artifact_id.to_owned(),
        queries,
        commands,
        forms,
        schedules,
        redirects,
        view_types: BTreeMap::new(),
        routes,
        template_context: TemplateContextExport {
            shared: BTreeMap::from([("company".into(), company_schema())]),
        },
    })
}

fn export_route(page: &Page, routes: &crate::routing::Catalog) -> Result<RouteExport> {
    let route = routes.route(&page.name)?;
    ensure!(
        route.path == page.path,
        "compiled route path differs from admitted page"
    );
    Ok(RouteExport {
        path: page.path.clone(),
        template: format!("ui/{}", page.template),
        query: page.operation.clone(),
        live: page.live,
        query_defaults: route.defaults.clone(),
        context_key: page.name.clone(),
    })
}

fn export_query(
    artifact: &Artifact,
    definition: &crate::app_contract::Definition,
    page: &Page,
) -> Result<QueryExport> {
    let operation = artifact
        .operations
        .iter()
        .find(|operation| operation.name == page.operation && operation.kind == "query")
        .with_context(|| format!("route {} has no registered query", page.name))?;
    let input = artifact
        .schema
        .inputs
        .get(&operation.input_type)
        .context("query input schema missing")?;
    let output = artifact
        .outputs
        .get(&operation.output_type)
        .context("query output schema missing")?;
    let contract = definition
        .operations
        .get(&operation.name)
        .with_context(|| format!("query contract missing: {}", operation.name))?;
    ensure!(
        contract.intent.target.input_type == operation.input_type
            && contract.intent.target.output_type == operation.output_type,
        "query contract handles differ from admitted operation"
    );
    ensure!(
        !contract.request_example.is_empty() && !contract.response_example.is_empty(),
        "query contract requires typed input and output examples"
    );
    let example_input: Value =
        serde_json::from_str(&contract.request_example).context("invalid query example input")?;
    let example_output: Value =
        serde_json::from_str(&contract.response_example).context("invalid query example output")?;
    input
        .validate_input(&example_input)
        .context("query example input does not match its contract")?;
    output
        .shape
        .validate_value(&example_output)
        .context("query example output does not match its contract")?;
    let mut input_schema = record_schema(input)?;
    crate::api_docs::annotate(&mut input_schema, &contract.intent.inputs)?;
    let mut output_schema = crate::operation_catalog::output_schema(&output.shape);
    crate::api_docs::annotate(&mut output_schema, &contract.intent.outputs)?;
    add_output_kinds(&mut output_schema, &output.shape)?;
    Ok(QueryExport {
        title: contract.intent.title.clone(),
        purpose: contract.intent.usage.purpose.clone(),
        input_schema,
        output_schema,
        view_type: None,
        example: Example {
            input: example_input,
            output: example_output,
        },
        routes: vec![page.name.clone()],
        api: ApiExport {
            method: "GET",
            path: format!("/api/{}", operation.name),
        },
    })
}

fn export_commands(
    artifact: &Artifact,
    definition: &crate::app_contract::Definition,
) -> Result<BTreeMap<String, CommandExport>> {
    let mut commands = BTreeMap::new();
    for operation in artifact
        .operations
        .iter()
        .filter(|operation| operation.kind == "command")
    {
        let contract = definition
            .operations
            .get(&operation.name)
            .with_context(|| format!("command contract missing: {}", operation.name))?;
        ensure!(
            contract.intent.target.input_type == operation.input_type
                && contract.intent.target.output_type == operation.output_type,
            "command contract handles differ from admitted operation"
        );
        ensure!(
            !contract.request_example.is_empty() && !contract.response_example.is_empty(),
            "command contract requires typed input and output examples"
        );
        let example_input: Value = serde_json::from_str(&contract.request_example)
            .context("invalid command example input")?;
        let example_output: Value = serde_json::from_str(&contract.response_example)
            .context("invalid command example output")?;
        let input = artifact
            .schema
            .inputs
            .get(&operation.input_type)
            .context("command input schema missing")?;
        let output = artifact
            .outputs
            .get(&operation.output_type)
            .context("command output schema missing")?;
        input
            .validate_input(&example_input)
            .context("command example input does not match its contract")?;
        output
            .shape
            .validate_value(&example_output)
            .context("command example output does not match its contract")?;
        let mut input_schema = record_schema(input)?;
        crate::api_docs::annotate(&mut input_schema, &contract.intent.inputs)?;
        let mut output_schema = crate::operation_catalog::output_schema(&output.shape);
        crate::api_docs::annotate(&mut output_schema, &contract.intent.outputs)?;
        add_output_kinds(&mut output_schema, &output.shape)?;
        let errors = contract
            .errors
            .iter()
            .map(|name| {
                let failure = definition
                    .errors
                    .get(name)
                    .with_context(|| format!("command error declaration missing: {name}"))?;
                Ok(ErrorExport {
                    name: name.clone(),
                    description: failure.description.clone(),
                    recovery: failure.recovery.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let internal = contract.execution.internal;
        let api = (!internal).then(|| ApiExport {
            method: "POST",
            path: format!("/api/{}", operation.name),
        });
        let edit = (!contract.execution.model.is_empty()).then(|| EditExport {
            model: contract.execution.model.clone(),
            id_field: contract.execution.id_field.clone(),
            version_field: contract.execution.version_field.clone(),
        });
        commands.insert(
            operation.name.clone(),
            CommandExport {
                title: contract.intent.title.clone(),
                purpose: contract.intent.usage.purpose.clone(),
                use_when: contract.intent.usage.use_when.clone(),
                avoid_when: contract.intent.usage.avoid_when.clone(),
                preconditions: contract.intent.usage.preconditions.clone(),
                effects: contract.intent.usage.effects.clone(),
                result: contract.intent.usage.result.clone(),
                input_schema,
                output_schema,
                errors,
                example: Example {
                    input: example_input,
                    output: example_output,
                },
                internal,
                api,
                edit,
            },
        );
    }
    Ok(commands)
}

fn export_forms(artifact: &Artifact, artifact_directory: &Path) -> Result<Vec<FormExport>> {
    let mut forms = Vec::new();
    let selector = scraper::Selector::parse("form[data-command]").expect("static selector");
    for (path, template) in &artifact.templates {
        let source = crate::web_templates::read_blob(artifact_directory, template)?;
        let html = scraper::Html::parse_fragment(&source);
        for form in html.select(&selector) {
            let command = form
                .value()
                .attr("data-command")
                .context("admitted command form missing command")?
                .to_owned();
            let fields = crate::web_forms::controls(form)?
                .into_iter()
                .map(|field| {
                    let hidden = field.hidden;
                    FormFieldExport {
                        name: field.name,
                        control: if hidden {
                            "hidden"
                        } else {
                            match field.tag.as_str() {
                                "input" => "input",
                                "textarea" => "textarea",
                                "select" => "select",
                                _ => unreachable!("validated form control"),
                            }
                        },
                        input_type: (field.tag == "input").then_some(field.input_type),
                    }
                })
                .collect();
            forms.push(FormExport {
                template: format!("ui/{path}"),
                command,
                fields,
            });
        }
    }
    forms.sort_by(|left, right| {
        (&left.template, &left.command).cmp(&(&right.template, &right.command))
    });
    Ok(forms)
}

fn export_schedule(schedule: &crate::artifact::Schedule) -> ScheduleExport {
    let hour_ms = 60 * 60 * 1000;
    let day_ms = 24 * hour_ms;
    let cadence = if schedule.interval_ms >= day_ms && schedule.interval_ms.is_multiple_of(day_ms) {
        json!({ "daily": { "everyDays": schedule.interval_ms / day_ms, "hour": schedule.anchor_hour } })
    } else if schedule.interval_ms.is_multiple_of(hour_ms) {
        json!({ "hours": schedule.interval_ms / hour_ms })
    } else {
        json!({ "minutes": schedule.interval_ms / (60 * 1000) })
    };
    ScheduleExport {
        command: schedule.operation.clone(),
        cadence,
        missed: schedule.missed.clone(),
        catch_up_bound: schedule.catch_up_bound,
    }
}

fn company_schema() -> Value {
    json!({
        "kind":"record",
        "type":"object",
        "required":["name"],
        "additionalProperties":false,
        "properties":{"name":{"kind":"string","type":"string","description":"Instance branding; supplied outside the app artifact."}}
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
    let mut schema = crate::operation_catalog::input_schema(kind);
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
        let mut schema = crate::operation_catalog::output_schema(&shape);
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
        let schema = crate::schema::Schema {
            models: BTreeMap::new(),
            inputs: BTreeMap::from([(
                "Input".into(),
                Record {
                    fields: BTreeMap::from([(
                        "limit".into(),
                        Kind::Unsigned(crate::numeric::Unsigned::U64),
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
        let intent = crate::operation_metadata::Entry {
            target: crate::operation_metadata::Target {
                operation: "gallery.list".into(),
                input_type: "Input".into(),
                output_type: "Output".into(),
            },
            title: "List items".into(),
            usage: crate::operation_metadata::Usage {
                purpose: "List items.".into(),
                use_when: Vec::new(),
                avoid_when: Vec::new(),
                preconditions: Vec::new(),
                effects: Vec::new(),
                result: "Items.".into(),
            },
            inputs: vec![crate::api_docs::Field {
                path: "limit".into(),
                description: "Maximum items.".into(),
            }],
            outputs: vec![crate::api_docs::Field {
                path: "title".into(),
                description: "Display title.".into(),
            }],
            input_sources: Vec::new(),
            follow_ups: Vec::new(),
        };
        let contract = crate::app_contract::Operation {
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
            format: crate::artifact::CURRENT_FORMAT,
            app_contract: Some(crate::app_contract::Definition {
                operations: BTreeMap::from([("gallery.list".into(), contract)]),
                presentation: crate::app_contract::Presentation {
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
            declarations: crate::registry::Catalog::default(),
            credential_declarations: Vec::new(),
            credential_manifest: Vec::new(),
            connection_declarations: Vec::new(),
            checked_types_digest: String::new(),
            roc_version: String::new(),
            worker_digest: String::new(),
            schema_digest: schema.hash()?,
            schema,
            identities: crate::identity::Registry::default(),
            operations: vec![crate::artifact::Operation {
                name: "gallery.list".into(),
                kind: "query".into(),
                input_type: "Input".into(),
                output_type: "Output".into(),
            }],
            properties: Vec::new(),
            pages: vec![
                Page {
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
                },
                Page {
                    name: "featured".into(),
                    title: "Featured".into(),
                    operation: "gallery.list".into(),
                    defaults: r#"{"limit":2}"#.into(),
                    path: "/featured".into(),
                    template: "pages/featured.html".into(),
                    input_type: "Input".into(),
                    output_type: "Output".into(),
                    live: false,
                    live_refresh_ms: 0,
                },
            ],
            schedules: Vec::new(),
            ingress: Vec::new(),
            redirects: Vec::new(),
            assets: Default::default(),
            web_resources: Default::default(),
            outputs: BTreeMap::from([(
                "Output".into(),
                crate::output_schema::Contract {
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
        let serialized =
            serde_json::to_value(export("sha256:fixture", &artifact, Path::new("."))?)?;
        assert_eq!(
            serialized,
            serde_json::to_value(export("sha256:fixture", &artifact, Path::new("."))?)?
        );
        assert_eq!(serialized["schemaVersion"], 1);
        assert_eq!(serialized["kind"], "clanker-app-contracts");
        assert_eq!(serialized["artifact"], "sha256:fixture");
        assert_eq!(serialized["queries"].as_object().unwrap().len(), 1);
        assert_eq!(
            serialized["queries"]["gallery.list"]["routes"][0],
            "featured"
        );
        assert_eq!(serialized["queries"]["gallery.list"]["routes"][1], "home");
        assert_eq!(
            serialized["queries"]["gallery.list"]["api"]["method"],
            "GET"
        );
        assert_eq!(
            serialized["queries"]["gallery.list"]["api"]["path"],
            "/api/gallery.list"
        );
        assert_eq!(serialized["commands"], json!({}));
        assert_eq!(serialized["forms"], json!([]));
        assert_eq!(serialized["schedules"], json!({}));
        assert_eq!(serialized["redirects"], json!({}));
        assert_eq!(
            serialized["queries"]["gallery.list"]["inputSchema"]["properties"]["limit"]["description"],
            "Maximum items."
        );
        assert_eq!(
            serialized["queries"]["gallery.list"]["outputSchema"]["properties"]["title"]["description"],
            "Display title."
        );
        assert_eq!(
            serialized["queries"]["gallery.list"]["example"]["input"]["limit"],
            2
        );
        assert_eq!(
            serialized["queries"]["gallery.list"]["example"]["output"]["title"],
            "Example"
        );
        assert_eq!(
            serialized["queries"]["gallery.list"]["viewType"],
            Value::Null
        );
        assert_eq!(serialized["viewTypes"], json!({}));
        assert_eq!(serialized["routes"]["home"]["query"], "gallery.list");
        assert_eq!(
            serialized["routes"]["home"]["template"],
            "ui/pages/home.html"
        );
        assert_eq!(serialized["routes"]["home"]["queryDefaults"]["limit"], 1);
        assert_eq!(serialized["routes"]["home"]["contextKey"], "home");
        assert_eq!(
            serialized["routes"]["featured"]["queryDefaults"]["limit"],
            2
        );
        assert_eq!(
            serialized["templateContext"]["shared"]["company"]["kind"],
            "record"
        );
        Ok(())
    }

    #[test]
    fn unsupported_output_shape_fails_closed() -> Result<()> {
        let shape = Type::Record(BTreeMap::from([("title".into(), Type::String)]));
        let mut schema = crate::operation_catalog::output_schema(&shape);
        schema["properties"] = json!({});
        assert!(add_output_kinds(&mut schema, &shape).is_err());
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
                (
                    "theme".into(),
                    Kind::Unsigned(crate::numeric::Unsigned::U64),
                ),
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
