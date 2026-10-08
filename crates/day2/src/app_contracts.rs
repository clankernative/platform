use crate::{
    artifact::{Artifact, LoadedArtifact, Page},
    output_schema::Type,
    schema::{Kind, Record},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

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
    export_file_with(
        artifact_directory,
        output,
        &mut FilesystemArtifactCapture,
        &mut FilesystemTemplateCapture,
        &mut FilesystemPublication,
    )
}

// These ports are private operator internals, never app capabilities. Production
// entrypoints always select normal admission; only private tests substitute captures.
trait ArtifactCapture {
    fn capture(&mut self, directory: &Path) -> Result<LoadedArtifact>;
}

trait TemplateCapture {
    fn capture(
        &mut self,
        directory: &Path,
        artifact: &Artifact,
    ) -> Result<BTreeMap<String, String>>;
}

trait Publication {
    fn publish(&mut self, directory: &Path, output: Option<&Path>, bytes: &[u8]) -> Result<()>;
}

struct FilesystemArtifactCapture;
struct FilesystemTemplateCapture;
struct FilesystemPublication;

impl TemplateCapture for FilesystemTemplateCapture {
    fn capture(
        &mut self,
        directory: &Path,
        artifact: &Artifact,
    ) -> Result<BTreeMap<String, String>> {
        crate::web_templates::validate(&artifact.templates)?;
        artifact
            .templates
            .iter()
            .map(|(path, template)| {
                Ok((
                    path.clone(),
                    crate::web_templates::read_blob(directory, template)?,
                ))
            })
            .collect()
    }
}

impl Publication for FilesystemPublication {
    fn publish(&mut self, directory: &Path, output: Option<&Path>, bytes: &[u8]) -> Result<()> {
        if let Some(path) = output {
            write_output(prepare_output(directory, path)?, bytes)
        } else {
            println!("{}", std::str::from_utf8(bytes)?);
            Ok(())
        }
    }
}

fn export_file_with(
    directory: &Path,
    output: Option<&Path>,
    artifact_capture: &mut impl ArtifactCapture,
    template_capture: &mut impl TemplateCapture,
    publication: &mut impl Publication,
) -> Result<()> {
    let bytes = export_bytes_with(directory, artifact_capture, template_capture)?;
    publication.publish(directory, output, &bytes)
}

struct OutputFile {
    destination: PathBuf,
    previous: Option<fs::Metadata>,
}

fn prepare_output(artifact_directory: &Path, path: &Path) -> Result<OutputFile> {
    // The operator owns the parent directory and must exclude concurrent namespace
    // mutation. Canonical paths are not a hostile-parent or inode-anchored sandbox.
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
    let previous = match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_file(),
                "output path must be a regular file"
            );
            Some(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    Ok(OutputFile {
        destination,
        previous,
    })
}

fn write_output(output: OutputFile, bytes: &[u8]) -> Result<()> {
    let mut temporary = tempfile::NamedTempFile::new_in(
        output
            .destination
            .parent()
            .context("output parent required")?,
    )?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    if let Some(previous) = output.previous {
        let current = fs::symlink_metadata(&output.destination)?;
        ensure!(
            current.file_type().is_file()
                && current.dev() == previous.dev()
                && current.ino() == previous.ino(),
            "output path changed before atomic replacement"
        );
        // Replace the agreed directory entry, never open/truncate its old inode.
        // Other hardlinks (including artifact inputs) retain their original bytes.
        temporary.persist(&output.destination)?;
    } else {
        // Do not clobber a file created after the absent-path check.
        temporary.persist_noclobber(&output.destination)?;
    }
    Ok(())
}

pub fn export_bytes(artifact_directory: &Path) -> Result<Vec<u8>> {
    export_bytes_with(
        artifact_directory,
        &mut FilesystemArtifactCapture,
        &mut FilesystemTemplateCapture,
    )
}

impl ArtifactCapture for FilesystemArtifactCapture {
    fn capture(&mut self, artifact_directory: &Path) -> Result<LoadedArtifact> {
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
        LoadedArtifact::load(&artifact_directory)
    }
}

fn export_bytes_with(
    directory: &Path,
    artifact_capture: &mut impl ArtifactCapture,
    template_capture: &mut impl TemplateCapture,
) -> Result<Vec<u8>> {
    let artifact = artifact_capture.capture(directory)?;
    let templates = template_capture.capture(artifact.directory(), artifact.contract())?;
    project_bytes(artifact.id(), artifact.contract(), &templates)
}

fn project_bytes(
    artifact_id: &str,
    artifact: &Artifact,
    templates: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec_pretty(&export(artifact_id, artifact, templates)?)?;
    ensure!(
        bytes.len() <= MAX_EXPORT_BYTES,
        "app contract export byte budget exceeded"
    );
    Ok(bytes)
}

fn export<'a>(
    artifact_id: &str,
    artifact: &'a Artifact,
    templates: &BTreeMap<String, String>,
) -> Result<Export<'a>> {
    crate::web_templates::validate(&artifact.templates)?;
    ensure!(
        templates.len() == artifact.templates.len(),
        "app contract template snapshot catalog mismatch"
    );
    for (path, template) in &artifact.templates {
        let source = templates
            .get(path)
            .with_context(|| format!("app contract template snapshot missing: {path}"))?;
        ensure!(
            source.len() as u64 == template.bytes
                && crate::digest(source.as_bytes()) == template.digest,
            "template_digest_mismatch"
        );
    }
    ensure!(
        artifact.format >= 7,
        "app contracts require explicit admitted routes"
    );
    let definition = artifact
        .app_contract
        .as_ref()
        .context("app contract export requires the admitted app contract")?;
    let route_catalog = crate::routing::Catalog::from_artifact(artifact)?;
    let mut queries = artifact
        .operations
        .iter()
        .filter(|operation| operation.kind == "query")
        .map(|operation| {
            Ok((
                operation.name.clone(),
                export_query(artifact, definition, operation)?,
            ))
        })
        .collect::<Result<BTreeMap<String, QueryExport>>>()?;
    let mut routes = BTreeMap::new();
    for page in &artifact.pages {
        let route = export_route(page, &route_catalog)?;
        queries
            .get_mut(&page.operation)
            .with_context(|| format!("route {} has no registered query", page.name))?
            .routes
            .push(page.name.clone());
        routes.insert(page.name.clone(), route);
    }
    for query in queries.values_mut() {
        query.routes.sort();
    }
    let commands = export_commands(artifact, definition)?;
    let forms = export_forms(templates)?;
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
    operation: &crate::artifact::Operation,
) -> Result<QueryExport> {
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
        routes: Vec::new(),
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

fn export_forms(templates: &BTreeMap<String, String>) -> Result<Vec<FormExport>> {
    let mut forms = Vec::new();
    let selector = scraper::Selector::parse("form[data-command]").expect("static selector");
    for (path, source) in templates {
        let html = scraper::Html::parse_fragment(source);
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
    let minute_ms = 60 * 1000;
    let hour_ms = 60 * minute_ms;
    let day_ms = 24 * hour_ms;
    let cadence = if schedule.interval_ms >= day_ms && schedule.interval_ms.is_multiple_of(day_ms) {
        json!({ "daily": { "everyDays": schedule.interval_ms / day_ms, "hour": schedule.anchor_hour } })
    } else if schedule.interval_ms.is_multiple_of(hour_ms) {
        json!({ "hours": schedule.interval_ms / hour_ms })
    } else if schedule.interval_ms.is_multiple_of(minute_ms) {
        json!({ "minutes": schedule.interval_ms / minute_ms })
    } else {
        json!({ "milliseconds": schedule.interval_ms })
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
    fn atomic_output_preserves_hardlinked_artifact_inputs() -> Result<()> {
        let root = tempfile::tempdir()?;
        let artifact = root.path().join("artifact");
        fs::create_dir(&artifact)?;
        for name in ["artifact.json", "worker", "checked-types.json"] {
            let source = artifact.join(name);
            let original = format!("admitted {name}").into_bytes();
            fs::write(&source, &original)?;
            fs::set_permissions(&source, fs::Permissions::from_mode(0o444))?;
            let identity = fs::metadata(&source)?;
            let destination = root.path().join(format!("export-{name}"));
            fs::hard_link(&source, &destination)?;
            write_output(
                prepare_output(&artifact, &destination)?,
                b"exported contract",
            )?;
            assert_eq!(fs::read(&source)?, original);
            let retained = fs::metadata(&source)?;
            assert_eq!(
                (retained.dev(), retained.ino()),
                (identity.dev(), identity.ino())
            );
            assert_eq!(retained.permissions().mode() & 0o777, 0o444);
            assert_eq!(retained.nlink(), 1);
            let output = fs::symlink_metadata(&destination)?;
            assert!(output.file_type().is_file());
            assert_eq!(output.permissions().mode() & 0o777, 0o600);
            assert_ne!(
                (output.dev(), output.ino()),
                (retained.dev(), retained.ino())
            );
            assert_eq!(fs::read(destination)?, b"exported contract");
        }
        assert_eq!(fs::read_dir(root.path())?.count(), 4);
        Ok(())
    }

    #[test]
    fn new_output_is_private_and_does_not_clobber_raced_destination() -> Result<()> {
        let root = tempfile::tempdir()?;
        let artifact = root.path().join("artifact");
        fs::create_dir(&artifact)?;
        let destination = root.path().join("export.json");
        write_output(prepare_output(&artifact, &destination)?, b"first export")?;
        assert_eq!(
            fs::metadata(&destination)?.permissions().mode() & 0o777,
            0o600
        );
        fs::remove_file(&destination)?;
        let pending = prepare_output(&artifact, &destination)?;
        fs::write(&destination, b"another writer")?;
        assert!(write_output(pending, b"must not replace").is_err());
        assert_eq!(fs::read(&destination)?, b"another writer");
        fs::remove_file(&destination)?;
        let protected = artifact.join("artifact.json");
        fs::write(&protected, b"admitted bytes")?;
        let pending = prepare_output(&artifact, &destination)?;
        std::os::unix::fs::symlink(&protected, &destination)?;
        assert!(write_output(pending, b"must not follow").is_err());
        assert!(fs::symlink_metadata(&destination)?.file_type().is_symlink());
        assert_eq!(fs::read(&protected)?, b"admitted bytes");
        assert_eq!(fs::read_dir(root.path())?.count(), 2);
        Ok(())
    }

    #[test]
    fn output_rejects_artifact_paths_symlinks_directories_and_changed_identity() -> Result<()> {
        let root = tempfile::tempdir()?;
        let artifact = root.path().join("artifact");
        fs::create_dir(&artifact)?;
        let protected = artifact.join("artifact.json");
        fs::write(&protected, b"admitted bytes")?;
        assert!(prepare_output(&artifact, &protected).is_err());
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(&artifact, &alias)?;
        assert!(prepare_output(&artifact, &alias.join("new.json")).is_err());
        assert!(prepare_output(&artifact, root.path()).is_err());
        let destination = root.path().join("export.json");
        std::os::unix::fs::symlink(&protected, &destination)?;
        assert!(prepare_output(&artifact, &destination).is_err());
        fs::remove_file(&destination)?;
        fs::write(&destination, b"agreed output")?;
        let pending = prepare_output(&artifact, &destination)?;
        fs::rename(&destination, root.path().join("old.json"))?;
        fs::hard_link(&protected, &destination)?;
        assert!(write_output(pending, b"must not replace changed output").is_err());
        assert_eq!(fs::read(&destination)?, b"admitted bytes");
        assert_eq!(fs::read(&protected)?, b"admitted bytes");
        assert_eq!(fs::read(root.path().join("old.json"))?, b"agreed output");
        Ok(())
    }

    #[test]
    fn export_rejects_symlink_and_oversized_inputs_before_admission() -> Result<()> {
        let root = tempfile::tempdir()?;
        let artifact = root.path().join("artifact");
        fs::create_dir(&artifact)?;
        let symlink = root.path().join("alias");
        std::os::unix::fs::symlink(&artifact, &symlink)?;
        assert!(
            export_bytes(&symlink)
                .unwrap_err()
                .to_string()
                .contains("artifact path must be a directory")
        );
        for (file, maximum) in [
            ("artifact.json", MAX_ARTIFACT_BYTES),
            ("worker", MAX_WORKER_BYTES),
            ("checked-types.json", MAX_CHECKED_TYPES_BYTES),
        ] {
            for name in ["artifact.json", "worker", "checked-types.json"] {
                fs::write(artifact.join(name), b"{}")?;
            }
            fs::File::create(artifact.join(file))?.set_len(maximum + 1)?;
            assert!(
                export_bytes(&artifact)
                    .unwrap_err()
                    .to_string()
                    .contains("byte budget invalid")
            );
            fs::remove_file(artifact.join(file))?;
            std::os::unix::fs::symlink(root.path().join("missing"), artifact.join(file))?;
            assert!(
                export_bytes(&artifact)
                    .unwrap_err()
                    .to_string()
                    .contains("file type or byte budget invalid")
            );
            fs::remove_file(artifact.join(file))?;
        }
        Ok(())
    }

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

    fn fixture() -> Result<(Artifact, BTreeMap<String, String>)> {
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
            intent: intent.clone(),
            request_example: r#"{"limit":2}"#.into(),
            response_example: r#"{"title":"Example"}"#.into(),
            deprecated: false,
            export_version: 0,
            execution: Default::default(),
            credential_access: Default::default(),
            errors: Vec::new(),
            required_all_rows: Vec::new(),
        };
        let mut command_intent = intent;
        command_intent.target.operation = "gallery.save".into();
        command_intent.title = "Save item".into();
        let command = crate::app_contract::Operation {
            intent: command_intent,
            request_example: r#"{"limit":2}"#.into(),
            response_example: r#"{"title":"Saved"}"#.into(),
            deprecated: false,
            export_version: 0,
            execution: Default::default(),
            credential_access: Default::default(),
            errors: vec!["gallery:invalid_item".into()],
            required_all_rows: Vec::new(),
        };
        let error = crate::app_contract::Failure {
            code: "gallery:invalid_item".into(),
            description: "The item is invalid.".into(),
            recovery: "Correct the item and retry.".into(),
            operation: command.intent.target.clone(),
            additional_operations: Vec::new(),
        };
        let template_bytes =
            b"<form data-command=\"gallery.save\"><input name=\"limit\" type=\"number\"></form>";
        let template_digest = crate::digest(template_bytes);
        let artifact = Artifact {
            format: crate::artifact::CURRENT_FORMAT,
            app_contract: Some(crate::app_contract::Definition {
                operations: BTreeMap::from([
                    ("gallery.list".into(), contract),
                    ("gallery.save".into(), command),
                ]),
                presentation: crate::app_contract::Presentation {
                    stylesheet: String::new(),
                    script: String::new(),
                },
                identities: String::new(),
                invariants: BTreeMap::new(),
                domains: BTreeMap::new(),
                errors: BTreeMap::from([("gallery:invalid_item".into(), error)]),
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
            operations: vec![
                crate::artifact::Operation {
                    name: "gallery.list".into(),
                    kind: "query".into(),
                    input_type: "Input".into(),
                    output_type: "Output".into(),
                },
                crate::artifact::Operation {
                    name: "gallery.save".into(),
                    kind: "command".into(),
                    input_type: "Input".into(),
                    output_type: "Output".into(),
                },
            ],
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
            schedules: vec![crate::artifact::Schedule {
                name: "minute-and-half".into(),
                operation: "gallery.save".into(),
                input: r#"{"limit":2}"#.into(),
                input_type: "Input".into(),
                interval_ms: 90_000,
                anchor_hour: 3,
                missed: "skip".into(),
                catch_up_bound: 0,
            }],
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
            templates: BTreeMap::from([(
                "pages/home.html".into(),
                crate::web_templates::Template {
                    digest: template_digest,
                    bytes: template_bytes.len() as u64,
                },
            )]),
            api_docs: BTreeMap::new(),
            operation_metadata: BTreeMap::new(),
            sources: BTreeMap::new(),
            admission: "local-spike-only".into(),
        };
        Ok((
            artifact,
            BTreeMap::from([(
                "pages/home.html".into(),
                String::from_utf8(template_bytes.to_vec())?,
            )]),
        ))
    }

    #[test]
    fn export_projects_admitted_routes_defaults_descriptions_and_examples() -> Result<()> {
        let (mut artifact, templates) = fixture()?;
        let serialized = serde_json::to_value(export("sha256:fixture", &artifact, &templates)?)?;
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
        assert_eq!(
            serialized["commands"]["gallery.save"]["api"]["method"],
            "POST"
        );
        assert_eq!(
            serialized["commands"]["gallery.save"]["api"]["path"],
            "/api/gallery.save"
        );
        assert_eq!(serialized["commands"]["gallery.save"]["edit"], Value::Null);
        assert_eq!(
            serialized["commands"]["gallery.save"]["errors"][0]["name"],
            "gallery:invalid_item"
        );
        assert_eq!(
            serialized["commands"]["gallery.save"]["errors"][0]["recovery"],
            "Correct the item and retry."
        );
        assert_eq!(serialized["forms"][0]["command"], "gallery.save");
        assert_eq!(serialized["forms"][0]["fields"][0]["name"], "limit");
        assert_eq!(
            serialized["schedules"]["minute-and-half"]["cadence"],
            json!({"milliseconds": 90_000})
        );
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
        let first_bytes = project_bytes("sha256:fixture", &artifact, &templates)?;
        artifact.operations.reverse();
        artifact.pages.reverse();
        assert_eq!(
            first_bytes,
            project_bytes("sha256:fixture", &artifact, &templates)?
        );
        artifact.pages.clear();
        let unrouted = serde_json::to_value(export("sha256:fixture", &artifact, &templates)?)?;
        assert_eq!(unrouted["queries"]["gallery.list"]["routes"], json!([]));
        assert_eq!(unrouted["queries"]["gallery.list"]["api"]["method"], "GET");
        artifact
            .app_contract
            .as_mut()
            .unwrap()
            .operations
            .get_mut("gallery.list")
            .unwrap()
            .response_example = r#"{"title":42}"#.into();
        assert!(export("sha256:fixture", &artifact, &templates).is_err());
        Ok(())
    }

    struct MemoryArtifactCapture {
        artifact: Artifact,
        fail: bool,
        trace: std::rc::Rc<std::cell::RefCell<Vec<Value>>>,
    }

    impl ArtifactCapture for MemoryArtifactCapture {
        fn capture(&mut self, directory: &Path) -> Result<LoadedArtifact> {
            self.trace.borrow_mut().push(json!("artifact"));
            ensure!(!self.fail, "injected artifact capture failure");
            Ok(LoadedArtifact::from_contract_for_tests(
                "sha256:fixture".into(),
                directory.to_path_buf(),
                self.artifact.clone(),
            ))
        }
    }

    struct MemoryTemplateCapture {
        templates: BTreeMap<String, String>,
        fail: bool,
        trace: std::rc::Rc<std::cell::RefCell<Vec<Value>>>,
    }

    impl TemplateCapture for MemoryTemplateCapture {
        fn capture(&mut self, _: &Path, _: &Artifact) -> Result<BTreeMap<String, String>> {
            self.trace.borrow_mut().push(json!("templates"));
            ensure!(!self.fail, "injected template capture failure");
            Ok(self.templates.clone())
        }
    }

    struct MemoryPublication {
        bytes: Option<Vec<u8>>,
        fail: bool,
        trace: std::rc::Rc<std::cell::RefCell<Vec<Value>>>,
    }

    impl Publication for MemoryPublication {
        fn publish(&mut self, _: &Path, _: Option<&Path>, bytes: &[u8]) -> Result<()> {
            self.trace.borrow_mut().push(json!("publish"));
            ensure!(!self.fail, "injected publication failure");
            self.bytes = Some(bytes.to_vec());
            Ok(())
        }
    }

    struct ExportReplayTrace {
        seed: u64,
        records: Vec<Value>,
    }

    impl Drop for ExportReplayTrace {
        fn drop(&mut self) {
            if std::thread::panicking() {
                let save = (|| -> Result<PathBuf> {
                    let root = tempfile::tempdir()?;
                    fs::write(
                        root.path().join("contract-export-replay.json"),
                        serde_json::to_vec(&json!({"seed":self.seed,"records":self.records}))?,
                    )?;
                    Ok(root.keep())
                })();
                eprintln!("contract export failure replay: {save:?}");
            }
        }
    }

    fn replay_exports(seed: u64) -> Result<Vec<u8>> {
        let mut schedule = seed;
        let mut evidence = ExportReplayTrace {
            seed,
            records: Vec::new(),
        };
        let records = &mut evidence.records;
        for _ in 0..32 {
            schedule = schedule.wrapping_mul(6364136223846793005).wrapping_add(1);
            let case = (schedule >> 32) % 6;
            let trace = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
            let (mut artifact, mut templates) = fixture()?;
            if case == 4 {
                templates.get_mut("pages/home.html").unwrap().push(' ');
            }
            if case == 5 {
                artifact
                    .app_contract
                    .as_mut()
                    .unwrap()
                    .operations
                    .get_mut("gallery.list")
                    .unwrap()
                    .response_example = r#"{"title":42}"#.into();
            }
            let mut capture = MemoryArtifactCapture {
                artifact,
                fail: case == 1,
                trace: trace.clone(),
            };
            let mut template_capture = MemoryTemplateCapture {
                templates,
                fail: case == 2,
                trace: trace.clone(),
            };
            let mut publication = MemoryPublication {
                bytes: None,
                fail: case == 3,
                trace: trace.clone(),
            };
            let result = export_file_with(
                Path::new("/artifact"),
                Some(Path::new("/output.json")),
                &mut capture,
                &mut template_capture,
                &mut publication,
            );
            // Independent expectations, not a second call to the projection.
            let expected_events = match case {
                1 => json!(["artifact"]),
                0 | 3 => json!(["artifact", "templates", "publish"]),
                _ => json!(["artifact", "templates"]),
            };
            let record = json!({
                "case":case, "trace":*trace.borrow(), "bytes":publication.bytes,
                "error":result.as_ref().err().map(|error| format!("{error:#}")),
            });
            records.push(record);
            assert_eq!(
                serde_json::to_value(&*trace.borrow())?,
                expected_events,
                "seed={seed} trace={records:?}"
            );
            assert_eq!(result.is_ok(), case == 0, "seed={seed} trace={records:?}");
            assert_eq!(
                publication.bytes.is_some(),
                case == 0,
                "seed={seed} trace={records:?}"
            );
            if let Some(bytes) = &publication.bytes {
                let document: Value = serde_json::from_slice(bytes)?;
                assert_eq!(document["artifact"], "sha256:fixture");
                assert_eq!(
                    document["routes"]["home"]["queryDefaults"],
                    json!({"limit":1})
                );
                assert_eq!(
                    document["queries"]["gallery.list"]["inputSchema"]["additionalProperties"],
                    false
                );
                assert_eq!(document["forms"][0]["fields"][0]["name"], "limit");
            }
        }
        Ok(serde_json::to_vec(&json!({"seed":seed,"records":records}))?)
    }

    #[test]
    fn seeded_export_ports_replay_byte_identically() -> Result<()> {
        for seed in [0, 42, 130, u64::MAX] {
            let trace = replay_exports(seed)?;
            assert_eq!(trace, replay_exports(seed)?);
            let root = tempfile::tempdir()?;
            let path = root.path().join("contract-export-replay.json");
            fs::write(&path, &trace)?;
            let replay: Value = serde_json::from_slice(&fs::read(path)?)?;
            assert_eq!(trace, replay_exports(replay["seed"].as_u64().unwrap())?);
            eprintln!("contract export replay: {}", root.keep().display());
        }
        Ok(())
    }

    #[test]
    fn filesystem_template_capture_matches_pure_snapshot() -> Result<()> {
        let (artifact, templates) = fixture()?;
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join("web_templates"))?;
        let descriptor = &artifact.templates["pages/home.html"];
        let path = root
            .path()
            .join("web_templates")
            .join(format!("{}.html", &descriptor.digest[7..]));
        fs::write(&path, &templates["pages/home.html"])?;
        let captured = FilesystemTemplateCapture.capture(root.path(), &artifact)?;
        assert_eq!(captured, templates);
        fs::remove_file(&path)?;
        assert_eq!(
            project_bytes("sha256:fixture", &artifact, &captured)?,
            project_bytes("sha256:fixture", &artifact, &templates)?
        );
        assert!(
            FilesystemTemplateCapture
                .capture(root.path(), &artifact)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn simulation_fixture_cannot_bypass_production_admission() -> Result<()> {
        let (artifact, templates) = fixture()?;
        assert!(project_bytes("sha256:fixture", &artifact, &templates).is_ok());
        let root = tempfile::tempdir()?;
        let directory = root.path().join("artifact");
        fs::create_dir(&directory)?;
        fs::write(
            directory.join("artifact.json"),
            serde_json::to_vec(&artifact)?,
        )?;
        fs::write(directory.join("worker"), b"not an admitted worker")?;
        fs::write(directory.join("checked-types.json"), b"{}")?;
        let output = root.path().join("output.json");
        fs::write(&output, b"agreed output")?;
        assert!(export_file(&directory, Some(&output)).is_err());
        assert_eq!(fs::read(output)?, b"agreed output");
        Ok(())
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_seed_export_replay(seed in proptest::prelude::any::<u64>()) {
            proptest::prop_assert_eq!(replay_exports(seed).unwrap(), replay_exports(seed).unwrap());
        }

        #[test]
        fn template_snapshot_changes_fail_closed(suffix in "[a-z]{1,64}") {
            let (artifact, mut templates) = fixture().unwrap();
            templates.get_mut("pages/home.html").unwrap().push_str(&suffix);
            proptest::prop_assert!(project_bytes("sha256:fixture", &artifact, &templates).is_err());
        }
    }

    #[test]
    fn snapshot_requires_exact_catalog() -> Result<()> {
        let (artifact, mut templates) = fixture()?;
        templates.insert("pages/unknown.html".into(), "<p>unknown</p>".into());
        assert!(project_bytes("sha256:fixture", &artifact, &templates).is_err());
        templates.remove("pages/unknown.html");
        templates.clear();
        assert!(project_bytes("sha256:fixture", &artifact, &templates).is_err());
        Ok(())
    }

    #[test]
    fn declared_schedule_cadence_preserves_exact_intervals() -> Result<()> {
        let mut schedule = crate::artifact::Schedule {
            name: "sweep".into(),
            operation: "gallery.save".into(),
            input: "{}".into(),
            input_type: "Input".into(),
            interval_ms: 90_000,
            anchor_hour: 3,
            missed: "skip".into(),
            catch_up_bound: 0,
        };
        for (interval, cadence) in [
            (90_000, json!({"milliseconds": 90_000})),
            (120_000, json!({"minutes": 2})),
            (7_200_000, json!({"hours": 2})),
            (172_800_000, json!({"daily": {"everyDays": 2, "hour": 3}})),
        ] {
            schedule.interval_ms = interval;
            assert_eq!(
                serde_json::to_value(export_schedule(&schedule))?["cadence"],
                cadence
            );
        }
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
