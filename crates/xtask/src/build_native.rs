//! Native compiler capabilities. Build.roc owns their order; this adapter owns
//! pinned toolchains, admission, checked codecs and artifact publication.
use super::*;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

struct Prepared {
    roc: PathBuf,
    rust_glue: &'static str,
    pin: Value,
    target: native_toolchain::Target,
    stage: PathBuf,
    hashes: BTreeMap<String, String>,
    assets: day2_assets::Catalog,
    web_resources: day2::web_resources::Catalog,
    templates: day2::web_templates::Catalog,
    namespace: String,
    projection: day2::registry::Projection,
    shape: Option<day2::registry::AppShape>,
    platform_hashes: BTreeMap<String, String>,
    inference_sources: BTreeMap<String, String>,
    imports: Option<day2::instance_catalog::ImportedContracts>,
    import_fixtures: Vec<day2::development::ImportedQueryFixture>,
}

struct Bound {
    checked_types: Vec<u8>,
    schema: Schema,
    identities: day2::identity::Registry,
    outputs: day2::output_schema::Catalog,
    declarations: day2::registry::Catalog,
    connections: Vec<day2::connection_declaration::ConnectionDeclaration>,
}

fn prepare(
    root: &Path,
    app: &Path,
    overrides: Option<&Path>,
    import_context: Option<&BuildImportContext>,
) -> Result<Prepared> {
    let platform_hashes = platform_sources(root)?;
    let native_pin = native_toolchain::load(root)?;
    let roc = native_pin.verified_compiler(root)?;
    let rust_glue = native_pin.rust_glue_path();
    let target = native_pin.target;
    let pin = native_pin.value;
    let stage = root.join("artifacts/build");
    if stage.exists() {
        fs::remove_dir_all(&stage)?;
    }
    fs::create_dir_all(stage.join("sdk"))?;
    let mut hashes = BTreeMap::new();
    hashes.insert("compiler/roc".into(), digest(&fs::read(&roc)?));
    hashes.insert(
        target.pin_path().to_owned(),
        digest(&fs::read(root.join(target.pin_path()))?),
    );
    let captured = stage.join("sources/app");
    snapshot(app, &captured, &mut hashes, "app")?;
    if let Some(overrides) = overrides {
        snapshot(overrides, &captured, &mut hashes, "app")?;
    }
    ui_assembly::expand(root, &captured, &mut hashes)?;
    let modules = day2::app_sources::stage(&captured, &stage.join("app"))?;
    fs::write(
        stage.join("app-modules.json"),
        serde_json::to_vec_pretty(&modules)?,
    )?;
    fs::copy(
        captured.join(day2::identity::REGISTRY_FILE),
        stage.join("app").join(day2::identity::REGISTRY_FILE),
    )?;
    let namespace =
        day2::app_inference::namespace(&fs::read_to_string(stage.join("app/App.roc"))?)?;
    let projection =
        day2::registry::Projection::declared(&fs::read_to_string(stage.join("app/App.roc"))?)?;
    let mut import_fixtures = Vec::new();
    let imports = if let Some(context) = import_context {
        let metadata = fs::symlink_metadata(&context.lock)?;
        ensure!(
            metadata.file_type().is_file() && metadata.len() <= 1_048_576,
            "invalid import lock file"
        );
        let lock: day2::instance_catalog::ImportLock =
            day2::json::decode(&fs::read(&context.lock)?)?;
        ensure!(
            !lock.apps.contains_key(&namespace),
            "app cannot import its own exported contract"
        );
        let catalog =
            day2::instance_catalog::CandidateCatalog::from_instance_file(&context.instance)?;
        let imports =
            day2::instance_catalog::ImportedContracts::from_resolved(catalog.resolve(&lock)?)?;
        import_fixtures = day2::development::imported_query_fixtures(&context.instance, &imports)?;
        fs::write(
            stage.join("app").join(day2::import_codegen::MODULE),
            day2::import_codegen::module(&imports)?,
        )?;
        Some(imports)
    } else {
        None
    };
    fs::write(
        stage.join("app/AppIdentity.roc"),
        day2::app_inference::identity_module(&namespace)?,
    )?;
    fs::write(
        stage.join("app/SchemaSource.roc"),
        day2::app_inference::staged_schema_source(&stage.join("app"), &modules)?,
    )?;
    let assets = day2_assets::package(&captured.join("assets"), &stage)?;
    let web_resources = day2::web_resources::package(&captured.join("ui"), &stage)?;
    let templates = day2::web_templates::package(&captured.join("ui"), &stage)?;
    fs::write(
        stage.join("app/Assets.roc"),
        day2_assets::roc_module(&assets)?,
    )?;
    hashes.extend(day2::sdk::stage(&root.join("sdk"), &stage.join("sdk"))?);
    let inference_sources = ["Path.roc", "Read.roc", "Write.roc"]
        .into_iter()
        .map(|name| {
            Ok((
                name.to_owned(),
                fs::read_to_string(stage.join("sdk").join(name))?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    fs::write(
        stage.join("sdk/Template.roc"),
        day2::web_templates::roc_sdk_module(&templates)?,
    )?;
    fs::write(
        stage.join("app/Templates.roc"),
        day2::web_templates::roc_module(&templates)?,
    )?;
    fs::copy(
        root.join("tools/schema-platform.roc"),
        stage.join("app/schema-platform.roc"),
    )?;
    Ok(Prepared {
        roc,
        rust_glue,
        pin,
        target,
        stage,
        hashes,
        assets,
        web_resources,
        templates,
        namespace,
        projection,
        shape: None,
        platform_hashes,
        inference_sources,
        imports,
        import_fixtures,
    })
}

fn data(_app: &Path, _isolated_job: Option<&Path>, prepared: &mut Prepared) -> Result<Bound> {
    let stage = &prepared.stage;
    let hashes = &mut prepared.hashes;
    let checked_types = fs::read(stage.join("checked-types.json"))?;
    let mut schema = Schema::from_checked_types(&checked_types)?;
    let identities = day2::identity::prepare(&stage.join("app"), &schema, true)?;
    let registry_bytes = fs::read(stage.join("app").join(day2::identity::REGISTRY_FILE))?;
    fs::write(
        stage.join("app").join(day2::identity::REGISTRY_FILE),
        &registry_bytes,
    )?;
    hashes.insert(
        format!("app/{}", day2::identity::REGISTRY_FILE),
        digest(&registry_bytes),
    );
    schema.bind_identities(&identities)?;
    let mut outputs = day2::output_schema::from_checked_types(&checked_types)?;
    for output in outputs.values_mut() {
        output.shape.bind_identities(&schema)?;
    }
    fs::write(stage.join("app/Data.roc"), schema.data_module()?)?;
    fs::write(
        stage.join("app/Domains.roc"),
        day2::domain::module(&schema, false)?,
    )?;
    fs::write(stage.join("app/Inputs.roc"), schema.inputs_module()?)?;
    fs::write(
        stage.join("app/Outputs.roc"),
        day2::output_schema::roc_module(&outputs)?,
    )?;
    let sources = hashes
        .keys()
        .filter(|path| path.starts_with("app/") && path.ends_with(".roc"))
        .map(|path| fs::read_to_string(stage.join("sources").join(path)))
        .collect::<std::io::Result<Vec<_>>>()?;
    for (name, source) in day2::app_inference::provisional_modules(&sources)? {
        fs::write(stage.join("app").join(name), source)?;
    }
    fs::write(stage.join("sdk/types.roc"), day2::sdk::reflection_package())?;
    for (name, source) in &prepared.inference_sources {
        fs::write(
            stage.join("sdk").join(name),
            day2::app_inference::provisional_sdk(name, source)?,
        )?;
    }
    fs::write(
        stage.join("app/app-platform.roc"),
        day2::registry::app_platform_for(None, prepared.projection),
    )?;
    Ok(Bound {
        checked_types,
        schema,
        identities,
        outputs,
        declarations: day2::registry::Catalog::default(),
        connections: Vec::new(),
    })
}

fn checked_app(prepared: &Prepared, bound: &Bound) -> Result<(Vec<u8>, day2::registry::Catalog)> {
    let checked = fs::read(prepared.stage.join("checked-types.json"))?;
    let mut schema = Schema::from_checked_types(&checked)?;
    schema.bind_identities(&bound.identities)?;
    let mut outputs = day2::output_schema::from_checked_types(&checked)?;
    for output in outputs.values_mut() {
        output.shape.bind_identities(&schema)?;
    }
    ensure!(
        schema.models == bound.schema.models
            && schema.foreign_keys == bound.schema.foreign_keys
            && schema.domains == bound.schema.domains,
        "app reflection changed storage and domain definitions"
    );
    if bound.declarations.unified {
        ensure!(
            schema == bound.schema && outputs == bound.outputs,
            "final app reflection changed codec contracts"
        );
    }
    ensure!(
        Some(day2::registry::AppShape::from_checked_types(&checked)?) == prepared.shape,
        "App.definition changed during inference"
    );
    let catalog = day2::registry::from_checked_types(&checked)?;
    Ok((checked, catalog))
}

fn bind(root: &Path, prepared: &mut Prepared, bound: &mut Bound) -> Result<()> {
    let (checked, catalog) = checked_app(prepared, bound)?;
    bound.checked_types = checked;
    bound.schema = Schema::from_checked_types(&bound.checked_types)?;
    bound.schema.bind_identities(&bound.identities)?;
    bound.outputs = day2::output_schema::from_checked_types(&bound.checked_types)?;
    for output in bound.outputs.values_mut() {
        output.shape.bind_identities(&bound.schema)?;
    }
    bound.declarations = catalog;
    let stage = &prepared.stage;
    for (name, source) in &prepared.inference_sources {
        fs::write(stage.join("sdk").join(name), source)?;
    }
    fs::write(stage.join("app/Inputs.roc"), bound.schema.inputs_module()?)?;
    fs::write(
        stage.join("app/Outputs.roc"),
        day2::output_schema::roc_module(&bound.outputs)?,
    )?;
    fs::write(
        stage.join("registry.json"),
        serde_json::to_vec(&bound.declarations)?,
    )?;
    for (name, source) in
        bound
            .declarations
            .modules(&bound.schema, &bound.outputs, &bound.connections, false)?
    {
        fs::write(stage.join("app").join(name), source)?;
    }
    fs::write(stage.join("sdk/main.roc"), day2::sdk::app_platform())?;
    fs::write(
        stage.join("app/main.roc"),
        day2::registry::entrypoint(false),
    )?;
    let admission = root.join("artifacts/admission");
    if admission.exists() {
        fs::remove_dir_all(&admission)?;
    }
    day2::admission::prepare(
        stage,
        &admission,
        &bound.schema,
        &bound.outputs,
        &prepared.assets,
        prepared.imports.as_ref(),
    )?;
    Ok(())
}

fn publish(root: &Path, prepared: &mut Prepared, bound: &Bound) -> Result<PathBuf> {
    let Prepared {
        stage,
        hashes,
        assets,
        web_resources,
        templates,
        pin,
        imports,
        ..
    } = prepared;
    let Bound {
        checked_types,
        schema,
        identities,
        outputs,
        declarations,
        connections,
    } = bound;
    let mut worker = Worker::start(&stage.join("worker"))?;
    let raw_manifest = worker.exchange(b"manifest")?;
    fs::write(stage.join("manifest.json"), &raw_manifest)?;
    let manifest: Manifest = serde_json::from_slice(&raw_manifest)?;
    ensure!(
        manifest.namespace == prepared.namespace,
        "App.definition namespace differs from its static literal"
    );
    let mut names = std::collections::BTreeSet::new();
    for operation in &manifest.operations {
        ensure!(names.insert(&operation.name), "duplicate operation");
        ensure!(
            operation.name.len() <= 80
                && operation
                    .name
                    .split('.')
                    .all(|part| day2_contracts::names::identifier(part).is_ok()),
            "invalid operation name"
        );
        ensure!(
            ["command", "query"].contains(&operation.kind.as_str()),
            "unsupported operation kind"
        );
        ensure!(
            schema.inputs.contains_key(&operation.input_type),
            "missing checked input contract"
        );
    }
    day2::properties::validate_catalog(&manifest.properties)?;
    let app_contract = day2::app_contract::decode(&worker.exchange(b"app-contract")?)?;
    let worker_digest = digest(&fs::read(stage.join("worker"))?);
    let schema_digest = schema.hash()?;
    let platform_hashes = platform_sources(root)?;
    ensure!(
        platform_hashes == prepared.platform_hashes,
        "platform inputs changed during build; rebuild from one stable snapshot"
    );
    hashes.extend(platform_hashes);
    let mut artifact = serde_json::json!({
        "format": day2::artifact::CURRENT_FORMAT, "identities": identities, "namespace": manifest.namespace, "declarations": declarations,
        "checked_types_digest": digest(checked_types),
        "roc_version": pin["roc_version"], "worker_digest": worker_digest,
        "schema_digest": schema_digest, "schema": schema, "operations": manifest.operations,
        "properties": manifest.properties,
        "verification_limits": day2::artifact::VerificationLimits::QUALIFIED,
        "pages": manifest.pages,
        "schedules": manifest.schedules,
        "ingress": manifest.ingress,
        "redirects": manifest.redirects,
        "assets": assets,
        "web_resources": web_resources,
        "outputs": outputs,
        "templates": templates,
        "app_contract": app_contract,
        "sources": &*hashes, "admission": "local-spike-only",
    });
    let checked: day2::artifact::Artifact = serde_json::from_value(artifact.clone())?;
    if !declarations.credentials.is_empty() {
        artifact["credential_declarations"] =
            serde_json::to_value(day2::credential_declaration::decode(
                &worker.exchange(b"credential-contract")?,
                &checked,
            )?)?;
        let with_declarations: day2::artifact::Artifact = serde_json::from_value(artifact.clone())?;
        artifact["credential_manifest"] =
            serde_json::to_value(day2::credential_authority::manifest(&with_declarations)?)?;
    }
    let final_connections =
        day2::connection_declaration::decode(&worker.exchange(b"connection-contract")?, &checked)?;
    ensure!(
        final_connections == *connections,
        "connection requirements changed after SDK binding"
    );
    if !connections.is_empty() {
        artifact["connection_declarations"] = serde_json::to_value(connections)?;
    }
    artifact["export_manifest"] = serde_json::to_value(
        day2::operation_contract::Manifest::from_checked_artifact(&checked)?,
    )?;
    if let Some(imports) = imports {
        artifact["imports"] = serde_json::to_value(imports)?;
    }
    publish_contract(
        root,
        stage,
        hashes,
        assets,
        web_resources,
        templates,
        schema,
        artifact,
    )
}

pub(super) fn platform_sources(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut hashes = BTreeMap::new();
    for path in [
        "Cargo.toml",
        "Cargo.lock",
        "architecture-rules.json",
        "architecture-boundaries.json",
        "architecture-proofs.json",
        "architecture/clippy.toml",
        "rust-toolchain.toml",
        "toolchain.json",
        ".dockerignore",
        "build-dependencies/clanker-ui.json",
    ] {
        hashes.insert(path.to_string(), digest(&fs::read(root.join(path))?));
    }
    for directory in [
        "crates",
        "tools",
        "vendor",
        "assets",
        "ops",
        "infra",
        "deploy",
        "toolchains",
    ] {
        hash_tree(root, &root.join(directory), &mut hashes)?;
    }
    Ok(hashes)
}

/// Re-capture through the ordinary build adapter before selecting a cached fixture.
/// The complete platform recipe and its runtime campaigns still run on this checkout.
pub(super) fn admit_cached_fixture(
    root: &Path,
    app: &Path,
    overrides: Option<&Path>,
    imports: Option<&BuildImportContext>,
    directory: &Path,
) -> Result<()> {
    let mut prepared = prepare(root, app, overrides, imports)?;
    let loaded = day2::artifact::LoadedArtifact::load(directory)?;
    loaded.require_current_api()?;
    native_toolchain::verify_executable_target(
        prepared.target,
        loaded.materialize_worker()?.as_ref(),
    )?;
    let contract = loaded.contract();
    ensure!(
        contract.namespace == prepared.namespace && contract.imports == prepared.imports,
        "cached fixture namespace or consumed import contract changed"
    );
    // Build.data allocates identities against these same retained checked types.
    // Re-derive that ledger instead of trusting the cache's original input index.
    let schema = Schema::from_checked_types(&fs::read(directory.join("checked-types.json"))?)?;
    let identities = day2::identity::prepare(&prepared.stage.join("app"), &schema, true)?;
    ensure!(
        serde_json::to_value(&identities)? == serde_json::to_value(&contract.identities)?,
        "cached fixture identity ledger changed"
    );
    prepared.hashes.insert(
        format!("app/{}", day2::identity::REGISTRY_FILE),
        digest(&fs::read(
            prepared
                .stage
                .join("app")
                .join(day2::identity::REGISTRY_FILE),
        )?),
    );
    prepared.hashes.extend(prepared.platform_hashes);
    prepared
        .hashes
        .extend(native_toolchain::stage_system_link_inputs(
            prepared.target,
            &prepared.stage,
        )?);
    admit_fixture_sources(prepared.target, &prepared.hashes, &contract.sources)
}

fn admit_fixture_sources(
    target: native_toolchain::Target,
    expected: &BTreeMap<String, String>,
    sources: &BTreeMap<String, String>,
) -> Result<()> {
    let mut actual = sources.clone();
    // The release host archive is an output, admitted by the artifact's worker
    // digest and the separate exact compiler/profile/source cache identity.
    let archive = actual
        .remove(&format!("native/{}/libhost.a", target.roc_target()))
        .context("cached fixture native archive identity missing")?;
    ensure!(
        archive.len() == 71
            && archive.starts_with("sha256:")
            && archive[7..].bytes().all(|byte| byte.is_ascii_hexdigit()),
        "cached fixture native archive identity invalid"
    );
    ensure!(
        actual == *expected,
        "cached fixture closed source inputs changed"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn publish_contract(
    _root: &Path,
    stage: &Path,
    _hashes: &BTreeMap<String, String>,
    assets: &day2_assets::Catalog,
    web_resources: &day2::web_resources::Catalog,
    templates: &day2::web_templates::Catalog,
    schema: &Schema,
    artifact: Value,
) -> Result<PathBuf> {
    let contract: day2::artifact::Artifact = serde_json::from_value(artifact.clone())?;
    contract
        .app_contract
        .as_ref()
        .context("complete application contract required")?
        .validate(&contract)?;
    let routes = day2::routing::Catalog::from_artifact(&contract)?;
    for page in &contract.pages {
        let context = contract.page_context_schema(page)?;
        if page.live {
            day2::web_templates::validate_live_page(
                stage,
                templates,
                &page.template,
                &context,
                assets,
                Some(&routes),
            )?;
        }
        day2::web_templates::validate_routed_page(
            stage,
            templates,
            &page.template,
            &context,
            assets,
            &routes,
        )?;
        day2::web_templates::validate_routed_bindings(
            stage,
            templates,
            &page.template,
            &context,
            assets,
            &routes,
            &contract,
        )?;
    }
    let identity = digest(&serde_json::to_vec(&artifact)?);
    let directory = stage
        .join("candidates")
        .join(identity.trim_start_matches("sha256:"));
    fs::create_dir_all(&directory)?;
    day2::web_resources::copy_blobs(stage, &directory, web_resources)?;
    day2::web_templates::copy_blobs(stage, &directory, templates)?;
    if !assets.is_empty() {
        fs::create_dir_all(directory.join("assets"))?;
        for asset in assets.values() {
            let name = format!("{}.png", day2_assets::hash_part(&asset.digest)?);
            fs::copy(
                stage.join("assets").join(&name),
                directory.join("assets").join(name),
            )?;
        }
    }
    fs::copy(stage.join("worker"), directory.join("worker"))?;
    fs::copy(
        stage.join("app").join(day2::identity::REGISTRY_FILE),
        directory.join(day2::identity::REGISTRY_FILE),
    )?;
    fs::copy(
        stage.join("checked-types.json"),
        directory.join("checked-types.json"),
    )?;
    fs::write(
        directory.join("artifact.json"),
        serde_json::to_vec_pretty(&artifact)?,
    )?;
    fs::write(
        directory.join("schema.sql"),
        schema.ddl()?.join(";\n") + ";\n",
    )?;
    day2::artifact::LoadedArtifact::load(&directory)
        .context("native build published candidate admission")?;
    println!("Built candidate; verifying required application obligations");
    Ok(directory)
}

pub fn execute(
    root: &Path,
    app: &Path,
    overrides: Option<&Path>,
    isolated_job: Option<&Path>,
    import_context: Option<&BuildImportContext>,
    runner: &Path,
) -> Result<PathBuf> {
    let mut prepared = None;
    let mut bound = None;
    let mut done = BTreeSet::new();
    let mut published = None;
    let receipt = day2::automation::run(runner, &["build-recipe"], |request| {
        let parameters: BTreeMap<String, Value> = request.decode()?;
        ensure!(
            parameters.is_empty(),
            "compiler capabilities accept no recipe overrides"
        );
        ensure!(!done.contains(&request.action), "duplicate compiler effect");
        if request.action == "build-stage" {
            prepared = Some(prepare(root, app, overrides, import_context)?);
        } else {
            let prepared = prepared
                .as_mut()
                .context("stage source before compilation")?;
            let stage = &prepared.stage;
            let roc = &prepared.roc;
            match request.action.as_str() {
                "build-schema" => run(
                    root,
                    day2::sandbox::compiler(root, stage, roc)?
                        .arg("glue")
                        .arg(root.join("tools/SchemaGlue.roc"))
                        .arg(stage)
                        .arg(stage.join("app/schema-platform.roc")),
                )?,
                "build-data" => {
                    ensure!(done.contains("build-schema"), "checked types required");
                    bound = Some(data(app, isolated_job, prepared)?);
                }
                "build-app-shape" | "build-app-types" | "build-app-check" => {
                    let prerequisite = match request.action.as_str() {
                        "build-app-shape" => "build-data",
                        "build-app-types" => "build-witnesses",
                        _ => "build-bind",
                    };
                    ensure!(
                        done.contains(prerequisite),
                        "missing app inference prerequisite: {prerequisite}"
                    );
                    run(
                        root,
                        day2::sandbox::compiler(root, stage, roc)?
                            .arg("glue")
                            .arg(root.join("tools/SchemaGlue.roc"))
                            .arg(stage)
                            .arg(stage.join("app/app-platform.roc")),
                    )?;
                    if request.action == "build-app-check" {
                        let bound = bound.as_mut().context("bound app required")?;
                        let (checked, catalog) = checked_app(prepared, bound)?;
                        ensure!(
                            catalog == bound.declarations,
                            "final handles changed the inferred catalog"
                        );
                        bound.checked_types = checked;
                    }
                }
                "build-witnesses" => {
                    ensure!(
                        done.contains("build-app-shape"),
                        "checked App.definition shape required"
                    );
                    let shape = day2::registry::AppShape::from_checked_types(&fs::read(
                        stage.join("checked-types.json"),
                    )?)?;
                    ensure!(
                        shape.unified,
                        "App.definition requires unified Api.command/Api.query definitions"
                    );
                    fs::write(
                        stage.join("app/app-platform.roc"),
                        day2::registry::app_platform_for(Some(&shape), prepared.projection),
                    )?;
                    prepared.shape = Some(shape);
                }
                "build-bind" => {
                    ensure!(
                        done.contains("build-connection-contract"),
                        "checked connection metadata required"
                    );
                    bind(
                        root,
                        prepared,
                        bound.as_mut().context("bound data required")?,
                    )?;
                }
                "build-connection-contract" => {
                    ensure!(
                        done.contains("build-app-types") && done.contains("build-host"),
                        "checked registration inventory and pure host required"
                    );
                    let bound = bound.as_mut().context("bound data required")?;
                    let (_, catalog) = checked_app(prepared, bound)?;
                    if !catalog.connections.is_empty() {
                        let source = stage.join("app/connection-probe.roc");
                        let executable = stage.join("connection-probe");
                        fs::write(&source, day2::connection_codegen::probe(&catalog))?;
                        run(
                            root,
                            day2::sandbox::compiler(root, stage, roc)?
                                .arg("build")
                                .arg(&source)
                                .arg(format!("--output={}", executable.display())),
                        )?;
                        // This worker can only evaluate the pure projection.
                        // No runtime, authority provider or effect dispatcher
                        // participates in declaration discovery.
                        let raw = Worker::start(&executable)?.exchange(b"connection-contract")?;
                        bound.connections =
                            day2::connection_declaration::decode_catalog(&raw, &catalog)?;
                        fs::remove_file(source)?;
                        fs::remove_file(executable)?;
                    }
                    day2::connection_declaration::validate_catalog(&bound.connections, &catalog)?;
                    fs::write(
                        stage.join("connections.json"),
                        serde_json::to_vec(&bound.connections)?,
                    )?;
                }
                "build-admission" => {
                    ensure!(
                        done.contains("build-app-check"),
                        "final app reflection required"
                    );
                    let admission = root.join("artifacts/admission");
                    run(
                        root,
                        day2::sandbox::compiler(root, &admission, roc)?
                            .args(["check", "--no-cache"])
                            .arg(admission.join("app/main.roc")),
                    )?;
                }
                "build-glue" => {
                    ensure!(
                        done.contains("build-app-types"),
                        "checked app types required before pure ABI generation"
                    );
                    // The pure ABI is always Str -> Str and does not import
                    // authored App code. Product linking still requires both
                    // final native admission profiles below.
                    fs::write(stage.join("sdk/main.roc"), day2::sdk::app_platform())?;
                    fs::create_dir_all(root.join("crates/worker/generated"))?;
                    run(
                        root,
                        day2::sandbox::compiler(root, stage, roc)?.args([
                            "glue",
                            prepared.rust_glue,
                            "crates/worker/generated",
                            "sdk/main.roc",
                        ]),
                    )?;
                }
                "build-host" => {
                    ensure!(done.contains("build-glue"), "checked ABI required");
                    let mut cargo = if let Some(job) = isolated_job {
                        day2::sandbox::build_host(job, &job.join("rust/bin/cargo"))?
                    } else {
                        Command::new("cargo")
                    };
                    cargo.args(["build", "--locked"]);
                    if isolated_job.is_some() {
                        cargo.arg("--offline");
                    }
                    run(root, cargo.args(["-p", "day2-roc-worker", "--release"]))?;
                    prepared.hashes.extend(native_toolchain::stage_link_inputs(
                        prepared.target,
                        stage,
                        &root.join("target/release/libday2_roc_worker.a"),
                    )?);
                }
                "build-check" => {
                    ensure!(done.contains("build-admission"), "final admission required");
                    ensure!(bound.is_some(), "bound schema required");
                    run(
                        root,
                        day2::sandbox::compiler(root, stage, roc)?
                            .args(["check", "--no-cache"])
                            .arg(stage.join("app/main.roc")),
                    )?;
                }
                "build-link" => {
                    ensure!(
                        done.contains("build-host")
                            && done.contains("build-check")
                            && done.contains("build-admission"),
                        "checked app and native host required"
                    );
                    run(
                        root,
                        day2::sandbox::compiler(root, stage, roc)?
                            .arg("build")
                            .arg(stage.join("app/main.roc"))
                            .arg(format!("--output={}", stage.join("worker").display())),
                    )?;
                }
                "build-publish" => {
                    ensure!(done.contains("build-link"), "linked worker required");
                    let artifact =
                        publish(root, prepared, bound.as_ref().context("checked schema")?)?;
                    published = Some(artifact.clone());
                }
                "build-verify" => {
                    ensure!(
                        done.contains("build-publish"),
                        "candidate contract admission required"
                    );
                    let artifact = published.as_ref().context("candidate required")?;
                    let evidence = day2::development::verify_with_runner_imports(
                        artifact,
                        &stage.join("verification"),
                        day2::development::DEFAULT_SEED,
                        2,
                        runner,
                        &prepared.import_fixtures,
                    )
                    .context("native build required application verification")?;
                    ensure!(
                        evidence.verification_complete,
                        "application verification obligations incomplete"
                    );
                    fs::write(
                        artifact.join("verification.json"),
                        serde_json::to_vec_pretty(&evidence)?,
                    )?;
                }
                "build-select" => {
                    ensure!(
                        done.contains("build-verify"),
                        "verified application required before selection"
                    );
                    let artifact = published.as_ref().context("candidate required")?;
                    let loaded = day2::artifact::LoadedArtifact::load(artifact)
                        .context("native build candidate selection admission")?;
                    ensure!(
                        platform_sources(root)? == prepared.platform_hashes,
                        "platform inputs changed during verification"
                    );
                    let destination = root
                        .join("artifacts")
                        .join(loaded.id().trim_start_matches("sha256:"));
                    if destination.exists() {
                        let existing = day2::artifact::LoadedArtifact::load(&destination)
                            .context("native build existing selection admission")?;
                        ensure!(existing.id() == loaded.id(), "existing artifact differs");
                        fs::copy(
                            artifact.join("verification.json"),
                            destination.join("verification.json"),
                        )?;
                    } else {
                        fs::rename(artifact, &destination)?;
                    }
                    use std::io::Write;
                    let mut pointer = tempfile::NamedTempFile::new_in(root.join("artifacts"))?;
                    pointer.write_all(&serde_json::to_vec_pretty(
                        &json!({ "artifact": loaded.id() }),
                    )?)?;
                    pointer.as_file().sync_all()?;
                    pointer.persist(root.join("artifacts/current.json"))?;
                    println!("Built and verified artifact: {}", destination.display());
                    published = Some(destination.clone());
                    done.insert(request.action);
                    return Ok(json!({"artifact":destination}));
                }
                _ => bail!("unknown compiler capability: {}", request.action),
            }
        }
        done.insert(request.action);
        Ok(json!({}))
    })?;
    let artifact = published.context("workflow omitted artifact publication")?;
    ensure!(
        done.contains("build-select"),
        "workflow omitted required application verification and selection"
    );
    ensure!(
        receipt["artifact"].as_str() == artifact.to_str(),
        "workflow build receipt differs from published artifact"
    );
    Ok(artifact)
}

#[cfg(test)]
mod platform_input_tests {
    use super::*;

    #[test]
    fn architecture_policy_tampering_changes_native_build_identity() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        fs::create_dir(root.join("architecture"))?;
        fs::create_dir(root.join("build-dependencies"))?;
        for name in [
            "Cargo.toml",
            "Cargo.lock",
            "architecture-rules.json",
            "architecture-boundaries.json",
            "architecture-proofs.json",
            "architecture/clippy.toml",
            "rust-toolchain.toml",
            "toolchain.json",
            ".dockerignore",
            "build-dependencies/clanker-ui.json",
        ] {
            fs::write(root.join(name), b"approved input")?;
        }
        for name in [
            "crates",
            "tools",
            "vendor",
            "assets",
            "ops",
            "infra",
            "deploy",
            "toolchains",
        ] {
            fs::create_dir(root.join(name))?;
        }
        let approved = platform_sources(root)?;
        assert_eq!(approved, platform_sources(root)?);
        for policy in [
            "architecture-rules.json",
            "architecture-boundaries.json",
            "architecture-proofs.json",
            "architecture/clippy.toml",
            "build-dependencies/clanker-ui.json",
        ] {
            assert_eq!(approved[policy], digest(b"approved input"));
            fs::write(root.join(policy), b"weakened restrictions")?;
            let changed = platform_sources(root)?;
            assert_ne!(approved, changed);
            assert_ne!(approved[policy], changed[policy]);
            fs::remove_file(root.join(policy))?;
            assert!(platform_sources(root).is_err());
            fs::write(root.join(policy), b"approved input")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod fixture_cache_admission_tests {
    use super::*;

    #[test]
    fn cached_fixture_requires_exact_closed_source_set_and_native_output() -> Result<()> {
        let expected: BTreeMap<String, String> = [
            "app/App.roc",
            "app/ui/page.html",
            "app/model-identities.json",
            "sdk/contracts/Api.roc",
            "toolchain.json",
            "ui/package",
            "ui-provider/executable",
        ]
        .into_iter()
        .map(|name| (name.into(), digest(name.as_bytes())))
        .collect();
        let mut artifact = expected.clone();
        artifact.insert("native/arm64mac/libhost.a".into(), digest(b"host archive"));
        admit_fixture_sources(native_toolchain::Target::MacArm64, &expected, &artifact)?;
        for name in expected.keys() {
            let mut changed = artifact.clone();
            changed.insert(name.clone(), digest(b"changed input"));
            assert!(
                admit_fixture_sources(native_toolchain::Target::MacArm64, &expected, &changed)
                    .is_err(),
                "{name}"
            );
            let mut missing = artifact.clone();
            missing.remove(name);
            assert!(
                admit_fixture_sources(native_toolchain::Target::MacArm64, &expected, &missing)
                    .is_err(),
                "{name}"
            );
        }
        let mut extra = artifact.clone();
        extra.insert("app/deleted.roc".into(), digest(b"old input"));
        assert!(
            admit_fixture_sources(native_toolchain::Target::MacArm64, &expected, &extra).is_err()
        );
        let mut missing_host = artifact.clone();
        missing_host.remove("native/arm64mac/libhost.a");
        assert!(
            admit_fixture_sources(native_toolchain::Target::MacArm64, &expected, &missing_host)
                .is_err()
        );
        artifact.insert("native/arm64mac/libhost.a".into(), "not a digest".into());
        assert!(
            admit_fixture_sources(native_toolchain::Target::MacArm64, &expected, &artifact)
                .is_err()
        );
        Ok(())
    }
    #[test]
    fn cached_fixture_linker_inputs_and_native_archive_are_target_bound() -> Result<()> {
        for target in [
            native_toolchain::Target::LinuxX64,
            native_toolchain::Target::LinuxArm64,
        ] {
            let prefix = format!("native/{}", target.roc_target());
            let expected = BTreeMap::from([
                ("app/App.roc".into(), digest(b"app")),
                (
                    format!("{prefix}/libc.so.6"),
                    digest(b"current reviewed image libc"),
                ),
                (
                    format!("{prefix}/loader"),
                    digest(b"current reviewed image loader"),
                ),
            ]);
            let host = format!("{prefix}/libhost.a");
            let mut sources = expected.clone();
            sources.insert(host.clone(), digest(b"native output"));
            admit_fixture_sources(target, &expected, &sources)?;
            for name in expected.keys() {
                let mut changed = sources.clone();
                changed.insert(name.clone(), digest(b"foreign source or image"));
                assert!(admit_fixture_sources(target, &expected, &changed).is_err());
                let mut missing = sources.clone();
                missing.remove(name);
                assert!(admit_fixture_sources(target, &expected, &missing).is_err());
            }
            sources.remove(&host);
            sources.insert(
                "native/arm64mac/libhost.a".into(),
                digest(b"foreign host output"),
            );
            assert!(admit_fixture_sources(target, &expected, &sources).is_err());
        }
        Ok(())
    }
}
