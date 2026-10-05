//! Native compiler capabilities. Build.roc owns their order; this adapter owns
//! pinned toolchains, admission, checked codecs and artifact publication.
use super::*;
use serde_json::{Value, json};
use std::collections::BTreeSet;

struct Prepared {
    roc: PathBuf,
    rust_glue: &'static str,
    pin: Value,
    target: native_toolchain::Target,
    stage: PathBuf,
    hashes: BTreeMap<String, String>,
    assets: day2::assets::Catalog,
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
    ui_adapter_port::expand(app, &captured, &mut hashes)?;
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
    let assets = day2::assets::package(&captured.join("assets"), &stage)?;
    let web_resources = day2::web_resources::package(&captured.join("ui"), &stage)?;
    let templates = day2::web_templates::package(&captured.join("ui"), &stage)?;
    fs::write(
        stage.join("app/Assets.roc"),
        day2::assets::roc_module(&assets)?,
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
    for (name, source) in bound
        .declarations
        .modules(&bound.schema, &bound.outputs, false)?
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
                    .all(|part| day2::schema::identifier(part).is_ok()),
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
    if !declarations.connections.is_empty() {
        artifact["connection_declarations"] =
            serde_json::to_value(day2::connection_declaration::decode(
                &worker.exchange(b"connection-contract")?,
                &checked,
            )?)?;
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

#[allow(clippy::too_many_arguments)]
fn publish_contract(
    _root: &Path,
    stage: &Path,
    _hashes: &BTreeMap<String, String>,
    assets: &day2::assets::Catalog,
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
            let name = format!("{}.png", day2::assets::hash_part(&asset.digest)?);
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
    day2::artifact::LoadedArtifact::load(&directory)?;
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
                        done.contains("build-app-types"),
                        "checked callback types required"
                    );
                    bind(
                        root,
                        prepared,
                        bound.as_mut().context("bound data required")?,
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
                        done.contains("build-admission"),
                        "admission required before ABI generation"
                    );
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
                        done.contains("build-host") && done.contains("build-check"),
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
                    )?;
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
                    let loaded = day2::artifact::LoadedArtifact::load(artifact)?;
                    ensure!(
                        platform_sources(root)? == prepared.platform_hashes,
                        "platform inputs changed during verification"
                    );
                    let destination = root
                        .join("artifacts")
                        .join(loaded.id().trim_start_matches("sha256:"));
                    if destination.exists() {
                        let existing = day2::artifact::LoadedArtifact::load(&destination)?;
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
