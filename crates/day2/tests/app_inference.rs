//! Mutate isolated copies of the ordinary Reports app. The final generated root
//! type must be consumed by both compiler profiles, never merely emitted.
use anyhow::{Context, Result, ensure};
use day2::{artifact::LoadedArtifact, registry, sandbox};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

struct Fixture {
    root: PathBuf,
    temporary: tempfile::TempDir,
    stage: PathBuf,
    artifact: LoadedArtifact,
    contract: day2::artifact::Artifact,
    authored: BTreeSet<PathBuf>,
}

impl Fixture {
    fn new() -> Result<Self> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()?;
        let artifact = LoadedArtifact::load(Path::new(
            &std::env::var_os("DAY2_TEST_REPORTS_ARTIFACT").context("run xtask verify-reports")?,
        ))?;
        let temporary = tempfile::tempdir_in(root.join("artifacts"))?;
        let stage = temporary.path().join("stage");
        fs::create_dir_all(stage.join("app"))?;
        let modules = day2::app_sources::stage(&root.join("examples/reports"), &stage.join("app"))?;
        fs::copy(
            root.join("examples/reports")
                .join(day2::identity::REGISTRY_FILE),
            stage.join("app").join(day2::identity::REGISTRY_FILE),
        )?;
        let schema_source =
            day2::app_inference::staged_schema_source(&stage.join("app"), &modules)?;
        let authored = modules
            .into_keys()
            .map(|name| stage.join("app").join(format!("{name}.roc")))
            .collect();
        day2::sdk::stage(&root.join("sdk"), &stage.join("sdk"))?;
        let contract = &artifact.contract();
        for (name, source) in
            contract
                .declarations
                .modules(&contract.schema, &contract.outputs, false)?
        {
            fs::write(stage.join("app").join(name), source)?;
        }
        for (name, source) in [
            (
                "AppIdentity.roc",
                day2::app_inference::identity_module("reports")?,
            ),
            ("SchemaSource.roc", schema_source),
            ("Data.roc", contract.schema.data_module()?),
            (
                "Domains.roc",
                day2::domain::module(&contract.schema, false)?,
            ),
            ("Inputs.roc", contract.schema.inputs_module()?),
            (
                "Outputs.roc",
                day2::output_schema::roc_module(&contract.outputs)?,
            ),
            ("Assets.roc", day2_assets::roc_module(&contract.assets)?),
            (
                "Templates.roc",
                day2::web_templates::roc_module(&contract.templates)?,
            ),
            ("main.roc", registry::entrypoint(false)),
            (
                "app-platform.roc",
                // Mirror the build: whether to project `schedules` is read from
                // App.roc, because no type table exists yet to ask.
                registry::app_platform_for(
                    None,
                    registry::Projection::declared(&fs::read_to_string(
                        stage.join("app/App.roc"),
                    )?)?,
                ),
            ),
        ] {
            fs::write(stage.join("app").join(name), source)?;
        }
        fs::write(
            stage.join("sdk/Template.roc"),
            day2::web_templates::roc_sdk_module(&contract.templates)?,
        )?;
        fs::write(stage.join("sdk/types.roc"), day2::sdk::reflection_package())?;
        fs::write(stage.join("sdk/main.roc"), day2::sdk::app_platform())?;
        fs::write(
            stage.join("registry.json"),
            serde_json::to_vec(&contract.declarations)?,
        )?;
        Ok(Self {
            root,
            temporary,
            stage,
            contract: artifact.contract().clone(),
            artifact,
            authored,
        })
    }

    fn change(&self, file: &str, from: &str, to: &str) -> Result<()> {
        let path = self.stage.join("app").join(file);
        let source = fs::read_to_string(&path)?;
        ensure!(
            source.contains(from),
            "test mutation no longer matches {file}: {from}"
        );
        fs::write(path, source.replacen(from, to, 1))?;
        Ok(())
    }

    fn check(&self) -> Result<()> {
        let restricted = self.temporary.path().join("admission");
        day2::admission::prepare(
            &self.stage,
            &restricted,
            &self.contract.schema,
            &self.contract.outputs,
            &self.contract.assets,
            None,
        )?;
        for profile in [&self.stage, &restricted] {
            let output = sandbox::compiler(
                &self.root,
                profile,
                &self.root.join("../.toolchains/roc").canonicalize()?,
            )?
            .args(["check", "--no-cache"])
            .arg(profile.join("app/main.roc"))
            .output()?;
            ensure!(
                output.status.success(),
                "Roc admission failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    fn reflect(&self) -> Result<Vec<u8>> {
        let output = sandbox::compiler(
            &self.root,
            &self.stage,
            &self.root.join("../.toolchains/roc").canonicalize()?,
        )?
        .args(["glue", "--no-cache"])
        .arg(self.root.join("tools/SchemaGlue.roc"))
        .arg(&self.stage)
        .arg(self.stage.join("app/app-platform.roc"))
        .output()?;
        ensure!(
            output.status.success(),
            "reflection failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(fs::read(self.stage.join("checked-types.json"))?)
    }

    fn rebind(&mut self) -> Result<()> {
        let mut original = Vec::new();
        for name in ["Path.roc", "Read.roc", "Write.roc"] {
            let path = self.stage.join("sdk").join(name);
            let source = fs::read_to_string(&path)?;
            fs::write(&path, day2::app_inference::provisional_sdk(name, &source)?)?;
            original.push((path, source));
        }
        // New operations need the same provisional handles as a clean build;
        // the existing artifact cannot supply their selectors or nominal codecs.
        // Like a fresh build, discovery sees authored sources only. Feeding the
        // previous generated registry back in would invent provisional handles
        // from private dispatcher members that the application never references.
        let sources = self
            .authored
            .iter()
            .map(fs::read_to_string)
            .collect::<std::io::Result<Vec<_>>>()?;
        for (name, source) in day2::app_inference::provisional_modules(&sources)? {
            fs::write(self.stage.join("app").join(name), source)?;
        }
        // Use the same two reflection passes as the build: discover registered
        // names, then export checked type witnesses for precisely those names.
        let shape = registry::AppShape::from_checked_types(
            &self.reflect().context("discover registered operations")?,
        )?;
        fs::write(
            self.stage.join("app/app-platform.roc"),
            registry::app_platform_for(
                Some(&shape),
                registry::Projection::declared(&fs::read_to_string(
                    self.stage.join("app/App.roc"),
                )?)?,
            ),
        )?;
        let checked = self.reflect().context("reflect operation codecs")?;
        for (path, source) in original {
            fs::write(path, source)?;
        }
        let mut schema = day2::schema::Schema::from_checked_types(&checked)?;
        schema.bind_identities(&self.contract.identities)?;
        let mut outputs = day2::output_schema::from_checked_types(&checked)?;
        for output in outputs.values_mut() {
            output.shape.bind_identities(&schema)?;
        }
        let catalog = registry::from_checked_types(&checked)?;
        for (name, source) in catalog.modules(&schema, &outputs, false)? {
            fs::write(self.stage.join("app").join(name), source)?;
        }
        fs::write(self.stage.join("app/Inputs.roc"), schema.inputs_module()?)?;
        fs::write(
            self.stage.join("app/Outputs.roc"),
            day2::output_schema::roc_module(&outputs)?,
        )?;
        fs::write(
            self.stage.join("registry.json"),
            serde_json::to_vec(&catalog)?,
        )?;
        self.contract.schema = schema;
        self.contract.outputs = outputs;
        self.contract.declarations = catalog;
        Ok(())
    }
}

#[test]
fn ordinary_reports_requires_its_complete_root_in_both_profiles() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.check()?;
    assert!(!fixture.stage.join("app/Catalog.roc").exists());
    assert!(!fixture.stage.join("app/ApiContract.roc").exists());
    assert!(!fixture.stage.join("app/ApiDocs.roc").exists());
    let catalog = registry::from_checked_types(&fs::read(
        fixture.artifact.directory().join("checked-types.json"),
    )?)?;
    assert!(catalog.unified);
    // Named rather than counted: a bare count still passes when a command is
    // renamed, and says nothing about which ones the root must carry.
    assert_eq!(
        catalog.commands.keys().collect::<Vec<_>>(),
        ["analyze", "notify", "revise", "submit", "sweep"]
    );
    assert_eq!(
        catalog.queries.keys().collect::<Vec<_>>(),
        ["detail", "list"]
    );
    assert!(serde_json::to_value(&catalog)?.get("jobs").is_none());
    assert!(
        fixture
            .contract
            .sources
            .contains_key("app/commands/submit/SubmitReport.roc")
    );
    assert!(
        fixture
            .contract
            .sources
            .contains_key("app/storage/Models.roc")
    );
    assert_eq!(
        fixture.contract.schema.models["reports"]
            .roc_type
            .as_deref(),
        Some("Models.Report")
    );
    // No host filename convention: only ordinary Roc imports bind meaning.
    let renamed = Fixture::new()?;
    let path = renamed.stage.join("app/Routes.roc");
    let source = fs::read_to_string(&path)?.replace("Routes ::", "Navigation ::");
    fs::remove_file(path)?;
    fs::write(renamed.stage.join("app/Navigation.roc"), source)?;
    let app = renamed.stage.join("app/App.roc");
    fs::write(
        &app,
        fs::read_to_string(&app)?.replace("import Routes", "import Navigation as Routes"),
    )?;
    renamed.check()?;
    let without_demo = Fixture::new()?;
    without_demo.change("App.roc", "import Demo\n", "")?;
    without_demo.change("App.roc", "examples: [Demo.definition]", "examples: []")?;
    fs::remove_file(without_demo.stage.join("app/Demo.roc"))?;
    without_demo.check()?;
    Ok(())
}

#[test]
fn separate_internal_commands_infer_independent_nominal_types_and_require_complete_definitions()
-> Result<()> {
    let mut fixture = Fixture::new()?;
    for name in ["AnalyzeReport", "AnalyzeReportTypes"] {
        let source = fs::read_to_string(fixture.stage.join("app").join(format!("{name}.roc")))?;
        let path = fixture.stage.join("app").join(format!(
            "{}.roc",
            name.replace("AnalyzeReport", "SecondAnalysis")
        ));
        fs::write(
            &path,
            source
                .replace("AnalyzeReport", "SecondAnalysis")
                .replace("Selectors.analyze_input_", "Selectors.second_input_"),
        )?;
        fixture.authored.insert(path);
    }
    fixture.change(
        "App.roc",
        "import AnalyzeReport",
        "import AnalyzeReport\nimport SecondAnalysis",
    )?;
    fixture.change(
        "App.roc",
        "analyze: AnalyzeReport.definition,",
        "analyze: AnalyzeReport.definition, second: SecondAnalysis.definition,",
    )?;
    fixture.rebind()?;
    let mut incomplete: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.stage.join("checked-types.json"))?)?;
    incomplete[0]["entries"]
        .as_array_mut()
        .context("compiler entries")?
        .retain(|entry| entry["symbol"] != "day2_command_input_second");
    assert!(
        registry::from_checked_types(&serde_json::to_vec(&incomplete)?).is_err(),
        "missing command type evidence accepted"
    );
    let catalog = &fixture.contract.declarations;
    // The five reports commands plus this fixture's synthesized `second`.
    assert_eq!(catalog.commands.len(), 6);
    assert_ne!(
        catalog.commands["analyze"].input,
        catalog.commands["second"].input
    );
    assert_eq!(
        catalog.commands["analyze"].output,
        catalog.commands["second"].output
    );
    fixture.check()?;
    let second = fixture.stage.join("app/SecondAnalysis.roc");
    let complete_definition = fs::read_to_string(&second)?;
    fixture.change(
        "SecondAnalysis.roc",
        "verification: { input: verify_input, check: verify_result }",
        "",
    )?;
    assert!(
        fixture.check().is_err(),
        "a second command omitted its verification"
    );
    fs::write(
        second,
        complete_definition
            .replace(
                "import SecondAnalysisTypes",
                "import SecondAnalysisTypes\nimport AnalyzeReport",
            )
            .replace(
                "Handler.prepared(prepare, decide)",
                "Handler.prepared(prepare, AnalyzeReport.decide)",
            ),
    )?;
    assert!(
        fixture.check().is_err(),
        "decision from another nominal command accepted"
    );
    Ok(())
}

#[test]
fn a_structural_request_alias_is_rejected_during_codec_binding() -> Result<()> {
    let mut fixture = Fixture::new()?;
    // Prove the binder's nominal check independently of compiler diagnostics:
    // an anonymous record has the same fields and no nominal name in native evidence.
    let mut evidence: serde_json::Value = serde_json::from_slice(&fs::read(
        fixture.artifact.directory().join("checked-types.json"),
    )?)?;
    let mut changed = 0;
    for node in evidence[0]["types"]
        .as_array_mut()
        .context("compiler types")?
    {
        if node["name"] == "SubmitReportTypes.Input" {
            assert_eq!(node["kind"], "record");
            node["name"] = serde_json::json!("");
            changed += 1;
        }
    }
    assert!(changed > 0, "missing positive nominal evidence");
    let bytes = serde_json::to_vec(&evidence)?;
    let error = day2::schema::Schema::from_checked_types(&bytes)
        .expect_err("anonymous request evidence accepted");
    assert!(
        format!("{error:#}").contains("unsupported qualified Roc type name"),
        "{error:#}"
    );

    // The pinned compiler sometimes crashes while reflecting this invalid source.
    // Source admission must still fail; that failure alone is not our binder proof.
    fixture.change("SubmitReportTypes.roc", "Input :=", "Input :")?;
    assert!(
        fixture.rebind().is_err(),
        "structural registered input accepted"
    );
    Ok(())
}

#[test]
fn resource_handles_and_issuance_context_cannot_be_forged_or_broadened() -> Result<()> {
    let ordinary = Fixture::new()?;
    ordinary.change(
        "GetReport.roc",
        "import pf.Context",
        "import pf.Context\nimport pf.Resource",
    )?;
    ordinary.change("GetReport.roc","GetReport :: [].{","GetReport :: [].{\n\tdecode : Str -> Try({ token : Str }, _)\n\tdecode = |raw| Json.parse(raw)\n\tnarrow : Context -> Observe(Resource)\n\tnarrow = |context| Resource.bind(context, \"notifications\").and_then(|resource| Resource.restrict_limits(resource, { max_request_bytes: 256, max_response_bytes: 512, max_calls_per_invocation: 1 })).and_then(|resource| Resource.expires_at(resource, 1000))\n")?;
    ordinary.check()?;
    for method in [
        "forge : Str -> Try(Resource, _)\n\tforge = |raw| Json.parse(raw)",
        "forge : Str -> Try(Context, _)\n\tforge = |raw| Json.parse(raw)",
        "forge : Resource\n\tforge = { token: \"guessed\" }",
        "broaden : Resource -> Observe(Resource)\n\tbroaden = |resource| Resource.bind(resource, \"notifications\")",
        "token : Resource -> Str\n\ttoken = |resource| Resource.token(resource)",
    ] {
        let fixture = Fixture::new()?;
        fixture.change(
            "GetReport.roc",
            "import pf.Context",
            "import pf.Context\nimport pf.Resource",
        )?;
        fixture.change(
            "GetReport.roc",
            "GetReport :: [].{",
            &format!("GetReport :: [].{{\n\t{method}\n"),
        )?;
        let error = fixture
            .check()
            .err()
            .with_context(|| format!("resource authority forgery compiled: {method}"))?;
        ensure!(
            format!("{error:#}").contains("Roc admission failed"),
            "wrong resource failure boundary: {error:#}"
        );
    }
    Ok(())
}

#[test]
fn omissions_stale_references_and_forged_factories_fail_compilation() -> Result<()> {
    let cases = [
        (
            "App.roc",
            "submit: SubmitReport.definition",
            "submit: { _ = SubmitReport.definition.command_program()\n SubmitReport.definition }",
        ),
        (
            "App.roc",
            "submit: SubmitReport.definition",
            "submit: { _ = SubmitReport.definition.admission_command_program()\n SubmitReport.definition }",
        ),
        (
            "App.roc",
            "detail: GetReport.definition",
            "detail: { _ = GetReport.definition.query_program()\n GetReport.definition }",
        ),
        (
            "NotifyReady.roc",
            "Observe.local(Query.get(Data.reports, input.report_id))",
            "Observe.local(Tx.get(Data.reports, input.report_id))",
        ),
        (
            "NotifyReady.roc",
            "Effects.value({ id: \"\", status: \"skipped\" })",
            "Tx.succeed({ id: \"\", status: \"skipped\" })",
        ),
        (
            "GetReport.roc",
            "Notifications.latest(context, input.report_id.to_str())",
            "Observe.capability(\"notifications.latest.v1\", \"{}\")",
        ),
        (
            "GetReport.roc",
            "Notifications.latest(context, input.report_id.to_str())",
            "Observe.admission_capability(\"notifications.latest.v1\", \"{}\")",
        ),
        // Storage is platform-generated: a leftover App.definition.storage no longer fits Product.
        (
            "App.roc",
            "namespace: \"reports\",",
            "namespace: \"reports\",\n\t\tstorage: {},",
        ),
        // A key names the model's own columns, and a one-column key must be a record.
        ("Models.roc", "ready: row.ready", "ready: row.readied"),
        (
            "Models.roc",
            "{ announced: row.announced, ready: row.ready }",
            "{ ready }",
        ),
        ("SubmitReport.roc", "contract,", ""),
        (
            "SubmitReport.roc",
            "verification: { input: verify_input, check: verify_result }",
            "",
        ),
        (
            "SubmitReportTypes.roc",
            "text : Text(Document) }",
            "text : Text(Document), note : Str }",
        ),
        ("App.roc", "errors: {},", ""),
        ("App.roc", "examples: [Demo.definition],", ""),
        ("App.roc", "presentation:", "unknown_presentation:"),
        (
            "App.roc",
            "submit: SubmitReport.definition",
            "detail: SubmitReport.definition",
        ),
        (
            "SubmitReport.roc",
            "handler: Handler.local(handle)",
            "handler: verify_input",
        ),
        (
            "App.roc",
            "properties: { reports: ReportInvariants.reports }",
            "properties: {}",
        ),
        (
            "ReportView.roc",
            "id: \"The stable report identifier.\",",
            "",
        ),
        (
            "ListReports.roc",
            "each: ReportView.fields",
            "each: { id: \"ID\" }",
        ),
        (
            "SubmitReport.roc",
            "title: \"The title for the new report.\",",
            "obsolete: \"Old field.\",",
        ),
        (
            "ReviseReport.roc",
            "Selectors.detail_output_id",
            "Selectors.detail_output_text",
        ),
        (
            "ReviseReport.roc",
            "Selectors.detail_output_version",
            "Selectors.detail_output_id",
        ),
        (
            "GetReport.roc",
            "Selectors.submit_output_id",
            "Selectors.submit_input_title",
        ),
        ("SubmitReport.roc", "Commands.analyze", "Commands.removed"),
        ("Routes.roc", "Reads.detail", "Reads.removed"),
        (
            "ReviseReport.roc",
            "Tx.get(Data.reports, input.report_id)",
            "Tx.reject(\"undocumented failure\")",
        ),
        (
            "ReviseReport.roc",
            "Tx.get(Data.reports, input.report_id)",
            "Tx.host_reject(\"forbidden bypass\")",
        ),
        (
            "ReportView.roc",
            "Domains.title(\"Weekly report\")",
            "pf.Text.from_spec(pf.TextSpec.define({ maximum_bytes: 999, nonblank: Bool.False, description: \"bypass\" }), \"Weekly report\")",
        ),
        (
            "AnalyzeReport.roc",
            "AnalyzeReportTypes.Result -> Tx(ReportView.Saved)",
            "AnalyzeReportTypes.Input -> Tx(ReportView.Saved)",
        ),
        ("AnalyzeReport.roc", "contract,", ""),
        (
            "AnalyzeReport.roc",
            "verification: { input: verify_input, check: verify_result }",
            "",
        ),
    ];
    for (file, from, to) in cases {
        let fixture = Fixture::new()?;
        fixture.change(file, from, to)?;
        let error = fixture
            .check()
            .err()
            .with_context(|| format!("invalid application compiled: {file}: {from}"))?;
        ensure!(
            format!("{error:#}").contains("Roc admission failed"),
            "wrong failure boundary for {file}: {error:#}"
        );
    }
    for module in [
        "SubmitReport.roc",
        "SubmitReportTypes.roc",
        "ReportScenarios.roc",
        "Models.roc",
        "AnalyzeReport.roc",
        "Demo.roc",
    ] {
        let fixture = Fixture::new()?;
        fs::remove_file(fixture.stage.join("app").join(module))?;
        assert!(fixture.check().is_err(), "missing {module} compiled");
    }
    for (expression, imports) in [
        (
            "Text.from_spec(Title.rules, \"Weekly report\")",
            "import pf.Text\nimport Title\n",
        ),
        (
            "Text.admission_from_spec(Title.rules, \"Weekly report\")",
            "import pf.Text\nimport Title\n",
        ),
    ] {
        let fixture = Fixture::new()?;
        fixture.change(
            "ReportView.roc",
            "import Domains",
            &format!("import Domains\n{imports}"),
        )?;
        fixture.change(
            "ReportView.roc",
            "Domains.title(\"Weekly report\")",
            expression,
        )?;
        ensure!(
            fixture.check().is_err(),
            "application forged a domain constructor"
        );
    }
    Ok(())
}
