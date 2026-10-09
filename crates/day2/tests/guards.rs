use anyhow::{Context, Result, ensure};
use day2::{artifact::LoadedArtifact, sandbox, worker::Worker};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    net::TcpListener,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn verified_artifact() -> Result<LoadedArtifact> {
    let path = std::env::var_os("DAY2_TEST_RELATIONAL_ARTIFACT")
        .context("run xtask verify or set DAY2_TEST_RELATIONAL_ARTIFACT to the built relational conformance artifact")?;
    LoadedArtifact::load(Path::new(&path))
}

fn compiler_fixture(root: &Path, stage: &Path, artifact: &LoadedArtifact) -> Result<()> {
    let app = stage.join("app");
    let sdk = stage.join("sdk");
    fs::create_dir(&app)?;
    fs::create_dir(&sdk)?;
    let source = root.join("fixtures/relational-conformance");
    let modules = day2::app_sources::stage(&source, &app)?;
    for path in modules.values() {
        let name = format!("app/{}", path.display());
        ensure!(
            artifact.contract().sources.get(&name)
                == Some(&day2::digest(&fs::read(source.join(path))?)),
            "conformance fixture source differs from verified artifact: {name}"
        );
    }
    day2::sdk::stage(&root.join("sdk"), &sdk)?;
    fs::copy(
        source.join(day2::identity::REGISTRY_FILE),
        app.join(day2::identity::REGISTRY_FILE),
    )?;
    for (module, source) in [
        (
            "SchemaSource.roc",
            day2::app_inference::staged_schema_source(&app, &modules)?,
        ),
        ("Data.roc", artifact.contract().schema.data_module()?),
        (
            "Domains.roc",
            day2::domain::module(&artifact.contract().schema, false)?,
        ),
        (
            "AppIdentity.roc",
            day2::app_inference::identity_module("deals")?,
        ),
        ("Inputs.roc", artifact.contract().schema.inputs_module()?),
        (
            "Outputs.roc",
            day2::output_schema::roc_module(&artifact.contract().outputs)?,
        ),
        (
            "Assets.roc",
            day2_assets::roc_module(&artifact.contract().assets)?,
        ),
        (
            "Templates.roc",
            day2::web_templates::roc_module(&artifact.contract().templates)?,
        ),
    ] {
        fs::write(app.join(module), source)?;
    }
    for (module, source) in artifact.contract().declarations.modules(
        &artifact.contract().schema,
        &artifact.contract().outputs,
        false,
    )? {
        fs::write(app.join(module), source)?;
    }
    fs::write(
        sdk.join("Template.roc"),
        day2::web_templates::roc_sdk_module(&artifact.contract().templates)?,
    )?;
    fs::write(sdk.join("main.roc"), day2::sdk::app_platform())?;
    Ok(())
}

#[test]
fn native_canary_confirms_runtime_denials_with_positive_control() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let read = directory.path().join("read.txt");
    let write = directory.path().join("write.txt");
    fs::write(&read, b"private fixture")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let request = serde_json::to_vec(
        &json!({"read":read,"write":write,"address":listener.local_addr()?.to_string()}),
    )?;
    let probe = Path::new(env!("CARGO_BIN_EXE_sandbox_probe"));
    let mut control = Command::new(probe)
        .env("DAY2_PROBE_SECRET", "fixture")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut input = control.stdin.take().unwrap();
    input.write_all(&request)?;
    input.write_all(b"\n")?;
    drop(input);
    let output = control.wait_with_output()?;
    assert!(output.status.success());
    let allowed: Value = serde_json::from_slice(&output.stdout)?;
    for capability in ["read", "write", "network", "exec", "environment"] {
        assert_eq!(allowed[capability], true, "positive control: {capability}");
    }
    fs::remove_file(&write)?;
    let mut worker = Worker::start(probe)?;
    let denied: Value = serde_json::from_slice(&worker.exchange(&request)?)?;
    for capability in ["read", "write", "network", "exec", "environment"] {
        assert_eq!(denied[capability], false, "denial: {capability}");
    }
    assert!(!write.exists());
    Ok(())
}

#[test]
fn worker_budgets_kill_nontermination_and_reject_oversized_frames() -> Result<()> {
    let probe = Path::new(env!("CARGO_BIN_EXE_sandbox_probe"));
    let start = Instant::now();
    {
        let mut worker = Worker::start(probe)?;
        assert!(worker.exchange(br#"{"mode":"hang"}"#).is_err());
    }
    assert!(start.elapsed() < Duration::from_secs(6));
    let mut worker = Worker::start(probe)?;
    assert!(worker.exchange(br#"{"mode":"oversize"}"#).is_err());
    assert!(worker.exchange(&vec![b'x'; 1_048_576]).is_err());
    Ok(())
}

#[test]
fn checked_compiler_rejects_wrong_models_forged_values_and_unavailable_io() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let temporary = tempfile::tempdir_in(root.join("artifacts"))?;
    let stage = temporary.path();
    let artifact = verified_artifact()?;
    compiler_fixture(&root, stage, &artifact)?;
    let roc = root.join("../.toolchains/roc").canonicalize()?;
    let guards = stage.join("app");
    fs::create_dir_all(&guards)?;
    let outside = tempfile::tempdir_in(root.join("artifacts"))?;
    let secret = outside.path().join("secret.txt");
    fs::write(&secret, b"private fixture")?;
    let inside = guards.join("allowed.txt");
    fs::write(&inside, b"allowed fixture")?;
    let header = "app [step] { pf: platform \"../sdk/main.roc\" }\n";
    let fixtures = [
        (
            "Valid",
            format!("{header}step : Str -> Str\nstep = |raw| raw\n"),
            true,
            "",
        ),
        (
            "ValidFile",
            format!(
                "{header}import \"allowed.txt\" as value : Str\nstep : Str -> Str\nstep = |_| value\n"
            ),
            true,
            "",
        ),
        (
            "WriteQuery",
            format!(
                "{header}import pf.Query\nimport pf.Tx\nbad : Query(Str)\nbad = Tx.succeed(\"no\")\nstep : Str -> Str\nstep = |_| {{ _ = bad\n \"no\" }}\n"
            ),
            false,
            "TYPE MISMATCH",
        ),
        (
            "WrongField",
            format!(
                "{header}import Models\nbad : Models.Stage\nbad = {{ name: \"Qualified\", deal_count: \"many\" }}\nstep : Str -> Str\nstep = |_| {{ _ = bad\n \"no\" }}\n"
            ),
            false,
            "TYPE MISMATCH",
        ),
        (
            "ValidReferences",
            format!(
                "{header}import pf.Tx\nimport pf.Model\nimport pf.Ref\nimport Models\nimport Data\ngood : Ref(Models.Stage) -> Tx(Model.Entity(Models.Stage))\ngood = |id| Tx.get(Data.stages, id)\nstep : Str -> Str\nstep = |_| {{ _ = good\n \"yes\" }}\n"
            ),
            true,
            "",
        ),
        (
            "WrongModelReference",
            format!(
                "{header}import pf.Tx\nimport pf.Model\nimport pf.Ref\nimport Models\nimport Data\nbad : Ref(Models.Stage) -> Tx(Model.Entity(Models.Deal))\nbad = |id| Tx.get(Data.deals, id)\nstep : Str -> Str\nstep = |_| {{ _ = bad\n \"no\" }}\n"
            ),
            false,
            "TYPE MISMATCH",
        ),
        (
            "ValidQueryReference",
            format!(
                "{header}import pf.Ref\nimport pf.Selection\nimport pf.Cursor\nimport pf.PageSize\nimport Models\nimport Data\ngood : Ref(Models.Stage) -> Selection(Models.Deal)\ngood = |id| Data.deals_by_stage_id(id, Cursor.start, PageSize.default)\nstep : Str -> Str\nstep = |_| {{ _ = good\n \"yes\" }}\n"
            ),
            true,
            "",
        ),
        (
            "WrongQueryReference",
            format!(
                "{header}import pf.Ref\nimport pf.Selection\nimport pf.Cursor\nimport pf.PageSize\nimport Models\nimport Data\nbad : Ref(Models.Deal) -> Selection(Models.Deal)\nbad = |id| Data.deals_by_stage_id(id, Cursor.start, PageSize.default)\nstep : Str -> Str\nstep = |_| {{ _ = bad\n \"no\" }}\n"
            ),
            false,
            "TYPE MISMATCH",
        ),
        (
            "UnknownQueryField",
            format!(
                "{header}import pf.Ref\nimport pf.Selection\nimport pf.Cursor\nimport pf.PageSize\nimport Models\nimport Data\nbad : Ref(Models.Stage) -> Selection(Models.Deal)\nbad = |id| Data.deals_by_stgae_id(id, Cursor.start, PageSize.default)\nstep : Str -> Str\nstep = |_| {{ _ = bad\n \"no\" }}\n"
            ),
            false,
            "DOES NOT EXIST",
        ),
        (
            "ForgedReference",
            format!(
                "{header}import pf.Ref\nimport Models\nbad : Ref(Models.Stage)\nbad = {{ value: 1, witness: [] }}\nstep : Str -> Str\nstep = |_| {{ _ = bad\n \"no\" }}\n"
            ),
            false,
            "TYPE MISMATCH",
        ),
        (
            "ForgedTitle",
            format!(
                "{header}import pf.Text\nimport Title\nbad : Text(Title)\nbad = {{ value: \"\" }}\nstep : Str -> Str\nstep = |_| {{ _ = bad\n \"no\" }}\n"
            ),
            false,
            "TYPE MISMATCH",
        ),
        (
            "SameShapeDifferentIdentity",
            format!(
                "{header}Left := {{ name : Str }}\nRight := {{ name : Str }}\nbad : Left -> Right\nbad = |value| value\nstep : Str -> Str\nstep = |_| {{ _ = bad\n \"no\" }}\n"
            ),
            false,
            "TYPE MISMATCH",
        ),
        (
            "MissingIo",
            format!("{header}import pf.File\nstep : Str -> Str\nstep = |raw| File.open(raw)\n"),
            false,
            "PACKAGE MODULE IS PRIVATE",
        ),
        (
            "RawAssetUrl",
            format!(
                "{header}import pf.Html\nbad : Html\nbad = Html.image(\"https://example.com/image.png\", \"Unregistered\")\nstep : Str -> Str\nstep = |_| Html.encode(bad)\n"
            ),
            false,
            "TYPE MISMATCH",
        ),
        (
            "ForgedAsset",
            format!(
                "{header}import pf.Asset\nbad : Asset\nbad = {{ key: \"forged\" }}\nstep : Str -> Str\nstep = |_| Asset.key(bad)\n"
            ),
            false,
            "TYPE MISMATCH",
        ),
        (
            "UnknownAsset",
            format!(
                "{header}import pf.Html\nimport Assets\nstep : Str -> Str\nstep = |_| Html.encode(Html.image(Assets.does_not_exist, \"Missing\"))\n"
            ),
            false,
            "DOES NOT EXIST",
        ),
        (
            "ForgedHtml",
            format!(
                "{header}import pf.Html\nbad : Html\nbad = {{ nodes: [] }}\nstep : Str -> Str\nstep = |_| Html.encode(bad)\n"
            ),
            false,
            "TYPE MISMATCH",
        ),
        (
            "WrongFormField",
            format!(
                "{header}import pf.Html\nimport pf.Button\nimport pf.Control\nimport Commands\nimport Inputs\nstep : Str -> Str\nstep = |_| Html.encode(Html.form(Commands.seed, [Control.text(Inputs.move_input_deal_id, \"Wrong input owner\")], Button.primary(\"No\")))\n"
            ),
            false,
            "TYPE MISMATCH",
        ),
        (
            "ValidCustomForm",
            format!(
                r#"{header}import pf.Html
import pf.Attribute
import pf.Form
import Commands
import Inputs
good : Html
good = Form.command(Commands.seed, [Attribute.class("custom-form")], [
    Form.element("label", [Attribute.class("custom-label")], [
        Form.node(Html.text("Title")),
        Form.input(Inputs.seed_input_title, [Attribute.type("text"), Attribute.class("custom-input")]),
    ]),
    Form.node(Html.button([Attribute.type("submit")], [Html.text("Create")])),
])
step : Str -> Str
step = |_| Html.encode(good)
"#
            ),
            true,
            "",
        ),
        (
            "WrongCustomFormField",
            format!(
                r#"{header}import pf.Html
import pf.Attribute
import pf.Form
import Commands
import Inputs
step : Str -> Str
step = |_| Html.encode(Form.command(Commands.seed, [], [Form.input(Inputs.move_input_deal_id, [Attribute.type("text")])]))
"#
            ),
            false,
            "TYPE MISMATCH",
        ),
        (
            "ForgedAttribute",
            format!(
                r#"{header}import pf.Html
import pf.Attribute
bad : Attribute
bad = {{ name: "class", value: "forged" }}
step : Str -> Str
step = |_| Html.encode(Html.div([bad], [Html.text("No")]))
"#
            ),
            false,
            "TYPE MISMATCH",
        ),
        (
            "CommandAsPage",
            format!(
                "{header}import pf.Page\nimport pf.Template\nimport pf.Write\nbad : Template, Write({{}}, Str) -> Page({{}})\nbad = |template, write| Page.define({{ name: \"bad\", title: \"Bad\", path: \"/\", template }}, write)\nstep : Str -> Str\nstep = |_| {{ _ = bad\n \"no\" }}\n"
            ),
            false,
            "TYPE MISMATCH",
        ),
        (
            "ValidTypedPages",
            format!(
                r#"{header}import pf.Page
import pf.PageBinding
import pf.Template
import pf.Read
import pf.Ref
import pf.Cursor
import pf.PageSize
import Models
ListInput : {{ after : Cursor, limit : PageSize }}
DetailInput : {{ deal_id : Ref(Models.Deal) }}
good : Template, Read(ListInput, Str), Read(DetailInput, Str) -> List(PageBinding)
good = |template, list, detail| {{
    directory : Page(ListInput)
    directory = Page.define({{ name: "directory", title: "Directory", path: "/", template }}, list).with_defaults({{ after: Cursor.start, limit: PageSize.default }})
    item : Page(DetailInput)
    item = Page.define({{ name: "detail", title: "Details", path: "/deals/{{deal_id}}", template }}, detail)
    [directory.register(), item.register()]
}}
step : Str -> Str
step = |_| {{ _ = good
 "yes" }}
"#
            ),
            true,
            "",
        ),
        (
            "WrongPageInput",
            format!(
                r#"{header}import pf.Page
import pf.Template
import pf.Read
Left := {{ id : I64 }}
Right := {{ id : I64 }}
bad : Template, Read(Left, Str) -> Page(Right)
bad = |template, read| Page.define({{ name: "detail", title: "Details", path: "/items/{{id}}", template }}, read)
step : Str -> Str
step = |_| {{ _ = bad
 "no" }}
"#
            ),
            false,
            "TYPE MISMATCH",
        ),
        (
            "ForgedTemplate",
            format!(
                "{header}import pf.Template\nbad : Template\nbad = \"pages/missing.html\"\nstep : Str -> Str\nstep = |_| Template.path(bad)\n"
            ),
            false,
            "TYPE MISMATCH",
        ),
        (
            "TemplateStringFactory",
            format!(
                "{header}import pf.Template\nstep : Str -> Str\nstep = |_| Template.path(Template.from_file(\"pages/missing.html\"))\n"
            ),
            false,
            "DOES NOT EXIST",
        ),
        (
            "OutsideFile",
            format!(
                "{header}import \"../../{}/secret.txt\" as value : Str\nstep : Str -> Str\nstep = |_| value\n",
                outside.path().file_name().unwrap().to_string_lossy()
            ),
            false,
            "FILE",
        ),
    ];
    for (name, source, success, diagnostic) in fixtures {
        let file = guards.join(format!("{name}.roc"));
        let source = source
            .replace(
                "Inputs.seed_input_title",
                &format!(
                    "Inputs.{}_title",
                    artifact.operation("deals.seed")?.input_type
                ),
            )
            .replace(
                "Inputs.move_input_deal_id",
                &format!(
                    "Inputs.{}_deal_id",
                    artifact.operation("deals.move")?.input_type
                ),
            );
        fs::write(&file, source)?;
        if name == "OutsideFile" {
            let control = Command::new(&roc)
                .args(["check", "--no-cache"])
                .arg(&file)
                .env("ROC_CACHE_DIR", guards.join("positive-cache"))
                .output()?;
            assert!(
                control.status.success(),
                "outside file positive control: {}{}",
                String::from_utf8_lossy(&control.stdout),
                String::from_utf8_lossy(&control.stderr)
            );
        }
        let output = sandbox::compiler(&root, stage, &roc)?
            .args(["check", "--no-cache"])
            .arg(&file)
            .output()?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        fs::write(guards.join(format!("{name}.diagnostic.txt")), &text)?;
        assert_eq!(output.status.success(), success, "{name}: {text}");
        assert!(
            success
                || text
                    .to_ascii_lowercase()
                    .contains(&diagnostic.to_ascii_lowercase()),
            "{name}: wrong diagnostic: {text}"
        );
    }
    Ok(())
}

#[test]
fn artifact_rejects_duplicate_dispatch_keys_and_changed_executables() -> Result<()> {
    let source = verified_artifact()?.directory().to_path_buf();
    let original: Value = serde_json::from_slice(&fs::read(source.join("artifact.json"))?)?;
    let directory = tempfile::tempdir()?;
    for mutation in [
        "worker",
        "operation",
        "empty_properties",
        "duplicate_properties",
    ] {
        let mut contract = original.clone();
        if mutation == "operation" {
            let duplicate = contract["operations"][0].clone();
            contract["operations"]
                .as_array_mut()
                .unwrap()
                .push(duplicate);
        }
        if mutation == "empty_properties" {
            contract["properties"] = json!([]);
        }
        if mutation == "duplicate_properties" {
            contract["properties"] = json!(["duplicate", "duplicate"]);
        }
        let hash = day2::digest(&serde_json::to_vec(&contract)?);
        let target = directory.path().join(hash.trim_start_matches("sha256:"));
        fs::create_dir(&target)?;
        fs::write(target.join("artifact.json"), serde_json::to_vec(&contract)?)?;
        fs::copy(source.join("worker"), target.join("worker"))?;
        if mutation == "worker" {
            fs::write(target.join("worker"), b"not the checked executable")?;
        }
        let error = LoadedArtifact::load(&target)
            .err()
            .expect("must reject artifact")
            .to_string();
        assert!(
            error.contains(match mutation {
                "worker" => "worker digest mismatch",
                "operation" => "duplicate operation name",
                "empty_properties" => "invalid property count",
                "duplicate_properties" => "duplicate property name",
                _ => unreachable!(),
            }),
            "{error}"
        );
    }
    Ok(())
}
