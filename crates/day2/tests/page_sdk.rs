use anyhow::Result;
use day2::{sandbox, web_templates};
use std::{fs, path::Path};

#[test]
fn generated_template_handles_and_typed_page_registration_are_compiler_checked() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let temporary = tempfile::tempdir_in(root.join("artifacts"))?;
    let stage = temporary.path();
    fs::create_dir_all(stage.join("sdk"))?;
    fs::create_dir_all(stage.join("app"))?;
    fs::create_dir_all(stage.join("ui/pages"))?;
    for name in ["directory", "details"] {
        fs::write(stage.join(format!("ui/pages/{name}.html")), "<p>Page</p>")?;
    }
    let templates = web_templates::package(&stage.join("ui"), stage)?;
    day2::sdk::stage(&root.join("sdk"), &stage.join("sdk"))?;
    fs::write(
        stage.join("sdk/Template.roc"),
        web_templates::roc_sdk_module(&templates)?,
    )?;
    fs::write(
        stage.join("app/Templates.roc"),
        web_templates::roc_module(&templates)?,
    )?;
    fs::write(
        stage.join("sdk/main.roc"),
        r#"platform "day2-pure"
    requires { step : Str -> Str }
    exposes [Page, PageBinding, Template, Read, Write, Input, Output, Query, Model, Selection, Predicate, Order, Product, Wire, Tx, QueryBinding, CommandBinding, Cursor, PageSize]
    packages {}
    provides { "day2_step": step_for_host }
    targets: { inputs_dir: "targets/", arm64mac: { inputs: ["libhost.a", app] } }
import Page
import PageBinding
import Template
import Read
import Write
import Input
import Output
import Query
import Model
import Selection
import Predicate
import Order
import Product
import Wire
import Tx
import QueryBinding
import CommandBinding
import Cursor
import PageSize
step_for_host : Str -> Str
step_for_host = |raw| step(raw)
"#,
    )?;
    let header = r#"app [step] { pf: platform "../sdk/main.roc" }
import pf.Page
import pf.PageBinding
import pf.Template
import pf.Read
import pf.Write
import pf.Cursor
import pf.PageSize
import Templates
ListInput := { after : Cursor, limit : PageSize }
DetailInput := { id : I64 }
OtherInput := { id : I64 }
"#;
    let footer = "\nstep : Str -> Str\nstep = |_| { _ = subject\n \"checked\" }\n";
    let fixtures = [
        (
            "Valid",
            r#"subject : Read(ListInput, Str), Read(DetailInput, Str) -> List(PageBinding)
subject = |list, detail| {
    directory : Page(ListInput)
    directory = Page.define({ name: "links", title: "Links", path: "/", template: Templates.directory }, list).live().with_defaults({ after: Cursor.start, limit: PageSize.default })
    item : Page(DetailInput)
    item = Page.define({ name: "link", title: "Details", path: "/links/{id}", template: Templates.details }, detail).live_refresh_every(5000)
    [directory.register(), item.register()]
}"#,
            true,
        ),
        (
            "WrongQueryInput",
            r#"subject : Read(DetailInput, Str) -> Page(OtherInput)
subject = |read| Page.define({ name: "link", title: "Details", path: "/links/{id}", template: Templates.details }, read)"#,
            false,
        ),
        (
            "CommandIsNotRead",
            r#"subject : Write(DetailInput, Str) -> Page(DetailInput)
subject = |write| Page.define({ name: "link", title: "Details", path: "/links/{id}", template: Templates.details }, write)"#,
            false,
        ),
        (
            "WrongDefaultFieldType",
            r#"subject : Read(ListInput, Str) -> Page(ListInput)
subject = |read| Page.define({ name: "links", title: "Links", path: "/", template: Templates.directory }, read).with_defaults({ after: "wrong", limit: 20 })"#,
            false,
        ),
        (
            "WrongDefaultNominalType",
            r#"subject : Read(DetailInput, Str), OtherInput -> Page(DetailInput)
subject = |read, input| Page.define({ name: "link", title: "Details", path: "/links/{id}", template: Templates.details }, read).with_defaults(input)"#,
            false,
        ),
        (
            "MissingTemplate",
            "subject : Template\nsubject = Templates.does_not_exist",
            false,
        ),
        (
            "ForgedTemplate",
            "subject : Template\nsubject = \"pages/details.html\"",
            false,
        ),
        (
            "NoTemplateStringFactory",
            "subject : Template\nsubject = Template.from_file(\"pages/details.html\")",
            false,
        ),
        (
            "NoUncheckedPageFactory",
            "subject : Page(DetailInput)\nsubject = { binding: {}, complete: |_value| {} }",
            false,
        ),
        (
            "NoUncheckedDefaultsFactory",
            r#"subject : Read(ListInput, Str) -> Page(ListInput)
subject = |read| Page.define({ name: "links", title: "Links", path: "/", template: Templates.directory }, read).with_defaults_json("{}")"#,
            false,
        ),
    ];
    let roc = root.join("../.toolchains/roc").canonicalize()?;
    for (name, source, expected) in fixtures {
        let file = stage.join(format!("app/{name}.roc"));
        fs::write(&file, format!("{header}{source}{footer}"))?;
        let output = sandbox::compiler(&root, stage, &roc)?
            .arg("check")
            .arg(&file)
            .output()?;
        assert_eq!(
            output.status.success(),
            expected,
            "{name}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !expected {
            let diagnostic = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .to_ascii_lowercase();
            let missing = matches!(
                name,
                "MissingTemplate" | "NoTemplateStringFactory" | "NoUncheckedDefaultsFactory"
            );
            assert!(
                if missing {
                    diagnostic.contains("does not exist") || diagnostic.contains("missing method")
                } else {
                    diagnostic.contains("type mismatch")
                },
                "{name}: unexpected compiler rejection: {diagnostic}"
            );
        }
    }
    let defaults = stage.join("app/Defaults.roc");
    fs::write(
        &defaults,
        format!(
            r#"{header}import pf.Input
import pf.Output
import pf.Query
import pf.Model
import pf.Selection
import pf.Product
import pf.Wire
import pf.Tx
import pf.QueryBinding
import pf.CommandBinding
decode : Str -> Try(ListInput, Str)
decode = |raw| {{
    parsed : Try({{ after : Str, limit : I64 }}, _)
    parsed = Json.parse(raw)
    wire = parsed.map_err(|_| "invalid_input")?
    after = Cursor.from_str(wire.after).map_err(|_| "invalid_cursor")?
    limit = PageSize.from_i64(wire.limit).map_err(|_| "invalid_page_size")?
    Ok({{ after, limit }})
}}
input = Input.define("list", decode, |value| Json.to_str({{ after: value.after.to_str(), limit: value.limit.to_i64() }}))
output : Output(Str)
output = Output.define("text", |value| Json.to_str(value))
model : Model(Str)
model = Model.define("items", "ite", |_| Ok("item"), |value| Json.to_str(value))
read : Read(ListInput, Str)
read = Read.define("links.list", input, output)
query = QueryBinding.define(read, |_context, bounds| Query.page(Selection.all(model, bounds.after, bounds.limit)).map(|_| "ok"))
config = {{ name: "links", title: "Links", path: "/", template: Templates.directory }}
empty = Page.define(config, read)
full = Page.define(config, read).with_defaults({{ after: Cursor.start, limit: PageSize.default }})
partial = Page.define(config, read).with_query_defaults({{ limit: 20.I64 }})
unconstrained = Page.define(config, read).with_query_defaults({{ limit: 20 }})
expect empty.register().metadata().defaults == "{{}}"
expect full.register().metadata().defaults == "{{\"after\":\"\",\"limit\":20}}"
expect partial.register().metadata().defaults == "{{\"limit\":20}}"
expect unconstrained.register().metadata().defaults == "{{\"limit\":20.0}}"
expect empty.register().metadata().live == Bool.False
expect empty.register().metadata().live_refresh_ms == 0
live = empty.live().with_defaults({{ after: Cursor.start, limit: PageSize.default }})
expect live.register().metadata().live == Bool.True
expect live.register().metadata().defaults == full.register().metadata().defaults
periodic = empty.live_refresh_every(5000).with_defaults({{ after: Cursor.start, limit: PageSize.default }})
expect periodic.register().metadata().live == Bool.True
expect periodic.register().metadata().live_refresh_ms == 5000
expect periodic.live().with_query_defaults({{ limit: 10.I64 }}).register().metadata().live_refresh_ms == 5000
expect empty.with_defaults({{ after: Cursor.start, limit: PageSize.default }}).live().register().metadata().live == Bool.True
poisoned = QueryBinding.define(read, |_context, bounds| Query.page(Selection.all(model, bounds.after, bounds.limit)).map(|_| "poisoned"))
poisoned_page = Page.define(config, Read.define("links.list", input, output)).with_defaults({{ after: Cursor.start, limit: PageSize.default }}).register()
product : Product.Contract
product = {{ namespace: "links", commands: [], queries: [query], properties: [], pages: [poisoned_page], schedules: [], ingress: [], redirects: [] }}
request : Wire.Request
request = {{
    operation: "$page.links",
    input: full.register().metadata().defaults,
    context: {{ actor: "test", invocation_id: "test", now: 0, authentication: "request", caller: [], authenticated: "", delegation_rule: "" }},
    observations: [{{
        instruction: {{ ..Wire.empty, kind: "page", model: "items", after: "", limit: 20 }},
        result: "{{\"items\":[],\"has_more\":false,\"next_after\":\"\"}}",
        error: "",
    }}],
}}
response : Product.Contract, Wire.Request -> Wire.Response
response = |contract, invocation| {{
    parsed : Try(Wire.Response, _)
    parsed = Json.parse(Product.step(contract, Json.to_str(invocation)))
    match parsed {{
        Ok(value) => value
        Err(_) => {{ kind: "invalid_response", instruction: Wire.empty, result: "", error: "invalid_response", consumed: 0 }}
    }}
}}
expected : Wire.Response
expected = {{ kind: "done", instruction: Wire.empty, result: "\"ok\"", error: "", consumed: 1 }}
expect response(product, request) == expected
expect response(product, {{ ..request, operation: "links.list" }}) == expected
expect response({{ ..product, queries: [poisoned] }}, {{ ..request, operation: "links.list" }}).result == "\"poisoned\""
expect response({{ ..product, queries: [] }}, request).error == "unknown_page_query"
command = CommandBinding.define(Write.define("links.list", input, output), |_context, _input| Tx.succeed("command"))
expect response({{ ..product, queries: [], commands: [command] }}, request).error == "unknown_page_query"
other_input : Input(OtherInput)
other_input = Input.define("other_input", |_raw| Ok({{ id: 1 }}), |value| Json.to_str({{ id: value.id }}))
other_read = Read.define("links.list", other_input, output)
other_page = Page.define(config, other_read).with_defaults({{ id: 1 }}).register()
expect other_page.metadata().input_type == "other_input"
expect response({{ ..product, pages: [other_page] }}, request).error == "unknown_page_query"
step : Str -> Str
step = |_| full.register().metadata().defaults
"#
        ),
    )?;
    let output = sandbox::compiler(&root, stage, &roc)?
        .arg("test")
        .arg(&defaults)
        .output()?;
    assert!(
        output.status.success(),
        "defaults evaluation: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        report.contains("All (19) tests passed"),
        "all defaults and registered-query dispatch expectations must execute: {report}"
    );
    Ok(())
}
