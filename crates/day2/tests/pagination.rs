use anyhow::Result;
use day2::{
    output_schema::{self, Contract, Type},
    sandbox,
    schema::{Kind, Record, Schema},
};
use serde_json::json;
use std::{collections::BTreeMap, fs, path::Path};

#[test]
fn opaque_pagination_wire_inputs_are_canonical_and_never_persistent_columns() -> Result<()> {
    let input = Record {
        identity: None,
        fields: BTreeMap::from([
            ("after".into(), Kind::IdCursor),
            ("limit".into(), Kind::PageSize),
        ]),
        roc_type: None,
    };
    input.validate_input(&json!({"after":"","limit":100}))?;
    for invalid in [
        json!({"after":0,"limit":20}),
        json!({"after":"01","limit":20}),
        json!({"after":"-1","limit":20}),
        json!({"after":"","limit":0}),
        json!({"after":"","limit":101}),
        json!({"after":"","limit":20.0}),
        json!({"after":"9223372036854775808","limit":20}),
    ] {
        assert!(input.validate_input(&invalid).is_err(), "{invalid}");
    }
    let schema = Schema {
        domains: BTreeMap::new(),
        models: BTreeMap::from([("rows".into(), input.clone())]),
        inputs: BTreeMap::from([("request".into(), input)]),
        foreign_keys: vec![],
        indexes: vec![],
    };
    assert!(schema.validate().is_err());
    Ok(())
}

#[test]
fn compiler_enforces_opaque_types_and_generated_codecs_reject_counterfeit_nominals() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let temporary = tempfile::tempdir_in(root.join("artifacts"))?;
    let stage = temporary.path();
    fs::create_dir_all(stage.join("sdk"))?;
    fs::create_dir_all(stage.join("app"))?;
    day2::sdk::stage(&root.join("sdk"), &stage.join("sdk"))?;
    fs::write(
        stage.join("sdk/main.roc"),
        r#"platform "day2-pure"
requires { step : Str -> Str }
exposes [Cursor, PageSize, CollectionPage, Input, Output, Model, Selection, Predicate, Order, Ref, Field, WebUrl, Query, Tx]
packages {}
provides { "day2_step": step_for_host }
targets: { inputs_dir: "targets/", arm64mac: { inputs: ["libhost.a", app] } }
import Cursor
import PageSize
import CollectionPage
import Input
import Output
import Model
import Selection
import Predicate
import Order
import Ref
import Field
import WebUrl
import Query
import Tx
step_for_host : Str -> Str
step_for_host = |raw| step(raw)
"#,
    )?;
    fs::write(
        stage.join("app/Models.roc"),
        "Models :: [].{ Row := { title : Str } }\n",
    )?;
    fs::write(
        stage.join("app/Contracts.roc"),
        "import pf.Cursor\nimport pf.PageSize\nContracts :: [].{ Request := { after : Cursor, limit : PageSize } }\n",
    )?;
    let schema = Schema {
        domains: BTreeMap::new(),
        models: BTreeMap::from([(
            "rows".into(),
            Record {
                identity: None,
                fields: BTreeMap::from([("title".into(), Kind::Text)]),
                roc_type: Some("Models.Row".into()),
            },
        )]),
        inputs: BTreeMap::from([(
            "request".into(),
            Record {
                identity: None,
                fields: BTreeMap::from([
                    ("after".into(), Kind::IdCursor),
                    ("limit".into(), Kind::PageSize),
                ]),
                roc_type: Some("Contracts.Request".into()),
            },
        )]),
        foreign_keys: vec![],
        indexes: vec![],
    };
    fs::write(stage.join("app/Data.roc"), schema.data_module()?)?;
    fs::write(stage.join("app/Inputs.roc"), schema.inputs_module()?)?;
    fs::write(
        stage.join("app/Outputs.roc"),
        output_schema::roc_module(&BTreeMap::from([
            (
                "list".into(),
                Contract {
                    shape: Type::IdPage(Box::new(Type::String)),
                    roc_type: "CollectionPage(Str)".into(),
                },
            ),
            (
                "cursor".into(),
                Contract {
                    shape: Type::IdCursor,
                    roc_type: "Cursor".into(),
                },
            ),
            (
                "size".into(),
                Contract {
                    shape: Type::PageSize,
                    roc_type: "PageSize".into(),
                },
            ),
        ]))?,
    )?;
    fs::write(
        stage.join("app/Cursor.roc"),
        "Cursor :: { value : I64 }.{ make : Cursor\n make = { value: 0 } }\n",
    )?;
    fs::write(
        stage.join("app/PageSize.roc"),
        "PageSize :: { value : I64 }.{ make : PageSize\n make = { value: 20 } }\n",
    )?;
    fs::write(
        stage.join("app/CollectionPage.roc"),
        "import pf.Cursor\nCollectionPage(a) :: { items : List(a), has_more : Bool, next_after : Cursor }.{ make : CollectionPage(Str)\n make = { items: [\"fake\"], has_more: Bool.False, next_after: Cursor.start } }\n",
    )?;
    let cases = [
        (
            "ForgedCursor",
            "import pf.Cursor\nsubject : Cursor\nsubject = { value: 0 }",
        ),
        (
            "ForgedSize",
            "import pf.PageSize\nsubject : PageSize\nsubject = { value: 20 }",
        ),
        (
            "ForgedPage",
            "import pf.Cursor\nimport pf.CollectionPage\nsubject : CollectionPage(Str)\nsubject = { items: [], has_more: Bool.False, next_after: Cursor.start }",
        ),
        (
            "RawCursor",
            "import pf.PageSize\nimport Data\nsubject = Data.all_rows(0, PageSize.default)",
        ),
        (
            "RawSize",
            "import pf.Cursor\nimport Data\nsubject = Data.all_rows(Cursor.start, 20)",
        ),
        (
            "SwappedBounds",
            "import pf.Cursor\nimport pf.PageSize\nimport Data\nsubject = Data.all_rows(PageSize.default, Cursor.start)",
        ),
        (
            "CounterfeitCursor",
            "import Cursor\nimport Outputs\nsubject = Outputs.cursor.encode(Cursor.make)",
        ),
        (
            "CounterfeitSize",
            "import PageSize\nimport Outputs\nsubject = Outputs.size.encode(PageSize.make)",
        ),
        (
            "CounterfeitPage",
            "import CollectionPage\nimport Outputs\nsubject = Outputs.list.encode(CollectionPage.make)",
        ),
        (
            "TransactionCannotBecomeQuery",
            "import pf.Query\nimport pf.Tx\nsubject : Query({})\nsubject = Tx.succeed({})",
        ),
    ];
    let roc = root.join("../.toolchains/roc").canonicalize()?;
    for (name, source) in cases {
        let path = stage.join(format!("app/{name}.roc"));
        fs::write(
            &path,
            format!(
                "app [step] {{ pf: platform \"../sdk/main.roc\" }}\n{source}\nstep : Str -> Str\nstep = |_| {{ _ = subject\n \"checked\" }}\n"
            ),
        )?;
        let output = sandbox::compiler(&root, stage, &roc)?
            .args(["check", "--no-cache"])
            .arg(&path)
            .output()?;
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !output.status.success(),
            "{name} admitted counterfeit value"
        );
        assert!(
            diagnostic.to_lowercase().contains("type mismatch"),
            "{name}: {diagnostic}"
        );
    }
    let too_many = vec!["\"item\""; 101].join(", ");
    let source = format!(
        r#"app [step] {{ pf: platform "../sdk/main.roc" }}
import pf.Cursor
import pf.PageSize
import pf.CollectionPage
import pf.Tx
import Inputs
import Outputs
import pf.Ref
parse_ref : Str -> Try(Str, [InvalidRef])
parse_ref = |raw| {{
    ref : Try(Ref({{}}), [InvalidRef])
    ref = Ref.for_model("ord", raw)
    id = ref?
    Ok(id.to_str())
}}
expect parse_ref("ord_01h455vb4pex5vsknk084sn02q") == Ok("ord_01h455vb4pex5vsknk084sn02q")
expect parse_ref("cus_01h455vb4pex5vsknk084sn02q") == Err(InvalidRef)
expect parse_ref("ord_81h455vb4pex5vsknk084sn02q") == Err(InvalidRef)
expect parse_ref("ord_01h455vb4pex5vsknk084sn02i") == Err(InvalidRef)
expect parse_ref("ord_00000000000000000000000000") == Err(InvalidRef)
expect parse_ref("ORD_01h455vb4pex5vsknk084sn02q") == Err(InvalidRef)
page_result : List(Str), Bool, Cursor -> Try(CollectionPage(Str), Str)
page_result = CollectionPage.from_parts
expect Cursor.from_str("") == Ok(Cursor.start)
expect Cursor.from_str("01") == Err(InvalidCursor)
expect Cursor.from_str("-1") == Err(InvalidCursor)
expect PageSize.from_i64(0) == Err(InvalidPageSize)
expect PageSize.from_i64(101) == Err(InvalidPageSize)
expect PageSize.from_i64(100) == Ok(PageSize.maximum)
expect match page_result([{too_many}], Bool.False, Cursor.start) {{
    Err(error) => error == "invalid_collection_page"
    Ok(_) => Bool.False
}}
expect match page_result(["item"], Bool.True, Cursor.start) {{
    Err(error) => error == "invalid_collection_page"
    Ok(_) => Bool.False
}}
expect match CollectionPage.from_parts(["item"], Bool.False, Cursor.start) {{
    Ok(page) => Outputs.list.encode(page.map(|item| item)) == "{{\"has_more\":false,\"items\":[\"item\"],\"next_after\":\"\"}}"
    Err(_) => Bool.False
}}
expect match Inputs.request.decode("{{\"after\":\"\",\"limit\":20}}") {{
    Ok(input) => Inputs.request.encode(input) == "{{\"after\":\"\",\"limit\":20}}"
    Err(_) => Bool.False
}}
expect match Tx.from_host(page_result([{too_many}], Bool.False, Cursor.start)).evaluate([]) {{
    Failed(failure) => failure.error == "invalid_collection_page"
    _ => Bool.False
}}
step : Str -> Str
step = |raw| raw
"#
    );
    let path = stage.join("app/Valid.roc");
    fs::write(&path, source)?;
    let output = sandbox::compiler(&root, stage, &roc)?
        .arg("test")
        .arg(path)
        .output()?;
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    anyhow::ensure!(
        output.status.success(),
        "pagination expectations: {diagnostic}"
    );
    anyhow::ensure!(
        diagnostic.contains("All (17) tests passed"),
        "pagination expectations did not all execute: {diagnostic}"
    );
    Ok(())
}
