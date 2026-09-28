#[path = "support/compiler.rs"]
mod compiler;
use anyhow::{Context, Result};
use day2::{
    admission, assets, output_schema, sandbox,
    schema::{Kind, Record, Schema},
};
use std::{collections::BTreeMap, fs, path::Path, time::Duration};

#[test]
fn authored_factory_calls_are_rejected_by_the_pinned_compiler_not_a_text_filter() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let temporary = tempfile::tempdir_in(root.join("artifacts"))?;
    let stage = temporary.path().join("executable");
    fs::create_dir_all(stage.join("app"))?;
    fs::create_dir_all(stage.join("sdk"))?;
    day2::sdk::stage(&root.join("sdk"), &stage.join("sdk"))?;
    fs::write(
        stage.join("sdk/main.roc"),
        r#"platform "day2-pure"
    requires { step : Str -> Str }
    exposes [Model, Input, Output, Selection, Predicate, Order, Ref, Field, Asset, WebUrl, Cursor, PageSize, CollectionPage, Context, Write, Read, CommandBinding, QueryBinding, Product, Tx, Query, Resource, Slack, Snowflake, OpenAi, Observe, Effects]
    packages {}
    provides { "day2_step": step_for_host }
    targets: { inputs_dir: "targets/", arm64mac: { inputs: ["libhost.a", app] } }
import Model
import Input
import Output
import Selection
import Ref
import Field
import Asset
import WebUrl
import Cursor
import PageSize
import CollectionPage
import Context
import Write
import Read
import CommandBinding
import QueryBinding
import Product
import Tx
import Query
import Predicate
import Order
import Resource
import Slack
import Snowflake
import OpenAi
import Observe
import Effects
step_for_host : Str -> Str
step_for_host = |raw| step(raw)
"#,
    )?;
    let schema = Schema {
        domains: BTreeMap::new(),
        models: BTreeMap::from([
            (
                "links".into(),
                Record {
                    identity: None,
                    fields: BTreeMap::from([("title".into(), Kind::Text)]),
                    roc_type: Some("Models.Link".into()),
                },
            ),
            (
                "notes".into(),
                Record {
                    identity: None,
                    fields: BTreeMap::from([("title".into(), Kind::Text)]),
                    roc_type: Some("Models.Note".into()),
                },
            ),
        ]),
        inputs: BTreeMap::from([(
            "create".into(),
            Record {
                identity: None,
                fields: BTreeMap::from([("title".into(), Kind::Text)]),
                roc_type: None,
            },
        )]),
        foreign_keys: vec![],
        indexes: vec![],
    };
    let outputs = BTreeMap::from([(
        "title".into(),
        output_schema::Contract {
            shape: output_schema::Type::String,
            roc_type: "Str".into(),
        },
    )]);
    let images = assets::Catalog::new();
    fs::write(
        stage.join("app/Models.roc"),
        "Models :: [].{\n Link := { title : Str }\n Note := { title : Str }\n}\n",
    )?;
    fs::write(stage.join("app/Data.roc"), schema.data_module()?)?;
    fs::write(stage.join("app/Inputs.roc"), schema.inputs_module()?)?;
    fs::write(
        stage.join("app/Outputs.roc"),
        output_schema::roc_module(&outputs)?,
    )?;
    fs::write(stage.join("app/Assets.roc"), assets::roc_module(&images)?)?;
    fs::write(
        stage.join("app/Factory.roc"),
        "import pf.Model as M\nFactory :: [].{\n build : Str, Str, (Str -> Try(a, Str)), (a -> Str) -> M(a)\n build = M.define\n}\n",
    )?;
    let header = "app [step] { pf: platform \"../sdk/main.roc\" }\n";
    let footer = "\nstep : Str -> Str\nstep = |_| { _ = subject\n \"checked\" }\n";
    let model_body = "Model.define(\"links\", \"lnk\", |_raw| Err(\"invalid\"), |_value| \"{}\")";
    let fixtures = [
        ("ValidLivePacks", "import pf.Slack\nimport pf.Snowflake\nimport pf.OpenAi\nsubject = (Slack.read, Slack.post, Snowflake.read, Snowflake.text, Snowflake.integer, Snowflake.boolean, OpenAi.generate)".into(), true),
        ("ResourceToken", "import pf.Resource\nsubject = Resource.token".into(), false),
        ("ResourceDecode", "import pf.Resource\nsubject = Resource.decode".into(), false),
        ("InvalidResourceRecord", "import pf.Resource\nsubject : Resource\nsubject = { token: \"forged\" }".into(), false),
        ("ValidGenerated", "import pf.Model\nimport pf.Input\nimport pf.Output\nimport Data\nimport Inputs\nimport Outputs\nsubject : Str\nsubject = Model.name(Data.links).concat(Input.name(Inputs.create)).concat(Output.name(Outputs.title))".into(), true),
        ("ValidSelection", "import pf.Selection\nimport pf.Cursor\nimport pf.PageSize\nimport Models\nimport Data\nsubject : Selection(Models.Link)\nsubject = Data.all_links(Cursor.start, PageSize.default)".into(), true),
        ("ValidGeneratedPredicate", "import pf.Predicate\nimport Models\nimport Data\nsubject : Predicate(Models.Link)\nsubject = Predicate.all([Data.links_title_equal(\"example\"), Predicate.any([Data.links_title_like(\"%ample%\"), Data.links_title_like(\"other%\")])])".into(), true),
        ("ValidGeneratedOrder", "import pf.Order\nimport Models\nimport Data\nsubject : List(Order(Models.Link))\nsubject = [Data.links_title_asc, Data.links_version_desc, Data.links_id_desc]".into(), true),
        ("ValidFilteredSelection", "import pf.Selection\nimport pf.Predicate\nimport pf.Cursor\nimport pf.PageSize\nimport Models\nimport Data\nsubject : Selection(Models.Link)\nsubject = Selection.filter(Data.links, Predicate.all([Data.links_title_equal(\"example\")])).order([Data.links_title_asc]).paginate(Cursor.start, PageSize.default)".into(), true),
        ("ValidFind", "import pf.Query\nimport pf.Model\nimport pf.Selection\nimport Models\nimport Data\nsubject : Query([Some(Model.Entity(Models.Link)), None])\nsubject = Query.find(Selection.filter(Data.links, Data.links_title_equal(\"example\")))".into(), true),
        ("InvalidEqualityType", "import pf.Predicate\nimport Models\nimport Data\nsubject : Predicate(Models.Link)\nsubject = Data.links_title_equal(42)".into(), false),
        ("InvalidPredicateModelCombination", "import pf.Predicate\nimport Models\nimport Data\nsubject : Predicate(Models.Link)\nsubject = Predicate.all([Data.links_title_equal(\"link\"), Data.notes_title_equal(\"note\")])".into(), false),
        ("InvalidSelectionPredicateModel", "import pf.Selection\nimport Models\nimport Data\nsubject : Selection(Models.Link)\nsubject = Selection.filter(Data.links, Data.notes_title_equal(\"note\"))".into(), false),
        ("InvalidSelectionOrderModel", "import pf.Selection\nimport Models\nimport Data\nsubject : Selection(Models.Link)\nsubject = Selection.filter(Data.links, Data.links_title_equal(\"link\")).order([Data.notes_title_asc])".into(), false),
        ("ValidField", "import pf.Field\nimport Inputs\nsubject : Str\nsubject = Field.name(Inputs.create_title)".into(), true),
        ("FactoryNameInString", "subject : Str\nsubject = \"Model.define Input.define import pf.Model as M\"".into(), true),
        ("DirectModel", format!("import pf.Model\nimport Models\nsubject : Model(Models.Link)\nsubject = {model_body}"), false),
        ("AliasedModel", "import pf.Model as M\nimport Models\nsubject : M(Models.Link)\nsubject = M.define(\"links\", \"lnk\", |_raw| Err(\"invalid\"), |_value| \"{}\")".into(), false),
        ("FirstClassFactory", "import pf.Model\nimport Models\nconstructor = Model.define\nsubject : Model(Models.Link)\nsubject = constructor(\"links\", \"lnk\", |_raw| Err(\"invalid\"), |_value| \"{}\")".into(), false),
        ("ForwardedFactory", "import pf.Model\nimport Models\nimport Factory as F\nsubject : Model(Models.Link)\nsubject = F.build(\"links\", \"lnk\", |_raw| Err(\"invalid\"), |_value| \"{}\")".into(), false),
        ("UnreachableFactory", format!("import pf.Model\nimport Models\nimport Data\nsubject : Str -> Model(Models.Link)\nsubject = |_input| if Bool.False {{ {model_body} }} else {{ Data.links }}"), false),
        ("InputFactory", "import pf.Input\nsubject : Input(Str)\nsubject = Input.define(\"create\", |raw| Ok(raw), |value| value)".into(), false),
        ("OutputFactory", "import pf.Output as O\nsubject : O(Str)\nsubject = O.define(\"title\", |value| value)".into(), false),
        ("SelectionAll", "import pf.Selection\nimport pf.Cursor\nimport pf.PageSize\nimport Models\nimport Data\nsubject : Selection(Models.Link)\nsubject = Selection.all(Data.links, Cursor.start, PageSize.default)".into(), false),
        ("SelectionIndexed", "import pf.Selection as S\nimport pf.Cursor\nimport pf.PageSize\nimport Models\nimport Data\nsubject : S(Models.Link)\nsubject = S.indexed(Data.links, \"title\", \"lnk_01900000000070008000000000000001\", Cursor.start, PageSize.default)".into(), false),
        ("SelectionAllFirstClass", "import pf.Selection as S\nimport pf.Cursor\nimport pf.PageSize\nimport Models\nimport Data\nconstructor = S.all\nsubject : S(Models.Link)\nsubject = constructor(Data.links, Cursor.start, PageSize.default)".into(), false),
        ("SelectionIndexedFirstClass", "import pf.Selection\nimport pf.Cursor\nimport pf.PageSize\nimport Models\nimport Data\nconstructor = Selection.indexed\nsubject : Selection(Models.Link)\nsubject = constructor(Data.links, \"title\", \"arbitrary\", Cursor.start, PageSize.default)".into(), false),
        ("PredicateFactory", "import pf.Predicate\nimport Models\nimport Data\nsubject : Predicate(Models.Link)\nsubject = Predicate.define(Data.links, \"title\", \"equal\", Json.to_str(\"example\"))".into(), false),
        ("PredicateFirstClassFactory", "import pf.Predicate as P\nimport Models\nimport Data\nconstructor = P.define\nsubject : P(Models.Link)\nsubject = constructor(Data.links, \"title\", \"equal\", Json.to_str(\"example\"))".into(), false),
        ("OrderFactory", "import pf.Order\nimport Models\nimport Data\nsubject : Order(Models.Link)\nsubject = Order.define(Data.links, \"title\", Bool.True)".into(), false),
        ("OrderFirstClassFactory", "import pf.Order as O\nimport Models\nimport Data\nconstructor = O.define\nsubject : O(Models.Link)\nsubject = constructor(Data.links, \"title\", Bool.False)".into(), false),
        ("WriteFactory", "import pf.Write as W\nimport Inputs\nimport Outputs\nsubject = W.define(\"links.create\", Inputs.create, Outputs.title)".into(), false),
        ("ReadFactory", "import pf.Read as R\nimport Inputs\nimport Outputs\nsubject = R.define(\"links.title\", Inputs.create, Outputs.title)".into(), false),
        ("ContextFactory", "import pf.Context as C\nsubject = C.from_wire({ actor: \"admin\", invocation_id: \"fake\", now: 0, authentication: \"request\", caller: [], authenticated: \"\", delegation_rule: \"\" })".into(), false),
        ("ContextFirstClass", "import pf.Context\nconstructor = Context.from_wire\nsubject = constructor({ actor: \"admin\", invocation_id: \"fake\", now: 0, authentication: \"request\", caller: [], authenticated: \"\", delegation_rule: \"\" })".into(), false),
        ("ProductFactory", "import pf.Product\nsubject = Product.step".into(), false),
        ("BindingFactory", "import pf.CommandBinding\nsubject = CommandBinding.define".into(), false),
        ("QueryBindingFactory", "import pf.QueryBinding\nsubject = QueryBinding.define".into(), false),
        ("RetiredJobBinding", "import pf.JobBinding\nsubject = JobBinding.define".into(), false),
        ("RetiredJobFactory", "import pf.Job\nimport Data\nimport Inputs\nsubject = Job.define(\"links.work\", Data.links, Inputs.create, Inputs.create)".into(), false),
        ("EvaluateDirect", "import pf.Tx\nsubject = Tx.evaluate(Tx.succeed(\"value\"), [])".into(), false),
        ("EvaluateFirstClass", "import pf.Tx as T\nevaluate = T.evaluate\nsubject = evaluate(T.succeed(\"value\"), [])".into(), false),
        ("EvaluateMethod", "import pf.Tx\nsubject = Tx.succeed(\"value\").evaluate([])".into(), false),
        ("FieldFactory", "import pf.Field\nsubject : Field({ title : Str })\nsubject = Field.define(\"wrong\")".into(), false),
        ("AssetFactory", "import pf.Asset\nsubject : Asset\nsubject = Asset.define(\"missing\")".into(), false),
        ("OpaqueRecord", "import pf.Model\nimport Models\nsubject : Model(Models.Link)\nsubject = { name: \"links\", decode: |_raw| Err(\"invalid\"), encode: |_value| \"{}\" }".into(), false),
        ("ExposedFactory", "import pf.Model exposing [define]\nimport pf.Model\nimport Models\nsubject : Model(Models.Link)\nsubject = define(\"links\", \"lnk\", |_raw| Err(\"invalid\"), |_value| \"{}\")".into(), false),
        ("QualifiedFactory", "import pf.Model\nimport Models\nsubject : Model(Models.Link)\nsubject = pf.Model.define(\"links\", \"lnk\", |_raw| Err(\"invalid\"), |_value| \"{}\")".into(), false),
        ("PackageEscape", "import ../../executable/sdk/Model as M\nimport Models\nsubject : M(Models.Link)\nsubject = M.define(\"links\", \"lnk\", |_raw| Err(\"invalid\"), |_value| \"{}\")".into(), false),
        ("AdmissionAlias", "import pf.Model as M\nimport Models\nsubject : M(Models.Link)\nsubject = M.admission_define(\"links\", \"lnk\", |_raw| Err(\"invalid\"), |_value| \"{}\")".into(), true),
        ("AdmissionFirstClass", "import pf.Model\nimport Models\nconstructor = Model.admission_define\nsubject : Model(Models.Link)\nsubject = constructor(\"links\", \"lnk\", |_raw| Err(\"invalid\"), |_value| \"{}\")".into(), true),
        ("AdmissionContext", "import pf.Context as C\nsubject = C.admission_from_wire({ actor: \"admin\", invocation_id: \"fake\", now: 0, authentication: \"request\", caller: [], authenticated: \"\", delegation_rule: \"\" })".into(), true),
        ("AdmissionPredicate", "import pf.Predicate\nimport Models\nimport Data\nsubject : Predicate(Models.Link)\nsubject = Predicate.admission_define(Data.links, \"title\", \"equal\", Json.to_str(\"example\"))".into(), true),
        ("AdmissionOrder", "import pf.Order\nimport Models\nimport Data\nsubject : Order(Models.Link)\nsubject = Order.admission_define(Data.links, \"title\", Bool.True)".into(), true),
        ("AdmissionWrite", "import pf.Write\nimport Inputs\nimport Outputs\nsubject = Write.admission_define(\"links.create\", Inputs.create, Outputs.title)".into(), true),
        ("AdmissionProduct", "import pf.Product\nsubject = Product.admission_step".into(), true),
        ("AdmissionEvaluate", "import pf.Tx\nsubject = Tx.admission_evaluate(Tx.succeed(\"value\"), [])".into(), true),
        ("AdmissionEvaluateFirstClass", "import pf.Tx as T\nevaluate = T.admission_evaluate\nsubject = evaluate(T.succeed(\"value\"), [])".into(), true),
        ("AdmissionUnreachable", "import pf.Model\nimport Models\nimport Data\nsubject : Str -> Model(Models.Link)\nsubject = |_input| if Bool.False { Model.admission_define(\"links\", \"lnk\", |_raw| Err(\"invalid\"), |_value| \"{}\") } else { Data.links }".into(), true),
        ("BothFactories", "import pf.Model\nimport Models\nsubject : Str -> Model(Models.Link)\nsubject = |profile| if profile == \"admission\" { Model.admission_define(\"links\", \"lnk\", |_raw| Err(\"invalid\"), |_value| \"{}\") } else { Model.define(\"links\", \"lnk\", |_raw| Err(\"invalid\"), |_value| \"{}\") }".into(), false),
    ];
    for (name, body, _) in &fixtures {
        fs::write(
            stage.join(format!("app/{name}.roc")),
            format!("{header}{body}{footer}"),
        )?;
    }
    let target = temporary.path().join("admission");
    admission::prepare(&stage, &target, &schema, &outputs, &images, None)?;
    assert!(admission::prepare(&stage, &target, &schema, &outputs, &images, None).is_err());
    let roc = root.join("../.toolchains/roc").canonicalize()?;
    for (name, _, expected) in fixtures {
        let path = format!("app/{name}.roc");
        assert_eq!(
            fs::read(stage.join(&path))?,
            fs::read(target.join(&path))?,
            "authored bytes changed: {name}"
        );
        // Positive controls ensure denied spellings are valid Roc programs in the
        // unrestricted profile, not merely syntax errors. Admission-only names
        // must conversely fail the normal check even through aliases or branches.
        // Retired job exports must fail in both profiles.
        if !matches!(
            name,
            "OpaqueRecord" | "ExposedFactory" | "QualifiedFactory" | "PackageEscape"
        ) {
            let output = compiler::output(
                sandbox::compiler(&root, &stage, &roc)?
                    .args(["check", "--no-cache"])
                    .arg(stage.join(&path)),
                Duration::from_secs(30),
            )
            .with_context(|| format!("normal profile {name}"))?;
            let diagnostic = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let has_no_errors = output.status.success()
                || (name.contains("Unreachable") && diagnostic.contains("0 errors and"));
            assert_eq!(
                has_no_errors,
                !name.starts_with("Admission")
                    && !name.starts_with("Retired")
                    && !name.starts_with("Invalid")
                    && name != "BothFactories",
                "normal profile {name}: {diagnostic}"
            );
        }
        let output = compiler::output(
            sandbox::compiler(&root, &target, &roc)?
                .args(["check", "--no-cache"])
                .arg(target.join(path)),
            Duration::from_secs(30),
        )
        .with_context(|| format!("admission profile {name}"))?;
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let has_no_errors = output.status.success()
            || (name.contains("Unreachable") && diagnostic.contains("0 errors and"));
        assert_eq!(has_no_errors, expected, "{name}: {diagnostic}");
        if !expected {
            assert!(
                !diagnostic.to_ascii_lowercase().contains("compiler bug"),
                "compiler crashed: {name}: {diagnostic}"
            );
        }
    }
    Ok(())
}
