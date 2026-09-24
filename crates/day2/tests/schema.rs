use anyhow::Result;
use day2::{
    artifact::LoadedArtifact,
    schema::{Kind, Schema},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn artifact() -> Result<LoadedArtifact> {
    let path = std::env::var_os("DAY2_TEST_RELATIONAL_ARTIFACT")
        .map(PathBuf::from)
        .expect("build the relational fixture and set DAY2_TEST_RELATIONAL_ARTIFACT");
    LoadedArtifact::load(&path)
}

#[test]
fn native_structured_inputs_reflect_and_roundtrip_without_flattening_records() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let temporary = tempfile::tempdir_in(root.join("artifacts"))?;
    let stage = temporary.path();
    fs::create_dir(stage.join("app"))?;
    day2::sdk::stage(&root.join("sdk"), &stage.join("sdk"))?;
    fs::write(stage.join("sdk/main.roc"), day2::sdk::app_platform())?;
    fs::write(
        stage.join("app/Models.roc"),
        "Models :: [].{ Row := { name : Str } }\n",
    )?;
    fs::write(
        stage.join("app/Contracts.roc"),
        r#"Contracts :: [].{
    Attribute : { key : Str, value : Str }
    Settings : { enabled : Bool, count : U64, note : [None, Some(Str)] }
    Input := { attributes : List(Attribute), groups : List(Str), settings : Settings }
}
"#,
    )?;
    fs::write(
        stage.join("app/input-platform.roc"),
        r#"platform "structured-input-reflection"
    requires { unused : {} -> {} }
    exposes []
    packages {}
    provides { "day2_schema": schema_shape, "day2_inputs": input_shape }
    targets: { inputs_dir: "targets/", arm64mac: { inputs: ["libhost.a", app] }, arm64glibc: { inputs: [app], output: Archive }, x64glibc: { inputs: [app], output: Archive } }
import Models
import Contracts
schema_shape : { rows : List(Models.Row) } -> { rows : List(Models.Row) }
schema_shape = |value| value
input_shape : { update : Contracts.Input } -> { update : Contracts.Input }
input_shape = |value| value
"#,
    )?;
    let run = |arguments: &[&Path]| -> Result<String> {
        let output = day2::sandbox::compiler(
            &root,
            stage,
            &root.join("../.toolchains/roc").canonicalize()?,
        )?
        .args(arguments)
        .output()?;
        let diagnostics = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        anyhow::ensure!(
            output.status.success(),
            "native structured input codecs: {diagnostics}"
        );
        Ok(diagnostics)
    };
    run(&[
        Path::new("glue"),
        &root.join("tools/SchemaGlue.roc"),
        stage,
        &stage.join("app/input-platform.roc"),
    ])?;
    let metadata = fs::read(stage.join("checked-types.json"))?;
    let schema = Schema::from_checked_types(&metadata)?;
    let input = &schema.inputs["update"];
    assert_eq!(input.roc_type.as_deref(), Some("Contracts.Input"));
    assert!(matches!(
        input.fields["attributes"],
        Kind::InputShape { .. }
    ));
    let valid = json!({"attributes":[{"key":"role","value":"déveloper"}], "groups":["engineering@example.test"],
        "settings":{"enabled":true,"count":u64::MAX,"note":{"Some":"retained"}}});
    input.validate_input(&valid)?;
    let encoded = serde_json::to_string(&valid.to_string())?;
    fs::write(stage.join("app/Inputs.roc"), schema.inputs_module()?)?;
    let mut source = format!(
        r#"app [step] {{ pf: platform "../sdk/main.roc" }}
import Inputs
step : Str -> Str
step = |raw| raw
expect match Inputs.update.decode({encoded}) {{
    Ok(value) => match Inputs.update.decode(Inputs.update.encode(value)) {{
        Ok(decoded) => decoded.attributes == [{{key: "role", value: "déveloper"}}]
            and decoded.groups == ["engineering@example.test"] and decoded.settings.enabled
            and decoded.settings.count == 18446744073709551615 and decoded.settings.note == Some("retained")
        Err(_) => Bool.False
    }}
    Err(_) => Bool.False
}}
"#
    );
    for bad in [json!(1.5), json!(-1)] {
        let mut invalid = valid.clone();
        invalid["settings"]["count"] = bad;
        let encoded = serde_json::to_string(&invalid.to_string())?;
        source.push_str(&format!("expect match Inputs.update.decode({encoded}) {{ Err(_) => Bool.True, Ok(_) => Bool.False }}\n"));
    }
    fs::write(stage.join("app/main.roc"), source)?;
    let diagnostics = run(&[Path::new("test"), &stage.join("app/main.roc")])?;
    assert!(
        diagnostics.contains("All (3) tests passed"),
        "expectations must execute: {diagnostics}"
    );
    Ok(())
}

#[test]
fn relational_storage_reflection_rejects_forged_text_codec_shapes() -> Result<()> {
    // Exercise the real compiler's storage reflection independently of the
    // function-bearing application registry. Full artifact parity is checked below.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let temporary = tempfile::tempdir_in(root.join("artifacts"))?;
    let stage = temporary.path();
    day2::app_sources::stage(
        &root.join("fixtures/relational-conformance"),
        &stage.join("app"),
    )?;
    day2::sdk::stage(&root.join("sdk"), &stage.join("sdk"))?;
    fs::write(stage.join("sdk/types.roc"), day2::sdk::reflection_package())?;
    let source = fs::read_to_string(stage.join("app/App.roc"))?;
    fs::write(
        stage.join("app/SchemaSource.roc"),
        day2::app_inference::schema_source(&source)?,
    )?;
    fs::copy(
        root.join("tools/schema-platform.roc"),
        stage.join("app/schema-platform.roc"),
    )?;
    let output = day2::sandbox::compiler(
        &root,
        stage,
        &root.join("../.toolchains/roc").canonicalize()?,
    )?
    .arg("glue")
    .arg(root.join("tools/SchemaGlue.roc"))
    .arg(stage)
    .arg(stage.join("app/schema-platform.roc"))
    .output()?;
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: Value = serde_json::from_slice(&fs::read(stage.join("checked-types.json"))?)?;
    let schema = Schema::from_checked_types(&serde_json::to_vec(&metadata)?)?;
    assert_eq!(schema.foreign_keys.len(), 4);
    assert_eq!(schema.indexes.len(), 3);
    assert_eq!(
        schema
            .indexes
            .iter()
            .find(|index| index.model == "history")
            .unwrap()
            .fields,
        ["deal_id", "from_stage_id", "occurred_at", "to_stage_id"]
    );
    assert_eq!(
        schema.models["deals"].fields["title"],
        Kind::StandardText {
            domain: "Title".into()
        }
    );
    for mutation in ["missing_value", "nontext_value"] {
        let mut forged = metadata.clone();
        let types = forged[0]["types"].as_array_mut().unwrap();
        let integer = types
            .iter()
            .position(|node| node["kind"] == "integer")
            .unwrap();
        let mut changed = false;
        for node in types {
            if node["name"] == "Text" {
                for field in node["fields"].as_array_mut().unwrap() {
                    if field["name"] == "value" {
                        changed = true;
                        if mutation == "missing_value" {
                            field["name"] = json!("raw");
                        } else {
                            field["type_id"] = json!(integer);
                        }
                    }
                }
            }
        }
        assert!(changed, "positive mutation control");
        assert!(
            Schema::from_checked_types(&serde_json::to_vec(&forged)?).is_err(),
            "{mutation}"
        );
    }
    Ok(())
}

#[test]
fn checked_nominal_types_generate_typed_references_codecs_and_indexes() -> Result<()> {
    let artifact = artifact()?;
    let metadata = fs::read(artifact.directory().join("checked-types.json"))?;
    let mut schema = Schema::from_checked_types(&metadata)?;
    let identities = serde_json::from_slice(&fs::read(
        artifact.directory().join("model-identities.json"),
    )?)?;
    schema.bind_identities(&identities)?;
    assert_eq!(schema, artifact.contract().schema);
    assert_eq!(
        schema.models["deals"].roc_type.as_deref(),
        Some("Models.Deal")
    );
    assert_eq!(
        schema.models["deals"].fields["stage_id"],
        Kind::ModelReference {
            target: "stages".into(),
            prefix: "sta".into()
        }
    );
    assert_eq!(
        schema.inputs[&artifact.operation("deals.seed")?.input_type].fields["title"],
        Kind::StandardText {
            domain: "Title".into()
        }
    );
    assert_eq!(schema.foreign_keys.len(), 4);
    let ddl = schema.ddl()?;
    assert_eq!(
        ddl.iter()
            .filter(|statement| statement.starts_with("CREATE INDEX"))
            .count(),
        5
    );
    assert_eq!(
        ddl.iter()
            .filter(|statement| statement.starts_with("CREATE UNIQUE INDEX"))
            .count(),
        2
    );
    assert!(schema.indexes.iter().any(|index| index.model == "deals"
        && index.unique
        && index.fields == ["stage_id", "title"]));
    let data = schema.data_module()?;
    assert!(data.contains(
        "deals_by_stage_id : Ref(Models.Stage), Cursor, PageSize -> Selection(Models.Deal)"
    ));
    assert!(
        data.contains("Domains.title(day2_value.title)")
            && data.contains("Text.to_str(value.title)")
    );
    let inputs = schema.inputs_module()?;
    assert!(inputs.contains("Ref.for_model(\"dea\", day2_value.deal_id)"));
    assert!(data.contains("Ref.for_model(\"sta\", day2_value.stage_id)"));
    Ok(())
}

#[test]
fn unsupported_or_ambiguous_compiler_metadata_fails_closed() -> Result<()> {
    let artifact = artifact()?;
    let original: Value =
        serde_json::from_slice(&fs::read(artifact.directory().join("checked-types.json"))?)?;
    for mutation in [
        "alias",
        "duplicate",
        "unregistered",
        "domain_shape",
        "unsupported",
        "invalid_node",
    ] {
        let mut document = original.clone();
        let table = &mut document[0];
        let entry = table["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["symbol"] == "day2_schema")
            .unwrap()["type_id"]
            .as_u64()
            .unwrap() as usize;
        let root = table["types"][entry]["ret"].as_u64().unwrap() as usize;
        match mutation {
            "alias" => {
                for node in table["types"].as_array_mut().unwrap() {
                    if node["name"] == "Models.Deal" {
                        node["name"] = json!("__AnonStruct_fixture");
                    }
                }
            }
            "duplicate" => {
                let mut duplicate = table["types"][root]["fields"][0].clone();
                duplicate["name"] = json!("duplicate");
                table["types"][root]["fields"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
            "unregistered" => table["types"][root]["fields"]
                .as_array_mut()
                .unwrap()
                .retain(|field| field["name"] != "stages"),
            "domain_shape" => {
                for node in table["types"].as_array_mut().unwrap() {
                    if node["name"] == "Text" {
                        for field in node["fields"].as_array_mut().unwrap() {
                            if field["name"] == "value" {
                                field["name"] = json!("raw");
                            }
                        }
                    }
                }
            }
            "unsupported" => {
                for node in table["types"].as_array_mut().unwrap() {
                    if node["kind"] == "integer" {
                        node["kind"] = json!("decimal");
                    }
                }
            }
            "invalid_node" => table["types"][entry]["ret"] = json!(999_999),
            _ => unreachable!(),
        }
        assert!(
            Schema::from_checked_types(&serde_json::to_vec(&document)?).is_err(),
            "{mutation}"
        );
    }
    Ok(())
}

#[test]
fn checked_storage_index_declarations_reject_forged_model_fields_and_markers() -> Result<()> {
    let artifact = artifact()?;
    let original: Value =
        serde_json::from_slice(&fs::read(artifact.directory().join("checked-types.json"))?)?;
    for mutation in ["model", "field", "marker", "witness", "empty"] {
        let mut document = original.clone();
        let table = &mut document[0];
        let entry = table["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["symbol"] == "day2_storage")
            .unwrap()["type_id"]
            .as_u64()
            .unwrap() as usize;
        let root = table["types"][entry]["ret"].as_u64().unwrap() as usize;
        let declarations = table["types"][root]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|field| field["name"] == "indexes")
            .unwrap()["type_id"]
            .as_u64()
            .unwrap() as usize;
        let model = table["types"][declarations]["fields"][0]["type_id"]
            .as_u64()
            .unwrap() as usize;
        let key = table["types"][model]["fields"][0]["type_id"]
            .as_u64()
            .unwrap() as usize;
        let witness = table["types"][key]["tags"][0]["payload"][0]
            .as_u64()
            .unwrap() as usize;
        let fields = table["types"][witness]["item"].as_u64().unwrap() as usize;
        match mutation {
            "model" => table["types"][declarations]["fields"][0]["name"] = json!("missing"),
            "field" => table["types"][fields]["fields"][0]["name"] = json!("missing"),
            "marker" => table["types"][key]["tags"][0]["name"] = json!("Unchecked"),
            "witness" => {
                let text = table["types"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .position(|node| node["kind"] == "text")
                    .unwrap();
                table["types"][fields]["fields"][0]["type_id"] = json!(text);
            }
            "empty" => table["types"][fields]["fields"] = json!([]),
            _ => unreachable!(),
        }
        assert!(
            Schema::from_checked_types(&serde_json::to_vec(&document)?).is_err(),
            "{mutation}"
        );
    }
    Ok(())
}

#[test]
fn schema_rejects_forged_relationships_and_generated_name_collisions() -> Result<()> {
    let artifact = artifact()?;
    let original = artifact.contract().schema.clone();
    for mutation in [
        "missing",
        "wrong_target",
        "duplicate",
        "unknown_target",
        "collision",
        "structural",
    ] {
        let mut schema = original.clone();
        match mutation {
            "missing" => {
                schema.foreign_keys.pop();
            }
            "wrong_target" => schema.foreign_keys[0].target = "history".into(),
            "duplicate" => schema.foreign_keys.push(schema.foreign_keys[0].clone()),
            "unknown_target" => {
                schema
                    .inputs
                    .get_mut(&artifact.operation("deals.move")?.input_type)
                    .unwrap()
                    .fields
                    .insert(
                        "deal_id".into(),
                        Kind::Reference {
                            target: "missing".into(),
                        },
                    );
            }
            "collision" => {
                let mut record = schema.models["stages"].clone();
                record.roc_type = Some("Models.OtherStage".into());
                schema.models.insert("all_deals".into(), record);
            }
            "structural" => schema.models.get_mut("stages").unwrap().roc_type = None,
            _ => unreachable!(),
        }
        assert!(schema.validate_typed().is_err(), "{mutation}");
    }
    assert!(
        serde_json::from_value::<Kind>(json!({"reference":{"target":"stages","unknown":true}}))
            .is_err()
    );
    Ok(())
}

#[test]
fn references_use_model_prefixed_strings_and_binary_uuid_storage() -> Result<()> {
    let artifact = artifact()?;
    let schema = &artifact.contract().schema;
    let input = &schema.inputs[&artifact.operation("deals.move")?.input_type];
    let deal = day2::identity::example("dea");
    let stage = day2::identity::example("sta");
    let valid = json!({"deal_id":deal,"target_stage_id":stage,"expected_version":1});
    // Input and worker transport share canonical, model-bound references.
    input.validate_input(&valid)?;
    input.validate_value(&valid)?;
    for id in [
        json!(1),
        json!("1"),
        json!(""),
        json!(stage),
        json!(deal.to_uppercase()),
        json!(format!("{deal} ")),
        json!("dea_00000000000000000000000000"),
    ] {
        let mut value = valid.clone();
        value["deal_id"] = id;
        assert!(input.validate_input(&value).is_err());
        assert!(input.validate_value(&value).is_err());
    }
    let mut unknown = valid;
    unknown["scope"] = json!("forged");
    assert!(input.validate_input(&unknown).is_err());
    let sql = schema.ddl()?.join("\n");
    assert!(
        sql.contains("id BLOB") && sql.contains("\"stage_id\" BLOB"),
        "{sql}"
    );
    Ok(())
}
