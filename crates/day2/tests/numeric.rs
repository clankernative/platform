use anyhow::Result;
use day2::{
    numeric::Unsigned,
    openapi,
    output_schema::{self, Type},
    schema::{Kind, Record, Schema},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};

fn record(fields: BTreeMap<String, Kind>, roc_type: &str) -> Record {
    Record {
        identity: None,
        fields,
        roc_type: Some(roc_type.into()),
    }
}

fn schema() -> Schema {
    Schema {
        domains: BTreeMap::new(),
        models: BTreeMap::from([(
            "rows".into(),
            record(
                BTreeMap::from([("count".into(), Kind::Unsigned(Unsigned::U32))]),
                "Models.Row",
            ),
        )]),
        inputs: BTreeMap::from([(
            "counts".into(),
            record(
                BTreeMap::from([
                    ("small".into(), Kind::Unsigned(Unsigned::U8)),
                    ("medium".into(), Kind::Unsigned(Unsigned::U16)),
                    ("large".into(), Kind::Unsigned(Unsigned::U32)),
                    ("huge".into(), Kind::Unsigned(Unsigned::U64)),
                    ("revision".into(), Kind::RowVersion),
                ]),
                "Contracts.Counts",
            ),
        )]),
        foreign_keys: vec![],
        indexes: vec![],
    }
}

#[test]
fn numeric_bounds_agree_for_inputs_outputs_and_openapi() -> Result<()> {
    for unsigned in [Unsigned::U8, Unsigned::U16, Unsigned::U32, Unsigned::U64] {
        let kind = Kind::Unsigned(unsigned);
        let shape = Type::Unsigned(unsigned);
        for value in [json!(0), json!(unsigned.maximum())] {
            assert!(kind.valid(&value));
            shape.validate_value(&value)?;
        }
        for value in [json!(-1), json!(1.5), json!("1"), json!(null)] {
            assert!(!kind.valid(&value));
            assert!(shape.validate_value(&value).is_err());
        }
        if let Some(overflow) = unsigned.maximum().checked_add(1) {
            assert!(!kind.valid(&json!(overflow)));
            assert!(shape.validate_value(&json!(overflow)).is_err());
        }
        let spec = openapi::input_schema(&kind);
        assert_eq!(spec, openapi::output_schema(&shape));
        assert_eq!(spec["minimum"], 0);
        assert_eq!(spec["maximum"], unsigned.maximum());
    }
    for value in [json!(-1), json!(0), json!(u64::MAX), json!(1.5)] {
        assert!(!Kind::RowVersion.valid(&value));
        assert!(Type::RowVersion.validate_value(&value).is_err());
    }
    for value in [json!(1), json!(i64::MAX)] {
        assert!(Kind::RowVersion.valid(&value));
        Type::RowVersion.validate_value(&value)?;
    }
    assert_eq!(openapi::output_schema(&Type::RowVersion)["minimum"], 1);
    assert_eq!(
        openapi::output_schema(&Type::RowVersion)["format"],
        "uint64"
    );
    assert_eq!(
        openapi::input_schema(&Kind::RowVersion),
        openapi::output_schema(&Type::RowVersion)
    );
    // Signed fields still represent genuinely signed values, regardless of their name.
    let signed = record(
        BTreeMap::from([("version".into(), Kind::Integer)]),
        "Contracts.Signed",
    );
    signed.validate_input(&json!({"version":-1}))?;
    assert_eq!(
        openapi::record_schema(&signed)["properties"]["version"]["minimum"],
        i64::MIN
    );
    Ok(())
}

#[test]
fn sqlite_enforces_unsigned_widths_and_exact_u64_storage() -> Result<()> {
    let mut schema = schema();
    let db = rusqlite::Connection::open_in_memory()?;
    for statement in schema.ddl()? {
        db.execute_batch(&statement)?;
    }
    for (id, value) in [(1, 0_i64), (2, i64::from(u32::MAX))] {
        db.execute(
            "INSERT INTO rows (id,version,created_at,count) VALUES (?1,1,0,?2)",
            [id, value],
        )?;
    }
    for value in [-1, i64::from(u32::MAX) + 1] {
        assert!(
            db.execute(
                "INSERT INTO rows (id,version,created_at,count) VALUES (3,1,0,?1)",
                [value]
            )
            .is_err()
        );
    }
    schema
        .models
        .get_mut("rows")
        .unwrap()
        .fields
        .insert("count".into(), Kind::Unsigned(Unsigned::U64));
    schema.validate()?;
    let db = rusqlite::Connection::open_in_memory()?;
    for statement in schema.ddl()? {
        db.execute_batch(&statement)?;
    }
    for value in [0_u64, i64::MAX as u64 + 1, u64::MAX] {
        db.execute(
            "INSERT INTO rows (version,created_at,count) VALUES (1,0,?1)",
            [value.to_be_bytes().as_slice()],
        )?;
    }
    use rusqlite::types::Value as SqlValue;
    for invalid in [
        SqlValue::Integer(-1),
        SqlValue::Integer(1),
        SqlValue::Real(1.5),
        SqlValue::Text(u64::MAX.to_string()),
        SqlValue::Blob(vec![0; 7]),
        SqlValue::Blob(vec![0; 9]),
        SqlValue::Null,
    ] {
        assert!(
            db.execute(
                "INSERT INTO rows (version,created_at,count) VALUES (1,0,?1)",
                [invalid],
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn checked_numeric_metadata_retains_width_and_domain_identity() -> Result<()> {
    let node = |kind: &str, name: &str, fields: Value, item: usize, args: Value, ret: usize| json!({"kind":kind,"name":name,"fields":fields,"item":item,"args":args,"ret":ret,"tags":[]});
    let mut metadata = json!([{"entries":[
        {"symbol":"day2_schema","type_id":7}, {"symbol":"day2_inputs","type_id":9}, {"symbol":"day2_outputs","type_id":9}
    ], "types":[
        node("unsigned","U32",json!([]),0,json!([]),0),
        node("integer","",json!([]),0,json!([]),0),
        node("record","RowVersion",json!([{"name":"value","type_id":1}]),0,json!([]),0),
        node("record","Contracts.Count",json!([{"name":"count","type_id":0},{"name":"revision","type_id":2}]),0,json!([]),0),
        node("record","Models.Row",json!([{"name":"count","type_id":0}]),0,json!([]),0),
        node("list","",json!([]),4,json!([]),0),
        node("record","__Tables",json!([{"name":"rows","type_id":5}]),0,json!([]),0),
        node("function","",json!([]),0,json!([6]),6),
        node("record","__Contracts",json!([{"name":"count","type_id":3}]),0,json!([]),0),
        node("function","",json!([]),0,json!([8]),8)
    ]}]);
    let raw = serde_json::to_vec(&metadata)?;
    let inputs = Schema::from_checked_types(&raw)?;
    assert_eq!(
        inputs.inputs["count"].fields["count"],
        Kind::Unsigned(Unsigned::U32)
    );
    assert_eq!(inputs.inputs["count"].fields["revision"], Kind::RowVersion);
    let outputs = output_schema::from_checked_types(&raw)?;
    let spec = openapi::output_schema(&outputs["count"].shape);
    assert_eq!(spec["properties"]["count"]["minimum"], 0);
    assert_eq!(spec["properties"]["revision"]["minimum"], 1);
    // Preserve historical RowVersion artifacts; newly checked SDK types use U64.
    metadata[0]["types"][1]["kind"] = json!("unsigned");
    metadata[0]["types"][1]["name"] = json!("U64");
    let raw = serde_json::to_vec(&metadata)?;
    assert_eq!(Schema::from_checked_types(&raw)?, inputs);
    assert_eq!(output_schema::from_checked_types(&raw)?, outputs);
    metadata[0]["types"][2]["fields"][0]["type_id"] = json!(0);
    assert!(Schema::from_checked_types(&serde_json::to_vec(&metadata)?).is_err());
    assert!(output_schema::from_checked_types(&serde_json::to_vec(&metadata)?).is_err());
    metadata[0]["types"][0]["name"] = json!("U128");
    assert!(Schema::from_checked_types(&serde_json::to_vec(&metadata)?).is_err());
    Ok(())
}

#[test]
fn native_generated_numeric_codecs_roundtrip_boundaries_and_reject_negative_values() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let temporary = tempfile::tempdir_in(root.join("artifacts"))?;
    let stage = temporary.path();
    fs::create_dir(stage.join("sdk"))?;
    fs::create_dir(stage.join("app"))?;
    day2::sdk::stage(&root.join("sdk"), &stage.join("sdk"))?;
    fs::write(stage.join("sdk/main.roc"), day2::sdk::app_platform())?;
    fs::write(
        stage.join("app/Contracts.roc"),
        "import pf.RowVersion\nContracts :: [].{ Counts := { small : U8, medium : U16, large : U32, huge : U64, revision : RowVersion } }\n",
    )?;
    fs::write(
        stage.join("app/Models.roc"),
        "Models :: [].{ Row := { count : U32 } }\n",
    )?;
    let schema = schema();
    fs::write(stage.join("app/Inputs.roc"), schema.inputs_module()?)?;
    let outputs = BTreeMap::from([(
        "counts".into(),
        output_schema::Contract {
            shape: Type::Record(BTreeMap::from([
                ("small".into(), Type::Unsigned(Unsigned::U8)),
                ("medium".into(), Type::Unsigned(Unsigned::U16)),
                ("large".into(), Type::Unsigned(Unsigned::U32)),
                ("huge".into(), Type::Unsigned(Unsigned::U64)),
                ("revision".into(), Type::RowVersion),
            ])),
            roc_type: "Contracts.Counts".into(),
        },
    )]);
    fs::write(
        stage.join("app/Outputs.roc"),
        output_schema::roc_module(&outputs)?,
    )?;
    // Use the generated decoders independently of the host's JSON validation.
    let valid =
        json!({"small":255,"medium":65535,"large":u32::MAX,"huge":u64::MAX,"revision":i64::MAX});
    let mut source = String::from(
        "app [step] { pf: platform \"../sdk/main.roc\" }\nimport Inputs\nimport Outputs\nimport pf.RowVersion\nstep : Str -> Str\nstep = |raw| raw\n",
    );
    source.push_str(&format!("expect match Inputs.counts.decode({}) {{\n Ok(value) => match Inputs.counts.decode(Outputs.counts.encode(value)) {{\n  Ok(decoded) => decoded.small == 255 and decoded.medium == 65535 and decoded.large == 4294967295 and decoded.huge == 18446744073709551615 and decoded.revision.to_i64() == 9223372036854775807\n  Err(_) => Bool.False\n }}\n Err(_) => Bool.False\n}}\n", serde_json::to_string(&valid.to_string())?));
    source.push_str("expect RowVersion.one.to_u64() == 1\nexpect match RowVersion.from_u64(9223372036854775807) { Ok(value) => value.to_u64() == 9223372036854775807 and value.to_i64() == 9223372036854775807, Err(_) => Bool.False }\nexpect match RowVersion.from_u64(0) { Err(_) => Bool.True, Ok(_) => Bool.False }\nexpect match RowVersion.from_u64(9223372036854775808) { Err(_) => Bool.True, Ok(_) => Bool.False }\nexpect match RowVersion.from_i64(-1) { Err(_) => Bool.True, Ok(_) => Bool.False }\n");
    let mut expected = 6;
    for field in ["small", "medium", "large", "huge", "revision"] {
        for value in [json!(-1), json!(1.5)] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            source.push_str(&format!("expect match Inputs.counts.decode({}) {{\n Err(_) => Bool.True\n Ok(_) => Bool.False\n}}\n",serde_json::to_string(&invalid.to_string())?));
            expected += 1;
        }
    }
    for (field, value) in [
        ("small", json!(256)),
        ("medium", json!(65536)),
        ("large", json!(u64::from(u32::MAX) + 1)),
        ("revision", json!(0)),
        ("revision", json!(u64::MAX)),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        source.push_str(&format!("expect match Inputs.counts.decode({}) {{\n Err(_) => Bool.True\n Ok(_) => Bool.False\n}}\n",serde_json::to_string(&invalid.to_string())?));
        expected += 1;
    }
    fs::write(stage.join("app/main.roc"), source)?;
    let output = day2::sandbox::compiler(&root, stage, &root.join("../.toolchains/roc"))?
        .arg("test")
        .arg(stage.join("app/main.roc"))
        .output()?;
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "native numeric codecs: {diagnostics}"
    );
    assert!(
        diagnostics.contains(&format!("All ({expected}) tests passed")),
        "expectations must execute: {diagnostics}"
    );
    Ok(())
}
