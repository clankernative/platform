use anyhow::Result;
use day2::{
    output_schema::{self, Type},
    schema::Schema,
};
use serde_json::{Value, json};

fn node(kind: &str, name: &str, fields: Value, item: usize, args: Value, ret: usize) -> Value {
    json!({"kind":kind,"name":name,"fields":fields,"item":item,"args":args,"ret":ret,"tags":[]})
}

fn metadata() -> Value {
    json!([{
        "entries":[
            {"symbol":"day2_outputs","type_id":7},
            {"symbol":"day2_schema","type_id":10},
            {"symbol":"day2_inputs","type_id":13}
        ],
        "types":[
            node("text", "", json!([]), 0, json!([]), 0),
            node("integer", "", json!([]), 0, json!([]), 0),
            node("boolean", "", json!([]), 0, json!([]), 0),
            node("record", "__AnonStruct_Link", json!([
                {"name":"title","type_id":0}, {"name":"version","type_id":1},
                {"name":"archived","type_id":2}
            ]), 0, json!([]), 0),
            node("list", "", json!([]), 3, json!([]), 0),
            node("record", "CollectionPage", json!([
                {"name":"items","type_id":4}, {"name":"has_more","type_id":2},
                {"name":"next_after","type_id":15}
            ]), 0, json!([]), 0),
            node("record", "__AnonStruct_Outputs", json!([{"name":"links","type_id":5}]), 0, json!([]), 0),
            node("function", "", json!([]), 0, json!([6]), 6),
            node("record", "Models.Row", json!([{"name":"title","type_id":0}]), 0, json!([]), 0),
            node("record", "__AnonStruct_Tables", json!([{"name":"rows","type_id":14}]), 0, json!([]), 0),
            node("function", "", json!([]), 0, json!([9]), 9),
            node("record", "__AnonStruct_Input", json!([{"name":"title","type_id":0}]), 0, json!([]), 0),
            node("record", "__AnonStruct_Inputs", json!([{"name":"create","type_id":11}]), 0, json!([]), 0),
            node("function", "", json!([]), 0, json!([12]), 12),
            node("list", "", json!([]), 8, json!([]), 0),
            node("record", "Cursor", json!([{"name":"value","type_id":1}]), 0, json!([]), 0)
        ]
    }])
}

fn catalog(document: &Value) -> Result<output_schema::Catalog> {
    output_schema::from_checked_types(&serde_json::to_vec(document)?)
}

#[test]
fn optional_text_output_reflection_and_wire_contract_are_exact() -> Result<()> {
    let mut document = metadata();
    let mut optional = node("union", "NoneOrSome", json!([]), 0, json!([]), 0);
    optional["tags"] = json!([
        {"name":"None","payload":[]}, {"name":"Some","payload":[0]}
    ]);
    document[0]["types"]
        .as_array_mut()
        .unwrap()
        .push(optional.clone());
    document[0]["types"][3]["fields"][0]["type_id"] = json!(16);
    let outputs = catalog(&document)?;
    let Type::CollectionPage(item) = &outputs["links"].shape else {
        panic!("page output")
    };
    let Type::Record(fields) = item.as_ref() else {
        panic!("record item")
    };
    assert_eq!(fields["title"], Type::OptionalText);
    let generated = output_schema::roc_module(&outputs)?;
    assert!(generated.contains("title : [None, Some(Str)]"));
    assert!(!generated.contains("import None") && !generated.contains("import Some"));
    let schema = day2::operation_catalog::output_schema(&Type::OptionalText);
    assert_eq!(schema["oneOf"][0]["const"], "None");
    assert_eq!(schema["oneOf"][1]["additionalProperties"], false);
    for value in [json!("None"), json!({"Some":""}), json!({"Some":"hello"})] {
        Type::OptionalText.validate_value(&value)?;
    }
    for value in [
        json!(null),
        json!(""),
        json!({}),
        json!({"None":null}),
        json!({"Some":false}),
        json!({"Some":[]}),
        json!({"Some":"ok","extra":0}),
        json!({"Some":"x".repeat(16 * 1024 + 1)}),
    ] {
        assert!(
            Type::OptionalText.validate_value(&value).is_err(),
            "{value}"
        );
    }
    for (field, value) in [
        ("fields", json!([{"name":"hidden","type_id":0}])),
        ("args", json!([0])),
        ("item", json!(1)),
        ("ret", json!(1)),
        ("tags", json!([{"name":"None","payload":[]}])),
        (
            "tags",
            json!([{"name":"None","payload":[0]}, {"name":"Some","payload":[0]}]),
        ),
        (
            "tags",
            json!([{"name":"None","payload":[]}, {"name":"Some","payload":[1]}]),
        ),
        (
            "tags",
            json!([{"name":"None","payload":[]}, {"name":"Some","payload":[0,0]}]),
        ),
        (
            "tags",
            json!([{"name":"None","payload":[]}, {"name":"Other","payload":[0]}]),
        ),
    ] {
        let mut forged = document.clone();
        forged[0]["types"][16][field] = value;
        assert!(catalog(&forged).is_err(), "optional metadata {field}");
    }
    Ok(())
}

fn box_references(document: &mut Value) {
    let table = &mut document[0];
    let types = table["types"].as_array_mut().unwrap();
    let count = types.len();
    for value in types.iter_mut() {
        for field in value["fields"].as_array_mut().unwrap() {
            field["type_id"] = json!(field["type_id"].as_u64().unwrap() + (2 * count) as u64);
        }
        for argument in value["args"].as_array_mut().unwrap() {
            *argument = json!(argument.as_u64().unwrap() + (2 * count) as u64);
        }
        if value["kind"] == "function" {
            value["ret"] = json!(value["ret"].as_u64().unwrap() + (2 * count) as u64);
        }
        if value["kind"] == "list" {
            value["item"] = json!(value["item"].as_u64().unwrap() + (2 * count) as u64);
        }
    }
    for payload in 0..(2 * count) {
        types.push(node("box", "", json!([]), payload, json!([]), 0));
    }
    for entry in table["entries"].as_array_mut().unwrap() {
        entry["type_id"] = json!(entry["type_id"].as_u64().unwrap() + (2 * count) as u64);
    }
}

#[test]
fn compiler_box_layout_does_not_change_database_or_output_contracts() -> Result<()> {
    let original = metadata();
    let mut boxed = original.clone();
    box_references(&mut boxed);
    let schema = Schema::from_checked_types(&serde_json::to_vec(&original)?)?;
    let boxed_schema = Schema::from_checked_types(&serde_json::to_vec(&boxed)?)?;
    assert_eq!(schema, boxed_schema);
    assert_eq!(schema.ddl()?, boxed_schema.ddl()?);
    assert_eq!(
        boxed_schema.models["rows"].roc_type.as_deref(),
        Some("Models.Row")
    );
    let outputs = catalog(&original)?;
    let boxed_outputs = catalog(&boxed)?;
    assert_eq!(outputs, boxed_outputs);
    assert_eq!(
        output_schema::roc_module(&outputs)?,
        output_schema::roc_module(&boxed_outputs)?
    );
    Ok(())
}

#[test]
fn compiler_boxes_do_not_hide_unsupported_or_recursive_data() -> Result<()> {
    for (path, value) in [
        ("/0/types/3/fields/0/type_id", json!(7)),
        ("/0/types/3/fields/0/type_id", json!(5)),
        ("/0/types/6/fields/0/type_id", json!(4)),
        ("/0/types/0/kind", json!("unsupported")),
    ] {
        let mut document = metadata();
        *document.pointer_mut(path).unwrap() = value;
        box_references(&mut document);
        assert!(catalog(&document).is_err(), "boxed output accepted: {path}");
    }
    for payload in [7, 8] {
        let mut document = metadata();
        document[0]["types"][8]["fields"][0]["type_id"] = json!(payload);
        box_references(&mut document);
        assert!(
            Schema::from_checked_types(&serde_json::to_vec(&document)?).is_err(),
            "boxed function or recursive model field was admitted"
        );
    }
    let mut document = metadata();
    let types = document[0]["types"].as_array_mut().unwrap();
    let mut payload = 0;
    for _ in 0..output_schema::MAX_DEPTH {
        types.push(node(
            "record",
            "__AnonStruct_Deep",
            json!([{"name":"value","type_id":payload}]),
            0,
            json!([]),
            0,
        ));
        payload = types.len() - 1;
    }
    document[0]["types"][3]["fields"][0]["type_id"] = json!(payload);
    box_references(&mut document);
    assert!(
        catalog(&document).is_err(),
        "boxed data bypassed depth budget"
    );
    Ok(())
}

#[test]
fn checked_nested_outputs_generate_typed_encoders_without_changing_database_schema() -> Result<()> {
    let original = metadata();
    let outputs = catalog(&original)?;
    let source = output_schema::roc_module(&outputs)?;
    assert!(source.contains(
        "links : Output(CollectionPage({ archived : Bool, title : Str, version : I64 }))"
    ));
    assert!(source.contains("CollectionPage.items(data).map"));
    assert!(source.contains("Cursor.to_str(CollectionPage.next_after(data))"));
    assert_eq!(source, output_schema::roc_module(&catalog(&original)?)?);
    outputs["links"].shape.validate_value(&json!({
        "items":[{"title":"Example", "version":1, "archived":false}],
        "has_more":false, "next_after":"1"
    }))?;
    let before = Schema::from_checked_types(&serde_json::to_vec(&original)?)?;
    let mut changed = original.clone();
    changed[0]["types"][3]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"subtitle","type_id":0}));
    assert_ne!(outputs, catalog(&changed)?);
    let after = Schema::from_checked_types(&serde_json::to_vec(&changed)?)?;
    assert_eq!(before.hash()?, after.hash()?);
    assert_eq!(before.ddl()?, after.ddl()?);
    Ok(())
}

#[test]
fn checked_output_graph_rejects_unsupported_cycles_ambiguity_and_invalid_references() -> Result<()>
{
    for mutation in [
        "unsupported",
        "cycle",
        "missing",
        "duplicate_witness",
        "duplicate_field",
        "duplicate_output",
        "invalid_ref",
        "bad_witness",
        "bad_name",
        "deep",
    ] {
        let mut document = metadata();
        match mutation {
            "unsupported" => document[0]["types"][0]["kind"] = json!("decimal"),
            "cycle" => document[0]["types"][4]["item"] = json!(5),
            "missing" => {
                document[0]["entries"] = json!([]);
            }
            "duplicate_witness" => {
                let entry = document[0]["entries"][0].clone();
                document[0]["entries"].as_array_mut().unwrap().push(entry);
            }
            "duplicate_field" => {
                let field = document[0]["types"][3]["fields"][0].clone();
                document[0]["types"][3]["fields"]
                    .as_array_mut()
                    .unwrap()
                    .push(field);
            }
            "duplicate_output" => {
                let field = document[0]["types"][6]["fields"][0].clone();
                document[0]["types"][6]["fields"]
                    .as_array_mut()
                    .unwrap()
                    .push(field);
            }
            "invalid_ref" => document[0]["types"][4]["item"] = json!(99_999),
            "bad_witness" => document[0]["types"][7]["args"] = json!([5]),
            "bad_name" => document[0]["types"][3]["fields"][0]["name"] = json!("bad-field"),
            "deep" => {
                let types = document[0]["types"].as_array_mut().unwrap();
                let mut item = 0;
                for _ in 0..output_schema::MAX_DEPTH {
                    types.push(node("list", "", json!([]), item, json!([]), 0));
                    item = types.len() - 1;
                }
                document[0]["types"][6]["fields"][0]["type_id"] = json!(item);
            }
            _ => unreachable!(),
        };
        assert!(catalog(&document).is_err(), "{mutation}");
    }
    Ok(())
}

#[test]
fn runtime_output_validation_is_exact_and_bounded() -> Result<()> {
    let outputs = catalog(&metadata())?;
    let shape = &outputs["links"].shape;
    let valid = json!({"items":[{"title":"Example","version":1,"archived":false}],"has_more":false,"next_after":"1"});
    for mutation in [
        "extra",
        "missing",
        "nested_extra",
        "null",
        "wrong_boolean",
        "wrong_integer",
        "overflow",
        "string_budget",
        "list_budget",
    ] {
        let mut value = valid.clone();
        match mutation {
            "extra" => value["unregistered"] = json!(true),
            "missing" => {
                value.as_object_mut().unwrap().remove("has_more");
            }
            "nested_extra" => value["items"][0]["extra"] = json!("no"),
            "null" => value["items"] = Value::Null,
            "wrong_boolean" => value["has_more"] = json!("false"),
            "wrong_integer" => value["next_after"] = json!(1.5),
            "overflow" => value["next_after"] = json!(u64::MAX),
            "string_budget" => value["items"][0]["title"] = json!("x".repeat(16 * 1_024 + 1)),
            "list_budget" => {
                value["items"] = json!(vec![
                    valid["items"][0].clone();
                    output_schema::MAX_PAGE_ITEMS + 1
                ])
            }
            _ => unreachable!(),
        }
        assert!(shape.validate_value(&value).is_err(), "{mutation}");
    }
    Type::Integer.validate_value(&json!(i64::MIN))?;
    Type::Integer.validate_value(&json!(i64::MAX))?;
    Ok(())
}

#[test]
fn empty_catalog_and_nominal_records_have_explicit_generated_contracts() -> Result<()> {
    let mut document = metadata();
    document[0]["types"][6] = node("unit", "", json!([]), 0, json!([]), 0);
    let empty = catalog(&document)?;
    assert!(empty.is_empty());
    assert_eq!(output_schema::roc_module(&empty)?, "Outputs :: [].{}\n");
    let mut document = metadata();
    document[0]["types"][3]["name"] = json!("Contracts.LinkView");
    let outputs = catalog(&document)?;
    let source = output_schema::roc_module(&outputs)?;
    assert!(source.contains("import Contracts\n"));
    assert!(source.contains("links : Output(CollectionPage(Contracts.LinkView))"));
    let mut forged = outputs;
    forged.get_mut("links").unwrap().roc_type = "Str)\nimport Danger".into();
    assert!(output_schema::roc_module(&forged).is_err());
    Ok(())
}

#[test]
fn bare_and_disguised_collections_are_rejected_recursively() -> Result<()> {
    let legacy = Type::List(Box::new(Type::String));
    assert!(legacy.validate_api().is_err());
    legacy.validate_value(&json!(["legacy-artifact"]))?;
    assert!(
        Type::Record(std::collections::BTreeMap::from([(
            "nested".into(),
            Type::CollectionPage(Box::new(legacy.clone()))
        )]))
        .validate_api()
        .is_err()
    );
    for shape in ["__AnonStruct_Page", "Contracts.DisguisedPage"] {
        let mut document = metadata();
        document[0]["types"][5]["name"] = json!(shape);
        assert!(catalog(&document).is_err());
    }
    let mut document = metadata();
    document[0]["types"][6]["fields"][0]["type_id"] = json!(4);
    assert!(catalog(&document).is_err());
    Ok(())
}

#[test]
fn collection_envelopes_enforce_canonical_cursors_continuations_and_nested_budgets() -> Result<()> {
    let shape = Type::CollectionPage(Box::new(Type::String));
    shape.validate_value(&json!({"items":[],"has_more":false,"next_after":"0"}))?;
    shape.validate_value(&json!({"items":vec!["item";100],"has_more":true,"next_after":"100"}))?;
    for invalid in [
        json!(["bare"]),
        json!({"items":[],"has_more":false}),
        json!({"items":[],"has_more":true,"next_after":"1"}),
        json!({"items":["x"],"has_more":true,"next_after":"0"}),
        json!({"items":["x"],"has_more":false,"next_after":1}),
        json!({"items":["x"],"has_more":false,"next_after":"01"}),
        json!({"items":["x"],"has_more":false,"next_after":"-1"}),
        json!({"items":["x"],"has_more":false,"next_after":"9223372036854775808"}),
        json!({"items":vec!["x";101],"has_more":false,"next_after":"1"}),
    ] {
        assert!(shape.validate_value(&invalid).is_err(), "{invalid}");
    }
    let nested = Type::CollectionPage(Box::new(shape));
    let full = json!({"items":vec!["item";100],"has_more":false,"next_after":"100"});
    let mut pages = vec![full; 10];
    // Count both the outer items and their children. The complete Notifications
    // schema needs 20 fields plus 1000 enum choices; the host still has a hard cap.
    pages.push(json!({"items":vec!["item";13],"has_more":false,"next_after":"13"}));
    nested.validate_value(&json!({"items":pages,"has_more":false,"next_after":"11"}))?;
    pages[10]["items"] = json!(vec!["item"; 14]);
    assert!(
        nested
            .validate_value(&json!({"items":pages,"has_more":false,"next_after":"11"}))
            .is_err()
    );
    assert_eq!(Type::Cursor.template_shape(), Type::String);
    assert_eq!(Type::PageSize.template_shape(), Type::Integer);
    Ok(())
}
