use anyhow::Result;
use day2::{api_docs, artifact::Artifact, openapi};
use serde_json::{Value, json};

fn artifact() -> Result<Artifact> {
    Ok(serde_json::from_value(json!({
        "format":10,"namespace":"example","roc_version":"test","worker_digest":"test","schema_digest":"test",
        "schema":{"models":{},"foreign_keys":[],"inputs":{"request":{"fields":{"note":"optional_text","version":"integer"}}}},
        "operations":[
            {"name":"example.save","kind":"command","input_type":"request","output_type":"page"},
            {"name":"example.read","kind":"query","input_type":"request","output_type":"page"}
        ],
        "outputs":{"page":{"roc_type":"Example","shape":{"collection_page":{"record":{"id":"string","version":"integer"}}}}},
        "sources":{},"admission":"local-spike-only"
    }))?)
}

fn entry(operation: &str) -> Value {
    json!({"operation":operation,"input_type":"request","output_type":"page","summary":"Save example",
        "description":"A useful operation.","response_description":"The saved items.",
        "inputs":[{"path":"note","description":"An optional note; send None to clear it."}],
        "outputs":[{"path":"items[].id","description":"Stable item identifier."}],
        "request_example":json!({"note":{"Some":"O'Reilly `literal` $(do_not_run)\n雪"},"version":9223372036854775807_i64}).to_string(),
        "response_example":json!({"items":[{"id":"7","version":9223372036854775807_i64}],"has_more":false,"next_after":"0"}).to_string(),"deprecated":false})
}

fn decode(artifact: &Artifact, entries: Value) -> Result<api_docs::Catalog> {
    api_docs::decode(
        &serde_json::to_vec(&json!({"entries":entries,"error":""}))?,
        &artifact.operations,
        &artifact.schema,
        &artifact.outputs,
    )
}

#[test]
fn documentation_rejects_drift_private_handlers_bad_examples_and_duplicates() -> Result<()> {
    let artifact = artifact()?;
    let valid = entry("example.save");
    decode(&artifact, json!([valid]))?;
    for (pointer, value) in [
        ("/operation", json!("example.missing")),
        ("/operation", json!("private.missing")),
        ("/input_type", json!("same_shape_different_nominal_handle")),
        ("/inputs/0/path", json!("missing")),
        ("/outputs/0/path", json!("items[].missing")),
        ("/outputs/0/path", json!("items.id")),
        ("/inputs/0/path", json!("note[]")),
        ("/request_example", json!("{\"version\":1}")),
        ("/request_example", json!("{\"note\":null,\"version\":1}")),
        (
            "/response_example",
            json!("{\"items\":[],\"has_more\":true,\"next_after\":\"0\"}"),
        ),
    ] {
        let mut invalid = valid.clone();
        *invalid.pointer_mut(pointer).unwrap() = value;
        assert!(decode(&artifact, json!([invalid])).is_err(), "{pointer}");
    }
    assert!(decode(&artifact, json!([valid, valid])).is_err());
    let mut duplicate = valid.clone();
    duplicate["inputs"]
        .as_array_mut()
        .unwrap()
        .push(valid["inputs"][0].clone());
    assert!(decode(&artifact, json!([duplicate])).is_err());
    let mut forged = valid.clone();
    forged["required"] = json!(false);
    assert!(decode(&artifact, json!([forged])).is_err());
    Ok(())
}

#[test]
fn unsigned_64_bit_examples_and_client_samples_preserve_the_full_range() -> Result<()> {
    let mut artifact = artifact()?;
    artifact
        .schema
        .inputs
        .get_mut("request")
        .unwrap()
        .fields
        .insert(
            "version".into(),
            day2::schema::Kind::Unsigned(day2::numeric::Unsigned::U64),
        );
    artifact.outputs.get_mut("page").unwrap().shape = serde_json::from_value(json!({
        "collection_page":{"record":{"id":"string","version":{"unsigned":"U64"}}}
    }))?;
    let mut docs = entry("example.save");
    docs["request_example"] = json!(json!({"note":"None","version":u64::MAX}).to_string());
    docs["response_example"] = json!(
        json!({"items":[{"id":"1","version":u64::MAX}],"has_more":false,"next_after":"0"})
            .to_string()
    );
    artifact.api_docs = decode(&artifact, json!([docs]))?;
    let spec = openapi::Catalog::from_artifact(&artifact)?.document(
        &artifact,
        "Example",
        "test",
        "day2_example",
        "http://127.0.0.1:1234",
    );
    let save = &spec["paths"]["/api/example.save"]["post"];
    assert_eq!(
        save["requestBody"]["content"]["application/json"]["example"]["version"].as_u64(),
        Some(u64::MAX)
    );
    assert_eq!(
        save["responses"]["200"]["content"]["application/json"]["example"]["items"][0]["version"]
            .as_u64(),
        Some(u64::MAX)
    );
    for sample in save["x-codeSamples"].as_array().unwrap() {
        assert!(
            sample["source"]
                .as_str()
                .unwrap()
                .contains("18446744073709551615")
        );
    }
    docs["request_example"] = json!(json!({"note":"None","version":-1}).to_string());
    assert!(decode(&artifact, json!([docs])).is_err());
    Ok(())
}

#[test]
fn spec_preserves_requiredness_int64_examples_and_operation_specific_prose() -> Result<()> {
    let mut artifact = artifact()?;
    artifact.api_docs = decode(&artifact, json!([entry("example.save")]))?;
    let spec = openapi::Catalog::from_artifact(&artifact)?.document(
        &artifact,
        "Example",
        "test",
        "day2_example",
        "http://127.0.0.1:1234",
    );
    let save = &spec["paths"]["/api/example.save"]["post"];
    assert_eq!(save["summary"], "Save example");
    assert_eq!(save["responses"]["200"]["description"], "The saved items.");
    let input = spec
        .pointer(
            save["x-day2-input-schema"]
                .as_str()
                .unwrap()
                .trim_start_matches('#'),
        )
        .unwrap();
    assert!(
        input["required"]
            .as_array()
            .unwrap()
            .contains(&json!("note"))
    );
    assert_eq!(input["properties"]["note"]["oneOf"][0]["const"], "None");
    assert!(
        input["properties"]["note"]["description"]
            .as_str()
            .unwrap()
            .contains("clear")
    );
    let read = &spec["paths"]["/api/example.read"]["get"];
    assert!(
        !read["parameters"][0]["description"]
            .as_str()
            .unwrap()
            .contains("clear")
    );
    let response = &save["responses"]["200"]["content"]["application/json"];
    assert_eq!(response["example"]["items"][0]["version"], json!(i64::MAX));
    let output = spec
        .pointer(
            response["schema"]["$ref"]
                .as_str()
                .unwrap()
                .trim_start_matches('#'),
        )
        .unwrap();
    assert_eq!(
        output["properties"]["items"]["items"]["properties"]["id"]["description"],
        "Stable item identifier."
    );
    assert!(spec["paths"].get("/api/private.missing").is_none());
    let samples = save["x-codeSamples"].as_array().unwrap();
    assert_eq!(samples.len(), 6);
    for sample in samples {
        let code = sample["source"].as_str().unwrap();
        assert!(code.contains("9223372036854775807"));
        for header in ["Cookie", "Origin", "X-CSRF-Token", "Idempotency-Key"] {
            assert!(
                code.contains(header),
                "{} missing {header}",
                sample["label"]
            );
        }
    }
    let curl = samples[0]["source"].as_str().unwrap();
    assert!(curl.contains("O'\"'\"'Reilly"));
    assert!(curl.contains("--data-raw '"));
    assert!(
        read["x-codeSamples"][0]["source"]
            .as_str()
            .unwrap()
            .contains("note=%22None%22")
    );
    assert!(
        !read["x-codeSamples"][0]["source"]
            .as_str()
            .unwrap()
            .contains("Idempotency-Key")
    );
    Ok(())
}
