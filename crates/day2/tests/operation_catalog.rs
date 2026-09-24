use anyhow::Result;
use day2::{artifact::Artifact, mcp, operation_catalog, operation_metadata};
use serde_json::{Value, json};

fn artifact() -> Result<Artifact> {
    Ok(serde_json::from_value(json!({
        "format":11,"namespace":"example","roc_version":"test","worker_digest":"test","schema_digest":"test",
        "schema":{"models":{},"foreign_keys":[],"inputs":{"request":{"fields":{"version":"row_version"}}}},
        "operations":[
            {"name":"example.save","kind":"command","input_type":"request","output_type":"page"},
            {"name":"example.read","kind":"query","input_type":"request","output_type":"page"}
        ],
        "outputs":{"page":{"roc_type":"Example","shape":{"record":{"version":"row_version"}}}},
        "sources":{},"admission":"local-spike-only"
    }))?)
}

fn entry(name: &str) -> Value {
    json!({"target":{"operation":name,"input_type":"request","output_type":"page"},"title":"Example operation",
        "usage":{"purpose":"Inspect or save the example.","use_when":["The user requests the example."],"avoid_when":[],"preconditions":[],
            "effects":if name.ends_with("save") {vec!["Saves the example."]} else {vec![]},"result":"The current revision."},
        "inputs":[{"path":"version","description":"The current revision of the example."}],"outputs":[],
        "input_sources":[{"input":"version","source":{"operation":"example.read","input_type":"request","output_type":"page"},"output":"version"}],
        "follow_ups":[]})
}

fn decode(artifact: &Artifact, entries: &Value) -> Result<operation_metadata::Catalog> {
    operation_metadata::decode(
        &serde_json::to_vec(&json!({"entries":entries,"error":""}))?,
        &artifact.operations,
        &artifact.schema,
        &artifact.outputs,
    )
}

#[test]
fn metadata_requires_complete_public_handles_and_compatible_field_links() -> Result<()> {
    let artifact = artifact()?;
    let valid = json!([entry("example.read"), entry("example.save")]);
    decode(&artifact, &valid)?;
    for (pointer, value) in [
        ("/0/target/operation", json!("private.missing")),
        ("/0/target/input_type", json!("another_nominal_type")),
        ("/0/target/output_type", json!("missing")),
        ("/0/usage/use_when", json!([])),
        ("/0/usage/effects", json!(["Writes data"])),
        ("/1/usage/effects", json!([])),
        ("/0/title", json!(" ")),
        ("/0/inputs/0/path", json!("missing")),
        ("/0/input_sources/0/input", json!("missing")),
        ("/0/input_sources/0/output", json!("version[]")),
        (
            "/0/input_sources/0/source/operation",
            json!("private.missing"),
        ),
        ("/0/input_sources/0/source/output_type", json!("forged")),
        (
            "/0/follow_ups",
            json!([{"target":{"operation":"private.missing","input_type":"request","output_type":"page"},"when":"Next"}]),
        ),
    ] {
        let mut invalid = valid.clone();
        *invalid.pointer_mut(pointer).unwrap() = value;
        assert!(decode(&artifact, &invalid).is_err(), "{pointer}");
    }
    for entries in [
        json!([]),
        json!([entry("example.read")]),
        json!([entry("example.read"), entry("example.read")]),
    ] {
        assert!(decode(&artifact, &entries).is_err());
    }
    let mut unknown = valid.clone();
    unknown[0]["usage"]["read_only"] = json!(true);
    assert!(decode(&artifact, &unknown).is_err());
    let mut changed = artifact.clone();
    changed.outputs.get_mut("page").unwrap().shape =
        serde_json::from_value(json!({"record":{"version":"string"}}))?;
    assert!(decode(&changed, &valid).is_err());
    Ok(())
}

#[test]
fn adding_removing_or_changing_operations_updates_both_projections_or_fails_admission() -> Result<()>
{
    let mut artifact = artifact()?;
    artifact.operation_metadata = decode(
        &artifact,
        &json!([entry("example.read"), entry("example.save")]),
    )?;
    artifact.api_docs = serde_json::from_value(json!({"example.save":{
        "operation":"example.save","input_type":"request","output_type":"page",
        "summary":"Legacy title","description":"Legacy operation prose.","response_description":"Legacy result meaning.",
        "inputs":[{"path":"version","description":"Legacy field prose."}],"outputs":[],
        "request_example":"","response_example":"","deprecated":false
    }}))?;
    let check = |artifact: &Artifact| -> Result<()> {
        let catalog = operation_catalog::Catalog::from_artifact(artifact)?;
        let spec = catalog.document(
            artifact,
            "Example",
            "test",
            "cookie",
            "http://127.0.0.1:1234",
        );
        assert_eq!(
            spec["paths"].as_object().unwrap().len(),
            catalog.endpoints.len() + 4
        );
        for endpoint in catalog.endpoints.values() {
            let tool = mcp::tool(endpoint);
            let http = &spec["paths"][endpoint.path()][endpoint.method().to_ascii_lowercase()];
            assert_eq!(tool["name"], http["operationId"]);
            assert_eq!(tool["title"], http["summary"]);
            assert_eq!(tool["description"], http["description"]);
            assert_eq!(
                tool["inputSchema"]["properties"]["input"]["properties"]["version"]["description"],
                "The current revision of the example."
            );
            assert_eq!(
                tool["_meta"]["io.day2/operationContract"],
                http["x-day2-operation-contract"]
            );
            let input = http["x-day2-input-schema"].as_str().unwrap();
            assert_eq!(
                &tool["inputSchema"]["properties"]["input"],
                spec.pointer(input.trim_start_matches('#')).unwrap()
            );
            let output = http["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
                .as_str()
                .unwrap();
            assert_eq!(
                &tool["outputSchema"]["properties"]["result"],
                spec.pointer(output.trim_start_matches('#')).unwrap()
            );
            assert_eq!(
                tool["annotations"]["readOnlyHint"],
                endpoint.operation.kind == "query"
            );
            assert_eq!(
                tool["annotations"]["destructiveHint"],
                endpoint.operation.kind == "command"
            );
            assert!(tool["description"].as_str().unwrap().contains("Use when:"));
        }
        assert!(!catalog.endpoints.contains_key("private.missing"));
        Ok(())
    };
    check(&artifact)?;
    let mut op = artifact.operations[1].clone();
    op.name = "example.more".into();
    artifact.operations.push(op);
    assert!(operation_catalog::Catalog::from_artifact(&artifact).is_err());
    artifact.operation_metadata.insert(
        "example.more".into(),
        serde_json::from_value(entry("example.more"))?,
    );
    check(&artifact)?;
    artifact
        .operations
        .retain(|operation| operation.name != "example.more");
    assert!(operation_catalog::Catalog::from_artifact(&artifact).is_err());
    artifact.operation_metadata.remove("example.more");
    artifact
        .schema
        .inputs
        .get_mut("request")
        .unwrap()
        .fields
        .insert("required_flag".into(), day2::schema::Kind::Boolean);
    check(&artifact)?;
    artifact
        .operation_metadata
        .get_mut("example.save")
        .unwrap()
        .usage
        .purpose = "New authoritative meaning".into();
    check(&artifact)?;
    Ok(())
}

#[test]
fn existing_apps_and_non_object_outputs_get_a_derived_server_without_invented_intent() -> Result<()>
{
    let mut artifact = artifact()?;
    artifact.outputs.get_mut("page").unwrap().shape =
        serde_json::from_value(json!({"unsigned":"U64"}))?;
    let catalog = operation_catalog::Catalog::from_artifact(&artifact)?;
    let tool = mcp::tool(&catalog.endpoints["example.read"]);
    assert_eq!(tool["title"], "example.read");
    assert!(
        tool["description"]
            .as_str()
            .unwrap()
            .starts_with("Read-only preparation followed by a local query.")
    );
    assert_eq!(
        tool["outputSchema"]["properties"]["result"]["type"],
        "integer"
    );
    assert_eq!(
        tool["outputSchema"]["properties"]["result"]["maximum"],
        u64::MAX
    );
    assert_eq!(
        tool["inputSchema"]["properties"]["input"]["required"],
        json!(["version"])
    );
    assert!(
        tool["inputSchema"]["properties"]
            .get("idempotency_key")
            .is_none()
    );
    Ok(())
}

#[test]
fn retired_completion_operation_kinds_are_rejected() -> Result<()> {
    let mut artifact = artifact()?;
    artifact.operations.push(day2::artifact::Operation {
        name: "example.complete".into(),
        kind: "completion".into(),
        input_type: "request".into(),
        output_type: String::new(),
    });
    assert!(operation_catalog::Catalog::from_artifact(&artifact).is_err());
    Ok(())
}
