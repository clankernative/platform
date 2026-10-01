use anyhow::{Context, Result, ensure};
use day2::{
    artifact::{Artifact, LoadedArtifact},
    development, protocol,
    store::{Fault, replay},
    worker::Worker,
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[test]
fn native_error_cases_preserve_typed_command_query_inputs_and_singleton_authoring() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let temporary = tempfile::tempdir_in(root.join("artifacts"))?;
    let stage = temporary.path();
    fs::create_dir(stage.join("app"))?;
    day2::sdk::stage(&root.join("sdk"), &stage.join("sdk"))?;
    fs::write(stage.join("sdk/main.roc"), day2::sdk::app_platform())?;
    fs::write(
        stage.join("app/main.roc"),
        r#"app [step] { pf: platform "../sdk/main.roc" }
import pf.Api
import pf.Input
import pf.Output
import pf.Write
import pf.Read
step : Str -> Str
step = |raw| raw
command_input : Input({ reason : Str })
command_input = Input.define("command_input", |raw| Json.parse(raw).map_err(|_| "input"), |value| Json.to_str(value))
query_input : Input({ path : Str })
query_input = Input.define("query_input", |raw| Json.parse(raw).map_err(|_| "input"), |value| Json.to_str(value))
result : Output(Str)
result = Output.define("result", |value| Json.to_str(value))
write : Write({ reason : Str }, Str)
write = Write.define("example.create", command_input, result)
read : Read({ path : Str }, Str)
read = Read.define("example.preview", query_input, result)
single = Api.error({description: "Invalid.", recovery: "Correct it.", verification: |_| Api.failed_command(write, |_snapshot, _seed| Ok({reason: ""}))})
shared = Api.error_cases({description: "Invalid.", recovery: "Correct it.", verification: |_| [
    Api.failed_command(write, |_snapshot, _seed| Ok({reason: ""})),
    Api.failed_query(read, |_snapshot, _seed| Ok({path: "relative"})),
]})
expect match Api.error_metadata("invalid", single) {
    Ok(metadata) => metadata.operation.operation == "example.create" and metadata.additional_operations.is_empty()
    Err(_) => Bool.False
}
expect match Api.error_metadata("invalid", shared) {
    Ok(metadata) => metadata.operation.input_type == "command_input" and metadata.additional_operations.map(|target| target.input_type) == ["query_input"]
    Err(_) => Bool.False
}
expect match (shared.verification)({}) {
    [command, query] => (command.input)("{}", 1) == Ok("{\"reason\":\"\"}") and (query.input)("{}", 1) == Ok("{\"path\":\"relative\"}")
    _ => Bool.False
}
expect Api.error_metadata("invalid", Api.error_cases({description: "Invalid.", recovery: "Correct it.", verification: |_| []})).is_err()
"#,
    )?;
    let output = day2::sandbox::compiler(
        &root,
        stage,
        &root.join("../.toolchains/roc").canonicalize()?,
    )?
    .arg("test")
    .arg(stage.join("app/main.roc"))
    .output()?;
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(
        output.status.success() && diagnostics.contains("All (4) tests passed"),
        "native error cases: {diagnostics}"
    );
    Ok(())
}

fn artifact() -> Result<PathBuf> {
    Ok(std::env::var_os("DAY2_TEST_REPORTS_ARTIFACT")
        .context("run xtask verify-reports")?
        .into())
}

#[test]
fn checked_credential_closure_fences_child_growth_and_provider_paths() -> Result<()> {
    let loaded = LoadedArtifact::load(&artifact()?)?;
    let mut value = serde_json::to_value(loaded.contract())?;
    let operations = &mut value["app_contract"]["operations"];
    operations["reports.submit"]["credential_access"] = json!({"enabled":true,"local_reads":[]});
    operations["reports.analyze"]["credential_access"] = json!({"enabled":true,"local_reads":[]});
    // This fixture exercises one complete child edge without the later provider
    // leg. The real checked app keeps that leg, which must be rejected below.
    operations["reports.analyze"]["execution"]["effects"]
        .as_array_mut()
        .context("analyze effects")?
        .retain(|effect| effect["kind"] != "request");
    value["credential_declarations"] = json!([{
        "registration":"family", "id":"reports_key", "profile":{"kind":"client"},
        "grant":"fixed", "roots":["reports.submit"], "lifetime_seconds":3600,
        "source":{"file":"App.roc","line":1}
    }]);
    let baseline: Artifact = serde_json::from_value(value.clone())?;
    let old = day2::credential_authority::manifest(&baseline)?;
    let old_root = &old[0].roots["reports.submit"];
    assert!(old_root.closure.children.contains_key("reports.analyze"));

    let model = baseline
        .schema
        .models
        .keys()
        .next()
        .context("report model")?
        .clone();
    value["app_contract"]["operations"]["reports.analyze"]["credential_access"] =
        json!({"enabled":true,"local_reads":[model]});
    let expanded: Artifact = serde_json::from_value(value.clone())?;
    let new = day2::credential_authority::manifest(&expanded)?;
    let new_root = &new[0].roots["reports.submit"];
    assert_eq!(old_root.operation_contract, new_root.operation_contract);
    assert!(!new_root.closure.is_within(&old_root.closure));
    assert_ne!(old[0].contract, new[0].contract);

    value["app_contract"]["operations"]["reports.analyze"]["execution"]["effects"]
        .as_array_mut()
        .context("analyze effects")?
        .push(json!({"kind":"request","model":"","fields":[],"command":"reports.notify"}));
    value["app_contract"]["operations"]["reports.notify"]["credential_access"] =
        json!({"enabled":true,"local_reads":[]});
    let unsupported: Artifact = serde_json::from_value(value)?;
    assert!(
        format!(
            "{:#}",
            day2::credential_authority::manifest(&unsupported).unwrap_err()
        )
        .contains("credential provider write requires a selected permission contract")
    );
    Ok(())
}

#[test]
fn native_required_all_rows_builders_preserve_typed_definitions() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let temporary = tempfile::tempdir_in(root.join("artifacts"))?;
    let stage = temporary.path();
    fs::create_dir(stage.join("app"))?;
    day2::sdk::stage(&root.join("sdk"), &stage.join("sdk"))?;
    fs::write(stage.join("sdk/main.roc"), day2::sdk::app_platform())?;
    fs::write(
        stage.join("app/main.roc"),
        r#"app [step] { pf: platform "../sdk/main.roc" }
import pf.Api
import pf.Context
import pf.Handler
import pf.Credential
import pf.Model
import pf.Query
import pf.Tx
step : Str -> Str
step = |raw| raw
rows : Model({ note : Str })
rows = Model.define("rows", "row", |raw| Json.parse(raw).map_err(|_| "row"), |value| Json.to_str(value))
logs : Model({ complete : Bool })
logs = Model.define("logs", "log", |raw| Json.parse(raw).map_err(|_| "log"), |value| Json.to_str(value))
usage = {purpose: "Check complete state.", use_when: [], avoid_when: [], preconditions: [], effects: [], result: "Result."}
command_base = Api.command({
    handler: Handler.local(|_context, input| Tx.succeed({accepted: !input.reason.is_empty()})),
    contract: {
        title: "Create", usage, inputs: {reason: "Reason."}, outputs: {accepted: "Accepted."},
        example: |_| Ok({input: {reason: "example"}, output: {accepted: Bool.True}}),
        input_sources: |_| [], follow_ups: [], deprecated: Bool.False, errors: [],
    },
    execution: Api.current_state([Api.create(rows)]),
    verification: {input: |_snapshot, _seed| Ok({reason: "generated"}), check: |_before, output, _after| Ok(output.accepted)},
})
query_base = Api.query({
    handler: Handler.local(|_context, input| Query.from_try(Ok({count: input.path.count_utf8_bytes()}))),
    contract: {
        title: "Preview", usage, inputs: {path: "Path."}, outputs: {count: "Count."},
        example: |_| Ok({input: {path: "/root"}, output: {count: 5}}),
        input_sources: |_| [], follow_ups: [], deprecated: Bool.False, errors: [],
    },
    verification: {input: |_snapshot, _seed| Ok({path: "/generated"}), check: |_before, output, _after| Ok(output.count == 10)},
})
command = command_base.require_all_rows(rows).require_all_rows(logs)
query = query_base.require_all_rows(logs).require_all_rows(rows)
command_program : Context, { reason : Str } -> Tx({ accepted : Bool })
command_program = command.command_program()
query_program : Context, { path : Str } -> Tx({ count : U64 })
query_program = query.query_program()
expect command_base.required_all_rows().is_empty() and query_base.required_all_rows().is_empty()
expect command.required_all_rows() == ["rows", "logs"] and query.required_all_rows() == ["logs", "rows"]
expect (command.contract().example)({}) == Ok({input: {reason: "example"}, output: {accepted: Bool.True}}) and (command.verification().input)("{}", 1) == Ok({reason: "generated"})
expect (query.contract().example)({}) == Ok({input: {path: "/root"}, output: {count: 5}}) and (query.verification().input)("{}", 1) == Ok({path: "/generated"})
expect (command.verification().check)("{}", {accepted: Bool.True}, "{}") == Ok(Bool.True) and (query.verification().check)("{}", {count: 10}, "{}") == Ok(Bool.True)
expect command.execution().effects.map(|effect| effect.kind) == ["create"] and command.require_all_rows(rows).required_all_rows() == ["rows", "logs", "rows"]
expect !command_base.credential_access().enabled and !query_base.credential_access().enabled
expect command_base.credential_read(rows).credential_read(logs).credential_access().local_reads == ["rows", "logs"]
expect query_base.credential_ready().credential_read(rows).credential_access() == { enabled: Bool.True, local_reads: ["rows"], metadata_reads: [], issues: [], issue_label: "", interactive: Bool.False }
expect query_base.credentials(Credential.metadata_access(Credential.client_family({id: "client", grant: Credential.fixed([]), lifetime_seconds: 10}))).credential_access().metadata_reads == ["client"] and query_base.credentials(Credential.metadata_access(Credential.personal_family({id: "personal", grant: Credential.fixed([]), lifetime_seconds: 10}))).credential_access().metadata_reads == ["personal"]
"#,
    )?;
    let output = day2::sandbox::compiler(
        &root,
        stage,
        &root.join("../.toolchains/roc").canonicalize()?,
    )?
    .arg("test")
    .arg(stage.join("app/main.roc"))
    .output()?;
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(
        output.status.success() && diagnostics.contains("All (10) tests passed"),
        "native read requirements: {diagnostics}"
    );
    Ok(())
}

#[test]
fn text_constraints_agree_in_native_codecs_host_and_shared_schemas() -> Result<()> {
    let artifact = LoadedArtifact::load(&artifact()?)?;
    let contract = artifact
        .contract()
        .app_contract
        .as_ref()
        .context("contract")?;
    let catalog = day2::operation_catalog::Catalog::from_artifact(artifact.contract())?;
    let input = &catalog.endpoints["reports.submit"].input_schema;
    assert_eq!(input["properties"]["title"]["x-day2-max-utf8-bytes"], 200);
    assert_eq!(input["properties"]["text"]["x-day2-max-utf8-bytes"], 8000);
    let executable = artifact.materialize_worker()?;
    let mut worker = Worker::start(&executable)?;
    for (title, valid) in [
        ("a".repeat(200), true),
        ("a".repeat(201), false),
        ("é".repeat(100), true),
        ("é".repeat(101), false),
        ("東京".repeat(33), true),
        ("東京".repeat(34), false),
        ("".into(), false),
        (" \n\t".into(), false),
        ("\u{00a0}\u{3000}".into(), false),
        ("\u{feff}".into(), true),
    ] {
        let request = protocol::Request {
            operation: "reports.submit".into(),
            input: json!({"title":title,"text":"Document"}).to_string(),
            context: protocol::Context {
                authentication: "request".into(),
                caller: Vec::new(),
                authenticated: String::new(),
                delegation_rule: String::new(),
                invocation_id: "domain-probe".into(),
                actor: "developer".into(),
                now: 100,
            },
            observations: vec![],
        };
        let response: protocol::Response =
            serde_json::from_slice(&worker.exchange(&serde_json::to_vec(&request)?)?)?;
        assert_eq!(
            response.error.is_empty(),
            valid,
            "native codec: {title:?}: {}",
            response.error
        );
        let tag = artifact.contract().schema.domains["title"].as_str();
        assert_eq!(
            contract.domains[tag].accepts(&title),
            valid,
            "host rules: {title:?}"
        );
    }
    let same = day2::compatibility::compare(&artifact, &artifact)?;
    assert!(!same.requires_transition && same.changes.is_empty());
    Ok(())
}

#[test]
fn compatibility_ignores_generated_codec_names_but_detects_internal_command_and_domain_changes()
-> Result<()> {
    let previous = LoadedArtifact::load(&artifact()?)?.contract().clone();
    let mut next = previous.clone();
    let old_key = next
        .operations
        .iter()
        .find(|operation| operation.name == "reports.analyze")
        .context("analysis")?
        .input_type
        .clone();
    let encoded = serde_json::to_string(&next)?;
    next = serde_json::from_str(
        &encoded.replace(&serde_json::to_string(&old_key)?, "\"input_reindexed\""),
    )?;
    let unchanged = day2::compatibility::compare_contracts(&previous, &next)?;
    assert!(unchanged.is_empty());

    next.app_contract
        .as_mut()
        .context("contract")?
        .operations
        .get_mut("reports.analyze")
        .context("internal command")?
        .execution
        .effects
        .retain(|effect| effect.kind != "request");
    let changed = day2::compatibility::compare_contracts(&previous, &next)?;
    assert!(
        changed
            .iter()
            .any(|change| change.subject == "internal_commands" && change.requires_transition)
    );

    let mut next = previous.clone();
    let rule = next
        .app_contract
        .as_mut()
        .context("contract")?
        .domains
        .get_mut("Title")
        .context("domain")?;
    rule.description = "Updated meaning".into();
    assert!(
        !day2::compatibility::compare_contracts(&previous, &next)?
            .iter()
            .any(|change| change.requires_transition)
    );
    next.app_contract
        .as_mut()
        .unwrap()
        .domains
        .get_mut("Title")
        .unwrap()
        .maximum_bytes = 199;
    assert!(
        day2::compatibility::compare_contracts(&previous, &next)?
            .iter()
            .any(|change| change.subject == "domains" && change.requires_transition)
    );
    Ok(())
}

#[test]
fn reports_revision_guard_survives_permissive_policy_and_replay() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let runtime = development::create(&artifact()?, &directory.path().join("instance"), None)?;
    let submit = runtime.invoke(
        "reports.submit",
        development::ACTOR,
        "submit",
        &json!({"title":"Report","text":"Original"}),
        100,
        Fault::None,
    )?;
    ensure!(submit.status == "success", "{}", submit.error);
    let input = json!({"report_id":submit.result["id"],"expected_version":1,"text":"Updated"});
    assert_eq!(
        runtime
            .invoke(
                "reports.revise",
                development::ACTOR,
                "first",
                &input,
                101,
                Fault::None
            )?
            .status,
        "success"
    );
    let before = runtime.inspect()?;
    let stale = runtime.invoke(
        "reports.revise",
        development::ACTOR,
        "stale",
        &input,
        102,
        Fault::None,
    )?;
    assert_eq!(stale.error, "conflict");
    assert_eq!(runtime.inspect()?, before);
    assert_eq!(
        runtime.invoke(
            "reports.revise",
            development::ACTOR,
            "stale",
            &input,
            103,
            Fault::None
        )?,
        stale
    );
    replay(runtime.artifact(), &runtime.trace("stale")?)?;
    Ok(())
}

#[test]
fn selected_build_evidence_covers_every_declared_obligation() -> Result<()> {
    let path = artifact()?;
    let artifact = LoadedArtifact::load(&path)?;
    let evidence: Value = serde_json::from_slice(&fs::read(path.join("verification.json"))?)?;
    assert_eq!(evidence["artifact"], artifact.id());
    assert_eq!(evidence["verification_complete"], true);
    assert!(evidence["failure"].is_null());
    let count = evidence["requested_cases_per_generator"]
        .as_u64()
        .context("case count")?;
    assert!(count >= 2);
    let obligations = evidence["obligations"].as_object().context("obligations")?;
    let definition = artifact
        .contract()
        .app_contract
        .as_ref()
        .context("contract")?;
    assert_eq!(
        obligations.len(),
        definition.operations.len()
            + definition
                .errors
                .values()
                .map(|error| error.targets().count())
                .sum::<usize>()
    );
    assert!(obligations.values().all(|value| value == count));
    Ok(())
}

#[test]
fn internal_examples_are_offline_only_and_do_not_expose_public_commands() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let runtime = development::create(&artifact()?, &directory.path().join("instance"), None)?;
    let catalog = development::examples(runtime.artifact())?;
    assert!(
        catalog
            .iter()
            .flat_map(|example| &example.steps)
            .any(|step| step.operation == "reports.sweep")
    );
    assert_eq!(
        runtime
            .accept(
                "reports.sweep",
                development::ACTOR,
                "public",
                &json!({}),
                100
            )
            .unwrap_err()
            .to_string(),
        "unknown_operation"
    );
    let live = day2::store::Runtime::load(runtime.instance_path(), runtime.app())?;
    let mut campaign = development::Campaign::new(live, Some("demo"), 42, 0)?;
    let request = day2::json::decode(br#"{"protocol":1,"action":"dev-examples","input":"{}"}"#)?;
    assert_eq!(
        campaign.effect(request).unwrap_err().to_string(),
        "internal_examples_require_simulated_providers"
    );
    let evidence = development::exercise(&runtime, Some("demo"), 42, 0)?;
    assert!(evidence.failure.is_none());
    assert!(
        evidence
            .traces
            .iter()
            .any(|trace| trace.request.operation == "reports.sweep")
    );
    assert_eq!(
        runtime
            .accept(
                "reports.sweep",
                development::ACTOR,
                "still-private",
                &json!({}),
                101
            )
            .unwrap_err()
            .to_string(),
        "unknown_operation"
    );
    Ok(())
}
