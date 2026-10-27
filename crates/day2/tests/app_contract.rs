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
    process::Command,
};

#[test]
fn native_error_cases_preserve_typed_command_query_inputs_and_singleton_authoring() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let temporary = crate::support::compiler::stage(&root)?;
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
actors = Api.error_cases({description: "Denied.", recovery: "Use an authorized principal.", verification: |_| [
    Api.failed_command_as(write, Api.verification_principal("command-synthetic"), |_snapshot, _seed| Ok({reason: "denied"})),
    Api.failed_query_as(read, Api.verification_principal("query-synthetic"), |_snapshot, _seed| Ok({path: "/denied"})),
]})
expect match Api.error_metadata("denied", actors) {
    Ok(metadata) => metadata.verification_actors == [{operation: "example.create", actor: "command-synthetic"}, {operation: "example.preview", actor: "query-synthetic"}]
    Err(_) => Bool.False
}
expect match (actors.verification)({}) {
    [command, query] => (command.input)("{}", 1) == Ok("{\"reason\":\"denied\"}") and (query.input)("{}", 1) == Ok("{\"path\":\"/denied\"}")
    _ => Bool.False
}
expect match Api.error_metadata("invalid", shared) {
    Ok(metadata) => metadata.verification_actors.is_empty()
    Err(_) => Bool.False
}
mixed = Api.error_cases({description: "Denied.", recovery: "Correct it.", verification: |_| [
    Api.failed_command(write, |_snapshot, _seed| Ok({reason: ""})),
    Api.failed_query_as(read, Api.verification_principal("query-synthetic"), |_snapshot, _seed| Ok({path: "/denied"})),
]})
expect match Api.error_metadata("denied", mixed) {
    Ok(metadata) => metadata.verification_actors == [{operation: "example.preview", actor: "query-synthetic"}]
    Err(_) => Bool.False
}
expect Api.error_metadata("denied", Api.error({description: "Denied.", recovery: "Correct it.", verification: |_| Api.failed_command_as(write, Api.verification_principal(""), |_snapshot, _seed| Ok({reason: ""}))})).is_err()
expect Api.error_metadata("denied", Api.error({description: "Denied.", recovery: "Correct it.", verification: |_| Api.failed_query_as(read, Api.verification_principal(""), |_snapshot, _seed| Ok({path: ""}))})).is_err()
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
        "native error cases: {diagnostics}"
    );
    Ok(())
}

#[test]
fn admitted_directory_user_path_reads_current_actor_without_hierarchy_or_mutation() -> Result<()> {
    use day2::integrations::simulated;
    const ACTOR: &str = "directory-sdk@example.test";
    const CUSTOMER: &str = "synthetic-customer-1";
    let artifact = PathBuf::from(
        std::env::var_os("DAY2_TEST_CONNECTION_DECLARATION_ARTIFACT").context(
            "build the connection-declaration fixture through the native verification recipe",
        )?,
    );
    let temporary = tempfile::tempdir()?;
    let runtime =
        day2::development::create_for(&artifact, &temporary.path().join("instance"), None, ACTOR)?;
    simulated::update_workspace_directory(runtime.db(), runtime.scope(), |state| {
        assert_eq!(state.world.customer_id, CUSTOMER);
        assert!(state.calls.is_empty());
        state.world.users.clear();
        state.world.users.insert(ACTOR.into(), serde_json::json!({
            "customerId":CUSTOMER,"orgUnitPath":"/Independent/SDK","primaryEmail":"not-a-profile-claim@example.test"
        }));
        // A hidden hierarchy dependency cannot accidentally make this pass.
        state.world.hierarchy = serde_json::json!({"malformed":"no hierarchy is available"});
        Ok(())
    })?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let before = runtime.inspect()?;
    let result = runtime.invoke(
        "connection_declaration.directory_user",
        ACTOR,
        "sdk-user-path",
        &serde_json::json!({}),
        now,
        day2::store::Fault::None,
    )?;
    assert_eq!(result.status, "success", "{}", result.error);
    assert_eq!(
        result.result,
        serde_json::json!({"actor":ACTOR,"customer_id":CUSTOMER,"user_path":"/Independent/SDK","captured_at":now})
    );
    assert_eq!(
        runtime.inspect()?,
        before,
        "the admitted native query remains read-only"
    );
    let calls = simulated::update_workspace_directory(runtime.db(), runtime.scope(), |state| {
        Ok(state.calls.clone())
    })?;
    assert_eq!(calls.len(), 1);
    assert!(calls[0].starts_with(simulated::DIRECTORY_USER_ENDPOINT));
    assert!(calls[0].contains(ACTOR));
    let forged = runtime.invoke(
        "connection_declaration.directory_user",
        ACTOR,
        "sdk-forged-user",
        &serde_json::json!({"actor":"someone-else@example.test"}),
        now + 1,
        day2::store::Fault::None,
    );
    assert!(forged.is_err() || forged.as_ref().unwrap().status != "success");
    assert_eq!(
        simulated::update_workspace_directory(runtime.db(), runtime.scope(), |state| Ok(state
            .calls
            .clone()))?,
        calls
    );
    simulated::update_workspace_directory(runtime.db(), runtime.scope(), |state| {
        state.world.users.insert(
            ACTOR.into(),
            serde_json::json!({"customerId":"wrong-customer","orgUnitPath":"/"}),
        );
        Ok(())
    })?;
    let wrong_customer = runtime.invoke(
        "connection_declaration.directory_user",
        ACTOR,
        "sdk-wrong-customer",
        &serde_json::json!({}),
        now + 2,
        day2::store::Fault::None,
    );
    assert!(wrong_customer.is_err() || wrong_customer.as_ref().unwrap().status != "success");
    assert_eq!(
        runtime.inspect()?,
        before,
        "bad provider facts publish no application state"
    );
    Ok(())
}

#[test]
fn example_step_generated_is_typed_and_has_an_explicit_wire_tag() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let stage = crate::support::compiler::stage(&root)?;
    day2::sdk::stage(&root.join("sdk"), &stage.path().join("sdk"))?;
    fs::write(stage.path().join("sdk/main.roc"), day2::sdk::app_platform())?;
    fs::write(
        stage.path().join("app.roc"),
        r#"app [step] { pf: platform "sdk/main.roc" }
import pf.Example
import pf.Input
import pf.Output
import pf.Write
step : Str -> Str
step = |raw| raw
input : Input({ name : Str })
input = Input.define("input", |raw| Json.parse(raw).map_err(|_| "invalid"), |value| Json.to_str(value))
output : Output(Str)
output = Output.define("output", |value| value)
create : Write({ name : Str }, Str)
create = Write.define("app.create", input, output)
generated = Example.define("later", Ok([Example.Step.generated(create, 0)]))
static = Example.define("first", Ok([Example.Step.command(create, {name: "known"})]))
encoded = Example.encode([generated, static])
expect encoded.contains("\"kind\":\"generated\"") and encoded.contains("\"kind\":\"command\"")
expect encoded.contains("\"operation\":\"app.create\"") and encoded.contains("\"payload\":\"0\"")
"#,
    )?;
    let compiler = root.join("../.toolchains/roc").canonicalize()?;
    let output = day2::sandbox::compiler(&root, stage.path(), &compiler)?
        .arg("test")
        .arg(stage.path().join("app.roc"))
        .output()?;
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(
        output.status.success() && diagnostics.contains("All (2) tests passed"),
        "generated example SDK contract: {diagnostics}"
    );
    Ok(())
}

#[test]
fn native_freetool_executor_sdk_encodes_closed_wire_variants() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let temporary = crate::support::compiler::stage(&root)?;
    let stage = temporary.path();
    day2::sdk::stage(&root.join("sdk"), &stage.join("sdk"))?;
    fs::write(stage.join("sdk/main.roc"), day2::sdk::app_platform())?;
    let source = r##"app [step] { pf: platform "sdk/main.roc" }
import pf.FreetoolExecutor
import pf.Context
import pf.Effects
import pf.Observe
import pf.Tx
step : Str -> Str
step = |raw| raw
run : FreetoolExecutor.Run
run = { resource_id: "resource", configuration_id: "configuration", immutable_version: 2, configuration_digest: "configuration-digest", run_id: "run", arguments_digest: "arguments-digest" }
context = Context.from_wire({ invocation_id: "invocation", actor: "actor", now: 1, authentication: "request", caller: [], authenticated: "", delegation_rule: "" })
http : FreetoolExecutor.Plan
http = Http({ method: "POST", url: "https://example.test/?q=\"quoted\"", headers: [{name: "X-Example", value: "line\\quoted\""}], body: "é\n" })
sql : FreetoolExecutor.Plan
sql = Postgres({ resource_binding_id: "resource\\\"", statement: "SELECT $1, '\"quoted\"'", parameters: [Null, Boolean(Bool.True), Integer(-42), Decimal("1.2300"), Text("line\n\"quoted\"\\"), Bytes([0, 255]), Date("2026-10-21"), Timestamp("2026-10-21T12:00:00Z")] })
expect FreetoolExecutor.encode_sql_value(Null) == "{\"type\":\"null\"}"
expect FreetoolExecutor.encode_sql_value(Boolean(Bool.True)) == "{\"type\":\"boolean\",\"value\":true}"
expect FreetoolExecutor.encode_sql_value(Integer(-42)) == "{\"type\":\"integer\",\"value\":-42}"
expect FreetoolExecutor.encode_sql_value(Decimal("1.2300")) == "{\"type\":\"decimal\",\"value\":\"1.2300\"}"
expect FreetoolExecutor.encode_sql_value(Text("line\n\"quoted\"\\")) == "{\"type\":\"text\",\"value\":\"line\\n\\\"quoted\\\"\\\\\"}"
expect FreetoolExecutor.encode_sql_value(Bytes([0, 255])) == "{\"type\":\"bytes\",\"value\":[0,255]}"
expect FreetoolExecutor.encode_sql_value(Date("2026-10-21")) == "{\"type\":\"date\",\"value\":\"2026-10-21\"}"
expect FreetoolExecutor.encode_sql_value(Timestamp("2026-10-21T12:00:00Z")) == "{\"type\":\"timestamp\",\"value\":\"2026-10-21T12:00:00Z\"}"
expect FreetoolExecutor.encode_plan(sql) == EXPECTED_SQL
request = |next| {
    program = FreetoolExecutor.bind(context).program().and_then(next)
    match Tx.evaluate(program, []) {
        Pending(binding) => match Tx.evaluate(program, [{instruction: binding.instruction, result: "{\"token\":\"fixture-handle\"}", error: ""}]) {
            Pending(action) => Ok(action.instruction)
            _ => Err("expected executor action")
        }
        _ => Err("expected resource binding")
    }
}
expect match request(|executor| FreetoolExecutor.register(executor, run, http).program()) {
    Ok(instruction) => {
        parsed : Try({handle : Str, run : FreetoolExecutor.Run, plan : {kind : Str, method : Str, url : Str, headers : List(List(Str)), body : List(U8)}}, _)
        parsed = Json.parse(instruction.data)
        match parsed {
            Ok(value) => instruction.kind == "external" and instruction.model == "freetool.register.v1" and value.handle == "fixture-handle" and value.run == run and value.plan.kind == "http" and value.plan.body == "é\n".to_utf8() and value.plan.url == "https://example.test/?q=\"quoted\"" and value.plan.headers == [["X-Example", "line\\quoted\""]]
            Err(_) => Bool.False
        }
    }
    Err(_) => Bool.False
}
expect match request(|executor| FreetoolExecutor.execute(executor, run).program()) {
    Ok(instruction) => {
        parsed : Try({handle : Str, run : FreetoolExecutor.Run}, _)
        parsed = Json.parse(instruction.data)
        instruction.kind == "external" and instruction.model == "freetool.execute.v1" and parsed == Ok({handle: "fixture-handle", run})
    }
    Err(_) => Bool.False
}
expect match request(|executor| FreetoolExecutor.status(executor, run).program()) {
    Ok(instruction) => instruction.kind == "observe" and instruction.model == "freetool.status.v1"
    Err(_) => Bool.False
}
expect match request(|executor| FreetoolExecutor.result_page(executor, run, 10, 20).program()) {
    Ok(instruction) => {
        parsed : Try({handle : Str, run : FreetoolExecutor.Run, offset : U64, limit : U32}, _)
        parsed = Json.parse(instruction.data)
        instruction.kind == "observe" and instruction.model == "freetool.result_page.v1" and parsed == Ok({handle: "fixture-handle", run, offset: 10, limit: 20})
    }
    Err(_) => Bool.False
}
"##;
    let expected_sql = serde_json::to_string(&json!({
        "kind": "postgres", "resource_binding_id": "resource\\\"", "statement": "SELECT $1, '\"quoted\"'",
        "parameters": [
            {"type": "null"}, {"type": "boolean", "value": true}, {"type": "integer", "value": -42},
            {"type": "decimal", "value": "1.2300"}, {"type": "text", "value": "line\n\"quoted\"\\"},
            {"type": "bytes", "value": [0, 255]}, {"type": "date", "value": "2026-10-21"},
            {"type": "timestamp", "value": "2026-10-21T12:00:00Z"}
        ]
    }))?;
    // Preserve the wire's field order while using serde to escape every value.
    let expected: Value = serde_json::from_str(&expected_sql)?;
    let expected_sql = format!(
        "{{\"kind\":\"postgres\",\"resource_binding_id\":{},\"statement\":{},\"parameters\":{}}}",
        expected["resource_binding_id"], expected["statement"], expected["parameters"]
    );
    fs::write(
        stage.join("app.roc"),
        source.replace("EXPECTED_SQL", &serde_json::to_string(&expected_sql)?),
    )?;
    let output = crate::support::compiler::output(
        day2::sandbox::compiler(
            &root,
            stage,
            &root.join("../.toolchains/roc").canonicalize()?,
        )?
        .args(["test", "--no-cache"])
        .arg(stage.join("app.roc")),
        std::time::Duration::from_secs(60),
    )?;
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(
        output.status.success() && diagnostics.contains("All (13) tests passed"),
        "Freetool SDK wire contracts: {diagnostics}"
    );
    Ok(())
}

#[test]
fn native_workspace_directory_pages_decode_through_public_sdk() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let temporary = crate::support::compiler::stage(&root)?;
    let stage = temporary.path();
    fs::create_dir(stage.join("app"))?;
    day2::sdk::stage(&root.join("sdk"), &stage.join("sdk"))?;
    fs::write(stage.join("sdk/main.roc"), day2::sdk::app_platform())?;
    let units = day2::workspace_directory::parse_org_unit_response(br#"{"organizationUnits":[{"orgUnitId":"root","name":"Root","orgUnitPath":"/"},{"orgUnitId":"eng","name":"Engineering","orgUnitPath":"/Engineering","parentOrgUnitId":"root","parentOrgUnitPath":"/"}]}"#)?;
    let page = serde_json::to_string(&day2::workspace_directory::page(&units, 0)?)?;
    let empty = serde_json::to_string(&day2::workspace_directory::page(&units, 2)?)?;
    struct NativeFixturePort(Vec<day2::workspace_directory::OrgUnit>);
    impl day2::workspace_directory::DirectoryReadPort for NativeFixturePort {
        fn user_org_unit_path(&mut self, _actor: &str) -> Result<String> {
            Ok("/Engineering".into())
        }
        fn list_org_units(&mut self) -> Result<day2::workspace_directory::ProviderPage> {
            Ok(day2::workspace_directory::ProviderPage {
                units: self.0.clone(),
                response_bytes: 256,
                hierarchy_captured_at: 100,
            })
        }
    }
    let input = day2::workspace_directory::CaptureInput {
        customer_id: "customer-1".into(),
        connection_id: "directory-connection/1".into(),
        actor: "alice@example.test".into(),
        captured_at: 200,
    };
    let membership = day2::workspace_directory::collect_complete(
        input.clone(),
        &mut NativeFixturePort(units.clone()),
    )?;
    let hierarchy =
        day2::workspace_directory::collect_hierarchy(input, &mut NativeFixturePort(units))?;
    let membership_json = serde_json::to_string(membership.metadata())?;
    let hierarchy_json = serde_json::to_string(hierarchy.metadata())?;
    let source = r#"app [step] { pf: platform "../sdk/main.roc" }
import pf.WorkspaceDirectory
import pf.Resource
import pf.Observe
import pf.Tx
step : Str -> Str
step = |raw| raw
read_page = |raw, offset| {
    program = Resource.decode("{\"token\":\"fixture-handle\"}")
        .and_then(|resource| WorkspaceDirectory.page_with(resource, "fixture-capture", offset))
        .program()
    match Tx.evaluate(program, []) {
        Pending(request) => Tx.evaluate(program, [{instruction: request.instruction, result: raw, error: ""}])
        other => other
    }
}
read_membership = |raw, resource_json| {
    program = Resource.decode(resource_json)
        .and_then(WorkspaceDirectory.capture_with)
        .program()
    match Tx.evaluate(program, []) {
        Pending(request) => Tx.evaluate(program, [{instruction: request.instruction, result: raw, error: ""}])
        other => other
    }
}
read_hierarchy = |raw, resource_json| {
    program = Resource.decode(resource_json)
        .and_then(WorkspaceDirectory.capture_hierarchy_with)
        .program()
    match Tx.evaluate(program, []) {
        Pending(request) => Tx.evaluate(program, [{instruction: request.instruction, result: raw, error: ""}])
        other => other
    }
}
requested_hierarchy_action = |resource_json| {
    program = Resource.decode(resource_json)
        .and_then(WorkspaceDirectory.capture_hierarchy_with)
        .program()
    match Tx.evaluate(program, []) {
        Pending(request) => request.instruction.model == HIERARCHY_CAPABILITY
        _ => Bool.False
    }
}
expect requested_hierarchy_action("{\"token\":\"fixture-handle\"}")
expect match read_page(PAGE_JSON, 0) {
    Done(result) => result.consumed == 1 and result.value.done and result.value.next == 2
        and result.value.items.len() == 2
        and result.value.items.any(|unit| unit.id == "root" and unit.parent_id == None and unit.parent_path == None)
        and result.value.items.any(|unit| unit.id == "eng" and unit.parent_id == Some("root") and unit.parent_path == Some("/"))
    _ => Bool.False
}
expect match read_page(EMPTY_JSON, 2) {
    Done(result) => result.consumed == 1 and result.value.done and result.value.next == 2 and result.value.items.is_empty()
    _ => Bool.False
}
expect match read_membership(MEMBERSHIP_JSON, "{\"token\":\"fixture-handle\"}") {
    Done(result) => result.consumed == 1 and result.value.user_path == "/Engineering"
        and result.value.source_captured_at == 100 and result.value.expires_at == 1000
    _ => Bool.False
}
expect match read_hierarchy(HIERARCHY_JSON, "{\"token\":\"fixture-handle\"}") {
    Done(result) => result.consumed == 1 and result.value.customer_id == "customer-1"
        and result.value.actor == "alice@example.test" and result.value.source_captured_at == 100
        and result.value.expires_at == 1000
    _ => Bool.False
}
"#
        .replace("PAGE_JSON", &serde_json::to_string(&page)?)
        .replace("EMPTY_JSON", &serde_json::to_string(&empty)?)
        .replace("MEMBERSHIP_JSON", &serde_json::to_string(&membership_json)?)
        .replace("HIERARCHY_JSON", &serde_json::to_string(&hierarchy_json)?)
        .replace(
            "HIERARCHY_CAPABILITY",
            &serde_json::to_string(&day2_capabilities::registry::Action::WorkspaceDirectoryHierarchy.capability())?,
        );
    fs::write(stage.join("app/main.roc"), source)?;
    let output = crate::support::compiler::output(
        day2::sandbox::compiler(
            &root,
            stage,
            &root.join("../.toolchains/roc").canonicalize()?,
        )?
        .arg("test")
        .arg(stage.join("app/main.roc")),
        std::time::Duration::from_secs(60),
    )?;
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(
        output.status.success() && diagnostics.contains("All (5) tests passed"),
        "native Directory contracts ({}): {diagnostics}",
        output.status
    );
    Ok(())
}

#[test]
fn admitted_failure_principals_are_atomic_replayable_and_simulation_only() -> Result<()> {
    let artifact_path = PathBuf::from(
        std::env::var_os("DAY2_TEST_VERIFICATION_ACTORS_ARTIFACT")
            .context("build fixtures/verification-actor-conformance or run xtask verify")?,
    );
    let loaded = LoadedArtifact::load(&artifact_path)?;
    let definition = loaded
        .contract()
        .app_contract
        .as_ref()
        .context("app contract")?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    // Retain both successful and failing histories under unique directories.
    let directory = tempfile::Builder::new()
        .prefix("verification-actors-")
        .tempdir_in(root.join("artifacts"))?
        .keep();
    let runtime = development::create(&artifact_path, &directory.join("instance"), None)?;
    let evidence = development::exercise(&runtime, None, 42, 2)?;
    assert!(evidence.failure.is_none());
    assert!(evidence.verification_complete);
    assert_eq!(evidence.generated, 4);
    assert_eq!(evidence.error_traces.len(), 4);
    // exercise uses the runtime clock. Error cases continue that clock after
    // every success step, strictly increasing across all failure targets.
    let latest_success = evidence
        .traces
        .iter()
        .map(|trace| trace.request.context.now)
        .max()
        .context("success traces")?;
    let error_times: Vec<_> = evidence
        .error_traces
        .iter()
        .map(|trace| trace.request.context.now)
        .collect();
    assert!(error_times[0] > latest_success);
    assert!(error_times.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(evidence.obligations.len(), 4);
    assert!(evidence.obligations.values().all(|count| *count == 2));
    let after = runtime.inspect()?;
    let expected = [
        (
            "verifiers.create_note",
            "command-denied-synthetic",
            "app:verifiers.create_denied",
        ),
        (
            "verifiers.count_notes",
            "query-denied-synthetic",
            "app:verifiers.count_denied",
        ),
    ];
    for (operation, actor, code) in expected {
        let failure = definition.errors.get(code).context("declared failure")?;
        assert_eq!(failure.verification_actor(&failure.operation), Some(actor));
        let traces: Vec<_> = evidence
            .error_traces
            .iter()
            .filter(|trace| trace.request.operation == operation)
            .collect();
        assert_eq!(traces.len(), 2);
        for (index, trace) in traces.into_iter().enumerate() {
            assert_eq!(trace.request.context.actor, actor);
            assert_eq!(trace.artifact, loaded.id());
            assert_eq!(trace.outcome.status, "failure");
            assert_eq!(trace.outcome.error, code);
            assert!(
                trace
                    .request
                    .observations
                    .iter()
                    .all(|observation| observation.instruction.kind != "external")
            );
            replay(&loaded, trace)?;
            let id = &trace.request.context.invocation_id;
            runtime.accept(
                operation,
                actor,
                id,
                &serde_json::from_str(&trace.request.input)?,
                trace.request.context.now,
            )?;
            assert_eq!(runtime.execute(id, Fault::None)?, trace.outcome);
            assert_eq!(runtime.inspect()?, after);
            let saved = directory.join(format!("{operation}-{index}.json"));
            let bytes = serde_json::to_vec_pretty(trace)?;
            fs::write(&saved, &bytes)?;
            eprintln!(
                "Replay: build-out/bin/day2 replay {} {}",
                artifact_path.display(),
                saved.display()
            );
            let replayed = Command::new(env!("CARGO_BIN_EXE_day2"))
                .arg("replay")
                .arg(&artifact_path)
                .arg(&saved)
                .output()?;
            ensure!(
                replayed.status.success(),
                "saved failure replay: {}",
                String::from_utf8_lossy(&replayed.stderr)
            );
            assert_eq!(fs::read(&saved)?, bytes);
            let mut changed_actor = trace.clone();
            changed_actor.request.context.actor = development::ACTOR.into();
            assert!(replay(&loaded, &changed_actor).is_err());
            let mut changed_artifact = trace.clone();
            changed_artifact.artifact = format!("sha256:{}", "0".repeat(64));
            assert!(replay(&loaded, &changed_artifact).is_err());
        }
    }
    for (operation, actor, input) in [
        (
            "verifiers.create_note",
            "query-denied-synthetic",
            json!({"text":"cross-target"}),
        ),
        (
            "verifiers.count_notes",
            "command-denied-synthetic",
            json!({}),
        ),
    ] {
        assert_eq!(
            runtime
                .accept(operation, actor, "wrong-target", &input, 100)
                .unwrap_err()
                .to_string(),
            "forbidden"
        );
        assert_eq!(runtime.inspect()?, after);
    }
    let mut narrowed = development::local_policy(&loaded)?;
    narrowed
        .operations
        .get_mut("verifiers.create_note")
        .context("command policy")?
        .actors
        .remove("command-denied-synthetic");
    assert_eq!(
        narrowed.admins,
        std::collections::BTreeSet::from([development::ACTOR.into()])
    );
    let narrowed_runtime =
        development::create(&artifact_path, &directory.join("narrowed"), Some(narrowed))?;
    let empty = narrowed_runtime.inspect()?;
    assert_eq!(
        narrowed_runtime
            .accept(
                "verifiers.create_note",
                "command-denied-synthetic",
                "narrowed",
                &json!({"text":"denied"}),
                100
            )
            .unwrap_err()
            .to_string(),
        "forbidden"
    );
    assert_eq!(narrowed_runtime.inspect()?, empty);
    let live = day2::store::Runtime::load(runtime.instance_path(), runtime.app())?;
    for (operation, actor, input) in [
        (
            "verifiers.create_note",
            "command-denied-synthetic",
            json!({"text":"denied"}),
        ),
        ("verifiers.count_notes", "query-denied-synthetic", json!({})),
    ] {
        assert_eq!(
            live.accept(operation, actor, "nonsimulated", &input, 100)
                .unwrap_err()
                .to_string(),
            "forbidden"
        );
        assert_eq!(live.inspect()?, after);
    }
    live.accept(
        "verifiers.create_note",
        development::ACTOR,
        "live-allowed",
        &json!({"text":"allowed"}),
        100,
    )?;
    assert_eq!(live.execute("live-allowed", Fault::None)?.status, "success");
    live.accept(
        "verifiers.count_notes",
        development::ACTOR,
        "live-read",
        &json!({}),
        100,
    )?;
    assert_eq!(
        live.execute("live-read", Fault::None)?.result,
        json!({"count":3})
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
    let temporary = crate::support::compiler::stage(&root)?;
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
expect command_base.observations().is_empty() and query_base.observations().is_empty()
expect command_base.observes("workspace_directory.capture.v1").observations() == ["workspace_directory.capture.v1"]
expect query_base.observes("workspace_directory.hierarchy.v1").observes("workspace_directory.page.v1").observations() == ["workspace_directory.hierarchy.v1", "workspace_directory.page.v1"]
expect command.required_all_rows() == ["rows", "logs"] and query.required_all_rows() == ["logs", "rows"]
expect (command.contract().example)({}) == Ok({input: {reason: "example"}, output: {accepted: Bool.True}}) and (command.verification().input)("{}", 1) == Ok({reason: "generated"})
expect (query.contract().example)({}) == Ok({input: {path: "/root"}, output: {count: 5}}) and (query.verification().input)("{}", 1) == Ok({path: "/generated"})
expect (command.verification().check)("{}", {accepted: Bool.True}, "{}") == Ok(Bool.True) and (query.verification().check)("{}", {count: 10}, "{}") == Ok(Bool.True)
expect command.execution().effects.map(|effect| effect.kind) == ["create"] and command.require_all_rows(rows).required_all_rows() == ["rows", "logs", "rows"]
expect !command_base.credential_access().enabled and !query_base.credential_access().enabled
expect command_base.credential_read(rows).credential_read(logs).credential_access().local_reads == ["rows", "logs"]
expect query_base.credential_ready().credential_read(rows).credential_access() == { enabled: Bool.True, local_reads: ["rows"], metadata_reads: [], issues: [], rotations: [], revocations: [], issue_label: "", management_lineage: "", rotation_head: "", rotation_revision: "", interactive: Bool.False }
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
        output.status.success() && diagnostics.contains("All (13) tests passed"),
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
    let mut campaign =
        development::Campaign::new(live, Some("demo"), 42, 0, development::CampaignTime::Local)?;
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
