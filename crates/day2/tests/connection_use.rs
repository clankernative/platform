//! Native positives and negatives for the generated semantic requirement API.
use crate::support::compiler;
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Name,
    oauth::{AccountBindingPolicy, ConnectionDeclaration, ConnectionOwner, ConnectionRequirement},
};
use std::{collections::BTreeSet, fs, path::Path, time::Duration};

fn requirement(name: &str, capability: &str, actions: &[&str]) -> ConnectionDeclaration {
    ConnectionDeclaration {
        registration: Name::try_from(name.to_owned()).unwrap(),
        requirement: ConnectionRequirement {
            logical_id: name.into(),
            revision: 1,
            capability: capability.into(),
            actions: actions
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<BTreeSet<_>>(),
            owner: ConnectionOwner::CurrentHuman,
            account_policy: AccountBindingPolicy::MappedHuman,
            usage: "Read provider data.".into(),
        },
    }
}

#[test]
fn native_connection_use_is_nominal_and_private_in_both_profiles() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let temporary = tempfile::tempdir_in(root.join("artifacts"))?;
    let stage = temporary.path().join("stage");
    fs::create_dir_all(stage.join("app"))?;
    day2::sdk::stage(&root.join("sdk"), &stage.join("sdk"))?;
    fs::write(stage.join("sdk/main.roc"), day2::sdk::app_platform())?;
    let connections = vec![
        requirement("availability", "google_calendar_events", &["list_events"]),
        requirement(
            "calendar",
            "google_calendar_events",
            &["list_events", "create_event"],
        ),
        requirement("projects", "gitlab_projects", &["list_projects"]),
    ];
    let path = std::env::var_os("DAY2_TEST_OAUTH_CALENDAR_ARTIFACT")
        .context("build oauth-calendar-canary or run xtask verify")?;
    let artifact = day2::artifact::LoadedArtifact::load(Path::new(&path))?;
    let schema = artifact.contract().schema.clone();
    fs::copy(
        root.join("fixtures/oauth-calendar-canary/storage/Models.roc"),
        stage.join("app/Models.roc"),
    )?;
    let outputs = day2::output_schema::Catalog::new();
    let catalog = day2::registry::Catalog {
        connections: connections
            .iter()
            .map(|entry| {
                (
                    entry.registration.as_str().to_owned(),
                    "current_human".into(),
                )
            })
            .collect(),
        ..Default::default()
    };
    fs::write(stage.join("registry.json"), serde_json::to_vec(&catalog)?)?;
    fs::write(
        stage.join("connections.json"),
        serde_json::to_vec(&connections)?,
    )?;
    fs::write(
        stage.join("app/Connections.roc"),
        day2::connection_codegen::module(&connections, false)?,
    )?;
    let prelude = r#"app [step] { pf: platform "../sdk/main.roc" }
import pf.Observe
import pf.Connection
import pf.GoogleCalendar
import Connections
step : Str -> Str
step = |_| {
    _ = prepare({})
    "checked"
}
window : GoogleCalendar.Window
window = { start: "2026-10-13T00:00:00Z", end: "2026-10-14T00:00:00Z" }
"#;
    let positive = r#"prepare : {} -> Observe(GoogleCalendar.ListOutcome)
prepare = |_| (Connections.calendar.resolve)({}).and_then(|resolution| match resolution {
    Available(connection) => (Connections.calendar.list_events)(connection, window)
    Unavailable(problem) => Observe.value(Unavailable(problem))
})
"#;
    for (name, body, expected) in [
        ("positive", positive.to_owned(), [true, true]),
        ("wrong_requirement", positive.replace("(Connections.calendar.resolve)", "(Connections.availability.resolve)"), [false, false]),
        ("wrong_capability", positive.replace("(Connections.calendar.resolve)", "(Connections.projects.resolve)"), [false, false]),
        ("read_only_write", positive.replace("(Connections.calendar.list_events)", "(Connections.availability.create_event)"), [false, false]),
        ("actor_override", positive.replace("resolve)({})", "resolve)({ actor: \"someone_else\" })"), [false, false]),
        ("forged_use", "prepare : {} -> Observe(GoogleCalendar.ListOutcome)\nprepare = |_| {\n    forged : Connections.Use_calendar\n    forged = { reference: \"forged\" }\n    (Connections.calendar.list_events)(forged, window)\n}\n".into(), [false, false]),
        ("json_forge", "prepare : {} -> Observe(Try(Connections.Use_calendar, _))\nprepare = |_| Observe.value(Json.parse(\"{\\\"reference\\\":\\\"forged\\\"}\"))\n".into(), [false, false]),
        ("json_escape", "prepare : {} -> Observe(Str)\nprepare = |_| (Connections.calendar.resolve)({}).map(|resolution| match resolution {\n    Available(connection) => Json.to_str(connection)\n    Unavailable(_) => \"unavailable\"\n})\n".into(), [false, false]),
        ("secret_getter", positive.replace("(Connections.calendar.list_events)(connection, window)", "Observe.value(Connection.access_token(connection))"), [false, false]),
        ("generic_resolver", "prepare : {} -> Observe(Connection.Resolution(Str))\nprepare = |_| Connection.resolve(\"calendar\")\n".into(), [true, false]),
        ("generic_reader", "prepare : {} -> Observe(GoogleCalendar.ListOutcome)\nprepare = |_| GoogleCalendar.list_events(\"calendar\", \"forged\", window)\n".into(), [true, false]),
        ("generated_constructor", "prepare : {} -> Observe(Connection.Resolution(Connections.Use_calendar))\nprepare = |_| Connections.day2_resolve_calendar({})\n".into(), [true, false]),
        ("renamed_constructor", "prepare : {} -> Observe(Connection.Resolution(Connections.Use_calendar))\nprepare = |_| Connections.admission_day2_resolve_calendar({})\n".into(), [false, true]),
        ("string_constructor", "prepare : {} -> Observe(GoogleCalendar.ListOutcome)\nprepare = |_| (Connections.calendar.list_events)(Connections.day2_wrap_calendar(\"forged\"), window)\n".into(), [true, false]),
        ("renamed_string_constructor", "prepare : {} -> Observe(GoogleCalendar.ListOutcome)\nprepare = |_| (Connections.calendar.list_events)(Connections.admission_day2_wrap_calendar(\"forged\"), window)\n".into(), [false, true]),
    ] {
        fs::write(stage.join("app/main.roc"), format!("{prelude}{body}"))?;
        let admission = temporary.path().join("admission");
        if admission.exists() { fs::remove_dir_all(&admission)?; }
        day2::admission::prepare(&stage, &admission, &schema, &outputs, &Default::default(), None)?;
        // Admission rebuilds the production registry entrypoint. This probe
        // checks the identical authored program against both sealed SDKs.
        fs::write(admission.join("app/main.roc"), format!("{prelude}{body}"))?;
        for (profile, directory) in [&stage, &admission].into_iter().enumerate() {
            let mut command = day2::sandbox::compiler(&root, directory, &root.join("../.toolchains/roc").canonicalize()?)?;
            command.args(["check", "--no-cache"]).arg(directory.join("app/main.roc"));
            let result = compiler::output(&mut command, Duration::from_secs(60))?;
            let diagnostics = format!("{}{}", String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
            ensure!(result.status.success() == expected[profile], "{name} profile {profile}: {diagnostics}");
            if !expected[profile] { ensure!(!diagnostics.to_lowercase().contains("file not found"), "missing fixture dependency: {diagnostics}"); }
        }
    }
    Ok(())
}

#[test]
fn native_reflected_use_cannot_enter_nested_public_codecs() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let temporary = tempfile::tempdir_in(root.join("artifacts"))?;
    let stage = temporary.path();
    fs::create_dir(stage.join("app"))?;
    day2::sdk::stage(&root.join("sdk"), &stage.join("sdk"))?;
    fs::write(
        stage.join("app/Connections.roc"),
        day2::connection_codegen::module(
            &[requirement(
                "calendar",
                "google_calendar_events",
                &["list_events"],
            )],
            false,
        )?,
    )?;
    let run = |source: &str| -> Result<Vec<u8>> {
        fs::write(stage.join("app/use-platform.roc"), source)?;
        let mut command = day2::sandbox::compiler(
            &root,
            stage,
            &root.join("../.toolchains/roc").canonicalize()?,
        )?;
        command
            .arg("glue")
            .arg(root.join("tools/SchemaGlue.roc"))
            .arg(stage)
            .arg(stage.join("app/use-platform.roc"));
        let output = compiler::output(&mut command, Duration::from_secs(60))?;
        ensure!(
            output.status.success(),
            "native reflection: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        fs::read(stage.join("checked-types.json")).context("native Use metadata")
    };
    let platform = r#"platform "use-reflection"
    requires { unused : {} -> {} }
    exposes []
    packages { pf: "../sdk/types.roc" }
    provides { "day2_schema": schema_shape, "day2_inputs": input_shape, "day2_outputs": output_shape }
    targets: { inputs_dir: "targets/", arm64mac: { inputs: ["libhost.a", app] }, arm64glibc: { inputs: [app], output: Archive }, x64glibc: { inputs: [app], output: Archive } }
import Connections
import pf.CollectionPage
Row := { value : Connections.Use_calendar }
Input := { wrapped : List({ value : Connections.Use_calendar }) }
schema_shape : { rows : List(Row) } -> { rows : List(Row) }
schema_shape = |value| value
input_shape : { use : Input } -> { use : Input }
input_shape = |value| value
output_shape : { use : CollectionPage({ value : Connections.Use_calendar }) } -> { use : CollectionPage({ value : Connections.Use_calendar }) }
output_shape = |value| value
"#;
    fs::write(stage.join("sdk/types.roc"), day2::sdk::reflection_package())?;
    let metadata = run(platform)?;
    let output_error = day2::output_schema::from_checked_types(&metadata)
        .err()
        .context("public Use output admitted")?;
    ensure!(
        format!("{output_error:#}").contains("connection Use"),
        "wrong output rejection: {output_error:#}"
    );
    let model_error = day2::schema::Schema::from_checked_types(&metadata)
        .err()
        .context("persistent Use model admitted")?;
    ensure!(
        format!("{model_error:#}").contains("connection Use"),
        "wrong model rejection: {model_error:#}"
    );
    let input_only = platform.replace(
        "Row := { value : Connections.Use_calendar }",
        "Row := { value : Str }",
    );
    let input_metadata = run(&input_only)?;
    let input_error = day2::schema::Schema::from_checked_types(&input_metadata)
        .err()
        .context("public Use input admitted")?;
    ensure!(
        format!("{input_error:#}").contains("connection Use"),
        "wrong input rejection: {input_error:#}"
    );
    Ok(())
}

#[test]
fn native_calendar_preparation_frames_bound_escaped_and_accumulated_results() -> Result<()> {
    use day2::protocol::{Context as InvocationContext, Instruction, Observation, Request};
    let path = std::env::var_os("DAY2_TEST_OAUTH_CALENDAR_ARTIFACT")
        .context("build oauth-calendar-canary or run xtask verify")?;
    let artifact = day2::artifact::LoadedArtifact::load(Path::new(&path))?;
    let events = (0..40)
        .map(|index| {
            serde_json::json!({
                "id":format!("escaped_{index}"),"summary":"\\\"\n\t\u{0}é".repeat(32),
                "start":"2026-10-13T10:00:00Z","end":"2026-10-13T11:00:00Z","all_day":false,
            })
        })
        .collect::<Vec<_>>();
    let result = serde_json::json!({"Listed":events}).to_string();
    ensure!(
        result.len() <= 30 * 1024,
        "test result exceeds the admitted complete-result budget"
    );
    let observation = Observation {
        instruction: Instruction {
            kind: "observe".into(),
            model: day2::connection_codegen::LIST_EVENTS.into(),
            data: serde_json::json!({"registration":"calendar","reference":"cu1_native_reference",
                "window":{"start":"2026-10-13T00:00:00Z","end":"2026-10-14T00:00:00Z"}})
            .to_string(),
            ..Default::default()
        },
        result,
        error: String::new(),
    };
    ensure!(
        serde_json::to_vec(&observation)?.len() <= 65_536,
        "actual observation envelope exceeds its native cap"
    );
    let mut request = Request {
        operation: "unregistered_wire_probe".into(),
        input:
            serde_json::json!({"start":"\\\"\n\t\u{0}é".repeat(2048),"end":"2026-10-14T00:00:00Z"})
                .to_string(),
        context: InvocationContext {
            invocation_id: "native_wire_probe".into(),
            actor: "alice@example.com".into(),
            now: 100,
            authentication: "app".into(),
            caller: (0..16).map(|i| format!("caller_{i}")).collect(),
            authenticated: "app:caller".into(),
            delegation_rule: "verified_human".into(),
        },
        observations: vec![observation.clone(); 8],
    };
    let executable = artifact.materialize_worker()?;
    let mut worker = day2::worker::Worker::start(&executable)?;
    let bounded = serde_json::to_vec(&request)?;
    ensure!(
        bounded.len() < 1_048_576,
        "positive frame must fit the native transport"
    );
    ensure!(
        !worker.exchange(&bounded)?.is_empty(),
        "native worker did not answer the bounded frame"
    );
    request.observations = vec![observation; 32];
    let oversized = serde_json::to_vec(&request)?;
    ensure!(
        oversized.len() >= 1_048_576,
        "accumulated escaped corpus must reach the actual native frame cap"
    );
    let error = worker
        .exchange(&oversized)
        .err()
        .context("oversized accumulated preparation frame admitted")?;
    ensure!(
        format!("{error:#}").contains("invalid worker frame"),
        "wrong native refusal: {error:#}"
    );
    Ok(())
}
