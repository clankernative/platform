use anyhow::{Context, Result, ensure};
use day2::{artifact::LoadedArtifact, connection_declaration as declaration};
use day2_capabilities::oauth::AccountBindingPolicy;
use std::{fs, path::Path, time::Duration};

use crate::support::compiler;

#[test]
fn native_registration_derives_the_admitted_artifact_contract() -> Result<()> {
    let path = std::env::var_os("DAY2_TEST_CONNECTION_DECLARATION_ARTIFACT")
        .context("build connection-declaration-conformance or run xtask verify")?;
    let artifact = LoadedArtifact::load(Path::new(&path))?;
    let declarations = &artifact.contract().connection_declarations;
    assert_eq!(declarations.len(), 2);
    assert_eq!(declarations[0].registration.as_str(), "availability");
    assert_eq!(
        declarations[0].requirement.account_policy,
        AccountBindingPolicy::ExplicitExternalAccount
    );
    assert_eq!(declarations[1].requirement.logical_id, "work_calendar");
    assert_eq!(
        declarations[1].requirement.account_policy,
        AccountBindingPolicy::MappedHuman
    );
    assert_eq!(declarations[1].requirement.actions.len(), 2);
    let mut worker = day2::worker::Worker::start(&artifact.materialize_worker()?)?;
    let raw = worker.exchange(b"connection-contract")?;
    assert_eq!(
        declaration::decode(&raw, artifact.contract())?,
        *declarations
    );
    Ok(())
}

#[test]
fn forged_artifact_intent_is_rejected_against_the_compiled_registration() -> Result<()> {
    let source = std::env::var_os("DAY2_TEST_CONNECTION_DECLARATION_ARTIFACT")
        .context("build connection-declaration-conformance or run xtask verify")?;
    let source = Path::new(&source);
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(source.join("artifact.json"))?)?;
    value["connection_declarations"][0]["requirement"]["usage"] = "Forged approved intent.".into();
    let digest = day2::digest(&serde_json::to_vec(&value)?);
    let temporary = tempfile::tempdir()?;
    let target = temporary
        .path()
        .join(digest.strip_prefix("sha256:").unwrap());
    fs::create_dir(&target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            fs::copy(entry.path(), target.join(entry.file_name()))?;
        }
    }
    fs::write(target.join("artifact.json"), serde_json::to_vec(&value)?)?;
    let error = LoadedArtifact::load(&target)
        .err()
        .context("forged requirement was admitted")?;
    ensure!(
        error
            .to_string()
            .contains("connection declarations differ from compiled App.definition"),
        "failed before compiled intent comparison: {error:#}"
    );
    Ok(())
}

#[test]
fn native_connection_declarations_require_nominal_access_and_account_policy() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let temporary = tempfile::tempdir_in(root.join("artifacts"))?;
    let stage = temporary.path();
    fs::create_dir(stage.join("app"))?;
    day2::sdk::stage(&root.join("sdk"), &stage.join("sdk"))?;
    fs::write(stage.join("sdk/main.roc"), day2::sdk::app_platform())?;
    let base = r#"app [step] { pf: platform "../sdk/main.roc" }
import pf.ConnectionRequirement
import pf.GoogleCalendar
step : Str -> Str
step = |_raw| Json.to_str(requirement.metadata())
requirement = ConnectionRequirement.for_current_human({
    id: "calendar", revision: 1, access: GoogleCalendar.read_events,
    account: ConnectionRequirement.company_account, usage: "Read work events.",
})
"#;
    for (name, source, expected) in [
        ("positive", base.to_owned(), true),
        (
            "raw_access",
            base.replace(
                "GoogleCalendar.read_events",
                "{ capability: \"google_calendar_events\", actions: [\"list_events\"] }",
            ),
            false,
        ),
        (
            "raw_account",
            base.replace("ConnectionRequirement.company_account", "\"mapped_human\""),
            false,
        ),
        (
            "arbitrary_owner",
            base.replace(
                "usage: \"Read work events.\",",
                "usage: \"Read work events.\", subject: \"another\",",
            ),
            false,
        ),
        (
            "provider_scope",
            base.replace(
                "usage: \"Read work events.\",",
                "usage: \"Read work events.\", scope: \"arbitrary\",",
            ),
            false,
        ),
    ] {
        fs::write(stage.join("app/main.roc"), source)?;
        let mut command = day2::sandbox::compiler(
            &root,
            stage,
            &root.join("../.toolchains/roc").canonicalize()?,
        )?;
        command.arg("check").arg(stage.join("app/main.roc"));
        let output = compiler::output(&mut command, Duration::from_secs(60))?;
        let diagnostics = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        ensure!(output.status.success() == expected, "{name}: {diagnostics}");
        if !expected {
            ensure!(
                diagnostics.to_lowercase().contains("type mismatch"),
                "{name} did not fail at its native type boundary: {diagnostics}"
            );
        }
    }
    Ok(())
}
