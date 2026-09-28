use anyhow::{Context, Result};
use day2::{artifact::LoadedArtifact, development, store::Runtime};
use day2_ops::{backup, projection};
use serde_json::Value;
use std::{fs, path::PathBuf};

fn artifact() -> Result<PathBuf> {
    std::env::var_os("DAY2_TEST_REPORTS_ARTIFACT")
        .map(PathBuf::from)
        .context("run xtask verify or set DAY2_TEST_REPORTS_ARTIFACT")
}

#[test]
fn native_campaign_cannot_receipt_omitted_checks_or_invented_commands() -> Result<()> {
    let scratch = tempfile::tempdir()?;
    let runtime = development::create(&artifact()?, &scratch.path().join("instance"), None)?;
    let before = runtime.inspect()?;
    let mut campaign = development::Campaign::new(runtime.clone(), None, 42, 8)?;
    let request = |action: &str, input: Value| day2::automation::Request {
        protocol: 1,
        action: action.into(),
        input: input.to_string(),
    };
    assert!(
        campaign
            .effect(request("dev-finish", serde_json::json!({})))
            .is_err()
    );
    assert!(
        campaign
            .effect(request(
                "dev-invoke",
                serde_json::json!({"operation":"reports.submit","input":"{}"})
            ))
            .is_err()
    );
    assert!(!campaign.is_complete());
    assert_eq!(runtime.inspect()?, before);
    Ok(())
}

#[test]
fn reports_examples_and_generated_commands_replay_with_independent_statistics() -> Result<()> {
    let artifact_path = artifact()?;
    let artifact = LoadedArtifact::load(&artifact_path)?;
    assert_eq!(development::examples(&artifact)?[0].steps.len(), 3);
    let samples = development::samples(&artifact, u64::MAX, 4)?;
    assert_eq!(
        samples
            .iter()
            .filter(|sample| sample.operation == "reports.submit")
            .map(|sample| sample.seed.as_str())
            .collect::<Vec<_>>(),
        ["18446744073709551615", "0", "1", "2"]
    );
    let scratch = tempfile::tempdir()?;
    let first = development::verify(&artifact_path, &scratch.path().join("first"), 42, 8)?;
    let second = development::verify(&artifact_path, &scratch.path().join("second"), 42, 8)?;
    // Generator inputs and business results are repeatable. Fresh databases
    // have independent identity seeds, so their UUIDs must be valid and distinct.
    let prefix = &artifact.contract().schema.models["reports"]
        .identity
        .as_ref()
        .context("Reports identity")?
        .prefix;
    let without_ids = |snapshot: &Value| -> Result<(Value, std::collections::BTreeSet<String>)> {
        let mut data = snapshot.clone();
        let mut identities = std::collections::BTreeSet::new();
        for row in data["reports"].as_array_mut().context("report rows")? {
            let id = row
                .as_object_mut()
                .context("report row")?
                .remove("id")
                .context("report ID")?;
            let id = id.as_str().context("text report ID")?;
            anyhow::ensure!(
                day2::identity::valid_for(id, prefix),
                "noncanonical report ID"
            );
            anyhow::ensure!(identities.insert(id.to_owned()), "duplicate report ID");
        }
        Ok((data, identities))
    };
    let (first_values, first_ids) = without_ids(&first.snapshot)?;
    let (second_values, second_ids) = without_ids(&second.snapshot)?;
    assert_eq!(first_values, second_values);
    assert!(first_ids.is_disjoint(&second_ids));
    // Eight generated cases for each of seven operations, plus the two
    // public submissions and one offline internal sweep in the demo.
    assert_eq!(
        (first.examples, first.generated, first.traces.len()),
        (1, 56, 59)
    );
    assert!(first.verification_complete);
    assert_eq!(first.obligations.len(), 7);
    assert!(first.obligations.values().all(|count| *count == 8));
    let rows = first.snapshot["reports"]
        .as_array()
        .context("report rows")?;
    assert_eq!(rows.len(), 10);
    for row in rows {
        let data: Value = serde_json::from_str(row["data"].as_str().context("row data")?)?;
        let text = data["text"].as_str().context("report text")?;
        assert_eq!(data["ready"], true);
        assert_eq!(data["bytes"], text.len());
        assert_eq!(
            data["lines"],
            text.bytes().filter(|byte| *byte == b'\n').count() + 1
        );
        assert_eq!(data["owner"], development::ACTOR);
    }
    assert!(development::verify(&artifact_path, &scratch.path().join("first"), 42, 8).is_err());
    assert_eq!(
        Runtime::load(&scratch.path().join("first/instance.json"), "app")?.inspect()?,
        first.snapshot
    );
    let runtime = development::create(&artifact_path, &scratch.path().join("bad-example"), None)?;
    assert!(development::exercise(&runtime, Some("does_not_exist"), 42, 0).is_err());
    let evidence: Value = serde_json::from_slice(&fs::read(
        scratch.path().join("bad-example/development.json"),
    )?)?;
    assert!(evidence["failure"].is_string());
    assert_eq!(evidence["artifact"], artifact.id());
    Ok(())
}

#[test]
fn online_backup_restores_wal_data_into_a_new_instance_and_rejects_tampering() -> Result<()> {
    let scratch = tempfile::tempdir()?;
    let runtime = development::create(&artifact()?, &scratch.path().join("original"), None)?;
    development::exercise(&runtime, Some("demo"), 42, 0)?;
    let before = runtime.inspect()?;
    let mut desired = day2::artifact::Instance::load(runtime.instance_path())?;
    let pending = desired.apps.get_mut("app").context("app binding")?;
    pending.writers.clear();
    pending.authority = None;
    pending.artifact = "not-activated-artifact".into();
    fs::write(runtime.instance_path(), serde_json::to_vec(&desired)?)?;
    let source_db = rusqlite::Connection::open(runtime.db())?;
    source_db.execute(
        "INSERT INTO day2_web_sessions VALUES('backup-session','developer',253402300799)",
        [],
    )?;
    source_db.execute(
        "INSERT OR REPLACE INTO day2_web_secret VALUES(1,?1)",
        [vec![7_u8; 32]],
    )?;
    let snapshot = scratch.path().join("backup");
    let manifest = backup::take(runtime.instance_path(), "app", &snapshot)?;
    assert_eq!(manifest.scope, runtime.scope());
    assert!(
        manifest
            .provider_databases
            .contains_key("carta.synthetic.sqlite")
    );
    assert!(
        manifest
            .provider_databases
            .contains_key("notifications.sqlite")
    );
    let provider_before =
        day2::simulation::Simulation::new(runtime.clone(), [19; 32], 100_000)?.snapshot()?;
    assert!(
        manifest.instance.apps["app"]
            .writers
            .contains(development::ACTOR)
    );
    assert!(manifest.instance.apps["app"].authority.is_some());
    let restored_path = backup::restore(&snapshot, &scratch.path().join("restored"))?;
    let restored = Runtime::load(&restored_path, "app")?;
    assert_eq!(restored.inspect()?, before);
    let provider_after =
        day2::simulation::Simulation::new(restored.clone(), [19; 32], 100_000)?.snapshot()?;
    assert_eq!(provider_before["provider"], provider_after["provider"]);
    assert_eq!(
        provider_before["carta_provider"],
        provider_after["carta_provider"]
    );
    let restored_authority =
        day2::authority_state::current(&rusqlite::Connection::open(restored.db())?)?;
    assert_ne!(restored_authority.stamp.epoch, manifest.authority.epoch);
    assert!(!restored_authority.document.enabled);
    let restored_db = rusqlite::Connection::open(restored.db())?;
    for table in ["day2_web_sessions", "day2_web_secret"] {
        assert_eq!(
            restored_db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                .get::<_, i64>(0))?,
            0
        );
        assert_eq!(
            source_db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                .get::<_, i64>(0))?,
            1
        );
    }
    assert!(restored.authorize_audit(development::ACTOR).is_err());
    assert!(
        restored
            .invoke(
                "reports.list",
                development::ACTOR,
                "restore-must-not-grant",
                &serde_json::json!({"after":"","limit":20}),
                100,
                day2::store::Fault::None,
            )
            .is_err()
    );
    let desired = day2::artifact::Instance::load(&restored_path)?;
    assert!(desired.apps["app"].authority.is_none());
    assert!(desired.apps["app"].writers.is_empty());
    assert_eq!(runtime.inspect()?, before);
    assert!(backup::restore(&snapshot, runtime.instance_path().parent().unwrap()).is_err());
    fs::write(snapshot.join("app.sqlite"), b"tampered")?;
    assert!(backup::restore(&snapshot, &scratch.path().join("bad")).is_err());
    assert!(!scratch.path().join("bad").exists());
    Ok(())
}

/// The runtime image's day2-backup (scheduled GKE backups) runs beside a serving
/// pod: it must not need the serve lock, and must leave a verified bundle that
/// restores to the same domain and journal contents.
#[test]
fn online_backup_cli_snapshots_a_serving_instance_into_a_verified_bundle() -> Result<()> {
    let binary = env!("CARGO_BIN_EXE_day2-backup");
    let scratch = tempfile::tempdir()?;
    let runtime = development::create(&artifact()?, &scratch.path().join("original"), None)?;
    development::exercise(&runtime, Some("demo"), 42, 0)?;
    let before = runtime.inspect()?;
    // What day2-serve holds for as long as it serves.
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(
            runtime
                .db()
                .parent()
                .context("state directory")?
                .join("app.serve.lock"),
        )?;
    lock.try_lock()?;
    let output = scratch.path().join("snapshot");
    let run = |instance: &std::path::Path, app: &str, output: &std::path::Path| {
        std::process::Command::new(binary)
            .arg(instance)
            .arg(app)
            .arg(output)
            .output()
    };
    let result = run(runtime.instance_path(), "app", &output)?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let summary: Value = serde_json::from_slice(&result.stdout)?;
    let manifest = backup::verify(&output)?;
    assert_eq!(summary["verified"], true);
    assert_eq!(
        summary["backup"],
        output.canonicalize()?.display().to_string()
    );
    assert_eq!(summary["app"], "app");
    assert_eq!(summary["scope"], runtime.scope());
    assert_eq!(summary["artifact"], runtime.artifact().id());
    assert_eq!(summary["database"], manifest.database);
    assert_eq!(
        summary["provider_databases"],
        serde_json::to_value(&manifest.provider_databases)?
    );
    assert_eq!(
        summary["authority"],
        serde_json::to_value(&manifest.authority)?
    );
    let restored = backup::restore(&output, &scratch.path().join("restored"))?;
    assert_eq!(Runtime::load(&restored, "app")?.inspect()?, before);
    assert_eq!(runtime.inspect()?, before);
    // An existing directory is never reused or overwritten.
    let again = run(runtime.instance_path(), "app", &output)?;
    assert!(!again.status.success());
    assert_eq!(backup::verify(&output)?.database, manifest.database);
    // Refusals exit non-zero, print no summary and leave no directory behind.
    let missing = scratch.path().join("unknown-app");
    let unknown = run(runtime.instance_path(), "unknown", &missing)?;
    assert!(!unknown.status.success() && unknown.stdout.is_empty());
    assert!(!missing.exists());
    let usage = std::process::Command::new(binary)
        .arg(runtime.instance_path())
        .output()?;
    assert!(!usage.status.success());
    assert!(String::from_utf8_lossy(&usage.stderr).contains("usage: day2-backup"));
    // Upload options are checked before any snapshot is taken.
    for options in [
        &["--upload-gcs", "example-backups"][..],
        &[
            "--upload-gcs",
            "gs://example-backups",
            "--object-prefix",
            "app",
        ],
        &[
            "--upload-gcs",
            "example-backups",
            "--object-prefix",
            "../app",
        ],
        &["--object-prefix", "app", "--upload-gcs", "example-backups"],
    ] {
        let refused = scratch.path().join("refused-upload");
        let result = std::process::Command::new(binary)
            .arg(runtime.instance_path())
            .arg("app")
            .arg(&refused)
            .args(options)
            .output()?;
        assert!(!result.status.success() && result.stdout.is_empty());
        assert!(!refused.exists());
    }
    drop(lock);
    Ok(())
}

#[test]
fn projection_uses_current_instance_contract_and_excludes_private_provider_configuration()
-> Result<()> {
    let scratch = tempfile::tempdir()?;
    let runtime = development::create(&artifact()?, &scratch.path().join("instance"), None)?;
    let projected = projection::instance(runtime.instance_path())?;
    assert!(projected.get("control").is_none());
    assert!(projected["apps"]["app"].get("background").is_none());
    let discovery = projection::artifact(&artifact()?)?;
    assert_eq!(discovery["version"], 1);
    assert!(discovery.get("jobs").is_none());
    assert!(
        discovery["operations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|operation| operation["kind"] != "completion")
    );
    let mut input: Value = serde_json::from_slice(&fs::read(runtime.instance_path())?)?;
    input["apps"]["app"]["background"]["unexpected"] = true.into();
    fs::write(runtime.instance_path(), serde_json::to_vec(&input)?)?;
    assert!(projection::instance(runtime.instance_path()).is_err());
    Ok(())
}
