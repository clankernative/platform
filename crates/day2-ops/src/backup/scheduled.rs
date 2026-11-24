//! Closed broker for the compiled scheduled-backup recipe. Roc chooses the
//! operation order; Rust retains exclusion, exact selections, actual manifests
//! and permanent refusal. Neither a child receipt nor this ordinary lease is
//! native source permission. The existing native-runtime admission refusal in
//! `take_with_lease` remains in force.
use anyhow::{Context, Result, bail, ensure};
use day2::{automation, backup_archive::Manifest, deployment::OperationLease};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::{backup, offsite};

struct Upload {
    bucket: String,
    prefix: String,
}

enum Stage {
    Ready,
    Taken(Manifest),
    Verified { manifest: Manifest, summary: Value },
    Complete { manifest: Manifest, summary: Value },
    Refused,
}

struct Session {
    instance: PathBuf,
    app: String,
    output: PathBuf,
    state: PathBuf,
    state_subpaths: Vec<String>,
    sqlite_paths: Vec<String>,
    upload: Option<Upload>,
    endpoints: offsite::Endpoints,
    lease: OperationLease,
    stage: Stage,
    failure: Option<anyhow::Error>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    instance: String,
    app_name: String,
    output: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Directory {
    directory: String,
}

fn text(path: &Path) -> Result<&str> {
    path.to_str().context("scheduled backup path must be UTF-8")
}

fn decode<T: serde::de::DeserializeOwned>(request: &automation::Request) -> Result<T> {
    let value: Value = request
        .decode()
        .map_err(|_| anyhow::anyhow!("scheduled_backup_request_codec"))?;
    ensure!(value.is_object(), "scheduled_backup_request_object");
    serde_json::from_value(value).map_err(|_| anyhow::anyhow!("scheduled_backup_request_codec"))
}

fn matches_taken(taken: &Manifest, verified: &Manifest) -> Result<()> {
    ensure!(
        serde_json::to_value(taken)? == serde_json::to_value(verified)?,
        "verified backup differs from the complete snapshot taken"
    );
    Ok(())
}

impl Session {
    fn new(
        instance: &Path,
        app: &str,
        output: &Path,
        state_subpaths: &[String],
        sqlite_paths: &[String],
        upload: Option<(&str, &str)>,
    ) -> Result<Self> {
        backup::validate_companion_selection(state_subpaths, sqlite_paths)?;
        let instance = instance.canonicalize()?;
        text(&instance)?;
        text(output)?;
        // Ordinary destination selection happens once, before capture. A future
        // native constructor must use its admitted slot, never this timestamp.
        let upload = upload
            .map(|(bucket, prefix)| -> Result<Upload> {
                offsite::validate_bucket(bucket)?;
                offsite::validate_prefix(prefix)?;
                let prefix = format!("{prefix}/{}", offsite::utc_stamp(SystemTime::now())?);
                offsite::validate_prefix(&prefix)?;
                Ok(Upload {
                    bucket: bucket.to_owned(),
                    prefix,
                })
            })
            .transpose()?;
        let state = instance
            .parent()
            .context("instance directory")?
            .join(".state");
        let lease = OperationLease::for_instance(&instance, app)?;
        Ok(Self {
            instance,
            app: app.to_owned(),
            output: output.to_owned(),
            state,
            state_subpaths: state_subpaths.to_vec(),
            sqlite_paths: sqlite_paths.to_vec(),
            upload,
            endpoints: offsite::Endpoints::google(),
            lease,
            stage: Stage::Ready,
            failure: None,
        })
    }

    fn handle(&mut self, request: automation::Request) -> Result<Value> {
        if self.failure.is_some() || matches!(self.stage, Stage::Refused) {
            bail!("scheduled_backup_refused");
        }
        let old = std::mem::replace(&mut self.stage, Stage::Refused);
        let result = (|| {
            self.lease.check(&self.state, &self.app)?;
            self.perform(old, request)
        })();
        // Preserve the primary result, but evaluate the real postcheck even
        // when the primitive or request validation failed.
        let post = self.lease.check(&self.state, &self.app);
        match (result, post) {
            (Ok((stage, value)), Ok(())) => {
                self.stage = stage;
                Ok(value)
            }
            (Err(error), _) | (Ok(_), Err(error)) => {
                // Retain the actual first error in Rust. The child gets only a
                // fixed refusal, and swallowing it cannot resume this session.
                self.failure = Some(error);
                bail!("scheduled_backup_refused")
            }
        }
    }

    fn perform(&self, old: Stage, request: automation::Request) -> Result<(Stage, Value)> {
        match (old, request.action.as_str()) {
            (Stage::Ready, "backup-snapshot") => {
                let selected: Snapshot = decode(&request)?;
                ensure!(
                    selected.instance == text(&self.instance)?
                        && selected.app_name == self.app
                        && selected.output == text(&self.output)?,
                    "scheduled_backup_selection_changed"
                );
                let taken = backup::take_with_lease(
                    &self.instance,
                    &self.app,
                    &self.output,
                    &self.state_subpaths,
                    &self.sqlite_paths,
                    &self.lease,
                )?;
                Ok((Stage::Taken(taken), json!({"captured":true})))
            }
            (Stage::Taken(taken), "backup-verify") => {
                let selected: Directory = decode(&request)?;
                ensure!(
                    selected.directory == text(&self.output)?,
                    "scheduled_backup_selection_changed"
                );
                let verified = backup::verify(&self.output)?;
                matches_taken(&taken, &verified)?;
                let summary = json!({
                    "backup": self.output.canonicalize()?,
                    "format": verified.format,
                    "app": verified.app,
                    "installation": verified.instance.installation,
                    "environment": verified.instance.environment,
                    "scope": verified.scope,
                    "artifact": verified.artifact,
                    "database": verified.database,
                    "provider_databases": verified.provider_databases,
                    "companion_state": verified.companion_state,
                    "authority": verified.authority,
                    "verified":true,
                });
                let stage = if self.upload.is_some() {
                    Stage::Verified {
                        manifest: verified,
                        summary,
                    }
                } else {
                    Stage::Complete {
                        manifest: verified,
                        summary,
                    }
                };
                Ok((stage, json!({"verified":true})))
            }
            (
                Stage::Verified {
                    manifest,
                    mut summary,
                },
                "backup-upload",
            ) => {
                let selected: Value = decode(&request)?;
                ensure!(selected == json!({}), "scheduled_backup_upload_request");
                let upload = self
                    .upload
                    .as_ref()
                    .context("scheduled_backup_upload_not_selected")?;
                // This existing ordinary uploader is not a native immutable-
                // image handoff proof. Its stronger file binding is a separate
                // required slice before any native accepting initializer.
                summary["upload"] = offsite::upload_gcs(
                    &self.output,
                    &upload.bucket,
                    &upload.prefix,
                    &self.endpoints,
                )?;
                Ok((
                    Stage::Complete { manifest, summary },
                    json!({"uploaded":true}),
                ))
            }
            _ => bail!("scheduled_backup_step_order"),
        }
    }

    fn finish(self, recipe: Result<Value>) -> Result<Value> {
        let result = (|| {
            if let Some(primary) = self.failure {
                return Err(primary);
            }
            let completed = recipe?;
            let Stage::Complete {
                manifest: _manifest,
                summary,
            } = self.stage
            else {
                bail!("scheduled_backup_incomplete");
            };
            ensure!(
                completed == json!({"scheduled_backup":"complete"}),
                "scheduled_backup_workflow_completion"
            );
            Ok(summary)
        })();
        // automation::run has stopped/reaped the concrete child before this
        // consuming finish. No formatting or native operation follows the
        // successful final postcheck, only the owned historical DATA move.
        let post = self.lease.check(&self.state, &self.app);
        match (result, post) {
            (Err(primary), _) => Err(primary),
            (Ok(_), Err(error)) => Err(error),
            (Ok(summary), Ok(())) => Ok(summary),
        }
    }
}

/// Execute the installed compiled recipe with one retained real lease.
/// There is no native accepting initializer or authority from a copied receipt.
pub fn run(
    instance: &Path,
    app: &str,
    output: &Path,
    state_subpaths: &[String],
    sqlite_paths: &[String],
    upload: Option<(&str, &str)>,
) -> Result<Value> {
    run_with_runner(
        Path::new("/usr/local/lib/day2/day2-workflows"),
        instance,
        app,
        output,
        state_subpaths,
        sqlite_paths,
        upload,
    )
}

// Only this module can select a runner. Production always supplies the fixed
// installed pair above; portable tests use the genuinely compiled, checked pair.
fn run_with_runner(
    runner: &Path,
    instance: &Path,
    app: &str,
    output: &Path,
    state_subpaths: &[String],
    sqlite_paths: &[String],
    upload: Option<(&str, &str)>,
) -> Result<Value> {
    let runner = automation::checked_runner(runner)?;
    let mut session = Session::new(instance, app, output, state_subpaths, sqlite_paths, upload)?;
    // These are copied DATA, never the retained lease or native ownership.
    let instance = text(&session.instance)?.to_owned();
    let app = session.app.clone();
    let output = text(&session.output)?.to_owned();
    let mode = if session.upload.is_some() {
        "with-upload"
    } else {
        "local-only"
    };
    let outcome = automation::run(
        &runner,
        &["scheduled-backup", &instance, &app, &output, mode],
        |request| session.handle(request),
    );
    session.finish(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(action: &str, input: Value) -> automation::Request {
        automation::Request {
            protocol: 1,
            action: action.into(),
            input: input.to_string(),
        }
    }

    // Ordinary private negative fixture: a real kernel lock, no source owner,
    // no installed app and no positive native/backup authority.
    fn unprepared(root: &Path) -> Result<Session> {
        let state = root.join(".state");
        std::fs::create_dir(&state)?;
        Ok(Session {
            instance: root.join("missing-instance.json"),
            app: "app".into(),
            output: root.join("must-not-exist"),
            lease: OperationLease::acquire(&state, "app")?,
            state,
            state_subpaths: vec![],
            sqlite_paths: vec![],
            upload: None,
            endpoints: offsite::Endpoints::google(),
            stage: Stage::Ready,
            failure: None,
        })
    }

    fn wiring_is_closed(binary: &str, module: &str) -> bool {
        let Some(binary) = binary
            .split("fn run() -> Result<Value> {")
            .nth(1)
            .and_then(|s| s.split("fn main()").next())
        else {
            return false;
        };
        let Some(entry) = module
            .split("pub fn run(")
            .nth(1)
            .and_then(|s| s.split("// Only this module").next())
        else {
            return false;
        };
        binary.matches("backup::run_scheduled(").count() == 1
            && ![
                "backup::take(",
                "backup::take_with_lease(",
                "backup::take_with_companion_state(",
                "OperationLease::",
                "automation::run(",
                "backup::verify(",
                "offsite::upload_gcs(",
                "automation::runner(",
                "Command::",
            ]
            .iter()
            .any(|call| binary.contains(call))
            && entry.matches("run_with_runner(").count() == 1
            && entry
                .matches("Path::new(\"/usr/local/lib/day2/day2-workflows\")")
                .count()
                == 1
            && !["std::env", "automation::runner(", "Command::"]
                .iter()
                .any(|call| entry.contains(call))
    }

    #[test]
    fn actual_binary_uses_one_broker_and_only_the_fixed_installed_runner() {
        let binary = include_str!("../bin/day2-backup.rs");
        let module = include_str!("scheduled.rs");
        assert!(wiring_is_closed(binary, module));
        assert_eq!(binary.matches("backup::run_scheduled(").count(), 1);
        assert!(!wiring_is_closed(
            &binary.replacen("backup::run_scheduled(", "backup::take(", 1),
            module
        ));
        for extra in [
            "backup::take_with_lease(",
            "backup::take_with_companion_state(",
            "OperationLease::for_instance(",
            "automation::run(",
        ] {
            // Keep the genuine broker call; reject an added parallel sequence.
            let changed = binary.replacen(
                "    backup::run_scheduled(",
                &format!("    {extra}untrusted);\n    backup::run_scheduled("),
                1,
            );
            assert_ne!(changed, binary);
            assert!(!wiring_is_closed(&changed, module));
        }
        let literal = "Path::new(\"/usr/local/lib/day2/day2-workflows\")";
        assert_eq!(module.matches(literal).count(), 1); // one actual production selection
        assert!(!wiring_is_closed(
            binary,
            &module.replacen(literal, "automation::runner()?", 1)
        ));
    }

    #[test]
    fn actual_broker_refuses_changed_source_toolchain_and_executable_before_session_creation()
    -> Result<()> {
        let root = tempfile::tempdir()?;
        let executable = root.path().join("not-an-executable");
        std::fs::write(&executable, b"unexecutable public fixture DATA")?;
        for (sources, toolchain, digest, expected) in [
            (
                "changed".into(),
                automation::toolchain_digest(),
                day2::digest(b"unexecutable public fixture DATA"),
                "Roc workflow sources changed; run xtask workflows",
            ),
            (
                automation::source_digest(),
                "changed".into(),
                day2::digest(b"unexecutable public fixture DATA"),
                "Roc workflow compiler changed; run xtask workflows",
            ),
            (
                automation::source_digest(),
                automation::toolchain_digest(),
                day2::digest(b"different bytes"),
                "Roc workflow executable changed",
            ),
        ] {
            std::fs::write(
                executable.with_extension("json"),
                serde_json::to_vec(&automation::Distribution {
                    sources,
                    toolchain,
                    executable: digest,
                })?,
            )?;
            // The nonexistent source would fail with IO instead if production
            // bypassed pin admission and tried to create a Session first.
            let output = root.path().join("must-not-exist");
            let result = run_with_runner(
                &executable,
                &root.path().join("missing-instance"),
                "app",
                &output,
                &[],
                &[],
                None,
            );
            assert_eq!(result.unwrap_err().to_string(), expected);
            assert!(!output.exists());
            assert!(!root.path().join(".state").exists());
        }
        Ok(())
    }

    #[test]
    fn request_codec_requires_unique_exact_objects_and_original_protocol() -> Result<()> {
        for input in [
            "[]",
            "null",
            "[\"chosen\"]",
            "{\"directory\":\"a\",\"directory\":\"b\"}",
            "{\"directory\":\"a\",\"other\":0}",
        ] {
            assert!(
                decode::<Directory>(&automation::Request {
                    protocol: 1,
                    action: "backup-verify".into(),
                    input: input.into()
                })
                .is_err()
            );
        }
        assert!(
            decode::<Directory>(&automation::Request {
                protocol: 0,
                action: "backup-verify".into(),
                input: "{\"directory\":\"a\"}".into()
            })
            .is_err()
        );
        assert_eq!(
            decode::<Directory>(&request("backup-verify", json!({"directory":"chosen"})))?
                .directory,
            "chosen"
        );
        Ok(())
    }

    #[test]
    fn complete_manifest_comparison_includes_every_historical_field() -> Result<()> {
        // Codec DATA only: not an admitted archive, source owner or stage.
        let value = json!({"format":3,"scope":"example/sandbox/app","artifact":"artifact","database":"db",
            "provider_databases":{},"rollout_artifacts":null,"companion_state":{},"app":"app",
            "authority":{"epoch":"epoch","revision":1},"resources":{"operations":{},"budgets":{}},
            "instance":{"installation":"example","environment":"sandbox","apps":{}}});
        let taken: Manifest = serde_json::from_value(value.clone())?;
        matches_taken(&taken, &serde_json::from_value(value.clone())?)?;
        for (field, changed) in [
            ("format", json!(4)),
            ("scope", json!("other/sandbox/app")),
            ("artifact", json!("changed")),
            ("database", json!("changed")),
            ("provider_databases", json!({"provider":"changed"})),
            ("rollout_artifacts", json!("changed")),
            ("companion_state", json!({"companion":"changed"})),
            ("app", json!("other")),
            ("authority", json!({"epoch":"other","revision":1})),
            (
                "resources",
                json!({"operations":{"reports.list":{}},"budgets":{}}),
            ),
            (
                "instance",
                json!({"installation":"other","environment":"sandbox","apps":{}}),
            ),
        ] {
            let mut changed_value = value.clone();
            changed_value[field] = changed;
            assert!(
                matches_taken(&taken, &serde_json::from_value(changed_value)?).is_err(),
                "unbound manifest field {field}"
            );
        }
        Ok(())
    }

    #[test]
    fn out_of_order_or_changed_selection_is_permanently_refused() -> Result<()> {
        for first in [
            request("backup-verify", json!({"directory":"foreign"})),
            request(
                "backup-snapshot",
                json!({"instance":"foreign","app_name":"app","output":"foreign"}),
            ),
        ] {
            let root = tempfile::tempdir()?;
            let mut session = unprepared(root.path())?;
            assert!(session.handle(first).is_err());
            let primary = session
                .failure
                .as_ref()
                .context("first refusal retained")?
                .to_string();
            assert!(session.handle(request("backup-snapshot",json!({"instance":session.instance,"app_name":"app","output":session.output}))).is_err());
            assert!(!session.output.exists());
            assert_eq!(
                session
                    .finish(Ok(json!({"scheduled_backup":"complete"})))
                    .unwrap_err()
                    .to_string(),
                primary
            );
        }
        Ok(())
    }

    #[test]
    fn real_primitive_failure_survives_child_completion_and_later_errors() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut session = unprepared(root.path())?;
        assert!(
            session
                .handle(request(
                    "backup-snapshot",
                    json!({"instance":session.instance,"app_name":"app","output":session.output})
                ))
                .is_err()
        );
        let original = session
            .failure
            .as_ref()
            .and_then(|e| e.downcast_ref::<std::io::Error>())
            .context("actual missing-source IO")?;
        let address = original as *const std::io::Error as usize;
        assert_eq!(original.kind(), std::io::ErrorKind::NotFound);
        assert!(session.handle(request("backup-upload", json!({}))).is_err());
        let error = session
            .finish(Err(anyhow::anyhow!("later child failure")))
            .unwrap_err();
        let retained = error
            .downcast_ref::<std::io::Error>()
            .context("same primary IO")?;
        assert_eq!(retained as *const std::io::Error as usize, address);
        assert!(!root.path().join("must-not-exist").exists());
        Ok(())
    }

    #[test]
    fn actual_runner_early_complete_and_wrong_recipe_cannot_complete_session() -> Result<()> {
        let runner = automation::runner()?;
        let root = tempfile::tempdir()?;
        let mut session = unprepared(root.path())?;
        let outcome = automation::run(&runner, &["ci-event", "push", "", "false"], |request| {
            session.handle(request)
        });
        // This real runner returns a complete DATA value with no effects. The
        // actual state gate must refuse independently of its completion marker.
        assert!(outcome.is_ok());
        assert_eq!(
            session.finish(outcome).unwrap_err().to_string(),
            "scheduled_backup_incomplete"
        );
        let root = tempfile::tempdir()?;
        let mut session = unprepared(root.path())?;
        let outcome = automation::run(
            &runner,
            &["platform", "restore", "inspect", "foreign"],
            |request| session.handle(request),
        );
        assert!(outcome.is_err());
        assert_eq!(
            session.finish(outcome).unwrap_err().to_string(),
            "scheduled_backup_step_order"
        );
        Ok(())
    }
    // The real compiled recipe shares the exact production broker. This is an
    // ordinary SQLite/recipe/exclusion fixture, not native source permission.
    #[test]
    fn compiled_scheduled_recipe_snapshots_serving_sqlite_with_same_exclusion() -> Result<()> {
        use day2::{development, store::Runtime};
        use std::fs;
        let runner = automation::runner()?;
        let artifact = std::env::var_os("DAY2_TEST_REPORTS_ARTIFACT")
            .map(PathBuf::from)
            .context("run xtask verify or set DAY2_TEST_REPORTS_ARTIFACT")?;
        let scratch = tempfile::tempdir()?;
        let runtime = development::create(&artifact, &scratch.path().join("original"), None)?;
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
        let run = |instance: &Path, app: &str, output: &Path| {
            run_with_runner(&runner, instance, app, output, &[], &[], None)
        };
        // Snapshot refusal precedes output creation, without taking the serving
        // lease or changing business state. This is the scheduled-backup path.
        let operation =
            day2::deployment::OperationLease::for_instance(runtime.instance_path(), "app")?;
        let blocked_path = scratch.path().join("blocked-by-release");
        let blocked = run(runtime.instance_path(), "app", &blocked_path);
        assert!(blocked.is_err());
        assert!(!blocked_path.exists());
        drop(operation);
        let summary = run(runtime.instance_path(), "app", &output)?;
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
        let again = run(runtime.instance_path(), "app", &output);
        assert!(again.is_err());
        assert_eq!(backup::verify(&output)?.database, manifest.database);
        // Refusals exit non-zero, print no summary and leave no directory behind.
        let missing = scratch.path().join("unknown-app");
        let unknown = run(runtime.instance_path(), "unknown", &missing);
        assert!(unknown.is_err());
        assert!(!missing.exists());
        let skipped = scratch.path().join("skipped-upload");
        let mut selected = Session::new(
            runtime.instance_path(),
            "app",
            &skipped,
            &[],
            &[],
            Some(("example-backups", "app")),
        )?;
        // If a regression accidentally requests upload, it cannot contact a
        // metadata/provider endpoint or obtain a credential in this fixture.
        selected.endpoints = offsite::Endpoints {
            metadata_token: "http://127.0.0.1:0/refused".into(),
            upload: "http://127.0.0.1:0/refused".into(),
        };
        let instance = text(&selected.instance)?.to_owned();
        let output = text(&selected.output)?.to_owned();
        let outcome = automation::run(
            &runner,
            &["scheduled-backup", &instance, "app", &output, "local-only"],
            |request| {
                assert!(OperationLease::for_instance(runtime.instance_path(), "app").is_err());
                selected.handle(request)
            },
        );
        assert_eq!(
            outcome.as_ref().ok(),
            Some(&json!({"scheduled_backup":"complete"}))
        );
        assert_eq!(
            selected.finish(outcome).unwrap_err().to_string(),
            "scheduled_backup_incomplete"
        );
        backup::verify(&skipped)?;
        assert_eq!(runtime.inspect()?, before);
        drop(lock);
        Ok(())
    }
}
