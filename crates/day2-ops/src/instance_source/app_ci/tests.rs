use super::*;
use crate::ci_results::Stored;
use crate::instance_source::tests::{
    COMMIT, Fake, Scenario, artifact, inputs, instance, manifest, ok, status,
};
use crate::instance_source::{Mode, POLL, Session, proof as any_proof};
use day2::sdk_release::Release;
use std::fs;

const CI_PREFIX: &str = "https://git.example.com/api/v1/repos/tools/links";
const DAY2_CI: &str = "https://git.example.com/api/v1/repos/tools/day2-ci";
const BUCKET: &str = "exampleco-tools-links-ci";
const WORKFLOW_SHA: &str = "9999999999999999999999999999999999999999";
const STARTED: &str = "2026-11-25T18:00:00Z";
/// The forge writes its local zone; a record keeps UTC.
const COMPLETED: &str = "2026-11-25T10:20:00-08:00";
const COMPLETED_UTC: &str = "2026-11-25T18:20:00Z";
const CREATED: &str = "2026-11-25T18:15:00.250Z";

fn runs_url() -> String {
    format!(
        "{CI_PREFIX}/actions/workflows/verification.yml/runs?scoped_workflow_source_repo_id=412\
         &event=push&branch=main&head_sha={COMMIT}&limit=50"
    )
}

fn run_url() -> String {
    format!("{CI_PREFIX}/actions/runs/41")
}

/// The forge's record of app CI's run 41, attempt 2, for COMMIT.
fn ci_run(status: &str, conclusion: &str) -> Value {
    json!({"id": 41, "head_sha": COMMIT, "event": "push", "head_branch": "main",
        "path": "verification.yml@refs/heads/main", "is_scoped": true,
        "workflow_repository_id": 412,
        "workflow_repository": {"id": 412, "full_name": "tools/day2-ci", "private": true, "archived": false},
        "workflow_commit_sha": WORKFLOW_SHA, "repository": {"id": 42, "full_name": "tools/links"},
        "run_attempt": 2, "run_number": 9, "status": status, "conclusion": conclusion,
        "started_at": STARTED, "completed_at": COMPLETED})
}

/// The receipt `ci check` wrote for the artifact, on the release's tooling.
fn checked() -> Value {
    let release = Release::decode(&manifest()).unwrap();
    let archive = BlobIdentity::of(&artifact());
    json!({"version": 1, "source_inputs": inputs(), "artifact_id": "cd".repeat(32),
        "sdk_distribution": {"digest": release.distribution.digest, "bytes": release.distribution.bytes},
        "verification": {"version": 1, "seed": 42, "cases": 4},
        "archive": {"digest": archive.digest, "bytes": archive.bytes},
        "examples": 12, "generated": 40, "lanes": ["native", "extension", "javascript"]})
}

fn metadata() -> BTreeMap<String, String> {
    [
        ("run", "41"),
        ("attempt", "2"),
        ("head", COMMIT),
        ("event", "push"),
        ("workflow_commit", WORKFLOW_SHA),
    ]
    .map(|(key, value)| (key.to_owned(), value.to_owned()))
    .into()
}

/// The binding for the app's derived repository, `tools/links`.
fn binding(scenario: &Scenario) -> Value {
    let mut binding = scenario.binding.clone();
    binding["repository"] = json!("tools/links");
    binding["source"]["repository"] = json!("tools/links");
    binding
}

fn object_path(file: &str) -> String {
    let sdk = BlobIdentity::of(&manifest()).digest;
    format!(
        "{}/{}-4/41/2/{file}",
        &sdk["sha256:".len()..],
        &inputs()["sha256:".len()..]
    )
}

fn store(
    fake: &Fake,
    file: &str,
    bytes: Vec<u8>,
    metadata: BTreeMap<String, String>,
    created: &str,
) {
    fake.0.borrow_mut().stored.insert(
        (BUCKET.to_owned(), object_path(file)),
        (
            Stored {
                generation: if file == RECEIPT {
                    "1700000000000002"
                } else {
                    "1700000000000001"
                }
                .into(),
                size: bytes.len() as u64,
                time_created: created.into(),
                metadata,
            },
            bytes,
        ),
    );
}

/// A scenario with forge.oidc: app CI's names in the instance, the derived
/// repository in the binding, and a successful run whose objects are stored.
struct Ci {
    scenario: Scenario,
}

impl Ci {
    fn new() -> Self {
        let mut scenario = Scenario::new();
        scenario.binding = binding(&scenario);
        let fake = &scenario.fake;
        fake.route(
            DAY2_CI,
            vec![ok(json!({"id": 412, "full_name": "tools/day2-ci",
                "owner": {"id": 74, "login": "tools"}}))],
        );
        fake.route(
            &runs_url(),
            vec![ok(
                json!({"total_count": 1, "workflow_runs": [ci_run("completed", "success")]}),
            )],
        );
        fake.route(&run_url(), vec![ok(ci_run("completed", "success"))]);
        store(
            fake,
            RECEIPT,
            checked().to_string().into_bytes(),
            metadata(),
            CREATED,
        );
        store(fake, ARTIFACT, artifact(), metadata(), CREATED);
        Self { scenario }
    }

    fn names() -> AppCi {
        AppCi {
            repository: "tools/day2-ci".into(),
            buckets: vec![
                Bucket {
                    id: "links".into(),
                    bucket: BUCKET.into(),
                },
                Bucket {
                    id: "notes".into(),
                    bucket: "exampleco-tools-notes-ci".into(),
                },
            ],
        }
    }

    fn request(&self) -> Value {
        let mut request = self.scenario.request(Mode::CheckedArtifact);
        request["instance"]["app_ci"] = serde_json::to_value(Self::names()).unwrap();
        request
    }

    fn session(&self) -> Result<Session> {
        self.scenario
            .session_with(Mode::CheckedArtifact, &self.request())
    }

    fn run(&self) -> Result<Value> {
        let mut session = self.session()?;
        let mut last = Value::Null;
        for step in Mode::CheckedArtifact.steps() {
            last = session.step(step)?;
        }
        Ok(last)
    }

    fn failure(&self) -> String {
        let error = format!("{:#}", self.run().unwrap_err());
        assert!(
            !self.scenario.path("ci-artifact.tar.gz").exists(),
            "{error}"
        );
        error
    }
}

fn expected_proof() -> Value {
    json!({
        "version": 2, "repository": "tools/links", "commit": COMMIT, "run": 41, "attempt": 2,
        "started_at": STARTED, "completed_at": COMPLETED_UTC,
        "workflow": {"repository": "tools/day2-ci", "repository_id": 412, "commit": WORKFLOW_SHA},
        "objects": {
            "receipt": {"uri": format!("gs://{BUCKET}/{}", object_path(RECEIPT)),
                "generation": "1700000000000002", "time_created": CREATED},
            "artifact": {"uri": format!("gs://{BUCKET}/{}", object_path(ARTIFACT)),
                "generation": "1700000000000001", "time_created": CREATED},
        },
        "receipt": checked(),
    })
}

#[test]
fn the_newest_scoped_run_s_stored_artifact_is_read_and_written_with_its_provenance() -> Result<()> {
    let ci = Ci::new();
    let receipt = ci.run()?;
    assert_eq!(receipt["proof"], expected_proof());
    assert_eq!(receipt["repository"], "tools/links");
    assert_eq!(receipt["commit"], COMMIT);
    assert_eq!(receipt["source_inputs"], inputs());
    assert_eq!(
        fs::read(ci.scenario.path("ci-artifact.tar.gz"))?,
        artifact()
    );
    // Only the forge's run records: the CI repository, the runs and the run again. Never the app's
    // own workflow, a commit status or a Gitea artifact.
    assert_eq!(
        ci.scenario.fake.calls(),
        [
            (DAY2_CI.to_owned(), true),
            (runs_url(), true),
            (run_url(), true)
        ]
    );
    // The receipt first, then the artifact, each at its exact generation.
    let reads = ci.scenario.fake.0.borrow().reads.clone();
    assert_eq!(
        reads,
        [
            (BUCKET.to_owned(), object_path(RECEIPT), None),
            (
                BUCKET.to_owned(),
                object_path(RECEIPT),
                Some("1700000000000002".to_owned())
            ),
            (BUCKET.to_owned(), object_path(ARTIFACT), None),
            (
                BUCKET.to_owned(),
                object_path(ARTIFACT),
                Some("1700000000000001".to_owned())
            ),
        ]
    );
    let binding = binding(&ci.scenario);
    any_proof(&receipt["proof"], &binding, COMMIT, &inputs())?;
    assert!(ci.scenario.fake.0.borrow().announced.is_empty());
    // The runner may not export the workflow commit; then the metadata omits it.
    let ci = Ci::new();
    let mut without = metadata();
    without.remove("workflow_commit");
    store(
        &ci.scenario.fake,
        RECEIPT,
        checked().to_string().into_bytes(),
        without.clone(),
        CREATED,
    );
    store(&ci.scenario.fake, ARTIFACT, artifact(), without, CREATED);
    assert_eq!(ci.run()?["proof"], expected_proof());
    Ok(())
}

#[test]
fn the_receipt_is_the_shape_the_cli_decodes() -> Result<()> {
    let ci = Ci::new();
    let mut receipt: Receipt = serde_json::from_value(ci.run()?)?;
    receipt.archive.as_mut().unwrap().path = "/work/ci-artifact.tar.gz".into();
    assert_eq!(
        serde_json::to_string_pretty(&receipt)? + "\n",
        include_str!("../../../../../cli/fixtures/source-receipt-app-ci.json")
    );
    Ok(())
}

#[test]
fn only_app_ci_s_scoped_push_run_of_the_exact_commit_counts() {
    let refused = |edit: fn(&mut Value), expected: &str| {
        let ci = Ci::new();
        let mut run = ci_run("completed", "success");
        edit(&mut run);
        ci.scenario
            .fake
            .route(&runs_url(), vec![ok(json!({"workflow_runs": [run]}))]);
        let error = ci.failure();
        assert!(error.contains(expected), "{error}");
    };
    let not_app_ci = "the forge's run is not app CI's scoped verification run of a push to main";
    refused(|run| run["is_scoped"] = json!(false), not_app_ci);
    refused(|run| run["is_scoped"] = json!("true"), not_app_ci);
    refused(|run| run["workflow_repository_id"] = json!(413), not_app_ci);
    refused(
        |run| run["workflow_repository"]["full_name"] = json!("tools/other-ci"),
        not_app_ci,
    );
    refused(
        |run| run["path"] = json!("roc.yml@refs/heads/main"),
        not_app_ci,
    );
    refused(|run| run["event"] = json!("pull_request"), not_app_ci);
    refused(|run| run["head_branch"] = json!("feature"), not_app_ci);
    refused(|run| run["repository"]["id"] = json!(43), not_app_ci);
    refused(|run| run["run_attempt"] = json!(0), not_app_ci);
    refused(
        |run| run["conclusion"] = json!("failure"),
        "app CI did not succeed on main",
    );
    refused(
        |run| run["started_at"] = json!("2026-11-25T18:00:00.5Z"),
        "app CI's run has no exact start and stop",
    );
    // The CI repository must be exactly <org>/day2-ci in the org.
    let ci = Ci::new();
    ci.scenario.fake.route(
        DAY2_CI,
        vec![ok(
            json!({"id": 412, "full_name": "Tools/day2-ci", "owner": {"id": 74, "login": "tools"}}),
        )],
    );
    assert!(
        ci.failure()
            .contains("another repository than tools/day2-ci")
    );
    let ci = Ci::new();
    ci.scenario.fake.route(DAY2_CI, vec![status(404)]);
    assert_eq!(ci.failure(), "forge_repository_missing");
}

#[test]
fn the_newest_run_decides_and_a_run_in_progress_is_waited_for() -> Result<()> {
    // An older failed run of the commit does not matter; the newest does.
    let ci = Ci::new();
    let mut older = ci_run("completed", "failure");
    older["id"] = json!(40);
    let mut other = ci_run("completed", "success");
    other["id"] = json!(50);
    other["head_sha"] = json!("f".repeat(40));
    ci.scenario.fake.route(
        &runs_url(),
        vec![
            ok(json!({"workflow_runs": []})),
            ok(json!({"workflow_runs": [other.clone(), older.clone(), ci_run("in_progress", "")]})),
            ok(json!({"workflow_runs": [other, older, ci_run("completed", "success")]})),
        ],
    );
    assert_eq!(ci.run()?["proof"], expected_proof());
    {
        let world = ci.scenario.fake.0.borrow();
        assert_eq!(world.announced, [WAITING]);
        assert_eq!(world.sleeps, [POLL, POLL]);
    }
    // A run that never finishes, or only another commit's, is retryable once the wait is over.
    let ci = Ci::new();
    let mut other = ci_run("completed", "success");
    other["head_sha"] = json!("f".repeat(40));
    ci.scenario
        .fake
        .route(&runs_url(), vec![ok(json!({"workflow_runs": [other]}))]);
    assert_eq!(ci.failure(), "checked_main_artifact_not_ready");
    let world = ci.scenario.fake.0.borrow();
    assert_eq!(world.now, WAIT);
    assert_eq!(world.announced, [WAITING]);
    Ok(())
}

#[test]
fn a_missing_object_is_waited_for_within_the_same_deadline() {
    for file in [RECEIPT, ARTIFACT] {
        let ci = Ci::new();
        ci.scenario
            .fake
            .0
            .borrow_mut()
            .stored
            .remove(&(BUCKET.to_owned(), object_path(file)));
        assert_eq!(ci.failure(), "checked_main_artifact_not_ready");
        let world = ci.scenario.fake.0.borrow();
        assert_eq!(world.announced, [WAITING]);
        assert_eq!(world.now, WAIT);
    }
}

#[test]
fn every_object_must_be_this_attempt_s_and_the_artifact_its_receipt_s() {
    let refused = |file: &str,
                   bytes: Vec<u8>,
                   metadata: BTreeMap<String, String>,
                   created: &str,
                   expected: &str| {
        let ci = Ci::new();
        store(&ci.scenario.fake, file, bytes, metadata, created);
        let error = ci.failure();
        assert!(error.contains(expected), "{file}: {error}");
    };
    for file in [RECEIPT, ARTIFACT] {
        let bytes = if file == RECEIPT {
            checked().to_string().into_bytes()
        } else {
            artifact()
        };
        // Created before the attempt started, or after it stopped.
        for created in [
            "2026-11-25T17:59:59.999Z",
            "2026-11-25T18:20:01.000Z",
            "2026-11-25T18:15:00+00:00",
        ] {
            refused(
                file,
                bytes.clone(),
                metadata(),
                created,
                "was not created during the run's attempt",
            );
        }
        // Another run, attempt, commit or event; an extra key; another workflow commit.
        for (key, value) in [
            ("run", "40"),
            ("attempt", "1"),
            ("head", "ffffffffffffffffffffffffffffffffffffffff"),
            ("event", "pull_request"),
            (
                "workflow_commit",
                "8888888888888888888888888888888888888888",
            ),
            ("extra", "x"),
        ] {
            let mut changed = metadata();
            changed.insert(key.to_owned(), value.to_owned());
            refused(
                file,
                bytes.clone(),
                changed,
                CREATED,
                "does not carry this run's metadata",
            );
        }
    }
    // The window's last second still counts: the forge keeps whole seconds.
    let ci = Ci::new();
    store(
        &ci.scenario.fake,
        ARTIFACT,
        artifact(),
        metadata(),
        "2026-11-25T18:20:00.999Z",
    );
    assert!(ci.run().is_ok());
    // An artifact of the right size but other bytes.
    let mut other = artifact();
    other[0] ^= 1;
    refused(
        ARTIFACT,
        other,
        metadata(),
        CREATED,
        "is not the archive its receipt names",
    );
    // An artifact of another size than the receipt names.
    refused(
        ARTIFACT,
        b"short".to_vec(),
        metadata(),
        CREATED,
        "is not the size its receipt names",
    );
}

#[test]
fn the_receipt_binds_the_inputs_the_profile_and_the_release_s_tooling() {
    let refused = |edit: fn(&mut Value), expected: &str| {
        let ci = Ci::new();
        let mut receipt = checked();
        edit(&mut receipt);
        store(
            &ci.scenario.fake,
            RECEIPT,
            receipt.to_string().into_bytes(),
            metadata(),
            CREATED,
        );
        let error = ci.failure();
        assert!(error.contains(expected), "{error}");
    };
    let other = "app CI's checked artifact belongs to another source or profile";
    refused(
        |r| r["source_inputs"] = json!(format!("sha256:{}", "00".repeat(32))),
        other,
    );
    refused(
        |r| r["sdk_distribution"]["digest"] = json!(format!("sha256:{}", "00".repeat(32))),
        "another SDK's tooling distribution",
    );
    refused(
        |r| r["lanes"] = json!(["native"]),
        "invalid ci check receipt",
    );
    refused(
        |r| r["verification"]["seed"] = json!(7),
        "invalid ci check receipt",
    );
    refused(|r| r["upload_id"] = json!(9), "invalid app CI receipt");
}

#[test]
fn a_rerun_during_the_download_supersedes_the_artifact() {
    let ci = Ci::new();
    let mut rerun = ci_run("in_progress", "");
    rerun["run_attempt"] = json!(3);
    ci.scenario.fake.route(&run_url(), vec![ok(rerun)]);
    assert!(
        ci.failure()
            .contains("app CI's attempt changed during the artifact download")
    );
    let ci = Ci::new();
    let mut moved = ci_run("completed", "success");
    moved["completed_at"] = json!("2026-11-25T18:21:00Z");
    ci.scenario.fake.route(&run_url(), vec![ok(moved)]);
    assert!(
        ci.failure()
            .contains("app CI's attempt changed during the artifact download")
    );
}

#[test]
fn with_forge_oidc_the_app_s_own_artifacts_are_never_read() {
    // A binding whose repository is not the derived <org>/<app> cannot be app CI's: ci store keys results by it.
    let ci = Ci::new();
    let mut request = ci.request();
    let mut legacy = ci.scenario.binding.clone();
    legacy["repository"] = json!("tools/links-app");
    legacy["source"]["repository"] = json!("tools/links-app");
    fs::write(ci.scenario.path("binding.json"), legacy.to_string()).unwrap();
    request["binding"] = json!(ci.scenario.path("binding.json"));
    let mut session = ci
        .scenario
        .session_with(Mode::CheckedArtifact, &request)
        .unwrap();
    let error = format!("{:#}", session.step("run").unwrap_err());
    assert!(
        error.contains("app CI stores results only for the app's repository tools/links"),
        "{error}"
    );
    // Nothing was read: the fake refuses every request it was not given.
    assert!(ci.scenario.fake.calls().is_empty());
}

#[test]
fn the_names_are_the_derived_ones() {
    let mut names = Ci::names();
    let with = |names: AppCi| {
        let mut instance = instance(&day2::digest(b"sdk"));
        instance.app_ci = Some(names);
        super::super::validate_instance(&instance)
    };
    assert!(with(names.clone()).is_ok());
    names.repository = "tools/app-ci".into();
    assert!(with(names).is_err());
    let mut names = Ci::names();
    names.buckets.reverse();
    assert!(with(names).is_err());
    let mut names = Ci::names();
    names.buckets[0].bucket = "exampleco-tools-links-results".into();
    assert!(with(names).is_err());
    let mut names = Ci::names();
    names.buckets.pop();
    assert!(with(names).is_err());
}

#[test]
fn the_provenance_is_exact_and_bound_to_the_binding_the_commit_and_the_inputs() {
    let binding = binding(&Scenario::new());
    proof(&expected_proof(), &binding, COMMIT, &inputs()).unwrap();
    let refused = |edit: &dyn Fn(&mut Value), commit: &str, inputs: &str| {
        let mut value = expected_proof();
        edit(&mut value);
        assert!(proof(&value, &binding, commit, inputs).is_err(), "{value}");
    };
    let same = |_: &mut Value| {};
    refused(&same, &"f".repeat(40), &inputs());
    refused(&same, COMMIT, &format!("sha256:{}", "00".repeat(32)));
    refused(&|v| v["extra"] = json!(1), COMMIT, &inputs());
    refused(
        &|v| v["repository"] = json!("tools/notes"),
        COMMIT,
        &inputs(),
    );
    refused(
        &|v| v["workflow"]["repository"] = json!("other/day2-ci"),
        COMMIT,
        &inputs(),
    );
    refused(
        &|v| v["workflow"]["commit"] = json!("short"),
        COMMIT,
        &inputs(),
    );
    refused(&|v| v["run"] = json!(0), COMMIT, &inputs());
    refused(
        &|v| v["completed_at"] = json!("2026-11-25T17:00:00Z"),
        COMMIT,
        &inputs(),
    );
    // A time is kept in UTC only, even when it names the same instant.
    refused(&|v| v["completed_at"] = json!(COMPLETED), COMMIT, &inputs());
    refused(
        &|v| v["objects"]["artifact"]["time_created"] = json!("2026-11-25T19:00:00Z"),
        COMMIT,
        &inputs(),
    );
    refused(
        &|v| {
            v["objects"]["artifact"]["uri"] = json!(format!(
                "gs://exampleco-tools-notes-ci/{}",
                object_path(ARTIFACT)
            ))
        },
        COMMIT,
        &inputs(),
    );
    refused(
        &|v| {
            v["objects"]["receipt"]["uri"] = json!(format!(
                "gs://{BUCKET}/{}",
                object_path(RECEIPT).replace("/41/2/", "/41/1/")
            ))
        },
        COMMIT,
        &inputs(),
    );
    refused(
        &|v| v["objects"]["receipt"]["generation"] = json!("0"),
        COMMIT,
        &inputs(),
    );
    refused(
        &|v| v["receipt"]["verification"]["cases"] = json!(6),
        COMMIT,
        &inputs(),
    );
    // A version 1 proof is the earlier shape, checked as before.
    let mut earlier = expected_proof();
    earlier["version"] = json!(1);
    assert!(any_proof(&earlier, &binding, COMMIT, &inputs()).is_err());
}

#[test]
fn creation_times_are_gcs_s() {
    assert_eq!(gcs_seconds("1970-01-01T00:00:01Z"), Some(1));
    assert_eq!(gcs_seconds("1970-01-01T00:00:01.999Z"), Some(1));
    assert_eq!(gcs_seconds("1970-01-01T00:00:01.123456789Z"), Some(1));
    for value in [
        "1970-01-01T00:00:01.Z",
        "1970-01-01T00:00:01.1234567890Z",
        "1970-01-01T00:00:01+00:00",
        "1970-01-01T00:00:01.5",
        "1970-01-01 00:00:01Z",
        "",
    ] {
        assert_eq!(gcs_seconds(value), None, "{value}");
    }
}
