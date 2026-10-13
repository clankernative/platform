//! Admit an authenticated merge-group full receipt for the exact landed commit.
//! This never executes downloaded binaries or turns a PR receipt into queue proof.
use super::{
    BuildCache, BuildIdentity, Identity, Prepared, Receipt, Targets, admit_join, build_identity,
    combine_parts, compiler_targets, identity,
};
use crate::run_with_budget;
use anyhow::{Context, Result, ensure};
use day2::digest;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

const REPOSITORY: &str = "clankernative/platform";
const WORKFLOW: &str = ".github/workflows/ci.yml";
const CANDIDATE: &str = "artifacts/ci-merge-candidate.json";
const DOWNLOADED: &str = "/tmp/day2-merge-receipt";
const REUSED: &str = "artifacts/ci-merge-reuse.json";
const REQUIRED: &[&str] = &[
    "secrets",
    "dependencies",
    "verify",
    "gitea-integration-example",
    "infrastructure (cluster)",
    "infrastructure (app-edge)",
    "infrastructure (security-shell-edge)",
    "infrastructure (security-shell)",
    "infrastructure (day2-app)",
    "infrastructure (qualification-runner)",
];

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    workflow_id: u64,
    run: Value,
    jobs: Value,
    checks: Value,
    artifact: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Joined {
    identity: Identity,
    prepared_digest: String,
    shards: Vec<Receipt>,
    effects: BTreeSet<String>,
    timings_ms: BTreeMap<String, u64>,
    timing_scope: String,
    mac: super::mac::Proof,
}

fn number(value: &Value, key: &str) -> Result<u64> {
    let number = value[key]
        .as_u64()
        .context("positive GitHub identity required")?;
    ensure!(number > 0, "positive GitHub identity required");
    Ok(number)
}

fn api(root: &Path, endpoint: &str) -> Result<Value> {
    // Fixed repository endpoints only; no response-supplied URL or credential output.
    let file = tempfile::NamedTempFile::new()?;
    run_with_budget(
        root,
        Command::new("gh")
            .args(["api", "--hostname", "github.com", "--method", "GET"])
            .arg(format!("repos/{REPOSITORY}/{endpoint}"))
            .env_remove("GH_DEBUG")
            .stdout(Stdio::from(file.reopen()?))
            .stderr(Stdio::null()),
        Duration::from_secs(120),
    )?;
    read_json(&file.path().canonicalize()?)
}

fn read_json(path: &Path) -> Result<Value> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 1024 * 1024 && path.canonicalize()? == path,
        "receipt must be a confined regular JSON file within its byte budget"
    );
    day2::json::decode_evidence(&fs::read(path)?)
}

fn output(name: &str, value: &str) -> Result<()> {
    ensure!(
        ["run", "artifact", "reused"].contains(&name)
            && (value == "true"
                || value == "false"
                || value.bytes().all(|byte| byte.is_ascii_digit())),
        "closed workflow output required"
    );
    let path = PathBuf::from(std::env::var("GITHUB_OUTPUT")?);
    let temporary = PathBuf::from(std::env::var("RUNNER_TEMP")?).canonicalize()?;
    ensure!(
        path.starts_with(temporary)
            && fs::symlink_metadata(&path)?.is_file()
            && path.canonicalize()? == path,
        "runner-owned workflow output required"
    );
    writeln!(
        OpenOptions::new().append(true).open(path)?,
        "{name}={value}"
    )?;
    Ok(())
}

fn hosted_main(root: &Path, snapshot: &str) -> Result<Identity> {
    ensure!(
        std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
            && eligible(
                &std::env::var("GITHUB_REPOSITORY")?,
                &std::env::var("GITHUB_EVENT_NAME")?,
                &std::env::var("GITHUB_REF")?
            ),
        "receipt reuse is limited to this repository's main push"
    );
    let current = identity(root, snapshot)?;
    ensure!(
        std::env::var("GITHUB_SHA").as_deref() == Ok(current.checkout.as_str()),
        "main push must check out its exact SHA"
    );
    Ok(current)
}

fn eligible(repository: &str, event: &str, reference: &str) -> bool {
    repository == REPOSITORY && event == "push" && reference == "refs/heads/main"
}

fn tree(root: &Path) -> Result<String> {
    let result = Command::new("git")
        .args(["rev-parse", "HEAD^{tree}"])
        .current_dir(root)
        .output()?;
    ensure!(result.status.success(), "resolve exact checkout tree");
    Ok(String::from_utf8(result.stdout)?.trim().into())
}

fn complete_page<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    let values = value[key]
        .as_array()
        .context("GitHub result array required")?;
    ensure!(
        value["total_count"].as_u64() == Some(values.len() as u64) && values.len() <= 100,
        "complete bounded GitHub result required"
    );
    Ok(values)
}

fn admit_candidate(candidate: &Candidate, current: &Identity, tree: &str) -> Result<()> {
    let run = &candidate.run;
    let run_id = number(run, "id")?;
    let attempt = number(run, "run_attempt")?;
    let repository_id = number(&run["repository"], "id")?;
    ensure!(
        run["repository"]["full_name"] == REPOSITORY
            && run["head_repository"]["full_name"] == REPOSITORY
            && run["head_repository"]["id"] == run["repository"]["id"]
            && run["path"] == WORKFLOW
            && run["workflow_id"] == candidate.workflow_id
            && run["event"] == "merge_group"
            && run["status"] == "completed"
            && run["conclusion"] == "success"
            && run["head_sha"] == current.checkout
            && run["head_commit"]["id"] == current.checkout
            && run["head_commit"]["tree_id"] == tree
            && run["head_branch"]
                .as_str()
                .is_some_and(|branch| branch.starts_with("gh-readonly-queue/main/")),
        "successful trusted exact-commit merge-group run required"
    );
    let jobs = complete_page(&candidate.jobs, "jobs")?;
    let checks = complete_page(&candidate.checks, "check_runs")?;
    for name in REQUIRED.iter().copied().chain(["verify-mac-compatibility"]) {
        let matching: Vec<_> = jobs.iter().filter(|job| job["name"] == name).collect();
        ensure!(
            matching.len() == 1,
            "exact required job missing or duplicated"
        );
        let job = matching[0];
        let id = number(job, "id")?;
        let url = format!("https://github.com/{REPOSITORY}/actions/runs/{run_id}/job/{id}");
        ensure!(
            job["run_id"] == run_id
                && job["run_attempt"] == attempt
                && job["head_sha"] == current.checkout
                && job["status"] == "completed"
                && job["conclusion"] == "success"
                && job["html_url"] == url,
            "all required jobs must succeed in the latest exact attempt"
        );
        let matching: Vec<_> = checks.iter().filter(|check| check["id"] == id).collect();
        ensure!(
            matching.len() == 1,
            "required job's actual check missing or duplicated"
        );
        let check = matching[0];
        ensure!(
            check["name"] == name
                && check["head_sha"] == current.checkout
                && check["status"] == "completed"
                && check["conclusion"] == "success"
                && check["app"]["id"] == 15368
                && check["details_url"] == url
                && check["check_suite"]["id"] == run["check_suite_id"],
            "all ten app-pinned checks must bind to the actual successful jobs"
        );
    }
    let mac_job = jobs.iter().find(|job|job["name"] == "verify-mac-compatibility").context("native Mac job required")?;
    let labels = mac_job["labels"].as_array().context("actual Mac runner labels required")?;
    ensure!(labels.iter().any(|label|label == "macos-15"),"native Mac runner job required");
    let artifact = &candidate.artifact;
    number(artifact, "id")?;
    ensure!(
        artifact["name"] == format!("day2-verification-receipt-{run_id}-{attempt}")
            && artifact["expired"] == false
            && artifact["size_in_bytes"]
                .as_u64()
                .is_some_and(|bytes| bytes <= 1024 * 1024)
            && artifact["workflow_run"]["id"] == run_id
            && artifact["workflow_run"]["head_sha"] == current.checkout
            && artifact["workflow_run"]["repository_id"] == repository_id
            && artifact["workflow_run"]["head_repository_id"] == repository_id,
        "current-attempt immutable full receipt artifact required"
    );
    Ok(())
}

fn candidate(root: &Path, current: &Identity) -> Result<Candidate> {
    let workflow = api(root, "actions/workflows/ci.yml")?;
    ensure!(
        workflow["path"] == WORKFLOW && workflow["state"] == "active",
        "active reviewed CI workflow required"
    );
    let workflow_id = number(&workflow, "id")?;
    let runs = api(
        root,
        &format!(
            "actions/workflows/{workflow_id}/runs?event=merge_group&head_sha={}&per_page=100",
            current.checkout
        ),
    )?;
    let listed = complete_page(&runs, "workflow_runs")?
        .iter()
        .max_by_key(|run| run["id"].as_u64())
        .context("no exact merge-group receipt")?;
    let id = number(listed, "id")?;
    let run = api(root, &format!("actions/runs/{id}"))?;
    let attempt = number(&run, "run_attempt")?;
    let suite = number(&run, "check_suite_id")?;
    let jobs = api(
        root,
        &format!("actions/runs/{id}/attempts/{attempt}/jobs?per_page=100"),
    )?;
    let checks = api(
        root,
        &format!("check-suites/{suite}/check-runs?filter=all&per_page=100"),
    )?;
    let artifacts = api(root, &format!("actions/runs/{id}/artifacts?per_page=100"))?;
    let name = format!("day2-verification-receipt-{id}-{attempt}");
    let matching: Vec<_> = complete_page(&artifacts, "artifacts")?
        .iter()
        .filter(|artifact| artifact["name"] == name)
        .collect();
    ensure!(
        matching.len() == 1,
        "one exact-attempt receipt artifact required"
    );
    let candidate = Candidate {
        workflow_id,
        run,
        jobs,
        checks,
        artifact: matching[0].clone(),
    };
    admit_candidate(&candidate, current, &tree(root)?)?;
    Ok(candidate)
}

pub(in super::super) fn find(root: &Path, snapshot: &str) -> Result<Value> {
    let result = (|| -> Result<Candidate> {
        let current = hosted_main(root, snapshot)?;
        candidate(root, &current)
    })();
    match result {
        Ok(candidate) => {
            fs::create_dir_all(root.join("artifacts"))?;
            fs::write(root.join(CANDIDATE), serde_json::to_vec_pretty(&candidate)?)?;
            output("run", &number(&candidate.run, "id")?.to_string())?;
            output("artifact", &number(&candidate.artifact, "id")?.to_string())?;
            Ok(json!({"candidate":true}))
        }
        Err(error) => {
            println!(
                "Merge-group proof unavailable; ordinary full verification required: {error:#}"
            );
            Ok(json!({"candidate":false}))
        }
    }
}

fn admit_full(
    candidate: &Candidate,
    current: &Identity,
    compiler: &BuildIdentity,
    targets: &Targets,
    files: &BTreeMap<String, Value>,
    mac_snapshot: &str,
) -> Result<()> {
    ensure!(
        files.len() == 6
            && [
                "verification.json",
                "ci-prepared.json",
                "ci-preparation-inputs.json",
                "ci-preparation-tests.json",
                "ci-verification.json",
                "ci-test-build-cache.json"
            ]
            .iter()
            .all(|name| files.contains_key(*name)),
        "exact complete native receipt files required"
    );
    let prepared: Prepared = serde_json::from_value(files["ci-prepared.json"].clone())?;
    let inputs: Prepared = serde_json::from_value(files["ci-preparation-inputs.json"].clone())?;
    let tests: Prepared = serde_json::from_value(files["ci-preparation-tests.json"].clone())?;
    let joined: Joined = serde_json::from_value(files["ci-verification.json"].clone())?;
    let cache: BuildCache = serde_json::from_value(files["ci-test-build-cache.json"].clone())?;
    let mut expected = serde_json::to_value(current)?;
    expected["run"] = number(&candidate.run, "id")?.to_string().into();
    expected["attempt"] = number(&candidate.run, "run_attempt")?.to_string().into();
    let expected: Identity = serde_json::from_value(expected)?;
    ensure!(
        compiler.snapshot == current.snapshot
            && compiler.workflow == current.workflow
            && compiler.workspace == current.workspace
            && compiler.host == current.host
            && compiler.architecture == current.architecture,
        "compiler proof must bind to current source and host"
    );
    ensure!(
        prepared.identity == expected
            && joined.identity == expected
            && serde_json::to_value(combine_parts(inputs, tests, &expected)?)?
                == serde_json::to_value(&prepared)?,
        "complete current-source queue preparation required"
    );
    ensure!(
        cache.identity == *compiler
            && cache.binaries == prepared.binaries
            && cache.programs == prepared.programs
            && cache.auxiliaries == prepared.auxiliaries,
        "queue compiler/config/profile and output inventory changed"
    );
    let directories: BTreeMap<_, _> = targets.members.values().cloned().collect();
    for (binaries, expected) in [
        (&cache.binaries, &targets.tests),
        (&cache.programs, &targets.programs),
        (&cache.auxiliaries, &targets.auxiliaries),
    ] {
        let mut observed = BTreeSet::new();
        for binary in binaries {
            ensure!(
                directories.get(&binary.package) == Some(&binary.directory)
                    && binary.permissions & 0o111 != 0
                    && binary.permissions & !0o777 == 0
                    && observed.insert((
                        binary.package.clone(),
                        binary.target.clone(),
                        binary.kind.clone()
                    ))
                    && binary
                        .digest
                        .strip_prefix("sha256:")
                        .is_some_and(|hash| hash.len() == 64
                            && hash.bytes().all(|byte| byte.is_ascii_hexdigit())),
                "exact current default target directories and byte identities required"
            );
        }
        ensure!(
            observed == *expected,
            "queue inventory must cover all current default targets and supporting programs"
        );
    }
    ensure!(expected.host == "linux" && expected.architecture == "x86_64","Linux portable full origin required");
    super::mac::admit(&joined.mac,&expected,mac_snapshot,compiler,targets)?;
    let timings = admit_join(&prepared, &joined.shards,Some(&joined.mac))?;
    let effects: BTreeSet<_> = timings.keys().cloned().collect();
    ensure!(
        joined.prepared_digest == digest(&serde_json::to_vec(&prepared)?)
            && joined.effects == effects
            && joined.timings_ms == timings
            && !joined.timing_scope.is_empty(),
        "complete original seven-campaign join required"
    );
    let full = &files["verification.json"];
    ensure!(
        full["status"] == "passed"
            && full["scope"] == "all"
            && full["workflow"] == current.workflow
            && full["input_snapshot"] == current.snapshot
            && full["host"] == current.host
            && full["architecture"] == current.architecture
            && full["timings_ms"]["steps"] == serde_json::to_value(timings)?,
        "complete original full receipt from exact current source required"
    );
    Ok(())
}

pub(in super::super) fn admit(root: &Path, snapshot: &str) -> Result<Value> {
    let current = hosted_main(root, snapshot)?;
    let candidate: Candidate = serde_json::from_value(read_json(&root.join(CANDIDATE))?)?;
    admit_candidate(&candidate, &current, &tree(root)?)?;
    let mut files = BTreeMap::new();
    ensure!(
        fs::symlink_metadata(DOWNLOADED)?.is_dir(),
        "fixed downloaded receipt directory required"
    );
    let downloaded = Path::new(DOWNLOADED).canonicalize()?;
    for name in [
        "verification.json",
        "ci-prepared.json",
        "ci-preparation-inputs.json",
        "ci-preparation-tests.json",
        "ci-verification.json",
        "ci-test-build-cache.json",
    ] {
        files.insert(name.into(), read_json(&downloaded.join(name))?);
    }
    admit_full(
        &candidate,
        &current,
        &build_identity(root, snapshot)?,
        &compiler_targets(root)?,
        &files,
        &super::super::verification_snapshot_for(root,"verify","macos","aarch64")?,
    )?;
    // A newer failed/in-progress attempt invalidates an earlier success. Recheck
    // authenticated metadata after artifact admission, never an older attempt URL.
    let latest = api(
        root,
        &format!("actions/runs/{}", number(&candidate.run, "id")?),
    )?;
    ensure!(
        latest == candidate.run,
        "merge-group run changed during admission"
    );
    let latest_candidate = self::candidate(root,&current)?;
    ensure!(serde_json::to_value(&latest_candidate)? == serde_json::to_value(&candidate)?,
        "latest origin jobs/checks/artifact changed during admission");
    ensure!(
        hosted_main(root, &super::super::verification_snapshot(root, "verify")?)? == current,
        "current source changed during receipt admission"
    );
    fs::write(
        root.join(REUSED),
        serde_json::to_vec_pretty(&json!({
            "kind":"reused-trusted-merge-group-full", "current":current, "tree":tree(root)?,
            "origin":candidate, "original_receipts":files,
            "fresh_runtime_executed":false, "scope":"exact commit only; other nine required jobs execute fresh"
        }))?,
    )?;
    output("reused", "true")?;
    println!(
        "Admitted exact successful merge-group full receipt; runtime was executed in its recorded origin run"
    );
    Ok(json!({"reused":true}))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{sample_identity, sample_part};
    use super::super::{Binary, SHARDS, effects, expected_binaries, program_output};
    use super::*;

    fn metadata(current: &Identity) -> Candidate {
        let jobs: Vec<_> = REQUIRED
            .iter().copied().chain(["verify-mac-compatibility"])
            .enumerate()
            .map(|(index, name)| {
                let id = index + 1;
                json!({"id":id,"name":name,"run_id":123,"run_attempt":1,"head_sha":current.checkout,
                "status":"completed","conclusion":"success","labels":[if name == "verify-mac-compatibility" { "macos-15" } else { "ubuntu-24.04" }],
                "html_url":format!("https://github.com/{REPOSITORY}/actions/runs/123/job/{id}")})
            })
            .collect();
        let checks: Vec<_> = jobs.iter().map(|job| json!({
            "id":job["id"],"name":job["name"],"head_sha":job["head_sha"],"status":"completed",
            "conclusion":"success","app":{"id":15368},"details_url":job["html_url"],"check_suite":{"id":99}
        })).collect();
        Candidate {
            workflow_id: 42,
            run: json!({"id":123,"run_attempt":1,"repository":{"id":77,"full_name":REPOSITORY},
                "head_repository":{"id":77,"full_name":REPOSITORY},"path":WORKFLOW,"workflow_id":42,
                "event":"merge_group","status":"completed","conclusion":"success","head_sha":current.checkout,
                "head_commit":{"id":current.checkout,"tree_id":"tree"},"head_branch":"gh-readonly-queue/main/pr-1-base",
                "check_suite_id":99}),
            jobs: json!({"total_count":jobs.len(),"jobs":jobs}),
            checks: json!({"total_count":checks.len(),"check_runs":checks}),
            artifact: json!({"id":7,"name":"day2-verification-receipt-123-1","expired":false,"size_in_bytes":100,
                "workflow_run":{"id":123,"head_sha":current.checkout,"repository_id":77,"head_repository_id":77}}),
        }
    }

    #[test]
    fn queue_reuse_rejects_prs_foreign_heads_failed_latest_attempts_and_unpinned_checks()
    -> Result<()> {
        let current = sample_identity();
        assert!(eligible(REPOSITORY, "push", "refs/heads/main"));
        for (repo, event, reference) in [
            ("foreign/repo", "push", "refs/heads/main"),
            (REPOSITORY, "pull_request", "refs/heads/main"),
            (REPOSITORY, "merge_group", "refs/heads/main"),
            (REPOSITORY, "workflow_dispatch", "refs/heads/main"),
            (REPOSITORY, "push", "refs/heads/other"),
        ] {
            assert!(!eligible(repo, event, reference));
        }
        admit_candidate(&metadata(&current), &current, "tree")?;
        for (pointer, replacement) in [
            ("/run/head_sha", json!("foreign")),
            ("/run/head_commit/tree_id", json!("foreign")),
            ("/run/event", json!("pull_request")),
            ("/run/status", json!("in_progress")),
            ("/run/conclusion", json!("failure")),
            ("/run/run_attempt", json!(2)),
            ("/run/path", json!("foreign.yml")),
            ("/run/workflow_id", json!(43)),
            ("/run/head_repository/id", json!(88)),
            ("/run/head_branch", json!("main")),
            ("/jobs/jobs/0/conclusion", json!("skipped")),
            ("/jobs/jobs/0/run_attempt", json!(2)),
            ("/jobs/jobs/0/run_id", json!(124)),
            ("/jobs/jobs/0/head_sha", json!("foreign")),
            ("/checks/check_runs/0/app/id", json!(1)),
            ("/checks/check_runs/0/check_suite/id", json!(98)),
            (
                "/checks/check_runs/0/details_url",
                json!("https://foreign/job/1"),
            ),
            ("/artifact/name", json!("day2-verification-receipt-123-2")),
            ("/artifact/expired", json!(true)),
            ("/artifact/size_in_bytes", json!(1024 * 1024 + 1)),
            ("/artifact/workflow_run/head_sha", json!("foreign")),
        ] {
            let mut value = serde_json::to_value(metadata(&current))?;
            *value.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                admit_candidate(&serde_json::from_value(value)?, &current, "tree").is_err(),
                "{pointer}"
            );
        }
        let mut incomplete = metadata(&current);
        incomplete.jobs["jobs"].as_array_mut().unwrap().pop();
        assert!(admit_candidate(&incomplete, &current, "tree").is_err());
        Ok(())
    }

    struct Full {
        candidate: Candidate,
        current: Identity,
        compiler: BuildIdentity,
        targets: Targets,
        files: BTreeMap<String, Value>,
    }

    fn full() -> Result<Full> {
        let mut current = sample_identity();
        current.host = "linux".into(); current.architecture = "x86_64".into();
        let candidate = metadata(&current);
        let mut inputs = sample_part("inputs")?;
        for id in inputs.fixtures.values_mut() {
            *id = format!("sha256:{}", "a".repeat(64));
        }
        inputs.identity = serde_json::from_value(serde_json::to_value(&current)?)?;
        let mut tests = sample_part("tests")?;
        tests.identity = serde_json::from_value(serde_json::to_value(&current)?)?;
        for (_,target,kind) in super::super::auxiliary_targets("linux") {
            tests.auxiliaries.push(Binary { package:"day2-sandbox".into(), target:target.clone(), kind,
                directory:"crates/day2-sandbox".into(), executable:program_output(&target),
                digest:format!("sha256:{}","c".repeat(64)), permissions:0o755 });
        }
        // A supporting program is separate from its test harness and required by
        // the integration-test package; it must never enlarge campaign selections.
        for (target, kind, path) in [
            ("day2", "bin", "target/debug/deps/day2-harness"),
            ("day2_integration", "test", "target/debug/deps/integration"),
        ] {
            tests.binaries.push(Binary {
                package: "day2".into(),
                target: target.into(),
                kind: vec![kind.into()],
                directory: "crates/day2".into(),
                executable: path.into(),
                digest: String::new(),
                permissions: 0o755,
            });
        }
        for (package,target,kind) in [("day2-control","control_integration","test"),("xtask","xtask","bin")] {
            tests.binaries.push(Binary { package:package.into(),target:target.into(),kind:vec![kind.into()],
                directory:format!("crates/{package}").into(),executable:format!("target/debug/deps/{target}").into(),
                digest:String::new(),permissions:0o755 });
        }
        tests.programs.push(Binary {
            package: "day2".into(),
            target: "day2".into(),
            kind: vec!["bin".into()],
            directory: "crates/day2".into(),
            executable: program_output("day2"),
            digest: String::new(),
            permissions: 0o755,
        });
        for binary in tests.binaries.iter_mut().chain(&mut tests.programs) {
            binary.digest = format!("sha256:{}", "b".repeat(64));
        }
        let prepared = combine_parts(
            serde_json::from_value(serde_json::to_value(&inputs)?)?,
            serde_json::from_value(serde_json::to_value(&tests)?)?,
            &current,
        )?;
        let compiler = BuildIdentity {
            snapshot: current.snapshot.clone(),
            workflow: current.workflow.clone(),
            workspace: current.workspace.clone(),
            host: current.host.clone(),
            architecture: current.architecture.clone(),
            rustc: "rust\nhost: x86_64-unknown-linux-gnu".into(),
            cargo: "cargo".into(),
            cc: "cc".into(),
            environment:format!("sha256:{}","d".repeat(64)),
            cargo_configuration: BTreeMap::new(),
            ci_workflow: "ci".into(),
        };
        let cache = BuildCache {
            identity: serde_json::from_value(serde_json::to_value(&compiler)?)?,
            binaries: prepared.binaries.clone(),
            programs: prepared.programs.clone(),
            auxiliaries: prepared.auxiliaries.clone(),
        };
        let mac = super::super::mac::tests::sample(&prepared,&compiler)?;
        let shards: Vec<_> = SHARDS
            .iter().filter(|shard|!["isolated-build","installation-build"].contains(shard))
            .map(|shard| Receipt {
                prepared_digest: digest(&serde_json::to_vec(&prepared).unwrap()),
                shard: (*shard).into(),
                passed: effects(shard),
                timings_ms: effects(shard).into_iter().map(|step| (step, 100)).collect(),
                binaries: expected_binaries(&prepared, shard),
            })
            .collect();
        let timings = admit_join(&prepared, &shards,Some(&mac))?;
        let joined = json!({"identity":current,"prepared_digest":digest(&serde_json::to_vec(&prepared)?),
            "shards":shards,"mac":mac,"effects":timings.keys().collect::<Vec<_>>(),"timings_ms":timings,"timing_scope":"admitted work"});
        let files = [
            ("verification.json",json!({"status":"passed","scope":"all","workflow":current.workflow,
                "input_snapshot":current.snapshot,"host":current.host,"architecture":current.architecture,"timings_ms":{"steps":timings}})),
            ("ci-prepared.json",serde_json::to_value(&prepared)?),("ci-preparation-inputs.json",serde_json::to_value(inputs)?),
            ("ci-preparation-tests.json",serde_json::to_value(tests)?),("ci-verification.json",joined),
            ("ci-test-build-cache.json",serde_json::to_value(cache)?),
        ].into_iter().map(|(name,value)|(name.into(),value)).collect();
        let targets = Targets {
            auxiliaries: super::super::auxiliary_targets("linux"),
            tests: prepared
                .binaries
                .iter()
                .map(|b| (b.package.clone(), b.target.clone(), b.kind.clone()))
                .collect(),
            programs: prepared
                .programs
                .iter()
                .map(|b| (b.package.clone(), b.target.clone(), b.kind.clone()))
                .collect(),
            members: prepared
                .binaries
                .iter().chain(&prepared.auxiliaries)
                .map(|b| (b.package.clone(), (b.package.clone(), b.directory.clone())))
                .collect(),
        };
        current.run = "999".into();
        current.attempt = "2".into();
        Ok(Full {
            candidate,
            current,
            compiler,
            targets,
            files,
        })
    }

    #[test]
    fn queue_reuse_requires_complete_parts_seven_campaigns_current_compiler_and_default_targets()
    -> Result<()> {
        let Full {
            candidate,
            current,
            compiler,
            targets,
            files,
        } = full()?;
        admit_candidate(&candidate, &current, "tree")?;
        admit_full(&candidate, &current, &compiler, &targets, &files,"mac-snapshot")?;
        for (name, pointer, replacement) in [
            ("ci-prepared.json", "/identity/checkout", json!("foreign")),
            ("ci-verification.json","/mac/prepared/identity/source_identity",json!("foreign")),
            ("ci-verification.json","/mac/prepared/identity/attempt",json!("2")),
            ("ci-verification.json","/mac/prepared/identity/host",json!("linux")),
            ("ci-verification.json","/mac/compiler/snapshot",json!("foreign")),
            ("ci-verification.json","/mac/cases/0/status",json!("skipped")),
            ("ci-verification.json","/mac/campaigns/0/prepared_digest",json!("foreign")),
            (
                "ci-preparation-inputs.json",
                "/identity/attempt",
                json!("2"),
            ),
            ("ci-preparation-tests.json", "/programs", json!([])),
            ("ci-verification.json", "/shards/0/binaries", json!([])),
            (
                "ci-verification.json",
                "/shards/0/prepared_digest",
                json!("foreign"),
            ),
            ("ci-verification.json", "/effects", json!([])),
            (
                "ci-test-build-cache.json",
                "/identity/snapshot",
                json!("foreign"),
            ),
            (
                "ci-test-build-cache.json",
                "/identity/ci_workflow",
                json!("foreign"),
            ),
            (
                "ci-test-build-cache.json",
                "/identity/environment",
                json!("foreign"),
            ),
            ("verification.json", "/scope", json!("fast")),
            ("verification.json", "/status", json!("failed")),
            ("verification.json", "/timings_ms/steps", json!({})),
        ] {
            let mut invalid = files.clone();
            *invalid.get_mut(name).unwrap().pointer_mut(pointer).unwrap() = replacement;
            assert!(
                admit_full(&candidate, &current, &compiler, &targets, &invalid,"mac-snapshot").is_err(),
                "{name}{pointer}"
            );
        }
        let mut incomplete = files.clone();
        incomplete.remove("verification.json");
        assert!(admit_full(&candidate, &current, &compiler, &targets, &incomplete,"mac-snapshot").is_err());
        let mut changed = targets;
        changed.tests.insert((
            "day2".into(),
            "new-default-target".into(),
            vec!["test".into()],
        ));
        assert!(admit_full(&candidate, &current, &compiler, &changed, &files,"mac-snapshot").is_err());
        Ok(())
    }
}
