//! The checked main artifact from app CI (docs/INSTANCE.md, "Source" and "App
//! CI"). With `forge.oidc`, every app's artifact comes from its results bucket:
//! the one the required org workflow in `<org>/day2-ci` stored for a push to
//! main, never an artifact the app repository's own workflow uploaded.
//!
//! Custody is the forge's run record, not a commit status (any writer on the
//! app repository can post one): the newest scoped run of `<org>/day2-ci`'s
//! `verification.yml` for the exact commit, its current attempt terminal and
//! successful. Both objects of that attempt must carry the run as metadata and
//! must have been created inside the attempt's start-to-stop window, and the
//! receipt binds the source inputs, the verification profile and the SDK's
//! tooling distribution. Without `forge.oidc` none of this runs.
//!
//! `ci reuse` (crate::ci_reuse) applies these run, object, receipt, archive and
//! re-read checks to an earlier main run's stored result too, after binding
//! that run's own commit archive to the key's source inputs as a deploy binds
//! its commit's. It selects differently: any current, successful attempt
//! under the key, not only the newest run of one commit.
use crate::ci_check::{RECEIPT_LIMIT, Receipt as Checked};
use crate::ci_results::{Stored, decimal};
use crate::instance_source::{
    ARTIFACT_LIMIT, App, Binding, File, Forge, Instance, NOT_READY, POLL, Receipt, Retryable,
    Session, WAIT, WAITING, commit, field, hash, int, object_with, proof_id, text, write_new,
};
use anyhow::{Context, Result, bail, ensure};
use day2::sdk_release::BlobIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// The required org workflow's file, and the path a push run on main reports.
pub const WORKFLOW: &str = "verification.yml";
pub const PATH: &str = "verification.yml@refs/heads/main";

/// The objects `ci store` writes for one attempt, receipt last.
pub const RECEIPT: &str = "receipt.json";
pub const ARTIFACT: &str = "artifact.tar.gz";

/// The provenance a candidate records for an artifact read from app CI.
pub const VERSION: i128 = 2;

/// App CI's names, which the CLI renders from day2.json only when it sets
/// `forge.oidc`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppCi {
    /// `<org>/day2-ci`: the repository whose scoped `verification.yml` is app CI.
    pub repository: String,
    /// Each app's results bucket, in the order of the instance's apps.
    pub buckets: Vec<Bucket>,
}

/// One app's results bucket, `<project>-<id>-ci`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bucket {
    pub id: String,
    pub bucket: String,
}

/// The derived names, again: `<org>/day2-ci`, and `<project>-<id>-ci` for every
/// app, in order.
pub fn validate(app_ci: &AppCi, instance: &Instance) -> Result<()> {
    let project = instance
        .bucket
        .strip_suffix("-tofu-state")
        .unwrap_or_default();
    ensure!(
        app_ci.repository == format!("{}/day2-ci", instance.org),
        "app CI's repository must be {}/day2-ci",
        instance.org
    );
    ensure!(
        app_ci.buckets.len() == instance.apps.len()
            && app_ci
                .buckets
                .iter()
                .zip(&instance.apps)
                .all(|(bucket, app): (&Bucket, &App)| {
                    bucket.id == app.id && bucket.bucket == format!("{project}-{}-ci", app.id)
                }),
        "app CI's results buckets must be <project>-<id>-ci for every app, in order"
    );
    Ok(())
}

/// The app CI run a deploy trusts: its current attempt and that attempt's
/// start and stop, as the forge reported them, and the day2-ci commit whose
/// workflow it ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub id: u64,
    pub attempt: u64,
    pub started_at: String,
    pub completed_at: String,
    pub workflow_commit: String,
}

impl Run {
    fn window(&self) -> Option<(i64, i64)> {
        Some((
            day2::google_workspace_calendar::rfc3339_seconds(&self.started_at)?,
            day2::google_workspace_calendar::rfc3339_seconds(&self.completed_at)?,
        ))
    }

    /// Whether a server-set creation time falls inside the attempt. The forge
    /// keeps whole seconds, so the comparison is in whole seconds.
    pub fn contains(&self, created: &str) -> bool {
        match (self.window(), gcs_seconds(created)) {
            (Some((start, stop)), Some(at)) => start <= at && at <= stop,
            _ => false,
        }
    }

    /// The metadata `ci store` writes for this run of `commit`: run, attempt,
    /// head and event, and the workflow commit when the runner exported it.
    pub fn wrote(&self, metadata: &BTreeMap<String, String>, commit: &str) -> bool {
        let mut expected = BTreeMap::from([
            ("run".to_owned(), self.id.to_string()),
            ("attempt".to_owned(), self.attempt.to_string()),
            ("head".to_owned(), commit.to_owned()),
            ("event".to_owned(), "push".to_owned()),
        ]);
        if metadata.contains_key("workflow_commit") {
            expected.insert("workflow_commit".to_owned(), self.workflow_commit.clone());
        }
        *metadata == expected
    }
}

/// A GCS creation time, `YYYY-MM-DDTHH:MM:SS[.fraction]Z`, as whole seconds
/// since the epoch.
pub fn gcs_seconds(value: &str) -> Option<i64> {
    let (whole, rest) = (value.get(..19)?, value.get(19..)?);
    if rest != "Z" {
        let digits = rest.strip_prefix('.')?.strip_suffix('Z')?;
        if !(1..=9).contains(&digits.len()) || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    day2::google_workspace_calendar::rfc3339_seconds(&format!("{whole}Z"))
}

/// The CI repository's own record: exactly `<org>/day2-ci`, owned by the
/// instance's org. Its ID is the scoped workflow source every run must name.
pub fn source(record: &Value, repository: &str, org: &str) -> Result<u64> {
    ensure!(
        record["full_name"] == repository && record["owner"]["login"] == org,
        "the forge answered for another repository than {repository}"
    );
    record["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("the forge gave no repository ID for app CI's repository")
}

/// The newest run for `commit` on a page of the scoped workflow's runs. Every
/// run the page lists for that commit must be app CI's: a push to main of the
/// app repository, of `<org>/day2-ci`'s scoped `verification.yml`. Runs of
/// other commits are not this deploy's.
pub fn newest<'a>(
    page: &'a Value,
    commit: &str,
    source_id: u64,
    source: &str,
    repository_id: &Value,
) -> Result<Option<&'a Value>> {
    let runs = field(page, "workflow_runs")?
        .as_array()
        .context("source response lacks workflow_runs")?;
    let mut newest: Option<(&Value, u64)> = None;
    for run in runs {
        ensure!(run.is_object(), "source response lacks workflow runs");
        if run.get("head_sha") != Some(&json!(commit)) {
            continue;
        }
        identity(run, source_id, source, repository_id)?;
        let id = run
            .get("id")
            .and_then(proof_id)
            .context("invalid app CI run")?;
        if newest.is_none_or(|(_, best)| id > best) {
            newest = Some((run, id));
        }
    }
    Ok(newest.map(|(run, _)| run))
}

/// A run is app CI's: scoped, from the pinned source, on the app repository,
/// of the push to main, with an attempt and an exact workflow commit.
pub fn identity(run: &Value, source_id: u64, source: &str, repository_id: &Value) -> Result<()> {
    let workflow = run.get("workflow_repository");
    ensure!(
        run.get("is_scoped") == Some(&Value::Bool(true))
            && run.get("workflow_repository_id") == Some(&json!(source_id))
            && workflow.and_then(|value| value.get("id")) == Some(&json!(source_id))
            && workflow.and_then(|value| value.get("full_name")) == Some(&json!(source))
            && run.get("event") == Some(&json!("push"))
            && run.get("head_branch") == Some(&json!("main"))
            && run.get("path") == Some(&json!(PATH))
            && run.get("repository").and_then(|value| value.get("id")) == Some(repository_id)
            && run
                .get("run_attempt")
                .and_then(int)
                .is_some_and(|attempt| attempt > 0)
            && run
                .get("workflow_commit_sha")
                .and_then(Value::as_str)
                .is_some_and(commit),
        "the forge's run is not app CI's scoped verification run of a push to main"
    );
    Ok(())
}

/// The run once its current attempt is terminal: successful, or a refusal.
/// Nothing while it is still queued or running.
pub fn completed(run: &Value) -> Result<Option<Run>> {
    if run.get("status") != Some(&json!("completed")) {
        return Ok(None);
    }
    ensure!(
        run.get("conclusion") == Some(&json!("success")),
        "app CI did not succeed on main; retry deployment after fixing CI"
    );
    let text = |name: &str| run.get(name).and_then(Value::as_str).map(str::to_owned);
    // The forge writes its local zone; the record keeps UTC.
    let instant = |name: &str| {
        text(name)
            .and_then(|value| day2::google_workspace_calendar::rfc3339_seconds(&value))
            .filter(|seconds| *seconds > 0)
            .and_then(utc)
    };
    let (Some(started_at), Some(completed_at)) = (instant("started_at"), instant("completed_at"))
    else {
        bail!("app CI's run has no exact start and stop");
    };
    let found = Run {
        id: run
            .get("id")
            .and_then(proof_id)
            .context("invalid app CI run")?,
        attempt: run
            .get("run_attempt")
            .and_then(Value::as_u64)
            .context("invalid app CI run")?,
        started_at,
        completed_at,
        workflow_commit: text("workflow_commit_sha").context("invalid app CI run")?,
    };
    ensure!(
        found.window().is_some_and(|(start, stop)| start <= stop),
        "app CI's run has no exact start and stop"
    );
    Ok(Some(found))
}

/// Seconds since the epoch as RFC 3339 in UTC, whole seconds: the one form a
/// record keeps a time in.
pub fn utc(seconds: i64) -> Option<String> {
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::try_from(seconds).ok()?);
    let stamp = crate::offsite::utc_stamp(at).ok()?;
    Some(format!(
        "{}-{}-{}T{}:{}:{}Z",
        stamp.get(0..4)?,
        stamp.get(4..6)?,
        stamp.get(6..8)?,
        stamp.get(9..11)?,
        stamp.get(11..13)?,
        stamp.get(13..15)?
    ))
}

/// A time exactly as a record keeps it.
fn canonical(value: &str) -> bool {
    day2::google_workspace_calendar::rfc3339_seconds(value).and_then(utc) == Some(value.to_owned())
}

/// `<sdk>/<source inputs>-<cases>/`: the key `ci store` writes every result
/// of one SDK release, source inputs and case count under, one
/// `<run>/<attempt>/` below it per stored attempt. `ci reuse` lists it.
pub fn key(sdk: &str, inputs: &str, cases: impl std::fmt::Display) -> String {
    let hex = |digest: &str| digest.trim_start_matches("sha256:").to_owned();
    format!("{}/{}-{cases}/", hex(sdk), hex(inputs))
}

/// `<sdk>/<source inputs>-<cases>/<run>/<attempt>/<file>`: the object `ci
/// store` wrote for this attempt of the binding's release, profile and inputs.
pub fn object_name(binding: &Binding, inputs: &str, run: &Run, file: &str) -> String {
    format!(
        "{}{}/{}/{file}",
        key(
            &binding.qualified_release.digest,
            inputs,
            &binding.verification["cases"]
        ),
        run.id,
        run.attempt
    )
}

/// A stored object is this attempt's: written by it, inside its window.
fn stored_by(stored: &Stored, run: &Run, commit: &str, what: &str) -> Result<()> {
    ensure!(
        run.wrote(&stored.metadata, commit),
        "app CI's {what} does not carry this run's metadata"
    );
    ensure!(
        run.contains(&stored.time_created),
        "app CI's {what} was not created during the run's attempt"
    );
    Ok(())
}

// The custody checks below are the deploy reader's, in its order. `ci reuse`
// applies the same functions to an earlier main run's stored result, once the
// forge's archive of that run's commit binds its source inputs.

/// The attempt's receipt object, before its bytes are read: this run's,
/// created during its attempt, within the receipt budget.
pub fn receipt_object(stored: &Stored, run: &Run, commit: &str) -> Result<()> {
    stored_by(stored, run, commit, RECEIPT)?;
    ensure!(
        (1..=RECEIPT_LIMIT).contains(&stored.size),
        "app CI's receipt exceeds its budget"
    );
    Ok(())
}

/// The receipt's bytes, decoded exactly: a complete run's.
pub fn decoded_receipt(bytes: &[u8]) -> Result<Checked> {
    let checked: Checked = day2::json::decode(bytes).context("invalid app CI receipt")?;
    checked.check()?;
    Ok(checked)
}

/// The receipt binds exactly these source inputs and this verification
/// profile (`{"version": 1, "seed": 42, "cases": <cases>}`).
pub fn binds(checked: &Checked, inputs: &str, verification: &Value) -> Result<()> {
    ensure!(
        checked.source_inputs == inputs
            && serde_json::to_value(&checked.verification)? == *verification,
        "app CI's checked artifact belongs to another source or profile"
    );
    Ok(())
}

/// The attempt's artifact object: this run's, created during its attempt,
/// the size its receipt names.
pub fn artifact_object(
    stored: &Stored,
    run: &Run,
    commit: &str,
    expected: &BlobIdentity,
) -> Result<()> {
    stored_by(stored, run, commit, ARTIFACT)?;
    ensure!(
        stored.size == expected.bytes && expected.bytes <= ARTIFACT_LIMIT,
        "app CI's artifact is not the size its receipt names"
    );
    Ok(())
}

/// The artifact's bytes are the archive its receipt names.
pub fn archive(data: &[u8], expected: &BlobIdentity) -> Result<()> {
    ensure!(
        BlobIdentity::of(data) == *expected,
        "app CI's artifact is not the archive its receipt names"
    );
    Ok(())
}

/// The run, read again after the artifact was downloaded: still app CI's run
/// of `commit` (see [`identity`]), the same successful attempt, with the same
/// window.
pub fn unchanged(
    latest: &Value,
    commit: &str,
    source_id: u64,
    source: &str,
    repository_id: &Value,
    run: &Run,
) -> Result<()> {
    ensure!(
        latest.get("head_sha") == Some(&json!(commit)),
        "app CI's run changed its commit"
    );
    identity(latest, source_id, source, repository_id)?;
    ensure!(
        completed(latest)? == Some(run.clone()),
        "app CI's attempt changed during the artifact download"
    );
    Ok(())
}

/// What the receipt read found, kept for the artifact and the proof.
pub(super) struct Found {
    pub(super) bucket: String,
    pub(super) receipt: (Stored, Checked),
    pub(super) artifact: Option<Stored>,
}

/// The proof's record of one object: where it is, its generation and its
/// server-set creation time.
fn described(bucket: &str, name: &str, stored: &Stored) -> Value {
    json!({"uri": format!("gs://{bucket}/{name}"), "generation": stored.generation,
        "time_created": stored.time_created})
}

/// The provenance proof for an artifact read from app CI, version 2, for
/// `binding`'s JSON, `source_commit` and the checked source inputs. It holds
/// the run and attempt the forge reported, the CI repository and the workflow
/// commit, both objects and the receipt exactly as stored.
pub fn proof(value: &Value, binding: &Value, source_commit: &str, inputs: &str) -> Result<()> {
    ensure!(
        object_with(
            value,
            &[
                "version",
                "repository",
                "commit",
                "run",
                "attempt",
                "started_at",
                "completed_at",
                "workflow",
                "objects",
                "receipt",
            ]
        ) && int(&value["version"]) == Some(VERSION)
            && ["run", "attempt"]
                .iter()
                .all(|key| proof_id(&value[*key]).is_some()),
        "invalid app CI provenance"
    );
    let repository = binding["repository"].as_str().unwrap_or_default();
    let org = repository.split('/').next().unwrap_or_default();
    let workflow = &value["workflow"];
    ensure!(
        value["repository"] == repository
            && value["commit"] == source_commit
            && commit(source_commit)
            && object_with(workflow, &["repository", "repository_id", "commit"])
            && workflow["repository"] == format!("{org}/day2-ci")
            && proof_id(&workflow["repository_id"]).is_some()
            && workflow["commit"].as_str().is_some_and(commit),
        "app CI provenance belongs to another repository, commit or workflow"
    );
    let run = Run {
        id: value["run"].as_u64().unwrap_or_default(),
        attempt: value["attempt"].as_u64().unwrap_or_default(),
        started_at: value["started_at"].as_str().unwrap_or_default().to_owned(),
        completed_at: value["completed_at"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        workflow_commit: workflow["commit"].as_str().unwrap_or_default().to_owned(),
    };
    ensure!(
        canonical(&run.started_at)
            && canonical(&run.completed_at)
            && run
                .window()
                .is_some_and(|(start, stop)| 0 < start && start <= stop),
        "app CI provenance has no exact start and stop"
    );
    let checked: Checked = serde_json::from_value(value["receipt"].clone())
        .context("invalid app CI receipt fields")?;
    checked.check()?;
    ensure!(
        checked.source_inputs == inputs
            && hash(inputs)
            && serde_json::to_value(&checked.verification)? == binding["verification"],
        "app CI's checked artifact belongs to another source or profile"
    );
    let objects = &value["objects"];
    ensure!(
        object_with(objects, &["receipt", "artifact"]),
        "invalid app CI objects"
    );
    let app = binding["app"].as_str().unwrap_or_default();
    let release = binding["qualified_release"]["digest"]
        .as_str()
        .unwrap_or_default()
        .trim_start_matches("sha256:");
    let prefix = format!(
        "{release}/{}-{}/{}/{}/",
        inputs.trim_start_matches("sha256:"),
        checked.verification.cases,
        run.id,
        run.attempt
    );
    let mut buckets = Vec::new();
    for (key, file) in [("receipt", RECEIPT), ("artifact", ARTIFACT)] {
        let object = &objects[key];
        let uri = object["uri"].as_str().unwrap_or_default();
        let bucket = uri
            .strip_prefix("gs://")
            .and_then(|rest| rest.strip_suffix(&format!("/{prefix}{file}")))
            .unwrap_or_default();
        ensure!(
            object_with(object, &["uri", "generation", "time_created"])
                && bucket
                    .strip_suffix(&format!("-{app}-ci"))
                    .is_some_and(|project| (6..=30).contains(&project.len()))
                && object["generation"]
                    .as_str()
                    .and_then(decimal)
                    .is_some_and(|generation| generation > 0)
                && object["time_created"]
                    .as_str()
                    .is_some_and(|created| run.contains(created)),
            "invalid app CI object provenance"
        );
        buckets.push(bucket);
    }
    ensure!(
        buckets[0] == buckets[1],
        "app CI's objects belong to different buckets"
    );
    Ok(())
}

impl Session {
    fn app_ci_names(&self) -> Result<AppCi> {
        self.instance
            .as_ref()
            .and_then(|instance| instance.app_ci.clone())
            .context("app CI names")
    }

    /// Wait for what is not there yet, within the deadline the run step set:
    /// announce once, then sleep at most `POLL`. Past the deadline it is
    /// retryable.
    fn pause(&mut self) -> Result<()> {
        let deadline = self.deadline.context("app CI deadline")?;
        let clock = self.effects.clock.as_mut();
        if clock.now() >= deadline {
            return Err(Retryable(NOT_READY).into());
        }
        if !self.announced {
            clock.announce(WAITING);
            self.announced = true;
        }
        let left = deadline.saturating_sub(clock.now());
        clock.sleep(POLL.min(left));
        Ok(())
    }

    /// run: the CI repository's ID, then, within this job, the newest app CI
    /// run for the exact commit until its current attempt is terminal, reading
    /// at most every 20 s for up to 2100 s. It must have succeeded.
    pub(super) fn ci_run(&mut self) -> Result<Value> {
        let commit = self.commit.clone().context("commit")?;
        let names = self.app_ci_names()?;
        let org = self.instance.as_ref().context("instance")?.org.clone();
        let binding = self.binding()?.clone();
        ensure!(
            binding.repository == format!("{org}/{}", binding.app),
            "app CI stores results only for the app's repository {org}/{}, not {}",
            binding.app,
            binding.repository
        );
        self.deadline = Some(self.effects.clock.now() + WAIT);
        let record = Forge::new(
            self.effects.transport.as_mut(),
            self.effects.token.as_deref(),
            &binding.server,
            &names.repository,
        )
        .repository()?;
        let source_id = source(&record, &names.repository, &org)?;
        loop {
            let (mut forge, _) = self.forge()?;
            let url = format!(
                "{}/actions/workflows/{WORKFLOW}/runs?scoped_workflow_source_repo_id={source_id}\
                 &event=push&branch=main&head_sha={commit}&limit=50",
                forge.prefix
            );
            let page = forge.json(&url)?;
            if let Some(run) = newest(
                &page,
                &commit,
                source_id,
                &names.repository,
                &binding.repository_id,
            )? && let Some(run) = completed(run)?
            {
                let reported = json!({"run": run.id, "attempt": run.attempt,
                    "started_at": run.started_at, "completed_at": run.completed_at});
                self.ci = Some((source_id, run));
                return Ok(reported);
            }
            self.pause()?;
        }
    }

    fn ci_bucket(&self) -> Result<String> {
        let app = &self.binding()?.app;
        self.app_ci_names()?
            .buckets
            .into_iter()
            .find(|bucket| bucket.id == *app)
            .map(|bucket| bucket.bucket)
            .context("the app's CI results bucket")
    }

    /// One object of the attempt, waiting while it is absent.
    fn ci_object(&mut self, bucket: &str, name: &str) -> Result<Stored> {
        loop {
            if let Some(stored) = self.effects.storage.object(bucket, name, None)? {
                return Ok(stored);
            }
            self.pause()?;
        }
    }

    /// job: the attempt's receipt, read as the apply identity: this run's,
    /// created during its attempt, a complete run's, and bound to this
    /// commit's source inputs, the binding's profile and its release's tooling
    /// distribution.
    pub(super) fn ci_receipt(&mut self) -> Result<Value> {
        let (_, run) = self.ci.clone().context("app CI run")?;
        let commit = self.commit.clone().context("commit")?;
        let inputs = self.inputs.clone().context("source inputs")?;
        let binding = self.binding()?.clone();
        let bucket = self.ci_bucket()?;
        let name = object_name(&binding, &inputs, &run, RECEIPT);
        let stored = self.ci_object(&bucket, &name)?;
        receipt_object(&stored, &run, &commit)?;
        let bytes =
            self.effects
                .storage
                .media(&bucket, &name, &stored.generation, stored.size, None)?;
        let checked = decoded_receipt(&bytes)?;
        let release = self.release()?;
        binds(&checked, &inputs, &binding.verification)?;
        ensure!(
            checked.sdk_distribution == release.distribution,
            "app CI checked the artifact on another SDK's tooling distribution"
        );
        let reported = json!({"receipt": format!("gs://{bucket}/{name}"),
            "generation": stored.generation});
        self.found = Some(Found {
            bucket,
            receipt: (stored, checked),
            artifact: None,
        });
        Ok(reported)
    }

    /// artifact: the attempt's artifact object: this run's, created during its
    /// attempt, the size the receipt names.
    pub(super) fn ci_artifact(&mut self) -> Result<Value> {
        let (_, run) = self.ci.clone().context("app CI run")?;
        let commit = self.commit.clone().context("commit")?;
        let inputs = self.inputs.clone().context("source inputs")?;
        let binding = self.binding()?.clone();
        let (bucket, expected) = {
            let found = self.found.as_ref().context("app CI receipt")?;
            (found.bucket.clone(), found.receipt.1.archive.clone())
        };
        let name = object_name(&binding, &inputs, &run, ARTIFACT);
        let stored = self.ci_object(&bucket, &name)?;
        artifact_object(&stored, &run, &commit, &expected)?;
        let reported = json!({"artifact": format!("gs://{bucket}/{name}"),
            "generation": stored.generation});
        self.found.as_mut().context("app CI receipt")?.artifact = Some(stored);
        Ok(reported)
    }

    /// download: the artifact's bytes at exactly that generation, whose digest
    /// must be the receipt's.
    pub(super) fn ci_download(&mut self) -> Result<Value> {
        let (_, run) = self.ci.clone().context("app CI run")?;
        let inputs = self.inputs.clone().context("source inputs")?;
        let binding = self.binding()?.clone();
        let found = self.found.as_ref().context("app CI receipt")?;
        let stored = found.artifact.clone().context("app CI artifact")?;
        let (bucket, expected) = (found.bucket.clone(), found.receipt.1.archive.clone());
        let name = object_name(&binding, &inputs, &run, ARTIFACT);
        let data =
            self.effects
                .storage
                .media(&bucket, &name, &stored.generation, stored.size, None)?;
        archive(&data, &expected)?;
        self.data = Some(data);
        Ok(json!({"digest": expected.digest, "bytes": expected.bytes}))
    }

    /// attempt: the run must still be app CI's same successful attempt, with
    /// the same window. Only then is the archive written and the proof
    /// returned.
    pub(super) fn ci_attempt(&mut self) -> Result<Value> {
        let (source_id, run) = self.ci.clone().context("app CI run")?;
        let commit = self.commit.clone().context("commit")?;
        let inputs = self.inputs.clone().context("source inputs")?;
        let names = self.app_ci_names()?;
        let (mut forge, binding) = self.forge()?;
        let latest = forge.json(&format!("{}/actions/runs/{}", forge.prefix, run.id))?;
        unchanged(
            &latest,
            &commit,
            source_id,
            &names.repository,
            &binding.repository_id,
            &run,
        )?;
        let binding = binding.clone();
        let found = self.found.as_ref().context("app CI receipt")?;
        let artifact = found.artifact.as_ref().context("app CI artifact")?;
        let evidence = json!({
            "version": VERSION,
            "repository": binding.repository,
            "commit": commit,
            "run": run.id,
            "attempt": run.attempt,
            "started_at": run.started_at,
            "completed_at": run.completed_at,
            "workflow": {"repository": names.repository, "repository_id": source_id,
                "commit": run.workflow_commit},
            "objects": {
                "receipt": described(&found.bucket, &object_name(&binding, &inputs, &run, RECEIPT),
                    &found.receipt.0),
                "artifact": described(&found.bucket, &object_name(&binding, &inputs, &run, ARTIFACT),
                    artifact),
            },
            "receipt": serde_json::to_value(&found.receipt.1)?,
        });
        proof(&evidence, &binding.value, &commit, &inputs)?;
        let expected = found.receipt.1.archive.clone();
        let output = self.output.clone().context("new archive")?;
        write_new(&output, self.data.as_ref().context("downloaded archive")?)?;
        Ok(serde_json::to_value(Receipt {
            archive: Some(File {
                path: text(&output)?.to_owned(),
                digest: expected.digest,
                bytes: expected.bytes,
            }),
            source_inputs: Some(inputs),
            proof: Some(evidence),
            ..self.receipt()
        })?)
    }
}

#[cfg(test)]
mod tests;
