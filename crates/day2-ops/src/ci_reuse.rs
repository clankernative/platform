//! `day2 ci reuse DIRECTORY CASES`: the org-scoped app CI workflow's second
//! step, after `day2 ci fetch DIRECTORY` and before `day2 ci check --reuse
//! DIRECTORY/reuse DIRECTORY/head CASES DIRECTORY/out`. A push run on main
//! looks for the result an earlier push run on main stored under the same key,
//! so check can verify it again instead of building the app and running its
//! campaign:
//!
//! `gs://<project>-<app>-ci/<sdk>/<source inputs>-<cases>/<run>/<attempt>/`
//!
//! - **Only push runs.** A `pull_request` run never reuses: the command says
//!   so and succeeds without reading a store input, minting a token, reaching
//!   any service or writing anything.
//! - **Run.** `DIRECTORY/event.json` must be the step's own run, as `ci store`
//!   checks it, and `DIRECTORY/reuse` must not exist yet.
//! - **Key.** The store inputs' SDK (`DAY2_CI_SDK`), the source inputs of
//!   `DIRECTORY/head/app`, recomputed as check and store compute them, and
//!   CASES, the instance's verification cases the check step is rendered with.
//! - **Custody** is exactly the deploy reader's ([`app_ci`]), applied to each
//!   stored attempt under the key, newest run first, at most [`CANDIDATES`]:
//!   the forge's record of that run (read with the job token from
//!   `GITHUB_TOKEN`) must be app CI's scoped verification run of a push to
//!   main, its current attempt the stored one, terminal and successful; both
//!   objects must carry that run's metadata, with the run's head commit, and
//!   have been created inside the attempt's window; the receipt must be a
//!   complete run's bound to the key's source inputs and cases, seed 42 and
//!   `DAY2_CI_DISTRIBUTION`; the archive must be the receipt's; the run must
//!   still be the same attempt once the archive is read; and it must not be
//!   this run. The CI repository is the one the forge names for this run's
//!   own scoped record: the job token reads only its own repository.
//! - **Credential.** git-oidc and Google STS, as `ci store` mints and
//!   exchanges, but for `devstorage.read_only`: the push identity's object
//!   read access, which includes listing.
//! - **Never fails the run.** Absence, a refusal of every candidate, a read
//!   that failed or stayed transient, missing inputs or the lookup's
//!   [`BUDGET`]: each is recorded as why nothing was reused, and the command
//!   succeeds, so check builds the app as it always does. Only a request, run
//!   record or directory that no later step could use either fails it.
//! - **Output.** For a push run, `DIRECTORY/reuse/` (0700) with `reuse.json`
//!   ([`Record`]) written last and, when a result was reused, its
//!   `app.tar.gz` and its `receipt.json`, the stored bytes.
use crate::{
    ci_check::SEED,
    ci_fetch::{self, Environment, Event, Waiting, retrying},
    ci_results::{Gcs, Storage, Stored, decimal},
    ci_store::{self, Inputs, Variables},
    instance_source::{self, Forge, System, Transport, app_ci},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(test)]
mod tests;

/// `DIRECTORY/reuse`, which `ci check --reuse` reads.
pub const REUSE: &str = "reuse";
/// The record in it, written last.
pub const RECORD: &str = "reuse.json";
/// The reused result's files in it, as `ci check` names its own output.
pub const ARCHIVE: &str = "app.tar.gz";
pub const RECEIPT: &str = "receipt.json";
/// The only access the exchanged token carries.
pub const SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_only";
/// Why a pull request run reuses nothing.
pub const PULL_REQUEST: &str = "pull_request runs never reuse: only main's push run reuses a \
     result an earlier push run on main stored";
/// Why a push run found nothing: plain absence.
pub const ABSENT: &str = "no earlier push run on main stored a result under this key";
/// The newest stored attempts tried, at most.
pub const CANDIDATES: usize = 8;
/// The pages of names read, at most.
pub const PAGES: usize = 10;
/// The whole lookup's time: a step that would begin later records a miss.
pub const BUDGET: Duration = Duration::from_secs(300);
const REQUEST_LIMIT: u64 = 65_536;
const RECORD_LIMIT: u64 = 65_536;

/// What the CLI hands the host.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub directory: PathBuf,
    pub cases: u64,
}

/// One object of the reused attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Object {
    pub name: String,
    pub generation: String,
    pub time_created: String,
}

/// The stored attempt a result was reused from, as the forge and the bucket
/// described it when its custody was checked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub run: u64,
    pub attempt: u64,
    /// The commit that run checked.
    pub head: String,
    pub workflow_commit: String,
    pub started_at: String,
    pub completed_at: String,
    pub bucket: String,
    pub receipt: Object,
    pub artifact: Object,
}

/// `DIRECTORY/reuse/reuse.json`: whether a result was reused and from where,
/// or why not. `ci check --reuse` reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub format: u32,
    pub reused: bool,
    pub reason: Option<String>,
    pub source: Option<Source>,
}

impl Record {
    /// Format 1: a reused result with its source and no reason, or a reason
    /// and nothing. A source names its attempt's two objects in one bucket.
    pub fn validate(&self) -> Result<()> {
        let shaped = match (&self.source, &self.reason) {
            (Some(source), None) if self.reused => {
                let object = |object: &Object, file: &str| {
                    object
                        .name
                        .ends_with(&format!("/{}/{}/{file}", source.run, source.attempt))
                        && decimal(&object.generation).is_some_and(|generation| generation > 0)
                        && app_ci::gcs_seconds(&object.time_created).is_some()
                };
                source.run > 0
                    && source.attempt > 0
                    && ci_fetch::canonical(&source.head)
                    && ci_fetch::canonical(&source.workflow_commit)
                    && app_ci::gcs_seconds(&source.started_at).is_some()
                    && app_ci::gcs_seconds(&source.completed_at).is_some()
                    && crate::offsite::validate_bucket(&source.bucket).is_ok()
                    && object(&source.receipt, app_ci::RECEIPT)
                    && object(&source.artifact, app_ci::ARTIFACT)
            }
            (None, Some(reason)) => !self.reused && !reason.is_empty(),
            _ => false,
        };
        ensure!(self.format == 1 && shaped, "invalid CI reuse record");
        Ok(())
    }

    /// `DIRECTORY/reuse.json`, exactly.
    pub fn read(directory: &Path) -> Result<Self> {
        let path = directory.join(RECORD);
        let bytes = day2_assets::read_regular(&path, RECORD_LIMIT)
            .with_context(|| format!("read {}", path.display()))?;
        let record: Self = day2::json::decode(&bytes).context("invalid CI reuse record")?;
        record.validate()?;
        Ok(record)
    }
}

/// One stored attempt the lookup tried, and why it was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tried {
    pub run: u64,
    pub attempt: u64,
    pub accepted: bool,
    pub reason: Option<String>,
}

/// What `day2 ci reuse` prints. cli/fixtures/ci-reuse-report.json pins the
/// shape for the host and the CLI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub format: u32,
    pub repository: String,
    pub event: String,
    pub run: u64,
    pub attempt: u64,
    /// Whether a stored result was reused; when not, why.
    pub reused: bool,
    pub reason: Option<String>,
    /// The bucket and the key listed, once the inputs were read.
    pub bucket: Option<String>,
    pub key: Option<String>,
    /// The stored attempts the key holds, and those tried, newest first.
    pub listed: u64,
    pub tried: Vec<Tried>,
    pub source: Option<Source>,
    /// `DIRECTORY/reuse`, for a push run.
    pub output: Option<PathBuf>,
}

/// The bucket a session reads, once Google STS has exchanged its token.
pub type Storages = Box<dyn FnMut(String) -> Result<Box<dyn Storage>>>;

/// What the session reaches outside itself.
pub struct Effects {
    /// The forge, with the job token.
    pub transport: Box<dyn Transport>,
    /// git-oidc and Google STS.
    pub client: reqwest::blocking::Client,
    pub waiting: Box<dyn Waiting>,
    pub sts: String,
    /// Whether git-oidc must be https: always, except against a test's
    /// local servers.
    pub https: bool,
    pub storage: Storages,
    /// The step's environment: the run, the job token and the store inputs.
    pub variables: Variables,
}

impl Effects {
    /// The forge over HTTPS; git-oidc and STS with `ci store`'s client; the
    /// JSON API with the exchanged token; the system clock; the process
    /// environment.
    pub fn native() -> Result<Self> {
        Ok(Self {
            transport: Box::new(instance_source::Native::new()?),
            client: ci_store::client(true)?,
            waiting: Box::new(System::new()),
            sts: ci_store::STS.to_owned(),
            https: true,
            storage: Box::new(|token| Ok(Box::new(Gcs::with_token(token)?) as Box<dyn Storage>)),
            variables: Box::new(|name| std::env::var_os(name)),
        })
    }
}

/// Where the lookup is: each step, in order, until it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Run,
    Mint,
    Exchange,
    List,
    Candidates,
    Done,
}

/// A stored attempt that passed custody, and its bytes.
struct Found {
    source: Source,
    receipt: Vec<u8>,
    archive: Vec<u8>,
}

/// One stored attempt's verdict: reused, or refused by a custody check.
enum Verdict {
    Accepted(Box<Found>),
    Refused(String),
}

/// A custody check's failure refuses the candidate; a failed read (`?`) ends
/// the lookup instead.
macro_rules! custody {
    ($check:expr) => {
        match $check {
            Ok(value) => value,
            Err(error) => return Ok(Verdict::Refused(format!("{error:#}"))),
        }
    };
}

pub struct Session {
    directory: PathBuf,
    cases: u64,
    effects: Effects,
    event: Event,
    server: String,
    token: Option<String>,
    inputs: Option<Inputs>,
    /// The head app's source inputs and the key they are listed under.
    head: Option<String>,
    key: Option<String>,
    /// The CI repository the forge names for this run: its ID and name.
    source: Option<(u64, String)>,
    started: Duration,
    stage: Stage,
    finished: bool,
    missed: Option<String>,
    subject: Option<String>,
    storage: Option<Box<dyn Storage>>,
    listed: u64,
    candidates: Vec<(u64, u64)>,
    tried: Vec<Tried>,
    found: Option<Found>,
}

impl Session {
    /// Validate the request, the run's record against the step's run and, for
    /// a push run, the inputs and the key. Nothing leaves the host. Missing or
    /// invalid inputs are a miss, not a failure.
    pub fn prepare(path: &Path, mut effects: Effects) -> Result<Self> {
        let raw = day2_assets::read_regular(path, REQUEST_LIMIT)?;
        let request: Request = day2::json::decode(&raw)?;
        ensure!(
            (4..=100).contains(&request.cases),
            "verification cases must be 4 to 100"
        );
        let directory = std::path::absolute(&request.directory)?;
        ensure!(
            fs::symlink_metadata(&directory).is_ok_and(|metadata| metadata.is_dir()),
            "ci reuse requires the run's directory, as ci fetch wrote it: {}",
            directory.display()
        );
        let event = Event::read(&directory)?;
        let run = Environment::read(&*effects.variables)?;
        ensure!(
            event.repository == run.repository
                && event.event == run.event_name
                && event.head == run.sha
                && event.run == run.run
                && event.attempt == run.attempt
                && event.workflow_commit == run.workflow_sha,
            "the run's record is not this run's: ci fetch writes it for the job's own run"
        );
        let push = event.event == "push";
        if push {
            ensure!(
                fs::symlink_metadata(directory.join(REUSE)).is_err(),
                "ci reuse runs once per run: {} exists",
                directory.join(REUSE).display()
            );
        }
        let started = effects.waiting.now();
        let mut session = Self {
            directory,
            cases: request.cases,
            effects,
            event,
            server: run.server,
            token: None,
            inputs: None,
            head: None,
            key: None,
            source: None,
            started,
            stage: Stage::Done,
            finished: false,
            missed: None,
            subject: None,
            storage: None,
            listed: 0,
            candidates: Vec::new(),
            tried: Vec::new(),
            found: None,
        };
        if !push {
            session.missed = Some(PULL_REQUEST.to_owned());
            return Ok(session);
        }
        match session.keyed() {
            Ok(()) => session.stage = Stage::Run,
            Err(error) => session.miss(&error),
        }
        Ok(session)
    }

    /// The job token, the store inputs (the run's) and the key: the release,
    /// the head app's source inputs and the cases.
    fn keyed(&mut self) -> Result<()> {
        let variables = &self.effects.variables;
        let token = variables(ci_fetch::TOKEN)
            .filter(|value| !value.is_empty())
            .with_context(|| {
                format!(
                    "ci reuse reads the forge with the job token in {}",
                    ci_fetch::TOKEN
                )
            })?
            .into_string()
            .map_err(|_: OsString| anyhow::anyhow!("{} must be UTF-8", ci_fetch::TOKEN))?;
        let inputs =
            Inputs::read_for(&**variables, self.effects.https, "to reuse a stored result")?;
        inputs.for_run(&self.event)?;
        let head =
            crate::ci_check::source_inputs(&self.directory.join("head").join(ci_fetch::APP))?;
        self.key = Some(app_ci::key(&inputs.sdk, &head, self.cases));
        self.head = Some(head);
        self.token = Some(token);
        self.inputs = Some(inputs);
        Ok(())
    }

    /// Whether to look: a push run whose inputs were read.
    pub fn plan(&self) -> Value {
        json!({"lookup": self.stage != Stage::Done})
    }

    fn next(&self) -> Option<&'static str> {
        if self.finished {
            return None;
        }
        Some(match self.stage {
            Stage::Run => "run",
            Stage::Mint => "mint",
            Stage::Exchange => "exchange",
            Stage::List => "list",
            Stage::Candidates => "candidate",
            Stage::Done => "result",
        })
    }

    /// The lookup ends with nothing reused, for `error`'s reason.
    fn miss(&mut self, error: &anyhow::Error) {
        self.missed = Some(format!("{error:#}"));
        self.stage = Stage::Done;
    }

    /// Run the next step, which must be `name`. A lookup step that fails ends
    /// the lookup with nothing reused and reports that it missed; only the
    /// result can fail the command.
    pub fn step(&mut self, name: &str) -> Result<Value> {
        let expected = self.next();
        let Some(step) = expected.filter(|step| *step == name) else {
            bail!(
                "ci reuse runs {} next, not {name}",
                expected.unwrap_or("nothing more")
            );
        };
        if step == "result" {
            self.finished = true;
            return self.result();
        }
        let elapsed = self.effects.waiting.now().saturating_sub(self.started);
        let outcome = if elapsed >= BUDGET {
            Err(anyhow::anyhow!(
                "the lookup ran past its {} s budget",
                BUDGET.as_secs()
            ))
        } else {
            match step {
                "run" => self.run(),
                "mint" => self.mint(),
                "exchange" => self.exchange(),
                "list" => self.list(),
                _ => self.candidate(),
            }
        };
        outcome.or_else(|error| {
            self.miss(&error);
            Ok(match step {
                "list" => json!({"missed": true, "candidates": []}),
                "candidate" => json!({"missed": true, "accepted": false}),
                _ => json!({"missed": true}),
            })
        })
    }

    fn inputs(&self) -> Result<&Inputs> {
        self.inputs.as_ref().context("the reuse inputs")
    }

    /// One JSON read from the run's own repository with the job token,
    /// retried while it fails transiently.
    fn forge(&mut self, path: &str) -> Result<Value> {
        let effects = &mut self.effects;
        let mut forge = Forge::new(
            effects.transport.as_mut(),
            self.token.as_deref(),
            &self.server,
            &self.event.repository,
        );
        let url = format!("{}{path}", forge.prefix);
        retrying(effects.waiting.as_mut(), "a forge read", |_| {
            forge.json(&url)
        })
    }

    /// run: the forge's record of this run names the CI repository, as a
    /// scoped run of `<org>/day2-ci`'s verification workflow for this push.
    fn run(&mut self) -> Result<Value> {
        let event = self.event.clone();
        let record = self.forge(&format!("/actions/runs/{}", event.run))?;
        let org = event.repository.split('/').next().unwrap_or_default();
        let source = format!("{org}/day2-ci");
        let source_id = record
            .get("workflow_repository_id")
            .and_then(instance_source::proof_id)
            .context("the forge names no workflow repository for this run")?;
        app_ci::identity(&record, source_id, &source, &json!(event.repository_id))?;
        ensure!(
            record.get("id").and_then(instance_source::proof_id) == Some(event.run)
                && record.get("head_sha") == Some(&json!(event.head))
                && record.get("run_attempt") == Some(&json!(event.attempt))
                && event.workflow_commit.as_ref().is_none_or(|commit| {
                    record.get("workflow_commit_sha") == Some(&json!(commit))
                }),
            "the forge's record of this run is not the run's"
        );
        self.source = Some((source_id, source));
        self.stage = Stage::Mint;
        Ok(json!({"missed": false}))
    }

    /// mint: git-oidc's token for the audience, as `ci store` mints it.
    fn mint(&mut self) -> Result<Value> {
        let inputs = self.inputs.as_ref().context("the reuse inputs")?;
        let subject = ci_store::mint(&self.effects.client, self.effects.waiting.as_mut(), inputs)?;
        self.subject = Some(subject);
        self.stage = Stage::Exchange;
        Ok(json!({"missed": false}))
    }

    /// exchange: Google STS's federated token, read only.
    fn exchange(&mut self) -> Result<Value> {
        let subject = self.subject.take().context("the minted token")?;
        let access = ci_store::exchange(
            &self.effects.client,
            &self.effects.sts,
            self.inputs()?,
            &subject,
            SCOPE,
        )?;
        self.storage = Some((self.effects.storage)(access)?);
        self.stage = Stage::List;
        Ok(json!({"missed": false}))
    }

    /// list: every name under the key, at most [`PAGES`] pages; each
    /// `<run>/<attempt>/receipt.json`, the commit marker `ci store` writes
    /// last, is a stored attempt. The newest [`CANDIDATES`] are tried.
    fn list(&mut self) -> Result<Value> {
        let key = self.key.clone().context("the key")?;
        let bucket = self.inputs()?.bucket.clone();
        let storage = self.storage.as_mut().context("the results bucket")?;
        let waiting = self.effects.waiting.as_mut();
        let mut attempts = BTreeSet::new();
        let mut page: Option<String> = None;
        for _ in 0..PAGES {
            let listing = retrying(waiting, "a results listing", |_| {
                storage.list(&bucket, &key, page.as_deref())
            })?;
            for name in &listing.names {
                let rest = name
                    .strip_prefix(&key)
                    .context("the listing names an object outside the key")?;
                if let Some(attempt) = stored(rest) {
                    attempts.insert(attempt);
                }
            }
            page = listing.next;
            if page.is_none() {
                break;
            }
        }
        ensure!(
            page.is_none(),
            "the key holds more than {PAGES} pages of results, more than the lookup reads"
        );
        self.listed = attempts.len() as u64;
        self.candidates = attempts.into_iter().rev().take(CANDIDATES).collect();
        if self.candidates.is_empty() {
            self.missed = Some(ABSENT.to_owned());
            self.stage = Stage::Done;
            return Ok(json!({"missed": true, "candidates": []}));
        }
        self.stage = Stage::Candidates;
        Ok(json!({"missed": false, "candidates": self.candidates.iter()
            .map(|(run, attempt)| json!({"run": run, "attempt": attempt})).collect::<Vec<_>>()}))
    }

    /// candidate: the next stored attempt, newest first, through every
    /// custody check. The first accepted ends the lookup, as does the last
    /// refused.
    fn candidate(&mut self) -> Result<Value> {
        let (run, attempt) = *self
            .candidates
            .get(self.tried.len())
            .context("no stored attempt is left")?;
        let verdict = match self.examine(run, attempt) {
            Ok(verdict) => verdict,
            Err(error) => {
                self.tried.push(Tried {
                    run,
                    attempt,
                    accepted: false,
                    reason: Some(format!("{error:#}")),
                });
                return Err(error);
            }
        };
        match verdict {
            Verdict::Accepted(found) => {
                self.tried.push(Tried {
                    run,
                    attempt,
                    accepted: true,
                    reason: None,
                });
                self.found = Some(*found);
                self.stage = Stage::Done;
                Ok(json!({"missed": false, "accepted": true}))
            }
            Verdict::Refused(reason) => {
                self.tried.push(Tried {
                    run,
                    attempt,
                    accepted: false,
                    reason: Some(reason),
                });
                let over = self.tried.len() == self.candidates.len();
                if over {
                    self.missed = Some(format!(
                        "custody refused every stored result tried under this key ({})",
                        self.tried.len()
                    ));
                    self.stage = Stage::Done;
                }
                Ok(json!({"missed": over, "accepted": false}))
            }
        }
    }

    fn object(&mut self, bucket: &str, name: &str) -> Result<Option<Stored>> {
        let storage = self.storage.as_mut().context("the results bucket")?;
        retrying(self.effects.waiting.as_mut(), "a results read", |_| {
            storage.object(bucket, name)
        })
    }

    fn media(&mut self, bucket: &str, name: &str, stored: &Stored) -> Result<Vec<u8>> {
        let storage = self.storage.as_mut().context("the results bucket")?;
        retrying(self.effects.waiting.as_mut(), "a results read", |_| {
            storage.media(bucket, name, &stored.generation, stored.size)
        })
    }

    /// One stored attempt under the deploy reader's custody checks, in its
    /// order: the run, the receipt object and bytes, the artifact object and
    /// bytes, the run again.
    fn examine(&mut self, id: u64, attempt: u64) -> Result<Verdict> {
        if id == self.event.run {
            return Ok(Verdict::Refused("it is this run's own result".to_owned()));
        }
        let (source_id, source) = self.source.clone().context("the CI repository")?;
        let repository_id = json!(self.event.repository_id);
        let (bucket, distribution) = {
            let inputs = self.inputs()?;
            (inputs.bucket.clone(), inputs.distribution.clone())
        };
        let key = self.key.clone().context("the key")?;
        let record = self.forge(&format!("/actions/runs/{id}"))?;
        let (run, head) = custody!(candidate(
            &record,
            id,
            attempt,
            source_id,
            &source,
            &repository_id
        ));
        let receipt_name = format!("{key}{id}/{attempt}/{}", app_ci::RECEIPT);
        let Some(receipt) = self.object(&bucket, &receipt_name)? else {
            return Ok(Verdict::Refused(
                "its receipt is no longer stored".to_owned(),
            ));
        };
        custody!(app_ci::receipt_object(&receipt, &run, &head));
        let bytes = self.media(&bucket, &receipt_name, &receipt)?;
        let checked = custody!(app_ci::decoded_receipt(&bytes));
        let head_inputs = self.head.clone().context("the head's source inputs")?;
        custody!(app_ci::binds(
            &checked,
            &head_inputs,
            &json!({"version": 1, "seed": SEED, "cases": self.cases})
        ));
        if checked.sdk_distribution.digest != distribution {
            return Ok(Verdict::Refused(
                "app CI checked the artifact on another SDK's tooling distribution".to_owned(),
            ));
        }
        let artifact_name = format!("{key}{id}/{attempt}/{}", app_ci::ARTIFACT);
        let Some(artifact) = self.object(&bucket, &artifact_name)? else {
            return Ok(Verdict::Refused(
                "its artifact is no longer stored".to_owned(),
            ));
        };
        custody!(app_ci::artifact_object(
            &artifact,
            &run,
            &head,
            &checked.archive
        ));
        let archive = self.media(&bucket, &artifact_name, &artifact)?;
        custody!(app_ci::archive(&archive, &checked.archive));
        let latest = self.forge(&format!("/actions/runs/{id}"))?;
        custody!(app_ci::unchanged(
            &latest,
            &head,
            source_id,
            &source,
            &repository_id,
            &run
        ));
        Ok(Verdict::Accepted(Box::new(Found {
            source: Source {
                run: run.id,
                attempt: run.attempt,
                head,
                workflow_commit: run.workflow_commit.clone(),
                started_at: run.started_at.clone(),
                completed_at: run.completed_at.clone(),
                bucket,
                receipt: Object {
                    name: receipt_name,
                    generation: receipt.generation,
                    time_created: receipt.time_created,
                },
                artifact: Object {
                    name: artifact_name,
                    generation: artifact.generation,
                    time_created: artifact.time_created,
                },
            },
            receipt: bytes,
            archive,
        })))
    }

    /// result: for a push run, `DIRECTORY/reuse/` with the reused result's
    /// files and, last, its record; then the report.
    fn result(&mut self) -> Result<Value> {
        let output = (self.event.event == "push").then(|| self.directory.join(REUSE));
        let record = Record {
            format: 1,
            reused: self.found.is_some(),
            reason: if self.found.is_some() {
                None
            } else {
                Some(self.missed.clone().unwrap_or_else(|| ABSENT.to_owned()))
            },
            source: self.found.as_ref().map(|found| found.source.clone()),
        };
        record.validate()?;
        if let Some(output) = &output {
            fs::DirBuilder::new().mode(0o700).create(output)?;
            if let Some(found) = &self.found {
                instance_source::write_new(&output.join(ARCHIVE), &found.archive)?;
                instance_source::write_new(&output.join(RECEIPT), &found.receipt)?;
            }
            let mut bytes = serde_json::to_vec_pretty(&record)?;
            bytes.push(b'\n');
            instance_source::write_new(&output.join(RECORD), &bytes)?;
        }
        Ok(serde_json::to_value(Report {
            format: 1,
            repository: self.event.repository.clone(),
            event: self.event.event.clone(),
            run: self.event.run,
            attempt: self.event.attempt,
            reused: record.reused,
            reason: record.reason,
            bucket: self.inputs.as_ref().map(|inputs| inputs.bucket.clone()),
            key: self.key.clone(),
            listed: self.listed,
            tried: self.tried.clone(),
            source: record.source,
            output,
        })?)
    }
}

/// `<run>/<attempt>/receipt.json` below the key: a stored attempt.
fn stored(rest: &str) -> Option<(u64, u64)> {
    let parts: Vec<&str> = rest.split('/').collect();
    let [run, attempt, file] = parts.as_slice() else {
        return None;
    };
    if *file != app_ci::RECEIPT {
        return None;
    }
    let positive = |part: &str| decimal(part).filter(|value| *value > 0);
    Some((positive(run)?, positive(attempt)?))
}

/// A stored attempt's run, as the forge reports it by ID: app CI's scoped
/// verification run of a push to main ([`app_ci::identity`]), the run asked
/// for, with a head commit, its current attempt terminal, successful and the
/// stored one.
fn candidate(
    record: &Value,
    id: u64,
    attempt: u64,
    source_id: u64,
    source: &str,
    repository_id: &Value,
) -> Result<(app_ci::Run, String)> {
    app_ci::identity(record, source_id, source, repository_id)?;
    ensure!(
        record.get("id").and_then(instance_source::proof_id) == Some(id),
        "the forge answered for another run than {id}"
    );
    let head = record
        .get("head_sha")
        .and_then(Value::as_str)
        .filter(|head| ci_fetch::canonical(head))
        .context("the run names no head commit")?
        .to_owned();
    let run = app_ci::completed(record)?.context("the run's current attempt is not terminal")?;
    ensure!(
        run.attempt == attempt,
        "the stored attempt {attempt} is not the run's current attempt {}",
        run.attempt
    );
    Ok((run, head))
}
