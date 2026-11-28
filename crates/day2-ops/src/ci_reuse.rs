//! `day2 ci reuse DIRECTORY CASES`: the org-scoped app CI workflow's second
//! step, after `day2 ci fetch DIRECTORY` and before `day2 ci check --reuse
//! DIRECTORY/reuse DIRECTORY/head CASES DIRECTORY/out`. A push run on main
//! looks for the result an earlier push run on main built and verified for the
//! same app source, so check can verify it again instead of building the app
//! and running its campaign:
//!
//! `gs://<project>-<app>-ci/<sdk>/<source inputs>-<cases>/<run>/<attempt>/`
//!
//! - **Only push runs.** A `pull_request` run never reuses: the command says
//!   so and succeeds without reading a store input, minting a token, reaching
//!   any service or writing anything.
//! - **Run.** `DIRECTORY/event.json` must be the step's own run, as `ci store`
//!   checks it, `DIRECTORY/reuse` must not exist yet, and the job token
//!   (`GITHUB_TOKEN`) and the store inputs must be present and the run's.
//! - **Key.** The store inputs' SDK (`DAY2_CI_SDK`), the source inputs of
//!   `DIRECTORY/head/app`, recomputed as check and store compute them, and
//!   CASES, the instance's verification cases the check step is rendered with.
//! - **Trust.** A stored entry's key and receipt were written by its own run's
//!   `ci store` from a directory the check step's app code could rewrite, so
//!   neither proves which source the result is for. A result is reused only
//!   when the forge binds it: the stored attempt is the current, successful
//!   attempt of a scoped app CI push run on main, and the forge's archive of
//!   that run's own commit has exactly this run's `app/` source inputs, as a
//!   deploy binds its own commit's archive to the receipt it reads. The run
//!   must also have run this run's `<org>/day2-ci` workflow commit, whose
//!   rendered workflow fixed the key's SDK and cases: its own create-only
//!   upload then took exactly the name it is found under.
//! - **Custody**, per stored attempt, newest run first, at most
//!   [`CANDIDATES`], as `ops/CiReuse.roc` orders the steps: `candidate` (the
//!   forge's record of that run: app CI's scoped verification run of a push
//!   to main of this run's workflow commit, its current attempt the stored
//!   one, terminal and successful, not this run), `source` (the forge's archive of that run's commit, whose
//!   `app/` source inputs must be the key's), `receipt` (this attempt's
//!   metadata and creation window, a complete run's receipt for the key's
//!   inputs and cases, seed 42 and `DAY2_CI_DISTRIBUTION`), `artifact` and
//!   `download` (the receipt's archive) and `attempt` (the run read again is
//!   the same attempt). The object, receipt, archive and re-read checks are
//!   the deploy reader's own ([`app_ci`]). Unlike a deploy, reuse does not
//!   require the newest run of a commit, and it takes the CI repository's ID
//!   from this run's own scoped record: the job token reads only its own
//!   repository.
//! - **Credential.** git-oidc and Google STS, as `ci store` mints and
//!   exchanges, but for `devstorage.read_only`: the push identity's object
//!   read access, which includes listing.
//! - **Deadline.** The lookup ends [`BUDGET`] after it starts. Every forge,
//!   git-oidc, STS and bucket request, downloads included, is bounded by the
//!   time left as well as by its own deadline, and retries end there too.
//! - **Misses and failures.** Absence under the key, every candidate refused,
//!   a read that stayed transient, the deadline, a refused mint or exchange
//!   (which store fails on itself; recorded by step, never by provider text)
//!   and a listing reply the bucket's contents shaped (too large, undecodable,
//!   a name outside the key) are recorded as why nothing was reused, and the
//!   command succeeds, so check builds the app. A stored
//!   attempt refused by a custody check or by a non-transient read refuses
//!   only that attempt. Misconfiguration fails the command (exit 6): an
//!   unusable request, run record or directory, a missing or invalid input,
//!   this run's own forge record refused or not app CI's or without its
//!   workflow commit, or a listing GCS refuses outright (401, 403, 404).
//! - **Output.** For a push run, `DIRECTORY/reuse/` (0700) with `reuse.json`
//!   ([`Record`]) written last and, when a result was reused, its
//!   `app.tar.gz` and its `receipt.json`, the stored bytes.
use crate::{
    ci_check::{Receipt as Checked, SEED},
    ci_fetch::{self, Environment, Event, Waiting, retrying_within, transient},
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
/// The whole lookup's deadline, from when it starts: every request is
/// bounded by the time left, and a step that would begin later misses.
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
    /// The next stored attempt, at one of its custody steps.
    Candidate(Custody),
    Done,
}

/// A stored attempt's custody steps, in `ops/CiReuse.roc`'s order: the deploy
/// reader's run, source binding, receipt, artifact, download and re-read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Custody {
    Run,
    Source,
    Receipt,
    Artifact,
    Download,
    Attempt,
}

impl Custody {
    fn name(self) -> &'static str {
        match self {
            Self::Run => "candidate",
            Self::Source => "source",
            Self::Receipt => "receipt",
            Self::Artifact => "artifact",
            Self::Download => "download",
            Self::Attempt => "attempt",
        }
    }

    fn next(self) -> Option<Self> {
        match self {
            Self::Run => Some(Self::Source),
            Self::Source => Some(Self::Receipt),
            Self::Receipt => Some(Self::Artifact),
            Self::Artifact => Some(Self::Download),
            Self::Download => Some(Self::Attempt),
            Self::Attempt => None,
        }
    }
}

/// What the current stored attempt's custody steps found so far.
#[derive(Default)]
struct Examined {
    run: Option<app_ci::Run>,
    /// The commit that run checked.
    head: Option<String>,
    receipt: Option<(Stored, Vec<u8>, Checked)>,
    artifact: Option<Stored>,
    archive: Option<Vec<u8>>,
}

/// A stored attempt that passed custody, and its bytes.
struct Found {
    source: Source,
    receipt: Vec<u8>,
    archive: Vec<u8>,
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
    /// The `<org>/day2-ci` commit whose workflow this run runs, as the forge
    /// records it. That rendered workflow fixes each app's SDK, tooling
    /// distribution and cases, so only a run of the same commit stored under
    /// this key by its own workflow.
    workflow_commit: Option<String>,
    /// When the lookup ends, on the session's clock.
    deadline: Duration,
    stage: Stage,
    finished: bool,
    missed: Option<String>,
    subject: Option<String>,
    storage: Option<Box<dyn Storage>>,
    listed: u64,
    candidates: Vec<(u64, u64)>,
    examined: Examined,
    tried: Vec<Tried>,
    found: Option<Found>,
}

impl Session {
    /// Validate the request, the run's record against the step's run and, for
    /// a push run, the job token, the inputs and the key. Nothing leaves the
    /// host. Anything missing or invalid fails: it is misconfiguration.
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
        let deadline = effects.waiting.now() + BUDGET;
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
            workflow_commit: None,
            deadline,
            stage: Stage::Done,
            finished: false,
            missed: None,
            subject: None,
            storage: None,
            listed: 0,
            candidates: Vec::new(),
            examined: Examined::default(),
            tried: Vec::new(),
            found: None,
        };
        if !push {
            session.missed = Some(PULL_REQUEST.to_owned());
            return Ok(session);
        }
        session.keyed()?;
        session.stage = Stage::Run;
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

    /// Whether to look: a push run.
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
            Stage::Candidate(custody) => custody.name(),
            Stage::Done => "result",
        })
    }

    /// The time left before the lookup's deadline.
    fn left(&mut self) -> Duration {
        self.deadline.saturating_sub(self.effects.waiting.now())
    }

    /// The lookup ends with nothing reused, for `reason`.
    fn miss(&mut self, reason: String) {
        self.missed = Some(reason);
        self.examined = Examined::default();
        self.stage = Stage::Done;
    }

    /// The current stored attempt.
    fn current(&self) -> Result<(u64, u64)> {
        self.candidates
            .get(self.tried.len())
            .copied()
            .context("no stored attempt is left")
    }

    /// The current stored attempt is refused for `reason`; the next is tried,
    /// or, after the last, the lookup misses.
    fn refuse(&mut self, reason: String) -> Result<()> {
        let (run, attempt) = self.current()?;
        self.tried.push(Tried {
            run,
            attempt,
            accepted: false,
            reason: Some(reason),
        });
        self.examined = Examined::default();
        if self.tried.len() == self.candidates.len() {
            self.miss(format!(
                "custody refused every stored result tried under this key ({})",
                self.tried.len()
            ));
        } else {
            self.stage = Stage::Candidate(Custody::Run);
        }
        Ok(())
    }

    /// Run the next step, which must be `name`. A step that fails transiently
    /// (after its retries, or at the deadline), or a refused mint or exchange,
    /// ends the lookup with nothing reused; a stored attempt's custody step
    /// that fails otherwise refuses only that attempt. This run's own record
    /// or the listing refused outright is misconfiguration: the step fails.
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
        let stage = self.stage;
        let mut refused = false;
        if self.left().is_zero() {
            self.note(
                stage,
                &format!(
                    "the lookup's {} s deadline passed before {step}",
                    BUDGET.as_secs()
                ),
            );
        } else {
            let outcome = match stage {
                Stage::Run => self.run(),
                Stage::Mint => self.mint(),
                Stage::Exchange => self.exchange(),
                Stage::List => self.list(),
                Stage::Candidate(custody) => self.custody(custody),
                Stage::Done => bail!("the lookup has ended"),
            };
            if let Err(error) = outcome {
                match stage {
                    Stage::Candidate(_) if !transient(&error) => {
                        self.refuse(format!("{error:#}"))?;
                        refused = true;
                    }
                    Stage::Run if !transient(&error) => {
                        return Err(error.context(
                            "ci reuse could not bind this run's own forge record: the job token, \
                             its actions: read permission or the run is misconfigured",
                        ));
                    }
                    // Only the bucket refusing the push identity is a
                    // misconfiguration. A reply the bucket's contents shape
                    // (too large, undecodable, a name outside the key) is
                    // something any writer could cause, so it is a miss.
                    Stage::List if access_refused(&error) => {
                        return Err(error.context(
                            "ci reuse could not list its key in the results bucket: the push \
                             identity's read access or the bucket is misconfigured",
                        ));
                    }
                    _ => {
                        // git-oidc's and STS's refusals carry provider text,
                        // which a record never keeps: only the step is named.
                        let detail = match stage {
                            Stage::Mint => "git-oidc did not mint this run's token".to_owned(),
                            Stage::Exchange => {
                                "Google STS did not exchange this run's token".to_owned()
                            }
                            _ => format!("{error:#}"),
                        };
                        let reason = if self.left().is_zero() {
                            format!(
                                "the lookup's {} s deadline passed during {step}: {detail}",
                                BUDGET.as_secs()
                            )
                        } else {
                            detail
                        };
                        self.note(stage, &reason);
                    }
                }
            }
        }
        let missed = self.stage == Stage::Done && self.found.is_none();
        Ok(match stage {
            Stage::List => json!({"missed": missed, "candidates": self.candidates.iter()
                .map(|(run, attempt)| json!({"run": run, "attempt": attempt})).collect::<Vec<_>>()}),
            Stage::Candidate(_) => json!({"missed": missed, "refused": refused}),
            _ => json!({"missed": missed}),
        })
    }

    /// The lookup misses for `reason`, which a stored attempt being examined
    /// also records as its own.
    fn note(&mut self, stage: Stage, reason: &str) {
        if let (Stage::Candidate(_), Ok((run, attempt))) = (stage, self.current()) {
            self.tried.push(Tried {
                run,
                attempt,
                accepted: false,
                reason: Some(reason.to_owned()),
            });
        }
        self.miss(reason.to_owned());
    }

    fn inputs(&self) -> Result<&Inputs> {
        self.inputs.as_ref().context("the reuse inputs")
    }

    /// One read from the run's own repository with the job token, retried
    /// while it fails transiently, each request and the retries bounded by
    /// the time left.
    fn forge<T>(&mut self, what: &str, read: impl Fn(&mut Forge<'_>) -> Result<T>) -> Result<T> {
        let limit = self.left();
        let effects = &mut self.effects;
        let transport = &mut effects.transport;
        let token = self.token.as_deref();
        let (server, repository) = (&self.server, &self.event.repository);
        retrying_within(effects.waiting.as_mut(), what, limit, |left| {
            read(&mut Forge::new(transport.as_mut(), token, server, repository).within(left))
        })
    }

    /// A JSON read below the repository's API prefix.
    fn forge_json(&mut self, path: &str) -> Result<Value> {
        self.forge("a forge read", |forge| {
            let url = format!("{}{path}", forge.prefix);
            forge.json(&url)
        })
    }

    /// run: the forge's record of this run names the CI repository, as a
    /// scoped run of `<org>/day2-ci`'s verification workflow for this push.
    fn run(&mut self) -> Result<()> {
        let event = self.event.clone();
        let record = self.forge_json(&format!("/actions/runs/{}", event.run))?;
        let org = event.repository.split('/').next().unwrap_or_default();
        let source = format!("{org}/day2-ci");
        let source_id = record
            .get("workflow_repository_id")
            .and_then(instance_source::proof_id)
            .context("the forge names no workflow repository for this run")?;
        app_ci::identity(&record, source_id, &source, &json!(event.repository_id))?;
        let workflow_commit = record
            .get("workflow_commit_sha")
            .and_then(Value::as_str)
            .filter(|commit| ci_fetch::canonical(commit))
            .context("the forge names no workflow commit for this run")?
            .to_owned();
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
        self.workflow_commit = Some(workflow_commit);
        self.stage = Stage::Mint;
        Ok(())
    }

    /// mint: git-oidc's token for the audience, as `ci store` mints it.
    fn mint(&mut self) -> Result<()> {
        let within = Some(self.left());
        let inputs = self.inputs.as_ref().context("the reuse inputs")?;
        let subject = ci_store::mint(
            &self.effects.client,
            self.effects.waiting.as_mut(),
            inputs,
            within,
        )?;
        self.subject = Some(subject);
        self.stage = Stage::Exchange;
        Ok(())
    }

    /// exchange: Google STS's federated token, read only.
    fn exchange(&mut self) -> Result<()> {
        let within = Some(self.left());
        let subject = self.subject.take().context("the minted token")?;
        let access = ci_store::exchange(
            &self.effects.client,
            &self.effects.sts,
            self.inputs()?,
            &subject,
            SCOPE,
            within,
        )?;
        self.storage = Some((self.effects.storage)(access)?);
        self.stage = Stage::List;
        Ok(())
    }

    /// list: every name under the key, at most [`PAGES`] pages; each
    /// `<run>/<attempt>/receipt.json`, the commit marker `ci store` writes
    /// last, is a stored attempt. The newest [`CANDIDATES`] are tried. A key
    /// with more pages, or with none, is a miss.
    fn list(&mut self) -> Result<()> {
        let key = self.key.clone().context("the key")?;
        let bucket = self.inputs()?.bucket.clone();
        let mut attempts = BTreeSet::new();
        let mut page: Option<String> = None;
        for _ in 0..PAGES {
            let limit = self.left();
            let storage = self.storage.as_mut().context("the results bucket")?;
            let listing = retrying_within(
                self.effects.waiting.as_mut(),
                "a results listing",
                limit,
                |left| storage.list(&bucket, &key, page.as_deref(), Some(left)),
            )?;
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
        if page.is_some() {
            self.miss(format!(
                "the key holds more than {PAGES} pages of results, more than the lookup reads"
            ));
            return Ok(());
        }
        self.listed = attempts.len() as u64;
        self.candidates = attempts.into_iter().rev().take(CANDIDATES).collect();
        if self.candidates.is_empty() {
            self.miss(ABSENT.to_owned());
        } else {
            self.stage = Stage::Candidate(Custody::Run);
        }
        Ok(())
    }

    /// One custody step of the current stored attempt; on success, the next.
    /// The last accepts the attempt.
    fn custody(&mut self, custody: Custody) -> Result<()> {
        match custody {
            Custody::Run => self.candidate_run()?,
            Custody::Source => self.candidate_source()?,
            Custody::Receipt => self.candidate_receipt()?,
            Custody::Artifact => self.candidate_artifact()?,
            Custody::Download => self.candidate_download()?,
            Custody::Attempt => self.candidate_attempt()?,
        }
        if let Some(next) = custody.next() {
            self.stage = Stage::Candidate(next);
        }
        Ok(())
    }

    fn object(&mut self, bucket: &str, name: &str) -> Result<Option<Stored>> {
        let limit = self.left();
        let storage = self.storage.as_mut().context("the results bucket")?;
        retrying_within(
            self.effects.waiting.as_mut(),
            "a results read",
            limit,
            |left| storage.object(bucket, name, Some(left)),
        )
    }

    fn media(&mut self, bucket: &str, name: &str, stored: &Stored) -> Result<Vec<u8>> {
        let limit = self.left();
        let storage = self.storage.as_mut().context("the results bucket")?;
        retrying_within(
            self.effects.waiting.as_mut(),
            "a results download",
            limit,
            |left| storage.media(bucket, name, &stored.generation, stored.size, Some(left)),
        )
    }

    /// `<key><run>/<attempt>/<file>` for the current stored attempt.
    fn object_name(&self, file: &str) -> Result<String> {
        let (run, attempt) = self.current()?;
        Ok(format!(
            "{}{run}/{attempt}/{file}",
            self.key.as_deref().context("the key")?
        ))
    }

    fn examined_run(&self) -> Result<(app_ci::Run, String)> {
        Ok((
            self.examined
                .run
                .clone()
                .context("the stored attempt's run")?,
            self.examined
                .head
                .clone()
                .context("the stored attempt's commit")?,
        ))
    }

    /// candidate: the next stored attempt's run, as the forge reports it by
    /// ID ([`candidate`]); never this run.
    fn candidate_run(&mut self) -> Result<()> {
        let (id, attempt) = self.current()?;
        ensure!(id != self.event.run, "it is this run's own result");
        let (source_id, source) = self.source.clone().context("the CI repository")?;
        let record = self.forge_json(&format!("/actions/runs/{id}"))?;
        let (run, head) = candidate(
            &record,
            id,
            attempt,
            source_id,
            &source,
            &json!(self.event.repository_id),
        )?;
        // The key's SDK and cases are only the stored receipt's claim. A run of
        // the same workflow commit was rendered with this run's SDK, tooling
        // distribution and cases, so its own upload took exactly this name:
        // one planted here for it would have collided with it.
        ensure!(
            Some(&run.workflow_commit) == self.workflow_commit.as_ref(),
            "app CI ran it from another <org>/day2-ci workflow commit than this run's"
        );
        self.examined = Examined {
            run: Some(run),
            head: Some(head),
            ..Examined::default()
        };
        Ok(())
    }

    /// source: the forge's archive of the run's own commit, read as fetch
    /// and deploy read one, must have exactly this run's `app/` source inputs,
    /// computed by the function deploy binds a commit's archive with. The
    /// key and the receipt alone are the stored run's own claims.
    fn candidate_source(&mut self) -> Result<()> {
        let (_, head) = self.examined_run()?;
        let archive = self.forge("a forge archive read", |forge| forge.archive(&head))?;
        let inputs = crate::instance_candidate::source_inputs(&archive, ci_fetch::APP)
            .context("the forge's archive of the run's commit")?;
        ensure!(
            Some(&inputs) == self.head.as_ref(),
            "the forge's archive of the run's commit {head} has other app/ source inputs than \
             this run's"
        );
        Ok(())
    }

    /// receipt: this attempt's, created during it, a complete run's for the
    /// key's source inputs and cases, seed 42 and `DAY2_CI_DISTRIBUTION`.
    fn candidate_receipt(&mut self) -> Result<()> {
        let (run, head) = self.examined_run()?;
        let (bucket, distribution) = {
            let inputs = self.inputs()?;
            (inputs.bucket.clone(), inputs.distribution.clone())
        };
        let name = self.object_name(app_ci::RECEIPT)?;
        let stored = self
            .object(&bucket, &name)?
            .context("its receipt is no longer stored")?;
        app_ci::receipt_object(&stored, &run, &head)?;
        let bytes = self.media(&bucket, &name, &stored)?;
        let checked = app_ci::decoded_receipt(&bytes)?;
        let inputs = self.head.clone().context("the head's source inputs")?;
        app_ci::binds(
            &checked,
            &inputs,
            &json!({"version": 1, "seed": SEED, "cases": self.cases}),
        )?;
        ensure!(
            checked.sdk_distribution.digest == distribution,
            "app CI checked the artifact on another SDK's tooling distribution"
        );
        self.examined.receipt = Some((stored, bytes, checked));
        Ok(())
    }

    /// artifact: this attempt's, created during it, the receipt's size.
    fn candidate_artifact(&mut self) -> Result<()> {
        let (run, head) = self.examined_run()?;
        let bucket = self.inputs()?.bucket.clone();
        let expected = self
            .examined
            .receipt
            .as_ref()
            .context("the stored receipt")?
            .2
            .archive
            .clone();
        let name = self.object_name(app_ci::ARTIFACT)?;
        let stored = self
            .object(&bucket, &name)?
            .context("its artifact is no longer stored")?;
        app_ci::artifact_object(&stored, &run, &head, &expected)?;
        self.examined.artifact = Some(stored);
        Ok(())
    }

    /// download: the artifact's bytes at that generation, the receipt's
    /// archive.
    fn candidate_download(&mut self) -> Result<()> {
        let bucket = self.inputs()?.bucket.clone();
        let stored = self
            .examined
            .artifact
            .clone()
            .context("the stored artifact")?;
        let expected = self
            .examined
            .receipt
            .as_ref()
            .context("the stored receipt")?
            .2
            .archive
            .clone();
        let name = self.object_name(app_ci::ARTIFACT)?;
        let archive = self.media(&bucket, &name, &stored)?;
        app_ci::archive(&archive, &expected)?;
        self.examined.archive = Some(archive);
        Ok(())
    }

    /// attempt: the run read again is still the same successful attempt of
    /// the same commit; only then is the stored attempt accepted.
    fn candidate_attempt(&mut self) -> Result<()> {
        let (run, head) = self.examined_run()?;
        let (id, attempt) = self.current()?;
        let (source_id, source) = self.source.clone().context("the CI repository")?;
        let latest = self.forge_json(&format!("/actions/runs/{id}"))?;
        app_ci::unchanged(
            &latest,
            &head,
            source_id,
            &source,
            &json!(self.event.repository_id),
            &run,
        )?;
        let bucket = self.inputs()?.bucket.clone();
        let receipt_name = self.object_name(app_ci::RECEIPT)?;
        let artifact_name = self.object_name(app_ci::ARTIFACT)?;
        let examined = std::mem::take(&mut self.examined);
        let (receipt, bytes, _) = examined.receipt.context("the stored receipt")?;
        let artifact = examined.artifact.context("the stored artifact")?;
        let archive = examined.archive.context("the downloaded artifact")?;
        self.tried.push(Tried {
            run: id,
            attempt,
            accepted: true,
            reason: None,
        });
        self.found = Some(Found {
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
        });
        self.stage = Stage::Done;
        Ok(())
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
/// Whether the results bucket refused the request outright: 401, 403 or 404.
fn access_refused(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.to_string().as_str(),
            "app_ci_results_http_401" | "app_ci_results_http_403" | "app_ci_results_http_404"
        )
    })
}

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
