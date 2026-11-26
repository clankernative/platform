//! `day2 ci fetch DIRECTORY`: the first step of the org-scoped app CI
//! workflow. It reads the Gitea Actions environment and the event the job
//! runs for, checks them against the forge with the job's own token, and
//! writes `DIRECTORY/head` (the head tree), `DIRECTORY/base` (a pull request's
//! merge base tree) and `DIRECTORY/event.json` (one exact record of the run).
//! `day2 ci check DIRECTORY/head [DIRECTORY/base] CASES DIRECTORY/out` then
//! reads only local trees, and `day2 ci store DIRECTORY` stores its artifact.
//!
//! - **Events.** `pull_request` checks the pull request's head commit against
//!   its merge base, as the app repositories' earlier routing did (`git
//!   merge-base` of the base and head commits); the event names the merge
//!   base Gitea computed (`pull_request.merge_base`), so no pull request
//!   permission is needed. The head repository must be the base repository: a
//!   fork's pull request is refused. `push` is accepted only on `refs/heads/main`, without a
//!   base, so every lane runs. Any other event is refused.
//! - **Trees.** Each is the commit's Gitea archive, read through
//!   `instance_source::Forge::archive`, the read deploy uses, and unpacked by
//!   `instance_candidate::unpack` with deploy's refusals, so the head tree's
//!   `app/` has the source inputs deploy computes from the same archive.
//! - **Token.** The job token is read from `GITHUB_TOKEN`, which the workflow
//!   sets for this step alone, and is sent only to the job's own forge. It is
//!   never printed. A read that fails transiently (a failed connection, HTTP
//!   408, 429 or 5xx) is retried with git-oidc's wait policy ([`retrying`]).
use crate::instance_source::{self, Clock, Forge, System, Transport};
use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fmt, fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(test)]
mod tests;

/// The one variable the job token is read from.
pub const TOKEN: &str = "GITHUB_TOKEN";
/// The only branch a push run checks.
pub const MAIN: &str = "refs/heads/main";
/// The app's directory in its repository, which deploy's source inputs cover.
pub const APP: &str = day2::app_capture::ROOT;
/// The run record `DIRECTORY/event.json`.
pub const EVENT_FILE: &str = "event.json";
/// How long one read keeps retrying a transient failure.
pub const DEADLINE: Duration = Duration::from_secs(120);
const REQUEST_LIMIT: u64 = 65_536;

/// The Gitea Actions variables a run is described by. Each is required except
/// the workflow commit, which a runner may not export.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Environment {
    /// `GITHUB_EVENT_NAME`.
    pub event_name: String,
    /// `GITHUB_EVENT_PATH`: the event payload the runner wrote.
    pub event_path: PathBuf,
    /// `GITHUB_REPOSITORY`: the consuming app repository, `<org>/<app>`.
    pub repository: String,
    /// `GITHUB_SERVER_URL`, without a final slash.
    pub server: String,
    /// `GITHUB_SHA`: the commit the run checks.
    pub sha: String,
    /// `GITHUB_RUN_ID`.
    pub run: u64,
    /// `GITHUB_RUN_ATTEMPT`.
    pub attempt: u64,
    /// `GITHUB_WORKFLOW_SHA`: the commit of the scoped workflow's definition,
    /// when the runner exports it.
    pub workflow_sha: Option<String>,
}

impl Environment {
    /// The variables, read through `variable` (the process environment in
    /// production). A value is never echoed in a refusal.
    pub fn read(variable: impl Fn(&str) -> Option<OsString>) -> Result<Self> {
        let text = |name: &str| -> Result<Option<String>> {
            match variable(name).filter(|value| !value.is_empty()) {
                Some(value) => Ok(Some(
                    value
                        .into_string()
                        .map_err(|_| anyhow!("{name} must be UTF-8"))?,
                )),
                None => Ok(None),
            }
        };
        let required =
            |name: &str| text(name)?.with_context(|| format!("{name} is required in a CI run"));
        let count = |name: &str| -> Result<u64> {
            required(name)?
                .parse::<u64>()
                .ok()
                .filter(|value| *value > 0)
                .with_context(|| format!("{name} must be a positive integer"))
        };
        // Gitea's server URL is its app URL, which ends in a slash.
        let server = required("GITHUB_SERVER_URL")?;
        let environment = Self {
            event_name: required("GITHUB_EVENT_NAME")?,
            event_path: PathBuf::from(required("GITHUB_EVENT_PATH")?),
            repository: required("GITHUB_REPOSITORY")?,
            server: server.strip_suffix('/').unwrap_or(&server).to_owned(),
            sha: required("GITHUB_SHA")?,
            run: count("GITHUB_RUN_ID")?,
            attempt: count("GITHUB_RUN_ATTEMPT")?,
            workflow_sha: text("GITHUB_WORKFLOW_SHA")?,
        };
        environment.validate()?;
        Ok(environment)
    }

    fn validate(&self) -> Result<()> {
        let app = app_repository(&self.repository)
            .context("GITHUB_REPOSITORY must be an app repository, <org>/<app id>")?;
        instance_source::validate_forge(&self.server, app.0)
            .context("GITHUB_SERVER_URL must be the forge's https origin")?;
        ensure!(
            canonical(&self.sha),
            "GITHUB_SHA must be a full lowercase commit"
        );
        ensure!(
            self.workflow_sha.as_deref().is_none_or(canonical),
            "GITHUB_WORKFLOW_SHA must be a full lowercase commit"
        );
        ensure!(
            self.event_path.is_absolute(),
            "GITHUB_EVENT_PATH must be absolute"
        );
        Ok(())
    }
}

/// A full lowercase commit that is not all zeros.
pub fn canonical(value: &str) -> bool {
    instance_source::commit(value) && value != "0".repeat(40)
}

/// An app ID as InstanceSpec (Names.AppId) accepts one: 2 to 20 lowercase
/// letters or digits, starting with a letter, never `tofu` or `day2...`.
pub fn app_id(id: &str) -> bool {
    (2..=20).contains(&id.len())
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !id.starts_with("day2")
        && id != "tofu"
}

/// An app repository's owner and app ID: `<org>/<id>`, the org lowercase and
/// the ID an [`app_id`], as InstanceSpec derives `<org>/<id>`.
pub fn app_repository(repository: &str) -> Option<(&str, &str)> {
    let (owner, id) = repository.split_once('/')?;
    let org = !owner.is_empty()
        && owner
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    (org && app_id(id)).then_some((owner, id))
}

/// What a run checks, from its event payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// A push to main: no base.
    Push,
    /// A same-repository pull request, by number, with the merge base Gitea
    /// computed for it.
    PullRequest { number: u64, base: String },
}

/// The event payload's trigger and repository ID, checked against the
/// environment before anything is read from the forge: the event is
/// `pull_request` or `push`, the payload's repository is the run's, a push is
/// to main at the run's commit, and a pull request's head is the run's commit
/// in the base repository itself, with a merge base.
pub fn trigger(environment: &Environment, payload: &Value) -> Result<(Trigger, u64)> {
    let id = instance_source::proof_id;
    let repository = &payload["repository"];
    let repository_id = id(&repository["id"]).context("the event names no repository ID")?;
    ensure!(
        repository["full_name"] == environment.repository.as_str(),
        "the event's repository is not GITHUB_REPOSITORY"
    );
    match environment.event_name.as_str() {
        "push" => {
            ensure!(
                payload["ref"] == MAIN,
                "app CI checks a push only to {MAIN}"
            );
            ensure!(
                payload["after"] == environment.sha.as_str(),
                "the push event's commit is not GITHUB_SHA"
            );
            Ok((Trigger::Push, repository_id))
        }
        "pull_request" => {
            let pull = &payload["pull_request"];
            let number = id(&pull["number"]).context("the event names no pull request")?;
            ensure!(
                pull["head"]["sha"] == environment.sha.as_str(),
                "the pull request event's head is not GITHUB_SHA"
            );
            // A fork's pull request, or one whose head repository is gone.
            ensure!(
                id(&pull["head"]["repo_id"]) == Some(repository_id)
                    && id(&pull["base"]["repo_id"]) == Some(repository_id),
                "app CI refuses a pull request from another repository"
            );
            let base = pull["merge_base"]
                .as_str()
                .filter(|base| canonical(base))
                .context("the pull request event names no merge base")?
                .to_owned();
            Ok((Trigger::PullRequest { number, base }, repository_id))
        }
        _ => bail!("app CI runs only for pull_request and push events"),
    }
}

/// `DIRECTORY/event.json`: the run `day2 ci store` records and stores under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub format: u32,
    /// `<org>/<app id>`.
    pub repository: String,
    pub repository_id: u64,
    /// `pull_request` or `push`.
    pub event: String,
    pub head: String,
    /// A pull request's merge base; a push has none.
    pub base: Option<String>,
    pub pull_request: Option<u64>,
    pub run: u64,
    pub attempt: u64,
    /// The scoped workflow definition's commit, when the runner exports it.
    pub workflow_commit: Option<String>,
}

impl Event {
    /// The record is exact: format 1, an app repository, a push without a base
    /// or pull request, a pull request with both, and full commits.
    pub fn validate(&self) -> Result<()> {
        let shaped = match self.event.as_str() {
            "push" => self.base.is_none() && self.pull_request.is_none(),
            "pull_request" => {
                self.base.as_deref().is_some_and(canonical)
                    && self.pull_request.is_some_and(|number| number > 0)
            }
            _ => false,
        };
        ensure!(
            self.format == 1
                && app_repository(&self.repository).is_some()
                && self.repository_id > 0
                && canonical(&self.head)
                && shaped
                && self.run > 0
                && self.attempt > 0
                && self.workflow_commit.as_deref().is_none_or(canonical),
            "invalid CI event record"
        );
        Ok(())
    }

    /// The app ID the repository is named for.
    pub fn app(&self) -> &str {
        app_repository(&self.repository).map_or("", |(_, app)| app)
    }

    /// `DIRECTORY/event.json`, exactly, at most 64 KiB.
    pub fn read(directory: &Path) -> Result<Self> {
        let path = directory.join(EVENT_FILE);
        let bytes = day2_assets::read_regular(&path, REQUEST_LIMIT)
            .with_context(|| format!("read {}", path.display()))?;
        let event: Self = day2::json::decode(&bytes).context("invalid CI event record")?;
        event.validate()?;
        Ok(event)
    }

    /// Created exclusively and synced, as the source adapter writes a new file.
    fn write(&self, directory: &Path) -> Result<()> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        instance_source::write_new(&directory.join(EVENT_FILE), &bytes)
    }
}

/// A failure another attempt may cure.
#[derive(Debug)]
pub struct Transient(pub String);

impl fmt::Display for Transient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for Transient {}

pub(crate) fn transient(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<Transient>().is_some()
            || cause.downcast_ref::<instance_source::Retryable>().is_some()
    })
}

/// Time and chance for [`retrying`]: the source adapter's clock, and jitter.
/// Tests substitute a fake.
pub trait Waiting: Clock {
    /// A uniform integer from 0 to `most`.
    fn jitter(&mut self, most: u64) -> u64;
}

/// The monotonic clock, real sleeps and stderr, with the system's randomness.
impl Waiting for System {
    fn jitter(&mut self, most: u64) -> u64 {
        use ring::rand::SecureRandom;
        let mut bytes = [0; 8];
        // Without randomness the pause is the shortest, never an error.
        if ring::rand::SystemRandom::new().fill(&mut bytes).is_err() {
            return 0;
        }
        u64::from_le_bytes(bytes) % (most + 1)
    }
}

/// The instance workflows' git-oidc wait, for any read: `attempt` gets the
/// time left before the 120 s deadline. A [`Transient`] or `Retryable` failure
/// is retried after `delay` plus a uniform jitter of up to `delay` seconds,
/// `delay` starting at 2 s and doubling to at most 16 s, while that pause and
/// 5 s more fit before the deadline; then the last failure is returned. Any
/// other failure returns at once.
pub fn retrying<T>(
    waiting: &mut dyn Waiting,
    what: &str,
    mut attempt: impl FnMut(Duration) -> Result<T>,
) -> Result<T> {
    let deadline = waiting.now() + DEADLINE;
    let mut delay = 2;
    let mut tries = 1;
    loop {
        let left = deadline.saturating_sub(waiting.now());
        let error = match attempt(left) {
            Ok(value) => return Ok(value),
            Err(error) if transient(&error) => error,
            Err(error) => return Err(error),
        };
        let pause = delay + waiting.jitter(delay);
        if waiting.now() + Duration::from_secs(pause + 5) > deadline {
            return Err(error.context(format!(
                "{what} did not succeed within {}s",
                DEADLINE.as_secs()
            )));
        }
        waiting.announce(&format!(
            "{what} failed transiently on attempt {tries} ({error:#}); retrying in {pause}s"
        ));
        waiting.sleep(Duration::from_secs(pause));
        delay = (delay * 2).min(16);
        tries += 1;
    }
}

/// What the session reaches outside itself.
pub struct Effects {
    pub transport: Box<dyn Transport>,
    pub waiting: Box<dyn Waiting>,
    pub environment: Environment,
    pub token: Option<String>,
}

impl Effects {
    /// The forge over HTTPS, the system clock, the process environment and
    /// `GITHUB_TOKEN`.
    pub fn native() -> Result<Self> {
        let token = match std::env::var_os(TOKEN).filter(|value| !value.is_empty()) {
            Some(value) => Some(
                value
                    .into_string()
                    .map_err(|_| anyhow!("{TOKEN} must be UTF-8"))?,
            ),
            None => None,
        };
        Ok(Self {
            transport: Box::new(instance_source::Native::new()?),
            waiting: Box::new(System::new()),
            environment: Environment::read(|name| std::env::var_os(name))?,
            token,
        })
    }
}

/// What the CLI hands the host.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub directory: PathBuf,
}

/// One tree the session wrote: its archive's identity and what it held.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tree {
    pub path: PathBuf,
    pub commit: String,
    pub archive: day2::sdk_release::BlobIdentity,
    pub files: u64,
    pub bytes: u64,
    pub directories: u64,
    pub links: u64,
}

/// What `day2 ci fetch` prints. cli/fixtures/ci-fetch-report.json pins the
/// shape for the host and the CLI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub format: u32,
    pub directory: PathBuf,
    pub event: Event,
    pub head: Tree,
    pub base: Option<Tree>,
    /// The head tree's app source inputs, as deploy computes them.
    pub source_inputs: String,
}

pub struct Session {
    directory: PathBuf,
    effects: Effects,
    trigger: Trigger,
    repository_id: u64,
    event: Option<Event>,
    done: Vec<&'static str>,
    head: Option<Tree>,
    base: Option<Tree>,
    inputs: Option<String>,
}

impl Session {
    /// Validate the request, the environment and the event payload, then create
    /// the new directory (0700) beside an existing parent. Nothing is read
    /// from the forge yet.
    pub fn prepare(path: &Path, effects: Effects) -> Result<Self> {
        let raw = day2_assets::read_regular(path, REQUEST_LIMIT)?;
        let request: Request = day2::json::decode(&raw)?;
        let directory = std::path::absolute(&request.directory)?;
        ensure!(
            effects.token.is_some(),
            "day2 ci fetch reads the forge with the job token in {TOKEN}"
        );
        let environment = &effects.environment;
        let payload =
            day2_assets::read_regular(&environment.event_path, instance_source::JSON_LIMIT)
                .context("read the event payload GITHUB_EVENT_PATH names")?;
        let payload = instance_source::decode(&payload).context("invalid event payload")?;
        let (trigger, repository_id) = trigger(environment, &payload)?;
        ensure!(
            fs::symlink_metadata(&directory).is_err(),
            "ci fetch requires a new directory: {}",
            directory.display()
        );
        ensure!(
            directory.parent().is_some_and(Path::is_dir),
            "the new directory's parent must exist: {}",
            directory.display()
        );
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        Ok(Self {
            directory,
            effects,
            trigger,
            repository_id,
            event: None,
            done: Vec::new(),
            head: None,
            base: None,
            inputs: None,
        })
    }

    /// The step that runs next: repository, event, head, then base for a pull
    /// request, then result.
    fn next(&self) -> Option<&'static str> {
        let mut steps = vec!["repository", "event", "head"];
        if matches!(self.trigger, Trigger::PullRequest { .. }) {
            steps.push("base");
        }
        steps.push("result");
        steps.get(self.done.len()).copied()
    }

    /// Run the next step, which must be `name`.
    pub fn step(&mut self, name: &str) -> Result<Value> {
        let expected = self.next();
        let Some(step) = expected.filter(|step| *step == name) else {
            bail!(
                "ci fetch runs {} next, not {name}",
                expected.unwrap_or("nothing more")
            );
        };
        let value = match step {
            "repository" => self.repository()?,
            "event" => self.event()?,
            "head" => self.head()?,
            "base" => self.base()?,
            _ => self.result()?,
        };
        self.done.push(step);
        Ok(value)
    }

    /// One read from the run's own repository with the job token, retried
    /// while it fails transiently.
    fn read<T>(&mut self, what: &str, read: impl Fn(&mut Forge<'_>) -> Result<T>) -> Result<T> {
        let effects = &mut self.effects;
        let mut forge = Forge::new(
            effects.transport.as_mut(),
            effects.token.as_deref(),
            &effects.environment.server,
            &effects.environment.repository,
        );
        retrying(effects.waiting.as_mut(), what, |_| read(&mut forge))
            .map_err(instance_source::reported)
    }

    /// The job token reads the repository the event names: its ID and name
    /// are the event's.
    fn repository(&mut self) -> Result<Value> {
        let repository = self.read("a forge read", |forge| {
            let prefix = forge.prefix.clone();
            forge.json(&prefix)
        })?;
        ensure!(
            instance_source::proof_id(&repository["id"]) == Some(self.repository_id)
                && repository["full_name"] == self.effects.environment.repository.as_str(),
            "the forge's repository is not the event's"
        );
        Ok(json!({"repository": self.effects.environment.repository, "id": self.repository_id}))
    }

    /// The run's record. A pull request's base is the merge base its event
    /// names: Gitea's own `git merge-base` of the base branch and the head.
    fn event(&mut self) -> Result<Value> {
        let environment = self.effects.environment.clone();
        let (base, pull_request) = match &self.trigger {
            Trigger::Push => (None, None),
            Trigger::PullRequest { number, base } => (Some(base.clone()), Some(*number)),
        };
        let event = Event {
            format: 1,
            repository: environment.repository.clone(),
            repository_id: self.repository_id,
            event: environment.event_name.clone(),
            head: environment.sha.clone(),
            base,
            pull_request,
            run: environment.run,
            attempt: environment.attempt,
            workflow_commit: environment.workflow_sha.clone(),
        };
        event.validate()?;
        let planned = json!({"base": event.base.is_some()});
        self.event = Some(event);
        Ok(planned)
    }

    /// One commit's archive, unpacked into `DIRECTORY/<name>`; the app's
    /// refusals apply only to the head, whose app is checked and deployed.
    fn tree(&mut self, name: &str, commit: &str, app: Option<&str>) -> Result<(Tree, Vec<u8>)> {
        let archive = self.read("a forge archive read", |forge| forge.archive(commit))?;
        let path = self.directory.join(name);
        let unpacked = crate::instance_candidate::unpack(&archive, app, &path)?;
        let tree = Tree {
            path,
            commit: commit.to_owned(),
            archive: day2::sdk_release::BlobIdentity::of(&archive),
            files: unpacked.files,
            bytes: unpacked.bytes,
            directories: unpacked.directories,
            links: unpacked.links,
        };
        Ok((tree, archive))
    }

    /// The head tree, and its app's source inputs as deploy computes them
    /// from the same archive.
    fn head(&mut self) -> Result<Value> {
        let commit = self.event.as_ref().context("the run's event")?.head.clone();
        let (tree, archive) = self.tree("head", &commit, Some(APP))?;
        let inputs = crate::instance_candidate::source_inputs(&archive, APP)?;
        let reported = json!({"files": tree.files, "source_inputs": inputs});
        self.inputs = Some(inputs);
        self.head = Some(tree);
        Ok(reported)
    }

    /// A pull request's merge base tree, for routing only.
    fn base(&mut self) -> Result<Value> {
        let commit = self
            .event
            .as_ref()
            .and_then(|event| event.base.clone())
            .context("the pull request's merge base")?;
        let (tree, _) = self.tree("base", &commit, None)?;
        let reported = json!({"files": tree.files});
        self.base = Some(tree);
        Ok(reported)
    }

    /// `DIRECTORY/event.json`, written last, and the report.
    fn result(&mut self) -> Result<Value> {
        let event = self.event.clone().context("the run's event")?;
        let head = self.head.clone().context("the head tree")?;
        ensure!(
            event.base.is_some() == self.base.is_some(),
            "a pull request's base tree is required"
        );
        event.write(&self.directory)?;
        Ok(serde_json::to_value(Report {
            format: 1,
            directory: self.directory.clone(),
            event,
            head,
            base: self.base.clone(),
            source_inputs: self.inputs.clone().context("the head's source inputs")?,
        })?)
    }
}
