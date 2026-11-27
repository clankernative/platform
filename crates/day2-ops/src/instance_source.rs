//! An instance's app sources on its Gitea forge, for `day2 instance source`:
//! a branch's head commit, a commit's archive, the CI-control digest of an
//! archive and its check against the instance's binding, and the checked
//! artifact the exact main commit's CI published, with its provenance. The CLI
//! renders the request from day2.json (the forge, its org, the registry, the
//! state bucket and each app's sdk and verification cases) and
//! InstanceSource.roc chooses the step order; this adapter validates the
//! request and the binding and refuses any step out of order.
//!
//! Value for value what the instance's existing deploy controller did, so a
//! proof either one wrote is valid to the other:
//! - Failures carry the controller's codes and messages. Only a transient read
//!   is retryable (HTTP 408, 429 or 5xx, a failed connection, a failed or short
//!   body read, a timeout, or the main run not finishing in time); the host
//!   reports it as `retryable: <code>` and the CLI exits 7. Every other refusal
//!   is permanent. Unlike the controller, a disconnect before the response
//!   headers or during a body is retryable: a network blip during a large
//!   download must not block a deployment until an operator steps in.
//! - Requests go only to the instance's forge (and, for an artifact ZIP, to the
//!   object storage it redirects to) and never follow a redirect. Each has one
//!   90 s window up to its response headers, then 90 s for each read of its
//!   bounded body. The forge token goes only to the forge itself, never to a
//!   redirect target other than the exact artifact's same-origin `/raw` route.
//! - The proof embeds the job log's receipt exactly as decoded, after it is
//!   validated: integers stay integers, booleans are not integers, and a
//!   duplicate key anywhere is refused.
//!
//! Neither provider-owned values nor the token ever appear in a failure.
use crate::instance_release;
use anyhow::{Context, Result, anyhow, bail, ensure};
use day2::sdk_release::{self, BlobIdentity, MANIFEST_LIMIT, Release};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fmt, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// Every JSON response and decoded document, as deployment_events.decode.
pub const JSON_LIMIT: u64 = 1_048_576;
/// A Gitea source archive.
pub const ARCHIVE_LIMIT: u64 = 64 << 20;
/// A native CI job's log.
pub const LOG_LIMIT: u64 = 8 << 20;
/// A checked app archive, ci_artifact.LIMIT.
pub const ARTIFACT_LIMIT: u64 = 128 << 20;
/// The ZIP Gitea serves a checked app archive in.
pub const ZIP_LIMIT: u64 = ARTIFACT_LIMIT + (2 << 20);
/// reqwest's blocking timeout: one window from connecting until the response
/// headers arrive, then again for each read of the body.
pub const TIMEOUT: Duration = Duration::from_secs(90);
/// How long one job waits for the exact main commit's CI to finish.
pub const WAIT: Duration = Duration::from_secs(2100);
/// The longest pause between two reads of the main runs.
pub const POLL: Duration = Duration::from_secs(20);
/// What the host prefixes a retryable failure's code with.
pub const RETRYABLE: &str = "retryable: ";
/// Printed once, to stderr, when the main run is not finished yet.
pub const WAITING: &str = "Waiting for the exact main commit's checked artifact";
/// The CI controls every app's archive must contain.
pub const CONTROLS: [&str; 5] = [
    ".ci/platform-release.json",
    ".ci/publish_artifact.py",
    ".ci/roc.json",
    ".ci/sdk_release.py",
    ".gitea/workflows/roc.yml",
];
/// App-owned control data: inventoried, never part of the digest.
const APP_CONTROL: &str = ".ci/roc.json";
pub(crate) const TEMPORARY: &str = "source_temporarily_unavailable";
pub(crate) const NOT_READY: &str = "checked_main_artifact_not_ready";
const MARKER: &str = "DAY2_CHECKED_APP_V1 ";
const WORKFLOW: &str = "roc.yml";
const JOB: &str = "roc";
const ARTIFACT_FILE: &[u8] = b"app.tar.gz";
const REQUEST_LIMIT: u64 = 65_536;
pub(crate) const ENTRY_LIMIT: usize = 8192;
pub(crate) const MEMBER_LIMIT: u64 = 16 << 20;
const CONTROL_LIMIT: u64 = 2 << 20;
const PROOF_LIMIT: u64 = 1 << 63;

/// The command a session runs; the host's action fixes it.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Head,
    Archive,
    Controls,
    VerifyControls,
    CheckedArtifact,
}

impl Mode {
    pub const ALL: [Self; 5] = [
        Self::Head,
        Self::Archive,
        Self::Controls,
        Self::VerifyControls,
        Self::CheckedArtifact,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Head => "head",
            Self::Archive => "archive",
            Self::Controls => "controls",
            Self::VerifyControls => "verify-controls",
            Self::CheckedArtifact => "checked-artifact",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.name() == name)
    }

    /// The steps a session runs, in order; the last returns the receipt.
    pub fn steps(self) -> &'static [&'static str] {
        match self {
            Self::Head => &["head"],
            Self::Archive => &["archive"],
            Self::Controls => &["controls"],
            Self::VerifyControls => &["controls", "release"],
            Self::CheckedArtifact => &["run", "job", "artifact", "download", "attempt"],
        }
    }
}

/// A transient read failure, deployment_events.RetryableFailure: the caller
/// may retry the deployment later. Its text is Python's code.
#[derive(Debug)]
pub struct Retryable(pub &'static str);

impl fmt::Display for Retryable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for Retryable {}

/// What the host reports for a failed step: a retryable failure anywhere in
/// the chain becomes exactly `retryable: <code>`; anything else is unchanged.
pub fn reported(error: anyhow::Error) -> anyhow::Error {
    match error
        .chain()
        .find_map(|cause| cause.downcast_ref::<Retryable>())
    {
        Some(Retryable(code)) => anyhow!("{RETRYABLE}{code}"),
        None => error,
    }
}

/// One response. A redirect or other non-2xx response has no body.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub location: Option<String>,
    pub body: Vec<u8>,
}

/// HTTP GET with closed semantics. Tests substitute a fake.
pub trait Transport {
    /// GET `url` with `Accept: application/json` and, given `token`,
    /// `Authorization: token <token>`. A redirect is never followed: any
    /// non-2xx response comes back with its Location and no body. A 2xx body is
    /// read up to `limit + 1` bytes. A failed connection, a failed or short body
    /// read and a timeout are `Retryable`.
    fn get(&mut self, url: &str, token: Option<&str>, limit: u64) -> Result<Response>;
}

/// reqwest over rustls: HTTPS only, no redirects, `TIMEOUT` up to the response
/// headers and again for each body read. Proxies come from the environment.
pub struct Native {
    client: reqwest::blocking::Client,
}

impl Native {
    pub fn new() -> Result<Self> {
        Self::build(true, TIMEOUT)
    }

    fn build(https_only: bool, timeout: Duration) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(https_only)
            .build()
            .context("source HTTP client")?;
        Ok(Self { client })
    }
}

impl Transport for Native {
    fn get(&mut self, url: &str, token: Option<&str>, limit: u64) -> Result<Response> {
        let mut request = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(token) = token {
            let mut value = reqwest::header::HeaderValue::from_str(&format!("token {token}"))
                .map_err(|_| anyhow!("the source token is not a valid header value"))?;
            value.set_sensitive(true);
            request = request.header(reqwest::header::AUTHORIZATION, value);
        }
        // Never format a transport error: it names the URL, and a signed
        // storage URL is a credential. A failed connection, a disconnect before
        // the headers and a timeout are all transient.
        let response = match request.send() {
            Ok(response) => response,
            Err(error) if error.is_builder() => bail!("invalid source URL"),
            Err(_) => return Err(Retryable(TEMPORARY).into()),
        };
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            return Ok(Response {
                status,
                location,
                body: Vec::new(),
            });
        }
        // Any failure while reading a 2xx body, a timeout or a body shorter than
        // its Content-Length is transient too.
        let declared = response.content_length();
        let mut body = Vec::new();
        let read = response.take(limit + 1).read_to_end(&mut body);
        let short = declared.is_some_and(|length| (body.len() as u64) < length.min(limit + 1));
        if read.is_err() || short {
            return Err(Retryable(TEMPORARY).into());
        }
        Ok(Response {
            status,
            location: None,
            body,
        })
    }
}

/// Time for the main-run wait. Tests substitute a fake.
pub trait Clock {
    fn now(&mut self) -> Duration;
    fn sleep(&mut self, duration: Duration);
    fn announce(&mut self, line: &str);
}

/// The monotonic clock, real sleeps and stderr.
pub struct System(Instant);

impl System {
    pub fn new() -> Self {
        Self(Instant::now())
    }
}

impl Default for System {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for System {
    fn now(&mut self) -> Duration {
        self.0.elapsed()
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }

    fn announce(&mut self, line: &str) {
        eprintln!("{line}");
    }
}

/// `AUTODEPLOY_SOURCE_TOKEN`, else `GITEA_TOKEN`; an empty value is unset.
/// The binding's server is always the instance's forge, so GITEA_TOKEN always
/// applies.
pub fn token() -> Result<Option<String>> {
    for name in ["AUTODEPLOY_SOURCE_TOKEN", "GITEA_TOKEN"] {
        if let Some(value) = std::env::var_os(name).filter(|value| !value.is_empty()) {
            return value
                .into_string()
                .map(Some)
                .map_err(|_| anyhow!("{name} must be UTF-8"));
        }
    }
    Ok(None)
}

/// What a session reaches outside itself.
pub struct Effects {
    pub transport: Box<dyn Transport>,
    pub clock: Box<dyn Clock>,
    /// gcloud, for the release manifest a control check reads.
    pub tools: Box<dyn instance_release::Tools>,
    /// The release cache, else `instance_release::cache_root()`.
    pub cache: Option<PathBuf>,
    pub token: Option<String>,
    /// App CI's results buckets, read as the apply identity.
    pub storage: Box<dyn crate::ci_results::Storage>,
}

impl Effects {
    pub fn native() -> Result<Self> {
        Ok(Self {
            transport: Box::new(Native::new()?),
            clock: Box::new(System::new()),
            tools: Box::new(instance_release::Native),
            cache: None,
            token: token()?,
            storage: Box::new(crate::ci_results::Gcs::native()?),
        })
    }
}

/// One app in day2.json, as the CLI derived it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct App {
    pub id: String,
    pub sdk: String,
    pub verification: u64,
}

/// The instance names the CLI derived from day2.json.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Instance {
    /// forge.server, `https://<host>`.
    pub server: String,
    /// forge.org.
    pub org: String,
    /// The project's Artifact Registry, `<region>-docker.pkg.dev/<project>`.
    pub registry: String,
    /// The derived state bucket, `<project>-tofu-state`.
    pub bucket: String,
    pub apps: Vec<App>,
    /// App CI's names, only when day2.json sets forge.oidc: then every checked
    /// artifact comes from app CI's results bucket (`app_ci`), and never from
    /// the app repository's own workflow.
    pub app_ci: Option<app_ci::AppCi>,
}

/// The CLI's rendered request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub mode: Mode,
    pub instance: Option<Instance>,
    /// The binding file: the deploy controller's source binding for one app.
    pub binding: Option<PathBuf>,
    pub commit: Option<String>,
    /// The checked source inputs, `sha256:<hex>`.
    pub inputs: Option<String>,
    /// An existing source archive to read.
    pub archive: Option<PathBuf>,
    /// A new file to write.
    pub output: Option<PathBuf>,
}

pub(crate) fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// ci_artifact.SHA: a full lowercase commit.
pub fn commit(value: &str) -> bool {
    lower_hex(value, 40)
}

/// ci_artifact.HASH: `sha256:<64 lowercase hex digits>`.
pub fn hash(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| lower_hex(hex, 64))
}

fn word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

/// A DNS name of lowercase labels, as InstanceSpec validates forge.server.
fn host(value: &str) -> bool {
    !value.is_empty()
        && value.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// The instance's forge: an https host and a lowercase org.
pub(crate) fn validate_forge(server: &str, org: &str) -> Result<()> {
    ensure!(
        server.strip_prefix("https://").is_some_and(host),
        "the instance forge must be https://<host>"
    );
    ensure!(
        !org.is_empty()
            && org
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "the instance forge org must be lowercase"
    );
    Ok(())
}

pub(crate) fn validate_instance(instance: &Instance) -> Result<()> {
    validate_forge(&instance.server, &instance.org)?;
    let bucket_project = instance
        .bucket
        .strip_suffix("-tofu-state")
        .filter(|project| !project.is_empty())
        .context("the release bucket must be the instance's <project>-tofu-state")?;
    let registry_project = instance
        .registry
        .split_once("-docker.pkg.dev/")
        .map(|(_, project)| project)
        .context("the registry must be the instance's <region>-docker.pkg.dev/<project>")?;
    ensure!(
        registry_project == bucket_project,
        "the registry and bucket must be the instance project's"
    );
    ensure!(
        !instance.apps.is_empty()
            && instance.apps.windows(2).all(|pair| pair[0].id < pair[1].id)
            && instance.apps.iter().all(|app| {
                !app.id.is_empty() && hash(&app.sdk) && (4..=100).contains(&app.verification)
            }),
        "the instance apps must be sorted, each with an sdk digest and 4 to 100 verification cases"
    );
    if let Some(names) = &instance.app_ci {
        app_ci::validate(names, instance)?;
    }
    Ok(())
}

/// The request's fields belong to its mode, and its instance names to one
/// instance.
pub fn validate(request: &Request) -> Result<()> {
    let has = |field: bool, wanted: bool| field == wanted;
    let (instance, binding, commit_wanted, inputs, archive, output) = match request.mode {
        Mode::Head => (true, true, false, false, false, false),
        Mode::Archive => (true, true, true, false, false, true),
        Mode::Controls => (false, false, false, false, true, false),
        Mode::VerifyControls => (true, true, false, false, true, false),
        Mode::CheckedArtifact => (true, true, true, true, false, true),
    };
    ensure!(
        has(request.instance.is_some(), instance)
            && has(request.binding.is_some(), binding)
            && has(request.commit.is_some(), commit_wanted)
            && has(request.inputs.is_some(), inputs)
            && has(request.archive.is_some(), archive)
            && has(request.output.is_some(), output),
        "an instance source {} request names only its own inputs",
        request.mode.name()
    );
    if let Some(instance) = &request.instance {
        validate_instance(instance)?;
    }
    if let Some(value) = &request.commit {
        ensure!(
            commit(value),
            "{} requires an exact commit",
            request.mode.name()
        );
    }
    if let Some(value) = &request.inputs {
        ensure!(
            hash(value),
            "the checked source inputs must be sha256:<hex>"
        );
    }
    Ok(())
}

/// A JSON integer, never a boolean or a float: Python's `type(x) is int`.
pub(crate) fn int(value: &Value) -> Option<i128> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .map(i128::from)
            .or_else(|| number.as_i64().map(i128::from)),
        _ => None,
    }
}

/// A positive integer below 2**63, as a proof's run, attempt and job.
pub(crate) fn proof_id(value: &Value) -> Option<u64> {
    int(value)
        .filter(|id| *id > 0 && *id < i128::from(PROOF_LIMIT))
        .and_then(|id| u64::try_from(id).ok())
}

pub(crate) fn object_with(value: &Value, fields: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
    })
}

/// A field a Python subscript required; its absence is a refusal.
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value
        .as_object()
        .and_then(|object| object.get(name))
        .with_context(|| format!("source response lacks {name}"))
}

/// deployment_events.decode: 1 MiB and no duplicate key at any depth. Only
/// fixed codes are reported, never the document.
pub fn decode(bytes: &[u8]) -> Result<Value> {
    ensure!(bytes.len() as u64 <= JSON_LIMIT, "event_byte_limit");
    // Python bounds a document by its bytes alone; every node takes a byte.
    day2::json::decode_with_limits(bytes, JSON_LIMIT as usize, JSON_LIMIT as usize).map_err(
        |error| {
            if format!("{error:#}").contains("duplicate JSON key") {
                anyhow!("duplicate_event_field")
            } else {
                anyhow!("invalid JSON")
            }
        },
    )
}

/// qualified_release.blob.
pub(crate) fn blob(value: &Value, limit: u64) -> Result<BlobIdentity> {
    let valid = object_with(value, &["digest", "bytes"])
        && value["digest"].as_str().is_some_and(hash)
        && int(&value["bytes"]).is_some_and(|bytes| bytes > 0 && bytes <= i128::from(limit));
    ensure!(valid, "invalid qualified release blob");
    Ok(serde_json::from_value(value.clone())?)
}

/// ci_artifact.verification_profile.
pub fn verification_profile(value: &Value) -> Result<()> {
    let valid = object_with(value, &["version", "seed", "cases"])
        && ["version", "seed", "cases"]
            .iter()
            .all(|key| int(&value[*key]).is_some())
        && int(&value["version"]) == Some(1)
        && int(&value["seed"]) == Some(42)
        && int(&value["cases"]).is_some_and(|cases| (4..=100).contains(&cases));
    ensure!(valid, "unsupported app verification profile");
    Ok(())
}

/// ci_artifact.contract.
pub fn contract(value: &Value) -> Result<()> {
    let valid = object_with(value, &["version", "workflow", "job", "digest"])
        && int(&value["version"]) == Some(1)
        && value["workflow"] == WORKFLOW
        && value["job"] == JOB
        && value["digest"].as_str().is_some_and(hash);
    ensure!(valid, "invalid checked-artifact CI contract");
    Ok(())
}

/// deploy.IDENTIFIER.
pub(crate) fn identifier(value: &str) -> bool {
    value.len() <= 40
        && value.starts_with(|c: char| c.is_ascii_lowercase())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `[a-zA-Z0-9_-][a-zA-Z0-9_.-]*/[a-zA-Z0-9_-][a-zA-Z0-9_.-]*`.
fn repository(value: &str) -> bool {
    let part = |part: &str| {
        part.bytes().next().is_some_and(word) && part.bytes().all(|b| word(b) || b == b'.')
    };
    value
        .split_once('/')
        .is_some_and(|(owner, name)| part(owner) && part(name))
}

/// `.` or `[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*`.
pub(crate) fn directory(value: &str) -> bool {
    value == "."
        || value
            .split('/')
            .all(|part| !part.is_empty() && part.bytes().all(word))
}

/// `[a-zA-Z0-9_-]+(?:[./][a-zA-Z0-9_-]+)*`.
fn branch(value: &str) -> bool {
    value
        .split(['.', '/'])
        .all(|part| !part.is_empty() && part.bytes().all(word))
}

/// `[a-z][a-z0-9_-]{0,31}`.
fn forge(value: &str) -> bool {
    value.len() <= 32
        && value.starts_with(|c: char| c.is_ascii_lowercase())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// deploy.image: `<registry>/<app>/<name>@sha256:<hex>`, or, without a
/// digest, the image repository.
pub(crate) fn app_image(value: &str, registry: &str, app: &str, pinned: bool) -> bool {
    let Some(rest) = value.strip_prefix(&format!("{registry}/{app}/")) else {
        return false;
    };
    let (name, digest) = match rest.split_once('@') {
        Some((name, digest)) if pinned => (name, Some(digest)),
        None if !pinned => (rest, None),
        _ => return false,
    };
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && digest.is_none_or(hash)
}

/// urllib.parse.urlsplit, as Python 3.12 splits an ASCII URL.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Split {
    pub scheme: String,
    pub netloc: String,
    pub path: String,
    pub query: String,
    pub fragment: String,
}

pub fn urlsplit(url: &str) -> Split {
    let url: String = url
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut rest = url.as_str();
    let mut split = Split::default();
    if let Some(index) = rest.find(':')
        && index > 0
        && rest.starts_with(|c: char| c.is_ascii_alphabetic())
        && rest[..index]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        split.scheme = rest[..index].to_ascii_lowercase();
        rest = &rest[index + 1..];
    }
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        split.netloc = after[..end].to_owned();
        rest = &after[end..];
    }
    if let Some((before, fragment)) = rest.split_once('#') {
        split.fragment = fragment.to_owned();
        rest = before;
    }
    if let Some((before, query)) = rest.split_once('?') {
        split.query = query.to_owned();
        rest = before;
    }
    split.path = rest.to_owned();
    split
}

/// deployment_events.identity's origin check: https, a host, and no
/// userinfo, path, query or fragment.
fn origin(value: &str) -> bool {
    let split = urlsplit(value);
    let userinfo = split.netloc.rsplit_once('@').map(|(userinfo, _)| userinfo);
    let (username, password) = match userinfo {
        Some(userinfo) => match userinfo.split_once(':') {
            Some((username, password)) => (username, password),
            None => (userinfo, ""),
        },
        None => ("", ""),
    };
    let hostport = split
        .netloc
        .rsplit_once('@')
        .map_or(split.netloc.as_str(), |(_, hostport)| hostport);
    let hostname = if hostport.starts_with('[') {
        hostport
            .split(']')
            .next()
            .unwrap_or_default()
            .trim_start_matches('[')
    } else {
        hostport.split(':').next().unwrap_or_default()
    };
    split.scheme == "https"
        && !hostname.is_empty()
        && username.is_empty()
        && password.is_empty()
        && split.path.is_empty()
        && split.query.is_empty()
        && split.fragment.is_empty()
}

/// The deploy controller's source binding for one app, validated as the
/// controller validates it, then against day2.json.
#[derive(Clone, Debug)]
pub struct Binding {
    /// Exactly the JSON the caller gave.
    pub value: Value,
    pub app: String,
    pub repository: String,
    pub directory: String,
    pub server: String,
    pub repository_id: Value,
    pub branch: String,
    pub forge: String,
    pub qualified_release: BlobIdentity,
    pub verification: Value,
    pub controls: String,
}

pub(crate) const BINDING_FIELDS: [&str; 10] = [
    "app",
    "repository",
    "directory",
    "runtime_image",
    "tooling_image",
    "image_repository",
    "source",
    "qualified_release",
    "verification",
    "ci_artifact",
];

/// A binding in one of the earlier controller's shapes without a qualified SDK
/// release and a checked main artifact: those builds compiled the app on the
/// build host, a path the platform does not provide.
pub(crate) fn unported_binding(value: &Value) -> Result<()> {
    let base = &BINDING_FIELDS[..7];
    let qualified = &BINDING_FIELDS[..9];
    ensure!(
        !object_with(value, base) && !object_with(value, qualified),
        "builds without a qualified SDK release and a checked main artifact are not supported: \
         the binding must name qualified_release, verification and ci_artifact"
    );
    Ok(())
}

/// deployment_events.identity.
pub(crate) fn identity(value: &Value) -> Result<()> {
    ensure!(
        object_with(
            value,
            &["forge", "server", "repository", "repository_id", "branch"]
        ),
        "invalid_source_identity"
    );
    ensure!(
        value["forge"].as_str().is_some_and(forge),
        "invalid_source_forge"
    );
    ensure!(
        value["server"].as_str().is_some_and(origin),
        "invalid_source_origin"
    );
    ensure!(
        value["repository"].as_str().is_some_and(repository),
        "invalid_source_repository"
    );
    let repository_id = &value["repository_id"];
    ensure!(
        int(repository_id).is_some_and(|id| id > 0)
            || repository_id.as_str().is_some_and(|id| {
                (1..=128).contains(&id.len())
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._:{}-".contains(&b))
            }),
        "invalid_native_repository_id"
    );
    ensure!(
        value["branch"].as_str().is_some_and(branch),
        "invalid_source_branch"
    );
    Ok(())
}

/// Whether a forge repository (`owner/name`) is one the platform owns in an
/// instance's org: every such repository is named `day2-<name>`. Gitea names
/// are case-insensitive, so the prefix is too.
pub(crate) fn platform_repository(repository: &str) -> bool {
    let name = repository
        .split_once('/')
        .map_or(repository, |(_, name)| name);
    name.len() >= 5 && name.as_bytes()[..5].eq_ignore_ascii_case(b"day2-")
}

/// A binding's source is an app repository on the instance's forge: its server
/// is forge.server, its repository is in forge.org, and it is not one of the
/// platform's own `day2-` repositories.
pub(crate) fn on_forge(binding: &Value, server: &str, org: &str) -> Result<()> {
    ensure!(
        binding["source"]["server"] == server,
        "the binding's source server is not day2.json's forge.server"
    );
    let repository = binding["repository"].as_str().unwrap_or_default();
    ensure!(
        repository.split_once('/').map(|(owner, _)| owner) == Some(org),
        "the binding's repository is not in day2.json's forge.org"
    );
    ensure!(
        !platform_repository(repository),
        "the binding's repository is a platform repository (day2-<name>), not an app's"
    );
    Ok(())
}

impl Binding {
    /// Validate `value` as Python did, then require it to describe one of the
    /// instance's apps on the instance's forge: the source server is
    /// forge.server, the repository is in forge.org and is not a platform
    /// `day2-` repository, and the qualified release and verification cases are
    /// the app's sdk and verification. The repository name itself is not
    /// derived; it may differ from `<org>/<app>`.
    pub fn check(value: Value, instance: &Instance) -> Result<Self> {
        unported_binding(&value)?;
        ensure!(
            object_with(&value, &BINDING_FIELDS),
            "invalid candidate build binding"
        );
        let string = |name: &str| value[name].as_str().unwrap_or_default().to_owned();
        let app = string("app");
        ensure!(identifier(&app), "invalid deployment app ID");
        let qualified_release = blob(&value["qualified_release"], MANIFEST_LIMIT)?;
        verification_profile(&value["verification"])?;
        contract(&value["ci_artifact"])?;
        let repository_name = string("repository");
        ensure!(
            value["repository"].is_string() && repository(&repository_name),
            "invalid deployment source repository"
        );
        let source = &value["source"];
        identity(source)?;
        ensure!(
            source["repository"] == value["repository"],
            "release source mismatch"
        );
        ensure!(
            source["forge"] == "gitea" && source["branch"] == "main",
            "checked-artifact source requires Gitea main"
        );
        let directory_name = string("directory");
        ensure!(
            value["directory"].is_string() && directory(&directory_name),
            "invalid app source directory"
        );
        let registry = &instance.registry;
        ensure!(
            app_image(&string("runtime_image"), registry, &app, true),
            "runtime must be a pinned app-local image"
        );
        ensure!(
            app_image(&string("tooling_image"), registry, &app, true),
            "pinned app-local tooling required"
        );
        ensure!(
            app_image(&string("image_repository"), registry, &app, false),
            "pinned app-local bootstrap image required"
        );
        let Some(spec) = instance.apps.iter().find(|spec| spec.id == app) else {
            bail!("the binding's app {app} is not in day2.json");
        };
        on_forge(&value, &instance.server, &instance.org)?;
        ensure!(
            qualified_release.digest == spec.sdk,
            "the binding's qualified release is not day2.json's apps.{app}.sdk"
        );
        ensure!(
            int(&value["verification"]["cases"]) == Some(i128::from(spec.verification)),
            "the binding's verification cases are not day2.json's apps.{app}.verification"
        );
        Ok(Self {
            app,
            repository: repository_name,
            directory: directory_name,
            server: instance.server.clone(),
            repository_id: source["repository_id"].clone(),
            branch: source["branch"].as_str().unwrap_or_default().to_owned(),
            forge: source["forge"].as_str().unwrap_or_default().to_owned(),
            qualified_release,
            verification: value["verification"].clone(),
            controls: value["ci_artifact"]["digest"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            value,
        })
    }
}

/// A tar member's name as Python's tarfile decodes it: UTF-8, each byte that
/// is not part of a valid sequence escaped to U+DC80..U+DCFF
/// (surrogateescape). Code points compare as Python's str does.
pub(crate) fn python_name(bytes: &[u8]) -> Vec<u32> {
    let mut name = Vec::new();
    for chunk in bytes.utf8_chunks() {
        name.extend(chunk.valid().chars().map(u32::from));
        name.extend(chunk.invalid().iter().map(|byte| 0xdc00 + u32::from(*byte)));
    }
    name
}

/// PurePosixPath(name).parts: an absolute path's root first ("//" for exactly
/// two leading slashes, else "/"), then its components without empty and "."
/// ones; ".." stays.
pub(crate) fn posix_parts(name: &[u32]) -> Vec<Vec<u32>> {
    let slash = u32::from(b'/');
    let leading = name.iter().take_while(|c| **c == slash).count();
    let mut parts = Vec::new();
    match leading {
        0 => {}
        2 => parts.push(vec![slash, slash]),
        _ => parts.push(vec![slash]),
    }
    parts.extend(
        name.split(|c| *c == slash)
            .filter(|part| !part.is_empty() && !(part.len() == 1 && part[0] == u32::from(b'.')))
            .map(<[u32]>::to_vec),
    );
    parts
}

pub(crate) fn ascii(name: &[u32], text: &str) -> bool {
    name.len() == text.len()
        && name
            .iter()
            .zip(text.bytes())
            .all(|(c, b)| *c == u32::from(b))
}

fn starts_with(name: &[u32], text: &str) -> bool {
    name.len() >= text.len() && ascii(&name[..text.len()], text)
}

fn ends_with(name: &[u32], text: &str) -> bool {
    name.len() >= text.len() && ascii(&name[name.len() - text.len()..], text)
}

/// A JSON string as Python's json.dumps writes it with ensure_ascii, from
/// code points that may include lone surrogates.
pub(crate) fn python_json_string(name: &[u32], out: &mut Vec<u8>) {
    out.push(b'"');
    for code in name {
        match *code {
            0x22 => out.extend_from_slice(b"\\\""),
            0x5c => out.extend_from_slice(b"\\\\"),
            0x0a => out.extend_from_slice(b"\\n"),
            0x0d => out.extend_from_slice(b"\\r"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            code @ 0x20..=0x7e => out.push(code as u8),
            code @ 0..=0xffff => out.extend_from_slice(format!("\\u{code:04x}").as_bytes()),
            code => {
                let value = code - 0x10000;
                let (high, low) = (0xd800 + (value >> 10), 0xdc00 + (value & 0x3ff));
                out.extend_from_slice(format!("\\u{high:04x}\\u{low:04x}").as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// The CI controls in a source archive: ci_artifact.control_files.
pub struct Controls {
    /// Each control file's normalized name and bytes, in Python's name order.
    pub files: BTreeMap<Vec<u32>, Vec<u8>>,
}

/// The decompressed tar bytes read at most: the 128 MiB member budget plus
/// room for every member's header and padding and for its extension headers.
pub(crate) const STREAM_LIMIT: u64 = ARTIFACT_LIMIT + (32 << 20);
/// The most a pax header or GNU long name may hold, checked before it is read.
const EXTENSION_LIMIT: u64 = 1 << 20;
const BUDGET: &str = "CI source archive exceeds budget";
const UNSUPPORTED: &str = "unsupported CI source archive entry";
const GLOBAL: &str = "unsupported CI source archive pax global header";

/// What the extension headers before a member say about it.
#[derive(Default)]
struct Extensions {
    /// A pax header was read.
    pax: bool,
    path: Option<Vec<u8>>,
    size: Option<u64>,
    /// A pax `linkpath` record.
    link_path: Option<Vec<u8>>,
    long_name: Option<Vec<u8>>,
    long_link: Option<Vec<u8>>,
}

impl Extensions {
    fn is_empty(&self) -> bool {
        !self.pax && self.long_name.is_none() && self.long_link.is_none()
    }
}

/// A NUL-terminated header field, as tarfile's nts reads it.
fn terminated(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    &bytes[..end]
}

/// Canonical decimal digits: no sign, space, separator or other form that
/// Python's int() and Rust's parse would read differently.
fn decimal(bytes: &[u8]) -> Option<u64> {
    (!bytes.is_empty() && bytes.iter().all(u8::is_ascii_digit))
        .then(|| std::str::from_utf8(bytes).ok()?.parse().ok())
        .flatten()
}

/// pax records, `<length> <key>=<value>\n`, each length the record's own in
/// decimal. Anything else is refused.
fn pax_records<'a>(mut data: &'a [u8], text: &TarText) -> Result<Vec<(&'a [u8], &'a [u8])>> {
    let mut records = Vec::new();
    while !data.is_empty() {
        let space = data
            .iter()
            .position(|b| *b == b' ')
            .context(text.unsupported)?;
        let length = decimal(&data[..space])
            .and_then(|length| usize::try_from(length).ok())
            .filter(|length| *length > space + 2 && *length <= data.len())
            .context(text.unsupported)?;
        ensure!(data[length - 1] == b'\n', text.unsupported);
        let record = &data[space + 1..length - 1];
        let equals = record
            .iter()
            .position(|b| *b == b'=')
            .context(text.unsupported)?;
        ensure!(equals > 0, text.unsupported);
        records.push((&record[..equals], &record[equals + 1..]));
        data = &data[length..];
    }
    Ok(records)
}

/// What a tar reading reports when the archive itself is unusable, in its
/// reader's words.
pub(crate) struct TarText {
    pub unreadable: &'static str,
    pub unsupported: &'static str,
    pub global: &'static str,
    pub budget: &'static str,
}

const CI_TEXT: TarText = TarText {
    unreadable: UNREADABLE,
    unsupported: UNSUPPORTED,
    global: GLOBAL,
    budget: BUDGET,
};

/// A member's type, as Python's tarfile classifies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// `isfile()`: a regular or contiguous file, or an old-style file whose
    /// header name does not end in a slash.
    Regular,
    /// `isdir()`, including an old-style file whose header name ends in a slash.
    Directory,
    /// `issym()`.
    Symlink,
    /// A hard link, device, FIFO or unknown type.
    Other,
}

/// One tar member, after any pax and GNU extension headers.
pub(crate) struct Member {
    /// The name as tarfile decodes it (surrogateescape).
    pub name: Vec<u32>,
    /// `PurePosixPath(name).parts`.
    pub parts: Vec<Vec<u32>>,
    pub kind: Kind,
    pub size: u64,
    /// The header's mode field.
    pub mode: u32,
    /// A symlink's target as tarfile reads it (a pax `linkpath`, else a GNU
    /// long link name, else the header's link name); empty for other kinds.
    pub link: Vec<u8>,
}

/// Read a gzip tar archive's members in order, as Python's tarfile reads them,
/// decompressing at most `limit` bytes. `visit` gets each member and a reader
/// of its data.
///
/// The tar crate reads blocks; extension headers are read here: pax `path` and
/// `size` and GNU long names apply to the next member whatever its header's
/// magic, and a pax global header carries only `comment`. An extension
/// header's declared size is checked before its data is read. The few shapes
/// tarfile reads differently are refused, not guessed:
/// - a pax global header with another record or after a pending extension,
///   and an extension with no member after it;
/// - a GNU long name beside a different pax path, two pax headers for one
///   member, a duplicate `path` or `size` record, a `GNU.sparse.*` record,
///   and a pax `size` that is not canonical decimal or not the header's;
/// - a name with a NUL byte, and a non-ustar header whose prefix field is not
///   empty;
/// - sparse and Solaris entries;
/// - data on a link, device, FIFO or directory entry, which tarfile would not
///   skip.
pub(crate) fn read_tar(
    archive: &[u8],
    limit: u64,
    text: &TarText,
    mut visit: impl FnMut(&Member, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    let mut stream = flate2::read::MultiGzDecoder::new(archive).take(limit);
    let read = members(&mut stream, text, &mut visit);
    // A stream cut off at its limit may otherwise look like an archive's end.
    ensure!(stream.limit() > 0, text.budget);
    read
}

fn members(
    stream: impl Read,
    text: &TarText,
    visit: &mut dyn FnMut(&Member, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    let mut source = tar::Archive::new(stream);
    let mut pending = Extensions::default();
    for entry in source
        .entries()
        .map_err(|_| anyhow!(text.unreadable))?
        .raw(true)
    {
        let mut entry = entry.map_err(|_| anyhow!(text.unreadable))?;
        let header: [u8; 512] = *entry.header().as_bytes();
        let kind = header[156];
        // Raw entries carry the header's own size.
        let size = entry.size();
        if matches!(kind, b'x' | b'g' | b'L' | b'K') {
            ensure!(size <= EXTENSION_LIMIT, text.budget);
            let mut data = Vec::new();
            (&mut entry)
                .take(size)
                .read_to_end(&mut data)
                .map_err(|_| anyhow!(text.unreadable))?;
            ensure!(data.len() as u64 == size, text.unreadable);
            match kind {
                b'x' => {
                    ensure!(!pending.pax, text.unsupported);
                    pending.pax = true;
                    for (key, value) in pax_records(&data, text)? {
                        match key {
                            b"path" => {
                                ensure!(pending.path.is_none(), text.unsupported);
                                pending.path = Some(value.to_vec());
                            }
                            b"size" => {
                                ensure!(pending.size.is_none(), text.unsupported);
                                pending.size = Some(decimal(value).context(text.unsupported)?);
                            }
                            b"linkpath" => {
                                ensure!(pending.link_path.is_none(), text.unsupported);
                                pending.link_path = Some(value.to_vec());
                            }
                            key => ensure!(!key.starts_with(b"GNU.sparse."), text.unsupported),
                        }
                    }
                }
                b'g' => ensure!(
                    pending.is_empty()
                        && pax_records(&data, text)
                            .is_ok_and(|records| records.iter().all(|(key, _)| *key == b"comment")),
                    text.global
                ),
                b'L' => {
                    ensure!(pending.long_name.is_none(), text.unsupported);
                    pending.long_name = Some(terminated(&data).to_vec());
                }
                _ => {
                    ensure!(pending.long_link.is_none(), text.unsupported);
                    pending.long_link = Some(terminated(&data).to_vec());
                }
            }
            continue;
        }
        let extensions = std::mem::take(&mut pending);
        let header_name = terminated(&header[..100]);
        let ustar = entry.header().as_ustar().is_some();
        let prefix_empty = header[345..500].iter().all(|b| *b == 0);
        let agree = |pax: &Option<Vec<u8>>, gnu: &Option<Vec<u8>>| match (pax, gnu) {
            (Some(pax), Some(gnu)) => pax == gnu,
            _ => true,
        };
        let names_agree = agree(&extensions.path, &extensions.long_name)
            && agree(&extensions.link_path, &extensions.long_link);
        // tarfile reads an old-style regular entry named with a final slash
        // as a directory, and skips data only after regular and unknown
        // entries.
        let regular = matches!(kind, b'0' | b'7') || (kind == 0 && !header_name.ends_with(b"/"));
        let directory = kind == b'5' || (kind == 0 && header_name.ends_with(b"/"));
        let skipped = regular || !(directory || matches!(kind, b'1'..=b'6'));
        ensure!(
            !matches!(kind, b'S' | b'X')
                && names_agree
                && extensions.size.is_none_or(|declared| declared == size)
                && (ustar || prefix_empty)
                && (skipped || size == 0),
            text.unsupported
        );
        let path = match extensions.path.or(extensions.long_name) {
            Some(path) => path,
            None => entry.header().path_bytes().into_owned(),
        };
        ensure!(!path.contains(&0), text.unsupported);
        let mode = entry
            .header()
            .mode()
            .map_err(|_| anyhow!(text.unreadable))?;
        let name = python_name(&path);
        let symlink = kind == b'2';
        let link = match extensions.link_path.or(extensions.long_link) {
            Some(link) => link,
            None if symlink => entry
                .header()
                .link_name_bytes()
                .map(|link| link.into_owned())
                .unwrap_or_default(),
            None => Vec::new(),
        };
        ensure!(!link.contains(&0), text.unsupported);
        let member = Member {
            parts: posix_parts(&name),
            name,
            kind: if regular {
                Kind::Regular
            } else if directory {
                Kind::Directory
            } else if symlink {
                Kind::Symlink
            } else {
                Kind::Other
            },
            size,
            mode,
            link: if symlink { link } else { Vec::new() },
        };
        visit(&member, &mut entry)?;
    }
    // An extension describes a member that must follow it.
    ensure!(pending.is_empty(), text.unsupported);
    Ok(())
}

impl Controls {
    /// Inventory executable CI inputs: every non-Markdown file under `.ci/` and
    /// `.gitea/workflows/roc.yml`, by their names below the archive's one root
    /// directory, read as `read_tar` reads an archive. The archive is bounded to
    /// 8192 entries, 16 MiB per member and 128 MiB in all, and decompression
    /// stops at `STREAM_LIMIT`; each control is a regular file of at most 2 MiB,
    /// unique by name; the required controls must be present.
    pub fn read(archive: &[u8]) -> Result<Self> {
        let mut files = BTreeMap::new();
        let mut root: Option<Vec<u32>> = None;
        let (mut entries, mut total) = (0_usize, 0_u64);
        read_tar(archive, STREAM_LIMIT, &CI_TEXT, |member, data| {
            let parts = &member.parts;
            ensure!(
                !parts.is_empty()
                    && parts[0][0] != u32::from(b'/')
                    && !parts.iter().any(|part| ascii(part, "..")),
                "unsafe CI source archive path"
            );
            let first = root.get_or_insert_with(|| parts[0].clone());
            ensure!(*first == parts[0], "CI source archive has multiple roots");
            entries += 1;
            total = total.saturating_add(member.size);
            ensure!(
                entries <= ENTRY_LIMIT && member.size <= MEMBER_LIMIT && total <= ARTIFACT_LIMIT,
                BUDGET
            );
            let mut relative = Vec::new();
            for (index, part) in parts[1..].iter().enumerate() {
                if index > 0 {
                    relative.push(u32::from(b'/'));
                }
                relative.extend_from_slice(part);
            }
            if relative.is_empty() {
                relative.push(u32::from(b'.'));
            }
            let selected = (starts_with(&relative, ".ci/") && !ends_with(&relative, ".md"))
                || ascii(&relative, ".gitea/workflows/roc.yml");
            if !selected || member.kind == Kind::Directory {
                return Ok(());
            }
            ensure!(
                member.kind == Kind::Regular
                    && member.size <= CONTROL_LIMIT
                    && !files.contains_key(&relative),
                "CI controls must be bounded unique regular files"
            );
            let mut bytes = Vec::new();
            data.take(member.size)
                .read_to_end(&mut bytes)
                .map_err(|_| anyhow!(UNREADABLE))?;
            ensure!(bytes.len() as u64 == member.size, UNREADABLE);
            files.insert(relative, bytes);
            Ok(())
        })?;
        ensure!(
            CONTROLS
                .iter()
                .all(|name| files.keys().any(|key| ascii(key, name))),
            "checked-artifact CI controls missing"
        );
        Ok(Self { files })
    }

    /// One control's bytes, by its ASCII name.
    fn get(&self, name: &str) -> Option<&[u8]> {
        self.files
            .iter()
            .find(|(key, _)| ascii(key, name))
            .map(|(_, bytes)| bytes.as_slice())
    }

    /// The bytes ci_artifact.control_digest hashes:
    /// `json.dumps({"version": 1, "files": [[name, bytes, hex], ...]},
    /// sort_keys=True, separators=(",", ":"))`, by name, without
    /// `.ci/roc.json`.
    pub fn document(&self) -> Vec<u8> {
        let mut out = b"{\"files\":[".to_vec();
        let mut first = true;
        for (name, bytes) in &self.files {
            if ascii(name, APP_CONTROL) {
                continue;
            }
            if !first {
                out.push(b',');
            }
            first = false;
            out.push(b'[');
            python_json_string(name, &mut out);
            let digest = day2::digest(bytes);
            out.extend_from_slice(format!(",{},\"{}\"]", bytes.len(), &digest[7..]).as_bytes());
        }
        out.extend_from_slice(b"],\"version\":1}");
        out
    }

    /// ci_artifact.control_digest.
    pub fn digest(&self) -> String {
        day2::digest(&self.document())
    }
}

/// The checks of ci_artifact.validate_controls that need no release, in its
/// order: the control digest is the approved one, and `.ci/platform-release.json`
/// is the binding's qualified release manifest.
pub fn approved_controls(controls: &Controls, binding: &Binding) -> Result<()> {
    ensure!(
        controls.digest() == binding.controls,
        "source CI differs from the instance-approved contract"
    );
    let selected = controls
        .get(".ci/platform-release.json")
        .context("checked-artifact CI controls missing")?;
    ensure!(
        BlobIdentity::of(selected) == binding.qualified_release,
        "source CI selects another qualified SDK"
    );
    Ok(())
}

/// The rest of ci_artifact.validate_controls, given the binding's qualified
/// release: `.ci/roc.json` names its platform commit, the binding's app root
/// and verification campaign, and only safe Roc test paths.
pub fn validate_controls(controls: &Controls, binding: &Binding, release: &Release) -> Result<()> {
    approved_controls(controls, binding)?;
    let roc = decode(
        controls
            .get(APP_CONTROL)
            .context("checked-artifact CI controls missing")?,
    )?;
    let profile = &binding.verification;
    let campaign = &roc["campaign"];
    let valid = object_with(
        &roc,
        &[
            "schemaVersion",
            "platformRevision",
            "appRoot",
            "campaign",
            "unitTests",
            "testSources",
        ],
    ) && int(&roc["schemaVersion"]) == Some(1)
        && roc["platformRevision"] == release.platform_commit.as_str()
        && roc["appRoot"] == binding.directory.as_str()
        && *campaign == json!({"seed": profile["seed"], "cases": profile["cases"]})
        && int(&campaign["seed"]).is_some()
        && int(&campaign["cases"]).is_some();
    ensure!(valid, "source CI app/SDK/verification profile mismatch");
    for key in ["unitTests", "testSources"] {
        let safe = roc[key].as_array().is_some_and(|names| {
            names.len() <= 1024
                && names.iter().all(|name| {
                    name.as_str().is_some_and(|name| {
                        name.len() > 4
                            && name.ends_with(".roc")
                            && name
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"_./-".contains(&b))
                            && name.split('/').all(|part| !part.is_empty() && part != "..")
                    })
                })
        });
        ensure!(safe, "unsafe pure Roc test declaration");
    }
    Ok(())
}

/// ci_artifact.receipt.
pub fn receipt(value: &Value, binding: &Value, source_commit: &str, inputs: &str) -> Result<()> {
    ensure!(
        object_with(
            value,
            &[
                "version",
                "repository",
                "source_commit",
                "source_inputs",
                "artifact_id",
                "sdk_release",
                "verification",
                "archive",
                "artifact_name",
                "examples",
                "generated",
                "upload_id",
            ]
        ),
        "invalid checked-artifact receipt fields"
    );
    ensure!(
        int(&value["version"]) == Some(1)
            && value["repository"] == binding["repository"]
            && value["source_commit"] == source_commit
            && commit(source_commit)
            && value["source_inputs"] == inputs
            && hash(inputs)
            && value["sdk_release"] == binding["qualified_release"]
            && value["verification"] == binding["verification"],
        "checked artifact belongs to another source/SDK/profile"
    );
    let name = value["artifact_name"].as_str().and_then(|name| {
        name.strip_prefix("day2-checked-app-")?
            .strip_prefix(source_commit)?
            .strip_prefix('-')
    });
    ensure!(
        value["artifact_id"]
            .as_str()
            .is_some_and(|id| lower_hex(id, 64))
            && name.is_some_and(|suffix| lower_hex(suffix, 32))
            && proof_id(&value["upload_id"]).is_some()
            && int(&value["examples"]).is_some_and(|examples| examples >= 0)
            && int(&value["generated"]).is_some_and(|generated| generated > 0),
        "invalid checked artifact or upload identity"
    );
    blob(&value["archive"], ARTIFACT_LIMIT)?;
    Ok(())
}

/// ci_artifact.proof, for `binding`'s JSON: version 1 for an artifact the app
/// repository's own workflow uploaded, version 2 for one read from app CI's
/// results bucket (`app_ci::proof`).
pub fn proof(value: &Value, binding: &Value, source_commit: &str, inputs: &str) -> Result<()> {
    ensure!(
        binding["source"]["forge"] == "gitea" && binding["source"]["branch"] == "main",
        "checked-artifact provenance requires Gitea main"
    );
    if int(&value["version"]) == Some(app_ci::VERSION) {
        return app_ci::proof(value, binding, source_commit, inputs);
    }
    ensure!(
        object_with(value, &["version", "run", "attempt", "job", "receipt"])
            && int(&value["version"]) == Some(1)
            && ["run", "attempt", "job"]
                .iter()
                .all(|key| proof_id(&value[*key]).is_some()),
        "invalid checked-artifact provenance"
    );
    receipt(&value["receipt"], binding, source_commit, inputs)
}

/// The decimal digits Python's `\d` matches in a str pattern (Unicode
/// category Nd, Unicode 15.0), as inclusive ranges.
const DECIMAL: [(u32, u32); 64] = [
    (0x30, 0x39),
    (0x660, 0x669),
    (0x6f0, 0x6f9),
    (0x7c0, 0x7c9),
    (0x966, 0x96f),
    (0x9e6, 0x9ef),
    (0xa66, 0xa6f),
    (0xae6, 0xaef),
    (0xb66, 0xb6f),
    (0xbe6, 0xbef),
    (0xc66, 0xc6f),
    (0xce6, 0xcef),
    (0xd66, 0xd6f),
    (0xde6, 0xdef),
    (0xe50, 0xe59),
    (0xed0, 0xed9),
    (0xf20, 0xf29),
    (0x1040, 0x1049),
    (0x1090, 0x1099),
    (0x17e0, 0x17e9),
    (0x1810, 0x1819),
    (0x1946, 0x194f),
    (0x19d0, 0x19d9),
    (0x1a80, 0x1a89),
    (0x1a90, 0x1a99),
    (0x1b50, 0x1b59),
    (0x1bb0, 0x1bb9),
    (0x1c40, 0x1c49),
    (0x1c50, 0x1c59),
    (0xa620, 0xa629),
    (0xa8d0, 0xa8d9),
    (0xa900, 0xa909),
    (0xa9d0, 0xa9d9),
    (0xa9f0, 0xa9f9),
    (0xaa50, 0xaa59),
    (0xabf0, 0xabf9),
    (0xff10, 0xff19),
    (0x104a0, 0x104a9),
    (0x10d30, 0x10d39),
    (0x11066, 0x1106f),
    (0x110f0, 0x110f9),
    (0x11136, 0x1113f),
    (0x111d0, 0x111d9),
    (0x112f0, 0x112f9),
    (0x11450, 0x11459),
    (0x114d0, 0x114d9),
    (0x11650, 0x11659),
    (0x116c0, 0x116c9),
    (0x11730, 0x11739),
    (0x118e0, 0x118e9),
    (0x11950, 0x11959),
    (0x11c50, 0x11c59),
    (0x11d50, 0x11d59),
    (0x11da0, 0x11da9),
    (0x11f50, 0x11f59),
    (0x16a60, 0x16a69),
    (0x16ac0, 0x16ac9),
    (0x16b50, 0x16b59),
    (0x1d7ce, 0x1d7ff),
    (0x1e140, 0x1e149),
    (0x1e2f0, 0x1e2f9),
    (0x1e4f0, 0x1e4f9),
    (0x1e950, 0x1e959),
    (0x1fbf0, 0x1fbf9),
];

fn python_digit(c: char) -> bool {
    let code = u32::from(c);
    DECIMAL
        .iter()
        .any(|(start, end)| (*start..=*end).contains(&code))
}

/// Python's `\s` in a str pattern: `str.isspace()`.
fn python_space(c: char) -> bool {
    matches!(
        u32::from(c),
        0x09..=0x0d | 0x1c..=0x20 | 0x85 | 0xa0 | 0x1680 | 0x2000..=0x200a | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000
    )
}

/// The receipts a native job log carries: what Python's
/// `re.findall(r"^\d{4}-\S+Z DAY2_CHECKED_APP_V1 (\{[^\r\n]*\})\r?$", log,
/// re.M)` returns. Lines end only at `\n`; the timestamp is four decimal
/// digits, a hyphen and a run of non-space characters ending in `Z`, then one
/// space; the receipt is `{` ... `}` with no CR or LF inside, then an optional
/// CR.
pub fn markers(log: &str) -> Vec<&str> {
    log.split('\n')
        .filter_map(|line| {
            let mut chars = line.char_indices();
            for _ in 0..4 {
                if !chars.next().is_some_and(|(_, c)| python_digit(c)) {
                    return None;
                }
            }
            if chars.next().map(|(_, c)| c) != Some('-') {
                return None;
            }
            let start = chars.next()?.0;
            let rest = &line[start..];
            let end = rest.find(python_space).unwrap_or(rest.len());
            let (stamp, after) = rest.split_at(end);
            if stamp.chars().count() < 2 || !stamp.ends_with('Z') {
                return None;
            }
            let body = after.strip_prefix(' ')?.strip_prefix(MARKER)?;
            let body = body.strip_suffix('\r').unwrap_or(body);
            (body.len() >= 2
                && body.starts_with('{')
                && body.ends_with('}')
                && !body.contains(['\r', '\n']))
            .then_some(body)
        })
        .collect()
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

const UNREADABLE: &str = "unreadable CI source archive";
const INVALID_ZIP: &str = "invalid artifact ZIP";
const ONLY_ARCHIVE: &str = "artifact ZIP must contain only app.tar.gz";

/// The checked app archive in Gitea's artifact ZIP, as ci_artifact.unpack_zip
/// reads it: exactly one entry, `app.tar.gz`, unencrypted, a regular file or
/// no file type, whose size and sha256 are the job receipt's.
///
/// Read by hand rather than with a ZIP crate, and only in the layout the
/// upload transport writes: one stored or deflated entry at offset 0, then its
/// data descriptor if the entry has one, then its central header, then the
/// end record, with no extra fields, comments, prepended bytes or ZIP64. The
/// local header must agree with the central one, a data descriptor must
/// repeat the central CRC and sizes, and the data must fill the space between
/// them exactly; the CRC-32 is checked as zipfile checks it.
pub fn unpack_zip(raw: &[u8], expected: &BlobIdentity) -> Result<Vec<u8>> {
    ensure!(
        raw.len() as u64 <= ZIP_LIMIT,
        "artifact ZIP exceeds byte budget"
    );
    let end = raw.len().checked_sub(22).context(INVALID_ZIP)?;
    let record = &raw[end..];
    ensure!(
        u32_at(record, 0) == 0x0605_4b50
            && u16_at(record, 4) == 0
            && u16_at(record, 6) == 0
            && u16_at(record, 20) == 0,
        INVALID_ZIP
    );
    ensure!(
        u16_at(record, 8) == 1 && u16_at(record, 10) == 1,
        ONLY_ARCHIVE
    );
    let directory_size = u32_at(record, 12) as usize;
    let directory_offset = u32_at(record, 16) as usize;
    ensure!(
        directory_offset.checked_add(directory_size) == Some(end) && directory_size >= 46,
        INVALID_ZIP
    );
    let central = &raw[directory_offset..end];
    let name_length = usize::from(u16_at(central, 28));
    ensure!(
        u32_at(central, 0) == 0x0201_4b50
            && 46 + name_length == central.len()
            && u16_at(central, 30) == 0
            && u16_at(central, 32) == 0,
        INVALID_ZIP
    );
    ensure!(&central[46..] == ARTIFACT_FILE, ONLY_ARCHIVE);
    let (needed, flags, method) = (u16_at(central, 6), u16_at(central, 8), u16_at(central, 10));
    let (time, date, crc) = (
        u16_at(central, 12),
        u16_at(central, 14),
        u32_at(central, 16),
    );
    let (compressed, size) = (u32_at(central, 20) as usize, u32_at(central, 24));
    let file_type = (u32_at(central, 38) >> 16) & 0o170_000;
    ensure!(
        u64::from(size) == expected.bytes
            && flags & 1 == 0
            && (file_type == 0 || file_type == 0o100_000),
        "invalid artifact ZIP entry"
    );
    let descriptor = flags & 0x8 != 0;
    let known_flags = if method == 8 { 0x80e } else { 0x808 };
    ensure!(
        needed <= 20
            && flags & !known_flags == 0
            && (method == 0 || method == 8)
            && u16_at(central, 34) == 0
            && u32_at(central, 42) == 0,
        INVALID_ZIP
    );
    ensure!(raw.len() >= 30 + ARTIFACT_FILE.len(), INVALID_ZIP);
    let local = &raw[..30];
    let (local_crc, local_compressed, local_size) = (
        u32_at(local, 14),
        u32_at(local, 18) as usize,
        u32_at(local, 22),
    );
    let sizes_agree = (local_crc, local_compressed, local_size) == (crc, compressed, size)
        || (descriptor && (local_crc, local_compressed, local_size) == (0, 0, 0));
    ensure!(
        u32_at(local, 0) == 0x0403_4b50
            && u16_at(local, 4) == needed
            && u16_at(local, 6) == flags
            && u16_at(local, 8) == method
            && u16_at(local, 10) == time
            && u16_at(local, 12) == date
            && sizes_agree
            && usize::from(u16_at(local, 26)) == ARTIFACT_FILE.len()
            && u16_at(local, 28) == 0
            && &raw[30..30 + ARTIFACT_FILE.len()] == ARTIFACT_FILE,
        INVALID_ZIP
    );
    let start = 30 + ARTIFACT_FILE.len();
    let data_end = start.checked_add(compressed).context(INVALID_ZIP)?;
    ensure!(data_end <= directory_offset, INVALID_ZIP);
    let trailer = &raw[data_end..directory_offset];
    let repeated = |at: usize| {
        u32_at(trailer, at) == crc
            && u32_at(trailer, at + 4) as usize == compressed
            && u32_at(trailer, at + 8) == size
    };
    let trailer_valid = match (descriptor, trailer.len()) {
        (false, 0) => true,
        (true, 12) => repeated(0),
        (true, 16) => u32_at(trailer, 0) == 0x0807_4b50 && repeated(4),
        _ => false,
    };
    ensure!(trailer_valid, INVALID_ZIP);
    let stored = &raw[start..data_end];
    let data = if method == 0 {
        ensure!(compressed as u64 == u64::from(size), INVALID_ZIP);
        stored.to_vec()
    } else {
        let mut decoder = flate2::read::DeflateDecoder::new(stored);
        let mut data = Vec::new();
        (&mut decoder)
            .take(u64::from(size) + 1)
            .read_to_end(&mut data)
            .map_err(|_| anyhow!(INVALID_ZIP))?;
        ensure!(decoder.total_in() == compressed as u64, INVALID_ZIP);
        data
    };
    let mut checksum = flate2::Crc::new();
    checksum.update(&data);
    ensure!(checksum.sum() == crc, INVALID_ZIP);
    ensure!(
        data.len() as u64 == expected.bytes && BlobIdentity::of(&data) == *expected,
        "downloaded artifact differs from the native CI job receipt"
    );
    Ok(data)
}

/// The response a forge read got: a 2xx body, or another status.
enum Got {
    Body(Vec<u8>),
    Status(u16, Option<String>),
}

/// urllib.parse.quote(value, safe=""): everything but `A-Za-z0-9_.-~` is
/// percent-encoded.
pub(crate) fn quote(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"_.-~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// `[a-z0-9][a-z0-9._-]*.storage.googleapis.com`.
fn storage_host(netloc: &str) -> bool {
    netloc
        .strip_suffix(".storage.googleapis.com")
        .is_some_and(|bucket| {
            bucket
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                && bucket
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        })
}

/// A completed main run's identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Run {
    id: u64,
    attempt: u64,
}

/// A file the session wrote or read, as the receipt reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    pub path: String,
    pub digest: String,
    pub bytes: u64,
}

/// What a source command reports. The host owns this shape; the CLI decodes
/// only it and passes it through verbatim, and cli/fixtures/source-receipt.json
/// (with app CI, source-receipt-app-ci.json)
/// pins it for both sides. Every field is present; those a mode does not
/// report are null.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub format: u32,
    pub mode: Mode,
    pub app_id: Option<String>,
    pub repository: Option<String>,
    /// head: the branch's commit. archive and checked-artifact: the commit read.
    pub commit: Option<String>,
    /// The archive written (archive, checked-artifact) or read (controls,
    /// verify-controls).
    pub archive: Option<File>,
    /// The CI-control digest (controls, verify-controls).
    pub controls: Option<String>,
    /// verify-controls: the qualified release's platform commit.
    pub platform_commit: Option<String>,
    /// checked-artifact: the checked source inputs.
    pub source_inputs: Option<String>,
    /// checked-artifact: the provenance proof, exactly as the controller's.
    pub proof: Option<Value>,
}

/// A path the CLI reports, which must be UTF-8.
fn text(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("{} is not UTF-8", path.display()))
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .with_context(|| format!("read {}", path.display()))?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "{} exceeds its {limit}-byte budget",
        path.display()
    );
    Ok(bytes)
}

/// Write a new file: created exclusively, then synced.
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    create_new(path, |file| file.write_all(bytes))
}

/// Create `path` exclusively, `write` it and sync it. If writing or syncing
/// fails, the partial file this call created is removed; a path that already
/// existed is never touched, because the exclusive create refuses it first.
fn create_new(path: &Path, write: impl FnOnce(&mut fs::File) -> std::io::Result<()>) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("instance source requires a new file: {}", path.display()))?;
    let written = write(&mut file).and_then(|()| file.sync_all());
    drop(file);
    let Err(error) = written else {
        return Ok(());
    };
    let error = anyhow::Error::from(error).context(format!("write {}", path.display()));
    Err(match fs::remove_file(path) {
        Ok(()) => error,
        Err(_) => error.context(format!(
            "the partial file {} could not be removed",
            path.display()
        )),
    })
}

/// What an embedded session is asked for: its commit and source inputs, the
/// archive it reads and the new file it writes.
pub struct Embedded {
    pub commit: Option<String>,
    pub inputs: Option<String>,
    pub archive: Option<PathBuf>,
    pub output: Option<PathBuf>,
}

pub struct Session {
    mode: Mode,
    effects: Effects,
    instance: Option<Instance>,
    binding: Option<Binding>,
    commit: Option<String>,
    inputs: Option<String>,
    archive: Option<PathBuf>,
    output: Option<PathBuf>,
    /// How many of the mode's steps are done.
    done: usize,
    /// verify-controls: the archive's approved controls and its identity.
    controls: Option<(Controls, File)>,
    run: Option<Run>,
    job: Option<u64>,
    checked: Option<Value>,
    data: Option<Vec<u8>>,
    /// App CI: the source repository's ID and the run, what its receipt read
    /// found, the one deadline every wait shares, and whether it was announced.
    ci: Option<(u64, app_ci::Run)>,
    found: Option<app_ci::Found>,
    deadline: Option<Duration>,
    announced: bool,
}

impl Session {
    /// Validate the CLI's request for a session the host started in `mode`,
    /// and the binding it names, before anything is read from the forge. A new
    /// file must not exist yet and its directory must; an archive to read must
    /// be a regular file.
    pub fn prepare(raw: &Path, mode: Mode, effects: Effects) -> Result<Self> {
        let request: Request = day2::json::decode(&read_bounded(raw, REQUEST_LIMIT)?)?;
        ensure!(
            request.mode == mode,
            "the host started an instance source {} but the request is for an instance source {}",
            mode.name(),
            request.mode.name()
        );
        validate(&request)?;
        let binding = match (&request.binding, &request.instance) {
            (Some(path), Some(instance)) => {
                let value = day2::json::decode(&read_bounded(path, JSON_LIMIT)?)
                    .context("invalid binding JSON")?;
                Some(Binding::check(value, instance)?)
            }
            _ => None,
        };
        let output = match &request.output {
            Some(path) => {
                let path = std::path::absolute(path)?;
                ensure!(
                    fs::symlink_metadata(&path).is_err(),
                    "instance source requires a new file: {}",
                    path.display()
                );
                ensure!(
                    path.parent().is_some_and(Path::is_dir),
                    "the new file's directory must exist: {}",
                    path.display()
                );
                Some(path)
            }
            None => None,
        };
        let archive = match &request.archive {
            Some(path) => {
                let path = std::path::absolute(path)?;
                ensure!(
                    fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_file()),
                    "the source archive must be a regular file: {}",
                    path.display()
                );
                Some(path)
            }
            None => None,
        };
        Ok(Self {
            mode,
            effects,
            instance: request.instance,
            binding,
            commit: request.commit,
            inputs: request.inputs,
            archive,
            output,
            done: 0,
            controls: None,
            run: None,
            job: None,
            checked: None,
            data: None,
            ci: None,
            found: None,
            deadline: None,
            announced: false,
        })
    }

    /// A session another host session runs in-process on files it owns: the
    /// instance and the binding are already validated, `output` is a new file
    /// in a private directory and `archive` a file that session wrote.
    pub fn embedded(
        mode: Mode,
        effects: Effects,
        instance: Instance,
        binding: Binding,
        given: Embedded,
    ) -> Self {
        Self {
            mode,
            effects,
            instance: Some(instance),
            binding: Some(binding),
            commit: given.commit,
            inputs: given.inputs,
            archive: given.archive,
            output: given.output,
            done: 0,
            controls: None,
            run: None,
            job: None,
            checked: None,
            data: None,
            ci: None,
            found: None,
            deadline: None,
            announced: false,
        }
    }

    /// The effects back, once an embedded session is done.
    pub fn into_effects(self) -> Effects {
        self.effects
    }

    /// Run the mode's next step, which must be `name`.
    pub fn step(&mut self, name: &str) -> Result<Value> {
        let expected = self.mode.steps().get(self.done).copied();
        let Some(next) = expected.filter(|next| *next == name) else {
            bail!(
                "instance source {} runs {} next, not {name}",
                self.mode.name(),
                expected.unwrap_or("nothing more")
            );
        };
        // With forge.oidc the same steps read app CI's run and results bucket, and the app repository's own
        // workflow artifacts are never read.
        let app_ci = self
            .instance
            .as_ref()
            .is_some_and(|instance| instance.app_ci.is_some());
        let value = match (self.mode, next) {
            (Mode::Head, _) => self.head()?,
            (Mode::Archive, _) => self.archive()?,
            (Mode::Controls, _) => self.controls()?,
            (Mode::VerifyControls, "controls") => self.approve_controls()?,
            (Mode::VerifyControls, _) => self.verify_controls()?,
            (_, "run") if app_ci => self.ci_run()?,
            (_, "job") if app_ci => self.ci_receipt()?,
            (_, "artifact") if app_ci => self.ci_artifact()?,
            (_, "download") if app_ci => self.ci_download()?,
            _ if app_ci => self.ci_attempt()?,
            (_, "run") => self.main_run()?,
            (_, "job") => self.job()?,
            (_, "artifact") => self.artifact()?,
            (_, "download") => self.download()?,
            _ => self.attempt()?,
        };
        self.done += 1;
        Ok(value)
    }

    fn binding(&self) -> Result<&Binding> {
        self.binding.as_ref().context("binding")
    }

    fn forge(&mut self) -> Result<(Forge<'_>, &Binding)> {
        let binding = self.binding.as_ref().context("binding")?;
        Ok((
            Forge::new(
                self.effects.transport.as_mut(),
                self.effects.token.as_deref(),
                &binding.server,
                &binding.repository,
            ),
            binding,
        ))
    }

    fn receipt(&self) -> Receipt {
        let binding = self.binding.as_ref();
        Receipt {
            format: 1,
            mode: self.mode,
            app_id: binding.map(|binding| binding.app.clone()),
            repository: binding.map(|binding| binding.repository.clone()),
            commit: self.commit.clone(),
            archive: None,
            controls: None,
            platform_commit: None,
            source_inputs: None,
            proof: None,
        }
    }

    /// Source.head: the binding's repository must still be the same
    /// repository, and its branch an exact commit.
    fn head(&mut self) -> Result<Value> {
        let (mut forge, binding) = self.forge()?;
        let prefix = forge.prefix.clone();
        let repository = match forge.get(&prefix, JSON_LIMIT, true)? {
            Got::Body(body) => decode(&body)?,
            Got::Status(status, _) => bail!("source_metadata_http_{status}"),
        };
        ensure!(
            *field(&repository, "id")? == binding.repository_id,
            "source_repository_identity_changed"
        );
        let url = format!("{prefix}/branches/{}", quote(&binding.branch));
        let branch = match forge.get(&url, JSON_LIMIT, true)? {
            Got::Body(body) => decode(&body)?,
            Got::Status(status, _) => bail!("source_metadata_http_{status}"),
        };
        let head = field(field(&branch, "commit")?, "id")?;
        let head = head
            .as_str()
            .filter(|head| commit(head) && *head != "0".repeat(40))
            .context("source_branch_commit_invalid")?
            .to_owned();
        self.commit = Some(head);
        Ok(serde_json::to_value(self.receipt())?)
    }

    /// Source.archive, for Gitea: the commit's archive, written to a new file.
    fn archive(&mut self) -> Result<Value> {
        let commit = self.commit.clone().context("commit")?;
        let (mut forge, _) = self.forge()?;
        let bytes = forge.archive(&commit)?;
        let output = self.output.clone().context("new archive")?;
        write_new(&output, &bytes)?;
        let identity = BlobIdentity::of(&bytes);
        Ok(serde_json::to_value(Receipt {
            archive: Some(File {
                path: text(&output)?.to_owned(),
                digest: identity.digest,
                bytes: identity.bytes,
            }),
            ..self.receipt()
        })?)
    }

    /// The archive to read and its identity.
    fn read_archive(&self) -> Result<(Controls, File)> {
        let path = self.archive.as_ref().context("source archive")?;
        let bytes = read_bounded(path, ARCHIVE_LIMIT)?;
        let identity = BlobIdentity::of(&bytes);
        let controls = Controls::read(&bytes)?;
        Ok((
            controls,
            File {
                path: text(path)?.to_owned(),
                digest: identity.digest,
                bytes: identity.bytes,
            },
        ))
    }

    /// The archive's CI-control digest.
    fn controls(&mut self) -> Result<Value> {
        let (controls, file) = self.read_archive()?;
        Ok(serde_json::to_value(Receipt {
            archive: Some(file),
            controls: Some(controls.digest()),
            ..self.receipt()
        })?)
    }

    /// The archive's control digest must be the binding's approved one, and its
    /// selected release the binding's, before anything is read from the bucket.
    fn approve_controls(&mut self) -> Result<Value> {
        let (controls, file) = self.read_archive()?;
        approved_controls(&controls, self.binding()?)?;
        let reported =
            json!({"controls": controls.digest(), "digest": file.digest, "bytes": file.bytes});
        self.controls = Some((controls, file));
        Ok(reported)
    }

    /// The binding's qualified release manifest, through the release cache:
    /// its digest and size verified, pinned under the instance's registry.
    fn release(&mut self) -> Result<Release> {
        let instance = self.instance.as_ref().context("instance")?;
        let reference = self.binding()?.qualified_release.clone();
        let root = match &self.effects.cache {
            Some(root) => root.clone(),
            None => instance_release::cache_root()?,
        };
        let objects = format!("gs://{}/{}", instance.bucket, instance_release::OBJECTS);
        let cache = instance_release::Cache::open(&root, &objects)?;
        let path = cache.fetch(&reference, MANIFEST_LIMIT, self.effects.tools.as_mut())?;
        let bytes = sdk_release::verify(&path, &reference, MANIFEST_LIMIT)
            .context("cached release bytes changed")?;
        let release = Release::decode(&bytes)?;
        release.pinned_under(&instance.registry)?;
        Ok(release)
    }

    /// Read the release, then check the rest of the approved controls against
    /// it. A failed bucket read is permanent, as a missing release is.
    fn verify_controls(&mut self) -> Result<Value> {
        let release = self.release()?;
        let (controls, file) = self.controls.take().context("approved controls")?;
        validate_controls(&controls, self.binding()?, &release)?;
        Ok(serde_json::to_value(Receipt {
            archive: Some(file),
            controls: Some(controls.digest()),
            platform_commit: Some(release.platform_commit.clone()),
            ..self.receipt()
        })?)
    }

    /// ci_artifact.main_run: wait within this job for the newest push run of
    /// the pinned workflow at exactly this main commit to complete, reading the
    /// runs at most every 20 s for up to 2100 s. It must be this repository's
    /// own run of its own commit, and must have succeeded.
    fn main_run(&mut self) -> Result<Value> {
        let commit = self.commit.clone().context("commit")?;
        let deadline = self.effects.clock.now() + WAIT;
        let mut announced = false;
        let path = format!("{WORKFLOW}@refs/heads/main");
        loop {
            let (mut forge, binding) = self.forge()?;
            let url = format!(
                "{}/actions/workflows/{WORKFLOW}/runs?branch=main&limit=50",
                forge.prefix
            );
            let page = forge.json(&url)?;
            let runs = field(&page, "workflow_runs")?
                .as_array()
                .context("source response lacks workflow_runs")?;
            let mut newest: Option<(&Value, u64)> = None;
            for run in runs {
                ensure!(run.is_object(), "source response lacks workflow runs");
                if run.get("head_sha") == Some(&json!(commit))
                    && run.get("event") == Some(&json!("push"))
                    && run.get("path") == Some(&json!(path))
                {
                    let id = run
                        .get("id")
                        .and_then(proof_id)
                        .context("invalid checked-artifact provenance")?;
                    if newest.is_none_or(|(_, best)| id > best) {
                        newest = Some((run, id));
                    }
                }
            }
            if let Some((run, id)) = newest {
                let attempt = run
                    .get("run_attempt")
                    .and_then(int)
                    .filter(|attempt| *attempt > 0);
                ensure!(
                    run.get("workflow_repository_id") == Some(&binding.repository_id)
                        && run
                            .get("repository")
                            .and_then(|repository| repository.get("id"))
                            == Some(&binding.repository_id)
                        && run.get("workflow_commit_sha") == Some(&json!(commit))
                        && run.get("head_branch") == Some(&json!("main"))
                        && attempt.is_some(),
                    "main CI workflow identity mismatch"
                );
                if *field(run, "status")? == "completed" {
                    ensure!(
                        run.get("conclusion") == Some(&json!("success")),
                        "main CI did not succeed; retry deployment after fixing CI"
                    );
                    let attempt = attempt
                        .and_then(|attempt| u64::try_from(attempt).ok())
                        .context("invalid checked-artifact provenance")?;
                    self.run = Some(Run { id, attempt });
                    return Ok(json!({"run": id, "attempt": attempt}));
                }
            }
            let clock = self.effects.clock.as_mut();
            if clock.now() >= deadline {
                return Err(Retryable(NOT_READY).into());
            }
            if !announced {
                clock.announce(WAITING);
                announced = true;
            }
            let left = deadline.saturating_sub(clock.now());
            clock.sleep(POLL.min(left));
        }
    }

    /// The run's one native job, of this attempt and commit, and the one
    /// receipt its log carries.
    fn job(&mut self) -> Result<Value> {
        let run = self.run.context("main run")?;
        let commit = self.commit.clone().context("commit")?;
        let inputs = self.inputs.clone().context("source inputs")?;
        let (mut forge, binding) = self.forge()?;
        let page = forge.json(&format!("{}/actions/runs/{}/jobs", forge.prefix, run.id))?;
        let jobs = field(&page, "jobs")?
            .as_array()
            .context("source response lacks jobs")?;
        ensure!(
            jobs.iter().all(Value::is_object),
            "source response lacks jobs"
        );
        let selected: Vec<&Value> = jobs
            .iter()
            .filter(|job| job.get("name") == Some(&json!(JOB)))
            .collect();
        ensure!(selected.len() == 1, "one native CI job required");
        let job = selected[0];
        ensure!(
            job.get("run_id") == Some(&json!(run.id))
                && job.get("head_sha") == Some(&json!(commit))
                && job.get("run_attempt") == Some(&json!(run.attempt))
                && job.get("status") == Some(&json!("completed"))
                && job.get("conclusion") == Some(&json!("success")),
            "native CI job identity/result mismatch"
        );
        let id = job
            .get("id")
            .and_then(proof_id)
            .context("invalid checked-artifact provenance")?;
        let url = format!("{}/actions/jobs/{id}/logs", forge.prefix);
        let log = match forge.get(&url, LOG_LIMIT, true)? {
            Got::Body(body) => body,
            Got::Status(status, _) => bail!("source_http_{status}"),
        };
        let log = String::from_utf8(log).map_err(|_| anyhow!("native job log is not UTF-8"))?;
        let lines = markers(&log);
        ensure!(
            lines.len() == 1,
            "one uploaded-artifact receipt required from the native job log"
        );
        let checked = decode(lines[0].as_bytes())?;
        receipt(&checked, &binding.value, &commit, &inputs)?;
        let upload = checked["upload_id"].clone();
        self.job = Some(id);
        self.checked = Some(checked);
        Ok(json!({"job": id, "upload_id": upload}))
    }

    /// The upload the receipt names: this run's, of this repository and
    /// commit, not expired, and within the ZIP budget.
    fn artifact(&mut self) -> Result<Value> {
        let run = self.run.context("main run")?;
        let commit = self.commit.clone().context("commit")?;
        let checked = self.checked.clone().context("job receipt")?;
        let (mut forge, binding) = self.forge()?;
        let upload = proof_id(&checked["upload_id"]).context("job receipt")?;
        let artifact = forge.json(&format!("{}/actions/artifacts/{upload}", forge.prefix))?;
        let workflow_run = artifact.get("workflow_run");
        let at = |name: &str| workflow_run.and_then(|value| value.get(name));
        ensure!(
            artifact.get("id") == Some(&checked["upload_id"])
                && artifact.get("name") == Some(&checked["artifact_name"])
                && artifact.get("expired") == Some(&Value::Bool(false))
                && artifact
                    .get("size_in_bytes")
                    .and_then(int)
                    .is_some_and(|size| size > 0 && size <= i128::from(ZIP_LIMIT))
                && at("id") == Some(&json!(run.id))
                && at("repository_id") == Some(&binding.repository_id)
                && at("head_sha") == Some(&json!(commit)),
            "uploaded artifact belongs to another run/source or has expired"
        );
        Ok(json!({"upload_id": upload, "size_in_bytes": artifact["size_in_bytes"]}))
    }

    /// Source.artifact_zip, then unpack_zip, in memory.
    fn download(&mut self) -> Result<Value> {
        let checked = self.checked.clone().context("job receipt")?;
        let upload = proof_id(&checked["upload_id"]).context("job receipt")?;
        let expected = blob(&checked["archive"], ARTIFACT_LIMIT)?;
        let (mut forge, binding) = self.forge()?;
        let raw = forge.artifact_zip(upload, &binding.server)?;
        let data = unpack_zip(&raw, &expected)?;
        self.data = Some(data);
        Ok(json!({"digest": expected.digest, "bytes": expected.bytes}))
    }

    /// A rerun can begin during the download: the run must still be the same
    /// successful attempt. Only then is the archive written, and the proof
    /// returned.
    fn attempt(&mut self) -> Result<Value> {
        let run = self.run.context("main run")?;
        let job = self.job.context("native job")?;
        let commit = self.commit.clone().context("commit")?;
        let inputs = self.inputs.clone().context("source inputs")?;
        let checked = self.checked.clone().context("job receipt")?;
        let (mut forge, binding) = self.forge()?;
        let latest = forge.json(&format!("{}/actions/runs/{}", forge.prefix, run.id))?;
        ensure!(
            latest.get("run_attempt") == Some(&json!(run.attempt))
                && latest.get("status") == Some(&json!("completed"))
                && latest.get("conclusion") == Some(&json!("success")),
            "main CI attempt changed during artifact download"
        );
        let evidence = json!({"version": 1, "run": run.id, "attempt": run.attempt,
            "job": job, "receipt": checked});
        proof(&evidence, &binding.value, &commit, &inputs)?;
        let expected = blob(&checked["archive"], ARTIFACT_LIMIT)?;
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

/// One repository on the instance's forge: the binding's for a source command,
/// the job's own for `day2 ci fetch`.
pub(crate) struct Forge<'a> {
    transport: &'a mut dyn Transport,
    token: Option<&'a str>,
    /// `<server>/api/v1/repos/<repository>`.
    pub(crate) prefix: String,
}

impl<'a> Forge<'a> {
    pub(crate) fn new(
        transport: &'a mut dyn Transport,
        token: Option<&'a str>,
        server: &str,
        repository: &str,
    ) -> Self {
        Self {
            transport,
            token,
            prefix: format!("{server}/api/v1/repos/{repository}"),
        }
    }

    /// Source.archive, for Gitea: a commit's archive, at most 64 MiB. Deploy
    /// and app CI read a commit's tree only through this.
    pub(crate) fn archive(&mut self, commit: &str) -> Result<Vec<u8>> {
        ensure!(crate::instance_source::commit(commit), "invalid commit");
        let url = format!("{}/archive/{commit}.tar.gz", self.prefix);
        match self.get(&url, ARCHIVE_LIMIT, true)? {
            Got::Body(body) => Ok(body),
            Got::Status(status, _) => bail!("source_archive_http_{status}"),
        }
    }

    /// Source.get: 408, 429 and 5xx are retryable; a 2xx body over `limit`
    /// is refused; any other status is the caller's to report.
    fn get(&mut self, url: &str, limit: u64, authenticated: bool) -> Result<Got> {
        let token = self.token.filter(|_| authenticated);
        let response = self.transport.get(url, token, limit)?;
        match response.status {
            200..=299 => {
                ensure!(
                    response.body.len() as u64 <= limit,
                    "source_response_byte_limit"
                );
                Ok(Got::Body(response.body))
            }
            408 | 429 | 500.. => Err(Retryable(TEMPORARY).into()),
            status => Ok(Got::Status(status, response.location)),
        }
    }

    /// The repository's own record: 404 is a repository that does not exist
    /// or that the token cannot read, and a renamed repository's redirect is
    /// never followed.
    pub(crate) fn repository(&mut self) -> Result<Value> {
        let url = self.prefix.clone();
        match self.get(&url, JSON_LIMIT, true)? {
            Got::Body(body) => decode(&body),
            Got::Status(404, _) => bail!("forge_repository_missing"),
            Got::Status(status, _) => bail!("forge_repository_http_{status}"),
        }
    }

    /// A JSON read Python left to urllib's HTTPError on any other status.
    pub(crate) fn json(&mut self, url: &str) -> Result<Value> {
        match self.get(url, JSON_LIMIT, true)? {
            Got::Body(body) => decode(&body),
            Got::Status(status, _) => bail!("source_http_{status}"),
        }
    }

    /// Source.artifact_zip: one 302 may be followed, to an https URL on the
    /// forge itself or on storage.googleapis.com (or a bucket host under it),
    /// with no userinfo or fragment. Only this artifact's same-origin `/raw`
    /// route receives the forge token; a second redirect is refused.
    fn artifact_zip(&mut self, upload: u64, server: &str) -> Result<Vec<u8>> {
        let url = format!("{}/actions/artifacts/{upload}/zip", self.prefix);
        let location = match self.get(&url, ZIP_LIMIT, true)? {
            Got::Body(body) => return Ok(body),
            Got::Status(302, location) => location.unwrap_or_default(),
            Got::Status(status, _) => bail!("checked_artifact_download_http_{status}"),
        };
        let (target, forge) = (urlsplit(&location), urlsplit(server));
        let same = target.netloc == forge.netloc;
        let allowed =
            same || target.netloc == "storage.googleapis.com" || storage_host(&target.netloc);
        ensure!(
            target.scheme == "https"
                && allowed
                && !target.netloc.contains('@')
                && target.fragment.is_empty(),
            "checked_artifact_redirect_refused"
        );
        // The request goes to exactly the host just allowed.
        let parsed = reqwest::Url::parse(&location)
            .map_err(|_| anyhow!("checked_artifact_redirect_refused"))?;
        ensure!(
            parsed.scheme() == "https"
                && parsed.host_str() == Some(target.netloc.as_str())
                && parsed.port().is_none()
                && parsed.username().is_empty()
                && parsed.password().is_none(),
            "checked_artifact_redirect_refused"
        );
        let authenticated = same && target.path == format!("{}/raw", urlsplit(&url).path);
        match self.get(&location, ZIP_LIMIT, authenticated)? {
            Got::Body(body) => Ok(body),
            Got::Status(status, _) => bail!("checked_artifact_download_http_{status}"),
        }
    }
}

pub mod app_ci;

#[cfg(test)]
pub(crate) mod tests;
