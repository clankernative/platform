//! `day2 ci store DIRECTORY`: the last step of the org-scoped app CI
//! workflow. After `day2 ci fetch DIRECTORY` and `day2 ci check
//! DIRECTORY/head [DIRECTORY/base] CASES DIRECTORY/out`, it stores the
//! checked artifact and its receipt, write-once, in the app's CI bucket:
//!
//! `gs://<project>-<app>-ci/<sdk>/<source inputs>-<cases>/<run>/<attempt>/`
//!
//! with `artifact.tar.gz` first and `receipt.json`, the commit marker, last.
//! `<sdk>` is the hex of the app's selected SDK release manifest digest and
//! `<source inputs>` the hex of the receipt's source inputs.
//!
//! - **Nothing to store.** A routed pull request run writes no artifact: the
//!   command says so and succeeds without reading any store input. A push run
//!   checks every lane, so it must have one.
//! - **Run.** `DIRECTORY/event.json` must be the step's own run: its
//!   repository, event, head, run, attempt and workflow commit are the step's
//!   `GITHUB_*` variables.
//! - **Inputs.** The token request, the bucket, the workload identity provider
//!   audience, the SDK release and its tooling distribution come from the
//!   rendered workflow (the store step's own `env:`, which `$GITHUB_ENV` cannot
//!   override), never from the app repository: `ACTIONS_ID_TOKEN_REQUEST_URL`
//!   (exactly `https://<forge.oidc>/token?v=1&repository=<the run's>`),
//!   `DAY2_CI_BUCKET` (`<project>-<app>-ci` for the run's app),
//!   `DAY2_CI_AUDIENCE`, `DAY2_CI_SDK` and `DAY2_CI_DISTRIBUTION`.
//! - **Receipt.** It must name that distribution and the source inputs of the
//!   fetched head's `app/`, recomputed here.
//! - **Credential.** git-oidc mints the job an OIDC token for the audience
//!   (`GET ${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=<audience>` with
//!   `Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}`, retried as the
//!   instance workflows retry it); Google STS exchanges it for a federated
//!   access token limited to Cloud Storage. There is no service account and
//!   no key. Neither token, nor the job token, is ever printed.
//! - **Uploads.** Create-only (`ifGenerationMatch=0`), each with the run,
//!   attempt, head commit, event and (when known) workflow commit as object
//!   metadata. The artifact's digest is checked against the receipt's again
//!   immediately before its bytes are sent. Any failure, a precondition
//!   failure included, fails the step and so the required job.
use crate::{
    ci_check::Receipt,
    ci_fetch::{Environment, Event, Transient, Waiting, retrying},
    instance_source,
    offsite::{self, Uploader},
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use day2::sdk_release::BlobIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(test)]
mod tests;

/// The git-oidc request URL the runner or workflow provides.
pub const ID_TOKEN_URL: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";
/// The job token git-oidc checks the request with.
pub const ID_TOKEN: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";
pub const BUCKET: &str = "DAY2_CI_BUCKET";
pub const AUDIENCE: &str = "DAY2_CI_AUDIENCE";
pub const SDK: &str = "DAY2_CI_SDK";
pub const DISTRIBUTION: &str = "DAY2_CI_DISTRIBUTION";
/// Where `day2 ci check` writes the artifact in the run's directory.
pub const OUTPUT: &str = "out";
pub const STS: &str = "https://sts.googleapis.com/v1/token";
/// The only access the exchanged token carries.
pub const SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_write";
/// Why a pull request run stores nothing.
pub const PULL_REQUEST: &str = "pull_request runs are verified, not stored: code the check step \
     ran could have written their artifact, so only main's push run is stored";
const ARTIFACT: &str = "artifact.tar.gz";
const RECEIPT: &str = "receipt.json";
const LANES: [&str; 3] = ["native", "extension", "javascript"];
const REQUEST_LIMIT: u64 = 65_536;
const RESPONSE_LIMIT: u64 = 65_536;
/// One mint request's longest wait, as the instance workflows' `--max-time`.
const MINT_ATTEMPT: Duration = Duration::from_secs(45);
const EXCHANGE: Duration = Duration::from_secs(60);
const UPLOAD: Duration = Duration::from_secs(900);

/// What the store step's environment provides.
#[derive(Clone)]
pub struct Inputs {
    pub id_token_url: String,
    pub id_token: String,
    pub bucket: String,
    /// The provider's https audience:
    /// `https://iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`.
    pub audience: String,
    /// The app's selected SDK release manifest, `sha256:<hex>`.
    pub sdk: String,
    /// That release's precompiled tooling distribution, `sha256:<hex>`: the SDK
    /// identity a receipt checked on its tooling records.
    pub distribution: String,
}

impl Inputs {
    /// Read and validate the variables. A value is never echoed in a refusal.
    pub fn read(variable: impl Fn(&str) -> Option<OsString>, https: bool) -> Result<Self> {
        let required = |name: &str| -> Result<String> {
            variable(name)
                .filter(|value| !value.is_empty())
                .with_context(|| {
                    format!(
                        "{name} is required to store the artifact: the workflow rendered from \
                         day2.json with forge.oidc sets it"
                    )
                })?
                .into_string()
                .map_err(|_| anyhow!("{name} must be UTF-8"))
        };
        let inputs = Self {
            id_token_url: required(ID_TOKEN_URL)?,
            id_token: required(ID_TOKEN)?,
            bucket: required(BUCKET)?,
            audience: required(AUDIENCE)?,
            sdk: required(SDK)?,
            distribution: required(DISTRIBUTION)?,
        };
        let url = reqwest::Url::parse(&inputs.id_token_url)
            .map_err(|_| anyhow!("{ID_TOKEN_URL} must be a URL"))?;
        // Exactly the request the rendered workflow pins: `<forge.oidc>/token?v=1
        // &repository=<org>/<app>`; the repository is checked against the run.
        let query: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        ensure!(
            ((url.scheme() == "https" && url.port().is_none()) || !https)
                && url.fragment().is_none()
                && url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/token"
                && query.len() == 2
                && query[0] == ("v".to_owned(), "1".to_owned())
                && query[1].0 == "repository",
            "{ID_TOKEN_URL} must be the rendered https://<broker>/token?v=1&repository=<repository>"
        );
        ensure!(
            inputs.id_token.bytes().all(|b| b.is_ascii_graphic()),
            "{ID_TOKEN} must be a token"
        );
        offsite::validate_bucket(&inputs.bucket).context(BUCKET)?;
        ensure!(
            provider(&inputs.audience),
            "{AUDIENCE} must be a workload identity provider's https audience"
        );
        ensure!(
            instance_source::hash(&inputs.sdk),
            "{SDK} must be a release manifest digest, sha256:<hex>"
        );
        ensure!(
            instance_source::hash(&inputs.distribution),
            "{DISTRIBUTION} must be a tooling distribution digest, sha256:<hex>"
        );
        Ok(inputs)
    }

    /// The STS audience: the provider's full resource name, the https
    /// audience without its scheme.
    pub fn sts_audience(&self) -> &str {
        self.audience.trim_start_matches("https:")
    }

    /// The repository the token request names.
    fn repository(&self) -> Option<String> {
        reqwest::Url::parse(&self.id_token_url)
            .ok()?
            .query_pairs()
            .find(|(key, _)| key == "repository")
            .map(|(_, value)| value.into_owned())
    }
}

/// The store inputs and the receipt belong to this run: the bucket is the
/// run's app's, the token request names the run's repository, the receipt was
/// checked on the selected release's tooling distribution, and its source
/// inputs are those of the fetched head's app.
fn bound(inputs: &Inputs, event: &Event, receipt: &Receipt, directory: &Path) -> Result<()> {
    ensure!(
        app_bucket(&inputs.bucket, event.app()),
        "{BUCKET} is not the app's CI bucket, <project>-{}-ci",
        event.app()
    );
    ensure!(
        inputs.repository().as_deref() == Some(event.repository.as_str()),
        "{ID_TOKEN_URL} names another repository than the run's"
    );
    ensure!(
        receipt.sdk_distribution.digest == inputs.distribution,
        "the artifact was checked on another SDK's tooling than {DISTRIBUTION} names"
    );
    let head = crate::ci_check::source_inputs(&directory.join("head").join(crate::ci_fetch::APP))?;
    ensure!(
        receipt.source_inputs == head,
        "the receipt's source inputs are not the fetched head app's"
    );
    Ok(())
}

/// `https://iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`.
pub fn provider(audience: &str) -> bool {
    let name = |part: &str| {
        (4..=32).contains(&part.len())
            && part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let Some(rest) = audience.strip_prefix("https://iam.googleapis.com/projects/") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('/').collect();
    matches!(
        parts.as_slice(),
        [number, "locations", "global", "workloadIdentityPools", pool, "providers", provider]
            if !number.is_empty()
                && number.len() <= 20
                && number.bytes().all(|b| b.is_ascii_digit())
                && name(pool)
                && name(provider)
    )
}

/// The app's CI bucket, as InstanceSpec derives it: `<project>-<app>-ci`.
fn app_bucket(bucket: &str, app: &str) -> bool {
    bucket
        .strip_suffix(&format!("-{app}-ci"))
        .is_some_and(|project| (6..=30).contains(&project.len()))
}

/// Where the token exchange and the uploads go. Tests pass a local server.
pub struct Endpoints {
    pub sts: String,
    pub upload: String,
    /// Whether every endpoint, git-oidc's included, must be https: always,
    /// except against a test's local servers.
    pub https: bool,
}

impl Endpoints {
    pub fn google() -> Self {
        Self {
            sts: STS.to_owned(),
            upload: offsite::GCS_UPLOAD_URL.to_owned(),
            https: true,
        }
    }
}

/// A step's environment, by variable name.
pub type Variables = Box<dyn Fn(&str) -> Option<OsString>>;

/// What the session reaches outside itself.
pub struct Effects {
    pub client: reqwest::blocking::Client,
    pub waiting: Box<dyn Waiting>,
    pub endpoints: Endpoints,
    /// The step's environment: the run as the runner describes it, and the
    /// store inputs, read only when there is an artifact to store.
    pub variables: Variables,
}

impl Effects {
    /// HTTPS only, no redirects and no proxy; Google's endpoints; the process
    /// environment.
    pub fn native() -> Result<Self> {
        Ok(Self {
            client: client(true)?,
            waiting: Box::new(instance_source::System::new()),
            endpoints: Endpoints::google(),
            variables: Box::new(|name| std::env::var_os(name)),
        })
    }
}

/// A client that never follows a redirect, connects within 10 s and ignores
/// proxy variables, which an earlier step could set through `$GITHUB_ENV`.
pub fn client(https_only: bool) -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(10))
        .timeout(UPLOAD)
        .redirect(reqwest::redirect::Policy::none())
        .https_only(https_only)
        .build()
        .context("CI store HTTP client")
}

/// What the CLI hands the host.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub directory: PathBuf,
}

/// One stored object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Object {
    pub name: String,
    pub bytes: u64,
    pub digest: String,
    pub generation: String,
}

/// What `day2 ci store` prints. cli/fixtures/ci-store-report.json pins the
/// shape for the host and the CLI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub format: u32,
    pub repository: String,
    pub event: String,
    pub run: u64,
    pub attempt: u64,
    /// Whether the run's artifact was stored; when not, why.
    pub stored: bool,
    pub reason: Option<String>,
    pub bucket: Option<String>,
    pub prefix: Option<String>,
    pub objects: Vec<Object>,
}

/// The checked artifact `ci check` wrote: its receipt, exactly as read.
struct Checked {
    receipt: Receipt,
    bytes: Vec<u8>,
}

pub struct Session {
    directory: PathBuf,
    effects: Effects,
    event: Event,
    checked: Option<Checked>,
    inputs: Option<Inputs>,
    done: Vec<&'static str>,
    subject: Option<String>,
    access: Option<String>,
    objects: Vec<Object>,
}

impl Session {
    /// Validate the request, the run's record, the inputs against it and, when
    /// `ci check` wrote one, the artifact's receipt. Nothing leaves the host.
    pub fn prepare(path: &Path, effects: Effects) -> Result<Self> {
        let raw = day2_assets::read_regular(path, REQUEST_LIMIT)?;
        let request: Request = day2::json::decode(&raw)?;
        let directory = std::path::absolute(&request.directory)?;
        ensure!(
            fs::symlink_metadata(&directory).is_ok_and(|metadata| metadata.is_dir()),
            "ci store requires the run's directory, as ci fetch wrote it: {}",
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
        // Only main's push run, which runs reviewed code, is stored: code the
        // check step ran could have written a pull request run's artifact.
        let output = directory.join(OUTPUT);
        let checked = match fs::symlink_metadata(&output) {
            _ if event.event != "push" => None,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => bail!(
                "a push run checks every lane and must store its artifact, but ci check wrote \
                 none to {}",
                output.display()
            ),
            Err(error) => return Err(error.into()),
            Ok(metadata) => {
                ensure!(
                    metadata.is_dir(),
                    "{} must be ci check's output directory",
                    output.display()
                );
                Some(checked(&output)?)
            }
        };
        // Only an artifact to store needs the store inputs and the credential.
        let inputs = match &checked {
            Some(checked) => {
                let inputs = Inputs::read(&*effects.variables, effects.endpoints.https)?;
                bound(&inputs, &event, &checked.receipt, &directory)?;
                Some(inputs)
            }
            None => None,
        };
        Ok(Self {
            directory,
            effects,
            event,
            checked,
            inputs,
            done: Vec::new(),
            subject: None,
            access: None,
            objects: Vec::new(),
        })
    }

    fn inputs(&self) -> Result<&Inputs> {
        self.inputs.as_ref().context("the store inputs")
    }

    /// Whether there is an artifact to store, which the recipe's order follows.
    pub fn plan(&self) -> Value {
        json!({"artifact": self.checked.is_some()})
    }

    fn next(&self) -> Option<&'static str> {
        let steps: &[&'static str] = if self.checked.is_some() {
            &["mint", "exchange", "artifact", "receipt", "result"]
        } else {
            &["result"]
        };
        steps.get(self.done.len()).copied()
    }

    /// Run the next step, which must be `name`.
    pub fn step(&mut self, name: &str) -> Result<Value> {
        let expected = self.next();
        let Some(step) = expected.filter(|step| *step == name) else {
            bail!(
                "ci store runs {} next, not {name}",
                expected.unwrap_or("nothing more")
            );
        };
        let value = match step {
            "mint" => self.mint()?,
            "exchange" => self.exchange()?,
            "artifact" => self.artifact()?,
            "receipt" => self.receipt()?,
            _ => self.result()?,
        };
        self.done.push(step);
        Ok(value)
    }

    /// git-oidc's token for the audience, as the instance workflows request
    /// it: network failures, 408, 429 and 5xx are retried within 120 s; any
    /// other answer fails at once with git-oidc's reason.
    fn mint(&mut self) -> Result<Value> {
        let inputs = self.inputs.as_ref().context("the store inputs")?;
        // The URL already has its query (checked when the inputs were read).
        let url = format!(
            "{}&audience={}",
            inputs.id_token_url,
            instance_source::quote(&inputs.audience)
        );
        let authorization = header(&format!("bearer {}", inputs.id_token))?;
        let client = &self.effects.client;
        let token = retrying(
            self.effects.waiting.as_mut(),
            "git-oidc's token mint",
            |left| {
                let response = client
                    .get(&url)
                    .header(reqwest::header::AUTHORIZATION, authorization.clone())
                    .timeout(left.min(MINT_ATTEMPT))
                    .send()
                    .map_err(|_| Transient("git-oidc could not be reached".to_owned()))?;
                let status = response.status().as_u16();
                let body = bounded(response)?;
                match status {
                    200 => Ok(body),
                    408 | 429 | 500.. => Err(Transient(format!(
                        "git-oidc answered HTTP {status}: {}",
                        excerpt(&body)
                    ))
                    .into()),
                    _ => bail!(
                        "git-oidc refused the token request with HTTP {status}: {}",
                        excerpt(&body)
                    ),
                }
            },
        )?;
        let value: Value =
            serde_json::from_slice(&token).map_err(|_| anyhow!("git-oidc returned no JSON"))?;
        let subject = value["value"]
            .as_str()
            .filter(|token| jwt(token))
            .context("git-oidc returned no token")?;
        self.subject = Some(subject.to_owned());
        Ok(json!({"minted": true}))
    }

    /// Google STS: the subject token for a federated access token limited to
    /// Cloud Storage. A refusal fails at once with STS's error code.
    fn exchange(&mut self) -> Result<Value> {
        let subject = self.subject.take().context("the minted token")?;
        let body = json!({
            "audience": self.inputs()?.sts_audience(),
            "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
            "scope": SCOPE,
            "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
            "subjectToken": subject,
        });
        let response = self
            .effects
            .client
            .post(&self.effects.endpoints.sts)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .timeout(EXCHANGE)
            .send()
            .map_err(|_| anyhow!("Google STS could not be reached"))?;
        let status = response.status().as_u16();
        let bytes = bounded(response)?;
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        ensure!(
            status == 200,
            "Google STS refused the token exchange with HTTP {status}: {}",
            excerpt(
                format!(
                    "{} {}",
                    value["error"].as_str().unwrap_or_default(),
                    value["error_description"].as_str().unwrap_or_default()
                )
                .as_bytes()
            )
        );
        let access = value["access_token"]
            .as_str()
            .filter(|token| !token.is_empty() && token.bytes().all(|b| b.is_ascii_graphic()))
            .filter(|_| {
                value["token_type"]
                    .as_str()
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("bearer"))
            })
            .context("Google STS returned no bearer access token")?;
        self.access = Some(access.to_owned());
        Ok(json!({"exchanged": true}))
    }

    /// `<sdk>/<source inputs>-<cases>/<run>/<attempt>`.
    fn prefix(&self) -> Result<String> {
        let receipt = &self
            .checked
            .as_ref()
            .context("the checked artifact")?
            .receipt;
        let hex = |digest: &str| digest.trim_start_matches("sha256:").to_owned();
        Ok(format!(
            "{}/{}-{}/{}/{}",
            hex(&self.inputs()?.sdk),
            hex(&receipt.source_inputs),
            receipt.verification.cases,
            self.event.run,
            self.event.attempt
        ))
    }

    /// The run as object metadata.
    fn metadata(&self) -> BTreeMap<String, String> {
        let mut metadata = BTreeMap::new();
        metadata.insert("run".into(), self.event.run.to_string());
        metadata.insert("attempt".into(), self.event.attempt.to_string());
        metadata.insert("head".into(), self.event.head.clone());
        metadata.insert("event".into(), self.event.event.clone());
        if let Some(commit) = &self.event.workflow_commit {
            metadata.insert("workflow_commit".into(), commit.clone());
        }
        metadata
    }

    fn upload(&mut self, file: &str, bytes: &[u8], content_type: &str) -> Result<Value> {
        let name = format!("{}/{file}", self.prefix()?);
        let token = self.access.clone().context("the access token")?;
        let uploader = Uploader::new(
            self.effects.client.clone(),
            &self.effects.endpoints.upload,
            &self.inputs()?.bucket,
            token,
        )?;
        let stored = uploader.put_with_metadata(&name, bytes, content_type, &self.metadata())?;
        let object = Object {
            name,
            bytes: bytes.len() as u64,
            digest: day2::digest(bytes),
            generation: stored["generation"]
                .as_str()
                .context("stored generation")?
                .to_owned(),
        };
        self.objects.push(object.clone());
        Ok(serde_json::to_value(object)?)
    }

    /// `artifact.tar.gz`: the bytes are read once, checked against the
    /// receipt's archive and only then sent.
    fn artifact(&mut self) -> Result<Value> {
        let expected = self
            .checked
            .as_ref()
            .context("the checked artifact")?
            .receipt
            .archive
            .clone();
        let path = self.directory.join(OUTPUT).join("app.tar.gz");
        let bytes = day2_assets::read_regular(&path, instance_source::ARTIFACT_LIMIT)?;
        ensure!(
            BlobIdentity::of(&bytes) == expected,
            "the artifact changed after ci check: its digest is not the receipt's"
        );
        self.upload(ARTIFACT, &bytes, "application/gzip")
    }

    /// `receipt.json`, unchanged since it was checked, last: the marker that
    /// the artifact beside it is complete.
    fn receipt(&mut self) -> Result<Value> {
        let path = self.directory.join(OUTPUT).join(RECEIPT);
        let bytes = day2_assets::read_regular(&path, REQUEST_LIMIT)?;
        let checked = self.checked.as_ref().context("the checked artifact")?;
        ensure!(
            bytes == checked.bytes,
            "the receipt changed after it was checked"
        );
        self.upload(RECEIPT, &bytes, "application/json")
    }

    fn result(&mut self) -> Result<Value> {
        let stored = self.checked.is_some();
        Ok(serde_json::to_value(Report {
            format: 1,
            repository: self.event.repository.clone(),
            event: self.event.event.clone(),
            run: self.event.run,
            attempt: self.event.attempt,
            stored,
            reason: (!stored).then(|| PULL_REQUEST.to_owned()),
            bucket: self.inputs.as_ref().map(|inputs| inputs.bucket.clone()),
            prefix: if stored { Some(self.prefix()?) } else { None },
            objects: self.objects.clone(),
        })?)
    }
}

/// `ci check`'s output: exactly `app.tar.gz` and `receipt.json`, regular
/// files, the receipt a complete run's: every lane, seed 42, 4 to 100 cases,
/// an archive within the artifact budget whose size the file has.
fn checked(output: &Path) -> Result<Checked> {
    let mut names = Vec::new();
    for entry in fs::read_dir(output)? {
        let entry = entry?;
        ensure!(
            entry.file_type()?.is_file(),
            "ci check's output holds only regular files"
        );
        names.push(entry.file_name());
    }
    names.sort();
    ensure!(
        names == [OsString::from("app.tar.gz"), OsString::from(RECEIPT)],
        "ci check's output must hold exactly app.tar.gz and receipt.json"
    );
    let bytes = day2_assets::read_regular(&output.join(RECEIPT), REQUEST_LIMIT)?;
    let receipt: Receipt = day2::json::decode(&bytes).context("invalid ci check receipt")?;
    let verification = &receipt.verification;
    ensure!(
        receipt.version == 1
            && receipt.lanes == LANES
            && instance_source::hash(&receipt.source_inputs)
            && instance_source::lower_hex(&receipt.artifact_id, 64)
            && instance_source::hash(&receipt.sdk_distribution.digest)
            && receipt.sdk_distribution.bytes > 0
            && instance_source::hash(&receipt.archive.digest)
            && (1..=instance_source::ARTIFACT_LIMIT).contains(&receipt.archive.bytes)
            && verification.version == 1
            && verification.seed == crate::ci_check::SEED
            && (4..=100).contains(&verification.cases)
            && receipt.generated > 0,
        "invalid ci check receipt"
    );
    ensure!(
        fs::symlink_metadata(output.join("app.tar.gz"))?.len() == receipt.archive.bytes,
        "the artifact is not the size its receipt names"
    );
    Ok(Checked { receipt, bytes })
}

fn header(value: &str) -> Result<reqwest::header::HeaderValue> {
    let mut value = reqwest::header::HeaderValue::from_str(value)
        .map_err(|_| anyhow!("the token is not a valid header value"))?;
    value.set_sensitive(true);
    Ok(value)
}

/// A response body of at most 64 KiB; a longer or unreadable one is transient.
fn bounded(response: reqwest::blocking::Response) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    response
        .take(RESPONSE_LIMIT + 1)
        .read_to_end(&mut body)
        .map_err(|_| Transient("the response body could not be read".to_owned()))?;
    ensure!(
        body.len() as u64 <= RESPONSE_LIMIT,
        "the response exceeds 64 KiB"
    );
    Ok(body)
}

/// At most 512 bytes of a reason, printable ASCII only.
fn excerpt(body: &[u8]) -> String {
    body.iter()
        .take(512)
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '?'
            }
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Three base64url segments: a JWT, not an arbitrary string.
fn jwt(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}
