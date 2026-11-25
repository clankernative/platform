use super::*;
use crate::{ci_check::Verification, instance_source::tests::Fake};
use std::{
    collections::{BTreeMap, VecDeque},
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
};

const HEAD: &str = "1111111111111111111111111111111111111111";
const BASE: &str = "2222222222222222222222222222222222222222";
const WORKFLOW: &str = "3333333333333333333333333333333333333333";
const JOB_TOKEN: &str = "synthetic-job-token";
// A synthetic JWT, assembled so secret scanners don't mistake the fixture for a token.
const SUBJECT: &str = concat!(
    "eyJhbGciOiJSUzI1NiJ9",
    ".",
    "eyJzdWIiOiJyZXBvIn0",
    ".",
    "c2lnbmF0dXJl"
);
const ACCESS: &str = "ya29.synthetic-access-token";
const BUCKET_NAME: &str = "exampleco-tools-links-ci";
const AUDIENCE_URL: &str = "https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/day2-ci/providers/gitea";
const GOLDEN_REPORT: &str = include_str!("../../../../cli/fixtures/ci-store-report.json");

fn sdk() -> String {
    format!("sha256:{}", "5d".repeat(32))
}

/// One request the fake servers saw.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl Seen {
    fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or_default()
    }

    fn query(&self, key: &str) -> Option<String> {
        reqwest::Url::parse(&format!("http://fake{}", self.target))
            .unwrap()
            .query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.into_owned())
    }

    /// A multipart upload's resource and bytes.
    fn parts(&self) -> (Value, Vec<u8>) {
        let boundary = self.headers["content-type"]
            .strip_prefix("multipart/related; boundary=")
            .unwrap()
            .to_owned();
        let separator = format!("\r\n--{boundary}");
        let body = &self.body;
        let find = |needle: &[u8], from: usize| {
            body[from..]
                .windows(needle.len())
                .position(|window| window == needle)
                .map(|at| at + from)
                .unwrap()
        };
        let first = find(b"\r\n\r\n", 0) + 4;
        let end = find(separator.as_bytes(), first);
        let resource = serde_json::from_slice(&body[first..end]).unwrap();
        let second = find(b"\r\n\r\n", end) + 4;
        let close = find(format!("\r\n--{boundary}--\r\n").as_bytes(), second);
        (resource, body[second..close].to_vec())
    }
}

/// Fake git-oidc, Google STS and Cloud Storage: scripted answers; the last
/// mint answer repeats.
#[derive(Default)]
struct Script {
    mint: VecDeque<(u16, String)>,
    sts: Option<(u16, String)>,
    /// An upload status for object names ending in the given text.
    refuse: Option<(String, u16)>,
    /// A successful upload's reply body for object names ending in the given text.
    reply: Option<(String, String)>,
    seen: Vec<Seen>,
}

struct Servers {
    base: String,
    script: Arc<Mutex<Script>>,
}

impl Servers {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let script = Arc::new(Mutex::new(Script {
            mint: [(200, json!({"value": SUBJECT}).to_string())].into(),
            ..Script::default()
        }));
        let shared = script.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    continue;
                }
                let mut words = line.split_whitespace();
                let method = words.next().unwrap_or_default().to_owned();
                let target = words.next().unwrap_or_default().to_owned();
                let mut headers = BTreeMap::new();
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    let header = header.trim_end();
                    if header.is_empty() {
                        break;
                    }
                    let (name, value) = header.split_once(':').unwrap();
                    headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
                }
                let length = headers
                    .get("content-length")
                    .map_or(0, |length| length.parse::<usize>().unwrap());
                let mut body = vec![0; length];
                std::io::Read::read_exact(&mut reader, &mut body).unwrap();
                let seen = Seen {
                    method,
                    target,
                    headers,
                    body,
                };
                let mut script = shared.lock().unwrap();
                let (status, response) = if seen.path() == "/token" {
                    if script.mint.len() > 1 {
                        script.mint.pop_front().unwrap()
                    } else {
                        script.mint.front().cloned().unwrap()
                    }
                } else if seen.path() == "/v1/token" {
                    script.sts.clone().unwrap_or((
                        200,
                        json!({"access_token": ACCESS, "issued_token_type":
                            "urn:ietf:params:oauth:token-type:access_token",
                            "token_type": "Bearer", "expires_in": 3599})
                        .to_string(),
                    ))
                } else {
                    let (resource, data) = seen.parts();
                    let name = resource["name"].as_str().unwrap().to_owned();
                    match &script.refuse {
                        Some((suffix, status)) if name.ends_with(suffix.as_str()) => {
                            (*status, "{}".to_owned())
                        }
                        _ if script
                            .reply
                            .as_ref()
                            .is_some_and(|(suffix, _)| name.ends_with(suffix.as_str())) =>
                        {
                            (200, script.reply.clone().unwrap().1)
                        }
                        _ => (
                            200,
                            json!({"name": name, "bucket": BUCKET_NAME,
                                "size": data.len().to_string(), "generation": "1700000000000001",
                                "metadata": resource["metadata"]})
                            .to_string(),
                        ),
                    }
                };
                script.seen.push(seen);
                drop(script);
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                    response.len()
                );
            }
        });
        Self { base, script }
    }

    fn seen(&self) -> Vec<Seen> {
        self.script.lock().unwrap().seen.clone()
    }
}

fn event(kind: &str) -> Event {
    let pull = kind == "pull_request";
    Event {
        format: 1,
        repository: "tools/links".into(),
        repository_id: 17,
        event: kind.into(),
        head: HEAD.into(),
        base: pull.then(|| BASE.into()),
        pull_request: pull.then_some(9),
        run: 41,
        attempt: 2,
        workflow_commit: Some(WORKFLOW.into()),
    }
}

fn artifact() -> Vec<u8> {
    (0..4096_u32).map(|value| (value % 251) as u8).collect()
}

fn distribution() -> String {
    format!("sha256:{}", "ef".repeat(32))
}

/// The fetched head's app, as ci fetch unpacked it.
fn head(ci: &Path) -> String {
    fs::create_dir_all(ci.join("head/app")).unwrap();
    fs::write(ci.join("head/app/App.roc"), b"App :: [].{}\n").unwrap();
    crate::ci_check::source_inputs(&ci.join("head/app")).unwrap()
}

fn receipt(archive: &[u8], source_inputs: &str) -> Receipt {
    Receipt {
        version: 1,
        source_inputs: source_inputs.to_owned(),
        artifact_id: "cd".repeat(32),
        sdk_distribution: BlobIdentity {
            digest: distribution(),
            bytes: 900,
        },
        verification: Verification {
            version: 1,
            seed: 42,
            cases: 6,
        },
        archive: BlobIdentity::of(archive),
        examples: 3,
        generated: 6,
        lanes: LANES.map(str::to_owned).to_vec(),
    }
}

/// One run's directory, as ci fetch and ci check left it.
struct Run {
    servers: Servers,
    fake: Fake,
    directory: tempfile::TempDir,
    event: Event,
    inputs: Inputs,
    /// The fetched head app's source inputs, which the receipt names.
    source_inputs: String,
    /// The runner's variables for this step beyond the run and the inputs.
    workflow_sha: Option<String>,
}

impl Run {
    fn new(kind: &str, checked: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let ci = directory.path().join("ci");
        fs::create_dir(&ci).unwrap();
        let event = event(kind);
        fs::write(
            ci.join("event.json"),
            serde_json::to_vec_pretty(&event).unwrap(),
        )
        .unwrap();
        let source_inputs = head(&ci);
        if checked {
            fs::create_dir(ci.join(OUTPUT)).unwrap();
            fs::write(ci.join("out/app.tar.gz"), artifact()).unwrap();
            fs::write(
                ci.join("out/receipt.json"),
                serde_json::to_vec(&receipt(&artifact(), &source_inputs)).unwrap(),
            )
            .unwrap();
        }
        fs::write(
            directory.path().join("request.json"),
            json!({"directory": ci}).to_string(),
        )
        .unwrap();
        let servers = Servers::start();
        let inputs = Inputs {
            id_token_url: format!("{}/token?v=1&repository=tools/links", servers.base),
            id_token: JOB_TOKEN.into(),
            bucket: BUCKET_NAME.into(),
            audience: AUDIENCE_URL.into(),
            sdk: sdk(),
            distribution: distribution(),
        };
        Self {
            servers,
            fake: Fake::default(),
            directory,
            workflow_sha: event.workflow_commit.clone(),
            event,
            inputs,
            source_inputs,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    /// The store step's variables: the run as the runner describes it, then
    /// the rendered store inputs.
    fn variables(&self) -> Vec<(&'static str, String)> {
        let event = &self.event;
        let mut variables = vec![
            ("GITHUB_EVENT_NAME", event.event.clone()),
            ("GITHUB_EVENT_PATH", "/runner/event.json".to_owned()),
            ("GITHUB_REPOSITORY", event.repository.clone()),
            ("GITHUB_SERVER_URL", "https://git.example.com/".to_owned()),
            ("GITHUB_SHA", event.head.clone()),
            ("GITHUB_RUN_ID", event.run.to_string()),
            ("GITHUB_RUN_ATTEMPT", event.attempt.to_string()),
            (ID_TOKEN_URL, self.inputs.id_token_url.clone()),
            (ID_TOKEN, self.inputs.id_token.clone()),
            (BUCKET, self.inputs.bucket.clone()),
            (AUDIENCE, self.inputs.audience.clone()),
            (SDK, self.inputs.sdk.clone()),
            (DISTRIBUTION, self.inputs.distribution.clone()),
        ];
        if let Some(sha) = &self.workflow_sha {
            variables.push(("GITHUB_WORKFLOW_SHA", sha.clone()));
        }
        variables
    }

    fn effects(&self) -> Effects {
        let variables = self.variables();
        Effects {
            client: client(false).unwrap(),
            waiting: Box::new(self.fake.clone()),
            endpoints: Endpoints {
                sts: format!("{}/v1/token", self.servers.base),
                upload: format!("{}/upload/storage/v1", self.servers.base),
                https: false,
            },
            variables: Box::new(move |name| {
                variables
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| OsString::from(value))
            }),
        }
    }

    /// `<sdk>/<source inputs>-<cases>/<run>/<attempt>`.
    fn prefix(&self) -> String {
        format!(
            "{}/{}-6/41/2",
            "5d".repeat(32),
            &self.source_inputs["sha256:".len()..]
        )
    }

    fn session(&self) -> Result<Session> {
        Session::prepare(&self.path("request.json"), self.effects())
    }

    /// The recipe's order: the plan, then mint, exchange, artifact, receipt
    /// and result, or only the result.
    fn store(&self) -> Result<Value> {
        let mut session = self.session()?;
        if session.plan()["artifact"] == true {
            for name in ["mint", "exchange", "artifact", "receipt"] {
                session.step(name)?;
            }
        }
        session.step("result")
    }

    fn failure(&self) -> String {
        let error = format!("{:#}", self.store().unwrap_err());
        for secret in [JOB_TOKEN, SUBJECT, ACCESS] {
            assert!(!error.contains(secret), "{error} shows a token");
        }
        error
    }
}

#[test]
fn the_artifact_then_its_receipt_are_stored_write_once_with_the_run() -> Result<()> {
    let run = Run::new("push", true);
    let report: Report = serde_json::from_value(run.store()?)?;
    let seen = run.servers.seen();
    assert_eq!(
        seen.iter()
            .map(|seen| (seen.method.as_str(), seen.path()))
            .collect::<Vec<_>>(),
        [
            ("GET", "/token"),
            ("POST", "/v1/token"),
            ("POST", "/upload/storage/v1/b/exampleco-tools-links-ci/o"),
            ("POST", "/upload/storage/v1/b/exampleco-tools-links-ci/o"),
        ]
    );
    // The mint: the configured URL, the audience appended, the job token as bearer.
    let mint = &seen[0];
    assert_eq!(
        mint.target,
        format!(
            "/token?v=1&repository=tools/links&audience={}",
            instance_source::quote(AUDIENCE_URL)
        )
    );
    assert_eq!(mint.query("audience").as_deref(), Some(AUDIENCE_URL));
    assert_eq!(mint.headers["authorization"], format!("bearer {JOB_TOKEN}"));
    // The exchange: the provider's resource name, a storage-only scope.
    let exchange: Value = serde_json::from_slice(&seen[1].body)?;
    assert_eq!(
        exchange,
        json!({
            "audience": AUDIENCE_URL.trim_start_matches("https:"),
            "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
            "scope": "https://www.googleapis.com/auth/devstorage.read_write",
            "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
            "subjectToken": SUBJECT,
        })
    );
    assert!(!seen[1].headers.contains_key("authorization"));
    // The uploads: create-only, the artifact first, the receipt last.
    let metadata = json!({"run": "41", "attempt": "2", "head": HEAD,
        "event": "push", "workflow_commit": WORKFLOW});
    for (upload, file, bytes, kind) in [
        (&seen[2], "artifact.tar.gz", artifact(), "application/gzip"),
        (
            &seen[3],
            "receipt.json",
            fs::read(run.path("ci/out/receipt.json"))?,
            "application/json",
        ),
    ] {
        assert_eq!(upload.query("uploadType").as_deref(), Some("multipart"));
        assert_eq!(upload.query("ifGenerationMatch").as_deref(), Some("0"));
        assert_eq!(
            upload.query("fields").as_deref(),
            Some("name,bucket,size,generation,metadata")
        );
        assert_eq!(upload.query("name"), None);
        assert_eq!(upload.headers["authorization"], format!("Bearer {ACCESS}"));
        let (resource, data) = upload.parts();
        assert_eq!(
            resource,
            json!({"name": format!("{}/{file}", run.prefix()), "contentType": kind, "metadata": metadata})
        );
        assert_eq!(data, bytes);
    }
    assert!(report.stored);
    assert_eq!(report.prefix, Some(run.prefix()));
    assert_eq!(report.bucket.as_deref(), Some(BUCKET_NAME));
    assert_eq!(report.objects.len(), 2);
    assert_eq!(
        report.objects[0].digest,
        BlobIdentity::of(&artifact()).digest
    );
    assert_eq!(report.objects[1].generation, "1700000000000001");
    Ok(())
}

#[test]
fn only_the_rendered_token_request_for_the_runs_repository_is_sent() -> Result<()> {
    // Another repository, a runner-wide URL without one, another path or
    // query: refused before anything is sent, so the job token goes only to
    // the request the workflow pins.
    for (url, refusal) in [
        ("/token?v=1&repository=tools/home", "another repository"),
        ("/token?v=1", "rendered"),
        ("/token", "rendered"),
        ("/mint?v=1&repository=tools/links", "rendered"),
        ("/token?v=1&repository=tools/links&audience=x", "rendered"),
        ("/token?repository=tools/links&v=1", "rendered"),
    ] {
        let mut run = Run::new("push", true);
        run.inputs.id_token_url = format!("{}{url}", run.servers.base);
        let error = run.failure();
        assert!(error.contains(refusal), "{url}: {error}");
        assert!(run.servers.seen().is_empty(), "{url}");
    }
    Ok(())
}

#[test]
fn without_a_workflow_commit_the_metadata_omits_it() -> Result<()> {
    let mut run = Run::new("push", true);
    run.event.workflow_commit = None;
    run.workflow_sha = None;
    fs::write(run.path("ci/event.json"), serde_json::to_vec(&run.event)?)?;
    run.store()?;
    let (resource, _) = run.servers.seen()[2].parts();
    assert_eq!(
        resource["metadata"],
        json!({"run": "41", "attempt": "2", "head": HEAD, "event": "push"})
    );
    Ok(())
}

#[test]
fn a_pull_request_run_is_verified_not_stored_and_reaches_no_service() -> Result<()> {
    // Even with an artifact: code the check step ran could have written it.
    let mut run = Run::new("pull_request", true);
    // No store input is read: a step without them succeeds.
    for input in [
        &mut run.inputs.id_token_url,
        &mut run.inputs.id_token,
        &mut run.inputs.bucket,
        &mut run.inputs.audience,
        &mut run.inputs.sdk,
        &mut run.inputs.distribution,
    ] {
        input.clear();
    }
    let session = run.session()?;
    assert_eq!(session.plan(), json!({"artifact": false}));
    let report: Report = serde_json::from_value(run.store()?)?;
    assert!(!report.stored);
    assert!(
        report
            .reason
            .unwrap()
            .starts_with("pull_request runs are verified, not stored")
    );
    assert_eq!((report.bucket, report.prefix), (None, None));
    assert!(run.servers.seen().is_empty());
    // The credential steps are not part of its order.
    let mut session = run.session()?;
    let error = format!("{:#}", session.step("mint").unwrap_err());
    assert!(error.contains("runs result next"), "{error}");
    // A routed pull request run, without an artifact, is the same.
    let routed = Run::new("pull_request", false);
    let report: Report = serde_json::from_value(routed.store()?)?;
    assert!(!report.stored && routed.servers.seen().is_empty());
    // A push checks every lane: no artifact is a failure.
    let push = Run::new("push", false);
    assert!(push.failure().contains("must store its artifact"));
    // A push run without the rendered token request names the missing input.
    let mut unrendered = Run::new("push", true);
    unrendered.inputs.id_token_url.clear();
    let error = unrendered.failure();
    assert!(
        error.contains("ACTIONS_ID_TOKEN_REQUEST_URL") && error.contains("forge.oidc"),
        "{error}"
    );
    assert!(unrendered.servers.seen().is_empty());
    Ok(())
}

#[test]
fn a_transient_mint_answer_is_retried_and_any_other_fails_at_once() -> Result<()> {
    let run = Run::new("push", true);
    run.servers.script.lock().unwrap().mint = [
        (503, "busy".to_owned()),
        (429, "slow down".to_owned()),
        (200, json!({"value": SUBJECT}).to_string()),
    ]
    .into();
    run.store()?;
    assert_eq!(
        run.fake.0.borrow().sleeps,
        [Duration::from_secs(2), Duration::from_secs(4)]
    );
    // A refusal is final, carries git-oidc's reason and reaches nothing else.
    let run = Run::new("push", true);
    run.servers.script.lock().unwrap().mint =
        [(403, "job token could not be verified\n".to_owned())].into();
    let error = run.failure();
    assert!(
        error.contains(
            "git-oidc refused the token request with HTTP 403: job token could not be verified"
        ),
        "{error}"
    );
    assert_eq!(run.servers.seen().len(), 1);
    assert!(run.fake.0.borrow().sleeps.is_empty());
    // Transient until the deadline: the last answer.
    let run = Run::new("push", true);
    run.servers.script.lock().unwrap().mint = [(502, "gateway".to_owned())].into();
    let error = run.failure();
    assert!(error.contains("within 120s"), "{error}");
    assert!(error.contains("HTTP 502: gateway"), "{error}");
    assert_eq!(run.servers.seen().len(), 10);
    // An answer without a token is a refusal too.
    let run = Run::new("push", true);
    run.servers.script.lock().unwrap().mint = [(200, json!({"value": "x"}).to_string())].into();
    assert!(run.failure().contains("no token"));
    Ok(())
}

#[test]
fn a_refused_exchange_or_upload_fails_the_job() -> Result<()> {
    let run = Run::new("push", true);
    run.servers.script.lock().unwrap().sts = Some((
        400,
        json!({"error": "invalid_grant", "error_description": "The audience in ID Token does not match."})
            .to_string(),
    ));
    let error = run.failure();
    assert!(
        error.contains("HTTP 400: invalid_grant The audience in ID Token does not match."),
        "{error}"
    );
    assert_eq!(run.servers.seen().len(), 2);
    let run = Run::new("push", true);
    run.servers.script.lock().unwrap().sts =
        Some((200, json!({"token_type": "Bearer"}).to_string()));
    assert!(run.failure().contains("no bearer access token"));
    // A precondition failure: this run and attempt stored it before. The
    // receipt is never written after a failed artifact.
    let run = Run::new("push", true);
    run.servers.script.lock().unwrap().refuse = Some(("artifact.tar.gz".to_owned(), 412));
    let error = run.failure();
    assert!(
        error.contains("offsite_Object_Status status=Some(412)"),
        "{error}"
    );
    assert_eq!(run.servers.seen().len(), 3);
    let run = Run::new("push", true);
    run.servers.script.lock().unwrap().refuse = Some(("receipt.json".to_owned(), 403));
    assert!(run.failure().contains("403"));
    // A reply that is not exactly the stored object and the metadata sent is closed provider data: it fails
    // the artifact without echoing anything, and the receipt is never written.
    for reply in [
        json!({"name": "not-a-secret", "bucket": BUCKET_NAME, "size": "1", "generation": "1",
               "metadata": {}}),
        json!({"name": "x", "bucket": BUCKET_NAME, "size": "1", "generation": "1",
               "metadata": {}, "selfLink": "not-a-secret"}),
    ] {
        let run = Run::new("push", true);
        run.servers.script.lock().unwrap().reply =
            Some(("artifact.tar.gz".to_owned(), reply.to_string()));
        let error = run.failure();
        assert!(error.contains("offsite_Object_"), "{error}");
        assert!(!error.contains("not-a-secret"), "{error}");
        assert_eq!(run.servers.seen().len(), 3);
    }
    let run = Run::new("push", true);
    let name = format!("{}/artifact.tar.gz", run.prefix());
    let echoed = json!({"name": name, "bucket": BUCKET_NAME, "size": artifact().len().to_string(),
        "generation": "1700000000000001", "metadata": {"run": "41"}});
    run.servers.script.lock().unwrap().reply =
        Some(("artifact.tar.gz".to_owned(), echoed.to_string()));
    assert!(run.failure().contains("offsite_Object_Mismatch"));
    assert_eq!(run.servers.seen().len(), 3);
    Ok(())
}

#[test]
fn the_artifact_is_checked_against_its_receipt_again_before_upload() -> Result<()> {
    let run = Run::new("push", true);
    let mut session = run.session()?;
    session.step("mint")?;
    session.step("exchange")?;
    // Same size, other bytes: only the digest can tell.
    let mut changed = artifact();
    changed[0] ^= 1;
    fs::write(run.path("ci/out/app.tar.gz"), &changed)?;
    let error = format!("{:#}", session.step("artifact").unwrap_err());
    assert!(error.contains("changed after ci check"), "{error}");
    assert_eq!(run.servers.seen().len(), 2);
    // A receipt that changed after it was checked is never stored.
    let run = Run::new("push", true);
    let mut session = run.session()?;
    for name in ["mint", "exchange", "artifact"] {
        session.step(name)?;
    }
    let mut receipt = receipt(&artifact(), &run.source_inputs);
    receipt.examples = 4;
    fs::write(
        run.path("ci/out/receipt.json"),
        serde_json::to_vec(&receipt)?,
    )?;
    assert!(format!("{:#}", session.step("receipt").unwrap_err()).contains("receipt changed"));
    assert_eq!(run.servers.seen().len(), 3);
    Ok(())
}

#[test]
fn the_inputs_and_the_record_must_be_this_runs_and_this_apps() -> Result<()> {
    let refused = |change: &dyn Fn(&mut Run)| -> String {
        let mut run = Run::new("push", true);
        change(&mut run);
        run.failure()
    };
    // Another app's bucket, or one that is not <project>-<app>-ci.
    assert!(refused(&|run| run.inputs.bucket = "exampleco-tools-home-ci".into()).contains(BUCKET));
    assert!(refused(&|run| run.inputs.bucket = "links-ci".into()).contains(BUCKET));
    // The record of another run, attempt, commit, repository, event or
    // workflow commit than the step's own variables describe.
    for field in [
        "run",
        "attempt",
        "head",
        "repository",
        "event",
        "workflow_commit",
    ] {
        let error = refused(&|run| {
            let mut value = serde_json::to_value(&run.event).unwrap();
            value[field] = match field {
                "run" => json!(40),
                "attempt" => json!(1),
                "head" | "workflow_commit" => json!(BASE),
                "event" => json!("pull_request"),
                _ => json!("tools/home"),
            };
            if field == "event" {
                value["base"] = json!(BASE);
                value["pull_request"] = json!(9);
            }
            fs::write(run.path("ci/event.json"), value.to_string()).unwrap();
        });
        assert!(error.contains("not this run's"), "{field}: {error}");
    }
    // A runner that exports no workflow commit while the record names one.
    assert!(refused(&|run| run.workflow_sha = None).contains("not this run's"));
    // A receipt checked on another SDK's tooling, or of another head than the
    // one fetched.
    assert!(
        refused(&|run| run.inputs.distribution = format!("sha256:{}", "aa".repeat(32)))
            .contains("another SDK")
    );
    let error = refused(&|run| {
        fs::write(run.path("ci/head/app/App.roc"), b"App :: [].{ other }\n").unwrap();
    });
    assert!(error.contains("fetched head"), "{error}");
    // ci check's output must be exactly the artifact and a complete run's receipt.
    assert!(refused(&|run| fs::write(run.path("ci/out/extra"), b"x").unwrap()).contains("exactly"));
    for change in [
        json!({"lanes": ["native"]}),
        json!({"verification": {"version": 1, "seed": 7, "cases": 6}}),
        json!({"version": 2}),
        json!({"extra": 1}),
    ] {
        let error = refused(&|run| {
            let mut value = serde_json::to_value(receipt(&artifact(), &run.source_inputs)).unwrap();
            for (key, field) in change.as_object().unwrap() {
                value[key] = field.clone();
            }
            fs::write(run.path("ci/out/receipt.json"), value.to_string()).unwrap();
        });
        assert!(error.contains("receipt"), "{change}: {error}");
    }
    assert!(
        refused(&|run| fs::write(run.path("ci/out/app.tar.gz"), b"short").unwrap())
            .contains("size")
    );
    Ok(())
}

#[test]
fn the_store_inputs_are_read_exactly_and_never_echoed() {
    let all = [
        (
            ID_TOKEN_URL,
            "https://git-oidc.example.com/token?v=1&repository=tools/links",
        ),
        (ID_TOKEN, JOB_TOKEN),
        (BUCKET, BUCKET_NAME),
        (AUDIENCE, AUDIENCE_URL),
        (
            SDK,
            "sha256:5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d",
        ),
        (
            DISTRIBUTION,
            "sha256:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
        ),
    ];
    let read = |pairs: Vec<(&str, &str)>| {
        Inputs::read(
            move |name| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| OsString::from(value))
            },
            true,
        )
    };
    let inputs = read(all.to_vec()).unwrap();
    assert_eq!(
        inputs.sts_audience(),
        "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/day2-ci/providers/gitea"
    );
    for (name, _) in all {
        let error = format!(
            "{:#}",
            read(all.into_iter().filter(|(key, _)| *key != name).collect())
                .err()
                .unwrap()
        );
        assert!(error.contains(name), "{error}");
    }
    for (name, value) in [
        (ID_TOKEN_URL, "not a url"),
        (
            ID_TOKEN_URL,
            "http://git-oidc.example.com/token?v=1&repository=tools/links",
        ),
        (
            ID_TOKEN_URL,
            "https://git-oidc.example.com:8443/token?v=1&repository=tools/links",
        ),
        (
            ID_TOKEN_URL,
            "https://user:secret@git-oidc.example.com/token",
        ),
        (ID_TOKEN, "two words"),
        (BUCKET, "Bucket"),
        (
            AUDIENCE,
            "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/day2-ci/providers/gitea",
        ),
        (
            AUDIENCE,
            "https://iam.googleapis.com/projects/project-id/locations/global/workloadIdentityPools/day2-ci/providers/gitea",
        ),
        (
            AUDIENCE,
            "https://iam.googleapis.com/projects/1/locations/us/workloadIdentityPools/day2-ci/providers/gitea",
        ),
        (SDK, "sha256:5D"),
        (DISTRIBUTION, "sha256:EF"),
    ] {
        let pairs = all
            .into_iter()
            .map(|(key, old)| (key, if key == name { value } else { old }))
            .collect();
        let error = format!("{:#}", read(pairs).err().unwrap());
        assert!(error.contains(name), "{name}: {error}");
        assert!(!error.contains(value), "{error} echoes {value}");
    }
}

#[test]
fn the_report_is_the_shape_the_cli_decodes() -> Result<()> {
    let golden: Report = serde_json::from_str(GOLDEN_REPORT)?;
    assert_eq!(
        serde_json::to_value(&golden)?,
        serde_json::from_str::<Value>(GOLDEN_REPORT)?
    );
    let run = Run::new("push", true);
    let report: Report = serde_json::from_value(run.store()?)?;
    assert_eq!(report.objects.len(), golden.objects.len());
    // The same layout: <sdk>/<source inputs>-<cases>/<run>/<attempt>.
    let shape = |prefix: &str| {
        let parts: Vec<&str> = prefix.split('/').collect();
        (
            parts.len(),
            parts[0].len(),
            parts[1].split_once('-').map(|(hex, _)| hex.len()),
        )
    };
    assert_eq!(
        shape(&report.prefix.unwrap()),
        shape(&golden.prefix.unwrap())
    );
    Ok(())
}

#[test]
fn steps_run_once_in_order() -> Result<()> {
    let run = Run::new("push", true);
    let mut session = run.session()?;
    assert_eq!(session.plan(), json!({"artifact": true}));
    for (name, expected) in [
        ("exchange", "mint"),
        ("artifact", "mint"),
        ("result", "mint"),
    ] {
        let error = format!("{:#}", session.step(name).unwrap_err());
        assert!(error.contains(&format!("runs {expected} next")), "{error}");
    }
    session.step("mint")?;
    assert!(session.step("mint").is_err());
    session.step("exchange")?;
    assert!(session.step("receipt").is_err());
    session.step("artifact")?;
    session.step("receipt")?;
    session.step("result")?;
    assert!(format!("{:#}", session.step("result").unwrap_err()).contains("nothing more"));
    Ok(())
}
