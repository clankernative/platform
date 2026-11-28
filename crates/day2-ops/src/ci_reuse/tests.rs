use super::*;
use crate::{
    ci_check::{LANES, Receipt, Verification},
    ci_results::Listing,
    ci_store::tests::{
        ACCESS, AUDIENCE_URL, BUCKET_NAME, HEAD, JOB_TOKEN, SUBJECT, Servers, WORKFLOW,
        distribution, sdk,
    },
    instance_source::tests::{Fake, TOKEN as FORGE_TOKEN, bytes, ok, status},
};
use day2::sdk_release::BlobIdentity;
use std::collections::BTreeMap;

const PREFIX: &str = "https://git.example.com/api/v1/repos/tools/links";
/// The commit an earlier main run checked, with the same `app/`.
const EARLIER: &str = "4444444444444444444444444444444444444444";
const STARTED: &str = "2026-11-25T18:00:00Z";
const COMPLETED: &str = "2026-11-25T18:20:00Z";
const CREATED: &str = "2026-11-25T18:15:00.250Z";
const GOLDEN_REPORT: &str = include_str!("../../../../cli/fixtures/ci-reuse-report.json");
/// The fetched head's `app/App.roc`, which an earlier commit with the same
/// `app/` also has.
const APP: &[u8] = b"App :: [].{}\n";
/// A stored attempt's custody steps, in the recipe's order.
const CUSTODY: [&str; 6] = [
    "candidate",
    "source",
    "receipt",
    "artifact",
    "download",
    "attempt",
];

fn event(kind: &str) -> Event {
    let pull = kind == "pull_request";
    Event {
        format: 1,
        repository: "tools/links".into(),
        repository_id: 17,
        event: kind.into(),
        head: HEAD.into(),
        base: pull.then(|| "2".repeat(40)),
        pull_request: pull.then_some(9),
        run: 41,
        attempt: 2,
        workflow_commit: Some(WORKFLOW.into()),
    }
}

/// The forge's record of app CI's run `id`, attempt `attempt`, of `head`.
fn record(id: u64, attempt: u64, head: &str, status: &str) -> Value {
    json!({"id": id, "head_sha": head, "event": "push", "head_branch": "main",
        "path": "verification.yml@refs/heads/main", "is_scoped": true,
        "workflow_repository_id": 412,
        "workflow_repository": {"id": 412, "full_name": "tools/day2-ci"},
        "workflow_commit_sha": WORKFLOW, "repository": {"id": 17, "full_name": "tools/links"},
        "run_attempt": attempt, "status": status,
        "conclusion": if status == "completed" { json!("success") } else { Value::Null },
        "started_at": STARTED, "completed_at": COMPLETED})
}

/// The forge's archive of a commit whose `app/App.roc` is `app`, as Gitea
/// writes one: everything below one root directory.
fn forge_archive(app: &[u8]) -> Vec<u8> {
    crate::ci_fetch::tests::archive(&[
        ("links/", b'5', 0o775, b""),
        ("links/README.md", b'0', 0o664, b"# Links\n"),
        ("links/app/", b'5', 0o775, b""),
        ("links/app/App.roc", b'0', 0o664, app),
    ])
}

fn archive_url(commit: &str) -> String {
    format!("{PREFIX}/archive/{commit}.tar.gz")
}

fn metadata(run: u64, attempt: u64, head: &str) -> BTreeMap<String, String> {
    [
        ("run", run.to_string()),
        ("attempt", attempt.to_string()),
        ("head", head.to_owned()),
        ("event", "push".to_owned()),
        ("workflow_commit", WORKFLOW.to_owned()),
    ]
    .map(|(key, value)| (key.to_owned(), value))
    .into()
}

fn artifact() -> Vec<u8> {
    (0..4096_u32).map(|value| (value % 251) as u8).collect()
}

/// The receipt an earlier main run's check wrote for the same `app/`.
fn receipt(inputs: &str, archive: &[u8]) -> Receipt {
    Receipt {
        version: 1,
        source_inputs: inputs.to_owned(),
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

/// One run's directory after ci fetch, its fake forge and bucket, and the
/// local git-oidc and STS.
struct Run {
    servers: Servers,
    fake: Fake,
    directory: tempfile::TempDir,
    event: Event,
    /// The fetched head app's source inputs.
    inputs: String,
    /// Variables left out of the step's environment.
    unset: Vec<&'static str>,
    /// A storage call GCS refuses (`list`, `object`, `media`) or that stays
    /// transient (`transient-list`, `transient-media`).
    failing: Option<&'static str>,
}

impl Run {
    fn new(kind: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let ci = directory.path().join("ci");
        fs::create_dir_all(ci.join("head/app")).unwrap();
        fs::write(ci.join("head/app/App.roc"), APP).unwrap();
        let inputs = crate::ci_check::source_inputs(&ci.join("head/app")).unwrap();
        let event = event(kind);
        fs::write(
            ci.join("event.json"),
            serde_json::to_vec_pretty(&event).unwrap(),
        )
        .unwrap();
        fs::write(
            directory.path().join("request.json"),
            json!({"directory": ci, "cases": 6}).to_string(),
        )
        .unwrap();
        let fake = Fake::default();
        fake.route(
            &format!("{PREFIX}/actions/runs/41"),
            vec![ok(record(41, 2, HEAD, "in_progress"))],
        );
        fake.route(&archive_url(EARLIER), vec![bytes(forge_archive(APP))]);
        Self {
            servers: Servers::start(),
            fake,
            directory,
            event,
            inputs,
            unset: Vec::new(),
            failing: None,
        }
    }

    fn ci(&self) -> PathBuf {
        self.directory.path().join("ci")
    }

    /// `<sdk>/<inputs>-6/`.
    fn key(&self) -> String {
        format!("{}/{}-6/", "5d".repeat(32), &self.inputs["sha256:".len()..])
    }

    /// Store an attempt's objects as `ci store` wrote them, and the forge's
    /// record of its run, of the commit `EARLIER`.
    fn stored(&self, run: u64, attempt: u64) {
        self.store_with(
            run,
            attempt,
            &receipt(&self.inputs, &artifact()),
            artifact(),
        );
        self.fake.route(
            &format!("{PREFIX}/actions/runs/{run}"),
            vec![ok(record(run, attempt, EARLIER, "completed"))],
        );
    }

    fn store_with(&self, run: u64, attempt: u64, receipt: &Receipt, archive: Vec<u8>) {
        let prefix = format!("{}{run}/{attempt}/", self.key());
        let put = |name: String, bytes: Vec<u8>, generation: &str| {
            self.fake.0.borrow_mut().stored.insert(
                (BUCKET_NAME.to_owned(), name),
                (
                    Stored {
                        generation: generation.into(),
                        size: bytes.len() as u64,
                        time_created: CREATED.into(),
                        metadata: metadata(run, attempt, EARLIER),
                    },
                    bytes,
                ),
            );
        };
        put(
            format!("{prefix}artifact.tar.gz"),
            archive,
            "1700000000000001",
        );
        put(
            format!("{prefix}receipt.json"),
            receipt.bytes().unwrap(),
            "1700000000000002",
        );
    }

    /// Change one stored object's projected metadata.
    fn restore(&self, run: u64, attempt: u64, file: &str, change: impl FnOnce(&mut Stored)) {
        let name = format!("{}{run}/{attempt}/{file}", self.key());
        let mut world = self.fake.0.borrow_mut();
        let (stored, _) = world
            .stored
            .get_mut(&(BUCKET_NAME.to_owned(), name))
            .unwrap();
        change(stored);
    }

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
            ("GITHUB_WORKFLOW_SHA", WORKFLOW.to_owned()),
            ("GITHUB_TOKEN", FORGE_TOKEN.to_owned()),
            (
                ci_store::ID_TOKEN_URL,
                format!("{}/token?v=1&repository=tools/links", self.servers.base),
            ),
            (ci_store::ID_TOKEN, JOB_TOKEN.to_owned()),
            (ci_store::BUCKET, BUCKET_NAME.to_owned()),
            (ci_store::AUDIENCE, AUDIENCE_URL.to_owned()),
            (ci_store::SDK, sdk()),
            (ci_store::DISTRIBUTION, distribution()),
        ];
        variables.retain(|(name, _)| !self.unset.contains(name));
        variables
    }

    fn effects(&self) -> Effects {
        let variables = self.variables();
        let fake = self.fake.clone();
        let failing = self.failing;
        Effects {
            transport: Box::new(self.fake.clone()),
            client: ci_store::client(false).unwrap(),
            waiting: Box::new(self.fake.clone()),
            sts: format!("{}/v1/token", self.servers.base),
            https: false,
            storage: Box::new(move |token| {
                assert_eq!(token, ACCESS);
                Ok(Box::new(Flaky {
                    fake: fake.clone(),
                    failing,
                }) as Box<dyn Storage>)
            }),
            variables: Box::new(move |name| {
                variables
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| OsString::from(value))
            }),
        }
    }

    fn session(&self) -> Result<Session> {
        Session::prepare(&self.directory.path().join("request.json"), self.effects())
    }

    /// The recipe's order: the plan; run, mint, exchange and list; each stored
    /// attempt's custody steps until one refuses it, the last accepting it;
    /// until an attempt is accepted or a step misses; then the result. Each
    /// step's reply is kept by name.
    fn reuse(&self) -> Result<(Report, Vec<(String, Value)>)> {
        let mut session = self.session()?;
        let mut replies = Vec::new();
        let mut step = |session: &mut Session, name: &str| -> Result<Value> {
            let reply = session.step(name)?;
            replies.push((name.to_owned(), reply.clone()));
            Ok(reply)
        };
        if session.plan()["lookup"] == true {
            'lookup: {
                for name in ["run", "mint", "exchange"] {
                    if step(&mut session, name)?["missed"] == true {
                        break 'lookup;
                    }
                }
                let listed = step(&mut session, "list")?;
                if listed["missed"] == true {
                    break 'lookup;
                }
                for _ in listed["candidates"].as_array().unwrap() {
                    let mut refused = false;
                    for name in CUSTODY {
                        let custody = step(&mut session, name)?;
                        if custody["missed"] == true {
                            break 'lookup;
                        }
                        if custody["refused"] == true {
                            refused = true;
                            break;
                        }
                    }
                    if !refused {
                        break 'lookup;
                    }
                }
            }
        }
        let report = serde_json::from_value(session.step("result")?)?;
        Ok((report, replies))
    }

    /// A lookup that reused nothing: its report, after checking that the run
    /// still succeeds, writes the miss and shows no token.
    fn missed(&self) -> Report {
        let (report, _) = self.reuse().unwrap();
        assert!(!report.reused && report.source.is_none(), "{report:?}");
        let shown = serde_json::to_string(&report).unwrap();
        for secret in [JOB_TOKEN, SUBJECT, ACCESS, FORGE_TOKEN] {
            assert!(!shown.contains(secret), "{shown} shows a token");
        }
        let record = Record::read(&self.ci().join(REUSE)).unwrap();
        assert_eq!((record.reused, &record.reason), (false, &report.reason));
        assert_eq!(
            fs::read_dir(self.ci().join(REUSE)).unwrap().count(),
            1,
            "only the record"
        );
        report
    }

    /// The first refused candidate's reason.
    fn refused(&self) -> String {
        let report = self.missed();
        report
            .tried
            .first()
            .and_then(|tried| tried.reason.clone())
            .unwrap_or_else(|| report.reason.clone().unwrap_or_default())
    }

    /// A lookup that fails the command: its error, which shows no token,
    /// after checking that nothing was written for check.
    fn failed(&self) -> String {
        let error = format!("{:#}", self.reuse().expect_err("the command fails"));
        for secret in [JOB_TOKEN, SUBJECT, ACCESS, FORGE_TOKEN] {
            assert!(!error.contains(secret), "{error} shows a token");
        }
        assert!(!self.ci().join(REUSE).exists(), "{error}");
        error
    }
}

/// The fake bucket, with one kind of call refused as GCS refuses a request,
/// or failing transiently every time.
struct Flaky {
    fake: Fake,
    failing: Option<&'static str>,
}

impl Flaky {
    fn fails(&self, call: &str) -> Result<()> {
        if self.failing == Some(&format!("transient-{call}")) {
            bail!(instance_source::Retryable(instance_source::TEMPORARY));
        }
        ensure!(self.failing != Some(call), "app_ci_results_http_403");
        Ok(())
    }
}

impl Storage for Flaky {
    fn object(
        &mut self,
        bucket: &str,
        name: &str,
        within: Option<Duration>,
    ) -> Result<Option<Stored>> {
        self.fails("object")?;
        self.fake.object(bucket, name, within)
    }

    fn media(
        &mut self,
        bucket: &str,
        name: &str,
        generation: &str,
        size: u64,
        within: Option<Duration>,
    ) -> Result<Vec<u8>> {
        self.fails("media")?;
        self.fake.media(bucket, name, generation, size, within)
    }

    fn list(
        &mut self,
        bucket: &str,
        prefix: &str,
        page: Option<&str>,
        within: Option<Duration>,
    ) -> Result<Listing> {
        self.fails("list")?;
        self.fake.list(bucket, prefix, page, within)
    }
}

#[test]
fn a_pull_request_run_never_reuses_and_reaches_nothing() -> Result<()> {
    let run = Run::new("pull_request");
    run.stored(40, 1);
    let session = run.session()?;
    assert_eq!(session.plan(), json!({"lookup": false}));
    let (report, replies) = run.reuse()?;
    assert!(replies.is_empty());
    assert_eq!(
        (report.reused, report.reason.as_deref(), &report.output),
        (false, Some(PULL_REQUEST), &None)
    );
    assert_eq!((&report.bucket, &report.key), (&None, &None));
    // No forge read, token, listing or file.
    assert!(run.fake.calls().is_empty());
    assert!(run.servers.seen().is_empty());
    assert!(run.fake.0.borrow().lists.is_empty());
    assert!(!run.ci().join(REUSE).exists());
    Ok(())
}

#[test]
fn an_earlier_main_runs_result_bound_to_its_own_commit_is_reused() -> Result<()> {
    let run = Run::new("push");
    run.stored(40, 1);
    let (report, replies) = run.reuse()?;
    let passed = json!({"missed": false, "refused": false});
    assert_eq!(
        replies,
        [
            ("run".to_owned(), json!({"missed": false})),
            ("mint".to_owned(), json!({"missed": false})),
            ("exchange".to_owned(), json!({"missed": false})),
            (
                "list".to_owned(),
                json!({"missed": false, "candidates": [{"run": 40, "attempt": 1}]})
            ),
        ]
        .into_iter()
        .chain(CUSTODY.map(|name| (name.to_owned(), passed.clone())))
        .collect::<Vec<_>>()
    );
    let key = run.key();
    let source = report.source.clone().context("source")?;
    assert_eq!(
        source,
        Source {
            run: 40,
            attempt: 1,
            head: EARLIER.into(),
            workflow_commit: WORKFLOW.into(),
            started_at: STARTED.into(),
            completed_at: COMPLETED.into(),
            bucket: BUCKET_NAME.into(),
            receipt: Object {
                name: format!("{key}40/1/receipt.json"),
                generation: "1700000000000002".into(),
                time_created: CREATED.into(),
            },
            artifact: Object {
                name: format!("{key}40/1/artifact.tar.gz"),
                generation: "1700000000000001".into(),
                time_created: CREATED.into(),
            },
        }
    );
    assert_eq!(
        (report.reused, &report.reason, report.listed),
        (true, &None, 1)
    );
    assert_eq!(report.key.as_deref(), Some(key.as_str()));
    assert_eq!(report.output, Some(run.ci().join(REUSE)));
    // The stored bytes, and the record last.
    let output = run.ci().join(REUSE);
    assert_eq!(fs::read(output.join(ARCHIVE))?, artifact());
    assert_eq!(
        fs::read(output.join(RECEIPT))?,
        receipt(&run.inputs, &artifact()).bytes()?
    );
    assert_eq!(
        Record::read(&output)?,
        Record {
            format: 1,
            reused: true,
            reason: None,
            source: Some(source),
        }
    );
    // The forge with the job token: this run, the candidate's run, the
    // archive of the candidate's own commit, the candidate's run again. Each
    // request is bounded by the lookup's time left.
    assert_eq!(
        run.fake.calls(),
        [
            (format!("{PREFIX}/actions/runs/41"), true),
            (format!("{PREFIX}/actions/runs/40"), true),
            (archive_url(EARLIER), true),
            (format!("{PREFIX}/actions/runs/40"), true),
        ]
    );
    assert!(
        run.fake
            .0
            .borrow()
            .withins
            .iter()
            .all(|within| within.is_some_and(|within| within <= BUDGET))
    );
    // git-oidc for the audience, then STS for read access only.
    let seen = run.servers.seen();
    assert_eq!(
        seen.iter().map(|seen| seen.path()).collect::<Vec<_>>(),
        ["/token", "/v1/token"]
    );
    assert_eq!(seen[0].query("audience").as_deref(), Some(AUDIENCE_URL));
    let exchange: Value = serde_json::from_slice(&seen[1].body)?;
    assert_eq!(
        exchange["scope"],
        "https://www.googleapis.com/auth/devstorage.read_only"
    );
    // The key, listed once; each object read at its described generation.
    assert_eq!(
        run.fake.0.borrow().lists,
        [(BUCKET_NAME.to_owned(), key.clone(), None)]
    );
    assert_eq!(
        run.fake.0.borrow().reads,
        [
            (BUCKET_NAME.into(), format!("{key}40/1/receipt.json"), None),
            (
                BUCKET_NAME.into(),
                format!("{key}40/1/receipt.json"),
                Some("1700000000000002".into())
            ),
            (
                BUCKET_NAME.into(),
                format!("{key}40/1/artifact.tar.gz"),
                None
            ),
            (
                BUCKET_NAME.into(),
                format!("{key}40/1/artifact.tar.gz"),
                Some("1700000000000001".into())
            ),
        ]
    );
    Ok(())
}

#[test]
fn absence_under_the_key_is_a_miss_and_the_run_builds() -> Result<()> {
    let run = Run::new("push");
    // Another key's result is not this key's.
    run.fake.0.borrow_mut().stored.insert(
        (
            BUCKET_NAME.into(),
            format!(
                "{}/{}-4/40/1/receipt.json",
                "5d".repeat(32),
                &run.inputs[7..]
            ),
        ),
        (
            Stored {
                generation: "1".into(),
                size: 1,
                time_created: CREATED.into(),
                metadata: BTreeMap::new(),
            },
            b"{".to_vec(),
        ),
    );
    let report = run.missed();
    assert_eq!(
        (report.reason.as_deref(), report.listed, report.tried.len()),
        (Some(ABSENT), 0, 0)
    );
    Ok(())
}

#[test]
fn the_newest_stored_attempt_that_passes_custody_is_reused() -> Result<()> {
    let run = Run::new("push");
    // Run 9 sorts after run 40 by name; run 40's attempt 1 was superseded by
    // its attempt 2, whose result is refused; run 7's is an older result.
    run.stored(9, 1);
    run.stored(7, 1);
    run.store_with(40, 1, &receipt(&run.inputs, &artifact()), artifact());
    run.stored(40, 2);
    run.restore(40, 2, "receipt.json", |stored| {
        stored.time_created = "2026-11-25T19:00:00Z".into();
    });
    // Names that are not a stored attempt's receipt are not candidates.
    for name in ["40/2/notes.txt", "x/1/receipt.json", "0/1/receipt.json"] {
        run.fake.0.borrow_mut().stored.insert(
            (BUCKET_NAME.into(), format!("{}{name}", run.key())),
            (
                Stored {
                    generation: "1".into(),
                    size: 1,
                    time_created: CREATED.into(),
                    metadata: BTreeMap::new(),
                },
                b"x".to_vec(),
            ),
        );
    }
    // A page at a time.
    run.fake.0.borrow_mut().page = Some(2);
    let (report, _) = run.reuse()?;
    assert_eq!(
        report
            .tried
            .iter()
            .map(|tried| (tried.run, tried.attempt, tried.accepted))
            .collect::<Vec<_>>(),
        [(40, 2, false), (40, 1, false), (9, 1, true)]
    );
    assert!(
        report.tried[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("not created during the run's attempt")),
        "{report:?}"
    );
    assert!(
        report.tried[1]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("not the run's current attempt 2")),
        "{report:?}"
    );
    assert_eq!(
        (report.listed, report.source.map(|source| source.run)),
        (4, Some(9))
    );
    assert!(run.fake.0.borrow().lists.len() > 1);
    Ok(())
}

#[test]
fn only_the_newest_attempts_are_tried_and_a_full_key_is_never_truncated() -> Result<()> {
    let run = Run::new("push");
    for id in 1..=10 {
        run.stored(id, 1);
        run.restore(id, 1, "receipt.json", |stored| {
            stored
                .metadata
                .insert("event".into(), "pull_request".into());
        });
    }
    let report = run.missed();
    assert_eq!(
        report
            .tried
            .iter()
            .map(|tried| tried.run)
            .collect::<Vec<_>>(),
        [10, 9, 8, 7, 6, 5, 4, 3]
    );
    assert_eq!(report.listed, 10);
    assert!(
        report
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("custody refused every stored result tried")),
        "{report:?}"
    );
    // More pages than the lookup reads: a miss, not a partial newest-first.
    let run = Run::new("push");
    run.stored(40, 1);
    run.stored(39, 1);
    run.fake.0.borrow_mut().page = Some(0);
    let report = run.missed();
    assert!(
        report
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("more than 10 pages")),
        "{report:?}"
    );
    assert!(report.tried.is_empty());
    Ok(())
}

#[test]
fn every_custody_check_refuses_the_candidate() {
    type Change = Box<dyn Fn(&mut Run)>;
    let forge = |change: fn(&mut Value)| -> Change {
        Box::new(move |run: &mut Run| {
            let mut value = record(40, 1, EARLIER, "completed");
            change(&mut value);
            run.fake
                .route(&format!("{PREFIX}/actions/runs/40"), vec![ok(value)]);
        })
    };
    let rewritten = |change: fn(&mut Receipt)| -> Change {
        Box::new(move |run: &mut Run| {
            let mut changed = receipt(&run.inputs, &artifact());
            change(&mut changed);
            run.store_with(40, 1, &changed, artifact());
        })
    };
    let archived = |archive: fn() -> Option<crate::instance_source::Response>| -> Change {
        Box::new(move |run: &mut Run| run.fake.route(&archive_url(EARLIER), vec![archive()]))
    };
    let identity = "not app CI's scoped verification run of a push to main";
    let cases: Vec<(&str, Change, &str)> = vec![
        (
            "not scoped",
            forge(|run| run["is_scoped"] = json!(false)),
            identity,
        ),
        (
            "another workflow repository",
            forge(|run| run["workflow_repository"]["full_name"] = json!("tools/other-ci")),
            identity,
        ),
        (
            "another workflow repository ID",
            forge(|run| run["workflow_repository_id"] = json!(413)),
            identity,
        ),
        (
            "another workflow path",
            forge(|run| run["path"] = json!("other.yml@refs/heads/main")),
            identity,
        ),
        (
            "a pull_request run",
            forge(|run| run["event"] = json!("pull_request")),
            identity,
        ),
        (
            "another branch",
            forge(|run| run["head_branch"] = json!("feature")),
            identity,
        ),
        (
            "another repository",
            forge(|run| run["repository"]["id"] = json!(18)),
            identity,
        ),
        (
            "another run",
            forge(|run| run["id"] = json!(39)),
            "the forge answered for another run than 40",
        ),
        (
            "attempt not current",
            forge(|run| run["run_attempt"] = json!(2)),
            "the stored attempt 1 is not the run's current attempt 2",
        ),
        (
            "not terminal",
            forge(|run| run["status"] = json!("in_progress")),
            "the run's current attempt is not terminal",
        ),
        (
            "not successful",
            forge(|run| run["conclusion"] = json!("failure")),
            "did not succeed",
        ),
        (
            "a run the forge no longer has",
            Box::new(|run: &mut Run| {
                run.fake
                    .route(&format!("{PREFIX}/actions/runs/40"), vec![status(404)])
            }),
            "source_http_404",
        ),
        // The key and the receipt are the stored run's own claims; the forge's
        // archive of its commit decides which source it checked.
        (
            "its commit's app/ has other source inputs",
            archived(|| bytes(forge_archive(b"App :: [].{ planted = 1 }\n"))),
            "has other app/ source inputs than this run's",
        ),
        (
            "its commit's archive is unreadable",
            archived(|| bytes(b"not a gzip archive".to_vec())),
            "the forge's archive of the run's commit",
        ),
        (
            "its commit's archive is too large",
            archived(|| bytes(vec![0; crate::instance_source::ARCHIVE_LIMIT as usize + 1])),
            "source_response_byte_limit",
        ),
        (
            "its commit's archive is not served",
            archived(|| status(404)),
            "source_archive_http_404",
        ),
        (
            "another head in the metadata",
            Box::new(|run: &mut Run| {
                run.restore(40, 1, "receipt.json", |stored| {
                    stored.metadata.insert("head".into(), HEAD.into());
                })
            }),
            "receipt.json does not carry this run's metadata",
        ),
        (
            "another workflow commit in the metadata",
            Box::new(|run: &mut Run| {
                run.restore(40, 1, "artifact.tar.gz", |stored| {
                    stored
                        .metadata
                        .insert("workflow_commit".into(), HEAD.into());
                })
            }),
            "artifact.tar.gz does not carry this run's metadata",
        ),
        (
            "extra metadata",
            Box::new(|run: &mut Run| {
                run.restore(40, 1, "receipt.json", |stored| {
                    stored.metadata.insert("reused_from".into(), "39".into());
                })
            }),
            "receipt.json does not carry this run's metadata",
        ),
        (
            "a receipt created before the attempt",
            Box::new(|run: &mut Run| {
                run.restore(40, 1, "receipt.json", |stored| {
                    stored.time_created = "2026-11-25T17:59:59.999Z".into();
                })
            }),
            "receipt.json was not created during the run's attempt",
        ),
        (
            "an artifact created after the attempt",
            Box::new(|run: &mut Run| {
                run.restore(40, 1, "artifact.tar.gz", |stored| {
                    stored.time_created = "2026-11-25T18:20:01Z".into();
                })
            }),
            "artifact.tar.gz was not created during the run's attempt",
        ),
        (
            "other source inputs",
            rewritten(|receipt| receipt.source_inputs = format!("sha256:{}", "ab".repeat(32))),
            "belongs to another source or profile",
        ),
        (
            "other cases",
            rewritten(|receipt| receipt.verification.cases = 4),
            "belongs to another source or profile",
        ),
        (
            "another seed",
            rewritten(|receipt| receipt.verification.seed = 43),
            "invalid ci check receipt",
        ),
        (
            "another distribution",
            rewritten(|receipt| {
                receipt.sdk_distribution.digest = format!("sha256:{}", "12".repeat(32))
            }),
            "another SDK's tooling distribution",
        ),
        (
            "a lane missing",
            rewritten(|receipt| {
                receipt.lanes.pop();
            }),
            "invalid ci check receipt",
        ),
        (
            "a receipt GCS refuses to read",
            Box::new(|run: &mut Run| run.failing = Some("object")),
            "app_ci_results_http_403",
        ),
        (
            "an archive of another digest",
            Box::new(|run: &mut Run| {
                let mut other = artifact();
                other[0] ^= 1;
                run.store_with(40, 1, &receipt(&run.inputs, &artifact()), other);
            }),
            "not the archive its receipt names",
        ),
        (
            "an archive of another size",
            Box::new(|run: &mut Run| {
                let mut other = artifact();
                other.push(0);
                run.store_with(40, 1, &receipt(&run.inputs, &artifact()), other);
            }),
            "not the size its receipt names",
        ),
        (
            "an artifact no longer stored",
            Box::new(|run: &mut Run| {
                let name = format!("{}40/1/artifact.tar.gz", run.key());
                run.fake
                    .0
                    .borrow_mut()
                    .stored
                    .remove(&(BUCKET_NAME.into(), name));
            }),
            "its artifact is no longer stored",
        ),
        (
            "a download GCS refuses",
            Box::new(|run: &mut Run| run.failing = Some("media")),
            "app_ci_results_http_403",
        ),
        (
            "a rerun during the download",
            Box::new(|run: &mut Run| {
                run.fake.route(
                    &format!("{PREFIX}/actions/runs/40"),
                    vec![
                        ok(record(40, 1, EARLIER, "completed")),
                        ok(record(40, 2, EARLIER, "in_progress")),
                    ],
                );
            }),
            "app CI's attempt changed during the artifact download",
        ),
    ];
    for (what, change, expected) in cases {
        let mut run = Run::new("push");
        run.stored(40, 1);
        change(&mut run);
        let reason = run.refused();
        assert!(reason.contains(expected), "{what}: {reason}");
        assert!(!run.ci().join(REUSE).join(ARCHIVE).exists(), "{what}");
    }
    // This run's own earlier attempt is never reused.
    let run = Run::new("push");
    run.store_with(41, 1, &receipt(&run.inputs, &artifact()), artifact());
    assert_eq!(run.refused(), "it is this run's own result");
}

#[test]
fn a_planted_result_is_never_reused_and_its_commit_is_never_downloaded_past() -> Result<()> {
    // Run 40 checked a commit whose app/ differs, yet stored its result under
    // this run's key; run 39 checked a commit with this run's app/.
    let run = Run::new("push");
    let planted = "5555555555555555555555555555555555555555";
    run.stored(40, 1);
    run.fake.route(
        &format!("{PREFIX}/actions/runs/40"),
        vec![ok(record(40, 1, planted, "completed"))],
    );
    for file in ["receipt.json", "artifact.tar.gz"] {
        run.restore(40, 1, file, |stored| {
            stored.metadata.insert("head".into(), planted.into());
        });
    }
    run.fake.route(
        &archive_url(planted),
        vec![bytes(forge_archive(b"App :: [].{ planted = 1 }\n"))],
    );
    run.stored(39, 1);
    let (report, _) = run.reuse()?;
    assert_eq!(
        report
            .tried
            .iter()
            .map(|tried| (tried.run, tried.accepted))
            .collect::<Vec<_>>(),
        [(40, false), (39, true)]
    );
    // The planted attempt was refused before any of its objects was read.
    let key = run.key();
    assert!(
        run.fake
            .0
            .borrow()
            .reads
            .iter()
            .all(|(_, name, _)| !name.starts_with(&format!("{key}40/")))
    );
    Ok(())
}

#[test]
fn one_candidates_missing_run_refuses_only_that_candidate() -> Result<()> {
    let run = Run::new("push");
    run.stored(40, 1);
    run.stored(39, 1);
    run.fake
        .route(&format!("{PREFIX}/actions/runs/40"), vec![status(404)]);
    let (report, _) = run.reuse()?;
    assert!(report.reused, "{report:?}");
    assert_eq!(
        report
            .tried
            .iter()
            .map(|tried| (tried.run, tried.accepted, tried.reason.clone()))
            .collect::<Vec<_>>(),
        [
            (40, false, Some("source_http_404".to_owned())),
            (39, true, None)
        ]
    );
    Ok(())
}

#[test]
fn a_transient_read_or_a_refused_credential_falls_back_to_a_build() {
    // Each, by what it breaks: the lookup ends at once, the run succeeds.
    let check = |what: &str, change: &dyn Fn(&mut Run), expected: &str| {
        let mut run = Run::new("push");
        run.stored(40, 1);
        run.stored(39, 1);
        change(&mut run);
        let report = run.missed();
        let reason = report.reason.clone().unwrap_or_default();
        assert!(reason.contains(expected), "{what}: {reason}");
        report
    };
    check(
        "a listing that stays transient",
        &|run| run.failing = Some("transient-list"),
        "a results listing did not succeed within 120s",
    );
    // A stored attempt's transient read ends the lookup: the next is not tried.
    let report = check(
        "a download that stays transient",
        &|run| run.failing = Some("transient-media"),
        "a results download did not succeed within 120s",
    );
    assert_eq!(report.tried.len(), 1);
    check(
        "a forge that stays unreachable",
        &|run| {
            run.fake
                .route(&format!("{PREFIX}/actions/runs/40"), vec![None])
        },
        "a forge read did not succeed within 120s",
    );
    check(
        "this run's record, transiently",
        &|run| {
            run.fake
                .route(&format!("{PREFIX}/actions/runs/41"), vec![status(503)])
        },
        "a forge read did not succeed within 120s",
    );
    // Store fails on a refused mint or exchange itself.
    check(
        "git-oidc",
        &|run| {
            run.servers.script.lock().unwrap().mint = [(403, "{}".to_owned())].into();
        },
        "git-oidc refused the token request with HTTP 403",
    );
    check(
        "Google STS",
        &|run| {
            run.servers.script.lock().unwrap().sts =
                Some((400, json!({"error": "invalid_grant"}).to_string()));
        },
        "Google STS refused the token exchange with HTTP 400: invalid_grant",
    );
}

#[test]
fn misconfiguration_fails_the_command() {
    let check = |what: &str, change: &dyn Fn(&mut Run), expected: &str| {
        let mut run = Run::new("push");
        run.stored(40, 1);
        change(&mut run);
        let error = run.failed();
        assert!(error.contains(expected), "{what}: {error}");
    };
    let own = "ci reuse could not bind this run's own forge record";
    check(
        "this run's record refused",
        &|run| {
            run.fake
                .route(&format!("{PREFIX}/actions/runs/41"), vec![status(403)])
        },
        own,
    );
    check(
        "this run's record missing",
        &|run| {
            run.fake
                .route(&format!("{PREFIX}/actions/runs/41"), vec![status(404)])
        },
        "source_http_404",
    );
    check(
        "this run's record names another commit",
        &|run| {
            run.fake.route(
                &format!("{PREFIX}/actions/runs/41"),
                vec![ok(record(41, 2, EARLIER, "in_progress"))],
            )
        },
        "the forge's record of this run is not the run's",
    );
    check(
        "this run is not a scoped run",
        &|run| {
            let mut value = record(41, 2, HEAD, "in_progress");
            value["is_scoped"] = json!(false);
            run.fake
                .route(&format!("{PREFIX}/actions/runs/41"), vec![ok(value)])
        },
        "not app CI's scoped verification run",
    );
    check(
        "the listing refused",
        &|run| run.failing = Some("list"),
        "ci reuse could not list its key in the results bucket: the push identity's read \
         access or the bucket is misconfigured: app_ci_results_http_403",
    );
    check(
        "no job token",
        &|run| run.unset.push("GITHUB_TOKEN"),
        "ci reuse reads the forge with the job token in GITHUB_TOKEN",
    );
    check(
        "no bucket",
        &|run| run.unset.push(ci_store::BUCKET),
        "DAY2_CI_BUCKET is required to reuse a stored result",
    );
}

#[test]
fn the_lookup_ends_at_its_deadline_even_mid_read() -> Result<()> {
    // This run's record and the candidate's take 100 s each, within their own
    // 120 s; the candidate's commit archive would take 400 s: its request is
    // bounded by the 100 s left, times out at the deadline, and the lookup
    // misses.
    let slowly = |run: &Run| {
        let mut world = run.fake.0.borrow_mut();
        for id in [41, 40] {
            world.slow.insert(
                format!("{PREFIX}/actions/runs/{id}"),
                Duration::from_secs(100),
            );
        }
    };
    let run = Run::new("push");
    run.stored(40, 1);
    slowly(&run);
    run.fake
        .0
        .borrow_mut()
        .slow
        .insert(archive_url(EARLIER), Duration::from_secs(400));
    let report = run.missed();
    let reason = report.reason.clone().unwrap_or_default();
    assert!(
        reason.contains("the lookup's 300 s deadline passed during source"),
        "{reason}"
    );
    assert_eq!(
        report
            .tried
            .iter()
            .map(|tried| (tried.run, tried.accepted))
            .collect::<Vec<_>>(),
        [(40, false)]
    );
    let world = run.fake.0.borrow();
    assert!(world.now <= BUDGET, "{:?}", world.now);
    assert!(
        world
            .withins
            .iter()
            .all(|within| within.is_some_and(|within| within <= BUDGET))
    );
    drop(world);
    // A slow download is bounded the same way.
    let run = Run::new("push");
    run.stored(40, 1);
    slowly(&run);
    run.fake.0.borrow_mut().slow.insert(
        format!("media:{}40/1/artifact.tar.gz", run.key()),
        Duration::from_secs(400),
    );
    let reason = run.missed().reason.unwrap_or_default();
    assert!(
        reason.contains("the lookup's 300 s deadline passed during download"),
        "{reason}"
    );
    assert!(run.fake.0.borrow().now <= BUDGET);
    // A step that would begin after the deadline misses without a request.
    let run = Run::new("push");
    run.stored(40, 1);
    let mut session = run.session()?;
    session.step("run")?;
    run.fake.0.borrow_mut().now += BUDGET;
    assert_eq!(session.step("mint")?, json!({"missed": true}));
    assert!(run.servers.seen().is_empty());
    let report: Report = serde_json::from_value(session.step("result")?)?;
    assert!(
        report
            .reason
            .is_some_and(|reason| reason.contains("deadline passed before mint"))
    );
    Ok(())
}

#[test]
fn steps_run_only_in_the_recipes_order() -> Result<()> {
    let run = Run::new("push");
    run.stored(40, 1);
    let mut session = run.session()?;
    assert!(session.step("mint").is_err(), "the run's record first");
    session.step("run")?;
    assert!(
        session.step("result").is_err(),
        "not before the lookup ends"
    );
    session.step("mint")?;
    session.step("exchange")?;
    session.step("list")?;
    assert!(session.step("list").is_err(), "once");
    assert!(
        session.step("receipt").is_err(),
        "the candidate's run first"
    );
    session.step("candidate")?;
    assert!(
        session.step("receipt").is_err(),
        "its commit's source first"
    );
    for name in ["source", "receipt", "artifact", "download"] {
        session.step(name)?;
    }
    assert!(
        session.step("candidate").is_err(),
        "the attempt is not done"
    );
    session.step("attempt")?;
    assert!(session.step("candidate").is_err(), "the lookup ended");
    session.step("result")?;
    assert!(session.step("result").is_err(), "once");
    Ok(())
}

#[test]
fn only_this_runs_directory_and_record_are_accepted() -> Result<()> {
    let run = Run::new("push");
    // Another run's record fails the step: no later step could use it.
    let mut other = run.event.clone();
    other.attempt = 1;
    fs::write(
        run.ci().join("event.json"),
        serde_json::to_vec_pretty(&other)?,
    )?;
    assert!(
        format!("{:#}", run.session().err().context("refused")?)
            .contains("the run's record is not this run's")
    );
    let run = Run::new("push");
    fs::create_dir(run.ci().join(REUSE))?;
    assert!(format!("{:#}", run.session().err().context("refused")?).contains("runs once per run"));
    let run = Run::new("push");
    fs::write(
        run.directory.path().join("request.json"),
        json!({"directory": run.ci(), "cases": 3}).to_string(),
    )?;
    assert!(run.session().is_err());
    Ok(())
}

#[test]
fn a_record_is_exact() {
    let source = || Source {
        run: 40,
        attempt: 1,
        head: EARLIER.into(),
        workflow_commit: WORKFLOW.into(),
        started_at: STARTED.into(),
        completed_at: COMPLETED.into(),
        bucket: BUCKET_NAME.into(),
        receipt: Object {
            name: "aa/bb-6/40/1/receipt.json".into(),
            generation: "2".into(),
            time_created: CREATED.into(),
        },
        artifact: Object {
            name: "aa/bb-6/40/1/artifact.tar.gz".into(),
            generation: "1".into(),
            time_created: CREATED.into(),
        },
    };
    let hit = Record {
        format: 1,
        reused: true,
        reason: None,
        source: Some(source()),
    };
    assert!(hit.validate().is_ok());
    let miss = Record {
        format: 1,
        reused: false,
        reason: Some(ABSENT.into()),
        source: None,
    };
    assert!(miss.validate().is_ok());
    for record in [
        Record {
            format: 2,
            ..hit.clone()
        },
        Record {
            reused: false,
            ..hit.clone()
        },
        Record {
            reason: Some("both".into()),
            ..hit.clone()
        },
        Record {
            reused: true,
            ..miss.clone()
        },
        Record {
            reason: Some(String::new()),
            ..miss.clone()
        },
        Record {
            source: Some(Source {
                receipt: Object {
                    name: "aa/bb-6/39/1/receipt.json".into(),
                    ..source().receipt
                },
                ..source()
            }),
            ..hit.clone()
        },
        Record {
            source: Some(Source {
                head: "0".repeat(40),
                ..source()
            }),
            ..hit.clone()
        },
    ] {
        assert!(record.validate().is_err(), "{record:?}");
    }
}

#[test]
fn the_report_shape_is_pinned_for_the_cli() -> Result<()> {
    let key = format!("{}/{}-6/", "5d".repeat(32), "ab".repeat(32));
    let report = Report {
        format: 1,
        repository: "tools/links".into(),
        event: "push".into(),
        run: 41,
        attempt: 2,
        reused: true,
        reason: None,
        bucket: Some(BUCKET_NAME.into()),
        key: Some(key.clone()),
        listed: 2,
        tried: vec![
            Tried {
                run: 40,
                attempt: 2,
                accepted: false,
                reason: Some("the stored attempt 2 is not the run's current attempt 3".into()),
            },
            Tried {
                run: 39,
                attempt: 1,
                accepted: true,
                reason: None,
            },
        ],
        source: Some(Source {
            run: 39,
            attempt: 1,
            head: EARLIER.into(),
            workflow_commit: WORKFLOW.into(),
            started_at: STARTED.into(),
            completed_at: COMPLETED.into(),
            bucket: BUCKET_NAME.into(),
            receipt: Object {
                name: format!("{key}39/1/receipt.json"),
                generation: "1700000000000002".into(),
                time_created: CREATED.into(),
            },
            artifact: Object {
                name: format!("{key}39/1/artifact.tar.gz"),
                generation: "1700000000000001".into(),
                time_created: CREATED.into(),
            },
        }),
        output: Some("/tmp/day2-ci/reuse".into()),
    };
    assert_eq!(serde_json::to_string_pretty(&report)? + "\n", GOLDEN_REPORT);
    assert_eq!(serde_json::from_str::<Report>(GOLDEN_REPORT)?, report);
    let mut extra: Value = serde_json::from_str(GOLDEN_REPORT)?;
    extra["source"]["receipt"]["metadata"] = json!({});
    assert!(serde_json::from_value::<Report>(extra).is_err());
    Ok(())
}

#[test]
fn a_reused_result_is_stored_as_this_runs_own_and_a_deploy_accepts_it() -> Result<()> {
    // ci reuse finds run 40's result for the same app/.
    let run = Run::new("push");
    run.stored(40, 1);
    let (report, _) = run.reuse()?;
    assert!(report.reused);
    // ci check verifies it again on the same SDK tooling and writes OUTPUT.
    let work = tempfile::tempdir()?;
    let request = work.path().join("check.json");
    fs::write(
        &request,
        serde_json::to_vec(&crate::ci_check::Request {
            head: run.ci().join("head"),
            base: None,
            cases: 6,
            output: run.ci().join(ci_store::OUTPUT),
            reuse: Some(run.ci().join(REUSE)),
        })?,
    )?;
    let sdk = receipt(&run.inputs, &artifact()).sdk_distribution;
    let mut checked =
        crate::ci_check::tests::reusing(&request, &work.path().join("platform"), sdk)?;
    assert_eq!(checked.step("artifact")?["artifact"], "reused");
    checked.step("result")?;
    // ci store stores OUTPUT as run 41's own entry, with run 41's metadata.
    let servers = Servers::start();
    let store_variables = {
        let mut variables = run.variables();
        variables.retain(|(name, _)| *name != ci_store::ID_TOKEN_URL);
        variables.push((
            ci_store::ID_TOKEN_URL,
            format!("{}/token?v=1&repository=tools/links", servers.base),
        ));
        variables
    };
    std::fs::write(
        run.directory.path().join("store.json"),
        json!({"directory": run.ci()}).to_string(),
    )?;
    let mut store = ci_store::Session::prepare(
        &run.directory.path().join("store.json"),
        ci_store::Effects {
            client: ci_store::client(false)?,
            waiting: Box::new(run.fake.clone()),
            endpoints: ci_store::Endpoints {
                sts: format!("{}/v1/token", servers.base),
                upload: format!("{}/upload/storage/v1", servers.base),
                https: false,
            },
            variables: Box::new(move |name| {
                store_variables
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| OsString::from(value))
            }),
        },
    )?;
    for name in ["mint", "exchange", "artifact", "receipt"] {
        store.step(name)?;
    }
    let stored: ci_store::Report = serde_json::from_value(store.step("result")?)?;
    assert_eq!(
        stored.prefix.as_deref(),
        Some(format!("{}41/2", run.key()).as_str())
    );
    // The deploy reader's custody, for a deploy of this run's commit, accepts
    // both uploaded objects as this attempt's.
    let this = app_ci::Run {
        id: 41,
        attempt: 2,
        started_at: STARTED.into(),
        completed_at: COMPLETED.into(),
        workflow_commit: WORKFLOW.into(),
    };
    let uploads: Vec<(Value, Vec<u8>)> = servers
        .seen()
        .iter()
        .filter(|seen| seen.path().starts_with("/upload/"))
        .map(|seen| seen.parts())
        .collect();
    assert_eq!(uploads.len(), 2);
    let as_stored = |(resource, bytes): &(Value, Vec<u8>)| Stored {
        generation: "1700000000000009".into(),
        size: bytes.len() as u64,
        time_created: CREATED.into(),
        metadata: serde_json::from_value(resource["metadata"].clone()).unwrap(),
    };
    let (artifact_upload, receipt_upload) = (&uploads[0], &uploads[1]);
    assert!(
        receipt_upload.0["name"]
            .as_str()
            .unwrap()
            .ends_with("/41/2/receipt.json")
    );
    app_ci::receipt_object(&as_stored(receipt_upload), &this, HEAD)?;
    let checked = app_ci::decoded_receipt(&receipt_upload.1)?;
    app_ci::binds(
        &checked,
        &run.inputs,
        &json!({"version": 1, "seed": 42, "cases": 6}),
    )?;
    app_ci::artifact_object(&as_stored(artifact_upload), &this, HEAD, &checked.archive)?;
    app_ci::archive(&artifact_upload.1, &checked.archive)?;
    // The stored receipt is the reused one, byte for byte.
    assert_eq!(
        receipt_upload.1,
        fs::read(run.ci().join(REUSE).join(RECEIPT))?
    );
    Ok(())
}
