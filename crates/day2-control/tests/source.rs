use base64::{Engine as _, engine::general_purpose::STANDARD};
use day2_control::{Digest, GitOid, source::*};
use serde_json::{Value, json};
use sha1::{Digest as _, Sha1};
use std::{
    collections::{BTreeMap, VecDeque},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const COMMIT: &str = "1111111111111111111111111111111111111111";
const TREE: &str = "2222222222222222222222222222222222222222";
const TOKEN: &str = "fixture-secret-not-for-logs";

#[derive(Clone, Debug)]
struct Request {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}
struct Reply {
    status: u16,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
    disconnect: bool,
}
impl Reply {
    fn json(value: Value) -> Self {
        Self::status(200, value)
    }
    fn status(status: u16, value: Value) -> Self {
        Self {
            status,
            body: serde_json::to_vec(&value).unwrap(),
            headers: vec![],
            disconnect: false,
        }
    }
    fn disconnect() -> Self {
        Self {
            status: 0,
            body: vec![],
            headers: vec![],
            disconnect: true,
        }
    }
}
struct Fixture {
    endpoint: String,
    requests: Arc<Mutex<Vec<Request>>>,
    remaining: Arc<Mutex<VecDeque<Reply>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl Fixture {
    fn new(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/api/v3/", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(vec![]));
        let remaining = Arc::new(Mutex::new(VecDeque::from(replies)));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen, queue, shutdown) = (requests.clone(), remaining.clone(), stop.clone());
        let worker = thread::spawn(move || {
            while !shutdown.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                seen.lock().unwrap().push(read_request(&mut stream));
                let reply = queue
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| Reply::status(500, json!({"unexpected":true})));
                if reply.disconnect {
                    continue;
                }
                let mut head = format!(
                    "HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                    reply.status,
                    reply.body.len()
                );
                for (name, value) in reply.headers {
                    head.push_str(&format!("{name}: {value}\r\n"));
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&reply.body);
            }
        });
        Self {
            endpoint,
            requests,
            remaining,
            stop,
            worker: Some(worker),
        }
    }
    fn client(&self) -> GithubSource {
        GithubSource::new(&self.endpoint).unwrap()
    }
    fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
    fn consumed(&self) {
        assert!(
            self.remaining.lock().unwrap().is_empty(),
            "fixture requests were skipped"
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let joined = worker.join();
            if !thread::panicking() {
                joined.unwrap();
            }
        }
    }
}
fn read_request(stream: &mut TcpStream) -> Request {
    let mut bytes = vec![];
    let head_end = loop {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() < 16_384);
        if bytes.ends_with(b"\r\n\r\n") {
            break bytes.len();
        }
    };
    let head = std::str::from_utf8(&bytes[..head_end]).unwrap();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap().split_whitespace();
    let method = first.next().unwrap().to_owned();
    let target = first.next().unwrap().to_owned();
    let headers: BTreeMap<_, _> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let count: usize = headers
        .get("content-length")
        .map_or(0, |value| value.parse().unwrap());
    assert!(count < 64_000);
    let mut body = vec![0; count];
    stream.read_exact(&mut body).unwrap();
    Request {
        method,
        target,
        headers,
        body,
    }
}
struct Secrets;
impl SecretResolver for Secrets {
    fn binding_revision(&self) -> Digest {
        Digest::new(b"source-fixture-secret-bindings-v1")
    }
    fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, SourceError> {
        assert!(matches!(reference.as_str(), "source-read" | "checks-write"));
        SecretValue::new(TOKEN.to_owned())
    }
}
fn binding() -> GithubBinding {
    GithubBinding {
        owner: "company".into(),
        repository: "app".into(),
        repository_id: 42,
        subdirectory: None,
        credential: Some("source-read".to_owned().try_into().unwrap()),
        checks: Some(CheckBinding {
            app_id: 17,
            credential: "checks-write".to_owned().try_into().unwrap(),
        }),
    }
}
fn commit() -> GitOid {
    COMMIT.to_owned().try_into().unwrap()
}
fn repo() -> Reply {
    Reply::json(json!({"id":42,"full_name":"company/app"}))
}
fn commit_reply() -> Reply {
    Reply::json(json!({"sha":COMMIT,"tree":{"sha":TREE}}))
}
fn blob_oid(bytes: &[u8]) -> String {
    let mut hash = Sha1::new();
    hash.update(format!("blob {}\0", bytes.len()));
    hash.update(bytes);
    format!("{:x}", hash.finalize())
}
fn entry(path: &str, bytes: &[u8]) -> Value {
    json!({"path":path,"mode":"100644","type":"blob","sha":blob_oid(bytes),"size":bytes.len()})
}
fn tree(entries: Vec<Value>) -> Reply {
    Reply::json(json!({"sha":TREE,"truncated":false,"tree":entries}))
}
fn blob(bytes: &[u8]) -> Reply {
    Reply::json(
        json!({"sha":blob_oid(bytes),"encoding":"base64","size":bytes.len(),"content":STANDARD.encode(bytes)}),
    )
}
fn publication() -> CheckPublication {
    CheckPublication {
        commit: commit(),
        effect_id: Digest::new(b"effect"),
        evidence: Digest::new(b"evidence"),
        conclusion: CheckConclusion::Success,
    }
}
fn check(id: u64) -> Value {
    let p = publication();
    json!({"id":id,"name":CHECK_NAME,"head_sha":COMMIT,"external_id":p.effect_id,"status":"completed","conclusion":"success","output":{"title":"Day2 verification","summary":p.summary()},"app":{"id":17}})
}
fn checks(values: Vec<Value>) -> Reply {
    Reply::json(json!({"total_count":values.len(),"check_runs":values}))
}

#[test]
fn immutable_source_uses_exact_objects_explicit_secret_and_verified_bytes() {
    let content = b"module [hello]\nhello = 1\n";
    let fixture = Fixture::new(vec![
        repo(),
        commit_reply(),
        tree(vec![entry("App.roc", content)]),
        blob(content),
    ]);
    let snapshot = fixture
        .client()
        .fetch(&binding(), &commit(), &Secrets)
        .unwrap();
    assert_eq!(snapshot.files()["App.roc"], content);
    assert_eq!(snapshot.evidence().repository_id, Some(42));
    assert_eq!(snapshot.evidence().tree.as_ref().unwrap().as_str(), TREE);
    let requests = fixture.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests[1].target,
        format!("/api/v3/repos/company/app/git/commits/{COMMIT}")
    );
    assert_eq!(
        requests[2].target,
        format!("/api/v3/repos/company/app/git/trees/{TREE}?recursive=1")
    );
    assert!(requests.iter().all(|r| r.method == "GET"
        && r.headers["authorization"] == format!("Bearer {TOKEN}")
        && r.headers["x-github-api-version"] == "2026-03-10"));
    assert!(!format!("{snapshot:?} {:?}", SecretValue::new(TOKEN.into()).unwrap()).contains(TOKEN));
    let root = tempfile::tempdir().unwrap();
    snapshot.materialize(&root.path().join("source")).unwrap();
    assert_eq!(
        std::fs::read(root.path().join("source/App.roc")).unwrap(),
        content
    );
    assert!(snapshot.materialize(&root.path().join("source")).is_err());
    fixture.consumed();
}

#[test]
fn subtree_navigation_is_nonrecursive_and_snapshot_paths_are_relative() {
    let subtree = "3333333333333333333333333333333333333333";
    let mut b = binding();
    b.subdirectory = Some("apps".into());
    b.credential = None;
    let fixture = Fixture::new(vec![
        repo(),
        commit_reply(),
        tree(vec![
            json!({"path":"apps","mode":"040000","type":"tree","sha":subtree}),
        ]),
        Reply::json(json!({"sha":subtree,"truncated":false,"tree":[entry("App.roc",b"app")]})),
        blob(b"app"),
    ]);
    let snapshot = fixture.client().fetch(&b, &commit(), &Secrets).unwrap();
    assert!(snapshot.files().contains_key("App.roc"));
    let requests = fixture.requests();
    assert_eq!(
        requests[2].target,
        format!("/api/v3/repos/company/app/git/trees/{TREE}")
    );
    assert!(
        requests
            .iter()
            .all(|r| !r.headers.contains_key("authorization"))
    );
    fixture.consumed();
}

#[test]
fn snapshots_reject_nonportable_and_conflicting_paths_before_materialization() {
    for path in [
        "../escape",
        "/absolute",
        "a//b",
        "a/../b",
        "a\\b",
        ".git/config",
        "A/.GIT/x",
        "a%2fb",
        "name.",
        "NUL.txt",
        "a b",
        "café",
        "a:b",
    ] {
        assert!(
            SourceSnapshot::from_files(commit(), BTreeMap::from([(path.into(), b"x".to_vec())]))
                .is_err(),
            "{path}"
        );
    }
    for paths in [
        ["App.roc", "app.roc"],
        ["ui/App.roc", "UI/other.roc"],
        ["ui", "ui/app.js"],
    ] {
        assert!(
            SourceSnapshot::from_files(
                commit(),
                paths
                    .into_iter()
                    .map(|path| (path.into(), vec![]))
                    .collect()
            )
            .is_err()
        );
    }
    assert!(
        SourceSnapshot::from_files(
            commit(),
            BTreeMap::from([("App.roc".into(), vec![0; MAX_FILE_BYTES + 1])])
        )
        .is_err()
    );
}

#[test]
fn content_digest_is_order_independent_but_binds_every_path_and_byte() {
    let one = SourceSnapshot::from_files(
        commit(),
        BTreeMap::from([("A.roc".into(), vec![1]), ("B.roc".into(), vec![2])]),
    )
    .unwrap();
    let two = SourceSnapshot::from_files(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_owned()
            .try_into()
            .unwrap(),
        BTreeMap::from([("B.roc".into(), vec![2]), ("A.roc".into(), vec![1])]),
    )
    .unwrap();
    assert_eq!(one.digest(), two.digest());
    assert_ne!(one.commit(), two.commit());
    for files in [
        BTreeMap::from([("C.roc".into(), vec![1]), ("B.roc".into(), vec![2])]),
        BTreeMap::from([("A.roc".into(), vec![9]), ("B.roc".into(), vec![2])]),
    ] {
        assert_ne!(
            one.digest(),
            SourceSnapshot::from_files(commit(), files)
                .unwrap()
                .digest()
        );
    }
}

#[test]
fn provider_and_secret_binding_changes_invalidate_configuration_evidence() {
    struct Rotated;
    impl SecretResolver for Rotated {
        fn resolve(&self, _: &SecretRef) -> Result<SecretValue, SourceError> {
            unreachable!()
        }
        fn binding_revision(&self) -> Digest {
            Digest::new(b"rotated-secret-version")
        }
    }
    let one = GithubSource::new("http://127.0.0.1:1001/").unwrap();
    let two = GithubSource::new("http://127.0.0.1:1002/").unwrap();
    assert_ne!(
        one.binding_revision(&binding(), &Secrets).unwrap(),
        two.binding_revision(&binding(), &Secrets).unwrap()
    );
    assert_ne!(
        one.binding_revision(&binding(), &Secrets).unwrap(),
        one.binding_revision(&binding(), &Rotated).unwrap()
    );
}

#[test]
fn recursive_tree_requires_consistent_directory_structure() {
    let dir = json!({"path":"ui","mode":"040000","type":"tree","sha":TREE});
    let fixture = Fixture::new(vec![
        repo(),
        commit_reply(),
        tree(vec![dir.clone(), entry("ui/app.js", b"ui")]),
        blob(b"ui"),
    ]);
    assert!(
        fixture
            .client()
            .fetch(&binding(), &commit(), &Secrets)
            .unwrap()
            .files()
            .contains_key("ui/app.js")
    );
    fixture.consumed();
    for entries in [
        vec![entry("ui/app.js", b"ui")],
        vec![dir, entry("UI/app.js", b"ui")],
        vec![entry("ui", b"ui"), entry("ui/app.js", b"ui")],
    ] {
        let fixture = Fixture::new(vec![repo(), commit_reply(), tree(entries)]);
        assert!(
            fixture
                .client()
                .fetch(&binding(), &commit(), &Secrets)
                .is_err()
        );
        fixture.consumed();
    }
}

#[test]
fn unsupported_modes_truncation_and_invalid_tree_paths_fail_before_blob_fetch() {
    for mode in ["100755", "120000", "160000"] {
        let mut value = entry("App.roc", b"app");
        value["mode"] = mode.into();
        if mode == "160000" {
            value["type"] = "commit".into();
        }
        let fixture = Fixture::new(vec![repo(), commit_reply(), tree(vec![value])]);
        assert_eq!(
            fixture
                .client()
                .fetch(&binding(), &commit(), &Secrets)
                .unwrap_err()
                .class,
            FailureClass::Unsupported
        );
        fixture.consumed();
    }
    for value in [
        json!({"sha":TREE,"truncated":true,"tree":[]}),
        json!({"sha":TREE,"truncated":false,"tree":[entry("../escape",b"x")]}),
        json!({"sha":TREE,"truncated":false,"tree":[entry("App.roc",b"x"),entry("App.roc",b"x")]}),
    ] {
        let fixture = Fixture::new(vec![repo(), commit_reply(), Reply::json(value)]);
        assert!(
            fixture
                .client()
                .fetch(&binding(), &commit(), &Secrets)
                .is_err()
        );
        fixture.consumed();
    }
}

#[test]
fn identity_and_blob_corruption_are_integrity_failures() {
    let fixture = Fixture::new(vec![Reply::json(
        json!({"id":43,"full_name":"company/app"}),
    )]);
    assert_eq!(
        fixture
            .client()
            .fetch(&binding(), &commit(), &Secrets)
            .unwrap_err()
            .class,
        FailureClass::Integrity
    );
    fixture.consumed();
    let fixture = Fixture::new(vec![
        repo(),
        Reply::json(json!({"sha":TREE,"tree":{"sha":TREE}})),
    ]);
    assert_eq!(
        fixture
            .client()
            .fetch(&binding(), &commit(), &Secrets)
            .unwrap_err()
            .class,
        FailureClass::Integrity
    );
    fixture.consumed();
    for content in [STANDARD.encode(b"bad"), "not-base64!".into()] {
        let fixture = Fixture::new(vec![
            repo(),
            commit_reply(),
            tree(vec![entry("App.roc", b"app")]),
            Reply::json(
                json!({"sha":blob_oid(b"app"),"encoding":"base64","size":3,"content":content}),
            ),
        ]);
        assert_eq!(
            fixture
                .client()
                .fetch(&binding(), &commit(), &Secrets)
                .unwrap_err()
                .class,
            FailureClass::Integrity
        );
        fixture.consumed();
    }
}

#[test]
fn provider_failures_are_classified_without_leaking_bodies_or_following_redirects() {
    for (status, class) in [
        (401, FailureClass::Unauthorized),
        (404, FailureClass::NotFound),
        (429, FailureClass::RateLimited),
        (503, FailureClass::Transient),
        (302, FailureClass::Unsupported),
    ] {
        let mut response = Reply::status(status, json!({"message":TOKEN}));
        response.headers.push((
            "Location".into(),
            "http://127.0.0.1:1/credential-theft".into(),
        ));
        let fixture = Fixture::new(vec![response]);
        let error = fixture
            .client()
            .fetch(&binding(), &commit(), &Secrets)
            .unwrap_err();
        assert_eq!(error.class, class);
        assert!(!error.to_string().contains(TOKEN));
        assert_eq!(fixture.requests().len(), 1);
        fixture.consumed();
    }
    for endpoint in [
        "http://github.com",
        "https://user:password@api.github.com",
        "https://api.github.com?token=secret",
        "file:///tmp/api",
    ] {
        assert!(GithubSource::new(endpoint).is_err());
    }
}

#[test]
fn check_publication_posts_once_with_bound_evidence_and_separate_write_credential() {
    let fixture = Fixture::new(vec![repo(), checks(vec![]), Reply::status(201, check(7))]);
    let receipt = fixture
        .client()
        .publish_check_once(&binding(), &publication(), &Secrets)
        .unwrap();
    assert_eq!(receipt.id, 7);
    assert_eq!(receipt.publication, publication());
    let requests = fixture.requests();
    assert_eq!(requests.iter().filter(|r| r.method == "POST").count(), 1);
    let body: Value = serde_json::from_slice(&requests[2].body).unwrap();
    assert_eq!(body["external_id"], publication().effect_id.as_str());
    assert_eq!(body["head_sha"], COMMIT);
    assert_eq!(body["output"]["summary"], publication().summary());
    fixture.consumed();
}

#[test]
fn failed_verification_posts_and_reconciles_failure_without_another_mutation() {
    let mut publication = publication();
    publication.conclusion = CheckConclusion::Failure;
    let mut failed_check = check(7);
    failed_check["conclusion"] = "failure".into();
    let fixture = Fixture::new(vec![
        repo(),
        checks(vec![]),
        Reply::status(201, failed_check.clone()),
        repo(),
        checks(vec![failed_check]),
    ]);
    let client = fixture.client();
    let receipt = client
        .publish_check_once(&binding(), &publication, &Secrets)
        .unwrap();
    assert_eq!(receipt.publication, publication);
    assert_eq!(
        client
            .observe_check(&binding(), &publication, &Secrets)
            .unwrap(),
        CheckObservation::Found(receipt)
    );
    let requests = fixture.requests();
    let posts: Vec<_> = requests
        .iter()
        .filter(|request| request.method == "POST")
        .collect();
    assert_eq!(posts.len(), 1);
    let body: Value = serde_json::from_slice(&posts[0].body).unwrap();
    assert_eq!(body["conclusion"], "failure");
    assert_eq!(body["external_id"], publication.effect_id.as_str());
    fixture.consumed();

    let mismatched = Fixture::new(vec![repo(), checks(vec![check(7)])]);
    assert_eq!(
        mismatched
            .client()
            .observe_check(&binding(), &publication, &Secrets)
            .unwrap_err()
            .code,
        "github_check_conflict"
    );
    mismatched.consumed();
}

#[test]
fn existing_check_reconciles_without_post_and_ignores_unrelated_conclusions() {
    let mut other = check(8);
    other["external_id"] = "unrelated".into();
    other["conclusion"] = "neutral".into();
    let fixture = Fixture::new(vec![repo(), checks(vec![other, check(7)])]);
    assert_eq!(
        fixture
            .client()
            .publish_check_once(&binding(), &publication(), &Secrets)
            .unwrap()
            .id,
        7
    );
    assert!(fixture.requests().iter().all(|r| r.method == "GET"));
    fixture.consumed();
}

#[test]
fn lost_post_response_is_ambiguous_and_observation_never_reposts() {
    for visible in [false, true] {
        let fixture = Fixture::new(vec![
            repo(),
            checks(vec![]),
            Reply::disconnect(),
            repo(),
            checks(if visible { vec![check(7)] } else { vec![] }),
        ]);
        let client = fixture.client();
        assert!(matches!(
            client.publish_check_once(&binding(), &publication(), &Secrets),
            Err(CheckPublishError::Ambiguous(_))
        ));
        let observed = client
            .observe_check(&binding(), &publication(), &Secrets)
            .unwrap();
        assert_eq!(matches!(observed, CheckObservation::Found(_)), visible);
        assert_eq!(
            fixture
                .requests()
                .iter()
                .filter(|r| r.method == "POST")
                .count(),
            1
        );
        fixture.consumed();
    }
}

#[test]
fn ambiguous_publication_responses_are_not_reported_as_rejections() {
    for status in [408, 500, 503, 200, 201] {
        let fixture = Fixture::new(vec![
            repo(),
            checks(vec![]),
            Reply::status(status, json!({"not":"a receipt"})),
        ]);
        assert!(
            matches!(
                fixture
                    .client()
                    .publish_check_once(&binding(), &publication(), &Secrets),
                Err(CheckPublishError::Ambiguous(_))
            ),
            "{status}"
        );
        fixture.consumed();
    }
    for status in [403, 422] {
        let fixture = Fixture::new(vec![
            repo(),
            checks(vec![]),
            Reply::status(status, json!({"message":TOKEN})),
        ]);
        assert!(matches!(
            fixture
                .client()
                .publish_check_once(&binding(), &publication(), &Secrets),
            Err(CheckPublishError::Rejected(_))
        ));
        fixture.consumed();
    }
}

#[test]
fn duplicate_or_conflicting_check_identity_fails_closed() {
    let mut wrong_app = check(7);
    wrong_app["app"]["id"] = 18.into();
    let mut wrong_head = check(7);
    wrong_head["head_sha"] = TREE.into();
    let mut wrong_evidence = check(7);
    wrong_evidence["output"]["summary"] = "forged".into();
    for values in [
        vec![check(7), check(8)],
        vec![wrong_app],
        vec![wrong_head],
        vec![wrong_evidence],
    ] {
        let fixture = Fixture::new(vec![repo(), checks(values)]);
        assert_eq!(
            fixture
                .client()
                .observe_check(&binding(), &publication(), &Secrets)
                .unwrap_err()
                .class,
            FailureClass::Integrity
        );
        fixture.consumed();
    }
}
