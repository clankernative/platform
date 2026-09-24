use day2_control::{
    Digest,
    gcp_secret_conformance::*,
    secrets::{AccessToken, AccessTokenProvider, SecretVersion},
    source::SourceError,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, VecDeque},
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const TOKEN: &str = "sandbox-token-never-in-evidence";
const RUN: &str = "day2-test-20260909";
const CREATED: &str = "2026-09-09T10:00:00.000001Z";
const OLD: &str = "\"opaque-before\"";
const NEW: &str = "\"opaque-after\"";

#[derive(Default)]
struct Tokens(AtomicUsize);
impl AccessTokenProvider for Tokens {
    fn access_token(&self) -> Result<AccessToken, SourceError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        AccessToken::new(TOKEN.to_owned())
    }
}

fn version(number: u64) -> SecretVersion {
    SecretVersion {
        project_number: 12345,
        secret: "disposable".into(),
        version: number,
    }
}

fn parent() -> Value {
    json!({
        "name":"projects/12345/secrets/disposable",
        "createTime":CREATED,
        "etag":"\"parent-opaque\"",
        "labels":{"day2-conformance-run":RUN,"unrelated":"ignored"},
        "versionAliases":{"blue":"1","green":"1"},
        "replication":{"automatic":{}}
    })
}

fn metadata(number: u64, state: &str, etag: &str) -> Value {
    json!({"name":version(number).resource_name(),"createTime":CREATED,"state":state,"etag":etag,"replicationStatus":{}})
}

fn attempt() -> DisableAttempt {
    DisableAttempt {
        effect: Digest::new(b"one-exact-disable"),
        version: version(1),
        expected_etag: OLD.to_owned().try_into().unwrap(),
        expected_create_time: CREATED.to_owned(),
    }
}

#[derive(Clone, Debug)]
struct Request {
    method: String,
    path: String,
    authorization: String,
    body: Vec<u8>,
}

struct Reply {
    status: u16,
    body: Vec<u8>,
}
impl Reply {
    fn json(status: u16, body: Value) -> Self {
        Self {
            status,
            body: serde_json::to_vec(&body).unwrap(),
        }
    }
    fn ok(body: Value) -> Self {
        Self::json(200, body)
    }
}

struct Server {
    endpoint: String,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    accepted: std::sync::mpsc::Receiver<()>,
    worker: Option<JoinHandle<()>>,
}
impl Server {
    fn new(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (accepted_sender, accepted) = std::sync::mpsc::channel();
        let (captured, shutdown) = (requests.clone(), stop.clone());
        let worker = thread::spawn(move || {
            let mut replies: VecDeque<_> = replies.into();
            while !shutdown.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                };
                // Accepted sockets can inherit the listener's nonblocking flag
                // on BSD systems; fixture reads must honor the bounded timeouts.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                accepted_sender.send(()).unwrap();
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    bytes.push(byte[0]);
                    assert!(bytes.len() <= 16_384);
                }
                let header = String::from_utf8(bytes).unwrap();
                let mut lines = header.lines();
                let mut request_line = lines.next().unwrap().split_ascii_whitespace();
                let method = request_line.next().unwrap().to_owned();
                let path = request_line.next().unwrap().to_owned();
                let mut length = 0;
                let mut authorization = String::new();
                for line in lines {
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse::<usize>().unwrap();
                        }
                        if name.eq_ignore_ascii_case("authorization") {
                            authorization = value.trim().to_owned();
                        }
                    }
                }
                assert!(length <= 4096);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                captured.lock().unwrap().push(Request {
                    method,
                    path,
                    authorization,
                    body,
                });
                let reply = replies
                    .pop_front()
                    .unwrap_or_else(|| Reply::json(500, json!({})));
                let header = format!(
                    "HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nLocation: http://127.0.0.1:1/forbidden\r\n\r\n",
                    reply.status,
                    reply.body.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(&reply.body);
            }
        });
        Self {
            endpoint,
            requests,
            stop,
            accepted,
            worker: Some(worker),
        }
    }

    fn client(&self) -> GcpSandboxClient {
        GcpSandboxClient::with_endpoint(
            &self.endpoint,
            12345,
            BTreeSet::from(["disposable".into()]),
            RUN.into(),
            Arc::new(Tokens::default()),
        )
        .unwrap()
    }

    fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}

#[test]
fn accepted_connection_waits_for_request_bytes_within_existing_deadline() {
    let server = Server::new(vec![Reply::ok(json!({"ready": true}))]);
    let address = server
        .endpoint
        .strip_prefix("http://")
        .unwrap()
        .trim_end_matches('/');
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    server
        .accepted
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    // Hold the first byte until the fixture has accepted the connection. A
    // nonblocking accepted stream would fail instead of waiting for this write.
    thread::sleep(Duration::from_millis(20));
    stream
        .write_all(b"GET /metadata HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 Fixture\r\n"));
    assert!(response.ends_with("{\"ready\":true}"));
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/metadata");
}

#[test]
fn explicit_fixture_and_two_aliases_resolve_to_one_numeric_identity() {
    let server = Server::new(vec![
        Reply::ok(parent()),
        Reply::ok(metadata(1, "ENABLED", OLD)),
        Reply::ok(metadata(2, "ENABLED", OLD)),
        Reply::ok(parent()),
        Reply::ok(metadata(1, "ENABLED", OLD)),
        Reply::ok(parent()),
        Reply::ok(metadata(1, "ENABLED", OLD)),
    ]);
    let client = server.client();
    let fixture = client.validate_fixture("disposable", [1, 2]).unwrap();
    assert_eq!(fixture.first.version, version(1));
    assert_eq!(fixture.second.version, version(2));
    let first = client.resolve_alias("disposable", "blue").unwrap();
    let second = client.resolve_alias("disposable", "green").unwrap();
    assert_eq!(first.version, second.version);
    assert_eq!(first.parent.etag, second.parent.etag);
    assert!(!serde_json::to_string(&first).unwrap().contains(TOKEN));
    let requests = server.requests();
    assert_eq!(requests.len(), 7);
    assert!(requests.iter().all(|r| r.method == "GET"
        && !r.path.contains(":access")
        && !r.path.contains("versions/blue")));
}

#[test]
fn every_disable_rechecks_disposable_ownership_before_sending_a_write() {
    let mut wrong = parent();
    wrong["labels"]["day2-conformance-run"] = json!("different-session");
    let server = Server::new(vec![Reply::ok(wrong)]);
    assert_eq!(
        server
            .client()
            .disable_once(&attempt(), ResponseDelivery::Deliver),
        Err(GcpError::OwnershipMismatch)
    );
    assert_eq!(server.requests().len(), 1);
    assert_eq!(server.requests()[0].method, "GET");
}

#[test]
fn conditional_disable_binds_original_etag_and_readback_is_only_observed_state() {
    let server = Server::new(vec![
        Reply::ok(parent()),
        Reply::ok(metadata(1, "ENABLED", OLD)),
        Reply::ok(metadata(1, "DISABLED", NEW)),
        Reply::ok(metadata(1, "DISABLED", NEW)),
    ]);
    let client = server.client();
    let outcome = client
        .disable_once(&attempt(), ResponseDelivery::Deliver)
        .unwrap();
    assert!(matches!(
        outcome,
        DisableOutcome::Acknowledged {
            metadata: VersionMetadata {
                state: VersionState::Disabled,
                ..
            }
        }
    ));
    assert!(matches!(
        client.observe_disabled(&version(1), CREATED).unwrap(),
        DisabledObservation::DisabledObservation { .. }
    ));
    let requests = server.requests();
    let writes: Vec<_> = requests
        .iter()
        .filter(|request| request.method == "POST")
        .collect();
    assert_eq!(writes.len(), 1);
    assert_eq!(
        writes[0].path,
        "/v1/projects/12345/secrets/disposable/versions/1:disable"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&writes[0].body).unwrap(),
        json!({"etag":OLD})
    );
    assert!(
        requests
            .iter()
            .all(|request| request.authorization == format!("Bearer {TOKEN}"))
    );
}

#[test]
fn lost_ack_is_reconciled_with_reads_after_reconstruction_without_a_second_post() {
    let server = Server::new(vec![
        Reply::ok(parent()),
        Reply::ok(metadata(1, "ENABLED", OLD)),
        Reply::ok(metadata(1, "DISABLED", NEW)),
        Reply::ok(metadata(1, "DISABLED", NEW)),
        Reply::ok(parent()),
        Reply::ok(metadata(1, "DISABLED", NEW)),
    ]);
    assert_eq!(
        server
            .client()
            .disable_once(&attempt(), ResponseDelivery::LoseAck)
            .unwrap(),
        DisableOutcome::Uncertain {}
    );
    let reconstructed = server.client();
    assert!(matches!(
        reconstructed
            .observe_disabled(&version(1), CREATED)
            .unwrap(),
        DisabledObservation::DisabledObservation { .. }
    ));
    assert_eq!(
        reconstructed.disable_once(&attempt(), ResponseDelivery::Deliver),
        Err(GcpError::PreconditionChanged)
    );
    assert_eq!(
        server
            .requests()
            .iter()
            .filter(|request| request.method == "POST")
            .count(),
        1
    );
}

#[test]
fn missing_or_enabled_readback_cannot_rule_out_late_application() {
    let server = Server::new(vec![
        Reply::json(404, json!({"message":"not evidence of absence"})),
        Reply::json(503, json!({"message":"not evidence of absence"})),
        Reply::ok(metadata(1, "ENABLED", OLD)),
        Reply::ok(parent()),
        Reply::ok(metadata(1, "ENABLED", OLD)),
        Reply::ok(metadata(1, "DISABLED", NEW)),
        Reply::ok(metadata(1, "DISABLED", NEW)),
    ]);
    let client = server.client();
    for expected in [
        ObservationReason::NotFound,
        ObservationReason::TransportUnknown,
        ObservationReason::NotDisabled,
    ] {
        let observation = client.observe_disabled(&version(1), CREATED).unwrap();
        assert!(
            matches!(observation,DisabledObservation::Inconclusive { reason,.. } if reason == expected)
        );
    }
    assert!(
        server
            .requests()
            .iter()
            .all(|request| request.method == "GET")
    );
    // The external fault gate has held this exact request. Its later delivery
    // must remain possible after all three inconclusive observations above.
    assert!(matches!(
        client
            .disable_once(&attempt(), ResponseDelivery::Deliver)
            .unwrap(),
        DisableOutcome::Acknowledged { .. }
    ));
    assert!(matches!(
        client.observe_disabled(&version(1), CREATED).unwrap(),
        DisabledObservation::DisabledObservation { .. }
    ));
    assert_eq!(
        server
            .requests()
            .iter()
            .filter(|request| request.method == "POST")
            .count(),
        1
    );
}

#[test]
fn post_failures_never_retry_and_remote_messages_never_escape() {
    for (reply, expected) in [
        (
            Reply::json(
                400,
                json!({"error":{"status":"FAILED_PRECONDITION","message":TOKEN}}),
            ),
            DisableOutcome::Rejected {
                reason: DisableRejection::PreconditionFailed,
            },
        ),
        (
            Reply::json(503, json!({"error":{"message":TOKEN}})),
            DisableOutcome::Uncertain {},
        ),
        (
            Reply::json(302, json!({"error":{"message":TOKEN}})),
            DisableOutcome::Rejected {
                reason: DisableRejection::RedirectForbidden,
            },
        ),
        (
            Reply::ok(json!({"name":TOKEN})),
            DisableOutcome::Uncertain {},
        ),
    ] {
        let server = Server::new(vec![
            Reply::ok(parent()),
            Reply::ok(metadata(1, "ENABLED", OLD)),
            reply,
        ]);
        let outcome = server
            .client()
            .disable_once(&attempt(), ResponseDelivery::Deliver)
            .unwrap();
        assert_eq!(outcome, expected);
        assert!(!serde_json::to_string(&outcome).unwrap().contains(TOKEN));
        assert_eq!(server.requests().len(), 3);
        assert_eq!(
            server
                .requests()
                .iter()
                .filter(|request| request.method == "POST")
                .count(),
            1
        );
    }
}

#[test]
fn untrusted_endpoints_unbound_versions_and_mutable_selectors_fail_before_credentials() {
    let tokens = Arc::new(Tokens::default());
    for endpoint in [
        "http://secretmanager.googleapis.com/",
        "https://evil.invalid/",
        "http://127.0.0.1:1/path/",
        "http://user@127.0.0.1:1/",
        "http://127.0.0.1:1/?extra=1",
    ] {
        assert!(
            GcpSandboxClient::with_endpoint(
                endpoint,
                12345,
                BTreeSet::from(["disposable".into()]),
                RUN.into(),
                tokens.clone()
            )
            .is_err()
        );
    }
    let client = GcpSandboxClient::with_endpoint(
        "http://127.0.0.1:1/",
        12345,
        BTreeSet::from(["disposable".into()]),
        RUN.into(),
        tokens.clone(),
    )
    .unwrap();
    let mut wrong = version(1);
    wrong.project_number = 999;
    assert_eq!(client.metadata(&wrong), Err(GcpError::NotAllowlisted));
    wrong = version(0);
    assert_eq!(client.metadata(&wrong), Err(GcpError::InvalidReference));
    assert_eq!(
        client.validate_fixture("disposable", [1, 1]),
        Err(GcpError::InvalidReference)
    );
    for alias in ["latest", "NEW", "../1", "a/b", ""] {
        assert_eq!(
            client.resolve_alias("disposable", alias),
            Err(GcpError::InvalidReference)
        );
    }
    assert_eq!(tokens.0.load(Ordering::SeqCst), 0);
}

#[test]
fn changed_incarnation_or_etag_never_refreshes_original_disable_precondition() {
    for (before, expected) in [
        (
            {
                let mut changed = metadata(1, "ENABLED", OLD);
                changed["createTime"] = json!("2026-09-10T00:00:00Z");
                changed
            },
            GcpError::IncarnationChanged,
        ),
        (metadata(1, "ENABLED", NEW), GcpError::PreconditionChanged),
    ] {
        let server = Server::new(vec![Reply::ok(parent()), Reply::ok(before)]);
        assert_eq!(
            server
                .client()
                .disable_once(&attempt(), ResponseDelivery::Deliver),
            Err(expected)
        );
        assert_eq!(server.requests().len(), 2);
        assert!(
            server
                .requests()
                .iter()
                .all(|request| request.method == "GET")
        );
    }
}

#[test]
fn metadata_identity_state_and_response_budget_fail_closed() {
    for (body, expected) in [
        (
            {
                let mut value = metadata(1, "ENABLED", OLD);
                value["name"] = json!("projects/12345/secrets/other/versions/1");
                value
            },
            GcpError::InvalidResponse,
        ),
        (
            metadata(1, "STATE_UNSPECIFIED", OLD),
            GcpError::InvalidResponse,
        ),
        (metadata(1, "ENABLED", ""), GcpError::InvalidResponse),
        (
            json!({"padding":"x".repeat(33*1024)}),
            GcpError::ResponseBudget,
        ),
    ] {
        let server = Server::new(vec![Reply::ok(body)]);
        assert_eq!(server.client().metadata(&version(1)), Err(expected));
        assert_eq!(server.requests().len(), 1);
    }
}

#[test]
fn opaque_etags_and_serialized_outcomes_reject_invalid_or_extra_fields() {
    for value in ["".to_owned(), "\n".to_owned(), "x".repeat(257)] {
        assert!(serde_json::from_value::<OpaqueEtag>(json!(value)).is_err());
    }
    assert_eq!(
        serde_json::from_value::<OpaqueEtag>(json!(OLD))
            .unwrap()
            .as_str(),
        OLD
    );
    assert!(
        serde_json::from_value::<DisableOutcome>(json!({"kind":"uncertain","not_applied":true}))
            .is_err()
    );
    assert!(serde_json::from_value::<DisableAttempt>(json!({
        "effect":Digest::new(b"test"),"version":version(1),"expected_etag":OLD,"expected_create_time":CREATED,"credentials":TOKEN
    })).is_err());
}
