use super::*;
use crate::oauth::{
    approval_registry::{
        ApprovalAuthority, ApprovalKeyMaterial, ApprovalKeyProvider, ApprovalKeyPurpose,
        ApprovalKeyRef, SelectedApprovalAuthority, StoredAppApprovals,
    },
    connect,
    profiles::{AccountBindingEvidence, tests as fixtures},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::json;
use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
};

const HUMAN: &str = "ada@example.com";
const SUBJECT: &str = "accounts.google.com:1234567890";
const MACHINE: &str = "security@company.iam.gserviceaccount.com";
const APP_AUDIENCE: &str = "/projects/1/global/backendServices/2";
const SHELL_AUDIENCE: &str = "/projects/1/global/backendServices/1";

fn human() -> iap::Verified {
    iap::Verified {
        email: HUMAN.into(),
        subject: SUBJECT.into(),
    }
}

struct Assertions {
    pair: EcdsaKeyPair,
    keys: String,
}
struct Keys(String);
impl iap::KeySource for Keys {
    fn fetch(&self) -> Result<String> {
        Ok(self.0.clone())
    }
}

impl Assertions {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let point = pair.public_key().as_ref();
        let keys =
            json!({"keys":[{"kid":"fixture","kty":"EC","crv":"P-256","alg":"ES256","use":"sig",
            "x":URL_SAFE_NO_PAD.encode(&point[1..33]),"y":URL_SAFE_NO_PAD.encode(&point[33..65])}]})
            .to_string();
        Self { pair, keys }
    }

    fn assertion(&self, audience: &str, email: &str, subject: &str) -> String {
        self.assertion_at(audience, email, subject, 0)
    }

    fn assertion_at(&self, audience: &str, email: &str, subject: &str, at: i64) -> String {
        let mut claims = json!({"iss":"https://cloud.google.com/iap","aud":audience,"email":email,
            "sub":subject,"iat":at,"exp":at + 600});
        if email == HUMAN {
            claims["hd"] = json!("example.com");
        }
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(json!({"kid":"fixture","alg":"ES256"}).to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = self
            .pair
            .sign(&SystemRandom::new(), signed.as_bytes())
            .unwrap();
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }

    fn receiver(&self, backend: Arc<dyn AppApprovals>) -> AppApprovalReceiver {
        AppApprovalReceiver {
            backend,
            registrations: None,
            authority: "app.example".into(),
            route: route_prefix("installation", "production", "app").unwrap(),
            workload: iap::Verifier::for_workload(
                APP_AUDIENCE,
                MACHINE,
                Box::new(Keys(self.keys.clone())),
            )
            .unwrap(),
            human: iap::Verifier::new(
                SHELL_AUDIENCE,
                "example.com",
                Box::new(Keys(self.keys.clone())),
            )
            .unwrap(),
        }
    }

    fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("app.example"));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            iap::ASSERTION_HEADER,
            self.assertion(APP_AUDIENCE, MACHINE, "service-123")
                .parse()
                .unwrap(),
        );
        headers
    }

    fn human_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            iap::ASSERTION_HEADER,
            self.assertion(SHELL_AUDIENCE, HUMAN, SUBJECT)
                .parse()
                .unwrap(),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("__Host-day2-security=browser-private-cookie"),
        );
        headers
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    facts: fixtures::QualificationFixture,
    authority: Arc<SelectedApprovalAuthority>,
    backend: Arc<StoredAppApprovals>,
    clock: Arc<AtomicI64>,
}

impl Fixture {
    fn new() -> Self {
        Self::with_keys(Arc::new(fixtures::TestApprovalKeys(0.into())))
    }

    fn with_keys(keys: Arc<dyn ApprovalKeyProvider>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.sqlite");
        let mut facts = fixtures::external_fixture();
        facts.intent.attempt = scoped_attempt("installation", "production", "app").unwrap();
        facts.intent.owner = HUMAN.into();
        let AccountBindingEvidence::ExplicitExternal { owner, .. } = &mut facts.instance.account
        else {
            unreachable!()
        };
        *owner = HUMAN.into();
        let mut db = crate::store::open(&path).unwrap();
        db.execute_batch(crate::audit::PRINCIPALS_DDL).unwrap();
        fixtures::quarantine_external_fixture(&mut db, &facts, &fixtures::exchange_key());
        drop(db);
        let authority = Arc::new(
            SelectedApprovalAuthority::new(
                &fixtures::selected_instance(),
                BTreeMap::from([(
                    ("app".into(), facts.intent.slot.clone()),
                    fixtures::selected_approval(&facts),
                )]),
                keys,
            )
            .unwrap(),
        );
        let clock = Arc::new(AtomicI64::new(6));
        let mut backend =
            StoredAppApprovals::new("app".into(), path.clone(), authority.clone()).unwrap();
        let at = clock.clone();
        backend.set_clock(Arc::new(move || Ok(at.load(Ordering::SeqCst))));
        Self {
            _directory: directory,
            path,
            facts,
            authority,
            backend: Arc::new(backend),
            clock,
        }
    }

    fn view(&self) -> ApprovalView {
        self.backend
            .lookup(&self.facts.intent.attempt, &human(), 6)
            .unwrap()
            .view
            .unwrap()
    }

    fn proof(&self, view: &ApprovalView) -> external::FreshExternalApproval {
        let shell = external::ShellApprovalKeyLease::new(
            &[12; 32],
            "shell_v1".into(),
            view.claim.security_origin.clone(),
            view.claim.approval.clone(),
        )
        .unwrap();
        shell
            .attest_view(
                &view.claim,
                view.digest().unwrap(),
                Digest::of(&"fresh-session").unwrap(),
                5,
                6,
            )
            .unwrap()
    }

    fn state(&self) -> connect::ConnectState {
        connect::state(
            &crate::store::open(&self.path).unwrap(),
            &self.facts.intent.attempt,
        )
        .unwrap()
        .unwrap()
    }
}

fn copy_proof(proof: &external::FreshExternalApproval) -> external::FreshExternalApproval {
    crate::json::decode(&serde_json::to_vec(proof).unwrap()).unwrap()
}

#[test]
fn receiver_requires_independent_machine_and_human_assertions_before_sqlite() {
    struct Spy(AtomicUsize);
    impl AppApprovals for Spy {
        fn app(&self) -> &str {
            "app"
        }

        fn lookup(&self, _: &str, _: &iap::Verified, _: i64) -> Result<HostLookup> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(HostLookup {
                owned: false,
                view: None,
            })
        }

        fn confirm(
            &self,
            _: &str,
            _: &Digest,
            _: &iap::Verified,
            _: external::FreshExternalApproval,
            _: i64,
        ) -> Result<bool> {
            panic!("not a confirmation")
        }
    }
    let assertions = Assertions::new();
    let spy = Arc::new(Spy(AtomicUsize::new(0)));
    let receiver = assertions.receiver(spy.clone());
    let id = scoped_attempt("installation", "production", "app").unwrap();
    let lookup = |id: &str, assertion: &str, version| {
        serde_json::to_vec(&RequestBody::Lookup {
            version,
            attempt: id.into(),
            human_assertion: assertion.into(),
        })
        .unwrap()
    };
    let human_assertion = assertions.assertion(SHELL_AUDIENCE, HUMAN, SUBJECT);
    let body = lookup(&id, &human_assertion, VERSION);
    let headers = assertions.headers();
    receiver
        .dispatch(&Method::POST, PATH, None, &headers, &body, 6)
        .unwrap();
    assert_eq!(spy.0.load(Ordering::SeqCst), 1);
    for (audience, email) in [
        (APP_AUDIENCE, HUMAN),
        (SHELL_AUDIENCE, MACHINE),
        (APP_AUDIENCE, "other@company.iam.gserviceaccount.com"),
    ] {
        let mut bad = headers.clone();
        bad.insert(
            iap::ASSERTION_HEADER,
            assertions
                .assertion(audience, email, SUBJECT)
                .parse()
                .unwrap(),
        );
        assert!(
            receiver
                .dispatch(&Method::POST, PATH, None, &bad, &body, 6)
                .is_err()
        );
    }
    for (audience, email) in [(APP_AUDIENCE, HUMAN), (SHELL_AUDIENCE, MACHINE)] {
        assert!(
            receiver
                .dispatch(
                    &Method::POST,
                    PATH,
                    None,
                    &headers,
                    &lookup(
                        &id,
                        &assertions.assertion(audience, email, SUBJECT),
                        VERSION
                    ),
                    6
                )
                .is_err()
        );
    }
    for bad in [
        scoped_attempt("installation", "production", "other").unwrap(),
        scoped_attempt("installation", "staging", "app").unwrap(),
        "attempt_1".into(),
    ] {
        assert!(
            receiver
                .dispatch(
                    &Method::POST,
                    PATH,
                    None,
                    &headers,
                    &lookup(&bad, &human_assertion, VERSION),
                    6
                )
                .is_err()
        );
    }
    for bad in [
        lookup(&id, &human_assertion, VERSION + 1),
        format!(
            "{{\"extra\":true,{}",
            std::str::from_utf8(&body).unwrap().trim_start_matches('{')
        )
        .into_bytes(),
        format!(
            "{{\"version\":1,{}",
            std::str::from_utf8(&body).unwrap().trim_start_matches('{')
        )
        .into_bytes(),
        vec![b' '; MAX_REQUEST + 1],
    ] {
        assert!(
            receiver
                .dispatch(&Method::POST, PATH, None, &headers, &bad, 6)
                .is_err()
        );
    }
    for (method, path, query) in [
        (Method::GET, PATH, None),
        (Method::POST, "/app-command", None),
        (Method::POST, PATH, Some("x=1")),
    ] {
        assert!(
            receiver
                .dispatch(&method, path, query, &headers, &body, 6)
                .is_err()
        );
    }
    for name in [
        header::HOST,
        header::CONTENT_TYPE,
        iap::ASSERTION_HEADER.parse().unwrap(),
    ] {
        let mut bad = headers.clone();
        bad.append(name.clone(), headers[&name].clone());
        assert!(
            receiver
                .dispatch(&Method::POST, PATH, None, &bad, &body, 6)
                .is_err()
        );
    }
    let mut bad = headers.clone();
    bad.insert(header::HOST, HeaderValue::from_static("other.example"));
    assert!(
        receiver
            .dispatch(&Method::POST, PATH, None, &bad, &body, 6)
            .is_err()
    );
    assert_eq!(
        spy.0.load(Ordering::SeqCst),
        1,
        "all invalid inputs are rejected before backend access"
    );
}

#[test]
fn sqlite_settlement_binds_preview_subject_signature_and_current_clock() {
    let fixture = Fixture::new();
    let view = fixture.view();
    let digest = view.digest().unwrap();
    let proof = fixture.proof(&view);
    let mut wrong = copy_proof(&proof);
    wrong.preview = Some(Digest::of(&"other preview").unwrap());
    assert!(
        fixture
            .backend
            .confirm(view.attempt(), &digest, &human(), wrong, 6)
            .is_err()
    );
    let mut wrong = copy_proof(&proof);
    wrong.account = Digest::of(&"other account").unwrap().as_str().into();
    assert!(
        fixture
            .backend
            .confirm(view.attempt(), &digest, &human(), wrong, 6)
            .is_err()
    );
    let mut wrong = copy_proof(&proof);
    wrong.preview = None;
    assert!(
        fixture
            .backend
            .confirm(view.attempt(), &digest, &human(), wrong, 6)
            .is_err()
    );
    let successor = iap::Verified {
        subject: "accounts.google.com:successor".into(),
        ..human()
    };
    assert!(
        fixture
            .backend
            .confirm(view.attempt(), &digest, &successor, copy_proof(&proof), 6)
            .is_err()
    );
    fixture.clock.store(99, Ordering::SeqCst);
    assert!(
        fixture
            .backend
            .confirm(view.attempt(), &digest, &human(), copy_proof(&proof), 6)
            .is_err()
    );
    fixture.clock.store(100, Ordering::SeqCst);
    assert!(
        !fixture
            .backend
            .confirm(view.attempt(), &digest, &human(), copy_proof(&proof), 6)
            .unwrap(),
        "expiry is checked after key acquisition"
    );
    assert_eq!(
        fixture.state(),
        connect::ConnectState::AwaitingAccountApproval
    );
    fixture.clock.store(6, Ordering::SeqCst);
    assert!(
        fixture
            .backend
            .confirm(view.attempt(), &digest, &human(), copy_proof(&proof), 6)
            .unwrap()
    );
    assert!(matches!(
        fixture.state(),
        connect::ConnectState::Activated { generation: 1, .. }
    ));
    assert!(
        !fixture
            .backend
            .confirm(view.attempt(), &digest, &human(), proof, 6)
            .unwrap()
    );
}

#[test]
fn replacing_selection_before_confirmation_revokes_or_rebinds_pending_approval() {
    for rebind in [false, true] {
        let fixture = Fixture::new();
        let view = fixture.view();
        let proof = fixture.proof(&view);
        let entries = if rebind {
            let mut changed = fixtures::selected_approval(&fixture.facts);
            changed.instance.binding_namespace = "oauth_binding_successor".into();
            BTreeMap::from([(("app".into(), fixture.facts.intent.slot.clone()), changed)])
        } else {
            BTreeMap::new()
        };
        fixture.authority.replace(entries).unwrap();
        assert!(
            !fixture
                .backend
                .confirm(view.attempt(), &view.digest().unwrap(), &human(), proof, 6)
                .unwrap_or(false)
        );
        assert_eq!(
            fixture.state(),
            connect::ConnectState::AwaitingAccountApproval
        );
    }
}

struct BlockingKeys {
    paused: AtomicBool,
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}
impl ApprovalKeyProvider for BlockingKeys {
    fn load(
        &self,
        reference: &ApprovalKeyRef,
        purpose: ApprovalKeyPurpose,
    ) -> Result<ApprovalKeyMaterial> {
        if purpose == ApprovalKeyPurpose::ShellAttestation && self.paused.load(Ordering::SeqCst) {
            self.entered.send(())?;
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))?;
        }
        fixtures::TestApprovalKeys(0.into()).load(reference, purpose)
    }
}

#[test]
fn selection_replacement_waits_for_the_leased_sqlite_commit() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let keys = Arc::new(BlockingKeys {
        paused: AtomicBool::new(false),
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let fixture = Fixture::with_keys(keys.clone());
    let view = fixture.view();
    let proof = fixture.proof(&view);
    keys.paused.store(true, Ordering::SeqCst);
    let backend = fixture.backend.clone();
    let id = view.attempt().to_owned();
    let digest = view.digest().unwrap();
    let commit = thread::spawn(move || backend.confirm(&id, &digest, &human(), proof, 6));
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let authority = fixture.authority.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let replacement = thread::spawn(move || {
        started_tx.send(()).unwrap();
        authority.replace(BTreeMap::new()).unwrap();
        done_tx.send(()).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(matches!(
        done_rx.recv_timeout(Duration::from_millis(40)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    release_tx.send(()).unwrap();
    assert!(commit.join().unwrap().unwrap());
    replacement.join().unwrap();
    done_rx.recv().unwrap();
    assert!(matches!(
        fixture.state(),
        connect::ConnectState::Activated { generation: 1, .. }
    ));
    assert!(
        fixture
            .authority
            .current("app", &fixture.facts.intent, &fixture.facts.binding, 6)
            .unwrap()
            .is_none()
    );
}

#[test]
fn cancellation_while_keys_are_loading_cannot_activate_quarantined_tokens() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let keys = Arc::new(BlockingKeys {
        paused: AtomicBool::new(false),
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let fixture = Fixture::with_keys(keys.clone());
    let view = fixture.view();
    let proof = fixture.proof(&view);
    keys.paused.store(true, Ordering::SeqCst);
    let backend = fixture.backend.clone();
    let id = view.attempt().to_owned();
    let digest = view.digest().unwrap();
    let commit = thread::spawn(move || backend.confirm(&id, &digest, &human(), proof, 6));
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let mut db = crate::store::open(&fixture.path).unwrap();
    assert!(
        connect::cancel(&mut db, view.attempt(), |tx| {
            super::super::custody::delete_attempt_material(tx, view.attempt())
        })
        .unwrap()
    );
    release_tx.send(()).unwrap();
    assert!(!commit.join().unwrap().unwrap());
    assert_eq!(fixture.state(), connect::ConnectState::Cancelled);
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM oauth_connection_slots WHERE status='active'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}

#[derive(Default)]
struct Bearers(Mutex<Vec<(String, String)>>);
impl PrivateBearerSource for Bearers {
    fn bearer(&self, app: &str, receiver: &Url) -> Result<String> {
        self.0
            .lock()
            .unwrap()
            .push((app.into(), receiver.to_string()));
        Ok("fixture-IAP-service-token".into())
    }
}

fn remote(endpoint: Url, bearers: Arc<Bearers>) -> RemoteApprovals {
    let mut targets = BTreeMap::new();
    for app in ["app", "unavailable"] {
        targets.insert(
            app.into(),
            Target {
                origin: format!("https://{app}.example/"),
                endpoint: if app == "app" {
                    endpoint.clone()
                } else {
                    Url::parse("http://127.0.0.1:1/unavailable").unwrap()
                },
                authority: format!("{app}.example"),
                route: route_prefix("installation", "production", app).unwrap(),
            },
        );
    }
    RemoteApprovals {
        targets,
        client: Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        bearers,
        shell_origin: "https://security.example/".into(),
    }
}

struct WireRequest {
    method: Method,
    path: String,
    headers: HeaderMap,
    body: Vec<u8>,
}
fn read_request(stream: &mut TcpStream) -> WireRequest {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let parts: Vec<_> = line.split_whitespace().collect();
    let method = parts[0].parse().unwrap();
    let path = parts[1].into();
    let mut headers = HeaderMap::new();
    loop {
        line.clear();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" {
            break;
        }
        let (name, value) = line.trim_end().split_once(':').unwrap();
        headers.append(
            name.parse::<header::HeaderName>().unwrap(),
            value.trim().parse().unwrap(),
        );
    }
    let length = headers[header::CONTENT_LENGTH]
        .to_str()
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    WireRequest {
        method,
        path,
        headers,
        body,
    }
}

enum Reply {
    Json(Vec<u8>),
    Raw(Vec<u8>),
    Lost,
}
fn server(
    count: usize,
    mut handle: impl FnMut(WireRequest) -> Reply + Send + 'static,
) -> (Url, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = Url::parse(&format!(
        "http://{}{}",
        listener.local_addr().unwrap(),
        PATH
    ))
    .unwrap();
    let task = thread::spawn(move || {
        for _ in 0..count {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "fixture request timed out");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            let request = read_request(&mut stream);
            match handle(request) {
                Reply::Json(body) => {
                    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                    stream.write_all(&body).unwrap();
                }
                Reply::Raw(bytes) => stream.write_all(&bytes).unwrap(),
                Reply::Lost => (),
            }
        }
    });
    (endpoint, task)
}

struct RegistrationOnly;
impl AppApprovals for RegistrationOnly {
    fn app(&self) -> &str {
        "workspace"
    }
    fn lookup(&self, _: &str, _: &iap::Verified, _: i64) -> Result<HostLookup> {
        anyhow::bail!("registration must not resolve an app attempt")
    }
    fn confirm(
        &self,
        _: &str,
        _: &Digest,
        _: &iap::Verified,
        _: external::FreshExternalApproval,
        _: i64,
    ) -> Result<bool> {
        anyhow::bail!("registration must not settle an app attempt")
    }
}

struct NoLiveFacts;
impl crate::oauth::admission::OutboundReadiness for NoLiveFacts {
    fn current(
        &self,
        _: &day2_capabilities::oauth::OutboundConnectionBinding,
        _: &day2_capabilities::oauth::ConnectionSlotKey,
        _: i64,
    ) -> Result<Option<crate::oauth::profiles::OutboundInstanceEvidence>> {
        Ok(None)
    }
}

struct NativeRegistrationSink {
    authority: crate::oauth::admission::ArtifactApprovalAuthority,
    readiness: Arc<crate::oauth::registration::GoogleReadiness>,
    calls: Arc<AtomicUsize>,
}
impl RegistrationSink for NativeRegistrationSink {
    fn receive(
        &self,
        proof: &crate::oauth::registration::publication::Publication,
        app: &str,
        identity: &iap::Verified,
        now: i64,
    ) -> Result<()> {
        self.authority
            .receive_registration(proof, app, identity, &self.readiness, now)?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn native_registration_crosses_authenticated_http_once_even_when_response_is_lost() -> Result<()> {
    use crate::oauth::{
        admission,
        registration::{
            GoogleReadiness,
            publication::{self, tests as native},
        },
    };
    for lost in [false, true] {
        let (selected, receipt) = native::fixture()?;
        let proof = publication::attest(&receipt, &selected, &native::Keys::default(), now()?)?;
        let assertions = Assertions::new();
        let at = now()?;
        let mut human_headers = HeaderMap::new();
        human_headers.insert(
            iap::ASSERTION_HEADER,
            assertions
                .assertion_at(SHELL_AUDIENCE, HUMAN, &native::identity().subject, at)
                .parse()?,
        );
        human_headers.insert(header::COOKIE, "private-browser-cookie".parse()?);
        let readiness = Arc::new(GoogleReadiness::new(Arc::new(NoLiveFacts)));
        let calls = Arc::new(AtomicUsize::new(0));
        let authority = admission::ArtifactApprovalAuthority::with_keys(
            selected,
            readiness.clone(),
            Arc::new(native::Keys::default()),
        );
        let mut receiver = assertions.receiver(Arc::new(RegistrationOnly));
        receiver.registrations = Some(Arc::new(NativeRegistrationSink {
            authority,
            readiness,
            calls: calls.clone(),
        }));
        let workload_assertion = assertions.assertion_at(APP_AUDIENCE, MACHINE, "service-123", at);
        let (endpoint, worker) = server(1, move |mut request| {
            assert_eq!(
                request.headers[header::AUTHORIZATION],
                "Bearer fixture-IAP-service-token"
            );
            assert!(!request.headers.contains_key(header::COOKIE));
            let raw = String::from_utf8_lossy(&request.body);
            assert!(!raw.contains("private-browser-cookie"));
            for forbidden in [
                "private-fixture-client-canary",
                "private-fixture-code-canary",
                "private-fixture-access-canary",
                "private-fixture-refresh-canary",
            ] {
                assert!(!raw.contains(forbidden));
            }
            request
                .headers
                .insert(iap::ASSERTION_HEADER, workload_assertion.parse().unwrap());
            let response = receiver
                .dispatch(
                    &request.method,
                    &request.path,
                    None,
                    &request.headers,
                    &request.body,
                    now().unwrap(),
                )
                .unwrap();
            if lost {
                Reply::Lost
            } else {
                Reply::Json(response)
            }
        });
        let bearers = Arc::new(Bearers::default());
        let mut client = remote(endpoint, bearers.clone());
        let target = client.targets.remove("app").unwrap();
        client.targets.insert("workspace".into(), target);
        assert_eq!(
            client.publish_registration(proof, &human_headers).is_err(),
            lost
        );
        worker.join().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            bearers.0.lock().unwrap().as_slice(),
            &[("workspace".into(), format!("https://app.example{PATH}"))]
        );
    }
    Ok(())
}

#[test]
fn registration_receiver_refuses_human_workload_substitution_and_wrong_app_before_import()
-> Result<()> {
    use crate::oauth::registration::publication::{self, tests as native};
    let (selected, receipt) = native::fixture()?;
    let proof = publication::attest(&receipt, &selected, &native::Keys::default(), now()?)?;
    let assertions = Assertions::new();
    let receiver = assertions.receiver(Arc::new(RegistrationOnly));
    let at = now()?;
    let request = RequestBody::Registration {
        version: VERSION,
        human_assertion: assertions.assertion_at(
            SHELL_AUDIENCE,
            HUMAN,
            &native::identity().subject,
            at,
        ),
        proof: Box::new(proof),
    };
    let bytes = serde_json::to_vec(&request)?;
    let mut headers = assertions.headers();
    headers.insert(
        iap::ASSERTION_HEADER,
        assertions
            .assertion_at(APP_AUDIENCE, HUMAN, SUBJECT, at)
            .parse()?,
    );
    assert!(
        receiver
            .dispatch(&Method::POST, PATH, None, &headers, &bytes, at)
            .is_err()
    );
    headers.insert(
        iap::ASSERTION_HEADER,
        assertions
            .assertion_at(SHELL_AUDIENCE, MACHINE, "service-123", at)
            .parse()?,
    );
    assert!(
        receiver
            .dispatch(&Method::POST, PATH, None, &headers, &bytes, at)
            .is_err()
    );
    headers.insert(
        iap::ASSERTION_HEADER,
        assertions
            .assertion_at(APP_AUDIENCE, MACHINE, "service-123", at)
            .parse()?,
    );
    // A receiver without its native registration composition fails closed.
    assert!(
        receiver
            .dispatch(&Method::POST, PATH, None, &headers, &bytes, at)
            .is_err()
    );
    let mut wrong = serde_json::from_slice::<serde_json::Value>(&bytes)?;
    wrong["proof"]["claim"]["app"] = json!("other_app");
    assert!(
        receiver
            .dispatch(
                &Method::POST,
                PATH,
                None,
                &headers,
                &serde_json::to_vec(&wrong)?,
                at
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn private_http_round_trip_activates_own_sqlite_once_without_forwarding_browser_or_custody_secrets()
{
    for lose_response in [false, true] {
        let fixture = Fixture::new();
        let assertions = Assertions::new();
        let human_headers = assertions.human_headers();
        let receiver = assertions.receiver(fixture.backend.clone());
        let workload = assertions.assertion(APP_AUDIENCE, MACHINE, "service-123");
        let requests = Arc::new(AtomicUsize::new(0));
        let calls = requests.clone();
        let count = if lose_response { 2 } else { 3 };
        let (endpoint, task) = server(count, move |mut request| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                request.headers[header::AUTHORIZATION],
                "Bearer fixture-IAP-service-token"
            );
            assert!(!request.headers.contains_key(header::COOKIE));
            assert!(!request.headers.contains_key(iap::ASSERTION_HEADER));
            let wire = std::str::from_utf8(&request.body).unwrap();
            for secret in [
                "secret_external_access",
                "browser-private-cookie",
                "app.sqlite",
                "code_ref",
                "custody_key",
                "verifier",
                "client_secret",
            ] {
                assert!(!wire.contains(secret), "leaked {secret}");
            }
            // Simulate IAP: strip Authorization and inject its signed workload
            // assertion. The receiver still independently verifies both JWTs.
            request.headers.remove(header::AUTHORIZATION);
            request
                .headers
                .insert(iap::ASSERTION_HEADER, workload.parse().unwrap());
            let response = receiver
                .dispatch(
                    &request.method,
                    &request.path,
                    None,
                    &request.headers,
                    &request.body,
                    6,
                )
                .unwrap();
            assert!(
                !std::str::from_utf8(&response)
                    .unwrap()
                    .contains("secret_external_access")
            );
            if lose_response && n == 1 {
                Reply::Lost
            } else {
                Reply::Json(response)
            }
        });
        let bearers = Arc::new(Bearers::default());
        let remote = remote(endpoint, bearers.clone());
        assert!(
            remote
                .pending(
                    &scoped_attempt("other", "production", "app").unwrap(),
                    &human(),
                    &human_headers,
                    6
                )
                .unwrap()
                .is_none()
        );
        assert!(bearers.0.lock().unwrap().is_empty());
        let view = remote
            .pending(&fixture.facts.intent.attempt, &human(), &human_headers, 6)
            .unwrap()
            .unwrap();
        let proof = fixture.proof(&view);
        let result = remote.confirm(&view, &human(), &human_headers, copy_proof(&proof), 6);
        if lose_response {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap());
            assert!(
                !remote
                    .confirm(&view, &human(), &human_headers, proof, 6)
                    .unwrap()
            );
        }
        task.join().unwrap();
        assert_eq!(requests.load(Ordering::SeqCst), count);
        assert!(matches!(
            fixture.state(),
            connect::ConnectState::Activated { generation: 1, .. }
        ));
        assert!(
            bearers
                .0
                .lock()
                .unwrap()
                .iter()
                .all(|(app, url)| app == "app" && url == "https://app.example/_day2/oauth/approval"),
            "no fanout to the unavailable app"
        );
    }
}

#[test]
fn remote_rejects_wrong_receiver_response_and_never_follows_redirects() {
    let assertions = Assertions::new();
    let id = scoped_attempt("installation", "production", "app").unwrap();
    for response in [
        json!({"operation":"lookup","version":1,"app":"other","attempt":id,"owned":false,"view":null}),
        json!({"operation":"lookup","version":2,"app":"app","attempt":id,"owned":false,"view":null}),
        json!({"operation":"lookup","version":1,"app":"app","attempt":"other","owned":false,"view":null}),
        json!({"operation":"confirm","version":1,"app":"app","attempt":id,"approved":true}),
        json!({"operation":"lookup","version":1,"app":"app","attempt":id,"owned":false,"view":null,"extra":true}),
    ] {
        let (endpoint, task) = server(1, move |_| {
            Reply::Json(serde_json::to_vec(&response).unwrap())
        });
        assert!(
            remote(endpoint, Arc::new(Bearers::default()))
                .pending(&id, &human(), &assertions.human_headers(), 6)
                .is_err()
        );
        task.join().unwrap();
    }
    for raw in [
        b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/leak\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", MAX_RESPONSE + 1).into_bytes(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
    ] {
        let (endpoint, task) = server(1, move |_| Reply::Raw(raw.clone()));
        assert!(remote(endpoint, Arc::new(Bearers::default())).pending(&id, &human(), &assertions.human_headers(), 6).is_err()); task.join().unwrap();
    }
    let (endpoint, task) = server(1, |_| Reply::Json(br#"{"version":1,"version":1}"#.to_vec()));
    assert!(
        remote(endpoint, Arc::new(Bearers::default()))
            .pending(&id, &human(), &assertions.human_headers(), 6)
            .is_err()
    );
    task.join().unwrap();
}

#[test]
fn instance_transport_is_optional_and_selects_exact_app_and_shell_audiences() {
    let mut instance = fixtures::selected_instance();
    let fixture = Fixture::new();
    assert!(AppApprovalReceiver::from_instance(&instance, fixture.backend.clone()).is_err());
    for email in [
        MACHINE,
        "human@example.com",
        "security@evil.example",
        "security@company.iam.gserviceaccount.com@other",
    ] {
        let transport = day2_capabilities::oauth::ShellTransport {
            service_account: email.into(),
        };
        assert_eq!(transport.validate().is_ok(), email == MACHINE);
    }
    instance.oauth_shell_transport = Some(day2_capabilities::oauth::ShellTransport {
        service_account: MACHINE.into(),
    });
    let roundtrip = Instance::from_bytes(&serde_json::to_vec(&instance).unwrap()).unwrap();
    assert_eq!(
        roundtrip.oauth_shell_transport,
        instance.oauth_shell_transport
    );
    let receiver = AppApprovalReceiver::from_instance(&roundtrip, fixture.backend.clone()).unwrap();
    assert_eq!(receiver.authority, "app.example");
    assert_eq!(
        receiver.route,
        route_prefix("installation", "production", "app").unwrap()
    );
    let mut unknown = serde_json::to_value(&roundtrip).unwrap();
    unknown["oauth_shell_transport"]["extra"] = json!(true);
    assert!(Instance::from_bytes(&serde_json::to_vec(&unknown).unwrap()).is_err());
}

#[test]
fn app_host_mounts_reserved_receiver_before_human_dispatch_and_drains_admission() -> Result<()> {
    // The HTTP edge verifies real-time assertions; the durable kernel fixture
    // retains its independently controlled clock and synthetic readiness facts.
    struct AtSix(Arc<StoredAppApprovals>);
    impl AppApprovals for AtSix {
        fn app(&self) -> &str {
            self.0.app()
        }
        fn lookup(&self, attempt: &str, identity: &iap::Verified, _: i64) -> Result<HostLookup> {
            self.0.lookup(attempt, identity, 6)
        }
        fn confirm(
            &self,
            attempt: &str,
            view: &Digest,
            identity: &iap::Verified,
            proof: external::FreshExternalApproval,
            _: i64,
        ) -> Result<bool> {
            self.0.confirm(attempt, view, identity, proof, 6)
        }
    }
    let fixture = Fixture::new();
    let assertions = Assertions::new();
    let instance = fixtures::selected_instance();
    let instance_path = fixture._directory.path().join("instance.json");
    std::fs::write(&instance_path, serde_json::to_vec(&instance)?)?;
    let mut contract: crate::artifact::Artifact = serde_json::from_value(json!({
        "format":crate::artifact::CURRENT_FORMAT,"namespace":"app","roc_version":"fixture",
        "worker_digest":"fixture","schema_digest":"fixture","sources":{},"admission":"local-spike-only",
        "schema":{"models":{"items":{"fields":{"value":"text"},"roc_type":"Item"}},"inputs":{"input":{"fields":{}}},"foreign_keys":[]},
        "properties":["items"],
        "outputs":{"output":{"shape":{"record":{}},"roc_type":"{}"}},
        "operations":[{"name":"app.preview","kind":"query","input_type":"input","output_type":"output"}],
        "app_contract":{"operations":{"app.preview":{
            "intent":{"target":{"operation":"app.preview","input_type":"input","output_type":"output"},
                "title":"Preview","usage":{"purpose":"Host routing conformance","use_when":["Inspect the host fixture"],"avoid_when":["Serving live business data"],"preconditions":["Admitted host fixture"],"effects":[],"result":"Checked result"},"input_sources":[],"follow_ups":[]},
            "request_example":"{}","response_example":"{}","deprecated":false,
            "execution":{"model":"","id_field":"","version_field":"","effects":[]},"errors":[]
        }},"presentation":{"stylesheet":"","script":""},"identities":crate::identity::REGISTRY_FILE,"invariants":{"items":"Host route fixture state"},"domains":{},"errors":{}}
    }))?;
    contract.identities.synchronize(&contract.schema.models)?;
    contract.schema.bind_identities(&contract.identities)?;
    contract.api_docs = contract.app_contract.as_ref().unwrap().documentation();
    contract.operation_metadata = contract.app_contract.as_ref().unwrap().intents();
    let artifact = crate::artifact::LoadedArtifact::from_contract_for_tests(
        crate::digest(b"host-route-fixture"),
        fixture._directory.path().into(),
        contract,
    );
    let runtime = crate::store::Runtime::from_artifact_for_tests(
        instance_path,
        "app".into(),
        fixture.path.clone(),
        artifact,
    )?;
    let receiver = Arc::new(assertions.receiver(Arc::new(AtSix(fixture.backend.clone()))));
    let verifier = iap::Verifier::new(
        APP_AUDIENCE,
        "example.com",
        Box::new(Keys(assertions.keys.clone())),
    )?;
    let edge = instance.apps["app"].edge.as_ref().unwrap().clone();
    let (origin_tx, origin_rx) = mpsc::sync_channel(1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let task = thread::spawn(move || -> Result<()> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?
            .block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                let origin = format!("http://{}", listener.local_addr()?);
                let mut server = crate::web::LocalServer::bind_edge_listener(
                    runtime, listener, &edge, verifier, 1,
                )?;
                server.mount_oauth(receiver)?;
                origin_tx.send((origin, server.admission())).unwrap();
                server
                    .serve(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            })
    });
    let (origin, admission) = match origin_rx.recv() {
        Ok(bound) => bound,
        Err(error) => {
            task.join().expect("app host fixture panicked")?;
            return Err(error.into());
        }
    };
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?;
    let at = now()?;
    let workload = assertions.assertion_at(APP_AUDIENCE, MACHINE, "service-123", at);
    let human = assertions.assertion_at(SHELL_AUDIENCE, HUMAN, SUBJECT, at);
    let body = serde_json::to_vec(&RequestBody::Lookup {
        version: VERSION,
        attempt: fixture.facts.intent.attempt.clone(),
        human_assertion: human,
    })?;
    let request = || {
        client
            .post(format!("{origin}{PATH}"))
            .header(header::HOST, "app.example")
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.clone())
    };
    assert_eq!(request().send()?.status(), StatusCode::FORBIDDEN);
    let response = request().header(iap::ASSERTION_HEADER, &workload).send()?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    let result: ResponseBody = crate::json::decode(&response.bytes()?)?;
    assert!(matches!(
        result,
        ResponseBody::Lookup {
            owned: true,
            view: Some(_),
            ..
        }
    ));
    let response = client
        .get(format!("{origin}/"))
        .header(header::HOST, "app.example")
        .header(iap::ASSERTION_HEADER, &workload)
        .send()?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    admission.stop();
    assert_eq!(
        request()
            .header(iap::ASSERTION_HEADER, workload)
            .send()?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        client
            .get(format!("{origin}/health/ready"))
            .send()?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let _ = shutdown_tx.send(());
    task.join().expect("app host fixture panicked")?;
    Ok(())
}
