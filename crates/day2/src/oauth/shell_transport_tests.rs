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

// The owned Google campaign below exercises this same private receiver and
// SQLite writer. It emulates the IAP edge and Google/Secret Manager inputs; it
// cannot establish hosted IAM, native lifetime, enrollment or live readiness.

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
            management: None,
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
        Self::with_directory_and_keys(tempfile::tempdir().unwrap(), keys)
    }

    fn with_directory_and_keys(
        directory: tempfile::TempDir,
        keys: Arc<dyn ApprovalKeyProvider>,
    ) -> Self {
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
            .attest_fixture_view(
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
fn production_approval_backend_refuses_authenticated_unsupported_routes_without_changing_rows()
-> Result<()> {
    let fixture = Fixture::new();
    let view = fixture.view();
    let assertions = Assertions::new();
    let receiver = assertions.receiver(Arc::new(
        crate::oauth::approval_registry::UnavailableAppApprovals::new("app".into())?,
    ));
    let original = crate::oauth::fresh_auth::FreshIntent::approval(&view, &human())?;
    let call = crate::oauth::fresh_owner::CallData::claim(&original, Digest::of(&"owner")?)?;
    let human_assertion = assertions.assertion(SHELL_AUDIENCE, HUMAN, SUBJECT);
    let before = crate::oauth::simulation::snapshot(&crate::store::open(&fixture.path)?)?;
    for request in [
        RequestBody::Lookup {
            version: VERSION,
            attempt: view.attempt().into(),
            human_assertion: human_assertion.clone(),
        },
        RequestBody::Confirm {
            version: VERSION,
            attempt: view.attempt().into(),
            human_assertion: human_assertion.clone(),
            view: view.digest()?,
            evidence: Box::new(fixture.proof(&view)),
        },
        RequestBody::FreshOwner {
            version: VERSION,
            human_assertion,
            call: Box::new(call),
        },
    ] {
        let refused = receiver
            .dispatch(
                &Method::POST,
                PATH,
                None,
                &assertions.headers(),
                &serde_json::to_vec(&request)?,
                6,
            )
            .err()
            .context("unsupported approval route unexpectedly succeeded")?;
        assert_eq!(refused.to_string(), "OAuth approval purpose unavailable");
        assert_eq!(
            crate::oauth::simulation::snapshot(&crate::store::open(&fixture.path)?)?,
            before,
        );
    }
    Ok(())
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
fn actual_pending_expiry_is_required_and_cannot_be_replaced_by_a_shell_lifetime() -> Result<()> {
    let fixture = Fixture::new();
    let view = fixture.view();
    assert_eq!(view.expires_at, fixture.facts.intent.expires_at);
    let original = crate::oauth::fresh_auth::FreshIntent::approval(&view, &human())?;
    assert_eq!(original.deadline(), fixture.facts.intent.expires_at);
    let bytes = serde_json::to_vec(&view)?;
    let decoded: ApprovalView = crate::json::decode(&bytes)?;
    assert_eq!(decoded.expires_at, fixture.facts.intent.expires_at);
    let mut absent: serde_json::Value = crate::json::decode(&bytes)?;
    absent.as_object_mut().unwrap().remove("expires_at");
    assert!(crate::json::decode::<ApprovalView>(&serde_json::to_vec(&absent)?).is_err());
    for deadline in [view.claim.quarantined_at, -1, i64::MAX] {
        let mut changed = view.clone();
        changed.expires_at = deadline;
        assert!(changed.validate(&human()).is_err());
    }
    let mut changed = view.clone();
    changed.expires_at -= 1;
    changed.validate(&human())?;
    assert_ne!(changed.digest()?, view.digest()?);
    assert!(original != crate::oauth::fresh_auth::FreshIntent::approval(&changed, &human())?);
    assert_eq!(
        fixture.state(),
        connect::ConnectState::AwaitingAccountApproval
    );
    Ok(())
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

#[test]
fn private_transport_replays_response_loss_and_receiver_substitution() -> Result<()> {
    use crate::oauth::{effects, simulation::World};
    for seed in 0..8 {
        for scenario in 0..4 {
            let run = || -> Result<_> {
                let world = World::new(seed);
                effects::scope(world.clone(), || {
                    let id = scoped_attempt("installation", "production", "app")?;
                    let body = json!({"operation":"lookup","version":1,"app":if scenario == 2 { "other" } else { "app" },
                        "attempt":id,"owned":false,"view":null});
                    world.script(
                        vec![(if scenario == 3 { 302 } else { 200 }, body.to_string())],
                        (scenario == 1).then_some(0),
                    );
                    let bearers = Arc::new(Bearers::default());
                    let remote = remote(
                        Url::parse("https://app.example/_day2/oauth/approval")?,
                        bearers.clone(),
                    );
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        iap::ASSERTION_HEADER,
                        HeaderValue::from_static("simulated-private-human-assertion"),
                    );
                    let response = remote.pending(&id, &human(), &headers, effects::wall_time()?);
                    assert_eq!(response.is_ok(), scenario == 0);
                    assert_eq!(
                        world.requests().len(),
                        1,
                        "ambiguous transport must not retry"
                    );
                    assert_eq!(
                        bearers.0.lock().unwrap().as_slice(),
                        &[(
                            "app".into(),
                            "https://app.example/_day2/oauth/approval".into()
                        )]
                    );
                    assert!(
                        remote
                            .pending("unrouted-attempt", &human(), &headers, 5)?
                            .is_none()
                    );
                    assert_eq!(
                        world.requests().len(),
                        1,
                        "unselected route must not fan out"
                    );
                    Ok((id, response.is_ok(), world.requests()))
                })
            };
            assert_eq!(run()?, run()?);
        }
    }
    Ok(())
}

struct WireRequest {
    method: Method,
    path: String,
    headers: HeaderMap,
    body: Vec<u8>,
}
fn read_request(stream: &mut TcpStream) -> WireRequest {
    // macOS accepts peers in the nonblocking listener's mode.
    stream.set_nonblocking(false).unwrap();
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

#[test]
fn accepted_fixture_socket_waits_for_request_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_nonblocking(true).unwrap();
    let (started, ready) = std::sync::mpsc::channel();
    let (sent, received) = std::sync::mpsc::channel();
    let reader = thread::spawn(move || {
        started.send(()).unwrap();
        sent.send(read_request(&mut peer)).unwrap();
    });
    ready.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(matches!(
        received.recv_timeout(Duration::from_millis(25)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    write!(
        client,
        "POST {PATH} HTTP/1.1\r\nContent-Length: 2\r\n\r\n{{}}"
    )
    .unwrap();
    let request = received.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(request.method, Method::POST);
    assert_eq!(request.path, PATH);
    assert_eq!(request.body, b"{}");
    reader.join().unwrap();
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

struct NoLiveFacts;
impl crate::oauth::admission::OutboundReadiness for NoLiveFacts {
    fn current(
        &self,
        _: &day2_capabilities::oauth::OutboundConnectionBinding,
        _: &day2_capabilities::oauth::ConnectionSlotKey,
        _: i64,
        _: &mut crate::oauth::admission::SubjectReader<'_, '_, '_, '_>,
    ) -> Result<Option<crate::oauth::profiles::OutboundInstanceEvidence>> {
        Ok(None)
    }
}

struct NativeRegistrationSink {
    authority: crate::oauth::admission::ArtifactApprovalAuthority,
    readiness: Arc<crate::oauth::registration::ProviderReadiness>,
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
            ProviderReadiness,
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
        let readiness = Arc::new(ProviderReadiness::new(Arc::new(NoLiveFacts)));
        let calls = Arc::new(AtomicUsize::new(0));
        let authority = admission::ArtifactApprovalAuthority::with_keys(
            selected,
            readiness.clone(),
            Arc::new(native::Keys::default()),
        );
        let mut receiver = assertions.receiver(Arc::new(
            crate::oauth::approval_registry::UnavailableAppApprovals::new("workspace".into())?,
        ));
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
fn mounted_management_authenticates_both_callers_and_lost_confirmation_is_not_regranted()
-> Result<()> {
    use crate::oauth::{
        admission,
        fresh_auth::{FreshIntent, VerifiedAuthTime},
        management::{
            Action,
            app::{Call, Manager, Reply as ManagementReply},
        },
        shell_oidc, simulation,
    };
    struct Port {
        at: AtomicI64,
        entropy: AtomicUsize,
        sends: AtomicUsize,
    }
    impl effects::Hooks for Port {
        fn provider_observation(
            &self,
            _: crate::oauth::shell_oidc::ProviderObservationData,
        ) -> Result<()> {
            anyhow::bail!("unscripted provider observation")
        }

        fn domain(&self) -> u64 {
            97833
        }
        fn wall_time(&self) -> Result<i64> {
            Ok(self.at.load(Ordering::SeqCst))
        }
        fn monotonic(&self) -> Duration {
            Duration::from_secs(self.at.load(Ordering::SeqCst) as u64)
        }
        fn fill(&self, bytes: &mut [u8]) -> Result<()> {
            let value = self.entropy.fetch_add(1, Ordering::SeqCst);
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = value.wrapping_add(index) as u8;
            }
            Ok(())
        }
        fn send(&self, _: reqwest::blocking::Request) -> Result<effects::Response> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("mounted management fixture forbids external HTTP")
        }
    }
    let directory = tempfile::tempdir()?;
    let (runtime, authority, signer) = admission::tests::management_fixture(directory.path())?;
    let database = runtime.db().to_path_buf();
    let instance = Instance::load(runtime.instance_path())?;
    let route = route_prefix(&instance.installation, &instance.environment, runtime.app())?;
    let manager = Arc::new(Manager::new(runtime, authority));
    let assertions = Assertions::new();
    let identity = iap::Verified {
        email: "alice@example.com".into(),
        subject: "accounts.google.com:alice".into(),
    };
    let claims = json!({"iss":"https://cloud.google.com/iap", "aud":SHELL_AUDIENCE,
        "email":identity.email,"sub":identity.subject,"hd":"example.com","iat":0,"exp":600});
    let signed = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(json!({"kid":"fixture","alg":"ES256"}).to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = assertions
        .pair
        .sign(&SystemRandom::new(), signed.as_bytes())
        .unwrap();
    let human_assertion = format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()));
    let mut receiver = assertions.receiver(Arc::new(
        crate::oauth::approval_registry::UnavailableAppApprovals::new("workspace".into())?,
    ));
    receiver.route = route;
    let receiver = Arc::new(receiver).with_management(manager)?;
    let port = Arc::new(Port {
        at: AtomicI64::new(100),
        entropy: AtomicUsize::new(1),
        sends: AtomicUsize::new(0),
    });
    let executor = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?;
    let listener = executor.block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))?;
    let endpoint = format!("http://{}{PATH}", listener.local_addr()?);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving_port = port.clone();
    let server = executor.spawn(effects::scope_async(
        serving_port,
        crate::oauth::native_http::serve(
            crate::oauth::native_http::Endpoint::Receiver(receiver),
            listener,
            1,
            Arc::new(AtomicBool::new(true)),
            async {
                let _ = stopped.await;
            },
        ),
    ));
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()?;
    let invoke = |headers: HeaderMap, body: Vec<u8>| -> Result<(StatusCode, Vec<u8>)> {
        let response = client.post(&endpoint).headers(headers).body(body).send()?;
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let status = response.status();
        Ok((status, response.bytes()?.to_vec()))
    };
    let encode = |call| {
        serde_json::to_vec(&RequestBody::Management {
            version: VERSION,
            human_assertion: human_assertion.clone(),
            call: Box::new(call),
        })
    };
    let capture = encode(Call::Capture {
        registration: "calendar".into(),
        operation: Action::Connect,
    })?;
    let snapshot = || simulation::snapshot(&crate::store::open(&database)?);
    let initial = snapshot()?;
    let mut no_workload = assertions.headers();
    no_workload.remove(iap::ASSERTION_HEADER);
    let mut human_as_workload = assertions.headers();
    human_as_workload.insert(iap::ASSERTION_HEADER, human_assertion.parse()?);
    let mut duplicate_workload = assertions.headers();
    duplicate_workload.append(iap::ASSERTION_HEADER, human_assertion.parse()?);
    for headers in [no_workload, human_as_workload, duplicate_workload] {
        assert_eq!(invoke(headers, capture.clone())?.0, StatusCode::FORBIDDEN);
        assert_eq!(snapshot()?, initial);
    }
    let mut wrong_human: serde_json::Value = serde_json::from_slice(&capture)?;
    wrong_human["human_assertion"] =
        json!(assertions.assertion(SHELL_AUDIENCE, MACHINE, "service-123"));
    let mut extra: serde_json::Value = serde_json::from_slice(&capture)?;
    extra["call"]["actor"] = json!("alice@example.com");
    let mut tampered: serde_json::Value = serde_json::from_slice(&capture)?;
    tampered["human_assertion"] = json!(format!("{human_assertion}tampered"));
    for body in [wrong_human, extra, tampered] {
        let (status, bytes) = invoke(assertions.headers(), serde_json::to_vec(&body)?)?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(bytes.is_empty());
        assert_eq!(snapshot()?, initial);
    }
    let (status, body) = invoke(assertions.headers(), capture)?;
    assert_eq!(status, StatusCode::OK);
    for forbidden in [
        "fixture-client-secret",
        "private-access-token",
        "private-refresh-token",
        "code_verifier",
    ] {
        assert!(!String::from_utf8_lossy(&body).contains(forbidden));
    }
    let ResponseBody::Management {
        version: VERSION,
        app,
        reply,
    } = crate::json::decode(&body)?
    else {
        anyhow::bail!("mounted capture response changed");
    };
    assert_eq!(app, "workspace");
    let ManagementReply::Pending { view } = *reply else {
        anyhow::bail!("mounted pending missing");
    };
    assert_eq!(view.human, identity.email);
    assert_eq!(view.subject, identity.subject);
    // The real authenticated receiver resolves this exact app-owned Pending.
    // Response loss can reconcile the one allocation but cannot allocate a
    // replacement owner, change purpose, or publish a different request.
    let original = FreshIntent::management(&view, &identity)?;
    let owner = Digest::new(b"one original native shell incarnation");
    let claim = crate::oauth::fresh_owner::CallData::claim(&original, owner.clone())?;
    let owner_body = |call: crate::oauth::fresh_owner::CallData| -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&RequestBody::FreshOwner {
            version: VERSION,
            human_assertion: human_assertion.clone(),
            call: Box::new(call),
        })?)
    };
    let before_claim = snapshot()?;
    let mut missing_workload = assertions.headers();
    missing_workload.remove(iap::ASSERTION_HEADER);
    assert_eq!(
        invoke(missing_workload, owner_body(claim.clone())?)?.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(snapshot()?, before_claim);
    let claim_bytes = owner_body(claim.clone())?;
    let mut changed_purpose: serde_json::Value = crate::json::decode(&claim_bytes)?;
    changed_purpose["call"]["purpose"] =
        serde_json::to_value(crate::oauth::fresh_owner::PurposeData::OAuthDisconnect)?;
    let mut changed_original: serde_json::Value = crate::json::decode(&claim_bytes)?;
    changed_original["call"]["original"] = json!(Digest::new(b"different original pending"));
    let mut browser_database: serde_json::Value = crate::json::decode(&claim_bytes)?;
    browser_database["call"]["database"] = json!("/tmp/selected-by-browser.sqlite");
    let mut nested_database: serde_json::Value = crate::json::decode(&claim_bytes)?;
    nested_database["call"]["operation"]["database"] = json!("/tmp/nested-ignored-field");
    let mut array_claim: serde_json::Value = crate::json::decode(&claim_bytes)?;
    array_claim["call"]["operation"] = json!(["claim"]);
    let mut array_fields: serde_json::Value = crate::json::decode(&claim_bytes)?;
    array_fields["call"]["operation"] = json!(["claim", {}]);
    for tampered in [
        changed_purpose,
        changed_original,
        browser_database,
        nested_database,
        array_claim,
        array_fields,
    ] {
        assert_eq!(
            invoke(assertions.headers(), serde_json::to_vec(&tampered)?)?.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(snapshot()?, before_claim);
        assert_eq!(
            crate::store::open(&database)?.query_row(
                "SELECT count(*) FROM native_fresh_owners",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
    }
    let (status, bytes) = invoke(assertions.headers(), claim_bytes.clone())?;
    assert_eq!(status, StatusCode::OK);
    let ResponseBody::FreshOwner {
        reply,
        app,
        version: VERSION,
    } = crate::json::decode(&bytes)?
    else {
        anyhow::bail!("native fresh allocation response changed");
    };
    assert_eq!(app, "workspace");
    reply.require_call(&claim, &original)?;
    assert!(matches!(
        reply.outcome,
        crate::oauth::fresh_owner::OutcomeData::Allocation {
            state: crate::oauth::fresh_owner::AllocationData::Allocated,
        }
    ));
    let committed_owner = snapshot()?;
    drop(bytes); // Lost reply: retry exactly the same owner and original.
    let (status, bytes) = invoke(assertions.headers(), claim_bytes)?;
    assert_eq!(status, StatusCode::OK);
    let ResponseBody::FreshOwner { reply, .. } = crate::json::decode(&bytes)? else {
        anyhow::bail!("native fresh reconciliation response changed");
    };
    reply.require_call(&claim, &original)?;
    assert!(matches!(
        reply.outcome,
        crate::oauth::fresh_owner::OutcomeData::Allocation {
            state: crate::oauth::fresh_owner::AllocationData::ExistingOwner,
        }
    ));
    assert_eq!(snapshot()?, committed_owner);
    let replacement =
        crate::oauth::fresh_owner::CallData::claim(&original, Digest::new(b"restarted shell"))?;
    let (status, bytes) = invoke(assertions.headers(), owner_body(replacement)?)?;
    assert_eq!(status, StatusCode::OK);
    let ResponseBody::FreshOwner { reply, .. } = crate::json::decode(&bytes)? else {
        anyhow::bail!("native fresh second owner response changed");
    };
    assert!(matches!(
        reply.outcome,
        crate::oauth::fresh_owner::OutcomeData::Allocation {
            state: crate::oauth::fresh_owner::AllocationData::OtherOwner,
        }
    ));
    assert_eq!(snapshot()?, committed_owner);
    let pending = snapshot()?;
    port.at.store(102, Ordering::SeqCst);
    let proof = effects::scope(port.clone(), || -> Result<_> {
        crate::oauth::native_management::reserve_shell(
            &FreshIntent::management(&view, &identity)?,
            102,
        )?;
        let fresh = VerifiedAuthTime::from_google(shell_oidc::Reauthenticated::fixture(
            FreshIntent::management(&view, &identity)?,
            identity.email.clone(),
            identity.subject.clone(),
            101,
        ));
        signer.attest_management(
            &view,
            &fresh,
            &identity,
            Digest::new(b"native-browser-session"),
            102,
        )
    })?;
    let confirm = encode(Call::Confirm {
        id: view.id.clone(),
        proof,
    })?;
    let mut forged: serde_json::Value = serde_json::from_slice(&confirm)?;
    forged["call"]["proof"]["session"] = json!(Digest::new(b"other-browser"));
    assert_eq!(
        invoke(assertions.headers(), serde_json::to_vec(&forged)?)?.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(snapshot()?, pending);
    // Discard the successful HTTP response, as a caller with a lost reply does.
    // The retry still traverses body admission, both JWT verifiers and SQLite.
    let (status, completed) = invoke(assertions.headers(), confirm.clone())?;
    assert_eq!(status, StatusCode::OK);
    for forbidden in [
        "fixture-client-secret",
        "private-access-token",
        "private-refresh-token",
        "code_verifier",
    ] {
        assert!(!String::from_utf8_lossy(&completed).contains(forbidden));
    }
    let ResponseBody::Management { reply, .. } = crate::json::decode(&completed)? else {
        anyhow::bail!("mounted confirmation response changed");
    };
    assert!(matches!(*reply, ManagementReply::Redirect { .. }));
    drop(completed);
    let committed = snapshot()?;
    assert_ne!(committed, pending);
    assert_eq!(
        invoke(assertions.headers(), confirm)?.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(snapshot()?, committed);
    let db = crate::store::open(&database)?;
    assert_eq!(
        connect::state(&db, &view.id)?,
        Some(connect::ConnectState::AwaitingProviderAuthorization)
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM oauth_connect_attempts", [], |row| row
            .get::<_, i64>(0))?,
        1
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM oauth_connection_slots", [], |row| row
            .get::<_, i64>(0))?,
        0
    );
    assert_eq!(port.sends.load(Ordering::SeqCst), 0);
    stop.send(()).unwrap();
    executor.block_on(server)??;
    Ok(())
}

#[test]
fn registration_receiver_refuses_human_workload_substitution_and_wrong_app_before_import()
-> Result<()> {
    use crate::oauth::registration::publication::{self, tests as native};
    let (selected, receipt) = native::fixture()?;
    let proof = publication::attest(&receipt, &selected, &native::Keys::default(), now()?)?;
    let assertions = Assertions::new();
    let receiver = assertions.receiver(Arc::new(
        crate::oauth::approval_registry::UnavailableAppApprovals::new("workspace".into())?,
    ));
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
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("app.sqlite");
    let assertions = Assertions::new();
    let instance = fixtures::selected_instance();
    let instance_path = directory.path().join("instance.json");
    std::fs::write(&instance_path, serde_json::to_vec(&instance)?)?;
    let mut contract: crate::artifact::Artifact = serde_json::from_value(json!({
        "format":crate::artifact::CURRENT_FORMAT,"verification_limits":crate::artifact::VerificationLimits::QUALIFIED,"namespace":"app","roc_version":"fixture",
        "worker_digest":"fixture","schema_digest":"fixture","sources":{},"admission":"local-spike-only",
        "schema":{"models":{"items":{"fields":{"value":"text"},"roc_type":"Item"}},"inputs":{"input":{"fields":{}}},"foreign_keys":[]},
        "properties":["items"],
        "outputs":{"output":{"shape":{"record":{}},"roc_type":"{}"}},
        "operations":[{"name":"app.preview","kind":"query","input_type":"input","output_type":"output"}],
        "app_contract":{"operations":{"app.preview":{
            "intent":{"target":{"operation":"app.preview","input_type":"input","output_type":"output"},
                "title":"Preview","usage":{"purpose":"Host routing conformance","use_when":["Inspect the host fixture"],"avoid_when":["Serving live business data"],"preconditions":["Admitted host fixture"],"effects":[],"result":"Checked result"},"input_sources":[],"follow_ups":[]},
            "request_example":"{}","response_example":"{}","deprecated":false,
            "execution":{"model":"","id_field":"","version_field":"","effects":[]},"errors":[],
            "verification_setup":[],"verification_delegation":[]
        }},"presentation":{"stylesheet":"","script":""},"identities":crate::identity::REGISTRY_FILE,"invariants":{"items":"Host route fixture state"},"domains":{},"errors":{}}
    }))?;
    contract
        .identities
        .synchronize(&contract.schema.models, &crate::host_inputs::SecureEntropy)?;
    contract.schema.bind_identities(&contract.identities)?;
    contract.api_docs = contract.app_contract.as_ref().unwrap().documentation();
    contract.operation_metadata = contract.app_contract.as_ref().unwrap().intents();
    let artifact = crate::artifact::LoadedArtifact::from_contract_for_tests(
        crate::digest(b"host-route-fixture"),
        directory.path().into(),
        contract,
    );
    let runtime = crate::store::Runtime::from_artifact_for_tests(
        instance_path,
        "app".into(),
        path,
        artifact,
    )?;
    runtime.initialize()?;
    let fixture =
        Fixture::with_directory_and_keys(directory, Arc::new(fixtures::TestApprovalKeys(0.into())));
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

mod owned_google {
    use super::*;
    use crate::oauth::effects::Hooks as _;
    use crate::oauth::{
        admission, clients,
        fresh_auth::FreshIntent,
        management::{
            Action,
            app::{Call, Manager, Reply as ManagementReply},
        },
        security_shell::{FreshAuthenticator, ReauthCallback, ReauthStart},
        shell_oidc::{GoogleFreshAuthenticator, ProviderInputSigner},
        simulation,
    };
    use serde::{Deserialize, Serialize};
    use std::{
        collections::{BTreeSet, VecDeque},
        io::Cursor,
        path::{Path, PathBuf},
        sync::Weak,
    };

    const EMAIL: &str = "alice@example.com";
    const GOOGLE_SUBJECT: &str = "accounts.google.com:alice";
    const CLIENT_SECRET: &[u8] = b"owned-provider-input-only";

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Case {
        Advance,
        IssuerAlias,
        ContinueWithoutLogin,
        ExpiredManual,
        ChangedManualPending,
        LostManualPublication,
        ManualInFlight,
        LostClaim,
        LostPublication,
        LostBaselinePublication,
        BaselineInFlight,
        FreshInFlight,
        LostBaselineExchange,
        LostFreshExchange,
        ChangedBaselinePending,
        ChangedFreshPending,
        ExpiredBaseline,
        ExpiredFresh,
        EqualAuthentication,
        OlderAuthentication,
        AuthenticationAfterIssue,
        MissingAuthentication,
        MissingBaselineAuthentication,
        WrongSubject,
        WrongClient,
        CrossPhase,
        CrossPhaseCode,
    }

    // Independent issuer-event policy: an old login is 99, the first token is
    // issued at 101, a genuinely later login is 102, and the second token is
    // issued at 103. This oracle reads no private host stage or transition.
    impl Case {
        fn fresh_authentication(self) -> Option<i64> {
            match self {
                Self::EqualAuthentication => Some(101),
                Self::OlderAuthentication => Some(100),
                Self::AuthenticationAfterIssue => Some(104),
                Self::MissingAuthentication => None,
                Self::ContinueWithoutLogin => Some(99),
                _ => Some(102),
            }
        }

        fn accepts_second_token(self) -> bool {
            self.fresh_authentication()
                .is_some_and(|auth| auth > 101 && auth <= 103)
                && !matches!(
                    self,
                    Self::WrongSubject
                        | Self::WrongClient
                        | Self::CrossPhase
                        | Self::CrossPhaseCode
                )
        }
    }

    struct FixtureHost;
    impl crate::host_inputs::Clock for FixtureHost {
        fn wall_time(&self) -> Result<Duration> {
            Ok(Duration::from_secs(100))
        }
        fn monotonic(&self) -> Duration {
            Duration::ZERO
        }
    }
    impl crate::host::Host for FixtureHost {
        fn entropy(&self, _: &str, _: &str) -> Result<[u8; 32]> {
            Ok([29; 32])
        }
        fn now_ms(&self) -> Result<i64> {
            Ok(100_000)
        }
        fn worker_action(
            &self,
            _: crate::protocol::Phase,
            _: &crate::protocol::Request,
        ) -> Result<crate::host::WorkerAction> {
            anyhow::bail!("owned Google fixture forbids workers")
        }
        fn record_exchange(
            &self,
            _: crate::protocol::Phase,
            _: &crate::protocol::Request,
            _: &Result<crate::protocol::Response>,
        ) -> Result<()> {
            anyhow::bail!("owned Google fixture forbids worker exchange")
        }
        fn monotonic(&self) -> Duration {
            Duration::ZERO
        }
    }

    struct Setup {
        directory: tempfile::TempDir,
        retention_root: PathBuf,
        instance: PathBuf,
        artifact: crate::artifact::LoadedArtifact,
        authority: Arc<admission::ArtifactApprovalAuthority>,
        signer: Arc<admission::ArtifactShellSigner>,
        assertions: Assertions,
        human_assertion: String,
        machine_assertion: String,
        provider: Arc<ProviderInputSigner>,
    }

    impl Setup {
        fn new() -> Result<Self> {
            let directory = tempfile::tempdir()?;
            let (runtime, authority, signer) =
                admission::tests::management_fixture(directory.path())?;
            let assertions = Assertions::new();
            let claims = json!({"iss":"https://cloud.google.com/iap","aud":SHELL_AUDIENCE,
                "email":EMAIL,"sub":GOOGLE_SUBJECT,"hd":"example.com","iat":0,"exp":600});
            let signed = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(br#"{"kid":"fixture","alg":"ES256"}"#),
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
            );
            let signature = assertions
                .pair
                .sign(&SystemRandom::new(), signed.as_bytes())
                .map_err(|_| anyhow::anyhow!("owned IAP input signing failed"))?;
            let human_assertion =
                format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()));
            let machine_assertion = assertions.assertion(APP_AUDIENCE, MACHINE, "service-123");
            Ok(Self {
                retention_root: Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../artifacts/oauth-owned-google"),
                instance: runtime.instance_path().to_path_buf(),
                artifact: runtime.artifact().clone(),
                directory,
                authority,
                signer,
                assertions,
                human_assertion,
                machine_assertion,
                provider: Arc::new(ProviderInputSigner::new()?),
            })
        }

        fn runtime(&self, ordinal: usize) -> Result<crate::store::Runtime> {
            let host = Arc::new(FixtureHost);
            let runtime = crate::store::Runtime::from_artifact_for_tests(
                self.instance.clone(),
                "workspace".into(),
                self.directory
                    .path()
                    .join(format!("owner-{ordinal}.sqlite")),
                self.artifact.clone(),
            )?
            .with_host(host.clone(), host);
            runtime.initialize()?;
            Ok(runtime)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SignedInput {
        claims: serde_json::Value,
        token: String,
    }

    struct Authorization {
        fields: BTreeMap<String, String>,
    }

    enum Reentry {
        Callback {
            auth: Weak<GoogleFreshAuthenticator>,
            query: String,
            headers: HeaderMap,
        },
        Manual {
            auth: Weak<GoogleFreshAuthenticator>,
            handle: String,
            csrf: String,
            headers: HeaderMap,
        },
    }

    struct Port {
        world: Arc<simulation::World>,
        receiver: Arc<AppApprovalReceiver>,
        database: PathBuf,
        machine: String,
        iap_keys: String,
        provider: Arc<ProviderInputSigner>,
        case: Case,
        authorizations: Mutex<BTreeMap<String, Authorization>>,
        exchanged: Mutex<BTreeSet<String>>,
        lose_reply: Mutex<Option<&'static str>>,
        reentry: Mutex<Option<Reentry>>,
        replay: Mutex<Option<VecDeque<SignedInput>>>,
        inputs: Mutex<Vec<SignedInput>>,
        entropy_inputs: Mutex<Vec<String>>,
        trace: Mutex<Vec<serde_json::Value>>,
        fills: AtomicUsize,
        token_sends: AtomicUsize,
        secret_sends: AtomicUsize,
        external_authentication: AtomicI64,
        observation_sink: Option<Arc<ObservationSink>>,
        expected_credential_wall: Option<i64>,
    }

    #[derive(Clone, Copy)]
    enum SinkOutcome {
        Complete,
        PartialUnknown,
        CompleteThenError,
        Unavailable,
    }

    struct ObservationSink {
        outcome: SinkOutcome,
        pause: bool,
        entered: tokio::sync::Notify,
        released: Mutex<bool>,
        release: std::sync::Condvar,
        attempts: Mutex<Vec<serde_json::Value>>,
        delivered: Mutex<Vec<u8>>,
    }

    impl ObservationSink {
        fn write(&self, data: crate::oauth::shell_oidc::ProviderObservationData) -> Result<()> {
            self.attempts
                .lock()
                .unwrap()
                .push(serde_json::to_value(&data)?);
            let mut line = serde_json::to_vec(&data)?;
            line.push(b'\n');
            self.entered.notify_one();
            if self.pause {
                let mut released = self.released.lock().unwrap();
                while !*released {
                    let (next, timeout) = self
                        .release
                        .wait_timeout(released, Duration::from_secs(10))
                        .unwrap();
                    ensure!(!timeout.timed_out(), "observation fixture release deadline");
                    released = next;
                }
            }
            match self.outcome {
                SinkOutcome::Complete => {
                    *self.delivered.lock().unwrap() = line;
                    Ok(())
                }
                SinkOutcome::PartialUnknown => {
                    *self.delivered.lock().unwrap() = line[..17].to_vec();
                    anyhow::bail!("scripted partial or unknown observation delivery")
                }
                SinkOutcome::CompleteThenError => {
                    *self.delivered.lock().unwrap() = line;
                    anyhow::bail!("scripted error after complete observation delivery")
                }
                SinkOutcome::Unavailable => anyhow::bail!("scripted observation sink unavailable"),
            }
        }
    }

    struct ReleaseObservation(Arc<ObservationSink>);
    impl Drop for ReleaseObservation {
        fn drop(&mut self) {
            *self.0.released.lock().unwrap() = true;
            self.0.release.notify_all();
        }
    }

    fn identity() -> iap::Verified {
        iap::Verified {
            email: EMAIL.into(),
            subject: GOOGLE_SUBJECT.into(),
        }
    }

    impl Port {
        fn require_observation_context(&self) -> Result<()> {
            if let Some(expected) = self.expected_credential_wall {
                ensure!(
                    crate::managed_credentials::effects::wall_time()? == expected
                        && effects::wall_time()? == self.wall_time()?,
                    "mounted request lost or replaced an effect track"
                );
            }
            Ok(())
        }

        fn response(status: u16, body: Vec<u8>) -> effects::Response {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            effects::Response::Simulated {
                status: reqwest::StatusCode::from_u16(status).unwrap(),
                headers,
                body: Cursor::new(body),
                peer: None,
            }
        }

        fn observe(&self, label: &str) -> Result<()> {
            let db = crate::store::open(&self.database)?;
            let mut rows = db.prepare("SELECT json_array(original,attempt,purpose,human,subject,context,owner,created_at,expires_at,stage,request,request_digest,result_digest) FROM native_fresh_owners ORDER BY original")?;
            let owners = rows
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            self.trace.lock().unwrap().push(json!({"event":label,"wall":self.wall_time()?,
                "fills":self.fills.load(Ordering::SeqCst),"tokens":self.token_sends.load(Ordering::SeqCst),
                "entropy_inputs":self.entropy_inputs.lock().unwrap().clone(),
                "owners":owners,"oauth":simulation::snapshot(&db)?}));
            Ok(())
        }

        fn owner(&self) -> Result<(i64, String, Option<String>)> {
            let db = crate::store::open(&self.database)?;
            Ok(db.query_row(
                "SELECT count(*),max(stage),max(request) FROM native_fresh_owners",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?)
        }

        fn change_current_pending(&self, id: &str) -> Result<()> {
            let db = crate::store::open(&self.database)?;
            ensure!(db.execute("UPDATE oauth_management_intents SET view=json_set(view,'$.challenge',?2) WHERE id=?1 AND state='pending'",
                rusqlite::params![id, Digest::new(b"changed actual app Pending").as_str()])? == 1,
                "owned campaign current Pending absent");
            Ok(())
        }

        fn capture(&self, phase: &str, location: &str, client: &str) -> Result<String> {
            let url = Url::parse(location)?;
            ensure!(
                url.origin().ascii_serialization() == "https://accounts.google.com"
                    && url.path() == "/o/oauth2/v2/auth"
                    && url.fragment().is_none(),
                "owned authorization endpoint changed"
            );
            let mut fields = BTreeMap::new();
            for (key, value) in url.query_pairs().into_owned() {
                ensure!(
                    fields.insert(key, value).is_none(),
                    "owned authorization duplicate field"
                );
            }
            ensure!(fields.len() == 12, "owned authorization field set changed");
            for (key, value) in [
                ("response_type", "code"),
                ("scope", "openid email"),
                ("client_id", client),
                (
                    "redirect_uri",
                    "https://security.example.com/_day2/reauth/callback",
                ),
                ("code_challenge_method", "S256"),
                ("max_age", "0"),
                ("claims", r#"{"id_token":{"auth_time":{"essential":true}}}"#),
                ("hd", "example.com"),
                ("login_hint", EMAIL),
            ] {
                ensure!(
                    fields.get(key).map(String::as_str) == Some(value),
                    "owned authorization selected field changed"
                );
            }
            for key in ["state", "nonce", "code_challenge"] {
                ensure!(
                    fields.get(key).is_some_and(|value| value.len() == 43),
                    "owned phase tuple missing"
                );
            }
            let code = format!("owned-{phase}-code");
            let mut authorizations = self.authorizations.lock().unwrap();
            if let Some(previous) = authorizations.get(&code) {
                ensure!(previous.fields == fields, "owned phase regenerated");
            } else {
                for previous in authorizations.values() {
                    for key in ["state", "nonce", "code_challenge"] {
                        ensure!(
                            previous.fields[key] != fields[key],
                            "owned phase reused tuple"
                        );
                    }
                }
                authorizations.insert(
                    code.clone(),
                    Authorization {
                        fields: fields.clone(),
                    },
                );
            }
            Ok(url::form_urlencoded::Serializer::new(String::new())
                .append_pair("iss", "https://accounts.google.com")
                .append_pair("state", &fields["state"])
                .append_pair("code", &code)
                .finish())
        }

        fn private_send(&self, request: reqwest::blocking::Request) -> Result<effects::Response> {
            ensure!(
                request.method() == reqwest::Method::POST
                    && request.url().path() == PATH
                    && request.url().query().is_none()
                    && request.headers()[header::AUTHORIZATION] == "Bearer owned-edge-input",
                "owned emulated IAP edge refused request"
            );
            let bytes = request
                .body()
                .and_then(reqwest::blocking::Body::as_bytes)
                .context("owned private body missing")?;
            let value: serde_json::Value = crate::json::decode(bytes)?;
            let operation = value["call"]["operation"]["operation"]
                .as_str()
                .unwrap_or("management");
            // The test edge supplies its separately signed machine assertion.
            // The actual receiver independently verifies it and the exact human
            // assertion carried by RemoteApprovals, then executes real SQLite.
            let mut headers = request.headers().clone();
            headers.insert(iap::ASSERTION_HEADER, self.machine.parse()?);
            let app_sink = crate::oauth::native_management::Sink::new();
            let result = app_sink.run(|| {
                self.receiver.dispatch(
                    &Method::POST,
                    PATH,
                    None,
                    &headers,
                    bytes,
                    self.wall_time()?,
                )
            });
            // Model the server's known local response completion separately
            // from the caller losing that reply below. Actual partial/failed
            // socket delivery is exercised by the native HTTP tests.
            let completion = app_sink.finish();
            if completion.is_err() {
                app_sink.abort();
            }
            let result = completion.and(result);
            let reentry = {
                let mut slot = self.reentry.lock().unwrap();
                if matches!(&*slot, Some(Reentry::Manual { .. })) {
                    slot.take()
                } else {
                    None
                }
            };
            if let Some(Reentry::Manual {
                auth,
                handle,
                csrf,
                headers,
            }) = reentry
            {
                ensure!(
                    auth.upgrade()
                        .context("in-flight manual owner missing")?
                        .resume_manual(&handle, &csrf, &identity(), &headers, self.wall_time()?)
                        .is_err(),
                    "manual POST was not fenced before app RPC"
                );
            }
            self.trace.lock().unwrap().push(
                json!({"rpc":operation,"request":Digest::new(bytes),"committed":result.is_ok()}),
            );
            if result.is_ok() {
                let mut loss = self.lose_reply.lock().unwrap();
                if *loss == Some(operation) {
                    *loss = None;
                    anyhow::bail!("owned campaign reply lost AFTER app commit");
                }
            }
            match result {
                Ok(bytes) => Ok(Self::response(200, bytes)),
                Err(_) => Ok(Self::response(403, Vec::new())),
            }
        }

        fn token_send(&self, request: reqwest::blocking::Request) -> Result<effects::Response> {
            ensure!(
                request.method() == reqwest::Method::POST
                    && request.url().as_str() == "https://oauth2.googleapis.com/token",
                "owned token endpoint changed"
            );
            self.token_sends.fetch_add(1, Ordering::SeqCst);
            let bytes = request
                .body()
                .and_then(reqwest::blocking::Body::as_bytes)
                .context("owned token body missing")?;
            let mut form = BTreeMap::new();
            for (key, value) in url::form_urlencoded::parse(bytes).into_owned() {
                ensure!(
                    form.insert(key, value).is_none(),
                    "owned token duplicate field"
                );
            }
            let code = form.get("code").context("owned token code missing")?;
            let authorizations = self.authorizations.lock().unwrap();
            let authorization = authorizations
                .get(code)
                .context("owned provider unknown code")?;
            ensure!(
                form.len() == 6
                    && form["grant_type"] == "authorization_code"
                    && form["client_id"] == authorization.fields["client_id"]
                    && form["redirect_uri"] == authorization.fields["redirect_uri"]
                    && form["client_secret"].as_bytes() == CLIENT_SECRET
                    && URL_SAFE_NO_PAD.encode(
                        ring::digest::digest(
                            &ring::digest::SHA256,
                            form["code_verifier"].as_bytes()
                        )
                        .as_ref()
                    ) == authorization.fields["code_challenge"],
                "owned provider PKCE/client binding refused"
            );
            let fresh = code == "owned-fresh-code";
            let mut claims = json!({"iss":"https://accounts.google.com","aud":authorization.fields["client_id"],
                "sub":"alice","email":EMAIL,"email_verified":true,"hd":"example.com","exp":500,
                "iat":if fresh {103} else {101},
                "auth_time":if fresh {self.external_authentication.load(Ordering::SeqCst)} else {99},"nonce":authorization.fields["nonce"]});
            if !fresh && self.case == Case::MissingBaselineAuthentication {
                claims.as_object_mut().unwrap().remove("auth_time");
            }
            if fresh {
                match self.case.fresh_authentication() {
                    Some(value)
                        if matches!(
                            self.case,
                            Case::EqualAuthentication
                                | Case::OlderAuthentication
                                | Case::AuthenticationAfterIssue
                        ) =>
                    {
                        claims["auth_time"] = json!(value)
                    }
                    Some(_) => {}
                    None => {
                        claims.as_object_mut().unwrap().remove("auth_time");
                    }
                }
                match self.case {
                    Case::WrongSubject => claims["sub"] = json!("another-human"),
                    Case::WrongClient => {
                        claims["aud"] = json!("different.apps.googleusercontent.com")
                    }
                    Case::CrossPhase => {
                        claims["nonce"] =
                            json!(authorizations["owned-baseline-code"].fields["nonce"])
                    }
                    Case::IssuerAlias => claims["iss"] = json!("accounts.google.com"),
                    _ => {}
                }
            }
            drop(authorizations);
            ensure!(
                self.exchanged.lock().unwrap().insert(code.clone()),
                "provider code already consumed"
            );
            self.trace
                .lock()
                .unwrap()
                .push(json!({"provider_exchange":code,"claims":claims}));
            // Reenter while the actual provider dispatch is in progress. The
            // same callback must already be fenced, before any second send.
            let reentry = self.reentry.lock().unwrap().take();
            if let Some(Reentry::Callback {
                auth,
                query,
                headers,
            }) = reentry
            {
                let auth = auth.upgrade().context("owned in-flight shell missing")?;
                ensure!(
                    auth.complete(&query, &identity(), &headers, self.wall_time()?)
                        .is_err(),
                    "in-flight callback was dispatched twice"
                );
            }
            if (!fresh && self.case == Case::LostBaselineExchange)
                || (fresh && self.case == Case::LostFreshExchange)
            {
                anyhow::bail!("owned provider exchange response lost AFTER code consumption");
            }
            let input = match self.replay.lock().unwrap().as_mut() {
                Some(replay) => {
                    let input = replay
                        .pop_front()
                        .context("owned signed input replay exhausted")?;
                    ensure!(input.claims == claims, "owned replay signed claims changed");
                    input
                }
                None => SignedInput {
                    token: self.provider.sign(&claims)?,
                    claims,
                },
            };
            self.inputs.lock().unwrap().push(input.clone());
            if !fresh && self.case == Case::LostBaselinePublication {
                *self.lose_reply.lock().unwrap() = Some("publish");
            }
            Ok(Self::response(
                200,
                serde_json::to_vec(&json!({"id_token":input.token}))?,
            ))
        }
    }

    impl effects::Hooks for Port {
        fn provider_observation(
            &self,
            data: crate::oauth::shell_oidc::ProviderObservationData,
        ) -> Result<()> {
            self.require_observation_context()?;
            self.observation_sink
                .as_ref()
                .context("unscripted provider observation")?
                .write(data)
        }

        fn domain(&self) -> u64 {
            effects::Hooks::domain(self.world.as_ref())
        }
        fn wall_time(&self) -> Result<i64> {
            effects::Hooks::wall_time(self.world.as_ref())
        }
        fn monotonic(&self) -> Duration {
            effects::Hooks::monotonic(self.world.as_ref())
        }
        fn fill(&self, bytes: &mut [u8]) -> Result<()> {
            self.fills.fetch_add(1, Ordering::SeqCst);
            effects::Hooks::fill(self.world.as_ref(), bytes)?;
            self.entropy_inputs
                .lock()
                .unwrap()
                .push(URL_SAFE_NO_PAD.encode(bytes));
            Ok(())
        }
        fn send(&self, request: reqwest::blocking::Request) -> Result<effects::Response> {
            self.require_observation_context()?;
            match request.url().host_str() {
                Some("app.example.com") => self.private_send(request),
                Some("www.gstatic.com")
                    if request.url().as_str() == iap::KEYS_URL
                        && request.method() == reqwest::Method::GET =>
                {
                    Ok(Self::response(200, self.iap_keys.as_bytes().to_vec()))
                }
                Some("www.googleapis.com") if request.url().path() == "/oauth2/v3/certs" => Ok(
                    Self::response(200, self.provider.jwks().as_bytes().to_vec()),
                ),
                Some("secretmanager.googleapis.com") => {
                    ensure!(
                        request.method() == reqwest::Method::GET
                            && request.url().path()
                                == "/v1/projects/12345/secrets/google_reauth/versions/3:access",
                        "owned secret selected version changed"
                    );
                    self.secret_sends.fetch_add(1, Ordering::SeqCst);
                    let name = request
                        .url()
                        .path()
                        .strip_prefix("/v1/")
                        .unwrap()
                        .strip_suffix(":access")
                        .unwrap();
                    Ok(Self::response(
                        200,
                        serde_json::to_vec(&json!({"name":name,"payload":{
                        "data":base64::engine::general_purpose::STANDARD.encode(CLIENT_SECRET),
                        "dataCrc32c":crc32c::crc32c(CLIENT_SECRET).to_string()}}))?,
                    ))
                }
                Some("oauth2.googleapis.com") => self.token_send(request),
                _ => anyhow::bail!("owned Google campaign forbids unscripted HTTP"),
            }
        }
    }

    struct EdgeBearer;
    impl PrivateBearerSource for EdgeBearer {
        fn bearer(&self, app: &str, receiver: &Url) -> Result<String> {
            ensure!(
                app == "workspace"
                    && receiver.as_str() == "https://app.example.com/_day2/oauth/approval",
                "owned app receiver selection changed"
            );
            Ok("owned-edge-input".into())
        }
    }

    #[derive(Debug, PartialEq, Serialize)]
    struct Transcript {
        events: Vec<serde_json::Value>,
        inputs: Vec<SignedInput>,
    }

    fn redirect(start: ReauthStart) -> Result<String> {
        match start {
            ReauthStart::Redirect(location) => Ok(location),
            _ => anyhow::bail!("owned Google Begin bypassed provider"),
        }
    }

    fn independently_reconstructed_profile(
        instance: &Instance,
        sources: &[Digest; 4],
    ) -> Result<Digest> {
        let client = &instance
            .oauth_clients
            .as_ref()
            .context("test client missing")?
            .reauthentication;
        let selected = &instance
            .control
            .as_ref()
            .context("test catalog missing")?
            .secrets[&client.credential];
        let day2_capabilities::SecretProvider::GcpVersion {
            project_number,
            secret,
            version,
        } = selected;
        let exchange = Digest::of(&(
            "google-code-client-reference-v1",
            project_number.get(),
            secret.as_str(),
            version.get(),
            "https://oauth2.googleapis.com/token",
        ))?;
        let (identity, edge) = instance.security_edge()?;
        let profile = Digest::of(&(
            "google-two-phase-profile-v1",
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
            "https://www.googleapis.com/oauth2/v3/certs",
            "https://accounts.google.com",
            &client.client_id,
            format!("{}/_day2/reauth/callback", edge.origin),
            &identity.hosted_domain,
            exchange,
            &sources[0],
            &sources[1],
            &sources[2],
            &sources[3],
        ))?;
        Digest::of(&("google-provider-profile-observation-v1", profile))
    }

    // Native HTTP adapter conformance using locally signed provider fixtures/current
    // app SQLite. It cannot supply real provider or native fresh-human proof.
    fn mounted_observation(
        case: Case,
        outcome: SinkOutcome,
        cancel: bool,
        with_registry: bool,
    ) -> Result<()> {
        let setup = Setup::new()?;
        let instance = Instance::load(&setup.instance)?;
        let runtime = setup.runtime(0)?;
        let database = runtime.db().to_path_buf();
        let manager = Arc::new(Manager::new(runtime, setup.authority.clone()));
        let mut receiver = setup.assertions.receiver(Arc::new(
            crate::oauth::approval_registry::UnavailableAppApprovals::new("workspace".into())?,
        ));
        receiver.authority = "app.example.com".into();
        receiver.route = route_prefix(&instance.installation, &instance.environment, "workspace")?;
        let receiver = Arc::new(receiver).with_management(manager)?;
        let serving_credentials = crate::managed_credentials::simulation::World::new(1130);
        serving_credentials.set_wall(73);
        let registry_credentials = crate::managed_credentials::simulation::World::new(1131);
        registry_credentials.set_wall(83);
        // Construct the ordinary registry BEFORE the OAuth fixture scope. Its
        // OAuth capture is None; its selected credential track must still win
        // while preserving the later ambient serving OAuth track.
        let registry = if with_registry {
            let authority = Arc::new(
                crate::managed_credentials::authority::SelectedAuthority::new(
                    Vec::new(),
                    Arc::new(fixtures::TestApprovalKeys(0.into())),
                )?,
            );
            Some(Arc::new(crate::managed_credentials::effects::scope(
                registry_credentials.clone(),
                || {
                    crate::managed_credentials::browser::Registry::new(
                        &instance,
                        Vec::new(),
                        authority,
                    )
                },
            )?))
        } else {
            None
        };
        let sink = Arc::new(ObservationSink {
            outcome,
            pause: cancel,
            entered: tokio::sync::Notify::new(),
            released: Mutex::new(false),
            release: std::sync::Condvar::new(),
            attempts: Mutex::new(Vec::new()),
            delivered: Mutex::new(Vec::new()),
        });
        let world = simulation::World::new(1129);
        world.advance(95);
        let port = Arc::new(Port {
            world,
            receiver,
            database,
            machine: setup.machine_assertion.clone(),
            iap_keys: setup.assertions.keys.clone(),
            provider: setup.provider.clone(),
            case,
            authorizations: Mutex::new(BTreeMap::new()),
            exchanged: Mutex::new(BTreeSet::new()),
            lose_reply: Mutex::new(None),
            reentry: Mutex::new(None),
            replay: Mutex::new(None),
            inputs: Mutex::new(Vec::new()),
            entropy_inputs: Mutex::new(Vec::new()),
            trace: Mutex::new(Vec::new()),
            fills: AtomicUsize::new(0),
            token_sends: AtomicUsize::new(0),
            secret_sends: AtomicUsize::new(0),
            external_authentication: AtomicI64::new(99),
            observation_sink: Some(sink.clone()),
            expected_credential_wall: Some(if with_registry { 83 } else { 73 }),
        });
        let owners = Arc::new(RemoteApprovals::from_instance(
            &instance,
            Arc::new(EdgeBearer),
        )?);
        let (client, exchange) = clients::reauthentication(
            &instance,
            Arc::new(crate::oauth::registration::tests::TokensSource(
                AtomicUsize::new(0),
            )),
        )?;
        let auth = Arc::new(GoogleFreshAuthenticator::new(
            SHELL_AUDIENCE,
            "example.com",
            "https://security.example.com/",
            client,
            exchange,
            owners.clone(),
        )?);
        let shell = crate::oauth::security_shell::SecurityShell::with_management_fixture(
            "https://security.example.com/".into(),
            owners.clone(),
            setup.signer.clone(),
            auth.clone(),
        )?;
        let shell = match registry {
            Some(registry) => shell.with_credentials(registry)?,
            None => shell,
        };
        let mut headers = HeaderMap::new();
        headers.insert(iap::ASSERTION_HEADER, setup.human_assertion.parse()?);
        headers.insert(
            header::HOST,
            HeaderValue::from_static("security.example.com"),
        );
        let setup_credentials = if with_registry {
            registry_credentials
        } else {
            serving_credentials.clone()
        };
        let prepare = {
            let port = port.clone();
            let auth = auth.clone();
            let owners = owners.clone();
            let shell = shell.clone();
            let headers = headers.clone();
            move || {
                crate::managed_credentials::effects::scope(setup_credentials, || {
                    effects::scope(port.clone(), || -> Result<_> {
                        let human = auth.identify(&headers, 100)?;
                        let ManagementReply::Pending { view } = owners.management(
                            "workspace",
                            Call::Capture {
                                registration: "calendar".into(),
                                operation: Action::Connect,
                            },
                            &headers,
                        )?
                        else {
                            anyhow::bail!("mounted current Pending absent");
                        };
                        let intent = FreshIntent::management(&view, &human)?;
                        let first = redirect(auth.begin(&human, intent, &headers, 100)?)?;
                        let client = &instance
                            .oauth_clients
                            .as_ref()
                            .unwrap()
                            .reauthentication
                            .client_id;
                        let baseline = port.capture("baseline", &first, client)?;
                        port.world.advance(1);
                        let ReauthCallback::Manual(manual) =
                            auth.complete(&baseline, &human, &headers, 101)?
                        else {
                            anyhow::bail!("mounted baseline skipped checkpoint");
                        };
                        let handle = manual
                            .strip_prefix(crate::oauth::shell_oidc::MANUAL_PREFIX)
                            .context("mounted manual path")?;
                        let prompt = auth.manual_view(handle, &human, &headers, 101)?;
                        let sources = [
                            Digest::new(include_bytes!("shell_oidc.rs")),
                            Digest::new(include_bytes!("google_begin.rs")),
                            Digest::new(include_bytes!("fresh_owner.rs")),
                            Digest::new(include_bytes!("../../../../Cargo.lock")),
                        ];
                        let expected_profile =
                            independently_reconstructed_profile(&instance, &sources)?;
                        for index in 0..4 {
                            let mut changed = sources.clone();
                            changed[index] = Digest::new(b"different qualified source bytes");
                            ensure!(
                                independently_reconstructed_profile(&instance, &changed)?
                                    != expected_profile,
                                "source substitution retained observation profile"
                            );
                        }
                        // These are independent reader-input substitutions, not qualified
                        // alternate serving instances or new provider registrations.
                        for field in 0..6 {
                            let mut changed = instance.clone();
                            match field {
                                0 => {
                                    changed
                                        .oauth_clients
                                        .as_mut()
                                        .unwrap()
                                        .reauthentication
                                        .client_id = "999-reauth.apps.googleusercontent.com".into()
                                }
                                1 => {
                                    changed.security_shell.as_mut().unwrap().origin =
                                        "https://other-security.example.com".into()
                                }
                                2 => {
                                    changed.identity.as_mut().unwrap().hosted_domain =
                                        "other.example.com".into()
                                }
                                _ => {
                                    let credential = changed
                                        .oauth_clients
                                        .as_ref()
                                        .unwrap()
                                        .reauthentication
                                        .credential
                                        .clone();
                                    let day2_capabilities::SecretProvider::GcpVersion {
                                        project_number,
                                        secret,
                                        version,
                                    } = changed
                                        .control
                                        .as_mut()
                                        .unwrap()
                                        .secrets
                                        .get_mut(&credential)
                                        .unwrap();
                                    match field {
                                        3 => {
                                            *project_number =
                                                std::num::NonZeroU64::new(12346).unwrap()
                                        }
                                        4 => {
                                            *secret = day2_capabilities::Name::try_from(
                                                "different_reauth".to_owned(),
                                            )?
                                        }
                                        5 => *version = std::num::NonZeroU64::new(4).unwrap(),
                                        _ => unreachable!(),
                                    }
                                }
                            }
                            ensure!(
                                independently_reconstructed_profile(&changed, &sources)?
                                    != expected_profile,
                                "metadata substitution retained observation profile"
                            );
                        }
                        let expected_correlation = Digest::of(&(
                            "google-provider-manual-observation-v1",
                            &expected_profile,
                            handle,
                        ))?;
                        port.external_authentication.store(102, Ordering::SeqCst);
                        port.world.advance(2);
                        let mut post = headers.clone();
                        post.insert(
                            header::ORIGIN,
                            HeaderValue::from_static("https://security.example.com"),
                        );
                        post.insert(
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("application/x-www-form-urlencoded"),
                        );
                        let body = url::form_urlencoded::Serializer::new(String::new())
                            .append_pair("csrf", &prompt.csrf)
                            .finish();
                        let offered = shell.dispatch(
                            &Method::POST,
                            &manual,
                            None,
                            &post,
                            body.as_bytes(),
                            103,
                        )?;
                        ensure!(
                            offered.status() == StatusCode::SEE_OTHER
                                && !offered.headers().contains_key(header::SET_COOKIE),
                            "manual produced a session"
                        );
                        let query = port.capture(
                            "fresh",
                            offered.headers()[header::LOCATION].to_str()?,
                            client,
                        )?;
                        if case == Case::ChangedFreshPending {
                            port.change_current_pending(&view.id)?;
                        }
                        if case == Case::ExpiredFresh {
                            port.world.advance(297);
                        }
                        let mut private_values = port.entropy_inputs.lock().unwrap().clone();
                        private_values.extend([handle.to_owned(), prompt.csrf]);
                        Ok((
                            query,
                            expected_profile,
                            expected_correlation,
                            simulation::snapshot(&crate::store::open(&port.database)?)?,
                            port.fills.load(Ordering::SeqCst),
                            private_values,
                        ))
                    })
                })
            }
        };
        let executor = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        let listener = executor.block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let (ready, prepared) = std::sync::mpsc::sync_channel(1);
        let prepare = move || {
            let result = prepare();
            match result {
                Ok(value) => {
                    ready
                        .send(Ok(value))
                        .map_err(|_| anyhow::anyhow!("native fixture driver lost"))?;
                    Ok(())
                }
                Err(error) => {
                    let _ = ready.send(Err(error.to_string()));
                    Err(error)
                }
            }
        };
        let serving_effects =
            crate::managed_credentials::effects::scope(serving_credentials.clone(), || {
                effects::scope(port.clone(), crate::managed_credentials::effects::capture)
            });
        let server = executor.spawn(serving_effects.run_async(crate::oauth::native_http::serve(
            crate::oauth::native_http::Endpoint::Prepared(
                Box::new(crate::oauth::native_http::Endpoint::Shell(shell)),
                Box::new(prepare),
            ),
            listener,
            1,
            Arc::new(AtomicBool::new(true)),
            async {
                let _ = shutdown.await;
            },
        )));
        let (query, expected_profile, expected_correlation, before, entropy, mut private_values) =
            prepared
                .recv_timeout(Duration::from_secs(10))
                .context("native fixture preparation timed out")?
                .map_err(anyhow::Error::msg)?;
        private_values.push(setup.human_assertion.clone());
        executor.block_on(crate::managed_credentials::effects::scope_async(
            serving_credentials,
            effects::scope_async(port.clone(), async {
                let client = reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?;
                let request = || {
                    client
                        .get(format!("{endpoint}/_day2/reauth/callback?{query}"))
                        .headers(headers.clone())
                };
                if cancel {
                    let _release_on_error = ReleaseObservation(sink.clone());
                    let browser = tokio::spawn(request().send());
                    tokio::time::timeout(Duration::from_secs(3), sink.entered.notified()).await?;
                    // Selection already happened at103. The same physical write
                    // may finish at the original400 cutoff; no authority renews.
                    port.world.advance(297);
                    browser.abort();
                    let _ = browser.await;
                    ensure!(
                        tokio::time::timeout(Duration::from_millis(20), request().send())
                            .await
                            .is_err(),
                        "paused observation released native capacity"
                    );
                    let _ = stop.send(());
                    tokio::task::yield_now().await;
                    ensure!(
                        !server.is_finished(),
                        "shutdown did not drain observation writer"
                    );
                    *sink.released.lock().unwrap() = true;
                    sink.release.notify_all();
                } else {
                    for _ in 0..2 {
                        let response = request().send().await?;
                        ensure!(
                            response.status() == StatusCode::FORBIDDEN
                                && !response.headers().contains_key(header::SET_COOKIE),
                            "observation minted response authority"
                        );
                        for value in response.headers().values() {
                            for private in [
                                expected_profile.as_str(),
                                expected_correlation.as_str(),
                                EMAIL,
                                std::str::from_utf8(CLIENT_SECRET)?,
                            ]
                            .into_iter()
                            .chain(private_values.iter().map(String::as_str))
                            {
                                ensure!(
                                    !value
                                        .as_bytes()
                                        .windows(private.len())
                                        .any(|window| window == private.as_bytes()),
                                    "private observation entered browser header"
                                );
                            }
                        }
                        ensure!(
                            response.bytes().await?.is_empty(),
                            "private observation entered browser body"
                        );
                    }
                    let _ = stop.send(());
                }
                tokio::time::timeout(Duration::from_secs(3), server).await???;
                Ok::<_, anyhow::Error>(())
            }),
        ))?;
        let attempts = sink.attempts.lock().unwrap();
        let accepted = case.accepts_second_token()
            && !matches!(case, Case::ChangedFreshPending | Case::ExpiredFresh);
        ensure!(
            attempts.len() == usize::from(accepted),
            "verified observation count or replay changed"
        );
        ensure!(
            simulation::snapshot(&crate::store::open(&port.database)?)? == before
                && port.fills.load(Ordering::SeqCst) == entropy,
            "refusal changed OAuth table projection or session entropy"
        );
        ensure!(
            port.token_sends.load(Ordering::SeqCst)
                == if matches!(case, Case::ChangedFreshPending | Case::ExpiredFresh) {
                    1
                } else {
                    2
                },
            "callback replay repeated exchange"
        );
        if let Some(record) = attempts.first() {
            ensure!(
                record
                    == &json!({"version":1,"kind":"google_provider_prerequisite","outcome":"signed_auth_time_and_ordering_verified_native_producer_unavailable","baseline_iat":101,"fresh_auth_time":102,"profile":expected_profile,"correlation":expected_correlation}),
                "operator record differs from independent metadata/manual projection"
            );
            let bytes = serde_json::to_vec(record)?;
            ensure!(
                bytes.len() < 1024 && bytes.is_ascii(),
                "operator record exceeded fixed bound"
            );
            let text = std::str::from_utf8(&bytes)?;
            for private in [
                EMAIL,
                GOOGLE_SUBJECT,
                std::str::from_utf8(CLIENT_SECRET)?,
                "owned-fresh-code",
                "owned-baseline-code",
                "https://",
                "nonce",
                "state",
                "verifier",
                "cookie",
            ] {
                ensure!(
                    !text.contains(private),
                    "private sentinel entered observation"
                );
            }
            for private in &private_values {
                ensure!(
                    !text.contains(private),
                    "private entropy or manual value entered observation"
                );
            }
            for input in port.inputs.lock().unwrap().iter() {
                ensure!(
                    !text.contains(&input.token),
                    "signed token entered observation"
                );
            }
        }
        let delivered = sink.delivered.lock().unwrap();
        if accepted {
            match outcome {
                SinkOutcome::Complete | SinkOutcome::CompleteThenError => ensure!(
                    delivered.last() == Some(&b'\n'),
                    "complete sink model missing line"
                ),
                SinkOutcome::PartialUnknown => {
                    ensure!(delivered.len() == 17, "partial sink model not exercised")
                }
                SinkOutcome::Unavailable => {
                    ensure!(delivered.is_empty(), "unavailable sink model wrote bytes")
                }
            }
        } else {
            ensure!(delivered.is_empty(), "unverified callback wrote diagnostic");
        }
        Ok(())
    }

    #[test]
    fn mounted_signed_provider_observation_never_authorizes_even_when_delivery_is_ambiguous()
    -> Result<()> {
        for outcome in [
            SinkOutcome::Complete,
            SinkOutcome::PartialUnknown,
            SinkOutcome::CompleteThenError,
            SinkOutcome::Unavailable,
        ] {
            mounted_observation(Case::Advance, outcome, false, false)?;
        }
        Ok(())
    }

    #[test]
    fn mounted_provider_observation_keeps_native_capacity_after_browser_cancellation() -> Result<()>
    {
        mounted_observation(Case::Advance, SinkOutcome::Complete, true, false)
    }

    #[test]
    fn mounted_provider_observation_refuses_unverified_or_noncurrent_inputs_without_writing()
    -> Result<()> {
        for case in [
            Case::EqualAuthentication,
            Case::OlderAuthentication,
            Case::AuthenticationAfterIssue,
            Case::MissingAuthentication,
            Case::WrongSubject,
            Case::WrongClient,
            Case::CrossPhase,
            Case::ChangedFreshPending,
            Case::ExpiredFresh,
        ] {
            mounted_observation(case, SinkOutcome::Complete, false, false)?;
        }
        Ok(())
    }

    #[test]
    fn mounted_provider_observation_composes_registry_credentials_with_serving_oauth() -> Result<()>
    {
        mounted_observation(Case::Advance, SinkOutcome::Complete, false, true)?;
        mounted_observation(Case::Advance, SinkOutcome::Complete, true, true)
    }

    fn run(
        setup: &Setup,
        ordinal: usize,
        seed: u64,
        case: Case,
        replay: Option<Vec<SignedInput>>,
    ) -> Result<Transcript> {
        let instance = Instance::load(&setup.instance)?;
        let runtime = setup.runtime(ordinal)?;
        let database = runtime.db().to_path_buf();
        let manager = Arc::new(Manager::new(runtime, setup.authority.clone()));
        let mut receiver = setup.assertions.receiver(Arc::new(
            crate::oauth::approval_registry::UnavailableAppApprovals::new("workspace".into())?,
        ));
        receiver.authority = "app.example.com".into();
        receiver.route = route_prefix(&instance.installation, &instance.environment, "workspace")?;
        let receiver = Arc::new(receiver).with_management(manager)?;
        let world = simulation::World::new(seed);
        world.advance(95);
        // Preserve supplied values even when the receiver never consumes them.
        let replay_inputs = replay.clone();
        let port = Arc::new(Port {
            world,
            receiver,
            database,
            machine: setup.machine_assertion.clone(),
            iap_keys: setup.assertions.keys.clone(),
            provider: setup.provider.clone(),
            case,
            authorizations: Mutex::new(BTreeMap::new()),
            exchanged: Mutex::new(BTreeSet::new()),
            lose_reply: Mutex::new(None),
            reentry: Mutex::new(None),
            replay: Mutex::new(replay.map(VecDeque::from)),
            inputs: Mutex::new(Vec::new()),
            entropy_inputs: Mutex::new(Vec::new()),
            trace: Mutex::new(Vec::new()),
            fills: AtomicUsize::new(0),
            token_sends: AtomicUsize::new(0),
            secret_sends: AtomicUsize::new(0),
            external_authentication: AtomicI64::new(99),
            observation_sink: None,
            expected_credential_wall: None,
        });
        let owners = Arc::new(RemoteApprovals::from_instance(
            &instance,
            Arc::new(EdgeBearer),
        )?);
        let authenticator = || -> Result<Arc<GoogleFreshAuthenticator>> {
            let (client, exchange) = clients::reauthentication(
                &instance,
                Arc::new(crate::oauth::registration::tests::TokensSource(
                    AtomicUsize::new(0),
                )),
            )?;
            Ok(Arc::new(GoogleFreshAuthenticator::new(
                SHELL_AUDIENCE,
                "example.com",
                "https://security.example.com/",
                client,
                exchange,
                owners.clone(),
            )?))
        };
        let auth = authenticator()?;
        let mut headers = HeaderMap::new();
        headers.insert(iap::ASSERTION_HEADER, setup.human_assertion.parse()?);
        headers.insert(
            header::HOST,
            HeaderValue::from_static("security.example.com"),
        );
        let result = effects::scope(port.clone(), || -> Result<()> {
            let human = auth.identify(&headers, 100)?;
            ensure!(
                human.email == EMAIL && human.subject == GOOGLE_SUBJECT,
                "owned current IAP identity changed"
            );
            let ManagementReply::Pending { view } = owners.management(
                "workspace",
                Call::Capture {
                    registration: "calendar".into(),
                    operation: Action::Connect,
                },
                &headers,
            )?
            else {
                anyhow::bail!("owned actual app Pending missing");
            };
            let intent = FreshIntent::management(&view, &human)?;
            ensure!(
                intent.app() == "workspace" && intent.deadline() == 400,
                "owned app or original expiry changed"
            );
            let before = port.fills.load(Ordering::SeqCst);
            *port.lose_reply.lock().unwrap() = match case {
                Case::LostClaim => Some("claim"),
                Case::LostPublication => Some("publish"),
                _ => None,
            };
            let first = auth.begin(&human, intent.clone(), &headers, 100);
            let baseline_url = if matches!(case, Case::LostClaim | Case::LostPublication) {
                ensure!(
                    first.is_err(),
                    "lost app reply was treated as observed success"
                );
                let allocated = port.fills.load(Ordering::SeqCst) - before;
                ensure!(
                    allocated == if case == Case::LostClaim { 1 } else { 7 },
                    "Google tuples allocated before Claim or regenerated"
                );
                port.observe("lost_app_reply")?;
                redirect(auth.begin(&human, intent.clone(), &headers, 100)?)?
            } else {
                redirect(first?)?
            };
            ensure!(
                port.fills.load(Ordering::SeqCst) - before == 7,
                "one owner plus two tuples must allocate exactly once"
            );
            let publication = port.owner()?;
            ensure!(
                publication.0 == 1 && publication.1 == "offered" && publication.2.is_some(),
                "URL preceded committed bundle"
            );
            let public: serde_json::Value =
                crate::json::decode(publication.2.as_ref().unwrap().as_bytes())?;
            ensure!(
                public.as_object().is_some_and(|fields| fields.len() == 3
                    && fields
                        .keys()
                        .all(|key| matches!(key.as_str(), "original" | "profile" | "bundle"))),
                "app publication exposed a private tuple or token"
            );
            ensure!(
                redirect(auth.begin(&human, intent.clone(), &headers, 100)?)? == baseline_url,
                "same shell replaced original baseline URL"
            );
            ensure!(
                port.fills.load(Ordering::SeqCst) - before == 7 && port.owner()? == publication,
                "reopening replaced app publication or native bundle"
            );
            // A process restart/other shell may name an owner, but cannot adopt
            // the committed row or allocate a replacement Google tuple pair.
            let other = authenticator()?;
            let fills = port.fills.load(Ordering::SeqCst);
            ensure!(
                other.begin(&human, intent.clone(), &headers, 100).is_err(),
                "other shell adopted original"
            );
            ensure!(
                port.fills.load(Ordering::SeqCst) == fills + 1 && port.owner()? == publication,
                "other shell allocated Google tuple or changed publication"
            );
            ensure!(
                other.begin(&human, intent.clone(), &headers, 100).is_err()
                    && port.fills.load(Ordering::SeqCst) == fills + 1,
                "refused other shell renewed allocation"
            );
            port.observe("baseline_offered")?;
            let client = &instance
                .oauth_clients
                .as_ref()
                .unwrap()
                .reauthentication
                .client_id;
            let baseline_query = port.capture("baseline", &baseline_url, client)?;
            port.world.advance(1);
            if case == Case::ChangedBaselinePending {
                port.change_current_pending(&view.id)?;
            }
            if case == Case::ExpiredBaseline {
                port.world.advance(299);
            }
            if case == Case::BaselineInFlight {
                *port.reentry.lock().unwrap() = Some(Reentry::Callback {
                    auth: Arc::downgrade(&auth),
                    query: baseline_query.clone(),
                    headers: headers.clone(),
                });
            }
            let first_callback =
                auth.complete(&baseline_query, &human, &headers, port.wall_time()?);
            if matches!(
                case,
                Case::ChangedBaselinePending
                    | Case::ExpiredBaseline
                    | Case::LostBaselineExchange
                    | Case::MissingBaselineAuthentication
            ) {
                ensure!(first_callback.is_err(), "refused baseline advanced");
                let expected = usize::from(matches!(
                    case,
                    Case::LostBaselineExchange | Case::MissingBaselineAuthentication
                ));
                ensure!(
                    port.token_sends.load(Ordering::SeqCst) == expected
                        && port.secret_sends.load(Ordering::SeqCst) == expected,
                    "baseline dispatched before current Pending/expiry check"
                );
                ensure!(
                    auth.complete(&baseline_query, &human, &headers, port.wall_time()?)
                        .is_err()
                        && auth
                            .begin(&human, intent.clone(), &headers, port.wall_time()?)
                            .is_err(),
                    "refused baseline was renewed"
                );
                port.observe("baseline_refused")?;
                return Ok(());
            }
            let manual_path = if case == Case::LostBaselinePublication {
                ensure!(
                    first_callback.is_err(),
                    "lost manual publication acknowledged"
                );
                ensure!(
                    port.token_sends.load(Ordering::SeqCst) == 1,
                    "baseline unexpectedly retried"
                );
                redirect(auth.begin(&human, intent.clone(), &headers, 101)?)?
            } else {
                match first_callback? {
                    ReauthCallback::Manual(location) => location,
                    _ => anyhow::bail!("baseline bypassed manual checkpoint"),
                }
            };
            let handle = manual_path
                .strip_prefix(crate::oauth::shell_oidc::MANUAL_PREFIX)
                .context("baseline exposed Google URL before manual resume")?;
            ensure!(
                auth.complete(&baseline_query, &human, &headers, 101)
                    .is_err(),
                "baseline code replayed"
            );
            ensure!(
                redirect(auth.begin(&human, intent.clone(), &headers, 101)?)? == manual_path
                    && port.owner()? == publication
                    && port.fills.load(Ordering::SeqCst) == fills + 1,
                "manual checkpoint regenerated original baseline or bundle"
            );
            let ui = crate::oauth::security_shell::SecurityShell::with_transport(
                "https://security.example.com/".into(),
                owners.clone(),
                setup.signer.clone(),
                auth.clone(),
            )?;
            let prompt = auth.manual_view(handle, &human, &headers, 101)?;
            ensure!(
                prompt.location == manual_path && prompt.human == EMAIL && prompt.deadline == 400,
                "manual checkpoint changed original human/deadline"
            );
            ensure!(
                other.manual_view(handle, &human, &headers, 101).is_err()
                    && other
                        .resume_manual(handle, &prompt.csrf, &human, &headers, 101)
                        .is_err(),
                "different cache owner adopted manual bundle"
            );
            // Adversarial callback with the correct not-yet-offered fresh state
            // learned from the controlled entropy INPUT port. This is not a
            // native cache getter or a proof; it models a leaked browser value.
            let premature_state = port.entropy_inputs.lock().unwrap()[before + 4].clone();
            let premature_query = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("iss", "https://accounts.google.com")
                .append_pair("state", &premature_state)
                .append_pair("code", "premature-fresh-code")
                .finish();
            ensure!(
                auth.complete(&premature_query, &human, &headers, 101)
                    .is_err()
                    && port.token_sends.load(Ordering::SeqCst) == 1
                    && port.secret_sends.load(Ordering::SeqCst) == 1,
                "fresh callback was enabled before explicit manual POST"
            );
            let page = ui.dispatch(&Method::GET, &manual_path, None, &headers, &[], 101)?;
            ensure!(
                page.status() == StatusCode::OK && !page.headers().contains_key(header::SET_COOKIE),
                "manual presentation minted a session"
            );
            let executor = tokio::runtime::Builder::new_current_thread().build()?;
            let page = executor.block_on(to_bytes(page.into_body(), 16 * 1024))?;
            let page = std::str::from_utf8(&page)?;
            ensure!(
                page.contains("Complete a fresh Google sign-in")
                    && page.contains(EMAIL)
                    && page.contains(&prompt.csrf)
                    && page.contains(&manual_path)
                    && !page.contains("o/oauth2/v2/auth"),
                "manual page missing bound form or exposing fresh URL"
            );
            let csrf = prompt.csrf;
            let mut post = headers.clone();
            post.insert(
                header::ORIGIN,
                HeaderValue::from_static("https://security.example.com"),
            );
            post.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
            post.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
            let body = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("csrf", &csrf)
                .finish();
            let before_negative = simulation::snapshot(&crate::store::open(&port.database)?)?;
            for invalid in [
                String::new(),
                "csrf=wrong".into(),
                format!("csrf={}", "A".repeat(43)),
                format!("csrf={handle}"),
                format!("{body}&extra=ignored"),
                format!("{body}&{body}"),
            ] {
                ensure!(
                    ui.dispatch(
                        &Method::POST,
                        &manual_path,
                        None,
                        &post,
                        invalid.as_bytes(),
                        101
                    )
                    .is_err(),
                    "manual form accepted missing/unknown/duplicate/wrong CSRF"
                );
            }
            for header_name in [header::ORIGIN, header::CONTENT_TYPE] {
                let mut wrong = post.clone();
                wrong.remove(&header_name);
                ensure!(
                    ui.dispatch(
                        &Method::POST,
                        &manual_path,
                        None,
                        &wrong,
                        body.as_bytes(),
                        101
                    )
                    .is_err(),
                    "manual form accepted missing origin/type"
                );
                wrong.insert(
                    header_name.clone(),
                    HeaderValue::from_static("https://foreign.example"),
                );
                ensure!(
                    ui.dispatch(
                        &Method::POST,
                        &manual_path,
                        None,
                        &wrong,
                        body.as_bytes(),
                        101
                    )
                    .is_err(),
                    "manual form accepted foreign origin/type"
                );
                let mut duplicate = post.clone();
                duplicate.append(header_name.clone(), post[&header_name].clone());
                ensure!(
                    ui.dispatch(
                        &Method::POST,
                        &manual_path,
                        None,
                        &duplicate,
                        body.as_bytes(),
                        101
                    )
                    .is_err(),
                    "manual form accepted duplicate origin/type"
                );
            }
            let mut cross_site = post.clone();
            cross_site.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
            ensure!(
                ui.dispatch(
                    &Method::POST,
                    &manual_path,
                    None,
                    &cross_site,
                    body.as_bytes(),
                    101
                )
                .is_err()
                    && ui
                        .dispatch(
                            &Method::PUT,
                            &manual_path,
                            None,
                            &post,
                            body.as_bytes(),
                            101
                        )
                        .is_err()
                    && ui
                        .dispatch(
                            &Method::GET,
                            &manual_path,
                            Some("extra=1"),
                            &headers,
                            &[],
                            101
                        )
                        .is_err()
                    && ui
                        .dispatch(&Method::GET, &manual_path, None, &headers, b"body", 101)
                        .is_err(),
                "manual route accepted cross-site/method/query/body input"
            );
            let mut foreign = human.clone();
            foreign.subject = "accounts.google.com:another".into();
            ensure!(
                auth.manual_view(handle, &foreign, &headers, 101).is_err()
                    && auth
                        .resume_manual(handle, &csrf, &foreign, &post, 101)
                        .is_err(),
                "manual checkpoint changed current subject"
            );
            ensure!(
                port.token_sends.load(Ordering::SeqCst) == 1
                    && port.secret_sends.load(Ordering::SeqCst) == 1
                    && port.fills.load(Ordering::SeqCst) == fills + 1
                    && port.owner()? == publication
                    && simulation::snapshot(&crate::store::open(&port.database)?)?
                        == before_negative,
                "invalid manual request dispatched a provider, replaced a bundle or changed SQLite"
            );
            ensure!(
                auth.manual_view(handle, &human, &headers, 101)?.csrf == csrf,
                "wrong CSRF consumed or replaced original manual authority"
            );
            port.observe("manual_checkpoint")?;
            if matches!(case, Case::ExpiredManual | Case::ChangedManualPending) {
                if case == Case::ExpiredManual {
                    port.world.advance(299);
                } else {
                    port.change_current_pending(&view.id)?;
                }
                ensure!(
                    auth.manual_view(handle, &human, &headers, port.wall_time()?)
                        .is_err()
                        && ui
                            .dispatch(
                                &Method::POST,
                                &manual_path,
                                None,
                                &post,
                                body.as_bytes(),
                                port.wall_time()?
                            )
                            .is_err()
                        && port.token_sends.load(Ordering::SeqCst) == 1
                        && port.secret_sends.load(Ordering::SeqCst) == 1
                        && port.owner()? == publication,
                    "manual checkpoint ignored actual current Pending/expiry"
                );
                port.observe("manual_refused")?;
                return Ok(());
            }
            // Independent provider EVENT, separate from the user's Continue.
            // The server and POST never change this fixture issuer timeline.
            port.world.advance(2);
            if case != Case::ContinueWithoutLogin {
                port.external_authentication.store(102, Ordering::SeqCst);
                port.trace
                    .lock()
                    .unwrap()
                    .push(json!({"external_google_authentication":102}));
            }
            if case == Case::LostManualPublication {
                *port.lose_reply.lock().unwrap() = Some("publish");
            }
            if case == Case::ManualInFlight {
                *port.reentry.lock().unwrap() = Some(Reentry::Manual {
                    auth: Arc::downgrade(&auth),
                    handle: handle.into(),
                    csrf: csrf.clone(),
                    headers: post.clone(),
                });
            }
            let first_resume = ui.dispatch(
                &Method::POST,
                &manual_path,
                None,
                &post,
                body.as_bytes(),
                103,
            );
            let resume = if case == Case::LostManualPublication {
                ensure!(
                    first_resume.is_err(),
                    "lost manual publication reply treated as acknowledged"
                );
                ensure!(
                    auth.complete(&premature_query, &human, &headers, 103)
                        .is_err()
                        && port.token_sends.load(Ordering::SeqCst) == 1,
                    "unknown manual publication enabled the fresh callback"
                );
                ui.dispatch(
                    &Method::POST,
                    &manual_path,
                    None,
                    &post,
                    body.as_bytes(),
                    103,
                )?
            } else {
                first_resume?
            };
            ensure!(
                case != Case::ManualInFlight || port.reentry.lock().unwrap().is_none(),
                "manual in-flight callback control was not exercised"
            );
            ensure!(
                resume.status() == StatusCode::SEE_OTHER
                    && !resume.headers().contains_key(header::SET_COOKIE),
                "manual resume minted a session"
            );
            let fresh_url = resume.headers()[header::LOCATION].to_str()?.to_owned();
            drop(resume); // Lost 303 reconciliation must retain exactly this URL.
            let repeated = ui.dispatch(
                &Method::POST,
                &manual_path,
                None,
                &post,
                body.as_bytes(),
                103,
            )?;
            ensure!(
                repeated.headers()[header::LOCATION].to_str()? == fresh_url
                    && redirect(auth.begin(&human, intent.clone(), &headers, 103)?)? == manual_path
                    && port.owner()? == publication
                    && port.fills.load(Ordering::SeqCst) == fills + 1
                    && port.token_sends.load(Ordering::SeqCst) == 1,
                "manual POST/reopen renewed original or auto-exchanged code"
            );
            port.observe("fresh_offered_after_explicit_continue")?;
            let fresh_query = port.capture("fresh", &fresh_url, client)?;
            if case == Case::ChangedFreshPending {
                port.change_current_pending(&view.id)?;
            }
            if case == Case::ExpiredFresh {
                port.world.advance(297);
            }
            if case == Case::FreshInFlight {
                *port.reentry.lock().unwrap() = Some(Reentry::Callback {
                    auth: Arc::downgrade(&auth),
                    query: fresh_query.clone(),
                    headers: headers.clone(),
                });
            }
            let submitted = if case == Case::CrossPhaseCode {
                let mut query = url::form_urlencoded::Serializer::new(String::new());
                for (name, value) in url::form_urlencoded::parse(fresh_query.as_bytes()) {
                    query.append_pair(
                        &name,
                        if name == "code" {
                            "owned-baseline-code"
                        } else {
                            value.as_ref()
                        },
                    );
                }
                query.finish()
            } else {
                fresh_query.clone()
            };
            let second_callback = auth.complete(&submitted, &human, &headers, port.wall_time()?);
            if matches!(case, Case::ChangedFreshPending | Case::ExpiredFresh) {
                ensure!(
                    second_callback.is_err()
                        && port.token_sends.load(Ordering::SeqCst) == 1
                        && port.secret_sends.load(Ordering::SeqCst) == 1,
                    "fresh exchange preceded current Pending/expiry check"
                );
            } else if case == Case::LostFreshExchange || !case.accepts_second_token() {
                ensure!(
                    second_callback.is_err() && port.token_sends.load(Ordering::SeqCst) == 2,
                    "issuer-event policy or dispatch ambiguity accepted"
                );
            } else {
                let ReauthCallback::Observed(observed) = second_callback? else {
                    anyhow::bail!("second callback did not finish observations");
                };
                let (baseline_iat, authenticated_at, original, _, request) = observed
                    .owned_ordering_data()
                    .context("actual two-token ordering absent")?;
                ensure!(
                    baseline_iat == 101
                        && authenticated_at == 102
                        && original == intent.commitment()?
                        && request == Digest::new(publication.2.as_ref().unwrap().as_bytes())
                        && observed.deadline()? == 400,
                    "original Google bundle or lifetime changed"
                );
                ensure!(
                    observed.require_post_pending_authentication().is_err(),
                    "DATA ordering bypassed missing lifetime/role/epoch/final-CAS producer"
                );
                let snapshot = simulation::snapshot(&crate::store::open(&port.database)?)?;
                let fills = port.fills.load(Ordering::SeqCst);
                let management = crate::oauth::management::shell::Shell::new(
                    "https://security.example.com".into(),
                    owners.clone(),
                    setup.signer.clone(),
                    auth.clone(),
                );
                let error = management
                    .reauthenticated(
                        crate::oauth::fresh_auth::VerifiedAuthTime::from_google(*observed),
                        &headers,
                        &human,
                        port.wall_time()?,
                    )
                    .err()
                    .context("ordered DATA allocated a management cookie")?;
                ensure!(
                    error.root_cause().to_string()
                        == "OAuth post-pending authentication producer unavailable"
                        && port.fills.load(Ordering::SeqCst) == fills
                        && simulation::snapshot(&crate::store::open(&port.database)?)? == snapshot
                        && port.owner()? == publication,
                    "management refusal changed cookie entropy or app SQLite"
                );
                port.trace.lock().unwrap().push(
                    json!({"event":"ordered_observation_only","baseline_iat":baseline_iat,
                    "authenticated_at":authenticated_at,"original":original,"publication":request}),
                );
            }
            let sends = port.token_sends.load(Ordering::SeqCst);
            ensure!(
                auth.complete(&fresh_query, &human, &headers, port.wall_time()?)
                    .is_err()
                    && auth
                        .complete(&baseline_query, &human, &headers, port.wall_time()?)
                        .is_err()
                    && auth
                        .begin(&human, intent, &headers, port.wall_time()?)
                        .is_err()
                    && auth
                        .manual_view(handle, &human, &headers, port.wall_time()?)
                        .is_err()
                    && ui
                        .dispatch(
                            &Method::POST,
                            &manual_path,
                            None,
                            &post,
                            body.as_bytes(),
                            port.wall_time()?
                        )
                        .is_err()
                    && port.token_sends.load(Ordering::SeqCst) == sends,
                "terminal callback/manual route reopened or replayed"
            );
            ensure!(
                port.owner()? == publication,
                "observation fabricated app completion"
            );
            port.observe("terminal")?;
            Ok(())
        });
        // Apply the unchanged oracle to EVERY successful scope return,
        // including expected baseline/manual refusals that return early.
        let result = result.and_then(|()| {
            ensure!(
                port.replay
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_none_or(VecDeque::is_empty),
                "owned signed replay inputs unused"
            );
            Ok(())
        });
        if let Err(error) = result {
            let trace = port.trace.lock().unwrap().clone();
            let inputs = port.inputs.lock().unwrap().clone();
            retain(
                setup,
                seed,
                case,
                &trace,
                &inputs,
                replay_inputs.as_deref(),
                Some(error.to_string()),
            )?;
            return Err(error.context(format!("owned Google campaign {case:?}, seed {seed}")));
        }
        let events = port.trace.lock().unwrap().clone();
        let inputs = port.inputs.lock().unwrap().clone();
        Ok(Transcript { events, inputs })
    }

    fn retain(
        setup: &Setup,
        seed: u64,
        case: Case,
        trace: &[serde_json::Value],
        inputs: &[SignedInput],
        replay_inputs: Option<&[SignedInput]>,
        error: Option<String>,
    ) -> Result<()> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
        let root = &setup.retention_root;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)?;
        let directory = tempfile::Builder::new()
            .prefix("campaign-")
            .tempdir_in(root)?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let record = json!({"version":2,"seed":seed,"case":case,"error":error,"trace":trace,
            "signed_provider_inputs":inputs,"replay_provider_inputs":replay_inputs,"artifact":setup.artifact.id(),
            "instance":Digest::new(&std::fs::read(&setup.instance)?),
            "source":Digest::of(&(include_str!("shell_oidc.rs"),include_str!("google_begin.rs"),
                include_str!("fresh_owner.rs"),include_str!("shell_transport.rs"),include_str!("shell_transport_tests.rs"),
                include_str!("simulation_sources.rs"),include_str!("../../../../Cargo.lock")))?,
            "iap_inputs":{"keys":setup.assertions.keys,"human":setup.human_assertion,"machine":setup.machine_assertion},
            "scope":"synthetic provider inputs, actual receiver/verifiers/SQLite; no native or hosted readiness"});
        let path = directory.path().join("replay.json");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&serde_json::to_vec(&record)?)?;
        file.sync_all()?;
        std::fs::File::open(directory.path())?.sync_all()?;
        let _retained = directory.keep();
        std::fs::File::open(root)?.sync_all()?;
        Ok(())
    }

    #[test]
    fn unused_signed_replay_inputs_retain_terminal_and_early_counterexamples() -> Result<()> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let controls = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../artifacts/oauth-owned-google-retention-control");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&controls)?;
        for case in [Case::Advance, Case::ExpiredManual] {
            let mut setup = Setup::new()?;
            let directory = tempfile::Builder::new()
                .prefix("counterexample-")
                .tempdir_in(&controls)?;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
            // Preserve each expected failure outside the 54 positive histories.
            setup.retention_root = directory.keep();
            std::fs::File::open(&controls)?.sync_all()?;
            let first = run(&setup, 0, 7, case, None)?;
            let extra = first
                .inputs
                .last()
                .context("signed replay fixture is empty")?
                .clone();
            let mut supplied = first.inputs.clone();
            supplied.push(extra);
            let error = run(&setup, 1, 7, case, Some(supplied.clone()))
                .err()
                .context("unused signed replay input must refuse")?;
            ensure!(
                error.root_cause().to_string() == "owned signed replay inputs unused",
                "counterexample failed before the unchanged unused-input oracle"
            );
            let retained =
                std::fs::read_dir(&setup.retention_root)?.collect::<std::io::Result<Vec<_>>>()?;
            ensure!(
                retained.len() == 1,
                "unused-input failure was not retained exactly once"
            );
            let directory = retained[0].path();
            let metadata = std::fs::symlink_metadata(&directory)?;
            ensure!(
                metadata.is_dir() && metadata.permissions().mode() & 0o7777 == 0o700,
                "counterexample directory is not private"
            );
            let path = directory.join("replay.json");
            let metadata = std::fs::symlink_metadata(&path)?;
            ensure!(
                metadata.is_file() && metadata.permissions().mode() & 0o7777 == 0o600,
                "counterexample file is not private"
            );
            let record: serde_json::Value = crate::json::decode(&std::fs::read(path)?)?;
            ensure!(
                record["version"] == 2
                    && record["seed"] == 7
                    && record["case"] == serde_json::to_value(case)?
                    && record["error"] == "owned signed replay inputs unused",
                "persisted counterexample lost its exact failure or case"
            );
            ensure!(
                record["signed_provider_inputs"] == serde_json::to_value(&first.inputs)?
                    && record["replay_provider_inputs"] == serde_json::to_value(&supplied)?
                    && record["trace"] == serde_json::to_value(&first.events)?,
                "persisted counterexample omitted raw supplied input or actual observations"
            );
        }
        Ok(())
    }

    #[test]
    fn owned_google_two_phase_receiver_sqlite_faults_and_signed_input_replay() -> Result<()> {
        let setup = Setup::new()?;
        let mut ordinal = 0;
        for seed in [7, 41] {
            for case in [
                Case::Advance,
                Case::IssuerAlias,
                Case::ContinueWithoutLogin,
                Case::ExpiredManual,
                Case::ChangedManualPending,
                Case::LostManualPublication,
                Case::ManualInFlight,
                Case::LostClaim,
                Case::LostPublication,
                Case::LostBaselinePublication,
                Case::BaselineInFlight,
                Case::FreshInFlight,
                Case::LostBaselineExchange,
                Case::LostFreshExchange,
                Case::ChangedBaselinePending,
                Case::ChangedFreshPending,
                Case::ExpiredBaseline,
                Case::ExpiredFresh,
                Case::EqualAuthentication,
                Case::OlderAuthentication,
                Case::AuthenticationAfterIssue,
                Case::MissingAuthentication,
                Case::MissingBaselineAuthentication,
                Case::WrongSubject,
                Case::WrongClient,
                Case::CrossPhase,
                Case::CrossPhaseCode,
            ] {
                let first = run(&setup, ordinal, seed, case, None)?;
                ordinal += 1;
                // A fresh SQLite database and process-local cache consume the
                // exact signed inputs, not regenerated signing randomness.
                let replay = run(&setup, ordinal, seed, case, Some(first.inputs.clone()))?;
                ordinal += 1;
                if first != replay {
                    retain(
                        &setup,
                        seed,
                        case,
                        &first.events,
                        &first.inputs,
                        None,
                        Some("semantic replay divergence".into()),
                    )?;
                    retain(
                        &setup,
                        seed,
                        case,
                        &replay.events,
                        &replay.inputs,
                        Some(first.inputs.as_slice()),
                        Some("replay observation".into()),
                    )?;
                    anyhow::bail!("owned Google replay diverged for {case:?}, seed {seed}");
                }
                retain(&setup, seed, case, &first.events, &first.inputs, None, None)?;
            }
        }
        Ok(())
    }
}
