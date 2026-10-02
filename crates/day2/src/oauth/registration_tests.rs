//! Real HTTP fixtures and an independent campaign-order model. Fixture
//! credentials never establish live Google or installation readiness.

use super::*;
use crate::oauth::admission::OutboundReadiness;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use day2_capabilities::oauth::{
    AccountBindingPolicy, ConnectionOwner, ProductReturnRef, SecurityOriginRef, SlotOwner,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    io::Write,
    net::TcpListener,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};

const ACTIONS: [&str; 9] = [
    "oauth-registration-open",
    "oauth-registration-reject-pkce",
    "oauth-registration-verify-pkce",
    "oauth-registration-reject-credential",
    "oauth-registration-exchange",
    "oauth-registration-account",
    "oauth-registration-refresh",
    "oauth-registration-refresh-account",
    "oauth-registration-seal",
];
const CODE_CANARY: &str = "private-fixture-code-canary";
const SECRET_CANARY: &str = "private-fixture-client-canary";
const ACCESS_CANARY: &str = "private-fixture-access-canary";
const REFRESH_CANARY: &str = "private-fixture-refresh-canary";

fn pin(name: &str) -> BindingRef {
    BindingRef::pin(Name::try_from(name.to_owned()).unwrap(), &name).unwrap()
}

pub(in crate::oauth) struct TokensSource(pub(in crate::oauth) AtomicUsize);

impl approval_keys::AccessTokenSource for TokensSource {
    fn access_token(&self) -> Result<String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok("private-fixture-workload-token".into())
    }
}

pub(super) struct Fixture {
    pub(super) target: Target,
    pub(super) binding: OutboundConnectionBinding,
    pub(super) slot: ConnectionSlotKey,
    pub(super) evidence: profiles::OutboundInstanceEvidence,
}

pub(super) fn fixture() -> Result<Fixture> {
    let instance = pin("company_instance");
    let origin_url = "https://security.example.com/".to_owned();
    let qualification = Digest::of(&"fixture-independent-shell-qualification")?;
    let shell = profiles::SecurityShellEvidence {
        instance: instance.clone(),
        origin_url: origin_url.clone(),
        origin: SecurityOriginRef(BindingRef {
            id: Name::try_from("shell".to_owned())?,
            revision: Digest::of(&(
                "oauth-security-shell-evidence-v1",
                &instance,
                &origin_url,
                &qualification,
            ))?,
        }),
        qualification,
    };
    let requirement = ConnectionRequirement {
        logical_id: "work_calendar".into(),
        revision: 1,
        capability: google::CAPABILITY.into(),
        actions: BTreeSet::from(["list_events".into()]),
        owner: ConnectionOwner::CurrentHuman,
        account_policy: AccountBindingPolicy::ExplicitExternalAccount,
        usage: "Read work calendar availability.".into(),
    };
    let mut binding = OutboundConnectionBinding {
        namespace: day2_capabilities::credentials::Namespace {
            installation: Name::try_from("company".to_owned())?,
            environment: Name::try_from("production".to_owned())?,
            app: Name::try_from("workspace".to_owned())?,
            binding_generation: 1,
        },
        requirement: requirement.nominal_identity()?,
        profile: google::reviewed(&requirement.account_policy)?
            .profile
            .protocol
            .identity()
            .binding
            .clone(),
        registration: pin("calendar_registration"),
        custody: pin("custody"),
        security_shell: shell.origin.clone(),
        account_binding: pin("approval"),
        shell_attestation: pin("approval"),
        product_return: ProductReturnRef(pin("product_return")),
        custody_verifier_secret: Name::try_from("verifier".to_owned())?,
        custody_encryption_secret: Name::try_from("encryption".to_owned())?,
        shell_attestation_secret: Name::try_from("attestation".to_owned())?,
    };
    let target = Target::new(
        &requirement,
        instance.clone(),
        admission::binding_namespace(&binding)?,
        shell.clone(),
        ClientSelection {
            registration: binding.registration.id.clone(),
            client_id: "12345-fixture.apps.googleusercontent.com".into(),
            secret: serde_json::from_value(
                json!({"kind":"gcp_version","project_number":12345,"secret":"google_client_secret","version":7}),
            )?,
            canary_subject: "google-canary-subject".into(),
            canary_tenant: "example.com".into(),
        },
    )?;
    binding.registration = target.registration_evidence()?.registration;
    let constraints = profiles::ExternalAccountConstraints {
        binding: pin("constraints"),
        issuer_url: google::ISSUER.into(),
        allowed_tenants: BTreeSet::from(["example.com".into()]),
        allowed_subjects: None,
    };
    let evidence = profiles::OutboundInstanceEvidence {
        instance: instance.clone(),
        binding_namespace: target.namespace.clone(),
        app_origin_url: "https://workspace.example.com/".into(),
        shell,
        registration: target.registration_evidence()?,
        custody: binding.custody.clone(),
        account: profiles::AccountBindingEvidence::ExplicitExternal {
            instance,
            approval: binding.account_binding.clone(),
            constraints,
            owner: "human@example.com".into(),
        },
        product_return: binding.product_return.clone(),
    };
    let slot = ConnectionSlotKey {
        installation: binding.namespace.installation.clone(),
        environment: binding.namespace.environment.clone(),
        app: binding.namespace.app.clone(),
        requirement: requirement.logical_id,
        owner: SlotOwner::Human {
            subject: "human@example.com".into(),
        },
    };
    Ok(Fixture {
        target,
        binding,
        slot,
        evidence,
    })
}

pub(in crate::oauth) fn secret_response() -> Value {
    json!({"name":"projects/12345/secrets/google_client_secret/versions/7", "payload":{
        "data":STANDARD.encode(SECRET_CANARY), "dataCrc32c":crc32c::crc32c(SECRET_CANARY.as_bytes()).to_string(),
    }})
}

fn token_response(refresh: bool) -> Value {
    let mut response = json!({"access_token":ACCESS_CANARY,"token_type":"Bearer","expires_in":3600,
        "scope":"openid email https://www.googleapis.com/auth/calendar.events.readonly", "id_token":"private-fixture-id-token"});
    if !refresh {
        response["refresh_token"] = json!(REFRESH_CANARY);
    }
    response
}

fn account_response() -> Value {
    json!({"sub":"google-canary-subject","hd":"example.com","email":"display@example.net","email_verified":true,"name":"Display only"})
}

pub(super) fn responses() -> Vec<(u16, String)> {
    vec![
        (200, secret_response()),
        (400, json!({"error":"invalid_grant"})),
        (200, token_response(false)),
        (401, json!({"error":"invalid_client"})),
        (200, token_response(false)),
        (200, account_response()),
        (200, token_response(true)),
        (200, account_response()),
        (200, secret_response()),
    ]
    .into_iter()
    .map(|(status, body)| (status, body.to_string()))
    .collect()
}

pub(in crate::oauth) struct Server {
    pub(in crate::oauth) endpoint: String,
    pub(in crate::oauth) requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Server {
    pub(in crate::oauth) fn new(responses: Vec<(u16, String)>) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let endpoint = format!("http://{}/", listener.local_addr()?);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (recorded, stopping) = (requests.clone(), stop.clone());
        let worker = thread::spawn(move || {
            for (status, body) in responses {
                let mut stream = loop {
                    if stopping.load(Ordering::SeqCst) {
                        return;
                    }
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1))
                        }
                        Err(error) => panic!("fixture accept: {error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    bytes.push(byte[0]);
                    assert!(bytes.len() < 16_384);
                }
                let headers = String::from_utf8(bytes.clone()).unwrap();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(|value| value.parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                let mut payload = vec![0; length];
                stream.read_exact(&mut payload).unwrap();
                bytes.extend(payload);
                recorded
                    .lock()
                    .unwrap()
                    .push(String::from_utf8(bytes).unwrap());
                if status == 0 {
                    continue;
                }
                write!(stream, "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        Ok(Self {
            endpoint,
            requests,
            stop,
            worker: Some(worker),
        })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn session(target: Target, server: &Server) -> Result<Session> {
    let identity = Digest::of(&target.description())?;
    let code = |raw: &str, purpose| Code {
        code: raw.into(),
        verifier: "v".repeat(43),
        target: identity.clone(),
        purpose,
        session: Digest::of(&"verified-shell-session").unwrap(),
        deadline: Instant::now() + Duration::from_secs(VALID_SECONDS as u64),
    };
    let codes = Codes {
        positive: code(CODE_CANARY, Purpose::Positive),
        reject_pkce: code("negative-pkce-code", Purpose::RejectPkce),
        reject_credential: code("negative-credential-code", Purpose::RejectCredential),
    };
    Session::at(
        target,
        codes,
        Wire::fixture(&server.endpoint)?,
        approval_keys::GcpSecretReader::fixture(
            &server.endpoint,
            Arc::new(TokensSource(AtomicUsize::new(0))),
        )?,
    )
}

fn request(action: &str) -> crate::automation::Request {
    crate::automation::Request {
        protocol: 1,
        action: action.into(),
        input: "{}".into(),
    }
}

fn campaign(session: &mut Session) -> Result<()> {
    for action in ACTIONS {
        let output = session.call(request(action))?;
        assert_eq!(output, json!({}));
        for secret in [CODE_CANARY, SECRET_CANARY, ACCESS_CANARY, REFRESH_CANARY] {
            assert!(!output.to_string().contains(secret));
        }
    }
    Ok(())
}

#[test]
fn live_wire_campaign_pins_client_callback_pkce_account_refresh_and_secret_version() -> Result<()> {
    let fixture = fixture()?;
    let callback = fixture.target.callback_url.clone();
    assert_eq!(fixture.target.description()["callback_url"], callback);
    assert_ne!(Url::parse(&callback)?.path(), "/_day2/reauth/callback");
    let server = Server::new(responses())?;
    let mut session = session(fixture.target, &server)?;
    campaign(&mut session)?;
    let receipt = session.finish()?;
    assert_eq!(receipt.registration(), &fixture.evidence.registration);
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 9);
    for index in [0, 8] {
        assert!(requests[index].starts_with(
            "GET /v1/projects/12345/secrets/google_client_secret/versions/7:access HTTP/1.1\r\n"
        ));
        assert!(
            requests[index]
                .to_ascii_lowercase()
                .contains("authorization: bearer private-fixture-workload-token")
        );
    }
    for index in [4, 6] {
        assert!(requests[index].starts_with("POST /token HTTP/1.1\r\n"));
        let (_, form) = requests[index].split_once("\r\n\r\n").unwrap();
        let form: BTreeMap<_, _> = url::form_urlencoded::parse(form.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(
            form["client_id"],
            "12345-fixture.apps.googleusercontent.com"
        );
        assert_eq!(form["client_secret"], SECRET_CANARY);
        if index == 4 {
            assert_eq!(form["grant_type"], "authorization_code");
            assert_eq!(form["redirect_uri"], callback);
            assert_eq!(form["code"], CODE_CANARY);
            assert_eq!(form["code_verifier"], "v".repeat(43));
        } else {
            assert_eq!(form["grant_type"], "refresh_token");
            assert_eq!(form["refresh_token"], REFRESH_CANARY);
            assert!(!form.contains_key("code"));
        }
    }
    for (index, wrong_verifier) in [(1, true), (3, false)] {
        let (_, form) = requests[index].split_once("\r\n\r\n").unwrap();
        let form: BTreeMap<_, _> = url::form_urlencoded::parse(form.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(form["redirect_uri"], callback);
        assert_eq!(
            form["client_id"],
            "12345-fixture.apps.googleusercontent.com"
        );
        if wrong_verifier {
            assert_ne!(form["code_verifier"], "v".repeat(43));
            assert_eq!(form["client_secret"], SECRET_CANARY);
        } else {
            assert_eq!(form["code_verifier"], "v".repeat(43));
            assert!(!form.contains_key("client_secret"));
        }
    }
    let form = |index: usize| {
        let (_, form) = requests[index].split_once("\r\n\r\n").unwrap();
        url::form_urlencoded::parse(form.as_bytes())
            .into_owned()
            .collect::<BTreeMap<_, _>>()
    };
    let wrong = form(1);
    let corrected = form(2);
    assert_eq!(corrected["code"], wrong["code"]);
    assert_eq!(corrected["client_secret"], wrong["client_secret"]);
    assert_eq!(corrected["redirect_uri"], wrong["redirect_uri"]);
    assert_ne!(corrected["code_verifier"], wrong["code_verifier"]);
    for index in [5, 7] {
        assert!(requests[index].starts_with("GET /userinfo HTTP/1.1\r\n"));
        assert!(
            requests[index]
                .to_ascii_lowercase()
                .contains(&format!("authorization: bearer {ACCESS_CANARY}"))
        );
    }
    Ok(())
}

#[test]
fn google_errors_response_loss_wrong_account_scopes_and_rotation_never_seal_or_retry() -> Result<()>
{
    let mut cases = Vec::new();
    for index in [2, 4, 6] {
        for status in [0, 302, 400, 401, 500] {
            let mut replies = responses();
            replies[index] = (
                status,
                json!({"error":"invalid_grant","error_description":SECRET_CANARY}).to_string(),
            );
            cases.push((index, replies));
        }
        for field in ["scope", "token_type", "expires_in", "access_token"] {
            let mut value = token_response(index == 6);
            value[field] = match field {
                "scope" => json!("openid email https://www.googleapis.com/auth/calendar"),
                "token_type" => json!("Basic"),
                "expires_in" => json!(0),
                _ => json!("unsafe\r\nvalue"),
            };
            let mut replies = responses();
            replies[index].1 = value.to_string();
            cases.push((index, replies));
        }
    }
    for index in [5, 7] {
        for field in ["sub", "hd", "email_verified"] {
            let mut value = account_response();
            value[field] = if field == "email_verified" {
                json!(false)
            } else {
                json!("wrong")
            };
            let mut replies = responses();
            replies[index].1 = value.to_string();
            cases.push((index, replies));
        }
    }
    let mut replies = responses();
    let mut value = token_response(false);
    value.as_object_mut().unwrap().remove("refresh_token");
    replies[4].1 = value.to_string();
    cases.push((4, replies));
    let mut replies = responses();
    let mut value = token_response(true);
    value["refresh_token"] = json!("unexpected-rotation");
    replies[6].1 = value.to_string();
    cases.push((6, replies));
    let mut replies = responses();
    replies[4].1 =
        format!("{{\"access_token\":\"{ACCESS_CANARY}\",\"access_token\":\"duplicate\"}}");
    cases.push((4, replies));
    let mut replies = responses();
    replies[8] = (403, json!({"error":SECRET_CANARY}).to_string());
    cases.push((8, replies));
    for index in [1, 3] {
        for (status, body) in [
            (200, token_response(false)),
            (500, json!({"error":"invalid_grant"})),
            (400, json!({"error":"unrelated_failure"})),
            (
                400,
                json!({"error":"invalid_grant", "access_token":ACCESS_CANARY}),
            ),
        ] {
            let mut replies = responses();
            replies[index] = (status, body.to_string());
            cases.push((index, replies));
        }
    }
    for (failed_index, replies) in cases {
        let server = Server::new(replies)?;
        let mut session = session(fixture()?.target, &server)?;
        for action in &ACTIONS[..failed_index] {
            session.call(request(action))?;
        }
        let error = session.call(request(ACTIONS[failed_index])).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Google registration qualification failed; start a new canary"
        );
        for secret in [CODE_CANARY, SECRET_CANARY, ACCESS_CANARY, REFRESH_CANARY] {
            assert!(!format!("{error:#}").contains(secret));
        }
        let count = server.requests.lock().unwrap().len();
        assert_eq!(count, failed_index + 1);
        for action in ACTIONS {
            assert!(session.call(request(action)).is_err());
        }
        assert_eq!(server.requests.lock().unwrap().len(), count);
        assert!(session.finish().is_err());
    }
    Ok(())
}

#[test]
fn exact_secret_version_name_checksum_and_payload_gate_before_provider_io() -> Result<()> {
    for mutate in 0..6 {
        let mut value = secret_response();
        match mutate {
            0 => {
                value["name"] = json!("projects/12345/secrets/google_client_secret/versions/latest")
            }
            1 => value["name"] = json!("projects/12345/secrets/other/versions/7"),
            2 => value["payload"]["dataCrc32c"] = json!("0"),
            3 => value["payload"]["data"] = json!("invalid-base64"),
            4 => {
                value["payload"]["data"] = json!(STANDARD.encode("unsafe\r\n"));
                value["payload"]["dataCrc32c"] = json!(crc32c::crc32c(b"unsafe\r\n").to_string());
            }
            5 => {
                value["payload"]["data"] = json!(STANDARD.encode([0xff]));
                value["payload"]["dataCrc32c"] = json!(crc32c::crc32c(&[0xff]).to_string());
            }
            _ => unreachable!(),
        }
        let server = Server::new(vec![(200, value.to_string())])?;
        let mut session = session(fixture()?.target, &server)?;
        assert!(session.call(request(ACTIONS[0])).is_err());
        assert!(session.call(request(ACTIONS[1])).is_err());
        assert_eq!(server.requests.lock().unwrap().len(), 1);
    }
    Ok(())
}

struct Facts {
    evidence: profiles::OutboundInstanceEvidence,
    calls: AtomicUsize,
}

impl OutboundReadiness for Facts {
    fn current(
        &self,
        _: &OutboundConnectionBinding,
        _: &ConnectionSlotKey,
        _: i64,
    ) -> Result<Option<profiles::OutboundInstanceEvidence>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(self.evidence.clone()))
    }
}

#[test]
fn readiness_requires_live_receipt_exact_selection_freshness_and_independent_facts() -> Result<()> {
    let fixture = fixture()?;
    let facts = Arc::new(Facts {
        evidence: fixture.evidence.clone(),
        calls: AtomicUsize::new(0),
    });
    let readiness = GoogleReadiness::new(facts.clone());
    let server = Server::new(responses())?;
    let mut session = session(fixture.target, &server)?;
    campaign(&mut session)?;
    let receipt = session.finish()?;
    let now = receipt.checked_at;
    assert!(
        readiness
            .current(&fixture.binding, &fixture.slot, now)?
            .is_none()
    );
    assert_eq!(facts.calls.load(Ordering::SeqCst), 0);
    readiness.publish(receipt)?;
    assert_eq!(
        readiness.current(&fixture.binding, &fixture.slot, now)?,
        Some(fixture.evidence.clone())
    );
    let count = facts.calls.load(Ordering::SeqCst);
    for candidate in 0..8 {
        let mut binding = fixture.binding.clone();
        let mut slot = fixture.slot.clone();
        let time = match candidate {
            0 => now - 1,
            1 => now + VALID_SECONDS,
            2 => {
                binding.registration.revision = Digest::of(&"other-registration")?;
                now
            }
            3 => {
                binding.profile.revision = Digest::of(&"other-profile")?;
                now
            }
            4 => {
                binding.requirement = Digest::of(&"other-requirement")?;
                now
            }
            5 => {
                slot.app = Name::try_from("other_app".to_owned())?;
                now
            }
            6 => {
                slot.requirement = "other_requirement".into();
                now
            }
            7 => {
                binding.namespace.binding_generation += 1;
                now
            }
            _ => unreachable!(),
        };
        assert!(readiness.current(&binding, &slot, time)?.is_none());
    }
    assert_eq!(facts.calls.load(Ordering::SeqCst), count);
    readiness.retire(&fixture.binding.registration.id)?;
    assert!(
        readiness
            .current(&fixture.binding, &fixture.slot, now)?
            .is_none()
    );
    assert!(
        GoogleReadiness::new(facts.clone())
            .current(&fixture.binding, &fixture.slot, now)?
            .is_none()
    );
    crate::oauth::host::Providers::google(Arc::new(readiness))?;
    Ok(())
}

#[test]
fn independent_order_model_rejects_every_skip_replay_and_workflow_argument_before_io() -> Result<()>
{
    for (prefix, expected) in ACTIONS.iter().enumerate() {
        for (offered, action) in ACTIONS.iter().enumerate() {
            if offered == prefix {
                continue;
            }
            let server = Server::new(responses())?;
            let mut session = session(fixture()?.target, &server)?;
            for action in &ACTIONS[..prefix] {
                session.call(request(action))?;
            }
            let prior = server.requests.lock().unwrap().len();
            assert!(session.call(request(action)).is_err());
            assert_eq!(server.requests.lock().unwrap().len(), prior);
            assert!(session.call(request(expected)).is_err());
            assert!(session.finish().is_err());
        }
    }
    let server = Server::new(responses())?;
    let mut session = session(fixture()?.target, &server)?;
    let mut attack = request(ACTIONS[0]);
    attack.input =
        json!({"client_secret":SECRET_CANARY,"token_endpoint":"https://attacker.example/token"})
            .to_string();
    assert!(session.call(attack).is_err());
    assert!(server.requests.lock().unwrap().is_empty());
    assert!(session.finish().is_err());
    Ok(())
}

#[test]
fn actual_private_roc_recipe_issues_the_same_native_receipt() -> Result<()> {
    let server = Server::new(responses())?;
    let session = session(fixture()?.target, &server)?;
    let receipt = session.run(&crate::automation::runner()?)?;
    assert_eq!(server.requests.lock().unwrap().len(), 9);
    assert!(receipt.fresh(receipt.checked_at));
    Ok(())
}

#[test]
fn authorization_derives_s256_and_accepts_only_its_fresh_session_and_state() -> Result<()> {
    let target = fixture()?.target;
    let human = Digest::of(&"verified-shell-session")?;
    for purpose in [
        Purpose::Positive,
        Purpose::RejectPkce,
        Purpose::RejectCredential,
    ] {
        let (authorization, location) = Authorization::begin(&target, purpose, human.clone())?;
        let url = Url::parse(&location)?;
        assert_eq!(url.origin().ascii_serialization(), google::ISSUER);
        let parameters: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(parameters["redirect_uri"], target.callback_url);
        assert_eq!(parameters["code_challenge_method"], "S256");
        assert_eq!(
            parameters["code_challenge"],
            super::super::custody::pkce_challenge(&authorization.verifier)?
        );
        assert_eq!(parameters["include_granted_scopes"], "false");
        assert!(!location.contains(&authorization.verifier));
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("state", &parameters["state"])
            .append_pair("code", CODE_CANARY)
            .append_pair("iss", google::ISSUER)
            .finish();
        let code = authorization.complete(query.as_bytes(), &human)?;
        assert_eq!(code.code, CODE_CANARY);
        assert!(code.purpose == purpose);
    }
    for attack in 0..5 {
        let (mut authorization, _) =
            Authorization::begin(&target, Purpose::Positive, human.clone())?;
        let mut query = format!("state={}&code={CODE_CANARY}", authorization.state);
        let session = if attack == 0 {
            Digest::of(&"different-shell-session")?
        } else {
            human.clone()
        };
        match attack {
            1 => query = format!("state=wrong&code={CODE_CANARY}"),
            2 => query.push_str("&iss=https%3A%2F%2Fattacker.example"),
            3 => query.push_str("&state=duplicate"),
            4 => authorization.started = Instant::now() - Duration::from_secs(VALID_SECONDS as u64),
            _ => {}
        }
        assert!(authorization.complete(query.as_bytes(), &session).is_err());
    }
    Ok(())
}
