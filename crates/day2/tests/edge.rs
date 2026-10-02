//! A real app behind the edge: signed IAP assertions -> HTTP -> session -> Roc.
//!
//! The server is the production edge server with one substitution, the key set,
//! because only a test that holds a signing key can present assertions at all.
//! Everything after the signature check — claims, subject binding, sessions,
//! CSRF, the app's authority policy and the invocation record — is the path a
//! request from IAP takes.
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use day2::{
    artifact::{Edge, Instance},
    iap::{ISSUER, KeySource, Verifier},
    store::Runtime,
    web::LocalServer,
};
use reqwest::{
    StatusCode,
    blocking::{Client, RequestBuilder, Response},
    header::{COOKIE, HOST, SET_COOKIE},
    redirect::Policy,
};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::{Value, json};
use std::{
    fs,
    num::NonZeroU16,
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const ORIGIN: &str = "https://go.v2.exampleco.test";
const AUTHORITY: &str = "go.v2.exampleco.test";
const AUDIENCE: &str = "/projects/1234/global/backendServices/5678";
const READER: &str = "ada@exampleco.test";
const OTHER: &str = "grace@exampleco.test";
const OUTSIDER: &str = "bob@exampleco.test";

struct Keys(String);

impl KeySource for Keys {
    fn fetch(&self) -> Result<String> {
        Ok(self.0.clone())
    }
}

struct Signer(Arc<EcdsaKeyPair>);

impl Signer {
    fn new() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow::anyhow!("keygen"))?;
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .map_err(|_| anyhow::anyhow!("key"))?;
        Ok(Self(Arc::new(pair)))
    }

    fn keys(&self) -> String {
        let point = self.0.public_key().as_ref();
        json!({"keys":[{"kid":"edge","kty":"EC","crv":"P-256","alg":"ES256",
            "x":URL_SAFE_NO_PAD.encode(&point[1..33]),"y":URL_SAFE_NO_PAD.encode(&point[33..65])}]})
        .to_string()
    }

    fn assertion(&self, claims: Value) -> String {
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(json!({"alg":"ES256","kid":"edge","typ":"JWT"}).to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = self
            .0
            .sign(&SystemRandom::new(), signed.as_bytes())
            .expect("sign");
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }

    fn person(&self, email: &str) -> String {
        self.assertion(claims(email, &format!("accounts.google.com:{email}")))
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn claims(email: &str, subject: &str) -> Value {
    json!({"iss":ISSUER,"aud":AUDIENCE,"iat":now(),"exp":now() + 600,
        "sub":subject,"email":email,"hd":"exampleco.test"})
}

fn instance(artifact: &str) -> Value {
    let actors = json!([READER, OTHER]);
    let read = json!({"actors":actors,"mode":{"kind":"read"},"models":{}});
    let mut forward = read.clone();
    forward["observations"] = json!(["app.query.v1"]);
    json!({"installation":"edgeco","environment":"test",
        "identity":{"scheme":"google_iap","hosted_domain":"exampleco.test"},
        "apps":{"go":{"artifact":artifact,"readers":actors,"writers":actors,
            "edge":{"origin":ORIGIN,"iap_audience":AUDIENCE},
            "authority":{"version":1,"admins":[],"operations":{
                "delegation.who":read,"delegation.forward":forward,
                "delegation.send":{"actors":actors,"mode":{"kind":"current_state"},"models":{},"effects":["app.send.v1"]},
                "delegation.status":{"actors":actors,"mode":{"kind":"read"},"models":{},"observations":["app.status.v1"]},
                "delegation.history":{"actors":actors,"mode":{"kind":"read"},"models":{},"observations":["audit.history.v1"]},
                "delegation.record":{"actors":actors,"mode":{"kind":"current_state"},
                    "models":{"entries":{"read":true,"create":true,
                        "rows":{"kind":"owner_or_admin","field":"actor"}}}}}}}}})
}

struct Server {
    origin: String,
    client: Client,
    runtime: Runtime,
    signer: Signer,
    _directory: tempfile::TempDir,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<Result<()>>>,
}

impl Server {
    fn start() -> Result<Self> {
        Self::start_with(instance)
    }

    fn start_with(instance: fn(&str) -> Value) -> Result<Self> {
        let artifact = std::env::var_os("DAY2_TEST_DELEGATION_ARTIFACT")
            .map(PathBuf::from)
            .context("run xtask verify or set DAY2_TEST_DELEGATION_ARTIFACT")?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("instance.json");
        fs::write(
            &path,
            serde_json::to_vec(&instance(artifact.to_str().context("artifact path")?))?,
        )?;
        let loaded = Instance::load(&path)?;
        let edge: Edge = loaded.edge("go")?.1.clone();
        let runtime = Runtime::load(&path, "go")?;
        runtime.initialize()?;
        let signer = Signer::new()?;
        let verifier = Verifier::new(AUDIENCE, "exampleco.test", Box::new(Keys(signer.keys())))?;
        let (send, receive) = mpsc::channel();
        let (stop, done) = tokio::sync::oneshot::channel();
        let served = runtime.clone();
        let thread = thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?
                .block_on(async move {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                    let address = listener.local_addr()?;
                    let server =
                        LocalServer::bind_edge_listener(served, listener, &edge, verifier, 4)?;
                    send.send(format!("http://{address}"))?;
                    server
                        .serve(async {
                            let _ = done.await;
                        })
                        .await
                })
        });
        let origin = receive.recv_timeout(Duration::from_secs(10))?;
        Ok(Self {
            origin,
            client: Client::builder()
                .redirect(Policy::none())
                .timeout(Duration::from_secs(30))
                .build()?,
            runtime,
            signer,
            _directory: directory,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// A request as the load balancer forwards it: to the pod's address, naming
    /// the edge host.
    fn get(&self, path: &str) -> RequestBuilder {
        self.client
            .get(format!("{}{path}", self.origin))
            .header(HOST, AUTHORITY)
    }

    fn as_person(&self, request: RequestBuilder, email: &str) -> RequestBuilder {
        request.header("x-goog-iap-jwt-assertion", self.signer.person(email))
    }

    fn sessions(&self) -> Result<i64> {
        Ok(rusqlite::Connection::open(self.runtime.db())?.query_row(
            "SELECT count(*) FROM day2_web_sessions",
            [],
            |row| row.get(0),
        )?)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            assert!(thread.join().expect("HTTP server").is_ok());
        }
    }
}

fn value(response: Response, status: StatusCode) -> Result<Value> {
    let actual = response.status();
    let text = response.text()?;
    assert_eq!(actual, status, "{text}");
    Ok(serde_json::from_str(&text)?)
}

fn refused(response: Response, status: StatusCode, code: &str) -> Result<()> {
    assert_eq!(value(response, status)?["error"]["code"], code);
    Ok(())
}

/// The `name=value` part of the session cookie a response set.
fn issued(response: &Response) -> Option<(String, String)> {
    let header = response
        .headers()
        .get(SET_COOKIE)?
        .to_str()
        .ok()?
        .to_owned();
    let pair = header.split(';').next()?.to_owned();
    Some((pair, header))
}

#[test]
fn a_person_is_whoever_their_verified_assertion_says() -> Result<()> {
    let server = Server::start()?;

    let response = server
        .as_person(server.get("/api/session"), READER)
        .send()?;
    let (cookie, header) = issued(&response).context("a session is issued")?;
    // Host-only, HTTPS-only, script-inaccessible: nothing on a sibling
    // subdomain at the edge can set, read or shadow it.
    assert!(cookie.starts_with("__Host-day2_go_"), "{header}");
    for attribute in ["Path=/", "HttpOnly", "Secure", "SameSite=Strict"] {
        assert!(header.contains(attribute), "{header}");
    }
    let session = value(response, StatusCode::OK)?;
    assert_eq!(session["actor"], READER);
    let csrf = session["csrf_token"].as_str().context("csrf")?.to_owned();

    // The identity reaches Roc as a request by that person, acting directly.
    let who = value(
        server
            .as_person(server.get("/api/delegation.who"), READER)
            .header(COOKIE, &cookie)
            .send()?,
        StatusCode::OK,
    )?;
    assert_eq!(
        who,
        json!({"actor":READER,"authenticated":READER,"rule":"","caller":"","authentication":"request"})
    );

    // A command carries the same person into the audit record.
    let response = server
        .as_person(
            server
                .client
                .post(format!("{}/api/delegation.record", server.origin))
                .header(HOST, AUTHORITY),
            READER,
        )
        .header(COOKIE, &cookie)
        .header("Origin", ORIGIN)
        .header("X-CSRF-Token", &csrf)
        .header("Idempotency-Key", "edge-one")
        .header("Content-Type", "application/json")
        .body(r#"{"note":"one"}"#)
        .send()?;
    let id = response.headers()["x-day2-invocation"].to_str()?.to_owned();
    value(response, StatusCode::OK)?;
    let (actor, initiator): (String, String) = rusqlite::Connection::open(server.runtime.db())?
        .query_row(
            "SELECT actor,initiator FROM day2_audit_events WHERE kind='invocation' AND identity=?1",
            [&id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
    assert_eq!((actor.as_str(), initiator.as_str()), (READER, READER));
    let origin: (String, String, String) = rusqlite::Connection::open(server.runtime.db())?
        .query_row(
            "SELECT principal,subject,kind FROM day2_invocation_origins WHERE invocation=?1",
            [&id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    assert_eq!(
        origin,
        (
            READER.to_owned(),
            format!("accounts.google.com:{READER}"),
            "iap".to_owned()
        )
    );

    // A session that already matches is reused, not reissued.
    let before = server.sessions()?;
    let response = server
        .as_person(server.get("/api/session"), READER)
        .header(COOKIE, &cookie)
        .send()?;
    assert!(issued(&response).is_none());
    assert_eq!(value(response, StatusCode::OK)?["actor"], READER);
    assert_eq!(server.sessions()?, before);

    // Someone else's cookie is not a session for this person.
    let response = server
        .as_person(server.get("/api/session"), OTHER)
        .header(COOKIE, &cookie)
        .send()?;
    assert!(
        issued(&response).is_some(),
        "the other person gets their own"
    );
    assert_eq!(value(response, StatusCode::OK)?["actor"], OTHER);
    Ok(())
}

#[test]
fn nothing_but_a_valid_assertion_admits_a_request() -> Result<()> {
    let server = Server::start()?;
    let (cookie, _) = issued(
        &server
            .as_person(server.get("/api/session"), READER)
            .send()?,
    )
    .context("session")?;
    let before = server.sessions()?;

    // No assertion, even with a live session cookie: the cookie never stands in.
    for request in [
        server.get("/api/session"),
        server.get("/api/session").header(COOKIE, &cookie),
        server.get("/api/delegation.who").header(COOKIE, &cookie),
    ] {
        refused(
            request.send()?,
            StatusCode::UNAUTHORIZED,
            "invalid_identity_assertion",
        )?;
    }
    // Nor a page, which is refused the same way before any route is chosen.
    assert_eq!(
        server.get("/").header(COOKIE, &cookie).send()?.status(),
        StatusCode::UNAUTHORIZED
    );

    let with = |claims: Value| {
        server
            .get("/api/session")
            .header("x-goog-iap-jwt-assertion", server.signer.assertion(claims))
            .send()
    };
    // Signed, valid, and for another app.
    let mut other_app = claims(READER, "accounts.google.com:ada");
    other_app["aud"] = json!("/projects/1234/global/backendServices/9999");
    refused(
        with(other_app)?,
        StatusCode::UNAUTHORIZED,
        "invalid_identity_assertion",
    )?;
    let mut outside = claims("eve@example.com", "accounts.google.com:eve");
    outside["hd"] = json!("example.com");
    refused(
        with(outside)?,
        StatusCode::UNAUTHORIZED,
        "invalid_identity_assertion",
    )?;
    // Two assertions: which one is the request from?
    refused(
        server
            .get("/api/session")
            .header("x-goog-iap-jwt-assertion", server.signer.person(READER))
            .header("x-goog-iap-jwt-assertion", server.signer.person(OTHER))
            .send()?,
        StatusCode::UNAUTHORIZED,
        "invalid_identity_assertion",
    )?;
    // A forged signature.
    let forger = Signer::new()?;
    refused(
        server
            .get("/api/session")
            .header("x-goog-iap-jwt-assertion", forger.person(READER))
            .send()?,
        StatusCode::UNAUTHORIZED,
        "invalid_identity_assertion",
    )?;
    // A service account at the human door.
    refused(
        with(claims(
            "control-plane@tools.iam.gserviceaccount.com",
            "accounts.google.com:svc",
        ))?,
        StatusCode::FORBIDDEN,
        "machine_caller_requires_delegation",
    )?;
    // A real colleague this app does not admit.
    refused(
        server
            .as_person(server.get("/api/session"), OUTSIDER)
            .send()?,
        StatusCode::FORBIDDEN,
        "forbidden",
    )?;
    assert_eq!(server.sessions()?, before, "no refusal issued a session");

    // The edge is its own address: another Host is refused after admission.
    refused(
        server
            .as_person(
                server
                    .client
                    .get(format!("{}/api/session", server.origin))
                    .header(HOST, "other.v2.exampleco.test"),
                READER,
            )
            .send()?,
        StatusCode::FORBIDDEN,
        "invalid_host",
    )?;
    // Health needs no assertion, because the load balancer has none.
    assert_eq!(
        server
            .client
            .get(format!("{}/health/live", server.origin))
            .send()?
            .status(),
        StatusCode::OK
    );
    // There is no sign-in link to use.
    assert_eq!(
        server
            .as_person(server.get("/login?token=x"), READER)
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );
    Ok(())
}

#[test]
fn an_address_given_to_a_new_account_is_not_the_old_person() -> Result<()> {
    let server = Server::start()?;
    let first = claims(READER, "accounts.google.com:original");
    let session = |claims: Value| {
        server
            .get("/api/session")
            .header("x-goog-iap-jwt-assertion", server.signer.assertion(claims))
            .send()
    };
    value(session(first.clone())?, StatusCode::OK)?;
    refused(
        session(claims(READER, "accounts.google.com:successor"))?,
        StatusCode::FORBIDDEN,
        "principal_subject_changed",
    )?;
    // The original account is unaffected.
    assert_eq!(value(session(first)?, StatusCode::OK)?["actor"], READER);
    Ok(())
}

#[test]
fn signing_out_at_the_edge_signs_out_of_the_identity_provider() -> Result<()> {
    let server = Server::start()?;
    let response = server
        .as_person(server.get("/api/session"), READER)
        .send()?;
    let (cookie, _) = issued(&response).context("session")?;
    let csrf = value(response, StatusCode::OK)?["csrf_token"]
        .as_str()
        .context("csrf")?
        .to_owned();
    let response = server
        .as_person(
            server
                .client
                .post(format!("{}/logout", server.origin))
                .header(HOST, AUTHORITY),
            READER,
        )
        .header(COOKIE, &cookie)
        .header("Origin", ORIGIN)
        .form(&[("_csrf", csrf.as_str())])
        .send()?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()["location"],
        "/?gcp-iap-mode=CLEAR_LOGIN_COOKIE"
    );
    let cleared = response.headers()[SET_COOKIE].to_str()?;
    assert!(
        cleared.contains("Max-Age=0") && cleared.contains("Secure"),
        "{cleared}"
    );
    Ok(())
}

/// One edit to an otherwise valid instance document.
type Change = dyn Fn(&mut Value);

#[test]
fn the_edge_is_declared_once_for_the_installation_and_never_loosely() -> Result<()> {
    let base = instance("artifacts/unused");
    let load = |change: &Change| {
        let mut document = base.clone();
        change(&mut document);
        Instance::from_bytes(&serde_json::to_vec(&document).unwrap())
    };
    assert!(load(&|_| {}).is_ok());
    let refusals: [(&str, &Change); 9] = [
        ("an edge with nothing to verify against", &|d| {
            d.as_object_mut().unwrap().remove("identity");
        }),
        ("plain http", &|d| {
            d["apps"]["go"]["edge"]["origin"] = json!("http://go.v2.exampleco.test");
        }),
        ("a path on the origin", &|d| {
            d["apps"]["go"]["edge"]["origin"] = json!("https://go.v2.exampleco.test/app");
        }),
        ("a port on the origin", &|d| {
            d["apps"]["go"]["edge"]["origin"] = json!("https://go.v2.exampleco.test:8443");
        }),
        ("an origin a browser would never send", &|d| {
            d["apps"]["go"]["edge"]["origin"] = json!("https://Go.V2.exampleco.test");
        }),
        ("an audience that is not a backend service", &|d| {
            d["apps"]["go"]["edge"]["iap_audience"] = json!("go.v2.exampleco.test");
        }),
        ("an unknown scheme", &|d| {
            d["identity"]["scheme"] = json!("header");
        }),
        ("an app choosing its own domain", &|d| {
            d["apps"]["go"]["edge"]["hosted_domain"] = json!("example.com");
        }),
        ("no hosted domain", &|d| {
            d["identity"]["hosted_domain"] = json!("");
        }),
    ];
    for (name, change) in refusals {
        assert!(load(change).is_err(), "{name}");
    }
    // Two apps behind one backend service would accept each other's assertions.
    assert!(
        load(&|d| {
            d["apps"]["links"] = d["apps"]["go"].clone();
            d["apps"]["links"]["edge"]["origin"] = json!("https://links.v2.exampleco.test");
        })
        .is_err()
    );
    assert!(
        load(&|d| {
            d["apps"]["links"] = d["apps"]["go"].clone();
            d["apps"]["links"]["edge"]["iap_audience"] =
                json!("/projects/1234/global/backendServices/9");
        })
        .is_err(),
        "nor may two apps share an origin"
    );
    Ok(())
}

#[test]
fn security_shell_has_its_own_verified_origin_and_iap_audience() -> Result<()> {
    let mut document = instance("artifacts/unused");
    assert!(
        Instance::from_bytes(&serde_json::to_vec(&document)?)?
            .security_edge()
            .is_err()
    );
    document["security_shell"] = json!({
        "origin": "https://security.v2.exampleco.test",
        "iap_audience": "/projects/1234/global/backendServices/10"
    });
    let installed = Instance::from_bytes(&serde_json::to_vec(&document)?)?;
    let (identity, shell) = installed.security_edge()?;
    assert_eq!(identity.hosted_domain, "exampleco.test");
    assert_eq!(shell.origin, "https://security.v2.exampleco.test");

    let mut changed = document.clone();
    changed.as_object_mut().unwrap().remove("identity");
    assert!(Instance::from_bytes(&serde_json::to_vec(&changed)?).is_err());

    let mut changed = document.clone();
    changed["security_shell"]["origin"] = document["apps"]["go"]["edge"]["origin"].clone();
    assert!(Instance::from_bytes(&serde_json::to_vec(&changed)?).is_err());

    let mut changed = document.clone();
    changed["security_shell"]["iap_audience"] =
        document["apps"]["go"]["edge"]["iap_audience"].clone();
    assert!(Instance::from_bytes(&serde_json::to_vec(&changed)?).is_err());

    let mut changed = document;
    changed["security_shell"]["origin"] = json!("https://security.v2.exampleco.test/app");
    assert!(Instance::from_bytes(&serde_json::to_vec(&changed)?).is_err());
    Ok(())
}

#[test]
fn an_installation_with_an_identity_provider_has_no_development_bundle() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("instance.json");
    fs::write(&path, serde_json::to_vec(&instance("artifacts/unused"))?)?;
    let error = day2::packaging::export(
        &path,
        "go",
        READER,
        &format!("sha256:{}", "a".repeat(64)),
        NonZeroU16::new(18080).unwrap(),
        &directory.path().join("bundle"),
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("development_export_refused_with_identity"),
        "{error:#}"
    );
    Ok(())
}

#[test]
fn which_sign_in_a_container_serves_is_the_instance_s_decision() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let with_identity = directory.path().join("edge.json");
    fs::write(
        &with_identity,
        serde_json::to_vec(&instance("artifacts/unused"))?,
    )?;
    let mut plain = instance("artifacts/unused");
    plain.as_object_mut().unwrap().remove("identity");
    plain["apps"]["go"].as_object_mut().unwrap().remove("edge");
    let without = directory.path().join("plain.json");
    fs::write(&without, serde_json::to_vec(&plain)?)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let serve = |path: &std::path::Path, access| {
        runtime
            .block_on(day2::deployment::serve(path, "go", access))
            .map(|()| String::new())
            .unwrap_or_else(|error| format!("{error:#}"))
    };
    let development = || day2::deployment::Access::Development {
        actor: READER,
        published_port: NonZeroU16::new(18080).unwrap(),
    };
    assert!(
        serve(&with_identity, development()).contains("development_auth_refused_with_identity")
    );
    assert!(serve(&without, day2::deployment::Access::Edge).contains("identity_not_declared"));
    Ok(())
}

/// The same app, admitting everyone at the verified domain instead of naming
/// people: `domain:` in the membership lists and in every operation's actors.
fn domain_instance(artifact: &str) -> Value {
    let mut document = instance(artifact);
    let everyone = json!(["domain:exampleco.test"]);
    let app = &mut document["apps"]["go"];
    app["readers"] = everyone.clone();
    app["writers"] = everyone.clone();
    for operation in app["authority"]["operations"]
        .as_object_mut()
        .unwrap()
        .values_mut()
    {
        operation["actors"] = everyone.clone();
    }
    document
}

#[test]
fn a_domain_entry_admits_verified_colleagues_as_themselves() -> Result<()> {
    const NEW_HIRE: &str = "newhire@exampleco.test";
    let server = Server::start_with(domain_instance)?;

    // Named nowhere, admitted by the domain, and a session for that person.
    let response = server
        .as_person(server.get("/api/session"), NEW_HIRE)
        .send()?;
    let (cookie, _) = issued(&response).context("a session is issued")?;
    let session = value(response, StatusCode::OK)?;
    assert_eq!(session["actor"], NEW_HIRE);
    let csrf = session["csrf_token"].as_str().context("csrf")?.to_owned();
    let who = value(
        server
            .as_person(server.get("/api/delegation.who"), NEW_HIRE)
            .header(COOKIE, &cookie)
            .send()?,
        StatusCode::OK,
    )?;
    assert_eq!(who["actor"], NEW_HIRE);
    assert_eq!(who["authenticated"], NEW_HIRE);

    // What they do is recorded against their own address, never the entry.
    let response = server
        .as_person(
            server
                .client
                .post(format!("{}/api/delegation.record", server.origin))
                .header(HOST, AUTHORITY),
            NEW_HIRE,
        )
        .header(COOKIE, &cookie)
        .header("Origin", ORIGIN)
        .header("X-CSRF-Token", &csrf)
        .header("Idempotency-Key", "domain-one")
        .header("Content-Type", "application/json")
        .body(r#"{"note":"hello"}"#)
        .send()?;
    let id = response.headers()["x-day2-invocation"].to_str()?.to_owned();
    value(response, StatusCode::OK)?;
    let db = rusqlite::Connection::open(server.runtime.db())?;
    let (actor, initiator): (String, String) = db.query_row(
        "SELECT actor,initiator FROM day2_audit_events WHERE kind='invocation' AND identity=?1",
        [&id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!((actor.as_str(), initiator.as_str()), (NEW_HIRE, NEW_HIRE));
    let recorded: i64 = db.query_row(
        "SELECT count(*) FROM day2_audit_events WHERE actor LIKE 'domain:%' OR initiator LIKE 'domain:%'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(recorded, 0, "no audit event names the domain entry");

    let before = server.sessions()?;
    let with = |claims: Value| {
        server
            .get("/api/session")
            .header("x-goog-iap-jwt-assertion", server.signer.assertion(claims))
            .send()
    };
    // A lookalike domain, correctly signed for its own hosted domain, is not
    // this installation's: the verifier refuses it before membership is asked.
    for lookalike in ["eve@evil-exampleco.test", "eve@sub.exampleco.test"] {
        let mut claims = claims(lookalike, &format!("accounts.google.com:{lookalike}"));
        claims["hd"] = json!(lookalike.split_once('@').unwrap().1);
        refused(
            with(claims)?,
            StatusCode::UNAUTHORIZED,
            "invalid_identity_assertion",
        )?;
    }
    // An address that does end in the domain, and carries the right `hd`, but
    // whose part after its first `@` is not the domain: the entry refuses it.
    refused(
        with(claims(
            "eve@evil.test@exampleco.test",
            "accounts.google.com:eve",
        ))?,
        StatusCode::FORBIDDEN,
        "forbidden",
    )?;
    // A service account has no person behind it, whatever the entry says.
    refused(
        with(claims(
            "control-plane@tools.iam.gserviceaccount.com",
            "accounts.google.com:svc",
        ))?,
        StatusCode::FORBIDDEN,
        "machine_caller_requires_delegation",
    )?;
    assert_eq!(server.sessions()?, before, "no refusal issued a session");
    Ok(())
}

#[test]
fn a_domain_entry_needs_the_installation_to_verify_that_domain() -> Result<()> {
    let base = domain_instance("artifacts/unused");
    let load = |change: &Change| {
        let mut document = base.clone();
        change(&mut document);
        Instance::from_bytes(&serde_json::to_vec(&document).unwrap())
            .map(|_| ())
            .map_err(|error| format!("{error:#}"))
    };
    assert_eq!(load(&|_| {}), Ok(()));
    let refusals: [(&str, &Change); 5] = [
        ("no identity provider", &|d| {
            d.as_object_mut().unwrap().remove("identity");
            d["apps"]["go"].as_object_mut().unwrap().remove("edge");
        }),
        ("another hosted domain", &|d| {
            d["identity"]["hosted_domain"] = json!("other.test");
        }),
        ("a subdomain of the hosted domain", &|d| {
            d["apps"]["go"]["readers"] = json!(["domain:sub.exampleco.test"]);
        }),
        ("an operation naming another domain", &|d| {
            d["apps"]["go"]["authority"]["operations"]["delegation.who"]["actors"] =
                json!(["domain:other.test"]);
        }),
        ("an uppercase domain", &|d| {
            d["apps"]["go"]["writers"] = json!(["domain:ExampleCo.test"]);
        }),
    ];
    for (name, change) in refusals {
        assert!(load(change).is_err(), "{name}");
    }
    let error = load(&|d| {
        d.as_object_mut().unwrap().remove("identity");
        d["apps"]["go"].as_object_mut().unwrap().remove("edge");
    })
    .unwrap_err();
    assert!(error.contains("google_iap"), "{error}");
    Ok(())
}
