//! Real session -> API -> sealed Roc context -> resource grant -> native callee.
//! No hand-built invocation context or simulated provider stands in for this path.
use anyhow::{Context, Result};
use day2::{
    authority_state::{self, LocalOperator},
    store::{Runtime, replay},
    web::LocalServer,
};
use reqwest::{
    StatusCode,
    blocking::{Client, RequestBuilder, Response},
    redirect::Policy,
};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

struct World {
    _directory: tempfile::TempDir,
    path: PathBuf,
    caller: Runtime,
    callee: Runtime,
}

impl World {
    fn new() -> Result<Self> {
        let artifact = std::env::var_os("DAY2_TEST_DELEGATION_ARTIFACT")
            .map(PathBuf::from)
            .context("run xtask verify or set DAY2_TEST_DELEGATION_ARTIFACT")?;
        let peer_artifact = std::env::var_os("DAY2_TEST_DELEGATION_PEER_ARTIFACT")
            .map(PathBuf::from)
            .context("run xtask build-delegation or verify")?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("instance.json");
        // Support can authenticate but has no direct business-operation grant.
        // All targets below have operation access so exclusions test delegation,
        // not an unrelated missing operation grant.
        let actors = json!([
            "customer",
            "another",
            "boss",
            "it",
            "app:worker",
            "svc:worker"
        ]);
        let read = json!({"actors":actors,"mode":{"kind":"read"},"models":{}});
        let mut forward = read.clone();
        forward["observations"] = json!(["app.query.v1"]);
        let binding = json!({"artifact":artifact,"readers":actors,"writers":actors,
        "authority":{"version":1,"admins":["boss"],"operations":{
            "delegation.who":read,"delegation.forward":forward,
            "delegation.history":{"actors":actors,"mode":{"kind":"read"},"models":{},"observations":["audit.history.v1"]},
            "delegation.record":{"actors":actors,"mode":{"kind":"current_state"},
                "models":{"entries":{"read":true,"create":true,"rows":{"kind":"owner_or_admin","field":"actor"}}}}
        },"delegations":{
            "support":{"authenticated":["support","other-support"],"may_act_as":{"kind":"any_human"},"paths":["request"]},
            "gateway":{"authenticated":["gateway"],"may_act_as":{"kind":"actors","actors":["customer"]},"paths":["ingress"]}
        }}});
        let mut instance = json!({"installation":"identityco","environment":"test",
            "control":{"version":1,"state_directory":directory.path().join("control"),"operators":["it"],"sources":{},"apps":{}},
            "apps":{"caller":binding,"peer_identity":binding}});
        instance["apps"]["peer_identity"]["artifact"] = json!(peer_artifact);
        let operations = instance["apps"]["peer_identity"]["authority"]["operations"]
            .as_object_mut()
            .unwrap();
        *operations = operations
            .iter()
            .filter(|(name, _)| name.as_str() != "delegation.forward")
            .map(|(name, policy)| {
                (
                    name.replace("delegation.", "peer_identity."),
                    policy.clone(),
                )
            })
            .collect();
        // Permit gateway an identity read so it can sign in, then test that its
        // ingress-only delegation still cannot select a target on requests.
        instance["apps"]["caller"]["readers"]
            .as_array_mut()
            .unwrap()
            .extend([json!("support"), json!("gateway")]);
        instance["apps"]["caller"]["authority"]["operations"]["delegation.who"]["actors"]
            .as_array_mut()
            .unwrap()
            .push(json!("gateway"));
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let callee = Runtime::load(&path, "peer_identity")?;
        callee.initialize()?;
        let digest = day2::delegation::schema_digest(&callee, "peer_identity.who")?;
        instance["resources"] = json!({"version":1,
            "connections":{"peer":{"revision":1,"provider":"local_delegation"}},
            "resources":{"peer":{"revision":1,"connection":{"id":"peer","revision":1},
                "target":{"kind":"app_operation","app":"peer_identity","operation":"peer_identity.who","schema_digest":digest}}},
            "policies":{"peer_read":{"revision":1,"owner":"it","actors":actors,"allowed_apps":["caller"],
                "slots":{"delegation":{"kind":"app_operation","allowed_resources":[{"id":"peer","revision":1}],
                    "actions":["delegate_query"],"limits":{"max_request_bytes":16384,"max_response_bytes":65536,"max_calls_per_invocation":4},"budgets":[]}}}},
            "budgets":{}});
        instance["apps"]["caller"]["resource_policies"] = json!([{
            "policy":{"id":"peer_read","revision":1},"operation":"delegation.forward",
            "bindings":{"delegation":{"id":"peer","revision":1}}}]);
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let caller = Runtime::load(&path, "caller")?;
        caller.initialize()?;
        fs::create_dir_all(directory.path().join("control"))?;
        let release =
            rusqlite::Connection::open(directory.path().join("control/build-journal.sqlite"))?;
        release.execute_batch("CREATE TABLE release_slots(target TEXT PRIMARY KEY,generation INTEGER,active TEXT); CREATE TABLE release_activations(release TEXT PRIMARY KEY,body TEXT); CREATE TABLE release_approvals(id TEXT PRIMARY KEY,body TEXT);")?;
        for (app, runtime) in [("caller", &caller), ("peer_identity", &callee)] {
            #[derive(serde::Serialize)]
            struct Target<'a> {
                company: &'a str,
                environment: &'a str,
                app: &'a str,
            }
            let key = serde_json::to_string(&Target {
                company: "identityco",
                environment: "test",
                app,
            })?;
            let target = json!({"company":"identityco","environment":"test","app":app});
            let release_id = day2_capabilities::Digest::of(&(app, runtime.artifact().id()))?;
            let readiness = day2_capabilities::Digest::new(app.as_bytes());
            let activation = day2_capabilities::Digest::of(&(
                "day2-release-activation-v1",
                &release_id,
                &readiness,
            ))?;
            let receipt = json!({"id":activation,"target":target,"release":release_id,"generation":1,"artifact":runtime.artifact().id(),"readiness":readiness}).to_string();
            release.execute(
                "INSERT INTO release_slots VALUES(?1,1,?2)",
                (&key, &receipt),
            )?;
            release.execute(
                "INSERT INTO release_activations VALUES(?1,?2)",
                (release_id.as_str(), &receipt),
            )?;
            release.execute("INSERT INTO release_approvals VALUES(?1,?2)", (release_id.as_str(), json!({"approval":{"target":target,"artifact":runtime.artifact().id()},"generation":1}).to_string()))?;
        }
        Ok(Self {
            _directory: directory,
            path,
            caller,
            callee,
        })
    }

    fn change(&self, app: &str, update: impl FnOnce(&mut Value)) -> Result<()> {
        let mut instance: Value = serde_json::from_slice(&fs::read(&self.path)?)?;
        update(
            &mut instance["apps"][if app == "callee" {
                "peer_identity"
            } else {
                app
            }],
        );
        fs::write(&self.path, serde_json::to_vec(&instance)?)?;
        let runtime = if app == "caller" {
            &self.caller
        } else {
            &self.callee
        };
        let db = rusqlite::Connection::open(runtime.db())?;
        let current = authority_state::current(&db)?;
        authority_state::apply_desired(
            runtime,
            &LocalOperator::assert_local("it")?,
            &format!("identity-policy-{}", current.stamp.revision),
            Some(current.stamp),
        )?;
        Ok(())
    }

    fn rows(&self) -> Result<i64> {
        Ok(rusqlite::Connection::open(self.caller.db())?.query_row(
            "SELECT count(*) FROM entries",
            [],
            |row| row.get(0),
        )?)
    }
}

struct Server {
    origin: String,
    client: Client,
    csrf: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<Result<()>>>,
}

impl Server {
    fn start(runtime: Runtime, actor: &str) -> Result<Self> {
        let actor = actor.to_owned();
        let (send, receive) = mpsc::channel();
        let (stop, done) = tokio::sync::oneshot::channel();
        let thread = thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?
                .block_on(async move {
                    let server = LocalServer::bind(runtime, &actor, 0).await?;
                    send.send((server.origin.clone(), server.login_url.clone()))?;
                    server
                        .serve(async {
                            let _ = done.await;
                        })
                        .await
                })
        });
        let (origin, login) = receive.recv_timeout(Duration::from_secs(10))?;
        let client = Client::builder()
            .cookie_store(true)
            .redirect(Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;
        let mut server = Self {
            origin,
            client,
            csrf: String::new(),
            stop: Some(stop),
            thread: Some(thread),
        };
        let response = server.client.get(login).send()?;
        assert_eq!(response.status(), StatusCode::OK);
        let html = Html::parse_document(&response.text()?);
        let fields: BTreeMap<String, String> = html
            .select(&Selector::parse("form input[name]").unwrap())
            .map(|input| {
                (
                    input.value().attr("name").unwrap().into(),
                    input.value().attr("value").unwrap_or("").into(),
                )
            })
            .collect();
        assert_eq!(
            server
                .client
                .post(format!("{}/login", server.origin))
                .header("Origin", &server.origin)
                .form(&fields)
                .send()?
                .status(),
            StatusCode::SEE_OTHER
        );
        let session = value(
            server
                .client
                .get(format!("{}/api/session", server.origin))
                .send()?,
            StatusCode::OK,
        )?;
        server.csrf = session["csrf_token"].as_str().context("csrf token")?.into();
        Ok(server)
    }

    fn get(&self, path: &str, actor: &str) -> RequestBuilder {
        self.client
            .get(format!("{}{path}", self.origin))
            .header("X-Day2-Act-As", actor)
            .header("Origin", &self.origin)
            .header("X-CSRF-Token", &self.csrf)
    }

    fn record(&self, actor: &str, key: &str) -> RequestBuilder {
        self.client
            .post(format!("{}/api/delegation.record", self.origin))
            .header("X-Day2-Act-As", actor)
            .header("Origin", &self.origin)
            .header("X-CSRF-Token", &self.csrf)
            .header("Idempotency-Key", key)
            .header("Content-Type", "application/json")
            .body(r#"{"note":"one"}"#)
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

fn identity(actor: &str, authenticated: &str, rule: &str, caller: &str, cause: &str) -> Value {
    json!({"actor":actor,"authenticated":authenticated,"rule":rule,"caller":caller,"authentication":cause})
}

fn audit(runtime: &Runtime, id: &str, actor: &str, initiator: &str, cause: &str) -> Result<()> {
    let db = rusqlite::Connection::open(runtime.db())?;
    let actual: (String, String, String, String) = db.query_row(
        "SELECT actor,initiator,trigger,outcome FROM day2_audit_events WHERE kind='invocation' AND identity=?1", [id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?;
    assert_eq!(
        actual,
        (
            actor.into(),
            initiator.into(),
            cause.into(),
            "success".into()
        )
    );
    replay(runtime.artifact(), &runtime.trace(id)?)?;
    Ok(())
}

#[test]
fn session_identity_reaches_roc_and_a_real_callee_without_changing_actor() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(world.caller.clone(), "support")?;
    let session = value(
        server
            .client
            .get(format!("{}/api/session", server.origin))
            .send()?,
        StatusCode::OK,
    )?;
    assert_eq!(session["actor"], "support");
    assert_eq!(
        server
            .client
            .get(format!("{}/api/delegation.who", server.origin))
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    let expected = identity("customer", "support", "support", "", "request");
    assert_eq!(
        value(
            server.get("/api/delegation.who", "customer").send()?,
            StatusCode::OK
        )?,
        expected
    );
    let response = server.get("/api/delegation.forward", "customer").send()?;
    let id = response.headers()["x-day2-invocation"].to_str()?.to_owned();
    let result = value(response, StatusCode::OK)?;
    assert_eq!(result["identity"], expected);
    let answer: Value = serde_json::from_str(result["answer"].as_str().context("callee JSON")?)?;
    assert_eq!(
        answer,
        identity("customer", "app:caller", "", "caller", "delegated")
    );
    audit(&world.caller, &id, "customer", "support", "request")?;
    let db = rusqlite::Connection::open(world.callee.db())?;
    let child: String = db.query_row("SELECT id FROM day2_invocations", [], |row| row.get(0))?;
    audit(&world.callee, &child, "customer", "app:caller", "delegated")?;
    // Header scope ends with this request; it never mutates the session.
    assert_eq!(
        value(
            server
                .client
                .get(format!("{}/api/session", server.origin))
                .send()?,
            StatusCode::OK
        )?["actor"],
        "support"
    );
    world.change("callee", |binding| {
        binding["authority"]["operations"]["peer_identity.who"]["actors"] = json!(["another"])
    })?;
    assert_eq!(
        server
            .get("/api/delegation.forward", "customer")
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM day2_invocations", [], |row| row
            .get::<_, i64>(0))?,
        1
    );
    Ok(())
}

#[test]
fn commands_and_async_receipts_bind_requester_target_and_idempotency() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(world.caller.clone(), "support")?;
    let response = server.record("customer", "once").send()?;
    let id = response.headers()["x-day2-invocation"].to_str()?.to_owned();
    let first = value(response, StatusCode::OK)?;
    assert_eq!(
        first["identity"],
        identity("customer", "support", "support", "", "request")
    );
    assert_eq!(
        value(server.record("customer", "once").send()?, StatusCode::OK)?,
        first
    );
    assert_eq!(world.rows()?, 1);
    assert_eq!(
        server.record("another", "once").send()?.status(),
        StatusCode::CONFLICT
    );
    audit(&world.caller, &id, "customer", "support", "request")?;
    let pending = value(
        server
            .record("customer", "async")
            .header("Prefer", "respond-async")
            .send()?,
        StatusCode::ACCEPTED,
    )?;
    let path = pending["status_url"].as_str().context("status URL")?;
    assert_eq!(
        server
            .client
            .get(format!("{}{path}", server.origin))
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server.get(path, "another").send()?.status(),
        StatusCode::FORBIDDEN
    );
    // This requester has ONLY the request delegation rule, not a business or audit grant.
    let other = Server::start(world.caller.clone(), "other-support")?;
    assert_eq!(
        other.get(path, "customer").send()?.status(),
        StatusCode::FORBIDDEN
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let receipt = value(server.get(path, "customer").send()?, StatusCode::OK)?;
        if receipt["status"] != "pending" {
            assert_eq!(receipt["status"], "success", "{receipt}");
            assert_eq!(receipt["result"]["identity"], first["identity"]);
            break;
        }
        assert!(Instant::now() < deadline, "async command did not finish");
        thread::sleep(Duration::from_millis(30));
    }
    assert_eq!(world.rows()?, 2);
    let async_id = pending["invocation_id"].as_str().unwrap();
    audit(&world.caller, async_id, "customer", "support", "request")?;
    world.change("caller", |binding| {
        binding["authority"]["delegations"]["support"]["paths"] = json!(["ingress"])
    })?;
    assert_eq!(
        server.get(path, "customer").send()?.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server.record("customer", "once").send()?.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server
            .record("customer", "new-after-revocation")
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(world.rows()?, 2);
    Ok(())
}

#[test]
fn app_history_is_granted_independently_redacted_scoped_and_cursor_paged() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(world.caller.clone(), "support")?;
    let mut records = Vec::new();
    for key in ["history-one", "history-two", "history-three"] {
        let result = value(
            server
                .record("customer", key)
                .body(r#"{"note":"SECRET-ROW-VALUE"}"#)
                .send()?,
            StatusCode::OK,
        )?;
        records.push(result["id"].clone());
    }
    // Reads and web/admission/rejection events exist but are outside this
    // app query's record-command filter. A nonowner can use the app query.
    value(
        server.get("/api/delegation.who", "customer").send()?,
        StatusCode::OK,
    )?;
    assert_eq!(
        server.record("boss", "rejected").send()?.status(),
        StatusCode::FORBIDDEN
    );
    assert!(
        world
            .caller
            .audit_entries("customer", &Default::default())
            .is_err()
    );
    let response = server
        .get("/api/delegation.history?after=&limit=2", "customer")
        .send()?;
    let invocation = response.headers()["x-day2-invocation"].to_str()?.to_owned();
    let first = value(response, StatusCode::OK)?;
    assert_eq!(first["items"].as_array().unwrap().len(), 2);
    assert_eq!(first["items"][0]["records"], records[2]);
    assert_eq!(first["items"][1]["records"], records[1]);
    assert_eq!(first["items"][0]["actor"], "customer");
    assert_eq!(first["items"][0]["initiator"], "support");
    assert_eq!(first["items"][0]["change_count"], 1);
    assert_eq!(first["has_more"], true);
    let cursor = first["next_after"].as_str().context("history cursor")?;
    assert!(cursor.starts_with("sel1_"));
    let saved = world.caller.trace(&invocation)?;
    replay(world.caller.artifact(), &saved)?;
    let observation = &saved.request.observations[0].result;
    let raw: Value = serde_json::from_str(observation)?;
    assert_eq!(raw["items"][0]["changes"][0]["model"], "entries");
    assert_eq!(raw["items"][0]["changes"][0]["before_version"], 0);
    assert_eq!(
        raw["items"][0]["changes"][0]["fields"],
        json!(["actor", "note"])
    );
    for forbidden in [
        "SECRET-ROW-VALUE",
        "input",
        "result",
        "token",
        "body",
        "admission",
        "rejected",
    ] {
        assert!(
            !observation.contains(forbidden),
            "history leaked {forbidden}"
        );
    }
    let next = format!("/api/delegation.history?after={cursor}&limit=2");
    assert_eq!(
        server.get(&next, "another").send()?.status(),
        StatusCode::BAD_REQUEST
    );
    let callee = Server::start(world.callee.clone(), "customer")?;
    let empty = value(
        callee
            .client
            .get(format!(
                "{}/api/peer_identity.history?after=&limit=2",
                callee.origin
            ))
            .send()?,
        StatusCode::OK,
    )?;
    assert_eq!(empty["items"], json!([]));
    assert_eq!(
        callee
            .client
            .get(format!(
                "{}{}",
                callee.origin,
                next.replace("/api/delegation.history", "/api/peer_identity.history")
            ))
            .send()?
            .status(),
        StatusCode::BAD_REQUEST
    );
    // Writes newer than the boundary do not duplicate or displace old entries.
    value(
        server.record("customer", "history-four").send()?,
        StatusCode::OK,
    )?;
    let older = value(server.get(&next, "customer").send()?, StatusCode::OK)?;
    assert_eq!(older["items"].as_array().unwrap().len(), 1);
    assert_eq!(older["items"][0]["records"], records[0]);
    assert_eq!(older["has_more"], false);
    assert_eq!(older["next_after"], "");
    assert_eq!(
        server
            .get("/api/delegation.history?after=&limit=51", "customer")
            .send()?
            .status(),
        StatusCode::BAD_REQUEST
    );
    rusqlite::Connection::open(world.caller.db())?.execute(
        "UPDATE day2_selection_cursors SET expires_at=0 WHERE token=?1",
        [cursor],
    )?;
    assert_eq!(
        server.get(&next, "customer").send()?.status(),
        StatusCode::BAD_REQUEST
    );
    world.change("caller", |binding| {
        binding["authority"]["operations"]["delegation.history"]["observations"] = json!([]);
    })?;
    assert_eq!(
        server
            .get("/api/delegation.history?after=&limit=2", "customer")
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[test]
fn target_selection_requires_a_session_origin_csrf_and_both_authority_gates() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(world.caller.clone(), "other-support")?;
    let url = format!("{}/api/delegation.who", server.origin);
    assert_eq!(
        Client::new()
            .get(&url)
            .header("X-Day2-Act-As", "customer")
            .header("X-Authenticated-User", "support")
            .send()?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    for request in [
        server
            .client
            .get(&url)
            .header("X-Day2-Act-As", "customer")
            .header("Origin", &server.origin),
        server
            .client
            .get(&url)
            .header("X-Day2-Act-As", "customer")
            .header("X-CSRF-Token", &server.csrf),
        server
            .client
            .get(&url)
            .header("X-Day2-Act-As", "customer")
            .header("Origin", "https://foreign.example")
            .header("X-CSRF-Token", &server.csrf),
        server
            .client
            .get(&url)
            .header("X-Day2-Act-As", "customer")
            .header("Origin", &server.origin)
            .header("X-CSRF-Token", "wrong"),
        server
            .get("/api/delegation.who", "customer")
            .header("Sec-Fetch-Site", "cross-site"),
        server
            .get("/api/delegation.who", "customer")
            .header("Origin", "https://foreign.example"),
    ] {
        assert_eq!(request.send()?.status(), StatusCode::FORBIDDEN);
    }
    for request in [
        server.get("/api/delegation.who", ""),
        server
            .get("/api/delegation.who", "customer")
            .header("X-Day2-Act-As", "another"),
        server.get("/api/delegation.who?actor=customer", "customer"),
    ] {
        assert_eq!(request.send()?.status(), StatusCode::BAD_REQUEST);
    }
    for target in ["boss", "it", "app:worker", "svc:worker", "no-access"] {
        assert_eq!(
            server.get("/api/delegation.who", target).send()?.status(),
            StatusCode::FORBIDDEN,
            "{target}"
        );
    }
    let db = rusqlite::Connection::open(world.caller.db())?;
    let rejected: i64 = db.query_row(
        "SELECT count(*) FROM day2_audit_events WHERE kind='admission' AND outcome='rejected'
         AND actor='it' AND initiator='other-support' AND trigger='request'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        rejected, 1,
        "denied target selection lost its authenticated requester"
    );
    let forged = server
        .get("/api/delegation.who", "customer")
        .header("X-Authenticated-User", "support")
        .header("X-Day2-Authenticated", "support")
        .send()?;
    assert_eq!(
        value(forged, StatusCode::OK)?["authenticated"],
        "other-support"
    );
    for field in ["actor", "authenticated", "delegation_rule", "caller"] {
        let body = json!({"note":"one",field:"customer"});
        assert_eq!(
            server
                .record("customer", &format!("forged-{field}"))
                .body(body.to_string())
                .send()?
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let gateway = Server::start(world.caller.clone(), "gateway")?;
    assert_eq!(
        gateway
            .get("/api/delegation.who", "customer")
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(world.rows()?, 0);
    Ok(())
}

#[test]
fn act_as_is_explicitly_rejected_on_other_surfaces_and_direct_requests_stay_direct() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(world.caller.clone(), "customer")?;
    let expected = identity("customer", "customer", "", "", "request");
    assert_eq!(
        value(
            server
                .client
                .get(format!("{}/api/delegation.who", server.origin))
                .send()?,
            StatusCode::OK
        )?,
        expected
    );
    assert_eq!(
        value(
            server.get("/api/delegation.who", "customer").send()?,
            StatusCode::OK
        )?,
        expected
    );
    for path in [
        "/api/session",
        "/api/audit",
        "/api/audit/events",
        "/docs",
        "/openapi.json",
        "/mcp",
        "/",
    ] {
        assert_eq!(
            server.get(path, "another").send()?.status(),
            StatusCode::BAD_REQUEST,
            "{path}"
        );
    }
    let spec = value(
        server
            .client
            .get(format!("{}/openapi.json", server.origin))
            .send()?,
        StatusCode::OK,
    )?;
    for (path, method) in [
        ("/api/delegation.who", "get"),
        ("/api/delegation.record", "post"),
        ("/api/invocations/{id}", "get"),
    ] {
        let parameters = spec["paths"][path][method]["parameters"]
            .as_array()
            .context("parameters")?;
        for header in ["X-Day2-Act-As", "Origin", "X-CSRF-Token"] {
            assert!(
                parameters
                    .iter()
                    .any(|parameter| parameter["name"] == header),
                "{path} lacks {header}"
            );
        }
    }
    Ok(())
}

#[test]
fn only_an_app_prefix_classifies_the_requester_as_an_application_in_roc() -> Result<()> {
    let world = World::new()?;
    world.change("caller", |binding| {
        binding["authority"]["delegations"]["support"]["authenticated"] = json!(["helpapp:desk"]);
    })?;
    let server = Server::start(world.caller.clone(), "helpapp:desk")?;
    assert_eq!(
        value(
            server.get("/api/delegation.who", "customer").send()?,
            StatusCode::OK
        )?,
        identity("customer", "helpapp:desk", "support", "", "request")
    );
    Ok(())
}
