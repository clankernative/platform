use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use day2::{
    artifact::{AppBinding, Instance},
    store::{Fault, Runtime, replay},
    web::LocalServer,
};
use reqwest::{
    StatusCode,
    blocking::{Client, Response},
    redirect::Policy,
};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::mpsc,
    thread,
    time::Duration,
};

struct World {
    directory: tempfile::TempDir,
    runtime: Runtime,
}

fn apply_desired_authority(runtime: &Runtime) -> Result<()> {
    let db = rusqlite::Connection::open(runtime.db())?;
    let current = day2::authority_state::current(&db)?;
    day2::authority_state::apply_desired(
        runtime,
        &day2::authority_state::LocalOperator::assert_local("web-test-operator")?,
        &format!("web-policy-{}", current.stamp.revision),
        Some(current.stamp),
    )?;
    Ok(())
}

#[test]
fn openapi_docs_and_json_queries_share_the_admitted_contract() -> Result<()> {
    let world = World::new()?;
    world.seed("api-docs-seed")?;
    let server = Server::start(world.runtime.clone(), "alice", 0)?;
    let anonymous = Client::new();
    for path in [
        "/openapi.json",
        "/api/session",
        "/api/links.list?after=&limit=20",
    ] {
        let response = anonymous.get(format!("{}{path}", server.origin)).send()?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            serde_json::from_str::<Value>(&response.text()?)?["error"]["code"],
            "sign_in_required"
        );
    }
    let client = server.client()?;
    let response = client
        .get(format!("{}/openapi.json", server.origin))
        .send()?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(response.headers()["cache-control"], "no-store");
    let spec: Value = serde_json::from_str(&response.text()?)?;
    assert_eq!(spec["openapi"], "3.1.1");
    assert_eq!(spec["info"]["title"], "links API");
    let operations = &world.runtime.artifact().contract().operations;
    assert_eq!(
        spec["paths"].as_object().unwrap().len(),
        operations.len() + 4
    );
    assert_eq!(
        spec["paths"]["/api/invocations/{id}"]["get"]["operationId"],
        "platform.invocation"
    );
    assert_eq!(
        spec["paths"]["/api/audit"]["get"]["operationId"],
        "platform.audit"
    );
    assert_eq!(
        spec["paths"]["/api/audit/events"]["get"]["operationId"],
        "platform.audit_events"
    );
    for operation in operations {
        let path = format!("/api/{}", operation.name);
        let method = if operation.kind == "query" {
            "get"
        } else {
            "post"
        };
        assert_eq!(spec["paths"][&path][method]["operationId"], operation.name);
        let reference = spec["paths"][&path][method]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].as_str().unwrap();
        assert!(spec.pointer(reference.trim_start_matches('#')).is_some());
    }
    for excluded in ["/", "/actions", "/audit", "/login", "/docs", "/assets"] {
        assert!(spec["paths"].get(excluded).is_none());
    }
    let docs = client.get(format!("{}/docs", server.origin)).send()?;
    assert_eq!(docs.status(), StatusCode::OK);
    assert_eq!(docs.headers()["cache-control"], "no-store");
    let csp = docs.headers()["content-security-policy"]
        .to_str()?
        .to_string();
    assert!(!csp.contains("unsafe-eval") && !csp.contains("unsafe-inline"));
    assert!(csp.contains("/assets/platform/api-docs.js"));
    let html = docs.text()?;
    assert!(html.contains("/openapi.json") && html.contains("/api/links.create"));
    assert!(!html.contains("datastar") && !html.contains("/assets/ui/"));
    for asset in ["api-docs.js", "api-docs.css"] {
        let response = anonymous
            .get(format!("{}/assets/platform/{asset}", server.origin))
            .send()?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-cache");
        assert!(response.headers().contains_key("etag"));
    }
    let response = client
        .get(format!("{}/api/links.list?after=&limit=20", server.origin))
        .send()?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("x-day2-invocation"));
    let value: Value = serde_json::from_str(&response.text()?)?;
    let operation = world.runtime.artifact().operation("links.list")?;
    world.runtime.artifact().contract().outputs[&operation.output_type]
        .shape
        .validate_value(&value)?;
    assert_eq!(value["items"].as_array().unwrap().len(), 1);
    for query in [
        "",
        "after=",
        "after=&limit=0",
        "after=&limit=101",
        "after=&limit=20&extra=1",
        "after=&after=1&limit=20",
        "after=%ZZ&limit=20",
        "after=%FF&limit=20",
        "after=0&limit=20",
    ] {
        let response = client
            .get(format!("{}/api/links.list?{query}", server.origin))
            .send()?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(
            serde_json::from_str::<Value>(&response.text()?)?["error"]["code"],
            "invalid_input"
        );
    }
    Ok(())
}

#[test]
fn platform_audit_pages_bind_filters_actor_scope_and_expiry() -> Result<()> {
    use day2::audit::PageRequest;
    let world = World::new()?;
    let first_row = world.seed("audit-a")?;
    world.seed("audit-b")?;
    world.seed("audit-c")?;
    let mut instance = Instance::load(world.runtime.instance_path())?;
    instance
        .apps
        .get_mut("links")
        .unwrap()
        .authority
        .as_mut()
        .unwrap()
        .admins
        .extend(["alice".into(), "bob".into()]);
    instance
        .apps
        .get_mut("other")
        .unwrap()
        .authority
        .as_mut()
        .unwrap()
        .admins
        .insert("alice".into());
    fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    apply_desired_authority(&world.runtime)?;

    let request = PageRequest {
        limit: 2,
        ..PageRequest::default()
    };
    assert!(world.runtime.audit_page("viewer", &request).is_err());
    let first = world.runtime.audit_page("alice", &request)?;
    assert_eq!(first.items.len(), 2);
    assert_eq!(first.items[0].invocation, "audit-c");
    assert_eq!(first.items[1].invocation, "audit-b");
    assert_eq!(first.next_cursor.len(), 69);
    assert_eq!(
        first.next_cursor,
        world.runtime.audit_page("alice", &request)?.next_cursor
    );
    let mut readers = Vec::new();
    for _ in 0..4 {
        let runtime = world.runtime.clone();
        let request = request.clone();
        readers.push(thread::spawn(move || runtime.audit_page("alice", &request)));
    }
    for reader in readers {
        assert_eq!(
            reader.join().expect("audit reader")?.next_cursor,
            first.next_cursor
        );
    }
    let next = PageRequest {
        cursor: first.next_cursor.clone(),
        ..request.clone()
    };
    assert!(world.runtime.audit_page("bob", &next).is_err());
    assert!(world.runtime.audit_event_page("alice", &next).is_err());
    for changed in [
        PageRequest {
            limit: 1,
            ..next.clone()
        },
        PageRequest {
            operation: Some("links.create".into()),
            ..next.clone()
        },
        PageRequest {
            cursor: "aud1_forged".into(),
            ..request.clone()
        },
    ] {
        assert!(world.runtime.audit_page("alice", &changed).is_err());
    }
    let other = Runtime::load(world.runtime.instance_path(), "other")?;
    other.initialize()?;
    assert!(other.audit_page("alice", &request)?.items.is_empty());
    assert!(other.audit_page("alice", &next).is_err());

    // New writes are newer than the saved boundary and cannot shift older pages.
    world.seed("audit-d")?;
    let rest = world.runtime.audit_page("alice", &next)?;
    assert_eq!(rest.items.len(), 1);
    assert_eq!(rest.items[0].invocation, "audit-a");
    assert!(rest.next_cursor.is_empty());
    let record = world.runtime.audit_page(
        "alice",
        &PageRequest {
            model: Some("links".into()),
            record_id: Some(first_row["id"].as_str().unwrap().into()),
            ..PageRequest::default()
        },
    )?;
    assert_eq!(record.items.len(), 1);
    assert_eq!(record.items[0].invocation, "audit-a");
    assert_eq!(
        record.items[0].changes[0].fields,
        ["destination", "owner", "title"]
    );
    let serialized = serde_json::to_string(&record)?;
    assert!(!serialized.contains("roc-lang.org") && !serialized.contains("Roc documentation"));

    let events = world.runtime.audit_event_page(
        "alice",
        &PageRequest {
            identity: Some("audit-a".into()),
            limit: 1,
            ..PageRequest::default()
        },
    )?;
    assert_eq!(events.items.len(), 1);
    assert_eq!(events.items[0].kind, "invocation");
    let event_rest = world.runtime.audit_event_page(
        "alice",
        &PageRequest {
            identity: Some("audit-a".into()),
            limit: 1,
            cursor: events.next_cursor,
            ..PageRequest::default()
        },
    )?;
    assert_eq!(event_rest.items[0].kind, "admission");
    assert!(event_rest.next_cursor.is_empty());

    world.db()?.execute(
        "UPDATE day2_audit_cursors SET expires_at=0 WHERE token=?1",
        [&next.cursor],
    )?;
    assert!(world.runtime.audit_page("alice", &next).is_err());
    let fresh = world.runtime.audit_page("alice", &request)?;
    // Capacity pressure cannot revoke a still-valid continuation.
    let remaining = 10_000 - world.count("day2_audit_cursors")?;
    world.db()?.execute("WITH RECURSIVE n(v) AS (SELECT 1 UNION ALL SELECT v+1 FROM n WHERE v<?1)
        INSERT INTO day2_audit_cursors SELECT 'aud1_'||printf('%064x',v), 'capacity_'||v, v, 253402300799 FROM n", [remaining])?;
    assert!(
        world
            .runtime
            .audit_page(
                "alice",
                &PageRequest {
                    limit: 1,
                    ..PageRequest::default()
                }
            )
            .is_err()
    );
    assert_eq!(
        world.runtime.audit_page("alice", &request)?.next_cursor,
        fresh.next_cursor
    );
    let revoked = PageRequest {
        cursor: fresh.next_cursor,
        ..request
    };
    instance
        .apps
        .get_mut("links")
        .unwrap()
        .authority
        .as_mut()
        .unwrap()
        .admins
        .remove("alice");
    fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    apply_desired_authority(&world.runtime)?;
    assert!(world.runtime.audit_page("alice", &revoked).is_err());
    Ok(())
}

#[test]
fn platform_audit_http_docs_enforce_authority_and_strict_inputs() -> Result<()> {
    let world = World::new()?;
    let row = world.seed("audit-http")?;
    let server = Server::start(world.runtime.clone(), "admin", 0)?;
    let client = server.client()?;
    let viewer_server = Server::start(world.runtime.clone(), "viewer", 0)?;
    let viewer = viewer_server.client()?;
    let writer_server = Server::start(world.runtime.clone(), "alice", 0)?;
    let writer = writer_server.client()?;
    for path in ["/audit", "/api/audit", "/api/audit/events"] {
        assert_eq!(
            writer
                .get(format!("{}{path}", writer_server.origin))
                .send()?
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            client
                .get(format!("{}{path}", server.origin))
                .send()?
                .status(),
            StatusCode::OK
        );
    }
    for path in ["/api/audit", "/api/audit/events"] {
        assert_eq!(
            Client::new()
                .get(format!("{}{path}", server.origin))
                .send()?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            viewer
                .get(format!("{}{path}", viewer_server.origin))
                .send()?
                .status(),
            StatusCode::FORBIDDEN
        );
        let response = client.get(format!("{}{path}", server.origin)).send()?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let data: Value = serde_json::from_str(&response.text()?)?;
        assert!(data["items"].is_array() && data["next_cursor"].is_string());
        let response = client.post(format!("{}{path}", server.origin)).send()?;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()["allow"], "GET");
        for query in [
            "limit=0",
            "limit=51",
            "limit=-1",
            "limit=abc",
            "limit=1&limit=2",
            "extra=1",
            "cursor=forged",
            "actor=%FF",
            "actor=%ZZ",
        ] {
            assert_eq!(
                client
                    .get(format!("{}{path}?{query}", server.origin))
                    .send()?
                    .status(),
                StatusCode::BAD_REQUEST,
                "{path}?{query}"
            );
        }
    }
    for path in [
        "/api/audit?kind=admission",
        "/api/audit?record_id=unknown",
        "/api/audit?status=pending",
        "/api/audit/events?model=links",
        "/api/audit/events?kind=unknown",
        "/api/audit/events?outcome=unknown",
    ] {
        assert_eq!(
            client
                .get(format!("{}{path}", server.origin))
                .send()?
                .status(),
            StatusCode::BAD_REQUEST,
            "{path}"
        );
    }
    let data: Value = serde_json::from_str(
        &client
            .get(format!("{}/api/audit", server.origin))
            .query(&[
                ("model", "links"),
                ("record_id", row["id"].as_str().unwrap()),
            ])
            .send()?
            .text()?,
    )?;
    assert_eq!(data["items"].as_array().unwrap().len(), 1);
    assert_eq!(data["items"][0]["invocation"], "audit-http");
    assert!(data["items"][0]["changes"][0].get("values").is_none());
    let docs = client
        .get(format!("{}/docs", server.origin))
        .send()?
        .text()?;
    assert!(docs.contains("platform.audit") && docs.contains("platform.audit_events"));
    assert!(
        docs.contains("/api/audit/events") && docs.contains("applications cannot disable capture")
    );
    let mut instance = Instance::load(world.runtime.instance_path())?;
    instance
        .apps
        .get_mut("links")
        .unwrap()
        .authority
        .as_mut()
        .unwrap()
        .admins
        .insert("owner-only".into());
    fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    apply_desired_authority(&world.runtime)?;
    let owner_server = Server::start(world.runtime.clone(), "owner-only", 0)?;
    let owner = owner_server.client()?;
    for path in [
        "/audit",
        "/api/audit",
        "/api/audit/events",
        "/docs",
        "/openapi.json",
    ] {
        assert_eq!(
            owner
                .get(format!("{}{path}", owner_server.origin))
                .send()?
                .status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        owner
            .get(format!(
                "{}/api/links.list?after=&limit=20",
                owner_server.origin
            ))
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[test]
fn api_commands_enforce_csrf_authority_and_stable_idempotency() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(world.runtime.clone(), "alice", 0)?;
    let client = server.client()?;
    let session: Value = serde_json::from_str(
        &client
            .get(format!("{}/api/session", server.origin))
            .send()?
            .text()?,
    )?;
    assert_eq!(session["actor"], "alice");
    let csrf = session["csrf_token"].as_str().unwrap();
    let input = json!({"title":"API link","destination":"https://example.com/"});
    let post = |path: &str, key: &str, input: &Value| {
        client
            .post(format!("{}{path}", server.origin))
            .header("Origin", &server.origin)
            .header("X-CSRF-Token", csrf)
            .header("Idempotency-Key", key)
            .header("Content-Type", "application/json")
            .body(input.to_string())
            .send()
    };
    for (origin, token, key, content_type, expected) in [
        (
            "https://evil.example",
            csrf,
            "test",
            "application/json",
            StatusCode::FORBIDDEN,
        ),
        (
            server.origin.as_str(),
            "forged",
            "test",
            "application/json",
            StatusCode::FORBIDDEN,
        ),
        (
            server.origin.as_str(),
            csrf,
            "",
            "application/json",
            StatusCode::BAD_REQUEST,
        ),
        (
            server.origin.as_str(),
            csrf,
            "bad key",
            "application/json",
            StatusCode::BAD_REQUEST,
        ),
        (
            server.origin.as_str(),
            csrf,
            "test",
            "text/plain",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
    ] {
        let response = client
            .post(format!("{}/api/links.create", server.origin))
            .header("Origin", origin)
            .header("X-CSRF-Token", token)
            .header("Idempotency-Key", key)
            .header("Content-Type", content_type)
            .body(input.to_string())
            .send()?;
        assert_eq!(response.status(), expected);
        assert!(serde_json::from_str::<Value>(&response.text()?)?["error"]["code"].is_string());
    }
    assert_eq!(world.count("links")?, 0);
    let first = post("/api/links.create", "api-retry", &input)?;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(first.headers()["cache-control"], "no-store");
    let invocation = first.headers()["x-day2-invocation"].clone();
    let saved: Value = serde_json::from_str(&first.text()?)?;
    let retry = post("/api/links.create", "api-retry", &input)?;
    assert_eq!(retry.status(), StatusCode::OK);
    assert_eq!(retry.headers()["x-day2-invocation"], invocation);
    assert_eq!(serde_json::from_str::<Value>(&retry.text()?)?, saved);
    assert_eq!(world.count("links")?, 1);
    let mut different = input.clone();
    different["title"] = json!("Different");
    assert_eq!(
        post("/api/links.create", "api-retry", &different)?.status(),
        StatusCode::CONFLICT
    );
    let edit =
        json!({"link_id":saved["id"],"expected_version":saved["version"],"title":"Updated link"});
    assert_eq!(
        post("/api/links.edit", "api-retry", &edit)?.status(),
        StatusCode::CONFLICT
    );
    let mut stale = edit.clone();
    stale["expected_version"] = json!(999);
    let rejected = post("/api/links.edit", "api-stale", &stale)?;
    assert_eq!(rejected.status(), StatusCode::CONFLICT);
    assert_eq!(
        serde_json::from_str::<Value>(&rejected.text()?)?["error"]["code"],
        "conflict"
    );
    assert_eq!(
        post("/api/links.create", "invalid-body", &json!({}))?.status(),
        StatusCode::BAD_REQUEST
    );
    for (method, path, expected, allow) in [
        (
            reqwest::Method::GET,
            "/api/links.create",
            StatusCode::METHOD_NOT_ALLOWED,
            Some("POST"),
        ),
        (
            reqwest::Method::DELETE,
            "/api/links.list",
            StatusCode::METHOD_NOT_ALLOWED,
            Some("GET"),
        ),
        (
            reqwest::Method::GET,
            "/api/missing",
            StatusCode::NOT_FOUND,
            None,
        ),
        (
            reqwest::Method::POST,
            "/api/$effects.complete",
            StatusCode::NOT_FOUND,
            None,
        ),
    ] {
        let response = client
            .request(method, format!("{}{path}", server.origin))
            .send()?;
        assert_eq!(response.status(), expected);
        assert_eq!(
            response
                .headers()
                .get("allow")
                .and_then(|v| v.to_str().ok()),
            allow
        );
        assert!(serde_json::from_str::<Value>(&response.text()?)?["error"].is_object());
    }
    let oversized = client
        .post(format!("{}/api/links.create", server.origin))
        .body("x".repeat(65_537))
        .send()?;
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        serde_json::from_str::<Value>(&oversized.text()?)?["error"]["code"],
        "body_too_large"
    );
    let mut instance = Instance::load(world.runtime.instance_path())?;
    instance.apps.get_mut("links").unwrap().writers.clear();
    instance
        .apps
        .get_mut("links")
        .unwrap()
        .authority
        .as_mut()
        .unwrap()
        .admins
        .insert("alice".into());
    fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    apply_desired_authority(&world.runtime)?;
    // An owner retains platform audit access independently of app membership.
    // Platform discovery/session endpoints remain available for the owner.
    for path in [
        "/docs",
        "/openapi.json",
        "/api/session",
        "/api/audit",
        "/api/audit/events",
    ] {
        assert_eq!(
            client
                .get(format!("{}{path}", server.origin))
                .send()?
                .status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        client
            .get(format!("{}/api/links.list?after=&limit=20", server.origin))
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post("/api/links.create", "api-retry", &input)?.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(world.count("links")?, 1);
    Ok(())
}

#[test]
fn api_reader_can_query_but_cannot_run_commands() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(world.runtime.clone(), "viewer", 0)?;
    let client = server.client()?;
    assert_eq!(
        client
            .get(format!("{}/api/links.list?after=&limit=20", server.origin))
            .send()?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client
            .post(format!("{}/api/links.create", server.origin))
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    Ok(())
}
impl World {
    fn new() -> Result<Self> {
        Self::named("webco")
    }
    /// A world bound to the repeated-field fixture, whose `things.tag` command
    /// declares `tags : List(Str)` — the only shape the form protocol permits to
    /// repeat. Separate from the links world so list decoding is exercised
    /// without perturbing the row-authority suites.
    fn repeated_fields() -> Result<Self> {
        let artifact = std::env::var_os("DAY2_TEST_REPEATED_FIELD_ARTIFACT")
            .map(PathBuf::from)
            .context("run xtask verify or set DAY2_TEST_REPEATED_FIELD_ARTIFACT")?;
        let directory = tempfile::tempdir()?;
        let instance = Instance {
            installation: "repeatco".into(),
            environment: "test".into(),
            branding: None,
            control: None,
            resources: None,
            apps: BTreeMap::from([(
                "things".into(),
                AppBinding {
                    retention: Default::default(),
                    journal: None,
                    security: None,
                    resource_policies: Vec::new(),
                    credential_families: Default::default(),
                    oauth_connections: Default::default(),
                    schedules: Default::default(),
                    ingress: Default::default(),
                    runtime: None,
                    authority: Some(serde_json::from_str(include_str!(
                        "../../../fixtures/authority-policies/repeated-field.json"
                    ))?),
                    artifact: artifact.to_string_lossy().into(),
                    readers: BTreeSet::from(["viewer".into()]),
                    writers: BTreeSet::from(["alice".into()]),
                    edge: None,
                },
            )]),
            identity: None,
            security_shell: None,
            oauth_shell_transport: None,
            oauth_clients: None,
            oauth_runtime: None,
        };
        let path = directory.path().join("instance.json");
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let runtime = Runtime::load(&path, "things")?;
        runtime.initialize()?;
        Ok(Self { directory, runtime })
    }
    fn named(installation: &str) -> Result<Self> {
        let artifact = std::env::var_os("DAY2_TEST_HTTP_ARTIFACT")
            .map(PathBuf::from)
            .context("run xtask verify or set DAY2_TEST_HTTP_ARTIFACT")?;
        let directory = tempfile::tempdir()?;
        let instance = Instance {
            installation: installation.into(),
            environment: "test".into(),
            branding: None,
            control: None,
            resources: None,
            identity: None,
            security_shell: None,
            oauth_shell_transport: None,
            oauth_clients: None,
            oauth_runtime: None,
            apps: BTreeMap::from([
                (
                    "links".into(),
                    AppBinding {
                        retention: Default::default(),
                        journal: None,
                        security: None,
                        resource_policies: Vec::new(),
                        credential_families: Default::default(),
                        oauth_connections: Default::default(),
                        schedules: Default::default(),
                        ingress: Default::default(),
                        runtime: None,
                        authority: Some(serde_json::from_str(include_str!(
                            "../../../fixtures/authority-policies/owned-links.json"
                        ))?),
                        artifact: artifact.to_string_lossy().into(),
                        readers: BTreeSet::from(["viewer".into()]),
                        writers: BTreeSet::from(["alice".into()]),
                        edge: None,
                    },
                ),
                (
                    "other".into(),
                    AppBinding {
                        retention: Default::default(),
                        journal: None,
                        security: None,
                        resource_policies: Vec::new(),
                        credential_families: Default::default(),
                        oauth_connections: Default::default(),
                        schedules: Default::default(),
                        ingress: Default::default(),
                        runtime: None,
                        authority: Some(serde_json::from_str(include_str!(
                            "../../../fixtures/authority-policies/owned-links.json"
                        ))?),
                        artifact: artifact.to_string_lossy().into(),
                        readers: BTreeSet::new(),
                        writers: BTreeSet::from(["alice".into()]),
                        edge: None,
                    },
                ),
            ]),
        };
        let path = directory.path().join("instance.json");
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let runtime = Runtime::load(&path, "links")?;
        runtime.initialize()?;
        Ok(Self { directory, runtime })
    }
    fn db(&self) -> Result<rusqlite::Connection> {
        Ok(rusqlite::Connection::open(self.runtime.db())?)
    }
    fn count(&self, table: &str) -> Result<i64> {
        Ok(self
            .db()?
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })?)
    }
    fn seed(&self, id: &str) -> Result<Value> {
        let result = self.runtime.invoke(
            "links.create",
            "alice",
            id,
            &json!({"title":"Roc documentation","destination":"https://www.roc-lang.org/"}),
            100,
            Fault::None,
        )?;
        assert_eq!(result.status, "success", "{}", result.error);
        Ok(result.result)
    }
}
struct Server {
    origin: String,
    login: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<Result<()>>>,
}

#[test]
fn apps_without_pages_get_the_same_api_and_documentation() -> Result<()> {
    let artifact = std::env::var_os("DAY2_TEST_RELATIONAL_ARTIFACT")
        .map(PathBuf::from)
        .context("run xtask verify or set DAY2_TEST_RELATIONAL_ARTIFACT")?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("instance.json");
    let policy: Value = serde_json::from_str(include_str!(
        "../../../fixtures/authority-policies/relational-conformance.json"
    ))?;
    fs::write(
        &path,
        serde_json::to_vec(
            &json!({"installation":"api_only","environment":"test","apps":{"relational":{
                "artifact":artifact,"readers":[],"writers":["alice"],"authority":policy
            }}}),
        )?,
    )?;
    let runtime = Runtime::load(&path, "relational")?;
    assert!(runtime.artifact().contract().pages.is_empty());
    let server = Server::start(runtime, "alice", 0)?;
    let client = server.client()?;
    let root = client.get(&server.origin).send()?;
    assert_eq!(root.status(), StatusCode::SEE_OTHER);
    assert_eq!(root.headers()["location"], "/docs");
    assert_eq!(
        client
            .get(format!("{}/docs", server.origin))
            .send()?
            .status(),
        StatusCode::OK
    );
    let spec: Value = serde_json::from_str(
        &client
            .get(format!("{}/openapi.json", server.origin))
            .send()?
            .text()?,
    )?;
    assert_eq!(
        spec["paths"]["/api/deals.list"]["get"]["operationId"],
        "deals.list"
    );
    assert_eq!(
        spec["paths"]["/api/deals.seed"]["post"]["operationId"],
        "deals.seed"
    );
    Ok(())
}
impl Server {
    fn start(runtime: Runtime, actor: &str, port: u16) -> Result<Self> {
        let (send, receive) = mpsc::channel();
        let (stop, done) = tokio::sync::oneshot::channel();
        let actor = actor.to_string();
        let thread = thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?
                .block_on(async move {
                    let server = LocalServer::bind(runtime, &actor, port).await?;
                    send.send((server.origin.clone(), server.login_url.clone()))?;
                    server
                        .serve(async {
                            let _ = done.await;
                        })
                        .await
                })
        });
        let (origin, login) = receive.recv_timeout(Duration::from_secs(10))?;
        Ok(Self {
            origin,
            login,
            stop: Some(stop),
            thread: Some(thread),
        })
    }
    fn client(&self) -> Result<Client> {
        let client = Client::builder()
            .cookie_store(true)
            .redirect(Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;
        let response = client.get(&self.login).send()?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let fields = form(&response.text()?, 0)?;
        let login = self.post(&client, "/login", &fields)?;
        assert_eq!(login.status(), StatusCode::SEE_OTHER);
        assert_eq!(login.headers()["cache-control"], "no-store");
        let cookie = login.headers()["set-cookie"].to_str()?;
        assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
        Ok(client)
    }
    fn post(
        &self,
        client: &Client,
        path: &str,
        fields: &BTreeMap<String, String>,
    ) -> Result<Response> {
        Ok(client
            .post(format!("{}{path}", self.origin))
            .header("Origin", &self.origin)
            .form(fields)
            .send()?)
    }
    fn page(&self, client: &Client) -> Result<String> {
        let response = client.get(format!("{}/", self.origin)).send()?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(
            response.headers()["content-security-policy"]
                .to_str()?
                .contains("frame-ancestors 'none'")
        );
        Ok(response.text()?)
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            assert!(thread.join().expect("server thread").is_ok());
        }
    }
}
fn selector(value: &str) -> Selector {
    Selector::parse(value).expect("test selector")
}
fn form(html: &str, index: usize) -> Result<BTreeMap<String, String>> {
    let document = Html::parse_document(html);
    let form = document
        .select(&selector("form"))
        .nth(index)
        .context("form missing")?;
    Ok(form
        .select(&selector("input[name]"))
        .map(|input| {
            (
                input.value().attr("name").unwrap().into(),
                input.value().attr("value").unwrap_or("").into(),
            )
        })
        .collect())
}
fn selected_form(html: &str, query: &str) -> Result<BTreeMap<String, String>> {
    let document = Html::parse_document(html);
    let form = document
        .select(&selector(query))
        .next()
        .with_context(|| format!("form missing: {query}"))?;
    Ok(form
        .select(&selector("input[name]"))
        .map(|input| {
            (
                input.value().attr("name").unwrap().into(),
                input.value().attr("value").unwrap_or("").into(),
            )
        })
        .collect())
}
fn create_form(html: &str) -> Result<BTreeMap<String, String>> {
    selected_form(html, "#create-link-form")
}
fn claims(fields: &BTreeMap<String, String>) -> Result<Value> {
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(
        fields["_ticket"].split_once('.').context("ticket")?.0,
    )?)?)
}
fn patch_elements(patch: &str) -> Result<String> {
    let lines: Vec<_> = patch
        .lines()
        .filter_map(|line| line.strip_prefix("data: elements "))
        .collect();
    anyhow::ensure!(!lines.is_empty(), "patch elements missing");
    Ok(lines.join("\n"))
}

#[test]
fn repeated_controls_decode_as_an_ordered_list_with_an_explicit_empty() -> Result<()> {
    // Repetition is authorized per field by the declared input record, so this
    // exercises the one command shape that permits it. Order is the submitted
    // document order, and the empty list has its own encoding rather than being
    // inferred from an absent field.
    let world = World::repeated_fields()?;
    let server = Server::start(world.runtime.clone(), "alice", 0)?;
    let client = server.client()?;
    let page = server.page(&client)?;
    let form = selected_form(&page, "form.command")?;
    let csrf = form["_csrf"].clone();
    let ticket = form["_ticket"].clone();

    let send = |pairs: &[(&str, &str)]| -> Result<StatusCode> {
        let mut encoded = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in pairs {
            encoded.append_pair(key, value);
        }
        Ok(client
            .post(format!("{}/actions", server.origin))
            .header("Origin", &server.origin)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(encoded.finish())
            .send()?
            .status())
    };
    // Each submission needs its own ticket, so re-read the form between posts.
    let fresh = |client: &Client| -> Result<(String, String)> {
        let page = server.page(client)?;
        let form = selected_form(&page, "form.command")?;
        Ok((form["_csrf"].clone(), form["_ticket"].clone()))
    };
    // tags_joined carries both order and arity; U64 columns are stored as blobs.
    let stored = |name: &str| -> Result<String> {
        Ok(world.db()?.query_row(
            "SELECT tags_joined FROM things WHERE name=?1",
            [name],
            |row| row.get(0),
        )?)
    };

    // Document order is the list order, and is not normalised away.
    assert_eq!(
        send(&[
            ("_csrf", &csrf),
            ("_ticket", &ticket),
            ("name", "ordered"),
            ("attributes.role", "reader"),
            ("groups", "eng"),
            ("tags", "docs"),
            ("tags", "runbook"),
        ])?,
        StatusCode::SEE_OTHER
    );
    assert_eq!(stored("ordered")?, "docs,runbook");

    // The reverse submission is a different value, not the same set.
    let (csrf, ticket) = fresh(&client)?;
    assert_eq!(
        send(&[
            ("_csrf", &csrf),
            ("_ticket", &ticket),
            ("name", "reversed"),
            ("attributes.role", "reader"),
            ("groups", "eng"),
            ("tags", "runbook"),
            ("tags", "docs"),
        ])?,
        StatusCode::SEE_OTHER
    );
    assert_eq!(stored("reversed")?, "runbook,docs");

    // One empty occurrence is the empty list; absence never has to mean anything.
    let (csrf, ticket) = fresh(&client)?;
    assert_eq!(
        send(&[
            ("_csrf", &csrf),
            ("_ticket", &ticket),
            ("name", "empty"),
            ("attributes.role", "reader"),
            ("groups", "eng"),
            ("tags", ""),
        ])?,
        StatusCode::SEE_OTHER
    );
    assert_eq!(stored("empty")?, "");

    // A blank among several is refused rather than silently dropped. An invalid
    // item is a value problem, so it surfaces on the form as 422 rather than as
    // the 400 a malformed body shape produces.
    let (csrf, ticket) = fresh(&client)?;
    assert_eq!(
        send(&[
            ("_csrf", &csrf),
            ("_ticket", &ticket),
            ("name", "blank-among"),
            ("attributes.role", "reader"),
            ("groups", "eng"),
            ("tags", "docs"),
            ("tags", ""),
            ("tags", "runbook"),
        ])?,
        StatusCode::UNPROCESSABLE_ENTITY
    );

    // Duplicate items are refused, matching the uniqueness rule domains apply.
    let (csrf, ticket) = fresh(&client)?;
    assert_eq!(
        send(&[
            ("_csrf", &csrf),
            ("_ticket", &ticket),
            ("name", "duplicated"),
            ("attributes.role", "reader"),
            ("groups", "eng"),
            ("tags", "docs"),
            ("tags", "docs"),
        ])?,
        StatusCode::UNPROCESSABLE_ENTITY
    );

    // The combined case: a body that legitimately repeats an app field still may
    // not repeat the CSRF token. This is the shape a permissive parser would have
    // accepted, because "reject every duplicate" is no longer available.
    let (csrf, ticket) = fresh(&client)?;
    assert_eq!(
        send(&[
            ("_csrf", &csrf),
            ("_csrf", "forged"),
            ("_ticket", &ticket),
            ("name", "polluted"),
            ("attributes.role", "reader"),
            ("groups", "eng"),
            ("tags", "docs"),
            ("tags", "runbook"),
        ])?,
        StatusCode::FORBIDDEN
    );
    // Nor may the single-valued field repeat alongside a legitimate list.
    let (csrf, ticket) = fresh(&client)?;
    assert_eq!(
        send(&[
            ("_csrf", &csrf),
            ("_ticket", &ticket),
            ("name", "one"),
            ("name", "two"),
            ("attributes.role", "reader"),
            ("groups", "eng"),
            ("tags", "docs"),
        ])?,
        StatusCode::BAD_REQUEST
    );

    // Only the three accepted submissions were stored.
    assert_eq!(world.count("things")?, 3);
    Ok(())
}

#[test]
fn keyed_and_unique_controls_decode_to_canonical_maps_and_sets() -> Result<()> {
    // A map carries its key in the control name, so one control is always one
    // complete entry and a half-populated pair cannot be expressed. A set repeats
    // its field name like a list but denotes one value per membership, so it is
    // canonically ordered and duplicates are refused rather than collapsed.
    let world = World::repeated_fields()?;
    let server = Server::start(world.runtime.clone(), "alice", 0)?;
    let client = server.client()?;
    let send = |pairs: &[(&str, &str)]| -> Result<StatusCode> {
        let mut encoded = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in pairs {
            encoded.append_pair(key, value);
        }
        Ok(client
            .post(format!("{}/actions", server.origin))
            .header("Origin", &server.origin)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(encoded.finish())
            .send()?
            .status())
    };
    let fresh = || -> Result<(String, String)> {
        let page = server.page(&client)?;
        let form = selected_form(&page, "form.command")?;
        Ok((form["_csrf"].clone(), form["_ticket"].clone()))
    };
    let stored = |name: &str| -> Result<(String, String)> {
        Ok(world.db()?.query_row(
            "SELECT attributes_joined, groups_joined FROM things WHERE name=?1",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?)
    };

    // Keys travel in the control names; entries come back in canonical key order
    // regardless of the order the controls were submitted in.
    let (csrf, ticket) = fresh()?;
    assert_eq!(
        send(&[
            ("_csrf", &csrf),
            ("_ticket", &ticket),
            ("name", "canonical"),
            ("tags", "docs"),
            ("attributes.team", "platform"),
            ("attributes.role", "reader"),
            ("groups", "eng"),
        ])?,
        StatusCode::SEE_OTHER
    );
    let (attributes, groups) = stored("canonical")?;
    assert_eq!(attributes, "role=reader,team=platform");
    assert_eq!(groups, "eng");

    // A set is order-insensitive: the reverse submission is the same value, unlike
    // the list case where order is preserved.
    let (csrf, ticket) = fresh()?;
    assert_eq!(
        send(&[
            ("_csrf", &csrf),
            ("_ticket", &ticket),
            ("name", "sorted"),
            ("tags", "docs"),
            ("attributes.role", "reader"),
            ("groups", "zulu"),
            ("groups", "alpha"),
        ])?,
        StatusCode::SEE_OTHER
    );
    assert_eq!(stored("sorted")?.1, "alpha,zulu");

    // Duplicate set members are refused, not silently collapsed.
    let (csrf, ticket) = fresh()?;
    assert_eq!(
        send(&[
            ("_csrf", &csrf),
            ("_ticket", &ticket),
            ("name", "dupe-member"),
            ("tags", "docs"),
            ("attributes.role", "reader"),
            ("groups", "eng"),
            ("groups", "eng"),
        ])?,
        StatusCode::UNPROCESSABLE_ENTITY
    );

    // A repeated map key is a duplicate control, refused before decoding.
    let (csrf, ticket) = fresh()?;
    assert_eq!(
        send(&[
            ("_csrf", &csrf),
            ("_ticket", &ticket),
            ("name", "dupe-key"),
            ("tags", "docs"),
            ("attributes.role", "reader"),
            ("attributes.role", "writer"),
            ("groups", "eng"),
        ])?,
        StatusCode::BAD_REQUEST
    );

    // Both collections have an explicit empty encoding.
    let (csrf, ticket) = fresh()?;
    assert_eq!(
        send(&[
            ("_csrf", &csrf),
            ("_ticket", &ticket),
            ("name", "empty-both"),
            ("tags", ""),
            ("attributes.role", ""),
            ("groups", ""),
        ])?,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a blank map value is not an empty map"
    );

    assert_eq!(world.count("things")?, 2);
    Ok(())
}

#[test]
fn repeated_control_fields_cannot_pollute_csrf_or_ticket_verification() -> Result<()> {
    // A form body may legitimately repeat a field the operation declares as a list,
    // so the body parser can no longer reject every duplicate key outright. The CSRF
    // token and signed ticket are therefore read by an exact single-occurrence scan
    // before the ticket is known. Without that, a submitted duplicate would make
    // verification depend on which occurrence the parser happened to keep.
    let world = World::new()?;
    let server = Server::start(world.runtime.clone(), "alice", 0)?;
    let client = server.client()?;
    let page = server.page(&client)?;
    let create = selected_form(&page, "form.command")?;
    let body = |pairs: &[(&str, &str)]| {
        let mut encoded = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in pairs {
            encoded.append_pair(key, value);
        }
        encoded.finish()
    };
    let send = |raw: String| -> Result<StatusCode> {
        Ok(client
            .post(format!("{}/actions", server.origin))
            .header("Origin", &server.origin)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(raw)
            .send()?
            .status())
    };
    let csrf = create["_csrf"].as_str();
    let ticket = create["_ticket"].as_str();

    // A well-formed submission still succeeds, so the checks below fail for the
    // stated reason rather than because the body was malformed.
    assert_eq!(
        send(body(&[
            ("_csrf", csrf),
            ("_ticket", ticket),
            ("title", "Accepted"),
            ("destination", "https://example.com/accepted"),
        ]))?,
        StatusCode::SEE_OTHER
    );

    // A second CSRF token must not be admitted, whichever occurrence wins. The
    // duplicate is refused while reading the token, so this is an authorization
    // failure rather than a field-shape complaint.
    for extra in ["", csrf, "forged"] {
        assert_eq!(
            send(body(&[
                ("_csrf", csrf),
                ("_csrf", extra),
                ("_ticket", ticket),
                ("title", "Polluted"),
                ("destination", "https://example.com/polluted"),
            ]))?,
            StatusCode::FORBIDDEN,
            "duplicate _csrf admitted with second value {extra:?}"
        );
    }

    // Nor a second ticket, which carries row identity and expected version.
    assert_eq!(
        send(body(&[
            ("_csrf", csrf),
            ("_ticket", ticket),
            ("_ticket", ticket),
            ("title", "Polluted"),
            ("destination", "https://example.com/polluted"),
        ]))?,
        StatusCode::FORBIDDEN
    );

    // A field the operation does not declare as a list still may not repeat.
    assert_eq!(
        send(body(&[
            ("_csrf", csrf),
            ("_ticket", ticket),
            ("title", "One"),
            ("title", "Two"),
            ("destination", "https://example.com/two"),
        ]))?,
        StatusCode::BAD_REQUEST
    );

    // Exactly one link was created: every polluted attempt was refused.
    assert_eq!(world.count("links")?, 1);
    Ok(())
}

#[test]
fn real_http_mpa_datastar_queries_forms_and_redacted_audit() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(world.runtime.clone(), "alice", 0)?;
    let client = server.client()?;
    let page = server.page(&client)?;
    assert!(page.contains("Owned links") && page.contains("No links yet."));
    let mut fields = create_form(&page)?;
    fields.insert(
        "title".into(),
        "<script>alert('x')</script> & documentation".into(),
    );
    fields.insert("destination".into(), "https://example.com/?a=1&b=2".into());
    let response = server.post(&client, "/actions", &fields)?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let id = response.headers()["x-day2-invocation"]
        .to_str()?
        .to_string();
    assert_eq!(world.count("links")?, 1);
    let page = server.page(&client)?;
    assert!(page.contains("&lt;script&gt;"));
    let parsed = Html::parse_document(&page);
    assert_eq!(parsed.select(&selector("script")).count(), 3);
    assert!(parsed.select(&selector("script")).all(|script| {
        script.value().attr("type") == Some("module")
            && script.value().attr("src").is_some_and(|src| {
                src == "/assets/platform/datastar-1.0.1.js"
                    || src == "/assets/platform/forms.js"
                    || (src.starts_with("/assets/ui/") && src.ends_with("/app.js"))
            })
            && script.text().collect::<String>().trim().is_empty()
    }));
    assert!(
        parsed
            .select(&selector("a.external"))
            .next()
            .unwrap()
            .text()
            .collect::<String>()
            .contains("<script>")
    );
    let mut edit = selected_form(&page, ".link-row form.command")?;
    let edit_claims = claims(&edit)?;
    assert!(edit_claims["bound"]["link_id"].is_string());
    assert_eq!(edit_claims["bound"]["expected_version"], 1);
    assert_eq!(edit_claims["editable"], json!(["title"]));
    assert_eq!(
        edit.keys().map(String::as_str).collect::<Vec<_>>(),
        ["_csrf", "_ticket", "title"]
    );
    assert_eq!(
        attribute(&page, ".link-row form.command", "data-day2-invocation")?,
        format!("web-{}", edit_claims["nonce"].as_str().unwrap())
    );
    let mut forged_bound = edit.clone();
    forged_bound.insert("expected_version".into(), "999".into());
    assert_eq!(
        server.post(&client, "/actions", &forged_bound)?.status(),
        StatusCode::BAD_REQUEST
    );
    edit.insert(
        "title".into(),
        "<script>alert('x')</script> & edited documentation".into(),
    );
    let response = client
        .post(format!("{}/actions", server.origin))
        .header("Origin", &server.origin)
        .header("Datastar-Request", "true")
        .form(&edit)
        .send()?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    assert_eq!(response.headers()["cache-control"], "no-store");
    let patch = response.text()?;
    assert!(patch.starts_with("event: datastar-patch-elements\n") && patch.ends_with("\n\n"));
    let fragment = Html::parse_fragment(&patch_elements(&patch)?);
    assert_eq!(fragment.select(&selector("main#day2-main")).count(), 1);
    assert!(patch.contains("edited documentation"));
    assert_eq!(fragment.select(&selector("script")).count(), 0);
    assert_eq!(
        fragment
            .select(&selector(".link-row"))
            .next()
            .unwrap()
            .value()
            .attr("data-title"),
        Some("<script>alert('x')</script> & edited documentation")
    );
    assert!(fragment.select(&selector("*")).all(|element| {
        element
            .value()
            .attrs()
            .all(|(name, _)| !name.starts_with("on"))
    }));
    let updated = Html::parse_document(&server.page(&client)?);
    assert_eq!(
        updated
            .select(&selector(".link-row[data-version='2']"))
            .count(),
        1
    );
    assert_eq!(world.count("day2_audit_changes")?, 2);
    let owner = Server::start(world.runtime.clone(), "admin", 0)?;
    let audit = owner
        .client()?
        .get(format!("{}/audit?operation=links.create", owner.origin))
        .send()?
        .text()?;
    assert!(
        audit.contains("Values redacted.")
            && audit.contains("destination, owner, title")
            && !audit.contains("alert(")
    );
    replay(world.runtime.artifact(), &world.runtime.trace(&id)?)?;
    let evidence = world.directory.path().join("properties");
    day2::properties::require(
        world.runtime.artifact(),
        &world.runtime.inspect()?,
        &evidence,
    )?;
    assert!(
        world
            .runtime
            .accept(
                "$page.links",
                "alice",
                "forged-page",
                &json!({"after":"","limit":20}),
                100
            )
            .is_err()
    );
    assert!(
        world
            .runtime
            .render_page(
                "missing",
                "alice",
                "missing-page",
                &json!({"after":"","limit":20}),
                100
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn template_page_query_data_is_deterministic_and_read_only() -> Result<()> {
    let world = World::new()?;
    world.seed("query-seed")?;
    let before = world.runtime.inspect()?;
    let input = json!({"after":"","limit":20});
    let first = world
        .runtime
        .render_page("links", "alice", "template-read-one", &input, 100)?;
    let second = world
        .runtime
        .render_page("links", "alice", "template-read-two", &input, 100)?;
    assert_eq!(first.status, "success");
    assert_eq!(second.status, "success");
    assert!(first.result.is_object(), "template pages return query data");
    assert_eq!(first.result, second.result);
    assert_eq!(world.runtime.inspect()?, before);
    assert_eq!(world.count("day2_audit_changes")?, 1);
    for id in ["template-read-one", "template-read-two"] {
        replay(world.runtime.artifact(), &world.runtime.trace(id)?)?;
    }
    Ok(())
}

#[test]
fn consumed_local_login_link_redirects_signed_in_browser_but_never_authenticates_another()
-> Result<()> {
    let world = World::new()?;
    let server = Server::start(world.runtime.clone(), "alice", 0)?;
    let client = server.client()?;
    let reopened = client.get(&server.login).send()?;
    assert_eq!(reopened.status(), StatusCode::SEE_OTHER);
    assert_eq!(reopened.headers()["location"], "/");
    assert!(!reopened.headers().contains_key("set-cookie"));
    let anonymous = Client::builder().redirect(Policy::none()).build()?;
    let denied = anonymous.get(&server.login).send()?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(!denied.headers().contains_key("set-cookie"));
    assert!(denied.text()?.contains("invalid, expired, or already used"));
    assert_eq!(world.count("day2_web_sessions")?, 1);
    Ok(())
}

#[test]
fn explicit_paths_bind_typed_ids_and_preserve_detail_form_navigation() -> Result<()> {
    let world = World::new()?;
    let first = world.seed("detail-one")?;
    let second = world.seed("detail-two")?;
    let first_id = first["id"].as_str().unwrap();
    let second_id = second["id"].as_str().unwrap();
    let routes = day2::routing::Catalog::from_artifact(world.runtime.artifact().contract())?;
    let url = routes.build_url("link", &json!({"link_id": first_id}))?;
    assert_eq!(url, format!("/links/{first_id}"));
    assert_eq!(routes.build_url("links", &json!({}))?, "/");
    assert_eq!(
        world.runtime.artifact().page("links")?.template,
        "pages/directory.html"
    );
    assert_eq!(
        world.runtime.artifact().page("link")?.template,
        "pages/details.html"
    );
    let server = Server::start(world.runtime.clone(), "alice", 0)?;
    let client = server.client()?;
    let directory = Html::parse_document(&server.page(&client)?);
    let links: BTreeSet<_> = directory
        .select(&selector("a.details-link"))
        .map(|link| link.value().attr("href").unwrap().to_owned())
        .collect();
    assert_eq!(
        links,
        BTreeSet::from([url.clone(), format!("/links/{second_id}")])
    );
    let response = client.get(format!("{}{url}", server.origin)).send()?;
    assert_eq!(response.status(), StatusCode::OK);
    let detail = response.text()?;
    assert!(detail.contains("id=\"owned-link-details\"") && detail.contains("Roc documentation"));
    assert_eq!(attribute(&detail, ".breadcrumbs a", "href")?, "/");
    let mut fields = selected_form(&detail, "form.edit-form")?;
    fields.insert("title".into(), "Edited first link".into());
    let ticket = claims(&fields)?;
    assert_eq!(ticket["page"], "link");
    assert_eq!(ticket["page_input"], json!({"link_id":first_id}));
    assert_eq!(ticket["bound"]["link_id"], first_id);
    for _ in 0..2 {
        let response = server.post(&client, "/actions", &fields)?;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()["location"], url);
    }
    let updated = client
        .get(format!("{}{url}", server.origin))
        .send()?
        .text()?;
    assert!(updated.contains("Edited first link"));
    assert_eq!(
        attribute(&updated, "#owned-link-details", "data-version")?,
        "2"
    );
    let next_ticket = claims(&selected_form(&updated, "form.edit-form")?)?;
    assert_eq!(next_ticket["bound"]["expected_version"], 2);
    let untouched = client
        .get(format!("{}/links/{second_id}", server.origin))
        .send()?
        .text()?;
    assert!(
        Html::parse_document(&untouched)
            .select(&selector("form.edit-form"))
            .next()
            .is_some()
    );
    assert_eq!(world.count("day2_audit_changes")?, 3);
    let viewer = Server::start(world.runtime.clone(), "viewer", 0)?;
    let viewer_client = viewer.client()?;
    let read_only = viewer_client
        .get(format!("{}/links/{second_id}", viewer.origin))
        .send()?;
    assert_eq!(read_only.status(), StatusCode::OK);
    assert!(
        Html::parse_document(&read_only.text()?)
            .select(&selector("form.command"))
            .next()
            .is_none()
    );
    assert_eq!(
        attribute(&untouched, "#owned-link-details", "data-version")?,
        "1"
    );
    let mut second_fields = selected_form(&untouched, "form.edit-form")?;
    second_fields.insert("title".into(), "Edited second link".into());
    let response = client
        .post(format!("{}/actions", server.origin))
        .header("Origin", &server.origin)
        .header("Datastar-Request", "true")
        .form(&second_fields)
        .send()?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let elements = patch_elements(&response.text()?)?;
    let fragment = Html::parse_fragment(&elements);
    assert_eq!(fragment.select(&selector("main#day2-main")).count(), 1);
    assert_eq!(fragment.select(&selector("#owned-link-details")).count(), 1);
    assert_eq!(fragment.select(&selector("#owned-links-app")).count(), 0);
    assert_eq!(fragment.select(&selector("form.edit-form")).count(), 1);
    assert!(elements.contains("Edited second link") && elements.contains(second_id));
    assert_eq!(
        attribute(&elements, "#owned-link-details", "data-version")?,
        "2"
    );
    assert_eq!(world.count("day2_audit_changes")?, 4);
    Ok(())
}

#[test]
fn path_and_query_errors_fail_closed_without_implicit_routes() -> Result<()> {
    let world = World::new()?;
    let saved = world.seed("path-validation")?;
    let id = saved["id"].as_str().unwrap();
    let server = Server::start(world.runtime.clone(), "alice", 0)?;
    let client = server.client()?;
    for path in [
        "/pages/links",
        "/directory.html",
        "/links",
        "/missing",
        "/links/lin_0000000000e008000000000000",
    ] {
        assert_eq!(
            client
                .get(format!("{}{path}", server.origin))
                .send()?
                .status(),
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    for path in [
        "/links/999999".into(),
        "/links/0".into(),
        "/links/01".into(),
        "/links/-1".into(),
        "/links/not-an-id".into(),
        "/links/9223372036854775808".into(),
        "/links/%2F".into(),
        "/links/%5C".into(),
        "/links/%FF".into(),
        "/links/1/".into(),
        "/links//1".into(),
        format!("/links/{id}?link_id={id}"),
        format!("/links/{id}?link_id=999"),
        format!("/links/{id}?actor=alice"),
        "/?after=&after=1".into(),
        "/?limit=banana".into(),
        "/?limit=0".into(),
        "/?limit=101".into(),
        "/?after=%ZZ".into(),
    ] {
        assert_eq!(
            client
                .get(format!("{}{path}", server.origin))
                .send()?
                .status(),
            StatusCode::BAD_REQUEST,
            "{path}"
        );
    }
    assert_eq!(world.count("day2_audit_changes")?, 1);
    Ok(())
}

#[test]
fn app_authored_layout_and_pinned_browser_resources_are_served_in_scope() -> Result<()> {
    let world = World::new()?;
    world.seed("layout-link")?;
    let server = Server::start(world.runtime.clone(), "alice", 0)?;
    let client = server.client()?;
    let page = server.page(&client)?;
    let document = Html::parse_document(&page);
    for query in [
        "#owned-links-app",
        "#link-search[type='search']",
        "#links-list",
        "#create-link-form.command",
        "#create-link-form input[name='title']",
        "#create-link-form input[name='destination']",
        ".link-row[data-version='1']",
    ] {
        assert_eq!(document.select(&selector(query)).count(), 1, "{query}");
    }
    assert!(
        document
            .select(&selector("link[rel='stylesheet']"))
            .all(|link| link.value().attr("href") != Some("/assets/platform/web.css"))
    );
    let script = attribute(&page, "script[src$='/app.js']", "src")?;
    let style = attribute(&page, "link[href$='/app.css']", "href")?;
    let base = script.strip_suffix("app.js").context("UI entrypoint")?;
    assert!(base.starts_with("/assets/ui/"));
    assert_eq!(
        base.split('/').nth(4),
        world.runtime.artifact().id().strip_prefix("sha256:")
    );
    assert_eq!(style, format!("{base}app.css"));
    let catalog = &world.runtime.artifact().contract().web_resources;
    assert!(catalog.contains_key("app.js") && catalog.contains_key("app.css"));
    for (path, resource) in catalog {
        let url = format!("{}{base}{path}", server.origin);
        let response = client.get(&url).send()?;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response.headers()["content-type"], resource.media_type);
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        let bytes = response.bytes()?;
        assert_eq!(bytes.len() as u64, resource.bytes);
        assert_eq!(day2::digest(&bytes), resource.digest, "{path}");
        assert_eq!(
            Client::new().get(&url).send()?.status(),
            StatusCode::UNAUTHORIZED,
            "{path}"
        );
    }
    assert_eq!(
        catalog["app.js"].media_type,
        "text/javascript; charset=utf-8"
    );
    assert_eq!(catalog["app.css"].media_type, "text/css; charset=utf-8");
    assert_eq!(
        client
            .get(format!("{}{base}not_admitted.js", server.origin))
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );
    let other = Runtime::load(world.runtime.instance_path(), "other")?;
    let other_server = Server::start(other, "alice", 0)?;
    let other_client = other_server.client()?;
    for resource in [&script, &style] {
        assert_eq!(
            other_client
                .get(format!("{}{resource}", other_server.origin))
                .send()?
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    let mut instance = Instance::load(world.runtime.instance_path())?;
    instance.apps.get_mut("links").unwrap().writers.clear();
    fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    apply_desired_authority(&world.runtime)?;
    assert_eq!(
        client
            .get(format!("{}{script}", server.origin))
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[test]
fn datastar_create_returns_app_markup_and_preserves_receipt_identity() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(world.runtime.clone(), "alice", 0)?;
    let client = server.client()?;
    let mut fields = create_form(&server.page(&client)?)?;
    fields.insert("title".into(), "Created through Datastar".into());
    fields.insert("destination".into(), "https://www.roc-lang.org/".into());
    let mut invocation = None;
    for _ in 0..2 {
        let response = client
            .post(format!("{}/actions", server.origin))
            .header("Origin", &server.origin)
            .header("Datastar-Request", "true")
            .form(&fields)
            .send()?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        let id = response.headers()["x-day2-invocation"].to_str()?.to_owned();
        if let Some(previous) = &invocation {
            assert_eq!(previous, &id);
        } else {
            invocation = Some(id.clone());
        }
        let patch = response.text()?;
        assert!(patch.contains("id=\"owned-links-app\""));
        assert!(patch.contains("Created through Datastar"));
        assert!(patch.contains("data-version=\"1\""));
        assert!(!patch.contains("<script") && !patch.contains("<link "));
        let elements = patch_elements(&patch)?;
        assert_eq!(
            attribute(&elements, "main#day2-main", "data-day2-status")?,
            "success"
        );
        assert_eq!(
            attribute(&elements, "main#day2-main", "data-day2-operation")?,
            "links.create"
        );
        assert_eq!(
            attribute(&elements, "main#day2-main", "data-day2-invocation")?,
            id
        );
        assert_eq!(world.count("links")?, 1);
        assert_eq!(world.count("day2_audit_changes")?, 1);
    }
    replay(
        world.runtime.artifact(),
        &world.runtime.trace(invocation.as_deref().unwrap())?,
    )?;
    Ok(())
}

#[test]
fn http_rejects_csrf_identity_injection_overposting_and_bad_urls() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(world.runtime.clone(), "alice", 0)?;
    let anonymous = Client::builder().redirect(Policy::none()).build()?;
    assert_eq!(
        anonymous
            .get(format!("{}/", server.origin))
            .header("X-Actor", "alice")
            .send()?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let client = server.client()?;
    assert_eq!(
        anonymous.get(&server.login).send()?.status(),
        StatusCode::FORBIDDEN
    );
    let mut fields = create_form(&server.page(&client)?)?;
    fields.insert("title".into(), "Documentation".into());
    fields.insert("destination".into(), "https://example.com/".into());
    for origin in [None, Some("https://attacker.example")] {
        let request = client
            .post(format!("{}/actions", server.origin))
            .form(&fields);
        let request = if let Some(origin) = origin {
            request.header("Origin", origin)
        } else {
            request
        };
        assert_eq!(request.send()?.status(), StatusCode::FORBIDDEN);
    }
    let mut bad = fields.clone();
    bad.insert("_csrf".into(), "invalid".into());
    assert!(
        !server
            .post(&client, "/actions", &bad)?
            .status()
            .is_success()
    );
    let mut bad = fields.clone();
    bad.insert("actor".into(), "administrator".into());
    assert_eq!(
        server.post(&client, "/actions", &bad)?.status(),
        StatusCode::BAD_REQUEST
    );
    let mut bad = fields.clone();
    bad.insert("_ticket".into(), format!("{}x", bad["_ticket"]));
    assert!(
        !server
            .post(&client, "/actions", &bad)?
            .status()
            .is_success()
    );
    assert_eq!(
        client
            .get(format!("{}/", server.origin))
            .header("Host", "attacker.example")
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .get(format!("{}/?after=&after=1", server.origin))
            .send()?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client
            .get(format!("{}/?actor=alice", server.origin))
            .send()?
            .status(),
        StatusCode::BAD_REQUEST
    );
    let oversized = client
        .post(format!("{}/actions", server.origin))
        .header("Origin", &server.origin)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("a".repeat(65_537))
        .send()?;
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    for url in [
        "javascript:alert(1)",
        "http://example.com/",
        "https://user:password@example.com/",
        "https://example.com/\nattack",
        "https://example.com\\@evil.test/",
    ] {
        let mut bad = fields.clone();
        bad.insert("destination".into(), url.into());
        let response = server.post(&client, "/actions", &bad)?;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "{url}");
        assert!(response.text()?.contains("Check the values"));
    }
    assert_eq!(world.count("links")?, 0);
    assert_eq!(world.count("day2_audit_changes")?, 0);
    assert!(world.count("day2_web_events")? > 10);
    Ok(())
}

#[test]
fn signed_forms_survive_restart_deduplicate_and_cannot_cross_apps() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(world.runtime.clone(), "alice", 0)?;
    let client = server.client()?;
    let mut fields = create_form(&server.page(&client)?)?;
    fields.insert("title".into(), "Stable receipt".into());
    fields.insert("destination".into(), "https://example.com/".into());
    let first = server.post(&client, "/actions", &fields)?;
    assert_eq!(first.status(), StatusCode::SEE_OTHER);
    let id = first.headers()["x-day2-invocation"].to_str()?.to_string();
    let port = url::Url::parse(&server.origin)?.port().unwrap();
    drop(server);
    let server = Server::start(world.runtime.clone(), "alice", port)?;
    let again = server.post(&client, "/actions", &fields)?;
    assert_eq!(again.status(), StatusCode::SEE_OTHER);
    assert_eq!(again.headers()["x-day2-invocation"], id);
    assert_eq!(world.count("links")?, 1);
    assert_eq!(world.count("day2_audit_changes")?, 1);
    let mut changed = fields.clone();
    changed.insert("title".into(), "Different payload".into());
    assert_eq!(
        server.post(&client, "/actions", &changed)?.status(),
        StatusCode::CONFLICT
    );
    let other = Runtime::load(world.runtime.instance_path(), "other")?;
    let other_server = Server::start(other.clone(), "alice", 0)?;
    let other_client = other_server.client()?;
    let other_fields = create_form(&other_server.page(&other_client)?)?;
    let mut cross = fields;
    cross.insert("_csrf".into(), other_fields["_csrf"].clone());
    assert_eq!(
        other_server
            .post(&other_client, "/actions", &cross)?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(other.inspect()?["links"].as_array().unwrap().is_empty());
    replay(world.runtime.artifact(), &world.runtime.trace(&id)?)?;
    Ok(())
}

#[test]
fn policy_revocation_takes_effect_on_existing_sessions_and_tickets() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(world.runtime.clone(), "alice", 0)?;
    let client = server.client()?;
    let mut fields = create_form(&server.page(&client)?)?;
    fields.insert("title".into(), "Cannot commit".into());
    fields.insert("destination".into(), "https://example.com/".into());
    let viewer_server = Server::start(world.runtime.clone(), "viewer", 0)?;
    let viewer = viewer_server.client()?;
    let page = viewer_server.page(&viewer)?;
    assert_eq!(
        Html::parse_document(&page)
            .select(&selector("form.command"))
            .count(),
        0
    );
    assert_eq!(
        viewer
            .get(format!("{}/audit", viewer_server.origin))
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut instance = Instance::load(world.runtime.instance_path())?;
    instance.apps.get_mut("links").unwrap().writers.clear();
    fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    apply_desired_authority(&world.runtime)?;
    assert_eq!(
        server.post(&client, "/actions", &fields)?.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client.get(format!("{}/", server.origin)).send()?.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(world.count("links")?, 0);
    Ok(())
}

#[test]
fn mandatory_admission_events_cover_rejections_duplicates_and_interruptions_without_payloads()
-> Result<()> {
    let world = World::new()?;
    let input =
        json!({"title":"private-body-marker","destination":"https://example.com/private-marker"});
    assert!(
        world
            .runtime
            .accept("links.create", "viewer", "denied", &input, 100)
            .is_err()
    );
    assert!(
        world
            .runtime
            .accept(
                "links.create",
                "alice",
                "malformed",
                &json!({"unexpected":"secret-input-marker"}),
                101
            )
            .is_err()
    );
    assert!(
        world
            .runtime
            .accept("secret-unknown-operation", "alice", "unknown", &input, 102)
            .is_err()
    );
    assert_eq!(world.count("day2_invocations")?, 0);
    world
        .runtime
        .accept("links.create", "alice", "pending", &input, 103)?;
    world
        .runtime
        .accept("links.create", "alice", "pending", &input, 104)?;
    assert!(
        world
            .runtime
            .accept(
                "links.create",
                "alice",
                "pending",
                &json!({"title":"other","destination":"https://example.com/"}),
                105
            )
            .is_err()
    );
    assert!(
        world
            .runtime
            .execute("pending", Fault::BeforeCommit)
            .is_err()
    );
    assert_eq!(world.count("day2_audit")?, 0);
    assert_eq!(world.count("day2_audit_changes")?, 0);
    let events = world.runtime.audit_events("admin", 0)?;
    assert_eq!(events.len(), 7);
    let event = |identity: &str| {
        events
            .iter()
            .find(|event| event.identity == identity)
            .unwrap()
    };
    assert_eq!(
        event("denied").reason.as_deref(),
        Some("authorization_rejected")
    );
    assert_eq!(event("malformed").reason.as_deref(), Some("invalid_input"));
    assert_eq!(event("unknown").operation, None);
    assert_eq!(
        event("unknown").reason.as_deref(),
        Some("unknown_operation")
    );
    assert_eq!(events[0].kind, "execution_attempt");
    assert_eq!(events[0].outcome, "interrupted");
    assert_eq!(events[0].actor, None);
    assert_eq!(events[0].initiator.as_deref(), Some("alice"));
    assert_eq!(events[1].reason.as_deref(), Some("idempotency_conflict"));
    assert_eq!(events[2].outcome, "reused");
    assert_eq!(events[3].outcome, "accepted");
    assert!(
        events
            .iter()
            .all(|event| event.scope == world.runtime.scope())
    );
    let serialized = serde_json::to_string(&events)?;
    for forbidden in [
        "private-body-marker",
        "private-marker",
        "secret-input-marker",
        "secret-unknown-operation",
    ] {
        assert!(!serialized.contains(forbidden));
    }
    assert!(world.runtime.audit_events("viewer", 0).is_err());
    assert_eq!(
        world.runtime.execute("pending", Fault::None)?.status,
        "success"
    );
    let complete = world.runtime.audit_events("admin", 0)?;
    assert_eq!(complete[0].kind, "invocation");
    assert_eq!(complete[0].outcome, "success");
    assert_eq!(complete[0].identity, "pending");
    assert_eq!(complete[0].actor.as_deref(), Some("alice"));
    assert_eq!(complete[0].at_ms, 103_000);
    for mutation in [
        "UPDATE day2_audit_events SET outcome='failure'",
        "DELETE FROM day2_audit_events",
        "INSERT OR REPLACE INTO day2_audit_events SELECT * FROM day2_audit_events LIMIT 1",
    ] {
        assert!(world.db()?.execute(mutation, []).is_err());
    }
    Ok(())
}

#[test]
fn admission_refuses_when_common_audit_is_unavailable_and_receipts_fail_closed() -> Result<()> {
    let world = World::new()?;
    let input = json!({"title":"Roc","destination":"https://www.roc-lang.org/"});
    world.db()?.execute_batch("CREATE TRIGGER test_stream_failure BEFORE INSERT ON day2_audit_events BEGIN SELECT RAISE(ABORT,'audit_unavailable'); END;")?;
    let error = world
        .runtime
        .accept("links.create", "alice", "unlogged", &input, 100)
        .unwrap_err();
    assert!(error.to_string().contains("mandatory_audit_unavailable"));
    assert_eq!(world.count("day2_invocations")?, 0);
    assert_eq!(world.count("day2_audit_events")?, 0);
    world
        .db()?
        .execute_batch("DROP TRIGGER test_stream_failure")?;
    world
        .runtime
        .accept("links.create", "alice", "accepted", &input, 100)?;
    world
        .db()?
        .execute_batch("DROP TRIGGER day2_receipt_event")?;
    assert!(world.runtime.execute("accepted", Fault::None).is_err());
    assert_eq!(world.count("day2_audit")?, 0);
    assert_eq!(world.count("day2_audit_changes")?, 0);
    assert_eq!(
        world.db()?.query_row(
            "SELECT status FROM day2_invocations WHERE id='accepted'",
            [],
            |row| row.get::<_, String>(0)
        )?,
        "pending"
    );
    Ok(())
}

#[test]
fn host_v1_upgrade_is_repeatable_and_does_not_invent_old_event_metadata() -> Result<()> {
    let world = World::new()?;
    world.seed("legacy-receipt")?;
    world.db()?.execute_batch(
        "DROP TRIGGER day2_receipt_event; DROP TRIGGER day2_web_audit_event;
        DROP TRIGGER day2_audit_no_replace; DROP TRIGGER day2_changes_no_replace; DROP TRIGGER day2_events_no_replace;
        UPDATE day2_meta SET value='1' WHERE key='host_schema';",
    )?;
    let before = world.count("day2_audit_events")?;
    world.runtime.initialize()?;
    world.runtime.initialize()?;
    assert_eq!(world.count("day2_audit_events")?, before);
    assert_eq!(
        world.db()?.query_row(
            "SELECT value FROM day2_meta WHERE key='host_schema'",
            [],
            |row| row.get::<_, String>(0)
        )?,
        // Schema 3 recorded the cause of each invocation; 4 widened its
        // constraint from an enumeration to a shape; 5 gave every application
        // table its deletion column; 6 added the record of removals; 7 recorded
        // which applications a call passed through; 8 separated who
        // authenticated from whom the work is for; 9 bound each address to
        // the account behind it; 10 let a completed invocation keep a receipt
        // in place of its trace.
        "10"
    );
    world.seed("new-receipt")?;
    assert_eq!(world.count("day2_audit_events")?, before + 2);
    Ok(())
}

/// An instance that predates soft deletion gains the column with its rows intact.
///
/// The migration is the only reason existing instances can adopt a platform
/// rule they were not built under. It has to reach every application table —
/// discovered from the database, not from the current artifact, because an
/// instance can hold tables the app no longer declares — and it has to leave
/// every existing row live, since a default of anything but zero would delete
/// the entire fleet's data on upgrade.
#[test]
fn a_pre_deletion_instance_gains_the_column_with_every_row_still_live() -> Result<()> {
    let world = World::new()?;
    world.seed("legacy-row")?;
    let before = world.count("links")?;
    assert!(before > 0, "the fixture holds a row to migrate");
    // A table the current artifact does not declare, to prove the migration
    // reads the database rather than the schema.
    world.db()?.execute_batch(
        "ALTER TABLE links DROP COLUMN deleted_at;
        CREATE TABLE retired_model(id INTEGER PRIMARY KEY, version INTEGER NOT NULL,
            created_at INTEGER NOT NULL);
        INSERT INTO retired_model VALUES(1,1,100);
        UPDATE day2_meta SET value='4' WHERE key='host_schema';",
    )?;
    world.runtime.initialize()?;

    let column = |table: &str| -> Result<i64> {
        Ok(world.db()?.query_row(
            "SELECT count(*) FROM pragma_table_info(?1) WHERE name='deleted_at'",
            [table],
            |row| row.get(0),
        )?)
    };
    assert_eq!(column("links")?, 1, "the declared table did not migrate");
    assert_eq!(
        column("retired_model")?,
        1,
        "a table the artifact no longer declares was skipped"
    );
    assert_eq!(column("day2_invocations")?, 0, "a platform table migrated");
    assert_eq!(
        world.db()?.query_row(
            "SELECT count(*) FROM links WHERE deleted_at = 0",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        before,
        "migrating deleted rows that existed before deletion did"
    );
    // Running it again is a no-op rather than an error on the existing column.
    world.runtime.initialize()?;
    assert_eq!(column("links")?, 1);
    Ok(())
}

#[test]
fn audit_is_atomic_append_only_redacted_and_fault_replayable() -> Result<()> {
    let world = World::new()?;
    let saved = world.seed("seed")?;
    for (n, fault) in [
        Fault::InterruptAfterWrite(1),
        Fault::BeforeCommit,
        Fault::AfterCommit,
    ]
    .into_iter()
    .enumerate()
    {
        let id = format!("create-{n}");
        let input = json!({"title":"private-data","destination":"https://example.com/private"});
        let before = world.count("links")?;
        assert!(
            world
                .runtime
                .invoke("links.create", "alice", &id, &input, 101, fault)
                .is_err()
        );
        assert_eq!(
            world.count("links")?,
            before + i64::from(fault == Fault::AfterCommit)
        );
        let outcome = world.runtime.execute(&id, Fault::None)?;
        assert_eq!(outcome.status, "success");
        assert_eq!(world.count("links")?, before + 1);
        replay(world.runtime.artifact(), &world.runtime.trace(&id)?)?;
    }
    let failed = world.runtime.invoke(
        "links.edit",
        "alice",
        "fail-edit",
        &json!({"link_id":saved["id"],"expected_version":1,"title":"Changed"}),
        102,
        Fault::FailAfterWrite(1),
    )?;
    assert_eq!(failed.status, "failure");
    assert_eq!(
        world.db()?.query_row(
            "SELECT count(*) FROM day2_audit_changes WHERE invocation='fail-edit'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    let changes: String = world.db()?.query_row(
        "SELECT group_concat(fields) FROM day2_audit_changes",
        [],
        |row| row.get(0),
    )?;
    assert!(!changes.contains("private-data") && !changes.contains("https://"));
    for table in ["day2_audit", "day2_audit_changes"] {
        assert!(
            world
                .db()?
                .execute(&format!("DELETE FROM {table}"), [])
                .is_err()
        );
        assert!(
            world
                .db()?
                .execute(
                    &format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table} LIMIT 1"),
                    []
                )
                .is_err()
        );
    }
    let before = world.count("links")?;
    world.db()?.execute_batch("CREATE TRIGGER test_audit_failure BEFORE INSERT ON day2_audit BEGIN SELECT RAISE(ABORT,'audit_unavailable'); END;")?;
    let input = json!({"title":"Atomic receipt","destination":"https://example.com/"});
    assert!(
        world
            .runtime
            .invoke(
                "links.create",
                "alice",
                "audit-down",
                &input,
                103,
                Fault::None
            )
            .is_err()
    );
    assert_eq!(world.count("links")?, before);
    world
        .db()?
        .execute_batch("DROP TRIGGER test_audit_failure;")?;
    assert_eq!(
        world.runtime.execute("audit-down", Fault::None)?.status,
        "success"
    );
    assert_eq!(world.count("links")?, before + 1);
    assert_eq!(
        world
            .runtime
            .audit_entries("viewer", &day2::audit::Filter::default())
            .unwrap_err()
            .to_string(),
        "forbidden"
    );
    day2::properties::require(
        world.runtime.artifact(),
        &world.runtime.inspect()?,
        &world.directory.path().join("properties"),
    )?;
    Ok(())
}

#[test]
fn http_resumes_the_same_ticket_after_interrupted_or_ambiguous_execution() -> Result<()> {
    let world = World::new()?;
    let mut server = Server::start(world.runtime.clone(), "alice", 0)?;
    let client = server.client()?;
    for fault in [Fault::InterruptAfterWrite(1), Fault::AfterCommit] {
        let mut fields = create_form(&server.page(&client)?)?;
        fields.insert("title".into(), "Recovered via HTTP".into());
        fields.insert("destination".into(), "https://example.com/".into());
        let ticket = claims(&fields)?;
        let id = format!("web-{}", ticket["nonce"].as_str().unwrap());
        let port = url::Url::parse(&server.origin)?.port().unwrap();
        // Stop the scheduler so another executor cannot finish the accepted
        // command before this executor reaches the requested interruption.
        drop(server);
        let before = world.count("links")?;
        let error = world
            .runtime
            .invoke(
                "links.create",
                "alice",
                &id,
                &json!({"title":fields["title"],"destination":fields["destination"]}),
                ticket["issued"].as_i64().unwrap(),
                fault,
            )
            .expect_err("execution must reach the requested interruption");
        assert!(fault.caused(&error), "unexpected interruption: {error:#}");
        let committed = i64::from(fault == Fault::AfterCommit);
        assert_eq!(world.count("links")?, before + committed);
        assert_eq!(
            world.db()?.query_row(
                "SELECT status FROM day2_invocations WHERE id=?1",
                [&id],
                |row| row.get::<_, String>(0)
            )?,
            if committed == 1 { "success" } else { "pending" }
        );
        assert_eq!(
            world.db()?.query_row(
                "SELECT count(*) FROM day2_audit_changes WHERE invocation=?1",
                [&id],
                |row| row.get::<_, i64>(0)
            )?,
            committed
        );
        server = Server::start(world.runtime.clone(), "alice", port)?;
        for _ in 0..2 {
            let response = server.post(&client, "/actions", &fields)?;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(response.headers()["x-day2-invocation"], id);
        }
        assert_eq!(
            world.db()?.query_row(
                "SELECT count(*) FROM day2_audit_changes WHERE invocation=?1",
                [&id],
                |row| row.get::<_, i64>(0)
            )?,
            1
        );
        replay(world.runtime.artifact(), &world.runtime.trace(&id)?)?;
    }
    assert_eq!(world.count("links")?, 2);
    Ok(())
}

fn brand_world(
    world: &World,
    name: &str,
    accent: &str,
    logo: &[u8],
    installation: &str,
) -> Result<()> {
    let source = world.directory.path().join("branding/source");
    fs::create_dir_all(source.join("assets"))?;
    fs::write(source.join("assets/logo.svg"), logo)?;
    fs::write(
        source.join("brand.json"),
        serde_json::to_vec(&json!({"name":name,"accent":accent}))?,
    )?;
    let bundle = day2::branding::build(&source, &world.directory.path().join("branding/bundles"))?;
    let mut instance = Instance::load(world.runtime.instance_path())?;
    assert_eq!(instance.installation, installation);
    instance.branding = Some(
        bundle
            .strip_prefix(world.directory.path())?
            .to_string_lossy()
            .into(),
    );
    fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    Ok(())
}
fn attribute(html: &str, query: &str, name: &str) -> Result<String> {
    Ok(Html::parse_document(html)
        .select(&selector(query))
        .next()
        .context("element missing")?
        .value()
        .attr(name)
        .context("attribute missing")?
        .into())
}

#[test]
fn asset_cache_policies_and_conditional_get_and_head() -> Result<()> {
    let world = World::new()?;
    brand_world(
        &world,
        "Cache Company",
        "#176e50",
        include_bytes!("../../../assets/icons/link.svg"),
        "webco",
    )?;
    let server = Server::start(world.runtime.clone(), "alice", 0)?;
    let public = Client::new();
    let login_html = public.get(&server.login).send()?.text()?;
    let client = server.client()?;
    let page = server.page(&client)?;
    let policies = [
        ("/assets/platform/web.css".into(), "no-cache"),
        ("/assets/platform/datastar-1.0.1.js".into(), "no-cache"),
        ("/assets/platform/icons/link.svg".into(), "no-cache"),
        (
            attribute(&page, "link[href$='theme.css']", "href")?,
            "public, max-age=31536000, immutable",
        ),
        (
            attribute(&login_html, ".brand img", "src")?,
            "public, max-age=31536000, immutable",
        ),
        (
            attribute(&page, "script[src$='/app.js']", "src")?,
            "private, no-cache",
        ),
        (
            attribute(&page, "link[href$='/app.css']", "href")?,
            "private, no-cache",
        ),
        (
            attribute(&page, "img.app-icon", "src")?,
            "private, no-cache",
        ),
    ];
    for (path, policy) in policies {
        let client = if policy.starts_with("private") {
            &client
        } else {
            &public
        };
        let url = format!("{}{path}", server.origin);
        let response = client.get(&url).send()?;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response.headers()["cache-control"], policy);
        let etag = response.headers()["etag"].to_str()?.to_owned();
        let content_type = response.headers()["content-type"].clone();
        let vary = response.headers().get("vary").cloned();
        assert_eq!(
            vary.as_ref().map(|v| v.to_str().unwrap()),
            policy.starts_with("private").then_some("Cookie")
        );
        let original = response.bytes()?;
        assert!(!original.is_empty());
        assert_eq!(etag, format!("\"{}\"", day2::digest(&original)));

        let response = client.head(&url).send()?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["etag"], etag);
        assert_eq!(response.headers()["cache-control"], policy);
        assert_eq!(response.headers()["content-type"], content_type);
        assert_eq!(
            response.headers()["content-length"]
                .to_str()?
                .parse::<usize>()?,
            original.len()
        );
        assert!(response.bytes()?.is_empty());

        for condition in [
            &etag,
            &format!("W/{etag}"),
            &format!("\"other,tag\", W/{etag}"),
            "*",
        ] {
            for method in [reqwest::Method::GET, reqwest::Method::HEAD] {
                let response = client
                    .request(method, &url)
                    .header("If-None-Match", condition)
                    .send()?;
                assert_eq!(
                    response.status(),
                    StatusCode::NOT_MODIFIED,
                    "{path}: {condition}"
                );
                assert_eq!(response.headers()["etag"], etag);
                assert_eq!(response.headers()["cache-control"], policy);
                assert_eq!(response.headers().get("vary"), vary.as_ref());
                assert!(!response.headers().contains_key("content-type"));
                // A 304 may omit Content-Length; if present it must describe
                // the original representation, never the empty 304 body.
                if let Some(length) = response.headers().get("content-length") {
                    assert_eq!(length.to_str()?.parse::<usize>()?, original.len());
                }
                assert_eq!(response.headers()["x-content-type-options"], "nosniff");
                assert!(response.bytes()?.is_empty());
            }
        }
        let response = client
            .get(&url)
            .header("If-None-Match", "\"unmatched\"")
            .header("If-None-Match", &etag)
            .send()?;
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert!(response.bytes()?.is_empty());

        for condition in [
            "\"unmatched\"".into(),
            format!("{etag}, broken"),
            format!("*, {etag}"),
            format!("{etag}suffix"),
        ] {
            let response = client.get(&url).header("If-None-Match", condition).send()?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["etag"], etag);
            assert_eq!(response.bytes()?, original);
        }
    }
    // A validator never makes a dynamic page or a missing asset cacheable.
    for (path, status) in [
        ("/", StatusCode::OK),
        ("/audit", StatusCode::FORBIDDEN),
        ("/assets/platform/missing.css", StatusCode::NOT_FOUND),
    ] {
        let response = client
            .get(format!("{}{path}", server.origin))
            .header("If-None-Match", "*")
            .send()?;
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(!response.headers().contains_key("etag"));
    }
    Ok(())
}

#[test]
fn asset_cache_revalidation_requires_current_authority_and_session() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(world.runtime.clone(), "alice", 0)?;
    let client = server.client()?;
    let page = server.page(&client)?;
    let mut assets = Vec::new();
    for path in [
        attribute(&page, "script[src$='/app.js']", "src")?,
        attribute(&page, "link[href$='/app.css']", "href")?,
        attribute(&page, "img.app-icon", "src")?,
    ] {
        let response = client.get(format!("{}{path}", server.origin)).send()?;
        assert_eq!(response.status(), StatusCode::OK);
        assets.push((path, response.headers()["etag"].to_str()?.to_owned()));
    }
    let public = Client::new();
    for (path, etag) in &assets {
        for condition in [etag.as_str(), "*"] {
            let response = public
                .get(format!("{}{path}", server.origin))
                .header("If-None-Match", condition)
                .send()?;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert!(!response.headers().contains_key("etag"));
        }
    }
    let mut instance = Instance::load(world.runtime.instance_path())?;
    instance.apps.get_mut("links").unwrap().writers.clear();
    fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    apply_desired_authority(&world.runtime)?;
    for (path, etag) in &assets {
        let response = client
            .get(format!("{}{path}", server.origin))
            .header("If-None-Match", etag)
            .send()?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(!response.headers().contains_key("etag"));
    }
    instance
        .apps
        .get_mut("links")
        .unwrap()
        .writers
        .insert("alice".into());
    fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    apply_desired_authority(&world.runtime)?;
    let logout = selected_form(&page, "form[action='/logout']")?;
    let response = server.post(&client, "/logout", &logout)?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    for (path, etag) in &assets {
        let response = client
            .get(format!("{}{path}", server.origin))
            .header("If-None-Match", etag)
            .send()?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    Ok(())
}

#[test]
fn asset_cache_validators_do_not_bypass_blob_integrity_or_brand_binding() -> Result<()> {
    let mut world = World::new()?;
    // Keep corruption confined to this test's artifact copy.
    fn copy_tree(source: &std::path::Path, target: &std::path::Path) -> Result<()> {
        fs::create_dir_all(target)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                copy_tree(&entry.path(), &target.join(entry.file_name()))?;
            } else {
                fs::copy(entry.path(), target.join(entry.file_name()))?;
            }
        }
        Ok(())
    }
    let artifact = world
        .directory
        .path()
        .join("artifacts")
        .join(day2::assets::hash_part(world.runtime.artifact().id())?);
    copy_tree(world.runtime.artifact().directory(), &artifact)?;
    let mut instance = Instance::load(world.runtime.instance_path())?;
    instance.apps.get_mut("links").unwrap().artifact = artifact.to_string_lossy().into();
    fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    day2::migration::activate(
        &world.runtime,
        &day2::artifact::LoadedArtifact::load(&artifact)?,
    )?;
    world.runtime = Runtime::load(world.runtime.instance_path(), "links")?;
    brand_world(
        &world,
        "Cache Company",
        "#176e50",
        include_bytes!("../../../assets/icons/link.svg"),
        "webco",
    )?;
    let brand = day2::branding::LoadedBrand::for_instance(world.runtime.instance_path())?
        .context("brand")?;
    let server = Server::start(world.runtime.clone(), "alice", 0)?;
    let login_html = Client::new().get(&server.login).send()?.text()?;
    let client = server.client()?;
    let page = server.page(&client)?;
    let module = &world.runtime.artifact().contract().web_resources["app.js"];
    let image = &world.runtime.artifact().contract().assets["directory_logo"];
    let logo = &brand.bundle.assets["logo"];
    for (path, file) in [
        (
            attribute(&page, "script[src$='/app.js']", "src")?,
            artifact
                .join("web_resources")
                .join(format!("{}.js", day2::assets::hash_part(&module.digest)?)),
        ),
        (
            attribute(&page, "img.app-icon", "src")?,
            artifact
                .join("assets")
                .join(format!("{}.png", day2::assets::hash_part(&image.digest)?)),
        ),
        (
            attribute(&login_html, ".brand img", "src")?,
            brand
                .directory
                .join("assets")
                .join(format!("{}.png", day2::assets::hash_part(&logo.digest)?)),
        ),
    ] {
        let url = format!("{}{path}", server.origin);
        let response = client.get(&url).send()?;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let etag = response.headers()["etag"].to_str()?.to_owned();
        let original = fs::read(&file)?;
        fs::write(&file, b"corrupted asset")?;
        for condition in [etag.as_str(), "*"] {
            let response = client.get(&url).header("If-None-Match", condition).send()?;
            assert!(
                response.status().is_server_error(),
                "{path}: {}",
                response.status()
            );
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert!(!response.headers().contains_key("etag"));
        }
        fs::write(&file, original)?;
    }
    let theme = attribute(&page, "link[href$='theme.css']", "href")?;
    let url = format!("{}{theme}", server.origin);
    let response = client.get(&url).send()?;
    assert_eq!(response.status(), StatusCode::OK);
    let etag = response.headers()["etag"].to_str()?.to_owned();
    let mut instance = Instance::load(world.runtime.instance_path())?;
    instance.branding = None;
    fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    let response = client.get(&url).header("If-None-Match", etag).send()?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(response.headers()["cache-control"], "no-store");
    Ok(())
}

#[test]
fn app_and_company_assets_are_scoped_independent_and_not_platform_globals() -> Result<()> {
    let one = World::new()?;
    let two = World::named("greenco")?;
    brand_world(
        &one,
        "Rose Company",
        "#8b3150",
        include_bytes!("../../../assets/icons/history.svg"),
        "webco",
    )?;
    brand_world(
        &two,
        "Green Company",
        "#176e50",
        include_bytes!("../../../assets/icons/link.svg"),
        "greenco",
    )?;
    let one_server = Server::start(one.runtime.clone(), "alice", 0)?;
    let two_server = Server::start(two.runtime.clone(), "alice", 0)?;
    let one_login = Client::new().get(&one_server.login).send()?.text()?;
    let two_login = Client::new().get(&two_server.login).send()?.text()?;
    let one_client = one_server.client()?;
    let two_client = two_server.client()?;
    let one_page = one_server.page(&one_client)?;
    let two_page = two_server.page(&two_client)?;
    assert!(one_page.contains("Rose Company") && !one_page.contains("Green Company"));
    assert!(two_page.contains("Green Company") && !two_page.contains("Rose Company"));
    assert_eq!(one.runtime.artifact().id(), two.runtime.artifact().id());
    let one_module = attribute(&one_page, "script[src$='/app.js']", "src")?;
    let two_module = attribute(&two_page, "script[src$='/app.js']", "src")?;
    assert_ne!(one_module, two_module);
    assert_eq!(
        two_client
            .get(format!("{}{one_module}", two_server.origin))
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );
    let one_theme = attribute(&one_page, "link[href$='theme.css']", "href")?;
    let two_theme = attribute(&two_page, "link[href$='theme.css']", "href")?;
    assert_ne!(one_theme, two_theme);
    assert!(
        one_client
            .get(format!("{}{one_theme}", one_server.origin))
            .send()?
            .text()?
            .contains("#8b3150")
    );
    assert!(
        two_client
            .get(format!("{}{two_theme}", two_server.origin))
            .send()?
            .text()?
            .contains("#176e50")
    );
    let one_logo = attribute(&one_login, ".brand img", "src")?;
    let two_logo = attribute(&two_login, ".brand img", "src")?;
    assert_ne!(one_logo, two_logo);
    assert_eq!(
        two_client
            .get(format!("{}{one_logo}", two_server.origin))
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );
    for (server, client, page) in [
        (&one_server, &one_client, &one_page),
        (&two_server, &two_client, &two_page),
    ] {
        for image in Html::parse_document(page).select(&selector("img")) {
            let src = image.value().attr("src").unwrap();
            let response = client.get(format!("{}{src}", server.origin)).send()?;
            assert_eq!(response.status(), StatusCode::OK, "{src}");
            if src.starts_with("/assets/app/") || src.starts_with("/assets/instance/") {
                assert_eq!(response.headers()["content-type"], "image/png");
                let image = image::load_from_memory(&response.bytes()?)?;
                assert!(image.width() > 0 && image.height() > 0);
            }
        }
    }
    let logo = attribute(&one_page, "img.app-icon", "src")?;
    assert!(logo.contains("/directory_logo/"));
    assert_eq!(
        two_client
            .get(format!("{}{logo}", two_server.origin))
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        Client::new()
            .get(format!("{}{logo}", one_server.origin))
            .send()?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let other = Runtime::load(one.runtime.instance_path(), "other")?;
    let other_server = Server::start(other, "alice", 0)?;
    let other_client = other_server.client()?;
    assert_eq!(
        other_client
            .get(format!("{}{logo}", other_server.origin))
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        one_client
            .get(format!(
                "{}/assets/platform/icons/archive.svg",
                one_server.origin
            ))
            .send()?
            .status(),
        StatusCode::NOT_FOUND
    );
    let create = Html::parse_document(&one_page);
    let button = create
        .select(&selector("form.command button"))
        .next()
        .unwrap();
    assert_eq!(button.value().attr("class"), Some("primary"));
    assert!(
        button
            .select(&selector("img"))
            .next()
            .unwrap()
            .value()
            .attr("src")
            .unwrap()
            .contains("/icons_plus/")
    );
    let mut instance = Instance::load(one.runtime.instance_path())?;
    instance.branding = None;
    fs::write(one.runtime.instance_path(), serde_json::to_vec(&instance)?)?;
    assert_eq!(
        one_client
            .get(format!("{}/", one_server.origin))
            .send()?
            .status(),
        StatusCode::CONFLICT
    );
    Ok(())
}

#[test]
fn company_brand_bindings_cannot_escape_the_instance_directory() -> Result<()> {
    let world = World::new()?;
    for binding in ["../outside/brand", "/private/brand", "branding/../outside"] {
        let mut instance = Instance::load(world.runtime.instance_path())?;
        instance.branding = Some(binding.into());
        fs::write(
            world.runtime.instance_path(),
            serde_json::to_vec(&instance)?,
        )?;
        assert!(day2::branding::LoadedBrand::for_instance(world.runtime.instance_path()).is_err());
    }
    Ok(())
}

#[test]
fn pending_invocations_upgrade_legacy_host_audit_schema_without_app_migration() -> Result<()> {
    let world = World::new()?;
    let input = json!({"title":"Legacy pending invocation","destination":"https://example.com/"});
    world
        .runtime
        .accept("links.create", "alice", "legacy-pending", &input, 100)?;
    world.db()?.execute_batch("DROP TABLE day2_audit_changes; DROP TABLE day2_web_events; DROP TABLE day2_web_sessions; DROP TABLE day2_web_secret; DROP TRIGGER day2_audit_no_update; DROP TRIGGER day2_audit_no_delete; DROP TRIGGER day2_receipt_event; DROP TRIGGER day2_audit_no_replace; DELETE FROM day2_meta WHERE key='host_schema';")?;
    assert_eq!(
        world.runtime.execute("legacy-pending", Fault::None)?.status,
        "success"
    );
    assert_eq!(world.count("links")?, 1);
    assert_eq!(world.count("day2_audit_changes")?, 1);
    assert_eq!(
        world
            .runtime
            .invoke(
                "links.create",
                "alice",
                "legacy-pending",
                &input,
                101,
                Fault::None
            )?
            .status,
        "success"
    );
    assert_eq!(world.count("links")?, 1);
    Ok(())
}
