use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use day2::{
    artifact::Instance,
    store::{Runtime, replay},
    web::LocalServer,
};
use reqwest::{
    StatusCode,
    blocking::{Client, Response},
    redirect::Policy,
};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::mpsc, thread, time::Duration};

struct World {
    directory: tempfile::TempDir,
    runtime: Runtime,
}

impl World {
    fn new() -> Result<Self> {
        let artifact = std::env::var_os("DAY2_TEST_OWNED_ARTIFACT")
            .map(PathBuf::from)
            .context("run xtask verify or set DAY2_TEST_OWNED_ARTIFACT")?;
        let directory = tempfile::tempdir()?;
        // This is company-owned admission policy, deliberately outside the app.
        let instance: Instance = serde_json::from_value(json!({
            "installation": "owned_webco", "environment": "test",
            "apps": {"owned": {
                "artifact": artifact,
                "readers": ["viewer"], "writers": ["alice", "bob", "admin"],
                "authority": {
                    "version": 1, "admins": ["admin"],
                    "operations": {
                        "links.create": {
                            "actors": ["alice", "bob", "admin"],
                            "mode": {"kind": "current_state"},
                            "models": {"links": {"read": true, "create": true,
                                "rows": {"kind": "owner_or_admin", "field": "owner"}}}
                        },
                        "links.edit": {
                            "actors": ["alice", "bob", "admin"],
                            "mode": {"kind": "edit", "model": "links", "id_field": "link_id", "version_field": "expected_version"},
                            "models": {"links": {"read": true, "update_fields": ["title"],
                                "rows": {"kind": "owner_or_admin", "field": "owner"}}}
                        },
                        "links.list": {
                            "actors": ["alice", "bob", "admin", "viewer"],
                            "mode": {"kind": "read"},
                            "models": {"links": {"read": true, "rows": {"kind": "all"}}}
                        },
                        "links.detail": {
                            "actors": ["alice", "bob", "admin", "viewer"],
                            "mode": {"kind": "read"},
                            "models": {"links": {"read": true, "rows": {"kind": "all"}}}
                        }
                    },
                    "constraints": {"links": {"title": {"nonempty": true, "max_bytes": 200}}}
                }
            }}
        }))?;
        let path = directory.path().join("instance.json");
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let runtime = Runtime::load(&path, "owned")?;
        runtime.initialize()?;
        Ok(Self { directory, runtime })
    }

    fn row(&self, id: &str) -> Result<Value> {
        let bytes = day2::identity::Id::from_text(id)?.bytes_for("lin")?;
        Ok(rusqlite::Connection::open(self.runtime.db())?.query_row(
            "SELECT id, version, title, destination, owner FROM links WHERE id=?1",
            [&bytes[..]],
            |row| {
                assert_eq!(row.get::<_, Vec<u8>>(0)?, bytes);
                Ok(json!({
                    "id": id, "version": row.get::<_, i64>(1)?,
                    "title": row.get::<_, String>(2)?, "destination": row.get::<_, String>(3)?,
                    "owner": row.get::<_, String>(4)?
                }))
            },
        )?)
    }

    fn changes(&self) -> Result<i64> {
        Ok(rusqlite::Connection::open(self.runtime.db())?.query_row(
            "SELECT count(*) FROM day2_audit_changes",
            [],
            |row| row.get(0),
        )?)
    }

    fn check_success(&self, invocation: &str) -> Result<Value> {
        let trace = self.runtime.trace(invocation)?;
        assert_eq!(trace.outcome.status, "success", "{}", trace.outcome.error);
        replay(self.runtime.artifact(), &trace)?;
        Ok(trace.outcome.result)
    }
}

struct Server {
    origin: String,
    login: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<Result<()>>>,
}

impl Server {
    fn start(runtime: Runtime, actor: &str) -> Result<Self> {
        let (send, receive) = mpsc::channel();
        let (stop, done) = tokio::sync::oneshot::channel();
        let actor = actor.to_owned();
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
        let page = client.get(&self.login).send()?;
        assert_eq!(page.status(), StatusCode::OK);
        let fields = form(&page.text()?, "form")?;
        let response = client
            .post(format!("{}/login", self.origin))
            .header("Origin", &self.origin)
            .form(&fields)
            .send()?;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        Ok(client)
    }

    fn page(&self, client: &Client, path: &str) -> Result<String> {
        let response = client.get(format!("{}{path}", self.origin)).send()?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        Ok(response.text()?)
    }

    fn submit(
        &self,
        client: &Client,
        fields: &BTreeMap<String, String>,
        datastar: bool,
    ) -> Result<Response> {
        let request = client
            .post(format!("{}/actions", self.origin))
            .header("Origin", &self.origin)
            .form(fields);
        Ok(if datastar {
            request.header("Datastar-Request", "true")
        } else {
            request
        }
        .send()?)
    }

    fn create(&self, world: &World, client: &Client, title: &str) -> Result<String> {
        let mut fields = form(&self.page(client, "/")?, "#create-link-form")?;
        assert_eq!(
            claims(&fields)?["editable"],
            json!(["title", "destination"])
        );
        fields.insert("title".into(), title.into());
        fields.insert("destination".into(), "https://example.com/handbook".into());
        let response = self.submit(client, &fields, false)?;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()["location"], "/");
        let saved = world.check_success(invocation(&response)?)?;
        Ok(saved["id"].as_str().context("created id")?.into())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            assert!(thread.join().expect("owned HTTP server thread").is_ok());
        }
    }
}

fn selector(value: &str) -> Selector {
    Selector::parse(value).expect("test selector")
}

fn form(html: &str, query: &str) -> Result<BTreeMap<String, String>> {
    let document = Html::parse_document(html);
    let form = document
        .select(&selector(query))
        .next()
        .with_context(|| format!("form missing: {query}"))?;
    Ok(form
        .select(&selector("input[name]"))
        .map(|field| {
            (
                field.value().attr("name").unwrap().into(),
                field.value().attr("value").unwrap_or("").into(),
            )
        })
        .collect())
}

fn claims(fields: &BTreeMap<String, String>) -> Result<Value> {
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(
        fields["_ticket"].split_once('.').context("ticket")?.0,
    )?)?)
}

fn invocation(response: &Response) -> Result<&str> {
    Ok(response
        .headers()
        .get("x-day2-invocation")
        .context("invocation header")?
        .to_str()?)
}

fn patch(response: Response, status: &str) -> Result<String> {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-day2-command-status"], status);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let text = response.text()?;
    assert!(text.starts_with("event: datastar-patch-elements\n"));
    let html = text
        .lines()
        .filter_map(|line| line.strip_prefix("data: elements "))
        .collect::<Vec<_>>()
        .join("\n");
    ensure!(!html.is_empty(), "patch elements missing");
    let document = Html::parse_fragment(&html);
    assert_eq!(document.select(&selector("main#day2-main")).count(), 1);
    assert_eq!(document.select(&selector("script")).count(), 0);
    Ok(html)
}

#[test]
fn native_owner_edit_is_durable_and_retries_once() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(world.runtime.clone(), "alice")?;
    let client = server.client()?;
    let id = server.create(&world, &client, "Initial title")?;
    assert_eq!(world.row(&id)?["owner"], "alice");
    let path = format!("/links/{id}");
    let mut fields = form(&server.page(&client, &path)?, "#edit-link-form")?;
    let ticket = claims(&fields)?;
    assert_eq!(ticket["operation"], "links.edit");
    assert_eq!(ticket["bound"], json!({"link_id":id,"expected_version":1}));
    assert_eq!(ticket["editable"], json!(["title"]));
    assert_eq!(
        fields.keys().map(String::as_str).collect::<Vec<_>>(),
        ["_csrf", "_ticket", "title"]
    );
    fields.insert("title".into(), "<b>Owner edit</b> & handbook".into());
    let first = server.submit(&client, &fields, false)?;
    assert_eq!(first.status(), StatusCode::SEE_OTHER);
    assert_eq!(first.headers()["location"], path);
    let invocation_id = invocation(&first)?.to_owned();
    world.check_success(&invocation_id)?;
    let retry = server.submit(&client, &fields, false)?;
    assert_eq!(retry.status(), StatusCode::SEE_OTHER);
    assert_eq!(invocation(&retry)?, invocation_id);
    assert_eq!(
        world.row(&id)?,
        json!({
            "id": id, "version": 2, "title": "<b>Owner edit</b> & handbook",
            "destination": "https://example.com/handbook", "owner": "alice"
        })
    );
    assert_eq!(world.changes()?, 2);
    let page = server.page(&client, &path)?;
    assert!(page.contains("&lt;b&gt;Owner edit&lt;/b&gt; &amp; handbook"));
    let owner = Server::start(world.runtime.clone(), "admin")?;
    let audit = owner.page(&owner.client()?, "/audit?operation=links.edit")?;
    assert!(audit.contains("links.edit") && audit.contains("Values redacted."));
    assert!(!audit.contains("Owner edit"));
    day2::properties::require(
        world.runtime.artifact(),
        &world.runtime.inspect()?,
        &world.directory.path().join("properties"),
    )?;
    Ok(())
}

#[test]
fn cross_owner_edit_is_denied_but_explicit_admin_can_edit() -> Result<()> {
    let world = World::new()?;
    let alice = Server::start(world.runtime.clone(), "alice")?;
    let alice_client = alice.client()?;
    let id = alice.create(&world, &alice_client, "Alice title")?;
    let path = format!("/links/{id}");
    let before = world.row(&id)?;
    let bob = Server::start(world.runtime.clone(), "bob")?;
    let bob_client = bob.client()?;
    let mut fields = form(&bob.page(&bob_client, &path)?, "#edit-link-form")?;
    fields.insert("title".into(), "Bob cannot change this".into());
    let rejected = bob.submit(&bob_client, &fields, false)?;
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    let rejected_id = invocation(&rejected)?.to_owned();
    let trace = world.runtime.trace(&rejected_id)?;
    assert_eq!(trace.outcome.status, "failure");
    assert_eq!(trace.outcome.error, "forbidden");
    assert_eq!(
        trace.guard.as_ref().context("execution guard")?.error,
        "forbidden"
    );
    assert!(trace.request.observations.is_empty());
    replay(world.runtime.artifact(), &trace)?;
    assert_eq!(world.row(&id)?, before);
    assert_eq!(world.changes()?, 1);

    let bob_id = bob.create(&world, &bob_client, "Bob title")?;
    assert_eq!(world.row(&bob_id)?["owner"], "bob");
    let admin = Server::start(world.runtime.clone(), "admin")?;
    let admin_client = admin.client()?;
    let mut fields = form(&admin.page(&admin_client, &path)?, "#edit-link-form")?;
    fields.insert("title".into(), "Admin revised title".into());
    let response = admin.submit(&admin_client, &fields, true)?;
    let invocation_id = invocation(&response)?.to_owned();
    let html = patch(response, "200")?;
    assert!(html.contains("Admin revised title"));
    assert_eq!(world.row(&id)?["owner"], "alice");
    assert_eq!(world.row(&id)?["version"], 2);
    assert_eq!(world.changes()?, 3);
    world.check_success(&invocation_id)?;
    let admin_id = admin.create(&world, &admin_client, "Admin-owned title")?;
    assert_eq!(world.row(&admin_id)?["owner"], "admin");
    Ok(())
}

#[test]
fn stale_signed_title_edit_conflicts_even_when_handler_reloads_latest_row() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(world.runtime.clone(), "alice")?;
    let client = server.client()?;
    let id = server.create(&world, &client, "Initial title")?;
    let path = format!("/links/{id}");
    let mut first = form(&server.page(&client, &path)?, "#edit-link-form")?;
    let mut stale = form(&server.page(&client, &path)?, "#edit-link-form")?;
    assert_ne!(first["_ticket"], stale["_ticket"]);
    assert_eq!(claims(&first)?["bound"], claims(&stale)?["bound"]);
    first.insert("title".into(), "Committed title".into());
    stale.insert("title".into(), "Unsaved stale title".into());
    let response = server.submit(&client, &first, true)?;
    let first_id = invocation(&response)?.to_owned();
    let html = patch(response, "200")?;
    assert!(html.contains("Committed title"));
    world.check_success(&first_id)?;
    let before = world.row(&id)?;
    let response = server.submit(&client, &stale, true)?;
    let failed_id = invocation(&response)?.to_owned();
    let html = patch(response, "409")?;
    assert!(html.contains("This record has changed."));
    let document = Html::parse_fragment(&html);
    assert_eq!(
        document
            .select(&selector("#owned-link-details"))
            .next()
            .unwrap()
            .value()
            .attr("data-version"),
        Some("2")
    );
    assert_eq!(
        document
            .select(&selector("#edit-title"))
            .next()
            .unwrap()
            .value()
            .attr("value"),
        Some("Committed title")
    );
    let trace = world.runtime.trace(&failed_id)?;
    assert_eq!(trace.outcome.status, "failure");
    assert_eq!(trace.outcome.error, "conflict");
    assert_eq!(
        trace.guard.as_ref().context("execution guard")?.error,
        "conflict"
    );
    assert!(trace.request.observations.is_empty());
    replay(world.runtime.artifact(), &trace)?;
    assert_eq!(world.row(&id)?, before);
    assert_eq!(world.changes()?, 2);
    let retry = server.submit(&client, &stale, false)?;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert_eq!(invocation(&retry)?, failed_id);
    assert_eq!(world.row(&id)?, before);
    assert_eq!(world.changes()?, 2);
    Ok(())
}

#[test]
fn hidden_edit_authority_cannot_be_overridden_and_reader_has_no_forms() -> Result<()> {
    let world = World::new()?;
    let alice = Server::start(world.runtime.clone(), "alice")?;
    let client = alice.client()?;
    let id = alice.create(&world, &client, "Protected title")?;
    let path = format!("/links/{id}");
    let page = alice.page(&client, &path)?;
    let fields = form(&page, "#edit-link-form")?;
    let before = world.row(&id)?;
    let bound = claims(&fields)?;
    assert_eq!(bound["bound"], json!({"link_id":id,"expected_version":1}));
    for (name, value) in [
        ("link_id", "999"),
        ("expected_version", "2"),
        ("owner", "admin"),
        ("destination", "https://other.example/"),
    ] {
        let mut forged = fields.clone();
        forged.insert(name.into(), value.into());
        let response = alice.submit(&client, &forged, false)?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(world.row(&id)?, before);
        assert_eq!(world.changes()?, 1);
    }
    let mut poisoned_ticket = fields.clone();
    let mut payload = bound;
    payload["bound"]["expected_version"] = json!(2);
    let signature = fields["_ticket"].split_once('.').context("ticket")?.1;
    poisoned_ticket.insert(
        "_ticket".into(),
        format!(
            "{}.{signature}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?)
        ),
    );
    assert_eq!(
        alice.submit(&client, &poisoned_ticket, false)?.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(world.row(&id)?, before);
    assert_eq!(world.changes()?, 1);

    let viewer = Server::start(world.runtime.clone(), "viewer")?;
    let viewer_client = viewer.client()?;
    let directory = viewer.page(&viewer_client, "/")?;
    assert!(
        !Html::parse_document(&directory)
            .select(&selector("#create-link-form"))
            .any(|form| form
                .select(&selector("input[name='_ticket']"))
                .next()
                .is_some())
    );
    let detail = viewer.page(&viewer_client, &path)?;
    assert!(detail.contains("Protected title"));
    assert!(
        !Html::parse_document(&detail)
            .select(&selector("#edit-link-form"))
            .any(|form| form
                .select(&selector("input[name='_ticket']"))
                .next()
                .is_some())
    );
    assert_eq!(
        viewer.submit(&viewer_client, &fields, false)?.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(world.row(&id)?, before);
    Ok(())
}
