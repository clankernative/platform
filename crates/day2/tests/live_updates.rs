use crate::support::commands as support;

use anyhow::{Context, Result, bail, ensure};
use day2::{capabilities::NotificationWorld, invocations, store::Fault};
use reqwest::{StatusCode, blocking::Client, redirect::Policy};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};
use support::World;

#[test]
fn live_queries_fan_out_cross_process_commits_and_reconnect_with_current_state() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(&world)?;
    let client = server.client()?;
    let url = server.live_url(&client, "/")?;
    let first = Stream::open(&client, &url)?;
    let second = Stream::open(&client.clone(), &url)?;
    for stream in [&first, &second] {
        let patch = stream.until("No reports yet.")?;
        assert_regions_only(&patch);
    }

    // The writer lives outside the HTTP host process. Its committed revision
    // must reach every subscribed view without an in-process notification.
    let saved = world.submit("live-submit", Fault::None)?;
    assert_eq!(saved.status, "success", "{}", saved.error);
    let report = saved.result["id"].as_str().context("report ID")?;
    for stream in [&first, &second] {
        let patch = stream.until("Complete")?;
        assert!(patch.contains("Quarterly report"));
        assert!(patch.contains(report));
        assert_regions_only(&patch);
    }
    // Submitted, analyzed, announced. Draining first makes this the settled
    // revision rather than whichever background write happened to land.
    invocations::drain(&world.runtime, 64)?;
    assert_eq!(world.runtime.inspect()?["reports"][0]["version"], 3);

    let reconnected = Stream::open(&client, &url)?;
    let patch = reconnected.until("Quarterly report")?;
    assert!(patch.contains("Complete"));
    assert!(!patch.contains("No reports yet."));
    assert_regions_only(&patch);
    Ok(())
}

#[test]
fn live_queries_ignore_rolled_back_duplicate_and_query_only_writes() -> Result<()> {
    let world = World::new()?;
    // Faults belong to this executor. Finish the rollback before the HTTP
    // scheduler can claim the accepted command without that fault.
    let revision = live_revision(&world)?;
    assert_eq!(
        world
            .submit("rolled-back", Fault::FailAfterWrite(1))?
            .status,
        "failure"
    );
    assert_eq!(live_revision(&world)?, revision);
    assert_eq!(world.runtime.inspect()?["reports"], json!([]));
    let server = Server::start(&world)?;
    let client = server.client()?;
    let stream = Stream::open(&client, &server.live_url(&client, "/")?)?;
    stream.until("No reports yet.")?;
    let query = world.runtime.invoke(
        "reports.list",
        "alice",
        "query-receipt",
        &json!({"after":"","limit":20}),
        101,
        Fault::None,
    )?;
    assert_eq!(query.status, "success", "{}", query.error);
    let query_receipts = list_query_receipts(&world)?;
    stream.quiet(Duration::from_millis(900))?;
    assert_eq!(list_query_receipts(&world)?, query_receipts);

    let saved = world.submit("deduplicated", Fault::None)?;
    assert_eq!(saved.status, "success");
    // Analysis marks the report complete at revision 2; its announcement commits
    // revision 3 afterwards. Observe that final write before asserting silence.
    let settled = stream.until("Revision 3")?;
    assert!(settled.contains("Complete"));
    stream.quiet(Duration::from_millis(600))?;
    assert_eq!(
        world.submit("deduplicated", Fault::None)?.result,
        saved.result
    );
    let report = saved.result["id"].clone();
    let conflict = world.runtime.invoke(
        "reports.revise",
        "alice",
        "stale-edit",
        &json!({"report_id":report,"expected_version":1,"text":"Stale browser draft"}),
        102,
        Fault::None,
    )?;
    assert_eq!(conflict.status, "failure");
    assert_eq!(conflict.error, "conflict");
    let query_receipts = list_query_receipts(&world)?;
    stream.quiet(Duration::from_millis(900))?;
    assert_eq!(list_query_receipts(&world)?, query_receipts);
    Ok(())
}

#[test]
fn live_command_acknowledgements_never_replace_data_regions_or_rebase_stale_edits() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(&world)?;
    let client = server.client()?;
    let stream = Stream::open(&client, &server.live_url(&client, "/")?)?;
    stream.until("No reports yet.")?;
    let page = client.get(&server.origin).send()?.text()?;
    let mut submit = form_fields(&page, "#create-report")?;
    submit.insert("title".into(), "Live form report".into());
    submit.insert("text".into(), "Original document".into());
    let response = client
        .post(format!("{}/actions", server.origin))
        .header("Origin", &server.origin)
        .header("Datastar-Request", "true")
        .form(&submit)
        .send()?;
    assert_eq!(response.status(), StatusCode::OK);
    let acknowledgement = response.text()?;
    assert!(acknowledgement.contains("id=\"day2-command-status\""));
    assert!(acknowledgement.contains("data-day2-status=\"success\""));
    assert!(acknowledgement.contains("id=\"create-report\""));
    assert!(!acknowledgement.contains("id=\"reports-list\""));
    assert!(!acknowledgement.contains("id=\"reports-heading\""));
    stream.until("Complete")?;

    let report = world.runtime.inspect()?["reports"][0]["id"].clone();
    let page = client
        .get(format!(
            "{}/reports/{}",
            server.origin,
            report.as_str().context("report ID")?
        ))
        .send()?
        .text()?;
    let mut edit = form_fields(&page, "#revise-report")?;
    // The other browser edits whatever revision is current. Pinning a number here
    // made the test a hostage to how many background writes precede this point,
    // and it raced the announcement, which commits after analysis completes.
    invocations::drain(&world.runtime, 64)?;
    let current = world.runtime.inspect()?["reports"][0]["version"]
        .as_u64()
        .context("report revision")?;
    let changed = world.runtime.invoke(
        "reports.revise",
        "alice",
        "other-editor",
        &json!({"report_id":report,"expected_version":current,"text":"Changed in another browser"}),
        102,
        Fault::None,
    )?;
    assert_eq!(changed.status, "success", "{}", changed.error);
    // Wait for the revision the page actually settles on rather than computing it:
    // the revise requests a re-analysis which requests an announcement, and the
    // stream may coalesce the intermediate revisions rather than show each one.
    invocations::drain(&world.runtime, 64)?;
    let settled = world.runtime.inspect()?["reports"][0]["version"]
        .as_u64()
        .context("settled revision")?;
    assert!(settled > current, "the other browser's edit did not commit");
    stream.until(&format!("Revision {settled}"))?;
    edit.insert(
        "text".into(),
        "Unfinished draft from the original revision".into(),
    );
    let response = client
        .post(format!("{}/actions", server.origin))
        .header("Origin", &server.origin)
        .header("Datastar-Request", "true")
        .form(&edit)
        .send()?;
    assert_eq!(response.status(), StatusCode::OK);
    let acknowledgement = response.text()?;
    assert!(acknowledgement.contains("data-day2-status=\"failure\""));
    assert!(!acknowledgement.contains("<form"));
    assert!(!acknowledgement.contains("<textarea"));
    assert!(!acknowledgement.contains("id=\"report-result\""));
    assert!(!acknowledgement.contains("id=\"report-heading\""));
    assert_eq!(
        world.detail(&report, "after-stale-edit")?["text"],
        "Changed in another browser"
    );
    Ok(())
}

#[test]
fn external_read_refresh_updates_detail_regions_without_replacing_the_editor() -> Result<()> {
    let world = World::new()?;
    let saved = world.submit("notified-report", Fault::None)?;
    let analysis = world.child("notified-report")?;
    assert_eq!(world.finish(&analysis)?.status, "success");
    let notification = world.child(&analysis)?;
    assert_eq!(world.finish(&notification)?.status, "success");
    let report = saved.result["id"].as_str().context("report ID")?;
    let before = world.runtime.inspect()?;
    let server = Server::start(&world)?;
    let client = server.client()?;
    let path = format!("/reports/{report}");
    let page = client
        .get(format!("{}{path}", server.origin))
        .send()?
        .text()?;
    assert!(
        page.contains("Editing revision 3."),
        "unexpected detail page: {}",
        Html::parse_document(&page)
            .root_element()
            .text()
            .collect::<String>()
    );
    assert!(page.contains("<textarea"));
    let stream = Stream::open(&client, &server.live_url(&client, &path)?)?;
    let initial = stream.until("Your ready notification was accepted.")?;
    assert!(initial.contains("Complete"));
    assert_regions_only(&initial);

    // Change the independent provider's semantic state with no app-model write.
    // The page's admitted refresh interval must refresh capability observations.
    let provider =
        rusqlite::Connection::open(world.runtime.db().with_file_name("notifications.sqlite"))?;
    provider.busy_timeout(Duration::from_secs(5))?;
    provider.execute(
        "UPDATE notification_world SET state=?1 WHERE id=1",
        [serde_json::to_string(&NotificationWorld::default())?],
    )?;
    let patch = stream.until("No ready notification yet.")?;
    assert!(patch.contains("Complete"));
    assert_regions_only(&patch);
    assert_eq!(world.runtime.inspect()?, before);
    stream.quiet(Duration::from_millis(1500))?;
    Ok(())
}

#[test]
fn live_subscriptions_validate_transport_and_close_when_the_session_logs_out() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(&world)?;
    let client = server.client()?;
    let page = client.get(&server.origin).send()?;
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(page.headers()["referrer-policy"], "strict-origin");
    let url = server.live_url(&client, "/")?;
    let anonymous = Client::builder().redirect(Policy::none()).build()?;
    assert_eq!(
        anonymous
            .get(&url)
            .header("Datastar-Request", "true")
            .send()?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(client.get(&url).send()?.status().is_client_error());
    assert_eq!(
        client
            .get(&url)
            .header("Datastar-Request", "true")
            .header("Sec-Fetch-Site", "cross-site")
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    for query in [
        "",
        "path=%2F&path=%2F",
        "path=%2F&extra=1",
        "path=%ZZ",
        "path=https%3A%2F%2Fexample.com%2F",
        "path=%2F%3Flimit%3D0",
        "path=%2F%3Fafter%3D%26limit%3D20%26extra%3D1",
        "path=%2F&datastar=%7B%22report_id%22%3A%22unexpected%22%7D",
        "path=%2F&datastar=%5B%5D",
        "path=%2F&datastar=%7B%7D&datastar=%7B%7D",
    ] {
        let response = client
            .get(format!("{}/_live?{query}", server.origin))
            .header("Datastar-Request", "true")
            .send()?;
        assert!(
            response.status().is_client_error(),
            "{query}: {}",
            response.status()
        );
    }
    // Datastar 1.0.1 appends an empty JSON signal envelope even with the host's
    // filterSignals include /^$/ expression. Exercise the real browser shape.
    let stream = Stream::open(&client, &format!("{url}&datastar=%7B%7D"))?;
    stream.until("No reports yet.")?;
    let session: Value = serde_json::from_str(
        &client
            .get(format!("{}/api/session", server.origin))
            .send()?
            .text()?,
    )?;
    // Native form submissions need the page's policy to retain their origin.
    // A null origin remains forbidden even with a valid session and CSRF token.
    let rejected = client
        .post(format!("{}/logout", server.origin))
        .header("Origin", "null")
        .form(&[(
            "_csrf",
            session["csrf_token"].as_str().context("CSRF token")?,
        )])
        .send()?;
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    let response = client
        .post(format!("{}/logout", server.origin))
        .header("Origin", &server.origin)
        .form(&[(
            "_csrf",
            session["csrf_token"].as_str().context("CSRF token")?,
        )])
        .send()?;
    assert_eq!(response.status(), StatusCode::OK);
    stream.closed()?;
    assert_eq!(
        client
            .get(&url)
            .header("Datastar-Request", "true")
            .send()?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

#[test]
fn live_subscriptions_stop_after_current_query_authority_is_revoked() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(&world)?;
    let client = server.client()?;
    let url = server.live_url(&client, "/")?;
    let stream = Stream::open(&client, &url)?;
    stream.until("No reports yet.")?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.list")
            .unwrap()
            .actors
            .remove("alice");
    })?;
    stream.closed()?;
    assert_eq!(
        client
            .get(&url)
            .header("Datastar-Request", "true")
            .send()?
            .status(),
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[test]
fn live_subscription_cannot_silently_reacquire_identical_activated_policy() -> Result<()> {
    let world = World::new()?;
    let server = Server::start(&world)?;
    let client = server.client()?;
    let url = server.live_url(&client, "/")?;
    let stream = Stream::open(&client, &url)?;
    stream.until("No reports yet.")?;
    // Even an activation with identical bytes advances authority. Equality of
    // policy contents must not let the existing subscription acquire a new grant.
    world.change_policy(|_| {})?;
    stream.closed()?;
    let renewed = Stream::open(&client, &url)?;
    renewed.until("No reports yet.")?;
    Ok(())
}

fn assert_regions_only(patch: &str) {
    assert!(patch.contains("event: datastar-patch-elements"), "{patch}");
    assert!(
        !patch.contains("<form"),
        "live update replaced command form: {patch}"
    );
    assert!(
        !patch.contains("<textarea"),
        "live update replaced draft: {patch}"
    );
    assert!(
        !patch.contains("name=\"expected_version\""),
        "live update replaced edit version: {patch}"
    );
    assert!(
        !patch.contains("id=\"day2-live\""),
        "live update replaced subscription: {patch}"
    );
}

fn live_revision(world: &World) -> Result<i64> {
    Ok(rusqlite::Connection::open(world.runtime.db())?.query_row(
        "SELECT revision FROM day2_live_revision WHERE id=1",
        [],
        |row| row.get(0),
    )?)
}

fn list_query_receipts(world: &World) -> Result<i64> {
    Ok(rusqlite::Connection::open(world.runtime.db())?.query_row(
        "SELECT count(*) FROM day2_invocations WHERE operation='reports.list'",
        [],
        |row| row.get(0),
    )?)
}

enum StreamMessage {
    Patch(String),
    Closed,
    Failed(String),
}

struct Stream {
    receive: Receiver<StreamMessage>,
}

impl Stream {
    fn open(client: &Client, url: &str) -> Result<Self> {
        let response = client
            .get(url)
            .header("Datastar-Request", "true")
            .header("Sec-Fetch-Site", "same-origin")
            .send()?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()["content-type"]
                .to_str()?
                .starts_with("text/event-stream")
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        let (send, receive) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(response);
            let mut frame = String::new();
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        let _ = send.send(StreamMessage::Closed);
                        break;
                    }
                    Ok(_) if line.trim_end().is_empty() => {
                        if frame.contains("event: datastar-patch-elements")
                            && send.send(StreamMessage::Patch(frame.clone())).is_err()
                        {
                            break;
                        }
                        frame.clear();
                    }
                    Ok(_) => frame.push_str(&line),
                    Err(error) => {
                        let _ = send.send(StreamMessage::Failed(error.to_string()));
                        break;
                    }
                }
            }
        });
        Ok(Self { receive })
    }

    fn until(&self, expected: &str) -> Result<String> {
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.receive.recv_timeout(remaining)? {
                StreamMessage::Patch(patch) if patch.contains(expected) => return Ok(patch),
                StreamMessage::Patch(_) => (),
                StreamMessage::Closed => bail!("live stream closed before {expected:?}"),
                StreamMessage::Failed(error) => {
                    bail!("live stream failed before {expected:?}: {error}")
                }
            }
        }
    }

    fn quiet(&self, duration: Duration) -> Result<()> {
        match self.receive.recv_timeout(duration) {
            Err(RecvTimeoutError::Timeout) => Ok(()),
            Ok(StreamMessage::Patch(patch)) => {
                bail!("unchanged live query emitted another patch: {patch}")
            }
            Ok(StreamMessage::Failed(error)) => bail!("live stream failed: {error}"),
            _ => bail!("live stream unexpectedly closed"),
        }
    }

    fn closed(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            match self
                .receive
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))?
            {
                StreamMessage::Closed => return Ok(()),
                StreamMessage::Patch(patch) => {
                    assert!(
                        patch.contains("Live updates stopped."),
                        "app patch after revocation: {patch}"
                    );
                    assert!(
                        !patch.contains("No reports yet."),
                        "stale data after revocation: {patch}"
                    );
                    assert_regions_only(&patch);
                }
                StreamMessage::Failed(error) => bail!("live stream did not close cleanly: {error}"),
            }
        }
    }
}

struct Server {
    child: Child,
    origin: String,
    login: String,
}

impl Server {
    fn start(world: &World) -> Result<Self> {
        let log_path = world.directory.path().join("live-server.log");
        let log = fs::File::create(&log_path)?;
        let child = Command::new(env!("CARGO_BIN_EXE_day2"))
            .args([
                "serve-local",
                world
                    .runtime
                    .instance_path()
                    .to_str()
                    .context("instance path")?,
                "reports",
                "alice",
                "0",
            ])
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?;
        let mut server = Self {
            child,
            origin: String::new(),
            login: String::new(),
        };
        server.started(&log_path)?;
        Ok(server)
    }

    fn started(&mut self, log_path: &Path) -> Result<()> {
        let started = Instant::now();
        loop {
            let log = fs::read_to_string(log_path)?;
            for line in log.lines() {
                if let Ok(value) = serde_json::from_str::<Value>(line)
                    && let (Some(origin), Some(login)) =
                        (value["origin"].as_str(), value["login_url"].as_str())
                {
                    self.origin = origin.into();
                    self.login = login.into();
                    return Ok(());
                }
            }
            ensure!(self.child.try_wait()?.is_none(), "server stopped: {log}");
            ensure!(
                started.elapsed() < Duration::from_secs(20),
                "server startup timeout: {log}"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn client(&self) -> Result<Client> {
        let client = Client::builder()
            .cookie_store(true)
            .redirect(Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;
        let response = client.get(&self.login).send()?;
        assert_eq!(response.status(), StatusCode::OK);
        let page = Html::parse_document(&response.text()?);
        let fields: BTreeMap<_, _> = page
            .select(&selector("form input[name]")?)
            .map(|field| {
                (
                    field.value().attr("name").unwrap().to_string(),
                    field.value().attr("value").unwrap_or("").to_string(),
                )
            })
            .collect();
        let response = client
            .post(format!("{}/login", self.origin))
            .header("Origin", &self.origin)
            .form(&fields)
            .send()?;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        Ok(client)
    }

    fn live_url(&self, client: &Client, path: &str) -> Result<String> {
        let response = client.get(format!("{}{path}", self.origin)).send()?;
        assert_eq!(response.status(), StatusCode::OK);
        let page = Html::parse_document(&response.text()?);
        let initializer = page
            .select(&selector("#day2-live[data-live-url]")?)
            .next()
            .context("platform live subscription initializer")?;
        assert!(initializer.value().attr("data-init").is_some());
        let url = initializer
            .value()
            .attr("data-live-url")
            .context("live subscription URL")?;
        assert!(url.starts_with("/_live?path="), "{url}");
        Ok(reqwest::Url::parse(&self.origin)?.join(url)?.to_string())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn selector(value: &str) -> Result<Selector> {
    Selector::parse(value).map_err(|_| anyhow::anyhow!("test selector"))
}

fn form_fields(html: &str, selector_text: &str) -> Result<BTreeMap<String, String>> {
    let parsed = Html::parse_document(html);
    let form = parsed
        .select(&selector(selector_text)?)
        .next()
        .with_context(|| {
            format!(
                "command form missing ({selector_text}): {}",
                parsed.root_element().text().collect::<String>()
            )
        })?;
    let mut fields = BTreeMap::new();
    for input in form.select(&selector("input[name], textarea[name]")?) {
        let name = input.value().attr("name").context("field name")?;
        let value = if input.value().name() == "textarea" {
            input.text().collect::<String>()
        } else {
            input.value().attr("value").unwrap_or("").into()
        };
        fields.insert(name.into(), value);
    }
    Ok(fields)
}
