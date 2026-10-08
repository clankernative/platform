//! The host owns long-lived transport; each query evaluation remains bounded.
use super::*;
use crate::{authority_state::AuthorityStamp, error::Failure, web_templates};
use axum::{
    body::Body,
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use std::{collections::BTreeSet, time::Duration};
use std::{
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use tokio::sync::{OwnedSemaphorePermit, mpsc, oneshot};

const CHECK_INTERVAL: Duration = Duration::from_millis(250);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

// An abandoned/lagging stream must fail its body so Datastar retries it. Only
// explicit authority termination is a clean EOF (and must not retry forever).
struct LiveBody {
    receiver: mpsc::Receiver<String>,
    terminal: Option<oneshot::Receiver<String>>,
    ended: bool,
}

impl tokio_stream::Stream for LiveBody {
    type Item = std::result::Result<String, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let stream = self.get_mut();
        if stream.ended {
            return Poll::Ready(None);
        }
        // Revocation bypasses the bounded data queue. Discard any unsent app
        // patches before releasing the final clear-regions event, even when a
        // slow consumer has kept the queue full throughout revocation.
        if let Some(terminal) = &mut stream.terminal {
            match Pin::new(terminal).poll(context) {
                Poll::Ready(Ok(value)) => {
                    stream.ended = true;
                    stream.receiver.close();
                    while stream.receiver.try_recv().is_ok() {}
                    return Poll::Ready(Some(Ok(value)));
                }
                Poll::Ready(Err(_)) => stream.terminal = None,
                Poll::Pending => {}
            }
        }
        match stream.receiver.poll_recv(context) {
            Poll::Ready(Some(value)) => Poll::Ready(Some(Ok(value))),
            Poll::Ready(None) => {
                stream.ended = true;
                Poll::Ready(Some(Err(std::io::Error::other("live stream interrupted"))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

fn stream_response(body: LiveBody) -> Response {
    (
        [
            (header::CONTENT_TYPE.as_str(), "text/event-stream"),
            ("x-accel-buffering", "no"),
        ],
        Body::from_stream(body),
    )
        .into_response()
}

/// Datastar's default retry mode retries interrupted streams but stops on HTTP
/// error responses. A transient overload therefore uses the same interrupted
/// SSE transport as a dropped connection; auth failures retain their 4xx status.
pub(super) fn retry_response() -> Response {
    let (sender, receiver) = mpsc::channel(1);
    sender
        .try_send(": live updates temporarily unavailable; reconnecting\n\n".into())
        .expect("new live retry channel");
    drop(sender);
    stream_response(LiveBody {
        receiver,
        terminal: None,
        ended: false,
    })
}

struct Subscription {
    page: String,
    input: Value,
    headers: HeaderMap,
    state: SubscriptionState,
}

/// Replayable decisions; database/rendering observations are supplied by the host.
struct SubscriptionState {
    actor: String,
    session: String,
    revision: i64,
    authority: AuthorityStamp,
    regions: BTreeMap<String, String>,
    document_image_origins: BTreeSet<String>,
    needs_image_refresh: bool,
    refreshed: Duration,
    refresh: Option<Duration>,
}

impl Host {
    pub(super) fn live_initializer(
        &self,
        name: &str,
        input: &Value,
        image_origins: &[String],
    ) -> Result<Markup> {
        if !self.runtime.artifact().page(name)?.live {
            return Ok(::maud::html! {});
        }
        let page_url = view::page_url(&self.runtime, name, input)?;
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("path", &page_url)
            .append_pair("image-origins", &serde_json::to_string(image_origins)?)
            .finish();
        let url = format!("/_live?{query}");
        ensure!(url.len() <= 8192, Failure::UriBudget);
        // The URL is encoded as a JS string and then as an HTML attribute. Do not
        // interpolate user input directly into an executable Datastar expression.
        let expression = format!(
            "@get({}, {{filterSignals: {{include: /^$/}}, requestCancellation: 'cleanup'}})",
            serde_json::to_string(&url)?
        );
        Ok(::maud::html! {
            div id="day2-live" data-live-url=(url) data-init=(expression) {
                div id="day2-live-status" role="status" aria-live="polite" {}
            }
        })
    }

    pub(super) fn live_response(
        self: &Arc<Self>,
        uri: &Uri,
        headers: &HeaderMap,
        session: &Session,
        at: i64,
    ) -> Result<Response> {
        ensure!(
            headers
                .get("datastar-request")
                .is_some_and(|value| value == "true"),
            Failure::InvalidInput
        );
        ensure!(
            headers
                .get("sec-fetch-site")
                .is_none_or(|value| value == "same-origin"),
            Failure::InvalidOrigin
        );
        ensure!(
            headers
                .get(header::ORIGIN)
                .is_none_or(|value| value == self.origin.as_str()),
            Failure::InvalidOrigin
        );
        let mut fields = security::fields(uri.query().unwrap_or("").as_bytes())?;
        let path = fields.remove("path").context(Failure::InvalidInput)?;
        // This is an untrusted description of the document's immutable CSP, not
        // permission to fetch or render anything. The browser enforces that CSP.
        let document_image_origins = parse_image_origins(fields.remove("image-origins"))?;
        if let Some(signals) = fields.remove("datastar") {
            ensure!(
                serde_json::from_str::<Value>(&signals).ok() == Some(serde_json::json!({})),
                Failure::InvalidInput
            );
        }
        ensure!(fields.is_empty(), Failure::UnknownFields);
        ensure!(
            path.starts_with('/') && !path.starts_with("//") && !path.contains('#'),
            Failure::InvalidInput
        );
        let target: Uri = path.parse().map_err(|_| Failure::InvalidInput)?;
        ensure!(
            target.scheme().is_none() && target.authority().is_none(),
            Failure::InvalidInput
        );
        let (page, input) = self
            .routes
            .as_ref()
            .context(Failure::UnknownPage)?
            .resolve(target.path(), target.query().unwrap_or(""))
            .map_err(|_| Failure::InvalidPageInput)?
            .context(Failure::UnknownPage)?;
        let definition = self.runtime.artifact().page(&page)?;
        ensure!(definition.live, Failure::UnknownPage);
        let permit = match self.live_capacity.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return Ok(retry_response()),
        };
        let authority = self
            .runtime
            .authority_snapshot(&definition.operation, &session.actor)?
            .stamp;
        // Sample BEFORE querying. A commit while we render forces another pass;
        // using a revision sampled afterwards would lose that change forever.
        let revision = crate::live::revision(&open(self.runtime.db())?)?;
        let content = self.page(&page, &input, session, at, None, None)?;
        let markup = content.into_string();
        let regions = web_templates::live_regions(&markup)?;
        let rendered_origins = web_templates::remote_image_origins(&markup)?;
        let needs_image_refresh = has_new_image_origins(&document_image_origins, &rendered_origins);
        let subscription = Subscription {
            page,
            input,
            headers: headers.clone(),
            state: SubscriptionState {
                actor: session.actor.clone(),
                session: session.hash.clone(),
                revision,
                authority,
                regions,
                document_image_origins,
                needs_image_refresh,
                refreshed: self.clock.monotonic(),
                refresh: (definition.live_refresh_ms > 0)
                    .then(|| Duration::from_millis(definition.live_refresh_ms)),
            },
        };
        // Recheck after rendering before any app data is released.
        let (_, current) = subscription.authorize(self, self.wall_seconds()?)?;
        ensure!(
            current == subscription.state.authority,
            Failure::AuthorityPolicyChanged
        );
        let (sender, receiver) = mpsc::channel(1);
        let (terminal_sender, terminal) = oneshot::channel();
        let refresh_url = view::page_url(&self.runtime, &subscription.page, &subscription.input)?;
        let initial = format!(
            "{}{}",
            subscription
                .state
                .regions
                .values()
                .cloned()
                .collect::<String>(),
            image_refresh_notice(subscription.state.needs_image_refresh, &refresh_url)
        );
        sender
            .try_send(elements(&initial, "outer"))
            .map_err(|_| anyhow::anyhow!("live_initial_frame"))?;
        let host = self.clone();
        tokio::spawn(async move {
            subscription
                .run(host, sender, terminal_sender, permit)
                .await;
        });
        Ok(stream_response(LiveBody {
            receiver,
            terminal: Some(terminal),
            ended: false,
        }))
    }
}

fn parse_image_origins(value: Option<String>) -> Result<BTreeSet<String>> {
    let Some(value) = value else {
        return Ok(BTreeSet::new());
    };
    let origins: Vec<String> = serde_json::from_str(&value).map_err(|_| Failure::InvalidInput)?;
    ensure!(origins.len() <= 32, Failure::InvalidInput);
    ensure!(
        serde_json::to_string(&origins)? == value,
        Failure::InvalidInput
    );
    let mut unique = BTreeSet::new();
    let mut previous: Option<String> = None;
    for origin in origins {
        ensure!(
            previous.as_ref().is_none_or(|value| value < &origin),
            Failure::InvalidInput
        );
        previous = Some(origin.clone());
        web_templates::validate_remote_image_source(&origin).map_err(|_| Failure::InvalidInput)?;
        let parsed = url::Url::parse(&origin).map_err(|_| Failure::InvalidInput)?;
        ensure!(
            parsed.origin().ascii_serialization() == origin,
            Failure::InvalidInput
        );
        ensure!(unique.insert(origin), Failure::InvalidInput);
    }
    Ok(unique)
}

fn has_new_image_origins(document: &BTreeSet<String>, rendered: &[String]) -> bool {
    rendered.iter().any(|origin| !document.contains(origin))
}

fn image_refresh_notice(needs_refresh: bool, page_url: &str) -> String {
    // Keep branching in ordinary Rust so the bounded canonical Maud grammar
    // can distinguish static attribute names from all evaluated expressions.
    let content = if needs_refresh {
        ::maud::html! {
            "Some new images need a page refresh to load. Your draft is unchanged. "
            a href=(page_url) { "Refresh page" }
        }
    } else {
        ::maud::html! {}
    };
    ::maud::html! {
        div id="day2-live-status" role="status" aria-live="polite" { (content) }
    }
    .into_string()
}

impl SubscriptionState {
    fn authorize_session(&self, session: &Session, wall: i64) -> Result<()> {
        ensure!(
            session.hash == self.session && session.actor == self.actor && wall < session.expires,
            Failure::SignInRequired
        );
        Ok(())
    }

    fn authorize(&self, session: &Session, authority: &AuthorityStamp, wall: i64) -> Result<()> {
        self.authorize_session(session, wall)?;
        // Bind to the admission stamp, including identical A -> B -> A policies.
        ensure!(
            *authority == self.authority,
            Failure::AuthorityPolicyChanged
        );
        Ok(())
    }

    fn needs_refresh(&self, revision: i64, monotonic: Duration) -> bool {
        revision != self.revision
            || self
                .refresh
                .is_some_and(|interval| monotonic.saturating_sub(self.refreshed) >= interval)
    }

    fn rendered(
        &mut self,
        revision: i64,
        monotonic: Duration,
        regions: BTreeMap<String, String>,
        rendered_origins: &[String],
        refresh_url: &str,
    ) -> Result<Option<String>> {
        ensure!(
            regions.keys().eq(self.regions.keys()),
            "live_region_set_changed"
        );
        let needs_image_refresh =
            has_new_image_origins(&self.document_image_origins, rendered_origins);
        let mut changed = regions
            .iter()
            .filter(|(id, markup)| self.regions.get(*id) != Some(*markup))
            .map(|(_, markup)| markup.as_str())
            .collect::<String>();
        if needs_image_refresh != self.needs_image_refresh {
            changed.push_str(&image_refresh_notice(needs_image_refresh, refresh_url));
        }
        self.needs_image_refresh = needs_image_refresh;
        self.regions = regions;
        self.revision = revision;
        self.refreshed = monotonic;
        Ok((!changed.is_empty()).then(|| elements(&changed, "outer")))
    }
}

impl Subscription {
    fn authorize(&self, host: &Host, wall: i64) -> Result<(Session, AuthorityStamp)> {
        ensure!(
            host.admitting.load(Ordering::Acquire),
            Failure::ArtifactBindingChanged
        );
        host.appearance.check_binding(&host.runtime)?;
        let session = security::session(&host.runtime, &self.headers, &host.cookie_name, wall)?;
        self.state.authorize_session(&session, wall)?;
        let operation = &host.runtime.artifact().page(&self.page)?.operation;
        let authority = host
            .runtime
            .authority_snapshot(operation, &self.state.actor)?
            .stamp;
        self.state.authorize(&session, &authority, wall)?;
        Ok((session, authority))
    }

    fn refresh(&mut self, host: &Host) -> Result<Option<String>> {
        let wall = host.wall_seconds()?;
        let (session, authority) = self.authorize(host, wall)?;
        let revision = crate::live::revision(&open(host.runtime.db())?)?;
        if !self.state.needs_refresh(revision, host.clock.monotonic()) {
            return Ok(None);
        }
        let markup = host.page(&self.page, &self.input, &session, wall, None, None)?;
        let markup = markup.into_string();
        let regions = web_templates::live_regions(&markup)?;
        let rendered_origins = web_templates::remote_image_origins(&markup)?;
        ensure!(
            regions.keys().eq(self.state.regions.keys()),
            "live_region_set_changed"
        );
        // Reobserve wall time and authority after rendering, before committing a patch.
        let (_, current) = self.authorize(host, host.wall_seconds()?)?;
        ensure!(current == authority, Failure::AuthorityPolicyChanged);
        let refresh_url = view::page_url(&host.runtime, &self.page, &self.input)?;
        self.state.rendered(
            revision,
            host.clock.monotonic(),
            regions,
            &rendered_origins,
            &refresh_url,
        )
    }

    async fn run(
        mut self,
        host: Arc<Host>,
        sender: mpsc::Sender<String>,
        terminal: oneshot::Sender<String>,
        _permit: OwnedSemaphorePermit,
    ) {
        let mut ticks = host.live_ticks.start(CHECK_INTERVAL);
        let mut heartbeat = host.clock.monotonic();
        loop {
            tokio::select! {
                _ = sender.closed() => break,
                _ = ticks.next() => {}
            }
            if !host.admitting.load(Ordering::Acquire) {
                break;
            }
            // Idle streams hold only their stream budget, never a worker, DB
            // transaction, or normal request permit. Query work shares capacity.
            let Ok(work) = host.capacity.clone().try_acquire_owned() else {
                continue;
            };
            let evaluator = host.clone();
            let refreshed = tokio::task::spawn_blocking(move || {
                let _work = work;
                let result = self.refresh(&evaluator);
                (self, result)
            })
            .await;
            let (subscription, result) = match refreshed {
                Ok(result) => result,
                Err(_) => break,
            };
            self = subscription;
            match result {
                Ok(Some(event)) => {
                    if sender.try_send(event).is_err() {
                        break;
                    }
                    heartbeat = host.clock.monotonic();
                }
                Ok(None)
                    if host.clock.monotonic().saturating_sub(heartbeat) >= HEARTBEAT_INTERVAL =>
                {
                    if sender.try_send(": keep-alive\n\n".into()).is_err() {
                        break;
                    }
                    heartbeat = host.clock.monotonic();
                }
                Ok(None) => {}
                Err(error) => {
                    let classified = crate::error::classify(&error);
                    if matches!(
                        classified.category(),
                        crate::error::Category::Authentication
                            | crate::error::Category::Forbidden
                            | crate::error::Category::Conflict
                            | crate::error::Category::NotFound
                    ) {
                        let mut cleared = String::new();
                        for id in self.state.regions.keys() {
                            cleared.push_str(&::maud::html! { div id=(id) {} }.into_string());
                        }
                        cleared.push_str(&::maud::html! { div id="day2-live-status" role="status" { "Live updates stopped. " a href="/" { "Reload to continue." } } }.into_string());
                        let _ = terminal.send(elements(&cleared, "outer"));
                    }
                    break;
                }
            }
        }
    }
}

impl Runtime {
    pub(crate) fn authority_snapshot(
        &self,
        operation: &str,
        actor: &str,
    ) -> Result<crate::authority_state::ActiveAuthority> {
        let mut db = open(self.db())?;
        let tx = db.transaction()?;
        crate::authority_state::authorize_in(&tx, self, operation, actor)
    }
}

fn elements(markup: &str, mode: &str) -> String {
    let mut event = format!("event: datastar-patch-elements\ndata: mode {mode}\n");
    for line in markup.replace('\r', "&#13;").split('\n') {
        event.push_str("data: elements ");
        event.push_str(line);
        event.push('\n');
    }
    event.push('\n');
    event
}

/// The subscription exclusively owns data regions. A command can replace only
/// its signed, stable form target and acknowledgement, avoiding response races.
pub(super) fn command_patch(
    markup: Markup,
    ticket: &Ticket,
    status: StatusCode,
    invocation: &str,
) -> Result<Response> {
    let document = scraper::Html::parse_fragment(&markup.into_string());
    let id = ticket.form_id.as_deref().context(Failure::InvalidTicket)?;
    let form = document
        .select(&scraper::Selector::parse("form[id]").expect("static selector"))
        .find(|form| form.value().attr("id") == Some(id));
    let notice = document
        .select(&scraper::Selector::parse("#day2-command-status").expect("static selector"))
        .next()
        .context("command notice")?;
    let content = ::maud::html! { div id="day2-command-status"
        data-day2-invocation=(invocation) data-day2-operation=(&ticket.operation)
        data-day2-status=(match status {
            StatusCode::OK => "success",
            StatusCode::ACCEPTED => "pending",
            _ => "failure",
        }) {
        (maud::PreEscaped(notice.inner_html()))
    } }
    .into_string();
    let mut events = elements(&content, "outer");
    // A rejected submission keeps the existing draft and its original ticket.
    // A deliberate reload is required after a stale edit; never silently rebase.
    // ACCEPTED is durable acceptance, so its form is reset with a fresh ticket
    // exactly like a success; only a genuine rejection retains the draft.
    if matches!(status, StatusCode::OK | StatusCode::ACCEPTED)
        && let Some(form) = form
    {
        // Morphing preserves dirty controls when their default values did
        // not change. Replace this submitted form so a successful create
        // resets its values together with its new idempotency ticket.
        events.push_str(&elements(&form.html(), "replace"));
    }
    Ok(([(header::CONTENT_TYPE, "text/event-stream")], events).into_response())
}

#[cfg(test)]
#[path = "web_live_simulation.rs"]
mod simulation_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt;

    #[test]
    fn image_origin_policy_hints_are_bounded_distinct_canonical_https_origins() {
        assert_eq!(parse_image_origins(None).unwrap(), BTreeSet::new());
        assert_eq!(
            parse_image_origins(Some(r#"["https://cdn.example.test"]"#.into())).unwrap(),
            BTreeSet::from(["https://cdn.example.test".into()])
        );
        for invalid in [
            r#"["http://cdn.example.test"]"#,
            r#"["https://cdn.example.test/path"]"#,
            r#"["https://user@cdn.example.test"]"#,
            r#"["https://*.example.test"]"#,
            r#"["https://cdn.example.test:bad"]"#,
            r#"["https://CDN.example.test"]"#,
            r#"["https://cdn.example.test","https://cdn.example.test"]"#,
            "[] ",
        ] {
            assert!(
                parse_image_origins(Some(invalid.into())).is_err(),
                "{invalid}"
            );
        }
        let too_many = (0..33)
            .map(|index| format!("https://cdn{index}.example.test"))
            .collect::<Vec<_>>();
        assert!(parse_image_origins(Some(serde_json::to_string(&too_many).unwrap())).is_err());
    }

    #[test]
    fn image_origin_refresh_notice_is_reserved_status_only_and_escaped() {
        let url = "/reports?name=a&next=b";
        let notice = image_refresh_notice(true, url);
        assert!(notice.contains("id=\"day2-live-status\""));
        assert!(notice.contains("role=\"status\""));
        assert!(
            notice
                .contains("Some new images need a page refresh to load. Your draft is unchanged.")
        );
        assert!(notice.contains("href=\"/reports?name=a&amp;next=b\""));
        assert!(!notice.contains("<form"));
        assert!(!notice.contains("data-init"));
        assert!(!image_refresh_notice(false, url).contains("Refresh page"));
        assert!(!image_refresh_notice(false, url).contains("Some new images"));
    }

    #[test]
    fn image_origin_subset_warns_only_for_new_hosts() {
        let document = BTreeSet::from(["https://one.example.test".into()]);
        assert!(!has_new_image_origins(
            &document,
            &["https://one.example.test".into()]
        ));
        assert!(!has_new_image_origins(&document, &[]));
        assert!(has_new_image_origins(
            &document,
            &["https://two.example.test".into()]
        ));
    }

    #[tokio::test]
    async fn terminal_revocation_discards_a_saturated_data_queue() -> Result<()> {
        let (sender, receiver) = mpsc::channel(1);
        let (terminal_sender, terminal) = oneshot::channel();
        sender.try_send("stale private app data".into())?;
        let mut body = LiveBody {
            receiver,
            terminal: Some(terminal),
            ended: false,
        };
        let clear = elements("<div id=\"private-region\"></div>", "outer");
        terminal_sender.send(clear.clone()).expect("live receiver");
        assert_eq!(body.next().await.transpose()?, Some(clear));
        assert!(sender.is_closed());
        assert!(body.next().await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn interrupted_producer_is_an_error_instead_of_clean_eof() -> Result<()> {
        let (sender, receiver) = mpsc::channel(1);
        let (terminal_sender, terminal) = oneshot::channel();
        sender.try_send(": keep-alive\n\n".into())?;
        let mut body = LiveBody {
            receiver,
            terminal: Some(terminal),
            ended: false,
        };
        drop(sender);
        drop(terminal_sender);
        assert_eq!(
            body.next().await.transpose()?,
            Some(": keep-alive\n\n".into())
        );
        assert!(body.next().await.context("interruption error")?.is_err());
        assert!(body.next().await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn disconnected_body_wakes_the_waiting_producer() -> Result<()> {
        let (sender, receiver) = mpsc::channel(1);
        let (terminal_sender, terminal) = oneshot::channel();
        let body = LiveBody {
            receiver,
            terminal: Some(terminal),
            ended: false,
        };
        drop(body);
        tokio::time::timeout(Duration::from_secs(1), sender.closed()).await?;
        assert!(terminal_sender.is_closed());
        Ok(())
    }

    #[tokio::test]
    async fn transient_overload_uses_the_native_datastar_stream_retry_path() -> Result<()> {
        let response = retry_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/event-stream"
        );
        assert_eq!(response.headers()["x-accel-buffering"], "no");
        let mut body = response.into_body().into_data_stream();
        let first = body.next().await.context("retry comment")??;
        assert!(first.starts_with(b": "));
        assert!(first.ends_with(b"\n\n"));
        assert!(body.next().await.context("retry interruption")?.is_err());
        assert!(body.next().await.is_none());
        Ok(())
    }

    #[test]
    fn html_line_breaks_cannot_inject_sse_fields_or_events() {
        assert_eq!(
            elements(
                "<p id=\"result\">A\r\n\nevent: forged\nid: forged</p>",
                "outer"
            ),
            "event: datastar-patch-elements\ndata: mode outer\ndata: elements <p id=\"result\">A&#13;\ndata: elements \ndata: elements event: forged\ndata: elements id: forged</p>\n\n"
        );
    }

    #[tokio::test]
    async fn successful_command_replaces_its_form_and_failure_preserves_the_draft() -> Result<()> {
        let ticket: Ticket = serde_json::from_value(serde_json::json!({
            "scope":"test", "artifact":"test", "session":"test", "actor":"alice",
            "page":"reports", "page_input":{}, "operation":"reports.submit", "form_id":"create-report",
            "bound":{}, "editable":["title"], "nonce":"test", "issued":0, "expires":1800
        }))?;
        let markup = html! {
            div id="day2-command-status" { "Saved." }
            div id="reports-list" data-live { "Current reports" }
            form id="create-report" {
                input name="title" value="";
                input type="hidden" name="_ticket" value="new-ticket";
            }
        };
        let response = command_patch(markup.clone(), &ticket, StatusCode::OK, "saved")?;
        let payload = String::from_utf8(to_bytes(response.into_body(), 16_384).await?.to_vec())?;
        let frames: Vec<_> = payload.trim_end().split("\n\n").collect();
        assert_eq!(frames.len(), 2);
        assert!(frames[0].contains("data: mode outer\n"));
        assert!(!frames[0].contains("<form"));
        assert!(frames[1].contains("data: mode replace\n"));
        assert!(frames[1].contains("<form id=\"create-report\""));
        assert!(frames[1].contains("new-ticket"));
        assert!(!payload.contains("reports-list"));
        let response = command_patch(markup, &ticket, StatusCode::CONFLICT, "rejected")?;
        let payload = String::from_utf8(to_bytes(response.into_body(), 16_384).await?.to_vec())?;
        assert_eq!(payload.matches("event: datastar-patch-elements").count(), 1);
        assert!(payload.contains("data-day2-status=\"failure\""));
        assert!(!payload.contains("<form"));
        assert!(!payload.contains("new-ticket"));
        Ok(())
    }

    #[test]
    fn fresh_page_query_retries_conflicts_with_new_receipts() -> Result<()> {
        let mut receipts = BTreeMap::<String, crate::protocol::Outcome>::new();
        let outcome = super::super::fresh_page_query(
            &crate::host_inputs::simulation::SeededEntropy::new(130),
            |id| {
                // An invocation ID identifies a durable receipt. Reusing a failed
                // ID must return that same failure, even after the underlying row
                // stops changing; recovery requires a fresh query invocation.
                if let Some(receipt) = receipts.get(id) {
                    return Ok(receipt.clone());
                }
                let receipt = if receipts.len() < 2 {
                    crate::protocol::Outcome {
                        status: "failure".into(),
                        result: Value::Null,
                        error: "preparation_conflict".into(),
                    }
                } else {
                    crate::protocol::Outcome {
                        status: "success".into(),
                        result: serde_json::json!({"version":4,"text":"Current document"}),
                        error: String::new(),
                    }
                };
                receipts.insert(id.into(), receipt.clone());
                Ok(receipt)
            },
        )?;
        assert_eq!(outcome.status, "success");
        assert_eq!(outcome.result["version"], 4);
        assert_eq!(outcome.result["text"], "Current document");
        assert_eq!(receipts.len(), 3);
        assert!(receipts.keys().all(|id| id.starts_with("page-")));
        assert_eq!(
            receipts
                .values()
                .filter(|receipt| receipt.status == "failure")
                .count(),
            2
        );
        Ok(())
    }

    #[test]
    fn fresh_page_query_bounds_continuous_conflicts_to_three_attempts() -> Result<()> {
        let conflict = crate::protocol::Outcome {
            status: "failure".into(),
            result: Value::Null,
            error: "preparation_conflict".into(),
        };
        let mut ids = Vec::new();
        let outcome = super::super::fresh_page_query(
            &crate::host_inputs::simulation::SeededEntropy::new(130),
            |id| {
                ids.push(id.to_string());
                Ok(conflict.clone())
            },
        )?;
        assert_eq!(outcome, conflict);
        assert_eq!(ids.len(), 3);
        assert_eq!(
            ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
            3
        );
        Ok(())
    }

    #[test]
    fn fresh_page_query_does_not_retry_other_outcomes() -> Result<()> {
        for (status, error) in [
            ("success", ""),
            ("pending", ""),
            ("failure", "forbidden"),
            ("failure", "not_found"),
            ("failure", "conflict"),
            ("failure", "preparation_deadline"),
        ] {
            let expected = crate::protocol::Outcome {
                status: status.into(),
                result: if status == "failure" {
                    Value::Null
                } else {
                    serde_json::json!({})
                },
                error: error.into(),
            };
            let mut attempts = 0;
            let outcome = super::super::fresh_page_query(
                &crate::host_inputs::simulation::SeededEntropy::new(130),
                |_| {
                    attempts += 1;
                    Ok(expected.clone())
                },
            )?;
            assert_eq!(outcome, expected);
            assert_eq!(attempts, 1, "{status}: {error}");
        }
        Ok(())
    }

    #[test]
    fn fresh_page_query_preserves_infrastructure_errors_without_retrying() {
        let mut attempts = 0;
        let error = super::super::fresh_page_query(
            &crate::host_inputs::simulation::SeededEntropy::new(130),
            |_| {
                attempts += 1;
                anyhow::bail!("provider unavailable")
            },
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "provider unavailable");
        assert_eq!(attempts, 1);
    }
}
