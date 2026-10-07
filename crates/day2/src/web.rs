use crate::{
    audit::Filter,
    digest,
    store::{Fault, Runtime, open},
    web_assets::Appearance,
    web_html::{self as view, document, icon},
    web_security::{self as security, Session, Ticket},
};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use maud::{Markup, html};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::Semaphore};

#[path = "web_live.rs"]
mod live;

struct Grant {
    hash: String,
    actor: String,
    expires: i64,
}
/// How a request comes to be from someone.
enum SignIn {
    /// Development: one link, printed at startup and good once, for one actor.
    Link(Mutex<Option<Grant>>),
    /// An identity provider in front of every request. Each request carries its
    /// own assertion and is verified on its own; the session cookie only
    /// anchors CSRF tokens and never stands in for the assertion.
    Edge(crate::iap::Verifier),
}
struct Notice<'a> {
    message: &'a str,
    error: bool,
    invocation: &'a str,
    operation: &'a str,
}
struct Host {
    oauth: Option<Arc<crate::oauth::shell_transport::AppApprovalReceiver>>,
    runtime: Runtime,
    credential_effects: crate::managed_credentials::effects::Captured,
    routes: Option<crate::routing::Catalog>,
    redirects: crate::redirects::Catalog,
    api: crate::openapi::Catalog,
    appearance: Appearance,
    authority: String,
    origin: String,
    cookie_name: String,
    secret: Vec<u8>,
    sign_in: SignIn,
    capacity: Arc<Semaphore>,
    /// Issuance must make progress while the originating query holds its own
    /// request permit. Keep this separately bounded from browser admission.
    app_capacity: Arc<Semaphore>,
    app_issue_capacity: Arc<Semaphore>,
    app_execute_capacity: Arc<Semaphore>,
    app_reconcile_capacity: Arc<Semaphore>,
    /// Requests waiting for a permit; bounded by [`MAX_QUEUED`].
    queued: std::sync::atomic::AtomicUsize,
    live_capacity: Arc<Semaphore>,
    admitting: Arc<AtomicBool>,
    health_endpoints: bool,
}
pub struct LocalServer {
    listener: TcpListener,
    host: Arc<Host>,
    pub origin: String,
    pub login_url: String,
}

pub(crate) struct Admission(Arc<AtomicBool>);

impl Admission {
    pub(crate) fn stop(&self) {
        self.0.store(false, Ordering::Release);
    }
}
fn now() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}

fn now_ms() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

/// How often the occurrence source looks for work. This is not the schedule
/// interval: occurrences are derived from the clock, so this only bounds how late
/// a run can start, never whether it happens. The shortest interval an application
/// may declare is a minute, so looking every ten seconds is frequent enough to keep
/// lateness small and rare enough to cost two indexed lookups per schedule.
const SCHEDULE_TICK: Duration = Duration::from_secs(10);

/// How often the journal is compacted, and how much one pass may do. Each batch is
/// its own short write transaction, so requests queue behind at most one batch; a
/// backlog larger than one pass drains over the following minutes.
const JOURNAL_TICK: Duration = Duration::from_secs(60);
const JOURNAL_BATCH: usize = 500;
const JOURNAL_BATCHES_PER_TICK: usize = 20;

/// A loopback documentation preview with no sessions or business API dispatcher.
pub async fn serve_docs_preview(
    artifact: crate::artifact::LoadedArtifact,
    port: u16,
) -> Result<()> {
    artifact.require_current_api()?;
    let catalog = crate::openapi::Catalog::from_artifact(artifact.contract())?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let mut spec = catalog.document(
        artifact.contract(),
        &artifact.contract().namespace,
        artifact.id(),
        "INSTANCE_SESSION_COOKIE",
        &origin,
    );
    spec["components"]["securitySchemes"]["AppSession"]["description"] = serde_json::json!(
        "Artifact preview: the cookie name is installation-specific. Use the live app's /openapi.json for its concrete authentication binding."
    );
    spec["x-day2-documentation-preview"] = serde_json::json!(true);
    let docs = crate::web_api::docs(&spec, &origin, None)?.into_string();
    let files = Arc::new(BTreeMap::from([
        ("/", ("text/html; charset=utf-8", docs.clone())),
        (
            crate::openapi::DOCS_PATH,
            ("text/html; charset=utf-8", docs),
        ),
        (
            crate::openapi::SPEC_PATH,
            ("application/json", serde_json::to_string_pretty(&spec)?),
        ),
        (
            "/assets/platform/api-docs.css",
            (
                "text/css",
                include_str!("../../../assets/api-docs.css").into(),
            ),
        ),
        (
            "/assets/platform/api-docs.js",
            (
                "text/javascript",
                include_str!("../../../assets/api-docs.js").into(),
            ),
        ),
    ]));
    drop(artifact);
    let router = Router::new().fallback(move |request: Request| {
        let files = files.clone();
        async move {
            let mut response = if !matches!(*request.method(), Method::GET | Method::HEAD) {
                (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "GET, HEAD")]).into_response()
            } else if let Some((kind, body)) = files.get(request.uri().path()) {
                ([(header::CONTENT_TYPE, *kind)], if request.method() == Method::HEAD { String::new() } else { body.clone() }).into_response()
            } else {
                StatusCode::NOT_FOUND.into_response()
            };
            response.headers_mut().insert("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'".parse().expect("static CSP"));
            secure(response)
        }
    });
    println!(
        "{}",
        serde_json::json!({"docs_url":format!("{origin}/docs"),"spec_url":format!("{origin}/openapi.json"),"mode":"documentation-preview"})
    );
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn validate_ingress_credentials(runtime: &Runtime) -> Result<()> {
    let instance = crate::artifact::Instance::load(runtime.instance_path())?;
    let binding = instance
        .apps
        .get(runtime.app())
        .context("app binding missing")?;
    for (name, endpoint) in binding
        .ingress
        .iter()
        .filter(|(_, endpoint)| !endpoint.disabled)
    {
        let declared = runtime
            .artifact()
            .contract()
            .ingress
            .iter()
            .find(|declared| &declared.name == name)
            .context("endpoint declaration missing")?;
        let live = instance
            .resources
            .as_ref()
            .and_then(|catalog| catalog.connections.get(&endpoint.connection.id))
            .filter(|definition| definition.revision == endpoint.connection.revision)
            .and_then(|definition| definition.live.as_ref())
            .with_context(|| format!("endpoint_connection_missing_or_stale: {name}"))?;
        crate::ingress::validate_connection(&declared.provider, live)?;
        let mounts = crate::integration_host::MountedCredentials::new(runtime.instance_path())?;
        mounts
            .verification_key(live)
            .map_err(|_| anyhow::anyhow!("endpoint_signing_secret_unavailable: {name}"))?;
    }
    Ok(())
}

impl LocalServer {
    /// Deliberately not a production authentication adapter. This API cannot bind
    /// a public address or trust identity headers from a caller/reverse proxy.
    pub async fn bind(runtime: Runtime, actor: &str, port: u16) -> Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
        let authority = listener.local_addr()?.to_string();
        Self::bind_development(runtime, actor, listener, authority, 4, false)
    }

    /// The container profile is explicitly development-only. Its launcher must
    /// publish this listener on host loopback; forwarded identity is never trusted.
    pub(crate) async fn bind_container(
        runtime: Runtime,
        actor: &str,
        published_port: std::num::NonZeroU16,
        concurrency: usize,
    ) -> Result<Self> {
        ensure!((1..=32).contains(&concurrency), "invalid HTTP concurrency");
        let listener = TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, 8080)).await?;
        Self::bind_development(
            runtime,
            actor,
            listener,
            format!("127.0.0.1:{published_port}"),
            concurrency,
            true,
        )
    }

    /// Serve behind the installation's identity provider, at the app's edge
    /// address. There is no sign-in link and no actor argument: who a request
    /// is from is whatever its verified assertion says, and nothing else.
    pub(crate) async fn bind_edge(
        runtime: Runtime,
        identity: &crate::artifact::IdentityProvider,
        edge: &crate::artifact::Edge,
        concurrency: usize,
    ) -> Result<Self> {
        ensure!((1..=32).contains(&concurrency), "invalid HTTP concurrency");
        let crate::artifact::IdentityScheme::GoogleIap = identity.scheme;
        let verifier = crate::iap::Verifier::new(
            &edge.iap_audience,
            &identity.hosted_domain,
            Box::new(crate::iap::GoogleKeys),
        )?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, 8080)).await?;
        Self::bind_edge_listener(runtime, listener, edge, verifier, concurrency)
    }

    /// The edge server on a listener the caller bound, verifying against the
    /// given keys. `bind_edge` is this with Google's keys on port 8080; tests
    /// use it to present assertions signed by keys they hold.
    pub fn bind_edge_listener(
        runtime: Runtime,
        listener: TcpListener,
        edge: &crate::artifact::Edge,
        verifier: crate::iap::Verifier,
        concurrency: usize,
    ) -> Result<Self> {
        Self::bind_listener(
            runtime,
            listener,
            edge.authority().into(),
            edge.origin.clone(),
            SignIn::Edge(verifier),
            concurrency,
            true,
        )
    }

    fn bind_development(
        runtime: Runtime,
        actor: &str,
        listener: TcpListener,
        authority: String,
        concurrency: usize,
        health_endpoints: bool,
    ) -> Result<Self> {
        runtime.artifact().require_current_api()?;
        let api = crate::openapi::Catalog::from_artifact(runtime.artifact().contract())?;
        // Authority lives in the database, so it has to exist before the actor
        // can be checked against it.
        runtime.initialize()?;
        ensure!(
            crate::web_api::session_allowed(&runtime, &api, actor),
            crate::error::Failure::Forbidden
        );
        let origin = format!("http://{authority}");
        let token = security::random()?;
        let mut server = Self::bind_listener(
            runtime,
            listener,
            authority,
            origin.clone(),
            SignIn::Link(Mutex::new(Some(Grant {
                hash: digest(token.as_bytes()),
                actor: actor.into(),
                expires: now()? + 600,
            }))),
            concurrency,
            health_endpoints,
        )?;
        server.login_url = format!("{origin}/login?token={token}");
        Ok(server)
    }

    fn bind_listener(
        runtime: Runtime,
        listener: TcpListener,
        authority: String,
        origin: String,
        sign_in: SignIn,
        concurrency: usize,
        health_endpoints: bool,
    ) -> Result<Self> {
        runtime.artifact().require_current_api()?;
        let api = crate::openapi::Catalog::from_artifact(runtime.artifact().contract())?;
        runtime.initialize()?;
        validate_ingress_credentials(&runtime)?;
        // `__Host-` makes the browser refuse the cookie unless it is Secure,
        // host-only and path `/`, so no sibling subdomain at the edge can set or
        // shadow it. Development is plain HTTP on loopback and cannot use it.
        let prefix = if matches!(sign_in, SignIn::Edge(_)) {
            "__Host-"
        } else {
            ""
        };
        let host = Arc::new(Host {
            oauth: None,
            credential_effects: crate::managed_credentials::effects::capture(),
            api,
            routes: (runtime.artifact().contract().format >= 7)
                .then(|| crate::routing::Catalog::from_artifact(runtime.artifact().contract()))
                .transpose()?,
            redirects: crate::redirects::Catalog::from_artifact(runtime.artifact().contract())?,
            appearance: Appearance::load(&runtime)?,
            secret: security::secret(&runtime)?,
            cookie_name: format!(
                "{prefix}day2_{}_{}",
                runtime.app(),
                &crate::assets::hash_part(&digest(runtime.scope().as_bytes()))?[..16]
            ),
            runtime,
            authority,
            origin: origin.clone(),
            sign_in,
            capacity: Arc::new(Semaphore::new(concurrency)),
            app_capacity: Arc::new(Semaphore::new(16)),
            app_issue_capacity: Arc::new(Semaphore::new(4)),
            app_execute_capacity: Arc::new(Semaphore::new(6)),
            app_reconcile_capacity: Arc::new(Semaphore::new(2)),
            queued: std::sync::atomic::AtomicUsize::new(0),
            live_capacity: Arc::new(Semaphore::new(64)),
            admitting: Arc::new(AtomicBool::new(true)),
            health_endpoints,
        });
        Ok(Self {
            listener,
            host,
            origin,
            login_url: String::new(),
        })
    }

    pub(crate) fn admission(&self) -> Admission {
        Admission(self.host.admitting.clone())
    }

    pub(crate) fn mount_oauth(
        &mut self,
        receiver: Arc<crate::oauth::shell_transport::AppApprovalReceiver>,
    ) -> Result<()> {
        ensure!(
            matches!(self.host.sign_in, SignIn::Edge(_)),
            "OAuth receiver requires the edge host"
        );
        receiver.require_host(self.host.runtime.app(), &self.host.authority)?;
        let host = Arc::get_mut(&mut self.host).context("OAuth must be mounted before serving")?;
        ensure!(host.oauth.is_none(), "OAuth receiver already mounted");
        host.oauth = Some(receiver);
        Ok(())
    }
    pub async fn serve(self, shutdown: impl Future<Output = ()> + Send + 'static) -> Result<()> {
        let runtime = self.host.runtime.clone();
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let commands = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(200));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = stopped.changed() => break,
                    _ = interval.tick() => {
                        let runtime = runtime.clone();
                        match tokio::task::spawn_blocking(move || crate::invocations::drain(&runtime, 8)).await {
                            Ok(Ok(_)) => {}
                            Ok(Err(error)) => eprintln!("command_scheduler_tick_failed {}", crate::error::diagnostic(&error)),
                            Err(_) => eprintln!("command_scheduler_task_failed"),
                        }
                    }
                }
            }
        });
        // Only applications that declare a schedule get an occurrence source.
        let declared = !self.host.runtime.artifact().contract().schedules.is_empty();
        let scheduled = declared.then(|| {
            let runtime = self.host.runtime.clone();
            let mut stopped = stop.subscribe();
            tokio::spawn(async move {
                // A refusal is a condition, not an event: an unbound schedule is
                // still unbound on the next tick. Report each one when it changes,
                // so a stuck schedule is visible without a line every ten seconds.
                let mut reported = crate::schedules::Refusals::default();
                let mut interval = tokio::time::interval(SCHEDULE_TICK);
                // A tick missed under load is skipped rather than replayed: the
                // occurrence it would have found is still derived from the clock on
                // the next one, so catching up here would only duplicate work.
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = stopped.changed() => break,
                        _ = interval.tick() => {
                            let runtime = runtime.clone();
                            let ticked = tokio::task::spawn_blocking(move || {
                                crate::schedules::tick(&runtime, now_ms()?)
                            })
                            .await;
                            match ticked {
                                Ok(Ok(ticks)) => {
                                    for tick in ticks {
                                        // A refusal is reported once, where it happens.
                                        // A schedule that silently does nothing cannot be
                                        // told from one that is working.
                                        if reported.should_report(
                                            &tick.schedule,
                                            tick.skipped.as_ref(),
                                        ) {
                                            eprintln!(
                                                "schedule_not_offered {} {:?}",
                                                tick.schedule,
                                                tick.skipped
                                            );
                                        }
                                        for (occurrence, outcome) in tick.offered {
                                            if outcome.status == "failure" {
                                                eprintln!(
                                                    "schedule_run_failed {} {occurrence} {}",
                                                    tick.schedule, outcome.error
                                                );
                                            }
                                        }
                                    }
                                }
                                Ok(Err(error)) => eprintln!(
                                    "schedule_source_tick_failed {}",
                                    crate::error::diagnostic(&error)
                                ),
                                Err(_) => eprintln!("schedule_source_task_failed"),
                            }
                        }
                    }
                }
            })
        });
        let journal = {
            let runtime = self.host.runtime.clone();
            let mut stopped = stop.subscribe();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(JOURNAL_TICK);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = stopped.changed() => break,
                        _ = interval.tick() => {
                            let runtime = runtime.clone();
                            let compacted = tokio::task::spawn_blocking(move || -> Result<()> {
                                for _ in 0..JOURNAL_BATCHES_PER_TICK {
                                    if crate::journal::compact(&runtime, now()?, JOURNAL_BATCH)? < JOURNAL_BATCH {
                                        break;
                                    }
                                }
                                Ok(())
                            })
                            .await;
                            match compacted {
                                Ok(Ok(())) => {}
                                Ok(Err(error)) => eprintln!(
                                    "journal_compaction_failed {}",
                                    crate::error::diagnostic(&error)
                                ),
                                Err(_) => eprintln!("journal_compaction_task_failed"),
                            }
                        }
                    }
                }
            })
        };
        let admitting = self.host.admitting.clone();
        let router = Router::new().fallback(handle).with_state(self.host);
        let result = axum::serve(self.listener, router)
            .with_graceful_shutdown(async move {
                shutdown.await;
                admitting.store(false, Ordering::Release);
            })
            .await;
        let _ = stop.send(true);
        commands.await?;
        journal.await?;
        if let Some(scheduled) = scheduled {
            scheduled.await?;
        }
        result?;
        Ok(())
    }
}

/// Longest a request waits for an execution permit before it is refused as busy.
const QUEUE_WAIT: Duration = Duration::from_secs(10);

/// Requests that may wait for a permit at once; beyond this, refuse immediately.
const MAX_QUEUED: usize = 256;

/// Wait in arrival order for an execution permit. Tokio's semaphore serves waiters
/// first come, first served, so a burst queues instead of being refused; only a
/// wait longer than `wait` or a line longer than [`MAX_QUEUED`] is busy.
async fn queued_permit(host: &Host, wait: Duration) -> Option<tokio::sync::OwnedSemaphorePermit> {
    struct Waiting<'a>(&'a std::sync::atomic::AtomicUsize);
    impl Drop for Waiting<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }
    if host.queued.fetch_add(1, Ordering::AcqRel) >= MAX_QUEUED {
        host.queued.fetch_sub(1, Ordering::AcqRel);
        return None;
    }
    let _waiting = Waiting(&host.queued);
    tokio::time::timeout(wait, host.capacity.clone().acquire_owned())
        .await
        .ok()?
        .ok()
}

/// Health answers `200 OK` with an empty body, not `204`: a Google Cloud load
/// balancer's HTTP health check counts only `200` as healthy, and every other
/// orchestrator probe accepts it too.
fn health_response(method: &Method, ready: bool) -> Response {
    let status = if !matches!(*method, Method::GET | Method::HEAD) {
        StatusCode::METHOD_NOT_ALLOWED
    } else if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    secure(status.into_response())
}

async fn handle(State(host): State<Arc<Host>>, request: Request) -> Response {
    host.credential_effects
        .clone()
        .run_async(handle_inner(host, request))
        .await
}

async fn handle_inner(host: Arc<Host>, request: Request) -> Response {
    if host.health_endpoints && matches!(request.uri().path(), "/health/live" | "/health/ready") {
        let ready =
            request.uri().path() == "/health/live" || host.admitting.load(Ordering::Acquire);
        return health_response(request.method(), ready);
    }
    if !host.admitting.load(Ordering::Acquire) {
        return secure(StatusCode::SERVICE_UNAVAILABLE.into_response());
    }
    if request.uri().path().starts_with("/_platform/app-") {
        return handle_app_call(host, request).await;
    }
    let json = crate::web_api::is_json(request.uri().path());
    let live_request = request.method() == Method::GET
        && request.uri().path() == "/_live"
        && request
            .headers()
            .get("datastar-request")
            .is_some_and(|value| value == "true");
    // Webhook providers abandon a delivery after a short deadline, so a delivery
    // queues for a permit only as long as it can still be answered in time.
    let wait = if request.method() == Method::POST
        && request
            .uri()
            .path()
            .starts_with(crate::ingress::ROUTE_PREFIX)
    {
        crate::ingress::ACCEPT_WAIT
    } else {
        QUEUE_WAIT
    };
    let permit = match host.capacity.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) if live_request => return secure(live::retry_response()),
        Err(_) => match queued_permit(&host, wait).await {
            Some(permit) => permit,
            None => {
                let mut response = transport_error(
                    json,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Server is busy. Retry this request.",
                );
                response.headers_mut().insert(
                    header::RETRY_AFTER,
                    axum::http::HeaderValue::from_static("1"),
                );
                return secure(response);
            }
        },
    };
    if request.uri().path().starts_with("/_day2/oauth/") {
        return match &host.oauth {
            Some(receiver) => {
                receiver
                    .clone()
                    .handle_admitted(request, Some(permit))
                    .await
            }
            None => secure(StatusCode::NOT_FOUND.into_response()),
        };
    }
    let (parts, body) = request.into_parts();
    let maximum_body = if parts.uri.path().starts_with(crate::ingress::ROUTE_PREFIX) {
        1_048_576
    } else {
        65_536
    };
    let body = match crate::managed_credentials::effects::timeout(
        Duration::from_secs(3),
        to_bytes(body, maximum_body),
    )
    .await
    {
        Ok(Ok(body)) => Ok(body),
        Ok(Err(_)) => Err(StatusCode::PAYLOAD_TOO_LARGE),
        Err(_) => Err(StatusCode::REQUEST_TIMEOUT),
    };
    let response = crate::managed_credentials::effects::spawn_blocking(move || {
        let _permit = permit;
        let at = if parts
            .uri
            .path()
            .starts_with(crate::managed_credentials::ingress::PREFIX)
        {
            crate::managed_credentials::effects::wall_time()?
        } else {
            now()?
        };
        let category = match parts.uri.path() {
            "/actions" => "command",
            "/login" => "sign_in",
            "/logout" => "sign_out",
            "/audit" | crate::openapi::AUDIT_PATH | crate::openapi::AUDIT_EVENTS_PATH => {
                "audit_read"
            }
            "/_live" => "live_read",
            path if path.starts_with(crate::ingress::ROUTE_PREFIX) => "ingress",
            path if path.starts_with("/assets/") => "asset",
            crate::mcp::PATH => "mcp",
            path if crate::web_api::is_json(path) => "api",
            "/docs" => "api_docs",
            _ => "page",
        };
        let admitted = host.admit(&parts.headers, parts.uri.path(), at);
        let (session, issued) = match &admitted {
            Ok((session, issued)) => (session.clone(), issued.clone()),
            Err(_) => (None, None),
        };
        // Record admission before running any business action. These events do
        // not contain query strings, request bodies, credentials or tickets.
        host.runtime.web_event(
            at,
            session.as_ref().map(|s| s.actor.as_str()),
            category,
            102,
        )?;
        let response = match (admitted, body) {
            (Err(error), _) => Ok(edge_refusal(json, &error)),
            (Ok(_), Ok(body)) => host.dispatch(
                &parts.method,
                &parts.uri,
                &parts.headers,
                &body,
                session.as_ref(),
                at,
            ),
            (Ok(_), Err(status)) => Ok(transport_error(
                json,
                status,
                "Request body exceeded its limit.",
            )),
        }
        .unwrap_or_else(|error| {
            if json {
                crate::web_api::failure(&error)
            } else {
                failure(&error)
            }
        });
        let mut response = response;
        if let Some(token) = issued {
            response
                .headers_mut()
                .append(header::SET_COOKIE, host.session_cookie(&token).parse()?);
        }
        host.runtime.web_event(
            at,
            session.as_ref().map(|s| s.actor.as_str()),
            category,
            response.status().as_u16(),
        )?;
        Ok::<_, anyhow::Error>(response)
    })
    .await;
    let response = match response {
        Ok(Ok(response)) => response,
        _ => transport_error(
            json,
            StatusCode::SERVICE_UNAVAILABLE,
            "Request could not be completed. Retry using the same form.",
        ),
    };
    secure(if live_request && response.status().is_server_error() {
        live::retry_response()
    } else {
        response
    })
}

async fn handle_app_call(host: Arc<Host>, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    if !matches!(
        path.as_str(),
        "/_platform/app-issue" | "/_platform/app-query"
    ) {
        return secure(StatusCode::NOT_FOUND.into_response());
    }
    if request.method() != Method::POST || request.uri().query().is_some() {
        return secure(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }
    let Some(port) = host.runtime.app_call_port().cloned() else {
        return secure(StatusCode::NOT_FOUND.into_response());
    };
    let mut assertions = request
        .headers()
        .get_all(crate::iap::ASSERTION_HEADER)
        .iter();
    let (Some(assertion), None) = (assertions.next(), assertions.next()) else {
        return secure(StatusCode::UNAUTHORIZED.into_response());
    };
    let Some(assertion) = assertion
        .to_str()
        .ok()
        .filter(|assertion| assertion.len() <= 16_384)
        .map(str::to_owned)
    else {
        return secure(StatusCode::UNAUTHORIZED.into_response());
    };
    let Ok(permit) = host.app_capacity.clone().try_acquire_owned() else {
        return secure(StatusCode::SERVICE_UNAVAILABLE.into_response());
    };
    let maximum = if path == "/_platform/app-issue" {
        300_000
    } else {
        200_000
    };
    let body = match tokio::time::timeout(
        Duration::from_secs(3),
        to_bytes(request.into_body(), maximum),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => return secure(StatusCode::PAYLOAD_TOO_LARGE.into_response()),
        Err(_) => return secure(StatusCode::REQUEST_TIMEOUT.into_response()),
    };
    drop(permit);
    let capacity = if path == "/_platform/app-issue" {
        &host.app_issue_capacity
    } else if crate::delegation_wire::claimed_purpose(&body)
        .is_ok_and(|purpose| purpose == crate::delegation::Purpose::Status)
    {
        &host.app_reconcile_capacity
    } else {
        &host.app_execute_capacity
    };
    let Ok(permit) = capacity.clone().try_acquire_owned() else {
        return secure(StatusCode::SERVICE_UNAVAILABLE.into_response());
    };
    match tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let _permit = permit;
        let at = now()?;
        host.runtime.web_event(at, None, "app_call", 102)?;
        let result = port.receive(&host.runtime, &path, &body, &assertion, at);
        host.runtime
            .web_event(at, None, "app_call", if result.is_ok() { 200 } else { 403 })?;
        result
    })
    .await
    {
        Ok(Ok(body)) => {
            secure(([(header::CONTENT_TYPE, "application/json")], body).into_response())
        }
        _ => secure((StatusCode::FORBIDDEN, "{\"error\":\"app_call_refused\"}").into_response()),
    }
}
impl Host {
    /// Who a request is from, before anything else looks at it.
    ///
    /// Development reads the session cookie the sign-in link set. At the edge
    /// the assertion is required on every request and decides who it is from;
    /// a request without a valid one is refused here, before dispatch, so no
    /// route can forget to ask. The one exception is inbound deliveries, which
    /// are from a provider rather than a person and are established by their
    /// own signature.
    ///
    /// The second value is a freshly issued session token, when the request
    /// arrived without a session for the person its assertion names.
    fn admit(
        &self,
        headers: &HeaderMap,
        path: &str,
        at: i64,
    ) -> Result<(Option<Session>, Option<String>)> {
        let cookie = || security::session(&self.runtime, headers, &self.cookie_name, at).ok();
        let SignIn::Edge(verifier) = &self.sign_in else {
            return Ok((cookie(), None));
        };
        if path.starts_with(crate::ingress::ROUTE_PREFIX) {
            return Ok((None, None));
        }
        if path.starts_with(crate::managed_credentials::ingress::PREFIX) {
            return Ok((None, None));
        }
        let mut assertions = headers.get_all(crate::iap::ASSERTION_HEADER).iter();
        let (Some(assertion), None) = (assertions.next(), assertions.next()) else {
            anyhow::bail!(crate::error::Failure::InvalidIdentityAssertion);
        };
        let verified = verifier.verify(
            assertion
                .to_str()
                .map_err(|_| crate::error::Failure::InvalidIdentityAssertion)?,
            at,
        )?;
        let db = open(self.runtime.db())?;
        self.runtime.check_binding(&db)?;
        crate::iap::bind_subject(&db, &verified, at)?;
        ensure!(
            crate::web_api::session_allowed(&self.runtime, &self.api, &verified.email),
            crate::error::Failure::Forbidden
        );
        // A cookie left by someone else — a shared browser, a changed Google
        // sign-in — is not this person's session, whatever it says.
        if let Some(mut session) = cookie().filter(|session| session.actor == verified.email) {
            session.origin = Some(verified);
            return Ok((Some(session), None));
        }
        let token = security::create_session(&self.runtime, &verified.email, at)?;
        let mut session = security::session_for_token(&self.runtime, &token, at)?;
        session.origin = Some(verified);
        Ok((Some(session), Some(token)))
    }

    fn session_cookie(&self, token: &str) -> String {
        let secure = if matches!(self.sign_in, SignIn::Edge(_)) {
            "; Secure"
        } else {
            ""
        };
        format!(
            "{}={token}; Path=/; HttpOnly{secure}; SameSite=Strict; Max-Age=28800",
            self.cookie_name
        )
    }

    fn dispatch(
        self: &Arc<Self>,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: &[u8],
        session: Option<&Session>,
        at: i64,
    ) -> Result<Response> {
        ensure!(
            headers.get_all(header::HOST).iter().count() == 1
                && headers.get(header::HOST).and_then(|v| v.to_str().ok()) == Some(&self.authority),
            crate::error::Failure::InvalidHost
        );
        ensure!(
            uri.to_string().len() <= 8192,
            crate::error::Failure::UriBudget
        );
        ensure!(
            !headers.contains_key("x-http-method-override"),
            crate::error::Failure::UnsupportedMethod
        );
        self.appearance.check_binding(&self.runtime)?;
        if uri
            .path()
            .starts_with(crate::managed_credentials::ingress::PREFIX)
        {
            return crate::managed_credentials::ingress::dispatch(
                &self.runtime,
                &self.api,
                method,
                uri,
                headers,
                body,
                at,
            );
        }
        // A provider delivery carries no browser origin, form encoding or
        // session: what establishes it is the signature over these exact bytes,
        // so it is dispatched before the browser guards and the session check.
        if method == Method::POST && uri.path().starts_with(crate::ingress::ROUTE_PREFIX) {
            ensure!(uri.query().is_none(), crate::error::Failure::UnknownFields);
            return self.delivery(
                &uri.path()[crate::ingress::ROUTE_PREFIX.len()..],
                headers,
                body,
                at,
            );
        }
        if headers.contains_key(crate::web_api::ACT_AS_HEADER) {
            ensure!(
                self.api
                    .endpoints
                    .values()
                    .any(|endpoint| endpoint.path() == uri.path())
                    || uri.path().starts_with("/api/invocations/"),
                crate::error::Failure::InvalidInput
            );
        }
        // Platform routes are dispatched before app pages and the Datastar form transport.
        if crate::web_api::is_json(uri.path()) || uri.path() == crate::openapi::DOCS_PATH {
            let session = session.context(crate::error::Failure::SignInRequired)?;
            ensure!(
                crate::web_api::session_allowed(&self.runtime, &self.api, &session.actor),
                crate::error::Failure::Forbidden
            );
            if uri.path() == crate::mcp::PATH {
                return crate::mcp::dispatch(
                    &crate::web_api::RequestContext {
                        runtime: &self.runtime,
                        catalog: &self.api,
                        secret: &self.secret,
                        session,
                        origin: &self.origin,
                        at,
                    },
                    method,
                    uri,
                    headers,
                    body,
                );
            }
            if matches!(
                uri.path(),
                crate::openapi::AUDIT_PATH | crate::openapi::AUDIT_EVENTS_PATH
            ) {
                self.runtime.authorize_audit(&session.actor)?;
                if method != Method::GET {
                    let mut response = crate::web_api::error(
                        StatusCode::METHOD_NOT_ALLOWED,
                        "unsupported_method",
                        "This endpoint requires GET.",
                    );
                    response.headers_mut().insert(header::ALLOW, "GET".parse()?);
                    return Ok(response);
                }
                ensure!(body.is_empty(), crate::error::Failure::InvalidInput);
                let events = uri.path() == crate::openapi::AUDIT_EVENTS_PATH;
                let request =
                    crate::audit::PageRequest::from_query(uri.query().unwrap_or(""), events)?;
                let page = if events {
                    serde_json::to_value(self.runtime.audit_event_page(&session.actor, &request)?)?
                } else {
                    serde_json::to_value(self.runtime.audit_page(&session.actor, &request)?)?
                };
                return Ok(crate::web_api::json_response(StatusCode::OK, page));
            }
            if matches!(
                uri.path(),
                crate::openapi::SPEC_PATH
                    | crate::openapi::DOCS_PATH
                    | crate::openapi::SESSION_PATH
            ) {
                if method != Method::GET {
                    let mut response = crate::web_api::error(
                        StatusCode::METHOD_NOT_ALLOWED,
                        "unsupported_method",
                        "This endpoint requires GET.",
                    );
                    response.headers_mut().insert(header::ALLOW, "GET".parse()?);
                    return Ok(response);
                }
                ensure!(
                    body.is_empty() && uri.query().is_none(),
                    crate::error::Failure::InvalidInput
                );
                if uri.path() == crate::openapi::SESSION_PATH {
                    return Ok(crate::web_api::json_response(
                        StatusCode::OK,
                        serde_json::json!({
                            "actor":session.actor,"csrf_token":security::csrf(&self.secret, session)?
                        }),
                    ));
                }
                let spec = self.api.document(
                    self.runtime.artifact().contract(),
                    self.runtime.app(),
                    self.runtime.artifact().id(),
                    &self.cookie_name,
                    &self.origin,
                );
                if uri.path() == crate::openapi::SPEC_PATH {
                    return Ok(crate::web_api::json_response(StatusCode::OK, spec));
                }
                let mut response = html_response(
                    StatusCode::OK,
                    crate::web_api::docs(&spec, &self.origin, Some(&session.actor))?,
                );
                response.headers_mut().insert("content-security-policy", format!(
                    "default-src 'none'; script-src {}/assets/platform/api-docs.js; style-src {}/assets/platform/api-docs.css; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'", self.origin, self.origin).parse()?);
                return Ok(response);
            }
            return crate::web_api::RequestContext {
                runtime: &self.runtime,
                catalog: &self.api,
                secret: &self.secret,
                session,
                origin: &self.origin,
                at,
            }
            .dispatch(method, uri, headers, body);
        }
        if method == Method::POST {
            ensure!(
                headers.get_all(header::ORIGIN).iter().count() == 1
                    && headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
                        == Some(&self.origin),
                crate::error::Failure::InvalidOrigin
            );
            ensure!(
                headers
                    .get("sec-fetch-site")
                    .is_none_or(|v| v == "same-origin"),
                crate::error::Failure::InvalidOrigin
            );
            ensure!(
                headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(
                        |v| v.split(';').next() == Some("application/x-www-form-urlencoded")
                    ),
                crate::error::Failure::UnsupportedContentType
            );
        } else {
            ensure!(
                (method == Method::GET
                    || (method == Method::HEAD && uri.path().starts_with("/assets/")))
                    && body.is_empty(),
                crate::error::Failure::UnsupportedMethod
            );
        }
        if matches!(*method, Method::GET | Method::HEAD) && uri.path().starts_with("/assets/") {
            let mut response =
                self.appearance
                    .serve(&self.runtime, uri.path(), session, headers)?;
            if method == Method::HEAD {
                *response.body_mut() = Body::empty();
            }
            return Ok(response);
        }
        if uri.path() == "/login" {
            // Signing in happened at the identity provider, before this request.
            if matches!(self.sign_in, SignIn::Edge(_)) {
                return Ok(error_page(StatusCode::NOT_FOUND, "Page not found."));
            }
            if method == Method::GET && session.is_some() {
                return redirect("/");
            }
            return self.login(method, uri, body, at);
        }
        let session = match session {
            Some(session) => session,
            None => {
                return Ok(error_page(
                    StatusCode::UNAUTHORIZED,
                    "Sign in using the local sign-in link printed by the server.",
                ));
            }
        };
        if uri.path() == "/_live" {
            ensure!(
                method == Method::GET,
                crate::error::Failure::UnsupportedMethod
            );
            return self.live_response(uri, headers, session, at);
        }
        match (method.as_str(), uri.path()) {
            ("GET", "/") if self.runtime.artifact().contract().pages.is_empty() => {
                redirect(crate::openapi::DOCS_PATH)
            }
            ("GET", "/") if self.routes.is_none() => {
                let page = self
                    .runtime
                    .artifact()
                    .contract()
                    .pages
                    .iter()
                    .find(|page| {
                        self.runtime
                            .authorize(&page.operation, &session.actor)
                            .is_ok()
                    })
                    .context(crate::error::Failure::Forbidden)?;
                redirect(&format!("/pages/{}", page.name))
            }
            ("GET", path) if self.routes.is_none() && path.starts_with("/pages/") => {
                let name = &path[7..];
                let input = self.page_input(name, uri.query().unwrap_or(""))?;
                let content = self.page(name, &input, session, at, None, None)?;
                self.app_response(StatusCode::OK, name, &input, session, content)
            }
            ("POST", "/actions") => {
                ensure!(uri.query().is_none(), crate::error::Failure::UnknownFields);
                self.action(headers, body, session, at)
            }
            ("POST", "/logout") => {
                ensure!(uri.query().is_none(), crate::error::Failure::UnknownFields);
                let mut fields = security::fields(body)?;
                security::verify_csrf(
                    &self.secret,
                    session,
                    &fields
                        .remove("_csrf")
                        .context(crate::error::Failure::InvalidCsrf)?,
                )?;
                ensure!(fields.is_empty(), crate::error::Failure::UnknownFields);
                open(self.runtime.db())?.execute(
                    "DELETE FROM day2_web_sessions WHERE hash=?1",
                    [&session.hash],
                )?;
                // At the edge the person is signed in to the identity
                // provider, not to this app; dropping our session alone would
                // sign them straight back in. IAP clears its own sign-in when
                // asked for this path.
                let mut response = if matches!(self.sign_in, SignIn::Edge(_)) {
                    redirect("/?gcp-iap-mode=CLEAR_LOGIN_COOKIE")?
                } else {
                    error_page(StatusCode::OK, "Signed out.")
                };
                response.headers_mut().insert(
                    header::SET_COOKIE,
                    self.session_cookie("")
                        .replace("Max-Age=28800", "Max-Age=0")
                        .parse()?,
                );
                Ok(response)
            }
            ("GET", "/audit") => self.audit(uri.query().unwrap_or(""), session),
            ("GET", path) if self.routes.is_some() => {
                let route = self
                    .routes
                    .as_ref()
                    .context("route catalog missing")?
                    .resolve(path, uri.query().unwrap_or(""));
                let invalid = || {
                    error_page(
                        StatusCode::BAD_REQUEST,
                        "The route contains invalid or unexpected fields.",
                    )
                };
                // Page routes take precedence. A redirect route answers only a
                // path no page route claims, even one a page route would refuse.
                match route {
                    Ok(Some((name, input))) => {
                        let content = self.page(&name, &input, session, at, None, None)?;
                        self.app_response(StatusCode::OK, &name, &input, session, content)
                    }
                    Ok(None) => self.redirect_route(
                        path,
                        headers,
                        session,
                        at,
                        error_page(StatusCode::NOT_FOUND, "Page not found."),
                    ),
                    Err(_)
                        if !self
                            .routes
                            .as_ref()
                            .context("route catalog missing")?
                            .claims(path) =>
                    {
                        self.redirect_route(path, headers, session, at, invalid())
                    }
                    Err(_) => Ok(invalid()),
                }
            }
            _ => Ok(error_page(StatusCode::NOT_FOUND, "Page not found.")),
        }
    }
    /// Accept one inbound delivery.
    ///
    /// The order here is the property the hold gate establishes, so it is written
    /// out rather than left to the reader: the endpoint must be declared, bound and
    /// enabled, and the signature must verify over the bytes as received, before
    /// anything reaches the runtime. A refused delivery leaves no invocation.
    ///
    /// A provider is told only whether its delivery was accepted. Every refusal is
    /// the same status and the same empty body: distinguishing "unknown endpoint"
    /// from "bad signature" would answer questions an attacker is asking.
    fn delivery(&self, name: &str, headers: &HeaderMap, body: &[u8], at: i64) -> Result<Response> {
        let refused = || -> Result<Response> {
            Ok(transport_error(
                true,
                StatusCode::UNAUTHORIZED,
                "ingress_refused",
            ))
        };
        let contract = self.runtime.artifact().contract();
        let Some(endpoint) = contract
            .ingress
            .iter()
            .find(|endpoint| endpoint.name == name)
        else {
            return refused();
        };
        let instance = crate::artifact::Instance::load(self.runtime.instance_path())?;
        let Some(binding) = instance
            .apps
            .get(self.runtime.app())
            .and_then(|app| app.ingress.get(name))
            .filter(|binding| !binding.disabled)
        else {
            return refused();
        };
        let Some(connection) = instance
            .resources
            .as_ref()
            .and_then(|catalog| catalog.connections.get(&binding.connection.id))
            .filter(|definition| definition.revision == binding.connection.revision)
            .and_then(|definition| definition.live.clone())
        else {
            return refused();
        };
        if crate::ingress::validate_connection(&endpoint.provider, &connection).is_err() {
            return refused();
        }
        let mounts =
            crate::integration_host::MountedCredentials::new(self.runtime.instance_path())?;
        let Ok(key) = mounts.verification_key(&connection) else {
            return refused();
        };
        // Lowercased once, because a provider identifying a delivery by header
        // must find it regardless of the casing the wire used.
        let received: BTreeMap<String, String> = headers
            .iter()
            .filter_map(|(name, value)| {
                Some((
                    name.as_str().to_ascii_lowercase(),
                    value.to_str().ok()?.to_owned(),
                ))
            })
            .collect();
        let admitted = crate::ingress::admit(
            &self.runtime,
            &crate::ingress::Endpoint {
                app: self.runtime.app().to_owned(),
                name: endpoint.name.clone(),
                operation: endpoint.operation.clone(),
                provider_identity: crate::ingress::identity_source(&endpoint.provider)?,
                signing: crate::ingress::signing(&endpoint.provider)?,
                input: crate::ingress::Input::for_provider(&endpoint.provider)?,
            },
            &crate::ingress::Binding {
                actor: &binding.actor,
                secret: key.as_hmac_key(),
            },
            &crate::ingress::Delivery {
                body,
                headers: &received,
            },
            at,
        );
        match admitted {
            Ok(_) => Ok(transport_error(true, StatusCode::OK, "")),
            Err(crate::ingress::Refused::Busy) => {
                let mut response = transport_error(
                    true,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Server is busy. Retry this request.",
                );
                response.headers_mut().insert(
                    header::RETRY_AFTER,
                    axum::http::HeaderValue::from_static("1"),
                );
                Ok(response)
            }
            Err(_) => refused(),
        }
    }

    /// Run a declared redirect route's command and answer with its destination.
    ///
    /// The person was admitted as for any page; the command runs through the
    /// ordinary invocation path, so its authority, input validation and mandatory
    /// audit are the command's own. Each followed link is a new invocation, as
    /// each followed link is a new visit. `unmatched` is the answer when no
    /// redirect route claims the path either.
    fn redirect_route(
        &self,
        path: &str,
        headers: &HeaderMap,
        session: &Session,
        at: i64,
        unmatched: Response,
    ) -> Result<Response> {
        use crate::redirects::{Match, Refusal};
        let (route, input) = match self.redirects.resolve(path) {
            Match::None => return Ok(unmatched),
            Match::Invalid => {
                return Ok(error_page(
                    StatusCode::BAD_REQUEST,
                    "This address is not a valid link.",
                ));
            }
            Match::Route(route, input) => (route, input),
        };
        match crate::redirects::refusal(headers) {
            // Declining a prefetch lets the browser fetch again when, and only
            // when, the person follows the link.
            Some(Refusal::Prefetch) => {
                return Ok(error_page(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Links are resolved only when they are followed.",
                ));
            }
            Some(Refusal::NotNavigation) => {
                return Ok(error_page(
                    StatusCode::FORBIDDEN,
                    "Links open only as a page you navigate to.",
                ));
            }
            None => {}
        }
        let id = format!("redirect-{}", security::random()?);
        let outcome = self.runtime.invoke_verified(
            &route.operation,
            crate::store::RequestIdentity {
                actor: &session.actor,
                origin: session.origin.as_ref(),
            },
            &id,
            &input,
            at,
            Fault::None,
        )?;
        let mut response = if outcome.status == "success" {
            match route.location(&outcome.result) {
                Ok(location) => {
                    let mut response = StatusCode::FOUND.into_response();
                    response
                        .headers_mut()
                        .insert(header::LOCATION, location.parse()?);
                    response
                }
                Err(error) => {
                    // The command committed; only the destination was refused.
                    eprintln!(
                        "redirect_location_refused {} {}",
                        route.name,
                        crate::error::diagnostic(&error)
                    );
                    error_page(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "This link's destination is not an address that can be opened.",
                    )
                }
            }
        } else if outcome.status == "pending" {
            error_page(
                StatusCode::ACCEPTED,
                "This link is still being resolved. Follow it again shortly.",
            )
        } else {
            let (status, _, message) =
                crate::web_api::outcome_failure(&self.runtime, &outcome.error);
            if route.not_found(&outcome.error) {
                if let Some(page) = &route.not_found_page {
                    self.page(page, &input, session, at, None, None)
                        .and_then(|content| {
                            self.app_response(StatusCode::NOT_FOUND, page, &input, session, content)
                        })
                        .unwrap_or_else(|error| failure(&error))
                } else {
                    error_page(StatusCode::NOT_FOUND, &message)
                }
            } else {
                error_page(status, &message)
            }
        };
        response
            .headers_mut()
            .insert("x-day2-invocation", id.parse()?);
        Ok(response)
    }

    fn login(&self, method: &Method, uri: &Uri, body: &[u8], at: i64) -> Result<Response> {
        ensure!(
            method != Method::POST || uri.query().is_none(),
            crate::error::Failure::UnknownFields
        );
        let mut fields = security::fields(if method == Method::POST {
            body
        } else {
            uri.query().unwrap_or("").as_bytes()
        })?;
        let token = fields
            .remove("token")
            .context(crate::error::Failure::InvalidLoginLink)?;
        ensure!(
            fields.is_empty() && token.len() == 43,
            crate::error::Failure::InvalidLoginLink
        );
        let SignIn::Link(grant) = &self.sign_in else {
            anyhow::bail!(crate::error::Failure::InvalidLoginLink);
        };
        let mut grant = grant
            .lock()
            .map_err(|_| anyhow::anyhow!("login_unavailable"))?;
        let current = grant
            .as_ref()
            .context(crate::error::Failure::InvalidLoginLink)?;
        ensure!(
            current.hash == digest(token.as_bytes()) && at < current.expires,
            crate::error::Failure::InvalidLoginLink
        );
        ensure!(
            crate::web_api::session_allowed(&self.runtime, &self.api, &current.actor),
            crate::error::Failure::Forbidden
        );
        if method == Method::GET {
            return Ok(html_response(
                StatusCode::OK,
                document(
                    "Sign in",
                    Some(&self.appearance),
                    html! {
                        main.login { div.stack { (view::brand(&self.appearance)?) h1 { "Local workspace" }
                            p.muted { (self.runtime.scope()) }
                            form method="post" action="/login" { input type="hidden" name="token" value=(token); button.primary type="submit" { (icon("shield-check")) "Continue as " (&current.actor) } }
                        } }
                    },
                )?,
            ));
        }
        let token = security::create_session(&self.runtime, &current.actor, at)?;
        *grant = None;
        let mut response = redirect("/")?;
        response
            .headers_mut()
            .insert(header::SET_COOKIE, self.session_cookie(&token).parse()?);
        Ok(response)
    }
    fn page_input(&self, name: &str, raw: &str) -> Result<Value> {
        let page = self.runtime.artifact().page(name)?;
        let record = &self.runtime.artifact().contract().schema.inputs[&self
            .runtime
            .artifact()
            .operation(&page.operation)?
            .input_type];
        let mut input: Value = serde_json::from_str(&page.defaults)?;
        for (name, value) in security::fields(raw.as_bytes())? {
            input[&name] = security::field_value(
                record
                    .fields
                    .get(&name)
                    .context(crate::error::Failure::UnknownFields)?,
                &value,
            )?;
        }
        record.validate_input(&input)?;
        Ok(input)
    }
    fn app_response(
        &self,
        status: StatusCode,
        name: &str,
        input: &Value,
        session: &Session,
        content: Markup,
    ) -> Result<Response> {
        let title = &self.runtime.artifact().page(name)?.title;
        if self.runtime.artifact().contract().format < 5 {
            return Ok(html_response(
                status,
                document(
                    title,
                    Some(&self.appearance),
                    view::shell(
                        &self.runtime,
                        &self.appearance,
                        session,
                        &self.secret,
                        name,
                        content,
                    )?,
                )?,
            ));
        }
        let stylesheet = self.appearance.stylesheet_url(&self.runtime)?;
        let script = self.appearance.script_url(&self.runtime)?;
        let theme = self.appearance.theme_url()?;
        let live = self.live_initializer(name, input)?;
        let mut response = html_response(
            status,
            html! {
                (maud::DOCTYPE) html lang="en" {
                    head {
                        meta charset="utf-8";
                        meta name="viewport" content="width=device-width, initial-scale=1";
                        title { (title) " | " (self.appearance.name()) }
                        @if let Some(theme) = theme { link rel="stylesheet" href=(theme); }
                        @if let Some(stylesheet) = stylesheet { link rel="stylesheet" href=(stylesheet); }
                        script type="module" src="/assets/platform/datastar-1.0.1.js" {}
                        script type="module" src="/assets/platform/forms.js" {}
                        @if let Some(script) = script { script type="module" src=(script) {} }
                    }
                    body { (live) (content) }
                }
            },
        );
        // App modules have ordinary browser authority. This policy governs loaded
        // resources, not the behavior of admitted JavaScript or Datastar expressions.
        response.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            format!(
                "default-src 'none'; script-src 'unsafe-eval' {}/assets/platform/datastar-1.0.1.js {}/assets/platform/forms.js {}{}; script-src-attr 'none'; style-src 'self' 'unsafe-inline'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; worker-src 'none'",
                self.origin, self.origin, self.origin, self.appearance.resource_prefix()
            ).parse()?,
        );
        Ok(response)
    }
    fn page(
        &self,
        name: &str,
        input: &Value,
        session: &Session,
        at: i64,
        notice: Option<Notice<'_>>,
        submitted: Option<view::Submitted<'_>>,
    ) -> Result<Markup> {
        // A completion can invalidate a prepared read between its observation
        // and validation. Retry only the page query with a fresh invocation;
        // the command and its durable receipt are never repeated here.
        let outcome = fresh_page_query(|id| {
            self.runtime
                .render_page(name, &session.actor, id, input, at)
        })?;
        if outcome.status != "success" {
            anyhow::bail!(match outcome.error.as_str() {
                "not_found" => crate::error::Failure::UnknownPage,
                "invalid_input" | "invalid_page_bounds" => crate::error::Failure::InvalidPageInput,
                "forbidden" => crate::error::Failure::Forbidden,
                "preparation_conflict" => crate::error::Failure::PreparationConflict,
                _ => crate::error::Failure::Internal,
            });
        }
        let renderer = view::View {
            runtime: &self.runtime,
            appearance: &self.appearance,
            secret: &self.secret,
            session,
            page: name,
            input,
            now: at,
            submitted,
        };
        let page = self.runtime.artifact().page(name)?;
        let content = if page.template.is_empty() {
            renderer.render(&outcome.result)?
        } else {
            self.runtime.artifact().contract().outputs[&page.output_type]
                .shape
                .validate_value(&outcome.result)?;
            let context = serde_json::json!({
                name: &outcome.result,
                "company": { "name": self.appearance.name() },
            });
            let asset_urls = self
                .runtime
                .artifact()
                .contract()
                .assets
                .keys()
                .map(|key| Ok((key.clone(), self.appearance.app_url(&self.runtime, key)?)))
                .collect::<Result<BTreeMap<_, _>>>()?;
            let markup = if let Some(routes) = &self.routes {
                crate::web_templates::render_routed(
                    self.runtime.artifact().directory(),
                    &self.runtime.artifact().contract().templates,
                    &page.template,
                    context,
                    asset_urls,
                    routes,
                    &self.origin,
                )?
            } else {
                crate::web_templates::render(
                    self.runtime.artifact().directory(),
                    &self.runtime.artifact().contract().templates,
                    &page.template,
                    context,
                    asset_urls,
                )?
            };
            crate::web_forms::bind(&renderer, &markup)?
        };
        Ok(html! { main id="day2-main"
            data-day2-invocation=[notice.as_ref().map(|value| value.invocation)]
            data-day2-operation=[notice.as_ref().map(|value| value.operation)]
            data-day2-status=[notice.as_ref().map(|value| if value.error { "failure" } else { "success" })] {
            div id="day2-command-status" {
                @if let Some(value) = notice { div class=(if value.error { "notice error" } else { "notice" }) role="status" { (value.message) } }
            }
            (content)
        } })
    }
    fn action(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        session: &Session,
        at: i64,
    ) -> Result<Response> {
        // The declared input record decides which fields may repeat, but it is
        // reached through the ticket inside this body. Both control fields are
        // therefore read first with an exact single-value requirement, so no
        // repeated `_csrf` or `_ticket` can ever reach verification.
        security::verify_csrf(
            &self.secret,
            session,
            &security::single_field(body, "_csrf").context(crate::error::Failure::InvalidCsrf)?,
        )?;
        let ticket: Ticket = serde_json::from_slice(&security::verify(
            &self.secret,
            &security::single_field(body, "_ticket")
                .context(crate::error::Failure::InvalidTicket)?,
        )?)?;
        ticket.verify(&self.runtime, session, at)?;
        let record = &self.runtime.artifact().contract().schema.inputs[&self
            .runtime
            .artifact()
            .operation(&ticket.operation)?
            .input_type];
        // Lists and sets repeat their field name; a map repeats only through distinct
        // `field.key` control names, so its base name is never itself repeated.
        let repeatable: std::collections::BTreeSet<String> = record
            .fields
            .iter()
            .filter(|(_, kind)| {
                matches!(
                    crate::web_forms::carrier(kind),
                    crate::web_forms::Carrier::List | crate::web_forms::Carrier::Set
                )
            })
            .map(|(name, _)| name.clone())
            .collect();
        let submitted = security::list_fields(body, &repeatable)?;
        // Group `field.key` controls under their declared field before decoding.
        let mut fields: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut keyed: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
        for (name, values) in submitted {
            if name == "_csrf" || name == "_ticket" {
                continue;
            }
            match crate::web_forms::split_control(&name) {
                (field, Some(key)) => {
                    keyed
                        .entry(field.to_owned())
                        .or_default()
                        .insert(key.to_owned(), values);
                }
                (field, None) => {
                    fields.insert(field.to_owned(), values);
                }
            }
        }
        let names: std::collections::BTreeSet<&str> = fields
            .keys()
            .chain(keyed.keys())
            .map(String::as_str)
            .collect();
        ensure!(
            names.len() == ticket.editable.len()
                && ticket
                    .editable
                    .iter()
                    .all(|name| names.contains(name.as_str())),
            crate::error::Failure::UnknownFields
        );
        let mut input = ticket.bound.clone();
        let validation: Result<()> = (|| {
            for (name, value) in &fields {
                ensure!(input.get(name).is_none(), "bound_field_override");
                input[name] = security::field_values(
                    record
                        .fields
                        .get(name)
                        .context(crate::error::Failure::UnknownFields)?,
                    value,
                )?;
            }
            for (name, entries) in &keyed {
                ensure!(input.get(name).is_none(), "bound_field_override");
                ensure!(
                    record
                        .fields
                        .get(name)
                        .is_some_and(|kind| crate::web_forms::carrier(kind)
                            == crate::web_forms::Carrier::Map),
                    crate::error::Failure::UnknownFields
                );
                input[name] = security::map_values(entries)?;
            }
            record.validate_input(&input)
        })();
        let id = format!("web-{}", ticket.nonce);
        if validation.is_ok()
            && crate::managed_credentials::issuance::access(&self.runtime, &ticket.operation)?
                .interactive
        {
            let location = crate::managed_credentials::browser::start(
                &self.runtime,
                &ticket.operation,
                &session.actor,
                &id,
                &input,
                Some(&ticket.page),
                at,
            )?;
            return Ok((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response());
        }
        let (status, message) = if validation.is_err() {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Check the values and try again.",
            )
        } else {
            let outcome = self.runtime.invoke_verified(
                &ticket.operation,
                crate::store::RequestIdentity {
                    actor: &session.actor,
                    origin: session.origin.as_ref(),
                },
                &id,
                &input,
                at,
                Fault::None,
            )?;
            if outcome.status == "success" {
                (StatusCode::OK, "Saved.")
            } else if outcome.status == "pending" {
                // A pending outcome is durable acceptance, not rejection: the
                // protocol requires an empty error for it. Reporting it as
                // rejected invited a retry that produced a second durable
                // invocation, so accepted work is acknowledged here and resolved
                // by its receipt or a live region.
                (
                    StatusCode::ACCEPTED,
                    "Accepted. This is still finishing; it will appear when it completes.",
                )
            } else if outcome.error == "forbidden" {
                (
                    StatusCode::FORBIDDEN,
                    "You do not have permission to make this change.",
                )
            } else if outcome.error == "conflict" {
                (
                    StatusCode::CONFLICT,
                    if self.runtime.artifact().page(&ticket.page)?.live {
                        "This record has changed. Your draft is preserved. Reload the document before trying again."
                    } else {
                        "This record has changed. The latest version is shown below."
                    },
                )
            } else {
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "The command was rejected. Check the values and try again.",
                )
            }
        };
        let datastar = headers
            .get("datastar-request")
            .is_some_and(|value| value == "true");
        let accepted = matches!(status, StatusCode::OK | StatusCode::ACCEPTED);
        let mut response = if accepted && !datastar {
            redirect(&view::page_url(
                &self.runtime,
                &ticket.page,
                &ticket.page_input,
            )?)?
        } else {
            // A rendering failure after commit is ambiguous only to the browser.
            // The unchanged signed ticket always identifies the durable receipt.
            let content = self.page(
                &ticket.page,
                &ticket.page_input,
                session,
                at,
                Some(Notice {
                    message,
                    error: !accepted,
                    invocation: &id,
                    operation: &ticket.operation,
                }),
                (!accepted).then_some(view::Submitted {
                    operation: &ticket.operation,
                    bound: &ticket.bound,
                    fields: &fields,
                }),
            )?;
            if datastar {
                if self.runtime.artifact().page(&ticket.page)?.live {
                    live::command_patch(content, &ticket, status, &id)?
                } else {
                    patch(content)
                }
            } else {
                self.app_response(status, &ticket.page, &ticket.page_input, session, content)?
            }
        };
        response
            .headers_mut()
            .insert("x-day2-invocation", id.parse()?);
        response
            .headers_mut()
            .insert("x-day2-command-status", status.as_str().parse()?);
        Ok(response)
    }
    fn audit(&self, raw: &str, session: &Session) -> Result<Response> {
        self.runtime.authorize_audit(&session.actor)?;
        let mut fields = security::fields(raw.as_bytes())?;
        let before = fields
            .remove("before")
            .map(|value| value.parse::<i64>())
            .transpose()?
            .unwrap_or(0);
        let optional = |fields: &mut BTreeMap<String, String>, key: &str| {
            fields.remove(key).filter(|v| !v.is_empty())
        };
        let filter = Filter {
            before,
            actor: optional(&mut fields, "actor"),
            operation: optional(&mut fields, "operation"),
            status: optional(&mut fields, "status"),
        };
        ensure!(fields.is_empty(), crate::error::Failure::UnknownFields);
        if let Some(status) = &filter.status {
            ensure!(
                ["success", "failure"].contains(&status.as_str()),
                "invalid_filter"
            );
        }
        let mut entries = self.runtime.audit_entries(&session.actor, &filter)?;
        let more = entries.len() > 50;
        entries.truncate(50);
        let mut next = url::form_urlencoded::Serializer::new(String::new());
        if let Some(entry) = entries.last() {
            next.append_pair("before", &entry.sequence.to_string());
        }
        for (name, value) in [
            ("actor", &filter.actor),
            ("operation", &filter.operation),
            ("status", &filter.status),
        ] {
            if let Some(value) = value {
                next.append_pair(name, value);
            }
        }
        let next = format!("/audit?{}", next.finish());
        let content = html! { main id="day2-main" {
            div.toolbar { h1 { "Audit log" } span.badge { (icon("shield-check")) "Platform record" } }
            p.muted { (self.runtime.scope()) }
            form.filters method="get" action="/audit" {
                label { "Actor" input name="actor" value=(filter.actor.as_deref().unwrap_or("")); }
                label { "Operation" input name="operation" value=(filter.operation.as_deref().unwrap_or("")); }
                label { "Status" select name="status" { option value="" { "All statuses" } option value="success" selected[filter.status.as_deref() == Some("success")] { "Success" } option value="failure" selected[filter.status.as_deref() == Some("failure")] { "Failure" } } }
                button type="submit" { (icon("list-filter")) "Filter" } a.button href="/audit" { "Clear" }
            }
            div.audit-list {
                @if entries.is_empty() { p.muted { "No matching activity." } }
                @for entry in &entries {
                    details { summary {
                        strong { (&entry.operation) } span.audit-actor { (&entry.actor) } span.badge { (&entry.status) }
                        time { (timestamp(entry.at)) }
                    }
                    div.audit-detail {
                        p { "Invocation " code { (&entry.invocation) } }
                        p { "Artifact " code { (&entry.artifact) } }
                        @if entry.changes.is_empty() { p.muted { "No committed row changes recorded." } }
                        @for change in &entry.changes {
                            p { strong { (&change.model) } " / " code { (&change.record_id) }
                                " | version " (change.before_version.map_or_else(|| "new".into(),|v| v.to_string())) " to " (change.after_version)
                                " | changed: " (change.fields.join(", "))
                            }
                        }
                        p.muted { "Values redacted." }
                    } }
                }
            }
            @if more { a.button href=(next) { "Older activity" (icon("history")) } }
            p.footnote { "UTC. Completed invocations are listed once, including read-only page queries. Legacy invocations may predate row-change capture." }
        } };
        Ok(html_response(
            StatusCode::OK,
            document(
                "Audit log",
                Some(&self.appearance),
                view::shell(
                    &self.runtime,
                    &self.appearance,
                    session,
                    &self.secret,
                    "$audit",
                    content,
                )?,
            )?,
        ))
    }
}
fn timestamp(at: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(at)
        .ok()
        .and_then(|at| {
            at.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| at.to_string())
}
fn redirect(path: &str) -> Result<Response> {
    ensure!(
        path.starts_with('/') && !path.starts_with("//"),
        "invalid_redirect"
    );
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, path.parse()?);
    Ok(response)
}
fn html_response(status: StatusCode, markup: Markup) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        markup.into_string(),
    )
        .into_response()
}
fn error_page(status: StatusCode, message: &str) -> Response {
    html_response(
        status,
        document(
            "Workspace",
            None,
            html! { main.login { div.stack {
                a.brand href="/" { (icon("link")) "Day2" } h1 { (status.as_u16()) }
                p { (message) } a.button href="/" { "Return to workspace" }
            } } },
        )
        .expect("unbranded platform document"),
    )
}
fn transport_error(json: bool, status: StatusCode, message: &str) -> Response {
    if json {
        let code = match status {
            StatusCode::PAYLOAD_TOO_LARGE => "body_too_large",
            StatusCode::REQUEST_TIMEOUT => "request_timeout",
            _ => "unavailable",
        };
        crate::web_api::error(status, code, message)
    } else {
        error_page(status, message)
    }
}
/// A request the edge would not admit. Told apart only as far as the person
/// can act on it: sign in again, use the delegation protocol, wait for an
/// outage, or ask an operator.
fn edge_refusal(json: bool, error: &anyhow::Error) -> Response {
    use crate::error::Failure;
    crate::web_api::record_failure(error);
    let failure = crate::error::classify(error);
    let (status, message) = match failure {
        Failure::IdentityKeysUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Sign-in could not be checked right now. Retry shortly.",
        ),
        Failure::MachineCallerRequiresDelegation => (
            StatusCode::FORBIDDEN,
            "Service accounts call applications through delegation, not as a person.",
        ),
        Failure::PrincipalSubjectChanged => (
            StatusCode::FORBIDDEN,
            "This address now belongs to a different account than the one first seen for it. An operator must confirm the change.",
        ),
        Failure::Forbidden => (StatusCode::FORBIDDEN, "This request is not authorized."),
        _ => (
            StatusCode::UNAUTHORIZED,
            "Sign in through your company account, then retry.",
        ),
    };
    let code = match failure {
        Failure::IdentityKeysUnavailable
        | Failure::MachineCallerRequiresDelegation
        | Failure::PrincipalSubjectChanged
        | Failure::Forbidden => failure,
        _ => Failure::InvalidIdentityAssertion,
    };
    if json {
        crate::web_api::error(status, code.code(), message)
    } else {
        error_page(status, message)
    }
}
fn failure(error: &anyhow::Error) -> Response {
    crate::web_api::record_failure(error);
    if crate::error::classify(error) == crate::error::Failure::InvalidLoginLink {
        return error_page(
            StatusCode::FORBIDDEN,
            "This local sign-in link is invalid, expired, or already used.",
        );
    }
    let (status, _, message) = crate::web_api::failure_details(error);
    error_page(status, message)
}

fn fresh_page_query(
    mut render: impl FnMut(&str) -> Result<crate::protocol::Outcome>,
) -> Result<crate::protocol::Outcome> {
    for attempt in 1..=3 {
        let id = format!("page-{}", security::random()?);
        let outcome = render(&id)?;
        if outcome.status != "failure" || outcome.error != "preparation_conflict" || attempt == 3 {
            return Ok(outcome);
        }
    }
    unreachable!("bounded page query attempts")
}

fn secure(mut response: Response) -> Response {
    for (name, value) in [
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self' 'unsafe-eval'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
        ),
        ("x-content-type-options", "nosniff"),
        // Native form POSTs need a non-null Origin for our same-origin check.
        // Keep referrers limited to the origin so paths and login tokens stay private.
        ("referrer-policy", "strict-origin"),
        ("cache-control", "no-store"),
        ("x-frame-options", "DENY"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=()",
        ),
        ("cross-origin-resource-policy", "same-origin"),
    ] {
        if !response.headers().contains_key(name) {
            response
                .headers_mut()
                .insert(name, value.parse().expect("static header"));
        }
    }
    response
}
fn patch(markup: Markup) -> Response {
    let mut event = String::from("event: datastar-patch-elements\ndata: mode replace\n");
    for line in markup.into_string().replace('\r', "&#13;").split('\n') {
        event.push_str("data: elements ");
        event.push_str(line);
        event.push('\n');
    }
    event.push('\n');
    ([(header::CONTENT_TYPE, "text/event-stream")], event).into_response()
}

#[cfg(test)]
mod deployment_health_tests {
    use super::*;

    #[tokio::test]
    async fn health_has_no_sensitive_body_or_mutating_method() -> Result<()> {
        for (method, ready, expected) in [
            (Method::GET, true, StatusCode::OK),
            (Method::HEAD, true, StatusCode::OK),
            (Method::GET, false, StatusCode::SERVICE_UNAVAILABLE),
            (Method::POST, true, StatusCode::METHOD_NOT_ALLOWED),
        ] {
            let response = health_response(&method, ready);
            assert_eq!(response.status(), expected);
            assert!(to_bytes(response.into_body(), 100).await?.is_empty());
        }
        let accepting = Arc::new(AtomicBool::new(true));
        Admission(accepting.clone()).stop();
        assert!(!accepting.load(Ordering::Acquire));
        Ok(())
    }
}
