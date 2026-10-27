use crate::{
    audit::Filter,
    digest,
    host_inputs::{Clock, Entropy, LiveTicks},
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
use rusqlite::OptionalExtension;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::Semaphore};

#[path = "web_freetool_credentials.rs"]
mod freetool_credentials;
#[path = "web_live.rs"]
pub(crate) mod live;

struct Grant {
    hash: String,
    actor: String,
    expires: i64,
}
impl Grant {
    fn issue(actor: &str, entropy: &dyn Entropy, clock: &dyn Clock) -> Result<(Self, String)> {
        let token = security::random(entropy)?;
        let wall = i64::try_from(clock.wall_time()?.as_secs())?;
        Ok((
            Self {
                hash: digest(token.as_bytes()),
                actor: actor.into(),
                expires: wall + 600,
            },
            token,
        ))
    }

    fn accepts(&self, token: &str, wall: i64) -> bool {
        self.hash == digest(token.as_bytes()) && wall < self.expires
    }
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
fn accepted_page_acknowledgement(
    status: StatusCode,
    invocation: &str,
    operation: &str,
    rejection: &PageOutcomeFailure,
    reload: &str,
) -> Markup {
    let message = match status {
        StatusCode::OK => "Saved. The page could not be refreshed.",
        StatusCode::ACCEPTED => {
            "Accepted. This is still finishing; the page could not be refreshed."
        }
        _ => unreachable!("only accepted commands receive a fallback acknowledgement"),
    };
    html! { main id="day2-main"
        data-day2-invocation=(invocation)
        data-day2-operation=(operation)
        data-day2-status=(if status == StatusCode::ACCEPTED { "pending" } else { "success" }) {
        div id="day2-command-status" {
            div class="notice" role="status" {
                p { (message) }
                p { (&rejection.message) }
                p { a href=(reload) { "Reload page" } " before making another change." }
                p { "Receipt: " code { @for character in invocation.chars() { (character) wbr; } } }
            }
        }
    } }
}

fn page_content_or_acknowledgement(
    rendered: Result<Markup>,
    status: StatusCode,
    invocation: &str,
    operation: &str,
    reload: &str,
) -> Result<Markup> {
    match rendered {
        Ok(content) => Ok(content),
        Err(error) if matches!(status, StatusCode::OK | StatusCode::ACCEPTED) => {
            match error.downcast::<PageOutcomeFailure>() {
                Ok(rejection) => Ok(accepted_page_acknowledgement(
                    status, invocation, operation, &rejection, reload,
                )),
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

pub(crate) struct Host {
    entropy: Arc<dyn Entropy>,
    clock: Arc<dyn Clock>,
    live_ticks: Arc<dyn LiveTicks>,
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
    presentation: Option<Arc<dyn crate::presentation::Port>>,
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

enum PresentationSource {
    Environment,
    #[cfg(test)]
    Test(Arc<dyn crate::presentation::Port>),
}

struct ListenerOptions {
    concurrency: usize,
    health_endpoints: bool,
    presentation: PresentationSource,
}

pub(crate) struct Admission(Arc<AtomicBool>);

impl Admission {
    pub(crate) fn stop(&self) {
        self.0.store(false, Ordering::Release);
    }
}
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

/// Diagnostic DATA only. These fixed labels grant no storage or serving
/// authority and never accept an error, path, provider value or request data.
#[derive(Clone, Copy)]
pub(crate) enum NativeStartupStep {
    Selection,
    InitialStorage,
    RuntimeAdmission,
    RuntimePostcheck,
    Configuration,
    Providers,
    Receiver,
    Edge,
    Verifier,
    Host,
    Contracts,
    ListenerStore,
    Ingress,
    Presentation,
    Routes,
    Appearance,
    SessionSecret,
    Mount,
    HostParts,
}

impl NativeStartupStep {
    fn code(self) -> &'static str {
        match self {
            Self::Selection => "selection",
            Self::InitialStorage => "initial_storage",
            Self::RuntimeAdmission => "runtime_admission",
            Self::RuntimePostcheck => "runtime_postcheck",
            Self::Configuration => "configuration",
            Self::Providers => "providers",
            Self::Receiver => "receiver",
            Self::Edge => "edge",
            Self::Verifier => "verifier",
            Self::Host => "host",
            Self::Contracts => "contracts",
            Self::ListenerStore => "listener_store",
            Self::Ingress => "ingress",
            Self::Presentation => "presentation",
            Self::Routes => "routes",
            Self::Appearance => "appearance",
            Self::SessionSecret => "session_secret",
            Self::Mount => "mount",
            Self::HostParts => "host_parts",
        }
    }
}

pub(crate) struct NativeStartupObservation {
    enabled: bool,
    completed: bool,
    step: NativeStartupStep,
}

impl NativeStartupObservation {
    pub(crate) fn new(enabled: bool, step: NativeStartupStep) -> Self {
        Self {
            enabled,
            completed: false,
            step,
        }
    }

    pub(crate) fn enter(&mut self, step: NativeStartupStep) {
        self.step = step;
    }

    pub(crate) fn complete(&mut self) {
        self.completed = true;
    }

    fn line(&self) -> Option<Vec<u8>> {
        if !self.enabled || self.completed {
            return None;
        }
        let mut line = b"day2-native-app-startup-refusal ".to_vec();
        line.extend(
            serde_json::to_vec(&serde_json::json!({
                "format":"day2_native_app_startup_refusal_v1",
                "stage":self.step.code(),
                "outcome":"not_completed",
            }))
            .ok()?,
        );
        line.push(b'\n');
        (line.len() <= 256).then_some(line)
    }
}

impl Drop for NativeStartupObservation {
    fn drop(&mut self) {
        use std::io::Write;
        if let Some(line) = self.line() {
            let _ = std::io::stderr().lock().write_all(&line);
        }
    }
}

/// Native Runtime metadata cannot authorize this admission. Its existing SQL
/// facade must obtain the real Current App owner BEFORE opening the file and
/// retain it through this snapshot's close and postchecks. No native DDL,
/// initializer, schema repair or alternate opener is introduced here.
pub(crate) fn admit_listener_storage(runtime: &Runtime) -> Result<()> {
    if !runtime.uses_native_storage() {
        return runtime.initialize();
    }
    runtime.sql_read(|db| validate_listener_snapshot(runtime, db))
}

/// Read-only predicates, not a native admission witness. Only the facade above
/// can supply the actual owned snapshot used by host construction.
pub(crate) fn validate_listener_snapshot(
    runtime: &Runtime,
    db: &rusqlite::Connection,
) -> Result<()> {
    runtime.check_binding(db)?;
    crate::audit::require_current_schema(db)?;
    let active = crate::authority_state::current(db)?;
    ensure!(
        active.artifact_id == runtime.artifact().id(),
        "native_listener_artifact_changed"
    );
    active.document.validate(runtime.artifact())?;
    if let Some(requirements) = &active.document.security {
        requirements.require_runtime()?;
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
            ListenerOptions {
                concurrency,
                health_endpoints: true,
                presentation: PresentationSource::Environment,
            },
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
        let inputs = runtime.inputs();
        let (grant, token) = Grant::issue(actor, inputs.entropy.as_ref(), inputs.clock.as_ref())?;
        let mut server = Self::bind_listener(
            runtime,
            listener,
            authority,
            origin.clone(),
            SignIn::Link(Mutex::new(Some(grant))),
            ListenerOptions {
                concurrency,
                health_endpoints,
                presentation: PresentationSource::Environment,
            },
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
        options: ListenerOptions,
    ) -> Result<Self> {
        let mut observed = NativeStartupObservation::new(
            runtime.uses_native_storage(),
            NativeStartupStep::Contracts,
        );
        runtime.artifact().require_current_api()?;
        let api = crate::openapi::Catalog::from_artifact(runtime.artifact().contract())?;
        observed.enter(NativeStartupStep::ListenerStore);
        admit_listener_storage(&runtime)?;
        observed.enter(NativeStartupStep::Ingress);
        validate_ingress_credentials(&runtime)?;
        // `__Host-` makes the browser refuse the cookie unless it is Secure,
        // host-only and path `/`, so no sibling subdomain at the edge can set or
        // shadow it. Development is plain HTTP on loopback and cannot use it.
        let prefix = if matches!(sign_in, SignIn::Edge(_)) {
            "__Host-"
        } else {
            ""
        };
        let inputs = runtime.inputs().clone();
        let entropy = inputs.entropy.clone();
        observed.enter(NativeStartupStep::Presentation);
        let declarations =
            crate::web_templates::presentation_catalog(&runtime.artifact().contract().templates)?;
        let presentation = match options.presentation {
            PresentationSource::Environment => {
                crate::presentation::load_environment(&declarations)?
            }
            #[cfg(test)]
            PresentationSource::Test(port) => Some(port),
        };
        let host = Arc::new(Host {
            entropy: entropy.clone(),
            clock: inputs.clock.clone(),
            live_ticks: inputs.live_ticks.clone(),
            oauth: None,
            credential_effects: crate::managed_credentials::effects::capture(),
            presentation,
            api,
            routes: {
                observed.enter(NativeStartupStep::Routes);
                (runtime.artifact().contract().format >= 7)
                    .then(|| crate::routing::Catalog::from_artifact(runtime.artifact().contract()))
                    .transpose()?
            },
            redirects: crate::redirects::Catalog::from_artifact(runtime.artifact().contract())?,
            appearance: {
                observed.enter(NativeStartupStep::Appearance);
                Appearance::load(&runtime)?
            },
            secret: {
                observed.enter(NativeStartupStep::SessionSecret);
                security::secret(&runtime, entropy.as_ref())?
            },
            cookie_name: format!(
                "{prefix}day2_{}_{}",
                runtime.app(),
                &day2_assets::hash_part(&digest(runtime.scope().as_bytes()))?[..16]
            ),
            runtime,
            authority,
            origin: origin.clone(),
            sign_in,
            capacity: Arc::new(Semaphore::new(options.concurrency)),
            app_capacity: Arc::new(Semaphore::new(16)),
            app_issue_capacity: Arc::new(Semaphore::new(4)),
            app_execute_capacity: Arc::new(Semaphore::new(6)),
            app_reconcile_capacity: Arc::new(Semaphore::new(2)),
            queued: std::sync::atomic::AtomicUsize::new(0),
            live_capacity: Arc::new(Semaphore::new(64)),
            admitting: Arc::new(AtomicBool::new(true)),
            health_endpoints: options.health_endpoints,
        });
        observed.complete();
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

    pub(crate) fn into_native_parts(
        mut self,
        admission: Arc<AtomicBool>,
    ) -> Result<(Arc<Host>, TcpListener)> {
        ensure!(self.host.oauth.is_some(), "native App receiver missing");
        Arc::get_mut(&mut self.host)
            .context("native App startup host escaped")?
            .admitting = admission;
        Ok((self.host, self.listener))
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
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let background = if self.host.oauth.is_none() {
            Some(tokio::spawn(crate::host_loop::run(
                self.host.runtime.clone(),
                self.host.clock.clone(),
                self.host.live_ticks.clone(),
                self.host.admitting.clone(),
                stopped,
            )))
        } else {
            None
        };
        let admitting = self.host.admitting.clone();
        let shutdown_admission = admitting.clone();
        let shutdown_stop = stop.clone();
        let shutdown = async move {
            shutdown.await;
            shutdown_admission.store(false, Ordering::Release);
            let _ = shutdown_stop.send(true);
        };
        let result = if self.host.oauth.is_some() {
            crate::oauth::native_http::serve(
                crate::oauth::native_http::Endpoint::App(self.host),
                self.listener,
                MAX_QUEUED,
                admitting.clone(),
                shutdown,
            )
            .await
        } else {
            let router = Router::new().fallback(handle).with_state(self.host);
            axum::serve(self.listener, router)
                .with_graceful_shutdown(shutdown)
                .await
                .map_err(Into::into)
        };
        // Also stop after an unexpected server exit. Already admitted requests
        // and blocking native calls may still finish; shutdown does not undo
        // their transactions or interrupt external calls. Await pump settlement.
        admitting.store(false, Ordering::Release);
        let _ = stop.send(true);
        if let Some(background) = background {
            background.await??;
        }
        result?;
        Ok(())
    }
}

/// Longest a request waits for an execution permit before it is refused as busy.
const QUEUE_WAIT: Duration = Duration::from_secs(10);

/// Requests that may wait for a permit at once; beyond this, refuse immediately.
pub(crate) const MAX_QUEUED: usize = 256;

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
    crate::oauth::native_http::timer(|| {
        tokio::time::timeout(wait, host.capacity.clone().acquire_owned())
    })
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

/// Closed response classification, never permission. Only this module's
/// literal health producer can set the health case; raw application responses
/// cannot acquire it through a path, header, status, body or extension.
pub(crate) struct NativeResponse {
    response: Response,
    literal_health: bool,
}

impl NativeResponse {
    pub(crate) fn application(response: Response) -> Self {
        Self {
            response,
            literal_health: false,
        }
    }

    fn health(method: &Method, ready: bool) -> Self {
        Self {
            response: health_response(method, ready),
            literal_health: true,
        }
    }

    pub(crate) fn response(&self) -> &Response {
        &self.response
    }

    pub(crate) fn into_response(self) -> Response {
        self.response
    }

    pub(crate) fn app_scope(
        &self,
        resolve: impl FnOnce() -> Result<Option<day2_capabilities::security_epoch::AuthorityScope>>,
    ) -> Result<Option<day2_capabilities::security_epoch::AuthorityScope>> {
        if self.literal_health {
            Ok(None)
        } else {
            resolve()
        }
    }
}

#[cfg(test)]
pub(crate) fn literal_health_fixture(method: &Method, ready: bool) -> NativeResponse {
    NativeResponse::health(method, ready)
}

fn literal_health_request(
    enabled: bool,
    admitting: &AtomicBool,
    request: &Request,
) -> Option<NativeResponse> {
    if !enabled || !matches!(request.uri().path(), "/health/live" | "/health/ready") {
        return None;
    }
    let ready = request.uri().path() == "/health/live" || admitting.load(Ordering::Acquire);
    Some(NativeResponse::health(request.method(), ready))
}

async fn handle(State(host): State<Arc<Host>>, request: Request) -> Response {
    handle_native(host, request).await.into_response()
}

pub(crate) fn native_selections(
    host: &Host,
) -> Result<Vec<crate::oauth::native_management::NativeSelection>> {
    host.oauth
        .as_ref()
        .context("native OAuth receiver missing")?
        .native_selections()
}

pub(crate) fn native_runtime_response_scope(
    host: &Host,
) -> Result<Option<day2_capabilities::security_epoch::AuthorityScope>> {
    crate::oauth::native_management::runtime_response_scope(&host.runtime)
}

pub(crate) async fn native_pump(
    host: Arc<Host>,
    stopped: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    crate::host_loop::run_on_owner(
        host.runtime.clone(),
        host.clock.clone(),
        host.live_ticks.clone(),
        host.admitting.clone(),
        stopped,
    )
    .await
}

pub(crate) async fn handle_native(host: Arc<Host>, request: Request) -> NativeResponse {
    host.credential_effects
        .clone()
        .run_async(async move {
            if let Some(response) =
                literal_health_request(host.health_endpoints, &host.admitting, &request)
            {
                return response;
            }
            NativeResponse::application(handle_inner(host, request).await)
        })
        .await
}

async fn handle_inner(host: Arc<Host>, request: Request) -> Response {
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
    } else if parts.uri.path().starts_with(freetool_credentials::PREFIX) {
        16_384
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
    let native = host.oauth.is_some();
    let dispatch = move || {
        let _permit = permit;
        let at = if parts
            .uri
            .path()
            .starts_with(crate::managed_credentials::ingress::PREFIX)
        {
            crate::managed_credentials::effects::wall_time()?
        } else {
            host.wall_seconds()?
        };
        let category = match parts.uri.path() {
            "/actions" => "command",
            "/login" => "sign_in",
            "/logout" => "sign_out",
            "/audit" | crate::openapi::AUDIT_PATH | crate::openapi::AUDIT_EVENTS_PATH => {
                "audit_read"
            }
            "/_live" => "live_read",
            path if path.starts_with(freetool_credentials::PREFIX) => "credential_management",
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
    };
    let response = if native {
        dispatch()
    } else {
        crate::managed_credentials::effects::spawn_blocking(dispatch)
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("web dispatch task failed")))
    };
    let response = match response {
        Ok(response) => response,
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
    let body = match crate::oauth::native_http::timer(|| {
        tokio::time::timeout(
            Duration::from_secs(3),
            to_bytes(request.into_body(), maximum),
        )
    })
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
    let native = host.oauth.is_some();
    let dispatch = move || -> Result<Vec<u8>> {
        let _permit = permit;
        let at = host.wall_seconds()?;
        host.runtime.web_event(at, None, "app_call", 102)?;
        let result = port.receive(&host.runtime, &path, &body, &assertion, at);
        host.runtime
            .web_event(at, None, "app_call", if result.is_ok() { 200 } else { 403 })?;
        result
    };
    let response = if native {
        dispatch()
    } else {
        tokio::task::spawn_blocking(dispatch)
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("app call task failed")))
    };
    match response {
        Ok(body) => secure(([(header::CONTENT_TYPE, "application/json")], body).into_response()),
        _ => secure((StatusCode::FORBIDDEN, "{\"error\":\"app_call_refused\"}").into_response()),
    }
}
impl Host {
    fn wall_seconds(&self) -> Result<i64> {
        Ok(i64::try_from(self.clock.wall_time()?.as_secs())?)
    }

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
        let token =
            security::create_session(&self.runtime, &verified.email, at, self.entropy.as_ref())?;
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
                        entropy: self.entropy.as_ref(),
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
                entropy: self.entropy.as_ref(),
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
        if uri.path().starts_with(freetool_credentials::PREFIX) {
            return self.freetool_credentials(method, uri, body, session, at);
        }
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
                self.get_page(name, &input, headers, session, at)
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
                        self.routed_page(&name, &input, headers, session, at)
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
        let id = format!("redirect-{}", security::random(self.entropy.as_ref())?);
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

    /// Render a routed page, or its app-owned failure page when it fails on the
    /// server. Page preparation runs first and answers its own refusals and
    /// preparation fallback; a failure page never runs preparation.
    ///
    /// The fallback answers with the original failure's status, after that
    /// failure is logged exactly as the platform error page would log it. It
    /// receives the same decoded input and nothing about the failure, and its
    /// query runs under its own grant and audit. Client, authority, conflict and
    /// declared application failures keep their platform pages. If the fallback
    /// fails too, the person sees the platform page for the original failure.
    fn routed_page(
        &self,
        name: &str,
        input: &Value,
        headers: &HeaderMap,
        session: &Session,
        at: i64,
    ) -> Result<Response> {
        let error = match self.get_page(name, input, headers, session, at) {
            Ok(response) => return Ok(response),
            Err(error) => error,
        };
        let fallback = self
            .routes
            .as_ref()
            .and_then(|routes| routes.route(name).ok())
            .and_then(|route| route.failure_page.as_deref());
        let Some(fallback) = fallback.filter(|_| serves_failure_page(&error)) else {
            return Err(error);
        };
        crate::web_api::record_failure(&error);
        let (status, _, message) = crate::web_api::failure_details(&error);
        Ok(self
            .page(fallback, input, session, at, None, None)
            .and_then(|content| self.app_response(status, fallback, input, session, content))
            .unwrap_or_else(|fallback_error| {
                crate::web_api::record_failure(&fallback_error);
                error_page(status, message)
            }))
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
            current.accepts(&token, at),
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
        let token =
            security::create_session(&self.runtime, &current.actor, at, self.entropy.as_ref())?;
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
        let component_script = self.appearance.component_script_url(&self.runtime)?;
        let font_policy = if self
            .runtime
            .artifact()
            .contract()
            .web_resources
            .values()
            .any(|resource| resource.media_type == "font/woff2")
        {
            format!(
                " font-src {}{};",
                self.origin,
                self.appearance.resource_prefix()
            )
        } else {
            String::new()
        };
        let theme = self.appearance.theme_url()?;
        let image_origins =
            crate::web_templates::remote_image_origins(&content.clone().into_string())?;
        let live = self.live_initializer(name, input, &image_origins)?;
        let image_sources = image_origins.join(" ");
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
                        script type="module" src="/assets/platform/reactive-queries.js" {}
                        @if let Some(script) = script { script type="module" src=(script) {} }
                        // Component behavior has a separate admitted entrypoint.
                        @if let Some(script) = component_script { script type="module" src=(script) {} }
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
                "default-src 'none'; script-src 'unsafe-eval' {}/assets/platform/datastar-1.0.1.js {}/assets/platform/forms.js {}/assets/platform/navigation.js {}/assets/platform/reactive-queries.js {}{}; script-src-attr 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' {};{} connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; worker-src 'none'",
                self.origin, self.origin, self.origin, self.origin, self.origin, self.appearance.resource_prefix(), image_sources, font_policy
            ).parse()?,
        );
        Ok(response)
    }
    fn check_preparation_authority(
        &self,
        expected: &[(String, crate::authority_state::AuthorityStamp)],
        actor: &str,
    ) -> Result<()> {
        for (operation, stamp) in expected {
            ensure!(
                self.runtime.authority_snapshot(operation, actor)?.stamp == *stamp,
                crate::error::Failure::Forbidden
            );
        }
        Ok(())
    }

    fn check_page_delivery(
        &self,
        operation: &str,
        expected: &crate::authority_state::AuthorityStamp,
        actor: &str,
        session: &Session,
    ) -> Result<()> {
        self.appearance.check_binding(&self.runtime)?;
        let current = self.runtime.authority_snapshot(operation, actor)?.stamp;
        let db = open(self.runtime.db())?;
        let current_session: Option<(String, i64)> = db
            .query_row(
                "SELECT actor,expires FROM day2_web_sessions WHERE hash=?1",
                [&session.hash],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        validate_presentation_delivery(
            expected,
            &current,
            actor,
            current_session.as_ref(),
            self.wall_seconds(),
        )
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
        self.page_with_outcome(name, input, session, at, notice, (submitted, None))
    }

    fn get_page(
        &self,
        name: &str,
        input: &Value,
        headers: &HeaderMap,
        session: &Session,
        at: i64,
    ) -> Result<Response> {
        let page = self.runtime.artifact().page(name)?;
        if page.preparation.is_empty() {
            let content = self.page(name, input, session, at, None, None)?;
            return self.app_response(StatusCode::OK, name, input, session, content);
        }
        if let Some(status) = page_preparation_refusal(headers) {
            let message = if status == StatusCode::SERVICE_UNAVAILABLE {
                "Page preparation is not run for speculative requests."
            } else {
                "Page preparation requires page navigation or a same-origin HTML refresh."
            };
            return Ok(error_page(status, message));
        }
        let input_record = &self.runtime.artifact().contract().schema.inputs[&self
            .runtime
            .artifact()
            .operation(&page.operation)?
            .input_type];
        input_record.validate_input(input)?;
        // Admission is an all-or-nothing preflight: no preparation command may
        // run until every operation needed by this page is authorized.
        let primary = self
            .runtime
            .authority_snapshot(&page.operation, &session.actor)?;
        let mut expected = Vec::with_capacity(
            page.preparation.len() + 1 + usize::from(!page.prepare_failure_operation.is_empty()),
        );
        expected.push((page.operation.clone(), primary.stamp.clone()));
        for operation in &page.preparation {
            expected.push((
                operation.clone(),
                self.runtime
                    .authority_snapshot(operation, &session.actor)?
                    .stamp,
            ));
        }
        if !page.prepare_failure_operation.is_empty() {
            let fallback = &page.prepare_failure_operation;
            expected.push((
                fallback.clone(),
                self.runtime
                    .authority_snapshot(fallback, &session.actor)?
                    .stamp,
            ));
        }
        self.check_preparation_authority(&expected, &session.actor)?;

        for (index, operation) in page.preparation.iter().enumerate() {
            self.check_preparation_authority(&expected, &session.actor)?;
            let id = format!(
                "page-prepare-{index}-{}",
                security::random(self.entropy.as_ref())?
            );
            let result = self.runtime.invoke_verified(
                operation,
                crate::store::RequestIdentity {
                    actor: &session.actor,
                    origin: session.origin.as_ref(),
                },
                &id,
                &serde_json::json!({}),
                at,
                Fault::None,
            );
            let failure = match result {
                Ok(outcome) if outcome.status == "success" => None,
                Ok(outcome) => {
                    let (status, _, message) =
                        crate::web_api::outcome_failure(&self.runtime, &outcome.error);
                    Some((status, message.to_owned()))
                }
                Err(error) => {
                    let (status, _, message) = crate::web_api::failure_details(&error);
                    Some((status, message.to_owned()))
                }
            };
            if let Some((status, message)) = failure {
                if page_preparation_denial(status) {
                    return Ok(error_page(status, &message));
                }
                if !page.prepare_failure_operation.is_empty() {
                    self.check_preparation_authority(&expected, &session.actor)?;
                    let fallback = &page.prepare_failure_operation;
                    let id = format!("page-fallback-{}", security::random(self.entropy.as_ref())?);
                    let fallback_result = self.runtime.invoke_verified(
                        fallback,
                        crate::store::RequestIdentity {
                            actor: &session.actor,
                            origin: session.origin.as_ref(),
                        },
                        &id,
                        input,
                        at,
                        Fault::None,
                    );
                    let outcome = fallback_result?;
                    if outcome.status != "success" {
                        return Ok(error_page(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "The page is temporarily unavailable.",
                        ));
                    }
                    let content = self.page_with_outcome(
                        name,
                        input,
                        session,
                        at,
                        None,
                        (None, Some(outcome)),
                    )?;
                    let response = self.app_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        name,
                        input,
                        session,
                        content,
                    )?;
                    self.check_preparation_authority(&expected, &session.actor)?;
                    self.check_page_delivery(
                        &page.operation,
                        &primary.stamp,
                        &session.actor,
                        session,
                    )?;
                    return Ok(response);
                }
                return Ok(error_page(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "The page is temporarily unavailable.",
                ));
            }
            self.check_preparation_authority(&expected, &session.actor)?;
        }
        self.check_preparation_authority(&expected, &session.actor)?;
        let content = self.page(name, input, session, at, None, None)?;
        let response = self.app_response(StatusCode::OK, name, input, session, content)?;
        self.check_preparation_authority(&expected, &session.actor)?;
        self.check_page_delivery(&page.operation, &primary.stamp, &session.actor, session)?;
        Ok(response)
    }

    fn page_with_outcome(
        &self,
        name: &str,
        input: &Value,
        session: &Session,
        at: i64,
        notice: Option<Notice<'_>>,
        (submitted, supplied_outcome): (
            Option<view::Submitted<'_>>,
            Option<crate::protocol::Outcome>,
        ),
    ) -> Result<Markup> {
        let page = self.runtime.artifact().page(name)?;
        let presentation_authority = if self.presentation.is_some() {
            Some(
                self.runtime
                    .authority_snapshot(&page.operation, &session.actor)?
                    .stamp,
            )
        } else {
            None
        };
        // A completion can invalidate a prepared read between its observation
        // and validation. Retry only the page query with a fresh invocation;
        // the command and its durable receipt are never repeated here.
        let outcome = match supplied_outcome {
            Some(outcome) => outcome,
            None => fresh_page_query(self.entropy.as_ref(), |id| {
                self.runtime
                    .render_page(name, &session.actor, id, input, at)
            })?,
        };
        if outcome.status != "success" {
            if let Some(rejection) = declared_page_rejection(&self.runtime, name, &outcome.error) {
                return Err(anyhow::Error::new(rejection));
            }
            let failure = match outcome.error.as_str() {
                "invalid_page_bounds" => crate::error::Failure::InvalidPageInput,
                code => crate::error::Failure::from_code(code)
                    .unwrap_or(crate::error::Failure::Internal),
            };
            anyhow::bail!(failure);
        }
        let renderer = view::View {
            runtime: &self.runtime,
            appearance: &self.appearance,
            secret: &self.secret,
            entropy: self.entropy.as_ref(),
            session,
            page: name,
            input,
            now: at,
            submitted,
        };
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
                crate::web_templates::render_routed_with_presentations(
                    crate::web_templates::RoutedRender {
                        directory: self.runtime.artifact().directory(),
                        catalog: &self.runtime.artifact().contract().templates,
                        path: &page.template,
                        context,
                        asset_urls,
                        routes,
                        origin: &self.origin,
                    },
                    self.presentation.clone(),
                )?
            } else {
                crate::web_templates::render_with_presentations(
                    self.runtime.artifact().directory(),
                    &self.runtime.artifact().contract().templates,
                    &page.template,
                    context,
                    asset_urls,
                    self.presentation.clone(),
                )?
            };
            crate::web_forms::bind(&renderer, &markup)?
        };
        // Presentation execution may take seconds. Do not return a formerly
        // authorized query after revocation or an A -> B -> A policy change.
        if let Some(authority) = presentation_authority {
            self.check_page_delivery(&page.operation, &authority, &session.actor, session)?;
        }
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
        for (name, native) in &ticket.native {
            ensure!(
                ticket.editable.iter().any(|editable| editable == name),
                crate::error::Failure::InvalidTicket
            );
            let kind = record
                .fields
                .get(name)
                .context(crate::error::Failure::InvalidTicket)?;
            let compatible = match native.mode {
                security::NativeMode::BooleanCheckbox => {
                    *kind == crate::schema::Kind::Boolean && native.omitted == Value::Bool(false)
                }
                security::NativeMode::ListCheckbox => {
                    crate::web_forms::scalar_list(kind)
                        && native.omitted == Value::Array(Vec::new())
                }
                security::NativeMode::MultipleSelect => {
                    crate::web_forms::scalar_list(kind)
                        && native.omitted == Value::Array(Vec::new())
                }
                security::NativeMode::SetCheckbox => {
                    crate::web_forms::carrier(kind) == crate::web_forms::Carrier::Set
                        && native.omitted == serde_json::json!({"members": []})
                }
                security::NativeMode::Radio => {
                    matches!(
                        kind,
                        crate::schema::Kind::Text | crate::schema::Kind::StandardText { .. }
                    ) && native.omitted == Value::String(String::new())
                }
            };
            ensure!(
                compatible
                    && (native.mode == security::NativeMode::MultipleSelect
                        || !native.choices.is_empty())
                    && native.choices.iter().all(|choice| !choice.is_empty())
                    && native
                        .choices
                        .iter()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        == native.choices.len(),
                crate::error::Failure::InvalidTicket
            );
            if let Some(values) = fields.get(name) {
                ensure!(
                    values.iter().all(|value| native.choices.contains(value)),
                    crate::error::Failure::UnknownFields
                );
            } else {
                fields.insert(name.clone(), vec![]);
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
                if value.is_empty() {
                    let default = ticket
                        .native
                        .get(name)
                        .context(crate::error::Failure::UnknownFields)?;
                    input[name] = default.omitted.clone();
                } else {
                    input[name] = security::field_values(
                        record
                            .fields
                            .get(name)
                            .context(crate::error::Failure::UnknownFields)?,
                        value,
                    )?;
                }
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
            let rendered = self.page(
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
            );
            let content = page_content_or_acknowledgement(
                rendered,
                status,
                &id,
                &ticket.operation,
                &view::page_url(&self.runtime, &ticket.page, &ticket.page_input)?,
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
        // Storage is reached only after the assertion verified, so telling a
        // busy database apart from a bad assertion reveals nothing to a forger.
        // The same request succeeds once the writer is free.
        Failure::IdentityKeysUnavailable | Failure::StorageBusy => (
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
        | Failure::StorageBusy
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
fn page_preparation_denial(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::BAD_REQUEST
    )
}

pub fn page_preparation_refusal(headers: &HeaderMap) -> Option<StatusCode> {
    let values = |key: &str| {
        headers
            .get_all(key)
            .iter()
            .map(|v| v.to_str().unwrap_or("").to_ascii_lowercase())
            .collect::<Vec<_>>()
    };
    if ["sec-purpose", "purpose", "x-purpose", "x-moz"]
        .iter()
        .flat_map(|key| values(key))
        .any(|value| value.contains("prefetch") || value.contains("preview"))
    {
        return Some(StatusCode::SERVICE_UNAVAILABLE);
    }
    let single = |key: &str| {
        let values = values(key);
        (values.len() == 1).then(|| values[0].as_str().to_owned())
    };
    if [
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "sec-fetch-user",
    ]
    .iter()
    .any(|key| values(key).len() > 1)
    {
        return Some(StatusCode::FORBIDDEN);
    }
    let site = single("sec-fetch-site");
    let mode = single("sec-fetch-mode");
    let dest = single("sec-fetch-dest");
    let user = single("sec-fetch-user");
    if user.as_deref().is_some_and(|value| value != "?1") {
        return Some(StatusCode::FORBIDDEN);
    }
    let navigation = matches!(mode.as_deref(), Some("navigate"))
        && matches!(dest.as_deref(), Some("document"))
        && matches!(
            site.as_deref(),
            Some("same-origin" | "same-site" | "cross-site" | "none")
        )
        && (user.as_deref() == Some("?1") || site.as_deref() == Some("none"));
    let same_origin_refresh = site.as_deref() == Some("same-origin")
        && matches!(mode.as_deref(), Some("cors" | "same-origin"))
        && dest.as_deref() == Some("empty")
        && user.is_none()
        && single("accept").is_some_and(|accept| {
            accept.split(',').any(|part| {
                part.split(';')
                    .next()
                    .is_some_and(|kind| kind.trim() == "text/html")
            })
        });
    if navigation || same_origin_refresh {
        None
    } else {
        Some(StatusCode::FORBIDDEN)
    }
}

fn failure(error: &anyhow::Error) -> Response {
    if let Some(page_failure) = error.downcast_ref::<PageOutcomeFailure>() {
        return error_page(page_failure.status, &page_failure.message);
    }
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

/// Whether a page failure is the server's, so an app-owned failure page may
/// answer it. Declared application rejections carry their own public message;
/// authentication, authority, input, conflict and not-found failures must keep
/// the platform's answer rather than look like an outage.
fn serves_failure_page(error: &anyhow::Error) -> bool {
    use crate::error::Category;
    error.downcast_ref::<PageOutcomeFailure>().is_none()
        && matches!(
            crate::error::classify(error).category(),
            Category::Internal | Category::Timeout | Category::Unavailable
        )
}

#[derive(Debug)]
struct PageOutcomeFailure {
    status: StatusCode,
    message: String,
}

impl std::fmt::Display for PageOutcomeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("page query failed")
    }
}

impl std::error::Error for PageOutcomeFailure {}

fn declared_page_rejection(
    runtime: &Runtime,
    page_name: &str,
    code: &str,
) -> Option<PageOutcomeFailure> {
    let artifact = runtime.artifact();
    let page = artifact.page(page_name).ok()?;
    let contract = artifact.contract().app_contract.as_ref()?;
    let operation = contract.operations.get(&page.operation)?;
    declared_page_rejection_for(&page.operation, &operation.errors, &contract.errors, code)?;
    let (status, _, message) = crate::web_api::outcome_failure(runtime, code);
    Some(PageOutcomeFailure { status, message })
}

fn declared_page_rejection_for<'a>(
    operation_name: &str,
    declared_errors: &[String],
    failures: &'a std::collections::BTreeMap<String, crate::app_contract::Failure>,
    code: &str,
) -> Option<&'a crate::app_contract::Failure> {
    if !declared_errors.iter().any(|declared| declared == code) {
        return None;
    }
    let failure = failures.get(code)?;
    if failure.code != code
        || !failure
            .targets()
            .any(|target| target.operation == operation_name)
    {
        return None;
    }
    Some(failure)
}

fn validate_presentation_delivery(
    expected: &crate::authority_state::AuthorityStamp,
    current: &crate::authority_state::AuthorityStamp,
    actor: &str,
    session: Option<&(String, i64)>,
    wall: Result<i64>,
) -> Result<()> {
    ensure!(
        current == expected,
        crate::error::Failure::AuthorityPolicyChanged
    );
    ensure!(
        session.is_some_and(|(session_actor, expires)| {
            session_actor == actor && wall.as_ref().is_ok_and(|at| at < expires)
        }),
        crate::error::Failure::SignInRequired
    );
    Ok(())
}

fn fresh_page_query(
    entropy: &dyn Entropy,
    mut render: impl FnMut(&str) -> Result<crate::protocol::Outcome>,
) -> Result<crate::protocol::Outcome> {
    for attempt in 1..=3 {
        let id = format!("page-{}", security::random(entropy)?);
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
mod page_failure_tests {
    use super::*;

    #[test]
    fn preparation_authority_and_input_failures_do_not_enter_fallback_policy() {
        assert!(page_preparation_denial(StatusCode::UNAUTHORIZED));
        assert!(page_preparation_denial(StatusCode::FORBIDDEN));
        assert!(page_preparation_denial(StatusCode::BAD_REQUEST));
        assert!(!page_preparation_denial(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(!page_preparation_denial(StatusCode::SERVICE_UNAVAILABLE));
    }

    #[tokio::test]
    async fn app_failure_html_uses_status_and_escapes_public_message() {
        let response = failure(&anyhow::Error::new(PageOutcomeFailure {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            message: "Use <a safe filter> & retry.".into(),
        }));
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = response.into_body();
        let markup = axum::body::to_bytes(body, usize::MAX)
            .await
            .expect("error page body");
        let markup = String::from_utf8(markup.to_vec()).expect("HTML is UTF-8");
        assert!(markup.contains("Use &lt;a safe filter&gt; &amp; retry."));
        assert!(!markup.contains("Use <a safe filter> & retry."));

        let response = failure(&anyhow::anyhow!("database connection details"));
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(response.into_body(), 4096)
            .await
            .expect("error body");
        let body = String::from_utf8(body.to_vec()).expect("HTML is UTF-8");
        assert!(!body.contains("database connection details"));
        assert!(body.contains("Retry commands with the same idempotency key."));
    }

    #[test]
    fn only_server_failures_render_an_app_failure_page() {
        use crate::error::Failure;
        let busy = anyhow::Error::new(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            None,
        ))
        .context("page query");
        for error in [
            anyhow::anyhow!("no such table: links"),
            busy,
            anyhow::Error::new(Failure::Internal),
            anyhow::Error::new(Failure::WorkerCrashed),
            anyhow::Error::new(Failure::WorkerTimeout),
            anyhow::Error::new(Failure::StorageBusy),
        ] {
            assert!(serves_failure_page(&error), "{error}");
        }
        for error in [
            anyhow::Error::new(PageOutcomeFailure {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                message: "Declared by the application.".into(),
            }),
            anyhow::Error::new(Failure::SignInRequired),
            anyhow::Error::new(Failure::Forbidden),
            anyhow::Error::new(Failure::AuthorityPolicyChanged),
            anyhow::Error::new(Failure::InvalidPageInput),
            anyhow::Error::new(Failure::PreparationConflict),
            anyhow::Error::new(Failure::UnknownPage),
        ] {
            assert!(!serves_failure_page(&error), "{error}");
        }
    }

    #[test]
    fn accepted_command_page_rejection_returns_receipt_acknowledgement() -> Result<()> {
        for (status, state, phrase) in [
            (StatusCode::OK, "success", "Saved."),
            (StatusCode::ACCEPTED, "pending", "Accepted."),
        ] {
            let content = page_content_or_acknowledgement(
                Err(anyhow::Error::new(PageOutcomeFailure {
                    status: StatusCode::UNPROCESSABLE_ENTITY,
                    message: "<Access & membership denied> Choose \"another\" space & retry."
                        .into(),
                })),
                status,
                "web-original-ticket-nonce",
                "freetool.space_update",
                "/spaces/example/settings?tab=details&view=current",
            )?;
            let markup = content.into_string();
            assert!(markup.contains("data-day2-invocation=\"web-original-ticket-nonce\""));
            assert!(markup.contains("data-day2-operation=\"freetool.space_update\""));
            assert!(markup.contains(&format!("data-day2-status=\"{state}\"")));
            assert!(markup.contains(phrase));
            assert!(markup.contains("&lt;Access &amp; membership denied&gt;"));
            assert!(markup.contains("Choose &quot;another&quot; space &amp; retry."));
            let document = scraper::Html::parse_fragment(&markup);
            let text = document.root_element().text().collect::<String>();
            assert!(text.contains("Reload page before making another change."));
            assert!(text.contains("Receipt: web-original-ticket-nonce"));
            assert!(markup.contains("<wbr>"));
            assert!(
                markup.contains("href=\"/spaces/example/settings?tab=details&amp;view=current\"")
            );
            assert!(!markup.contains("<form") && !markup.contains("_ticket"));
        }
        Ok(())
    }

    #[test]
    fn acknowledgement_fallback_does_not_convert_rejected_or_operational_errors() {
        let rejected = page_content_or_acknowledgement(
            Err(anyhow::Error::new(PageOutcomeFailure {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                message: "Denied. Reload.".into(),
            })),
            StatusCode::UNPROCESSABLE_ENTITY,
            "receipt",
            "operation",
            "/",
        )
        .unwrap_err();
        assert!(rejected.downcast_ref::<PageOutcomeFailure>().is_some());
        let operational = page_content_or_acknowledgement(
            Err(anyhow::anyhow!("rendering database failure")),
            StatusCode::OK,
            "receipt",
            "operation",
            "/",
        )
        .unwrap_err();
        assert_eq!(operational.to_string(), "rendering database failure");
    }

    #[test]
    fn app_failure_requires_exact_operation_declaration_and_matching_target() {
        let code = "app:freetool.space_page_denied";
        let declarations = vec![code.into()];
        let matching = std::collections::BTreeMap::from([(
            code.into(),
            crate::app_contract::Failure {
                code: code.into(),
                description: "Denied".into(),
                recovery: "Reload".into(),
                operation: crate::operation_metadata::Target {
                    operation: "freetool.space_page".into(),
                    input_type: "input".into(),
                    output_type: "output".into(),
                },
                additional_operations: Vec::new(),
                verification_actors: Vec::new(),
                verification_delegations: Vec::new(),
            },
        )]);
        assert!(
            declared_page_rejection_for("freetool.space_page", &declarations, &matching, code)
                .is_some()
        );
        assert!(
            declared_page_rejection_for("freetool.other_page", &declarations, &matching, code)
                .is_none()
        );
        assert!(declared_page_rejection_for("freetool.space_page", &[], &matching, code).is_none());
    }
}

#[cfg(test)]
#[path = "presentation_delivery_tests.rs"]
mod presentation_delivery_tests;

#[cfg(test)]
mod deployment_health_tests {
    use super::*;

    #[test]
    fn only_the_enabled_literal_platform_paths_can_produce_health_classification() {
        let admitting = AtomicBool::new(true);
        for path in [
            "/",
            "/health/ready/",
            "/health/ready/../query",
            "/_platform/app-query",
        ] {
            let request = axum::http::Request::builder()
                .uri(path)
                .body(Body::empty())
                .unwrap();
            assert!(literal_health_request(true, &admitting, &request).is_none());
        }
        let request = axum::http::Request::builder()
            .uri("/health/ready")
            .body(Body::empty())
            .unwrap();
        assert!(literal_health_request(false, &admitting, &request).is_none());
        assert!(literal_health_request(true, &admitting, &request).is_some());
    }

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

    #[tokio::test]
    async fn a_busy_database_during_sign_in_asks_for_a_retry_not_a_new_sign_in() -> Result<()> {
        let busy = anyhow::Error::new(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            None,
        ))
        .context("bind verified subject");
        let response = edge_refusal(true, &busy);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
        assert_eq!(body["error"]["code"], "storage_busy");
        // Anything else that is not a typed refusal still reads as a failed
        // assertion, so a forger learns nothing about which check failed.
        for error in [
            anyhow::anyhow!("malformed assertion"),
            anyhow::Error::new(crate::error::Failure::InvalidIdentityAssertion),
        ] {
            let response = edge_refusal(true, &error);
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let body: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
            assert_eq!(body["error"]["code"], "invalid_identity_assertion");
        }
        Ok(())
    }
}

#[cfg(test)]
mod native_startup_tests {
    use super::*;

    fn native_admission_is_preserved(body: &syn::Block) -> bool {
        let [
            syn::Stmt::Expr(syn::Expr::If(branch), _),
            syn::Stmt::Expr(syn::Expr::MethodCall(current), _),
        ] = body.stmts.as_slice()
        else {
            return false;
        };
        let syn::Expr::Unary(condition) = &*branch.cond else {
            return false;
        };
        let syn::Expr::MethodCall(selected) = &*condition.expr else {
            return false;
        };
        let [syn::Stmt::Expr(syn::Expr::Return(returned), _)] = branch.then_branch.stmts.as_slice()
        else {
            return false;
        };
        let Some(returned) = &returned.expr else {
            return false;
        };
        let syn::Expr::MethodCall(initializer) = &**returned else {
            return false;
        };
        matches!(condition.op, syn::UnOp::Not(_))
            && branch.else_branch.is_none()
            && selected.method == "uses_native_storage"
            && selected.args.is_empty()
            && matches!(&*selected.receiver, syn::Expr::Path(path) if path.path.is_ident("runtime"))
            && initializer.method == "initialize"
            && initializer.args.is_empty()
            && matches!(&*initializer.receiver, syn::Expr::Path(path) if path.path.is_ident("runtime"))
            && current.method == "sql_read"
            && current.args.len() == 1
            && matches!(&*current.receiver, syn::Expr::Path(path) if path.path.is_ident("runtime"))
            && matches!(&current.args[0], syn::Expr::Closure(closure)
                if closure.inputs.len() == 1
                && matches!(&closure.inputs[0], syn::Pat::Ident(input) if input.ident == "db")
                && matches!(&*closure.body, syn::Expr::Call(call)
                    if matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("validate_listener_snapshot"))
                    && call.args.len() == 2
                    && matches!(&call.args[0], syn::Expr::Path(path) if path.path.is_ident("runtime"))
                    && matches!(&call.args[1], syn::Expr::Path(path) if path.path.is_ident("db"))))
    }

    #[test]
    fn native_listener_requires_the_actual_current_sql_owner_instead_of_an_initializer_or_noop() {
        let source = syn::parse_file(include_str!("web.rs")).unwrap();
        let admission = source
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "admit_listener_storage" => {
                    Some(&*item.block)
                }
                _ => None,
            })
            .unwrap();
        assert!(native_admission_is_preserved(admission));
        let mut skipped = admission.clone();
        *skipped.stmts.last_mut().unwrap() = syn::Stmt::Expr(syn::parse_quote!(Ok(())), None);
        assert!(!native_admission_is_preserved(&skipped));
        let mut initializer = admission.clone();
        *initializer.stmts.last_mut().unwrap() =
            syn::Stmt::Expr(syn::parse_quote!(runtime.initialize()), None);
        assert!(!native_admission_is_preserved(&initializer));
        let mut noop = admission.clone();
        *noop.stmts.last_mut().unwrap() =
            syn::Stmt::Expr(syn::parse_quote!(runtime.sql_read(|_| Ok(()))), None);
        assert!(!native_admission_is_preserved(&noop));
        let mut ignored = admission.clone();
        *ignored.stmts.last_mut().unwrap() = syn::Stmt::Expr(
            syn::parse_quote!(runtime.sql_read(|db| {
                let _ = validate_listener_snapshot(runtime, db);
                Ok(())
            })),
            None,
        );
        assert!(!native_admission_is_preserved(&ignored));

        let binder = source.items.iter().find_map(|item| match item {
            syn::Item::Impl(item) if matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("LocalServer")) => {
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == "bind_listener" => Some(&item.block),
                    _ => None,
                })
            }, _ => None,
        }).unwrap();
        fn calls_admission(body: &syn::Block) -> bool {
            use syn::visit::Visit;
            #[derive(Default)]
            struct Calls {
                admission: usize,
                initializer: usize,
            }
            impl<'ast> Visit<'ast> for Calls {
                fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                    if matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("admit_listener_storage"))
                    {
                        self.admission += 1;
                    }
                    syn::visit::visit_expr_call(self, call);
                }
                fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                    if call.method == "initialize" {
                        self.initializer += 1;
                    }
                    syn::visit::visit_expr_method_call(self, call);
                }
            }
            let mut calls = Calls::default();
            calls.visit_block(body);
            let direct: Vec<_> = body.stmts.iter().enumerate().filter_map(|(index, statement)| {
                let syn::Stmt::Expr(syn::Expr::Try(propagated), _) = statement else { return None; };
                let syn::Expr::Call(call) = &*propagated.expr else { return None; };
                (matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("admit_listener_storage"))
                    && call.args.len() == 1
                    && matches!(&call.args[0], syn::Expr::Reference(reference)
                        if reference.mutability.is_none()
                        && matches!(&*reference.expr, syn::Expr::Path(path) if path.path.is_ident("runtime"))))
                    .then_some(index)
            }).collect();
            let host = body.stmts.iter().position(|statement| matches!(statement,
                syn::Stmt::Local(local) if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "host")));
            calls.admission == 1
                && calls.initializer == 0
                && direct.len() == 1
                && host.is_some_and(|host| direct[0] < host)
        }
        assert!(calls_admission(binder));
        let mut restored = binder.clone();
        restored
            .stmts
            .insert(0, syn::parse_quote!(runtime.initialize()?;));
        assert!(!calls_admission(&restored));
        let position = binder.stmts.iter().position(|statement| matches!(statement,
            syn::Stmt::Expr(syn::Expr::Try(tried), _)
                if matches!(&*tried.expr, syn::Expr::Call(call)
                    if matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("admit_listener_storage"))))).unwrap();
        for replacement in [
            syn::parse_quote!(if false {
                admit_listener_storage(&runtime)?;
            }),
            syn::parse_quote!(let _ = admit_listener_storage(&runtime);),
        ] {
            let mut skipped = binder.clone();
            skipped.stmts[position] = replacement;
            assert!(!calls_admission(&skipped));
        }
        let mut late = binder.clone();
        let admission = late.stmts.remove(position);
        late.stmts.push(admission);
        assert!(!calls_admission(&late));
    }

    #[test]
    fn startup_refusal_has_only_closed_labels_and_known_completion_emits_nothing() -> Result<()> {
        let stages = [
            NativeStartupStep::Selection,
            NativeStartupStep::InitialStorage,
            NativeStartupStep::RuntimeAdmission,
            NativeStartupStep::RuntimePostcheck,
            NativeStartupStep::Configuration,
            NativeStartupStep::Providers,
            NativeStartupStep::Receiver,
            NativeStartupStep::Edge,
            NativeStartupStep::Verifier,
            NativeStartupStep::Host,
            NativeStartupStep::Contracts,
            NativeStartupStep::ListenerStore,
            NativeStartupStep::Ingress,
            NativeStartupStep::Presentation,
            NativeStartupStep::Routes,
            NativeStartupStep::Appearance,
            NativeStartupStep::SessionSecret,
            NativeStartupStep::Mount,
            NativeStartupStep::HostParts,
        ];
        let mut codes = std::collections::BTreeSet::new();
        for stage in stages {
            let mut observed = NativeStartupObservation::new(true, stage);
            let line = observed.line().context("refusal line")?;
            assert!(line.len() <= 256);
            let text = std::str::from_utf8(&line)?;
            let data: Value = serde_json::from_str(
                text.strip_prefix("day2-native-app-startup-refusal ")
                    .unwrap(),
            )?;
            assert_eq!(data.as_object().unwrap().len(), 3);
            assert_eq!(data["format"], "day2_native_app_startup_refusal_v1");
            assert_eq!(data["outcome"], "not_completed");
            assert!(codes.insert(data["stage"].as_str().unwrap().to_owned()));
            observed.complete();
            assert!(observed.line().is_none());
        }
        let mut inactive = NativeStartupObservation::new(false, NativeStartupStep::Providers);
        inactive.enter(NativeStartupStep::SessionSecret);
        assert!(inactive.line().is_none());
        Ok(())
    }
}
