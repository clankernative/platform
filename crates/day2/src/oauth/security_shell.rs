//! Isolated browser approval for an external provider account. The shell has
//! its own origin and short-lived cookie; app sessions never authorize it.

#[cfg(test)]
use super::approval_registry;
use super::{
    admission, approval_keys, connect, external, profiles, registration, shell_oidc,
    shell_transport,
};
use crate::{artifact::Instance, iap, managed_credentials::browser as credentials};
use crate::{managed_credentials::crypto::KeyLease, store::open, web_security};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::to_bytes,
    extract::Request,
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use day2_capabilities::{
    Digest,
    oauth::{ConnectionRequirement, ProviderPermissionContract},
};
use maud::{DOCTYPE, html};
use std::{
    collections::HashMap,
    future::Future,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
};

const COOKIE: &str = "__Host-day2_security_shell";
const PREFIX: &str = "/oauth/approvals/";
const SESSION_SECONDS: i64 = 300;
const MAX_SESSIONS: usize = 1024;

pub(crate) trait ShellGuard: Send + Sync {
    fn check(&self, now: i64) -> Result<()>;
}

struct NoAppFacts;

impl admission::OutboundReadiness for NoAppFacts {
    fn current(
        &self,
        _: &day2_capabilities::oauth::OutboundConnectionBinding,
        _: &day2_capabilities::oauth::ConnectionSlotKey,
        _: i64,
    ) -> Result<Option<profiles::OutboundInstanceEvidence>> {
        Ok(None)
    }
}

/// The host registry resolves these current, admitted values on each request.
/// Request fields never select a requirement, key, registration or account.
pub(crate) struct ApprovalContext {
    pub db: PathBuf,
    pub intent: connect::ConnectIntent,
    pub binding: connect::CallbackBinding,
    pub requirement: ConnectionRequirement,
    pub permission: ProviderPermissionContract,
    pub reviewed: profiles::ReviewedBrowserCodeProfile,
    pub instance: profiles::OutboundInstanceEvidence,
    pub custody_key: KeyLease,
    pub shell_key: external::ShellApprovalKeyLease,
}

impl ApprovalContext {
    pub(super) fn qualification(&self) -> profiles::OutboundQualification<'_> {
        profiles::OutboundQualification {
            intent: &self.intent,
            binding: &self.binding,
            requirement: &self.requirement,
            permission: &self.permission,
            reviewed: &self.reviewed,
            instance: &self.instance,
        }
    }
}

pub(crate) trait ApprovalRegistry: Send + Sync {
    fn resolve(&self, attempt: &str, now: i64) -> Result<Option<ApprovalContext>>;
}

/// The caller must verify an interactive reauthentication event at the shell
/// edge. An ordinary IAP assertion or the app's web session is insufficient:
/// neither proves when the human last authenticated.
pub(crate) trait FreshAuthenticator: Send + Sync {
    fn identify(&self, headers: &HeaderMap, now: i64) -> Result<iap::Verified>;
    fn begin(
        &self,
        identity: &iap::Verified,
        attempt: &str,
        challenge: &Digest,
        now: i64,
    ) -> Result<ReauthStart>;
    fn complete(
        &self,
        _query: &str,
        _identity: &iap::Verified,
        _now: i64,
    ) -> Result<shell_oidc::Reauthenticated> {
        anyhow::bail!("reauthentication callback unavailable")
    }
}

pub(crate) enum ReauthStart {
    #[cfg(test)]
    Authenticated(FreshHuman),
    Redirect(String),
}

pub(crate) struct FreshHuman {
    pub human: String,
    pub subject: String,
    pub authenticated_at: i64,
}

#[derive(Clone)]
struct ShellSession {
    attempt: String,
    human: String,
    subject: String,
    challenge: Digest,
    preview: Digest,
    authenticated_at: i64,
    expires_at: i64,
    csrf: String,
}

/// Mount this router only behind the dedicated HTTPS security origin. The
/// listener must not be shared with the app's route dispatcher.
pub(crate) struct SecurityShell {
    origin: String,
    authority: String,
    approvals: Arc<dyn shell_transport::ShellApprovals>,
    signer: Arc<dyn shell_transport::ApprovalSigner>,
    authenticator: Arc<dyn FreshAuthenticator>,
    sessions: Mutex<HashMap<String, ShellSession>>,
    credentials: Option<Arc<credentials::Registry>>,
    canaries: Option<Arc<registration::shell::Canaries>>,
    guard: Option<Arc<dyn ShellGuard>>,
}

pub(crate) struct RegistrationShell {
    pub shell: Arc<SecurityShell>,
    pub signer: Arc<admission::ArtifactShellSigner>,
    pub canaries: Arc<registration::shell::Canaries>,
}

struct RegistrationPublication {
    signer: Arc<admission::ArtifactShellSigner>,
    approvals: Arc<shell_transport::RemoteApprovals>,
    guard: Option<Arc<dyn ShellGuard>>,
}

impl registration::shell::ReceiptPublisher for RegistrationPublication {
    fn publish(&self, receipt: &registration::Receipt, headers: &HeaderMap, _: i64) -> Result<()> {
        let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        if let Some(guard) = &self.guard {
            guard.check(now)?;
        }
        self.signer
            .publish_registration(receipt, self.approvals.as_ref(), headers, now)
    }
}

impl SecurityShell {
    /// The ordinary GKE launcher uses one immutable admitted selection, empty
    /// receipts and the dedicated shell identity. Target pins are desired
    /// metadata; native edge guards run before authenticated dispatch and again
    /// after provider probes, before publication.
    pub(crate) fn from_gke_runtime(
        instance_path: &Path,
        runner: &Path,
    ) -> Result<RegistrationShell> {
        let selected = admission::QualifiedConnections::from_instance_file(
            instance_path,
            &super::google::catalog()?,
        )?;
        let instance = selected.instance();
        super::clients::shell_secret_containers(instance)?;
        instance
            .oauth_runtime
            .as_ref()
            .context("OAuth runtime missing")?
            .shell_resources
            .as_ref()
            .context("security shell resources missing")?;
        let account = &instance
            .oauth_shell_transport
            .as_ref()
            .context("OAuth shell transport missing")?
            .service_account;
        let tokens = Arc::new(approval_keys::GkeMetadataAccessTokens::selected(account)?);
        let facts = Arc::new(admission::live::ShellFacts::from_gke(
            instance,
            tokens.clone(),
        )?);
        let targets = selected.google_targets(facts.selection())?;
        ensure!(
            !targets.is_empty(),
            "security shell has no selected registrations"
        );
        for target in &targets {
            let expected = target.registration_evidence()?;
            let mut current = false;
            for binding in instance
                .apps
                .values()
                .flat_map(|app| app.oauth_connections.values())
            {
                if target.publication_matches(
                    &binding.registration.id,
                    &admission::binding_namespace(binding)?,
                ) && binding.registration == expected.registration
                {
                    current = true;
                }
            }
            ensure!(current, "security shell registration selection changed");
        }
        let origin = instance.security_edge()?.1.origin.clone();
        let (mut shell, signer, approvals) = Self::from_selected(selected)?;
        Arc::get_mut(&mut shell)
            .context("security shell already shared")?
            .guard = Some(facts.clone());
        let readiness = Arc::new(registration::GoogleReadiness::new(Arc::new(NoAppFacts)));
        let canaries = Arc::new(
            registration::shell::Canaries::new(&origin, targets, runner, tokens, readiness)?
                .with_publication(Arc::new(RegistrationPublication {
                    signer: signer.clone(),
                    approvals,
                    guard: Some(facts),
                })),
        );
        Ok(RegistrationShell {
            shell: shell.with_registration(canaries.clone())?,
            signer,
            canaries,
        })
    }

    /// Compose the shell from the exact instance-selected artifacts and keys.
    /// This is an explicit GKE host entry point, not an application route or a
    /// readiness assertion. The shell has no app storage paths or custody keys.
    pub(crate) fn from_gke_instance(
        instance_path: &Path,
        catalog: &admission::ReviewedCatalog,
    ) -> Result<(Arc<Self>, Arc<admission::ArtifactShellSigner>)> {
        let selected = admission::QualifiedConnections::from_instance_file(instance_path, catalog)?;
        let (shell, signer, _) = Self::from_selected(selected)?;
        Ok((shell, signer))
    }

    /// One admitted snapshot supplies both the ordinary approval shell and its
    /// Google qualification routes. The launcher still supplies independently
    /// qualified shell evidence and its native registration receipt registry.
    pub(crate) fn from_gke_with_registration(
        instance_path: &Path,
        shell: &profiles::SecurityShellEvidence,
        runner: &Path,
        readiness: Arc<registration::GoogleReadiness>,
    ) -> Result<RegistrationShell> {
        let selected = admission::QualifiedConnections::from_instance_file(
            instance_path,
            &super::google::catalog()?,
        )?;
        let targets = selected.google_targets(shell)?;
        let origin = selected.instance().security_edge()?.1.origin.clone();
        let tokens = Arc::new(approval_keys::GkeMetadataAccessTokens::selected(
            &selected
                .instance()
                .oauth_shell_transport
                .as_ref()
                .context("OAuth shell transport missing")?
                .service_account,
        )?);
        let (shell, signer, approvals) = Self::from_selected(selected)?;
        let canaries = Arc::new(
            registration::shell::Canaries::new(&origin, targets, runner, tokens, readiness)?
                .with_publication(Arc::new(RegistrationPublication {
                    signer: signer.clone(),
                    approvals,
                    guard: None,
                })),
        );
        Ok(RegistrationShell {
            shell: shell.with_registration(canaries.clone())?,
            signer,
            canaries,
        })
    }

    fn from_selected(
        selected: admission::QualifiedConnections,
    ) -> Result<(
        Arc<Self>,
        Arc<admission::ArtifactShellSigner>,
        Arc<shell_transport::RemoteApprovals>,
    )> {
        let instance = selected.instance().clone();
        let tokens = Arc::new(approval_keys::GkeMetadataAccessTokens::selected(
            &instance
                .oauth_shell_transport
                .as_ref()
                .context("OAuth shell transport missing")?
                .service_account,
        )?);
        let bearers = Arc::new(super::workload::IapWorkload::from_gke_instance(&instance)?);
        let signer = Arc::new(admission::ArtifactShellSigner::with_gcp(
            selected,
            tokens.clone(),
        )?);
        let (identity, edge) = instance.security_edge()?;
        let origin = format!("{}/", edge.origin);
        let (client_id, exchange) = super::clients::reauthentication(&instance, tokens)?;
        let authenticator = Arc::new(shell_oidc::GoogleFreshAuthenticator::new(
            &edge.iap_audience,
            &identity.hosted_domain,
            &origin,
            client_id,
            exchange,
        )?);
        let approvals = Arc::new(shell_transport::RemoteApprovals::from_instance(
            &instance, bearers,
        )?);
        Ok((
            Self::with_transport(origin, approvals.clone(), signer.clone(), authenticator)?,
            signer,
            approvals,
        ))
    }

    #[cfg(test)]
    pub(crate) fn new(
        origin: String,
        registry: Arc<approval_registry::StoredApprovalRegistry>,
        authenticator: Arc<dyn FreshAuthenticator>,
    ) -> Result<Arc<Self>> {
        let local = Arc::new(approval_registry::LocalShellApprovals(registry));
        Self::with_transport(origin, local.clone(), local, authenticator)
    }

    pub(crate) fn with_transport(
        origin: String,
        approvals: Arc<dyn shell_transport::ShellApprovals>,
        signer: Arc<dyn shell_transport::ApprovalSigner>,
        authenticator: Arc<dyn FreshAuthenticator>,
    ) -> Result<Arc<Self>> {
        let url = url::Url::parse(&origin)?;
        ensure!(
            url.scheme() == "https"
                && format!("{}/", url.origin().ascii_serialization()) == origin
                && url.username().is_empty()
                && url.password().is_none(),
            "security shell requires a canonical HTTPS origin"
        );
        let authority = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_owned(),
        };
        ensure!(!authority.is_empty(), "security shell authority missing");
        Ok(Arc::new(Self {
            origin: url.origin().ascii_serialization(),
            authority,
            approvals,
            signer,
            authenticator,
            sessions: Mutex::new(HashMap::new()),
            credentials: None,
            canaries: None,
            guard: None,
        }))
    }

    /// Attach the same installation's selected local credential adapter before
    /// serving. OAuth retains its separately configured private transport; both
    /// flows share this isolated edge and fresh OIDC verifier.
    pub(crate) fn with_credentials(
        mut self: Arc<Self>,
        registry: Arc<credentials::Registry>,
    ) -> Result<Arc<Self>> {
        ensure!(
            registry.origin() == self.origin,
            "credential registry security origin mismatch"
        );
        Arc::get_mut(&mut self)
            .context("security shell already shared")?
            .credentials = Some(registry);
        Ok(self)
    }

    pub(crate) async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        self.serve_bounded(
            listener,
            32,
            Arc::new(AtomicBool::new(true)),
            std::future::pending(),
        )
        .await
    }

    pub(crate) async fn serve_bounded(
        self: Arc<Self>,
        listener: TcpListener,
        concurrency: usize,
        admission: Arc<AtomicBool>,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> Result<()> {
        ensure!(
            (1..=32).contains(&concurrency),
            "invalid security shell concurrency"
        );
        let capacity = Arc::new(Semaphore::new(concurrency));
        let router_capacity = capacity.clone();
        let router = Router::new().fallback(move |request: Request| {
            let shell = self.clone();
            let admission = admission.clone();
            let capacity = router_capacity.clone();
            async move {
                let path = request.uri().path();
                if matches!(path, "/health/live" | "/health/ready") {
                    let status =
                        if request.method() != Method::GET || request.uri().query().is_some() {
                            StatusCode::BAD_REQUEST
                        } else if path == "/health/ready" && !admission.load(Ordering::Acquire) {
                            StatusCode::SERVICE_UNAVAILABLE
                        } else {
                            StatusCode::OK
                        };
                    return protected(status.into_response());
                }
                if !admission.load(Ordering::Acquire) {
                    return protected(StatusCode::SERVICE_UNAVAILABLE.into_response());
                }
                let Ok(permit) = capacity.try_acquire_owned() else {
                    return protected(StatusCode::SERVICE_UNAVAILABLE.into_response());
                };
                shell.handle(request, permit, admission).await
            }
        });
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown)
            .await?;
        // Detached HTTP requests may have an unabortable native operation. Its
        // permit remains held through completion, including browser disconnect.
        let _drained = capacity.acquire_many(concurrency.try_into()?).await?;
        Ok(())
    }

    /// The native launcher supplies live shell-qualified targets and a private
    /// receipt registry. Instance metadata alone cannot construct those proofs.
    pub(crate) fn with_registration(
        mut self: Arc<Self>,
        canaries: Arc<registration::shell::Canaries>,
    ) -> Result<Arc<Self>> {
        ensure!(
            canaries.origin() == self.origin,
            "registration shell origin mismatch"
        );
        Arc::get_mut(&mut self)
            .context("security shell already shared")?
            .canaries = Some(canaries);
        Ok(self)
    }

    async fn handle(
        self: Arc<Self>,
        request: Request,
        permit: OwnedSemaphorePermit,
        admission: Arc<AtomicBool>,
    ) -> Response {
        let (parts, body) = request.into_parts();
        let body = match tokio::time::timeout(Duration::from_secs(3), to_bytes(body, 4096)).await {
            Ok(Ok(body)) => body,
            Ok(Err(_)) => return protected(StatusCode::PAYLOAD_TOO_LARGE.into_response()),
            Err(_) => return protected(StatusCode::REQUEST_TIMEOUT.into_response()),
        };
        let at = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(time) => time.as_secs() as i64,
            Err(_) => return protected(StatusCode::SERVICE_UNAVAILABLE.into_response()),
        };
        let method = parts.method;
        let path = parts.uri.path().to_owned();
        let query = parts.uri.query().map(str::to_owned);
        let headers = parts.headers;
        let response = tokio::task::spawn_blocking(move || {
            // A disconnected browser cannot release capacity while its native
            // provider operation is still running and cannot be cancelled.
            let _permit = permit;
            ensure!(
                admission.load(Ordering::Acquire),
                "security shell is draining"
            );
            self.dispatch(&method, &path, query.as_deref(), &headers, &body, at)
        })
        .await;
        protected(match response {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => StatusCode::FORBIDDEN.into_response(),
            Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        })
    }

    pub(super) fn dispatch(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        body: &[u8],
        at: i64,
    ) -> Result<Response> {
        ensure!(
            headers.get_all(header::HOST).iter().count() == 1
                && headers
                    .get(header::HOST)
                    .and_then(|value| value.to_str().ok())
                    == Some(self.authority.as_str())
                && !headers.contains_key("x-http-method-override"),
            "invalid security shell request"
        );
        let identity = self.authenticator.identify(headers, at)?;
        if let Some(guard) = &self.guard {
            guard.check(at)?;
        }
        if registration::shell::reserved(path) {
            return self
                .canaries
                .as_ref()
                .context("registration campaign unavailable")?
                .dispatch(method, path, query, headers, body, &identity, at);
        }
        if path == shell_oidc::GoogleOidc::callback_path() {
            ensure!(
                *method == Method::GET && body.is_empty(),
                "invalid reauthentication callback method"
            );
            return self.reauth_callback(
                query.context("missing reauthentication callback")?,
                headers,
                &identity,
                at,
            );
        }
        ensure!(query.is_none(), "security shell query refused");
        if let Some(attempt) = path.strip_prefix(credentials::PREFIX) {
            ensure!(
                !attempt.is_empty()
                    && attempt.len() <= 128
                    && attempt
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "invalid credential attempt"
            );
            return self.credential_dispatch(method, attempt, headers, body, &identity, at);
        }
        let attempt = path.strip_prefix(PREFIX).unwrap_or_default();
        if attempt.is_empty()
            || attempt.len() > 128
            || !attempt
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Ok(StatusCode::NOT_FOUND.into_response());
        }
        match *method {
            Method::GET => {
                ensure!(body.is_empty(), "GET body refused");
                self.page(attempt, headers, &identity, at)
            }
            Method::POST => {
                ensure!(
                    headers.get_all(header::ORIGIN).iter().count() == 1
                        && headers
                            .get(header::ORIGIN)
                            .and_then(|value| value.to_str().ok())
                            == Some(self.origin.as_str())
                        && headers
                            .get(header::CONTENT_TYPE)
                            .and_then(|value| value.to_str().ok())
                            == Some("application/x-www-form-urlencoded"),
                    "security shell form origin or type mismatch"
                );
                self.confirm(attempt, headers, body, &identity, at)
            }
            _ => Ok((
                StatusCode::METHOD_NOT_ALLOWED,
                [(header::ALLOW, "GET, POST")],
            )
                .into_response()),
        }
    }

    fn pending(
        &self,
        attempt: &str,
        identity: &iap::Verified,
        headers: &HeaderMap,
        at: i64,
    ) -> Result<Option<shell_transport::ApprovalView>> {
        let Some(view) = self.approvals.pending(attempt, identity, headers, at)? else {
            return Ok(None);
        };
        ensure!(
            view.attempt() == attempt
                && view.shell_origin == format!("{}/", self.origin)
                && view.app_origin != format!("{}/", self.origin),
            "security shell registry origin mismatch"
        );
        view.validate(identity)?;
        Ok(Some(view))
    }

    fn page(
        &self,
        attempt: &str,
        headers: &HeaderMap,
        identity: &iap::Verified,
        at: i64,
    ) -> Result<Response> {
        let Some(pending) = self.pending(attempt, identity, headers, at)? else {
            return Ok(StatusCode::NOT_FOUND.into_response());
        };
        ensure!(
            identity.email == pending.human(),
            "shell human does not own pending approval"
        );
        let (session, issued): (ShellSession, Option<String>) = match self
            .read_session(headers, at)?
        {
            Some(session) if valid_session(&session, &pending, identity, at) => (session, None),
            _ => {
                match self
                    .authenticator
                    .begin(identity, attempt, pending.challenge(), at)?
                {
                    #[cfg(test)]
                    ReauthStart::Authenticated(human) => {
                        let (session, token) = self.issue_session(&pending, identity, human, at)?;
                        (session, Some(token))
                    }
                    ReauthStart::Redirect(url) => {
                        return Ok(
                            (StatusCode::SEE_OTHER, [(header::LOCATION, url)]).into_response()
                        );
                    }
                }
            }
        };
        let account = &pending.observed;
        let scopes = &pending.scopes;
        let markup = html! {
            (DOCTYPE)
            html lang="en" {
                head { meta charset="utf-8"; title { "Approve external account" } }
                body {
                    main {
                        h1 { "Approve external account" }
                        p { "Confirm the provider identity for this connection." }
                        dl {
                            dt { "Connection" } dd { (pending.logical_id) }
                            dt { "Purpose" } dd { (pending.usage) }
                            dt { "Issuer" } dd { (account.issuer) }
                            dt { "Subject" } dd { (account.subject) }
                            dt { "Tenant" } dd { (account.tenant) }
                            dt { "Display email" } dd { (account.display_email) }
                        }
                        h2 { "Accepted provider scopes" }
                        ul { @for scope in scopes { li { (scope) } } }
                        form method="post" action=(path_for(attempt)) {
                            input type="hidden" name="csrf" value=(session.csrf);
                            input type="hidden" name="challenge" value=(pending.challenge().as_str());
                            button type="submit" { "Approve this account" }
                        }
                    }
                }
            }
        };
        let mut response = (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            markup.into_string(),
        )
            .into_response();
        if let Some(token) = issued {
            response.headers_mut().insert(header::SET_COOKIE, format!(
                "{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}"
            ).parse()?);
        }
        Ok(response)
    }

    fn issue_session(
        &self,
        pending: &shell_transport::ApprovalView,
        identity: &iap::Verified,
        human: FreshHuman,
        at: i64,
    ) -> Result<(ShellSession, String)> {
        ensure!(
            human.human == pending.human()
                && human.human == identity.email
                && human.subject == identity.subject
                && human.authenticated_at > pending.quarantined_at()
                && human.authenticated_at <= at
                && at - human.authenticated_at <= SESSION_SECONDS,
            "fresh shell authentication required"
        );
        let token = web_security::random()?;
        let session = ShellSession {
            attempt: pending.attempt().to_owned(),
            human: human.human,
            subject: human.subject,
            challenge: pending.challenge().clone(),
            preview: pending.digest()?,
            authenticated_at: human.authenticated_at,
            expires_at: human.authenticated_at + SESSION_SECONDS,
            csrf: web_security::random()?,
        };
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("shell session lock failed"))?;
        sessions.retain(|_, value| at < value.expires_at);
        ensure!(
            sessions.len() < MAX_SESSIONS,
            "shell session capacity reached"
        );
        sessions.insert(
            Digest::new(token.as_bytes()).as_str().to_owned(),
            session.clone(),
        );
        Ok((session, token))
    }

    fn reauth_callback(
        &self,
        query: &str,
        headers: &HeaderMap,
        identity: &iap::Verified,
        at: i64,
    ) -> Result<Response> {
        let proof = self.authenticator.complete(query, identity, at)?;
        if proof.attempt.starts_with("credential-") {
            let registry = self
                .credentials
                .as_ref()
                .context("credential security shell unavailable")?;
            let (_, pending) = registry
                .resolve(&proof.attempt, identity, at)?
                .context("credential intent unavailable")?;
            ensure!(
                proof.challenge == pending.challenge()?,
                "credential reauthentication challenge changed"
            );
            let (_, token) = self.credential_session(
                &pending,
                identity,
                FreshHuman {
                    human: proof.human,
                    subject: identity.subject.clone(),
                    authenticated_at: proof.authenticated_at,
                },
                at,
            )?;
            return credential_redirect(&pending.path(), Some(&token));
        }
        let Some(pending) = self.pending(&proof.attempt, identity, headers, at)? else {
            return Ok(StatusCode::NOT_FOUND.into_response());
        };
        ensure!(
            proof.challenge == *pending.challenge(),
            "reauthentication challenge changed"
        );
        let (_, token) = self.issue_session(
            &pending,
            identity,
            FreshHuman {
                human: proof.human,
                subject: identity.subject.clone(),
                authenticated_at: proof.authenticated_at,
            },
            at,
        )?;
        let mut response = (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, path_for(pending.attempt()))],
        )
            .into_response();
        response.headers_mut().insert(header::SET_COOKIE, format!(
            "{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}"
        ).parse()?);
        Ok(response)
    }

    fn confirm(
        &self,
        attempt: &str,
        headers: &HeaderMap,
        body: &[u8],
        identity: &iap::Verified,
        at: i64,
    ) -> Result<Response> {
        let Some(pending) = self.pending(attempt, identity, headers, at)? else {
            return Ok(StatusCode::NOT_FOUND.into_response());
        };
        let Some(token) = cookie_token(headers)? else {
            return Ok(StatusCode::UNAUTHORIZED.into_response());
        };
        let key = Digest::new(token.as_bytes()).as_str().to_owned();
        let fields = web_security::fields(body)?;
        ensure!(
            fields.len() == 2
                && fields.get("challenge").map(String::as_str)
                    == Some(pending.challenge().as_str()),
            "security shell challenge mismatch"
        );
        let session = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| anyhow::anyhow!("shell session lock failed"))?;
            let Some(session) = sessions.get(&key) else {
                return Ok(StatusCode::UNAUTHORIZED.into_response());
            };
            ensure!(
                valid_session(session, &pending, identity, at)
                    && fields.get("csrf") == Some(&session.csrf),
                "security shell session or CSRF mismatch"
            );
            sessions.remove(&key).expect("checked shell session")
        };
        let evidence = self.signer.attest(
            &pending,
            Digest::new(token.as_bytes()),
            session.authenticated_at,
            at,
        )?;
        let approved = self
            .approvals
            .confirm(&pending, identity, headers, evidence, at)?;
        let mut response = if approved {
            (StatusCode::OK, "External account approved.").into_response()
        } else {
            StatusCode::CONFLICT.into_response()
        };
        response.headers_mut().insert(
            header::SET_COOKIE,
            format!("{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0").parse()?,
        );
        Ok(response)
    }

    fn read_session(&self, headers: &HeaderMap, at: i64) -> Result<Option<ShellSession>> {
        let Some(token) = cookie_token(headers)? else {
            return Ok(None);
        };
        let key = Digest::new(token.as_bytes());
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("shell session lock failed"))?;
        Ok(sessions
            .get(key.as_str())
            .filter(|session| at < session.expires_at)
            .cloned())
    }

    fn credential_session(
        &self,
        pending: &credentials::Pending,
        identity: &iap::Verified,
        human: FreshHuman,
        at: i64,
    ) -> Result<(ShellSession, String)> {
        ensure!(
            human.human == pending.actor
                && human.human == identity.email
                && human.subject == identity.subject
                && human.authenticated_at > pending.created_at
                && human.authenticated_at <= at
                && at - human.authenticated_at <= SESSION_SECONDS,
            "fresh credential authentication required"
        );
        let token = web_security::random()?;
        let session = ShellSession {
            attempt: pending.attempt.clone(),
            human: human.human,
            subject: human.subject,
            challenge: pending.challenge()?,
            preview: pending.challenge()?,
            authenticated_at: human.authenticated_at,
            expires_at: (human.authenticated_at + SESSION_SECONDS).min(pending.expires_at),
            csrf: web_security::random()?,
        };
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("shell session lock failed"))?;
        sessions.retain(|_, value| at < value.expires_at);
        ensure!(
            sessions.len() < MAX_SESSIONS,
            "shell session capacity reached"
        );
        sessions.insert(
            Digest::new(token.as_bytes()).as_str().to_owned(),
            session.clone(),
        );
        Ok((session, token))
    }

    fn credential_dispatch(
        &self,
        method: &Method,
        attempt: &str,
        headers: &HeaderMap,
        body: &[u8],
        identity: &iap::Verified,
        at: i64,
    ) -> Result<Response> {
        let registry = self
            .credentials
            .as_ref()
            .context("credential security shell unavailable")?;
        let Some((runtime, pending)) = registry.resolve(attempt, identity, at)? else {
            return Ok(StatusCode::NOT_FOUND.into_response());
        };
        let challenge = pending.challenge()?;
        let valid = |session: &ShellSession| {
            session.attempt == attempt
                && session.human == identity.email
                && session.subject == identity.subject
                && session.challenge == challenge
                && session.preview == challenge
                && session.authenticated_at > pending.created_at
                && session.authenticated_at <= at
                && at < session.expires_at
        };
        if *method == Method::GET {
            ensure!(body.is_empty(), "credential GET body refused");
            let (session, issued): (ShellSession, Option<String>) =
                match self.read_session(headers, at)? {
                    Some(session) if valid(&session) => (session, None),
                    _ => match self
                        .authenticator
                        .begin(identity, attempt, &challenge, at)?
                    {
                        #[cfg(test)]
                        ReauthStart::Authenticated(human) => {
                            let (session, token) =
                                self.credential_session(&pending, identity, human, at)?;
                            (session, Some(token))
                        }
                        ReauthStart::Redirect(url) => {
                            return Ok(
                                (StatusCode::SEE_OTHER, [(header::LOCATION, url)]).into_response()
                            );
                        }
                    },
                };
            let confirmed = {
                use rusqlite::OptionalExtension;
                open(runtime.db())?
                    .query_row(
                        "SELECT status='success' FROM day2_invocations WHERE id=?1",
                        [&pending.invocation],
                        |row| row.get::<_, bool>(0),
                    )
                    .optional()?
                    .unwrap_or(false)
            };
            let contract = runtime.artifact().contract();
            let app = contract
                .app_contract
                .as_ref()
                .context("credential command contract missing")?;
            let intent = &app
                .operations
                .get(&pending.operation)
                .context("credential command missing")?
                .intent;
            let family = contract
                .credential_manifest
                .iter()
                .find(|family| family.id.as_str() == pending.family)
                .context("credential family declaration missing")?;
            let principal = match family.profile {
                day2_capabilities::credentials::ManagedProfile::Client => "Named client",
                day2_capabilities::credentials::ManagedProfile::Personal => {
                    "Your personal identity"
                }
                _ => anyhow::bail!("unsupported interactive credential profile"),
            };
            let action_title = match pending.intent.action() {
                "issue" => "Create credential",
                "rotate" => "Rotate credential",
                "revoke" => "Revoke credential",
                _ => anyhow::bail!("unsupported credential action"),
            };
            let has_delivery = open(runtime.db())?.query_row(
                "SELECT EXISTS(SELECT 1 FROM day2_credential_receipts WHERE invocation=?1 AND action IN ('issue','rotate'))",
                [&pending.invocation], |row| row.get::<_, bool>(0))?;
            let markup = html! { (DOCTYPE) html lang="en" {
                head { meta charset="utf-8"; title { "Credential action" } }
                body { main {
                    h1 { @if confirmed { "Credential action completed" } @else { (action_title) } }
                    p { (intent.title) }
                    p { (intent.usage.purpose) }
                    dl { dt { "Application" } dd { (runtime.app()) } dt { "Command" } dd { (pending.operation) }
                        dt { "Family" } dd { (pending.family) } dt { "Action" } dd { (action_title) }
                        dt { "Confirmed intent" } dd { (serde_json::to_string(&pending.intent)?) }
                        dt { "Principal" } dd { (principal) }
                        dt { "Recipient" } dd { (identity.email) }
                        dt { "Lifetime" } dd { (family.lifetime_seconds) " seconds" } }
                    h2 { "Fixed permissions" }
                    ul { @for operation in family.roots.keys() {
                        li { @if let Some(operation) = app.operations.get(operation) { (operation.intent.title) " — " }
                            code { (operation) } }
                    } }
                    @if !confirmed {
                        p { "Confirm this product command. The credential transition and product writes commit together." }
                        h2 { "Command input" }
                        pre { (pending.input.to_string()) }
                    }
                    form method="post" action=(pending.path()) {
                        input type="hidden" name="csrf" value=(session.csrf);
                        input type="hidden" name="challenge" value=(challenge.as_str());
                        @if confirmed {
                            @if has_delivery { button type="submit" name="action" value="reveal" { "Reveal key" } }
                            button type="submit" name="action" value="acknowledge" { "Finish" }
                        } @else { button type="submit" name="action" value="confirm" { (action_title) } }
                    }
                } }
            } };
            let mut response = (
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                markup.into_string(),
            )
                .into_response();
            if let Some(token) = issued {
                response
                    .headers_mut()
                    .insert(header::SET_COOKIE, credential_cookie(&token)?.parse()?);
            }
            return Ok(response);
        }
        if *method != Method::POST {
            return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
        ensure!(
            headers.get_all(header::ORIGIN).iter().count() == 1
                && headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) == Some(&self.origin)
                && headers.get_all(header::CONTENT_TYPE).iter().count() == 1
                && headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    == Some("application/x-www-form-urlencoded")
                && headers
                    .get("sec-fetch-site")
                    .is_none_or(|value| value == "same-origin"),
            "credential form origin or type mismatch"
        );
        let token = cookie_token(headers)?.context("credential shell session required")?;
        let session = self
            .read_session(headers, at)?
            .context("credential shell session expired")?;
        let fields = web_security::fields(body)?;
        ensure!(
            valid(&session)
                && fields.len() == 3
                && fields.get("csrf") == Some(&session.csrf)
                && fields.get("challenge").map(String::as_str) == Some(challenge.as_str()),
            "credential session, challenge or CSRF mismatch"
        );
        let session_binding = format!(
            "shell-{}",
            Digest::new(token.as_bytes())
                .as_str()
                .trim_start_matches("sha256:")
        );
        match fields.get("action").map(String::as_str) {
            Some("confirm") => {
                let outcome = credentials::confirm(
                    &runtime,
                    &pending,
                    identity,
                    &session_binding,
                    session.authenticated_at,
                    at,
                )?;
                ensure!(
                    outcome.status == "success",
                    "credential product command failed"
                );
                credential_redirect(&pending.path(), None)
            }
            Some("reveal") => {
                let secret = credentials::deliver(
                    &runtime,
                    &pending,
                    identity,
                    &session_binding,
                    at,
                    false,
                )?
                .context("credential delivery unavailable")?;
                let markup = html! { (DOCTYPE) html lang="en" {
                    head { meta charset="utf-8"; title { "Your credential key" } }
                    body { main { h1 { "Your credential key" } p { "Copy this key before closing delivery." }
                        pre { (secret) }
                        form method="post" action=(pending.path()) {
                            input type="hidden" name="csrf" value=(session.csrf);
                            input type="hidden" name="challenge" value=(challenge.as_str());
                            button type="submit" name="action" value="acknowledge" { "I saved the key; close delivery" }
                        }
                    } }
                } };
                Ok((
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    markup.into_string(),
                )
                    .into_response())
            }
            Some("acknowledge") => {
                credentials::deliver(&runtime, &pending, identity, &session_binding, at, true)?;
                self.sessions
                    .lock()
                    .map_err(|_| anyhow::anyhow!("shell session lock failed"))?
                    .remove(Digest::new(token.as_bytes()).as_str());
                let instance = Instance::load(runtime.instance_path())?;
                let (_, edge) = instance.edge(runtime.app())?;
                let path = pending
                    .product_return
                    .as_deref()
                    .map(|page| runtime.artifact().page(page).map(|page| page.path.as_str()))
                    .transpose()?
                    .unwrap_or("/");
                let mut response = credential_redirect(&format!("{}{path}", edge.origin), None)?;
                response.headers_mut().insert(
                    header::SET_COOKIE,
                    format!("{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")
                        .parse()?,
                );
                Ok(response)
            }
            _ => anyhow::bail!("unknown credential action"),
        }
    }
}

fn credential_cookie(token: &str) -> Result<String> {
    ensure!(token_shape(token), "invalid credential shell cookie");
    Ok(format!(
        "{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}"
    ))
}

fn credential_redirect(path: &str, token: Option<&str>) -> Result<Response> {
    let mut response = (StatusCode::SEE_OTHER, [(header::LOCATION, path)]).into_response();
    if let Some(token) = token {
        response
            .headers_mut()
            .insert(header::SET_COOKIE, credential_cookie(token)?.parse()?);
    }
    Ok(response)
}

fn valid_session(
    session: &ShellSession,
    pending: &shell_transport::ApprovalView,
    identity: &iap::Verified,
    at: i64,
) -> bool {
    session.attempt == pending.attempt()
        && session.human == pending.human()
        && session.human == identity.email
        && session.subject == identity.subject
        && session.challenge == *pending.challenge()
        && pending
            .digest()
            .is_ok_and(|digest| digest == session.preview)
        && session.authenticated_at > pending.quarantined_at()
        && at >= session.authenticated_at
        && at < session.expires_at
        && at - session.authenticated_at <= SESSION_SECONDS
}

fn cookie_token(headers: &HeaderMap) -> Result<Option<String>> {
    let mut token = None;
    for header in headers.get_all(header::COOKIE) {
        for cookie in cookie::Cookie::split_parse(header.to_str()?) {
            let cookie = cookie?;
            if cookie.name() == COOKIE {
                ensure!(token.is_none(), "ambiguous shell session");
                ensure!(token_shape(cookie.value()), "invalid shell session");
                token = Some(cookie.value().to_owned());
            }
        }
    }
    Ok(token)
}

fn token_shape(token: &str) -> bool {
    token.len() == 43
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn path_for(attempt: &str) -> String {
    format!("{PREFIX}{attempt}")
}

fn protected(mut response: Response) -> Response {
    for (name, value) in [
        (
            "content-security-policy",
            "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=()",
        ),
        ("cross-origin-resource-policy", "same-origin"),
    ] {
        response
            .headers_mut()
            .insert(name, value.parse().expect("static security header"));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_credentials::authority::{SelectedAuthority, Selection};
    use crate::oauth::approval_registry::{
        ApprovalKeyMaterial, ApprovalKeyProvider, ApprovalKeyPurpose, ApprovalKeyRef,
    };
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct NoOAuth;
    impl shell_transport::ShellApprovals for NoOAuth {
        fn pending(
            &self,
            _: &str,
            _: &iap::Verified,
            _: &HeaderMap,
            _: i64,
        ) -> Result<Option<shell_transport::ApprovalView>> {
            Ok(None)
        }

        fn confirm(
            &self,
            _: &shell_transport::ApprovalView,
            _: &iap::Verified,
            _: &HeaderMap,
            _: external::FreshExternalApproval,
            _: i64,
        ) -> Result<bool> {
            anyhow::bail!("OAuth confirmation unavailable in credential fixture")
        }
    }

    impl shell_transport::ApprovalSigner for NoOAuth {
        fn attest(
            &self,
            _: &shell_transport::ApprovalView,
            _: Digest,
            _: i64,
            _: i64,
        ) -> Result<external::FreshExternalApproval> {
            anyhow::bail!("OAuth signer unavailable in credential fixture")
        }
    }

    struct BrowserIdentity {
        fresh: bool,
    }
    impl FreshAuthenticator for BrowserIdentity {
        fn identify(&self, headers: &HeaderMap, _: i64) -> Result<iap::Verified> {
            Ok(iap::Verified {
                email: headers
                    .get("test-email")
                    .map(|v| v.to_str())
                    .transpose()?
                    .unwrap_or("alice@example.com")
                    .into(),
                subject: headers
                    .get("test-subject")
                    .map(|v| v.to_str())
                    .transpose()?
                    .unwrap_or("accounts.google.com:google-alice")
                    .into(),
            })
        }
        fn begin(
            &self,
            identity: &iap::Verified,
            _: &str,
            _: &Digest,
            now: i64,
        ) -> Result<ReauthStart> {
            if !self.fresh {
                return Ok(ReauthStart::Redirect(
                    "https://accounts.google.com/reauthenticate".into(),
                ));
            }
            Ok(ReauthStart::Authenticated(FreshHuman {
                human: identity.email.clone(),
                subject: identity.subject.clone(),
                authenticated_at: now,
            }))
        }
    }

    struct BrowserKeys(AtomicUsize);
    struct HoldingGuard {
        calls: AtomicUsize,
        entered: tokio::sync::Notify,
        released: Mutex<bool>,
        release: std::sync::Condvar,
    }

    impl ShellGuard for HoldingGuard {
        fn check(&self, _: i64) -> Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            let mut released = self.released.lock().unwrap();
            while !*released {
                let (next, timeout) = self
                    .release
                    .wait_timeout(released, Duration::from_secs(10))
                    .unwrap();
                ensure!(!timeout.timed_out(), "fixture native dispatch deadline");
                released = next;
            }
            Ok(())
        }
    }

    fn isolated_shell() -> Result<Arc<SecurityShell>> {
        let approvals = Arc::new(NoOAuth);
        SecurityShell::with_transport(
            "https://security.example.com/".into(),
            approvals.clone(),
            approvals,
            Arc::new(BrowserIdentity { fresh: false }),
        )
    }

    #[tokio::test]
    async fn guarded_http_keeps_capacity_through_disconnect_and_drains_native_dispatch()
    -> Result<()> {
        let guard = Arc::new(HoldingGuard {
            calls: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            released: Mutex::new(false),
            release: std::sync::Condvar::new(),
        });
        let mut shell = isolated_shell()?;
        Arc::get_mut(&mut shell).unwrap().guard = Some(guard.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let admission = Arc::new(AtomicBool::new(true));
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(shell.serve_bounded(listener, 1, admission.clone(), async {
            let _ = shutdown.await;
        }));
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        assert_eq!(
            client
                .get(format!("{endpoint}/oauth/approvals/attempt"))
                .header(header::HOST, "other.example.com")
                .send()
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(guard.calls.load(Ordering::SeqCst), 0);
        let browser = tokio::spawn({
            let client = client.clone();
            let endpoint = endpoint.clone();
            async move {
                client
                    .get(format!("{endpoint}/oauth/approvals/attempt"))
                    .header(header::HOST, "security.example.com")
                    .send()
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(3), guard.entered.notified()).await?;
        browser.abort();
        assert_eq!(
            client
                .get(format!("{endpoint}/oauth/approvals/attempt"))
                .header(header::HOST, "security.example.com")
                .send()
                .await?
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let health = client
            .get(format!("{endpoint}/health/ready"))
            .send()
            .await?;
        assert_eq!(health.status(), StatusCode::OK);
        assert_eq!(health.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(guard.calls.load(Ordering::SeqCst), 1);
        admission.store(false, Ordering::Release);
        assert_eq!(
            client
                .get(format!("{endpoint}/health/ready"))
                .send()
                .await?
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            client
                .get(format!("{endpoint}/oauth/approvals/attempt"))
                .header(header::HOST, "security.example.com")
                .send()
                .await?
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let _ = stop.send(());
        tokio::task::yield_now().await;
        assert!(!server.is_finished());
        *guard.released.lock().unwrap() = true;
        guard.release.notify_all();
        tokio::time::timeout(Duration::from_secs(3), server).await???;
        Ok(())
    }

    #[tokio::test]
    async fn shell_http_bounds_body_size_and_body_wait_before_native_dispatch() -> Result<()> {
        let shell = isolated_shell()?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(shell.serve_bounded(
            listener,
            1,
            Arc::new(AtomicBool::new(true)),
            async {
                let _ = shutdown.await;
            },
        ));
        let client = reqwest::Client::builder().no_proxy().build()?;
        assert_eq!(
            client
                .post(format!("http://{address}/oauth/approvals/attempt"))
                .header(header::HOST, "security.example.com")
                .body(vec![b'x'; 4097])
                .send()
                .await?
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let response = tokio::task::spawn_blocking(move || -> Result<String> {
            use std::io::{Read, Write};
            let mut socket = std::net::TcpStream::connect(address)?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            socket.write_all(b"POST /oauth/approvals/attempt HTTP/1.1\r\nHost: security.example.com\r\nContent-Length: 10\r\nConnection: close\r\n\r\n")?;
            let mut response = String::new();
            socket.read_to_string(&mut response)?;
            Ok(response)
        }).await??;
        assert!(response.starts_with("HTTP/1.1 408"), "{response}");
        let _ = stop.send(());
        tokio::time::timeout(Duration::from_secs(3), server).await???;
        Ok(())
    }

    impl ApprovalKeyProvider for BrowserKeys {
        fn load(
            &self,
            reference: &ApprovalKeyRef,
            purpose: ApprovalKeyPurpose,
        ) -> Result<ApprovalKeyMaterial> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(ApprovalKeyMaterial {
                binding: reference.binding.clone(),
                version: reference.version.clone(),
                purpose,
                bytes: match purpose {
                    ApprovalKeyPurpose::CustodyVerifier => [29; 32],
                    ApprovalKeyPurpose::CustodyEncryption => [41; 32],
                    _ => anyhow::bail!("unexpected credential key purpose"),
                },
            })
        }
    }

    struct BrowserWorld {
        _directory: tempfile::TempDir,
        runtime: crate::store::Runtime,
        instance: Instance,
        authority: Arc<SelectedAuthority>,
        selections: Vec<Selection>,
        keys: Arc<BrowserKeys>,
        now: i64,
    }

    fn browser_world(quota: u32) -> Result<BrowserWorld> {
        let artifact = PathBuf::from(
            std::env::var_os("DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT")
                .context("credential fixture artifact required")?,
        );
        let directory = tempfile::tempdir()?;
        let runtime = crate::development::create_for(
            &artifact,
            &directory.path().join("instance"),
            None,
            "alice@example.com",
        )?;
        let mut instance = Instance::load(runtime.instance_path())?;
        instance.identity = Some(crate::artifact::IdentityProvider {
            scheme: crate::artifact::IdentityScheme::GoogleIap,
            hosted_domain: "example.com".into(),
        });
        instance.security_shell = Some(crate::artifact::Edge {
            origin: "https://security.example.com".into(),
            iap_audience: "/projects/1/global/backendServices/2".into(),
        });
        instance.apps.get_mut("app").unwrap().edge = Some(crate::artifact::Edge {
            origin: "https://app.example.com".into(),
            iap_audience: "/projects/1/global/backendServices/3".into(),
        });
        let app = instance.apps.get_mut("app").unwrap();
        app.readers.insert("credential_client:client_keys".into());
        app.writers.insert("credential_client:client_keys".into());
        app.authority
            .as_mut()
            .context("browser authority")?
            .operations
            .get_mut("credential_metadata.ping")
            .context("credential root")?
            .actors
            .insert("credential_client:client_keys".into());
        app.authority
            .as_mut()
            .context("browser authority")?
            .operations
            .get_mut("credential_metadata.record_use")
            .context("credential command root")?
            .actors
            .insert("credential_client:client_keys".into());
        std::fs::write(runtime.instance_path(), serde_json::to_vec(&instance)?)?;
        let runtime = crate::store::Runtime::load(runtime.instance_path(), runtime.app())?;
        let current = crate::authority_state::current(&open(runtime.db())?)?;
        crate::authority_state::apply_desired(
            &runtime,
            &crate::authority_state::LocalOperator::assert_local("alice@example.com")?,
            "credential-api-membership",
            Some(current.stamp),
        )?;
        let now = runtime.host().now_ms()?.div_euclid(1000);
        let active = crate::authority_state::current(&open(runtime.db())?)?;
        let selections: Vec<_> = active
            .document
            .credentials
            .values()
            .map(|family| Selection {
                binding: family.binding.clone(),
                management: family.management.clone(),
                security_origin: "https://security.example.com".into(),
                verifier: ApprovalKeyRef {
                    binding: family.binding.verifier.clone(),
                    version: "verifier_1".into(),
                },
                encryption: ApprovalKeyRef {
                    binding: family.binding.custody.clone(),
                    version: "encryption_1".into(),
                },
                security_epoch: 1,
                observed_at: now - 2,
                ready_until: now + 298,
                grant_until: now + 7200,
                max_active_lineages: quota,
                issuers: BTreeMap::from([(
                    "alice@example.com".into(),
                    "accounts.google.com:google-alice".into(),
                )]),
            })
            .collect();
        let keys = Arc::new(BrowserKeys(AtomicUsize::new(0)));
        let authority = Arc::new(SelectedAuthority::new(selections.clone(), keys.clone())?);
        let runtime = runtime.with_credential_authority(authority.clone());
        Ok(BrowserWorld {
            _directory: directory,
            runtime,
            instance,
            authority,
            selections,
            keys,
            now,
        })
    }

    fn credential_shell(world: &BrowserWorld, fresh: bool) -> Result<Arc<SecurityShell>> {
        let oauth = Arc::new(NoOAuth);
        SecurityShell::with_transport(
            "https://security.example.com/".into(),
            oauth.clone(),
            oauth,
            Arc::new(BrowserIdentity { fresh }),
        )?
        .with_credentials(Arc::new(credentials::Registry::new(
            &world.instance,
            vec![world.runtime.clone()],
            world.authority.clone(),
        )?))
    }

    fn credential_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "security.example.com".parse().unwrap());
        headers.insert(
            header::ORIGIN,
            "https://security.example.com".parse().unwrap(),
        );
        headers.insert(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        headers
    }

    fn navigate(
        world: &BrowserWorld,
        shell: &SecurityShell,
        operation: &str,
        id: &str,
    ) -> Result<(String, HeaderMap, ShellSession)> {
        navigate_input(
            world,
            shell,
            operation,
            id,
            &serde_json::json!({"label":"Transcription client"}),
        )
    }

    fn navigate_input(
        world: &BrowserWorld,
        shell: &SecurityShell,
        operation: &str,
        id: &str,
        input: &serde_json::Value,
    ) -> Result<(String, HeaderMap, ShellSession)> {
        let url = credentials::start(
            &world.runtime,
            operation,
            "alice@example.com",
            id,
            input,
            None,
            world.now - 1,
        )?;
        let path = url::Url::parse(&url)?.path().to_owned();
        let mut headers = credential_headers();
        let response = shell.dispatch(&Method::GET, &path, None, &headers, &[], world.now)?;
        ensure!(
            response.status() == StatusCode::OK,
            "credential navigation failed"
        );
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()?
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        headers.insert(header::COOKIE, cookie.parse()?);
        let session = shell
            .read_session(&headers, world.now)?
            .context("shell session missing")?;
        Ok((path, headers, session))
    }

    fn credential_body(session: &ShellSession, action: &str) -> Vec<u8> {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("csrf", &session.csrf)
            .append_pair("challenge", session.challenge.as_str())
            .append_pair("action", action)
            .finish()
            .into_bytes()
    }

    async fn credential_token(response: Response) -> Result<String> {
        let html = String::from_utf8(to_bytes(response.into_body(), 8192).await?.to_vec())?;
        Ok(html
            .split_once("<pre>")
            .context("protected token")?
            .1
            .split_once("</pre>")
            .context("protected token end")?
            .0
            .into())
    }

    #[tokio::test]
    async fn credential_browser_rotates_revokes_and_fences_accepted_work() -> Result<()> {
        use crate::managed_credentials::ingress;
        for kind in ["client", "personal"] {
            let world = browser_world(1)?;
            let shell = credential_shell(&world, true)?;
            let (issue_path, issue_headers, issue_session) = navigate(
                &world,
                &shell,
                &format!("credential_metadata.create_{kind}"),
                "issued",
            )?;
            shell.dispatch(
                &Method::POST,
                &issue_path,
                None,
                &issue_headers,
                &credential_body(&issue_session, "confirm"),
                world.now,
            )?;
            let issued = world.runtime.execute("issued", crate::store::Fault::None)?;
            let old_token = credential_token(shell.dispatch(
                &Method::POST,
                &issue_path,
                None,
                &issue_headers,
                &credential_body(&issue_session, "reveal"),
                world.now,
            )?)
            .await?;
            let admission = ingress::prepare(
                &world.runtime,
                "credential_metadata.record_use",
                &old_token,
                world.now,
            )?;
            world.runtime.accept_credential(
                "credential_metadata.record_use",
                &admission,
                "old-work",
                &serde_json::json!({"note":"use_before_rotation"}),
                world.now,
            )?;
            let expected = serde_json::json!({"lineage":issued.result["lineage"],"head":issued.result["version"],"revision":1});
            let (path, headers, session) = navigate_input(
                &world,
                &shell,
                &format!("credential_metadata.rotate_{kind}"),
                "rotated",
                &expected,
            )?;
            let mut wrong = headers.clone();
            wrong.insert(header::ORIGIN, "https://app.example.com".parse()?);
            assert!(
                shell
                    .dispatch(
                        &Method::POST,
                        &path,
                        None,
                        &wrong,
                        &credential_body(&session, "confirm"),
                        world.now
                    )
                    .is_err()
            );
            assert_eq!(
                shell
                    .dispatch(
                        &Method::POST,
                        &path,
                        None,
                        &headers,
                        &credential_body(&session, "confirm"),
                        world.now
                    )?
                    .status(),
                StatusCode::SEE_OTHER
            );
            let rotated = world
                .runtime
                .execute("rotated", crate::store::Fault::None)?;
            assert_eq!(rotated.result["status"], "rotated");
            assert_eq!(rotated.result["lineage"], issued.result["lineage"]);
            // Quota one permits replacement: rotation adds no lineage.
            assert_eq!(
                open(world.runtime.db())?.query_row(
                    "SELECT count(*) FROM day2_credential_lineages",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                1
            );
            assert!(
                ingress::prepare(
                    &world.runtime,
                    "credential_metadata.ping",
                    &old_token,
                    world.now
                )
                .is_err()
            );
            let reopened =
                crate::store::Runtime::load(world.runtime.instance_path(), world.runtime.app())?
                    .with_credential_authority(world.authority.clone());
            assert_eq!(
                reopened
                    .execute("old-work", crate::store::Fault::None)?
                    .status,
                "blocked"
            );
            assert_eq!(
                open(world.runtime.db())?.query_row(
                    "SELECT count(*) FROM use_receipts",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                0
            );
            let before = world.keys.0.load(Ordering::SeqCst);
            assert!(
                shell
                    .dispatch(
                        &Method::POST,
                        &issue_path,
                        None,
                        &issue_headers,
                        &credential_body(&issue_session, "reveal"),
                        world.now
                    )
                    .is_err()
            );
            assert_eq!(world.keys.0.load(Ordering::SeqCst), before);
            let public = shell.dispatch(&Method::GET, &path, None, &headers, &[], world.now)?;
            let public = String::from_utf8(to_bytes(public.into_body(), 32_768).await?.to_vec())?;
            assert!(!public.contains("d2c1."));
            let new_token = credential_token(shell.dispatch(
                &Method::POST,
                &path,
                None,
                &headers,
                &credential_body(&session, "reveal"),
                world.now,
            )?)
            .await?;
            let recovered = credential_token(shell.dispatch(
                &Method::POST,
                &path,
                None,
                &headers,
                &credential_body(&session, "reveal"),
                world.now,
            )?)
            .await?;
            assert_eq!(new_token, recovered);
            let current = ingress::prepare(
                &world.runtime,
                "credential_metadata.record_use",
                &new_token,
                world.now,
            )?;
            world.runtime.accept_credential(
                "credential_metadata.record_use",
                &current,
                "new-work",
                &serde_json::json!({"note":"use_before_revoke"}),
                world.now,
            )?;
            // A stale predecessor produces Conflict and no new delivery; finish remains available.
            let (stale_path, stale_headers, stale_session) = navigate_input(
                &world,
                &shell,
                &format!("credential_metadata.rotate_{kind}"),
                "stale",
                &expected,
            )?;
            shell.dispatch(
                &Method::POST,
                &stale_path,
                None,
                &stale_headers,
                &credential_body(&stale_session, "confirm"),
                world.now,
            )?;
            assert_eq!(
                world
                    .runtime
                    .execute("stale", crate::store::Fault::None)?
                    .result["status"],
                "conflict"
            );
            assert!(
                shell
                    .dispatch(
                        &Method::POST,
                        &stale_path,
                        None,
                        &stale_headers,
                        &credential_body(&stale_session, "reveal"),
                        world.now
                    )
                    .is_err()
            );
            shell.dispatch(
                &Method::POST,
                &stale_path,
                None,
                &stale_headers,
                &credential_body(&stale_session, "acknowledge"),
                world.now,
            )?;
            let (revoke_path, revoke_headers, revoke_session) = navigate_input(
                &world,
                &shell,
                &format!("credential_metadata.revoke_{kind}"),
                "revoked",
                &serde_json::json!({"lineage":issued.result["lineage"]}),
            )?;
            shell.dispatch(
                &Method::POST,
                &revoke_path,
                None,
                &revoke_headers,
                &credential_body(&revoke_session, "confirm"),
                world.now,
            )?;
            assert_eq!(
                world
                    .runtime
                    .execute("revoked", crate::store::Fault::None)?
                    .result["status"],
                "revoked"
            );
            let before = world.keys.0.load(Ordering::SeqCst);
            assert!(
                shell
                    .dispatch(
                        &Method::POST,
                        &revoke_path,
                        None,
                        &revoke_headers,
                        &credential_body(&revoke_session, "reveal"),
                        world.now
                    )
                    .is_err()
            );
            assert!(
                shell
                    .dispatch(
                        &Method::POST,
                        &path,
                        None,
                        &headers,
                        &credential_body(&session, "reveal"),
                        world.now
                    )
                    .is_err()
            );
            assert_eq!(world.keys.0.load(Ordering::SeqCst), before);
            assert!(
                ingress::prepare(
                    &world.runtime,
                    "credential_metadata.ping",
                    &new_token,
                    world.now
                )
                .is_err()
            );
            assert_eq!(
                reopened
                    .execute("new-work", crate::store::Fault::None)?
                    .status,
                "blocked"
            );
            shell.dispatch(
                &Method::POST,
                &revoke_path,
                None,
                &revoke_headers,
                &credential_body(&revoke_session, "acknowledge"),
                world.now,
            )?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn credential_api_admits_only_current_tokens_and_rechecks_durable_execution() -> Result<()>
    {
        use crate::managed_credentials::{ingress, store as credential_store};
        let world = browser_world(10)?;
        let shell = credential_shell(&world, true)?;
        let server =
            crate::web::LocalServer::bind(world.runtime.clone(), "alice@example.com", 0).await?;
        let origin = server.origin.clone();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(server.serve(async {
            let _ = stopped.await;
        }));
        let client = reqwest::Client::new();
        for (operation, id, family) in [
            (
                "credential_metadata.create_client",
                "api-client",
                "client_keys",
            ),
            (
                "credential_metadata.create_personal",
                "api-personal",
                "personal_keys",
            ),
        ] {
            let (path, headers, session) = navigate(&world, &shell, operation, id)?;
            shell.dispatch(
                &Method::POST,
                &path,
                None,
                &headers,
                &credential_body(&session, "confirm"),
                world.now,
            )?;
            let revealed = shell.dispatch(
                &Method::POST,
                &path,
                None,
                &headers,
                &credential_body(&session, "reveal"),
                world.now,
            )?;
            let html = String::from_utf8(to_bytes(revealed.into_body(), 8192).await?.to_vec())?;
            let token = html
                .split_once("<pre>")
                .context("protected token")?
                .1
                .split_once("</pre>")
                .context("protected token end")?
                .0
                .to_owned();
            let url = format!("{origin}{}credential_metadata.ping", ingress::PREFIX);
            let response = client.get(&url).bearer_auth(&token).send().await?;
            assert_eq!(response.status(), StatusCode::OK);
            let accepted = response.headers()["x-day2-invocation"].to_str()?.to_owned();
            assert_eq!(
                crate::json::decode::<serde_json::Value>(&response.bytes().await?)?,
                serde_json::json!({"ready":true})
            );
            let trace = world.runtime.trace(&accepted)?;
            assert_eq!(trace.request.context.authentication, "credential");
            let actor = &trace.request.context.actor;
            if family == "client_keys" {
                assert_eq!(crate::authority::client_family(actor), Some(family));
            } else {
                assert_eq!(actor, "alice@example.com");
            }
            let evidence: String = open(world.runtime.db())?.query_row(
                "SELECT evidence FROM day2_credential_origins WHERE invocation=?1",
                [&accepted],
                |row| row.get(0),
            )?;
            assert!(!evidence.contains(&token));
            assert!(!serde_json::to_string(&trace)?.contains(&token));
            let status_url = format!("{origin}{}invocations/{accepted}", ingress::PREFIX);
            assert_eq!(
                client
                    .get(&status_url)
                    .bearer_auth(&token)
                    .send()
                    .await?
                    .status(),
                StatusCode::OK
            );
            let command = format!("{origin}{}credential_metadata.record_use", ingress::PREFIX);
            let body = format!("{{\"note\":\"use_{id}\"}}");
            let before: i64 = open(world.runtime.db())?.query_row(
                "SELECT count(*) FROM use_receipts",
                [],
                |row| row.get(0),
            )?;
            let mut command_id = String::new();
            for _ in 0..2 {
                let response = client
                    .post(&command)
                    .bearer_auth(&token)
                    .header("content-type", "application/json")
                    .header("idempotency-key", format!("record-{id}"))
                    .body(body.clone())
                    .send()
                    .await?;
                assert_eq!(response.status(), StatusCode::OK);
                let current = response.headers()["x-day2-invocation"].to_str()?.to_owned();
                if command_id.is_empty() {
                    command_id = current;
                } else {
                    assert_eq!(command_id, current);
                }
            }
            let after: i64 = open(world.runtime.db())?.query_row(
                "SELECT count(*) FROM use_receipts",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(after, before + 1);
            assert_eq!(
                client
                    .post(&command)
                    .bearer_auth(&token)
                    .header("content-type", "application/json")
                    .header("idempotency-key", format!("record-{id}"))
                    .body("{\"note\":\"use_changed\"}")
                    .send()
                    .await?
                    .status(),
                StatusCode::CONFLICT
            );
            for (header, value) in [
                ("cookie", "session=forged"),
                ("origin", "https://app.example.com"),
                ("x-day2-act-as", "alice@example.com"),
                ("x-goog-iap-jwt-assertion", "forged"),
            ] {
                assert_eq!(
                    client
                        .get(&url)
                        .bearer_auth(&token)
                        .header(header, value)
                        .send()
                        .await?
                        .status(),
                    StatusCode::UNAUTHORIZED
                );
            }
            assert_eq!(
                client.get(&url).send().await?.status(),
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                client
                    .get(&url)
                    .bearer_auth("invalid")
                    .send()
                    .await?
                    .status(),
                StatusCode::UNAUTHORIZED
            );
            let management = format!(
                "{origin}{}credential_metadata.create_client",
                ingress::PREFIX
            );
            assert_eq!(
                client
                    .post(management)
                    .bearer_auth(&token)
                    .header("idempotency-key", "forbidden-management")
                    .header("content-type", "application/json")
                    .body("{\"label\":\"unapproved\"}")
                    .send()
                    .await?
                    .status(),
                StatusCode::UNAUTHORIZED
            );
            let pending = format!("pending-{family}");
            let admission = ingress::prepare(
                &world.runtime,
                "credential_metadata.ping",
                &token,
                world.now,
            )?;
            for change in ["epoch", "verifier", "unavailable", "account"] {
                if change == "account" && family != "personal_keys" {
                    continue;
                }
                let interrupted = format!("{change}-{family}");
                world.runtime.accept_credential(
                    "credential_metadata.ping",
                    &admission,
                    &interrupted,
                    &serde_json::json!({}),
                    world.now,
                )?;
                let mut changed = world.selections.clone();
                let selected = changed
                    .iter_mut()
                    .find(|selected| selected.binding.family.as_str() == family)
                    .context("selected family")?;
                match change {
                    "epoch" => selected.security_epoch += 1,
                    "verifier" => selected.verifier.version = "verifier_2".into(),
                    "account" => selected.issuers.clear(),
                    _ => changed.clear(),
                }
                world.authority.replace(changed)?;
                let response = client.get(&url).bearer_auth(&token).send().await?;
                assert_eq!(
                    response.status(),
                    if change == "unavailable" {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        StatusCode::UNAUTHORIZED
                    }
                );
                let outcome = world
                    .runtime
                    .execute(&interrupted, crate::store::Fault::None);
                if change == "unavailable" {
                    assert_eq!(
                        crate::error::classify(&outcome.unwrap_err()),
                        crate::error::Failure::CredentialUnavailable
                    );
                } else {
                    assert_eq!(outcome?.status, "blocked");
                }
                // Disposable snapshots simulate independent adapter decisions;
                // production epoch monotonicity needs its selected live adapter.
                world.authority.replace(world.selections.clone())?;
            }
            let missing = format!("missing-origin-{family}");
            world.runtime.accept_credential(
                "credential_metadata.ping",
                &admission,
                &missing,
                &serde_json::json!({}),
                world.now,
            )?;
            open(world.runtime.db())?.execute(
                "DELETE FROM day2_credential_origins WHERE invocation=?1",
                [&missing],
            )?;
            assert_eq!(
                world
                    .runtime
                    .execute(&missing, crate::store::Fault::None)?
                    .status,
                "blocked"
            );
            world.runtime.accept_credential(
                "credential_metadata.ping",
                &admission,
                &pending,
                &serde_json::json!({}),
                world.now,
            )?;
            let db = open(world.runtime.db())?;
            let lineage: String = db.query_row(
                "SELECT id FROM day2_credential_lineages WHERE family=?1",
                [family],
                |row| row.get(0),
            )?;
            let active = crate::authority_state::current(&db)?;
            let mut db = open(world.runtime.db())?;
            let tx = crate::write_queue::immediate(&mut db)?;
            credential_store::stage_revoke(
                &tx,
                &active.document.credentials[family].binding.namespace,
                &lineage,
            )?;
            tx.commit()?;
            // A token verified before revocation must fail the acceptance
            // writer's recheck as well as subsequent HTTP authentication.
            assert!(
                world
                    .runtime
                    .accept_credential(
                        "credential_metadata.ping",
                        &admission,
                        &format!("stale-admission-{family}"),
                        &serde_json::json!({}),
                        world.now
                    )
                    .is_err()
            );
            assert_eq!(
                client.get(&url).bearer_auth(&token).send().await?.status(),
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                client
                    .get(&status_url)
                    .bearer_auth(&token)
                    .send()
                    .await?
                    .status(),
                StatusCode::UNAUTHORIZED
            );
            // The already-admitted command cannot regain authority after restart.
            let reopened =
                crate::store::Runtime::load(world.runtime.instance_path(), world.runtime.app())?
                    .with_credential_authority(world.authority.clone());
            let outcome = reopened.execute(&pending, crate::store::Fault::None)?;
            assert_eq!(outcome.status, "blocked");
            let reason: String = open(reopened.db())?.query_row(
                "SELECT reason FROM day2_authority_blocks WHERE invocation=?1",
                [&pending],
                |row| row.get(0),
            )?;
            assert_eq!(reason, "credential_authority_changed");
            token.into_bytes().fill(0);
        }
        let _ = stop.send(());
        serving.await??;
        Ok(())
    }

    #[tokio::test]
    async fn credential_browser_issues_native_product_commands_and_protects_delivery() -> Result<()>
    {
        let world = browser_world(10)?;
        let shell = credential_shell(&world, true)?;
        for (operation, id) in [
            ("credential_metadata.create_client", "client-browser"),
            ("credential_metadata.create_personal", "personal-browser"),
        ] {
            let (path, headers, session) = navigate(&world, &shell, operation, id)?;
            let input = serde_json::json!({"label":"Transcription client"});
            assert!(
                world
                    .runtime
                    .accept(operation, "alice@example.com", id, &input, world.now)
                    .is_err()
            );
            let before = world.keys.0.load(Ordering::SeqCst);
            let confirm = credential_body(&session, "confirm");
            let token = cookie_token(&headers)?.context("credential cookie missing")?;
            let session_key = Digest::new(token.as_bytes());
            shell
                .sessions
                .lock()
                .unwrap()
                .get_mut(session_key.as_str())
                .unwrap()
                .preview = Digest::of(&"changed-credential-preview")?;
            assert!(
                shell
                    .dispatch(&Method::POST, &path, None, &headers, &confirm, world.now)
                    .is_err()
            );
            assert_eq!(world.keys.0.load(Ordering::SeqCst), before);
            shell
                .sessions
                .lock()
                .unwrap()
                .get_mut(session_key.as_str())
                .unwrap()
                .preview = session.preview.clone();
            let mut wrong = headers.clone();
            wrong.insert(header::ORIGIN, "https://app.example.com".parse()?);
            assert!(
                shell
                    .dispatch(&Method::POST, &path, None, &wrong, &confirm, world.now)
                    .is_err()
            );
            assert_eq!(world.keys.0.load(Ordering::SeqCst), before);
            assert_eq!(
                shell
                    .dispatch(&Method::POST, &path, None, &headers, &confirm, world.now)?
                    .status(),
                StatusCode::SEE_OTHER
            );
            // Lost-response retry runs the identical accepted product invocation.
            assert_eq!(
                shell
                    .dispatch(&Method::POST, &path, None, &headers, &confirm, world.now)?
                    .status(),
                StatusCode::SEE_OTHER
            );
            let outcome = world.runtime.execute(id, crate::store::Fault::None)?;
            assert_eq!(outcome.status, "success", "{outcome:?}");
            assert!(!outcome.result.to_string().contains("d2c1."));
            assert!(!serde_json::to_string(&world.runtime.trace(id)?)?.contains("d2c1."));
            let get = shell.dispatch(&Method::GET, &path, None, &headers, &[], world.now)?;
            let page = String::from_utf8(to_bytes(get.into_body(), 8192).await?.to_vec())?;
            assert!(!page.contains("d2c1."));
            assert!(page.contains("credential_metadata.ping") && page.contains("3600 seconds"));
            let reveal = credential_body(&session, "reveal");
            let before = world.keys.0.load(Ordering::SeqCst);
            let mut wrong = headers.clone();
            wrong.insert("test-subject", "someone-else".parse()?);
            assert!(
                shell
                    .dispatch(&Method::POST, &path, None, &wrong, &reveal, world.now)
                    .is_err()
            );
            let mut wrong = headers.clone();
            wrong.append(header::COOKIE, headers[header::COOKIE].clone());
            assert!(
                shell
                    .dispatch(&Method::POST, &path, None, &wrong, &reveal, world.now)
                    .is_err()
            );
            let mut bad = session.clone();
            bad.csrf = "forged".into();
            assert!(
                shell
                    .dispatch(
                        &Method::POST,
                        &path,
                        None,
                        &headers,
                        &credential_body(&bad, "reveal"),
                        world.now
                    )
                    .is_err()
            );
            let mut bad = session.clone();
            bad.challenge = Digest::new(b"forged challenge");
            assert!(
                shell
                    .dispatch(
                        &Method::POST,
                        &path,
                        None,
                        &headers,
                        &credential_body(&bad, "reveal"),
                        world.now
                    )
                    .is_err()
            );
            assert!(
                shell
                    .dispatch(
                        &Method::POST,
                        &path,
                        Some("version=forged"),
                        &headers,
                        &reveal,
                        world.now
                    )
                    .is_err()
            );
            assert_eq!(world.keys.0.load(Ordering::SeqCst), before);
            // Receipt identity must still match the selected family's contract.
            let db = open(world.runtime.db())?;
            let contract: String = db.query_row(
                "SELECT family_contract FROM day2_credential_receipts WHERE invocation=?1",
                [id],
                |row| row.get(0),
            )?;
            db.execute(
                "UPDATE day2_credential_receipts SET family_contract='foreign' WHERE invocation=?1",
                [id],
            )?;
            assert!(
                shell
                    .dispatch(&Method::POST, &path, None, &headers, &reveal, world.now)
                    .is_err()
            );
            assert_eq!(world.keys.0.load(Ordering::SeqCst), before);
            db.execute(
                "UPDATE day2_credential_receipts SET family_contract=?1 WHERE invocation=?2",
                rusqlite::params![contract, id],
            )?;
            let response = protected(shell.dispatch(
                &Method::POST,
                &path,
                None,
                &headers,
                &reveal,
                world.now,
            )?);
            assert_eq!(response.headers()["cache-control"], "no-store");
            let html = String::from_utf8(to_bytes(response.into_body(), 8192).await?.to_vec())?;
            assert!(html.contains("d2c1."));
            assert!(!html.contains("ciphertext"));
            let acknowledge = credential_body(&session, "acknowledge");
            assert_eq!(
                shell
                    .dispatch(
                        &Method::POST,
                        &path,
                        None,
                        &headers,
                        &acknowledge,
                        world.now
                    )?
                    .headers()[header::LOCATION],
                "https://app.example.com/"
            );
            let before = world.keys.0.load(Ordering::SeqCst);
            assert!(
                shell
                    .dispatch(&Method::POST, &path, None, &headers, &reveal, world.now)
                    .is_err()
            );
            assert_eq!(world.keys.0.load(Ordering::SeqCst), before);
        }
        let db = open(world.runtime.db())?;
        let counts: (i64,i64) = db.query_row("SELECT (SELECT count(*) FROM entries), (SELECT count(*) FROM day2_credential_lineages)",[],|row| Ok((row.get(0)?,row.get(1)?)))?;
        assert_eq!(counts, (2, 2));
        let personal: String = db.query_row(
            "SELECT principal FROM day2_credential_lineages WHERE family='personal_keys'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(personal, "accounts.google.com:google-alice");
        Ok(())
    }

    #[test]
    fn credential_browser_requires_fresh_auth_and_current_readiness() -> Result<()> {
        let world = browser_world(1)?;
        let shell = credential_shell(&world, false)?;
        let url = credentials::start(
            &world.runtime,
            "credential_metadata.create_client",
            "alice@example.com",
            "fresh-required",
            &serde_json::json!({"label":"Client"}),
            None,
            world.now - 1,
        )?;
        let path = url::Url::parse(&url)?.path().to_owned();
        let headers = credential_headers();
        assert_eq!(
            shell
                .dispatch(&Method::GET, &path, None, &headers, &[], world.now)?
                .status(),
            StatusCode::SEE_OTHER
        );
        assert!(
            shell
                .dispatch(
                    &Method::POST,
                    &path,
                    None,
                    &headers,
                    b"action=confirm",
                    world.now
                )
                .is_err()
        );
        assert_eq!(world.keys.0.load(Ordering::SeqCst), 0);
        let shell = credential_shell(&world, true)?;
        let (path, headers, session) = navigate(
            &world,
            &shell,
            "credential_metadata.create_client",
            "current-required",
        )?;
        let mut selections = world.selections.clone();
        selections[0].security_epoch += 1;
        world.authority.replace(Vec::new())?;
        assert!(
            shell
                .dispatch(
                    &Method::POST,
                    &path,
                    None,
                    &headers,
                    &credential_body(&session, "confirm"),
                    world.now
                )
                .is_err()
        );
        assert_eq!(world.keys.0.load(Ordering::SeqCst), 0);
        world.authority.replace(world.selections.clone())?;
        assert_eq!(
            shell
                .dispatch(
                    &Method::POST,
                    &path,
                    None,
                    &headers,
                    &credential_body(&session, "confirm"),
                    world.now
                )?
                .status(),
            StatusCode::SEE_OTHER
        );
        world.authority.replace(selections)?;
        let before = world.keys.0.load(Ordering::SeqCst);
        assert!(
            shell
                .dispatch(
                    &Method::POST,
                    &path,
                    None,
                    &headers,
                    &credential_body(&session, "reveal"),
                    world.now
                )
                .is_err()
        );
        assert_eq!(world.keys.0.load(Ordering::SeqCst), before);
        world.authority.replace(world.selections.clone())?;
        let (path, headers, session) = navigate(
            &world,
            &shell,
            "credential_metadata.create_client",
            "over-quota",
        )?;
        assert!(
            shell
                .dispatch(
                    &Method::POST,
                    &path,
                    None,
                    &headers,
                    &credential_body(&session, "confirm"),
                    world.now
                )
                .is_err()
        );
        let db = open(world.runtime.db())?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM entries", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        Ok(())
    }

    #[tokio::test]
    async fn credential_app_navigation_only_freezes_canonical_intent() -> Result<()> {
        let world = browser_world(10)?;
        let session = crate::web_security::Session {
            hash: "test-app-session".into(),
            actor: "alice@example.com".into(),
            expires: world.now + 300,
            origin: None,
        };
        let catalog =
            crate::operation_catalog::Catalog::from_artifact(world.runtime.artifact().contract())?;
        let secret = [17; 32];
        let context = crate::web_api::RequestContext {
            runtime: &world.runtime,
            catalog: &catalog,
            secret: &secret,
            session: &session,
            origin: "https://app.example.com",
            at: world.now - 1,
        };
        let uri = "/api/security-actions".parse()?;
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://app.example.com".parse()?);
        headers.insert(header::CONTENT_TYPE, "application/json".parse()?);
        headers.insert("idempotency-key", "navigation".parse()?);
        let body = serde_json::json!({"operation":"credential_metadata.create_client","payload":"{\"label\":\"Client\"}","product_return":"keys"}).to_string();
        assert!(
            context
                .dispatch(&Method::POST, &uri, &headers, body.as_bytes())
                .is_err()
        );
        headers.insert(
            "x-csrf-token",
            crate::web_security::csrf(&secret, &session)?.parse()?,
        );
        let response = context.dispatch(&Method::POST, &uri, &headers, body.as_bytes())?;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let pending: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await?)?;
        let retry = context.dispatch(&Method::POST, &uri, &headers, body.as_bytes())?;
        let retried: serde_json::Value =
            serde_json::from_slice(&to_bytes(retry.into_body(), 8192).await?)?;
        assert_eq!(pending, retried);
        let path = url::Url::parse(pending["confirmation_url"].as_str().unwrap())?
            .path()
            .to_owned();
        assert!(path.starts_with(credentials::PREFIX));
        let mut changed: serde_json::Value = serde_json::from_str(&body)?;
        changed["payload"] = serde_json::json!("{\"label\":\"Other\"}");
        assert!(
            context
                .dispatch(
                    &Method::POST,
                    &uri,
                    &headers,
                    changed.to_string().as_bytes()
                )
                .is_err()
        );
        headers.insert("idempotency-key", "foreign-return".parse()?);
        changed["product_return"] = serde_json::json!("https://evil.example/");
        assert!(
            context
                .dispatch(
                    &Method::POST,
                    &uri,
                    &headers,
                    changed.to_string().as_bytes()
                )
                .is_err()
        );
        headers.insert("idempotency-key", "extra-subject".parse()?);
        changed["product_return"] = serde_json::json!("keys");
        changed["payload"] =
            serde_json::json!("{\"label\":\"Client\",\"subject\":\"someone-else\"}");
        assert!(
            context
                .dispatch(
                    &Method::POST,
                    &uri,
                    &headers,
                    changed.to_string().as_bytes()
                )
                .is_err()
        );
        let db = open(world.runtime.db())?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM day2_invocations", [], |row| row
                .get::<_, i64>(0))?,
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM day2_credential_lineages", [], |row| {
                row.get::<_, i64>(0)
            })?,
            0
        );
        assert_eq!(world.keys.0.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn cookie_parser_rejects_duplicate_or_malformed_shell_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, format!("{COOKIE}=bad").parse().unwrap());
        assert!(cookie_token(&headers).is_err());
        headers.clear();
        let token = web_security::random().unwrap();
        headers.append(header::COOKIE, format!("{COOKIE}={token}").parse().unwrap());
        headers.append(header::COOKIE, format!("{COOKIE}={token}").parse().unwrap());
        assert!(cookie_token(&headers).is_err());
    }

    #[test]
    fn shell_responses_are_locked_down() {
        let response = protected((StatusCode::OK, axum::body::Body::empty()).into_response());
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(
            response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
    }

    #[test]
    fn confirmation_session_is_bound_to_every_displayed_preview_field() {
        use crate::oauth::profiles::tests as fixtures;
        let facts = fixtures::external_fixture();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.sqlite");
        let mut db = rusqlite::Connection::open(&path).unwrap();
        let key = fixtures::exchange_key();
        fixtures::quarantine_external_fixture(&mut db, &facts, &key);
        let pending = crate::oauth::external::load_pending_external(&db, facts.input(), &key, 5)
            .unwrap()
            .unwrap();
        let shell_key = crate::oauth::external::ShellApprovalKeyLease::new(
            &[12; 32],
            "shell_v1".into(),
            pending.security_origin().clone(),
            pending.approval_binding().clone(),
        )
        .unwrap();
        let identity = iap::Verified {
            email: facts.intent.owner.clone(),
            subject: "accounts.google.com:12345".into(),
        };
        let context = ApprovalContext {
            db: path,
            intent: facts.intent,
            binding: facts.binding,
            requirement: facts.requirement,
            permission: facts.permission,
            reviewed: facts.reviewed,
            instance: facts.instance,
            custody_key: key,
            shell_key,
        };
        let view =
            shell_transport::ApprovalView::from_pending("app", &context, &pending, &identity)
                .unwrap();
        let session = ShellSession {
            attempt: view.attempt().into(),
            human: identity.email.clone(),
            subject: identity.subject.clone(),
            challenge: view.challenge().clone(),
            preview: view.digest().unwrap(),
            authenticated_at: 5,
            expires_at: 305,
            csrf: "fixture".into(),
        };
        assert!(valid_session(&session, &view, &identity, 6));
        for mutation in 0..6 {
            let mut changed = view.clone();
            match mutation {
                0 => changed.usage = "A different purpose".into(),
                1 => {
                    changed.scopes.insert("calendar.write".into());
                }
                2 => changed.observed.display_email = "other@example.com".into(),
                3 => changed.terms = Digest::of(&"retired terms").unwrap(),
                4 => changed.binding_namespace = "retired_binding".into(),
                5 => changed.app_origin = "https://other.example/".into(),
                _ => unreachable!(),
            }
            assert!(
                !valid_session(&session, &changed, &identity, 6),
                "mutation {mutation}"
            );
        }
    }
}
