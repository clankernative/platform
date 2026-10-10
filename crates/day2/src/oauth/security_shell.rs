//! Isolated browser approval for an external provider account. The shell has
//! its own origin and short-lived cookie; app sessions never authorize it.

#[cfg(test)]
use super::approval_registry;
use super::{
    admission, approval_keys, connect, external,
    fresh_auth::{FreshIntent, FreshPurpose, VerifiedAuthTime},
    profiles, registration, shell_oidc, shell_transport,
};
use crate::oauth::effects;
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
    time::Duration,
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
    fn begin(&self, identity: &iap::Verified, intent: FreshIntent, now: i64)
    -> Result<ReauthStart>;
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

#[cfg(test)]
pub(crate) struct FreshHuman {
    pub human: String,
    pub subject: String,
    pub authenticated_at: i64,
}

#[derive(Clone)]
pub(crate) struct ShellSession {
    attempt: String,
    human: String,
    subject: String,
    challenge: Digest,
    preview: Digest,
    authenticated_at: i64,
    expires_at: i64,
    csrf: String,
    proof: Arc<VerifiedAuthTime>,
    digest: Digest,
}

impl ShellSession {
    fn approval(
        view: &shell_transport::ApprovalView,
        identity: &iap::Verified,
        proof: VerifiedAuthTime,
        digest: Digest,
        csrf: String,
        at: i64,
    ) -> Result<Self> {
        proof.require_approval(view, identity)?;
        proof.require_current(at)?;
        Ok(Self {
            attempt: view.attempt().into(),
            human: proof.human().into(),
            subject: proof.subject().into(),
            challenge: view.challenge().clone(),
            preview: view.digest()?,
            authenticated_at: proof.authenticated_at(),
            expires_at: proof.deadline()?,
            csrf,
            proof: Arc::new(proof),
            digest,
        })
    }

    pub(in crate::oauth) fn require_approval(
        &self,
        view: &shell_transport::ApprovalView,
        at: i64,
    ) -> Result<()> {
        let identity = iap::Verified {
            email: self.proof.human().into(),
            subject: self.proof.subject().into(),
        };
        ensure!(
            valid_session(self, view, &identity, at),
            "fresh OAuth shell session changed or expired"
        );
        Ok(())
    }

    pub(in crate::oauth) fn digest(&self) -> Digest {
        self.digest.clone()
    }

    pub(in crate::oauth) fn authenticated_at(&self) -> i64 {
        self.proof.authenticated_at()
    }

    pub(in crate::oauth) fn observe_current(&self, entry_now: i64) -> Result<i64> {
        self.proof.observe_current(entry_now)
    }

    #[cfg(test)]
    pub(in crate::oauth) fn approval_signed_fixture(
        view: &shell_transport::ApprovalView,
        identity: &iap::Verified,
        google: shell_oidc::Reauthenticated,
        digest: Digest,
        at: i64,
    ) -> Result<Self> {
        Self::approval(
            view,
            identity,
            VerifiedAuthTime::from_google(google),
            digest,
            "signed fixture".into(),
            at,
        )
    }

    #[cfg(test)]
    pub(in crate::oauth) fn approval_fixture(
        view: &shell_transport::ApprovalView,
        identity: &iap::Verified,
        authenticated_at: i64,
        digest: Digest,
    ) -> Result<Self> {
        let proof = VerifiedAuthTime::from_google(shell_oidc::Reauthenticated::fixture(
            FreshIntent::approval(view, identity)?,
            identity.email.clone(),
            identity.subject.clone(),
            authenticated_at,
        ));
        Ok(Self {
            attempt: view.attempt().into(),
            human: identity.email.clone(),
            subject: identity.subject.clone(),
            challenge: view.challenge().clone(),
            preview: view.digest()?,
            authenticated_at,
            expires_at: proof.deadline()?,
            csrf: "fixture".into(),
            proof: Arc::new(proof),
            digest,
        })
    }
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
        let now = effects::wall_time()?;
        if let Some(guard) = &self.guard {
            guard.check(now).map_err(|error| {
                registration::QualificationFailure::at(
                    registration::QualificationStage::ShellReadiness,
                    error,
                )
            })?;
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
            &super::catalog::reviewed()?,
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
        let targets = selected.registration_targets(facts.selection())?;
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
        let readiness = Arc::new(registration::ProviderReadiness::new(Arc::new(NoAppFacts)));
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
        readiness: Arc<registration::ProviderReadiness>,
    ) -> Result<RegistrationShell> {
        let selected = admission::QualifiedConnections::from_instance_file(
            instance_path,
            &super::catalog::reviewed()?,
        )?;
        let targets = selected.registration_targets(shell)?;
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
        let captured = self
            .credentials
            .as_ref()
            .map_or_else(crate::managed_credentials::effects::capture, |registry| {
                registry.effects()
            });
        captured
            .run_async(self.handle_scoped(request, permit, admission))
            .await
    }

    async fn handle_scoped(
        self: Arc<Self>,
        request: Request,
        permit: OwnedSemaphorePermit,
        admission: Arc<AtomicBool>,
    ) -> Response {
        let (parts, body) = request.into_parts();
        let body = match effects::timeout(Duration::from_secs(3), to_bytes(body, 4096)).await {
            Ok(Ok(body)) => body,
            Ok(Err(_)) => return protected(StatusCode::PAYLOAD_TOO_LARGE.into_response()),
            Err(_) => return protected(StatusCode::REQUEST_TIMEOUT.into_response()),
        };
        let at = match effects::wall_time() {
            Ok(time) => time,
            Err(_) => return protected(StatusCode::SERVICE_UNAVAILABLE.into_response()),
        };
        let method = parts.method;
        let path = parts.uri.path().to_owned();
        let query = parts.uri.query().map(str::to_owned);
        let headers = parts.headers;
        let response = crate::managed_credentials::effects::spawn_blocking(move || {
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
            Ok(Err(error)) => qualification_failure_response(&error),
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
            guard.check(at).map_err(|error| {
                if registration::shell::reserved(path) {
                    registration::QualificationFailure::at(
                        registration::QualificationStage::ShellReadiness,
                        error,
                    )
                } else {
                    error
                }
            })?;
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
        let (session, issued): (ShellSession, Option<String>) =
            match self.read_session(headers, at)? {
                Some(session) if valid_session(&session, &pending, identity, at) => (session, None),
                _ => {
                    match self.authenticator.begin(
                        identity,
                        FreshIntent::approval(&pending, identity)?,
                        at,
                    )? {
                        #[cfg(test)]
                        ReauthStart::Authenticated(human) => {
                            let (session, token) =
                                self.issue_session_fixture(&pending, identity, human, at)?;
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
        proof: VerifiedAuthTime,
        at: i64,
    ) -> Result<(ShellSession, String)> {
        proof.require_approval(pending, identity)?;
        proof.require_current(at)?;
        let token = effects::random()?;
        let session = ShellSession::approval(
            pending,
            identity,
            proof,
            Digest::new(token.as_bytes()),
            effects::random()?,
            at,
        )?;
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

    #[cfg(test)]
    fn issue_session_fixture(
        &self,
        pending: &shell_transport::ApprovalView,
        identity: &iap::Verified,
        human: FreshHuman,
        at: i64,
    ) -> Result<(ShellSession, String)> {
        self.issue_session(
            pending,
            identity,
            VerifiedAuthTime::from_google(shell_oidc::Reauthenticated::fixture(
                FreshIntent::approval(pending, identity)?,
                human.human,
                human.subject,
                human.authenticated_at,
            )),
            at,
        )
    }

    fn reauth_callback(
        &self,
        query: &str,
        headers: &HeaderMap,
        identity: &iap::Verified,
        at: i64,
    ) -> Result<Response> {
        let proof =
            VerifiedAuthTime::from_google(self.authenticator.complete(query, identity, at)?);
        proof.require_current(at)?;
        if proof.purpose() == FreshPurpose::CredentialIntent {
            let registry = self
                .credentials
                .as_ref()
                .context("credential security shell unavailable")?;
            let (runtime, pending) = registry
                .resolve(proof.attempt(), identity, at)?
                .context("credential intent unavailable")?;
            ensure!(
                proof.challenge() == &pending.challenge()?,
                "credential reauthentication challenge changed"
            );
            let (_, token) = self.credential_session(&runtime, &pending, identity, proof, at)?;
            return credential_redirect(&pending.path(), Some(&token));
        }
        let Some(pending) = self.pending(proof.attempt(), identity, headers, at)? else {
            return Ok(StatusCode::NOT_FOUND.into_response());
        };
        ensure!(
            proof.challenge() == pending.challenge(),
            "reauthentication challenge changed"
        );
        let (_, token) = self.issue_session(&pending, identity, proof, at)?;
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
        let evidence = self.signer.attest(&pending, &session, at)?;
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
        runtime: &crate::store::Runtime,
        pending: &credentials::Pending,
        identity: &iap::Verified,
        proof: VerifiedAuthTime,
        at: i64,
    ) -> Result<(ShellSession, String)> {
        proof.require_intent(
            &credentials::fresh_intent(runtime, pending, identity)?,
            identity,
        )?;
        proof.require_current(at)?;
        let token = effects::random()?;
        let session = ShellSession {
            attempt: pending.attempt.clone(),
            human: proof.human().into(),
            subject: proof.subject().into(),
            challenge: pending.challenge()?,
            preview: pending.challenge()?,
            authenticated_at: proof.authenticated_at(),
            expires_at: proof.deadline()?.min(pending.expires_at),
            csrf: effects::random()?,
            proof: Arc::new(proof),
            digest: Digest::new(token.as_bytes()),
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

    #[cfg(test)]
    fn credential_session_fixture(
        &self,
        runtime: &crate::store::Runtime,
        pending: &credentials::Pending,
        identity: &iap::Verified,
        human: FreshHuman,
        at: i64,
    ) -> Result<(ShellSession, String)> {
        self.credential_session(
            runtime,
            pending,
            identity,
            VerifiedAuthTime::from_google(shell_oidc::Reauthenticated::fixture(
                credentials::fresh_intent(runtime, pending, identity)?,
                human.human,
                human.subject,
                human.authenticated_at,
            )),
            at,
        )
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
        let intent = credentials::fresh_intent(&runtime, &pending, identity)?;
        intent.require_shell_origin(&self.origin)?;
        let valid = |session: &ShellSession| {
            session.attempt == attempt
                && session.proof.require_intent(&intent, identity).is_ok()
                && session.proof.require_current(at).is_ok()
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
            let (session, issued): (ShellSession, Option<String>) = match self
                .read_session(headers, at)?
            {
                Some(session) if valid(&session) => (session, None),
                _ => match self.authenticator.begin(identity, intent.clone(), at)? {
                    #[cfg(test)]
                    ReauthStart::Authenticated(human) => {
                        let (session, token) = self
                            .credential_session_fixture(&runtime, &pending, identity, human, at)?;
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
                    &session.proof,
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
                    &session.proof,
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
                credentials::deliver(
                    &runtime,
                    &pending,
                    identity,
                    &session_binding,
                    &session.proof,
                    at,
                    true,
                )?;
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
        && session.proof.require_approval(pending, identity).is_ok()
        && session.proof.require_current(at).is_ok()
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

fn qualification_failure_response(error: &anyhow::Error) -> Response {
    let Some(failure) = error.downcast_ref::<registration::QualificationFailure>() else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let markup = html! { (DOCTYPE) html lang="en" {
        head { meta charset="utf-8"; title { "Qualification failed" } }
        body {
            h1 { "Qualification failed" }
            p { "Registration readiness was not confirmed by this attempt." }
            p { "Stage: " code { (failure.stage()) } }
            p { "Outcome: " code { (failure.outcome()) } }
            p { "Resolve the failure before starting a new qualification. Do not replay a callback." }
        }
    }};
    (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        markup.into_string(),
    )
        .into_response()
}

fn protected(mut response: Response) -> Response {
    // A form's 303 redirect is still subject to form-action. Finish that POST
    // on the shell origin, then navigate from a new document to the native-
    // selected HTTPS destination. No request field selects this destination.
    if response.status() == StatusCode::SEE_OTHER
        && let Some(destination) = response.headers().get(header::LOCATION)
        && let Ok(destination) = destination.to_str()
        && let Ok(url) = url::Url::parse(destination)
        && url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
    {
        let page = html! {
            (DOCTYPE)
            html {
                head {
                    meta charset="utf-8";
                    meta http-equiv="refresh" content=(format!("0;url={destination}"));
                    title { "Continue" }
                }
                body { p { a href=(destination) { "Continue" } } }
            }
        };
        *response.status_mut() = StatusCode::OK;
        response.headers_mut().remove(header::LOCATION);
        response.headers_mut().remove(header::CONTENT_LENGTH);
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            "text/html; charset=utf-8"
                .parse()
                .expect("static content type"),
        );
        *response.body_mut() = axum::body::Body::from(page.into_string());
    }
    for (name, value) in [
        (
            "content-security-policy",
            "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        // no-referrer makes browser navigation POSTs send Origin: null.
        // Keep their HTTPS origin without disclosing callback paths or queries.
        ("referrer-policy", "strict-origin"),
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

    #[tokio::test]
    async fn qualification_failure_page_exposes_only_closed_native_diagnostics() -> Result<()> {
        let secret = "private-fixture-code-and-client-secret";
        let error = registration::QualificationFailure::at(
            registration::QualificationStage::Publication,
            anyhow::anyhow!("https://provider.example/callback?code={secret}"),
        );
        let response = protected(qualification_failure_response(&error));
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()["referrer-policy"], "strict-origin");
        let body = to_bytes(response.into_body(), 4096).await?;
        let body = std::str::from_utf8(&body)?;
        assert!(body.contains("Qualification failed"));
        assert!(body.contains("owning_app_publication"));
        assert!(body.contains("refused"));
        assert!(!body.contains(secret));
        assert!(!body.contains("provider.example"));

        let response = qualification_failure_response(&anyhow::anyhow!(secret));
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(to_bytes(response.into_body(), 4096).await?.is_empty());
        Ok(())
    }

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
            _: &ShellSession,
            _: i64,
        ) -> Result<external::FreshExternalApproval> {
            anyhow::bail!("OAuth signer unavailable in credential fixture")
        }
    }

    struct BrowserIdentity {
        fresh: bool,
    }

    #[tokio::test]
    async fn protected_navigation_preserves_form_boundary_and_escapes_handoff() -> Result<()> {
        let destination = "https://app.example.com/?one=a&two=\"<b>";
        let response = protected(
            (
                StatusCode::SEE_OTHER,
                [
                    (header::LOCATION, destination),
                    (header::SET_COOKIE, "session=closed"),
                ],
            )
                .into_response(),
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(header::LOCATION));
        assert_eq!(response.headers()[header::SET_COOKIE], "session=closed");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()["referrer-policy"], "strict-origin");
        assert_eq!(
            response.headers()["content-security-policy"],
            "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        );
        let page = String::from_utf8(to_bytes(response.into_body(), 8192).await?.to_vec())?;
        assert!(page.contains("http-equiv=\"refresh\" content=\"0;url=https://app.example.com/?one=a&amp;two=&quot;&lt;b&gt;\""));
        assert!(page.contains("href=\"https://app.example.com/?one=a&amp;two=&quot;&lt;b&gt;\""));
        assert!(!page.contains("<b>"));
        let response =
            protected((StatusCode::SEE_OTHER, [(header::LOCATION, "/local")]).into_response());
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/local");
        Ok(())
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
        fn begin(&self, identity: &iap::Verified, _: FreshIntent, now: i64) -> Result<ReauthStart> {
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

    #[tokio::test(start_paused = true)]
    async fn body_deadlines_and_blocking_dispatch_use_the_simulated_environment() -> Result<()> {
        let world = crate::oauth::simulation::World::new(11);
        effects::scope_async(world.clone(), async {
            let shell = isolated_shell()?;
            let capacity = Arc::new(Semaphore::new(1));
            let start = tokio::time::Instant::now();
            let body = axum::body::Body::from_stream(tokio_stream::pending::<
                Result<axum::body::Bytes, std::io::Error>,
            >());
            let request = Request::builder()
                .uri("/_day2/oauth/approve/attempt")
                .header(header::HOST, "security.example.com")
                .body(body)?;
            let response = shell
                .clone()
                .handle(
                    request,
                    capacity.clone().acquire_owned().await?,
                    Arc::new(AtomicBool::new(true)),
                )
                .await;
            assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
            assert_eq!(tokio::time::Instant::now() - start, Duration::from_secs(3));
            assert_eq!(capacity.available_permits(), 1);
            assert_eq!(effects::wall_time()?, 5);
            let request = Request::builder()
                .uri("/_day2/oauth/approve/attempt")
                .header(header::HOST, "security.example.com")
                .body(axum::body::Body::empty())?;
            let response = shell
                .handle(
                    request,
                    capacity.clone().acquire_owned().await?,
                    Arc::new(AtomicBool::new(false)),
                )
                .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(capacity.available_permits(), 1);
            assert!(world.requests().is_empty());
            Ok(())
        })
        .await
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
        let runtime = crate::development::create_verification_for(
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
        crate::development::repin_credential_verification_data(&mut instance, runtime.artifact())?;
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

    async fn reject_navigation_origins(
        client: &reqwest::Client,
        endpoint: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<()> {
        for rejected in [None, Some("null"), Some("https://app.example.com")] {
            let mut headers = headers.clone();
            headers.remove(header::ORIGIN);
            if let Some(origin) = rejected {
                headers.insert(header::ORIGIN, origin.parse()?);
            }
            let response = client
                .post(endpoint)
                .headers(headers)
                .body(body.to_vec())
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
        Ok(())
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
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(shell.clone().serve_bounded(
            listener,
            4,
            Arc::new(AtomicBool::new(true)),
            async {
                let _ = shutdown.await;
            },
        ));
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        for (operation, id) in [
            ("credential_metadata.create_client", "client-browser"),
            ("credential_metadata.create_personal", "personal-browser"),
        ] {
            let input = serde_json::json!({"label":"Transcription client"});
            let url = credentials::start(
                &world.runtime,
                operation,
                "alice@example.com",
                id,
                &input,
                None,
                world.now - 1,
            )?;
            let path = url::Url::parse(&url)?.path().to_owned();
            let endpoint = format!("{endpoint}{path}");
            let mut headers = credential_headers();
            let page = client
                .get(&endpoint)
                .headers(headers.clone())
                .send()
                .await?;
            assert_eq!(page.status(), StatusCode::OK);
            assert_eq!(page.headers()[header::CACHE_CONTROL], "no-store");
            // strict-origin is the policy that preserves normal navigation POST Origin.
            assert_eq!(page.headers()["referrer-policy"], "strict-origin");
            assert_eq!(
                page.headers()["content-security-policy"],
                "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
            );
            let cookie = page.headers()[header::SET_COOKIE]
                .to_str()?
                .split(';')
                .next()
                .context("credential cookie missing")?
                .to_owned();
            headers.insert(header::COOKIE, cookie.parse()?);
            let session = shell
                .read_session(&headers, world.now)?
                .context("credential session missing")?;
            let at = effects::wall_time;
            let page = page.text().await?;
            assert!(!page.contains("d2c1."));
            assert!(page.contains(&format!("name=\"csrf\" value=\"{}\"", session.csrf)));
            assert!(page.contains(&format!(
                "name=\"challenge\" value=\"{}\"",
                session.challenge.as_str()
            )));
            assert!(page.contains(&format!("method=\"post\" action=\"{path}\"")));
            assert!(
                world
                    .runtime
                    .accept(operation, "alice@example.com", id, &input, at()?)
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
                    .dispatch(&Method::POST, &path, None, &headers, &confirm, at()?)
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
                    .dispatch(&Method::POST, &path, None, &wrong, &confirm, at()?)
                    .is_err()
            );
            assert_eq!(world.keys.0.load(Ordering::SeqCst), before);
            reject_navigation_origins(&client, &endpoint, &headers, &confirm).await?;
            assert_eq!(world.keys.0.load(Ordering::SeqCst), before);
            assert_eq!(
                client
                    .post(&endpoint)
                    .headers(headers.clone())
                    .body(confirm.clone())
                    .send()
                    .await?
                    .status(),
                StatusCode::SEE_OTHER
            );
            // Lost-response retry runs the identical accepted product invocation.
            assert_eq!(
                shell
                    .dispatch(&Method::POST, &path, None, &headers, &confirm, at()?)?
                    .status(),
                StatusCode::SEE_OTHER
            );
            let outcome = world.runtime.execute(id, crate::store::Fault::None)?;
            assert_eq!(outcome.status, "success", "{outcome:?}");
            assert!(!outcome.result.to_string().contains("d2c1."));
            assert!(!serde_json::to_string(&world.runtime.trace(id)?)?.contains("d2c1."));
            let get = client
                .get(&endpoint)
                .headers(headers.clone())
                .send()
                .await?;
            assert_eq!(get.headers()[header::CACHE_CONTROL], "no-store");
            let page = get.text().await?;
            assert!(!page.contains("d2c1."));
            assert!(page.contains("credential_metadata.ping") && page.contains("3600 seconds"));
            let reveal = credential_body(&session, "reveal");
            let before = world.keys.0.load(Ordering::SeqCst);
            let mut wrong = headers.clone();
            wrong.insert("test-subject", "someone-else".parse()?);
            assert!(
                shell
                    .dispatch(&Method::POST, &path, None, &wrong, &reveal, at()?)
                    .is_err()
            );
            let mut wrong = headers.clone();
            wrong.append(header::COOKIE, headers[header::COOKIE].clone());
            assert!(
                shell
                    .dispatch(&Method::POST, &path, None, &wrong, &reveal, at()?)
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
                        at()?
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
                        at()?
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
                        at()?
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
            let malformed_contract = db
                .execute(
                    "UPDATE day2_credential_receipts SET family_contract='foreign' WHERE invocation=?1",
                    [id],
                )
                .unwrap_err();
            assert_eq!(
                malformed_contract.sqlite_error_code(),
                Some(rusqlite::ErrorCode::ConstraintViolation)
            );
            assert_eq!(
                malformed_contract
                    .sqlite_error()
                    .map(|error| error.extended_code),
                Some(rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER)
            );
            assert_eq!(
                db.query_row(
                    "SELECT family_contract FROM day2_credential_receipts WHERE invocation=?1",
                    [id],
                    |row| row.get::<_, String>(0),
                )?,
                contract
            );
            let foreign_contract = Digest::of(&"foreign-credential-family-contract")?;
            assert_ne!(foreign_contract.as_str(), contract);
            assert_eq!(
                db.execute(
                    "UPDATE day2_credential_receipts SET family_contract=?1 WHERE invocation=?2",
                    rusqlite::params![foreign_contract.as_str(), id],
                )?,
                1
            );
            assert_eq!(
                db.query_row(
                    "SELECT family_contract FROM day2_credential_receipts WHERE invocation=?1",
                    [id],
                    |row| row.get::<_, String>(0),
                )?,
                foreign_contract.as_str()
            );
            assert!(
                shell
                    .dispatch(&Method::POST, &path, None, &headers, &reveal, at()?)
                    .is_err()
            );
            assert_eq!(world.keys.0.load(Ordering::SeqCst), before);
            db.execute(
                "UPDATE day2_credential_receipts SET family_contract=?1 WHERE invocation=?2",
                rusqlite::params![contract, id],
            )?;
            reject_navigation_origins(&client, &endpoint, &headers, &reveal).await?;
            assert_eq!(world.keys.0.load(Ordering::SeqCst), before);
            session
                .proof
                .require_current(at()?)
                .context("credential proof refused after negative delivery probes")?;
            let response = client
                .post(&endpoint)
                .headers(headers.clone())
                .body(reveal.clone())
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["cache-control"], "no-store");
            let html = response.text().await?;
            assert!(html.contains("d2c1."));
            assert!(!html.contains("ciphertext"));
            let acknowledge = credential_body(&session, "acknowledge");
            let before = world.keys.0.load(Ordering::SeqCst);
            reject_navigation_origins(&client, &endpoint, &headers, &acknowledge).await?;
            assert_eq!(world.keys.0.load(Ordering::SeqCst), before);
            let response = client
                .post(&endpoint)
                .headers(headers.clone())
                .body(acknowledge)
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(!response.headers().contains_key(header::LOCATION));
            let page = response.text().await?;
            assert!(
                page.contains("http-equiv=\"refresh\" content=\"0;url=https://app.example.com/\"")
            );
            assert!(page.contains("href=\"https://app.example.com/\""));
            assert!(!page.contains("d2c1."));
            let before = world.keys.0.load(Ordering::SeqCst);
            assert!(
                shell
                    .dispatch(&Method::POST, &path, None, &headers, &reveal, at()?)
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
        let _ = stop.send(());
        tokio::time::timeout(Duration::from_secs(3), server).await???;
        Ok(())
    }

    #[test]
    fn credential_signed_google_session_keeps_original_intent_across_three_roles() -> Result<()> {
        // The normal checked Credential Metadata artifact and actual local
        // registry/product-command consumer remain mandatory. This is a native
        // signed fixture, not a Google live campaign or remote app transport.
        struct CredentialClock(Arc<super::super::simulation::World>);

        impl crate::host::Host for CredentialClock {
            fn entropy(&self, scope: &str, invocation: &str) -> Result<[u8; 32]> {
                crate::host::Host::entropy(&crate::host::System, scope, invocation)
            }

            fn now_ms(&self) -> Result<i64> {
                effects::Hooks::wall_time(self.0.as_ref())?
                    .checked_mul(1000)
                    .context("fixture runtime milliseconds overflow")
            }

            fn worker_action(
                &self,
                phase: crate::protocol::Phase,
                request: &crate::protocol::Request,
            ) -> Result<crate::host::WorkerAction> {
                crate::host::Host::worker_action(&crate::host::System, phase, request)
            }

            fn record_exchange(
                &self,
                phase: crate::protocol::Phase,
                request: &crate::protocol::Request,
                result: &Result<crate::protocol::Response>,
            ) -> Result<()> {
                crate::host::Host::record_exchange(&crate::host::System, phase, request, result)
            }

            fn deadline(
                &self,
                phase: crate::protocol::Phase,
                started: std::time::Instant,
            ) -> Result<()> {
                crate::host::Host::deadline(&crate::host::System, phase, started)
            }
        }

        let mut world = browser_world(1)?;
        let clock = super::super::simulation::World::new(904);
        clock.advance(u64::try_from(
            world
                .now
                .checked_sub(5)
                .context("fixture wall time invalid")?,
        )?);
        world.runtime = world
            .runtime
            .with_host(Arc::new(CredentialClock(clock.clone())));
        effects::scope(clock.clone(), || {
            let identity = iap::Verified {
                email: "alice@example.com".into(),
                subject: "accounts.google.com:google-alice".into(),
            };
            let registry = Arc::new(credentials::Registry::new(
                &world.instance,
                vec![world.runtime.clone()],
                world.authority.clone(),
            )?);
            let url = credentials::start(
                &world.runtime,
                "credential_metadata.create_client",
                &identity.email,
                "signed-google-three-roles",
                &serde_json::json!({"label":"Client"}),
                None,
                world.now - 1,
            )?;
            let path = url::Url::parse(&url)?.path().to_owned();
            let attempt = path
                .strip_prefix(credentials::PREFIX)
                .context("credential attempt")?;
            let (runtime, pending) = registry
                .resolve(attempt, &identity, world.now)?
                .context("actual pending")?;
            let intent = credentials::fresh_intent(&runtime, &pending, &identity)?;
            let (authenticator, assertions, callback) = shell_oidc::fixture_login(
                &identity,
                intent.clone(),
                world.now,
                world.now + 1,
                world.now + 1,
            )?;
            let mut substitutions = Vec::new();
            for mutation in 0..5 {
                let mut changed = pending.clone();
                let mut owner = identity.clone();
                match mutation {
                    0 => changed.input["label"] = serde_json::json!("different intent"),
                    1 => owner.subject = "accounts.google.com:replacement".into(),
                    2 => changed.binding = Digest::new(b"different selected binding"),
                    3 => changed.authority.revision += 1,
                    4 => changed.created_at -= 1,
                    _ => unreachable!(),
                }
                let changed = credentials::fresh_intent(&runtime, &changed, &owner)?;
                assert!(
                    authenticator
                        .begin(&owner, changed.clone(), world.now)
                        .is_err(),
                    "active Google intent accepted substitution {mutation}"
                );
                substitutions.push((changed, owner));
            }
            let opposite = FreshIntent::fixture_oauth(
                &identity,
                attempt,
                &pending.challenge()?,
                "https://security.example.com/",
            )?;
            assert!(
                authenticator
                    .begin(&identity, opposite.clone(), world.now)
                    .is_err()
            );
            let oauth = Arc::new(NoOAuth);
            let shell = SecurityShell::with_transport(
                "https://security.example.com/".into(),
                oauth.clone(),
                oauth,
                authenticator,
            )?
            .with_credentials(registry.clone())?;
            let mut headers = credential_headers();
            headers.insert(
                iap::ASSERTION_HEADER,
                assertions[iap::ASSERTION_HEADER].clone(),
            );
            clock.advance(1);
            assert_eq!(effects::wall_time()?, world.now + 1);
            assert_eq!(
                world.runtime.host().now_ms()?.div_euclid(1000),
                effects::wall_time()?
            );
            let response = shell.dispatch(
                &Method::GET,
                shell_oidc::GoogleOidc::callback_path(),
                Some(&callback),
                &headers,
                &[],
                world.now + 1,
            )?;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            let cookie = response.headers()[header::SET_COOKIE]
                .to_str()?
                .split(';')
                .next()
                .context("issued credential cookie")?
                .to_owned();
            headers.insert(header::COOKIE, cookie.parse()?);
            let session = shell
                .read_session(&headers, world.now + 1)?
                .context("actual Google session")?;
            session.proof.require_intent(&intent, &identity)?;
            assert!(session.proof.purpose() == FreshPurpose::CredentialIntent);
            assert!(session.proof.require_intent(&opposite, &identity).is_err());
            for (changed, owner) in &substitutions {
                assert!(session.proof.require_intent(changed, owner).is_err());
            }
            assert!(
                shell
                    .dispatch(
                        &Method::GET,
                        shell_oidc::GoogleOidc::callback_path(),
                        Some(&callback),
                        &headers,
                        &[],
                        world.now + 1
                    )
                    .is_err()
            );
            let at = world.now + 1;
            assert_eq!(effects::wall_time()?, at);
            assert_eq!(
                world.runtime.host().now_ms()?.div_euclid(1000),
                effects::wall_time()?
            );
            let confirmed = shell.dispatch(
                &Method::POST,
                &path,
                None,
                &headers,
                &credential_body(&session, "confirm"),
                at,
            )?;
            assert_eq!(confirmed.status(), StatusCode::SEE_OTHER);
            let (current_runtime, current) = registry
                .resolve(attempt, &identity, at)?
                .context("confirmed pending")?;
            assert!(intent == credentials::fresh_intent(&current_runtime, &current, &identity)?);
            let revealed = shell.dispatch(
                &Method::POST,
                &path,
                None,
                &headers,
                &credential_body(&session, "reveal"),
                at,
            )?;
            assert_eq!(revealed.status(), StatusCode::OK);
            drop(revealed);
            let acknowledged = shell.dispatch(
                &Method::POST,
                &path,
                None,
                &headers,
                &credential_body(&session, "acknowledge"),
                at,
            )?;
            assert_eq!(acknowledged.status(), StatusCode::SEE_OTHER);
            assert!(shell.sessions.lock().unwrap().is_empty());
            assert!(
                shell
                    .dispatch(
                        &Method::POST,
                        &path,
                        None,
                        &headers,
                        &credential_body(&session, "reveal"),
                        at
                    )
                    .is_err()
            );
            assert_eq!(
                open(world.runtime.db())?
                    .query_row("SELECT count(*) FROM entries", [], |row| row
                        .get::<_, i64>(0))?,
                1
            );
            for expired in [false, true] {
                clock.advance(1);
                let at = effects::wall_time()?;
                let id = if expired {
                    "signed-google-pending-expired"
                } else {
                    "signed-google-pending-replaced"
                };
                let url = credentials::start(
                    &world.runtime,
                    "credential_metadata.create_client",
                    &identity.email,
                    id,
                    &serde_json::json!({"label":"Original"}),
                    None,
                    at - 1,
                )?;
                let path = url::Url::parse(&url)?.path().to_owned();
                let attempt = path
                    .strip_prefix(credentials::PREFIX)
                    .context("new credential attempt")?;
                let (runtime, mut pending) = registry
                    .resolve(attempt, &identity, at)?
                    .context("original pending")?;
                let original = credentials::fresh_intent(&runtime, &pending, &identity)?;
                let (authenticator, assertions, callback) =
                    shell_oidc::fixture_login(&identity, original, at, at + 1, at + 1)?;
                if expired {
                    pending.expires_at = at;
                } else {
                    pending.input["label"] =
                        serde_json::json!("Replaced after original Google begin");
                }
                assert_eq!(open(runtime.db())?.execute(
                "UPDATE day2_credential_browser SET intent=?1,expires_at=?2 WHERE attempt=?3",
                rusqlite::params![serde_json::to_string(&pending)?, pending.expires_at, attempt])?, 1);
                let oauth = Arc::new(NoOAuth);
                let changed_shell = SecurityShell::with_transport(
                    "https://security.example.com/".into(),
                    oauth.clone(),
                    oauth,
                    authenticator,
                )?
                .with_credentials(registry.clone())?;
                let mut current_headers = credential_headers();
                current_headers.insert(
                    iap::ASSERTION_HEADER,
                    assertions[iap::ASSERTION_HEADER].clone(),
                );
                clock.advance(1);
                let keys_before = world.keys.0.load(Ordering::SeqCst);
                assert!(
                    changed_shell
                        .dispatch(
                            &Method::GET,
                            shell_oidc::GoogleOidc::callback_path(),
                            Some(&callback),
                            &current_headers,
                            &[],
                            at + 1
                        )
                        .is_err()
                );
                assert!(changed_shell.sessions.lock().unwrap().is_empty());
                assert_eq!(world.keys.0.load(Ordering::SeqCst), keys_before);
            }
            Ok(())
        })
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

    mod signed_replay {
        use super::*;
        use crate::managed_credentials::effects as credential_effects;
        use serde::{Deserialize, Serialize};
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        /// Separate ID and private synthetic-secret tracks, coupled clocks.
        /// Scoped domains are genuine unique handles, never replay authority.
        struct Clock {
            oauth: Arc<crate::oauth::simulation::World>,
            credentials: Arc<crate::managed_credentials::simulation::World>,
            time: Mutex<(i64, Duration)>,
        }

        impl Clock {
            fn new() -> Arc<Self> {
                Arc::new(Self {
                    oauth: crate::oauth::simulation::World::new(17),
                    credentials: crate::managed_credentials::simulation::World::new(17),
                    time: Mutex::new((1_000, Duration::ZERO)),
                })
            }

            fn wall(&self) -> i64 {
                self.time.lock().unwrap().0
            }

            fn complete(&self) {
                self.time.lock().unwrap().0 = 1_001;
            }

            fn expire_ticks(&self) -> Result<()> {
                let mut time = self.time.lock().unwrap();
                time.1 = time
                    .1
                    .checked_add(Duration::from_secs(300))
                    .context("replay ticks overflow")?;
                Ok(())
            }
        }

        impl effects::Hooks for Clock {
            fn domain(&self) -> u64 {
                effects::Hooks::domain(self.oauth.as_ref())
            }
            fn wall_time(&self) -> Result<i64> {
                Ok(self.wall())
            }
            fn monotonic(&self) -> Duration {
                self.time.lock().unwrap().1
            }
            fn fill(&self, bytes: &mut [u8]) -> Result<()> {
                effects::Hooks::fill(self.oauth.as_ref(), bytes)
            }
            fn send(&self, _: reqwest::blocking::Request) -> Result<effects::Response> {
                anyhow::bail!("mounted replay has no network transport")
            }
        }

        impl credential_effects::Hooks for Clock {
            fn domain(&self) -> u64 {
                effects::Hooks::domain(self)
            }
            fn wall_time(&self) -> Result<i64> {
                Ok(self.wall())
            }
            fn monotonic(&self) -> Duration {
                self.time.lock().unwrap().1
            }
            fn fill_id(&self, bytes: &mut [u8]) -> Result<()> {
                credential_effects::Hooks::fill_id(self.credentials.as_ref(), bytes)
            }
            fn fill_secret(&self, bytes: &mut [u8]) -> Result<()> {
                credential_effects::Hooks::fill_secret(self.credentials.as_ref(), bytes)
            }
        }

        struct Host {
            original: crate::store::Runtime,
            clock: Arc<Clock>,
        }

        impl crate::host::Host for Host {
            fn entropy(&self, scope: &str, invocation: &str) -> Result<[u8; 32]> {
                self.original.host().entropy(scope, invocation)
            }
            fn now_ms(&self) -> Result<i64> {
                self.clock
                    .wall()
                    .checked_mul(1_000)
                    .context("replay wall overflow")
            }
            fn worker_action(
                &self,
                phase: crate::protocol::Phase,
                request: &crate::protocol::Request,
            ) -> Result<crate::host::WorkerAction> {
                self.original.host().worker_action(phase, request)
            }
            fn record_exchange(
                &self,
                phase: crate::protocol::Phase,
                request: &crate::protocol::Request,
                result: &Result<crate::protocol::Response>,
            ) -> Result<()> {
                self.original.host().record_exchange(phase, request, result)
            }
            fn deadline(
                &self,
                phase: crate::protocol::Phase,
                started: std::time::Instant,
            ) -> Result<()> {
                // Existing Simulation modeled Host boundary. The physical
                // Worker watchdog is unchanged; real elapsed is not replayed.
                self.original.host().deadline(phase, started)
            }
        }

        struct CredentialKeys {
            counts: Mutex<[usize; 2]>,
            selected: Vec<(ApprovalKeyRef, ApprovalKeyPurpose)>,
            delay: AtomicBool,
            clock: Arc<Clock>,
        }

        impl ApprovalKeyProvider for CredentialKeys {
            fn load(
                &self,
                reference: &ApprovalKeyRef,
                purpose: ApprovalKeyPurpose,
            ) -> Result<ApprovalKeyMaterial> {
                ensure!(
                    self.selected
                        .iter()
                        .any(|(expected, role)| expected == reference && *role == purpose),
                    "credential replay selected binding/version/purpose changed"
                );
                let (index, version, byte) = match purpose {
                    ApprovalKeyPurpose::CustodyVerifier => (0, "verifier_1", 29),
                    ApprovalKeyPurpose::CustodyEncryption => (1, "encryption_1", 41),
                    _ => anyhow::bail!("credential replay attempted shell key access"),
                };
                ensure!(
                    reference.version == version,
                    "credential replay selected key version changed"
                );
                self.counts.lock().unwrap()[index] += 1;
                if self.delay.swap(false, Ordering::SeqCst) {
                    self.clock.expire_ticks()?;
                }
                Ok(ApprovalKeyMaterial {
                    binding: reference.binding.clone(),
                    version: version.into(),
                    purpose,
                    bytes: [byte; 32],
                })
            }
        }

        struct CredentialWorld {
            _directory: tempfile::TempDir,
            runtime: crate::store::Runtime,
            registry: Arc<credentials::Registry>,
            keys: Arc<CredentialKeys>,
            pending: credentials::Pending,
            foreign: credentials::Pending,
            namespace: day2_capabilities::credentials::Namespace,
            family_contract: Digest,
        }

        fn credential_world(clock: Arc<Clock>) -> Result<CredentialWorld> {
            use std::io::Write;
            let artifact = PathBuf::from(
                std::env::var_os("DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT").context(
                    "signed replay requires the normal checked Credential Metadata artifact",
                )?,
            );
            let mut instance = crate::development::verification_instance_data(
                &artifact,
                None,
                "alice@example.com",
            )?;
            let app = instance.apps.get_mut("app").context("replay app")?;
            app.readers.insert("credential_client:client_keys".into());
            app.writers.insert("credential_client:client_keys".into());
            for operation in ["credential_metadata.ping", "credential_metadata.record_use"] {
                app.authority
                    .as_mut()
                    .context("replay authority")?
                    .operations
                    .get_mut(operation)
                    .context("replay operation")?
                    .actors
                    .insert("credential_client:client_keys".into());
            }
            let admitted = crate::artifact::LoadedArtifact::load(&artifact)?;
            crate::development::repin_credential_verification_data(&mut instance, &admitted)?;
            let instance = Instance::from_bytes(&serde_json::to_vec(&instance)?)?;
            let desired_binding = instance.apps["app"]
                .credential_families
                .get("client_keys")
                .context("replay original desired family binding")?
                .clone();
            let desired_contract = admitted
                .contract()
                .credential_manifest
                .iter()
                .find(|family| family.id.as_str() == "client_keys")
                .context("replay original artifact family contract")?
                .contract
                .clone();
            let directory = tempfile::tempdir()?;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
            let path = directory.path().join("instance.json");
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(&serde_json::to_vec(&instance)?)?;
            file.sync_all()?;
            let runtime = crate::store::Runtime::load(&path, "app")?;
            ensure!(
                !runtime.db().exists(),
                "replay database was already initialized"
            );
            let simulation = crate::simulation::Simulation::new(runtime, [17; 32], 1_000_000)?;
            let original = simulation.runtime().clone();
            let runtime = original.clone().with_host(Arc::new(Host {
                original,
                clock: clock.clone(),
            }));
            runtime.initialize()?;
            let active = crate::authority_state::current(&open(runtime.db())?)?;
            ensure!(
                active.stamp.revision == 1,
                "replay must have one fresh authority initialization"
            );
            let selected_family = active
                .document
                .credentials
                .get("client_keys")
                .context("replay declared client family")?;
            ensure!(
                selected_family.binding == desired_binding
                    && selected_family.qualification.family_contract == desired_contract,
                "replay initialized authority differs from original admitted DATA"
            );
            let namespace = selected_family.binding.namespace.clone();
            let family_contract = selected_family.qualification.family_contract.clone();
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
                    observed_at: 998,
                    ready_until: 1_298,
                    grant_until: 8_200,
                    max_active_lineages: 1,
                    issuers: BTreeMap::from([(
                        "alice@example.com".into(),
                        "accounts.google.com:google-alice".into(),
                    )]),
                })
                .collect();
            let selected = selections
                .iter()
                .flat_map(|entry| {
                    [
                        (entry.verifier.clone(), ApprovalKeyPurpose::CustodyVerifier),
                        (
                            entry.encryption.clone(),
                            ApprovalKeyPurpose::CustodyEncryption,
                        ),
                    ]
                })
                .collect();
            let keys = Arc::new(CredentialKeys {
                counts: Mutex::new([0; 2]),
                selected,
                delay: AtomicBool::new(false),
                clock,
            });
            let authority = Arc::new(SelectedAuthority::new(selections, keys.clone())?);
            let runtime = runtime.with_credential_authority(authority.clone());
            let registry = Arc::new(credentials::Registry::new(
                &instance,
                vec![runtime.clone()],
                authority,
            )?);
            let identity = identity();
            let start = |invocation: &str, label: &str| -> Result<credentials::Pending> {
                let location = credentials::start(
                    &runtime,
                    "credential_metadata.create_client",
                    &identity.email,
                    invocation,
                    &serde_json::json!({"label":label}),
                    None,
                    1_000,
                )?;
                let url = url::Url::parse(&location)?;
                let attempt = url
                    .path()
                    .strip_prefix(credentials::PREFIX)
                    .context("replay pending path")?;
                Ok(registry
                    .resolve(attempt, &identity, 1_000)?
                    .context("replay actual pending")?
                    .1)
            };
            let pending = start("signed-replay-target", "Replay client")?;
            let foreign = start("signed-replay-foreign", "Untouched foreign client")?;
            ensure!(
                pending.family == "client_keys"
                    && pending.operation == "credential_metadata.create_client"
                    && pending.actor == "alice@example.com"
                    && pending.input == serde_json::json!({"label":"Replay client"})
                    && pending.invocation == "signed-replay-target"
                    && pending.artifact == runtime.artifact().id()
                    && pending.authority == active.stamp
                    && pending.binding == Digest::of(&desired_binding)?
                    && pending.created_at == 1_000
                    && pending.expires_at == 1_300,
                "replay original desired owner/family/operation/authority/binding"
            );
            Ok(CredentialWorld {
                _directory: directory,
                runtime,
                registry,
                keys,
                pending,
                foreign,
                namespace,
                family_contract,
            })
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        enum Consumer {
            OAuth,
            Credential,
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        enum Case {
            Positive,
            WrongSubject,
            OppositePurpose,
            Invalidate,
            TicksExpired,
            KeyDelay,
            Restart,
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        enum Step {
            Begin,
            Reuse,
            OppositePurpose,
            Invalidate,
            Callback,
            View,
            ExpireTicks,
            DelayKey,
            Restart,
            Confirm,
            Reveal,
            Acknowledge,
            Duplicate,
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
        enum Disposition {
            Ok,
            Redirect,
            NotFound,
            Unauthorized,
            Refused,
        }

        #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
        struct PublicState {
            wall: i64,
            ticks: u64,
            sessions: usize,
            google_pending: usize,
            activation: i64,
            product: i64,
            receipts: i64,
            product_rows: i64,
            delivery_closed: i64,
            response_verified: bool,
            oauth_keys: admission::tests::ReplayKeyCounts,
            credential_keys: [usize; 2],
            providers: shell_oidc::ReplayProviderCounts,
        }

        /// Independent finite state machine: literal transitions and counts,
        /// no production transition/result boolean is used for prediction.
        struct Model {
            consumer: Consumer,
            case: Case,
            state: PublicState,
            restarted: bool,
        }

        impl Model {
            fn new(consumer: Consumer, case: Case) -> Self {
                Self {
                    consumer,
                    case,
                    restarted: false,
                    state: PublicState {
                        wall: 1_000,
                        ticks: 0,
                        sessions: 0,
                        google_pending: 0,
                        activation: 0,
                        product: 0,
                        receipts: 0,
                        product_rows: 0,
                        delivery_closed: 0,
                        response_verified: false,
                        oauth_keys: Default::default(),
                        credential_keys: [0; 2],
                        providers: Default::default(),
                    },
                }
            }

            fn app_lookup(&mut self) {
                if self.consumer == Consumer::OAuth {
                    self.state.oauth_keys.app_verifier += 1;
                    self.state.oauth_keys.app_encryption += 1;
                    self.state.oauth_keys.app_attestation += 1;
                }
            }

            fn step(&mut self, step: Step) -> Disposition {
                match step {
                    Step::Begin => {
                        self.app_lookup();
                        self.state.providers.iap_keys += 1;
                        self.state.google_pending = 1;
                        Disposition::Redirect
                    }
                    Step::Reuse => {
                        self.app_lookup();
                        Disposition::Redirect
                    }
                    Step::OppositePurpose => Disposition::Refused,
                    Step::Invalidate | Step::DelayKey => Disposition::Ok,
                    Step::ExpireTicks => {
                        self.state.ticks += 300;
                        Disposition::Ok
                    }
                    Step::Restart => {
                        self.restarted = true;
                        self.state.sessions = 0;
                        self.state.google_pending = 0;
                        Disposition::Ok
                    }
                    Step::Callback => {
                        self.state.wall = 1_001;
                        self.state.google_pending = 0;
                        if self.restarted {
                            self.state.providers.iap_keys += 1;
                            return Disposition::Refused;
                        }
                        if self.case == Case::WrongSubject {
                            return Disposition::Refused;
                        }
                        self.state.providers.google_keys += 1;
                        self.state.providers.exchanges += 1;
                        if self.case == Case::Invalidate {
                            return if self.consumer == Consumer::OAuth {
                                Disposition::NotFound
                            } else {
                                Disposition::Refused
                            };
                        }
                        self.app_lookup();
                        self.state.sessions = 1;
                        Disposition::Redirect
                    }
                    Step::View => {
                        self.app_lookup();
                        Disposition::Ok
                    }
                    Step::Confirm => {
                        self.app_lookup();
                        if self.case == Case::TicksExpired {
                            return Disposition::Refused;
                        }
                        if self.case == Case::Restart {
                            self.state.providers.iap_keys += 1;
                            return if self.consumer == Consumer::OAuth {
                                Disposition::Unauthorized
                            } else {
                                Disposition::Refused
                            };
                        }
                        match self.consumer {
                            Consumer::OAuth => {
                                self.state.sessions = 0;
                                self.state.oauth_keys.shell_attestation += 1;
                                if self.case == Case::KeyDelay {
                                    self.state.ticks += 300;
                                    return Disposition::Refused;
                                }
                                self.app_lookup();
                                self.state.activation = 1;
                                Disposition::Ok
                            }
                            Consumer::Credential => {
                                self.state.credential_keys = [1; 2];
                                if self.case == Case::KeyDelay {
                                    self.state.ticks += 300;
                                    return Disposition::Refused;
                                }
                                // Browser prepare and ordinary invoke prepare own distinct leases.
                                self.state.credential_keys = [2; 2];
                                self.state.product = 1;
                                self.state.receipts = 1;
                                self.state.product_rows = 1;
                                Disposition::Redirect
                            }
                        }
                    }
                    Step::Reveal => {
                        self.state.credential_keys = [3; 2];
                        self.state.response_verified = true;
                        Disposition::Ok
                    }
                    Step::Acknowledge => {
                        self.state.sessions = 0;
                        self.state.delivery_closed = 1;
                        Disposition::Redirect
                    }
                    Step::Duplicate => {
                        if self.case == Case::WrongSubject
                            || self.case == Case::Invalidate
                            || self.case == Case::Restart
                        {
                            Disposition::Refused
                        } else if self.consumer == Consumer::OAuth {
                            Disposition::NotFound
                        } else {
                            Disposition::Refused
                        }
                    }
                }
            }
        }

        type OAuthReplayWorld = (
            tempfile::TempDir,
            admission::tests::MountedReplayFixture,
            admission::tests::MountedReplayFixture,
            PathBuf,
            PathBuf,
            Vec<Table>,
        );

        struct World {
            clock: Arc<Clock>,
            consumer: Consumer,
            login: shell_oidc::ReplayLogin,
            previous_providers: shell_oidc::ReplayProviderCounts,
            shell: Arc<SecurityShell>,
            oauth: Option<OAuthReplayWorld>,
            credential: Option<CredentialWorld>,
            path: String,
            headers: HeaderMap,
            callback: Option<String>,
            session: Option<ShellSession>,
            original_intent: Option<FreshIntent>,
            original_authorization: Option<Digest>,
            response_verified: bool,
            response_identity: Option<Digest>,
            invalidated: bool,
            acknowledged: bool,
            response_status: Mutex<Option<u16>>,
        }

        impl World {
            fn new(consumer: Consumer, clock: Arc<Clock>) -> Result<Self> {
                let (oauth, credential, audience, client, path) = match consumer {
                    Consumer::OAuth => {
                        let directory = tempfile::tempdir()?;
                        std::fs::set_permissions(
                            directory.path(),
                            std::fs::Permissions::from_mode(0o700),
                        )?;
                        let database = directory.path().join("target.sqlite");
                        let foreign_database = directory.path().join("foreign.sqlite");
                        let delay_clock = clock.clone();
                        let target = admission::tests::mounted_replay_fixture(
                            &database,
                            Arc::new(move || delay_clock.expire_ticks()),
                        )?;
                        let foreign = admission::tests::mounted_replay_fixture(
                            &foreign_database,
                            Arc::new(|| anyhow::bail!("foreign key delay is forbidden")),
                        )?;
                        let before = snapshot(&foreign_database)?;
                        let audience = target.audience.clone();
                        let client = target.client.clone();
                        let path = path_for(&target.attempt);
                        (
                            Some((
                                directory,
                                target,
                                foreign,
                                database,
                                foreign_database,
                                before,
                            )),
                            None,
                            audience,
                            client,
                            path,
                        )
                    }
                    Consumer::Credential => {
                        let world = credential_world(clock.clone())?;
                        let path = world.pending.path();
                        (
                            None,
                            Some(world),
                            "/projects/1/global/backendServices/2".into(),
                            "123.apps.googleusercontent.com".into(),
                            path,
                        )
                    }
                };
                let login = shell_oidc::ReplayLogin::new(
                    &identity(),
                    &audience,
                    &client,
                    "https://security.example.com/",
                    1_001,
                    1_001,
                    1_301,
                )?;
                let shell = Self::mount(&login, oauth.as_ref(), credential.as_ref())?;
                let mut headers = login.headers(&identity(), 1_000)?;
                headers.extend(credential_headers());
                Ok(Self {
                    clock,
                    consumer,
                    login,
                    previous_providers: Default::default(),
                    shell,
                    oauth,
                    credential,
                    path,
                    headers,
                    callback: None,
                    session: None,
                    original_intent: None,
                    original_authorization: None,
                    response_verified: false,
                    response_identity: None,
                    invalidated: false,
                    acknowledged: false,
                    response_status: Mutex::new(None),
                })
            }

            fn mount(
                login: &shell_oidc::ReplayLogin,
                oauth: Option<&OAuthReplayWorld>,
                credential: Option<&CredentialWorld>,
            ) -> Result<Arc<SecurityShell>> {
                if let Some((_, target, _, _, _, _)) = oauth {
                    return SecurityShell::with_transport(
                        "https://security.example.com/".into(),
                        Arc::new(approval_registry::LocalShellApprovals(
                            target.registry.clone(),
                        )),
                        target.signer.clone(),
                        login.authenticator.clone(),
                    );
                }
                let world = credential.context("replay credential world")?;
                let no_oauth = Arc::new(NoOAuth);
                SecurityShell::with_transport(
                    "https://security.example.com/".into(),
                    no_oauth.clone(),
                    no_oauth,
                    login.authenticator.clone(),
                )?
                .with_credentials(world.registry.clone())
            }

            fn dispatch(
                &self,
                method: Method,
                path: &str,
                query: Option<&str>,
                body: &[u8],
            ) -> Result<Response> {
                let response = self.shell.dispatch(
                    &method,
                    path,
                    query,
                    &self.headers,
                    body,
                    self.clock.wall(),
                )?;
                *self.response_status.lock().unwrap() = Some(response.status().as_u16());
                Ok(response)
            }

            fn capture_intent(&mut self) -> Result<()> {
                self.original_intent = Some(self.login.pending_intent()?);
                self.original_authorization = Some(self.login.authorization_identity()?);
                Ok(())
            }

            fn original_session_binding(&self) -> Result<String> {
                let token = cookie_token(&self.headers)?
                    .context("replay original signed cookie missing")?;
                Ok(format!(
                    "shell-{}",
                    Digest::new(token.as_bytes())
                        .as_str()
                        .trim_start_matches("sha256:")
                ))
            }

            fn credential_relations(
                &self,
                db: &rusqlite::Connection,
                world: &CredentialWorld,
            ) -> Result<Option<crate::managed_credentials::crypto::MaterialIdentity>> {
                use rusqlite::OptionalExtension;
                let raw: String = db.query_row(
                    "SELECT intent FROM day2_credential_browser WHERE invocation=?1",
                    [&world.pending.invocation],
                    |row| row.get(0),
                )?;
                let mut expected = serde_json::to_value(&world.pending)?;
                // This sole scheduled replacement is the causal negative
                // input. All other original owner/authority fields stay fixed.
                let actual: serde_json::Value = crate::json::decode(raw.as_bytes())?;
                if self.invalidated {
                    expected["input"]["label"] = serde_json::json!("Replaced current intent");
                }
                ensure!(
                    actual == expected && world.pending.artifact == world.runtime.artifact().id(),
                    "replay original credential pending/artifact/authority/binding changed"
                );
                let confirmation: Option<String> = db.query_row("SELECT confirmation FROM day2_credential_confirmations WHERE invocation=?1",
                    [&world.pending.invocation],|row| row.get(0)).optional()?;
                let Some(confirmation) = confirmation else {
                    let count: i64 = db.query_row("SELECT (SELECT count(*) FROM day2_credential_lineages)
                        +(SELECT count(*) FROM day2_credential_versions)+(SELECT count(*) FROM day2_credential_material)
                        +(SELECT count(*) FROM day2_credential_deliveries)+(SELECT count(*) FROM day2_credential_receipts)
                        +(SELECT count(*) FROM day2_credential_confirmations)",[],|row| row.get(0))?;
                    ensure!(
                        count == 0,
                        "replay credential writer ran without original confirmation"
                    );
                    return Ok(None);
                };
                let confirmation: serde_json::Value = crate::json::decode(confirmation.as_bytes())?;
                let original = serde_json::to_value(&world.pending)?;
                for key in [
                    "invocation",
                    "operation",
                    "actor",
                    "input",
                    "family",
                    "intent",
                    "artifact",
                    "authority",
                    "binding",
                ] {
                    ensure!(
                        confirmation[key] == original[key],
                        "replay credential confirmation retargeted original DATA"
                    );
                }
                let session = self.original_session_binding()?;
                ensure!(
                    confirmation["subject"] == "accounts.google.com:google-alice"
                        && confirmation["session"] == session
                        && confirmation["security_epoch"] == 1
                        && confirmation["authenticated_at"] == 1_001
                        && confirmation["approved_at"] == 1_001
                        && confirmation["expires_at"] == world.pending.expires_at.min(1_301),
                    "replay credential confirmation wrong subject/session/epoch/lifetime"
                );
                let namespace = Digest::of(&("credential-namespace-v1", &world.namespace))?;
                let principal = format!(
                    "client/client_keys/{}",
                    Digest::of(&(
                        "credential-client-v1",
                        &world.namespace,
                        &world.pending.invocation
                    ))?
                    .as_str()
                    .trim_start_matches("sha256:")
                );
                let exact: i64 = db.query_row("SELECT count(*) FROM day2_credential_receipts r
                    JOIN day2_credential_lineages l ON l.id=r.lineage JOIN day2_credential_versions v ON v.id=r.version
                    JOIN day2_credential_material m ON m.version=v.id JOIN day2_credential_deliveries d ON d.version=v.id
                    JOIN day2_invocations i ON i.id=r.invocation
                    WHERE r.namespace=?1 AND r.invocation=?2 AND r.family_contract=?3 AND r.action='issue'
                      AND l.namespace=?1 AND l.family='client_keys' AND l.family_contract=?3
                      AND l.principal=?4 AND l.creator='alice@example.com' AND l.label='Replay client'
                      AND l.recipient='alice@example.com' AND l.session=?5 AND l.security_epoch=1 AND l.state='active'
                      AND l.revision=1 AND l.head=v.id AND v.lineage=l.id AND v.predecessor IS NULL
                      AND v.security_epoch=1 AND v.verifier_key_version='verifier_1' AND v.issued_at=1001
                      AND v.state='active' AND v.grant_digest=l.grant_digest
                      AND m.material_revision=1 AND m.envelope_revision=1 AND m.encryption_key_version='encryption_1'
                      AND d.recipient=l.recipient AND d.session=l.session
                      AND d.state=?8 AND d.closed_reason=?9
                      AND i.status='success' AND i.operation=?6 AND i.actor='alice@example.com' AND i.artifact=?7",
                    rusqlite::params![namespace.as_str(),world.pending.invocation,world.family_contract.as_str(),principal,session,
                        world.pending.operation,world.pending.artifact,
                        if self.acknowledged {"closed"} else {"available"},
                        if self.acknowledged {"acknowledged"} else {""}],|row| row.get(0))?;
                ensure!(
                    exact == 1,
                    "replay wrong original credential receipt/lineage/version/delivery/writer relationship"
                );
                for table in [
                    "day2_credential_confirmations",
                    "day2_credential_lineages",
                    "day2_credential_versions",
                    "day2_credential_material",
                    "day2_credential_deliveries",
                    "day2_credential_receipts",
                ] {
                    let count: i64 =
                        db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                            row.get(0)
                        })?;
                    ensure!(count == 1, "replay extra foreign credential writer rows");
                }
                let (lineage,version,namespace_json,identity_json):(String,String,String,String) = db.query_row(
                    "SELECT l.id,v.id,l.namespace_json,m.identity_json FROM day2_credential_receipts r
                     JOIN day2_credential_lineages l ON l.id=r.lineage JOIN day2_credential_versions v ON v.id=r.version
                     JOIN day2_credential_material m ON m.version=v.id WHERE r.invocation=?1",
                    [&world.pending.invocation],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?;
                ensure!(
                    crate::json::decode::<day2_capabilities::credentials::Namespace>(
                        namespace_json.as_bytes()
                    )? == world.namespace,
                    "replay wrong original credential namespace"
                );
                let identity = crate::managed_credentials::crypto::MaterialIdentity {
                    namespace: world.namespace.clone(),
                    family: "client_keys".into(),
                    lineage,
                    version,
                    recipient: "alice@example.com".into(),
                    security_epoch: 1,
                    material_revision: 1,
                };
                ensure!(
                    crate::json::decode::<crate::managed_credentials::crypto::MaterialIdentity>(
                        identity_json.as_bytes()
                    )? == identity,
                    "replay material retargeted original owner/family/epoch/version"
                );
                use base64::Engine as _;
                let reference = format!(
                    "cr1_clients_{}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(
                        &day2_capabilities::credentials::LineageRef {
                            namespace: world.namespace.clone(),
                            family: day2_capabilities::Name::try_from("client_keys".to_owned())?,
                            id: identity.lineage.clone()
                        }
                    )?)
                );
                let entry: String =
                    db.query_row("SELECT note FROM entries", [], |row| row.get(0))?;
                let product: (String, String, String, Vec<u8>) = db.query_row(
                    "SELECT family,lineage,head,revision FROM key_receipts",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )?;
                let product_count: i64 =
                    db.query_row("SELECT count(*) FROM key_receipts", [], |row| row.get(0))?;
                ensure!(
                    entry == reference
                        && product
                            == (
                                "clients".into(),
                                reference,
                                identity.version.clone(),
                                1_u64.to_be_bytes().to_vec()
                            )
                        && product_count == 1,
                    "replay app row does not refer to original issued lineage/version"
                );
                Ok(Some(identity))
            }

            fn verify_private_response(&mut self, response: Response) -> Result<()> {
                let world = self.credential.as_ref().context("replay reveal consumer")?;
                let bytes = tokio::runtime::Builder::new_current_thread()
                    .build()?
                    .block_on(to_bytes(response.into_body(), 8192))?;
                let html = std::str::from_utf8(&bytes)?;
                ensure!(
                    html.matches("<pre>").count() == 1,
                    "replay private reveal shape"
                );
                let token = html
                    .split_once("<pre>")
                    .context("replay private reveal missing")?
                    .1
                    .split_once("</pre>")
                    .context("replay private reveal incomplete")?
                    .0;
                // No body/token is returned, logged, or included in evidence.
                // This validates the real delivered secret using the original
                // fixed verifier lease; provider counters do not change.
                let mut connection = open(world.runtime.db())?;
                let db = connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
                let identity = self
                    .credential_relations(&db, world)?
                    .context("replay original issued material absent")?;
                let (selector,verifier,key):(String,Vec<u8>,String) = db.query_row(
                    "SELECT selector,verifier,verifier_key_version FROM day2_credential_versions WHERE id=?1",
                    [&identity.version],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
                let lease = crate::managed_credentials::crypto::VerifierLease::new(
                    &[29; 32],
                    "verifier_1".into(),
                )?;
                ensure!(
                    crate::managed_credentials::crypto::token_selector(token)? == selector
                        && crate::managed_credentials::crypto::verify_managed(
                            &lease, &identity, &selector, &verifier, &key, token
                        )?,
                    "replay private reveal did not match original material/verifier"
                );
                self.response_identity = Some(Digest::of(&(
                    "verified-original-private-reveal-v2",
                    &identity,
                    token.len(),
                    Digest::new(token.as_bytes()),
                ))?);
                self.response_verified = true;
                Ok(())
            }

            fn step(&mut self, step: Step, case: Case) -> Result<Disposition> {
                *self.response_status.lock().unwrap() = None;
                match step {
                    Step::Begin | Step::Reuse => {
                        let response = self.dispatch(Method::GET, &self.path, None, &[])?;
                        let location = response
                            .headers()
                            .get(header::LOCATION)
                            .context("replay expected redirect Location absent")?;
                        self.callback = Some(self.login.capture_authorization(location.to_str()?)?);
                        if step == Step::Begin {
                            self.capture_intent()?;
                        }
                        Ok(disposition(response.status()))
                    }
                    Step::OppositePurpose => {
                        let intent = if self.consumer == Consumer::OAuth {
                            let world = credential_world(self.clock.clone())?;
                            let mut pending = world.pending.clone();
                            pending.attempt =
                                self.original_intent.as_ref().unwrap().attempt().into();
                            credentials::fresh_intent(&world.runtime, &pending, &identity())?
                        } else {
                            let world = self.credential.as_ref().unwrap();
                            FreshIntent::fixture_oauth(
                                &identity(),
                                &world.pending.attempt,
                                &world.pending.challenge()?,
                                "https://security.example.com/",
                            )?
                        };
                        ensure!(
                            self.login
                                .authenticator
                                .begin(&identity(), intent, self.clock.wall())
                                .is_err(),
                            "opposite purpose accepted"
                        );
                        Ok(Disposition::Refused)
                    }
                    Step::Invalidate => {
                        if let Some((_, target, _, database, _, _)) = &self.oauth {
                            ensure!(
                                connect::cancel(&mut open(database)?, &target.attempt, |_| Ok(()))?,
                                "replay cancel failed"
                            );
                        } else {
                            let world = self.credential.as_ref().unwrap();
                            let mut changed = world.pending.clone();
                            changed.input["label"] = serde_json::json!("Replaced current intent");
                            ensure!(open(world.runtime.db())?.execute(
                                "UPDATE day2_credential_browser SET intent=?1,expires_at=?2 WHERE attempt=?3",
                                rusqlite::params![serde_json::to_string(&changed)?,changed.expires_at,changed.attempt])? == 1,
                                "replay current pending replacement");
                        }
                        self.invalidated = true;
                        Ok(Disposition::Ok)
                    }
                    Step::Callback | Step::Duplicate
                        if self.session.is_none()
                            || case == Case::WrongSubject
                            || case == Case::Invalidate
                            || case == Case::Restart =>
                    {
                        self.clock.complete();
                        if case == Case::WrongSubject {
                            let mut subject = identity();
                            if step == Step::Callback {
                                subject.subject = "accounts.google.com:alternate".into();
                            }
                            let assertion = self.login.headers(&subject, self.clock.wall())?;
                            self.headers.insert(
                                iap::ASSERTION_HEADER,
                                assertion[iap::ASSERTION_HEADER].clone(),
                            );
                            self.original_authorization =
                                Some(self.login.authorization_identity()?);
                        }
                        let response = self.dispatch(
                            Method::GET,
                            shell_oidc::GoogleOidc::callback_path(),
                            self.callback.as_deref(),
                            &[],
                        );
                        if let Ok(response) = response {
                            let status = response.status();
                            if let Some(cookie) = response.headers().get(header::SET_COOKIE) {
                                self.headers.insert(
                                    header::COOKIE,
                                    cookie
                                        .to_str()?
                                        .split(';')
                                        .next()
                                        .context("replay cookie")?
                                        .parse()?,
                                );
                                self.session =
                                    self.shell.read_session(&self.headers, self.clock.wall())?;
                                let session =
                                    self.session.as_ref().context("replay signed session")?;
                                session.proof.require_intent(
                                    self.original_intent.as_ref().unwrap(),
                                    &identity(),
                                )?;
                            }
                            Ok(disposition(status))
                        } else {
                            Ok(Disposition::Refused)
                        }
                    }
                    Step::View => Ok(disposition(
                        self.dispatch(Method::GET, &self.path, None, &[])?.status(),
                    )),
                    Step::ExpireTicks => {
                        self.clock.expire_ticks()?;
                        Ok(Disposition::Ok)
                    }
                    Step::DelayKey => {
                        if let Some((_, target, _, _, _, _)) = &self.oauth {
                            target.delay_next_attestation();
                        } else {
                            self.credential
                                .as_ref()
                                .unwrap()
                                .keys
                                .delay
                                .store(true, Ordering::SeqCst);
                        }
                        Ok(Disposition::Ok)
                    }
                    Step::Restart => {
                        self.previous_providers = self.login.counts();
                        let (audience, client) = if let Some((_, target, _, _, _, _)) = &self.oauth
                        {
                            (target.audience.as_str(), target.client.as_str())
                        } else {
                            (
                                "/projects/1/global/backendServices/2",
                                "123.apps.googleusercontent.com",
                            )
                        };
                        self.login = shell_oidc::ReplayLogin::new(
                            &identity(),
                            audience,
                            client,
                            "https://security.example.com/",
                            1_001,
                            1_001,
                            1_301,
                        )?;
                        self.shell = Self::mount(
                            &self.login,
                            self.oauth.as_ref(),
                            self.credential.as_ref(),
                        )?;
                        Ok(Disposition::Ok)
                    }
                    Step::Confirm | Step::Reveal | Step::Acknowledge | Step::Duplicate => {
                        let session = self
                            .session
                            .as_ref()
                            .context("replay original session missing")?;
                        let body = if self.consumer == Consumer::OAuth {
                            url::form_urlencoded::Serializer::new(String::new())
                                .append_pair("challenge", session.challenge.as_str())
                                .append_pair("csrf", &session.csrf)
                                .finish()
                                .into_bytes()
                        } else {
                            credential_body(
                                session,
                                match step {
                                    Step::Acknowledge => "acknowledge",
                                    Step::Confirm => "confirm",
                                    _ => "reveal",
                                },
                            )
                        };
                        let result = self.dispatch(Method::POST, &self.path, None, &body);
                        match result {
                            Ok(response) => {
                                let status = response.status();
                                if step == Step::Reveal && status == StatusCode::OK {
                                    self.verify_private_response(response)?;
                                }
                                if step == Step::Acknowledge && status == StatusCode::SEE_OTHER {
                                    self.acknowledged = true;
                                }
                                Ok(disposition(status))
                            }
                            Err(_) => Ok(Disposition::Refused),
                        }
                    }
                    _ => anyhow::bail!("replay program precondition"),
                }
            }

            fn observe(&self) -> Result<(PublicState, Digest, Vec<Table>, Vec<Table>)> {
                let mut providers = self.login.counts();
                providers.iap_keys += self.previous_providers.iap_keys;
                providers.google_keys += self.previous_providers.google_keys;
                providers.exchanges += self.previous_providers.exchanges;
                let mut state = PublicState {
                    wall: self.clock.wall(),
                    ticks: effects::Hooks::monotonic(self.clock.as_ref()).as_secs(),
                    sessions: self.shell.sessions.lock().unwrap().len(),
                    google_pending: self.login.pending_count(),
                    activation: 0,
                    product: 0,
                    receipts: 0,
                    product_rows: 0,
                    delivery_closed: 0,
                    response_verified: self.response_verified,
                    oauth_keys: Default::default(),
                    credential_keys: [0; 2],
                    providers,
                };
                if let Some((_, target, foreign, database, foreign_database, before)) = &self.oauth
                {
                    state.oauth_keys = target.key_counts();
                    let mut db = open(database)?;
                    let read =
                        db.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
                    state.activation = read.query_row(
                        "SELECT count(*) FROM oauth_connection_slots WHERE status='active'",
                        [],
                        |row| row.get(0),
                    )?;
                    let exact: i64 = read.query_row("SELECT count(*) FROM oauth_connection_slots
                        WHERE slot=?1 AND generation=1 AND token_version=1 AND security_epoch=1 AND status='active'",
                        [&target.slot],|row| row.get(0))?;
                    ensure!(
                        exact == state.activation,
                        "replay wrong OAuth slot/generation/epoch publication"
                    );
                    ensure!(
                        foreign.key_counts() == Default::default(),
                        "foreign authority accessed"
                    );
                    let foreign_snapshot = snapshot(foreign_database)?;
                    ensure!(
                        foreign_snapshot == *before,
                        "foreign OAuth database changed"
                    );
                    let relation = target.verify_rows(&read)?;
                    Ok((state, relation, snapshot_in(&read)?, foreign_snapshot))
                } else {
                    let world = self.credential.as_ref().unwrap();
                    state.credential_keys = *world.keys.counts.lock().unwrap();
                    let mut connection = open(world.runtime.db())?;
                    let db = connection
                        .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
                    state.product = db.query_row(
                        "SELECT count(*) FROM day2_invocations WHERE status='success'",
                        [],
                        |row| row.get(0),
                    )?;
                    state.receipts =
                        db.query_row("SELECT count(*) FROM day2_credential_receipts", [], |row| {
                            row.get(0)
                        })?;
                    state.product_rows =
                        db.query_row("SELECT count(*) FROM entries", [], |row| row.get(0))?;
                    state.delivery_closed = db.query_row(
                        "SELECT count(*) FROM day2_credential_deliveries WHERE state='closed'",
                        [],
                        |row| row.get(0),
                    )?;
                    let exact: i64 = db.query_row("SELECT count(*) FROM day2_credential_receipts WHERE invocation=?1 AND action='issue'",
                        [&world.pending.invocation],|row| row.get(0))?;
                    ensure!(exact == state.receipts, "replay foreign credential receipt");
                    let foreign: (String,String,String,i64) = db.query_row(
                        "SELECT invocation,attempt,intent,expires_at FROM day2_credential_browser WHERE invocation=?1",
                        [&world.foreign.invocation],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?;
                    ensure!(
                        foreign
                            == (
                                world.foreign.invocation.clone(),
                                world.foreign.attempt.clone(),
                                serde_json::to_string(&world.foreign)?,
                                world.foreign.expires_at
                            ),
                        "foreign credential browser row changed"
                    );
                    let raw: String = db.query_row(
                        "SELECT intent FROM day2_credential_browser WHERE invocation=?1",
                        [&world.pending.invocation],
                        |row| row.get(0),
                    )?;
                    let mut expected_pending = serde_json::to_value(&world.pending)?;
                    if self.invalidated {
                        expected_pending["input"]["label"] =
                            serde_json::json!("Replaced current intent");
                    }
                    ensure!(
                        crate::json::decode::<serde_json::Value>(raw.as_bytes())?
                            == expected_pending,
                        "replay credential scheduled pending replacement changed other fields"
                    );
                    let material = self.credential_relations(&db, world)?;
                    let relation = Digest::of(&(
                        "original-credential-owner-relations-v2",
                        &world.pending,
                        &world.namespace,
                        &world.family_contract,
                        &material,
                        &self.response_identity,
                    ))?;
                    Ok((state, relation, snapshot_in(&db)?, Vec::new()))
                }
            }
        }

        fn disposition(status: StatusCode) -> Disposition {
            match status {
                StatusCode::OK => Disposition::Ok,
                StatusCode::SEE_OTHER => Disposition::Redirect,
                StatusCode::NOT_FOUND => Disposition::NotFound,
                StatusCode::UNAUTHORIZED => Disposition::Unauthorized,
                _ => Disposition::Refused,
            }
        }

        fn program(consumer: Consumer, case: Case) -> Vec<Step> {
            let mut steps = vec![Step::Begin];
            if case == Case::OppositePurpose {
                steps.push(Step::OppositePurpose);
            }
            steps.push(Step::Reuse);
            if case == Case::Invalidate {
                steps.push(Step::Invalidate);
            }
            steps.push(Step::Callback);
            if matches!(case, Case::WrongSubject | Case::Invalidate) {
                steps.push(Step::Duplicate);
                return steps;
            }
            steps.push(Step::View);
            match case {
                Case::TicksExpired => steps.push(Step::ExpireTicks),
                Case::KeyDelay => steps.push(Step::DelayKey),
                Case::Restart => steps.push(Step::Restart),
                _ => {}
            }
            steps.push(Step::Confirm);
            if matches!(case, Case::TicksExpired | Case::KeyDelay) {
                return steps;
            }
            if consumer == Consumer::Credential && case != Case::Restart {
                steps.extend([Step::Reveal, Step::Acknowledge]);
            }
            steps.push(Step::Duplicate);
            steps
        }

        #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
        struct Observation {
            step: Step,
            expected: Disposition,
            actual: Disposition,
            response_status: Option<u16>,
            expected_state: PublicState,
            actual_state: PublicState,
            authorization: Digest,
            original_relations: Digest,
            response_identity: Option<Digest>,
            target: Vec<Table>,
            foreign: Vec<Table>,
        }

        #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
        struct Failure {
            category: String,
            index: Option<usize>,
            step: Option<Step>,
            field: String,
            protected_detail: Option<Digest>,
            response_status: Option<u16>,
        }

        impl Failure {
            fn error(
                category: &str,
                index: Option<usize>,
                step: Option<Step>,
                error: &anyhow::Error,
            ) -> Self {
                Self {
                    category: category.into(),
                    index,
                    step,
                    field: category.into(),
                    protected_detail: Some(Digest::new(format!("{error:#}").as_bytes())),
                    response_status: None,
                }
            }

            fn signature(&self) -> (&str, Option<Step>, &str) {
                (&self.category, self.step, &self.field)
            }
        }

        #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
        struct Trace {
            version: u32,
            consumer: Consumer,
            case: Case,
            program: Vec<Step>,
            sources: BTreeMap<String, Digest>,
            toolchain: Digest,
            artifact: Option<String>,
            fixture: Digest,
            observations: Vec<Observation>,
            first_failure: Option<Failure>,
            refusals: Vec<Failure>,
        }

        impl Trace {
            fn refuse(&mut self, failure: Failure) {
                if self.first_failure.is_none() {
                    self.first_failure = Some(failure.clone());
                }
                self.refusals.push(failure);
            }
        }

        const TRACE_BYTES: usize = 4 * 1_024 * 1_024;
        const SNAPSHOT_BYTES: usize = 96 * 1_024;

        fn execute(consumer: Consumer, case: Case, steps: &[Step]) -> Trace {
            let mut trace = Trace {version:2,consumer,case,program:steps.to_vec(),
                sources:BTreeMap::from([
                    ("crates/day2/src/development.rs".into(),Digest::new(include_bytes!("../development.rs"))),
                    ("crates/day2/src/oauth/admission.rs".into(),Digest::new(include_bytes!("admission.rs"))),
                    ("crates/day2/src/oauth/shell_oidc.rs".into(),Digest::new(include_bytes!("shell_oidc.rs"))),
                    ("crates/day2/src/oauth/security_shell.rs".into(),Digest::new(include_bytes!("security_shell.rs"))),
                ]),toolchain:Digest::new(include_bytes!("../../../../toolchain.json")),artifact:None,
                fixture:Digest::new(b"signed-google-replay-v2;seed=17;wall=1000;complete=1001;exp=1301;fixed-reviewed-keys;modeled-host-deadline"),
                observations:Vec::new(),first_failure:None,refusals:Vec::new()};
            if steps.is_empty() || steps.len() > 16 || !prerequisites(consumer, case, steps) {
                trace.refuse(Failure {
                    category: "program_refusal".into(),
                    index: None,
                    step: None,
                    field: "program".into(),
                    protected_detail: None,
                    response_status: None,
                });
                return trace;
            }
            let clock = Clock::new();
            effects::scope(clock.clone(), || {
                credential_effects::scope(clock.clone(), || {
                    let mut world = match World::new(consumer, clock) {
                        Ok(world) => world,
                        Err(error) => {
                            trace.refuse(Failure::error("setup_refusal", None, None, &error));
                            return trace;
                        }
                    };
                    trace.artifact = world
                        .credential
                        .as_ref()
                        .map(|world| world.runtime.artifact().id().to_owned());
                    let mut model = Model::new(consumer, case);
                    for (index, step) in steps.iter().copied().enumerate() {
                        let expected = model.step(step);
                        let actual = match world.step(step, case) {
                            Ok(actual) => actual,
                            Err(error) => {
                                let mut failure =
                                    Failure::error("step_refusal", Some(index), Some(step), &error);
                                failure.response_status = *world.response_status.lock().unwrap();
                                trace.refuse(failure);
                                // Capture the complete post-error state too: a
                                // failing action may already have committed writes.
                                Disposition::Refused
                            }
                        };
                        let (actual_state, original_relations, target, foreign) =
                            match world.observe() {
                                Ok(value) => value,
                                Err(error) => {
                                    trace.refuse(Failure::error(
                                        "snapshot_or_relation_refusal",
                                        Some(index),
                                        Some(step),
                                        &error,
                                    ));
                                    break;
                                }
                            };
                        // The original begin and exact unsigned claim inputs are
                        // retained even when a restart discards volatile verifier state.
                        let Some(authorization) = world.original_authorization.clone() else {
                            trace.refuse(Failure {
                                category: "authorization_refusal".into(),
                                index: Some(index),
                                step: Some(step),
                                field: "original_authorization".into(),
                                protected_detail: None,
                                response_status: *world.response_status.lock().unwrap(),
                            });
                            break;
                        };
                        let observation = Observation {
                            step,
                            expected,
                            actual,
                            response_status: *world.response_status.lock().unwrap(),
                            expected_state: model.state.clone(),
                            actual_state: actual_state.clone(),
                            authorization,
                            original_relations,
                            response_identity: world.response_identity.clone(),
                            target,
                            foreign,
                        };
                        let admitted = serde_json::to_vec(&observation).ok();
                        let existing = serde_json::to_vec(&trace).ok();
                        if !matches!((&admitted,&existing),(Some(next),Some(old)) if old.len()+next.len()+4096 <= TRACE_BYTES)
                        {
                            trace.refuse(Failure {
                                category: "trace_envelope_refusal".into(),
                                index: Some(index),
                                step: Some(step),
                                field: "complete_observation".into(),
                                protected_detail: admitted.as_ref().map(|bytes| Digest::new(bytes)),
                                response_status: *world.response_status.lock().unwrap(),
                            });
                            break;
                        }
                        trace.observations.push(observation);
                        if actual != expected || actual_state != model.state {
                            let (field, detail) = if actual != expected {
                                ("disposition".into(), Digest::of(&(expected, actual)).ok())
                            } else {
                                let expected =
                                    serde_json::to_value(&model.state).expect("literal model JSON");
                                let actual = serde_json::to_value(&actual_state)
                                    .expect("observed public JSON");
                                (
                                    first_difference(&expected, &actual, "actual_state")
                                        .unwrap_or_else(|| "actual_state".into()),
                                    Digest::of(&(&expected, &actual)).ok(),
                                )
                            };
                            trace.refuse(Failure {
                                category: "model_mismatch".into(),
                                index: Some(index),
                                step: Some(step),
                                field,
                                protected_detail: detail,
                                response_status: *world.response_status.lock().unwrap(),
                            });
                            break;
                        }
                        if trace.first_failure.is_some() {
                            break;
                        }
                    }
                    trace
                })
            })
        }

        fn prerequisites(consumer: Consumer, case: Case, steps: &[Step]) -> bool {
            // Preserve the original owner's begin/callback, the actual
            // negative trigger, final post and one-use probe. Reduction can
            // remove only the two optional observations, never manufacture a
            // refusal by deleting its causal action or lifetime boundary.
            let declared = program(consumer, case);
            let essential = |steps: &[Step]| {
                steps
                    .iter()
                    .copied()
                    .filter(|step| !matches!(step, Step::Reuse | Step::View))
                    .collect::<Vec<_>>()
            };
            if essential(steps) != essential(&declared) {
                return false;
            }
            let mut cursor = 0;
            for step in steps {
                let Some(offset) = declared[cursor..].iter().position(|actual| actual == step)
                else {
                    return false;
                };
                cursor += offset + 1;
            }
            let mut begun = false;
            let mut callback = false;
            let mut confirmed = false;
            let mut revealed = false;
            for step in steps {
                match step {
                    Step::Begin if !begun => begun = true,
                    Step::Reuse | Step::OppositePurpose | Step::Invalidate
                        if begun && !callback => {}
                    Step::Callback if begun && !callback => callback = true,
                    Step::View | Step::ExpireTicks | Step::DelayKey | Step::Restart if callback => {
                    }
                    Step::Confirm if callback && !confirmed => confirmed = true,
                    Step::Reveal if confirmed && !revealed => revealed = true,
                    Step::Acknowledge if revealed => {}
                    Step::Duplicate if callback => {}
                    _ => return false,
                }
            }
            begun && callback
        }

        fn first_difference(
            left: &serde_json::Value,
            right: &serde_json::Value,
            path: &str,
        ) -> Option<String> {
            if left == right {
                return None;
            }
            match (left, right) {
                (serde_json::Value::Object(left), serde_json::Value::Object(right)) => {
                    for key in left
                        .keys()
                        .chain(right.keys())
                        .collect::<std::collections::BTreeSet<_>>()
                    {
                        let next = format!("{path}.{key}");
                        match (left.get(key), right.get(key)) {
                            (Some(left), Some(right)) => {
                                if let Some(path) = first_difference(left, right, &next) {
                                    return Some(path);
                                }
                            }
                            _ => return Some(next),
                        }
                    }
                }
                (serde_json::Value::Array(left), serde_json::Value::Array(right)) => {
                    for index in 0..left.len().max(right.len()) {
                        let next = format!("{path}[{index}]");
                        match (left.get(index), right.get(index)) {
                            (Some(left), Some(right)) => {
                                if let Some(path) = first_difference(left, right, &next) {
                                    return Some(path);
                                }
                            }
                            _ => return Some(next),
                        }
                    }
                }
                _ => {}
            }
            Some(path.into())
        }

        fn persist_failure(first: &Trace, second: &Trace) -> Result<()> {
            use std::io::Write;
            let directory = tempfile::Builder::new()
                .prefix("day2roc-signed-replay-failure-")
                .tempdir()?;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
            // Keep the directory BEFORE any fallible write/reduction. Failed
            // reduction or storage cannot delete previously saved originals.
            let path = directory.keep();
            eprintln!("private signed replay failure evidence: {}", path.display());
            let write = |name: &str, bytes: &[u8]| -> Result<()> {
                let limit = if matches!(name, "first.json" | "second.json" | "reduced.json") {
                    TRACE_BYTES
                } else {
                    65_536
                };
                ensure!(
                    bytes.len() <= limit,
                    "replay complete trace storage envelope"
                );
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path.join(name))?;
                file.write_all(bytes)?;
                file.sync_all()?;
                Ok(())
            };
            write("first.json", &serde_json::to_vec(first)?)?;
            write("second.json", &serde_json::to_vec(second)?)?;
            let difference = first_difference(
                &serde_json::to_value(first)?,
                &serde_json::to_value(second)?,
                "trace",
            );
            write(
                "original-difference.json",
                &serde_json::to_vec(&serde_json::json!({"first_differing_safe_field":difference,
                "first_failure":first.first_failure,"second_failure":second.first_failure,
                "source_artifact_tool_fixture_binding":"in both complete original traces"}))?,
            )?;
            let original = if first.first_failure.is_some() {
                first
            } else {
                second
            };
            let mut reduced = original.clone();
            let mut attempts = 0usize;
            let mut refusals = Vec::new();
            if let Some(category) = original.first_failure.as_ref() {
                let mut index = 1;
                while index < reduced.program.len() && attempts < 64 {
                    let mut candidate = reduced.program.clone();
                    candidate.remove(index);
                    if !prerequisites(first.consumer, first.case, &candidate) {
                        index += 1;
                        continue;
                    }
                    attempts += 1;
                    let actual = execute(first.consumer, first.case, &candidate);
                    let actual_failure = actual.first_failure.clone();
                    // Preserve exact original failed field AND protected
                    // counterexample values, not merely a generic refusal.
                    if actual.first_failure.as_ref().is_some_and(|failure| {
                        failure.signature() == category.signature()
                            && failure.protected_detail == category.protected_detail
                            && failure.response_status == category.response_status
                    }) {
                        reduced = actual;
                    } else {
                        index += 1;
                    }
                    refusals.push(serde_json::json!({"attempt":attempts,"program":candidate,"actual_failure":actual_failure}));
                }
            }
            write("reduced.json", &serde_json::to_vec(&reduced)?)?;
            write(
                "reduction.json",
                &serde_json::to_vec(&serde_json::json!({
                    "version":2,"classification":"synthetic-local-signed-replay-only",
                    "reduction_attempts":attempts,"actual_attempt_refusals":refusals,
                    "equality_only_divergence":"original pair retained without speculative reduction",
                    "saved_corpus_input":"absent; this is a newly retained actual divergence",
                }))?,
            )?;
            Ok(())
        }

        fn compare(consumer: Consumer, case: Case) -> Result<()> {
            let steps = program(consumer, case);
            ensure!(
                prerequisites(consumer, case, &steps),
                "signed replay declared prerequisites"
            );
            let first = execute(consumer, case, &steps);
            let second = execute(consumer, case, &steps);
            if first.first_failure.is_some() || second.first_failure.is_some() || first != second {
                persist_failure(&first, &second)?;
                anyhow::bail!(
                    "signed replay model or exact-state divergence; private evidence retained"
                );
            }
            ensure!(
                first.observations.len() == steps.len(),
                "signed replay incomplete trace"
            );
            Ok(())
        }

        #[test]
        fn signed_google_replay_two_positive_owner_histories() -> Result<()> {
            for consumer in [Consumer::OAuth, Consumer::Credential] {
                compare(consumer, Case::Positive)?;
            }
            Ok(())
        }

        #[test]
        fn signed_google_replay_six_paired_negative_owner_histories() -> Result<()> {
            for case in [
                Case::WrongSubject,
                Case::OppositePurpose,
                Case::Invalidate,
                Case::TicksExpired,
                Case::KeyDelay,
                Case::Restart,
            ] {
                for consumer in [Consumer::OAuth, Consumer::Credential] {
                    compare(consumer, case)?;
                }
            }
            Ok(())
        }

        fn identity() -> iap::Verified {
            iap::Verified {
                email: "alice@example.com".into(),
                subject: "accounts.google.com:google-alice".into(),
            }
        }

        // Every value in every user-table column is protected regardless of
        // its name. Type, length and SHA256 bind all exact bytes, including
        // integer/REAL bits; no column is dropped or normalized. Public model
        // counts are a separate projection. Bounds cover produced payload,
        // not Vec capacity or total allocator overhead.
        #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
        struct Table {
            name: String,
            definition: Digest,
            columns: Vec<String>,
            rows: Vec<Vec<serde_json::Value>>,
        }

        fn snapshot(path: &Path) -> Result<Vec<Table>> {
            let mut db = open(path)?;
            let read = db.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
            snapshot_in(&read)
        }

        fn snapshot_in(db: &rusqlite::Connection) -> Result<Vec<Table>> {
            let mut total = 0usize;
            let mut catalog = db.prepare("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*' ORDER BY name LIMIT 257")?;
            let definitions = catalog
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            ensure!(definitions.len() <= 256, "replay table budget");
            let mut tables = Vec::new();
            for (name, sql) in definitions {
                total = total
                    .checked_add(name.len())
                    .and_then(|size| size.checked_add(sql.len()))
                    .context("replay catalog byte overflow")?;
                ensure!(total <= 4 * 1_024 * 1_024, "replay catalog byte budget");
                let quoted = format!("\"{}\"", name.replace('"', "\"\""));
                let mut statement = db.prepare(&format!("SELECT * FROM {quoted} LIMIT 129"))?;
                let columns = statement
                    .column_names()
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                ensure!(columns.len() <= 64, "replay column budget");
                let mut query = statement.query([])?;
                let mut rows = Vec::new();
                while let Some(row) = query.next()? {
                    ensure!(rows.len() < 128, "replay row budget");
                    let mut values = Vec::new();
                    for index in 0..columns.len() {
                        use rusqlite::types::ValueRef;
                        let value = match row.get_ref(index)? {
                            ValueRef::Null => serde_json::json!(["null"]),
                            ValueRef::Integer(value) => {
                                serde_json::json!(["integer", 8, Digest::new(&value.to_le_bytes())])
                            }
                            ValueRef::Real(value) => serde_json::json!([
                                "real_bits",
                                8,
                                Digest::new(&value.to_bits().to_le_bytes())
                            ]),
                            ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
                                ensure!(bytes.len() <= 65_536, "replay field budget");
                                total = total
                                    .checked_add(bytes.len())
                                    .context("replay byte overflow")?;
                                ensure!(total <= 4 * 1_024 * 1_024, "replay byte budget");
                                let kind = if matches!(row.get_ref(index)?, ValueRef::Text(_)) {
                                    "text"
                                } else {
                                    "blob"
                                };
                                serde_json::json!([kind, bytes.len(), Digest::new(bytes)])
                            }
                        };
                        total = total
                            .checked_add(serde_json::to_vec(&value)?.len())
                            .context("replay payload byte overflow")?;
                        ensure!(total <= 4 * 1_024 * 1_024, "replay produced payload budget");
                        values.push(value);
                    }
                    rows.push(values);
                }
                // Complete typed row keys, with duplicates preserved.
                rows.sort_by_key(|row| serde_json::to_vec(row).expect("replay JSON row"));
                tables.push(Table {
                    name,
                    definition: Digest::new(sql.as_bytes()),
                    columns,
                    rows,
                });
            }
            ensure!(
                serde_json::to_vec(&tables)?.len() <= SNAPSHOT_BYTES,
                "replay complete snapshot payload budget"
            );
            Ok(tables)
        }
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
        let session = ShellSession::approval_fixture(
            &view,
            &identity,
            5,
            Digest::new(b"fixture issued shell cookie"),
        )
        .unwrap();
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
