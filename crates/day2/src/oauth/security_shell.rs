//! Isolated browser approval for an external provider account. The shell has
//! its own origin and short-lived cookie; app sessions never authorize it.

#[cfg(test)]
use super::approval_registry;
use super::{admission, approval_keys, connect, external, profiles, shell_oidc, shell_transport};
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
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;

const COOKIE: &str = "__Host-day2_security_shell";
const PREFIX: &str = "/oauth/approvals/";
const SESSION_SECONDS: i64 = 300;
const MAX_SESSIONS: usize = 1024;

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
}

impl SecurityShell {
    /// Compose the shell from the exact instance-selected artifacts and keys.
    /// This is an explicit GKE host entry point, not an application route or a
    /// readiness assertion. The shell has no app storage paths or custody keys.
    pub(crate) fn from_gke_instance(
        instance_path: &Path,
        catalog: &admission::ReviewedCatalog,
        bearers: Arc<dyn shell_transport::PrivateBearerSource>,
        client_id: String,
        client_secret: String,
    ) -> Result<(Arc<Self>, Arc<admission::ArtifactShellSigner>)> {
        let selected = admission::QualifiedConnections::from_instance_file(instance_path, catalog)?;
        let instance = selected.instance().clone();
        let signer = Arc::new(admission::ArtifactShellSigner::with_gcp(
            selected,
            Arc::new(approval_keys::GkeMetadataAccessTokens::new()?),
        )?);
        let (identity, edge) = instance.security_edge()?;
        let origin = format!("{}/", edge.origin);
        let authenticator = Arc::new(shell_oidc::GoogleFreshAuthenticator::new(
            &edge.iap_audience,
            &identity.hosted_domain,
            &origin,
            client_id,
            client_secret,
        )?);
        let approvals = Arc::new(shell_transport::RemoteApprovals::from_instance(
            &instance, bearers,
        )?);
        Ok((
            Self::with_transport(origin, approvals, signer.clone(), authenticator)?,
            signer,
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
        }))
    }

    /// Attach the same installation's host-selected credential runtimes before
    /// serving. Both flows share this isolated edge and fresh OIDC verifier.
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
        let router = Router::new().fallback(move |request: Request| {
            let shell = self.clone();
            async move { shell.handle(request).await }
        });
        axum::serve(listener, router).await?;
        Ok(())
    }

    async fn handle(self: Arc<Self>, request: Request) -> Response {
        let (parts, body) = request.into_parts();
        let body = match to_bytes(body, 4096).await {
            Ok(body) => body,
            Err(_) => return protected(StatusCode::PAYLOAD_TOO_LARGE.into_response()),
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
            let markup = html! { (DOCTYPE) html lang="en" {
                head { meta charset="utf-8"; title { "Credential action" } }
                body { main {
                    h1 { @if confirmed { "Credential delivery" } @else { "Create credential" } }
                    dl { dt { "Application" } dd { (runtime.app()) } dt { "Command" } dd { (pending.operation) }
                        dt { "Family" } dd { (pending.family) } dt { "Label" } dd { (pending.label) }
                        dt { "Recipient" } dd { (identity.email) } }
                    @if !confirmed { p { "Confirm this product command. It creates the credential and its product records together." } }
                    form method="post" action=(pending.path()) {
                        input type="hidden" name="csrf" value=(session.csrf);
                        input type="hidden" name="challenge" value=(challenge.as_str());
                        @if confirmed {
                            button type="submit" name="action" value="reveal" { "Reveal key" }
                            button type="submit" name="action" value="acknowledge" { "Finish and close delivery" }
                        } @else { button type="submit" name="action" value="confirm" { "Create credential" } }
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
    use std::{collections::BTreeMap, sync::atomic::{AtomicUsize, Ordering}};

    struct NoOAuth;
    impl shell_transport::ShellApprovals for NoOAuth {
        fn pending(&self, _: &str, _: &iap::Verified, _: &HeaderMap, _: i64) -> Result<Option<shell_transport::ApprovalView>> {
            Ok(None)
        }

        fn confirm(&self, _: &shell_transport::ApprovalView, _: &iap::Verified, _: &HeaderMap, _: external::FreshExternalApproval, _: i64) -> Result<bool> {
            anyhow::bail!("OAuth confirmation unavailable in credential fixture")
        }
    }

    impl shell_transport::ApprovalSigner for NoOAuth {
        fn attest(&self, _: &shell_transport::ApprovalView, _: Digest, _: i64, _: i64) -> Result<external::FreshExternalApproval> {
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
                    .unwrap_or("google-alice")
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
        std::fs::write(runtime.instance_path(), serde_json::to_vec(&instance)?)?;
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
                issuers: BTreeMap::from([("alice@example.com".into(), "google-alice".into())]),
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
        let url = credentials::start(
            &world.runtime,
            operation,
            "alice@example.com",
            id,
            &serde_json::json!({"label":"Transcription client"}),
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
            assert!(
                !String::from_utf8(to_bytes(get.into_body(), 8192).await?.to_vec())?
                    .contains("d2c1.")
            );
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
        assert_eq!(personal, "google-alice");
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
