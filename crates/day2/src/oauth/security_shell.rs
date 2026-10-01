//! Isolated browser approval for an external provider account. The shell has
//! its own origin and short-lived cookie; app sessions never authorize it.

#[cfg(test)]
use super::approval_registry;
use super::{admission, approval_keys, connect, external, profiles, shell_oidc, shell_transport};
use crate::iap;
use crate::{managed_credentials::crypto::KeyLease, web_security};
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
}

impl SecurityShell {
    /// Compose the shell from the exact instance-selected artifacts and keys.
    /// This is an explicit GKE host entry point, not an application route or a
    /// readiness assertion. The shell has no app storage paths or custody keys.
    pub(crate) fn from_gke_instance(
        instance_path: &Path,
        catalog: &admission::ReviewedCatalog,
        client_id: String,
        client_secret: String,
    ) -> Result<(Arc<Self>, Arc<admission::ArtifactShellSigner>)> {
        let selected = admission::QualifiedConnections::from_instance_file(instance_path, catalog)?;
        let instance = selected.instance().clone();
        let bearers = Arc::new(super::workload::IapWorkload::from_gke_instance(&instance)?);
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
        }))
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
