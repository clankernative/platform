//! Isolated browser approval for an external provider account. The shell has
//! its own origin and short-lived cookie; app sessions never authorize it.

use super::{connect, external, profiles};
use crate::{managed_credentials::crypto::KeyLease, store::open, web_security};
use anyhow::{Result, ensure};
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
    collections::{BTreeSet, HashMap},
    path::PathBuf,
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
    fn qualification(&self) -> profiles::OutboundQualification<'_> {
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
    fn resolve(&self, attempt: &str) -> Result<Option<ApprovalContext>>;
}

/// The caller must verify an interactive reauthentication event at the shell
/// edge. An ordinary IAP assertion or the app's web session is insufficient:
/// neither proves when the human last authenticated.
pub(crate) trait FreshAuthenticator: Send + Sync {
    fn verify_fresh(&self, headers: &HeaderMap, now: i64) -> Result<FreshHuman>;
}

pub(crate) struct FreshHuman {
    pub human: String,
    pub authenticated_at: i64,
}

#[derive(Clone)]
struct ShellSession {
    attempt: String,
    human: String,
    challenge: Digest,
    authenticated_at: i64,
    expires_at: i64,
    csrf: String,
}

/// Mount this router only behind the dedicated HTTPS security origin. The
/// listener must not be shared with the app's route dispatcher.
pub(crate) struct SecurityShell {
    origin: String,
    authority: String,
    db: PathBuf,
    registry: Arc<dyn ApprovalRegistry>,
    authenticator: Arc<dyn FreshAuthenticator>,
    sessions: Mutex<HashMap<String, ShellSession>>,
}

impl SecurityShell {
    pub(crate) fn new(
        origin: String,
        db: PathBuf,
        registry: Arc<dyn ApprovalRegistry>,
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
            db,
            registry,
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
        let response = self.dispatch(
            &parts.method,
            parts.uri.path(),
            parts.uri.query(),
            &parts.headers,
            &body,
            at,
        );
        protected(response.unwrap_or_else(|_| StatusCode::FORBIDDEN.into_response()))
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
                && query.is_none()
                && !headers.contains_key("x-http-method-override"),
            "invalid security shell request"
        );
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
                self.page(attempt, headers, at)
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
                self.confirm(attempt, headers, body, at)
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
        at: i64,
    ) -> Result<Option<(ApprovalContext, external::PendingExternalApproval)>> {
        let Some(context) = self.registry.resolve(attempt)? else {
            return Ok(None);
        };
        ensure!(
            context.intent.attempt == attempt
                && context.instance.shell.origin_url == format!("{}/", self.origin)
                && context.instance.app_origin_url != format!("{}/", self.origin),
            "security shell registry origin mismatch"
        );
        let db = open(&self.db)?;
        let pending = external::load_pending_external(
            &db,
            context.qualification(),
            &context.custody_key,
            at,
        )?;
        Ok(pending.map(|pending| (context, pending)))
    }

    fn page(&self, attempt: &str, headers: &HeaderMap, at: i64) -> Result<Response> {
        let Some((context, pending)) = self.pending(attempt, at)? else {
            return Ok(StatusCode::NOT_FOUND.into_response());
        };
        let (session, issued) = match self.read_session(headers, at)? {
            Some(session) if valid_session(&session, &pending, at) => (session, None),
            _ => {
                let human = self.authenticator.verify_fresh(headers, at)?;
                ensure!(
                    human.human == pending.human()
                        && human.authenticated_at > pending.quarantined_at()
                        && human.authenticated_at <= at
                        && at - human.authenticated_at <= SESSION_SECONDS,
                    "fresh shell authentication required"
                );
                let token = web_security::random()?;
                let session = ShellSession {
                    attempt: attempt.to_owned(),
                    human: human.human,
                    challenge: pending.challenge().clone(),
                    authenticated_at: human.authenticated_at,
                    expires_at: (human.authenticated_at + SESSION_SECONDS)
                        .min(at + SESSION_SECONDS),
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
                (session, Some(token))
            }
        };
        let account = pending.observed_account();
        let scopes: BTreeSet<&str> = context
            .permission
            .action_scopes
            .values()
            .flat_map(|scopes| scopes.iter().map(String::as_str))
            .collect();
        let markup = html! {
            (DOCTYPE)
            html lang="en" {
                head { meta charset="utf-8"; title { "Approve external account" } }
                body {
                    main {
                        h1 { "Approve external account" }
                        p { "Confirm the provider identity for this connection." }
                        dl {
                            dt { "Connection" } dd { (context.requirement.logical_id) }
                            dt { "Purpose" } dd { (context.requirement.usage) }
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

    fn confirm(
        &self,
        attempt: &str,
        headers: &HeaderMap,
        body: &[u8],
        at: i64,
    ) -> Result<Response> {
        let Some((context, pending)) = self.pending(attempt, at)? else {
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
                valid_session(session, &pending, at) && fields.get("csrf") == Some(&session.csrf),
                "security shell session or CSRF mismatch"
            );
            sessions.remove(&key).expect("checked shell session")
        };
        let evidence = context.shell_key.attest(
            &pending,
            Digest::new(token.as_bytes()),
            session.authenticated_at,
            at,
        )?;
        let mut db = open(&self.db)?;
        let approved = external::approve_external(
            &mut db,
            context.qualification(),
            &context.custody_key,
            &context.shell_key,
            evidence,
            at,
        )?;
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
    pending: &external::PendingExternalApproval,
    at: i64,
) -> bool {
    session.attempt == pending.attempt()
        && session.human == pending.human()
        && session.challenge == *pending.challenge()
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
}
