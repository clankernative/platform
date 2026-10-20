//! Native shell UI and one-shot browser ownership for product management.
//! This module has no app database, provider credential or custody key.
use super::{
    Action, View,
    app::{Call, Reply},
};
use crate::{
    iap,
    oauth::{
        admission, effects,
        fresh_auth::{FreshIntent, VerifiedAuthTime},
        protocol,
        security_shell::{FreshAuthenticator, ReauthStart},
        shell_transport::RemoteApprovals,
    },
    web_security,
};
use anyhow::{Context as _, Result, ensure};
use axum::{
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use day2_capabilities::Digest;
use maud::{DOCTYPE, html};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

const COOKIE: &str = "__Host-day2_oauth_management";

/// Borrowed HTTP data only. Authentication and session ownership are checked by
/// the shell independently; constructing this does not authorize a callback.
pub(in crate::oauth) struct CallbackRequest<'a> {
    pub method: &'a Method,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a HeaderMap,
    pub body: &'a [u8],
}

#[derive(PartialEq, Eq)]
enum Stage {
    Confirm,
    Provider { state: Digest },
}

struct Session {
    view: View,
    proof: VerifiedAuthTime,
    csrf: String,
    digest: Digest,
    stage: Stage,
}

pub(in crate::oauth) struct Shell {
    origin: String,
    remote: Arc<RemoteApprovals>,
    signer: Arc<admission::ArtifactShellSigner>,
    authenticator: Arc<dyn FreshAuthenticator>,
    sessions: Mutex<HashMap<String, Session>>,
}

impl Shell {
    pub(in crate::oauth) fn new(
        origin: String,
        remote: Arc<RemoteApprovals>,
        signer: Arc<admission::ArtifactShellSigner>,
        authenticator: Arc<dyn FreshAuthenticator>,
    ) -> Self {
        Self {
            origin,
            remote,
            signer,
            authenticator,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn pending(
        &self,
        id: &str,
        headers: &HeaderMap,
        identity: &iap::Verified,
        now: i64,
    ) -> Result<View> {
        let app = self.remote.management_owner(id)?;
        let Reply::Pending { view } =
            self.remote
                .management(app, Call::Pending { id: id.into() }, headers)?
        else {
            anyhow::bail!("OAuth management pending unavailable");
        };
        view.validate(identity, now)?;
        ensure!(
            view.id == id && view.shell_origin == format!("{}/", self.origin),
            "OAuth management shell changed"
        );
        Ok(*view)
    }

    pub(in crate::oauth) fn reauthenticated(
        &self,
        proof: VerifiedAuthTime,
        headers: &HeaderMap,
        identity: &iap::Verified,
        now: i64,
    ) -> Result<Response> {
        let view = self.pending(proof.attempt(), headers, identity, now)?;
        proof.require_intent(&FreshIntent::management(&view, identity)?, identity)?;
        proof.require_current(now)?;
        proof.validate_management_observation()?;
        let intent = FreshIntent::management(&view, identity)?;
        crate::oauth::native_management::with_consumer(
            &intent,
            crate::oauth::native_management::Phase::Session,
            now,
            |current| {
                proof.require_management_authentication(current)?;
                let token = effects::random()?;
                let digest = Digest::new(token.as_bytes());
                let session = Session {
                    view: view.clone(),
                    proof,
                    csrf: effects::random()?,
                    digest: digest.clone(),
                    stage: Stage::Confirm,
                };
                let mut sessions = self
                    .sessions
                    .lock()
                    .map_err(|_| anyhow::anyhow!("OAuth management session unavailable"))?;
                sessions.retain(|_, s| now < s.view.expires_at);
                ensure!(
                    sessions.len() < 1024,
                    "OAuth management session capacity reached"
                );
                current.check()?;
                ensure!(
                    !sessions.contains_key(digest.as_str()),
                    "OAuth management session collision"
                );
                current.arm()?;
                sessions.insert(digest.as_str().into(), session);
                // An expired/changed owner after insertion must not leave a
                // usable session even if the response is never constructed.
                let response = (|| {
                    current.check()?;
                    with_cookie(
                        redirect(&format!("{}pending/{}", super::PREFIX, view.id)),
                        &token,
                        view.expires_at - now,
                    )
                })();
                if response.is_err() {
                    sessions.remove(digest.as_str());
                }
                response
            },
        )
    }

    pub(in crate::oauth) fn dispatch(
        &self,
        method: &Method,
        tail: &str,
        headers: &HeaderMap,
        body: &[u8],
        identity: &iap::Verified,
        now: i64,
    ) -> Result<Response> {
        if let Some(id) = tail.strip_prefix("pending/") {
            crate::oauth::shell_transport::attempt(id)?;
            return self.confirmation(method, id, headers, body, identity, now);
        }
        let parts = tail.split('/').collect::<Vec<_>>();
        ensure!(parts.len() == 2, "OAuth management route unavailable");
        let (app, registration) = (parts[0], parts[1]);
        day2_contracts::names::identifier(app)?;
        crate::oauth::connect::identifier(registration)?;
        if *method == Method::GET {
            ensure!(body.is_empty(), "OAuth management GET body refused");
            return Ok(page(html! {
                (DOCTYPE) html lang="en" { head { meta charset="utf-8"; title { "Manage connection" } }
                    body { main { h1 { "Manage connection" } p { (app) " / " (registration) }
                        p { "A new authentication and confirmation is required for each action." }
                        form method="post" {
                            button type="submit" name="operation" value="connect" { "Connect" }
                            button type="submit" name="operation" value="disconnect" { "Disconnect" }
                        }
                    } }
                }
            }));
        }
        require_post(method, headers, &self.origin)?;
        let fields = web_security::fields(body)?;
        ensure!(fields.len() == 1, "OAuth management form refused");
        let action = match fields.get("operation").map(String::as_str) {
            Some("connect") => Action::Connect,
            Some("disconnect") => Action::Disconnect,
            _ => anyhow::bail!("OAuth management operation refused"),
        };
        let Reply::Pending { view } = self.remote.management(
            app,
            Call::Capture {
                registration: registration.into(),
                operation: action,
            },
            headers,
        )?
        else {
            anyhow::bail!("OAuth management context unavailable");
        };
        let at = effects::wall_time()?;
        ensure!(at >= now, "OAuth management clock moved backwards");
        view.validate(identity, at)?;
        ensure!(
            view.app == app
                && view.registration == registration
                && view.action == action
                && view.shell_origin == format!("{}/", self.origin),
            "OAuth management capture changed"
        );
        match self.authenticator.begin(
            identity,
            FreshIntent::management(&view, identity)?,
            headers,
            at,
        )? {
            ReauthStart::Redirect(location) => Ok(redirect(&location)),
            #[cfg(test)]
            ReauthStart::Authenticated(_) => {
                anyhow::bail!("OAuth management requires signed callback")
            }
        }
    }

    fn confirmation(
        &self,
        method: &Method,
        id: &str,
        headers: &HeaderMap,
        body: &[u8],
        identity: &iap::Verified,
        now: i64,
    ) -> Result<Response> {
        let view = self.pending(id, headers, identity, now)?;
        let token = cookie(headers)?.context("OAuth management browser session missing")?;
        let key = Digest::new(token.as_bytes());
        if *method == Method::GET {
            ensure!(body.is_empty(), "OAuth management GET body refused");
            let sessions = self
                .sessions
                .lock()
                .map_err(|_| anyhow::anyhow!("OAuth management session unavailable"))?;
            let session = sessions
                .get(key.as_str())
                .context("OAuth management session unavailable")?;
            valid(session, &view, identity, now, Stage::Confirm)?;
            return Ok(page(html! {
                (DOCTYPE) html lang="en" { head { meta charset="utf-8"; title { "Confirm connection action" } }
                    body { main { h1 { "Confirm connection action" }
                        p { @match view.action { Action::Connect => "Connect", Action::Disconnect => "Disconnect" } " " (view.logical_id) }
                        p { (view.usage) } p { "Account: " (view.human) }
                        ul { @for scope in &view.scopes { li { (scope) } } }
                        @if view.action == Action::Disconnect { p { "Local access will stop. Google revocation affects this account's grants for all clients in the Google project and requires operator assessment; this action sends no provider revocation request." } }
                        form method="post" {
                            input type="hidden" name="csrf" value=(session.csrf);
                            input type="hidden" name="challenge" value=(view.challenge.as_str());
                            button type="submit" { "Confirm" }
                        }
                    } }
                }
            }));
        }
        require_post(method, headers, &self.origin)?;
        let fields = web_security::fields(body)?;
        ensure!(
            fields.len() == 2
                && fields.get("challenge").map(String::as_str) == Some(view.challenge.as_str()),
            "OAuth management challenge changed"
        );
        let mut session = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| anyhow::anyhow!("OAuth management session unavailable"))?;
            let session = sessions
                .get(key.as_str())
                .context("OAuth management session unavailable")?;
            valid(session, &view, identity, now, Stage::Confirm)?;
            ensure!(
                fields.get("csrf") == Some(&session.csrf),
                "OAuth management CSRF refused"
            );
            sessions
                .remove(key.as_str())
                .context("OAuth management session consumed")?
        };
        let proof = self.signer.attest_management(
            &view,
            &session.proof,
            identity,
            session.digest.clone(),
            now,
        )?;
        let reply = self.remote.management(
            &view.app,
            Call::Confirm {
                id: id.into(),
                proof,
            },
            headers,
        )?;
        match reply {
            Reply::Redirect { location } => {
                ensure!(
                    view.action == Action::Connect,
                    "OAuth management redirect purpose changed"
                );
                let url = url::Url::parse(&location)?;
                ensure!(
                    url.as_str().split('?').next() == Some(crate::oauth::google::AUTHORIZATION)
                        && url.fragment().is_none(),
                    "OAuth management redirect refused"
                );
                let states = url
                    .query_pairs()
                    .filter(|(key, _)| key == "state")
                    .map(|(_, value)| value.into_owned())
                    .collect::<Vec<_>>();
                ensure!(
                    states.len() == 1 && states[0].starts_with(&format!("product.{}.", view.id)),
                    "OAuth authorization state refused"
                );
                session.stage = Stage::Provider {
                    state: crate::oauth::connect::callback_state_hash(states[0].as_bytes())?,
                };
                self.sessions
                    .lock()
                    .map_err(|_| anyhow::anyhow!("OAuth management session unavailable"))?
                    .insert(key.as_str().into(), session);
                Ok(redirect(&location))
            }
            Reply::Completed { status } => clear_cookie(page(
                html! { (DOCTYPE) html { body { main { h1 { "Connection action completed" } p { (status) } } } } },
            )),
            Reply::Pending { .. } => {
                anyhow::bail!("OAuth management confirmation response refused")
            }
        }
    }

    /// Called before the registration campaign's callback router. An unknown
    /// product state is refused here and cannot fall through to qualification.
    pub(in crate::oauth) fn provider_callback(
        &self,
        request: CallbackRequest<'_>,
        identity: &iap::Verified,
        now: i64,
    ) -> Result<Option<Response>> {
        let CallbackRequest {
            method,
            path,
            query,
            headers,
            body,
        } = request;
        if !path.starts_with("/_day2/oauth/callback/") {
            return Ok(None);
        }
        let Some(query) = query else {
            return Ok(None);
        };
        ensure!(query.len() <= 8192, "OAuth callback query budget");
        // This is routing data only. In particular, a malformed registration
        // callback must still reach its own qualification-stage parser. Any
        // product state (including a duplicate) selects the strict parser below.
        if !url::form_urlencoded::parse(query.as_bytes())
            .any(|(name, value)| name == "state" && value.starts_with("product."))
        {
            return Ok(None);
        }
        ensure!(
            *method == Method::GET && body.is_empty(),
            "OAuth callback method refused"
        );
        let parsed = protocol::parse_callback(
            query.as_bytes(),
            &crate::oauth::catalog::Adapter::GoogleCalendar.callback_parameters(),
        )?;
        let (state, issuer) = match &parsed {
            protocol::ParsedCallback::Code { state, issuer, .. }
            | protocol::ParsedCallback::Denied { state, issuer, .. } => {
                (state.as_str(), issuer.as_deref())
            }
        };
        ensure!(
            issuer == Some(crate::oauth::google::ISSUER),
            "OAuth callback issuer changed"
        );
        let Some(tail) = state.strip_prefix("product.") else {
            return Ok(None);
        };
        let (id, random) = tail
            .split_once('.')
            .context("OAuth product callback state invalid")?;
        crate::oauth::shell_transport::attempt(id)?;
        ensure!(
            random.len() == 43
                && random
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "OAuth callback state invalid"
        );
        let token = cookie(headers)?.context("OAuth callback browser session missing")?;
        let digest = Digest::new(token.as_bytes());
        let session = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| anyhow::anyhow!("OAuth management session unavailable"))?;
            let session = sessions
                .get(digest.as_str())
                .context("OAuth callback browser session consumed")?;
            let view = &session.view;
            ensure!(
                view.id == id && url::Url::parse(&view.callback_url)?.path() == path,
                "OAuth callback route changed"
            );
            valid(
                session,
                view,
                identity,
                now,
                Stage::Provider {
                    state: crate::oauth::connect::callback_state_hash(state.as_bytes())?,
                },
            )?;
            sessions
                .remove(digest.as_str())
                .context("OAuth callback browser session consumed")?
        };
        let view = &session.view;
        let Reply::Completed { status } = self.remote.management(
            &view.app,
            Call::Callback {
                id: id.into(),
                query: query.into(),
                session: digest,
            },
            headers,
        )?
        else {
            anyhow::bail!("OAuth callback settlement response refused");
        };
        Ok(Some(clear_cookie(page(
            html! { (DOCTYPE) html { body { main { h1 { "Connection action completed" } p { (status) } } } } },
        ))?))
    }
}

fn valid(
    session: &Session,
    view: &View,
    identity: &iap::Verified,
    now: i64,
    stage: Stage,
) -> Result<()> {
    view.validate(identity, now)?;
    ensure!(
        session.view == *view && session.stage == stage,
        "OAuth management session changed"
    );
    session
        .proof
        .require_intent(&FreshIntent::management(view, identity)?, identity)?;
    session.proof.require_current(now)
}

fn require_post(method: &Method, headers: &HeaderMap, origin: &str) -> Result<()> {
    ensure!(
        *method == Method::POST
            && headers.get_all(header::ORIGIN).iter().count() == 1
            && headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) == Some(origin)
            && headers.get_all(header::CONTENT_TYPE).iter().count() == 1
            && headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                == Some("application/x-www-form-urlencoded"),
        "OAuth management form origin or type refused"
    );
    Ok(())
}

fn cookie(headers: &HeaderMap) -> Result<Option<String>> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE) {
        let value = value.to_str()?;
        ensure!(value.len() <= 16384, "OAuth management cookie budget");
        for pair in value.split(';') {
            if let Some(token) = pair.trim().strip_prefix(&format!("{COOKIE}=")) {
                ensure!(
                    found.is_none()
                        && token.len() == 43
                        && token
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
                    "OAuth management cookie refused"
                );
                found = Some(token.into());
            }
        }
    }
    Ok(found)
}

fn redirect(location: &str) -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response()
}
fn page(markup: maud::Markup) -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        markup.into_string(),
    )
        .into_response()
}
fn with_cookie(mut response: Response, token: &str, seconds: i64) -> Result<Response> {
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!("{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={seconds}")
            .parse()?,
    );
    Ok(response)
}
fn clear_cookie(response: Response) -> Result<Response> {
    with_cookie(response, "", 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, AtomicUsize, Ordering::SeqCst},
        time::Duration,
    };

    struct Port(AtomicU64);
    impl effects::Hooks for Port {
        fn provider_observation(
            &self,
            _: crate::oauth::shell_oidc::ProviderObservationData,
        ) -> Result<()> {
            anyhow::bail!("unscripted provider observation")
        }

        fn domain(&self) -> u64 {
            97832
        }
        fn wall_time(&self) -> Result<i64> {
            Ok(102)
        }
        fn monotonic(&self) -> Duration {
            Duration::from_secs(102)
        }
        fn fill(&self, bytes: &mut [u8]) -> Result<()> {
            let n = self.0.fetch_add(1, SeqCst);
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = n.wrapping_add(i as u64) as u8;
            }
            Ok(())
        }
        fn send(&self, _: reqwest::blocking::Request) -> Result<effects::Response> {
            anyhow::bail!("unexpected management test HTTP")
        }
    }

    struct Bearers(AtomicUsize);
    impl crate::oauth::shell_transport::PrivateBearerSource for Bearers {
        fn bearer(&self, _: &str, _: &url::Url) -> Result<String> {
            self.0.fetch_add(1, SeqCst);
            anyhow::bail!("fixture receiver unavailable")
        }
    }

    struct Auth;
    impl FreshAuthenticator for Auth {
        fn identify(&self, _: &HeaderMap, _: i64) -> Result<iap::Verified> {
            anyhow::bail!("unused fixture edge")
        }
        fn begin(
            &self,
            _: &iap::Verified,
            _: FreshIntent,
            _: &HeaderMap,
            _: i64,
        ) -> Result<ReauthStart> {
            anyhow::bail!("unused fixture auth")
        }
    }

    fn callback_query(state: &str, issuer: Option<&str>, denied: bool) -> String {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("state", state);
        if denied {
            query.append_pair("error", "access_denied");
        } else {
            query.append_pair("code", "private-code");
        }
        if let Some(issuer) = issuer {
            query.append_pair("iss", issuer);
        }
        query.finish()
    }

    #[test]
    fn forged_callback_retains_exact_session_and_one_matching_callback_consumes_it() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let (runtime, authority, signer) = admission::tests::management_fixture(directory.path())?;
        let instance = crate::artifact::Instance::load(&directory.path().join("instance.json"))?;
        let bearers = Arc::new(Bearers(AtomicUsize::new(0)));
        let remote = Arc::new(RemoteApprovals::from_instance(&instance, bearers.clone())?);
        let shell = Shell::new(
            "https://security.example.com".into(),
            remote,
            signer,
            Arc::new(Auth),
        );
        let identity = iap::Verified {
            email: "alice@example.com".into(),
            subject: "accounts.google.com:alice".into(),
        };
        effects::scope(Arc::new(Port(AtomicU64::new(1))), || -> Result<()> {
            let manager = crate::oauth::management::app::Manager::new(runtime, authority);
            let view = manager.capture("calendar", Action::Connect, &identity, 102)?;
            // Fixture times stay within the original pending interval.
            let proof =
                VerifiedAuthTime::from_google(crate::oauth::shell_oidc::Reauthenticated::fixture(
                    FreshIntent::management(&view, &identity)?,
                    identity.email.clone(),
                    identity.subject.clone(),
                    103,
                ));
            let state = format!("product.{}.{}", view.id, "r".repeat(43));
            let token = "t".repeat(43);
            let digest = Digest::new(token.as_bytes());
            let session = Session {
                view: view.clone(),
                proof,
                csrf: "csrf".into(),
                digest: digest.clone(),
                stage: Stage::Provider {
                    state: crate::oauth::connect::callback_state_hash(state.as_bytes())?,
                },
            };
            shell
                .sessions
                .lock()
                .unwrap()
                .insert(digest.as_str().into(), session);
            let proof_address = {
                let sessions = shell.sessions.lock().unwrap();
                &sessions.get(digest.as_str()).unwrap().proof as *const VerifiedAuthTime as usize
            };
            let mut headers = HeaderMap::new();
            headers.insert(header::COOKIE, format!("{COOKIE}={token}").parse()?);
            headers.insert(
                crate::iap::ASSERTION_HEADER,
                "fixture-human-assertion".parse()?,
            );
            let path = url::Url::parse(&view.callback_url)?.path().to_owned();
            for (path, state) in [
                (
                    path.clone(),
                    format!("product.{}.{}", view.id, "s".repeat(43)),
                ),
                (format!("{path}wrong"), state.clone()),
                (
                    path.clone(),
                    format!("product.other_attempt.{}", "r".repeat(43)),
                ),
            ] {
                let query = callback_query(&state, Some(crate::oauth::google::ISSUER), false);
                assert!(
                    shell
                        .provider_callback(
                            CallbackRequest {
                                method: &Method::GET,
                                path: &path,
                                query: Some(&query),
                                headers: &headers,
                                body: &[]
                            },
                            &identity,
                            104
                        )
                        .is_err()
                );
                assert_eq!(shell.sessions.lock().unwrap().len(), 1);
                assert_eq!(bearers.0.load(SeqCst), 0);
            }
            for denied in [false, true] {
                let query = callback_query(&state, Some(crate::oauth::google::ISSUER), denied);
                for invalid in [
                    callback_query(&state, None, denied),
                    callback_query(&state, Some(""), denied),
                    callback_query(&state, Some("https://attacker.example"), denied),
                    format!("{query}&iss={}", crate::oauth::google::ISSUER),
                ] {
                    assert!(
                        shell
                            .provider_callback(
                                CallbackRequest {
                                    method: &Method::GET,
                                    path: &path,
                                    query: Some(&invalid),
                                    headers: &headers,
                                    body: &[]
                                },
                                &identity,
                                104
                            )
                            .is_err()
                    );
                    let sessions = shell.sessions.lock().unwrap();
                    assert_eq!(sessions.len(), 1);
                    let retained = sessions
                        .get(digest.as_str())
                        .context("session disappeared")?;
                    assert_eq!(retained.view, view);
                    assert_eq!(retained.digest, digest);
                    assert_eq!(retained.csrf, "csrf");
                    assert_eq!(
                        &retained.proof as *const VerifiedAuthTime as usize,
                        proof_address
                    );
                    assert!(
                        retained.stage
                            == Stage::Provider {
                                state: crate::oauth::connect::callback_state_hash(
                                    state.as_bytes()
                                )?
                            }
                    );
                    assert_eq!(bearers.0.load(SeqCst), 0);
                }
            }
            let query = callback_query(&state, Some(crate::oauth::google::ISSUER), false);
            // The barrier releases two actual dispatchers against the same
            // session. Even a refused bearer acquisition has only one winner;
            // the loser must not acquire a second private transport credential.
            let start = std::sync::Barrier::new(3);
            std::thread::scope(|threads| {
                let run = || {
                    effects::scope(Arc::new(Port(AtomicU64::new(1))), || {
                        start.wait();
                        shell
                            .provider_callback(
                                CallbackRequest {
                                    method: &Method::GET,
                                    path: &path,
                                    query: Some(&query),
                                    headers: &headers,
                                    body: &[],
                                },
                                &identity,
                                104,
                            )
                            .is_err()
                    })
                };
                let first = threads.spawn(run);
                let second = threads.spawn(run);
                start.wait();
                assert!(first.join().unwrap());
                assert!(second.join().unwrap());
            });
            assert!(
                shell
                    .provider_callback(
                        CallbackRequest {
                            method: &Method::GET,
                            path: &path,
                            query: Some(&query),
                            headers: &headers,
                            body: &[]
                        },
                        &identity,
                        104
                    )
                    .is_err()
            );
            assert_eq!(bearers.0.load(SeqCst), 1);
            assert!(shell.sessions.lock().unwrap().is_empty());
            Ok(())
        })
    }

    #[test]
    fn nonproduct_callback_keeps_its_own_parser_and_product_duplicates_fail_closed() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let (_, _, signer) = admission::tests::management_fixture(directory.path())?;
        let instance = crate::artifact::Instance::load(&directory.path().join("instance.json"))?;
        let bearers = Arc::new(Bearers(AtomicUsize::new(0)));
        let shell = Shell::new(
            "https://security.example.com".into(),
            Arc::new(RemoteApprovals::from_instance(&instance, bearers.clone())?),
            signer,
            Arc::new(Auth),
        );
        let identity = iap::Verified {
            email: "alice@example.com".into(),
            subject: "accounts.google.com:alice".into(),
        };
        let headers = HeaderMap::new();
        for query in [
            None,
            Some("state=qualification&unexpected=private"),
            Some("state=qualification&state=other&code=%GG"),
        ] {
            assert!(
                shell
                    .provider_callback(
                        CallbackRequest {
                            method: &Method::GET,
                            path: "/_day2/oauth/callback/registration",
                            query,
                            headers: &headers,
                            body: &[]
                        },
                        &identity,
                        104
                    )?
                    .is_none()
            );
        }
        for query in [
            "state=qualification&state=product.bad&code=private",
            "st%61te=product.bad&code=%GG",
            "state=product.bad&unexpected=private",
        ] {
            assert!(
                shell
                    .provider_callback(
                        CallbackRequest {
                            method: &Method::GET,
                            path: "/_day2/oauth/callback/registration",
                            query: Some(query),
                            headers: &headers,
                            body: &[]
                        },
                        &identity,
                        104
                    )
                    .is_err()
            );
        }
        assert!(shell.sessions.lock().unwrap().is_empty());
        assert_eq!(bearers.0.load(SeqCst), 0);
        Ok(())
    }

    #[test]
    fn management_cookie_is_lax_for_provider_callback_and_duplicate_cookie_is_refused() -> Result<()>
    {
        let response = with_cookie(StatusCode::OK.into_response(), &"t".repeat(43), 300)?;
        let header = response.headers()[header::SET_COOKIE].to_str()?;
        assert!(header.contains("Secure; HttpOnly; SameSite=Lax; Max-Age=300"));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{COOKIE}={}; {COOKIE}={}", "t".repeat(43), "u".repeat(43)).parse()?,
        );
        assert!(cookie(&headers).is_err());
        headers.clear();
        headers.insert(header::ORIGIN, "https://attacker.example".parse()?);
        headers.insert(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse()?,
        );
        assert!(require_post(&Method::POST, &headers, "https://security.example.com").is_err());
        Ok(())
    }
}
