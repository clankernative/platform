//! IAP-authenticated, one-use browser routing for the private qualification
//! campaign. No callback, form or instance boolean can manufacture a receipt.

use super::{Authorization, Codes, GoogleReadiness, Purpose, Receipt, Session, Target};
use crate::oauth::effects::{self, Instant};
use crate::{iap, oauth::approval_keys::AccessTokenSource};
use anyhow::{Context, Result, ensure};
use axum::{
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use day2_capabilities::Digest;
use maud::{DOCTYPE, html};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

const PREFIX: &str = "/_day2/oauth/qualification/";
const CALLBACK: &str = "/_day2/oauth/callback/";
const COOKIE: &str = "__Host-day2_oauth_canary";
const SECONDS: i64 = 300;

pub(in crate::oauth) fn reserved(path: &str) -> bool {
    path.starts_with(PREFIX) || path.starts_with(CALLBACK)
}

trait Campaign: Send + Sync {
    fn run(&self, target: Target, codes: Codes) -> Result<Receipt>;
}

pub(in crate::oauth) trait ReceiptPublisher: Send + Sync {
    fn publish(&self, receipt: &Receipt, headers: &HeaderMap, now: i64) -> Result<()>;
}

struct NativeCampaign {
    runner: PathBuf,
    tokens: Arc<dyn AccessTokenSource>,
}

impl Campaign for NativeCampaign {
    fn run(&self, target: Target, codes: Codes) -> Result<Receipt> {
        Session::new(target, codes, self.tokens.clone())?.run(&self.runner)
    }
}

enum Stage {
    Form(String),
    Authorization(Authorization),
}

struct Pending {
    target: Target,
    generation: u64,
    identity: iap::Verified,
    session: Digest,
    started_at: i64,
    started: Instant,
    stage: Stage,
    reject_pkce: Option<super::Code>,
    reject_credential: Option<super::Code>,
}

struct State {
    generation: u64,
    targets: BTreeMap<String, Target>,
    pending: BTreeMap<String, Pending>,
}

/// A native launcher attaches this to the dedicated shell. Target construction
/// requires admitted artifacts and independent shell evidence. The browser may
/// start only the explicitly selected canary user's campaign.
pub(crate) struct Canaries {
    origin: String,
    state: Mutex<State>,
    campaign: Arc<dyn Campaign>,
    readiness: Arc<GoogleReadiness>,
    publisher: Option<Arc<dyn ReceiptPublisher>>,
}

impl Canaries {
    pub(crate) fn new(
        origin: &str,
        targets: Vec<Target>,
        runner: &Path,
        tokens: Arc<dyn AccessTokenSource>,
        readiness: Arc<GoogleReadiness>,
    ) -> Result<Self> {
        Self::at(
            origin,
            targets,
            Arc::new(NativeCampaign {
                runner: crate::automation::checked_runner(runner)?,
                tokens,
            }),
            readiness,
        )
    }

    fn at(
        origin: &str,
        targets: Vec<Target>,
        campaign: Arc<dyn Campaign>,
        readiness: Arc<GoogleReadiness>,
    ) -> Result<Self> {
        let url = url::Url::parse(origin)?;
        ensure!(
            url.scheme() == "https" && url.origin().ascii_serialization() == origin,
            "invalid registration shell origin"
        );
        let targets = Self::targets(origin, targets)?;
        Ok(Self {
            origin: origin.into(),
            state: Mutex::new(State {
                generation: 1,
                targets,
                pending: BTreeMap::new(),
            }),
            campaign,
            readiness,
            publisher: None,
        })
    }

    pub(in crate::oauth) fn with_publication(
        mut self,
        publisher: Arc<dyn ReceiptPublisher>,
    ) -> Self {
        self.publisher = Some(publisher);
        self
    }

    fn targets(origin: &str, targets: Vec<Target>) -> Result<BTreeMap<String, Target>> {
        ensure!(targets.len() <= 128, "registration target budget");
        let mut selected = BTreeMap::new();
        let mut callbacks = std::collections::BTreeSet::new();
        for target in targets {
            ensure!(
                target.shell.origin_url == format!("{origin}/"),
                "registration shell selection mismatch"
            );
            ensure!(
                callbacks.insert(target.callback_url.clone()),
                "ambiguous registration callback"
            );
            ensure!(
                selected
                    .insert(target.registration.as_str().into(), target)
                    .is_none(),
                "ambiguous registration selection"
            );
        }
        Ok(selected)
    }

    pub(crate) fn origin(&self) -> &str {
        &self.origin
    }

    /// Provider probes hold no routing lock. Final bounded publication and
    /// selection retirement share it; an in-flight retired campaign cannot publish.
    pub(crate) fn replace(&self, targets: Vec<Target>) -> Result<()> {
        let targets = Self::targets(&self.origin, targets)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("registration routing unavailable"))?;
        let generation = state
            .generation
            .checked_add(1)
            .context("registration generation exhausted")?;
        for target in state.targets.values() {
            self.readiness.retire(&target.registration)?;
        }
        state.targets = targets;
        state.generation = generation;
        state.pending.clear();
        Ok(())
    }

    // Keep the shell's HTTP fields separate from its verified IAP identity.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::oauth) fn dispatch(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        body: &[u8],
        identity: &iap::Verified,
        now: i64,
    ) -> Result<Response> {
        if path.starts_with(CALLBACK) {
            ensure!(
                *method == Method::GET && body.is_empty(),
                "invalid canary callback method"
            );
            return self.callback(
                path,
                query.context("canary callback missing")?,
                headers,
                identity,
                now,
            );
        }
        let id = path
            .strip_prefix(PREFIX)
            .context("invalid qualification route")?;
        ensure!(query.is_none(), "qualification query refused");
        match *method {
            Method::GET => {
                ensure!(body.is_empty(), "qualification GET body refused");
                self.page(id, path, identity, now)
            }
            Method::POST => {
                ensure!(
                    headers.get_all(header::ORIGIN).iter().count() == 1
                        && headers
                            .get(header::ORIGIN)
                            .and_then(|value| value.to_str().ok())
                            == Some(self.origin.as_str())
                        && headers.get_all(header::CONTENT_TYPE).iter().count() == 1
                        && headers
                            .get(header::CONTENT_TYPE)
                            .and_then(|value| value.to_str().ok())
                            == Some("application/x-www-form-urlencoded"),
                    "invalid qualification form origin or content type"
                );
                self.start(id, headers, body, identity, now)
            }
            _ => Ok(StatusCode::METHOD_NOT_ALLOWED.into_response()),
        }
    }

    fn page(&self, id: &str, path: &str, identity: &iap::Verified, now: i64) -> Result<Response> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("registration routing unavailable"))?;
        let target = state
            .targets
            .get(id)
            .context("registration not selected")?
            .clone();
        selected_human(&target, identity)?;
        state.pending.retain(|_, pending| fresh(pending, now));
        ensure!(state.pending.len() < 128, "qualification session budget");
        let token = effects::random()?;
        let csrf = effects::random()?;
        let session = Digest::of(&(
            "oauth-canary-shell-session-v1",
            &token,
            &identity.subject,
            &target.setup_description()?,
        ))?;
        let description = serde_json::to_string_pretty(&target.setup_description()?)?;
        let generation = state.generation;
        state.pending.insert(
            Digest::new(token.as_bytes()).as_str().into(),
            Pending {
                target,
                generation,
                identity: identity.clone(),
                session,
                started_at: now,
                started: Instant::now(),
                stage: Stage::Form(csrf.clone()),
                reject_pkce: None,
                reject_credential: None,
            },
        );
        let markup = html! { (DOCTYPE) html lang="en" { head { meta charset="utf-8"; title { "Google OAuth qualification" } }
            body { h1 { "Google OAuth qualification" }
                p { "Use the isolated canary account. Three Google authorizations are required. The campaign tests code exchange, account identity and refresh." }
                p { "This setup describes the selected client and exact callback. It does not establish readiness." }
                pre { (description) }
                form method="post" action=(path) { input type="hidden" name="csrf" value=(csrf); button type="submit" { "Start qualification" } }
            }
        }};
        let mut response = (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            markup.into_string(),
        )
            .into_response();
        response.headers_mut().insert(
            header::SET_COOKIE,
            format!("{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={SECONDS}")
                .parse()?,
        );
        Ok(response)
    }

    fn take(
        &self,
        headers: &HeaderMap,
        identity: &iap::Verified,
        now: i64,
    ) -> Result<(String, Pending)> {
        let token = cookie_token(headers)?;
        let key = Digest::new(token.as_bytes()).as_str().to_owned();
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("registration routing unavailable"))?;
        let pending = state
            .pending
            .remove(&key)
            .context("canary session expired or replayed")?;
        ensure!(
            pending.generation == state.generation
                && fresh(&pending, now)
                && pending.identity.subject == identity.subject
                && pending.identity.email == identity.email,
            "canary session identity or selection changed"
        );
        selected_human(&pending.target, identity)?;
        Ok((key, pending))
    }

    fn put(&self, key: String, pending: Pending, now: i64) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("registration routing unavailable"))?;
        ensure!(
            state.generation == pending.generation && fresh(&pending, now),
            "canary selection expired or retired"
        );
        ensure!(
            state.pending.len() < 128 && !state.pending.contains_key(&key),
            "canary session budget or replay"
        );
        state.pending.insert(key, pending);
        Ok(())
    }

    fn start(
        &self,
        id: &str,
        headers: &HeaderMap,
        body: &[u8],
        identity: &iap::Verified,
        now: i64,
    ) -> Result<Response> {
        let (key, mut pending) = self.take(headers, identity, now)?;
        ensure!(
            pending.target.registration.as_str() == id,
            "canary registration changed"
        );
        let Stage::Form(csrf) = &pending.stage else {
            anyhow::bail!("canary form replayed");
        };
        let fields: Vec<_> = url::form_urlencoded::parse(body).collect();
        ensure!(
            fields.len() == 1 && fields[0].0 == "csrf" && fields[0].1 == *csrf,
            "invalid canary form"
        );
        let (authorization, location) = Authorization::begin(
            &pending.target,
            Purpose::RejectPkce,
            pending.session.clone(),
        )?;
        pending.stage = Stage::Authorization(authorization);
        self.put(key, pending, now)?;
        Ok(redirect(&location))
    }

    fn callback(
        &self,
        path: &str,
        query: &str,
        headers: &HeaderMap,
        identity: &iap::Verified,
        now: i64,
    ) -> Result<Response> {
        let (key, mut pending) = self.take(headers, identity, now)?;
        ensure!(
            url::Url::parse(&pending.target.callback_url)?.path() == path,
            "canary callback selection changed"
        );
        let Stage::Authorization(authorization) = pending.stage else {
            anyhow::bail!("canary authorization missing");
        };
        let mut code = Some(authorization.complete(query.as_bytes(), &pending.session)?);
        let next = if pending.reject_pkce.is_none() {
            pending.reject_pkce = code.take();
            Some(Purpose::RejectCredential)
        } else if pending.reject_credential.is_none() {
            pending.reject_credential = code.take();
            Some(Purpose::Positive)
        } else {
            None
        };
        if let Some(purpose) = next {
            let (authorization, location) =
                Authorization::begin(&pending.target, purpose, pending.session.clone())?;
            pending.stage = Stage::Authorization(authorization);
            self.put(key, pending, now)?;
            return Ok(redirect(&location));
        }
        let codes = Codes {
            positive: code.context("positive canary missing")?,
            reject_pkce: pending.reject_pkce.context("PKCE canary missing")?,
            reject_credential: pending
                .reject_credential
                .context("credential canary missing")?,
        };
        let receipt = self
            .campaign
            .run(pending.target, codes)
            .map_err(|_| anyhow::anyhow!("qualification failed; start a new canary"))?;
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("registration routing unavailable"))?;
        ensure!(
            state.generation == pending.generation
                && pending.started.elapsed() < Duration::from_secs(SECONDS as u64),
            "completed canary selection expired or retired"
        );
        if let Some(publisher) = &self.publisher {
            publisher.publish(&receipt, headers, now).map_err(|_| {
                anyhow::anyhow!("registration publication unavailable; start a new canary")
            })?;
        }
        self.readiness.publish(receipt)?;
        let markup = html! { (DOCTYPE) html lang="en" { head { meta charset="utf-8"; title { "Qualification completed" } }
            body { h1 { "Qualification completed" } p { "The native registration receipt is valid for five minutes. Independent shell, custody and account readiness are still required." } }
        }};
        let mut response = (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            markup.into_string(),
        )
            .into_response();
        response.headers_mut().insert(
            header::SET_COOKIE,
            format!("{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0").parse()?,
        );
        Ok(response)
    }
}

fn fresh(pending: &Pending, now: i64) -> bool {
    now >= pending.started_at
        && now - pending.started_at < SECONDS
        && pending.started.elapsed() < Duration::from_secs(SECONDS as u64)
}

fn selected_human(target: &Target, identity: &iap::Verified) -> Result<()> {
    ensure!(
        identity.subject == format!("accounts.google.com:{}", target.canary_subject),
        "qualification requires the selected canary human"
    );
    Ok(())
}

fn cookie_token(headers: &HeaderMap) -> Result<String> {
    let mut token = None;
    for header in headers.get_all(header::COOKIE) {
        for cookie in cookie::Cookie::split_parse(header.to_str()?) {
            let cookie = cookie?;
            if cookie.name() == COOKIE {
                ensure!(
                    token.is_none()
                        && cookie.value().len() == 43
                        && cookie
                            .value()
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric()
                                || byte == b'-'
                                || byte == b'_'),
                    "invalid canary cookie"
                );
                token = Some(cookie.value().to_owned());
            }
        }
    }
    token.context("canary cookie missing")
}

fn redirect(location: &str) -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response()
}

#[cfg(test)]
mod tests {
    use super::super::{
        Wire,
        admission::OutboundReadiness,
        approval_keys,
        tests::{Server, TokensSource, fixture, responses},
    };
    use super::*;
    use std::sync::{atomic::AtomicUsize, mpsc};

    struct Facts(super::super::profiles::OutboundInstanceEvidence);
    impl OutboundReadiness for Facts {
        fn current(
            &self,
            _: &day2_capabilities::oauth::OutboundConnectionBinding,
            _: &day2_capabilities::oauth::ConnectionSlotKey,
            _: i64,
        ) -> Result<Option<super::super::profiles::OutboundInstanceEvidence>> {
            Ok(Some(self.0.clone()))
        }
    }

    struct PublicationObserved {
        calls: AtomicUsize,
        fail: bool,
    }
    impl ReceiptPublisher for PublicationObserved {
        fn publish(&self, receipt: &Receipt, headers: &HeaderMap, _: i64) -> Result<()> {
            assert!(receipt.fresh(time_now()));
            assert!(headers.contains_key(header::COOKIE));
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ensure!(!self.fail, "fixture publication response lost");
            Ok(())
        }
    }

    struct Pause {
        sealed: mpsc::Sender<()>,
        resume: Mutex<mpsc::Receiver<()>>,
    }

    struct FixtureCampaign {
        endpoint: String,
        runner: PathBuf,
        pause: Option<Pause>,
    }

    impl Campaign for FixtureCampaign {
        fn run(&self, target: Target, codes: Codes) -> Result<Receipt> {
            let receipt = Session::at(
                target,
                codes,
                Wire::fixture(&self.endpoint)?,
                approval_keys::GcpSecretReader::fixture(
                    &self.endpoint,
                    Arc::new(TokensSource(AtomicUsize::new(0))),
                )?,
            )?
            .run(&self.runner)?;
            if let Some(pause) = &self.pause {
                pause.sealed.send(())?;
                pause
                    .resume
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(10))?;
            }
            Ok(receipt)
        }
    }

    fn identity() -> iap::Verified {
        iap::Verified {
            email: "canary@example.com".into(),
            subject: "accounts.google.com:google-canary-subject".into(),
        }
    }

    async fn begin(canaries: &Canaries, now: i64) -> Result<(HeaderMap, String)> {
        let path = format!("{PREFIX}calendar_registration");
        let page = canaries.dispatch(
            &Method::GET,
            &path,
            None,
            &HeaderMap::new(),
            &[],
            &identity(),
            now,
        )?;
        let cookie = page.headers()[header::SET_COOKIE]
            .to_str()?
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert!(
            page.headers()[header::SET_COOKIE]
                .to_str()?
                .contains("Secure; HttpOnly; SameSite=Lax")
        );
        let markup = String::from_utf8(
            axum::body::to_bytes(page.into_body(), 16_384)
                .await?
                .to_vec(),
        )?;
        assert!(markup.contains("/_day2/oauth/callback/"));
        assert!(!markup.contains("private-fixture-client-canary"));
        assert!(!markup.contains("code_verifier"));
        let csrf = markup
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .context("form csrf missing")?
            .split('"')
            .next()
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, cookie.parse()?);
        headers.insert(header::ORIGIN, "https://security.example.com".parse()?);
        headers.insert(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse()?,
        );
        let response = canaries.dispatch(
            &Method::POST,
            &path,
            None,
            &headers,
            format!("csrf={csrf}").as_bytes(),
            &identity(),
            now,
        )?;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        Ok((
            headers,
            response.headers()[header::LOCATION].to_str()?.into(),
        ))
    }

    fn callback(location: &str, code: &str) -> Result<(String, String)> {
        let location = url::Url::parse(location)?;
        let params: BTreeMap<_, _> = location.query_pairs().into_owned().collect();
        assert_eq!(params["code_challenge_method"], "S256");
        let path = url::Url::parse(&params["redirect_uri"])?.path().to_owned();
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("state", params["state"].as_str()),
                ("code", code),
                ("iss", crate::oauth::google::ISSUER),
            ])
            .finish();
        Ok((path, query))
    }

    fn advance(
        canaries: &Canaries,
        headers: &HeaderMap,
        location: &str,
        index: usize,
        now: i64,
    ) -> Result<String> {
        let (path, query) = callback(location, &format!("private-code-{index}"))?;
        let response = canaries.dispatch(
            &Method::GET,
            &path,
            Some(&query),
            headers,
            &[],
            &identity(),
            now,
        )?;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        Ok(response.headers()[header::LOCATION].to_str()?.into())
    }

    fn time_now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    struct ProofIdentity;
    impl crate::oauth::security_shell::FreshAuthenticator for ProofIdentity {
        fn identify(&self, headers: &HeaderMap, _: i64) -> Result<iap::Verified> {
            ensure!(
                headers
                    .get("test-proof")
                    .is_some_and(|value| value == "verified"),
                "test IAP proof missing"
            );
            Ok(identity())
        }

        fn begin(
            &self,
            _: &iap::Verified,
            _: &str,
            _: &Digest,
            _: i64,
        ) -> Result<crate::oauth::security_shell::ReauthStart> {
            anyhow::bail!("reauthentication is unrelated to qualification")
        }
    }

    struct NoApprovals;
    impl crate::oauth::shell_transport::ShellApprovals for NoApprovals {
        fn pending(
            &self,
            _: &str,
            _: &iap::Verified,
            _: &HeaderMap,
            _: i64,
        ) -> Result<Option<crate::oauth::shell_transport::ApprovalView>> {
            anyhow::bail!("qualification must not use app approval RPC")
        }
        fn confirm(
            &self,
            _: &crate::oauth::shell_transport::ApprovalView,
            _: &iap::Verified,
            _: &HeaderMap,
            _: crate::oauth::external::FreshExternalApproval,
            _: i64,
        ) -> Result<bool> {
            anyhow::bail!("qualification must not settle product connections")
        }
    }
    impl crate::oauth::shell_transport::ApprovalSigner for NoApprovals {
        fn attest(
            &self,
            _: &crate::oauth::shell_transport::ApprovalView,
            _: Digest,
            _: i64,
            _: i64,
        ) -> Result<crate::oauth::external::FreshExternalApproval> {
            anyhow::bail!("qualification must not sign product account approval")
        }
    }

    #[test]
    fn mounted_qualification_routes_require_the_shell_host_and_iap_identity() -> Result<()> {
        let fixture = fixture()?;
        let server = Server::new(vec![])?;
        let readiness = Arc::new(GoogleReadiness::new(Arc::new(Facts(fixture.evidence))));
        let campaign = Arc::new(FixtureCampaign {
            endpoint: server.endpoint.clone(),
            runner: crate::automation::runner()?,
            pause: None,
        });
        let canaries = Arc::new(Canaries::at(
            "https://security.example.com",
            vec![fixture.target],
            campaign,
            readiness,
        )?);
        let shell = crate::oauth::security_shell::SecurityShell::with_transport(
            "https://security.example.com/".into(),
            Arc::new(NoApprovals),
            Arc::new(NoApprovals),
            Arc::new(ProofIdentity),
        )?
        .with_registration(canaries)?;
        let path = format!("{PREFIX}calendar_registration");
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "security.example.com".parse()?);
        assert!(
            shell
                .dispatch(&Method::GET, &path, None, &headers, &[], time_now())
                .is_err()
        );
        headers.insert("test-proof", "verified".parse()?);
        assert_eq!(
            shell
                .dispatch(&Method::GET, &path, None, &headers, &[], time_now())?
                .status(),
            StatusCode::OK
        );
        headers.insert(header::HOST, "app.example.com".parse()?);
        assert!(
            shell
                .dispatch(&Method::GET, &path, None, &headers, &[], time_now())
                .is_err()
        );
        assert!(server.requests.lock().unwrap().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn three_browser_authorizations_run_the_pinned_recipe_and_publish_native_readiness()
    -> Result<()> {
        let fixture = fixture()?;
        let server = Server::new(responses())?;
        let readiness = Arc::new(GoogleReadiness::new(Arc::new(Facts(
            fixture.evidence.clone(),
        ))));
        let campaign = Arc::new(FixtureCampaign {
            endpoint: server.endpoint.clone(),
            runner: crate::automation::runner()?,
            pause: None,
        });
        let published = Arc::new(PublicationObserved {
            calls: AtomicUsize::new(0),
            fail: false,
        });
        let canaries = Arc::new(
            Canaries::at(
                "https://security.example.com",
                vec![fixture.target],
                campaign,
                readiness.clone(),
            )?
            .with_publication(published.clone()),
        );
        let now = time_now();
        let (headers, location) = begin(&canaries, now).await?;
        let location = advance(&canaries, &headers, &location, 1, now)?;
        let location = advance(&canaries, &headers, &location, 2, now)?;
        assert!(server.requests.lock().unwrap().is_empty());
        assert!(
            readiness
                .current(&fixture.binding, &fixture.slot, now)?
                .is_none()
        );
        let (path, query) = callback(&location, "private-code-3")?;
        let worker = canaries.clone();
        let (request_headers, request_path, request_query) =
            (headers.clone(), path.clone(), query.clone());
        let response = tokio::task::spawn_blocking(move || {
            worker.dispatch(
                &Method::GET,
                &request_path,
                Some(&request_query),
                &request_headers,
                &[],
                &identity(),
                now,
            )
        })
        .await??;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()[header::SET_COOKIE]
                .to_str()?
                .contains("Max-Age=0")
        );
        assert_eq!(server.requests.lock().unwrap().len(), 9);
        assert_eq!(published.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            readiness.current(&fixture.binding, &fixture.slot, time_now())?,
            Some(fixture.evidence)
        );
        assert!(
            canaries
                .dispatch(
                    &Method::GET,
                    &path,
                    Some(&query),
                    &headers,
                    &[],
                    &identity(),
                    now
                )
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn lost_publication_consumes_the_campaign_without_local_readiness_or_retry() -> Result<()>
    {
        let fixture = fixture()?;
        let server = Server::new(responses())?;
        let readiness = Arc::new(GoogleReadiness::new(Arc::new(Facts(fixture.evidence))));
        let published = Arc::new(PublicationObserved {
            calls: AtomicUsize::new(0),
            fail: true,
        });
        let canaries = Arc::new(
            Canaries::at(
                "https://security.example.com",
                vec![fixture.target],
                Arc::new(FixtureCampaign {
                    endpoint: server.endpoint.clone(),
                    runner: crate::automation::runner()?,
                    pause: None,
                }),
                readiness.clone(),
            )?
            .with_publication(published.clone()),
        );
        let now = time_now();
        let (headers, location) = begin(&canaries, now).await?;
        let location = advance(&canaries, &headers, &location, 1, now)?;
        let location = advance(&canaries, &headers, &location, 2, now)?;
        let (path, query) = callback(&location, "private-code-3")?;
        let worker = canaries.clone();
        let (request_headers, request_path, request_query) =
            (headers.clone(), path.clone(), query.clone());
        assert!(
            tokio::task::spawn_blocking(move || worker.dispatch(
                &Method::GET,
                &request_path,
                Some(&request_query),
                &request_headers,
                &[],
                &identity(),
                now
            ))
            .await?
            .is_err()
        );
        assert!(
            canaries
                .dispatch(
                    &Method::GET,
                    &path,
                    Some(&query),
                    &headers,
                    &[],
                    &identity(),
                    now
                )
                .is_err()
        );
        assert_eq!(server.requests.lock().unwrap().len(), 9);
        assert_eq!(published.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            readiness
                .current(&fixture.binding, &fixture.slot, time_now())?
                .is_none()
        );
        Ok(())
    }

    #[tokio::test]
    async fn changed_identity_state_route_cookie_time_or_retired_selection_never_reaches_provider()
    -> Result<()> {
        let server = Server::new(vec![])?;
        let fixture = fixture()?;
        let readiness = Arc::new(GoogleReadiness::new(Arc::new(Facts(fixture.evidence))));
        let campaign = Arc::new(FixtureCampaign {
            endpoint: server.endpoint.clone(),
            runner: crate::automation::runner()?,
            pause: None,
        });
        let canaries = Canaries::at(
            "https://security.example.com",
            vec![fixture.target.clone()],
            campaign,
            readiness,
        )?;
        let now = time_now();
        for mutation in 0..10 {
            canaries.replace(vec![fixture.target.clone()])?;
            let (mut headers, location) = begin(&canaries, now).await?;
            let (mut path, mut query) = callback(&location, "private-code")?;
            let mut human = identity();
            let mut at = now;
            let mut method = Method::GET;
            match mutation {
                0 => human.subject = "accounts.google.com:other".into(),
                1 => human.email = "different@example.com".into(),
                2 => {
                    let cookie = headers[header::COOKIE].clone();
                    headers.append(header::COOKIE, cookie);
                }
                3 => {
                    headers.remove(header::COOKIE);
                }
                4 => path.push('x'),
                5 => query.push_str("&state=duplicate"),
                6 => query = query.replace("accounts.google.com", "attacker.example"),
                7 => at = now + SECONDS,
                8 => at = now - 1,
                9 => {
                    canaries.replace(vec![])?;
                    method = Method::POST;
                }
                _ => unreachable!(),
            }
            assert!(
                canaries
                    .dispatch(&method, &path, Some(&query), &headers, &[], &human, at)
                    .is_err(),
                "mutation {mutation}"
            );
        }
        assert!(server.requests.lock().unwrap().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn forms_cannot_choose_credentials_and_failed_callbacks_are_consumed() -> Result<()> {
        let fixture = fixture()?;
        let server = Server::new(vec![])?;
        let readiness = Arc::new(GoogleReadiness::new(Arc::new(Facts(fixture.evidence))));
        let campaign = Arc::new(FixtureCampaign {
            endpoint: server.endpoint.clone(),
            runner: crate::automation::runner()?,
            pause: None,
        });
        let canaries = Canaries::at(
            "https://security.example.com",
            vec![fixture.target.clone()],
            campaign,
            readiness,
        )?;
        let now = time_now();
        let path = format!("{PREFIX}calendar_registration");
        let mut other = identity();
        other.subject = "accounts.google.com:other".into();
        assert!(
            canaries
                .dispatch(
                    &Method::GET,
                    &path,
                    None,
                    &HeaderMap::new(),
                    &[],
                    &other,
                    now
                )
                .is_err()
        );
        for mutation in 0..4 {
            canaries.replace(vec![fixture.target.clone()])?;
            let page = canaries.dispatch(
                &Method::GET,
                &path,
                None,
                &HeaderMap::new(),
                &[],
                &identity(),
                now,
            )?;
            let token = page.headers()[header::SET_COOKIE]
                .to_str()?
                .split(';')
                .next()
                .unwrap();
            let mut headers = HeaderMap::new();
            headers.insert(header::COOKIE, token.parse()?);
            headers.insert(header::ORIGIN, "https://security.example.com".parse()?);
            headers.insert(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded".parse()?,
            );
            let markup = String::from_utf8(
                axum::body::to_bytes(page.into_body(), 16_384)
                    .await?
                    .to_vec(),
            )?;
            let csrf = markup
                .split("name=\"csrf\" value=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            let mut body = format!("csrf={csrf}");
            match mutation {
                0 => body.push_str(
                    "&client_secret=private-injected&callback_url=https://attacker.example",
                ),
                1 => body.push_str(&format!("&csrf={csrf}")),
                2 => {
                    headers.insert(header::ORIGIN, "https://app.example.com".parse()?);
                }
                3 => {
                    let origin = headers[header::ORIGIN].clone();
                    headers.append(header::ORIGIN, origin);
                }
                _ => unreachable!(),
            }
            assert!(
                canaries
                    .dispatch(
                        &Method::POST,
                        &path,
                        None,
                        &headers,
                        body.as_bytes(),
                        &identity(),
                        now
                    )
                    .is_err()
            );
        }
        canaries.replace(vec![fixture.target])?;
        let (headers, location) = begin(&canaries, now).await?;
        let (path, query) = callback(&location, "private-code")?;
        let wrong = query.replace("state=", "state=wrong");
        assert!(
            canaries
                .dispatch(
                    &Method::GET,
                    &path,
                    Some(&wrong),
                    &headers,
                    &[],
                    &identity(),
                    now
                )
                .is_err()
        );
        assert!(
            canaries
                .dispatch(
                    &Method::GET,
                    &path,
                    Some(&query),
                    &headers,
                    &[],
                    &identity(),
                    now
                )
                .is_err()
        );
        assert!(server.requests.lock().unwrap().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn retirement_while_wire_campaign_runs_refuses_late_receipt_publication() -> Result<()> {
        let fixture = fixture()?;
        let server = Server::new(responses())?;
        let readiness = Arc::new(GoogleReadiness::new(Arc::new(Facts(fixture.evidence))));
        let (sealed, observed) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        let campaign = Arc::new(FixtureCampaign {
            endpoint: server.endpoint.clone(),
            runner: crate::automation::runner()?,
            pause: Some(Pause {
                sealed,
                resume: Mutex::new(resumed),
            }),
        });
        let canaries = Arc::new(Canaries::at(
            "https://security.example.com",
            vec![fixture.target],
            campaign,
            readiness.clone(),
        )?);
        let now = time_now();
        let (headers, location) = begin(&canaries, now).await?;
        let location = advance(&canaries, &headers, &location, 1, now)?;
        let location = advance(&canaries, &headers, &location, 2, now)?;
        let (path, query) = callback(&location, "private-code-3")?;
        let worker = canaries.clone();
        let task = std::thread::spawn(move || {
            worker.dispatch(
                &Method::GET,
                &path,
                Some(&query),
                &headers,
                &[],
                &identity(),
                now,
            )
        });
        observed.recv_timeout(Duration::from_secs(10))?;
        canaries.replace(vec![])?;
        resume.send(())?;
        assert!(task.join().unwrap().is_err());
        assert_eq!(server.requests.lock().unwrap().len(), 9);
        assert!(
            readiness
                .current(&fixture.binding, &fixture.slot, now)?
                .is_none()
        );
        Ok(())
    }
}
