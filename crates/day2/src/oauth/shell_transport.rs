//! Private shell/app-host transport. Only identity presentation and a signed
//! confirmation cross this boundary. Custody and SQLite stay with the app host.

use super::{account::ProviderAccount, external, security_shell::ApprovalContext};
use crate::{artifact::Instance, iap, web_security};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::to_bytes,
    extract::Request,
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use day2_capabilities::Digest;
use reqwest::{blocking::Client, header::HeaderValue};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use url::Url;

pub(crate) const PATH: &str = "/_day2/oauth/approval";
const VERSION: u32 = 1;
const MAX_REQUEST: usize = 48 * 1024;
const MAX_RESPONSE: usize = 24 * 1024;
const LOOKUP_SECONDS: u64 = 10;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovalView {
    pub app: String,
    pub subject: String,
    pub requirement: Digest,
    pub permission: Digest,
    pub logical_id: String,
    pub usage: String,
    pub scopes: BTreeSet<String>,
    pub observed: ProviderAccount,
    pub claim: external::ApprovalClaim,
    pub binding_namespace: String,
    pub terms: Digest,
    pub shell_origin: String,
    pub app_origin: String,
}

impl ApprovalView {
    pub(crate) fn from_pending(
        app: &str,
        context: &ApprovalContext,
        pending: &external::PendingExternalApproval,
        identity: &iap::Verified,
    ) -> Result<Self> {
        let view = Self {
            app: app.into(),
            subject: identity.subject.clone(),
            requirement: context.requirement.nominal_identity()?,
            permission: context.permission.consent_digest(&context.requirement)?,
            logical_id: context.requirement.logical_id.clone(),
            usage: context.requirement.usage.clone(),
            scopes: context
                .permission
                .action_scopes
                .values()
                .flatten()
                .cloned()
                .collect(),
            observed: pending.observed_account().clone(),
            claim: pending.claim(),
            binding_namespace: context.binding.binding_namespace().into(),
            terms: Digest::of(&(
                "oauth-shell-current-terms-v1",
                &context.requirement,
                &context.permission,
                context.reviewed.review_revision()?,
                &context.instance,
            ))?,
            shell_origin: context.instance.shell.origin_url.clone(),
            app_origin: context.instance.app_origin_url.clone(),
        };
        view.validate(identity)?;
        Ok(view)
    }

    pub(crate) fn digest(&self) -> Result<Digest> {
        Digest::of(&("oauth-shell-approval-view-v1", self))
    }

    pub(crate) fn validate(&self, identity: &iap::Verified) -> Result<()> {
        crate::schema::identifier(&self.app)?;
        super::connect::identifier(&self.logical_id)?;
        super::connect::identifier(&self.binding_namespace)?;
        super::connect::identifier(&self.claim.slot)?;
        attempt(&self.claim.attempt)?;
        ensure!(
            self.subject == identity.subject
                && self.claim.human == identity.email
                && self.subject.len() <= 256
                && !self.subject.is_empty()
                && !self
                    .subject
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control())
                && self.claim.generation > 0
                && self.claim.quarantined_at >= 0
                && !self.usage.trim().is_empty()
                && self.usage.len() <= 1024
                && !self.usage.chars().any(char::is_control)
                && !self.scopes.is_empty()
                && self.scopes.len() <= 32,
            "invalid OAuth approval view"
        );
        for scope in &self.scopes {
            ensure!(
                !scope.is_empty()
                    && scope.len() <= 256
                    && !scope.chars().any(|c| c.is_whitespace() || c.is_control()),
                "invalid OAuth approval scope"
            );
        }
        for value in [
            &self.observed.issuer,
            &self.observed.subject,
            &self.observed.tenant,
        ] {
            ensure!(
                !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control),
                "invalid OAuth approval identity"
            );
        }
        ensure!(
            self.observed.display_email.len() <= 320
                && !self.observed.display_email.chars().any(char::is_control)
                && super::account::provider_account_digest(&self.observed)?.as_str()
                    == self.claim.account
                && Digest::of(&("oauth-accepted-scopes-v1", &self.permission, &self.scopes))?
                    .as_str()
                    == self.claim.scope_evidence,
            "OAuth approval presentation does not match account or scopes"
        );
        origin(&self.shell_origin)?;
        origin(&self.app_origin)?;
        ensure!(
            self.shell_origin != self.app_origin,
            "OAuth approval origin collision"
        );
        Ok(())
    }

    pub(crate) fn attempt(&self) -> &str {
        &self.claim.attempt
    }

    pub(crate) fn human(&self) -> &str {
        &self.claim.human
    }

    pub(crate) fn challenge(&self) -> &Digest {
        &self.claim.challenge
    }

    pub(crate) fn quarantined_at(&self) -> i64 {
        self.claim.quarantined_at
    }
}

pub(crate) trait ShellApprovals: Send + Sync {
    fn pending(
        &self,
        attempt: &str,
        identity: &iap::Verified,
        headers: &HeaderMap,
        now: i64,
    ) -> Result<Option<ApprovalView>>;

    fn confirm(
        &self,
        view: &ApprovalView,
        identity: &iap::Verified,
        headers: &HeaderMap,
        evidence: external::FreshExternalApproval,
        now: i64,
    ) -> Result<bool>;
}

pub(crate) trait ApprovalSigner: Send + Sync {
    fn attest(
        &self,
        view: &ApprovalView,
        session: Digest,
        authenticated_at: i64,
        now: i64,
    ) -> Result<external::FreshExternalApproval>;
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum RequestBody {
    Lookup {
        version: u32,
        attempt: String,
        human_assertion: String,
    },
    Confirm {
        version: u32,
        attempt: String,
        human_assertion: String,
        view: Digest,
        evidence: Box<external::FreshExternalApproval>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum ResponseBody {
    Lookup {
        version: u32,
        app: String,
        attempt: String,
        owned: bool,
        view: Option<Box<ApprovalView>>,
    },
    Confirm {
        version: u32,
        app: String,
        attempt: String,
        approved: bool,
    },
}

pub(crate) struct HostLookup {
    pub owned: bool,
    pub view: Option<ApprovalView>,
}

/// One backend serves exactly one selected app database. Implementations hold
/// current authority through final local settlement and never make external
/// calls from inside the SQLite transaction.
pub(crate) trait AppApprovals: Send + Sync {
    fn app(&self) -> &str;

    fn lookup(&self, attempt: &str, identity: &iap::Verified, now: i64) -> Result<HostLookup>;

    fn confirm(
        &self,
        attempt: &str,
        expected: &Digest,
        identity: &iap::Verified,
        evidence: external::FreshExternalApproval,
        now: i64,
    ) -> Result<bool>;
}

/// Separate machine and human assertions are verified against separate selected
/// audiences. A valid human front-door assertion is never a workload credential.
pub(crate) struct AppApprovalReceiver {
    backend: Arc<dyn AppApprovals>,
    authority: String,
    workload: iap::Verifier,
    human: iap::Verifier,
    route: String,
}

impl AppApprovalReceiver {
    pub(crate) fn require_host(&self, app: &str, authority: &str) -> Result<()> {
        ensure!(
            self.backend.app() == app && self.authority == authority,
            "OAuth receiver host mismatch"
        );
        Ok(())
    }
    pub(crate) fn from_instance(
        instance: &Instance,
        backend: Arc<dyn AppApprovals>,
    ) -> Result<Arc<Self>> {
        let (identity, shell) = instance.security_edge()?;
        let transport = instance
            .oauth_shell_transport
            .as_ref()
            .context("OAuth shell transport missing")?;
        transport.validate()?;
        let edge = instance
            .apps
            .get(backend.app())
            .and_then(|app| app.edge.as_ref())
            .context("OAuth receiver app edge missing")?;
        let route = route_prefix(&instance.installation, &instance.environment, backend.app())?;
        Ok(Arc::new(Self {
            backend,
            authority: edge.authority().into(),
            route,
            workload: iap::Verifier::for_workload(
                &edge.iap_audience,
                &transport.service_account,
                Box::new(iap::GoogleKeys),
            )?,
            human: iap::Verifier::new(
                &shell.iap_audience,
                &identity.hosted_domain,
                Box::new(iap::GoogleKeys),
            )?,
        }))
    }

    /// A host may mount this reserved handler ahead of its app dispatcher. It
    /// cannot be implemented as an app command/query or an authenticated human
    /// API. Workload authorization remains mandatory on every request.
    pub(crate) async fn handle(self: Arc<Self>, request: Request) -> Response {
        self.handle_admitted(request, None).await
    }

    pub(crate) async fn handle_admitted(
        self: Arc<Self>,
        request: Request,
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ) -> Response {
        let (parts, body) = request.into_parts();
        let body =
            match tokio::time::timeout(Duration::from_secs(3), to_bytes(body, MAX_REQUEST)).await {
                Ok(Ok(body)) => body,
                Ok(Err(_)) => return protected(StatusCode::PAYLOAD_TOO_LARGE.into_response()),
                Err(_) => return protected(StatusCode::REQUEST_TIMEOUT.into_response()),
            };
        let result = tokio::task::spawn_blocking(move || {
            // Keep host capacity until authentication and local settlement
            // finish, including when the HTTP caller disconnects.
            let _permit = permit;
            self.dispatch(
                &parts.method,
                parts.uri.path(),
                parts.uri.query(),
                &parts.headers,
                &body,
                now()?,
            )
        })
        .await;
        let response = match result {
            Ok(Ok(bytes)) => ([(header::CONTENT_TYPE, "application/json")], bytes).into_response(),
            Ok(Err(_)) => StatusCode::FORBIDDEN.into_response(),
            Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };
        protected(response)
    }

    pub(crate) async fn serve(self: Arc<Self>, listener: tokio::net::TcpListener) -> Result<()> {
        axum::serve(
            listener,
            Router::new().fallback(move |request| self.clone().handle(request)),
        )
        .await?;
        Ok(())
    }

    fn dispatch(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        body: &[u8],
        at: i64,
    ) -> Result<Vec<u8>> {
        ensure!(
            *method == Method::POST
                && path == PATH
                && query.is_none()
                && body.len() <= MAX_REQUEST
                && headers.get_all(header::HOST).iter().count() == 1
                && headers
                    .get(header::HOST)
                    .and_then(|value| value.to_str().ok())
                    == Some(&self.authority)
                && headers.get_all(header::CONTENT_TYPE).iter().count() == 1
                && headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    == Some("application/json")
                && !headers.contains_key("x-http-method-override"),
            "invalid OAuth private request"
        );
        self.workload.verify_workload(one_assertion(headers)?, at)?;
        let request: RequestBody = crate::json::decode(body)?;
        let response = match request {
            RequestBody::Lookup {
                version,
                attempt: id,
                human_assertion,
            } => {
                ensure!(version == VERSION, "unsupported OAuth private version");
                routed_attempt(&id, &self.route)?;
                let identity = self.human.verify(&human_assertion, at)?;
                let lookup = self.backend.lookup(&id, &identity, at)?;
                ResponseBody::Lookup {
                    version: VERSION,
                    app: self.backend.app().into(),
                    attempt: id,
                    owned: lookup.owned,
                    view: lookup.view.map(Box::new),
                }
            }
            RequestBody::Confirm {
                version,
                attempt: id,
                human_assertion,
                view,
                evidence,
            } => {
                ensure!(
                    version == VERSION && evidence.attempt == id,
                    "invalid OAuth confirmation"
                );
                routed_attempt(&id, &self.route)?;
                let identity = self.human.verify(&human_assertion, at)?;
                let approved = self.backend.confirm(&id, &view, &identity, *evidence, at)?;
                ResponseBody::Confirm {
                    version: VERSION,
                    app: self.backend.app().into(),
                    attempt: id,
                    approved,
                }
            }
        };
        let bytes = serde_json::to_vec(&response)?;
        ensure!(bytes.len() <= MAX_RESPONSE, "OAuth private response budget");
        Ok(bytes)
    }
}

/// The private host supplies a credential for exactly the selected receiver
/// URL. It must use its qualified IAP workload signer, never browser/app ADC.
pub(crate) trait PrivateBearerSource: Send + Sync {
    fn bearer(&self, app: &str, receiver: &Url) -> Result<String>;
}

struct Target {
    origin: String,
    endpoint: Url,
    authority: String,
    route: String,
}

pub(crate) struct RemoteApprovals {
    targets: BTreeMap<String, Target>,
    client: Client,
    bearers: Arc<dyn PrivateBearerSource>,
    shell_origin: String,
}

impl RemoteApprovals {
    pub(crate) fn from_instance(
        instance: &Instance,
        bearers: Arc<dyn PrivateBearerSource>,
    ) -> Result<Self> {
        let (_, shell) = instance.security_edge()?;
        instance
            .oauth_shell_transport
            .as_ref()
            .context("OAuth shell transport missing")?
            .validate()?;
        let mut targets = BTreeMap::new();
        for (app, binding) in &instance.apps {
            if binding.oauth_connections.is_empty() {
                continue;
            }
            let edge = binding
                .edge
                .as_ref()
                .context("OAuth receiver app edge missing")?;
            let base = format!("{}/", edge.origin);
            origin(&base)?;
            targets.insert(
                app.clone(),
                Target {
                    endpoint: Url::parse(&base)?.join(PATH)?,
                    origin: base,
                    authority: edge.authority().into(),
                    route: route_prefix(&instance.installation, &instance.environment, app)?,
                },
            );
        }
        ensure!(
            !targets.is_empty() && targets.len() <= 128,
            "OAuth receiver budget"
        );
        Ok(Self {
            targets,
            bearers,
            shell_origin: format!("{}/", shell.origin),
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(2))
                .timeout(Duration::from_secs(15))
                .build()?,
        })
    }

    fn send(&self, app: &str, request: &RequestBody, deadline: Instant) -> Result<ResponseBody> {
        let target = self
            .targets
            .get(app)
            .context("OAuth receiver is not selected")?;
        let audience = Url::parse(&target.origin)?.join(PATH)?;
        let token = self.bearers.bearer(app, &audience)?;
        ensure!(
            !token.is_empty()
                && token.len() <= 8192
                && token.bytes().all(|byte| byte.is_ascii_graphic()),
            "invalid OAuth workload credential"
        );
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))?;
        authorization.set_sensitive(true);
        let bytes = serde_json::to_vec(request)?;
        ensure!(bytes.len() <= MAX_REQUEST, "OAuth private request budget");
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .context("OAuth private deadline reached")?;
        let response = self
            .client
            .post(target.endpoint.clone())
            .header(header::HOST, &target.authority)
            .header(header::AUTHORIZATION, authorization)
            .header(header::CONTENT_TYPE, "application/json")
            .timeout(timeout)
            .body(bytes)
            .send()?;
        ensure!(
            response.status().is_success()
                && response
                    .headers()
                    .get_all(header::CONTENT_TYPE)
                    .iter()
                    .count()
                    == 1
                && response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .is_some_and(|value| value == "application/json")
                && response
                    .content_length()
                    .is_none_or(|size| size <= MAX_RESPONSE as u64),
            "OAuth private receiver unavailable"
        );
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= MAX_RESPONSE, "OAuth private response budget");
        crate::json::decode(&bytes)
    }
}

impl ShellApprovals for RemoteApprovals {
    fn pending(
        &self,
        id: &str,
        identity: &iap::Verified,
        headers: &HeaderMap,
        _: i64,
    ) -> Result<Option<ApprovalView>> {
        attempt(id)?;
        let Some((app, target)) = self
            .targets
            .iter()
            .find(|(_, target)| id.starts_with(&target.route))
        else {
            return Ok(None);
        };
        routed_attempt(id, &target.route)?;
        let request = RequestBody::Lookup {
            version: VERSION,
            attempt: id.into(),
            human_assertion: one_assertion(headers)?.into(),
        };
        let deadline = Instant::now() + Duration::from_secs(LOOKUP_SECONDS);
        let ResponseBody::Lookup {
            version,
            app: observed_app,
            attempt: observed_id,
            owned: owns,
            view,
        } = self.send(app, &request, deadline)?
        else {
            anyhow::bail!("invalid OAuth lookup response");
        };
        ensure!(
            version == VERSION
                && observed_app == *app
                && observed_id == id
                && (owns || view.is_none()),
            "OAuth lookup receiver mismatch"
        );
        if let Some(view) = &view {
            view.validate(identity)?;
            ensure!(
                view.app == *app
                    && view.attempt() == id
                    && view.app_origin == target.origin
                    && view.shell_origin == self.shell_origin,
                "OAuth approval view receiver mismatch"
            );
        }
        Ok(view.map(|view| *view))
    }

    fn confirm(
        &self,
        view: &ApprovalView,
        identity: &iap::Verified,
        headers: &HeaderMap,
        evidence: external::FreshExternalApproval,
        _: i64,
    ) -> Result<bool> {
        view.validate(identity)?;
        let target = self
            .targets
            .get(&view.app)
            .context("OAuth receiver is not selected")?;
        routed_attempt(view.attempt(), &target.route)?;
        ensure!(
            view.app_origin == target.origin && view.shell_origin == self.shell_origin,
            "OAuth confirmation origin mismatch"
        );
        let request = RequestBody::Confirm {
            version: VERSION,
            attempt: view.attempt().into(),
            human_assertion: one_assertion(headers)?.into(),
            view: view.digest()?,
            evidence: Box::new(evidence),
        };
        // A consuming confirmation is sent once. Ambiguous network failures
        // never trigger an automatic retry or a second signature.
        let ResponseBody::Confirm {
            version,
            app,
            attempt,
            approved,
        } = self.send(
            &view.app,
            &request,
            Instant::now() + Duration::from_secs(15),
        )?
        else {
            anyhow::bail!("invalid OAuth confirmation response");
        };
        ensure!(
            version == VERSION && app == view.app && attempt == view.attempt(),
            "OAuth confirmation receiver mismatch"
        );
        Ok(approved)
    }
}

fn origin(value: &str) -> Result<()> {
    let url = Url::parse(value)?;
    ensure!(
        value.len() <= 1024
            && url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && format!("{}/", url.origin().ascii_serialization()) == value,
        "invalid OAuth transport origin"
    );
    Ok(())
}

pub(crate) fn attempt(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)),
        "invalid OAuth private attempt"
    );
    Ok(())
}

/// Installation/app namespace plus a fresh 256-bit random suffix. Routing is
/// public metadata, never authority; ownership, human and current contracts
/// still come from the app host's durable pending attempt.
pub(crate) fn scoped_attempt(installation: &str, environment: &str, app: &str) -> Result<String> {
    Ok(format!(
        "{}{}",
        route_prefix(installation, environment, app)?,
        web_security::random()?
    ))
}

pub(super) fn route_prefix(installation: &str, environment: &str, app: &str) -> Result<String> {
    for value in [installation, environment, app] {
        crate::schema::identifier(value)?;
    }
    let digest = Digest::of(&(
        "oauth-shell-attempt-route-v1",
        installation,
        environment,
        app,
    ))?;
    Ok(format!("a_{}_", crate::assets::hash_part(digest.as_str())?))
}

pub(super) fn routed_attempt(id: &str, route: &str) -> Result<()> {
    attempt(id)?;
    let suffix = id
        .strip_prefix(route)
        .context("OAuth attempt belongs to another receiver")?;
    ensure!(
        suffix.len() == 43
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)),
        "invalid OAuth routed attempt"
    );
    Ok(())
}

fn one_assertion(headers: &HeaderMap) -> Result<&str> {
    let mut values = headers.get_all(iap::ASSERTION_HEADER).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        anyhow::bail!("OAuth private request requires one IAP assertion");
    };
    let value = value.to_str()?;
    ensure!(value.len() <= 16_384, "OAuth assertion budget");
    Ok(value)
}

fn now() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}

fn protected(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

#[cfg(test)]
#[path = "shell_transport_tests.rs"]
mod tests;
