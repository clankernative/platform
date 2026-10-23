//! Native secret entry. Roc authorizes the resource, but never receives the
//! form body. Custody is a separate operator-granted command boundary; neither
//! an execution grant nor permission to read a result grants secret management.
use super::{Host, security};
use crate::{error::Failure, integrations::FreetoolCredentialAction as Action};
use anyhow::{Context, Result, ensure};
use axum::{
    http::{Method, StatusCode, Uri},
    response::Response,
};
use day2_capabilities::resources::{Action as ResourceAction, ResolvedGrant, ResourceTarget};
use maud::{Markup, html};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

pub(super) const PREFIX: &str = crate::freetool_executor::CREDENTIALS_PATH_PREFIX;
const OPERATION: &str = "freetool.credential_enrollment_access";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Access {
    resource_id: String,
    space_id: String,
    revision: u64,
    resource_kind: String,
    can_enroll: bool,
}

impl Access {
    fn validate(&self, resource: &str) -> Result<()> {
        ensure!(
            self.can_enroll
                && self.resource_id == resource
                && self.revision > 0
                && crate::identity::valid_for(&self.space_id, "spa")
                && matches!(self.resource_kind.as_str(), "http" | "postgres"),
            Failure::Forbidden
        );
        Ok(())
    }
}

#[derive(Serialize)]
struct Identity<'a> {
    installation: &'a str,
    application: &'a str,
    actor: &'a str,
    artifact: &'a str,
    operation: &'a str,
    resource_id: &'a str,
    resource_revision: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ticket {
    scope: String,
    artifact: String,
    session: String,
    actor: String,
    resource: String,
    revision: u64,
    resource_kind: String,
    credential_version: u64,
    target_digest: String,
    grant_digest: String,
    nonce: String,
    issued: i64,
    expires: i64,
}

impl Ticket {
    fn check(
        &self,
        binding: (&str, &str),
        session: &security::Session,
        at: i64,
        access: &Access,
        grant: &ResolvedGrant,
    ) -> Result<()> {
        ensure!(
            self.scope == binding.0
                && self.artifact == binding.1
                && self.session == session.hash
                && self.actor == session.actor,
            Failure::TicketScopeMismatch
        );
        ensure!(
            self.issued <= at
                && at < self.expires
                && self.expires <= self.issued.saturating_add(1800)
                && self.expires <= session.expires,
            Failure::TicketExpired
        );
        ensure!(
            self.resource == access.resource_id
                && self.revision == access.revision
                && self.resource_kind == access.resource_kind
                && self.grant_digest == grant_digest(grant)?,
            Failure::TicketScopeMismatch
        );
        ensure!(
            self.nonce.len() == 43
                && self
                    .nonce
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            Failure::InvalidTicket
        );
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Target {
    scheme: String,
    host: String,
    port: u16,
    allowed_path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    username: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Status {
    status: CredentialState,
    credential_id: Option<String>,
    version: u64,
    #[serde(default)]
    approved_target: Option<Target>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum CredentialState {
    Active,
    Absent,
    StaleTarget,
}

impl Status {
    fn label(&self) -> &'static str {
        match self.status {
            CredentialState::Active => "Configured",
            CredentialState::Absent => "No credential enrolled",
            CredentialState::StaleTarget => "Target changed; enroll a new credential",
        }
    }
    fn target_digest(&self) -> Result<String> {
        let target = self
            .approved_target
            .as_ref()
            .context(Failure::ResourceForbidden)?;
        ensure!(
            !target.host.is_empty()
                && target.host.len() <= 253
                && target.port > 0
                && target.allowed_path_prefixes.len() <= 256,
            Failure::ResourceForbidden
        );
        Ok(crate::digest(&serde_json::to_vec(target)?))
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Credential {
    HttpBearer { token: String },
    HttpBasic { username: String, password: String },
    HttpHeader { name: String, value: String },
    PostgresPassword { username: String, password: String },
}

impl Drop for Credential {
    fn drop(&mut self) {
        match self {
            Self::HttpBearer { token } => token.zeroize(),
            Self::HttpBasic { username, password }
            | Self::PostgresPassword { username, password } => {
                username.zeroize();
                password.zeroize();
            }
            Self::HttpHeader { name, value } => {
                name.zeroize();
                value.zeroize();
            }
        }
    }
}

struct Fields(BTreeMap<String, String>);
impl Drop for Fields {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}
impl Fields {
    fn take(&mut self, key: &str) -> Result<String> {
        self.0.remove(key).context(Failure::InvalidForm)
    }
}

fn credential(fields: &mut Fields, kind: &str, action: Action) -> Result<Option<Credential>> {
    if matches!(action, Action::Retain | Action::Clear) {
        ensure!(fields.0.is_empty(), Failure::UnknownFields);
        return Ok(None);
    }
    let selected = Zeroizing::new(fields.take("kind")?);
    let value = match (kind, selected.as_str()) {
        ("http", "http_bearer") => Credential::HttpBearer {
            token: fields.take("secret")?,
        },
        ("http", "http_basic") => Credential::HttpBasic {
            username: fields.take("name")?,
            password: fields.take("secret")?,
        },
        ("http", "http_header") => Credential::HttpHeader {
            name: fields.take("name")?,
            value: fields.take("secret")?,
        },
        ("postgres", "postgres_password") => Credential::PostgresPassword {
            username: fields.take("name")?,
            password: fields.take("secret")?,
        },
        _ => anyhow::bail!(Failure::InvalidForm),
    };
    // Bearer forms share the ordinary name control; it must be empty, not a
    // hidden second credential or silently ignored authority assertion.
    if matches!(value, Credential::HttpBearer { .. }) {
        ensure!(fields.take("name")?.is_empty(), Failure::InvalidForm);
    }
    ensure!(fields.0.is_empty(), Failure::UnknownFields);
    Ok(Some(value))
}

fn grant_digest(grant: &ResolvedGrant) -> Result<String> {
    Ok(crate::digest(&serde_json::to_vec(grant)?))
}

fn select_grant<'a>(
    grants: &'a BTreeMap<String, ResolvedGrant>,
    actor: &str,
    resource: &str,
    at: i64,
) -> Result<&'a ResolvedGrant> {
    let now_ms = at
        .checked_mul(1000)
        .context(Failure::ResourceAuthorityExpired)?;
    let mut matches = grants.values().filter(|grant| {
        let ResourceTarget::FreetoolExecutor {
            service_id,
            scope,
            credential_managers,
        } = &grant.target
        else {
            return false;
        };
        service_id == &grant.connection.id
            && scope.authorizes(resource)
            && credential_managers.contains(actor)
            && grant.actors.contains(actor)
            && grant.actions.contains(&ResourceAction::FreetoolStatus)
            && grant.expires_at_ms.is_none_or(|expiry| now_ms < expiry)
    });
    let grant = matches.next().context(Failure::ResourceForbidden)?;
    ensure!(matches.next().is_none(), Failure::ResourceForbidden);
    let connection = grant.live.as_ref().context(Failure::ResourceForbidden)?;
    ensure!(
        matches!(
            connection,
            day2_capabilities::integrations::LiveConnection::FreetoolExecutor { .. }
        ),
        Failure::ResourceForbidden
    );
    connection.validate()?;
    Ok(grant)
}

impl Host {
    fn credential_access(
        &self,
        session: &security::Session,
        resource: &str,
        at: i64,
    ) -> Result<(Access, ResolvedGrant)> {
        ensure!(
            self.runtime.app() == "freetool"
                && self.runtime.artifact().operation(OPERATION)?.kind == "query",
            Failure::Forbidden
        );
        let db = crate::store::open(self.runtime.db())?;
        self.runtime.check_binding(&db)?;
        let session_live: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM day2_web_sessions WHERE hash=?1 AND actor=?2 AND expires>?3)",
            rusqlite::params![session.hash, session.actor, at], |row| row.get(0),
        )?;
        ensure!(session_live, Failure::SignInRequired);
        drop(db);
        let authority = self.runtime.authority_snapshot(OPERATION, &session.actor)?;
        let grants = authority
            .document
            .resources
            .operations
            .get(OPERATION)
            .context(Failure::ResourceForbidden)?;
        let grant = select_grant(grants, &session.actor, resource, at)?.clone();
        let outcome = self.runtime.invoke_verified(
            OPERATION,
            crate::store::RequestIdentity {
                actor: &session.actor,
                origin: session.origin.as_ref(),
            },
            &format!(
                "credential-access-{}",
                security::random(self.entropy.as_ref())?
            ),
            &json!({"resource_id":resource}),
            at,
            crate::store::Fault::None,
        )?;
        ensure!(outcome.status == "success", Failure::Forbidden);
        let access: Access =
            serde_json::from_value(outcome.result).map_err(|_| Failure::Forbidden)?;
        access.validate(resource)?;
        // Both the business query and native effect depend on the same activated
        // operator policy; a policy replacement while the query ran is refused.
        ensure!(
            authority.stamp
                == self
                    .runtime
                    .authority_snapshot(OPERATION, &session.actor)?
                    .stamp,
            Failure::AuthorityPolicyChanged
        );
        Ok((access, grant))
    }

    fn credential_service(
        &self,
        session: &security::Session,
        access: &Access,
        grant: &ResolvedGrant,
        action: Action,
        ticket: Option<&Ticket>,
        credential: Option<&Credential>,
    ) -> Result<Status> {
        let installation = self
            .runtime
            .scope()
            .strip_suffix("/freetool")
            .context(Failure::Forbidden)?;
        let identity = Identity {
            installation,
            application: "freetool",
            actor: &session.actor,
            artifact: self.runtime.artifact().id(),
            operation: OPERATION,
            resource_id: &access.resource_id,
            resource_revision: access.revision,
        };
        #[derive(Serialize)]
        struct Mutation<'a, 'b> {
            identity: Identity<'a>,
            expected_version: u64,
            idempotency_key: &'b str,
            #[serde(skip_serializing_if = "Option::is_none")]
            credential: Option<&'b Credential>,
        }
        let body = Zeroizing::new(if let Some(ticket) = ticket {
            serde_json::to_vec(&Mutation {
                identity,
                expected_version: ticket.credential_version,
                idempotency_key: &ticket.nonce,
                credential,
            })?
        } else {
            #[derive(Serialize)]
            struct Read<'a> {
                identity: Identity<'a>,
            }
            serde_json::to_vec(&Read { identity })?
        });
        ensure!(
            body.len() <= 16_384 && body.len() as u64 <= grant.limits.max_request_bytes,
            Failure::ResourceLimitExceeded
        );
        let bytes = self.runtime.integrations().freetool_credential_request(
            grant.live.as_ref().context(Failure::ResourceForbidden)?,
            action,
            &body,
        )?;
        ensure!(
            bytes.len() as u64 <= grant.limits.max_response_bytes,
            Failure::ResourceLimitExceeded
        );
        let status: Status = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("freetool_credential_response_invalid"))?;
        ensure!(
            status
                .credential_id
                .as_ref()
                .is_none_or(|id| id.len() <= 256),
            "freetool_credential_response_invalid"
        );
        Ok(status)
    }

    pub(super) fn freetool_credentials(
        &self,
        method: &Method,
        uri: &Uri,
        body: &[u8],
        session: &security::Session,
        at: i64,
    ) -> Result<Response> {
        let response = match self.credential_request(method, uri, body, session, at) {
            Ok(response) => response,
            Err(error) => {
                let (status, message) = match crate::error::classify(&error) {
                    Failure::SignInRequired => (
                        StatusCode::UNAUTHORIZED,
                        "Your session has ended. Sign in again before managing credentials.",
                    ),
                    Failure::VersionConflict => (
                        StatusCode::CONFLICT,
                        "The saved credential changed after this form opened. Reopen the credential page before replacing or removing it.",
                    ),
                    Failure::Forbidden | Failure::ResourceForbidden => (
                        StatusCode::FORBIDDEN,
                        "Credential management is not permitted for this resource. Both resource-edit permission and an operator credential-management grant are required.",
                    ),
                    Failure::InvalidCsrf
                    | Failure::InvalidTicket
                    | Failure::TicketScopeMismatch
                    | Failure::TicketExpired
                    | Failure::AuthorityPolicyChanged => (
                        StatusCode::CONFLICT,
                        "This form is no longer current. Reopen the resource credential page before making changes.",
                    ),
                    Failure::InvalidForm
                    | Failure::UnknownFields
                    | Failure::DuplicateOrExcessFields
                    | Failure::ResourceLimitExceeded => (
                        StatusCode::BAD_REQUEST,
                        "The credential form is invalid or too large. Reopen it and check the authentication type and required fields.",
                    ),
                    _ => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Credential custody could not confirm this request. Reopen the credential page to check its current status. Submitted secrets are never redisplayed.",
                    ),
                };
                super::html_response(
                    status,
                    html! { (maud::DOCTYPE) html lang="en" {
                        head { meta charset="utf-8"; meta name="viewport" content="width=device-width,initial-scale=1";
                            title { "Resource credentials · Freetool" }
                            link rel="stylesheet" href="/assets/platform/web.css"; }
                        body { main class="login stack" { h1 { "Credential request not completed" }
                            p role="alert" { (message) }
                            a href="/" { "Return to Freetool" }
                        } }
                    } },
                )
            }
        };
        Ok(secret_response(response))
    }

    fn credential_request(
        &self,
        method: &Method,
        uri: &Uri,
        body: &[u8],
        session: &security::Session,
        at: i64,
    ) -> Result<Response> {
        ensure!(uri.query().is_none(), Failure::UnknownFields);
        let resource = uri
            .path()
            .strip_prefix(PREFIX)
            .context(Failure::InvalidForm)?;
        ensure!(
            crate::identity::valid_for(resource, "res"),
            Failure::InvalidForm
        );
        let (access, grant) = self.credential_access(session, resource, at)?;
        let status = if *method == Method::POST {
            ensure!(body.len() <= 16_384, Failure::ResourceLimitExceeded);
            let mut fields = Fields(security::fields(body)?);
            security::verify_csrf(&self.secret, session, &fields.take("_csrf")?)?;
            let ticket: Ticket =
                serde_json::from_slice(&security::verify(&self.secret, &fields.take("_ticket")?)?)
                    .map_err(|_| Failure::InvalidTicket)?;
            ticket.check(
                (self.runtime.scope(), self.runtime.artifact().id()),
                session,
                at,
                &access,
                &grant,
            )?;
            let action = match fields.take("action")?.as_str() {
                "replace" => Action::Replace,
                "retain" => Action::Retain,
                "clear" => Action::Clear,
                _ => anyhow::bail!(Failure::InvalidForm),
            };
            let credential = credential(&mut fields, &access.resource_kind, action)?;
            let current =
                self.credential_service(session, &access, &grant, Action::Status, None, None)?;
            ensure!(
                ticket.target_digest == current.target_digest()?,
                Failure::TicketScopeMismatch
            );
            // A status read may wait on the service. Recheck the session and
            // business/operator authority immediately before the mutation.
            let current_at = self.wall_seconds()?;
            let (access, grant) = self.credential_access(session, resource, current_at)?;
            ticket.check(
                (self.runtime.scope(), self.runtime.artifact().id()),
                session,
                current_at,
                &access,
                &grant,
            )?;
            // Never journal or send submitted values to the app. The custody
            // service owns CAS and durable replay of this signed attempt nonce.
            self.credential_service(
                session,
                &access,
                &grant,
                action,
                Some(&ticket),
                credential.as_ref(),
            )?;
            // POST/redirect/GET drops secret values and avoids resubmission on refresh.
            return super::redirect(uri.path());
        } else {
            ensure!(*method == Method::GET, Failure::UnsupportedMethod);
            self.credential_service(session, &access, &grant, Action::Status, None, None)?
        };
        let ticket = Ticket {
            scope: self.runtime.scope().into(),
            artifact: self.runtime.artifact().id().into(),
            session: session.hash.clone(),
            actor: session.actor.clone(),
            resource: resource.into(),
            revision: access.revision,
            resource_kind: access.resource_kind.clone(),
            credential_version: status.version,
            target_digest: status.target_digest()?,
            grant_digest: grant_digest(&grant)?,
            nonce: security::random(self.entropy.as_ref())?,
            issued: at,
            expires: at.saturating_add(1800).min(session.expires),
        };
        let token = security::sign(&self.secret, &serde_json::to_vec(&ticket)?)?;
        let csrf = security::csrf(&self.secret, session)?;
        Ok(super::html_response(
            StatusCode::OK,
            page(uri.path(), &access, &status, &csrf, &token),
        ))
    }
}

fn secret_response(mut response: Response) -> Response {
    // Secret entry deliberately excludes both app scripts and the platform's
    // usual progressive-enhancement scripts, including on failure responses.
    response.headers_mut().insert(axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static("default-src 'none'; script-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"));
    response
}

fn page(path: &str, access: &Access, status: &Status, csrf: &str, token: &str) -> Markup {
    html! {
        (maud::DOCTYPE)
        html lang="en" {
            head { meta charset="utf-8"; meta name="viewport" content="width=device-width,initial-scale=1";
                title { "Manage resource credentials · Freetool" }
                link rel="stylesheet" href="/assets/platform/web.css";
            }
            body { main class="login stack credentials" {
                h1 { "Manage resource credentials" }
                p { "Credentials are sent directly to private encrypted custody. They are never saved in the tool definition or its audit history." }
                p role="status" { (status.label()) }
                @if let Some(target) = &status.approved_target {
                    h2 { "Operator-approved destination" }
                    p { (target.scheme) "://" (target.host) ":" (target.port) }
                    @if let Some(database) = &target.database { p { "Database: " (database) } }
                    @if let Some(username) = &target.username { p { "Database user: " (username) } }
                    @for prefix in &target.allowed_path_prefixes { p { "Allowed path: " (prefix) } }
                }
                h2 { "Enroll or replace" }
                form method="post" action=(path) autocomplete="off" class="stack" {
                    input type="hidden" name="_csrf" value=(csrf);
                    input type="hidden" name="_ticket" value=(token);
                    input type="hidden" name="action" value="replace";
                    @if access.resource_kind == "postgres" {
                        input type="hidden" name="kind" value="postgres_password";
                        p { "PostgreSQL password" }
                    } @else {
                        label for="kind" { "Authentication" }
                        select id="kind" name="kind" {
                            option value="http_bearer" { "Bearer token" }
                            option value="http_basic" { "Basic authentication" }
                            option value="http_header" { "Private header" }
                        }
                    }
                    p { label for="name" { "Username or header name (leave empty for a bearer token)" }
                        input id="name" name="name" maxlength="256" autocomplete="off"; }
                    p { label for="secret" { "Password, token, or private header value" }
                        input id="secret" type="password" name="secret" maxlength="8192" autocomplete="new-password" required; }
                    button type="submit" class="primary" { "Save credential" }
                }
                h2 { "Existing credential" }
                form method="post" action=(path) {
                    input type="hidden" name="_csrf" value=(csrf);
                    input type="hidden" name="_ticket" value=(token);
                    input type="hidden" name="action" value="retain";
                    button type="submit" { "Keep existing credential" }
                }
                details { summary { "Remove credential" }
                    p { "Tools that require this credential will stop authenticating until a replacement is enrolled." }
                    form method="post" action=(path) {
                        input type="hidden" name="_csrf" value=(csrf);
                        input type="hidden" name="_ticket" value=(token);
                        input type="hidden" name="action" value="clear";
                        button type="submit" class="danger" { "Remove credential" }
                    }
                }
                p { a href=(format!("/spaces/{}/resources/editor?resource_id={}", access.space_id, access.resource_id)) { "Back to resource" } }
            } }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn granted() -> Result<ResolvedGrant> {
        serde_json::from_value(json!({
            "policy":{"id":"custody_policy","revision":1},
            "resource":{"id":"custody_resource","revision":1},
            "connection":{"id":"freetool_local","revision":1},
            "provider":"freetool_executor",
            "live":{"provider":"freetool_executor","endpoint":"http://127.0.0.1:9876",
                "credential_ref":{"id":"transport_key","revision":1}},
            "target":{"kind":"freetool_executor","service_id":"freetool_local",
                "scope":{"kind":"explicit","allowed_resources":["resource"]},"credential_managers":["editor"]},
            "actions":["freetool_status"],"actors":["editor"],
            "limits":{"max_request_bytes":16384,"max_response_bytes":16384,"max_calls_per_invocation":3},
            "budgets":[],"expires_at_ms":100000
        })).map_err(Into::into)
    }

    #[test]
    fn custody_grant_is_explicit_actor_resource_service_and_expiry_bound() -> Result<()> {
        let grant = granted()?;
        let good = BTreeMap::from([("custody".into(), grant.clone())]);
        select_grant(&good, "editor", "resource", 99)?;
        assert!(select_grant(&good, "reader", "resource", 99).is_err());
        assert!(select_grant(&good, "editor", "other_resource", 99).is_err());
        let mut app_wide = grant.clone();
        if let ResourceTarget::FreetoolExecutor { scope, .. } = &mut app_wide.target {
            *scope = day2_capabilities::resources::FreetoolResourceScope::AnyAppResource;
        }
        select_grant(
            &BTreeMap::from([("custody".into(), app_wide)]),
            "editor",
            "resource-created-by-app",
            99,
        )?;
        assert!(select_grant(&good, "editor", "resource", 100).is_err());
        let mut no_management = grant.clone();
        if let ResourceTarget::FreetoolExecutor {
            credential_managers,
            ..
        } = &mut no_management.target
        {
            credential_managers.clear();
        }
        assert!(
            select_grant(
                &BTreeMap::from([("custody".into(), no_management.clone())]),
                "editor",
                "resource",
                99
            )
            .is_err()
        );
        assert!(no_management.target.is_subset_of(&grant.target));
        assert!(!grant.target.is_subset_of(&no_management.target));
        let mut wrong_service = grant.clone();
        wrong_service.connection.id = "another_service".into();
        assert!(
            select_grant(
                &BTreeMap::from([("custody".into(), wrong_service)]),
                "editor",
                "resource",
                99
            )
            .is_err()
        );
        let ambiguous = BTreeMap::from([("a".into(), grant.clone()), ("b".into(), grant)]);
        assert!(select_grant(&ambiguous, "editor", "resource", 99).is_err());
        Ok(())
    }

    #[test]
    fn signed_ticket_rejects_scope_session_resource_policy_and_version_changes() -> Result<()> {
        let grant = granted()?;
        let mut access = Access {
            resource_id: "resource".into(),
            space_id: crate::identity::example("spa"),
            revision: 7,
            resource_kind: "http".into(),
            can_enroll: true,
        };
        let session = security::Session {
            hash: "session".into(),
            actor: "editor".into(),
            expires: 100,
            origin: None,
        };
        let ticket = Ticket {
            scope: "local/dev/freetool".into(),
            artifact: "artifact".into(),
            session: session.hash.clone(),
            actor: session.actor.clone(),
            resource: access.resource_id.clone(),
            revision: access.revision,
            resource_kind: access.resource_kind.clone(),
            credential_version: 2,
            target_digest: "target".into(),
            grant_digest: grant_digest(&grant)?,
            nonce: "a".repeat(43),
            issued: 10,
            expires: 90,
        };
        let secret = [1; 32];
        let signed = security::sign(&secret, &serde_json::to_vec(&ticket)?)?;
        let decoded: Ticket = serde_json::from_slice(&security::verify(&secret, &signed)?)?;
        let binding = ("local/dev/freetool", "artifact");
        decoded.check(binding, &session, 20, &access, &grant)?;
        assert!(security::verify(&[2; 32], &signed).is_err());
        assert!(
            decoded
                .check(
                    ("other/dev/freetool", "artifact"),
                    &session,
                    20,
                    &access,
                    &grant
                )
                .is_err()
        );
        assert!(
            decoded
                .check(binding, &session, 90, &access, &grant)
                .is_err()
        );
        let mut revoked = session.clone();
        revoked.hash = "new-session".into();
        assert!(
            decoded
                .check(binding, &revoked, 20, &access, &grant)
                .is_err()
        );
        let mut changed = grant.clone();
        changed.connection.revision += 1;
        assert!(
            decoded
                .check(binding, &session, 20, &access, &changed)
                .is_err()
        );
        access.revision += 1;
        assert!(
            decoded
                .check(binding, &session, 20, &access, &grant)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn business_access_is_resource_bound_and_fail_closed() -> Result<()> {
        let resource = crate::identity::example("res");
        let mut access = Access {
            resource_id: resource.clone(),
            space_id: crate::identity::example("spa"),
            revision: 1,
            resource_kind: "http".into(),
            can_enroll: true,
        };
        access.validate(&resource)?;
        assert!(access.validate("another-resource").is_err());
        access.can_enroll = false;
        assert!(access.validate(&resource).is_err());
        access.can_enroll = true;
        access.resource_kind = "unknown".into();
        assert!(access.validate(&resource).is_err());
        Ok(())
    }

    #[test]
    fn secret_form_rejects_extra_fields_and_cross_provider_credentials() -> Result<()> {
        let make = |kind: &str| {
            Fields(BTreeMap::from([
                ("kind".into(), kind.into()),
                ("name".into(), "".into()),
                ("secret".into(), "synthetic-private-token".into()),
            ]))
        };
        assert!(credential(&mut make("http_bearer"), "postgres", Action::Replace).is_err());
        assert!(credential(&mut make("postgres_password"), "http", Action::Replace).is_err());
        assert!(credential(&mut make("http_bearer"), "http", Action::Retain).is_err());
        let mut injected = make("http_bearer");
        injected.0.insert("actor".into(), "administrator".into());
        assert!(credential(&mut injected, "http", Action::Replace).is_err());
        let value =
            credential(&mut make("http_bearer"), "http", Action::Replace)?.context("credential")?;
        assert!(matches!(value, Credential::HttpBearer { .. }));
        assert!(credential(&mut Fields(BTreeMap::new()), "http", Action::Clear)?.is_none());
        Ok(())
    }

    #[test]
    fn native_form_escapes_destination_and_never_renders_credential_bytes() {
        let access = Access {
            resource_id: crate::identity::example("res"),
            space_id: crate::identity::example("spa"),
            revision: 1,
            resource_kind: "http".into(),
            can_enroll: true,
        };
        let status = Status {
            status: CredentialState::Active,
            credential_id: Some("private-custody-id".into()),
            version: 2,
            approved_target: Some(Target {
                scheme: "https".into(),
                host: "<script>evil</script>".into(),
                port: 443,
                allowed_path_prefixes: vec![],
                database: None,
                username: None,
            }),
        };
        let output = page("/safe", &access, &status, "csrf", "ticket").into_string();
        assert!(!output.contains("<script>evil"));
        assert!(!output.contains("private-custody-id"));
        assert!(output.contains("type=\"password\""));
        assert!(!output.contains("name=\"actor\""));
        assert!(!output.contains("data-command"));
    }
}
