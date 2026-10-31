//! Closed, finite App metadata handlers on their actual retained HTTP owner.
//! Request/response DATA never construct native authority. Routed app pages,
//! human/OAuth/command and streaming handlers are deliberately not this lane.
use super::{
    Host, QUEUE_WAIT, SignIn, check_request_head, edge_refusal, failure, queued_permit, secure,
    transport_error,
};
use crate::{error::Failure, oauth::native_management::HostSql, store::SqlDecision};
use crate::{
    store::Runtime,
    web_security::{self as security, Session},
};
use anyhow::{Context, Result, ensure};
use axum::{
    body::to_bytes,
    extract::Request,
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::Response,
};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

#[derive(Clone, Copy)]
enum HostHandler {
    Docs,
    OpenApi,
    Session,
    NoPagesRootRedirect,
    DocsScript,
    DocsStyle,
}

impl HostHandler {
    fn select(method: &Method, path: &str, artifact: &crate::artifact::Artifact) -> Option<Self> {
        if method != Method::GET {
            return None;
        }
        match path {
            "/" if artifact.pages.is_empty() => Some(Self::NoPagesRootRedirect),
            "/assets/platform/api-docs.js" => Some(Self::DocsScript),
            "/assets/platform/api-docs.css" => Some(Self::DocsStyle),
            crate::openapi::DOCS_PATH => Some(Self::Docs),
            crate::openapi::SPEC_PATH => Some(Self::OpenApi),
            crate::openapi::SESSION_PATH => Some(Self::Session),
            _ => None,
        }
    }

    fn path(self) -> &'static str {
        match self {
            Self::NoPagesRootRedirect => "/",
            Self::DocsScript => "/assets/platform/api-docs.js",
            Self::DocsStyle => "/assets/platform/api-docs.css",
            Self::Docs => crate::openapi::DOCS_PATH,
            Self::OpenApi => crate::openapi::SPEC_PATH,
            Self::Session => crate::openapi::SESSION_PATH,
        }
    }

    fn category(self) -> &'static str {
        match self {
            Self::Docs => "api_docs",
            Self::OpenApi | Self::Session => "api",
            Self::NoPagesRootRedirect => "page",
            Self::DocsScript | Self::DocsStyle => "asset",
        }
    }
}

// No Debug/Serialize: headers, verified identity and response cookies are not
// diagnostics. The semaphore stays owned through concrete handler completion.
pub(crate) struct PreparedHostRequest {
    host: Arc<Host>,
    handler: HostHandler,
    uri: Uri,
    headers: HeaderMap,
    body: std::result::Result<axum::body::Bytes, StatusCode>,
    verified: std::result::Result<crate::iap::Verified, Failure>,
    cookie: Option<String>,
    at: i64,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

pub(crate) fn native_host_candidate<B>(host: &Host, request: &axum::http::Request<B>) -> bool {
    host.oauth.is_some()
        && host.runtime.uses_native_storage()
        && HostHandler::select(
            request.method(),
            request.uri().path(),
            host.runtime.artifact().contract(),
        )
        .is_some()
}

/// Runs only after the native HTTP original was captured. JWT public-key I/O
/// and body readiness occur before any SQLite loan, on that unchanged original.
pub(crate) async fn prepare_host_request(
    host: Arc<Host>,
    request: Request,
) -> Result<PreparedHostRequest> {
    ensure!(
        host.admitting.load(Ordering::Acquire),
        "native host admission stopped"
    );
    let handler = HostHandler::select(
        request.method(),
        request.uri().path(),
        host.runtime.artifact().contract(),
    )
    .context("native host route not selected")?;
    ensure!(
        native_host_candidate(&host, &request),
        "native host storage not selected"
    );
    let permit = match host.capacity.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => queued_permit(&host, QUEUE_WAIT)
            .await
            .context("native host capacity unavailable")?,
    };
    let (parts, body) = request.into_parts();
    let body = match crate::managed_credentials::effects::timeout(
        Duration::from_secs(3),
        to_bytes(body, 65_536),
    )
    .await
    {
        Ok(Ok(body)) => Ok(body),
        Ok(Err(_)) => Err(StatusCode::PAYLOAD_TOO_LARGE),
        Err(_) => Err(StatusCode::REQUEST_TIMEOUT),
    };
    let at = host.wall_seconds()?;
    let SignIn::Edge(verifier) = &host.sign_in else {
        anyhow::bail!("native host requires edge assertion");
    };
    let verified = (|| {
        let mut assertions = parts.headers.get_all(crate::iap::ASSERTION_HEADER).iter();
        let (Some(assertion), None) = (assertions.next(), assertions.next()) else {
            anyhow::bail!(Failure::InvalidIdentityAssertion);
        };
        verifier.verify(
            assertion
                .to_str()
                .map_err(|_| Failure::InvalidIdentityAssertion)?,
            at,
        )
    })();
    // Only checked authentication outcomes become known denial DATA. Native,
    // SQL and unknown errors never enter this conversion.
    let verified = match verified {
        Ok(verified) => Ok(verified),
        Err(error) => match error.downcast_ref::<Failure>().copied() {
            Some(
                failure @ (Failure::InvalidIdentityAssertion
                | Failure::IdentityKeysUnavailable
                | Failure::MachineCallerRequiresDelegation),
            ) => Err(failure),
            _ => return Err(error),
        },
    };
    let cookie = security::session_token(&parts.headers, &host.cookie_name).ok();
    Ok(PreparedHostRequest {
        host,
        handler,
        uri: parts.uri,
        headers: parts.headers,
        body,
        verified,
        cookie,
        at,
        _permit: permit,
    })
}

enum Admitted {
    Session(Session),
    NeedsSession,
    Denied(Failure),
}

/// Real SQL failures escape through HostSql and poison its actual parent.
/// Expected identity/permission refusals alone are explicit checked DATA.
fn admit_host_in(
    runtime: &Runtime,
    api: &crate::openapi::Catalog,
    db: &rusqlite::Connection,
    verified: &crate::iap::Verified,
    cookie: Option<&str>,
    at: i64,
) -> Result<Admitted> {
    runtime.check_binding(db)?;
    if let Err(error) = crate::iap::bind_subject(db, verified, at) {
        return match error.downcast_ref::<Failure>() {
            Some(Failure::PrincipalSubjectChanged) => {
                Ok(Admitted::Denied(Failure::PrincipalSubjectChanged))
            }
            _ => Err(error),
        };
    }
    if !crate::web_api::session_allowed_in(runtime, api, db, &verified.email)? {
        return Ok(Admitted::Denied(Failure::Forbidden));
    }
    if let Some(token) = cookie {
        match security::session_for_token_in(db, token, at) {
            Ok(mut session) if session.actor == verified.email => {
                session.origin = Some(verified.clone());
                return Ok(Admitted::Session(session));
            }
            Ok(_) => {}
            Err(error) if error.downcast_ref::<Failure>() == Some(&Failure::SignInRequired) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(Admitted::NeedsSession)
}

impl Host {
    pub(crate) fn prepared_host_runtime(&self) -> &Runtime {
        &self.runtime
    }

    pub(crate) fn prepared_host_effects(&self) -> crate::managed_credentials::effects::Captured {
        self.credential_effects.clone()
    }

    pub(crate) fn execute_host_request(
        self: &Arc<Self>,
        request: PreparedHostRequest,
        sql: &mut HostSql<'_, '_>,
    ) -> Result<Response> {
        ensure!(
            HostHandler::select(
                &Method::GET,
                request.handler.path(),
                self.runtime.artifact().contract()
            )
            .is_some(),
            "native prepared host route changed"
        );
        ensure!(
            Arc::ptr_eq(self, &request.host),
            "native prepared host identity changed"
        );
        let PreparedHostRequest {
            handler,
            uri,
            headers,
            body,
            verified,
            cookie,
            at,
            _permit,
            ..
        } = request;
        let mut issued = None;
        let admission = match verified {
            Err(failure) => Admitted::Denied(failure),
            Ok(ref verified) => {
                let admission = sql.write(|db| {
                    Ok(SqlDecision::Commit(admit_host_in(
                        &self.runtime,
                        &self.api,
                        db,
                        verified,
                        cookie.as_deref(),
                        at,
                    )?))
                })?;
                match admission {
                    Admitted::NeedsSession => {
                        // Entropy never runs with a SQL transaction live and
                        // follows the first actual permission/session check.
                        let token = security::random(self.entropy.as_ref())?;
                        sql.write(|db| {
                            // Revalidate after that external boundary on the
                            // same parent, without another owner factory.
                            match admit_host_in(
                                &self.runtime,
                                &self.api,
                                db,
                                verified,
                                cookie.as_deref(),
                                at,
                            )? {
                                Admitted::NeedsSession => {
                                    security::create_session_in(
                                        db,
                                        &verified.email,
                                        at,
                                        token.clone(),
                                    )?;
                                    let mut session =
                                        security::session_for_token_in(db, &token, at)?;
                                    session.origin = Some(verified.clone());
                                    issued = Some(token);
                                    Ok(SqlDecision::Commit(Admitted::Session(session)))
                                }
                                other => Ok(SqlDecision::Commit(other)),
                            }
                        })?
                    }
                    other => other,
                }
            }
        };
        let session = match &admission {
            Admitted::Session(session) => Some(session),
            _ => None,
        };
        let actor = session.map(|session| session.actor.as_str());
        let pre = crate::audit::WebEvent::new(at, actor, handler.category(), 102)?;
        sql.write(|db| {
            self.runtime.web_event_in(db, pre)?;
            Ok(SqlDecision::Commit(()))
        })?;
        let json = crate::web_api::is_json(handler.path());
        let mut response = match &admission {
            Admitted::Denied(failure) => edge_refusal(json, &anyhow::anyhow!(*failure)),
            Admitted::NeedsSession => anyhow::bail!("native host admission incomplete"),
            Admitted::Session(session) => match body {
                Err(status) => transport_error(json, status, "Request body exceeded its limit."),
                Ok(body) => {
                    let checked = check_request_head(&self.authority, &uri, &headers);
                    // Preserve head-guard -> appearance -> actor guard ->
                    // current authorization order. External file work occurs
                    // after pre-audit and outside every SQL loan.
                    let checked = match checked {
                        Ok(()) => {
                            self.appearance.check_binding(&self.runtime)?;
                            check_metadata_actor(&headers)
                        }
                        Err(error) => Err(error),
                    };
                    let allowed = if checked.is_ok() {
                        sql.read(|db| {
                            self.runtime.check_binding(db)?;
                            crate::web_api::session_allowed_in(
                                &self.runtime,
                                &self.api,
                                db,
                                &session.actor,
                            )
                        })?
                    } else {
                        false
                    };
                    match checked.and_then(|()| {
                        ensure!(allowed, Failure::Forbidden);
                        check_metadata_body(handler, &uri, &body)?;
                        Ok(())
                    }) {
                        Ok(()) => match handler {
                            HostHandler::NoPagesRootRedirect => self.no_pages_root_redirect()?,
                            HostHandler::DocsScript | HostHandler::DocsStyle => {
                                crate::web_assets::platform(handler.path(), &headers)?
                            }
                            HostHandler::Docs | HostHandler::OpenApi | HostHandler::Session => {
                                self.metadata_response(handler.path(), session)?
                            }
                        },
                        Err(error) => {
                            // This result contains only the explicit pure
                            // routing guards/permission boolean above.
                            if json {
                                crate::web_api::failure(&error)
                            } else {
                                failure(&error)
                            }
                        }
                    }
                }
            },
        };
        if let Some(token) = issued {
            response
                .headers_mut()
                .append(header::SET_COOKIE, self.session_cookie(&token).parse()?);
        }
        let post =
            crate::audit::WebEvent::new(at, actor, handler.category(), response.status().as_u16())?;
        sql.write(|db| {
            self.runtime.web_event_in(db, post)?;
            Ok(SqlDecision::Commit(()))
        })?;
        Ok(secure(response))
    }
}

fn check_metadata_actor(headers: &HeaderMap) -> Result<()> {
    ensure!(
        !headers.contains_key(crate::web_api::ACT_AS_HEADER),
        Failure::InvalidInput
    );
    Ok(())
}

fn check_metadata_body(handler: HostHandler, uri: &Uri, body: &[u8]) -> Result<()> {
    // The original no-pages '/' redirect permits a query string. Metadata
    // endpoints have the separate existing no-query contract.
    ensure!(
        body.is_empty()
            && (matches!(
                handler,
                HostHandler::NoPagesRootRedirect | HostHandler::DocsScript | HostHandler::DocsStyle
            ) || uri.query().is_none()),
        Failure::InvalidInput
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::redirect;
    use serde_json::Value;
    use std::collections::BTreeMap;

    fn explicit_sql_only(source: &str) -> bool {
        use syn::visit::{self, Visit};
        struct Check(bool);
        impl<'ast> Visit<'ast> for Check {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                if matches!(
                    call.method.to_string().as_str(),
                    "sql_read"
                        | "sql_write"
                        | "authorize"
                        | "authorize_audit"
                        | "may_request_delegation"
                        | "dispatch"
                ) {
                    self.0 = false;
                }
                visit::visit_expr_method_call(self, call);
            }
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if let syn::Expr::Path(path) = &*call.func {
                    let names: Vec<_> = path
                        .path
                        .segments
                        .iter()
                        .map(|part| part.ident.to_string())
                        .collect();
                    if names.last().is_some_and(|name| {
                        matches!(
                            name.as_str(),
                            "open"
                                | "with_runtime_sql"
                                | "session_allowed"
                                | "session_for_token"
                                | "create_session"
                                | "session"
                        )
                    }) {
                        self.0 = false;
                    }
                }
                visit::visit_expr_call(self, call);
            }
        }
        let Ok(file) = syn::parse_file(source) else {
            return false;
        };
        let mut checked = Check(true);
        checked.visit_file(&file);
        checked.0
    }

    #[test]
    fn production_host_caller_rejects_hidden_sql_factories_and_unchanged_dispatch_mutants() {
        let source = include_str!("web_host_request.rs")
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .unwrap();
        assert!(explicit_sql_only(source));
        for (from, to) in [
            ("sql.write(", "self.runtime.sql_write("),
            (
                "security::session_for_token_in(",
                "security::session_for_token(",
            ),
            (
                "crate::web_api::session_allowed_in(",
                "crate::web_api::session_allowed(",
            ),
            ("self.metadata_response(", "self.dispatch("),
        ] {
            assert!(
                source.contains(from),
                "mutant must target actual production call: {from}"
            );
            assert!(
                !explicit_sql_only(&source.replace(from, to)),
                "nested factory must refuse: {from}"
            );
        }
    }

    fn metadata_request_guards(
        authority: &str,
        uri: &Uri,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<()> {
        check_request_head(authority, uri, headers)?;
        check_metadata_actor(headers)?;
        check_metadata_body(HostHandler::Docs, uri, body)?;
        Ok(())
    }

    fn fixture() -> Result<(tempfile::TempDir, Runtime, crate::openapi::Catalog)> {
        let root = tempfile::tempdir()?;
        let runtime = crate::oauth::admission::host_request_test_runtime(root.path())?;
        // This lower fixture admits real storage/authority but deliberately
        // has no complete browser contract. Supply only the catalog DATA this
        // primitive reads (the actual registered operation key), never claim
        // a served/admitted browser artifact from this test.
        let operation = runtime.artifact().route("read")?.clone();
        let api = crate::openapi::Catalog {
            endpoints: BTreeMap::from([(
                "read".into(),
                crate::operation_catalog::Endpoint {
                    operation,
                    input_schema: Value::Null,
                    output_schema: Value::Null,
                    summary: String::new(),
                    description: String::new(),
                    execution_description: "fixture",
                    response_description: String::new(),
                    request_example: Value::Null,
                    response_example: Value::Null,
                    response_example_source: "fixture",
                    deprecated: false,
                    metadata: None,
                },
            )]),
        };
        Ok((root, runtime, api))
    }

    fn alice() -> crate::iap::Verified {
        crate::iap::Verified {
            email: "alice@example.com".into(),
            subject: "google-alice".into(),
        }
    }

    #[test]
    fn finite_host_plan_excludes_real_pages_human_commands_streams_and_non_gets() -> Result<()> {
        let (_root, runtime, _) = fixture()?;
        let mut contract = runtime.artifact().contract().clone();
        contract.pages.clear();
        for path in [
            "/",
            "/docs",
            "/openapi.json",
            "/api/session",
            "/assets/platform/api-docs.js",
            "/assets/platform/api-docs.css",
        ] {
            assert!(HostHandler::select(&Method::GET, path, &contract).is_some());
            for method in [Method::HEAD, Method::POST, Method::PUT, Method::DELETE] {
                assert!(HostHandler::select(&method, path, &contract).is_none());
            }
        }
        for path in [
            "/_day2/oauth/connect",
            "/_platform/app-query",
            "/_live",
            "/actions",
            "/api/queries/read",
            "/pages/index",
            "/docs/",
            "/assets/platform/forms.js",
        ] {
            assert!(
                HostHandler::select(&Method::GET, path, &contract).is_none(),
                "{path}"
            );
        }
        contract
            .pages
            .push(serde_json::from_value(serde_json::json!({
                "name":"index","title":"Index","operation":"read","defaults":"{}",
                "preparation":["prepare"],"prepare_failure_operation":"fallback"
            }))?);
        assert!(
            HostHandler::select(&Method::GET, "/", &contract).is_none(),
            "a real root page cannot enter the no-pages redirect variant"
        );
        assert!(HostHandler::select(&Method::GET, "/docs", &contract).is_some());
        Ok(())
    }

    #[test]
    fn explicit_host_session_uses_real_sqlite_and_never_substitutes_cookie_actor() -> Result<()> {
        let (_root, runtime, api) = fixture()?;
        let token = "a".repeat(43);
        let other = "b".repeat(43);
        runtime.sql_write(|db| {
            assert!(matches!(
                admit_host_in(&runtime, &api, db, &alice(), None, 100)?,
                Admitted::NeedsSession
            ));
            security::create_session_in(db, "alice@example.com", 100, token.clone())?;
            security::create_session_in(db, "bob@example.com", 100, other.clone())?;
            Ok(())
        })?;
        runtime.sql_write(|db| {
            let Admitted::Session(session) =
                admit_host_in(&runtime, &api, db, &alice(), Some(&token), 101)?
            else {
                anyhow::bail!("expected actual Alice session");
            };
            assert_eq!(session.actor, "alice@example.com");
            assert_eq!(session.origin, Some(alice()));
            assert!(matches!(
                admit_host_in(&runtime, &api, db, &alice(), Some(&other), 101)?,
                Admitted::NeedsSession
            ));
            assert!(
                matches!(
                    admit_host_in(&runtime, &api, db, &alice(), Some(&token), 28_900)?,
                    Admitted::NeedsSession
                ),
                "expiry equality refuses the old cookie"
            );
            let mut foreign_subject = alice();
            foreign_subject.subject = "reassigned-google-subject".into();
            assert!(matches!(
                admit_host_in(&runtime, &api, db, &foreign_subject, Some(&token), 101)?,
                Admitted::Denied(Failure::PrincipalSubjectChanged)
            ));
            let bob = crate::iap::Verified {
                email: "bob@example.com".into(),
                subject: "google-bob".into(),
            };
            assert!(matches!(
                admit_host_in(&runtime, &api, db, &bob, Some(&other), 101)?,
                Admitted::Denied(Failure::Forbidden)
            ));
            Ok(())
        })?;
        Ok(())
    }

    #[test]
    fn explicit_host_sql_failures_and_foreign_artifact_are_not_known_auth_denials() -> Result<()> {
        for changed in ["artifact", "session_schema", "principal_schema"] {
            let (_root, runtime, api) = fixture()?;
            let token = "a".repeat(43);
            let db = crate::store::open(runtime.db())?;
            {
                match changed {
                    "artifact" => {
                        db.execute(
                            "UPDATE day2_authority SET artifact_id='foreign' WHERE singleton=1",
                            [],
                        )?;
                    }
                    "session_schema" => {
                        db.execute("DROP TABLE day2_web_sessions", [])?;
                    }
                    "principal_schema" => {
                        db.execute("DROP TABLE day2_principals", [])?;
                    }
                    _ => unreachable!(),
                }
            }
            drop(db);
            let result = runtime
                .sql_write(|db| admit_host_in(&runtime, &api, db, &alice(), Some(&token), 100));
            assert!(
                result.is_err(),
                "{changed} must propagate, never become Denied or NeedsSession"
            );
            if changed == "artifact" {
                assert_eq!(
                    result.err().unwrap().downcast_ref::<Failure>(),
                    Some(&Failure::ArtifactBindingChanged)
                );
            }
        }
        Ok(())
    }

    #[test]
    fn explicit_host_routing_guards_keep_singular_host_override_query_and_body_refusals()
    -> Result<()> {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "calendar.example.com".parse()?);
        assert!(
            metadata_request_guards("calendar.example.com", &"/docs".parse()?, &headers, b"")
                .is_ok()
        );
        assert!(
            metadata_request_guards("calendar.example.com", &"/docs?a=1".parse()?, &headers, b"")
                .is_err()
        );
        assert!(
            metadata_request_guards("calendar.example.com", &"/docs".parse()?, &headers, b"x")
                .is_err()
        );
        for key in ["x-http-method-override", crate::web_api::ACT_AS_HEADER] {
            let mut altered = headers.clone();
            altered.insert(key, "read".parse()?);
            assert!(
                metadata_request_guards("calendar.example.com", &"/docs".parse()?, &altered, b"")
                    .is_err()
            );
        }
        headers.append(header::HOST, "calendar.example.com".parse()?);
        assert!(
            metadata_request_guards("calendar.example.com", &"/docs".parse()?, &headers, b"")
                .is_err()
        );
        Ok(())
    }
    #[test]
    fn no_pages_root_and_docs_assets_keep_their_distinct_query_and_response_contracts() -> Result<()>
    {
        let uri = "/?retained=1".parse()?;
        assert!(check_metadata_body(HostHandler::NoPagesRootRedirect, &uri, b"").is_ok());
        assert!(check_metadata_body(HostHandler::Docs, &uri, b"").is_err());
        assert!(check_metadata_body(HostHandler::NoPagesRootRedirect, &uri, b"x").is_err());
        for (handler, expected, kind) in [
            (
                HostHandler::DocsScript,
                include_bytes!("../../../assets/api-docs.js").as_slice(),
                "text/javascript",
            ),
            (
                HostHandler::DocsStyle,
                include_bytes!("../../../assets/api-docs.css").as_slice(),
                "text/css",
            ),
        ] {
            assert!(check_metadata_body(handler, &uri, b"").is_ok());
            let response = crate::web_assets::platform(handler.path(), &HeaderMap::new())?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CONTENT_TYPE], kind);
            assert!(expected.len() <= 65_536);
            let etag = response.headers()[header::ETAG].clone();
            let bytes = futures_executor::block_on(to_bytes(response.into_body(), 65_536))?;
            assert_eq!(bytes.as_ref(), expected);
            let mut headers = HeaderMap::new();
            headers.insert(header::IF_NONE_MATCH, etag);
            let unchanged = crate::web_assets::platform(handler.path(), &headers)?;
            assert_eq!(unchanged.status(), StatusCode::NOT_MODIFIED);
            assert!(
                futures_executor::block_on(to_bytes(unchanged.into_body(), 65_536))?.is_empty()
            );
        }
        let response = redirect(crate::openapi::DOCS_PATH)?;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/docs");
        Ok(())
    }
}
