//! Separate-origin local resource administration. App sessions and cookies confer
//! no operator authority. A short-lived, process-local bearer is issued only by
//! an explicit local operator launch and is never available to app resources.
use crate::resource_admin;
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::net::TcpListener;

#[derive(Clone)]
struct Host {
    path: PathBuf,
    operator: String,
    authority: String,
    origin: String,
    secret: Vec<u8>,
    expires_ms: i64,
}

pub struct AdminServer {
    listener: TcpListener,
    host: Arc<Host>,
    pub origin: String,
    pub login_url: String,
}

impl AdminServer {
    pub async fn bind(path: &Path, operator: &str, port: u16) -> Result<Self> {
        resource_admin::authorize(path, operator)?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
        let authority = listener.local_addr()?.to_string();
        let origin = format!("http://{authority}");
        let mut secret = vec![0; 32];
        getrandom::fill(&mut secret).map_err(|_| anyhow::anyhow!("entropy_unavailable"))?;
        let host = Arc::new(Host {
            path: path.canonicalize()?,
            operator: operator.into(),
            authority,
            origin: origin.clone(),
            secret,
            expires_ms: resource_admin::now_ms()? + 8 * 60 * 60 * 1000,
        });
        let token = crate::web_security::sign(&host.secret, &host.session_message()?)?;
        Ok(Self {
            listener,
            host,
            origin: origin.clone(),
            login_url: format!("{origin}/#session={token}"),
        })
    }

    pub async fn serve(self, shutdown: impl Future<Output = ()> + Send + 'static) -> Result<()> {
        let router = Router::new()
            .route("/", get(index))
            .route("/admin.js", get(script))
            .route("/admin.css", get(styles))
            .route("/api", post(api))
            .layer(DefaultBodyLimit::max(1_048_576))
            .with_state(self.host);
        axum::serve(self.listener, router)
            .with_graceful_shutdown(shutdown)
            .await?;
        Ok(())
    }
}

impl Host {
    fn session_message(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            "day2-resource-admin-v1",
            &self.origin,
            &self.operator,
            self.expires_ms,
        ))?)
    }

    fn check_host(&self, headers: &HeaderMap) -> Result<()> {
        ensure!(
            headers.get_all(header::HOST).iter().count() == 1
                && headers.get(header::HOST).and_then(|v| v.to_str().ok())
                    == Some(self.authority.as_str()),
            "invalid_admin_host"
        );
        if let Some(origin) = headers.get(header::ORIGIN) {
            ensure!(origin.to_str()? == self.origin, "invalid_admin_origin");
        }
        Ok(())
    }

    fn authenticate(&self, headers: &HeaderMap) -> Result<()> {
        self.check_host(headers)?;
        ensure!(
            headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) == Some(self.origin.as_str()),
            "invalid_admin_origin"
        );
        ensure!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                == Some("application/json"),
            "invalid_admin_content_type"
        );
        ensure!(
            resource_admin::now_ms()? < self.expires_ms,
            "admin_session_expired"
        );
        ensure!(
            headers.get_all(header::AUTHORIZATION).iter().count() == 1,
            "admin_session_required"
        );
        let token = headers
            .get(header::AUTHORIZATION)
            .context("admin_session_required")?
            .to_str()?
            .strip_prefix("Bearer ")
            .context("admin_session_required")?;
        ensure!(
            crate::web_security::verify(&self.secret, token)? == self.session_message()?,
            "admin_session_required"
        );
        // Revoking an operator in desired installation administration takes effect
        // immediately for the admin service, independently of app activation.
        resource_admin::authorize(&self.path, &self.operator)
    }
}

fn response(status: StatusCode, content_type: &'static str, body: impl Into<String>) -> Response {
    (status, [(header::CONTENT_TYPE, content_type),
        (header::CACHE_CONTROL, "no-store"),
        (header::CONTENT_SECURITY_POLICY, "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY")], body.into()).into_response()
}

fn asset(
    host: &Host,
    headers: &HeaderMap,
    content_type: &'static str,
    body: &'static str,
) -> Response {
    if host.check_host(headers).is_err() {
        return response(
            StatusCode::FORBIDDEN,
            "text/plain",
            "Invalid administration origin",
        );
    }
    response(StatusCode::OK, content_type, body)
}

async fn index(State(host): State<Arc<Host>>, headers: HeaderMap) -> Response {
    asset(
        &host,
        &headers,
        "text/html; charset=utf-8",
        include_str!("resource_admin_ui/index.html"),
    )
}

async fn script(State(host): State<Arc<Host>>, headers: HeaderMap) -> Response {
    asset(
        &host,
        &headers,
        "text/javascript; charset=utf-8",
        include_str!("resource_admin_ui/admin.js"),
    )
}

async fn styles(State(host): State<Arc<Host>>, headers: HeaderMap) -> Response {
    asset(
        &host,
        &headers,
        "text/css; charset=utf-8",
        include_str!("resource_admin_ui/admin.css"),
    )
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Snapshot,
    Save {
        authoring: resource_admin::Authoring,
    },
    Preview {
        app: String,
    },
    Propose {
        app: String,
        proposal: resource_admin::Proposal,
    },
    Reviews {
        app: String,
    },
    Decide {
        app: String,
        decision: resource_admin::Decision,
    },
    Allocate {
        app: String,
        request: resource_admin::Allocate,
    },
    Attach {
        app: String,
        request: resource_admin::Attach,
    },
    SetupCompanyBudget,
    RecoverBudget {
        app: String,
        request: resource_admin::Recover,
    },
    ResolveOverruns {
        app: String,
        request: crate::budget::OverrunResolution,
    },
    ReconcileUsage {
        app: String,
        request: crate::budget::UsageReconciliation,
    },
    CompanyBudget,
    ProposePoolReduction {
        request: crate::budget::PoolReductionRequest,
    },
    ReturnCompanyCapacity {
        app: String,
        request: resource_admin::ReturnCompanyCapacity,
    },
    DecidePoolReduction {
        request: resource_admin::DecidePoolReduction,
    },
    ImportPoolReduction {
        app: String,
        request: resource_admin::ImportPoolReduction,
    },
}

fn dispatch(host: &Host, action: Action) -> Result<Value> {
    let path = &host.path;
    let operator = &host.operator;
    match action {
        Action::Snapshot => {
            let authoring = resource_admin::authoring(path, operator)?;
            Ok(
                json!({"operator":operator,"mode":"local-operator","administrator":resource_admin::is_administrator(path, operator)?,"authoring":authoring,"expires_ms":host.expires_ms}),
            )
        }
        Action::Save { authoring } => Ok(serde_json::to_value(resource_admin::save(
            path, operator, &authoring,
        )?)?),
        Action::Preview { app } => resource_admin::preview(path, &app, operator),
        Action::Propose { app, proposal } => {
            resource_admin::propose(path, &app, operator, &proposal)
        }
        Action::Reviews { app } => resource_admin::reviews(path, &app, operator),
        Action::Decide { app, decision } => resource_admin::decide(path, &app, operator, &decision),
        Action::Allocate { app, request } => {
            resource_admin::allocate(path, &app, operator, &request)
        }
        Action::Attach { app, request } => Ok(serde_json::to_value(resource_admin::attach(
            path, &app, operator, &request,
        )?)?),
        Action::SetupCompanyBudget => resource_admin::setup_company_budget(path, operator),
        Action::RecoverBudget { app, request } => {
            resource_admin::recover_budget(path, &app, operator, &request)
        }
        Action::ResolveOverruns { app, request } => {
            resource_admin::resolve_overruns(path, &app, operator, &request)
        }
        Action::ReconcileUsage { app, request } => {
            resource_admin::reconcile_usage(path, &app, operator, &request)
        }
        Action::CompanyBudget => resource_admin::company_budget(path, operator),
        Action::ProposePoolReduction { request } => {
            resource_admin::propose_pool_reduction(path, operator, &request)
        }
        Action::ReturnCompanyCapacity { app, request } => {
            resource_admin::return_company_capacity(path, &app, operator, &request)
        }
        Action::DecidePoolReduction { request } => {
            resource_admin::decide_pool_reduction(path, operator, &request)
        }
        Action::ImportPoolReduction { app, request } => {
            resource_admin::import_pool_reduction(path, &app, operator, &request)
        }
    }
}

async fn api(State(host): State<Arc<Host>>, headers: HeaderMap, body: Bytes) -> Response {
    if host.authenticate(&headers).is_err() {
        return response(StatusCode::FORBIDDEN, "application/json", json!({"error":"Operator session required. Launch administration again if it expired."}).to_string());
    }
    let result = tokio::task::spawn_blocking(move || -> Result<Value> {
        dispatch(&host, crate::json::decode(&body)?)
    })
    .await;
    match result {
        Ok(Ok(value)) => response(StatusCode::OK, "application/json", value.to_string()),
        Ok(Err(error)) => response(
            StatusCode::BAD_REQUEST,
            "application/json",
            json!({"error":error.to_string()}).to_string(),
        ),
        Err(_) => response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "application/json",
            json!({"error":"Administration request failed"}).to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Result<(tempfile::TempDir, Host, HeaderMap)> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("instance.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({
                "installation":"test","environment":"test","apps":{"app":{"artifact":"unused","readers":[],"writers":[]}},
                "control":{"version":1,"state_directory":dir.path().join("control"),"operators":["it"],
                    "sources":{"repo":{"kind":"local_git","repository":dir.path().join("repo")}},"apps":{"app":{"source":"repo"}}}
            }))?,
        )?;
        let host = Host {
            path,
            operator: "it".into(),
            authority: "127.0.0.1:40123".into(),
            origin: "http://127.0.0.1:40123".into(),
            secret: vec![72; 32],
            expires_ms: resource_admin::now_ms()? + 10000,
        };
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, host.authority.parse()?);
        headers.insert(header::ORIGIN, host.origin.parse()?);
        headers.insert(header::CONTENT_TYPE, "application/json".parse()?);
        headers.insert(
            header::AUTHORIZATION,
            format!(
                "Bearer {}",
                crate::web_security::sign(&host.secret, &host.session_message()?)?
            )
            .parse()?,
        );
        Ok((dir, host, headers))
    }

    #[test]
    fn app_cookies_foreign_origins_and_replayed_other_server_tokens_never_authorize_admin()
    -> Result<()> {
        let (_dir, host, headers) = fixture()?;
        host.authenticate(&headers)?;
        let mut cookies = headers.clone();
        cookies.remove(header::AUTHORIZATION);
        cookies.insert(header::COOKIE, "day2-session=anything".parse()?);
        assert!(host.authenticate(&cookies).is_err());
        for (key, value) in [
            (header::ORIGIN, "http://127.0.0.1:40124"),
            (header::HOST, "attacker.example:40123"),
            (header::CONTENT_TYPE, "text/plain"),
            (header::AUTHORIZATION, "Bearer forged"),
        ] {
            let mut changed = headers.clone();
            changed.insert(key, value.parse()?);
            assert!(host.authenticate(&changed).is_err());
        }
        let mut missing = headers.clone();
        missing.remove(header::ORIGIN);
        assert!(host.authenticate(&missing).is_err());
        let mut other = host.clone();
        other.secret = vec![21; 32];
        assert!(other.authenticate(&headers).is_err());
        other = host.clone();
        other.expires_ms = 0;
        assert!(other.authenticate(&headers).is_err());
        let mut instance: Value = serde_json::from_slice(&std::fs::read(&host.path)?)?;
        instance["control"]["operators"] = json!(["someone-else"]);
        std::fs::write(&host.path, serde_json::to_vec(&instance)?)?;
        assert!(host.authenticate(&headers).is_err());
        Ok(())
    }

    #[test]
    fn resource_authoring_is_cas_and_never_edits_other_instance_authority() -> Result<()> {
        let (_dir, host, _) = fixture()?;
        let before: Value = serde_json::from_slice(&std::fs::read(&host.path)?)?;
        let mut update = resource_admin::authoring(&host.path, "it")?;
        update.catalog =
            json!({"version":1,"connections":{},"resources":{},"policies":{},"budgets":{}});
        let next = resource_admin::save(&host.path, "it", &update)?;
        assert_ne!(update.revision, next.revision);
        assert!(resource_admin::save(&host.path, "it", &update).is_err());
        assert!(resource_admin::save(&host.path, "app-actor", &next).is_err());
        let after: Value = serde_json::from_slice(&std::fs::read(&host.path)?)?;
        assert_eq!(before["control"], after["control"]);
        assert_eq!(
            before["apps"]["app"]["writers"],
            after["apps"]["app"]["writers"]
        );
        assert!(
            !host
                .path
                .parent()
                .unwrap()
                .join(".state/app.sqlite")
                .exists()
        );
        Ok(())
    }
}
