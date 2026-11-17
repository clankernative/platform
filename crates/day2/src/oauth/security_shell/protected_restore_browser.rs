//! Dedicated IAP browser ceremony. Cookies, prompts, locators and public
//! approval records are correlation DATA, never restore authority. The final
//! request uses a distinct consuming native entry; its actual supplier remains
//! bound to genuine native transport; deployment and delivery qualification
//! remain separate from returned presentation DATA.
mod state;

use super::{SecurityShell, protected_restore_prompt};
use crate::security_epoch::native_enrollment::{
    ProtectedRestoreReply as Reply, ProtectedRestoreRequest as Request,
};
use crate::{iap, oauth::effects};
use anyhow::{Context, Result, ensure};
use axum::{
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use maud::{DOCTYPE, html};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

pub(super) const PAGE: &str = "/restore/protected";
const SCRIPT: &str = "/restore/protected.js";
const BEGIN: &str = "/restore/protected/begin";
const APPROVE: &str = "/restore/protected/approve";
const EXECUTE: &str = "/restore/protected/execution";
const AUTHENTICATE: &str = "/restore/protected/authenticate";
const ABANDON: &str = "/restore/protected/abandon";
const COOKIE: &str = "__Host-day2_protected_restore";
const MAX_BODY: usize = 65_536;

#[derive(Default)]
pub(super) struct Browser {
    state: Mutex<state::Store>,
}

/// Borrowed parts of the same already identified Shell request, not native
/// authority or a new authentication/clock context. Construction samples none.
pub(super) struct BrowserRequest<'request> {
    pub(super) method: &'request Method,
    pub(super) path: &'request str,
    pub(super) query: Option<&'request str>,
    pub(super) headers: &'request HeaderMap,
    pub(super) body: &'request [u8],
    pub(super) identity: &'request iap::Verified,
    pub(super) at: i64,
}

// Fixed results from the actual native courier, never browser-supplied DATA.
enum ReceivedReply {
    Ordinary(Reply),
    Installed(Box<crate::security_epoch::native_enrollment::RestoreInstalledOutputData>),
}

#[derive(Clone)]
struct RestoreDocument(String);

#[derive(Serialize, Deserialize)]
#[serde(tag = "action", deny_unknown_fields)]
enum Post {
    #[serde(rename = "begin")]
    Begin {
        csrf: String,
        app: String,
        input: String,
    },
    #[serde(rename = "approve")]
    Approve { csrf: String, assertion: String },
    #[serde(rename = "execution")]
    Execution { csrf: String, handoff: String },
    #[serde(rename = "authenticate")]
    Authenticate { csrf: String, assertion: String },
    #[serde(rename = "abandon")]
    Abandon { csrf: String },
}

impl Post {
    fn decode(body: &[u8]) -> Result<Self> {
        ensure!(body.len() <= MAX_BODY, "restore_browser_body_bound");
        let value: serde_json::Value =
            crate::json::decode(body).map_err(|_| anyhow::anyhow!("restore_browser_request"))?;
        let post: Self = serde_json::from_value(value.clone())
            .map_err(|_| anyhow::anyhow!("restore_browser_request"))?;
        ensure!(
            serde_json::to_value(&post)? == value,
            "restore_browser_request_shape"
        );
        Ok(post)
    }
}

pub(super) fn reserved(path: &str) -> bool {
    matches!(
        path,
        PAGE | SCRIPT | BEGIN | APPROVE | EXECUTE | AUTHENTICATE | ABANDON
    )
}

pub(super) fn body_limit(path: &str) -> usize {
    if matches!(path, BEGIN | APPROVE | EXECUTE | AUTHENTICATE | ABANDON) {
        MAX_BODY
    } else {
        4096
    }
}

fn token_shape(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn cookie(headers: &HeaderMap) -> Result<Option<String>> {
    let mut selected = None;
    for line in headers.get_all(header::COOKIE) {
        for part in line.to_str()?.split(';') {
            if let Some((name, value)) = part.trim().split_once('=')
                && name == COOKIE
            {
                ensure!(
                    selected.is_none() && token_shape(value),
                    "restore_browser_cookie"
                );
                selected = Some(value.to_owned());
            }
        }
    }
    Ok(selected)
}

fn require_post(headers: &HeaderMap, origin: &str) -> Result<()> {
    ensure!(
        headers.get_all(header::ORIGIN).iter().count() == 1
            && headers
                .get(header::ORIGIN)
                .and_then(|value| value.to_str().ok())
                == Some(origin),
        "restore_browser_origin"
    );
    ensure!(
        headers.get_all(header::CONTENT_TYPE).iter().count() == 1
            && headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                == Some("application/json"),
        "restore_browser_content_type"
    );
    Ok(())
}

fn decoded(value: &str, bound: usize) -> Result<Vec<u8>> {
    ensure!(
        value.len() <= bound.div_ceil(3) * 4,
        "restore_browser_input_bound"
    );
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| anyhow::anyhow!("restore_browser_input_encoding"))?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= bound && URL_SAFE_NO_PAD.encode(&bytes) == value,
        "restore_browser_input_bound"
    );
    Ok(bytes)
}

fn prompt_response(prompt: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], prompt).into_response()
}

impl Browser {
    pub(super) fn dispatch(
        &self,
        shell: &SecurityShell,
        request: BrowserRequest<'_>,
    ) -> Result<Option<Response>> {
        let BrowserRequest {
            method,
            path,
            query,
            headers,
            body,
            identity,
            at,
        } = request;
        if !reserved(path) {
            return Ok(None);
        }
        ensure!(query.is_none(), "restore_browser_query");
        if matches!(path, PAGE | SCRIPT) {
            ensure!(
                *method == Method::GET && body.is_empty(),
                "restore_browser_method"
            );
            if path == SCRIPT {
                return Ok(Some(
                    (
                        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                        include_bytes!("../../../../../assets/protected-restore.js").as_slice(),
                    )
                        .into_response(),
                ));
            }
            return Ok(Some(self.page(shell, headers, identity, at)?));
        }
        ensure!(*method == Method::POST, "restore_browser_method");
        require_post(headers, &shell.origin)?;
        let token = cookie(headers)?.context("restore_browser_session_missing")?;
        let post = Post::decode(body)?;
        let response = match (path, post) {
            (BEGIN, Post::Begin { csrf, app, input }) => {
                let bytes = decoded(&input, 32_768)?;
                let selection = shell
                    .native_selections
                    .iter()
                    .find(|selection| selection.scope().app.as_str() == app)
                    .context("restore_browser_selection")?;
                // Existing pure decoder compares against the SAME immutable
                // installed Shell selection. The Controller repeats real
                // registry/native admission independently after the claim.
                let command = crate::oauth::native_management::protected_restore_command_data(
                    selection.scope(),
                    &bytes,
                )?;
                let claim = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("restore_browser_state_refused"))?
                    .begin(
                        &token,
                        &csrf,
                        identity,
                        at,
                        selection.scope().clone(),
                        command,
                    )?;
                let reply = crate::oauth::native_management::protected_restore_request(
                    &claim.scope,
                    Request::BeginApproval { input: bytes },
                )?;
                self.received_reply(shell, claim, ReceivedReply::Ordinary(reply), identity)?
            }
            (APPROVE, Post::Approve { csrf, assertion }) => {
                let bytes = decoded(&assertion, 16_384)?;
                let claim = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("restore_browser_state_refused"))?
                    .approve(&token, &csrf, identity, at)?;
                let reply = crate::oauth::native_management::protected_restore_request(
                    &claim.scope,
                    Request::Approve {
                        id: claim.command.id.clone(),
                        assertion: bytes,
                    },
                )?;
                self.received_reply(shell, claim, ReceivedReply::Ordinary(reply), identity)?
            }
            (EXECUTE, Post::Execution { csrf, handoff }) => {
                ensure!(token_shape(&handoff), "restore_browser_handoff");
                let claim = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("restore_browser_state_refused"))?
                    .execute(&token, &csrf, &handoff, identity, at)?;
                let reply = crate::oauth::native_management::protected_restore_request(
                    &claim.scope,
                    Request::BeginExecution {
                        id: claim.command.id.clone(),
                    },
                )?;
                self.received_reply(shell, claim, ReceivedReply::Ordinary(reply), identity)?
            }
            (AUTHENTICATE, Post::Authenticate { csrf, assertion }) => {
                let bytes = decoded(&assertion, 16_384)?;
                let claim = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("restore_browser_state_refused"))?
                    .authenticate(&token, &csrf, identity, at)?;
                let data = crate::oauth::native_management::protected_restore_authenticate(
                    &claim.scope,
                    &claim.command.id,
                    &bytes,
                )?;
                self.received_reply(
                    shell,
                    claim,
                    ReceivedReply::Installed(Box::new(data)),
                    identity,
                )?
            }
            (ABANDON, Post::Abandon { csrf }) => {
                let claim = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("restore_browser_state_refused"))?
                    .abandon(&token, &csrf, identity, at)?;
                let reply = crate::oauth::native_management::protected_restore_request(
                    &claim.scope,
                    Request::Abandon {
                        id: claim.command.id.clone(),
                    },
                )?;
                self.received_reply(shell, claim, ReceivedReply::Ordinary(reply), identity)?
            }
            _ => anyhow::bail!("restore_browser_phase_changed"),
        };
        Ok(Some(response))
    }

    /// The actual native exchange finishes before this lock. Only bounded
    /// parsing, local entropy and in-memory claim publication occur here: no
    /// Controller/provider exchange, SQL transaction or new role is entered.
    /// Keep the lock through the independent post so another browser request
    /// cannot observe a usable phase before its guard has passed.
    fn received_reply(
        &self,
        shell: &SecurityShell,
        claim: state::Claim,
        reply: ReceivedReply,
        identity: &iap::Verified,
    ) -> Result<Response> {
        let scope = claim.scope.clone();
        let command = claim.command.clone();
        let mut store = match self.state.lock() {
            Ok(store) => store,
            Err(_) => {
                crate::oauth::native_management::refuse_protected_restore_reply();
                anyhow::bail!("restore_browser_state_refused");
            }
        };
        // The mutex wait is before this actual saved-original precheck.
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::oauth::native_management::check_protected_restore_reply(&scope)?;
            match (&claim.step, reply) {
                (
                    state::Step::Begin,
                    ReceivedReply::Ordinary(Reply::ApprovalPrompt { id, prompt }),
                ) => {
                    let approver = protected_restore_prompt::approval(
                        &prompt,
                        &id,
                        &claim.command,
                        identity,
                        &shell.origin,
                    )?;
                    store.approval_prompt(claim, approver)?;
                    Ok(prompt_response(prompt))
                }
                (
                    state::Step::Approve { .. },
                    ReceivedReply::Ordinary(Reply::ApprovalRecorded { commitment }),
                ) => {
                    let handoff = effects::random()?;
                    ensure!(token_shape(&handoff), "restore_browser_entropy");
                    store.recorded(claim, commitment, handoff.clone())?;
                    Ok(prompt_response(serde_json::to_vec(
                        &serde_json::json!({"handoff":handoff}),
                    )?))
                }
                (
                    state::Step::Execute { approver, recorded },
                    ReceivedReply::Ordinary(Reply::ExecutionPrompt { id, prompt }),
                ) => {
                    let approval_request = protected_restore_prompt::execution(
                        &prompt,
                        &id,
                        &claim.command,
                        recorded,
                        approver,
                        identity,
                        &shell.origin,
                    )?;
                    store.execution_prompt(claim, approval_request)?;
                    Ok(prompt_response(prompt))
                }
                (state::Step::Authenticate { .. }, ReceivedReply::Installed(data)) => {
                    store.authenticated(claim, &data)?;
                    // Installation metadata only, not proof of HTTP delivery.
                    Ok(prompt_response(serde_json::to_vec(&serde_json::json!({
                        "kind":"protected_restore_installed_metadata_v1",
                        "operation":data.operation,"target":data.target,"installed":data.installed,
                        "notice":"Native installation metadata only; future readiness and HTTP delivery are not established."
                    }))?))
                }
                (state::Step::Abandon, ReceivedReply::Ordinary(Reply::Abandoned)) => {
                    store.abandoned(claim)?;
                    Ok(StatusCode::NO_CONTENT.into_response())
                }
                _ => anyhow::bail!("restore_browser_reply_changed"),
            }
        }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::oauth::native_management::check_protected_restore_reply(&scope)
        }));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            store.refuse_reply(&scope, &command);
            crate::oauth::native_management::refuse_protected_restore_reply();
        }
        // Both actual observations precede result selection and mutex release.
        // This cannot undo an already completed native installation or erase an
        // uncertain external effect; it only keeps this browser flow refused.
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(response)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(response)
                }
            },
        }
    }

    fn page(
        &self,
        shell: &SecurityShell,
        headers: &HeaderMap,
        identity: &iap::Verified,
        at: i64,
    ) -> Result<Response> {
        let supplied = cookie(headers)?;
        let (token, csrf, has_flow, fresh) = if let Some(token) = supplied {
            let store = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("restore_browser_state_refused"))?;
            let (csrf, has_flow) = store.session(&token, identity, at)?;
            (token, csrf.to_owned(), has_flow, false)
        } else {
            let token = effects::random()?;
            let csrf = effects::random()?;
            ensure!(
                token_shape(&token) && token_shape(&csrf),
                "restore_browser_entropy"
            );
            self.state
                .lock()
                .map_err(|_| anyhow::anyhow!("restore_browser_state_refused"))?
                .open(token.clone(), csrf.clone(), identity, at)?;
            (token, csrf, false, true)
        };
        let page = html! {(DOCTYPE) html { head { meta charset="utf-8"; title {"Protected restore"} script type="module" src=(SCRIPT) {} } body { main id="protected-restore" data-origin=(&shell.origin) data-csrf=(&csrf) data-bound=(has_flow.to_string()) {
            h1 {"Protected restore"}
            p {"Signed in as " (&identity.email) ". Approval and execution use passkeys from the reviewed instance registry."}
            p {"Native execution is not qualified on this private implementation. Approval, prompts and HTTP status do not establish completion."}
            label for="restore-app" {"Application"}
            select id="restore-app" { @for selection in &shell.native_selections { option value=(selection.scope().app.as_str()) {(selection.scope().app.as_str())} } }
            label for="restore-input" {"Operator restore input file"} input id="restore-input" type="file";
            button id="restore-begin" type="button" disabled[has_flow] {"Review approval"}
            pre id="restore-review" {}
            button id="restore-approve" type="button" disabled {"Approve with passkey"}
            label for="restore-handoff" {"One-use executor handoff"} input id="restore-handoff" type="text" autocomplete="off";
            button id="restore-execution" type="button" {"Review executor prompt"}
            button id="restore-authenticate" type="button" disabled {"Authenticate and request installation"}
            button id="restore-abandon" type="button" {"Abandon pending ceremony"}
            p id="restore-status" role="status" aria-live="polite" {"No restore has completed. Reload never retries a sent action."}
        } } }};
        let mut response = (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            page.into_string(),
        )
            .into_response();
        if fresh {
            response.headers_mut().insert(
                header::SET_COOKIE,
                format!("{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=300")
                    .parse()?,
            );
        }
        response
            .extensions_mut()
            .insert(RestoreDocument(shell.origin.clone()));
        Ok(response)
    }
}

pub(super) fn protect_document(response: &mut Response) {
    if let Some(RestoreDocument(origin)) = response.extensions_mut().remove::<RestoreDocument>() {
        response.headers_mut().insert(header::CONTENT_SECURITY_POLICY, format!("default-src 'none'; script-src {origin}{SCRIPT}; script-src-attr 'none'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; worker-src 'none'").parse().expect("admitted shell origin"));
        response.headers_mut().insert("permissions-policy", "publickey-credentials-create=(), publickey-credentials-get=(self), camera=(), microphone=(), geolocation=()".parse().expect("static permissions policy"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedicated_post_boundary_refuses_foreign_or_duplicate_origin_cookie_and_shape() -> Result<()>
    {
        let origin = "https://security.example.com";
        let mut headers = HeaderMap::from_iter([
            (header::ORIGIN, origin.parse()?),
            (header::CONTENT_TYPE, "application/json".parse()?),
        ]);
        require_post(&headers, origin)?;
        headers.insert(header::ORIGIN, "https://app.example.com".parse()?);
        assert!(require_post(&headers, origin).is_err());
        headers.insert(header::ORIGIN, origin.parse()?);
        headers.append(header::ORIGIN, origin.parse()?);
        assert!(require_post(&headers, origin).is_err());
        headers.remove(header::ORIGIN);
        assert!(require_post(&headers, origin).is_err());
        let token = "a".repeat(43);
        headers.insert(header::COOKIE, format!("{COOKIE}={token}").parse()?);
        assert_eq!(cookie(&headers)?, Some(token.clone()));
        headers.append(header::COOKIE, format!("{COOKIE}={token}").parse()?);
        assert!(cookie(&headers).is_err());
        for body in [
            br#"{"action":"abandon","csrf":"c","extra":true}"#.as_slice(),
            br#"{"action":"abandon","csrf":"c","csrf":"c"}"#,
            br#"["abandon","c"]"#,
            br#"{"action":"authenticate","csrf":"c","approved":true}"#,
            br#"{"action":"abandon","csrf":null}"#,
        ] {
            assert!(Post::decode(body).is_err());
        }
        assert!(Post::decode(br#"{"action":"abandon","csrf":"c"}"#).is_ok());
        assert!(
            matches!(Post::decode(br#"{"action":"authenticate","csrf":"c","assertion":"YQ"}"#)?, Post::Authenticate { csrf, assertion } if csrf == "c" && assertion == "YQ")
        );
        for body in [
            br#"["authenticate","c","YQ"]"#.as_slice(),
            br#"{"action":"authenticate","csrf":"c","assertion":"YQ","assertion":"Yg"}"#,
            br#"{"action":"authenticate","csrf":"c","assertion":null}"#,
            br#"{"action":"authenticate","csrf":"c","assertion":"YQ","installed":true}"#,
        ] {
            assert!(Post::decode(body).is_err());
        }
        assert!(Post::decode(&vec![b' '; MAX_BODY + 1]).is_err());
        assert!(decoded(&URL_SAFE_NO_PAD.encode([7; 32_769]), 32_768).is_err());
        assert!(decoded("YQ==", 32_768).is_err());
        assert_eq!(decoded("YQ", 32_768)?, b"a");
        for path in [
            "/oauth/approvals/a",
            "/restore/protected/authenticate/",
            "/restore/protected/begin/",
            PAGE,
            SCRIPT,
        ] {
            assert_eq!(body_limit(path), 4096);
        }
        for path in [BEGIN, APPROVE, EXECUTE, AUTHENTICATE, ABANDON] {
            assert!(reserved(path));
            assert_eq!(body_limit(path), MAX_BODY);
        }
        Ok(())
    }

    #[test]
    fn actual_browser_asset_has_one_explicit_terminal_send_and_no_retry_or_status_inference() {
        let source = include_str!("../../../../../assets/protected-restore.js");
        for required in [
            "navigator.credentials.get",
            "userVerification: 'required'",
            "format: 'day2_restore_passkey_assertion_v1'",
            "credentials: 'same-origin'",
            "redirect: 'error'",
            "spent = true",
            "prompt = null",
            "executionPrompt = null",
            "if (busy || terminal) return",
            "terminal = true",
            "result.kind === 'protected_restore_installed_metadata_v1'",
            "result.operation === saved.operation",
            "window.location.origin === origin",
        ] {
            assert!(
                source.contains(required),
                "missing browser boundary {required}"
            );
        }
        for forbidden in [
            "setInterval",
            "setTimeout",
            "localStorage",
            "sessionStorage",
            ".elements",
            ".action",
            ".method",
            "innerHTML",
            "document.cookie",
            "RestoreCompleted",
        ] {
            assert!(
                !source.contains(forbidden),
                "unexpected browser path {forbidden}"
            );
        }
        assert_eq!(source.matches("post('authenticate'").count(), 1);
        let final_send = source.find("post('authenticate'").unwrap();
        let spent = source.find("terminal = true").unwrap();
        assert!(spent < final_send);
    }
}

#[cfg(test)]
mod terminal_source_tests {
    use quote::ToTokens;
    use syn::visit::Visit;

    fn same(a: &syn::Expr, b: &syn::Expr) -> bool {
        fn attrs(a: &[syn::Attribute], b: &[syn::Attribute]) -> bool {
            a.len() == b.len()
                && a.iter().zip(b).all(|(a, b)| {
                    a.to_token_stream().to_string() == b.to_token_stream().to_string()
                })
        }
        match (a, b) {
            (syn::Expr::Call(a), syn::Expr::Call(b)) => {
                attrs(&a.attrs, &b.attrs)
                    && same(&a.func, &b.func)
                    && a.args.len() == b.args.len()
                    && a.args.iter().zip(&b.args).all(|(a, b)| same(a, b))
            }
            (syn::Expr::MethodCall(a), syn::Expr::MethodCall(b)) => {
                attrs(&a.attrs, &b.attrs)
                    && a.method == b.method
                    && a.turbofish.to_token_stream().to_string()
                        == b.turbofish.to_token_stream().to_string()
                    && same(&a.receiver, &b.receiver)
                    && a.args.len() == b.args.len()
                    && a.args.iter().zip(&b.args).all(|(a, b)| same(a, b))
            }
            (syn::Expr::Try(a), syn::Expr::Try(b)) => {
                attrs(&a.attrs, &b.attrs) && same(&a.expr, &b.expr)
            }
            _ => a.to_token_stream().to_string() == b.to_token_stream().to_string(),
        }
    }

    fn guarded(body: &syn::Block) -> bool {
        fn local(stmt: &syn::Stmt, name: &str, expected: syn::Expr) -> bool {
            let syn::Stmt::Local(local) = stmt else {
                return false;
            };
            local.attrs.is_empty()
                && local.pat.to_token_stream().to_string() == name
                && local
                    .init
                    .as_ref()
                    .is_some_and(|i| i.diverge.is_none() && same(&i.expr, &expected))
        }
        let [bytes, claim, data, syn::Stmt::Expr(checked, None)] = body.stmts.as_slice() else {
            return false;
        };
        local(bytes,"bytes",syn::parse_quote!(decoded(&assertion,16_384)?))
            // A temporary mutex guard ends with this statement, before the
            // actual native send. Neither an actor string nor a supplied DTO
            // can substitute for the already saved one-use command claim.
            && local(claim,"claim",syn::parse_quote!(self.state.lock().map_err(|_|anyhow::anyhow!("restore_browser_state_refused"))?.authenticate(&token,&csrf,identity,at)?))
            && local(data,"data",syn::parse_quote!(crate::oauth::native_management::protected_restore_authenticate(&claim.scope,&claim.command.id,&bytes)?))
            && same(checked,&syn::parse_quote!(self.received_reply(shell,claim,ReceivedReply::Installed(Box::new(data)),identity)?))
    }

    fn phase_body(source: &str) -> syn::Block {
        let mut found = Vec::new();
        for item in syn::parse_file(source).unwrap().items {
            if let syn::Item::Impl(item) = item
                && matches!(&*item.self_ty,syn::Type::Path(path) if path.path.is_ident("Browser"))
            {
                for item in item.items {
                    if let syn::ImplItem::Fn(item) = item
                        && item.sig.ident == "received_reply"
                    {
                        found.push(item.block);
                    }
                }
            }
        }
        assert_eq!(found.len(), 1);
        found.pop().unwrap()
    }

    fn phase_guarded(body: &syn::Block) -> bool {
        fn compact(v: impl ToTokens) -> String {
            v.to_token_stream()
                .to_string()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect()
        }
        fn caught(stmt: &syn::Stmt, name: &str) -> Option<syn::Block> {
            let syn::Stmt::Local(local) = stmt else {
                return None;
            };
            if !matches!(&local.pat,syn::Pat::Ident(id) if id.ident==name) {
                return None;
            }
            let syn::Expr::Call(catch) = &*local.init.as_ref()?.expr else {
                return None;
            };
            if compact(&catch.func) != "std::panic::catch_unwind" || catch.args.len() != 1 {
                return None;
            }
            let syn::Expr::Call(safe) = &catch.args[0] else {
                return None;
            };
            if compact(&safe.func) != "std::panic::AssertUnwindSafe" || safe.args.len() != 1 {
                return None;
            }
            let syn::Expr::Closure(closure) = &safe.args[0] else {
                return None;
            };
            let syn::Expr::Block(block) = &*closure.body else {
                return None;
            };
            Some(block.block.clone())
        }
        if body.stmts.len() != 7 {
            return false;
        }
        let syn::Stmt::Local(store) = &body.stmts[2] else {
            return false;
        };
        let Some(syn::LocalInit { expr, .. }) = &store.init else {
            return false;
        };
        if !matches!(&**expr,syn::Expr::Match(m) if compact(&m.expr)=="self.state.lock()") {
            return false;
        }
        let Some(primary) = caught(&body.stmts[3], "requested") else {
            return false;
        };
        let pre: syn::Stmt = syn::parse_quote!(crate::oauth::native_management::check_protected_restore_reply(&scope)?;);
        let post: syn::Block = syn::parse_quote!({
            crate::oauth::native_management::check_protected_restore_reply(&scope)
        });
        if primary.stmts.len() != 2
            || compact(&primary.stmts[0]) != compact(pre)
            || caught(&body.stmts[4], "checked").map(compact) != Some(compact(post))
        {
            return false;
        }
        let refusal: syn::Stmt = syn::parse_quote!(if !matches!(&requested, Ok(Ok(_)))
            || !matches!(&checked, Ok(Ok(())))
        {
            store.refuse_reply(&scope, &command);
            crate::oauth::native_management::refuse_protected_restore_reply();
        });
        let result: syn::Stmt = syn::parse_quote!(match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(response)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(response)
                }
            },
        });
        if compact(&body.stmts[5]) != compact(refusal) || compact(&body.stmts[6]) != compact(result)
        {
            return false;
        }
        let syn::Stmt::Expr(syn::Expr::Match(routes), None) = &primary.stmts[1] else {
            return false;
        };
        fn variant(pat: &syn::Pat, path: &str) -> bool {
            matches!(pat,syn::Pat::Struct(p) if compact(&p.path)==path && p.fields.is_empty() && p.rest.is_some())
        }
        let mut terminal = 0;
        let mut entropy = 0;
        for arm in &routes.arms {
            let syn::Pat::Tuple(pair) = &arm.pat else {
                continue;
            };
            if pair.elems.len() != 2 {
                return false;
            }
            let syn::Pat::TupleStruct(payload) = &pair.elems[1] else {
                continue;
            };
            if payload.elems.len() != 1 {
                return false;
            }
            if variant(&pair.elems[0], "state::Step::Authenticate")
                && compact(&payload.path) == "ReceivedReply::Installed"
                && matches!(&payload.elems[0],syn::Pat::Ident(p) if p.ident=="data" && p.mutability.is_none() && p.subpat.is_none())
            {
                let syn::Expr::Block(block) = &*arm.body else {
                    return false;
                };
                let expected: syn::Stmt = syn::parse_quote!(store.authenticated(claim,&data)?;);
                if block.block.stmts.first().map(compact) != Some(compact(expected)) {
                    return false;
                }
                terminal += 1;
            }
            if variant(&pair.elems[0], "state::Step::Approve")
                && compact(&payload.path) == "ReceivedReply::Ordinary"
                && matches!(&payload.elems[0],syn::Pat::Struct(p) if compact(&p.path)=="Reply::ApprovalRecorded" && p.fields.len()==1 && p.rest.is_none()
                    && matches!(&p.fields[0].member,syn::Member::Named(n) if n=="commitment")
                    && matches!(&*p.fields[0].pat,syn::Pat::Ident(n) if n.ident=="commitment"))
            {
                let syn::Expr::Block(block) = &*arm.body else {
                    return false;
                };
                let expected: syn::Stmt = syn::parse_quote!(let handoff=effects::random()?;);
                if block.block.stmts.first().map(compact) != Some(compact(expected)) {
                    return false;
                }
                entropy += 1;
            }
        }
        terminal == 1 && entropy == 1
    }

    #[test]
    fn actual_reply_phase_guards_entropy_and_keeps_claim_visibility_until_independent_posts() {
        let source = include_str!("protected_restore_browser.rs");
        let actual = phase_body(source);
        assert!(phase_guarded(&actual));
        let mut missing = actual.clone();
        missing.stmts[3] = syn::parse_quote! {let requested=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Ok(unchecked_reply)));};
        assert!(!phase_guarded(&missing));
        let mut no_post = actual.clone();
        no_post.stmts[4] = syn::parse_quote!(let checked=Ok(Ok(())););
        assert!(!phase_guarded(&no_post));
        let mut late = actual.clone();
        late.stmts.swap(3, 4);
        assert!(!phase_guarded(&late));
        let mut visible = actual.clone();
        visible.stmts.insert(4, syn::parse_quote!(drop(store);));
        assert!(!phase_guarded(&visible));
        let mut recover = actual.clone();
        recover.stmts[5] = syn::parse_quote!(let _uncertainty_ignored=(););
        assert!(!phase_guarded(&recover));
        let mut conditional = actual.clone();
        let syn::Stmt::Local(local) = &conditional.stmts[4] else {
            panic!("actual post");
        };
        let observed = local.init.as_ref().unwrap().expr.clone();
        conditional.stmts[4] =
            syn::parse_quote!(let checked=if requested.is_ok(){#observed}else{Ok(Ok(()))};);
        assert!(!phase_guarded(&conditional));
        let mut no_terminal = actual;
        let syn::Stmt::Local(primary) = &mut no_terminal.stmts[3] else {
            panic!("primary local");
        };
        let syn::Expr::Call(catch) = &mut *primary.init.as_mut().unwrap().expr else {
            panic!("actual catch");
        };
        let syn::Expr::Call(safe) = &mut catch.args[0] else {
            panic!("actual safe");
        };
        let syn::Expr::Closure(closure) = &mut safe.args[0] else {
            panic!("actual closure");
        };
        let syn::Expr::Block(block) = &mut *closure.body else {
            panic!("actual body");
        };
        let syn::Stmt::Expr(syn::Expr::Match(routes), None) = &mut block.block.stmts[1] else {
            panic!("actual fixed routes");
        };
        let mut removed = 0;
        for arm in &mut routes.arms {
            if let syn::Expr::Block(block) = &mut *arm.body {
                let wanted: syn::Stmt = syn::parse_quote!(store.authenticated(claim,&data)?;);
                if block.block.stmts.first().is_some_and(|s| {
                    s.to_token_stream().to_string() == wanted.to_token_stream().to_string()
                }) {
                    block.block.stmts.remove(0);
                    removed += 1;
                }
            }
        }
        assert_eq!(removed, 1, "one actual terminal result check");
        assert!(!phase_guarded(&no_terminal));
    }

    #[test]
    fn actual_terminal_route_claims_before_native_and_checks_that_same_result_before_metadata() {
        #[derive(Default)]
        struct Terminal {
            bodies: Vec<syn::Block>,
        }
        impl<'a> Visit<'a> for Terminal {
            fn visit_arm(&mut self, arm: &'a syn::Arm) {
                if let syn::Pat::Tuple(pat) = &arm.pat
                    && let Some(syn::Pat::Ident(first)) = pat.elems.first()
                    && first.ident == "AUTHENTICATE"
                    && let syn::Expr::Block(block) = &*arm.body
                {
                    self.bodies.push(block.block.clone());
                }
                syn::visit::visit_arm(self, arm);
            }
        }
        let mut selected = Terminal::default();
        selected
            .visit_file(&syn::parse_file(include_str!("protected_restore_browser.rs")).unwrap());
        assert_eq!(selected.bodies.len(), 1);
        let actual = &selected.bodies[0];
        assert!(guarded(actual));
        let mut reordered = actual.clone();
        reordered.stmts.swap(1, 2);
        assert!(!guarded(&reordered));
        let mut unchecked = actual.clone();
        unchecked.stmts.remove(3);
        assert!(!guarded(&unchecked));
        let mut forged = actual.clone();
        forged.stmts[2] = syn::parse_quote!(let data=caller_output;);
        assert!(!guarded(&forged));
        let mut other = actual.clone();
        other.stmts[2] = syn::parse_quote!(let data=crate::oauth::native_management::protected_restore_authenticate(&other.scope,&claim.command.id,&bytes)?;);
        assert!(!guarded(&other));
        let mut other_result = actual.clone();
        other_result.stmts[3] = syn::Stmt::Expr(
            syn::parse_quote!(self.received_reply(
                shell,
                claim,
                ReceivedReply::Installed(Box::new(other)),
                identity
            )?),
            None,
        );
        assert!(!guarded(&other_result));
    }
}
