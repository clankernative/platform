//! Local browser key generation/export only. No registration/approval write,
//! signed record, key source, registry update or administrator admission.
use crate::iap;
use anyhow::{Result, ensure};
use axum::{
    http::{Method, header},
    response::{IntoResponse, Response},
};
use maud::{DOCTYPE, html};

pub(super) const PAGE: &str = "/restore/passkeys/export";
pub(super) const SCRIPT: &str = "/restore/passkeys/export.js";
#[derive(Clone)]
struct ExportDocument(String);

pub(super) fn dispatch(
    method: &Method,
    path: &str,
    query: Option<&str>,
    body: &[u8],
    identity: &iap::Verified,
    origin: &str,
) -> Result<Option<Response>> {
    if !matches!(path, PAGE | SCRIPT) {
        return Ok(None);
    }
    ensure!(
        *method == Method::GET && query.is_none() && body.is_empty(),
        "passkey_export_request_refused"
    );
    if path == SCRIPT {
        return Ok(Some(
            (
                [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                include_bytes!("../../../../../assets/restore-passkey-export.js").as_slice(),
            )
                .into_response(),
        ));
    }
    ensure!(
        (3..=256).contains(&identity.email.len())
            && (1..=1024).contains(&identity.subject.len())
            && !identity
                .email
                .chars()
                .chain(identity.subject.chars())
                .any(char::is_control),
        "passkey_export_identity_bound"
    );
    let page = html! {(DOCTYPE) html {head {meta charset="utf-8";title{"Create a restore passkey"} script type="module" src=(SCRIPT) {}} body {
        main id="restore-passkey-export" data-origin=(origin) data-email=(&identity.email) data-subject=(&identity.subject) {
            h1{"Create a restore passkey"}
            p{"Create a passkey on your authenticator, then submit its public record in a reviewed instance configuration change."}
            p{"This page does not enroll a key or grant restore access. Reviewers must check the administrator binding in the current policy."}
            p{"Account: " (&identity.email)}
            button id="create-passkey" type="button" {"Create passkey"}
            p id="passkey-status" role="status" aria-live="polite" {"No key has been created."}
            label for="public-key-record" {"Public record for review"}
            textarea id="public-key-record" readonly rows="18" cols="80" {}
            p{"Copy only this public record into the reviewed configuration. Keep the passkey on your authenticator."}
        }
    }}};
    let mut response = (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        page.into_string(),
    )
        .into_response();
    response
        .extensions_mut()
        .insert(ExportDocument(origin.to_owned()));
    Ok(Some(response))
}

/// Only the actual private page factory can attach this response-local marker.
/// Existing shell pages retain their original CSP and form boundaries.
pub(super) fn protect_document(response: &mut Response) {
    if let Some(ExportDocument(origin)) = response.extensions_mut().remove::<ExportDocument>() {
        response.headers_mut().insert(header::CONTENT_SECURITY_POLICY,format!("default-src 'none'; script-src {origin}{SCRIPT}; script-src-attr 'none'; connect-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; worker-src 'none'").parse().expect("admitted shell origin"));
        response.headers_mut().insert("permissions-policy","publickey-credentials-create=(self), publickey-credentials-get=(), camera=(), microphone=(), geolocation=()".parse().expect("static permissions policy"));
    }
}
