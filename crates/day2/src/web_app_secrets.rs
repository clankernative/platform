//! Session-authenticated management endpoints; no act-as or credential ingress.
use crate::{
    app_secrets::{self, Operation, State, Write},
    error::Failure,
    web_api::{RequestContext, json_response, single_header},
};
use anyhow::{Result, ensure};
use axum::{
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use zeroize::{Zeroize as _, Zeroizing};

pub(crate) fn dispatch(
    context: &RequestContext<'_>,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    provider: &dyn app_secrets::Provider,
) -> Result<Response> {
    dispatch_inner(context, method, uri, headers, body, provider).or_else(|cause| {
        let (status, code, message) = crate::web_api::failure_details(&cause);
        crate::web_api::record_failure(&cause);
        let message = if status.is_server_error() && uri.path() == crate::app_export::PATH {
            "The protected SQLite export was not prepared. Inspect current ownership before creating a new download request."
        } else if status.is_server_error() {
            "The secret outcome is uncertain. Inspect app secrets status with the original request ID; do not resubmit the value."
        } else { message };
        Ok(crate::web_api::error(status, &code, message))
    })
}

fn dispatch_inner(
    context: &RequestContext<'_>,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    provider: &dyn app_secrets::Provider,
) -> Result<Response> {
    ensure!(
        uri.query().is_none() && !headers.contains_key(crate::web_api::ACT_AS_HEADER),
        Failure::InvalidInput
    );
    if *method == Method::GET {
        ensure!(body.is_empty(), Failure::InvalidInput);
        if uri.path() == crate::app_export::PATH {
            return Ok(json_response(
                StatusCode::OK,
                serde_json::to_value(crate::app_export::metadata(
                    context.runtime,
                    &context.session.actor,
                )?)?,
            ));
        }
        if uri.path() == app_secrets::PATH {
            return Ok(json_response(
                StatusCode::OK,
                serde_json::to_value(app_secrets::list(context.runtime, &context.session.actor)?)?,
            ));
        }
        let request = uri
            .path()
            .strip_prefix("/api/app-secrets/requests/")
            .ok_or(Failure::NotFound)?;
        return Ok(json_response(
            StatusCode::OK,
            serde_json::to_value(app_secrets::status(
                context.runtime,
                &context.session.actor,
                request,
            )?)?,
        ));
    }
    ensure!(
        *method == Method::POST
            && [
                app_secrets::PATH,
                "/api/app-secrets/reveal",
                crate::app_export::PATH
            ]
            .contains(&uri.path()),
        Failure::UnsupportedMethod
    );
    ensure!(
        single_header(headers, "origin") == Some(context.origin)
            && headers
                .get("sec-fetch-site")
                .is_none_or(|value| value == "same-origin"),
        Failure::InvalidOrigin
    );
    ensure!(
        single_header(headers, "content-type") == Some("application/json"),
        Failure::UnsupportedContentType
    );
    crate::web_security::verify_csrf(
        context.secret,
        context.session,
        single_header(headers, "x-csrf-token").ok_or(Failure::InvalidCsrf)?,
    )
    .map_err(|_| Failure::InvalidCsrf)?;
    let request_id =
        single_header(headers, "idempotency-key").ok_or(Failure::InvalidIdempotencyKey)?;
    if uri.path() == "/api/app-secrets/reveal" {
        let mut input: app_secrets::Selection =
            crate::json::decode(body).map_err(|_| Failure::InvalidInput)?;
        input.request_id = request_id.into();
        let bytes = app_secrets::reveal(context.runtime, &context.session.actor, &input, provider)?;
        return binary(
            bytes,
            serde_json::json!({"protocol":1,"kind":"app-secret-value","scope":context.runtime.scope(),"actor":context.session.actor,"request_id":request_id,"authority":input.expected_authority,"name":input.name,"incarnation":input.incarnation,"version":input.version}),
        );
    }
    if uri.path() == crate::app_export::PATH {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input {
            expected_authority: crate::authority_state::AuthorityStamp,
        }
        let input: Input = crate::json::decode(body).map_err(|_| Failure::InvalidInput)?;
        let bytes = crate::app_export::download(
            context.runtime,
            &context.session.actor,
            &input.expected_authority,
            request_id,
        )?;
        return binary(
            bytes,
            serde_json::json!({"protocol":1,"kind":"app-sqlite","scope":context.runtime.scope(),"actor":context.session.actor,"request_id":request_id,"authority":input.expected_authority,"artifact":context.runtime.artifact().id()}),
        );
    }
    #[derive(Deserialize)]
    #[serde(transparent)]
    struct Encoded(String);
    impl Drop for Encoded {
        fn drop(&mut self) {
            self.0.zeroize();
        }
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        operation: Operation,
        name: String,
        expected_authority: crate::authority_state::AuthorityStamp,
        expected_version: Option<u64>,
        value: Option<Encoded>,
        expected_incarnation: Option<String>,
    }
    let mut input: Input = crate::json::decode(body).map_err(|_| Failure::InvalidInput)?;
    ensure!(
        input.operation != Operation::Reveal
            && ((input.operation == Operation::Delete) == input.value.is_none()),
        Failure::InvalidInput
    );
    let decoded = match &mut input.value {
        Some(value) => {
            let result = STANDARD.decode(&value.0);
            value.0.zeroize();
            result
        }
        None => Ok(Vec::new()),
    };
    let value = Zeroizing::new(decoded.map_err(|_| Failure::InvalidInput)?);
    let receipt = app_secrets::write(
        context.runtime,
        &context.session.actor,
        &Write {
            operation: input.operation,
            name: input.name,
            expected_authority: input.expected_authority,
            expected_version: input.expected_version,
            expected_incarnation: input.expected_incarnation,
            request_id: request_id.into(),
            value,
        },
        provider,
    )?;
    let status = match receipt.state {
        State::Stored | State::Deleted => StatusCode::OK,
        State::Refused => StatusCode::CONFLICT,
        _ => StatusCode::ACCEPTED,
    };
    Ok(json_response(status, serde_json::to_value(receipt)?))
}

fn binary(mut bytes: Zeroizing<Vec<u8>>, metadata: serde_json::Value) -> Result<Response> {
    let header = STANDARD.encode(serde_json::to_vec(&metadata)?);
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .header("x-content-type-options", "nosniff")
        .header("x-day2-result", header)
        .body(axum::body::Body::from(std::mem::take(&mut *bytes)))?)
}
