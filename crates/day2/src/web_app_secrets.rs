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
        let message = if status.is_server_error() {
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
        *method == Method::POST && uri.path() == app_secrets::PATH,
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
        value: Encoded,
    }
    let mut input: Input = crate::json::decode(body).map_err(|_| Failure::InvalidInput)?;
    let decoded = STANDARD.decode(&input.value.0);
    input.value.0.zeroize();
    let value = Zeroizing::new(decoded.map_err(|_| Failure::InvalidInput)?);
    let receipt = app_secrets::write(
        context.runtime,
        &context.session.actor,
        &Write {
            operation: input.operation,
            name: input.name,
            expected_authority: input.expected_authority,
            expected_version: input.expected_version,
            request_id: request_id.into(),
            value,
        },
        provider,
    )?;
    let status = match receipt.state {
        State::Stored => StatusCode::OK,
        State::Refused => StatusCode::CONFLICT,
        _ => StatusCode::ACCEPTED,
    };
    Ok(json_response(status, serde_json::to_value(receipt)?))
}
