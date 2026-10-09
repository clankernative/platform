use crate::{
    openapi,
    operation_catalog::Catalog,
    store::{ActingAs, Fault, Runtime},
    web_security::{self as security, Session},
};
use anyhow::{Context, Result, ensure};
use axum::{
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use maud::{Markup, html};
use serde_json::{Value, json};

pub(crate) const ACT_AS_HEADER: &str = "x-day2-act-as";

pub(crate) fn session_allowed(runtime: &Runtime, catalog: &Catalog, actor: &str) -> bool {
    catalog
        .endpoints
        .keys()
        .any(|operation| runtime.authorize(operation, actor).is_ok())
        || runtime.authorize_audit(actor).is_ok()
        || runtime.may_request_delegation(actor).unwrap_or(false)
}

pub(crate) fn is_json(path: &str) -> bool {
    path.starts_with(crate::managed_credentials::ingress::PREFIX)
        || path == "/api"
        || path.starts_with(openapi::API_PREFIX)
        || path == openapi::SPEC_PATH
        || path == crate::mcp::PATH
}
pub(crate) fn json_response(status: StatusCode, value: Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string_pretty(&value).expect("JSON value serialization"),
    )
        .into_response()
}
pub(crate) fn error(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(status, json!({"error":{"code":code,"message":message}}))
}
pub(crate) fn failure(cause: &anyhow::Error) -> Response {
    record_failure(cause);
    let (status, code, message) = failure_details(cause);
    let mut response = error(status, &code, message);
    if crate::error::classify(cause) == crate::error::Failure::CredentialRejected {
        response.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            axum::http::HeaderValue::from_static("Bearer"),
        );
    }
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("1"),
        );
    }
    response
}

pub(crate) fn record_failure(cause: &anyhow::Error) {
    if matches!(
        crate::error::classify(cause).category(),
        crate::error::Category::Internal
            | crate::error::Category::Timeout
            | crate::error::Category::Unavailable
    ) {
        eprintln!("http_execution_failed {}", crate::error::diagnostic(cause));
    }
}
pub(crate) fn failure_details(cause: &anyhow::Error) -> (StatusCode, String, &'static str) {
    typed_failure_details(crate::error::classify(cause))
}

fn typed_failure_details(failure: crate::error::Failure) -> (StatusCode, String, &'static str) {
    use crate::error::Category;
    if failure == crate::error::Failure::CredentialRejected {
        return (
            StatusCode::UNAUTHORIZED,
            failure.code().into(),
            "The credential is not valid for this request.",
        );
    }
    if failure == crate::error::Failure::ExternalAmbiguous {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            failure.code().into(),
            "The provider outcome is unknown. Check the invocation status before taking further action.",
        );
    }
    let (status, message) = match failure.category() {
        Category::NotFound => (StatusCode::NOT_FOUND, "The requested record was not found."),
        Category::Conflict => (
            StatusCode::CONFLICT,
            "Read current state before preparing a new edit with a new idempotency key.",
        ),
        Category::Authentication => (
            StatusCode::UNAUTHORIZED,
            "Sign in using the app's local sign-in link.",
        ),
        Category::Forbidden => (StatusCode::FORBIDDEN, "This request is not authorized."),
        Category::InvalidInput => (
            StatusCode::BAD_REQUEST,
            "The request contains invalid or unexpected fields.",
        ),
        Category::Method => (
            StatusCode::METHOD_NOT_ALLOWED,
            "HTTP method does not match the operation.",
        ),
        Category::ContentType => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Commands require application/json.",
        ),
        Category::Timeout => (
            StatusCode::GATEWAY_TIMEOUT,
            "Execution was interrupted. Check the invocation before retrying with the same idempotency key.",
        ),
        Category::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "The server is busy. Retry the same request; commands keep their idempotency key.",
        ),
        Category::Internal => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error".into(),
                "The operation could not be completed. Retry commands with the same idempotency key.",
            );
        }
    };
    (status, failure.code().into(), message)
}

pub(crate) fn outcome_failure(runtime: &Runtime, code: &str) -> (StatusCode, String, String) {
    if let Some(error) = runtime
        .artifact()
        .contract()
        .app_contract
        .as_ref()
        .and_then(|definition| definition.errors.get(code))
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            code.into(),
            format!("{} {}", error.description, error.recovery),
        );
    }
    let (status, code, message) = typed_failure_details(
        crate::error::Failure::from_code(code).unwrap_or(crate::error::Failure::Internal),
    );
    (status, code, message.into())
}

pub(crate) struct RequestContext<'a> {
    pub runtime: &'a Runtime,
    pub catalog: &'a Catalog,
    pub secret: &'a [u8],
    pub entropy: &'a dyn crate::host_inputs::Entropy,
    pub session: &'a Session,
    pub origin: &'a str,
    pub at: i64,
}
impl RequestContext<'_> {
    fn actor<'a>(&'a self, headers: &'a HeaderMap) -> Result<&'a str> {
        if !headers.contains_key(ACT_AS_HEADER) {
            return Ok(&self.session.actor);
        }
        let actor =
            single_header(headers, ACT_AS_HEADER).context(crate::error::Failure::InvalidInput)?;
        crate::authority::valid_actor(actor).context(crate::error::Failure::InvalidInput)?;
        // Selecting another principal is an explicit session-authenticated
        // action, even for a read. No forwarded identity header authenticates it.
        ensure!(
            single_header(headers, "origin") == Some(self.origin)
                && headers
                    .get("sec-fetch-site")
                    .is_none_or(|value| value == "same-origin"),
            crate::error::Failure::InvalidOrigin
        );
        security::verify_csrf(
            self.secret,
            self.session,
            single_header(headers, "x-csrf-token").context(crate::error::Failure::InvalidCsrf)?,
        )
        .context(crate::error::Failure::InvalidCsrf)?;
        Ok(actor)
    }

    pub fn dispatch(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Response> {
        let actor = self.actor(headers)?;
        if uri.path() == "/api/security-actions" {
            ensure!(
                *method == Method::POST
                    && uri.query().is_none()
                    && !headers.contains_key(ACT_AS_HEADER),
                crate::error::Failure::InvalidInput
            );
            ensure!(
                single_header(headers, "origin") == Some(self.origin)
                    && headers
                        .get("sec-fetch-site")
                        .is_none_or(|v| v == "same-origin"),
                crate::error::Failure::InvalidOrigin
            );
            ensure!(
                single_header(headers, "content-type").is_some_and(|value| value
                    .split(';')
                    .next()
                    .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))),
                crate::error::Failure::UnsupportedContentType
            );
            security::verify_csrf(
                self.secret,
                self.session,
                single_header(headers, "x-csrf-token")
                    .context(crate::error::Failure::InvalidCsrf)?,
            )?;
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Navigation {
                operation: String,
                payload: String,
                product_return: String,
            }
            let navigation: Navigation = crate::json::decode(body)?;
            let input: Value = crate::json::decode(navigation.payload.as_bytes())?;
            let invocation = command_invocation(
                self.runtime,
                actor,
                single_header(headers, "idempotency-key")
                    .context(crate::error::Failure::InvalidIdempotencyKey)?,
            )?;
            let confirmation_url = crate::managed_credentials::browser::start(
                self.runtime,
                &navigation.operation,
                actor,
                &invocation,
                &input,
                Some(&navigation.product_return),
                self.at,
            )?;
            return Ok(json_response(
                StatusCode::ACCEPTED,
                json!({"invocation_id":invocation,"status":"awaiting_confirmation","confirmation_url":confirmation_url}),
            ));
        }
        if let Some(id) = uri.path().strip_prefix("/api/invocations/") {
            ensure!(
                *method == Method::GET,
                crate::error::Failure::UnsupportedMethod
            );
            ensure!(
                uri.query().is_none() && body.is_empty(),
                crate::error::Failure::InvalidInput
            );
            let receipt = if actor == self.session.actor {
                crate::invocations::status(self.runtime, id, actor)?
            } else {
                crate::invocations::status_on_behalf_of(
                    self.runtime,
                    id,
                    actor,
                    &self.session.actor,
                )?
            };
            return Ok(json_response(
                StatusCode::OK,
                serde_json::to_value(receipt)?,
            ));
        }
        let Some(endpoint) = self
            .catalog
            .endpoints
            .values()
            .find(|endpoint| endpoint.path() == uri.path())
        else {
            return Ok(error(
                StatusCode::NOT_FOUND,
                "unknown_operation",
                "Operation not found.",
            ));
        };
        if method.as_str() != endpoint.method() {
            let mut response = error(
                StatusCode::METHOD_NOT_ALLOWED,
                "unsupported_method",
                "HTTP method does not match the operation.",
            );
            response
                .headers_mut()
                .insert(header::ALLOW, endpoint.method().parse()?);
            return Ok(response);
        }
        let operation = &endpoint.operation;
        let record = &self.runtime.artifact().contract().schema.inputs[&operation.input_type];
        let (input, invocation) = if method == Method::GET {
            ensure!(body.is_empty(), crate::error::Failure::InvalidInput);
            let input = openapi::query_input(record, uri.query().unwrap_or(""))
                .context(crate::error::Failure::InvalidInput)?;
            (
                input,
                format!("api-query-{}", security::random(self.entropy)?),
            )
        } else {
            ensure!(uri.query().is_none(), crate::error::Failure::InvalidInput);
            ensure!(
                single_header(headers, "origin") == Some(self.origin)
                    && headers
                        .get("sec-fetch-site")
                        .is_none_or(|v| v == "same-origin"),
                crate::error::Failure::InvalidOrigin
            );
            ensure!(
                single_header(headers, "content-type").is_some_and(|value| value
                    .split(';')
                    .next()
                    .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))),
                crate::error::Failure::UnsupportedContentType
            );
            security::verify_csrf(
                self.secret,
                self.session,
                single_header(headers, "x-csrf-token")
                    .context(crate::error::Failure::InvalidCsrf)?,
            )
            .context(crate::error::Failure::InvalidCsrf)?;
            let key = single_header(headers, "idempotency-key")
                .context(crate::error::Failure::InvalidIdempotencyKey)?;
            let input: Value =
                serde_json::from_slice(body).context(crate::error::Failure::InvalidInput)?;
            record
                .validate_input(&input)
                .context(crate::error::Failure::InvalidInput)?;
            let invocation = command_invocation(self.runtime, &self.session.actor, key)?;
            (input, invocation)
        };
        if crate::managed_credentials::issuance::access(self.runtime, &operation.name)?.interactive
        {
            ensure!(
                method == Method::POST
                    && actor == self.session.actor
                    && !headers.contains_key(ACT_AS_HEADER),
                crate::error::Failure::Forbidden
            );
            let confirmation_url = crate::managed_credentials::browser::start(
                self.runtime,
                &operation.name,
                actor,
                &invocation,
                &input,
                None,
                self.at,
            )?;
            return Ok(json_response(
                StatusCode::ACCEPTED,
                json!({"invocation_id":invocation,"status":"awaiting_confirmation","confirmation_url":confirmation_url}),
            ));
        }
        self.runtime.accept_on_behalf_of_verified(
            &operation.name,
            ActingAs {
                authenticated: &self.session.actor,
                actor,
                trigger: crate::audit::Trigger::Request,
            },
            &invocation,
            &input,
            self.at,
            self.session.origin.as_ref(),
        )?;
        let outcome = if method == Method::POST
            && single_header(headers, "prefer") == Some("respond-async")
        {
            crate::protocol::Outcome {
                status: "pending".into(),
                result: Value::Null,
                error: String::new(),
            }
        } else {
            self.runtime.execute(&invocation, Fault::None)?
        };
        let mut response = if outcome.status == "success" {
            json_response(StatusCode::OK, outcome.result)
        } else if outcome.status == "pending" {
            let location = format!("/api/invocations/{invocation}");
            let mut response = json_response(
                StatusCode::ACCEPTED,
                json!({"invocation_id":invocation,"status":"pending","status_url":location}),
            );
            response
                .headers_mut()
                .insert(header::LOCATION, location.parse()?);
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, "1".parse()?);
            response
        } else {
            let (status, code, message) = outcome_failure(self.runtime, &outcome.error);
            error(status, &code, &message)
        };
        response
            .headers_mut()
            .insert("x-day2-invocation", invocation.parse()?);
        Ok(response)
    }
}
pub(crate) fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    (headers.get_all(name).iter().count() == 1)
        .then(|| headers.get(name)?.to_str().ok())
        .flatten()
}

pub(crate) fn command_invocation(runtime: &Runtime, actor: &str, key: &str) -> Result<String> {
    ensure!(
        !key.is_empty()
            && key.len() <= 128
            && key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
        crate::error::Failure::InvalidIdempotencyKey
    );
    // Both API transports share actor/app receipts. Payload/operation changes
    // conflict even if the caller retries through a different transport.
    let identity = serde_json::to_vec(&(runtime.scope(), actor, key))?;
    Ok(format!(
        "api-command-{}",
        crate::digest(&identity).trim_start_matches("sha256:")
    ))
}

/// Render from the OpenAPI document itself. No app templates or scripts run here.
pub(crate) fn docs(spec: &Value, origin: &str, actor: Option<&str>) -> Result<Markup> {
    let paths = spec["paths"].as_object().context("OpenAPI paths")?;
    let title = spec["info"]["title"].as_str().context("OpenAPI title")?;
    Ok(html! {
        (maud::DOCTYPE) html lang="en" { head {
            meta charset="utf-8"; meta name="viewport" content="width=device-width, initial-scale=1";
            title { (title) " · API reference" }
            link rel="stylesheet" href="/assets/platform/api-docs.css";
            script src="/assets/platform/api-docs.js" defer {}
        } body data-preview=(if actor.is_none() { "true" } else { "false" }) {
            a.skip href="#reference" { "Skip to API reference" }
            aside.sidebar {
                a.wordmark href="/docs" { span.brandmark { "d2" } "Developer docs" }
                p.eyebrow { "WORKSPACE API" } h2 { (title) }
                label.search { span { "Find an operation" } input id="search" type="search" placeholder="Search operations…"; }
                nav aria-label="API reference" {
                    a href="#overview" { "Overview" }
                    @for group in ["query", "command", "platform"] {
                        div.operation-group {
                            p.nav-label { (group) }
                            @for (_, methods) in paths {
                                @for (method, operation) in methods.as_object().context("OpenAPI methods")? {
                                    @if operation["tags"][0] == group {
                                        a.operation-link href=(format!("#{}", operation["operationId"].as_str().unwrap_or_default())) {
                                            span class=(format!("verb {method}")) { (method.to_uppercase()) }
                                            (operation["summary"].as_str().unwrap_or_default())
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                div.sidebar-footer { a href="/openapi.json" { "Raw OpenAPI spec ↗" } @if actor.is_some() { a href="/" { "Open app ↗" } } }
            }
            main id="reference" {
                header.topbar { span { "API REFERENCE" } span.session { span.dot {} @if let Some(actor) = actor { "Signed in as " strong { (actor) } } @else { "Documentation preview" } } }
                section.overview id="overview" {
                    p.eyebrow { "GENERATED FROM YOUR APP CONTRACTS" }
                    h1 { "Build with " (title.trim_end_matches(" API")) "." }
                    p.lead { "Explore every query and command. Understand each field, inspect example responses, and copy a request in your language." }
                    @if actor.is_none() { p.hint { "Read-only documentation preview. Request execution is disabled." } }
                    div.overview-actions { a.button.primary href="/openapi.json" { "View OpenAPI 3.1.1 ↗" } code.origin { (origin) } }
                    div.facts {
                        div { h3 { "Read with GET" } p { "Pass each declared input as a query parameter. Results are JSON and are never cached." } }
                        div { h3 { "Write with POST" } p { "Send JSON with your session, CSRF token, and a stable idempotency key. Commands change live app data." } }
                        div { h3 { "Retry safely" } p { "Reuse the same key and input after an uncertain response. Choose a new key for a new command." } }
                    }
                    details.guide { summary { "Authentication, limits & error responses" }
                        p { "Live apps also expose an MCP server at " code { "/mcp" } ". It uses the same operation descriptions and schemas as this reference. Configure a Streamable HTTP client with the app session cookie; command calls also need Origin and X-CSRF-Token. Pass application arguments in input and a stable idempotency_key for commands. Tool results wrap the application response in result." }
                        p { "Use the app’s local sign-in link to establish its HttpOnly session cookie. The request console uses your current session. Other clients must retain that cookie, fetch /api/session for a CSRF token, and send X-CSRF-Token, Origin, and Idempotency-Key with commands." }
                        p { "All declared application input fields are required. Platform audit filters are optional. Reference IDs are prefixed strings; pagination cursors are opaque strings; signed and unsigned integers are JSON numbers. Preserve integer precision in your client. Requests are limited to 64 KiB and URLs to 8192 bytes." }
                        p { "Request samples use standard HTTP clients. Set DAY2_SESSION_COOKIE to the full session cookie (name=value). For commands, set DAY2_CSRF_TOKEN from GET /api/session and DAY2_IDEMPOTENCY_KEY to a new key for each command, preserving it on retries. Samples do not contain credentials." }
                        p { "Failures return an error object containing code and message. HTTP 400 indicates invalid input, 401/403 authentication or authorization, 409 a conflict, and 422 an application rejection. The raw spec includes all response codes." }
                        p { "These are local session-authenticated APIs. Internal commands and Datastar browser routes are excluded from this reference." }
                    }
                }
                p id="empty" role="status" hidden { "No matching operations." }
                @for (path, methods) in paths {
                    @for (method, operation) in methods.as_object().context("OpenAPI methods")? {
                        (operation_card(spec, path, method, operation)?)
                    }
                }
                footer { "Day2 platform · Generated from the admitted artifact · OpenAPI 3.1.1" }
            }
        } }
    })
}
fn operation_card(spec: &Value, path: &str, method: &str, operation: &Value) -> Result<Markup> {
    let id = operation["operationId"]
        .as_str()
        .context("OpenAPI operationId")?;
    let parameters = operation["parameters"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let input = operation["x-day2-input-schema"]
        .as_str()
        .and_then(|reference| spec.pointer(reference.trim_start_matches('#')));
    let schema = &operation["responses"]["200"]["content"]["application/json"]["schema"];
    let output = match schema.get("$ref").and_then(Value::as_str) {
        Some(reference) => spec
            .pointer(reference.trim_start_matches('#'))
            .context("OpenAPI response schema")?,
        None => {
            ensure!(schema.is_object(), "OpenAPI response schema");
            schema
        }
    };
    Ok(html! {
        article.operation id=(id) data-search=(format!("{method} {path} {id} {}", operation["summary"].as_str().unwrap_or(id))) {
            div.operation-heading { span class=(format!("verb {method}")) { (method.to_uppercase()) } code { (path) } }
            h2 { (operation["summary"].as_str().unwrap_or(id)) @if operation["deprecated"] == true { span.pill.deprecated { "Deprecated" } } }
            p.description { (operation["description"].as_str().unwrap_or_default()) }
            div.operation-actions { code.operation-id { (id) } button.copy-link type="button" data-anchor=(id) { "Copy link" } }
            div.operation-grid {
                div.contract {
                    @if !parameters.is_empty() {
                        h3.section-title { (if method == "get" { "Parameters" } else { "Request headers" }) }
                        @for parameter in &parameters {
                            @let schema = parameter.get("schema").unwrap_or(&parameter["content"]["application/json"]["schema"]);
                            @let example = parameter.get("example").unwrap_or(&parameter["content"]["application/json"]["example"]);
                            (field_row(parameter["name"].as_str().unwrap_or_default(), schema, parameter["required"] == true, parameter["description"].as_str(), example)?)
                        }
                    }
                    @if let Some(input) = input {
                        @if method == "post" { h3.section-title { "Request body" span.media-type { "application/json" } } (fields(input, &operation["requestBody"]["content"]["application/json"]["example"])?) }
                        details.raw-schema { summary { "View input JSON Schema" } pre { code { (serde_json::to_string_pretty(input)?) } } }
                    }
                    h3.section-title { "Response" span.pill.success { "200" } span.media-type { "application/json" } }
                    p.response-description { (operation["responses"]["200"]["description"].as_str().unwrap_or_default()) }
                    (fields(output, &operation["responses"]["200"]["content"]["application/json"]["example"])?)
                    details.raw-schema { summary { "View response JSON Schema" } pre { code { (serde_json::to_string_pretty(output)?) } } }
                    @if let Some(description) = operation["x-day2-execution-description"].as_str() { details.guide { summary { "Execution & retry behavior" } p { (description) } } }
                    @if let Some(models) = operation["x-day2-required-all-rows"].as_array().filter(|models| !models.is_empty()) {
                        details.guide { summary { "Required data visibility" }
                            p { "This operation requires read access to every row in the following models. The platform checks this prerequisite against the actor's effective permissions; the declaration does not grant access." }
                            ul { @for model in models { li { code { (model.as_str().unwrap_or_default()) } } } }
                        }
                    }
                    details.guide.errors { summary { "Error responses" }
                        @for (status, response) in operation["responses"].as_object().context("responses")? {
                            @if status != "200" { p { code { (status) } " " (response["description"].as_str().unwrap_or_default()) } }
                        }
                    }
                }
                div.request-panels {
                    section.code-panel {
                        div.panel-heading { strong { "Request example" } button.copy-code type="button" { "Copy" } }
                        div.code-tabs role="tablist" aria-label=(format!("{id} request language")) {
                            @for (index, sample) in operation["x-codeSamples"].as_array().context("code samples")?.iter().enumerate() {
                                button.code-tab type="button" role="tab" id=(format!("{id}-tab-{index}")) aria-controls=(format!("{id}-code-{index}")) aria-selected=(if index == 0 { "true" } else { "false" }) tabindex=(if index == 0 { "0" } else { "-1" }) data-language=(index) { (sample["label"].as_str().unwrap_or_default()) }
                            }
                        }
                        @for (index, sample) in operation["x-codeSamples"].as_array().context("code samples")?.iter().enumerate() {
                            pre.code-sample role="tabpanel" id=(format!("{id}-code-{index}")) aria-labelledby=(format!("{id}-tab-{index}")) hidden[index != 0] data-language=(index) tabindex="0" { code { (sample["source"].as_str().unwrap_or_default()) } }
                        }
                        p.sample-note { "Set " code { "DAY2_SESSION_COOKIE" } @if method == "post" { ", " code { "DAY2_CSRF_TOKEN" } " and " code { "DAY2_IDEMPOTENCY_KEY" } } ". See authentication above." }
                    }
                    section.response-panel {
                        div.panel-heading { strong { "Response example" } label { span.sr-only { "Response status" } select.response-select aria-label=(format!("{id} response status")) {
                            @for (status, _) in operation["responses"].as_object().context("responses")? { option value=(status) selected[status == "200"] { (status) } }
                        } } button.copy-code type="button" { "Copy" } }
                        @for (status, response) in operation["responses"].as_object().context("responses")? {
                            @let example = response.get("content").and_then(|content| content.get("application/json")).and_then(|json| json.get("example")).cloned().unwrap_or_else(|| serde_json::json!({"error":{"code":status,"message":response["description"]}}));
                            div.response-sample data-status=(status) hidden[status != "200"] {
                                p.sample-note { (response["description"].as_str().unwrap_or_default()) }
                                pre tabindex="0" { code.json-example { (serde_json::to_string_pretty(&example)?) } }
                            }
                        }
                        p.sample-note { (if operation["x-day2-response-example-source"] == "app-authored" { "App-authored example, validated against the response contract." } else { "Illustrative example generated from the schema. Actual values will differ." }) }
                    }
                    details.try-panel { summary { "Try this operation" } form.console data-method=(method.to_uppercase()) data-path=(path) {
                    h3 { "Try this operation" }
                    @if method == "get" {
                        @for parameter in parameters.iter().filter(|parameter| parameter["in"] == "query" || parameter["in"] == "path") {
                            @let name = parameter["name"].as_str().context("OpenAPI parameter")?;
                            @let schema = if parameter.get("schema").is_some() { &parameter["schema"] } else { &parameter["content"]["application/json"]["schema"] };
                            @let example = if parameter.get("content").is_some() { parameter["content"]["application/json"]["example"].to_string() } else { parameter["example"].as_str().map(str::to_string).unwrap_or_else(|| parameter["example"].to_string()) };
                            label { span { (name) " " small { (schema["type"].as_str().unwrap_or("JSON")) (if parameter["required"] == true { " · required" } else { " · optional" }) } }
                                input name=(name) value=(example) aria-label=(name) data-location=(parameter["in"].as_str().unwrap_or("query"));
                                @if let Some(description) = schema["description"].as_str() { small.hint { (description) } }
                            }
                        }
                        @if parameters.is_empty() { p.hint { "No input parameters." } }
                    } @else {
                        label { span { "JSON body" } textarea name="body" rows="8" spellcheck="false" aria-label="JSON body" { (serde_json::to_string_pretty(&operation["requestBody"]["content"]["application/json"]["example"])?) } }
                        label { span { "Idempotency key" } input name="idempotency" autocomplete="off" aria-label="Idempotency key"; }
                        button.new-key type="button" { "New command key" }
                        p.hint { "Running this command changes live app data." }
                    }
                    button.send.primary type="submit" disabled { (if method == "post" { "Run command" } else { "Send request" }) span { "↗" } }
                    noscript { p.hint { "Enable JavaScript to use the request console. Schemas remain available above." } }
                    div.result hidden { p.result-status role="status" {} pre { code {} } }
                    } }
                }
            }
        }
    })
}

fn type_label(schema: &Value) -> String {
    if let Some(types) = schema["type"].as_array() {
        return types
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" | ");
    }
    if let Some(variants) = schema["oneOf"].as_array() {
        return variants
            .iter()
            .map(type_label)
            .collect::<Vec<_>>()
            .join(" | ");
    }
    if let Some(value) = schema.get("const") {
        return value.to_string();
    }
    let kind = schema["type"].as_str().unwrap_or("value");
    if kind == "array" {
        return format!("{}[]", type_label(&schema["items"]));
    }
    if schema.get("enum").is_some() {
        return format!("enum<{kind}>");
    }
    schema["format"]
        .as_str()
        .map_or_else(|| kind.to_string(), |format| format!("{kind}<{format}>"))
}

fn fields(schema: &Value, example: &Value) -> Result<Markup> {
    if let Some(properties) = schema["properties"].as_object() {
        Ok(html! { div.field-list {
            @for (name, field) in properties {
                (field_row(name, field, schema["required"].as_array().is_some_and(|required| required.iter().any(|value| value == name)), None, &example[name])?)
            }
        } })
    } else {
        field_row("value", schema, true, None, example)
    }
}

fn field_row(
    name: &str,
    schema: &Value,
    required: bool,
    description: Option<&str>,
    example: &Value,
) -> Result<Markup> {
    let kind = type_label(schema);
    Ok(html! {
        div.field-row {
            div.field-heading { code { (name) } span.pill.field-type { (kind) } span class=(if required { "pill required" } else { "pill optional" }) { (if required { "Required" } else { "Optional" }) } }
            @if let Some(description) = description.or_else(|| schema["description"].as_str()) { p.field-description { (description) } }
            @if let Some(wire) = schema["x-day2-wire-description"].as_str() { p.field-constraint { (wire) } }
            div.constraints {
                @for (key, label) in [("minimum", "Min"), ("maximum", "Max"), ("minLength", "Min characters"), ("maxLength", "Max characters"), ("x-day2-max-utf8-bytes", "Max UTF-8 bytes"), ("maxItems", "Max items")] {
                    @if let Some(value) = schema.get(key) { span { (label) ": " code { (value) } } }
                }
                @if let Some(value) = schema.get("enum") { span { "Allowed: " code { (value) } } }
            }
            @if schema["type"] == "object" && schema["properties"].is_object() {
                details.nested-fields { summary { "Child fields" } (fields(schema, example)?) }
            } @else if schema["type"] == "array" {
                details.nested-fields { summary { "Item fields" } (fields(&schema["items"], &example[0])?) }
            } @else if let Some(variants) = schema["oneOf"].as_array() {
                p.field-constraint { "One of these representations is required; the field cannot be omitted." }
                @for variant in variants { @if variant["type"] == "object" { details.nested-fields { summary { (type_label(variant)) " fields" } (fields(variant, example)?) } } }
            } @else if !example.is_null() { p.field-example { "Example: " code { (example) } } }
        }
    })
}

#[cfg(test)]
mod failure_tests {
    use super::*;
    use crate::error::Failure;

    #[test]
    fn transport_classification_survives_context_and_retains_ambiguous_outcomes() {
        for (failure, status) in [
            (Failure::Forbidden, StatusCode::FORBIDDEN),
            (Failure::RequiredAllRowsUnavailable, StatusCode::FORBIDDEN),
            (Failure::Conflict, StatusCode::CONFLICT),
            (Failure::InvalidInput, StatusCode::BAD_REQUEST),
            (Failure::WorkerTimeout, StatusCode::GATEWAY_TIMEOUT),
        ] {
            let error = anyhow::Error::new(failure).context("outer request context");
            let details = failure_details(&error);
            assert_eq!(details, typed_failure_details(failure));
            assert_eq!(details.0, status);
            assert_eq!(details.1, failure.code());
        }
        assert_eq!(
            failure_details(&anyhow::anyhow!("forbidden")).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let details = typed_failure_details(Failure::ExternalAmbiguous);
        assert_eq!(details.1, "external_outcome_ambiguous");
        assert!(!details.2.contains("Retry"));
    }
}
