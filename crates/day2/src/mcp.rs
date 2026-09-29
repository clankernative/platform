//! Stateless JSON responses over MCP Streamable HTTP, backed by the shared API catalog.
use crate::{
    operation_catalog::Endpoint,
    store::Fault,
    web_api::{self, RequestContext, single_header},
    web_security as security,
};
use anyhow::{Context, Result, ensure};
use axum::{
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

pub const PATH: &str = "/mcp";
pub const VERSION: &str = "2026-07-28";
pub const LEGACY_VERSION: &str = "2025-11-25";
const SUPPORTED: &[&str] = &[VERSION, LEGACY_VERSION, "2025-06-18"];
const INSTRUCTIONS: &str = "Tools are generated from this app's admitted operation catalog. Pass the declared fields in input. Commands also require a caller-generated idempotency_key: preserve it and the input after an uncertain response; use a new key for a new intent. Results are wrapped in result. Examples are illustrative, not existing records. Calls use the signed-in actor and current app policy. Requested commands may still be running after their parent command returns.";

pub fn tool(endpoint: &Endpoint) -> Value {
    let read = endpoint.operation.kind == "query";
    let mut input = json!({"type":"object","properties":{"input":endpoint.input_schema},"required":["input"],"additionalProperties":false});
    let mut example = json!({"input":endpoint.request_example});
    if !read {
        input["properties"]["idempotency_key"] = json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$",
            "description":"Caller-generated key scoped to this actor and app. Preserve this key and input on retry after an uncertain response; use a new key for a new intent. Reuse with different input or another operation conflicts."});
        input["required"]
            .as_array_mut()
            .expect("required array")
            .push(json!("idempotency_key"));
        example["idempotency_key"] = json!("CHOOSE_A_NEW_KEY");
    }
    input["examples"] = json!([example]);
    let output = json!({"type":"object","properties":{"result":endpoint.output_schema},"required":["result"],"additionalProperties":false,
        "examples":[{"result":endpoint.response_example}]});
    json!({"name":endpoint.operation.name,"title":endpoint.summary,"description":endpoint.description,
        "inputSchema":input,"outputSchema":output,
        // Commands conservatively retain the destructive hint. Exact retries
        // include the required key and are protected by the durable receipt.
        "annotations":{"readOnlyHint":read,"destructiveHint":!read,"idempotentHint":true,"openWorldHint":false},
        "_meta":{"io.day2/operationContract":endpoint.metadata,"io.day2/deprecated":endpoint.deprecated,
            "io.day2/responseExampleSource":endpoint.response_example_source}})
}

fn rpc_error(status: StatusCode, id: &Value, code: i64, message: &str) -> Response {
    rpc_failure(status, id, json!({"code":code,"message":message}))
}

fn rpc_failure(status: StatusCode, id: &Value, error: Value) -> Response {
    let mut response = json!({"jsonrpc":"2.0","error":error});
    // MCP error envelopes omit an unavailable ID; null is not a RequestId.
    if !id.is_null() {
        response["id"] = id.clone();
    }
    web_api::json_response(status, response)
}

fn unsupported(id: &Value, requested: &str) -> Response {
    rpc_failure(
        StatusCode::BAD_REQUEST,
        id,
        json!({"code":-32022,"message":"Unsupported protocol version","data":{"supported":SUPPORTED,"requested":requested}}),
    )
}

fn tool_error(code: &str, message: &str) -> Value {
    json!({"isError":true,"content":[{"type":"text","text":json!({"error":{"code":code,"message":message}}).to_string()}]})
}

fn allowed(params: &Value, names: &[&str]) -> bool {
    params.as_object().is_some_and(|fields| {
        fields
            .keys()
            .all(|key| key == "_meta" || names.contains(&key.as_str()))
    })
}

fn accepts(headers: &HeaderMap, kind: &str) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|value| {
            let mut parts = value.split(';').map(str::trim);
            parts
                .next()
                .is_some_and(|value| value.eq_ignore_ascii_case(kind))
                && parts.all(|part| {
                    let Some((name, value)) = part.split_once('=') else {
                        return false;
                    };
                    !name.trim().eq_ignore_ascii_case("q")
                        || value
                            .trim()
                            .parse::<f32>()
                            .is_ok_and(|q| q > 0.0 && q <= 1.0)
                })
        })
}

pub(crate) fn dispatch(
    context: &RequestContext<'_>,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response> {
    ensure!(uri.query().is_none(), crate::error::Failure::InvalidInput);
    if headers.contains_key(header::ORIGIN) {
        ensure!(
            single_header(headers, "origin") == Some(context.origin),
            crate::error::Failure::InvalidOrigin
        );
    }
    ensure!(
        headers
            .get("sec-fetch-site")
            .is_none_or(|value| value == "same-origin" || value == "none"),
        crate::error::Failure::InvalidOrigin
    );
    if method != Method::POST {
        return Ok((StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "POST")]).into_response());
    }
    ensure!(
        single_header(headers, "content-type").is_some_and(|value| value
            .split(';')
            .next()
            .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))),
        crate::error::Failure::UnsupportedContentType
    );
    if !accepts(headers, "application/json") || !accepts(headers, "text/event-stream") {
        return Ok(rpc_error(
            StatusCode::NOT_ACCEPTABLE,
            &Value::Null,
            -32600,
            "Accept must include application/json and text/event-stream.",
        ));
    }
    let raw: Value = match crate::json::decode(body) {
        Ok(raw) => raw,
        Err(_) => {
            return Ok(rpc_error(
                StatusCode::BAD_REQUEST,
                &Value::Null,
                -32700,
                "Invalid JSON or duplicate fields.",
            ));
        }
    };
    let id = raw.get("id").cloned().unwrap_or(Value::Null);
    let valid_id = raw.get("id").is_none_or(|id| {
        id.as_str().is_some_and(|id| id.len() <= 128) || id.is_i64() || id.is_u64()
    });
    if !raw.as_object().is_some_and(|fields| {
        fields
            .keys()
            .all(|key| ["jsonrpc", "id", "method", "params"].contains(&key.as_str()))
    }) || raw["jsonrpc"] != "2.0"
        || !raw["method"].is_string()
        || !valid_id
    {
        return Ok(rpc_error(
            StatusCode::BAD_REQUEST,
            &Value::Null,
            -32600,
            "Expected one JSON-RPC request or notification.",
        ));
    }
    let method = raw["method"].as_str().expect("checked method");
    let params = raw.get("params").cloned().unwrap_or_else(|| json!({}));
    if !params.is_object() || params.get("_meta").is_some_and(|meta| !meta.is_object()) {
        return Ok(rpc_error(
            StatusCode::BAD_REQUEST,
            &id,
            -32602,
            "Parameters must be an object.",
        ));
    }
    let header_version = single_header(headers, "mcp-protocol-version");
    let body_version = params["_meta"]["io.modelcontextprotocol/protocolVersion"].as_str();
    let modern = header_version == Some(VERSION) || body_version.is_some();
    if modern {
        let Some(version) = body_version else {
            return Ok(rpc_error(
                StatusCode::BAD_REQUEST,
                &id,
                -32602,
                "Request metadata must include protocolVersion and clientCapabilities.",
            ));
        };
        if !params["_meta"]["io.modelcontextprotocol/clientCapabilities"].is_object() {
            return Ok(rpc_error(
                StatusCode::BAD_REQUEST,
                &id,
                -32602,
                "Request metadata must include clientCapabilities.",
            ));
        }
        if header_version != Some(version)
            || single_header(headers, "mcp-method") != Some(method)
            || (method == "tools/call" && !name_matches(headers, &params["name"]))
        {
            return Ok(rpc_error(
                StatusCode::BAD_REQUEST,
                &id,
                -32020,
                "MCP headers must match the request body.",
            ));
        }
        if version != VERSION {
            return Ok(unsupported(&id, version));
        }
    } else if method != "initialize"
        && !header_version.is_some_and(|version| SUPPORTED.contains(&version))
    {
        return Ok(unsupported(&id, header_version.unwrap_or("missing")));
    } else if headers.contains_key("mcp-protocol-version")
        && !header_version.is_some_and(|version| SUPPORTED.contains(&version))
    {
        return Ok(unsupported(&id, header_version.unwrap_or("invalid")));
    }
    if raw.get("id").is_none() {
        if !method.starts_with("notifications/") {
            return Ok(rpc_error(
                StatusCode::BAD_REQUEST,
                &Value::Null,
                -32600,
                "Requests require an id.",
            ));
        }
        // Notifications never dispatch application operations. No stateful MCP
        // session or server-initiated stream is advertised.
        return Ok(StatusCode::ACCEPTED.into_response());
    }
    let invalid = || {
        rpc_error(
            StatusCode::BAD_REQUEST,
            &id,
            -32602,
            "Invalid method parameters.",
        )
    };
    let info = json!({"name":context.runtime.app(),"version":context.runtime.artifact().id()});
    let mut result = match method {
        "initialize" if !modern => {
            if !allowed(&params, &["protocolVersion", "capabilities", "clientInfo"])
                || !params["protocolVersion"].is_string()
                || !params["capabilities"].is_object()
                || !params["clientInfo"]["name"].is_string()
                || !params["clientInfo"]["version"].is_string()
            {
                return Ok(invalid());
            }
            let version = if params["protocolVersion"] == "2025-06-18" {
                "2025-06-18"
            } else {
                LEGACY_VERSION
            };
            json!({"protocolVersion":version,"capabilities":{"tools":{"listChanged":false}},"serverInfo":info,"instructions":INSTRUCTIONS})
        }
        "server/discover" if modern => {
            if !allowed(&params, &[]) {
                return Ok(invalid());
            }
            json!({"supportedVersions":SUPPORTED,"capabilities":{"tools":{}},"instructions":INSTRUCTIONS})
        }
        "ping" => {
            if !allowed(&params, &[]) {
                return Ok(invalid());
            }
            json!({})
        }
        "tools/list" => {
            if !allowed(&params, &["cursor"]) || params.get("cursor").is_some() {
                return Ok(invalid());
            }
            // The artifact has a bounded catalog. Return it in one page and
            // re-evaluate current actor authority on every discovery request.
            json!({"tools":context.catalog.endpoints.values().filter(|endpoint| context.runtime.authorize(&endpoint.operation.name, &context.session.actor).is_ok()).map(tool).collect::<Vec<_>>()})
        }
        "tools/call" => {
            if !allowed(&params, &["name", "arguments"])
                || !params["name"].is_string()
                || !params["arguments"].is_object()
            {
                return Ok(invalid());
            }
            let Some(endpoint) = context
                .catalog
                .endpoints
                .get(params["name"].as_str().expect("tool name"))
            else {
                return Ok(rpc_error(
                    StatusCode::BAD_REQUEST,
                    &id,
                    -32602,
                    "Unknown public tool.",
                ));
            };
            context
                .runtime
                .authorize(&endpoint.operation.name, &context.session.actor)?;
            if endpoint.operation.kind == "command" {
                ensure!(
                    single_header(headers, "origin") == Some(context.origin),
                    crate::error::Failure::InvalidOrigin
                );
                security::verify_csrf(
                    context.secret,
                    context.session,
                    single_header(headers, "x-csrf-token")
                        .context(crate::error::Failure::InvalidCsrf)?,
                )
                .context(crate::error::Failure::InvalidCsrf)?;
            }
            call(context, endpoint, &params["arguments"])
        }
        _ => {
            return Ok(rpc_error(
                if modern {
                    StatusCode::NOT_FOUND
                } else {
                    StatusCode::OK
                },
                &id,
                -32601,
                "Method not found.",
            ));
        }
    };
    if modern {
        result["resultType"] = json!("complete");
        result["_meta"]["io.modelcontextprotocol/serverInfo"] = info;
    }
    Ok(web_api::json_response(
        StatusCode::OK,
        json!({"jsonrpc":"2.0","id":id,"result":result}),
    ))
}

fn name_matches(headers: &HeaderMap, name: &Value) -> bool {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let Some(header) = single_header(headers, "mcp-name") else {
        return false;
    };
    let decoded = if let Some(encoded) = header
        .strip_prefix("=?base64?")
        .and_then(|value| value.strip_suffix("?="))
    {
        STANDARD
            .decode(encoded)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    } else {
        Some(header.into())
    };
    decoded.as_deref() == name.as_str() && name.is_string()
}

fn call(context: &RequestContext<'_>, endpoint: &Endpoint, arguments: &Value) -> Value {
    let read = endpoint.operation.kind == "query";
    let fields = arguments.as_object().expect("checked arguments");
    if fields
        .keys()
        .any(|key| key != "input" && (read || key != "idempotency_key"))
    {
        return tool_error(
            "invalid_input",
            "Pass only input and, for commands, idempotency_key.",
        );
    }
    let operation = &endpoint.operation;
    let input = &arguments["input"];
    if context.runtime.artifact().contract().schema.inputs[&operation.input_type]
        .validate_input(input)
        .is_err()
    {
        return tool_error(
            "invalid_input",
            "Input must match the declared schema, including all required fields.",
        );
    }
    let invocation = if read {
        security::random().map(|key| format!("mcp-query-{key}"))
    } else {
        arguments["idempotency_key"]
            .as_str()
            .context(crate::error::Failure::InvalidIdempotencyKey)
            .and_then(|key| {
                web_api::command_invocation(context.runtime, &context.session.actor, key)
            })
    };
    let invocation = match invocation {
        Ok(invocation) => invocation,
        Err(_) if !read => {
            return tool_error(
                "invalid_idempotency_key",
                "Commands require an idempotency_key of 1 to 128 ASCII letters, digits, underscores or hyphens.",
            );
        }
        Err(_) => {
            return tool_error(
                "internal_error",
                "The query could not be started. Retry the query.",
            );
        }
    };
    let outcome = context.runtime.invoke_verified(
        &operation.name,
        crate::store::RequestIdentity {
            actor: &context.session.actor,
            origin: context.session.origin.as_ref(),
        },
        &invocation,
        input,
        context.at,
        Fault::None,
    );
    let mut result = match outcome {
        Ok(outcome) if outcome.status == "success" => {
            let structured = json!({"result":outcome.result});
            json!({"isError":false,"structuredContent":structured,"content":[{"type":"text","text":structured.to_string()}]})
        }
        Ok(outcome) if outcome.status == "pending" => {
            json!({"content":[{"type":"text","text":"Command accepted; execution is continuing."}],"structuredContent":{"invocation_id":invocation,"status":"pending","status_url":format!("/api/invocations/{invocation}")},"isError":false})
        }
        Ok(outcome) => {
            let (_, code, message) = web_api::outcome_failure(context.runtime, &outcome.error);
            tool_error(&code, &message)
        }
        Err(error) => {
            let (_, code, message) = web_api::failure_details(&error);
            tool_error(&code, message)
        }
    };
    result["_meta"]["io.day2/invocation"] = json!(invocation);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weighted_accept_and_encoded_method_names_are_supported() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            "application/json;q=0.9, text/event-stream; q=1"
                .parse()
                .unwrap(),
        );
        assert!(accepts(&headers, "application/json"));
        assert!(accepts(&headers, "text/event-stream"));
        headers.insert(
            header::ACCEPT,
            "application/json;q=0, text/event-stream".parse().unwrap(),
        );
        assert!(!accepts(&headers, "application/json"));
        headers.insert("mcp-name", "=?base64?cmVwb3J0cy5saXN0?=".parse().unwrap());
        assert!(name_matches(&headers, &json!("reports.list")));
        assert!(!name_matches(&headers, &json!("reports.submit")));
        headers.append("mcp-name", "reports.list".parse().unwrap());
        assert!(!name_matches(&headers, &json!("reports.list")));
    }

    #[tokio::test]
    async fn error_envelopes_preserve_known_ids_and_omit_unavailable_ids() {
        for id in [Value::Null, json!(0), json!("request-1"), json!(u64::MAX)] {
            let response = rpc_error(StatusCode::BAD_REQUEST, &id, -32600, "Invalid request.");
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            let value: Value = serde_json::from_slice(&body).unwrap();
            if id.is_null() {
                assert!(value.get("id").is_none());
            } else {
                assert_eq!(value["id"], id);
            }
            assert_eq!(value["error"]["code"], -32600);
        }
    }
}
