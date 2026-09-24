//! https://developers.openai.com/api/reference/typescript/resources/responses/methods/create
//! Rates and model context are versioned operator inputs, not a pricing promise.

use super::{AdapterError, PreparedCall, ResponseProfile, transport::WireRequest};
use day2_capabilities::integrations::{LiveConnection, OpenAiText};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerateRequest {
    handle: String,
    text: String,
    max_output_tokens: u64,
}

pub(super) fn prepare(
    connection: &LiveConnection,
    profile: &OpenAiText,
    input: &str,
) -> Result<PreparedCall, AdapterError> {
    let LiveConnection::OpenAi {
        project_id,
        organization_id,
        ..
    } = connection
    else {
        return Err(AdapterError::InvalidProfile);
    };
    let input: GenerateRequest =
        serde_json::from_str(input).map_err(|_| AdapterError::InvalidRequest)?;
    if input.handle.is_empty()
        || input.text.is_empty()
        || input.text.len() as u64 > profile.max_input_bytes
        || !(16..=profile.max_output_tokens).contains(&input.max_output_tokens)
    {
        return Err(AdapterError::InvalidRequest);
    }
    let body = json!({"model":profile.model,"input":input.text,"max_output_tokens":input.max_output_tokens,
        "store":false,"background":false,"stream":false,"tools":[],"tool_choice":"none",
        "text":{"format":{"type":"text"}},"service_tier":"default","truncation":"disabled"});
    let mut request = WireRequest::json(
        "https://api.openai.com/v1/responses",
        body.to_string().into_bytes(),
    );
    request.headers.push(("openai-project", project_id.clone()));
    if let Some(organization) = organization_id {
        request
            .headers
            .push(("openai-organization", organization.clone()));
    }
    let reservation = profile
        .cost_microusd(profile.max_input_tokens, input.max_output_tokens)
        .map_err(|_| AdapterError::InvalidProfile)?;
    Ok(PreparedCall {
        connection: connection.clone(),
        request,
        response: ResponseProfile::OpenAi {
            profile: profile.clone(),
            output_limit: input.max_output_tokens,
        },
        response_limit: 0,
        reserved_monetary_microusd: Some(reservation),
    })
}

pub(super) fn response(
    json: &Value,
    profile: &OpenAiText,
    output_limit: u64,
) -> (Result<Value, AdapterError>, Option<u64>, bool) {
    // A changed model, service tier or hosted tool could carry a different
    // tariff. Token counts alone cannot settle that provider obligation.
    let price_identity = json.get("model").and_then(Value::as_str) == Some(&profile.model)
        && json.get("service_tier").and_then(Value::as_str) == Some("default")
        && json
            .get("tools")
            .and_then(Value::as_array)
            .is_some_and(|tools| tools.is_empty())
        && json
            .get("output")
            .and_then(Value::as_array)
            .is_some_and(|output| {
                output.iter().all(|item| {
                    matches!(
                        item.get("type").and_then(Value::as_str),
                        Some("message" | "reasoning")
                    )
                })
            });
    let usage = if price_identity {
        usage(json, profile)
    } else {
        Err(AdapterError::ResponseInvalid)
    };
    let cost = usage.as_ref().ok().map(|(_, _, cost)| *cost);
    let result = usage.and_then(|(input_tokens, output_tokens, _)| {
        if input_tokens > profile.max_input_tokens
            || output_tokens > output_limit
            || json.get("model").and_then(Value::as_str) != Some(&profile.model)
            || json.get("status").and_then(Value::as_str) != Some("completed")
            || json.get("store") != Some(&Value::Bool(false))
            || json
                .get("background")
                .is_some_and(|background| background != &Value::Bool(false))
            || json.get("service_tier").and_then(Value::as_str) != Some("default")
            || json
                .get("tools")
                .and_then(Value::as_array)
                .is_none_or(|tools| !tools.is_empty())
        {
            return Err(AdapterError::ResponseInvalid);
        }
        let output = json
            .get("output")
            .and_then(Value::as_array)
            .ok_or(AdapterError::ResponseInvalid)?;
        let mut text = String::new();
        for item in output {
            match item.get("type").and_then(Value::as_str) {
                Some("reasoning") => {
                    // Reasoning tokens are included in billed output usage; the
                    // reasoning payload is never interpreted or forwarded.
                }
                Some("message") => {
                    if item.get("role").and_then(Value::as_str) != Some("assistant")
                        || item.get("status").and_then(Value::as_str) != Some("completed")
                    {
                        return Err(AdapterError::ResponseInvalid);
                    }
                    let content = item
                        .get("content")
                        .and_then(Value::as_array)
                        .ok_or(AdapterError::ResponseInvalid)?;
                    for part in content {
                        match part.get("type").and_then(Value::as_str) {
                            Some("output_text") => text.push_str(
                                part.get("text")
                                    .and_then(Value::as_str)
                                    .ok_or(AdapterError::ResponseInvalid)?,
                            ),
                            Some("refusal") => return Err(AdapterError::ProviderDenied),
                            _ => return Err(AdapterError::ResponseInvalid),
                        }
                    }
                }
                _ => return Err(AdapterError::ResponseInvalid),
            }
        }
        if text.is_empty() {
            return Err(AdapterError::ResponseInvalid);
        }
        Ok(json!({"text":text,"input_tokens":input_tokens,"output_tokens":output_tokens}))
    });
    // Complete trustworthy usage settles charges even when content fails the
    // allowed output contract. Missing usage keeps the whole reservation held.
    let unknown = cost.is_none();
    (result, cost, unknown)
}

fn usage(json: &Value, profile: &OpenAiText) -> Result<(u64, u64, u64), AdapterError> {
    let usage = json.get("usage").ok_or(AdapterError::ResponseInvalid)?;
    let input = usage
        .get("input_tokens")
        .and_then(Value::as_u64)
        .ok_or(AdapterError::ResponseInvalid)?;
    let output = usage
        .get("output_tokens")
        .and_then(Value::as_u64)
        .ok_or(AdapterError::ResponseInvalid)?;
    let total = usage
        .get("total_tokens")
        .and_then(Value::as_u64)
        .ok_or(AdapterError::ResponseInvalid)?;
    if input.checked_add(output) != Some(total) {
        return Err(AdapterError::ResponseInvalid);
    }
    let cost = profile
        .cost_microusd(input, output)
        .map_err(|_| AdapterError::ResponseInvalid)?;
    Ok((input, output, cost))
}
