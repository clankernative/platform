//! https://docs.slack.dev/reference/methods/chat.postMessage/
//! https://docs.slack.dev/reference/methods/conversations.history/

use super::{AdapterError, PreparedCall, ResponseProfile};
use crate::integrations::transport::{Method, WireRequest};
use day2_capabilities::{
    integrations::{LiveConnection, SlackChannel},
    resources::Action,
};
use serde::Deserialize;
use serde_json::{Value, json};

/// The endpoints this adapter talks to. Named here so the offline simulation
/// routes on the same constants the live path builds, and a changed endpoint
/// cannot leave the simulation answering an address the adapter no longer uses.
pub(super) const IDENTITY: &str = "https://slack.com/api/auth.test";
pub(super) const HISTORY: &str = "https://slack.com/api/conversations.history";
pub(super) const POST: &str = "https://slack.com/api/chat.postMessage";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadRequest {
    handle: String,
    limit: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PostRequest {
    handle: String,
    text: String,
}

pub(super) fn prepare(
    action: Action,
    connection: &LiveConnection,
    channel: &SlackChannel,
    input: &str,
) -> Result<PreparedCall, AdapterError> {
    let (request, response) = match action {
        Action::SlackRead => {
            let input: ReadRequest =
                serde_json::from_str(input).map_err(|_| AdapterError::InvalidRequest)?;
            if input.handle.is_empty() || !(1..=100).contains(&input.limit) {
                return Err(AdapterError::InvalidRequest);
            }
            let query = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("channel", &channel.channel_id)
                .append_pair("limit", &input.limit.to_string())
                .append_pair("include_all_metadata", "false")
                .finish();
            (
                WireRequest {
                    url: format!("{HISTORY}?{query}"),
                    body: vec![],
                    headers: vec![],
                    method: Method::Get,
                },
                ResponseProfile::SlackRead {
                    channel: channel.channel_id.clone(),
                    limit: input.limit,
                },
            )
        }
        Action::SlackPost => {
            let input: PostRequest =
                serde_json::from_str(input).map_err(|_| AdapterError::InvalidRequest)?;
            if input.handle.is_empty()
                || input.text.is_empty()
                || input.text.chars().count() > 4000
                || input
                    .text
                    .chars()
                    .any(|c| c.is_control() && c != '\n' && c != '\t')
            {
                return Err(AdapterError::InvalidRequest);
            }
            // Escape Slack's special entities to prevent <@user>, <!channel>,
            // custom links and other syntax from adding notification authority.
            let text = input
                .text
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            let body = json!({"channel":channel.channel_id,"text":text,"mrkdwn":false,
                "parse":"none","link_names":false,"unfurl_links":false,"unfurl_media":false});
            (
                WireRequest::json(POST, body.to_string().into_bytes()),
                ResponseProfile::SlackPost {
                    channel: channel.channel_id.clone(),
                },
            )
        }
        _ => return Err(AdapterError::InvalidProfile),
    };
    Ok(PreparedCall {
        connection: connection.clone(),
        request,
        response,
        response_limit: 0,
        reserved_monetary_microusd: Some(0),
    })
}

pub(super) fn known_rejection(json: &Value) -> bool {
    json.get("ok") == Some(&Value::Bool(false))
        && json
            .get("error")
            .and_then(Value::as_str)
            .is_some_and(|code| {
                matches!(
                    code,
                    "invalid_auth"
                        | "not_authed"
                        | "token_revoked"
                        | "token_expired"
                        | "missing_scope"
                        | "channel_not_found"
                        | "not_in_channel"
                        | "is_archived"
                        | "no_permission"
                        | "invalid_arguments"
                        | "msg_too_long"
                        | "no_text"
                        | "rate_limited"
                        | "ratelimited"
                )
            })
}

fn ok(json: &Value) -> Result<(), AdapterError> {
    if json.get("ok") == Some(&Value::Bool(true)) {
        Ok(())
    } else if known_rejection(json) {
        Err(AdapterError::ProviderDenied)
    } else {
        Err(AdapterError::ResponseInvalid)
    }
}

pub(super) fn post_response(json: &Value, channel: &str) -> Result<Value, AdapterError> {
    ok(json)?;
    if json.get("channel").and_then(Value::as_str) != Some(channel) {
        return Err(AdapterError::ResponseInvalid);
    }
    let ts = timestamp(json.get("ts"))?;
    Ok(json!({"channel":channel,"timestamp":ts,"status":"accepted"}))
}

pub(super) fn read_response(
    json: &Value,
    channel: &str,
    limit: u16,
) -> Result<Value, AdapterError> {
    ok(json)?;
    let messages = json
        .get("messages")
        .and_then(Value::as_array)
        .ok_or(AdapterError::ResponseInvalid)?;
    if messages.len() > usize::from(limit) {
        return Err(AdapterError::ResponseInvalid);
    }
    let mut projection = Vec::new();
    for message in messages {
        if message.get("type").and_then(Value::as_str) != Some("message") {
            return Err(AdapterError::ResponseInvalid);
        }
        let text = message
            .get("text")
            .and_then(Value::as_str)
            .ok_or(AdapterError::ResponseInvalid)?;
        let timestamp = timestamp(message.get("ts"))?;
        // No files, attachments, metadata, URLs, secondary fetches or rendered HTML.
        projection.push(json!({"text":text,"timestamp":timestamp}));
    }
    let has_more = json
        .get("has_more")
        .and_then(Value::as_bool)
        .ok_or(AdapterError::ResponseInvalid)?;
    Ok(json!({"channel":channel,"messages":projection,"has_more":has_more}))
}

fn timestamp(value: Option<&Value>) -> Result<&str, AdapterError> {
    value
        .and_then(Value::as_str)
        .filter(|value| {
            value.len() <= 32
                && value.split_once('.').is_some_and(|(seconds, decimal)| {
                    !seconds.is_empty()
                        && !decimal.is_empty()
                        && seconds
                            .bytes()
                            .chain(decimal.bytes())
                            .all(|b| b.is_ascii_digit())
                })
        })
        .ok_or(AdapterError::ResponseInvalid)
}
