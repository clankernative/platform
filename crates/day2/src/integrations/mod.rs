//! Closed live adapters. Only already-authorized, pinned profiles enter here.
//! Provider wire data and credentials never become error strings or logs.

mod gitea_actions;
mod github_actions;
mod linear_work;
mod object_store;
mod openai;
pub mod simulated;
mod slack;
mod slack_webhook;
mod snowflake;
mod transport;

pub use transport::LocalSecret;
pub(crate) use transport::{
    Authorization, CredentialResolver, Credentials, HttpTransport, Method, Transport,
};
pub(crate) use transport::{TransportError, WireRequest, WireResponse};

use day2_capabilities::{
    integrations::LiveConnection,
    resources::{Action, ResourceTarget},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

pub(crate) const MAX_WIRE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdapterError {
    InvalidRequest,
    InvalidProfile,
    CredentialUnavailable,
    ProviderDenied,
    RateLimited,
    TransportUnavailable,
    ResponseInvalid,
    ResponseTooLarge,
    Incomplete,
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "integration_request_invalid",
            Self::InvalidProfile => "integration_profile_invalid",
            Self::CredentialUnavailable => "integration_credential_unavailable",
            Self::ProviderDenied => "integration_provider_denied",
            Self::RateLimited => "integration_rate_limited",
            Self::TransportUnavailable => "integration_transport_unavailable",
            Self::ResponseInvalid => "integration_response_invalid",
            Self::ResponseTooLarge => "integration_response_too_large",
            Self::Incomplete => "integration_outcome_incomplete",
        })
    }
}

impl std::error::Error for AdapterError {}

pub(crate) struct PreparedCall {
    connection: LiveConnection,
    request: transport::WireRequest,
    response: ResponseProfile,
    response_limit: u64,
    reserved_monetary_microusd: Option<u64>,
}

enum ResponseProfile {
    SlackWebhook {
        endpoint_sha256: String,
    },
    SlackRead {
        channel: String,
        limit: u16,
    },
    SlackPost {
        channel: String,
    },
    Snowflake {
        columns: Vec<String>,
        max_rows: u32,
    },
    OpenAi {
        profile: day2_capabilities::integrations::OpenAiText,
        output_limit: u64,
    },
    Gitea {
        action: Action,
        endpoint: String,
        owner: String,
        target: gitea_actions::Target,
        page: u64,
        limit: u64,
    },
    GitHubJob,
    /// Answered by a redirect rather than a body: the result is the signed URL.
    GitHubJobLog,
    LinearIssues,
    LinearIssueDetail,
    LinearAssignableUsers,
    LinearReassign,
    /// Existence and size. The answer is entirely in headers: a HEAD carries no
    /// body, so there is nothing to parse and nothing to bound.
    ObjectHead,
    /// Reclaiming storage. S3 deletes are idempotent — a key that was never there
    /// reports the same 204 as one that was — so absence is success, not a
    /// failure to report to an application.
    ObjectDelete,
}

impl PreparedCall {
    pub(crate) fn connection(&self) -> &LiveConnection {
        &self.connection
    }

    pub(crate) fn reserved_monetary_microusd(&self) -> Option<u64> {
        self.reserved_monetary_microusd
    }

    pub(crate) fn request_bytes(&self) -> u64 {
        self.request.payload_bytes()
            + if matches!(self.connection, LiveConnection::Slack { .. }) {
                2
            } else {
                0
            }
    }

    pub(crate) fn response_limit(&self) -> u64 {
        self.response_limit
    }

    pub(crate) fn max_calls(&self) -> u64 {
        if matches!(self.connection, LiveConnection::Slack { .. }) {
            2
        } else {
            1
        }
    }
}

pub(crate) struct AdapterOutcome {
    pub(crate) result: Result<String, AdapterError>,
    pub(crate) request_bytes: u64,
    pub(crate) response_bytes: u64,
    /// None is an unsupported monetary metric or unmeasurable outcome; inspect
    /// outcome_unknown separately. Snowflake warehouse invoices are unmetered.
    pub(crate) monetary_microusd: Option<u64>,
    pub(crate) dispatched: bool,
    pub(crate) calls: u64,
    pub(crate) outcome_unknown: bool,
    pub(crate) correlation: Vec<ExchangeCorrelation>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExchangePhase {
    IdentityCheck,
    Operation,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExchangeCorrelation {
    pub(crate) phase: ExchangePhase,
    pub(crate) http_status: Option<u16>,
    pub(crate) request_id: Option<String>,
    pub(crate) statement_handle: Option<String>,
}

fn correlation_identifier(value: &str) -> Option<String> {
    (!value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.:".contains(&byte)))
    .then(|| value.to_owned())
}

fn statement_uuid(value: &str) -> Option<String> {
    (value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        }))
    .then(|| value.to_owned())
}

pub(crate) fn prepare(
    action: &Action,
    connection: &LiveConnection,
    target: &ResourceTarget,
    request_json: &str,
    max_request_bytes: u64,
    max_response_bytes: u64,
) -> Result<PreparedCall, AdapterError> {
    connection
        .validate()
        .map_err(|_| AdapterError::InvalidProfile)?;
    target
        .validate()
        .map_err(|_| AdapterError::InvalidProfile)?;
    if request_json.len() as u64 > max_request_bytes.min(MAX_WIRE_BYTES)
        || max_response_bytes == 0
        || max_request_bytes == 0
    {
        return Err(AdapterError::InvalidRequest);
    }
    let mut call = match (action, connection, target) {
        (
            Action::SlackWebhookPost,
            LiveConnection::SlackWebhook { .. },
            ResourceTarget::SlackWebhookDestination { endpoint_sha256 },
        ) => slack_webhook::prepare(connection, endpoint_sha256, request_json)?,
        (
            Action::SlackRead | Action::SlackPost,
            LiveConnection::Slack { .. },
            ResourceTarget::SlackChannel { channel },
        ) => slack::prepare(*action, connection, channel, request_json)?,
        (
            Action::SnowflakeRead,
            LiveConnection::Snowflake { .. },
            ResourceTarget::SnowflakeView { query },
        ) => snowflake::prepare(connection, query, request_json)?,
        (
            Action::OpenAiGenerate,
            LiveConnection::OpenAi { .. },
            ResourceTarget::OpenAiText { profile },
        ) => openai::prepare(connection, profile, request_json)?,
        (
            Action::GiteaRuns
            | Action::GiteaRun
            | Action::GiteaRunJobs
            | Action::GiteaJob
            | Action::GiteaJobLog
            | Action::GiteaRunners,
            LiveConnection::GiteaActions { .. },
            ResourceTarget::GiteaOrganization { owner },
        ) => gitea_actions::prepare(*action, connection, owner, request_json)?,
        (
            Action::GitHubJob | Action::GitHubJobLog,
            LiveConnection::GitHubActions { .. },
            ResourceTarget::GitHubRepository { owner, repo },
        ) => github_actions::prepare(*action, connection, owner, repo, request_json)?,
        (
            Action::LinearWorkIssues
            | Action::LinearWorkIssueDetail
            | Action::LinearWorkAssignableUsers
            | Action::LinearWorkReassign,
            LiveConnection::LinearWork { .. },
            ResourceTarget::LinearIssueSource { source },
        ) => linear_work::prepare(*action, connection, source, request_json)?,

        _ => return Err(AdapterError::InvalidProfile),
    };
    call.response_limit = max_response_bytes.min(MAX_WIRE_BYTES);
    if call.request_bytes() > max_request_bytes.min(MAX_WIRE_BYTES) {
        return Err(AdapterError::InvalidRequest);
    }
    Ok(call)
}

pub(crate) fn execute(
    call: &PreparedCall,
    resolver: &dyn CredentialResolver,
    transport: &dyn Transport,
    attempt: &str,
) -> AdapterOutcome {
    let known_cost = if matches!(call.connection, LiveConnection::Snowflake { .. }) {
        None
    } else {
        Some(0)
    };
    let mut outcome = AdapterOutcome {
        result: Err(AdapterError::CredentialUnavailable),
        request_bytes: 0,
        response_bytes: 0,
        monetary_microusd: known_cost,
        dispatched: false,
        calls: 0,
        outcome_unknown: false,
        correlation: vec![],
    };
    if attempt.is_empty()
        || attempt.len() > 256
        || !attempt
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        outcome.result = Err(AdapterError::InvalidRequest);
        return outcome;
    }
    // An object store authorizes in the URL, so there is no bearer credential to
    // resolve — and resolving one would read the secret access key and put it in an
    // Authorization header, handing the store the key to the whole bucket. The
    // credential is not fetched at all on this path rather than fetched and left
    // unused.
    let presigned = matches!(call.connection, LiveConnection::ObjectStore { .. });
    let credentials = if presigned {
        None
    } else {
        let Ok(credentials) = resolver.resolve(call.connection()) else {
            return outcome;
        };
        Some(credentials)
    };
    let webhook = matches!(call.connection, LiveConnection::SlackWebhook { .. });
    let authorization = match &credentials {
        Some(_) if webhook => Authorization::Webhook,
        Some(credentials) => Authorization::Bearer(credentials),
        None => Authorization::Presigned,
    };
    // Verify Slack workspace identity before transmitting app content. auth.test
    // returns no channel content and is bounded by the same response-byte limit.
    if let LiveConnection::Slack { workspace_id, .. } = &call.connection {
        let identity = transport::WireRequest::json(slack::IDENTITY, b"{}".to_vec());
        let response = transmit(
            &identity,
            call,
            authorization,
            transport,
            &mut outcome,
            ExchangePhase::IdentityCheck,
        );
        let Some(response) = response else {
            outcome.outcome_unknown = true;
            return outcome;
        };
        let identity_ok = parse_http_json(&response).and_then(|json| {
            if json.get("ok") == Some(&Value::Bool(true))
                && json.get("team_id").and_then(Value::as_str) == Some(workspace_id)
            {
                Ok(())
            } else {
                Err(AdapterError::ProviderDenied)
            }
        });
        if let Err(error) = identity_ok {
            outcome.result = Err(error);
            return outcome;
        }
    }
    // Once this point is reached, POST outcomes may include an accepted effect
    // or charge even if the HTTP response is lost. No adapter retries a request.
    let mut request = call.request.clone();
    if let ResponseProfile::SlackWebhook { endpoint_sha256 } = &call.response {
        let Some(credential) = &credentials else {
            return outcome;
        };
        let Ok(url) = credential.slack_webhook_url(endpoint_sha256) else {
            return outcome;
        };
        request.url = url.to_owned();
    }
    if matches!(call.connection, LiveConnection::OpenAi { .. }) {
        // Diagnostic correlation only; the API does not promise deduplication.
        request
            .headers
            .push(("x-client-request-id", attempt.into()));
    }
    let Some(response) = transmit(
        &request,
        call,
        authorization,
        transport,
        &mut outcome,
        ExchangePhase::Operation,
    ) else {
        outcome.outcome_unknown = true;
        outcome.monetary_microusd = None;
        return outcome;
    };
    // An object store answers in a status line and a few headers. Nothing here is
    // JSON — a HEAD has no body at all, and an S3 error body is XML — so the JSON
    // path would reject every successful response as ResponseInvalid.
    // The log location is a redirect, so there is no body to parse and the
    // JSON path would reject a perfectly good answer.
    if matches!(call.response, ResponseProfile::GitHubJobLog) {
        let (result, unknown) = github_actions::log_response(&response);
        outcome.result = result;
        outcome.monetary_microusd = Some(0);
        outcome.outcome_unknown = unknown;
        return outcome;
    }
    if matches!(
        call.response,
        ResponseProfile::ObjectHead | ResponseProfile::ObjectDelete
    ) {
        let (result, unknown) = object_store::response(&call.response, &response);
        outcome.result = result;
        outcome.monetary_microusd = Some(0);
        outcome.outcome_unknown = unknown;
        return outcome;
    }
    if matches!(
        call.response,
        ResponseProfile::Gitea {
            action: Action::GiteaJobLog,
            ..
        }
    ) {
        outcome.result = gitea_actions::log_response(&response).map(|value| value.to_string());
        outcome.monetary_microusd = Some(0);
        outcome.outcome_unknown = false;
        return outcome;
    }
    if matches!(call.response, ResponseProfile::SlackWebhook { .. }) {
        let (result, unknown) = slack_webhook::response(&response);
        outcome.result = result.map(|value| value.to_string());
        outcome.outcome_unknown = unknown;
        return outcome;
    }
    let parsed = parse_http_json(&response);
    if let Err(error) = parsed {
        outcome.result = Err(error);
        outcome.outcome_unknown = !matches!(response.status, 400 | 401 | 403 | 404 | 429);
        if outcome.outcome_unknown {
            outcome.monetary_microusd = None;
        }
        return outcome;
    }
    let json = parsed.expect("checked JSON result");
    let (result, cost, unknown) = match &call.response {
        ResponseProfile::SlackWebhook { .. } => (Err(AdapterError::ResponseInvalid), Some(0), true),
        ResponseProfile::SlackRead { channel, limit } => {
            (slack::read_response(&json, channel, *limit), Some(0), false)
        }
        ResponseProfile::SlackPost { channel } => {
            let result = slack::post_response(&json, channel);
            let unknown = result.is_err() && !slack::known_rejection(&json);
            (result, Some(0), unknown)
        }
        ResponseProfile::Snowflake { columns, max_rows } => {
            let result = snowflake::response(&json, columns, *max_rows);
            (result, None, false)
        }
        ResponseProfile::OpenAi {
            profile,
            output_limit,
        } => openai::response(&json, profile, *output_limit),
        ResponseProfile::Gitea {
            action,
            endpoint,
            owner,
            target,
            page,
            limit,
        } => (
            gitea_actions::response(*action, &json, endpoint, owner, *page, *limit)
                .and_then(|value| gitea_actions::validate_target(*action, value, target)),
            Some(0),
            false,
        ),
        ResponseProfile::GitHubJob => (github_actions::job_response(&json), Some(0), false),
        // Handled above, before any JSON parsing was attempted.
        ResponseProfile::GitHubJobLog => (Err(AdapterError::ResponseInvalid), Some(0), true),
        ResponseProfile::LinearIssues => (linear_work::issues_response(&json), Some(0), false),
        ResponseProfile::LinearIssueDetail => (linear_work::detail_response(&json), Some(0), false),
        ResponseProfile::LinearAssignableUsers => {
            (linear_work::assignees_response(&json), Some(0), false)
        }
        ResponseProfile::LinearReassign => {
            let result = linear_work::reassign_response(&json);
            // A reassignment that neither succeeded nor was refused leaves the
            // owner genuinely unknown: the mutation may have landed.
            let unknown = matches!(result, Err(AdapterError::ResponseInvalid));
            (result, Some(0), unknown)
        }
        // Handled above, before any JSON parsing was attempted.
        ResponseProfile::ObjectHead | ResponseProfile::ObjectDelete => {
            (Err(AdapterError::ResponseInvalid), Some(0), true)
        }
    };
    outcome.result = result.map(|value| value.to_string());
    outcome.monetary_microusd = cost;
    outcome.outcome_unknown = unknown;
    outcome
}

fn transmit(
    request: &transport::WireRequest,
    call: &PreparedCall,
    authorization: Authorization<'_>,
    transport: &dyn Transport,
    outcome: &mut AdapterOutcome,
    phase: ExchangePhase,
) -> Option<transport::WireResponse> {
    let remaining = call.response_limit().checked_sub(outcome.response_bytes)?;
    if remaining == 0 {
        outcome.result = Err(AdapterError::ResponseTooLarge);
        return None;
    }
    outcome.dispatched = true;
    outcome.calls += 1;
    outcome.request_bytes += request.payload_bytes();
    match transport.send(request, authorization, remaining) {
        Ok(response) => {
            outcome.response_bytes += response.body.len() as u64;
            let statement_handle = if response.body.len() as u64 <= remaining
                && response.json_content_type
                && matches!(call.connection, LiveConnection::Snowflake { .. })
            {
                serde_json::from_slice::<Value>(&response.body)
                    .ok()
                    .and_then(|json| {
                        json.get("statementHandle")
                            .and_then(Value::as_str)
                            .and_then(statement_uuid)
                    })
            } else {
                None
            };
            outcome.correlation.push(ExchangeCorrelation {
                phase,
                http_status: (100..=599)
                    .contains(&response.status)
                    .then_some(response.status),
                request_id: if matches!(call.connection, LiveConnection::OpenAi { .. }) {
                    response
                        .request_id
                        .as_deref()
                        .and_then(correlation_identifier)
                } else {
                    None
                },
                statement_handle,
            });
            if response.body.len() as u64 > remaining {
                outcome.result = Err(AdapterError::ResponseTooLarge);
                None
            } else {
                Some(response)
            }
        }
        Err(error) => {
            outcome.response_bytes += error.response_bytes;
            outcome.correlation.push(ExchangeCorrelation {
                phase,
                http_status: error
                    .http_status
                    .filter(|status| (100..=599).contains(status)),
                request_id: if matches!(call.connection, LiveConnection::OpenAi { .. }) {
                    error.request_id.as_deref().and_then(correlation_identifier)
                } else {
                    None
                },
                statement_handle: None,
            });
            outcome.result = Err(error.kind);
            None
        }
    }
}

fn parse_http_json(response: &transport::WireResponse) -> Result<Value, AdapterError> {
    if response.status == 429 {
        return Err(AdapterError::RateLimited);
    }
    if matches!(response.status, 400 | 401 | 403 | 404) {
        return Err(AdapterError::ProviderDenied);
    }
    if response.status != 200 {
        return Err(AdapterError::Incomplete);
    }
    if !response.json_content_type {
        return Err(AdapterError::ResponseInvalid);
    }
    serde_json::from_slice(&response.body).map_err(|_| AdapterError::ResponseInvalid)
}

#[cfg(test)]
#[path = "coverage_tests.rs"]
mod coverage_tests;

#[cfg(test)]
#[path = "parity_tests.rs"]
mod parity_tests;

#[cfg(test)]
mod tests;

pub(crate) use object_store::GRANT_SECONDS;

/// One object-store request against an already-signed URL.
///
/// Signing happens where the grant's scope check happens, so every object
/// operation passes the same gate before a URL exists: `head` and `delete` are
/// scoped exactly as the grants are, and there is one place to read to see that.
///
/// This is deliberately not an arm of `prepare`. That function builds a request
/// from a connection and an input, and an object request additionally needs the
/// secret — which lives behind the credential resolver and must not be widened
/// into a general argument of request building.
pub(crate) fn object_call(
    connection: &LiveConnection,
    operation: ObjectOperation,
    url: String,
    max_response_bytes: u64,
) -> PreparedCall {
    let (method, response) = match operation {
        ObjectOperation::Head => (Method::Head, ResponseProfile::ObjectHead),
        ObjectOperation::Delete => (Method::Delete, ResponseProfile::ObjectDelete),
    };
    PreparedCall {
        connection: connection.clone(),
        request: WireRequest {
            url,
            body: vec![],
            headers: vec![],
            method,
        },
        response,
        response_limit: max_response_bytes.min(MAX_WIRE_BYTES),
        reserved_monetary_microusd: Some(0),
    }
}

/// Which object operation to perform.
///
/// One argument rather than a method and a response profile, because those two
/// cannot be allowed to disagree: a request signed as a DELETE whose response is
/// read as a HEAD would report an object's size after destroying it. Deriving both
/// from one value makes that combination unwritable, and keeps `ResponseProfile`
/// private to this module.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObjectOperation {
    Head,
    Delete,
}

/// Presign one object operation. The secret is borrowed for the computation and
/// never stored, transmitted or logged.
#[allow(clippy::too_many_arguments)]
pub(crate) fn presign(
    access_key_id: &str,
    secret: &str,
    region: &str,
    method: &str,
    endpoint: &str,
    bucket: &str,
    key: &str,
    now: i64,
) -> Result<String, AdapterError> {
    object_store::Signer {
        access_key_id,
        secret,
        region,
    }
    .presign(
        method,
        endpoint,
        bucket,
        key,
        object_store::GRANT_SECONDS,
        now,
    )
}
