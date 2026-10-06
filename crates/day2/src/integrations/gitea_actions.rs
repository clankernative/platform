//! Gitea 1.27 Actions reads, scoped to one operator-approved organization.
//! No caller-selected origin, owner, arbitrary path, or workflow mutation.

use super::{AdapterError, PreparedCall, ResponseProfile, WireResponse};
use crate::integrations::transport::{Method, WireRequest};
use day2_capabilities::{integrations::LiveConnection, resources::Action};
use serde::Deserialize;
use serde_json::{Value, json};

/// The exact target captured before the read; provider data cannot select another attempt.
pub(super) struct Target {
    repo: String,
    id: i64,
    attempt: i64,
}

pub(super) fn validate_target(
    action: Action,
    value: Value,
    target: &Target,
) -> Result<Value, AdapterError> {
    let matches = |row: &Value, id_field: &str| {
        row["repo"].as_str() == Some(target.repo.as_str())
            && row[id_field].as_i64() == Some(target.id)
            && (target.attempt == 0 || row["attempt"].as_i64() == Some(target.attempt))
    };
    let valid = match action {
        Action::GiteaRun | Action::GiteaJob => matches(&value, "id"),
        Action::GiteaRunJobs => value["items"]
            .as_array()
            .is_some_and(|items| items.iter().all(|row| matches(row, "run_id"))),
        Action::GiteaRuns | Action::GiteaRunners => true,
        _ => false,
    };
    if valid {
        Ok(value)
    } else {
        Err(AdapterError::ResponseInvalid)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    handle: String,
    #[serde(default)]
    repo: String,
    #[serde(default)]
    id: i64,
    #[serde(default)]
    attempt: i64,
    #[serde(default = "first_page")]
    page: u64,
    #[serde(default = "page_size")]
    limit: u64,
    #[serde(default)]
    status: String,
}

fn first_page() -> u64 {
    1
}
fn page_size() -> u64 {
    20
}

fn segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
}

pub(super) fn prepare(
    action: Action,
    connection: &LiveConnection,
    owner: &str,
    input: &str,
) -> Result<PreparedCall, AdapterError> {
    let LiveConnection::GiteaActions { endpoint, .. } = connection else {
        return Err(AdapterError::InvalidProfile);
    };
    let request: Request = serde_json::from_str(input).map_err(|_| AdapterError::InvalidRequest)?;
    if request.handle.is_empty()
        || request.attempt < 0
        || !segment(owner)
        || !(1..=100_000).contains(&request.page)
        || !(1..=50).contains(&request.limit)
        || !matches!(
            request.status.as_str(),
            "" | "pending" | "queued" | "in_progress" | "failure" | "success" | "skipped"
        )
    {
        return Err(AdapterError::InvalidRequest);
    }
    let base = format!("{endpoint}/api/v1");
    let pagination = format!("page={}&limit={}", request.page, request.limit);
    let url = match action {
        // Gitea 1.27 rejects an empty status ("invalid status"); an
        // unfiltered listing omits the parameter.
        Action::GiteaRuns if request.repo.is_empty() && request.id == 0 => {
            if request.status.is_empty() {
                format!("{base}/orgs/{owner}/actions/runs?{pagination}")
            } else {
                format!(
                    "{base}/orgs/{owner}/actions/runs?{pagination}&status={}",
                    request.status
                )
            }
        }
        Action::GiteaRunners
            if request.repo.is_empty() && request.id == 0 && request.status.is_empty() =>
        {
            format!("{base}/orgs/{owner}/actions/runners")
        }
        Action::GiteaRun | Action::GiteaRunJobs | Action::GiteaJob | Action::GiteaJobLog
            if segment(&request.repo) && request.id > 0 && request.status.is_empty() =>
        {
            let repo = &request.repo;
            let id = request.id;
            let run_path = if request.attempt == 0 {
                format!("{base}/repos/{owner}/{repo}/actions/runs/{id}")
            } else {
                format!(
                    "{base}/repos/{owner}/{repo}/actions/runs/{id}/attempts/{}",
                    request.attempt
                )
            };
            match action {
                Action::GiteaRun => run_path,
                Action::GiteaRunJobs => format!("{run_path}/jobs?{pagination}"),
                Action::GiteaJob => format!("{base}/repos/{owner}/{repo}/actions/jobs/{id}"),
                Action::GiteaJobLog => {
                    format!("{base}/repos/{owner}/{repo}/actions/jobs/{id}/logs")
                }
                _ => unreachable!(),
            }
        }
        _ => return Err(AdapterError::InvalidRequest),
    };
    Ok(PreparedCall {
        connection: connection.clone(),
        request: WireRequest {
            url,
            body: vec![],
            headers: vec![("accept", "application/json".into())],
            method: Method::Get,
        },
        response: ResponseProfile::Gitea {
            action,
            endpoint: endpoint.clone(),
            owner: owner.into(),
            target: Target {
                repo: request.repo,
                id: request.id,
                attempt: request.attempt,
            },
            page: request.page,
            limit: request.limit,
        },
        response_limit: 0,
        reserved_monetary_microusd: Some(0),
    })
}

fn text(value: &Value, field: &str, max: usize) -> Result<String, AdapterError> {
    let value = match value.get(field) {
        None | Some(Value::Null) => "",
        Some(Value::String(value)) => value,
        _ => return Err(AdapterError::ResponseInvalid),
    };
    if value.len() > max {
        return Err(AdapterError::ResponseTooLarge);
    }
    Ok(value.to_owned())
}

fn required_text(value: &Value, field: &str, max: usize) -> Result<String, AdapterError> {
    let value = text(value, field, max)?;
    if value.trim().is_empty() {
        Err(AdapterError::ResponseInvalid)
    } else {
        Ok(value)
    }
}

fn number(value: &Value, field: &str) -> Result<i64, AdapterError> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .filter(|n| *n >= 0)
        .ok_or(AdapterError::ResponseInvalid)
}

fn instant(value: &Value, field: &str) -> Result<i64, AdapterError> {
    let raw = text(value, field, 64)?;
    if raw.is_empty() {
        return Ok(-1);
    }
    let ms = super::linear_work::instant_ms(&raw);
    if ms < 0 {
        return Err(AdapterError::ResponseInvalid);
    }
    // Gitea uses the Unix epoch when a queued/skipped job has no instant.
    Ok(if ms == 0 { -1 } else { ms / 1000 })
}

fn repository(value: &Value, endpoint: &str, owner: &str) -> Result<String, AdapterError> {
    // Job responses omit repository metadata. Validate their API URL instead;
    // never accept a provider-supplied URL as a new outbound authority.
    let url = text(value, "url", 2048)?;
    let prefix = format!("{endpoint}/api/v1/repos/{owner}/");
    let rest = url
        .strip_prefix(&prefix)
        .ok_or(AdapterError::ResponseInvalid)?;
    let (repo, suffix) = rest.split_once('/').ok_or(AdapterError::ResponseInvalid)?;
    if !segment(repo) || !suffix.starts_with("actions/") {
        return Err(AdapterError::ResponseInvalid);
    }
    Ok(repo.into())
}

pub(super) fn run(value: &Value, endpoint: &str, owner: &str) -> Result<Value, AdapterError> {
    let id = number(value, "id")?;
    if id == 0 {
        return Err(AdapterError::ResponseInvalid);
    }
    Ok(json!({
        "id": id, "attempt": number(value, "run_attempt")?,
        "owner": owner, "repo": repository(value, endpoint, owner)?,
        "title": text(value, "display_title", 2048)?, "path": text(value, "path", 2048)?,
        "event": text(value, "event", 128)?, "branch": text(value, "head_branch", 1024)?,
        "sha": text(value, "head_sha", 128)?, "status": required_text(value, "status", 64)?,
        "conclusion": text(value, "conclusion", 64)?,
        "started_at": instant(value, "started_at")?, "completed_at": instant(value, "completed_at")?,
        "url": text(value, "html_url", 2048)?,
    }))
}

pub(super) fn job(value: &Value, endpoint: &str, owner: &str) -> Result<Value, AdapterError> {
    let id = number(value, "id")?;
    if id == 0 {
        return Err(AdapterError::ResponseInvalid);
    }
    let labels = value
        .get("labels")
        .and_then(Value::as_array)
        .ok_or(AdapterError::ResponseInvalid)?;
    if labels.len() > 32
        || labels
            .iter()
            .any(|v| v.as_str().is_none_or(|s| s.len() > 256))
    {
        return Err(AdapterError::ResponseTooLarge);
    }
    Ok(json!({
        "id": id, "run_id": number(value, "run_id")?, "attempt": number(value, "run_attempt")?,
        "owner": owner, "repo": repository(value, endpoint, owner)?,
        "name": text(value, "name", 2048)?, "status": required_text(value, "status", 64)?,
        "conclusion": text(value, "conclusion", 64)?,
        "created_at": instant(value, "created_at")?, "started_at": instant(value, "started_at")?,
        "completed_at": instant(value, "completed_at")?, "runner_id": match value.get("runner_id") { None | Some(Value::Null) => 0, Some(_) => number(value, "runner_id")? },
        "runner_name": text(value, "runner_name", 1024)?, "labels": labels,
        "url": text(value, "html_url", 2048)?,
    }))
}

fn runner(value: &Value) -> Result<Value, AdapterError> {
    let labels = value
        .get("labels")
        .and_then(Value::as_array)
        .ok_or(AdapterError::ResponseInvalid)?;
    if labels.len() > 32 {
        return Err(AdapterError::ResponseTooLarge);
    }
    let labels = labels
        .iter()
        .map(|v| text(v, "name", 256))
        .collect::<Result<Vec<_>, _>>()?;
    let boolean = |field| {
        value
            .get(field)
            .and_then(Value::as_bool)
            .ok_or(AdapterError::ResponseInvalid)
    };
    Ok(json!({
        "id": number(value, "id")?, "name": text(value, "name", 1024)?,
        "status": required_text(value, "status", 64)?, "busy": boolean("busy")?,
        "disabled": boolean("disabled")?, "ephemeral": boolean("ephemeral")?, "labels": labels,
    }))
}

pub(super) fn response(
    action: Action,
    json: &Value,
    endpoint: &str,
    owner: &str,
    page: u64,
    limit: u64,
) -> Result<Value, AdapterError> {
    if action == Action::GiteaRun {
        return run(json, endpoint, owner);
    }
    if action == Action::GiteaJob {
        return job(json, endpoint, owner);
    }
    let key = match action {
        Action::GiteaRuns => "workflow_runs",
        Action::GiteaRunJobs => "jobs",
        Action::GiteaRunners => "runners",
        _ => return Err(AdapterError::InvalidProfile),
    };
    let rows = json
        .get(key)
        .and_then(Value::as_array)
        .ok_or(AdapterError::ResponseInvalid)?;
    let bound = if action == Action::GiteaRunners {
        100
    } else {
        limit as usize
    };
    if rows.len() > bound {
        return Err(AdapterError::ResponseTooLarge);
    }
    let total = number(json, "total_count")? as u64;
    let items = rows
        .iter()
        .map(|value| match action {
            Action::GiteaRuns => run(value, endpoint, owner),
            Action::GiteaRunJobs => job(value, endpoint, owner),
            Action::GiteaRunners => runner(value),
            _ => unreachable!(),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if action == Action::GiteaRunners {
        if total != items.len() as u64 {
            return Err(AdapterError::Incomplete);
        }
        return Ok(json!({ "items": items }));
    }
    let has_more = page * limit < total;
    // A changing page is possible, but an empty page before the declared end
    // cannot be treated as completed synchronization.
    if rows.is_empty() && has_more {
        return Err(AdapterError::Incomplete);
    }
    Ok(json!({ "items": items, "has_more": has_more, "next_page": page + 1, "total": total }))
}

pub(super) fn log_response(response: &WireResponse) -> Result<Value, AdapterError> {
    match response.status {
        401 | 403 => return Err(AdapterError::ProviderDenied),
        429 => return Err(AdapterError::RateLimited),
        404 => return Ok(json!({ "available": false, "text": "", "truncated": false })),
        200 => {}
        _ => return Err(AdapterError::ResponseInvalid),
    }
    // The transport enforces MAX_WIRE_BYTES before this point. Keep a UTF-8
    // tail for classification and expose whether earlier content was omitted.
    let text = std::str::from_utf8(&response.body).map_err(|_| AdapterError::ResponseInvalid)?;
    let mut start = text.len().saturating_sub(12_000);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    Ok(json!({ "available": true, "text": &text[start..], "truncated": start != 0 }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use day2_capabilities::resources::VersionRef;

    const ORIGIN: &str = "https://git.example.test";
    const OWNER: &str = "example-org";

    #[test]
    fn recorded_gitea_127_responses_preserve_provider_facts() {
        // External wire fixtures with documented redactions, not simulation output.
        let runs: Value = serde_json::from_slice(include_bytes!(
            "../../fixtures/provider-responses/gitea.runs.json"
        ))
        .unwrap();
        let jobs: Value = serde_json::from_slice(include_bytes!(
            "../../fixtures/provider-responses/gitea.jobs.json"
        ))
        .unwrap();
        let runners: Value = serde_json::from_slice(include_bytes!(
            "../../fixtures/provider-responses/gitea.runners.json"
        ))
        .unwrap();
        let page = response(Action::GiteaRuns, &runs, ORIGIN, OWNER, 1, 2).unwrap();
        assert_eq!(page["items"][0]["id"], 49144);
        assert_eq!(page["items"][0]["conclusion"], "skipped");
        assert_eq!(page["has_more"], true);
        let page = response(Action::GiteaRunJobs, &jobs, ORIGIN, OWNER, 1, 2).unwrap();
        assert_eq!(page["items"][0]["id"], 2);
        assert_eq!(page["items"][1]["started_at"], -1);
        assert_eq!(page["items"][1]["runner_name"], "");
        let pool = response(Action::GiteaRunners, &runners, ORIGIN, OWNER, 1, 20).unwrap();
        assert_eq!(pool["items"].as_array().unwrap().len(), 19);
    }

    #[test]
    fn malformed_or_cross_organization_data_is_not_an_empty_success() {
        let mut runs: Value = serde_json::from_slice(include_bytes!(
            "../../fixtures/provider-responses/gitea.runs.json"
        ))
        .unwrap();
        assert!(response(Action::GiteaRuns, &runs, ORIGIN, "other-org", 1, 2).is_err());
        runs["workflow_runs"][0]["id"] = json!(0);
        assert!(response(Action::GiteaRuns, &runs, ORIGIN, OWNER, 1, 2).is_err());
        assert!(response(Action::GiteaRuns, &json!({}), ORIGIN, OWNER, 1, 20).is_err());
        assert!(
            response(
                Action::GiteaRuns,
                &json!({"workflow_runs":[],"total_count":100}),
                ORIGIN,
                OWNER,
                1,
                20
            )
            .is_err()
        );
        assert!(
            response(
                Action::GiteaRunners,
                &json!({"runners":[],"total_count":1}),
                ORIGIN,
                OWNER,
                1,
                20
            )
            .is_err()
        );
    }

    #[test]
    fn exact_reads_reject_other_repositories_runs_and_attempts() {
        let target = Target {
            repo: "example-repo".into(),
            id: 7,
            attempt: 2,
        };
        let run = json!({"repo":"example-repo", "id":7, "attempt":2});
        assert!(validate_target(Action::GiteaRun, run.clone(), &target).is_ok());
        for (field, wrong) in [
            ("repo", json!("another-repo")),
            ("id", json!(8)),
            ("attempt", json!(1)),
        ] {
            let mut mismatched = run.clone();
            mismatched[field] = wrong;
            assert!(validate_target(Action::GiteaRun, mismatched, &target).is_err());
        }
        let job = json!({"repo":"example-repo", "id":99, "run_id":7, "attempt":2});
        assert!(
            validate_target(
                Action::GiteaRunJobs,
                json!({"items":[job.clone()]}),
                &target
            )
            .is_ok()
        );
        for (field, wrong) in [
            ("repo", json!("another-repo")),
            ("run_id", json!(8)),
            ("attempt", json!(1)),
        ] {
            let mut mismatched = job.clone();
            mismatched[field] = wrong;
            assert!(
                validate_target(Action::GiteaRunJobs, json!({"items":[mismatched]}), &target)
                    .is_err()
            );
        }
        // Attempt zero requests Gitea's latest attempt, whose identity is still checked.
        let latest = Target {
            attempt: 0,
            ..target
        };
        assert!(validate_target(Action::GiteaRun, run, &latest).is_ok());
    }

    #[test]
    fn unassigned_jobs_can_omit_runner_identity_without_losing_the_job() {
        let mut recorded: Value = serde_json::from_slice(include_bytes!(
            "../../fixtures/provider-responses/gitea.jobs.json"
        ))
        .unwrap();
        let item = &mut recorded["jobs"][1];
        item.as_object_mut().unwrap().remove("runner_id");
        item.as_object_mut().unwrap().remove("runner_name");
        item["status"] = json!("completed");
        item["conclusion"] = json!("cancelled");
        let parsed = job(item, ORIGIN, OWNER).unwrap();
        assert_eq!(parsed["runner_id"], 0);
        assert_eq!(parsed["runner_name"], "");
        assert_eq!(parsed["conclusion"], "cancelled");
        assert_eq!(parsed["started_at"], -1);
        item["runner_id"] = json!("not-an-id");
        assert!(job(item, ORIGIN, OWNER).is_err());
        item["runner_id"] = json!(-1);
        assert!(job(item, ORIGIN, OWNER).is_err());
    }

    #[test]
    fn missing_status_is_not_a_successful_observation() {
        let mut recorded: Value = serde_json::from_slice(include_bytes!(
            "../../fixtures/provider-responses/gitea.runs.json"
        ))
        .unwrap();
        recorded["workflow_runs"][0]
            .as_object_mut()
            .unwrap()
            .remove("status");
        assert!(response(Action::GiteaRuns, &recorded, ORIGIN, OWNER, 1, 2).is_err());
    }

    #[test]
    fn caller_cannot_escape_the_granted_organization_or_select_an_arbitrary_url() {
        let connection = LiveConnection::GiteaActions {
            signing_secret_ref: None,
            credential_ref: VersionRef {
                id: "example".into(),
                revision: 1,
            },
            endpoint: ORIGIN.into(),
        };
        for repo in ["..", "a/b", "a?owner=other", "a%2fb", "https://evil.test"] {
            assert!(
                prepare(
                    Action::GiteaRunJobs,
                    &connection,
                    OWNER,
                    &json!({"handle":"h","repo":repo,"id":1}).to_string()
                )
                .is_err()
            );
        }
        assert!(
            prepare(
                Action::GiteaRuns,
                &connection,
                OWNER,
                &json!({"handle":"h","page":0}).to_string()
            )
            .is_err()
        );
        assert!(
            prepare(
                Action::GiteaRuns,
                &connection,
                OWNER,
                &json!({"handle":"h","limit":51}).to_string()
            )
            .is_err()
        );
        assert!(
            prepare(
                Action::GiteaRuns,
                &connection,
                OWNER,
                &json!({"handle":"h","owner":"other"}).to_string()
            )
            .is_err()
        );
        let call = prepare(
            Action::GiteaRunJobs,
            &connection,
            OWNER,
            &json!({"handle":"h","repo":"example-repo","id":7,"attempt":2,"page":3,"limit":20})
                .to_string(),
        )
        .unwrap();
        assert_eq!(
            call.request.url,
            "https://git.example.test/api/v1/repos/example-org/example-repo/actions/runs/7/attempts/2/jobs?page=3&limit=20"
        );
        for (status, query) in [
            ("", "page=1&limit=5"),
            ("queued", "page=1&limit=5&status=queued"),
        ] {
            let call = prepare(
                Action::GiteaRuns,
                &connection,
                OWNER,
                &json!({"handle":"h","page":1,"limit":5,"status":status}).to_string(),
            )
            .unwrap();
            assert_eq!(
                call.request.url,
                format!("https://git.example.test/api/v1/orgs/example-org/actions/runs?{query}")
            );
        }
    }

    #[test]
    fn log_tail_is_bounded_utf8_and_explicit_about_missing_content() {
        let response = WireResponse {
            status: 200,
            json_content_type: false,
            body: "é".repeat(8001).into_bytes(),
            request_id: None,
            metadata: vec![],
        };
        let log = log_response(&response).unwrap();
        assert_eq!(log["truncated"], true);
        assert!(log["text"].as_str().unwrap().len() <= 12_000);
        let missing = WireResponse {
            status: 404,
            ..response
        };
        assert_eq!(log_response(&missing).unwrap()["available"], false);
        let denied = WireResponse {
            status: 403,
            ..missing
        };
        assert_eq!(log_response(&denied), Err(AdapterError::ProviderDenied));
    }
}
