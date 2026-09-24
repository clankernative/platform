//! GitHub Actions: whether a CI job finished, and where to read its log.
//!
//! Two reads, and the second is the interesting one. GitHub answers a log
//! request with a 302 to a signed blob URL, and the log itself is unbounded —
//! a build can print megabytes. So this adapter returns the *URL* and never the
//! bytes, exactly as object downloads do: the platform authorizes a transfer
//! rather than performing one, and a 64-KiB observation is never asked to carry
//! something that does not fit.
//!
//! The repository comes from the grant, never from the application. A CI log
//! can contain whatever a build printed — tokens, customer data, source — so
//! letting an application name the repository would make the grant meaningless.

use super::{AdapterError, PreparedCall, ResponseProfile, transport::WireRequest};
use day2_capabilities::{integrations::LiveConnection, resources::Action};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobRequest {
    handle: String,
    /// GitHub's numeric job id, as a string. Numeric ids exceed what JSON
    /// integers carry safely in every client, and this only ever goes into a
    /// path.
    job_id: String,
}

/// A job id is digits and nothing else. It is interpolated into a path, so
/// anything else is refused rather than escaped.
fn job_id(value: &str) -> Result<&str, AdapterError> {
    let ok = !value.is_empty() && value.len() <= 32 && value.bytes().all(|b| b.is_ascii_digit());
    ok.then_some(value).ok_or(AdapterError::InvalidRequest)
}

fn handle(value: &str) -> Result<(), AdapterError> {
    (!value.is_empty())
        .then_some(())
        .ok_or(AdapterError::InvalidRequest)
}

pub(super) fn prepare(
    action: Action,
    connection: &LiveConnection,
    owner: &str,
    repo: &str,
    input: &str,
) -> Result<PreparedCall, AdapterError> {
    let LiveConnection::GitHubActions { endpoint, .. } = connection else {
        return Err(AdapterError::InvalidProfile);
    };
    let input: JobRequest =
        serde_json::from_str(input).map_err(|_| AdapterError::InvalidRequest)?;
    handle(&input.handle)?;
    let job = job_id(&input.job_id)?;
    let base = format!("{endpoint}/repos/{owner}/{repo}/actions/jobs/{job}");
    let (url, response) = match action {
        Action::GitHubJob => (base, ResponseProfile::GitHubJob),
        Action::GitHubJobLog => (format!("{base}/logs"), ResponseProfile::GitHubJobLog),
        _ => return Err(AdapterError::InvalidProfile),
    };
    Ok(PreparedCall {
        connection: connection.clone(),
        request: WireRequest {
            url,
            body: vec![],
            headers: vec![("accept", "application/vnd.github+json".into())],
            method: super::Method::Get,
        },
        response,
        response_limit: 0,
        reserved_monetary_microusd: Some(0),
    })
}

/// What a job's state means for the thing watching it.
///
/// The distinction that matters is *finished or not*, and the source this
/// replaces is deliberate about it: anything other than an explicitly running
/// state counts as finished, so a status GitHub adds later closes a watched job
/// rather than leaving it open forever.
pub(super) fn job_response(json: &Value) -> Result<Value, AdapterError> {
    let text = |name: &str| {
        json.get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let status = text("status");
    let running = matches!(
        status.as_str(),
        "queued" | "waiting" | "pending" | "requested" | "in_progress"
    );
    let conclusion = text("conclusion");
    Ok(json!({
        "status": status,
        // Empty until GitHub decides one. A finished job with no conclusion is
        // reported as "completed" by the service this replaces; that mapping is
        // the caller's to make, so the raw fact is passed through.
        "conclusion": conclusion,
        "finished": !running,
        "queued": matches!(status.as_str(), "queued" | "waiting" | "pending" | "requested"),
        "started_at_ms": super::linear_work::instant_ms(&text("started_at")),
        "completed_at_ms": super::linear_work::instant_ms(&text("completed_at")),
        "name": text("name"),
        "html_url": text("html_url"),
    }))
}

/// Seconds a log URL stays usable. GitHub's signed links are short-lived; this
/// is what the caller is told, not a promise the platform can extend.
pub(super) const LOG_URL_SECONDS: u64 = 60;

/// The signed log location, from the redirect GitHub answers with.
///
/// A 200 here means GitHub returned the log inline instead of redirecting,
/// which this deliberately does not pass through: the whole point is to stay
/// off the data path, and a body that fits today is not a guarantee.
pub(super) fn log_response(response: &super::WireResponse) -> (Result<String, AdapterError>, bool) {
    let location = response
        .metadata
        .iter()
        .find(|(name, _)| *name == "location")
        .map(|(_, value)| value.as_str());
    match (response.status, location) {
        (301 | 302 | 303 | 307 | 308, Some(url)) if url.starts_with("https://") => (
            Ok(json!({"url": url, "expires_in": LOG_URL_SECONDS}).to_string()),
            false,
        ),
        // A job with no log yet is an answer, not a failure.
        (404, _) => (Ok(json!({"url": "", "expires_in": 0}).to_string()), false),
        (401 | 403, _) => (Err(AdapterError::ProviderDenied), false),
        (429, _) => (Err(AdapterError::RateLimited), false),
        _ => (Err(AdapterError::ResponseInvalid), true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Job payloads recorded against the real GitHub API by the service this
    /// pack is built for, taken from its own adapter tests.
    ///
    /// The base the simulation cannot supply. A simulation written next to an
    /// adapter emits whatever shapes that adapter already reads, so the two
    /// agree about a misreading and every gate passes while the live call
    /// returns something else. This is the check that caught a silently-zeroed
    /// priority in the Linear pack, so it is done first here rather than last.
    const RECORDED_COMPLETED: &str = r#"{
      "id": 42, "run_id": 7, "run_attempt": 1, "name": "android-test",
      "workflow_path": ".github/workflows/mobile.yml",
      "runner_id": 10, "runner_name": "runner-a", "runner_group_name": "mobile",
      "labels": ["self-hosted", "android"],
      "status": "completed", "conclusion": "success",
      "created_at": "2026-01-02T10:55:00Z",
      "started_at": "2026-01-02T11:00:00Z",
      "completed_at": "2026-01-02T11:30:00Z",
      "html_url": "https://github.test/job", "steps": []
    }"#;

    const RECORDED_RUNNING: &str =
        r#"{"status":"in_progress","started_at":"2026-07-09T12:00:00Z"}"#;

    const RECORDED_CANCELLED: &str = r#"{"status":"completed","conclusion":"cancelled",
        "started_at":"2026-07-09T12:00:00Z","completed_at":"2026-07-09T12:30:00Z"}"#;

    fn parse(raw: &str) -> Value {
        serde_json::from_str(raw).expect("recorded response parses")
    }

    #[test]
    fn a_recorded_completed_job_reports_its_own_timings() {
        let job = job_response(&parse(RECORDED_COMPLETED)).expect("projected");
        assert_eq!(job["status"], "completed");
        assert_eq!(job["conclusion"], "success");
        assert_eq!(job["finished"], true);
        assert_eq!(job["queued"], false);
        assert_eq!(job["name"], "android-test");
        // GitHub's times, not the poller's. Checked as numbers so a timestamp
        // that failed to parse cannot pass as "some time".
        assert_eq!(job["started_at_ms"], 1_767_351_600_000i64);
        assert_eq!(job["completed_at_ms"], 1_767_353_400_000i64);
    }

    #[test]
    fn a_running_job_is_not_finished_and_carries_no_completion() {
        let job = job_response(&parse(RECORDED_RUNNING)).expect("projected");
        assert_eq!(job["finished"], false);
        assert_eq!(job["queued"], false);
        assert_eq!(job["conclusion"], "");
        // -1, not 0. A zero would be 1970 and would read as a job that finished
        // fifty-six years ago.
        assert_eq!(job["completed_at_ms"], -1);
    }

    #[test]
    fn an_unknown_status_counts_as_finished_rather_than_running_forever() {
        // The decision the source is explicit about: anything that is not an
        // explicitly running state closes the job. A watcher that only accepted
        // `completed` would hold a job open forever the day GitHub adds a state.
        let invented = parse(r#"{"status":"neutralised","conclusion":"skipped"}"#);
        let job = job_response(&invented).expect("projected");
        assert_eq!(job["finished"], true);
        assert_eq!(job["queued"], false);
        // And a cancelled job is finished with its real conclusion.
        let cancelled = job_response(&parse(RECORDED_CANCELLED)).expect("projected");
        assert_eq!(cancelled["finished"], true);
        assert_eq!(cancelled["conclusion"], "cancelled");
        // Every waiting state is queued, and none of them is finished.
        for waiting in ["queued", "waiting", "pending", "requested"] {
            let job =
                job_response(&parse(&format!(r#"{{"status":"{waiting}"}}"#))).expect("projected");
            assert_eq!(job["queued"], true, "{waiting}");
            assert_eq!(job["finished"], false, "{waiting}");
        }
    }

    fn redirect(status: u16, location: Option<&str>) -> super::super::WireResponse {
        super::super::WireResponse {
            status,
            json_content_type: false,
            body: vec![],
            request_id: None,
            metadata: location
                .map(|url| vec![("location", url.to_owned())])
                .unwrap_or_default(),
        }
    }

    #[test]
    fn a_log_location_comes_from_the_redirect_and_never_from_a_body() {
        let (result, unknown) = log_response(&redirect(302, Some("https://blob.test/log?sig=x")));
        assert!(!unknown);
        let value: Value = serde_json::from_str(&result.expect("located")).unwrap();
        assert_eq!(value["url"], "https://blob.test/log?sig=x");
        assert_eq!(value["expires_in"], LOG_URL_SECONDS);

        // A job with no log yet is an answer, not a failure: a queued job has
        // printed nothing.
        let (result, unknown) = log_response(&redirect(404, None));
        assert!(!unknown);
        let value: Value = serde_json::from_str(&result.expect("answered")).unwrap();
        assert_eq!(value["url"], "");

        // A 200 means GitHub returned the log inline. Refused rather than
        // passed through: staying off the data path is the point, and a body
        // that fits today is not a guarantee.
        let mut inline = redirect(200, None);
        inline.body = b"a build log".to_vec();
        assert!(log_response(&inline).0.is_err());

        // A redirect to somewhere unencrypted is not a location worth handing on.
        assert!(
            log_response(&redirect(302, Some("http://blob.test/log")))
                .0
                .is_err()
        );

        for (status, expected) in [
            (403, AdapterError::ProviderDenied),
            (429, AdapterError::RateLimited),
        ] {
            assert_eq!(
                log_response(&redirect(status, None)).0.unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn a_job_id_that_is_not_digits_never_reaches_a_path() {
        // The id is interpolated into a URL, so traversal and query injection
        // are refused at the door rather than escaped later.
        for hostile in ["", "1/../../secrets", "7?x=1", "abc", &"9".repeat(64)] {
            assert!(job_id(hostile).is_err(), "{hostile:?}");
        }
        assert_eq!(job_id("101").unwrap(), "101");
    }
}
