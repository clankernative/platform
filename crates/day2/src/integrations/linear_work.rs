//! Linear's GraphQL API, for reading tracked work and reassigning it.
//!
//! Four operations, three of them reads. The queries are fixed here rather than
//! composed from application input: a GraphQL document is a program, and an
//! application that could supply one could read any object in the workspace
//! regardless of what its grant names. The application supplies a cursor and an
//! issue id, and nothing else reaches the wire.
//!
//! Paging is one page per invocation, deliberately. The source this replaces
//! followed every `hasNextPage` in a loop, which cannot be expressed against a
//! bounded observation and should not be: an unbounded read inside one invocation
//! is an unbounded invocation. A caller that needs the whole queue ingests it a
//! page at a time on a schedule, which is durable, resumable and observable.

use super::{AdapterError, PreparedCall, ResponseProfile, transport::WireRequest};
use day2_capabilities::{
    integrations::{LinearWorkSource, LiveConnection},
    resources::Action,
};
use serde::Deserialize;
use serde_json::{Value, json};

/// The one endpoint this adapter talks to.
pub(super) const GRAPHQL: &str = "https://api.linear.app/graphql";

/// How many issues one page carries. Bounded so a page fits an observation with
/// room for the projection; the source's 100 would not.
const PAGE: usize = 25;
/// Comments and history entries returned with an issue's detail.
const ACTIVITY: usize = 10;
/// Members returned for an assignment decision.
const MEMBERS: usize = 100;

const ISSUE_FIELDS: &str = "id identifier title url dueDate priority priorityLabel createdAt \
     updatedAt state { name type } assignee { id name displayName email } \
     parent { assignee { name displayName email } } project { lead { name displayName email } } \
     team { key name } labels(first: 25) { nodes { name color } } \
     attachments(first: 20) { nodes { title url } }";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageRequest {
    handle: String,
    /// The opaque cursor from a previous page. Empty means the first page.
    #[serde(default)]
    after: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueRequest {
    handle: String,
    issue_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReassignRequest {
    handle: String,
    issue_id: String,
    /// Empty clears the assignee. That is a real operation rather than a missing
    /// value, so it is spelled as an empty string and sent as an explicit null:
    /// omitting the field would leave the current owner in place, which is a
    /// different outcome than the one the application asked for.
    #[serde(default)]
    assignee_id: String,
}

/// The resource token the SDK sends with every request.
///
/// The host has already resolved the grant by the time this runs, so the adapter
/// does not use it to decide anything — but the field must be declared, because
/// the request is parsed with `deny_unknown_fields` and would otherwise be
/// rejected. Checking it is non-empty keeps it a validated field rather than an
/// unread one.
fn handle(value: &str) -> Result<(), AdapterError> {
    (!value.is_empty())
        .then_some(())
        .ok_or(AdapterError::InvalidRequest)
}

/// Linear ids are UUIDs or short identifiers; bound and restrict them rather than
/// interpolating whatever arrived into a query variable.
fn identifier(value: &str) -> Result<&str, AdapterError> {
    let ok = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte));
    ok.then_some(value).ok_or(AdapterError::InvalidRequest)
}

fn cursor(value: &str) -> Result<&str, AdapterError> {
    let ok = value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_=+/".contains(&byte));
    ok.then_some(value).ok_or(AdapterError::InvalidRequest)
}

pub(super) fn prepare(
    action: Action,
    connection: &LiveConnection,
    source: &LinearWorkSource,
    input: &str,
) -> Result<PreparedCall, AdapterError> {
    let (body, response) = match action {
        Action::LinearWorkIssues => {
            let input: PageRequest =
                serde_json::from_str(input).map_err(|_| AdapterError::InvalidRequest)?;
            handle(&input.handle)?;
            let after = cursor(&input.after)?;
            let after = (!after.is_empty()).then_some(after);
            // The grant picks the query, not the application. A view grant can
            // only ever read that view, and a label grant only that label.
            let (query, variables) = match source {
                LinearWorkSource::CustomView { view_id, .. } => (
                    format!(
                        "query Day2ViewIssues($viewId: String!, $after: String) {{ \
                         customView(id: $viewId) {{ id name \
                         issues(first: {PAGE}, after: $after, includeArchived: false) \
                         {{ nodes {{ {ISSUE_FIELDS} }} pageInfo {{ hasNextPage endCursor }} }} }} }}"
                    ),
                    json!({"viewId": identifier(view_id)?, "after": after}),
                ),
                LinearWorkSource::Label { label } => (
                    format!(
                        "query Day2LabelIssues($labelName: String!, $after: String) {{ \
                         issues(first: {PAGE}, after: $after, includeArchived: false, \
                         filter: {{ labels: {{ some: {{ name: {{ eq: $labelName }} }} }} }}) \
                         {{ nodes {{ {ISSUE_FIELDS} }} pageInfo {{ hasNextPage endCursor }} }} }}"
                    ),
                    json!({"labelName": label, "after": after}),
                ),
            };
            (
                json!({"query": query, "variables": variables}),
                ResponseProfile::LinearIssues,
            )
        }
        Action::LinearWorkIssueDetail => {
            let input: IssueRequest =
                serde_json::from_str(input).map_err(|_| AdapterError::InvalidRequest)?;
            handle(&input.handle)?;
            let issue = identifier(&input.issue_id)?;
            (
                json!({
                    "query": format!(
                        "query Day2IssueDetail($issueId: String!) {{ issue(id: $issueId) {{ \
                         description comments(last: {ACTIVITY}) {{ nodes {{ body createdAt \
                         user {{ name displayName }} botActor {{ name }} }} }} \
                         history(last: {ACTIVITY}) {{ nodes {{ createdAt \
                         actor {{ name displayName }} botActor {{ name }} \
                         fromState {{ name }} toState {{ name }} \
                         fromAssignee {{ name displayName }} toAssignee {{ name displayName }} \
                         fromPriority toPriority fromDueDate toDueDate }} }} }} }}"
                    ),
                    "variables": {"issueId": issue},
                }),
                ResponseProfile::LinearIssueDetail,
            )
        }
        Action::LinearWorkAssignableUsers => {
            let input: IssueRequest =
                serde_json::from_str(input).map_err(|_| AdapterError::InvalidRequest)?;
            handle(&input.handle)?;
            let issue = identifier(&input.issue_id)?;
            (
                json!({
                    "query": format!(
                        "query Day2IssueAssignees($issueId: String!) {{ issue(id: $issueId) {{ \
                         id assignee {{ id }} team {{ id name \
                         members(first: {MEMBERS}, includeDisabled: false) \
                         {{ nodes {{ id name displayName email active }} }} }} }} }}"
                    ),
                    "variables": {"issueId": issue},
                }),
                ResponseProfile::LinearAssignableUsers,
            )
        }
        Action::LinearWorkReassign => {
            let input: ReassignRequest =
                serde_json::from_str(input).map_err(|_| AdapterError::InvalidRequest)?;
            handle(&input.handle)?;
            let issue = identifier(&input.issue_id)?;
            // Explicit null clears the owner. Omitting the variable would leave
            // the current assignee untouched, so the two must not be conflated.
            let assignee = if input.assignee_id.is_empty() {
                Value::Null
            } else {
                json!(identifier(&input.assignee_id)?)
            };
            (
                json!({
                    "query": "mutation Day2IssueReassign($issueId: String!, $assigneeId: String) \
                              { issueUpdate(id: $issueId, input: { assigneeId: $assigneeId }) \
                              { success issue { id assignee { id name displayName } } } }",
                    "variables": {"issueId": issue, "assigneeId": assignee},
                }),
                ResponseProfile::LinearReassign,
            )
        }
        _ => return Err(AdapterError::InvalidProfile),
    };
    Ok(PreparedCall {
        connection: connection.clone(),
        request: WireRequest::json(GRAPHQL, body.to_string().into_bytes()),
        response,
        response_limit: 0,
        reserved_monetary_microusd: Some(0),
    })
}

/// GraphQL answers 200 with an `errors` array, so a failure is not a status code.
fn data(json: &Value) -> Result<&Value, AdapterError> {
    if json
        .get("errors")
        .and_then(Value::as_array)
        .is_some_and(|errors| !errors.is_empty())
    {
        return Err(AdapterError::ProviderDenied);
    }
    json.get("data").ok_or(AdapterError::ResponseInvalid)
}

fn text(value: Option<&Value>) -> String {
    value.and_then(Value::as_str).unwrap_or_default().to_owned()
}

/// A Linear number, which is not always an integer.
///
/// Priority arrives as `2` on an issue and as `2.0` in a history entry — the same
/// value in two JSON shapes. Reading it only as an integer silently yields nothing
/// for every history entry, which is how a priority change becomes invisible
/// rather than wrong. Recorded provider responses are what showed this; a
/// simulation written against this adapter would have emitted whichever shape the
/// adapter already read.
fn number(value: Option<&Value>) -> i64 {
    let Some(value) = value else { return 0 };
    value
        .as_i64()
        .or_else(|| value.as_f64().map(|number| number as i64))
        .unwrap_or_default()
}

/// Days from the Unix epoch for `YYYY-MM-DD`, or `NO_DATE` when absent.
///
/// Linear reports a due date as a calendar date with no time and no zone, which
/// is what it means: an issue is due *on a day*, not at an instant. Keeping it as
/// a day number preserves that, where converting to an instant would invent a
/// midnight in some zone and make "due today" depend on which one.
pub(super) const NO_DATE: i64 = -1;

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    // Howard Hinnant's algorithm, the inverse of the one the object store signer
    // uses. Exact across the whole range and free of leap-year special cases.
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let month_prime = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * month_prime + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn date_parts(value: &str) -> Option<(i64, i64, i64)> {
    let bytes = value.as_bytes();
    if bytes.len() < 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let part = |range: std::ops::Range<usize>| value.get(range)?.parse::<i64>().ok();
    let (year, month, day) = (part(0..4)?, part(5..7)?, part(8..10)?);
    ((1..=12).contains(&month) && (1..=31).contains(&day)).then_some((year, month, day))
}

pub(super) fn date_days(value: &str) -> i64 {
    match date_parts(value) {
        Some((year, month, day)) => days_from_civil(year, month, day),
        None => NO_DATE,
    }
}

/// Milliseconds from the Unix epoch for an ISO-8601 instant, or `NO_DATE`.
///
/// Linear sends UTC (`...Z`). Fractional seconds are accepted and truncated;
/// anything else is refused rather than guessed, because a timestamp silently
/// read as zero would make every issue look decades stale.
pub(super) fn instant_ms(value: &str) -> i64 {
    let Some((year, month, day)) = date_parts(value) else {
        return NO_DATE;
    };
    let bytes = value.as_bytes();
    if bytes.len() < 20 || bytes[10] != b'T' || bytes[13] != b':' || bytes[16] != b':' {
        return NO_DATE;
    }
    let part = |range: std::ops::Range<usize>| value.get(range)?.parse::<i64>().ok();
    let (Some(hour), Some(minute), Some(second)) = (part(11..13), part(14..16), part(17..19))
    else {
        return NO_DATE;
    };
    if hour > 23 || minute > 59 || second > 60 {
        return NO_DATE;
    }
    let millis = value
        .split_once('.')
        .and_then(|(_, rest)| rest.get(..3)?.parse::<i64>().ok())
        .unwrap_or(0);
    days_from_civil(year, month, day) * 86_400_000
        + hour * 3_600_000
        + minute * 60_000
        + second * 1_000
        + millis
}

/// A person, projected to what an assignment decision needs.
fn person(value: Option<&Value>) -> Value {
    let Some(value) = value.filter(|value| value.is_object()) else {
        return json!({"id": "", "name": "", "email": ""});
    };
    let name = if value.get("displayName").and_then(Value::as_str).is_some() {
        text(value.get("displayName"))
    } else {
        text(value.get("name"))
    };
    json!({"id": text(value.get("id")), "name": name, "email": text(value.get("email"))})
}

pub(super) fn issues_response(json: &Value) -> Result<Value, AdapterError> {
    let data = data(json)?;
    // A view grant answers under `customView`, a label grant directly under
    // `issues`. Both shapes end at the same connection.
    let connection = data
        .get("customView")
        .and_then(|view| view.get("issues"))
        .or_else(|| data.get("issues"))
        .ok_or(AdapterError::ResponseInvalid)?;
    let nodes = connection
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or(AdapterError::ResponseInvalid)?;
    if nodes.len() > PAGE {
        return Err(AdapterError::ResponseInvalid);
    }
    let issues = nodes
        .iter()
        .map(|issue| {
            let state = issue.get("state");
            json!({
                "id": text(issue.get("id")),
                "identifier": text(issue.get("identifier")),
                "title": text(issue.get("title")),
                "url": text(issue.get("url")),
                "due_date": text(issue.get("dueDate")),
                "due_date_days": date_days(&text(issue.get("dueDate"))),
                "priority": number(issue.get("priority")),
                "priority_label": text(issue.get("priorityLabel")),
                "created_at_ms": instant_ms(&text(issue.get("createdAt"))),
                "updated_at_ms": instant_ms(&text(issue.get("updatedAt"))),
                "state_name": text(state.and_then(|state| state.get("name"))),
                "state_type": text(state.and_then(|state| state.get("type"))),
                "assignee": person(issue.get("assignee")),
                "parent_owner": person(
                    issue.get("parent").and_then(|parent| parent.get("assignee")),
                ),
                "project_owner": person(
                    issue.get("project").and_then(|project| project.get("lead")),
                ),
                "team_key": text(issue.get("team").and_then(|team| team.get("key"))),
                "team_name": text(issue.get("team").and_then(|team| team.get("name"))),
                "labels": issue
                    .get("labels")
                    .and_then(|labels| labels.get("nodes"))
                    .and_then(Value::as_array)
                    .map(|nodes| {
                        nodes.iter().map(|label| text(label.get("name"))).collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
                "attachment_urls": issue
                    .get("attachments")
                    .and_then(|attachments| attachments.get("nodes"))
                    .and_then(Value::as_array)
                    .map(|nodes| {
                        nodes.iter().map(|node| text(node.get("url"))).collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect::<Vec<_>>();
    let page = connection.get("pageInfo");
    Ok(json!({
        "issues": issues,
        // The cursor is only meaningful when there is another page; returning one
        // alongside has_more=false invites a caller to loop forever on the tail.
        "has_more": page
            .and_then(|page| page.get("hasNextPage"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "next_cursor": text(page.and_then(|page| page.get("endCursor"))),
    }))
}

pub(super) fn detail_response(json: &Value) -> Result<Value, AdapterError> {
    let issue = data(json)?
        .get("issue")
        .filter(|issue| issue.is_object())
        .ok_or(AdapterError::ResponseInvalid)?;
    let entries = |key: &str, map: &dyn Fn(&Value) -> Value| -> Vec<Value> {
        issue
            .get(key)
            .and_then(|node| node.get("nodes"))
            .and_then(Value::as_array)
            .map(|nodes| nodes.iter().take(ACTIVITY).map(map).collect())
            .unwrap_or_default()
    };
    let actor = |entry: &Value, key: &str| -> String {
        let bot = text(entry.get("botActor").and_then(|bot| bot.get("name")));
        if bot.is_empty() {
            let value = person(entry.get(key));
            text(value.get("name"))
        } else {
            bot
        }
    };
    Ok(json!({
        "description": text(issue.get("description")),
        "comments": entries(
            "comments",
            &|entry| json!({
                "body": text(entry.get("body")),
                "occurred_at": text(entry.get("createdAt")),
                "actor": actor(entry, "user"),
            }),
        ),
        "history": entries(
            "history",
            &|entry| json!({
                "occurred_at": text(entry.get("createdAt")),
                "actor": actor(entry, "actor"),
                "from_state": text(entry.get("fromState").and_then(|state| state.get("name"))),
                "to_state": text(entry.get("toState").and_then(|state| state.get("name"))),
                "from_assignee": text(
                    person(entry.get("fromAssignee")).get("name"),
                ),
                "to_assignee": text(person(entry.get("toAssignee")).get("name")),
                "from_due_date": text(entry.get("fromDueDate")),
                "to_due_date": text(entry.get("toDueDate")),
                // The source's domain models a priority change as its own kind of
                // activity, so dropping it here would lose a change the queue is
                // meant to show.
                "from_priority": number(entry.get("fromPriority")),
                "to_priority": number(entry.get("toPriority")),
            }),
        ),
    }))
}

pub(super) fn assignees_response(json: &Value) -> Result<Value, AdapterError> {
    let issue = data(json)?
        .get("issue")
        .filter(|issue| issue.is_object())
        .ok_or(AdapterError::ResponseInvalid)?;
    let team = issue.get("team");
    let members = team
        .and_then(|team| team.get("members"))
        .and_then(|members| members.get("nodes"))
        .and_then(Value::as_array)
        .ok_or(AdapterError::ResponseInvalid)?;
    if members.len() > MEMBERS {
        return Err(AdapterError::ResponseInvalid);
    }
    Ok(json!({
        "team_name": text(team.and_then(|team| team.get("name"))),
        "current_assignee_id": text(
            issue.get("assignee").and_then(|assignee| assignee.get("id")),
        ),
        "members": members
            .iter()
            // A disabled member cannot own work, and offering one as a candidate
            // produces a reassignment the provider will refuse.
            .filter(|member| member.get("active").and_then(Value::as_bool).unwrap_or(true))
            .map(|member| person(Some(member)))
            .collect::<Vec<_>>(),
    }))
}

pub(super) fn reassign_response(json: &Value) -> Result<Value, AdapterError> {
    let payload = data(json)?
        .get("issueUpdate")
        .filter(|payload| payload.is_object())
        .ok_or(AdapterError::ResponseInvalid)?;
    if !payload
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(AdapterError::ProviderDenied);
    }
    let assignee = payload.get("issue").and_then(|issue| issue.get("assignee"));
    // A cleared assignee is success with no owner, not a failure to report one.
    Ok(json!({"assignee": person(assignee)}))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Responses recorded against the real Linear API by the service this
    /// migration replaces, taken from its own adapter tests.
    ///
    /// This is the base the simulation cannot supply. A simulation written
    /// alongside this adapter emits whatever shapes the adapter already reads, so
    /// the two agree about a misreading and the coverage gate passes while the
    /// live call returns something else. These fixtures come from a different
    /// team writing against the actual provider, and they immediately showed two
    /// things this adapter had wrong: history priorities arrive as decimals, and
    /// a priority change is an activity the projection was dropping.
    const RECORDED_ISSUE_PAGE: &str = r##"{
      "data": { "customView": { "issues": {
        "nodes": [{
          "id": "linear-1", "identifier": "OPS-1", "title": "Linear fixture",
          "url": "https://linear.app/exampleco/issue/OPS-1",
          "dueDate": null, "priority": 2, "priorityLabel": "High",
          "createdAt": "2026-01-05T20:00:00Z", "updatedAt": "2026-01-10T20:00:00Z",
          "state": { "name": "In Progress", "type": "started" },
          "assignee": { "name": "Scott", "email": "scott@example.test" },
          "parent": { "assignee": { "displayName": "Parent owner" } },
          "project": { "lead": { "email": "project.lead@example.test" } },
          "team": { "key": "OPS", "name": "Operations" },
          "labels": { "nodes": [
            { "name": "No due date: Customer approval", "color": "#F2C94C" },
            { "name": "Product Owners Standup", "color": "#5E6AD2" } ] },
          "attachments": { "nodes": [
            { "title": "Slack source", "url": "https://exampleco.slack.com/archives/C123/p1" } ] }
        }],
        "pageInfo": { "hasNextPage": false, "endCursor": null }
      } } }
    }"##;

    const RECORDED_DETAIL: &str = r###"{
      "data": { "issue": {
        "description": "## Reproduction",
        "comments": { "nodes": [
          { "body": "Newest comment", "createdAt": "2026-02-01T12:00:00Z",
            "user": null, "botActor": { "name": "Comment Bot" } },
          { "body": "Comment five", "createdAt": "2026-02-01T05:00:00Z",
            "user": { "email": "commenter@example.test" } },
          { "body": "Comment four", "createdAt": "2026-02-01T04:00:00Z" } ] },
        "history": { "nodes": [
          { "createdAt": "2026-02-01T11:00:00Z",
            "actor": { "displayName": "History User" },
            "fromState": { "name": "Todo" }, "toState": { "name": "In Progress" } },
          { "createdAt": "2026-02-01T10:00:00Z",
            "botActor": { "name": "Workflow Bot" },
            "fromAssignee": null, "toAssignee": { "name": "Alex" } },
          { "createdAt": "2026-02-01T09:00:00Z",
            "fromPriority": 2.0, "toPriority": 1.0 },
          { "createdAt": "2026-02-01T08:00:00Z",
            "fromDueDate": null, "toDueDate": "2026-02-14" } ] }
      } }
    }"###;

    fn parse(raw: &str) -> Value {
        serde_json::from_str(raw).expect("recorded response parses")
    }

    #[test]
    fn a_recorded_issue_page_projects_without_losing_its_fields() {
        let page = issues_response(&parse(RECORDED_ISSUE_PAGE)).expect("projected");
        let issue = &page["issues"][0];
        assert_eq!(issue["identifier"], "OPS-1");
        assert_eq!(issue["priority"], 2);
        assert_eq!(issue["state_type"], "started");
        // A null due date is empty rather than absent: an issue with no due date
        // is exactly what one of the compliance policies looks for.
        assert_eq!(issue["due_date"], "");
        // displayName where there is one, name where there is not.
        assert_eq!(issue["parent_owner"]["name"], "Parent owner");
        assert_eq!(issue["assignee"]["name"], "Scott");
        assert_eq!(issue["labels"][1], "Product Owners Standup");
        assert_eq!(page["has_more"], false);
        // A null endCursor must not become the string "null".
        assert_eq!(page["next_cursor"], "");
    }

    #[test]
    fn a_recorded_history_entry_keeps_its_priority_change() {
        let detail = detail_response(&parse(RECORDED_DETAIL)).expect("projected");
        // Decimal in the recorded response, whole number here. Reading it only as
        // an integer yields 0 for both, which is what this pins.
        let priority = &detail["history"][2];
        assert_eq!(priority["from_priority"], 2);
        assert_eq!(priority["to_priority"], 1);
        // A bot actor stands in for an absent user rather than blanking the actor.
        assert_eq!(detail["comments"][0]["actor"], "Comment Bot");
        // A comment with no `user` key at all is not a parse failure.
        assert_eq!(detail["comments"][2]["body"], "Comment four");
        assert_eq!(detail["history"][0]["actor"], "History User");
        assert_eq!(detail["history"][1]["to_assignee"], "Alex");
        assert_eq!(detail["history"][3]["to_due_date"], "2026-02-14");
    }

    #[test]
    fn a_graphql_error_is_a_refusal_rather_than_an_empty_result() {
        // GraphQL answers 200 with an errors array, so a failure here is not a
        // status code and an adapter reading only `data` would report success
        // with nothing in it.
        let refused = parse(r#"{"errors":[{"message":"Access denied"}],"data":null}"#);
        assert_eq!(
            issues_response(&refused).unwrap_err(),
            AdapterError::ProviderDenied
        );
        assert_eq!(
            reassign_response(&refused).unwrap_err(),
            AdapterError::ProviderDenied
        );
    }

    #[test]
    fn a_refused_reassignment_is_not_reported_as_a_move() {
        let refused = parse(r#"{"data":{"issueUpdate":{"success":false,"issue":null}}}"#);
        assert_eq!(
            reassign_response(&refused).unwrap_err(),
            AdapterError::ProviderDenied
        );
        // Clearing an owner succeeds with no assignee, which is a move rather
        // than a failure to report one.
        let cleared = parse(
            r#"{"data":{"issueUpdate":{"success":true,
            "issue":{"id":"linear-1","assignee":null}}}}"#,
        );
        let value = reassign_response(&cleared).expect("cleared");
        assert_eq!(value["assignee"]["id"], "");
    }
}

#[cfg(test)]
mod dates {
    use super::*;

    /// Both fixtures' own timestamps, which is the point: the format under test
    /// is the one the provider actually sends, not one chosen here.
    #[test]
    fn recorded_timestamps_and_due_dates_become_numbers() {
        // "2026-01-05T20:00:00Z" from the recorded issue page.
        assert_eq!(instant_ms("2026-01-05T20:00:00Z"), 1_767_643_200_000);
        // "2026-02-14" from the recorded history entry.
        assert_eq!(date_days("2026-02-14"), 20_498);
        // Round-trips against the day-number arithmetic the object store signer
        // already validates in the other direction.
        assert_eq!(date_days("1970-01-01"), 0);
        assert_eq!(date_days("2024-02-29"), 19_782);
        assert_eq!(instant_ms("1970-01-01T00:00:00Z"), 0);
        // Fractional seconds are truncated rather than refused: Linear sends them.
        assert_eq!(instant_ms("2026-01-05T20:00:00.250Z"), 1_767_643_200_250);
    }

    #[test]
    fn an_absent_or_malformed_date_is_refused_rather_than_read_as_the_epoch() {
        // The failure this prevents is the quiet one. Zero is a real instant, so a
        // timestamp that failed to parse and became 0 would make an issue look
        // fifty-six years stale and trip every staleness policy at once.
        for absent in ["", "null", "not-a-date", "2026-13-01", "2026-01-32"] {
            assert_eq!(date_days(absent), NO_DATE, "{absent:?}");
            assert_eq!(instant_ms(absent), NO_DATE, "{absent:?}");
        }
        // A date alone is a date, not an instant.
        assert_eq!(date_days("2026-02-14"), 20_498);
        assert_eq!(instant_ms("2026-02-14"), NO_DATE);
    }
}
