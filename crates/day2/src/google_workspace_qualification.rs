//! Operator-run live Google Workspace qualification. Never part of
//! verification and never reached by an application: the private
//! `ops/GoogleWorkspaceQualification.roc` recipe, run by `xtask
//! google-workspace-qualify`, drives one [`Qualification`] through its steps.
//!
//! Every probe is an ordinary action, planned by the same [`Plan::authorize`]
//! the host calls and run by [`google_workspace::observe`] through a port: the
//! native port in a live run, the simulated one in tests. Between the adapter
//! and that port a recording layer keeps only closed classifications of what
//! Google sent (statuses, byte counts, reviewed error reasons, counts of
//! reviewed field forms) and fences writes: the read probes may send none, the
//! share probe one, and every later probe none, so a run creates at most one
//! permission whatever the adapter does. The receipt names each fixture by its
//! role in the profile and carries the profile's digest. It never holds an
//! address, ID, token or other provider value, and it reports
//! `provider_qualified: false` until a reviewer accepts it.
//!
//! An operator's machine has no metadata server. The run's workload token is
//! the operator's own short-lived access token, which the session reads from an
//! owner-private file and hands to [`Qualification::native`]. The private
//! [`OperatorWorkload`] port answers the metadata exchange with it and passes
//! every other exchange through unchanged, so IAM `generateAccessToken` and
//! `signJwt` and the JWT-bearer exchange run exactly as they do in the runtime.
//! Nothing outside this module can build that port, and nothing in it can run
//! anything but the fixed probes below.
use crate::google_auth::{AccessToken, Exchange, IamMethod, Reply, Unreached};
use crate::google_workspace::{
    self as workspace, ApiRequest, Failure, GooglePort, Meter, Plan, Source,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    integrations::LiveConnection, registry::Action, resources::ResourceTarget,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// What an operator reviewed before a run: the grant, and the live fixtures
/// named by their role. See docs/GOOGLE-WORKSPACE.md, "Live fixture setup".
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationProfile {
    pub format: u32,
    pub service_account: String,
    pub calendar_reader: String,
    pub email_domain: String,
    pub grantee_domains: Vec<String>,
    pub calendars: Calendars,
    pub window: Window,
    pub events: Events,
    pub group: String,
    pub group_alias: String,
    pub group_member: String,
    /// An artifact of `events.recorded`, generated and not yet shared with
    /// `group`.
    pub artifact: String,
    /// Unix seconds after which this profile no longer authorizes a run.
    pub expires_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Calendars {
    /// The reader holds its own `writer` rule.
    pub in_play: String,
    /// Shared with the reader as free/busy only.
    pub free_busy: String,
    /// The reader has no access at all.
    pub unshared: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub time_min: String,
    pub time_max: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Events {
    /// Created on `in_play` by a person in the domain, with a recorded Meet.
    pub recorded: String,
    /// Imported on `in_play` naming another in-domain person as organizer.
    pub imported: String,
}

/// A profile authorizes a run for at most a week.
const MAX_PROFILE_HORIZON_SECONDS: i64 = 7 * 86_400;
/// Events pages followed through the adapter.
const MAX_EVENT_PAGES: u64 = 4;
/// Seconds waited before each check that the created permission is listed.
const VISIBILITY_DELAYS: [u64; 7] = [0, 1, 2, 4, 8, 16, 32];
const HANDLE: &str = "qualification";

/// The mandatory profile guard, checked before the token is read and again
/// before anything is sent: a supported format, an unexpired authorization at
/// most a week out, distinct fixtures, and every probe's request authorized by
/// the adapter's own rules.
pub fn admit(profile: &QualificationProfile, now: i64) -> Result<()> {
    ensure!(
        profile.format == 1,
        "google_workspace_qualification_profile_format"
    );
    ensure!(
        now < profile.expires_at && profile.expires_at - now <= MAX_PROFILE_HORIZON_SECONDS,
        "google_workspace_qualification_profile_expired"
    );
    let calendars = &profile.calendars;
    ensure!(
        calendars.in_play != calendars.free_busy
            && calendars.in_play != calendars.unshared
            && calendars.free_busy != calendars.unshared
            && profile.events.recorded != profile.events.imported
            && profile.group != profile.group_alias
            && profile.group != profile.group_member,
        "google_workspace_qualification_profile_invalid"
    );
    reads(profile, Source::Native)?;
    plan(
        profile,
        Source::Native,
        Action::GoogleWorkspaceShareArtifact,
        share_request(profile, &profile.group),
    )?;
    Ok(())
}

fn plan(
    profile: &QualificationProfile,
    source: Source,
    action: Action,
    request: Value,
) -> Result<Plan> {
    Plan::authorize(
        action,
        &LiveConnection::GoogleWorkspace {
            service_account: profile.service_account.clone(),
        },
        &ResourceTarget::GoogleWorkspaceDomain {
            calendar_reader: profile.calendar_reader.clone(),
            email_domain: profile.email_domain.clone(),
            grantee_domains: profile.grantee_domains.clone(),
        },
        &request.to_string(),
        source,
    )
    .map(|(plan, _)| plan)
    .context("google_workspace_qualification_profile_invalid")
}

fn share_request(profile: &QualificationProfile, group: &str) -> Value {
    json!({"handle":HANDLE,"calendar_id":profile.calendars.in_play,
        "event_id":profile.events.recorded,"artifact":profile.artifact,"group_email":group})
}

fn events_request(
    profile: &QualificationProfile,
    time_max: &str,
    page_token: Option<&str>,
) -> Value {
    json!({"handle":HANDLE,"calendar_id":profile.calendars.in_play,
        "time_min":profile.window.time_min,"time_max":time_max,
        "page_token":page_token.map_or(json!("None"), |token| json!({"Some":token}))})
}

/// The fixed read probes, in order, each with its reviewed name. Events
/// pages after the first and the token-binding probe depend on the first
/// page, so they are planned as they run.
fn reads(profile: &QualificationProfile, source: Source) -> Result<Vec<(&'static str, Plan)>> {
    let calendars = &profile.calendars;
    let event = |id: &str| json!({"handle":HANDLE,"calendar_id":calendars.in_play,"event_id":id});
    let calendar = |id: &str| json!({"handle":HANDLE,"calendar_id":id,"group_email":profile.group});
    let group = |address: &str| json!({"handle":HANDLE,"group_email":address});
    [
        ("directory_group", Action::GoogleWorkspaceGroup, group(&profile.group)),
        ("directory_group_alias", Action::GoogleWorkspaceGroup, group(&profile.group_alias)),
        (
            "directory_group_member",
            Action::GoogleWorkspaceGroupMember,
            json!({"handle":HANDLE,"group_email":profile.group,"member_email":profile.group_member}),
        ),
        ("calendar_in_play", Action::GoogleWorkspaceCalendar, calendar(&calendars.in_play)),
        ("calendar_free_busy", Action::GoogleWorkspaceCalendar, calendar(&calendars.free_busy)),
        ("calendar_unshared", Action::GoogleWorkspaceCalendar, calendar(&calendars.unshared)),
        (
            "events_page",
            Action::GoogleWorkspaceCalendarEvents,
            events_request(profile, &profile.window.time_max, None),
        ),
        ("event_recorded", Action::GoogleWorkspaceCalendarEvent, event(&profile.events.recorded)),
        ("event_imported", Action::GoogleWorkspaceCalendarEvent, event(&profile.events.imported)),
        (
            "conferences_recorded",
            Action::GoogleWorkspaceEventConferences,
            event(&profile.events.recorded),
        ),
        (
            "conferences_imported",
            Action::GoogleWorkspaceEventConferences,
            event(&profile.events.imported),
        ),
        // The alias is refused before any owner token: fenced, it can never
        // reach Drive.
        (
            "share_alias",
            Action::GoogleWorkspaceShareArtifact,
            share_request(profile, &profile.group_alias),
        ),
    ]
    .into_iter()
    .map(|(name, action, request)| Ok((name, plan(profile, source, action, request)?)))
    .collect()
}

/// The operator's access token standing in for the metadata server's workload
/// token: the metadata exchange is answered with it and nothing else is
/// changed. Private, built only by [`Qualification::native`] and the
/// simulated constructor, and never printable.
struct OperatorWorkload<P> {
    inner: P,
    token: String,
}

impl<P: GooglePort> GooglePort for OperatorWorkload<P> {
    fn authenticate(
        &mut self,
        exchange: &Exchange<'_>,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Unreached> {
        match exchange {
            Exchange::Metadata => Ok(Reply {
                status: 200,
                metadata_flavor: true,
                json: true,
                body: json!({"access_token":self.token,"token_type":"Bearer"})
                    .to_string()
                    .into_bytes(),
                retry_after_seconds: None,
            }),
            other => self.inner.authenticate(other, max_bytes),
        }
    }

    fn call(
        &mut self,
        request: &ApiRequest,
        token: &AccessToken,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Unreached> {
        self.inner.call(request, token, max_bytes)
    }
}

/// One exchange as closed classifications: never a body, header or value.
#[derive(Debug, Default, Serialize)]
struct Recorded {
    endpoint: &'static str,
    http_status: Option<u16>,
    response_bytes: u64,
    /// No complete reply arrived.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    incomplete: bool,
    /// A write the fence refused: it was never sent.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    fenced: bool,
    /// Reviewed error reasons and statuses, and counts of reviewed forms.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    shape: BTreeMap<&'static str, u64>,
}

/// Error reasons, statuses and OAuth error codes a receipt may name. Anything
/// else is counted as `reason_other`.
const REASONS: &[&str] = &[
    "ACCESS_TOKEN_SCOPE_INSUFFICIENT",
    "ALREADY_EXISTS",
    "FAILED_PRECONDITION",
    "IAM_PERMISSION_DENIED",
    "INVALID_ARGUMENT",
    "NOT_FOUND",
    "PERMISSION_DENIED",
    "RATE_LIMIT_EXCEEDED",
    "RESOURCE_EXHAUSTED",
    "RESOURCE_QUOTA_EXCEEDED",
    "SERVICE_DISABLED",
    "UNAUTHENTICATED",
    "accessNotConfigured",
    "authError",
    "badRequest",
    "conflict",
    "dailyLimitExceeded",
    "duplicate",
    "forbidden",
    "insufficientFilePermissions",
    "insufficientPermissions",
    "invalid",
    "invalidSharingRequest",
    "invalid_grant",
    "invalid_request",
    "notFound",
    "quotaExceeded",
    "rateLimitExceeded",
    "required",
    "sharingRateLimitExceeded",
    "unauthorized_client",
    "userRateLimitExceeded",
];
const CONFERENCE_TYPES: &[(&str, &str)] = &[
    ("hangoutsMeet", "conference_hangouts_meet"),
    ("addOn", "conference_add_on"),
    ("eventHangout", "conference_event_hangout"),
    ("eventNamedHangout", "conference_event_named_hangout"),
];
const PERMISSION_TYPES: &[(&str, &str)] = &[
    ("user", "type_user"),
    ("group", "type_group"),
    ("domain", "type_domain"),
    ("anyone", "type_anyone"),
];
const ROLES: &[(&str, &str)] = &[
    ("owner", "role_owner"),
    ("organizer", "role_organizer"),
    ("fileOrganizer", "role_file_organizer"),
    ("writer", "role_writer"),
    ("commenter", "role_commenter"),
    ("reader", "role_reader"),
];
const STATES: &[(&str, &str)] = &[
    ("STARTED", "state_started"),
    ("ENDED", "state_ended"),
    ("FILE_GENERATED", "state_file_generated"),
];

fn known(table: &[(&str, &'static str)], value: Option<&str>, other: &'static str) -> &'static str {
    table
        .iter()
        .find(|(name, _)| Some(*name) == value)
        .map_or(other, |(_, key)| *key)
}

/// Meet IDs the adapter accepts: at most 128 letters, digits, `-` and `_`.
fn bounded_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
}

fn count(shape: &mut BTreeMap<&'static str, u64>, key: &'static str) {
    *shape.entry(key).or_default() += 1;
}

/// Counts of reviewed forms in a reply body, by endpoint. Each key is a
/// constant; each value a count.
fn classify(
    endpoint: &str,
    status: u16,
    body: &Value,
    request: Option<&ApiRequest>,
) -> BTreeMap<&'static str, u64> {
    let mut shape = BTreeMap::new();
    if status >= 400 {
        let error = &body["error"];
        let reasons = error["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|item| item["reason"].as_str())
            .chain(
                error["details"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|detail| detail["reason"].as_str()),
            )
            .chain([error["status"].as_str(), body["error"].as_str()])
            .flatten();
        for reason in reasons {
            count(
                &mut shape,
                REASONS
                    .iter()
                    .find(|known| **known == reason)
                    .copied()
                    .unwrap_or("reason_other"),
            );
        }
        return shape;
    }
    let items = match endpoint {
        "calendar_events" | "calendar_acl" => "items",
        "meet_conference_records" => "conferenceRecords",
        "meet_recordings" => "recordings",
        "meet_transcripts" => "transcripts",
        "meet_smart_notes" => "smartNotes",
        "drive_permissions" => "permissions",
        _ => "",
    };
    if let Some(items) = body.get(items).and_then(Value::as_array) {
        shape.insert("items", items.len() as u64);
    }
    match body.get("nextPageToken") {
        Some(Value::String(token)) if token.is_empty() => {
            count(&mut shape, "next_page_token_empty")
        }
        Some(Value::String(_)) => count(&mut shape, "next_page_token_present"),
        Some(_) => count(&mut shape, "next_page_token_other"),
        None => {}
    }
    let list = |name: &str| body[name].as_array().cloned().unwrap_or_default();
    let artifact = |shape: &mut BTreeMap<&'static str, u64>, item: &Value| {
        count(shape, known(STATES, item["state"].as_str(), "state_other"));
        let destination = item["driveDestination"]["file"]
            .as_str()
            .or(item["docsDestination"]["document"].as_str());
        count(
            shape,
            match destination {
                None => "destination_absent",
                Some(id) if id.starts_with("files/") || id.starts_with("documents/") => {
                    "destination_prefixed"
                }
                Some(id) if bounded_id(id) => "destination_bare",
                Some(_) => "destination_other",
            },
        );
        let id = item["name"]
            .as_str()
            .and_then(|name| name.rsplit('/').next())
            .unwrap_or_default();
        if !bounded_id(id) {
            count(shape, "ids_outside_bound");
        }
    };
    match endpoint {
        "calendar_events" => {
            for item in list("items") {
                match item["status"].as_str() {
                    None => count(&mut shape, "id_only"),
                    Some("cancelled") => count(&mut shape, "cancelled"),
                    Some(_) => {}
                }
                if item["start"]["date"].is_string() {
                    count(&mut shape, "all_day");
                }
                if let Some(visibility @ ("private" | "confidential")) = item["visibility"].as_str()
                {
                    count(
                        &mut shape,
                        if visibility == "private" {
                            "private"
                        } else {
                            "confidential"
                        },
                    );
                }
                let kind = item["conferenceData"]["conferenceSolution"]["key"]["type"].as_str();
                if kind.is_some() {
                    count(
                        &mut shape,
                        known(CONFERENCE_TYPES, kind, "conference_other"),
                    );
                }
                if item["hangoutLink"].is_string() {
                    count(
                        &mut shape,
                        if kind.is_some() {
                            "hangout_link"
                        } else {
                            "hangout_link_without_conference"
                        },
                    );
                }
            }
        }
        "meet_conference_records" => {
            for item in list("conferenceRecords") {
                let id = item["name"]
                    .as_str()
                    .and_then(|name| name.strip_prefix("conferenceRecords/"));
                let space = item["space"]
                    .as_str()
                    .and_then(|name| name.strip_prefix("spaces/"));
                if !(id.is_some_and(bounded_id) && space.is_some_and(bounded_id)) {
                    count(&mut shape, "ids_outside_bound");
                }
            }
        }
        "meet_recordings" | "meet_transcripts" | "meet_smart_notes" => {
            for item in list(items) {
                artifact(&mut shape, &item);
            }
        }
        "meet_artifact" => artifact(&mut shape, body),
        "drive_permissions" => {
            for item in list("permissions") {
                count(
                    &mut shape,
                    known(PERMISSION_TYPES, item["type"].as_str(), "type_other"),
                );
                count(
                    &mut shape,
                    known(ROLES, item["role"].as_str(), "role_other"),
                );
                if item["deleted"] == true {
                    count(&mut shape, "deleted");
                }
            }
        }
        "drive_permission_create" => {
            let sent: Value = request
                .and_then(ApiRequest::body)
                .and_then(|body| serde_json::from_str(body).ok())
                .unwrap_or_default();
            let (sent, echoed) = (sent["emailAddress"].as_str(), body["emailAddress"].as_str());
            count(
                &mut shape,
                if body["type"] == "group" {
                    "echo_type_group"
                } else {
                    "echo_type_other"
                },
            );
            count(
                &mut shape,
                if body["role"] == "reader" {
                    "echo_role_reader"
                } else {
                    "echo_role_other"
                },
            );
            count(
                &mut shape,
                match (sent, echoed) {
                    (Some(sent), Some(echoed)) if sent == echoed => "echo_address_exact",
                    (Some(sent), Some(echoed)) if sent.eq_ignore_ascii_case(echoed) => {
                        "echo_address_case_only"
                    }
                    (_, None) => "echo_address_absent",
                    _ => "echo_address_other",
                },
            );
        }
        _ => {}
    }
    shape
}

/// Records each exchange and fences writes. `writes` is how many creates the
/// running probe may still send; any other is refused here, unsent.
struct Recording {
    inner: Box<dyn GooglePort>,
    exchanges: Vec<Recorded>,
    writes: u8,
    creates_sent: u64,
    creates_fenced: u64,
}

impl Recording {
    fn record(
        &mut self,
        endpoint: &'static str,
        reply: &std::result::Result<Reply, Unreached>,
        request: Option<&ApiRequest>,
    ) {
        self.exchanges.push(match reply {
            Ok(reply) => Recorded {
                endpoint,
                http_status: Some(reply.status),
                response_bytes: reply.body.len() as u64,
                // Authentication bodies hold tokens: only a refusal's OAuth or
                // IAM reason is read.
                shape: serde_json::from_slice::<Value>(&reply.body)
                    .ok()
                    .filter(|_| request.is_some() || reply.status >= 400)
                    .map(|body| classify(endpoint, reply.status, &body, request))
                    .unwrap_or_default(),
                ..Recorded::default()
            },
            Err(unreached) => Recorded {
                endpoint,
                http_status: unreached.http_status,
                response_bytes: unreached.response_bytes,
                incomplete: true,
                ..Recorded::default()
            },
        });
    }
}

impl GooglePort for Recording {
    fn authenticate(
        &mut self,
        exchange: &Exchange<'_>,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Unreached> {
        let endpoint = match exchange {
            Exchange::Metadata => "metadata",
            Exchange::Iam {
                method: IamMethod::GenerateAccessToken,
                ..
            } => "iam_generate_access_token",
            Exchange::Iam {
                method: IamMethod::SignJwt,
                ..
            } => "iam_sign_jwt",
            Exchange::Token { .. } => "oauth_token",
        };
        let reply = self.inner.authenticate(exchange, max_bytes);
        self.record(endpoint, &reply, None);
        reply
    }

    fn call(
        &mut self,
        request: &ApiRequest,
        token: &AccessToken,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Unreached> {
        if request.body().is_some() {
            if self.writes == 0 {
                self.creates_fenced += 1;
                self.exchanges.push(Recorded {
                    endpoint: request.endpoint,
                    fenced: true,
                    ..Recorded::default()
                });
                return Err(Unreached::default());
            }
            self.writes -= 1;
            self.creates_sent += 1;
        }
        let reply = self.inner.call(request, token, max_bytes);
        self.record(request.endpoint, &reply, Some(request));
        reply
    }
}

/// Every outcome tag and failure code a probe may report.
const OUTCOMES: &[&str] = &[
    "AllDay",
    "AlreadyShared",
    "Conflict",
    "Found",
    "GroupNotFound",
    "GroupNotPrimary",
    "Member",
    "NoMeeting",
    "NoOwner",
    "NotFound",
    "NotMember",
    "NotReady",
    "NotShared",
    "Shared",
    "SharingRefused",
];

/// The outcome's tag, a stable failure code, or `other`: always a constant.
fn tag(result: &Result<String>) -> (&'static str, Value) {
    match result {
        Ok(json) => {
            let value: Value = serde_json::from_str(json).unwrap_or_default();
            let name = value.as_str().or_else(|| {
                value
                    .as_object()
                    .and_then(|map| map.keys().next())
                    .map(String::as_str)
            });
            let tag = OUTCOMES
                .iter()
                .find(|known| Some(**known) == name)
                .copied()
                .unwrap_or("other_outcome");
            let inner = value
                .as_object()
                .and_then(|map| map.values().next())
                .cloned()
                .unwrap_or_default();
            (tag, inner)
        }
        Err(error) => {
            let code = error.to_string();
            let code = Failure::ALL
                .iter()
                .map(|failure| failure.code())
                .find(|known| *known == code);
            (code.unwrap_or("other_error"), Value::Null)
        }
    }
}

fn text(value: &Value) -> Option<&str> {
    value["Some"]
        .as_str()
        .or(value.as_str().filter(|text| *text != "None"))
}

#[derive(Serialize)]
struct Entry {
    probe: &'static str,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Map::is_empty")]
    details: Map<String, Value>,
    calls: u64,
    request_bytes: u64,
    response_bytes: u64,
    exchanges: Vec<Recorded>,
}

/// One qualification run: the read probes, then the one write and its
/// visibility checks, then the receipt.
pub struct Qualification {
    profile: QualificationProfile,
    source: Source,
    port: OperatorWorkload<Recording>,
    entries: Vec<Entry>,
    /// Provider values one probe needs from another; dropped with the run.
    permission: Option<String>,
    visible_after_seconds: Option<u64>,
    /// [`VISIBILITY_DELAYS`]; shorter in tests.
    delays: &'static [u64],
    read: bool,
    shared: bool,
    started: i64,
}

impl Qualification {
    /// A live run through the native port, with `token` as the workload.
    pub fn native(profile: QualificationProfile, token: String) -> Result<Self> {
        let port = crate::google_workspace_http::NativeGooglePort::new()?;
        Self::new(profile, token, Source::Native, Box::new(port))
    }

    /// A run against the provider's committed simulated world, through the
    /// same probes and fences.
    pub fn simulated(
        profile: QualificationProfile,
        token: String,
        database: &std::path::Path,
        scope: &str,
    ) -> Result<Self> {
        let port = workspace::SimulatedGooglePort::new(database, scope)?;
        Self::new(profile, token, Source::Simulated, Box::new(port))
    }

    fn new(
        profile: QualificationProfile,
        token: String,
        source: Source,
        inner: Box<dyn GooglePort>,
    ) -> Result<Self> {
        let started = crate::oauth::effects::wall_time()?;
        admit(&profile, started)?;
        ensure!(
            (1..=8192).contains(&token.len()) && token.bytes().all(|byte| byte.is_ascii_graphic()),
            "google_workspace_qualification_token_invalid"
        );
        Ok(Self {
            profile,
            source,
            port: OperatorWorkload {
                inner: Recording {
                    inner,
                    exchanges: Vec::new(),
                    writes: 0,
                    creates_sent: 0,
                    creates_fenced: 0,
                },
                token,
            },
            entries: Vec::new(),
            permission: None,
            visible_after_seconds: None,
            delays: &VISIBILITY_DELAYS,
            read: false,
            shared: false,
            started,
        })
    }

    /// Run one probe with `writes` creates allowed, and record it.
    fn probe(
        &mut self,
        name: &'static str,
        plan: &Plan,
        writes: u8,
    ) -> Result<(&'static str, Value, bool)> {
        self.port.inner.writes = writes;
        let (result, meter): (Result<String>, Meter) =
            workspace::observe(plan, &mut self.port, crate::oauth::effects::wall_time()?);
        self.port.inner.writes = 0;
        let exchanges = std::mem::take(&mut self.port.inner.exchanges);
        let fenced = exchanges.iter().any(|exchange| exchange.fenced);
        let (outcome, value) = tag(&result);
        self.entries.push(Entry {
            probe: name,
            outcome,
            details: Map::new(),
            calls: meter.calls,
            request_bytes: meter.request_bytes,
            response_bytes: meter.response_bytes,
            exchanges,
        });
        Ok((outcome, value, fenced))
    }

    fn detail(&mut self, name: &'static str, value: Value) {
        if let Some(entry) = self.entries.last_mut() {
            entry.details.insert(name.to_owned(), value);
        }
    }

    /// Every read probe, in order. Nothing is written: the fence refuses any
    /// create, so the alias probe cannot reach Drive whatever Google answers.
    pub fn read(&mut self) -> Result<Value> {
        ensure!(!self.read, "google_workspace_qualification_step_replayed");
        self.read = true;
        let profile = self.profile.clone();
        let organizer_kind = |organizer: Option<&str>, creator: Option<&str>| -> &'static str {
            match organizer {
                None => "absent",
                Some(organizer) if Some(organizer) == creator => "creator",
                Some(organizer) if organizer.ends_with("@group.calendar.google.com") => {
                    "group_calendar"
                }
                Some(organizer) if organizer.ends_with("@resource.calendar.google.com") => {
                    "resource_calendar"
                }
                Some(organizer) if organizer.ends_with(&format!("@{}", profile.email_domain)) => {
                    "person_in_domain"
                }
                Some(_) => "person_elsewhere",
            }
        };
        for (name, plan) in reads(&profile, self.source)? {
            let (outcome, value, _) = self.probe(name, &plan, 0)?;
            match name {
                "directory_group" | "directory_group_alias" if outcome == "Found" => {
                    let email = value["email"].as_str();
                    self.detail(
                        "primary_is_group",
                        json!(email == Some(profile.group.as_str())),
                    );
                    self.detail(
                        "primary_is_alias",
                        json!(email == Some(profile.group_alias.as_str())),
                    );
                }
                "calendar_in_play" | "calendar_free_busy" | "calendar_unshared"
                    if outcome == "Found" =>
                {
                    let role = ["None", "FreeBusyReader", "Reader", "Writer", "Owner"]
                        .into_iter()
                        .find(|role| value["group_role"] == *role)
                        .unwrap_or("other");
                    self.detail("group_role", json!(role));
                }
                "events_page" => self.events_pages(&value)?,
                "event_recorded" | "event_imported" if outcome == "Found" => {
                    let creator = text(&value["creator"]);
                    let organizer = text(&value["organizer"]);
                    self.detail("organizer", json!(organizer_kind(organizer, creator)));
                    self.detail(
                        "creator_in_domain",
                        json!(creator.is_some_and(|creator| {
                            creator.ends_with(&format!("@{}", profile.email_domain))
                        })),
                    );
                    self.detail(
                        "meeting_code",
                        json!(text(&value["meeting_code"]).is_some()),
                    );
                }
                "conferences_recorded" | "conferences_imported" if outcome == "Found" => {
                    let records = value["records"].as_array().cloned().unwrap_or_default();
                    let artifacts = |kind: &str| -> u64 {
                        records
                            .iter()
                            .map(|record| record[kind].as_array().map_or(0, Vec::len) as u64)
                            .sum()
                    };
                    let listed = records.iter().any(|record| {
                        ["recordings", "smart_notes", "transcripts"]
                            .iter()
                            .any(|kind| {
                                record[*kind]
                                    .as_array()
                                    .into_iter()
                                    .flatten()
                                    .any(|artifact| artifact["name"] == profile.artifact.as_str())
                            })
                    });
                    self.detail("records", json!(records.len()));
                    self.detail("recordings", json!(artifacts("recordings")));
                    self.detail("smart_notes", json!(artifacts("smart_notes")));
                    self.detail("transcripts", json!(artifacts("transcripts")));
                    self.detail("artifact_listed", json!(listed));
                }
                _ => {}
            }
        }
        Ok(json!({ "probes": self.entries.len() }))
    }

    /// Follow events pages through the adapter, then send the first page's
    /// token with another query, to see whether Google binds the two.
    fn events_pages(&mut self, first: &Value) -> Result<()> {
        let profile = self.profile.clone();
        let page = |value: &Value| {
            (
                value["events"].as_array().map_or(0, Vec::len),
                text(&value["next_page_token"]).map(str::to_owned),
            )
        };
        let (events, mut next) = page(first);
        self.detail("page", json!(1));
        self.detail("events", json!(events));
        self.detail("next_page_token", json!(next.is_some()));
        let first_token = next.clone();
        let mut ordinal = 1;
        while let Some(token) = next.take().filter(|_| ordinal < MAX_EVENT_PAGES) {
            ordinal += 1;
            let request = events_request(&profile, &profile.window.time_max, Some(&token));
            let Ok(plan) = plan(
                &profile,
                self.source,
                Action::GoogleWorkspaceCalendarEvents,
                request,
            ) else {
                // A token the adapter would refuse to send.
                self.entries.push(Entry {
                    probe: "events_page",
                    outcome: "page_token_refused_by_adapter",
                    details: Map::new(),
                    calls: 0,
                    request_bytes: 0,
                    response_bytes: 0,
                    exchanges: Vec::new(),
                });
                break;
            };
            let (_, value, _) = self.probe("events_page", &plan, 0)?;
            let (events, following) = page(&value);
            self.detail("page", json!(ordinal));
            self.detail("events", json!(events));
            self.detail("next_page_token", json!(following.is_some()));
            next = following;
        }
        // Another query: the same calendar and start, a window one day long.
        let other = crate::google_workspace_calendar::rfc3339_seconds(&profile.window.time_min)
            .and_then(|start| crate::google_workspace_meet::utc(start + 86_400));
        if let (Some(token), Some(time_max)) = (first_token, other)
            && let Ok(plan) = plan(
                &profile,
                self.source,
                Action::GoogleWorkspaceCalendarEvents,
                events_request(&profile, &time_max, Some(&token)),
            )
        {
            self.probe("events_token_other_query", &plan, 0)?;
        }
        Ok(())
    }

    /// The one write, then checks that the permission is listed. Each check
    /// is the share again with the fence closed: it lists first and answers
    /// `AlreadyShared` once Drive lists the permission, and any create it
    /// would send instead is refused unsent. A check is a scheduled read,
    /// never a retry: whatever it answers, the next one waits its turn.
    pub fn share(&mut self) -> Result<Value> {
        ensure!(
            self.read && !self.shared,
            "google_workspace_qualification_step_out_of_order"
        );
        self.shared = true;
        let profile = self.profile.clone();
        let share = plan(
            &profile,
            self.source,
            Action::GoogleWorkspaceShareArtifact,
            share_request(&profile, &profile.group),
        )?;
        let (outcome, value, _) = self.probe("share", &share, 1)?;
        self.permission = value["permission_id"].as_str().map(str::to_owned);
        if !matches!(outcome, "Shared" | "google_workspace_share_outcome_unknown") {
            return Ok(json!({ "outcome": outcome }));
        }
        let mut waited = 0;
        for delay in self.delays.iter().copied() {
            if delay > 0 {
                std::thread::sleep(std::time::Duration::from_secs(delay));
            }
            waited += delay;
            let (again, value, fenced) = self.probe("share_again", &share, 0)?;
            self.detail("waited_seconds", json!(waited));
            if again == "AlreadyShared" && !fenced {
                let same = self
                    .permission
                    .as_deref()
                    .map(|id| value["permission_id"] == id);
                self.detail("same_permission", json!(same));
                self.visible_after_seconds = Some(waited);
                break;
            }
        }
        Ok(json!({ "outcome": outcome }))
    }

    /// The receipt. Consumes the run, dropping the port, the operator token
    /// and every provider value it held.
    pub fn finish(self) -> Result<Value> {
        ensure!(
            self.shared,
            "google_workspace_qualification_step_out_of_order"
        );
        let recording = &self.port.inner;
        ensure!(
            recording.creates_sent <= 1,
            "google_workspace_qualification_wrote_twice"
        );
        Ok(json!({
            "format": 1,
            "adapter": "google-workspace-v1",
            "provider_qualified": false,
            "source": match self.source { Source::Native => "native", Source::Simulated => "simulated" },
            "workload": "operator_token",
            "profile_digest": crate::digest(&serde_json::to_vec(&self.profile)?),
            "started_at": self.started,
            "finished_at": crate::oauth::effects::wall_time()?,
            "creates_sent": recording.creates_sent,
            "creates_fenced": recording.creates_fenced,
            "visible_after_seconds": self.visible_after_seconds,
            "probes": self.entries,
        }))
    }
}

/// A seeded simulated organization and the profile that names its fixtures,
/// for tests of the whole session and for rehearsing a profile offline.
pub fn simulated_rehearsal(
    directory: &std::path::Path,
) -> Result<(std::path::PathBuf, QualificationProfile, String)> {
    use crate::integrations::simulated::{self as simulated, GoogleAclRule, GoogleCalendar};
    let mut world = simulated::google_workspace_development_fixture();
    let domain = simulated::GOOGLE_DEVELOPMENT_DOMAIN;
    let reader = simulated::GOOGLE_DEVELOPMENT_CALENDAR_READER;
    let in_play = simulated::GOOGLE_DEVELOPMENT_CALENDAR;
    let calendar = |role: &str| GoogleCalendar {
        summary: "Qualification".into(),
        acl: [(role != "none").then(|| GoogleAclRule {
            scope_type: "user".into(),
            scope_value: Some(reader.into()),
            role: role.into(),
        })]
        .into_iter()
        .flatten()
        .collect(),
        events: Vec::new(),
    };
    world.calendars.insert(
        "c_free_busy@group.calendar.google.com".into(),
        calendar("freeBusyReader"),
    );
    world.calendars.insert(
        "c_unshared@group.calendar.google.com".into(),
        calendar("none"),
    );
    let events = &mut world.calendars.get_mut(in_play).context("calendar")?.events;
    let mut imported = events[0].clone();
    imported.id = "imported0004".into();
    imported.creator = Some(format!("grace@{domain}"));
    events.push(imported);
    let engineering = format!("engineering@{domain}");
    world
        .groups
        .get_mut(&engineering)
        .context("group")?
        .aliases
        .insert(format!("eng-alias@{domain}"));
    let database = directory.join("app.sqlite");
    simulated::seed(
        &database,
        "qualification",
        &simulated::SimulatedFixture {
            slack: simulated::SlackWorld {
                workspace_id: "TQUALIFY".into(),
                ..Default::default()
            },
            snowflake: simulated::SnowflakeWorld {
                account: "qualify".into(),
                ..Default::default()
            },
            openai: simulated::OpenAiWorld {
                project_id: "proj_qualify".into(),
                model: "model-qualify".into(),
                max_input_tokens: 1,
                ..Default::default()
            },
            google_workspace: world,
            ..Default::default()
        },
    )?;
    // The simulated metadata server's token stands in for an operator's.
    let reply = workspace::SimulatedGooglePort::new(&database, "qualification")?
        .authenticate(
            &Exchange::Metadata,
            crate::google_auth::MAX_EXCHANGE_RESPONSE_BYTES,
        )
        .map_err(|_| anyhow::anyhow!("simulated metadata"))?;
    let token: Value = serde_json::from_slice(&reply.body)?;
    let profile = QualificationProfile {
        format: 1,
        service_account: simulated::GOOGLE_DEVELOPMENT_SERVICE_ACCOUNT.into(),
        calendar_reader: reader.into(),
        email_domain: domain.into(),
        grantee_domains: vec![domain.into()],
        calendars: Calendars {
            in_play: in_play.into(),
            free_busy: "c_free_busy@group.calendar.google.com".into(),
            unshared: "c_unshared@group.calendar.google.com".into(),
        },
        window: Window {
            time_min: "2026-01-01T00:00:00Z".into(),
            time_max: "2026-01-31T00:00:00Z".into(),
        },
        events: Events {
            recorded: "standup0001".into(),
            imported: "imported0004".into(),
        },
        group: engineering,
        group_alias: format!("eng-alias@{domain}"),
        group_member: format!("ada@{domain}"),
        artifact: "conferenceRecords/conf-standup-1/recordings/rec-1".into(),
        expires_at: crate::oauth::effects::wall_time()? + 86_400,
    };
    Ok((
        database,
        profile,
        token["access_token"]
            .as_str()
            .context("simulated token")?
            .to_owned(),
    ))
}

#[cfg(test)]
#[path = "google_workspace_qualification_tests.rs"]
mod tests;
