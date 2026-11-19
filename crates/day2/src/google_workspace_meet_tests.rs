//! `google_workspace.event_conferences.v1`: the event's owner, its conference
//! records and their artifacts, through the real pipeline and the simulated
//! world.
use super::*;
use crate::google_workspace_meet::{
    self as meet, ARTIFACT_PAGE_CEILING, Collection, MAX_ARTIFACTS, MAX_RECORDS,
    RECORD_PAGE_CEILING,
};
use crate::integrations::simulated::{
    GOOGLE_MEET_RECORDINGS_ENDPOINT, GOOGLE_MEET_RECORDS_ENDPOINT,
    GOOGLE_MEET_SMART_NOTES_ENDPOINT, GOOGLE_MEET_TRANSCRIPTS_ENDPOINT, GoogleArtifact,
    GoogleConferenceRecord, GoogleSpace,
};

const ADA: &str = "ada@synthetic.example";
const GRACE: &str = "grace@synthetic.example";

pub(super) fn conferences(event: &str) -> Plan {
    plan_for(
        Action::GoogleWorkspaceEventConferences,
        &serde_json::json!({"handle":"h","calendar_id":CALENDAR,"event_id":event}).to_string(),
    )
    .unwrap()
}

/// The development organization with one more event on its calendar.
fn with_event(event: GoogleEvent) -> GoogleWorkspaceWorld {
    with_calendar(|calendar| calendar.events.push(event))
}

/// A timed event on the review's slot with a Meet code.
fn meeting(id: &str, organizer: Option<&str>, creator: Option<&str>) -> GoogleEvent {
    GoogleEvent {
        organizer: organizer.map(str::to_owned),
        creator: creator.map(str::to_owned),
        conference_id: Some("klm-nopq-rst".into()),
        conference_type: Some("hangoutsMeet".into()),
        ..timed(id, "2026-01-06T15:00:00Z", "2026-01-06T16:00:00Z")
    }
}

/// Who each signJwt asked to sign for, in order.
fn impersonated(world: &World) -> Vec<String> {
    world
        .state()
        .calls
        .iter()
        .filter(|call| call.starts_with(GOOGLE_IAM_SIGN_ENDPOINT))
        .map(|call| call.rsplit(':').next().unwrap_or_default().to_owned())
        .collect()
}

fn encoded_query(pairs: &[(&str, &str)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(name, value);
    }
    serializer.finish()
}

#[test]
fn conferences_are_read_as_the_events_owner_with_meets_scope_alone() {
    let world = World::development();
    let plan = conferences("standup0001");
    let (result, meter) = world.observe(&plan);
    let record = |id: &str| format!("conferenceRecords/{id}");
    assert_eq!(
        decoded(result),
        serde_json::json!({"Found":{"owner":ADA,"meeting_code":"abc-defg-hij","records":[
            {"name":record("conf-standup-2"),"space":"spaces/spaceStandup01",
                "start_time":"2026-01-05T17:22:00Z","end_time":"None",
                "recordings":[{"name":format!("{}/recordings/rec-2", record("conf-standup-2")),
                    "state":"Started","file_id":"None"}],
                "smart_notes":[],"transcripts":[]},
            {"name":record("conf-standup-1"),"space":"spaces/spaceStandup01",
                "start_time":"2026-01-05T17:01:02.345Z","end_time":{"Some":"2026-01-05T17:20:00Z"},
                "recordings":[{"name":format!("{}/recordings/rec-1", record("conf-standup-1")),
                    "state":"FileGenerated","file_id":{"Some":"1recStandupFile01"}}],
                "smart_notes":[{"name":format!("{}/smartNotes/note-1", record("conf-standup-1")),
                    "state":"Ended","document_id":"None"}],
                "transcripts":[{"name":format!("{}/transcripts/tr-1", record("conf-standup-1")),
                    "state":"FileGenerated","document_id":{"Some":"1docStandupTranscript"}}]}]}})
    );
    // The reader's three exchanges, its rule and the event; the owner's three
    // exchanges; one page of records; each record's three artifact lists.
    assert_eq!(meter.calls, 3 + 2 + 3 + 1 + 2 * 3);
    assert!(meter.calls <= plan.planned_calls());
    assert!(meter.response_bytes <= plan.response_envelope());
    assert_eq!(impersonated(&world), [READER, ADA]);
    let calls = world.state().calls;
    assert_eq!(
        calls[8],
        format!(
            "{GOOGLE_MEET_RECORDS_ENDPOINT}:v2/conferenceRecords?{}",
            encoded_query(&[
                ("pageSize", "5"),
                (
                    "filter",
                    r#"space.meeting_code = "abc-defg-hij" AND start_time >= "2026-01-05T16:30:00Z" AND start_time <= "2026-01-05T18:00:00Z""#
                ),
                (
                    "fields",
                    "conferenceRecords(name,space,startTime,endTime),nextPageToken"
                ),
                ("prettyPrint", "false"),
            ])
        )
    );
    assert_eq!(
        calls[9],
        format!(
            "{GOOGLE_MEET_RECORDINGS_ENDPOINT}:v2/conferenceRecords/conf-standup-2/recordings?{}",
            encoded_query(&[
                ("pageSize", "5"),
                (
                    "fields",
                    "recordings(name,state,driveDestination(file)),nextPageToken"
                ),
                ("prettyPrint", "false"),
            ])
        )
    );
    assert!(calls[10].starts_with(GOOGLE_MEET_SMART_NOTES_ENDPOINT));
    assert!(calls[11].starts_with(GOOGLE_MEET_TRANSCRIPTS_ENDPOINT));
}

#[test]
fn a_group_or_resource_calendars_event_is_read_as_its_creator_in_the_domain() {
    // The review is organized by the group calendar and created by grace.
    let world = World::development();
    let (result, _) = world.observe(&conferences("review0002"));
    let found = decoded(result)["Found"].clone();
    assert_eq!(found["owner"], GRACE);
    assert_eq!(
        found["records"][0]["name"],
        "conferenceRecords/conf-review-1"
    );
    assert_eq!(
        found["records"][0]["start_time"],
        "2026-01-06T15:00:30.123456Z"
    );
    assert_eq!(impersonated(&world), [READER, GRACE]);
    // A resource calendar's event too.
    let world = World::new(with_event(meeting(
        "room0001",
        Some("c_room@resource.calendar.google.com"),
        Some(GRACE),
    )));
    let (result, _) = world.observe(&conferences("room0001"));
    assert_eq!(decoded(result)["Found"]["owner"], GRACE);
}

/// The impersonation bound's negative regressions: nobody outside the grant's
/// email domain, and nobody but the derived owner, is ever asked for.
#[test]
fn nobody_but_a_derived_owner_in_the_domain_is_impersonated() {
    for (name, organizer, creator) in [
        (
            "an organizer outside the domain",
            Some("ada@other.example"),
            None,
        ),
        (
            "an organizer in a subdomain",
            Some("ada@sub.synthetic.example"),
            None,
        ),
        (
            "a group organizer and a creator outside the domain",
            Some("c_team@group.calendar.google.com"),
            Some("ada@other.example"),
        ),
        (
            "a resource organizer and no creator",
            Some("c_room@resource.calendar.google.com"),
            None,
        ),
        (
            "an outside organizer and an inside creator",
            Some("ada@other.example"),
            Some(GRACE),
        ),
        ("no organizer at all", None, Some(GRACE)),
        // An organizer can be forged with events.import: an in-domain
        // organizer counts only as its own event's creator.
        (
            "an in-domain organizer someone else created the event for",
            Some(ADA),
            Some(GRACE),
        ),
        ("an in-domain organizer and no creator", Some(ADA), None),
        // Every delegated subject is an exact Workspace address.
        (
            "an upper-case creator",
            Some("Ada@synthetic.example"),
            Some("Ada@synthetic.example"),
        ),
    ] {
        let world = World::new(with_event(meeting("owner0001", organizer, creator)));
        let (result, meter) = world.observe(&conferences("owner0001"));
        assert_eq!(decoded(result), serde_json::json!("NoOwner"), "{name}");
        // Only the reader was ever signed for, and nothing reached Meet.
        assert_eq!(impersonated(&world), [READER], "{name}");
        assert_eq!(meter.calls, 5, "{name}");
    }
}

#[test]
fn an_event_that_cannot_have_conferences_says_why() {
    let cases: Vec<(&str, GoogleEvent, serde_json::Value)> = vec![
        (
            "no Meet code",
            GoogleEvent {
                conference_id: None,
                conference_type: None,
                ..meeting("plain0001", Some(ADA), None)
            },
            serde_json::json!("NoMeeting"),
        ),
        (
            "another conference solution's code",
            GoogleEvent {
                conference_type: Some("addOn".into()),
                ..meeting("addon0001", Some(ADA), None)
            },
            serde_json::json!("NoMeeting"),
        ),
        (
            "a cancelled instance without times",
            GoogleEvent {
                id: "series_20260113T170000Z".into(),
                status: "cancelled".into(),
                original_start: Some(GoogleTime::at("2026-01-13T17:00:00Z")),
                ..GoogleEvent::default()
            },
            serde_json::json!("NotFound"),
        ),
    ];
    for (name, event, expected) in cases {
        let id = event.id.clone();
        let world = World::new(with_event(event));
        assert_eq!(
            decoded(world.observe(&conferences(&id)).0),
            expected,
            "{name}"
        );
        assert_eq!(impersonated(&world), [READER], "{name}");
    }
    let world = World::development();
    assert_eq!(
        decoded(world.observe(&conferences("offsite0003")).0),
        serde_json::json!("AllDay")
    );
    assert_eq!(
        decoded(world.observe(&conferences("absent0000")).0),
        serde_json::json!("NotFound")
    );
    // A calendar not shared with the reader is not shared here either.
    let world = World::new(with_calendar(|calendar| {
        calendar.acl = vec![rule("domain", Some("synthetic.example"), "reader")];
    }));
    assert_eq!(
        decoded(world.observe(&conferences("standup0001")).0),
        serde_json::json!("NotShared")
    );
    // A cancelled event that keeps its times and code is read like any
    // other: whether to act on it is the application's policy.
    let world = World::new(with_calendar(|calendar| {
        calendar.events[0].status = "cancelled".into();
    }));
    assert_eq!(
        decoded(world.observe(&conferences("standup0001")).0)["Found"]["owner"],
        ADA
    );
}

/// Meet may serve a short or empty page that still continues (AIP-158): the
/// second page is read, and the ceiling still holds.
#[test]
fn short_and_empty_record_pages_continue_within_the_ceiling() {
    let plan = conferences("standup0001");
    let mut five = simulated::google_workspace_development_fixture();
    for index in 0..3 {
        five.conference_records.insert(
            format!("conf-extra-{index}"),
            GoogleConferenceRecord {
                space: "spaceStandup01".into(),
                start_time: format!("2026-01-05T17:4{index}:00Z"),
                ..GoogleConferenceRecord::default()
            },
        );
    }
    five.meet_record_pages = vec![2];
    let (result, meter) = World::new(five).observe(&plan);
    assert_eq!(
        decoded(result)["Found"]["records"].as_array().map(Vec::len),
        Some(MAX_RECORDS)
    );
    assert_eq!(meter.calls, plan.planned_calls());
    let mut empty = simulated::google_workspace_development_fixture();
    empty.meet_record_pages = vec![0];
    let (result, meter) = World::new(empty.clone()).observe(&plan);
    assert_eq!(
        decoded(result)["Found"]["records"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(meter.calls, 3 + 2 + 3 + 2 + 2 * 3);
    // Two empty pages that still continue reach the ceiling.
    empty.meet_record_pages = vec![0, 0];
    let (result, _) = World::new(empty).observe(&plan);
    assert_eq!(code(&result), "google_workspace_conference_record_budget");
}

#[test]
fn records_in_more_than_one_space_are_a_conflict() {
    let mut organization = simulated::google_workspace_development_fixture();
    organization.spaces.insert(
        "spaceStandup02".into(),
        GoogleSpace {
            meeting_code: "abc-defg-hij".into(),
            owner: ADA.into(),
        },
    );
    organization.conference_records.insert(
        "conf-elsewhere".into(),
        GoogleConferenceRecord {
            space: "spaceStandup02".into(),
            start_time: "2026-01-05T17:05:00Z".into(),
            ..GoogleConferenceRecord::default()
        },
    );
    let world = World::new(organization);
    let (result, meter) = world.observe(&conferences("standup0001"));
    assert_eq!(decoded(result), serde_json::json!("Conflict"));
    // No artifact of either space was listed.
    assert_eq!(meter.calls, 3 + 2 + 3 + 1);
}

#[test]
fn records_and_artifacts_past_their_bounds_fail_rather_than_truncate() {
    // Six records for the stand-up's space and window.
    let mut organization = simulated::google_workspace_development_fixture();
    for index in 0..4 {
        organization.conference_records.insert(
            format!("conf-extra-{index}"),
            GoogleConferenceRecord {
                space: "spaceStandup01".into(),
                start_time: format!("2026-01-05T17:4{index}:00Z"),
                ..GoogleConferenceRecord::default()
            },
        );
    }
    let world = World::new(organization);
    let plan = conferences("standup0001");
    let (result, meter) = world.observe(&plan);
    assert_eq!(code(&result), "google_workspace_conference_record_budget");
    assert_eq!(meter.calls, 3 + 2 + 3 + RECORD_PAGE_CEILING);
    // Exactly the bound fits.
    let mut organization = simulated::google_workspace_development_fixture();
    for index in 0..3 {
        organization.conference_records.insert(
            format!("conf-extra-{index}"),
            GoogleConferenceRecord {
                space: "spaceStandup01".into(),
                start_time: format!("2026-01-05T17:4{index}:00Z"),
                ..GoogleConferenceRecord::default()
            },
        );
    }
    let (result, meter) = World::new(organization).observe(&plan);
    assert_eq!(
        decoded(result)["Found"]["records"].as_array().map(Vec::len),
        Some(MAX_RECORDS)
    );
    assert!(meter.calls <= plan.planned_calls());
    // Six recordings on one record.
    let mut organization = simulated::google_workspace_development_fixture();
    let record = organization
        .conference_records
        .get_mut("conf-standup-1")
        .unwrap();
    record.recordings = (0..=MAX_ARTIFACTS)
        .map(|index| GoogleArtifact {
            id: format!("rec-{index}"),
            state: "ENDED".into(),
            file: None,
        })
        .collect();
    let (result, _) = World::new(organization).observe(&plan);
    assert_eq!(code(&result), "google_workspace_artifact_budget");
}

/// Worlds whose event conferences fail in each Meet-specific way: a refused
/// owner, too many records, too many artifacts.
pub(super) fn failing_worlds() -> Vec<(GoogleWorkspaceWorld, Plan)> {
    let mut refused = simulated::google_workspace_development_fixture();
    refused.suspended.insert(ADA.into());
    let mut records = simulated::google_workspace_development_fixture();
    for index in 0..4 {
        records.conference_records.insert(
            format!("conf-extra-{index}"),
            GoogleConferenceRecord {
                space: "spaceStandup01".into(),
                start_time: format!("2026-01-05T17:4{index}:00Z"),
                ..GoogleConferenceRecord::default()
            },
        );
    }
    let mut artifacts = simulated::google_workspace_development_fixture();
    artifacts
        .conference_records
        .get_mut("conf-standup-1")
        .unwrap()
        .transcripts = (0..=MAX_ARTIFACTS)
        .map(|index| GoogleArtifact {
            id: format!("tr-{index}"),
            state: "STARTED".into(),
            file: None,
        })
        .collect();
    [refused, records, artifacts]
        .into_iter()
        .map(|world| (world, conferences("standup0001")))
        .collect()
}

#[test]
fn a_refused_owner_is_its_own_failure_and_never_the_readers() {
    for adjust in [
        (|world: &mut GoogleWorkspaceWorld| {
            world.suspended.insert(ADA.into());
        }) as fn(&mut GoogleWorkspaceWorld),
        |world| {
            world.users.remove(ADA);
        },
    ] {
        let mut organization = simulated::google_workspace_development_fixture();
        adjust(&mut organization);
        let world = World::new(organization);
        let (result, meter) = world.observe(&conferences("standup0001"));
        assert_eq!(code(&result), "google_workspace_owner_refused");
        assert_eq!(
            meter.last,
            Some(LastExchange {
                phase: Phase::Token,
                http_status: Some(400),
                retry_after_seconds: None,
            })
        );
        assert_eq!(impersonated(&world), [READER, ADA]);
    }
    // A refused reader stays a failed authentication.
    let mut organization = simulated::google_workspace_development_fixture();
    organization.suspended.insert(READER.into());
    let (result, _) = World::new(organization).observe(&conferences("standup0001"));
    assert_eq!(code(&result), "google_workspace_authentication_failed");
}

impl World {
    /// One Meet request with any bearer, as a client could send it.
    fn meet_route(&self, segments: &[&str], bearer: &str, query: &[(&'static str, &str)]) -> Reply {
        simulated::google_workspace_serve(
            &self.database,
            SCOPE,
            simulated::GoogleRequest::Api {
                request: &ApiRequest::meet("probe", segments, query),
                bearer,
            },
            MAX_CALENDAR_RESPONSE_BYTES,
        )
        .unwrap()
    }
}

#[test]
fn the_simulation_shows_records_only_to_the_spaces_owner_and_the_reviewed_query() {
    let world = World::development();
    let token = |subject: &str, scopes: &[&str]| {
        world
            .token(google_auth::Identity::Delegated(subject), scopes)
            .unwrap()
    };
    let filter = r#"space.meeting_code = "abc-defg-hij" AND start_time >= "2026-01-05T16:30:00Z" AND start_time <= "2026-01-05T18:00:00Z""#;
    let records = |bearer: &str, filter: &str| {
        let reply = world.meet_route(
            &["conferenceRecords"],
            bearer,
            &[
                ("pageSize", "5"),
                ("filter", filter),
                ("fields", meet::RECORDS_FIELDS),
            ],
        );
        (
            reply.status,
            serde_json::from_slice::<serde_json::Value>(&reply.body).unwrap(),
        )
    };
    let ada = token(ADA, &[meet::MEET_READ_SCOPE]);
    let (status, body) = records(ada.bearer(), filter);
    assert_eq!(status, 200);
    assert_eq!(body["conferenceRecords"].as_array().map(Vec::len), Some(2));
    // Grace may not see ada's space: no records, and its artifacts refused.
    let grace = token(GRACE, &[meet::MEET_READ_SCOPE]);
    assert_eq!(
        records(grace.bearer(), filter),
        (200, serde_json::json!({}))
    );
    let artifacts = |bearer: &str| {
        world
            .meet_route(
                &["conferenceRecords", "conf-standup-1", "recordings"],
                bearer,
                &[
                    ("pageSize", "5"),
                    ("fields", Collection::Recordings.fields()),
                ],
            )
            .status
    };
    assert_eq!(artifacts(ada.bearer()), 200);
    assert_eq!(artifacts(grace.bearer()), 403);
    // The Calendar reader's token has no Meet scope.
    let reader = token(
        READER,
        &[CALENDAR_READ_SCOPE, calendar::CALENDAR_ACL_READ_SCOPE],
    );
    assert_eq!(records(reader.bearer(), filter).0, 403);
    // Only the pinned filter grammar is parsed.
    for unreviewed in [
        r#"space.meeting_code = "abc-defg-hij""#,
        r#"space.meeting_code="abc-defg-hij" AND start_time>="2026-01-05T16:30:00Z" AND start_time<="2026-01-05T18:00:00Z""#,
        r#"space.meeting_code = "abc-defg-hij" AND start_time >= "2026-01-05T16:30:00.000Z" AND start_time <= "2026-01-05T18:00:00Z""#,
        r#"space.meeting_code = "ABC-defg-hij" AND start_time >= "2026-01-05T16:30:00Z" AND start_time <= "2026-01-05T18:00:00Z""#,
        r#"space.name = "spaces/spaceStandup01" AND start_time >= "2026-01-05T16:30:00Z" AND start_time <= "2026-01-05T18:00:00Z""#,
    ] {
        assert_eq!(records(ada.bearer(), unreviewed).0, 400, "{unreviewed}");
    }
    for query in [
        vec![
            ("pageSize", "100"),
            ("filter", filter),
            ("fields", meet::RECORDS_FIELDS),
        ],
        vec![
            ("pageSize", "5"),
            ("filter", filter),
            ("fields", "conferenceRecords"),
        ],
        vec![("pageSize", "5"), ("fields", meet::RECORDS_FIELDS)],
    ] {
        assert_eq!(
            world
                .meet_route(&["conferenceRecords"], ada.bearer(), &query)
                .status,
            400
        );
    }
}

#[test]
fn artifacts_advance_to_a_generated_file_the_next_read_reports() {
    let world = World::development();
    let name = "conferenceRecords/conf-standup-2/recordings/rec-2";
    let state = |world: &World| {
        let (result, _) = world.observe(&conferences("standup0001"));
        decoded(result)["Found"]["records"][0]["recordings"][0].clone()
    };
    assert_eq!(state(&world)["state"], "Started");
    let advance = || {
        simulated::update_google_workspace(&world.database, SCOPE, |state| {
            simulated::google_meet_advance(&mut state.world, name)
        })
    };
    advance().unwrap();
    assert_eq!(state(&world)["state"], "Ended");
    assert_eq!(state(&world)["file_id"], "None");
    advance().unwrap();
    let generated = state(&world);
    assert_eq!(generated["state"], "FileGenerated");
    let file = generated["file_id"]["Some"].as_str().unwrap().to_owned();
    let saved = &world.state().world.drive_files[&file];
    assert_eq!(
        (saved.owner.as_str(), saved.mime_type.as_str()),
        (ADA, "video/mp4")
    );
    assert!(advance().is_err(), "a generated file does not advance");
}

pub(super) fn meet_fault_cases() -> Vec<(&'static str, SimulatedFault, &'static str)> {
    use SimulatedFault::*;
    let mut cases = Vec::new();
    for endpoint in [
        GOOGLE_MEET_RECORDS_ENDPOINT,
        GOOGLE_MEET_RECORDINGS_ENDPOINT,
        GOOGLE_MEET_SMART_NOTES_ENDPOINT,
        GOOGLE_MEET_TRANSCRIPTS_ENDPOINT,
    ] {
        cases.extend([
            (endpoint, RateLimited, "rate_limited"),
            (endpoint, RateLimitForbidden, "rate_limited"),
            (endpoint, ServerError, "unavailable"),
            (endpoint, ConnectionLost, "unavailable"),
            (endpoint, NotJson, "response_invalid"),
            (endpoint, Oversized, "response_too_large"),
            (endpoint, BadRequest, "request_refused"),
            (endpoint, Denied, "denied"),
            // A 404 on a list is a record gone since it was listed; the
            // records list itself is never missing.
            (
                endpoint,
                Gone,
                if endpoint == GOOGLE_MEET_RECORDS_ENDPOINT {
                    "response_invalid"
                } else {
                    "conference_record_gone"
                },
            ),
        ]);
    }
    cases
}

#[test]
fn every_scheduled_meet_fault_is_classified_and_consumed() {
    for (endpoint, fault, expected) in meet_fault_cases() {
        let world = World::development();
        world.fault(endpoint, fault);
        let plan = conferences("standup0001");
        let (result, meter) = world.observe(&plan);
        assert_eq!(
            code(&result),
            format!("google_workspace_{expected}"),
            "{endpoint} {fault:?}"
        );
        let last = meter.last.unwrap();
        assert_eq!(last.phase, Phase::Meet, "{endpoint} {fault:?}");
        if fault == SimulatedFault::RateLimited {
            assert_eq!(last.retry_after_seconds, Some(30));
        }
        let (retried, _) = world.observe(&plan);
        assert!(retried.is_ok(), "{endpoint} {fault:?} did not recover");
    }
}

#[test]
fn the_plan_reserves_both_delegations_and_every_page_the_ceilings_admit() {
    let plan = conferences("standup0001");
    let api = 2 + RECORD_PAGE_CEILING + MAX_RECORDS as u64 * 3 * ARTIFACT_PAGE_CEILING;
    assert_eq!(plan.planned_calls(), 6 + api);
    assert_eq!(plan.planned_calls(), 25);
    assert_eq!(plan.max_response_bytes(), MAX_CALENDAR_RESPONSE_BYTES);
    assert_eq!(
        plan.response_envelope(),
        6 * (google_auth::MAX_EXCHANGE_RESPONSE_BYTES as u64 + 1)
            + api * (MAX_CALENDAR_RESPONSE_BYTES as u64 + 1)
    );
    // The application names an event exactly as calendar_event does.
    for (calendar, event) in [
        ("C_ENGINEERING@group.calendar.google.com", "standup0001"),
        (CALENDAR, "../standup0001"),
        (CALENDAR, ""),
    ] {
        assert_eq!(
            plan_for(
                Action::GoogleWorkspaceEventConferences,
                &serde_json::json!({"handle":"h","calendar_id":calendar,"event_id":event})
                    .to_string(),
            )
            .unwrap_err()
            .to_string(),
            "google_workspace_request_invalid"
        );
    }
}

#[test]
fn the_owner_window_and_filter_are_exact() {
    use crate::carta::OptionalText;
    let event = |organizer: Option<&str>, creator: Option<&str>| calendar::Event {
        id: "e".into(),
        status: calendar::EventStatus::Confirmed(calendar::Times {
            start: "2026-01-05T09:00:00-08:00".into(),
            end: "2026-01-05T09:30:00-08:00".into(),
        }),
        visibility: calendar::Visibility::Default,
        original_start: OptionalText::None,
        organizer: organizer.map_or(OptionalText::None, |value| OptionalText::Some(value.into())),
        creator: creator.map_or(OptionalText::None, |value| OptionalText::Some(value.into())),
        meeting_code: OptionalText::Some("abc-defg-hij".into()),
    };
    let owner = |organizer, creator| meet::owner(&event(organizer, creator), "example.com");
    assert_eq!(
        owner(Some("ada@example.com"), Some("ada@example.com")).as_deref(),
        Some("ada@example.com")
    );
    for calendar in [
        "c_1@group.calendar.google.com",
        "c_1@resource.calendar.google.com",
    ] {
        assert_eq!(
            owner(Some(calendar), Some("bob@example.com")).as_deref(),
            Some("bob@example.com")
        );
    }
    for (organizer, creator) in [
        (Some("ada@example.com"), None),
        (Some("ada@example.com"), Some("bob@example.com")),
        (Some("ada@example.com"), Some("ADA@example.com")),
        (Some("o'neil@example.com"), Some("o'neil@example.com")),
        (Some("a%b@example.com"), Some("a%b@example.com")),
        (Some("ada@other.example"), Some("bob@example.com")),
        (Some("ada@Example.com"), None),
        (Some("ada@example.com.other"), None),
        (
            Some("c_1@group.v.calendar.google.com"),
            Some("bob@example.com"),
        ),
        (
            Some("c_1@group.calendar.google.com"),
            Some("bob@sub.example.com"),
        ),
        (None, Some("bob@example.com")),
    ] {
        assert_eq!(owner(organizer, creator), None, "{organizer:?} {creator:?}");
    }
    let times = calendar::Times {
        start: "2026-01-05T09:00:00-08:00".into(),
        end: "2026-01-05T09:30:00-08:00".into(),
    };
    let window = meet::record_window(&times).unwrap();
    assert_eq!(
        meet::record_filter("abc-defg-hij", window).as_deref(),
        Some(
            r#"space.meeting_code = "abc-defg-hij" AND start_time >= "2026-01-05T16:30:00Z" AND start_time <= "2026-01-05T18:00:00Z""#
        )
    );
    for (seconds, rendered) in [
        (0, "1970-01-01T00:00:00Z"),
        (951_782_400, "2000-02-29T00:00:00Z"),
        (1_767_225_599, "2025-12-31T23:59:59Z"),
        (253_402_300_799, "9999-12-31T23:59:59Z"),
    ] {
        assert_eq!(meet::utc(seconds).as_deref(), Some(rendered));
        assert_eq!(calendar::rfc3339_seconds(rendered), Some(seconds));
    }
    assert_eq!(meet::utc(253_402_300_800), None);
    for (timestamp, seconds) in [
        ("2026-01-05T17:00:00Z", Some(1_767_632_400)),
        ("2026-01-05T17:00:00.123Z", Some(1_767_632_400)),
        ("2026-01-05T17:00:00.123456Z", Some(1_767_632_400)),
        ("2026-01-05T17:00:00.123456789Z", Some(1_767_632_400)),
        ("2026-01-05T17:00:00.1Z", None),
        ("2026-01-05T17:00:00.Z", None),
        ("2026-01-05T17:00:00+00:00", None),
        ("2026-01-05T17:00:00.12aZ", None),
    ] {
        assert_eq!(meet::meet_timestamp(timestamp), seconds, "{timestamp}");
    }
}

#[test]
fn meet_responses_are_validated_name_by_name() {
    let window = (1_767_630_600, 1_767_636_000);
    let records = |records: serde_json::Value| {
        meet::parse_records_page(
            serde_json::json!({ "conferenceRecords": records })
                .to_string()
                .as_bytes(),
            window,
        )
    };
    let record = |name: &str, space: &str, start: &str| serde_json::json!({"name":name,"space":space,"startTime":start});
    assert!(
        records(serde_json::json!([record(
            "conferenceRecords/a-1_B",
            "spaces/s1",
            "2026-01-05T17:00:00Z"
        )]))
        .is_ok()
    );
    for (name, page) in [
        (
            "another resource",
            serde_json::json!([record("spaces/a", "spaces/s1", "2026-01-05T17:00:00Z")]),
        ),
        (
            "a path in the ID",
            serde_json::json!([record(
                "conferenceRecords/a/b",
                "spaces/s1",
                "2026-01-05T17:00:00Z"
            )]),
        ),
        (
            "an escaped ID",
            serde_json::json!([record(
                "conferenceRecords/a%2Fb",
                "spaces/s1",
                "2026-01-05T17:00:00Z"
            )]),
        ),
        (
            "an empty ID",
            serde_json::json!([record(
                "conferenceRecords/",
                "spaces/s1",
                "2026-01-05T17:00:00Z"
            )]),
        ),
        (
            "a long ID",
            serde_json::json!([record(
                &format!("conferenceRecords/{}", "a".repeat(129)),
                "spaces/s1",
                "2026-01-05T17:00:00Z"
            )]),
        ),
        (
            "a bad space",
            serde_json::json!([record(
                "conferenceRecords/a",
                "space/s1",
                "2026-01-05T17:00:00Z"
            )]),
        ),
        (
            "a start before the window",
            serde_json::json!([record(
                "conferenceRecords/a",
                "spaces/s1",
                "2026-01-05T16:29:59Z"
            )]),
        ),
        (
            "a start after the window",
            serde_json::json!([record(
                "conferenceRecords/a",
                "spaces/s1",
                "2026-01-05T18:00:01Z"
            )]),
        ),
        (
            "an offset start",
            serde_json::json!([record(
                "conferenceRecords/a",
                "spaces/s1",
                "2026-01-05T09:00:00-08:00"
            )]),
        ),
        (
            "an end before the start",
            serde_json::json!([{"name":"conferenceRecords/a","space":"spaces/s1",
            "startTime":"2026-01-05T17:00:00Z","endTime":"2026-01-05T16:59:59Z"}]),
        ),
        (
            "more records than a page",
            serde_json::json!(vec![
                record(
                    "conferenceRecords/a",
                    "spaces/s1",
                    "2026-01-05T17:00:00Z"
                );
                6
            ]),
        ),
    ] {
        assert_eq!(
            records(page).err(),
            Some(Failure::ResponseInvalid),
            "{name}"
        );
    }
    let artifacts = |collection: Collection, items: serde_json::Value| {
        let mut page = serde_json::Map::new();
        page.insert(collection.segment().into(), items);
        meet::parse_artifact_page(
            serde_json::Value::Object(page).to_string().as_bytes(),
            "rec1",
            collection,
        )
    };
    assert_eq!(
        artifacts(
            Collection::Recordings,
            serde_json::json!([{"name":"conferenceRecords/rec1/recordings/r1","state":"FILE_GENERATED",
                "driveDestination":{"file":"1abc_DEF-2"}}])
        )
        .unwrap()
        .0[0]
            .id
            .as_deref(),
        Some("1abc_DEF-2")
    );
    assert_eq!(
        artifacts(
            Collection::Transcripts,
            serde_json::json!([{"name":"conferenceRecords/rec1/transcripts/t1","state":"ENDED"}])
        )
        .unwrap()
        .0[0]
            .state,
        meet::ArtifactState::Ended
    );
    for (name, collection, items) in [
        (
            "another record's recording",
            Collection::Recordings,
            serde_json::json!([{"name":"conferenceRecords/rec2/recordings/r1","state":"ENDED"}]),
        ),
        (
            "a transcript among recordings",
            Collection::Recordings,
            serde_json::json!([{"name":"conferenceRecords/rec1/transcripts/r1","state":"ENDED"}]),
        ),
        (
            "an unspecified state",
            Collection::Recordings,
            serde_json::json!([{"name":"conferenceRecords/rec1/recordings/r1","state":"STATE_UNSPECIFIED"}]),
        ),
        (
            "a Docs destination on a recording",
            Collection::Recordings,
            serde_json::json!([{"name":"conferenceRecords/rec1/recordings/r1","state":"ENDED","docsDestination":{"document":"d"}}]),
        ),
        (
            "a Drive destination on a smart note",
            Collection::SmartNotes,
            serde_json::json!([{"name":"conferenceRecords/rec1/smartNotes/n1","state":"ENDED","driveDestination":{"file":"f"}}]),
        ),
        (
            "a prefixed file ID",
            Collection::Recordings,
            serde_json::json!([{"name":"conferenceRecords/rec1/recordings/r1","state":"FILE_GENERATED","driveDestination":{"file":"files/1abc"}}]),
        ),
        (
            "a prefixed document ID",
            Collection::Transcripts,
            serde_json::json!([{"name":"conferenceRecords/rec1/transcripts/t1","state":"FILE_GENERATED","docsDestination":{"document":"documents/1abc"}}]),
        ),
        (
            "a file ID with a path",
            Collection::Recordings,
            serde_json::json!([{"name":"conferenceRecords/rec1/recordings/r1","state":"FILE_GENERATED","driveDestination":{"file":"a/b"}}]),
        ),
        (
            "a long document ID",
            Collection::Transcripts,
            serde_json::json!([{"name":"conferenceRecords/rec1/transcripts/t1","state":"FILE_GENERATED",
                "docsDestination":{"document":"d".repeat(129)}}]),
        ),
        (
            "more artifacts than a page",
            Collection::SmartNotes,
            serde_json::json!(vec![
                serde_json::json!({"name":"conferenceRecords/rec1/smartNotes/n1","state":"ENDED"});
                6
            ]),
        ),
    ] {
        assert_eq!(
            artifacts(collection, items).err(),
            Some(Failure::ResponseInvalid),
            "{name}"
        );
    }
    // Another collection's list in the reply is not this one's.
    assert_eq!(
        meet::parse_artifact_page(br#"{"transcripts":[]}"#, "rec1", Collection::Recordings).err(),
        Some(Failure::ResponseInvalid)
    );
}

#[test]
fn a_meet_refusal_is_classified_from_its_status_and_reason() {
    let error = |error: serde_json::Value| serde_json::json!({ "error": error }).to_string();
    assert_eq!(
        calendar::forbidden(
            error(serde_json::json!({"code":403,"message":"m","status":"PERMISSION_DENIED"}))
                .as_bytes()
        ),
        Failure::Denied
    );
    assert_eq!(
        calendar::forbidden(
            error(serde_json::json!({"code":403,"status":"PERMISSION_DENIED","details":[
                {"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"RATE_LIMIT_EXCEEDED"}]}))
            .as_bytes()
        ),
        Failure::RateLimited
    );
    assert_eq!(
        calendar::forbidden(
            error(
                serde_json::json!({"code":403,"status":"PERMISSION_DENIED","details":[
                {"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"SERVICE_DISABLED"}]})
            )
            .as_bytes()
        ),
        Failure::Denied
    );
    assert_eq!(
        calendar::forbidden(
            error(serde_json::json!({"code":403,"status":"PERMISSION_DENIED","details":[
                {"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"RESOURCE_QUOTA_EXCEEDED"}]}))
            .as_bytes()
        ),
        Failure::RateLimited
    );
    // Only an ErrorInfo detail's reason is read.
    assert_eq!(
        calendar::forbidden(
            error(
                serde_json::json!({"code":403,"status":"PERMISSION_DENIED","details":[
                {"@type":"type.googleapis.com/google.rpc.Help","reason":"RATE_LIMIT_EXCEEDED"}]})
            )
            .as_bytes()
        ),
        Failure::Denied
    );
    assert_eq!(
        calendar::forbidden(error(serde_json::json!({"code":403,"message":"m"})).as_bytes()),
        Failure::ResponseInvalid
    );
}

/// The largest outcome the adapter can admit, with every ID and address at its
/// bound, journals within one observation.
#[test]
fn the_largest_admissible_conferences_fit_one_observation() {
    use crate::carta::OptionalText;
    let id = |tag: char| tag.to_string().repeat(meet::MAX_MEET_ID_BYTES);
    let file = "f".repeat(meet::MAX_FILE_ID_BYTES);
    let time = "2026-01-05T17:00:00.123456789Z";
    let record_id = id('r');
    let named =
        |collection: &str| format!("conferenceRecords/{record_id}/{collection}/{}", id('a'));
    let document = |collection: &str| meet::Document {
        name: named(collection),
        state: meet::ArtifactState::FileGenerated,
        document_id: OptionalText::Some(file.clone()),
    };
    let record = meet::ConferenceRecord {
        name: format!("conferenceRecords/{record_id}"),
        space: format!("spaces/{}", id('s')),
        start_time: time.into(),
        end_time: OptionalText::Some(time.into()),
        recordings: vec![
            meet::Recording {
                name: named("recordings"),
                state: meet::ArtifactState::FileGenerated,
                file_id: OptionalText::Some(file.clone()),
            };
            MAX_ARTIFACTS
        ],
        smart_notes: vec![document("smartNotes"); MAX_ARTIFACTS],
        transcripts: vec![document("transcripts"); MAX_ARTIFACTS],
    };
    let domain = "@synthetic.example";
    let largest = meet::EventConferences {
        owner: format!(
            "{}{domain}",
            "o".repeat(calendar::MAX_ADDRESS_BYTES - domain.len())
        ),
        meeting_code: "abc-defg-hij".into(),
        records: vec![record; MAX_RECORDS],
    };
    let outcome = meet::found(largest).expect("the largest outcome fits the page bound");
    let result = encode(&outcome);
    let journaled = crate::capture_delivery::journal_bytes(&result).unwrap();
    assert!(
        journaled <= crate::capture_delivery::MAX_PAGE_JOURNAL_BYTES,
        "{journaled}"
    );
    let instruction = crate::protocol::Instruction {
        kind: "observe".into(),
        model: "google_workspace.event_conferences.v1".into(),
        data: "h".repeat(MAX_INPUT_BYTES),
        ..Default::default()
    };
    let observation = crate::resources::bounded_observation(crate::protocol::Observation {
        instruction,
        result: result.clone(),
        error: String::new(),
    })
    .unwrap();
    assert_eq!(
        observation.result, result,
        "the outcome did not fit one observation"
    );
}
