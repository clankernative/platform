//! `google_workspace.share_artifact.v1`, the provider's only write, through the
//! real pipeline and the simulated world.
use super::*;
use crate::google_workspace_drive as drive;
use crate::integrations::simulated::{
    GOOGLE_DRIVE_PERMISSIONS_ENDPOINT, GOOGLE_DRIVE_SHARE_ENDPOINT, GOOGLE_MEET_ARTIFACT_ENDPOINT,
    GoogleDrivePermission,
};

const RECORDING: &str = "conferenceRecords/conf-standup-1/recordings/rec-1";
const FILE: &str = "1recStandupFile01";
const GROUP: &str = "engineering@synthetic.example";

pub(super) fn share(event: &str, artifact: &str, group: &str) -> Plan {
    plan_for(
        Action::GoogleWorkspaceShareArtifact,
        &serde_json::json!({"handle":"h","calendar_id":CALENDAR,"event_id":event,
            "artifact":artifact,"group_email":group})
        .to_string(),
    )
    .unwrap()
}

fn standup() -> Plan {
    share("standup0001", RECORDING, GROUP)
}

/// The file's permissions to anyone but its owner.
fn granted(world: &World, file: &str) -> Vec<GoogleDrivePermission> {
    world.state().world.drive_files[file]
        .permissions
        .iter()
        .filter(|permission| permission.role != "owner")
        .cloned()
        .collect()
}

fn creates(world: &World) -> usize {
    world
        .state()
        .calls
        .iter()
        .filter(|call| call.starts_with(GOOGLE_DRIVE_SHARE_ENDPOINT))
        .count()
}

#[test]
fn an_artifact_is_shared_once_as_its_owner_and_found_again() {
    let world = World::development();
    let plan = standup();
    assert!(plan.is_write());
    // Three delegations' exchanges (reader, service account, owner), the
    // rule and the event, the group, two record pages, the artifact, two
    // permission pages, the create and two reconciling pages.
    assert_eq!(plan.planned_calls(), 8 + 2 + 1 + 2 + 1 + 2 + 1 + 2);
    let (result, meter) = world.observe(&plan);
    let shared = decoded(result);
    let id = shared["Shared"]["permission_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(meter.calls <= plan.planned_calls() && !meter.unknown);
    assert_eq!(
        granted(&world, FILE),
        [GoogleDrivePermission {
            id: id.clone(),
            kind: "group".into(),
            role: "reader".into(),
            email_address: Some(GROUP.into()),
            deleted: false,
            created_by: Some("ada@synthetic.example".into()),
        }]
    );
    let calls = world.state().calls;
    let signed: Vec<_> = calls
        .iter()
        .filter(|call| call.starts_with(GOOGLE_IAM_SIGN_ENDPOINT))
        .map(|call| call.rsplit(':').next().unwrap().to_owned())
        .collect();
    assert_eq!(signed, [READER, "ada@synthetic.example"]);
    assert!(calls.contains(&format!(
        "{GOOGLE_MEET_ARTIFACT_ENDPOINT}:v2/{RECORDING}?fields=name%2Cstate%2CdriveDestination%28file%29&prettyPrint=false"
    )));
    assert_eq!(
        calls.last().unwrap(),
        &format!(
            "{GOOGLE_DRIVE_SHARE_ENDPOINT}:drive/v3/files/{FILE}/permissions?supportsAllDrives=true&sendNotificationEmail=false&fields=id%2Ctype%2Crole%2CemailAddress&prettyPrint=false"
        )
    );
    // Run again, as a duplicate delivery would: found, and nothing created.
    let (again, _) = world.observe(&plan);
    assert_eq!(
        decoded(again),
        serde_json::json!({"AlreadyShared":{"permission_id":id}})
    );
    assert_eq!((creates(&world), granted(&world, FILE).len()), (1, 1));
    assert_eq!(
        drive::share_body(GROUP),
        r#"{"type":"group","role":"reader","emailAddress":"engineering@synthetic.example"}"#
    );
}

/// The development organization where `eng-alias@` names engineering and
/// `team@synthetic.example` names a group whose primary address is outside
/// the grant.
fn aliased() -> GoogleWorkspaceWorld {
    let mut world = simulated::google_workspace_development_fixture();
    world
        .groups
        .get_mut(GROUP)
        .unwrap()
        .aliases
        .insert("eng-alias@synthetic.example".into());
    world.groups.insert(
        "team@other.example".into(),
        GoogleGroup {
            id: "group-team".into(),
            name: "Team".into(),
            members: Default::default(),
            aliases: ["team@synthetic.example".to_owned()].into(),
        },
    );
    world
}

/// The bound's negative regressions: nothing is created for an event the grant
/// cannot share from, nor for an artifact that is not this event's own.
#[test]
fn nothing_is_created_for_an_event_or_artifact_that_cannot_be_shared() {
    let mut forged = simulated::google_workspace_development_fixture();
    let event = &mut forged.calendars.get_mut(CALENDAR).unwrap().events[0];
    event.creator = Some("grace@synthetic.example".into());
    let mut unshared = simulated::google_workspace_development_fixture();
    unshared.calendars.get_mut(CALENDAR).unwrap().acl =
        vec![rule("domain", Some("synthetic.example"), "reader")];
    for (name, world, plan, expected) in [
        ("a forged organizer", forged, standup(), "NoOwner"),
        ("a calendar not in play", unshared, standup(), "NotShared"),
        (
            "an artifact Meet has not generated",
            simulated::google_workspace_development_fixture(),
            share(
                "standup0001",
                "conferenceRecords/conf-standup-2/recordings/rec-2",
                GROUP,
            ),
            "NotReady",
        ),
        (
            "another event's record",
            simulated::google_workspace_development_fixture(),
            share(
                "standup0001",
                "conferenceRecords/conf-review-1/recordings/rec-1",
                GROUP,
            ),
            "NotFound",
        ),
        (
            "an artifact the record does not have",
            simulated::google_workspace_development_fixture(),
            share(
                "standup0001",
                "conferenceRecords/conf-standup-1/transcripts/absent",
                GROUP,
            ),
            "NotFound",
        ),
        (
            "an all-day event",
            simulated::google_workspace_development_fixture(),
            share("offsite0003", RECORDING, GROUP),
            "AllDay",
        ),
        (
            "a group the Directory does not know",
            simulated::google_workspace_development_fixture(),
            share("standup0001", RECORDING, "unknown@synthetic.example"),
            "GroupNotFound",
        ),
        (
            "an alias of a granted group",
            aliased(),
            share("standup0001", RECORDING, "eng-alias@synthetic.example"),
            "GroupNotPrimary",
        ),
        (
            "an in-grant alias of a group outside the grant",
            aliased(),
            share("standup0001", RECORDING, "team@synthetic.example"),
            "GroupNotPrimary",
        ),
    ] {
        let world = World::new(world);
        let (result, meter) = world.observe(&plan);
        assert_eq!(decoded(result), serde_json::json!(expected), "{name}");
        assert!(!meter.unknown, "{name}");
        assert!(granted(&world, FILE).is_empty(), "{name}");
    }
    // A policy that limits sharing to other domains refuses it, and an
    // existing grant of reader or more is found rather than added to.
    let mut restricted = simulated::google_workspace_development_fixture();
    restricted
        .drive_trusted_domains
        .insert("other.example".into());
    let world = World::new(restricted);
    assert_eq!(
        decoded(world.observe(&standup()).0),
        serde_json::json!("SharingRefused")
    );
    let mut writer = simulated::google_workspace_development_fixture();
    writer
        .drive_files
        .get_mut(FILE)
        .unwrap()
        .permissions
        .extend([
            GoogleDrivePermission {
                id: "deleted1".into(),
                kind: "group".into(),
                role: "owner".into(),
                email_address: Some(GROUP.into()),
                deleted: true,
                created_by: None,
            },
            GoogleDrivePermission {
                id: "writer1".into(),
                kind: "group".into(),
                role: "writer".into(),
                email_address: Some("Engineering@Synthetic.Example".into()),
                deleted: false,
                created_by: None,
            },
        ]);
    let world = World::new(writer);
    assert_eq!(
        decoded(world.observe(&standup()).0),
        serde_json::json!({"AlreadyShared":{"permission_id":"writer1"}})
    );
    assert_eq!(creates(&world), 0);
}

/// An outcome's tag, or a failure's code without its prefix.
pub(super) fn answer(result: &Result<String>) -> String {
    match result {
        Ok(json) => {
            let value: serde_json::Value = serde_json::from_str(json).unwrap();
            value
                .as_str()
                .map(str::to_owned)
                .or_else(|| value.as_object().and_then(|map| map.keys().next().cloned()))
                .unwrap_or_default()
        }
        Err(error) => error
            .to_string()
            .trim_start_matches("google_workspace_")
            .to_owned(),
    }
}

/// The simulated port, with the create answered `status`/`body` after serving
/// it when `serve`, and the second permission list lost when `lose_relist`.
struct Answering {
    inner: SimulatedGooglePort,
    serve: bool,
    status: u16,
    body: &'static str,
    lose_relist: bool,
    lists: usize,
}

impl GooglePort for Answering {
    fn authenticate(
        &mut self,
        exchange: &Exchange<'_>,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Unreached> {
        self.inner.authenticate(exchange, max_bytes)
    }

    fn call(
        &mut self,
        request: &ApiRequest,
        token: &AccessToken,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Unreached> {
        if request.body().is_some() {
            if self.serve {
                let _ = self.inner.call(request, token, max_bytes);
            }
            return Ok(Reply {
                status: self.status,
                metadata_flavor: false,
                json: true,
                body: self.body.as_bytes().to_vec(),
                retry_after_seconds: None,
            });
        }
        if request.endpoint == "drive_permissions" {
            self.lists += 1;
            if self.lose_relist && self.lists > 1 {
                return Err(Unreached::default());
            }
        }
        self.inner.call(request, token, max_bytes)
    }
}

/// An answer to the create that is not definite is settled in the same
/// attempt by listing again: a grant found is known usage, and only a failed
/// list or a grant still absent is an unknown outcome.
#[test]
fn the_creates_answers_are_reconciled_inside_the_attempt() {
    // Faults the world serves: a lost reply after the permission landed, a
    // conflict after it landed, and answers before anything was served.
    for (fault, expected, unknown, landed) in [
        (SimulatedFault::ReplyLost, "Shared", false, 1),
        (SimulatedFault::Conflict, "AlreadyShared", false, 1),
        (
            SimulatedFault::ServerError,
            "share_outcome_unknown",
            true,
            0,
        ),
        (
            SimulatedFault::ConnectionLost,
            "share_outcome_unknown",
            true,
            0,
        ),
        (SimulatedFault::Oversized, "share_outcome_unknown", true, 0),
        (SimulatedFault::Gone, "NotFound", false, 0),
        (SimulatedFault::Denied, "denied", false, 0),
        (SimulatedFault::RateLimitForbidden, "rate_limited", false, 0),
        (SimulatedFault::RateLimited, "rate_limited", false, 0),
        (SimulatedFault::BadRequest, "request_refused", false, 0),
    ] {
        let world = World::development();
        world.fault(GOOGLE_DRIVE_SHARE_ENDPOINT, fault);
        let (result, meter) = world.observe(&standup());
        assert_eq!(answer(&result), expected, "{fault:?}");
        assert_eq!(meter.unknown, unknown, "{fault:?}");
        assert_eq!(granted(&world, FILE).len(), landed, "{fault:?}");
        assert!(meter.calls <= standup().planned_calls());
    }
    // A 409 the list cannot confirm, a list that fails after a conflict, and
    // a sharing refusal that landed anyway or did not.
    let refusal = r#"{"error":{"code":400,"errors":[{"reason":"invalidSharingRequest"}]}}"#;
    for (serve, status, body, lose_relist, expected) in [
        (false, 409, "{}", false, "share_outcome_unknown"),
        (true, 409, "{}", true, "share_outcome_unknown"),
        (true, 400, refusal, false, "Shared"),
        (false, 400, refusal, false, "SharingRefused"),
    ] {
        let world = World::development();
        let mut port = Answering {
            inner: SimulatedGooglePort::new(&world.database, SCOPE).unwrap(),
            serve,
            status,
            body,
            lose_relist,
            lists: 0,
        };
        let (result, meter) = observe(&standup(), &mut port, 1_000);
        assert_eq!(answer(&result), expected, "{serve} {status} {lose_relist}");
        assert_eq!(meter.unknown, expected == "share_outcome_unknown");
    }
}

pub(super) fn share_fault_cases() -> Vec<(&'static str, SimulatedFault, &'static str)> {
    use SimulatedFault::*;
    let mut cases = Vec::new();
    for endpoint in [
        GOOGLE_MEET_ARTIFACT_ENDPOINT,
        GOOGLE_DRIVE_PERMISSIONS_ENDPOINT,
    ] {
        cases.extend([
            (endpoint, RateLimited, "rate_limited"),
            (endpoint, RateLimitForbidden, "rate_limited"),
            (endpoint, Denied, "denied"),
            (endpoint, ServerError, "unavailable"),
            (endpoint, ConnectionLost, "unavailable"),
            (endpoint, NotJson, "response_invalid"),
            (endpoint, Oversized, "response_too_large"),
            (endpoint, BadRequest, "request_refused"),
        ]);
    }
    cases.push((
        GOOGLE_DRIVE_SHARE_ENDPOINT,
        ConnectionLost,
        "share_outcome_unknown",
    ));
    cases
}

#[test]
fn every_scheduled_share_read_fault_is_classified_and_consumed() {
    for (endpoint, fault, expected) in share_fault_cases() {
        let world = World::development();
        world.fault(endpoint, fault);
        let (result, _) = world.observe(&standup());
        assert_eq!(
            code(&result),
            format!("google_workspace_{expected}"),
            "{endpoint} {fault:?}"
        );
        // Reads fail before anything is created; the next share recovers.
        let (retried, _) = world.observe(&standup());
        assert!(retried.is_ok(), "{endpoint} {fault:?}");
        assert_eq!(granted(&world, FILE).len(), 1, "{endpoint} {fault:?}");
    }
    // A file with more permissions than the pages a share reads.
    let mut long = simulated::google_workspace_development_fixture();
    let file = long.drive_files.get_mut(FILE).unwrap();
    file.permissions.extend(
        (0..drive::PERMISSION_PAGE_CEILING * drive::PERMISSION_PAGE_SIZE as u64).map(|index| {
            GoogleDrivePermission {
                id: format!("user{index}"),
                kind: "user".into(),
                role: "reader".into(),
                email_address: Some(format!("person{index}@synthetic.example")),
                ..GoogleDrivePermission::default()
            }
        }),
    );
    let world = World::new(long);
    let (result, _) = world.observe(&standup());
    assert_eq!(code(&result), "google_workspace_permission_page_budget");
    assert_eq!(creates(&world), 0);
}

#[test]
fn share_inputs_and_drive_replies_are_exact() {
    for (artifact, group) in [
        ("conferenceRecords/conf-standup-1/recordings", GROUP),
        ("conferenceRecords/conf-standup-1/notes/rec-1", GROUP),
        ("spaces/s1", GROUP),
        (RECORDING, "Engineering@synthetic.example"),
    ] {
        let request = serde_json::json!({"handle":"h","calendar_id":CALENDAR,
            "event_id":"standup0001","artifact":artifact,"group_email":group});
        assert_eq!(
            plan_for(Action::GoogleWorkspaceShareArtifact, &request.to_string())
                .unwrap_err()
                .to_string(),
            "google_workspace_request_invalid",
            "{artifact} {group}"
        );
    }
    let outside = plan_for(
        Action::GoogleWorkspaceShareArtifact,
        &serde_json::json!({"handle":"h","calendar_id":CALENDAR,"event_id":"standup0001",
            "artifact":RECORDING,"group_email":"team@other.example"})
        .to_string(),
    )
    .unwrap_err();
    assert!(matches!(
        outside.downcast_ref::<crate::error::Failure>(),
        Some(crate::error::Failure::ResourceForbidden)
    ));
    let created =
        |body: serde_json::Value| drive::parse_created(body.to_string().as_bytes(), GROUP);
    assert_eq!(
        created(
            serde_json::json!({"id":"123","type":"group","role":"reader","emailAddress":GROUP})
        ),
        Ok("123".into())
    );
    for body in [
        serde_json::json!({"id":"123","type":"group","role":"writer","emailAddress":GROUP}),
        serde_json::json!({"id":"123","type":"user","role":"reader","emailAddress":GROUP}),
        serde_json::json!({"id":"123","type":"group","role":"reader","emailAddress":"other@synthetic.example"}),
        serde_json::json!({"id":"1/2","type":"group","role":"reader","emailAddress":GROUP}),
    ] {
        assert_eq!(
            created(body.clone()),
            Err(Failure::ResponseInvalid),
            "{body}"
        );
    }
    assert_eq!(
        drive::parse_permissions_page(
            br#"{"permissions":[{"id":"1","type":"group","role":"editor","emailAddress":"x@y.example"}]}"#,
            GROUP
        ),
        Err(Failure::ResponseInvalid)
    );
    assert!(drive::sharing_refused(
        br#"{"error":{"code":400,"errors":[{"reason":"invalidSharingRequest"}]}}"#
    ));
    assert!(!drive::sharing_refused(
        br#"{"error":{"code":400,"errors":[{"reason":"badRequest"}]}}"#
    ));
    assert_eq!(
        crate::google_workspace_meet::parse_artifact(
            br#"{"name":"conferenceRecords/conf-standup-1/recordings/rec-9","state":"ENDED"}"#,
            RECORDING
        ),
        Err(Failure::ResponseInvalid)
    );
}
