use super::*;
use crate::integrations::simulated::{
    self, GOOGLE_ENDPOINTS, GOOGLE_GROUP_ENDPOINT, GOOGLE_HAS_MEMBER_ENDPOINT,
    GOOGLE_IAM_TOKEN_ENDPOINT, GOOGLE_METADATA_ENDPOINT, GOOGLE_WORKSPACE_WORLD,
    GoogleWorkspaceWorld, ScheduledFault, SimulatedFault,
};
use day2_capabilities::integrations::LiveConnection;

const SCOPE: &str = "installation/google-workspace";

fn connection(service_account: &str) -> LiveConnection {
    LiveConnection::GoogleWorkspace {
        service_account: service_account.into(),
    }
}

/// A plan on the development grant and connection, as the host authorizes it.
pub(crate) fn plan_for(action: Action, request: &str) -> Result<Plan> {
    plan_with(
        action,
        &connection(simulated::GOOGLE_DEVELOPMENT_SERVICE_ACCOUNT),
        request,
    )
}

fn plan_with(action: Action, connection: &LiveConnection, request: &str) -> Result<Plan> {
    let (plan, handle) = Plan::authorize(
        action,
        connection,
        &simulated::google_workspace_development_target(),
        request,
    )?;
    ensure!(handle == "h", "handle not carried");
    Ok(plan)
}

fn group_plan(group: &str) -> Plan {
    plan_for(
        Action::GoogleWorkspaceGroup,
        &serde_json::json!({"handle":"h","group_email":group}).to_string(),
    )
    .unwrap()
}

fn member_plan(group: &str, member: &str) -> Plan {
    plan_for(
        Action::GoogleWorkspaceGroupMember,
        &serde_json::json!({"handle":"h","group_email":group,"member_email":member}).to_string(),
    )
    .unwrap()
}

/// A seeded world in a fresh directory. The other providers' required fixture
/// fields are filled with inert values; only Google Workspace is exercised.
struct World {
    _directory: tempfile::TempDir,
    database: std::path::PathBuf,
}

impl World {
    fn new(google: GoogleWorkspaceWorld) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("app.sqlite");
        simulated::seed(
            &database,
            SCOPE,
            &simulated::SimulatedFixture {
                slack: simulated::SlackWorld {
                    workspace_id: "TGOOGLE".into(),
                    ..Default::default()
                },
                snowflake: simulated::SnowflakeWorld {
                    account: "google-test".into(),
                    ..Default::default()
                },
                openai: simulated::OpenAiWorld {
                    project_id: "proj_google".into(),
                    model: "model-google".into(),
                    max_input_tokens: 1,
                    ..Default::default()
                },
                google_workspace: google,
                ..Default::default()
            },
        )
        .unwrap();
        Self {
            _directory: directory,
            database,
        }
    }

    fn development() -> Self {
        Self::new(simulated::google_workspace_development_fixture())
    }

    fn observe(&self, plan: &Plan) -> (Result<String>, Meter) {
        let mut port = SimulatedGooglePort::new(&self.database, SCOPE).unwrap();
        observe(plan, &mut port, 1_000)
    }

    fn fault(&self, endpoint: &str, fault: SimulatedFault) {
        simulated::schedule_faults(
            &self.database,
            SCOPE,
            GOOGLE_WORKSPACE_WORLD,
            vec![ScheduledFault {
                endpoint: endpoint.into(),
                remaining: 1,
                fault,
            }],
        )
        .unwrap();
    }

    fn state(&self) -> simulated::World<GoogleWorkspaceWorld> {
        simulated::update_google_workspace(&self.database, SCOPE, |state| Ok(state.clone()))
            .unwrap()
    }
}

fn code(result: &Result<String>) -> String {
    result.as_ref().unwrap_err().to_string()
}

#[test]
fn groups_are_read_as_the_service_account_with_only_the_group_scope() {
    let world = World::development();
    let (result, meter) = world.observe(&group_plan("engineering@synthetic.example"));
    assert_eq!(
        result.unwrap(),
        r#"{"Found":{"email":"engineering@synthetic.example","id":"group-engineering","name":"Engineering"}}"#
    );
    assert_eq!(meter.calls, 3);
    assert!(meter.response_bytes > 0 && meter.request_bytes > 0);
    let state = world.state();
    assert_eq!(
        state.calls,
        [
            GOOGLE_METADATA_ENDPOINT.to_owned(),
            format!(
                "{GOOGLE_IAM_TOKEN_ENDPOINT}:{}",
                simulated::GOOGLE_DEVELOPMENT_SERVICE_ACCOUNT
            ),
            format!(
                "{GOOGLE_GROUP_ENDPOINT}:admin/directory/v1/groups/engineering@synthetic.example?fields=id%2Cemail%2Cname"
            ),
        ]
    );
    // Serving a read changes nothing but the request log.
    assert_eq!(
        state.world,
        simulated::google_workspace_development_fixture()
    );
    let (missing, meter) = world.observe(&group_plan("absent@synthetic.example"));
    assert_eq!(missing.unwrap(), r#""NotFound""#);
    assert_eq!(meter.calls, 3);
}

#[test]
fn membership_is_direct_or_nested_and_a_missing_group_is_distinct() {
    let world = World::development();
    let member = |group: &str, person: &str| {
        let (result, meter) = world.observe(&member_plan(group, person));
        (result.unwrap(), meter.calls)
    };
    assert_eq!(
        member("engineering@synthetic.example", "ada@synthetic.example"),
        (r#""Member""#.into(), 4)
    );
    // Through the nested platform group.
    assert_eq!(
        member("engineering@synthetic.example", "grace@synthetic.example"),
        (r#""Member""#.into(), 4)
    );
    assert_eq!(
        member("platform@synthetic.example", "ada@synthetic.example"),
        (r#""NotMember""#.into(), 4)
    );
    // An unknown member is a 404 from hasMember once the group exists.
    assert_eq!(
        member("empty@synthetic.example", "nobody@synthetic.example"),
        (r#""NotMember""#.into(), 4)
    );
    // The group lookup answers before hasMember is ever sent.
    assert_eq!(
        member("absent@synthetic.example", "ada@synthetic.example"),
        (r#""GroupNotFound""#.into(), 3)
    );
    assert!(
        !world
            .state()
            .calls
            .iter()
            .any(|call| call.contains("absent@synthetic.example/hasMember"))
    );
}

#[test]
fn requests_outside_the_grant_or_malformed_are_refused_before_any_exchange() {
    let forbidden = |action, request: serde_json::Value| {
        let error = plan_for(action, &request.to_string()).unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<crate::error::Failure>(),
                Some(crate::error::Failure::ResourceForbidden)
            ),
            "{error}"
        );
    };
    forbidden(
        Action::GoogleWorkspaceGroup,
        serde_json::json!({"handle":"h","group_email":"team@other.example"}),
    );
    forbidden(
        Action::GoogleWorkspaceGroupMember,
        serde_json::json!({"handle":"h","group_email":"engineering@synthetic.example",
            "member_email":"outsider@other.example"}),
    );
    // A provider action of another kind never reaches this adapter.
    forbidden(
        Action::SlackRead,
        serde_json::json!({"handle":"h","group_email":"engineering@synthetic.example"}),
    );
    let invalid = |action, request: &str| {
        assert_eq!(
            plan_for(action, request).unwrap_err().to_string(),
            "google_workspace_request_invalid",
            "{request}"
        );
    };
    for request in [
        r#"{"handle":"h","group_email":"Engineering@synthetic.example"}"#,
        r#"{"handle":"h","group_email":"engineering"}"#,
        r#"{"handle":"h","group_email":"a b@synthetic.example"}"#,
        r#"{"handle":"h","group_email":"engineering@synthetic.example","extra":1}"#,
        r#"{"handle":"h"}"#,
        "not json",
    ] {
        invalid(Action::GoogleWorkspaceGroup, request);
    }
    invalid(
        Action::GoogleWorkspaceGroupMember,
        r#"{"handle":"h","group_email":"engineering@synthetic.example","member_email":"ADA@synthetic.example"}"#,
    );
    invalid(
        Action::GoogleWorkspaceGroup,
        &format!(
            r#"{{"handle":"h","group_email":"{}@synthetic.example"}}"#,
            "x".repeat(MAX_INPUT_BYTES)
        ),
    );
    // Another provider's connection cannot carry this action.
    let other = LiveConnection::WorkspaceDirectory {
        service_account: simulated::GOOGLE_DEVELOPMENT_SERVICE_ACCOUNT.into(),
        auth: day2_capabilities::integrations::WorkspaceDirectoryAuth::DirectServiceAccount,
    };
    assert!(
        plan_with(
            Action::GoogleWorkspaceGroup,
            &other,
            r#"{"handle":"h","group_email":"engineering@synthetic.example"}"#,
        )
        .is_err()
    );
}

#[test]
fn another_service_account_or_a_missing_directory_role_is_refused_by_the_world() {
    let world = World::development();
    let plan = plan_with(
        Action::GoogleWorkspaceGroup,
        &connection("someone-else@synthetic-project.iam.gserviceaccount.com"),
        r#"{"handle":"h","group_email":"engineering@synthetic.example"}"#,
    )
    .unwrap();
    let (result, meter) = world.observe(&plan);
    assert_eq!(code(&result), "google_workspace_authentication_failed");
    assert_eq!(meter.calls, 2);
    assert_eq!(
        meter.last,
        Some(LastExchange {
            phase: Phase::Iam,
            http_status: Some(403),
            retry_after_seconds: None,
        })
    );
    let mut without_role = simulated::google_workspace_development_fixture();
    without_role.directory_reader = false;
    let world = World::new(without_role);
    let (result, meter) = world.observe(&group_plan("engineering@synthetic.example"));
    assert_eq!(code(&result), "google_workspace_denied");
    assert_eq!(meter.last.map(|last| last.phase), Some(Phase::Directory));
}

#[test]
fn an_unseeded_world_is_unavailable_and_never_reaches_a_network() {
    let directory = tempfile::tempdir().unwrap();
    assert!(SimulatedGooglePort::new(&directory.path().join("app.sqlite"), SCOPE).is_err());
    // A seeded world for another scope is not this scope's world.
    let world = World::development();
    assert!(SimulatedGooglePort::new(&world.database, "installation/other").is_err());
}

#[test]
fn every_scheduled_fault_is_classified_per_exchange_without_provider_content() {
    use SimulatedFault::*;
    let cases = [
        // The metadata server is the runtime's own identity: any failure there
        // is the workload identity being unavailable.
        (
            GOOGLE_METADATA_ENDPOINT,
            RateLimited,
            "workload_identity_unavailable",
        ),
        (
            GOOGLE_METADATA_ENDPOINT,
            ServerError,
            "workload_identity_unavailable",
        ),
        (
            GOOGLE_METADATA_ENDPOINT,
            ConnectionLost,
            "workload_identity_unavailable",
        ),
        (
            GOOGLE_METADATA_ENDPOINT,
            NotJson,
            "workload_identity_unavailable",
        ),
        (
            GOOGLE_METADATA_ENDPOINT,
            Oversized,
            "workload_identity_unavailable",
        ),
        (GOOGLE_IAM_TOKEN_ENDPOINT, RateLimited, "rate_limited"),
        (GOOGLE_IAM_TOKEN_ENDPOINT, ServerError, "unavailable"),
        (GOOGLE_IAM_TOKEN_ENDPOINT, Denied, "authentication_failed"),
        (GOOGLE_IAM_TOKEN_ENDPOINT, ConnectionLost, "unavailable"),
        (GOOGLE_IAM_TOKEN_ENDPOINT, NotJson, "authentication_failed"),
        (GOOGLE_IAM_TOKEN_ENDPOINT, Oversized, "response_too_large"),
        (GOOGLE_GROUP_ENDPOINT, RateLimited, "rate_limited"),
        (GOOGLE_GROUP_ENDPOINT, ServerError, "unavailable"),
        (GOOGLE_GROUP_ENDPOINT, Denied, "denied"),
        (GOOGLE_GROUP_ENDPOINT, ConnectionLost, "unavailable"),
        (GOOGLE_GROUP_ENDPOINT, NotJson, "response_invalid"),
        (GOOGLE_GROUP_ENDPOINT, Oversized, "response_too_large"),
        (GOOGLE_HAS_MEMBER_ENDPOINT, RateLimited, "rate_limited"),
        (GOOGLE_HAS_MEMBER_ENDPOINT, ServerError, "unavailable"),
        (GOOGLE_HAS_MEMBER_ENDPOINT, Denied, "denied"),
        (GOOGLE_HAS_MEMBER_ENDPOINT, ConnectionLost, "unavailable"),
        (GOOGLE_HAS_MEMBER_ENDPOINT, NotJson, "response_invalid"),
        (GOOGLE_HAS_MEMBER_ENDPOINT, Oversized, "response_too_large"),
    ];
    for (endpoint, fault, expected) in cases {
        let world = World::development();
        world.fault(endpoint, fault);
        let plan = member_plan("engineering@synthetic.example", "ada@synthetic.example");
        let (result, meter) = world.observe(&plan);
        let error = code(&result);
        assert_eq!(
            error,
            format!("google_workspace_{expected}"),
            "{endpoint} {fault:?}"
        );
        assert!(meter.calls >= 1);
        let last = meter.last.unwrap();
        if fault == RateLimited && endpoint != GOOGLE_METADATA_ENDPOINT {
            assert_eq!(last.retry_after_seconds, Some(30));
        }
        // A failure consumed what the response carried; nothing it carried
        // is in the error.
        assert!(!error.contains("simulated"));
        // The fault was consumed: the same action now succeeds.
        let (retried, _) = world.observe(&plan);
        assert_eq!(retried.unwrap(), r#""Member""#, "{endpoint} {fault:?}");
    }
    // Every reviewed endpoint in the world is reachable by these actions except
    // delegation, which no Directory read uses.
    for endpoint in GOOGLE_ENDPOINTS {
        assert!(
            cases.iter().any(|(case, ..)| *case == endpoint)
                || endpoint.contains("sign_jwt")
                || endpoint.contains("oauth.token"),
            "{endpoint}"
        );
    }
}

#[test]
fn group_responses_are_validated_and_bound_to_the_grantee_domains() {
    let domains = vec!["synthetic.example".to_owned()];
    let parse = |body: &str| parse_group(body.as_bytes(), &domains);
    assert_eq!(
        parse(
            r#"{"id":"g","email":"Team@Synthetic.Example","name":"Team","kind":"admin#directory#group"}"#
        ),
        Ok(Group {
            id: "g".into(),
            email: "team@synthetic.example".into(),
            name: "Team".into(),
        })
    );
    assert_eq!(
        parse(r#"{"id":"g","email":"team@other.example","name":"Team"}"#),
        Err(Failure::GroupOutsideGrant)
    );
    for body in [
        r#"{"id":"","email":"team@synthetic.example","name":"Team"}"#,
        r#"{"id":"g h","email":"team@synthetic.example","name":"Team"}"#,
        r#"{"id":"g","email":"not-an-address","name":"Team"}"#,
        r#"{"id":"g","email":"team@synthetic.example","name":" "}"#,
        r#"{"id":"g","email":"team@synthetic.example","name":"a\u0000b"}"#,
        r#"{"id":"g","email":"team@synthetic.example"}"#,
        "[]",
    ] {
        assert_eq!(parse(body), Err(Failure::ResponseInvalid), "{body}");
    }
    assert_eq!(parse_membership(br#"{"isMember":false}"#), Ok(false));
    assert_eq!(
        parse_membership(br#"{"isMember":"yes"}"#),
        Err(Failure::ResponseInvalid)
    );
}

#[test]
fn reservations_cover_every_exchange_and_its_probe() {
    let group = group_plan("engineering@synthetic.example");
    assert_eq!(group.planned_calls(), 3);
    assert_eq!(
        group.response_envelope(),
        2 * (google_auth::MAX_EXCHANGE_RESPONSE_BYTES as u64 + 1)
            + (MAX_DIRECTORY_RESPONSE_BYTES as u64 + 1)
    );
    let member = member_plan("engineering@synthetic.example", "ada@synthetic.example");
    assert_eq!(member.planned_calls(), 4);
    let world = World::development();
    for plan in [group, member] {
        let (result, meter) = world.observe(&plan);
        result.unwrap();
        assert!(meter.calls <= plan.planned_calls());
        assert!(meter.response_bytes <= plan.response_envelope());
        assert!(meter.request_bytes <= MAX_ACTION_REQUEST_BYTES);
    }
    for failure in Failure::ALL {
        assert!(failure.code().starts_with("google_workspace_"));
    }
}

#[test]
fn directory_statuses_and_the_request_budget_map_to_their_own_codes() {
    let reply = |status: u16| Reply {
        status,
        metadata_flavor: false,
        json: true,
        body: b"{}".to_vec(),
        retry_after_seconds: None,
    };
    for (status, expected) in [
        (400, Failure::RequestRefused),
        (401, Failure::AuthenticationFailed),
        (403, Failure::Denied),
        (429, Failure::RateLimited),
        (503, Failure::Unavailable),
        (302, Failure::ResponseInvalid),
    ] {
        assert_eq!(accept(&reply(status), 64), Err(expected), "{status}");
    }
    assert_eq!(accept(&reply(200), 64), Ok(()));
    let mut meter = Meter::default();
    assert_eq!(
        meter.send(Phase::Directory, MAX_ACTION_REQUEST_BYTES as usize + 1),
        Err(Failure::RequestBudget)
    );
    // A refused send is not a call and consumes nothing.
    assert_eq!(meter, Meter::default());
}
