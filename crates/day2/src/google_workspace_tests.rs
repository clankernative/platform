use super::*;
use crate::integrations::simulated::{
    self, GOOGLE_ACL_ENDPOINT, GOOGLE_ACL_RULE_ENDPOINT, GOOGLE_CALENDAR_ENDPOINT,
    GOOGLE_DEVELOPMENT_CALENDAR, GOOGLE_ENDPOINTS, GOOGLE_EVENT_ENDPOINT, GOOGLE_EVENTS_ENDPOINT,
    GOOGLE_GROUP_ENDPOINT, GOOGLE_HAS_MEMBER_ENDPOINT, GOOGLE_IAM_SIGN_ENDPOINT,
    GOOGLE_IAM_TOKEN_ENDPOINT, GOOGLE_METADATA_ENDPOINT, GOOGLE_OAUTH_TOKEN_ENDPOINT,
    GOOGLE_WORKSPACE_WORLD, GoogleAclRule, GoogleCalendar, GoogleEvent, GoogleGroup, GoogleTime,
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
        Source::Simulated,
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
                "{GOOGLE_GROUP_ENDPOINT}:admin/directory/v1/groups/engineering@synthetic.example?fields=id%2Cemail%2Cname&prettyPrint=false"
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
    // Even inside the grant, a member in another domain than the group is a
    // question Google refuses for nested groups, so it is never asked.
    let two_domains = ResourceTarget::GoogleWorkspaceDomain {
        calendar_reader: simulated::GOOGLE_DEVELOPMENT_CALENDAR_READER.into(),
        email_domain: "synthetic.example".into(),
        grantee_domains: vec![
            "groups.synthetic.example".into(),
            "synthetic.example".into(),
        ],
    };
    let error = Plan::authorize(
        Action::GoogleWorkspaceGroupMember,
        &connection(simulated::GOOGLE_DEVELOPMENT_SERVICE_ACCOUNT),
        &two_domains,
        r#"{"handle":"h","group_email":"engineering@synthetic.example","member_email":"ada@groups.synthetic.example"}"#,
        Source::Simulated,
    )
    .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<crate::error::Failure>(),
        Some(crate::error::Failure::ResourceForbidden)
    ));
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

fn directory_fault_cases() -> Vec<(&'static str, SimulatedFault, &'static str)> {
    use SimulatedFault::*;
    vec![
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
        (GOOGLE_GROUP_ENDPOINT, BadRequest, "request_refused"),
        (GOOGLE_HAS_MEMBER_ENDPOINT, BadRequest, "request_refused"),
    ]
}

/// The delegated flow's own endpoints, which no Directory read uses.
fn delegation_fault_cases() -> Vec<(&'static str, SimulatedFault, google_auth::Failure)> {
    use SimulatedFault::*;
    vec![
        (
            GOOGLE_IAM_SIGN_ENDPOINT,
            ServerError,
            google_auth::Failure::Unavailable,
        ),
        (
            GOOGLE_IAM_SIGN_ENDPOINT,
            Denied,
            google_auth::Failure::AuthenticationFailed,
        ),
        (
            GOOGLE_OAUTH_TOKEN_ENDPOINT,
            RateLimited,
            google_auth::Failure::RateLimited,
        ),
        (
            GOOGLE_OAUTH_TOKEN_ENDPOINT,
            NotJson,
            google_auth::Failure::AuthenticationFailed,
        ),
    ]
}

#[test]
fn every_scheduled_fault_is_classified_per_exchange_without_provider_content() {
    use SimulatedFault::*;
    for (endpoint, fault, expected) in directory_fault_cases() {
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
}

#[test]
fn every_simulated_endpoint_has_a_scheduled_fault_case() {
    for endpoint in GOOGLE_ENDPOINTS {
        assert!(
            directory_fault_cases()
                .iter()
                .any(|(case, ..)| *case == endpoint)
                || calendar_fault_cases()
                    .iter()
                    .any(|(case, ..)| *case == endpoint)
                || meet::meet_fault_cases()
                    .iter()
                    .any(|(case, ..)| *case == endpoint)
                || delegation_fault_cases()
                    .iter()
                    .any(|(case, ..)| *case == endpoint),
            "{endpoint} has no fault case"
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
fn api_statuses_map_to_their_own_codes() {
    let reply = |status: u16, body: &str| Reply {
        status,
        metadata_flavor: false,
        json: true,
        body: body.as_bytes().to_vec(),
        retry_after_seconds: None,
    };
    let reason =
        |reason: &str| format!(r#"{{"error":{{"code":403,"errors":[{{"reason":"{reason}"}}]}}}}"#);
    for (status, body, expected) in [
        (400, "{}".to_owned(), Failure::RequestRefused),
        (401, "{}".to_owned(), Failure::AuthenticationFailed),
        // A 403 is a refusal or a limit, by Google's reason; without one it
        // cannot be classified.
        (403, reason("forbidden"), Failure::Denied),
        (403, reason("quotaExceeded"), Failure::RateLimited),
        (403, "{}".to_owned(), Failure::ResponseInvalid),
        (429, "{}".to_owned(), Failure::RateLimited),
        (503, "{}".to_owned(), Failure::Unavailable),
        (302, "{}".to_owned(), Failure::ResponseInvalid),
    ] {
        assert_eq!(
            accept(&reply(status, &body), 256),
            Err(expected),
            "{status} {body}"
        );
    }
    assert_eq!(accept(&reply(200, "{}"), 64), Ok(()));
}

/// Token exchanges answered by the simulated world, outside any action, so the
/// world's own authentication can be probed directly.
struct WorldWire(SimulatedGooglePort);

impl google_auth::TokenWire for WorldWire {
    fn exchange(
        &mut self,
        exchange: &Exchange<'_>,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Unreached> {
        self.0.authenticate(exchange, max_bytes)
    }
}

impl World {
    fn wire(&self) -> WorldWire {
        WorldWire(SimulatedGooglePort::new(&self.database, SCOPE).unwrap())
    }

    fn token(
        &self,
        identity: google_auth::Identity<'_>,
        scopes: &[&str],
    ) -> std::result::Result<AccessToken, google_auth::Failure> {
        google_auth::acquire(
            &mut self.wire(),
            &google_auth::TokenRequest {
                service_account: simulated::GOOGLE_DEVELOPMENT_SERVICE_ACCOUNT,
                identity,
                scopes,
            },
            1_000,
        )
    }

    /// One Directory request with any bearer, as a client could send it.
    fn directory(&self, segments: &[&str], bearer: &str) -> Reply {
        simulated::google_workspace_serve(
            &self.database,
            SCOPE,
            simulated::GoogleRequest::Api {
                // The reviewed query for each route, as the adapter sends it.
                request: &ApiRequest::directory(
                    "probe",
                    segments,
                    if segments.contains(&"hasMember") {
                        &[]
                    } else {
                        &[("fields", "id,email,name")]
                    },
                ),
                bearer,
            },
            MAX_DIRECTORY_RESPONSE_BYTES,
        )
        .unwrap()
    }
}

const CALENDAR_SCOPE: &str = "https://www.googleapis.com/auth/calendar.readonly";

#[test]
fn the_simulated_directory_refuses_forged_workload_and_underscoped_bearers() {
    let world = World::development();
    let group = ["groups", "engineering@synthetic.example"];
    let has_member = [
        "groups",
        "engineering@synthetic.example",
        "hasMember",
        "ada@synthetic.example",
    ];
    assert_eq!(world.directory(&group, "forged").status, 401);
    assert_eq!(
        world
            .directory(&group, "simulated.e30.0000000000000000")
            .status,
        401
    );
    // The workload's own token is for IAM only.
    let metadata = world
        .wire()
        .0
        .authenticate(
            &Exchange::Metadata,
            google_auth::MAX_EXCHANGE_RESPONSE_BYTES,
        )
        .unwrap();
    let workload: serde_json::Value = serde_json::from_slice(&metadata.body).unwrap();
    assert_eq!(
        world
            .directory(&group, workload["access_token"].as_str().unwrap())
            .status,
        401
    );
    // A token minted for groups alone cannot ask about membership.
    let group_only = world
        .token(google_auth::Identity::ServiceAccount, &[GROUP_READ_SCOPE])
        .unwrap();
    assert_eq!(world.directory(&group, group_only.bearer()).status, 200);
    assert_eq!(
        world.directory(&has_member, group_only.bearer()).status,
        403
    );
}

#[test]
fn delegation_succeeds_only_for_an_authorized_scope_and_a_person_in_the_organization() {
    let world = World::development();
    let delegated = world
        .token(
            google_auth::Identity::Delegated("ada@synthetic.example"),
            &[CALENDAR_SCOPE],
        )
        .unwrap();
    let calls = world.state().calls;
    assert!(calls[1].starts_with(GOOGLE_IAM_SIGN_ENDPOINT));
    assert_eq!(calls[2], GOOGLE_OAUTH_TOKEN_ENDPOINT);
    // A delegated person does not hold the service account's Directory role.
    assert_eq!(
        world
            .directory(
                &["groups", "engineering@synthetic.example"],
                delegated.bearer()
            )
            .status,
        403
    );
    // The client is not authorized for this scope domain-wide.
    assert_eq!(
        world
            .token(
                google_auth::Identity::Delegated("ada@synthetic.example"),
                &[GROUP_READ_SCOPE],
            )
            .err(),
        Some(google_auth::Failure::AuthenticationFailed)
    );
    // Neither someone outside the organization, nor a group, nor a suspended
    // person can be impersonated: the token endpoint refuses the subject.
    let mut suspended = simulated::google_workspace_development_fixture();
    suspended.suspended.insert("ada@synthetic.example".into());
    let suspended = World::new(suspended);
    for (world, subject) in [
        (&world, "ada@other.example"),
        (&world, "engineering@synthetic.example"),
        (&suspended, "ada@synthetic.example"),
    ] {
        assert_eq!(
            world
                .token(google_auth::Identity::Delegated(subject), &[CALENDAR_SCOPE])
                .err(),
            Some(google_auth::Failure::SubjectRefused),
            "{subject}"
        );
    }
    // Another service account's assertion is not this world's to exchange.
    let other = google_auth::acquire(
        &mut world.wire(),
        &google_auth::TokenRequest {
            service_account: "someone-else@synthetic-project.iam.gserviceaccount.com",
            identity: google_auth::Identity::Delegated("ada@synthetic.example"),
            scopes: &[CALENDAR_SCOPE],
        },
        1_000,
    );
    assert_eq!(
        other.err(),
        Some(google_auth::Failure::AuthenticationFailed)
    );
}

#[test]
fn delegated_exchange_faults_are_classified_and_consumed() {
    for (endpoint, fault, expected) in delegation_fault_cases() {
        let world = World::development();
        world.fault(endpoint, fault);
        let delegated = google_auth::Identity::Delegated("ada@synthetic.example");
        assert_eq!(
            world.token(delegated, &[CALENDAR_SCOPE]).err(),
            Some(expected),
            "{endpoint} {fault:?}"
        );
        assert!(world.token(delegated, &[CALENDAR_SCOPE]).is_ok());
    }
}

#[test]
fn the_simulated_membership_check_follows_the_reference() {
    let mut organization = simulated::google_workspace_development_fixture();
    organization
        .users
        .insert("lin@groups.synthetic.example".into());
    organization.groups.insert(
        "partners@synthetic.example".into(),
        GoogleGroup {
            id: "group-partners".into(),
            name: "Partners".into(),
            members: ["lin@groups.synthetic.example".to_owned()].into(),
            aliases: Default::default(),
        },
    );
    let world = World::new(organization);
    let token = world
        .token(
            google_auth::Identity::ServiceAccount,
            &[GROUP_READ_SCOPE, GROUP_MEMBER_READ_SCOPE],
        )
        .unwrap();
    let ask = |group: &str, member: &str| {
        world.directory(&["groups", group, "hasMember", member], token.bearer())
    };
    let answer =
        |reply: Reply| -> serde_json::Value { serde_json::from_slice(&reply.body).unwrap() };
    // A direct member in another domain is answered.
    let direct = ask("partners@synthetic.example", "lin@groups.synthetic.example");
    assert_eq!(direct.status, 200);
    assert_eq!(answer(direct)["isMember"], true);
    // A nested question across domains is invalid input.
    assert_eq!(
        ask(
            "engineering@synthetic.example",
            "lin@groups.synthetic.example"
        )
        .status,
        400
    );
    // The member key is a user, never a group.
    assert_eq!(
        ask(
            "engineering@synthetic.example",
            "platform@synthetic.example"
        )
        .status,
        404
    );
    // Addresses are matched exactly, never normalised.
    assert_eq!(
        ask("Engineering@synthetic.example", "ada@synthetic.example").status,
        404
    );
    assert_eq!(
        ask("engineering@synthetic.example", "Ada@synthetic.example").status,
        404
    );
}

#[test]
fn every_failure_is_produced_through_an_action() {
    let mut produced = std::collections::BTreeSet::new();
    let mut record = |world: &World, plan: &Plan| {
        let (result, _) = world.observe(plan);
        produced.insert(code(&result));
    };
    let read = group_plan("engineering@synthetic.example");
    for (endpoint, fault) in [
        (GOOGLE_METADATA_ENDPOINT, SimulatedFault::ServerError),
        (GOOGLE_GROUP_ENDPOINT, SimulatedFault::RateLimited),
        (GOOGLE_GROUP_ENDPOINT, SimulatedFault::ServerError),
        (GOOGLE_GROUP_ENDPOINT, SimulatedFault::BadRequest),
        (GOOGLE_GROUP_ENDPOINT, SimulatedFault::NotJson),
        (GOOGLE_GROUP_ENDPOINT, SimulatedFault::Oversized),
    ] {
        let world = World::development();
        world.fault(endpoint, fault);
        record(&world, &read);
    }
    record(
        &World::development(),
        &plan_with(
            Action::GoogleWorkspaceGroup,
            &connection("someone-else@synthetic-project.iam.gserviceaccount.com"),
            r#"{"handle":"h","group_email":"engineering@synthetic.example"}"#,
        )
        .unwrap(),
    );
    let mut without_role = simulated::google_workspace_development_fixture();
    without_role.directory_reader = false;
    record(&World::new(without_role), &read);
    // An in-grant alias whose group's primary address is elsewhere.
    let mut aliased = simulated::google_workspace_development_fixture();
    aliased.groups.insert(
        "team@other.example".into(),
        GoogleGroup {
            id: "group-team".into(),
            name: "Team".into(),
            members: Default::default(),
            aliases: ["team@synthetic.example".to_owned()].into(),
        },
    );
    record(&World::new(aliased), &group_plan("team@synthetic.example"));
    // A calendar whose ACL is longer than the pages an action reads.
    record(
        &World::new(with_long_acl(
            ACL_PAGE_CEILING as usize * ACL_PAGE_SIZE as usize + 1,
        )),
        &calendar_read("engineering@synthetic.example"),
    );
    // An event's owner the token endpoint refuses, and records or artifacts
    // past their bounds.
    for (world, plan) in meet::failing_worlds() {
        record(&World::new(world), &plan);
    }
    let expected: std::collections::BTreeSet<_> = Failure::ALL
        .iter()
        .map(|failure| failure.code().to_owned())
        .collect();
    assert_eq!(produced, expected);
}

// Calendar reads: delegated as the grant's Calendar reader, and bounded by the
// reader's own ACL rule.

const CALENDAR: &str = GOOGLE_DEVELOPMENT_CALENDAR;
const READER: &str = simulated::GOOGLE_DEVELOPMENT_CALENDAR_READER;

fn calendar_read(group: &str) -> Plan {
    plan_for(
        Action::GoogleWorkspaceCalendar,
        &serde_json::json!({"handle":"h","calendar_id":CALENDAR,"group_email":group}).to_string(),
    )
    .unwrap()
}

fn events_on(
    calendar: &str,
    time_min: &str,
    time_max: &str,
    page_token: Option<&str>,
) -> Result<Plan> {
    plan_for(
        Action::GoogleWorkspaceCalendarEvents,
        &serde_json::json!({"handle":"h","calendar_id":calendar,"time_min":time_min,
            "time_max":time_max,"page_token":page_token.map_or(serde_json::json!("None"),
                |token| serde_json::json!({"Some":token}))})
        .to_string(),
    )
}

fn events_read(time_min: &str, time_max: &str, page_token: Option<&str>) -> Result<Plan> {
    events_on(CALENDAR, time_min, time_max, page_token)
}

fn january() -> Plan {
    events_read("2026-01-01T00:00:00Z", "2026-01-31T00:00:00Z", None).unwrap()
}

fn event_read(calendar: &str, event: &str) -> Result<Plan> {
    plan_for(
        Action::GoogleWorkspaceCalendarEvent,
        &serde_json::json!({"handle":"h","calendar_id":calendar,"event_id":event}).to_string(),
    )
}

fn decoded(result: Result<String>) -> serde_json::Value {
    serde_json::from_str(&result.unwrap()).unwrap()
}

fn rule(scope_type: &str, value: Option<&str>, role: &str) -> GoogleAclRule {
    GoogleAclRule {
        scope_type: scope_type.into(),
        scope_value: value.map(str::to_owned),
        role: role.into(),
    }
}

/// The development organization with one more calendar setting.
fn with_calendar(adjust: impl FnOnce(&mut GoogleCalendar)) -> GoogleWorkspaceWorld {
    let mut organization = simulated::google_workspace_development_fixture();
    adjust(organization.calendars.get_mut(CALENDAR).unwrap());
    organization
}

/// An ACL with `rules` user entries before the group's, the reader's own
/// writer rule first.
fn with_long_acl(rules: usize) -> GoogleWorkspaceWorld {
    with_calendar(|calendar| {
        let mut acl = vec![rule("user", Some(READER), "writer")];
        acl.extend((1..rules).map(|index| GoogleAclRule {
            scope_value: Some(format!("person{index}@synthetic.example")),
            ..rule("user", None, "reader")
        }));
        acl.push(rule(
            "group",
            Some("engineering@synthetic.example"),
            "owner",
        ));
        calendar.acl = acl;
    })
}

/// Each action's first Calendar call is the reader's rule; the calendar
/// itself is read by `calendar.v1`, or when the rule is not found.
fn calendar_plan_for(endpoint: &str) -> Plan {
    match endpoint {
        GOOGLE_EVENTS_ENDPOINT => january(),
        GOOGLE_EVENT_ENDPOINT => event_read(CALENDAR, "standup0001").unwrap(),
        _ => calendar_read("engineering@synthetic.example"),
    }
}

/// The expected answer to one fault: a code, or an outcome.
enum Expected {
    Code(&'static str),
    Outcome(&'static str),
}

fn calendar_fault_cases() -> Vec<(&'static str, SimulatedFault, Expected)> {
    use SimulatedFault::*;
    let mut cases = Vec::new();
    for endpoint in [
        GOOGLE_ACL_RULE_ENDPOINT,
        GOOGLE_CALENDAR_ENDPOINT,
        GOOGLE_ACL_ENDPOINT,
        GOOGLE_EVENTS_ENDPOINT,
        GOOGLE_EVENT_ENDPOINT,
    ] {
        cases.extend([
            (endpoint, RateLimited, Expected::Code("rate_limited")),
            // Google reports a rate or quota limit as a 403 with its reason.
            (endpoint, RateLimitForbidden, Expected::Code("rate_limited")),
            (endpoint, ServerError, Expected::Code("unavailable")),
            (endpoint, ConnectionLost, Expected::Code("unavailable")),
            (endpoint, NotJson, Expected::Code("response_invalid")),
            (endpoint, Oversized, Expected::Code("response_too_large")),
            (endpoint, BadRequest, Expected::Code("request_refused")),
            // A refused read of the reader's own rule, on a calendar the
            // reader can see, is not shared. Anywhere else it is a refusal.
            (
                endpoint,
                Denied,
                if endpoint == GOOGLE_ACL_RULE_ENDPOINT {
                    Expected::Outcome("NotShared")
                } else {
                    Expected::Code("denied")
                },
            ),
        ]);
    }
    cases
}

#[test]
fn every_scheduled_calendar_fault_is_classified_and_consumed() {
    for (endpoint, fault, expected) in calendar_fault_cases() {
        let world = World::development();
        world.fault(endpoint, fault);
        let plan = calendar_plan_for(endpoint);
        let (result, meter) = world.observe(&plan);
        match expected {
            Expected::Code(code_suffix) => assert_eq!(
                code(&result),
                format!("google_workspace_{code_suffix}"),
                "{endpoint} {fault:?}"
            ),
            Expected::Outcome(outcome) => {
                assert_eq!(
                    decoded(result),
                    serde_json::json!(outcome),
                    "{endpoint} {fault:?}"
                )
            }
        }
        assert_eq!(meter.last.map(|last| last.phase), Some(Phase::Calendar));
        let (retried, _) = world.observe(&plan);
        assert!(retried.is_ok(), "{endpoint} {fault:?} did not recover");
    }
}

#[test]
fn a_forbidden_reply_is_classified_by_its_reason_and_never_carries_it() {
    let body = |reasons: &[&str]| {
        serde_json::json!({"error":{"code":403,"message":"secret detail",
            "errors":reasons.iter().map(|reason| serde_json::json!({"domain":"usageLimits",
                "reason":reason,"message":"secret detail"})).collect::<Vec<_>>()}})
        .to_string()
        .into_bytes()
    };
    for reason in calendar::RATE_REASONS {
        assert_eq!(calendar::forbidden(&body(&[reason])), Failure::RateLimited);
    }
    for reason in [
        "forbidden",
        "insufficientPermissions",
        "accessNotConfigured",
        "requiredAccessLevel",
    ] {
        assert_eq!(
            calendar::forbidden(&body(&[reason])),
            Failure::Denied,
            "{reason}"
        );
    }
    // Any rate reason among several makes it a limit, not a refusal.
    assert_eq!(
        calendar::forbidden(&body(&["forbidden", "userRateLimitExceeded"])),
        Failure::RateLimited
    );
    for malformed in [
        &b"not json"[..],
        br#"{"error":{"code":403}}"#,
        br#"{"error":{"errors":[]}}"#,
    ] {
        assert_eq!(calendar::forbidden(malformed), Failure::ResponseInvalid);
    }
    // Only the classified code leaves; the reason and message never do.
    for failure in [
        Failure::RateLimited,
        Failure::Denied,
        Failure::ResponseInvalid,
    ] {
        assert!(!failure.code().contains("secret") && !failure.code().contains("Exceeded"));
    }
}

#[test]
fn a_calendar_is_read_as_the_calendar_reader_and_answers_one_groups_role() {
    let world = World::development();
    let (result, meter) = world.observe(&calendar_read("engineering@synthetic.example"));
    assert_eq!(
        decoded(result),
        serde_json::json!({"Found":{"id":CALENDAR,"summary":"Engineering","group_role":"Reader"}})
    );
    // Metadata, signJwt, the token exchange, the reader's own rule, the
    // calendar and one ACL page, each with compact output.
    assert_eq!(meter.calls, 6);
    let calls = world.state().calls;
    assert!(calls[1].starts_with(GOOGLE_IAM_SIGN_ENDPOINT));
    assert_eq!(calls[2], GOOGLE_OAUTH_TOKEN_ENDPOINT);
    assert_eq!(
        calls[3],
        format!(
            "{GOOGLE_ACL_RULE_ENDPOINT}:calendar/v3/calendars/{CALENDAR}/acl/user:{READER}?fields=scope%28type%2Cvalue%29%2Crole&prettyPrint=false"
        )
    );
    assert!(calls[4].starts_with(GOOGLE_CALENDAR_ENDPOINT));
    assert!(calls[5].starts_with(GOOGLE_ACL_ENDPOINT));
    assert!(
        calls[3..]
            .iter()
            .all(|call| call.ends_with("prettyPrint=false"))
    );
    // A group the ACL does not name holds no role, and the ACL never leaves.
    let (result, _) = world.observe(&calendar_read("platform@synthetic.example"));
    assert_eq!(decoded(result)["Found"]["group_role"], "None");
    // A calendar that does not exist, or one the reader cannot see at all, is
    // not found.
    let hidden = with_calendar(|calendar| {
        calendar.acl.retain(|rule| {
            rule.scope_value.as_deref() != Some(READER) && rule.scope_type != "group"
        })
    });
    let (result, _) = World::new(hidden).observe(&calendar_read("engineering@synthetic.example"));
    assert_eq!(decoded(result), serde_json::json!("NotFound"));
    let other = plan_for(
        Action::GoogleWorkspaceCalendar,
        r#"{"handle":"h","calendar_id":"c_absent@group.calendar.google.com","group_email":"engineering@synthetic.example"}"#,
    )
    .unwrap();
    assert_eq!(
        decoded(world.observe(&other).0),
        serde_json::json!("NotFound")
    );
}

/// The bound's negative regression: a calendar the reader can see, even with
/// writer access, but not through its own explicit writer or owner rule, is
/// not shared on every action.
#[test]
fn only_the_readers_own_writer_or_owner_rule_puts_a_calendar_in_play() {
    let reader_group = |world: &mut GoogleWorkspaceWorld| {
        world.groups.insert(
            "readers@synthetic.example".into(),
            GoogleGroup {
                id: "group-readers".into(),
                name: "Readers".into(),
                members: [READER.to_owned()].into(),
                aliases: Default::default(),
            },
        );
    };
    let cases: Vec<(&str, Vec<GoogleAclRule>)> = vec![
        // Organization-wide sharing, which Google models as a domain rule.
        (
            "domain reader",
            vec![rule("domain", Some("synthetic.example"), "reader")],
        ),
        (
            "domain writer",
            vec![rule("domain", Some("synthetic.example"), "writer")],
        ),
        ("default reader", vec![rule("default", None, "reader")]),
        (
            "group writer",
            vec![rule("group", Some("readers@synthetic.example"), "writer")],
        ),
        (
            "the reader's own reader rule",
            vec![rule("user", Some(READER), "reader")],
        ),
        (
            "the reader's own free/busy rule under a domain rule",
            vec![
                rule("user", Some(READER), "freeBusyReader"),
                rule("domain", Some("synthetic.example"), "reader"),
            ],
        ),
    ];
    for (name, acl) in cases {
        let mut organization = with_calendar(|calendar| {
            calendar.acl = acl.clone();
            calendar.acl.push(rule(
                "group",
                Some("engineering@synthetic.example"),
                "reader",
            ));
        });
        reader_group(&mut organization);
        let world = World::new(organization);
        for plan in [
            calendar_read("engineering@synthetic.example"),
            january(),
            event_read(CALENDAR, "standup0001").unwrap(),
        ] {
            assert_eq!(
                decoded(world.observe(&plan).0),
                serde_json::json!("NotShared"),
                "{name}: {plan:?}"
            );
        }
    }
    // The same calendars with the reader's own writer or owner rule are in play.
    for role in ["writer", "owner"] {
        let world = World::new(with_calendar(|calendar| {
            calendar.acl = vec![
                rule("domain", Some("synthetic.example"), "reader"),
                rule("user", Some(READER), role),
                rule("group", Some("engineering@synthetic.example"), "reader"),
            ];
        }));
        assert_eq!(
            decoded(
                world
                    .observe(&calendar_read("engineering@synthetic.example"))
                    .0
            )["Found"]["group_role"],
            "Reader",
            "{role}"
        );
        assert!(decoded(world.observe(&january()).0).get("Found").is_some());
    }
}

#[test]
fn the_acl_is_paged_to_its_ceiling_and_never_answered_from_part_of_it() {
    // The group's entry on the last page the ceiling reads.
    let fits = ACL_PAGE_CEILING as usize * ACL_PAGE_SIZE as usize - 1;
    let world = World::new(with_long_acl(fits));
    let (result, meter) = world.observe(&calendar_read("engineering@synthetic.example"));
    assert_eq!(decoded(result)["Found"]["group_role"], "Owner");
    assert_eq!(meter.calls, 3 + 2 + ACL_PAGE_CEILING);
    // One rule further and the role cannot be answered.
    let world = World::new(with_long_acl(fits + 1));
    let plan = calendar_read("engineering@synthetic.example");
    let (result, meter) = world.observe(&plan);
    assert_eq!(code(&result), "google_workspace_acl_page_budget");
    assert_eq!(meter.calls, plan.planned_calls());
    assert!(meter.response_bytes <= plan.response_envelope());
}

/// Every rule Google can report under the fixed mask is bounded: a scope type,
/// a value no longer than an address, and a role. A full page of the longest,
/// compact as requested, fits one Calendar response with half of it to spare,
/// and the simulation serves the ceiling's worth through the real path.
#[test]
fn a_page_of_maximal_acl_entries_fits_the_response_bound() {
    let domain = "@synthetic.example";
    let longest = format!(
        "{}{domain}",
        "g".repeat(calendar::MAX_ADDRESS_BYTES - domain.len())
    );
    let maximal = rule("group", Some(&longest), "freeBusyReader");
    let token = "t".repeat(calendar::MAX_PAGE_TOKEN_BYTES);
    let wire =
        serde_json::json!({"scope":{"type":"group","value":longest},"role":"freeBusyReader"});
    assert_eq!(wire.to_string().len(), 315);
    let body = serde_json::json!({
        "items": vec![wire; ACL_PAGE_SIZE as usize],
        "nextPageToken": token,
    })
    .to_string();
    assert_eq!(body.len(), 32_654);
    assert!(2 * body.len() <= MAX_CALENDAR_RESPONSE_BYTES);
    let reply = Reply {
        status: 200,
        metadata_flavor: false,
        json: true,
        body: body.clone().into_bytes(),
        retry_after_seconds: None,
    };
    assert_eq!(accept(&reply, MAX_CALENDAR_RESPONSE_BYTES), Ok(()));
    assert_eq!(
        calendar::parse_acl_page(body.as_bytes(), "engineering@synthetic.example"),
        Ok((None, Some(token)))
    );
    // Every page the ceiling reads full of them, the group's entry last.
    let world = World::new(with_calendar(|calendar| {
        let mut acl = vec![rule("user", Some(READER), "writer")];
        let rules = ACL_PAGE_CEILING as usize * ACL_PAGE_SIZE as usize;
        acl.extend(std::iter::repeat_n(maximal, rules - 2));
        acl.push(rule(
            "group",
            Some("engineering@synthetic.example"),
            "reader",
        ));
        calendar.acl = acl;
    }));
    let plan = calendar_read("engineering@synthetic.example");
    let (result, meter) = world.observe(&plan);
    assert_eq!(decoded(result)["Found"]["group_role"], "Reader");
    assert_eq!(meter.calls, plan.planned_calls());
    assert!(meter.response_bytes <= plan.response_envelope());
}

fn timed(id: &str, start: &str, end: &str) -> GoogleEvent {
    GoogleEvent {
        id: id.into(),
        status: "confirmed".into(),
        start: Some(GoogleTime::at(start)),
        end: Some(GoogleTime::at(end)),
        organizer: Some("ada@synthetic.example".into()),
        ..GoogleEvent::default()
    }
}

/// A calendar with every shape the events read must handle.
fn varied_calendar() -> GoogleWorkspaceWorld {
    with_calendar(|calendar| {
        calendar.events = vec![
            GoogleEvent {
                conference_id: Some("abc-defg-hij".into()),
                conference_type: Some("hangoutsMeet".into()),
                ..timed(
                    "timed0001",
                    "2026-01-05T09:00:00-08:00",
                    "2026-01-05T09:30:00-08:00",
                )
            },
            // A recurring instance whose Meet code is only in its link, run by
            // a resource calendar and created by a person.
            GoogleEvent {
                original_start: Some(GoogleTime::at("2026-01-06T17:00:00Z")),
                organizer: Some("c_room@resource.calendar.google.com".into()),
                creator: Some("o'neil+meetings@synthetic.example".into()),
                hangout_link: Some("https://meet.google.com/klm-nopq-rst".into()),
                visibility: Some("confidential".into()),
                ..timed(
                    "series_20260106T170000Z",
                    "2026-01-06T17:00:00Z",
                    "2026-01-06T18:00:00Z",
                )
            },
            // A cancelled instance reported by id alone.
            GoogleEvent {
                id: "series_20260113T170000Z".into(),
                status: "cancelled".into(),
                original_start: Some(GoogleTime::at("2026-01-13T17:00:00Z")),
                ..GoogleEvent::default()
            },
            // A Meet-shaped code from another conference solution, and a link
            // that is not Meet's: no Meet code either way.
            GoogleEvent {
                conference_id: Some("uvw-xyza-bcd".into()),
                conference_type: Some("addOn".into()),
                hangout_link: Some("https://example.com/abc-defg-hij".into()),
                visibility: Some("private".into()),
                ..timed(
                    "private0004",
                    "2026-01-08T10:00:00Z",
                    "2026-01-08T11:00:00Z",
                )
            },
            GoogleEvent {
                start: Some(GoogleTime::day("2026-01-09")),
                end: Some(GoogleTime::day("2026-01-10")),
                ..timed("allday0005", "2026-01-09T00:00:00Z", "2026-01-10T00:00:00Z")
            },
            // A cancelled instance of an all-day series: all-day, so omitted.
            GoogleEvent {
                id: "daily_20260112".into(),
                status: "cancelled".into(),
                original_start: Some(GoogleTime::day("2026-01-12")),
                ..GoogleEvent::default()
            },
            // Outside January entirely, and one ending exactly at its start.
            timed(
                "february0006",
                "2026-02-02T10:00:00Z",
                "2026-02-02T11:00:00Z",
            ),
            timed("edge0007", "2025-12-31T23:00:00Z", "2026-01-01T00:00:00Z"),
        ];
    })
}

#[test]
fn events_are_one_bounded_page_of_timed_events_with_their_meeting_codes() {
    let world = World::new(varied_calendar());
    let (result, meter) = world.observe(&january());
    let page = decoded(result)["Found"].clone();
    assert_eq!(meter.calls, 5);
    let events = page["events"].as_array().unwrap();
    let ids: Vec<_> = events
        .iter()
        .map(|event| event["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "timed0001",
            "series_20260106T170000Z",
            "private0004",
            "series_20260113T170000Z"
        ]
    );
    // An all-day event and a cancelled instance of an all-day series.
    assert_eq!(page["all_day_omitted"], 2);
    assert_eq!(page["next_page_token"], "None");
    assert_eq!(
        events[0]["status"],
        serde_json::json!({"Confirmed":{"start":"2026-01-05T09:00:00-08:00","end":"2026-01-05T09:30:00-08:00"}})
    );
    assert_eq!(
        events[0]["meeting_code"],
        serde_json::json!({"Some":"abc-defg-hij"})
    );
    assert_eq!(
        events[1]["meeting_code"],
        serde_json::json!({"Some":"klm-nopq-rst"})
    );
    assert_eq!(
        events[1]["original_start"],
        serde_json::json!({"Some":"2026-01-06T17:00:00Z"})
    );
    assert_eq!(
        events[1]["organizer"],
        serde_json::json!({"Some":"c_room@resource.calendar.google.com"})
    );
    assert_eq!(
        events[1]["creator"],
        serde_json::json!({"Some":"o'neil+meetings@synthetic.example"})
    );
    assert_eq!(events[1]["visibility"], "Confidential");
    assert_eq!(events[2]["meeting_code"], "None");
    assert_eq!(events[2]["visibility"], "Private");
    assert_eq!(events[3]["status"], serde_json::json!("CancelledUntimed"));
}

#[test]
fn event_pages_continue_only_the_query_that_issued_them() {
    let many = |calendar: &mut GoogleCalendar| {
        calendar.events = (0..30)
            .map(|index| {
                timed(
                    &format!("event{index:04}"),
                    &format!("2026-01-{:02}T10:00:00Z", index % 28 + 1),
                    &format!("2026-01-{:02}T11:00:00Z", index % 28 + 1),
                )
            })
            .collect();
    };
    let mut organization = with_calendar(many);
    let second_calendar = "c_second@group.calendar.google.com";
    let mut other = organization.calendars[CALENDAR].clone();
    many(&mut other);
    organization.calendars.insert(second_calendar.into(), other);
    let world = World::new(organization);
    let window = ("2026-01-01T00:00:00Z", "2026-01-31T00:00:00Z");
    let first = decoded(world.observe(&january()).0)["Found"].clone();
    assert_eq!(
        first["events"].as_array().unwrap().len(),
        calendar::EVENT_PAGE_SIZE as usize
    );
    let token = first["next_page_token"]["Some"]
        .as_str()
        .unwrap()
        .to_owned();
    let second = decoded(
        world
            .observe(&events_read(window.0, window.1, Some(&token)).unwrap())
            .0,
    )["Found"]
        .clone();
    assert_eq!(second["events"].as_array().unwrap().len(), 5);
    assert_eq!(second["next_page_token"], "None");
    // The same token on another window is refused by Google, not reinterpreted.
    let (result, _) =
        world.observe(&events_read("2026-01-02T00:00:00Z", window.1, Some(&token)).unwrap());
    assert_eq!(code(&result), "google_workspace_request_refused");
    // A real token another calendar's query issued is refused here too.
    let elsewhere = decoded(
        world
            .observe(&events_on(second_calendar, window.0, window.1, None).unwrap())
            .0,
    )["Found"]["next_page_token"]["Some"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(elsewhere, token);
    let (result, _) = world.observe(&events_read(window.0, window.1, Some(&elsewhere)).unwrap());
    assert_eq!(code(&result), "google_workspace_request_refused");
}

#[test]
fn an_event_is_found_all_day_or_not_found() {
    let world = World::new(varied_calendar());
    let read = |event: &str| decoded(world.observe(&event_read(CALENDAR, event).unwrap()).0);
    assert_eq!(
        read("timed0001")["Found"]["meeting_code"],
        serde_json::json!({"Some":"abc-defg-hij"})
    );
    assert_eq!(
        read("series_20260113T170000Z")["Found"]["status"],
        serde_json::json!("CancelledUntimed")
    );
    assert_eq!(read("allday0005"), serde_json::json!("AllDay"));
    assert_eq!(read("daily_20260112"), serde_json::json!("AllDay"));
    assert_eq!(read("absent0000"), serde_json::json!("NotFound"));
    // IDs are matched exactly.
    assert_eq!(read("TIMED0001"), serde_json::json!("NotFound"));
}

#[test]
fn calendar_inputs_are_exact_and_refused_before_any_exchange() {
    let invalid = |action: Action, request: serde_json::Value| {
        assert_eq!(
            plan_for(action, &request.to_string())
                .unwrap_err()
                .to_string(),
            "google_workspace_request_invalid",
            "{request}"
        );
    };
    for calendar in [
        "C_ENGINEERING@group.calendar.google.com",
        "../c_engineering@group.calendar.google.com",
        "c_engineering%2F@group.calendar.google.com",
        "a/b@group.calendar.google.com",
        "en.usa#holiday@group.v.calendar.google.com",
        "primary",
        "c_engineering@localhost",
        "c engineering@group.calendar.google.com",
        "",
    ] {
        invalid(
            Action::GoogleWorkspaceCalendar,
            serde_json::json!({"handle":"h","calendar_id":calendar,"group_email":"engineering@synthetic.example"}),
        );
        invalid(
            Action::GoogleWorkspaceCalendarEvent,
            serde_json::json!({"handle":"h","calendar_id":calendar,"event_id":"standup0001"}),
        );
    }
    for event in [
        "../standup0001",
        "a/b",
        "a b",
        "a%2Fb",
        "a.b",
        "",
        &"x".repeat(1025),
    ] {
        invalid(
            Action::GoogleWorkspaceCalendarEvent,
            serde_json::json!({"handle":"h","calendar_id":CALENDAR,"event_id":event}),
        );
    }
    for (time_min, time_max) in [
        // No offset, fractional seconds, a lower-case separator, an impossible
        // date, a reversed window, an empty one and one longer than 31 days.
        ("2026-01-01T00:00:00", "2026-01-31T00:00:00Z"),
        ("2026-01-01T00:00:00.5Z", "2026-01-31T00:00:00Z"),
        ("2026-01-01t00:00:00Z", "2026-01-31T00:00:00Z"),
        ("2026-02-30T00:00:00Z", "2026-03-02T00:00:00Z"),
        ("2026-01-31T00:00:00Z", "2026-01-01T00:00:00Z"),
        ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        ("2026-01-01T00:00:00Z", "2026-02-01T00:00:01Z"),
        ("2026-01-01T00:00:00+24:00", "2026-01-31T00:00:00Z"),
    ] {
        assert!(
            events_read(time_min, time_max, None).is_err(),
            "{time_min} {time_max}"
        );
    }
    // Exactly 31 days, and an offset window, are admitted.
    assert!(events_read("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", None).is_ok());
    assert!(
        events_read(
            "2026-01-01T00:00:00-08:00",
            "2026-01-31T23:59:59+05:30",
            None
        )
        .is_ok()
    );
    // Nothing JSON escapes, so a carried token journals at its own size.
    for token in ["", "a b", "a\"b", "a\\b", &"x".repeat(1025)] {
        assert!(
            events_read("2026-01-01T00:00:00Z", "2026-01-31T00:00:00Z", Some(token)).is_err(),
            "{token}"
        );
    }
    // A group outside the grant is refused as an authorization.
    let error = plan_for(
        Action::GoogleWorkspaceCalendar,
        &serde_json::json!({"handle":"h","calendar_id":CALENDAR,"group_email":"team@other.example"})
            .to_string(),
    )
    .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<crate::error::Failure>(),
        Some(crate::error::Failure::ResourceForbidden)
    ));
}

impl World {
    /// One Calendar request with any bearer, as a client could send it.
    fn calendar_route(
        &self,
        segments: &[&str],
        bearer: &str,
        query: &[(&'static str, &str)],
    ) -> Reply {
        simulated::google_workspace_serve(
            &self.database,
            SCOPE,
            simulated::GoogleRequest::Api {
                request: &ApiRequest::calendar("probe", segments, query),
                bearer,
            },
            MAX_CALENDAR_RESPONSE_BYTES,
        )
        .unwrap()
    }
}

#[test]
fn the_simulation_answers_calendars_only_to_a_delegated_subject_with_access() {
    let mut organization = simulated::google_workspace_development_fixture();
    organization
        .users
        .insert("outsider@synthetic.example".into());
    let world = World::new(organization);
    let route = ["calendars", CALENDAR];
    let mask = [("fields", calendar::CALENDAR_FIELDS)];
    let token = |subject: &str, scopes: &[&str]| {
        world
            .token(google_auth::Identity::Delegated(subject), scopes)
            .unwrap()
    };
    // The reader, delegated with calendar.readonly, sees the calendar.
    let reader = token(READER, &[CALENDAR_READ_SCOPE]);
    assert_eq!(
        world.calendar_route(&route, reader.bearer(), &mask).status,
        200
    );
    // Only the reviewed query is served.
    assert_eq!(
        world.calendar_route(&route, reader.bearer(), &[]).status,
        400
    );
    assert_eq!(
        world
            .calendar_route(
                &route,
                reader.bearer(),
                &[("fields", "id,summary,timeZone")]
            )
            .status,
        400
    );
    // Nor any events query but the reviewed one, on the events route too.
    type Query = Vec<(&'static str, &'static str)>;
    type Adjust = fn(&mut Query);
    let events = ["calendars", CALENDAR, "events"];
    let status = |adjust: Adjust| {
        let mut query: Query = calendar::EVENTS_QUERY.to_vec();
        query.extend([
            ("timeMin", "2026-01-01T00:00:00Z"),
            ("timeMax", "2026-01-31T00:00:00Z"),
            ("fields", calendar::EVENTS_FIELDS),
        ]);
        adjust(&mut query);
        world
            .calendar_route(&events, reader.bearer(), &query)
            .status
    };
    assert_eq!(status(|_| {}), 200);
    let unreviewed: [(&str, Adjust); 5] = [
        ("a larger page", |query| query[3] = ("maxResults", "250")),
        ("deleted events hidden", |query| {
            query[2] = ("showDeleted", "false")
        }),
        ("another mask", |query| {
            query[6] = ("fields", "items(id,description),nextPageToken")
        }),
        ("an extra parameter", |query| query.push(("q", "standup"))),
        ("no window", |query| {
            query.retain(|(name, _)| *name != "timeMin")
        }),
    ];
    for (name, adjust) in unreviewed {
        assert_eq!(status(adjust), 400, "{name}");
    }
    // Someone no rule applies to does not see it; a group rule shows it to a
    // member, through nested membership too.
    let outsider = token("outsider@synthetic.example", &[CALENDAR_READ_SCOPE]);
    assert_eq!(
        world
            .calendar_route(&route, outsider.bearer(), &mask)
            .status,
        404
    );
    let grace = token(
        "grace@synthetic.example",
        &[CALENDAR_READ_SCOPE, CALENDAR_ACL_READ_SCOPE],
    );
    assert_eq!(
        world.calendar_route(&route, grace.bearer(), &mask).status,
        200
    );
    // But reading a rule needs writer or owner.
    let grace_rule = format!("user:{READER}");
    assert_eq!(
        world
            .calendar_route(
                &["calendars", CALENDAR, "acl", &grace_rule],
                grace.bearer(),
                &[("fields", calendar::RULE_FIELDS)]
            )
            .status,
        403
    );
    // The service account itself has no calendars.
    let direct = world
        .token(
            google_auth::Identity::ServiceAccount,
            &[CALENDAR_READ_SCOPE],
        )
        .unwrap();
    assert_eq!(
        world.calendar_route(&route, direct.bearer(), &mask).status,
        404
    );
    // A token for another scope cannot read Calendar at all.
    let meetings = token(
        READER,
        &["https://www.googleapis.com/auth/meetings.space.readonly"],
    );
    assert_eq!(
        world
            .calendar_route(&route, meetings.bearer(), &mask)
            .status,
        403
    );
    // A reader who is not a person in the organization cannot be delegated to.
    let mut without_reader = simulated::google_workspace_development_fixture();
    without_reader.users.remove(READER);
    let (result, meter) =
        World::new(without_reader).observe(&calendar_read("engineering@synthetic.example"));
    assert_eq!(code(&result), "google_workspace_authentication_failed");
    assert_eq!(meter.last.map(|last| last.phase), Some(Phase::Token));
}

#[test]
fn calendar_plans_reserve_the_delegated_envelope() {
    let read = calendar_read("engineering@synthetic.example");
    assert_eq!(read.planned_calls(), 3 + 2 + ACL_PAGE_CEILING);
    assert_eq!(read.max_response_bytes(), MAX_CALENDAR_RESPONSE_BYTES);
    assert_eq!(
        read.response_envelope(),
        3 * (google_auth::MAX_EXCHANGE_RESPONSE_BYTES as u64 + 1)
            + (2 + ACL_PAGE_CEILING) * (MAX_CALENDAR_RESPONSE_BYTES as u64 + 1)
    );
    for plan in [january(), event_read(CALENDAR, "standup0001").unwrap()] {
        assert_eq!(plan.planned_calls(), 5);
    }
    assert_eq!(
        group_plan("engineering@synthetic.example").max_response_bytes(),
        MAX_DIRECTORY_RESPONSE_BYTES
    );
    let world = World::new(varied_calendar());
    for plan in [read, january(), event_read(CALENDAR, "timed0001").unwrap()] {
        let (result, meter) = world.observe(&plan);
        result.unwrap();
        assert!(meter.calls <= plan.planned_calls());
        assert!(meter.response_bytes <= plan.response_envelope());
        assert!(meter.request_bytes <= MAX_ACTION_REQUEST_BYTES);
    }
    // The not-shared path stays inside the same envelope.
    let world = World::new(with_calendar(|calendar| {
        calendar.acl = vec![rule("default", None, "reader")];
    }));
    for plan in [january(), event_read(CALENDAR, "standup0001").unwrap()] {
        let (result, meter) = world.observe(&plan);
        assert_eq!(decoded(result), serde_json::json!("NotShared"));
        assert!(meter.calls <= plan.planned_calls());
    }
}

/// Every address and id is bounded to characters JSON never escapes, so the
/// largest page the adapter can admit still fits one journaled observation.
#[test]
fn the_largest_admissible_page_fits_one_observation() {
    let address = |local: char, length: usize| {
        let domain = "@synthetic.example";
        format!(
            "{}{domain}",
            String::from(local).repeat(length - domain.len())
        )
    };
    let time = "2026-01-05T09:00:00+05:30";
    let item = |index: usize| {
        serde_json::json!({
            "id": format!("{index:02}{}", "a".repeat(calendar::MAX_ID_BYTES - 2)),
            "status": "confirmed",
            "visibility": "confidential",
            "start": {"dateTime": time},
            "end": {"dateTime": time},
            "originalStartTime": {"dateTime": time},
            "organizer": {"email": address('o', calendar::MAX_ADDRESS_BYTES)},
            "creator": {"email": address('c', calendar::MAX_ADDRESS_BYTES)},
            "conferenceData": {"conferenceId": "abc-defg-hij",
                "conferenceSolution": {"key": {"type": "hangoutsMeet"}}},
        })
    };
    let body = serde_json::json!({
        "items": (0..calendar::EVENT_PAGE_SIZE as usize).map(item).collect::<Vec<_>>(),
        "nextPageToken": "t".repeat(calendar::MAX_PAGE_TOKEN_BYTES),
    })
    .to_string();
    let page = calendar::parse_events_page(body.as_bytes()).unwrap();
    assert_eq!(page.events.len(), calendar::EVENT_PAGE_SIZE as usize);
    let result = encode(&calendar::EventsOutcome::Found(page));
    // The largest request the adapter admits, padded through its handle.
    let mut request = serde_json::json!({"handle":"","calendar_id":address('x', calendar::MAX_ADDRESS_BYTES),
        "time_min":time,"time_max":time,"page_token":{"Some":"t".repeat(calendar::MAX_PAGE_TOKEN_BYTES)}});
    let unpadded = request.to_string().len();
    request["handle"] = serde_json::json!("h".repeat(MAX_INPUT_BYTES - unpadded));
    let data = request.to_string();
    assert_eq!(data.len(), MAX_INPUT_BYTES);
    let instruction = crate::protocol::Instruction {
        kind: "observe".into(),
        model: "google_workspace.calendar_events.v1".into(),
        data,
        ..Default::default()
    };
    let journaled = crate::resources::bounded_observation(crate::protocol::Observation {
        instruction,
        result: result.clone(),
        error: String::new(),
    })
    .unwrap();
    assert_eq!(
        journaled.result, result,
        "the page did not fit one observation"
    );
    assert!(journaled.error.is_empty());
    // An address with characters JSON escapes is refused, never journaled.
    for email in [
        "a\"b@synthetic.example",
        "a\\b@synthetic.example",
        "a b@synthetic.example",
        "a@b@c.example",
    ] {
        let mut escaped = serde_json::from_str::<serde_json::Value>(&body).unwrap();
        escaped["items"][0]["creator"]["email"] = serde_json::json!(email);
        assert_eq!(
            calendar::parse_events_page(escaped.to_string().as_bytes()),
            Err(Failure::ResponseInvalid),
            "{email}"
        );
    }
}

#[path = "google_workspace_meet_tests.rs"]
mod meet;
