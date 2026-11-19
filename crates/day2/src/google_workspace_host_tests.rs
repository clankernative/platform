//! Host-only conformance for `google_workspace.group.v1` and `group_member.v1`:
//! real acceptance, opaque handles, the authority transaction, budget
//! reservation and SQLite settlement, against the simulated Google world. The
//! contract is supplied by the test; this does not claim compiled Roc artifact
//! admission.
use super::*;
use crate::{
    authority_state, integration_host,
    integrations::simulated::{
        GOOGLE_ACL_ENDPOINT, GOOGLE_DEVELOPMENT_CALENDAR, GOOGLE_DEVELOPMENT_CALENDAR_READER,
        GOOGLE_DEVELOPMENT_SERVICE_ACCOUNT, GOOGLE_GROUP_ENDPOINT, ScheduledFault, SimulatedFault,
    },
};
use day2_capabilities::{integrations::LiveConnection, resources::ResourceTarget};
use rusqlite::TransactionBehavior;
use std::collections::BTreeMap;

const ACTOR: &str = "lookup@synthetic.example";
const SCOPE: &str = "workspaceco/test/app";
const NOW: i64 = 1_700_000_001;
const GROUP: &str = "google_workspace.group.v1";
const MEMBER: &str = "google_workspace.group_member.v1";
const CALENDAR: &str = "google_workspace.calendar.v1";
const EVENTS: &str = "google_workspace.calendar_events.v1";
const EVENT: &str = "google_workspace.calendar_event.v1";
const CONFERENCES: &str = "google_workspace.event_conferences.v1";

struct Setup {
    simulated: bool,
    max_request_bytes: u64,
    max_response_bytes: u64,
    max_calls: u64,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            simulated: true,
            max_request_bytes: crate::google_workspace::MAX_ACTION_REQUEST_BYTES,
            max_response_bytes: crate::google_workspace::MAX_RESPONSE_BYTES as u64,
            max_calls: 32,
        }
    }
}

/// Operations and the slot each binds:
/// - `lookup` reads through the reviewed connection;
/// - `lookup_other` reads through a second connection naming another service
///   account;
/// - `directory` holds only a Workspace Directory grant.
fn runtime(setup: Setup) -> Result<(tempfile::TempDir, Runtime)> {
    let directory = tempfile::tempdir()?;
    let instance_path = directory.path().join("instance.json");
    let state = directory.path().join(".state");
    fs::create_dir_all(&state)?;
    let artifact_directory = directory.path().join("google-workspace-contract");
    fs::create_dir(&artifact_directory)?;
    let live = |service_account: &str| {
        serde_json::to_value(LiveConnection::GoogleWorkspace {
            service_account: service_account.into(),
        })
    };
    let target = serde_json::to_value(ResourceTarget::GoogleWorkspaceDomain {
        calendar_reader: GOOGLE_DEVELOPMENT_CALENDAR_READER.into(),
        email_domain: "synthetic.example".into(),
        grantee_domains: vec!["synthetic.example".into()],
    })?;
    let operation = |observations: &[&str]| json!({"actors":[ACTOR],"mode":{"kind":"read"},"models":{},"observations":observations,"effects":[]});
    let policy = json!({"version":1,"admins":[],"operations":{
        "lookup":operation(&[CALENDAR, EVENT, EVENTS, CONFERENCES, GROUP, MEMBER]),
        "lookup_other":operation(&[GROUP]),
        "directory":operation(&[CALENDAR, CONFERENCES, GROUP, "workspace_directory.user_path.v1"])}});
    let slot = |resource: &str| {
        json!({"google_workspace":{"kind":"google_workspace_domain",
            "allowed_resources":[{"id":resource,"revision":1}],
            "actions":["google_workspace_calendar","google_workspace_calendar_event",
                "google_workspace_calendar_events","google_workspace_event_conferences",
                "google_workspace_group","google_workspace_group_member"],
            "limits":{"max_request_bytes":setup.max_request_bytes,
                "max_response_bytes":setup.max_response_bytes,
                "max_calls_per_invocation":setup.max_calls},
            "budgets":[{"id":"workspace_budget","revision":1}]}})
    };
    let catalog = json!({"version":1,
        "connections":{
            "workspace":{"revision":1,"provider":"google_workspace",
                "live":live(GOOGLE_DEVELOPMENT_SERVICE_ACCOUNT)?},
            "workspace_other":{"revision":1,"provider":"google_workspace",
                "live":live("someone-else@synthetic-project.iam.gserviceaccount.com")?},
            "directory":{"revision":1,"provider":"workspace_directory",
                "live":{"provider":"workspace_directory",
                    "service_account":"directory-reader@synthetic-project.iam.gserviceaccount.com",
                    "auth":{"mode":"direct_service_account"}}}},
        "resources":{
            "groups":{"revision":1,"connection":{"id":"workspace","revision":1},"target":target},
            "groups_other":{"revision":1,"connection":{"id":"workspace_other","revision":1},"target":target},
            "directory":{"revision":1,"connection":{"id":"directory","revision":1},
                "target":{"kind":"workspace_directory","customer_id":"Csynthetic"}}},
        "policies":{
            "workspace_read":{"revision":1,"owner":"it","actors":[ACTOR],"allowed_apps":["app"],
                "max_duration_seconds":null,"slots":slot("groups")},
            "workspace_other_read":{"revision":1,"owner":"it","actors":[ACTOR],"allowed_apps":["app"],
                "max_duration_seconds":null,"slots":slot("groups_other")},
            "directory_read":{"revision":1,"owner":"it","actors":[ACTOR],"allowed_apps":["app"],
                "max_duration_seconds":null,"slots":{"google_workspace":{"kind":"workspace_directory",
                    "allowed_resources":[{"id":"directory","revision":1}],
                    "actions":["workspace_directory_user_path"],
                    "limits":{"max_request_bytes":32_768,"max_response_bytes":65_537,
                        "max_calls_per_invocation":4},"budgets":[]}}}},
        "budgets":{"workspace_budget":{"revision":1,"scope":"app","period_seconds":3600,
            "limits":{"calls":1000,"bytes":100_000_000,"concurrency":1}}}});
    let attachment = |policy: &str, operation: &str, resource: &str| {
        json!({"policy":{"id":policy,"revision":1},"operation":operation,
            "bindings":{"google_workspace":{"id":resource,"revision":1}}})
    };
    let instance = json!({"installation":"workspaceco","environment":"test","resources":catalog,
        "apps":{"app":{"artifact":artifact_directory,"readers":[ACTOR],"writers":[ACTOR],"authority":policy,
            "resource_policies":[
                attachment("workspace_read", "lookup", "groups"),
                attachment("workspace_other_read", "lookup_other", "groups_other"),
                attachment("directory_read", "directory", "directory")]}}});
    fs::write(&instance_path, serde_json::to_vec(&instance)?)?;
    let contract = serde_json::from_value(json!({
        "format":crate::artifact::CURRENT_FORMAT,"verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
        "roc_version":"google-workspace-test","worker_digest":"google-workspace-test",
        "schema_digest":"google-workspace-test",
        "schema":{"models":{"items":{"fields":{"value":"text"}}},"inputs":{"input":{"fields":{}}},"foreign_keys":[]},
        "operations":[{"name":"lookup","kind":"query","input_type":"input","output_type":"output"},
            {"name":"lookup_other","kind":"query","input_type":"input","output_type":"output"},
            {"name":"directory","kind":"query","input_type":"input","output_type":"output"}],
        "sources":{},"admission":"local-spike-only"}))?;
    let inputs = crate::host_inputs::Inputs {
        clock: Arc::new(crate::host_inputs::simulation::VirtualClock(
            std::sync::Mutex::new((
                std::time::Duration::from_secs(NOW as u64),
                std::time::Duration::ZERO,
            )),
        )),
        ..Default::default()
    };
    let runtime = Runtime {
        integrations: Arc::new(integration_host::Host::local(&instance_path)?),
        app_calls: None,
        credentials: None,
        connections: None,
        rolling: false,
        restore_registry_selector: None,
        executor_generation: Arc::new(std::sync::OnceLock::new()),
        instance_digest: crate::digest(b"nonrolling test instance"),
        native_database: None,
        instance_path,
        app: "app".into(),
        db: state.join("app.sqlite"),
        scope: SCOPE.into(),
        hosted_domain: None,
        artifact: Arc::new(LoadedArtifact::from_contract_for_tests(
            "google-workspace-test".into(),
            artifact_directory,
            contract,
        )),
        host: Arc::new(crate::host::System(inputs.clone())),
        inputs,
    };
    let runtime = if setup.simulated {
        runtime.with_integrations(integration_host::Host::simulated_providers_with_app_calls(
            &state.join("app.sqlite"),
            SCOPE,
        ))
    } else {
        runtime
    };
    runtime.initialize()?;
    crate::integrations::simulated::seed(
        runtime.db(),
        SCOPE,
        &crate::integrations::simulated::SimulatedFixture {
            slack: crate::integrations::simulated::SlackWorld {
                workspace_id: "TWORKSPACE".into(),
                ..Default::default()
            },
            snowflake: crate::integrations::simulated::SnowflakeWorld {
                account: "workspace-test".into(),
                ..Default::default()
            },
            openai: crate::integrations::simulated::OpenAiWorld {
                project_id: "proj_workspace".into(),
                model: "model-workspace".into(),
                max_input_tokens: 100_000,
                ..Default::default()
            },
            google_workspace: crate::integrations::simulated::google_workspace_development_fixture(
            ),
            ..Default::default()
        },
    )?;
    Ok((directory, runtime))
}

/// Bind the operation's resource and authorize one capability, as preparation
/// does, without reserving or dispatching anything.
fn authorize(
    runtime: &Runtime,
    operation: &str,
    invocation: &str,
    capability: &str,
    data: impl FnOnce(&str) -> Value,
) -> Result<(
    Request,
    Instruction,
    crate::capabilities::Authorized,
    rusqlite::Connection,
)> {
    runtime.accept(operation, ACTOR, invocation, &json!({}), NOW)?;
    let mut connection = open(runtime.db())?;
    let request;
    let instruction;
    let authorized;
    {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        request = Request {
            operation: operation.into(),
            input: "{}".into(),
            context: crate::store::invocation_context(&tx, invocation)?,
            observations: vec![],
        };
        let bound = crate::resources::host_operation(
            &tx,
            runtime,
            &request,
            &Instruction {
                kind: "observe".into(),
                model: crate::resources::BIND.into(),
                data: json!({"binding":"google_workspace","invocation":invocation}).to_string(),
                ..Default::default()
            },
        )?
        .context("google workspace resource binding")?;
        let handle = serde_json::from_str::<Value>(&bound)?["token"]
            .as_str()
            .context("opaque handle")?
            .to_owned();
        instruction = Instruction {
            kind: "observe".into(),
            model: capability.into(),
            data: data(&handle).to_string(),
            ..Default::default()
        };
        let active = authority_state::current(&tx)?;
        authorized = crate::capabilities::authorized(
            &tx,
            runtime,
            &request,
            &instruction,
            active.policy()?,
            "ob_google_workspace",
        )?;
        tx.commit()?;
    }
    Ok((request, instruction, authorized, connection))
}

struct Admitted {
    result: std::result::Result<String, String>,
    usage: crate::resources::ProviderUsage,
    reserved: crate::resources::ProviderQuote,
    correlation: Vec<crate::integrations::ExchangeCorrelation>,
}

/// One observation through admission, reservation, dispatch and settlement.
fn admitted(
    runtime: &Runtime,
    operation: &str,
    invocation: &str,
    capability: &str,
    data: impl FnOnce(&str) -> Value,
) -> Result<Admitted> {
    let (request, instruction, capability, mut connection) =
        authorize(runtime, operation, invocation, capability, data)?;
    let resource = capability.resource().clone();
    let reserved = capability.quote();
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    crate::resources::record_use(&tx, invocation, &resource)?;
    let reservation = crate::resources::reserve_in(
        &tx,
        runtime,
        &request,
        &instruction,
        invocation,
        &resource,
        reserved,
    )?;
    tx.commit()?;
    let outcome = crate::capabilities::observe(runtime, capability, invocation);
    let result = outcome.result.and_then(|result| {
        crate::resources::validate_result(&resource, &result)?;
        Ok(result)
    });
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    crate::resources::record_correlation_in(&tx, invocation, &outcome.correlation)?;
    crate::resources::settle_in(&tx, &reservation, outcome.usage)?;
    tx.commit()?;
    Ok(Admitted {
        result: result.map_err(|error| crate::error::observation_code(&error)),
        usage: outcome.usage,
        reserved,
        correlation: outcome.correlation,
    })
}

fn group(handle: &str) -> Value {
    json!({"handle":handle,"group_email":"engineering@synthetic.example"})
}

fn calls(runtime: &Runtime) -> Result<Vec<String>> {
    crate::integrations::simulated::update_google_workspace(runtime.db(), SCOPE, |state| {
        Ok(state.calls.clone())
    })
}

/// Settled budget usage by unit, and whatever is still held.
fn budget(runtime: &Runtime) -> Result<BTreeMap<String, (i64, i64)>> {
    let connection = open(runtime.db())?;
    let mut query = connection.prepare("SELECT unit,used,held FROM day2_budget_accounts")?;
    let rows = query
        .query_map([], |row| Ok((row.get(0)?, (row.get(1)?, row.get(2)?))))?
        .collect::<rusqlite::Result<BTreeMap<String, (i64, i64)>>>()?;
    Ok(rows)
}

#[test]
fn a_read_reserves_its_envelope_and_settles_exactly_what_it_measured() -> Result<()> {
    let (_directory, runtime) = runtime(Setup::default())?;
    let read = admitted(&runtime, "lookup", "group-read", GROUP, group)?;
    assert_eq!(
        read.result,
        Ok(
            r#"{"Found":{"email":"engineering@synthetic.example","id":"group-engineering","name":"Engineering"}}"#
                .into()
        )
    );
    assert!(read.correlation.is_empty());
    assert_eq!(
        read.reserved.request_bytes,
        crate::google_workspace::MAX_ACTION_REQUEST_BYTES
    );
    // Metadata, IAM and the Directory: the IAM body and the Directory query are
    // the only request payload, and every response byte is counted.
    assert_eq!(read.usage.calls, 3);
    let iam = crate::google_auth::direct_body(&[crate::google_workspace::GROUP_READ_SCOPE])?;
    assert_eq!(
        read.usage.request_bytes,
        (iam.len() + "fields=id%2Cemail%2Cname&prettyPrint=false".len()) as u64
    );
    assert!(
        read.usage.response_bytes > 0 && read.usage.response_bytes < read.reserved.response_bytes
    );
    assert!(read.usage.known && read.usage.dispatched);
    assert_eq!(calls(&runtime)?.len(), 3);
    let settled = budget(&runtime)?;
    assert_eq!(settled["calls"], (3, 0));
    assert_eq!(
        settled["bytes"],
        (
            (read.usage.request_bytes + read.usage.response_bytes) as i64,
            0
        )
    );

    let membership = admitted(&runtime, "lookup", "member-read", MEMBER, |handle| {
        json!({"handle":handle,"group_email":"engineering@synthetic.example",
            "member_email":"grace@synthetic.example"})
    })?;
    assert_eq!(membership.result, Ok(r#""Member""#.into()));
    assert_eq!(membership.usage.calls, 4);
    assert_eq!(budget(&runtime)?["calls"], (7, 0));
    Ok(())
}

#[test]
fn a_failed_read_correlates_only_its_final_phase_status_and_retry_after() -> Result<()> {
    let (_directory, runtime) = runtime(Setup::default())?;
    crate::integrations::simulated::schedule_faults(
        runtime.db(),
        SCOPE,
        crate::integrations::simulated::GOOGLE_WORKSPACE_WORLD,
        vec![ScheduledFault {
            endpoint: GOOGLE_GROUP_ENDPOINT.into(),
            remaining: 1,
            fault: SimulatedFault::RateLimited,
        }],
    )?;
    let failed = admitted(&runtime, "lookup", "rate-limited", GROUP, group)?;
    assert_eq!(failed.result, Err("google_workspace_rate_limited".into()));
    assert_eq!(
        serde_json::to_value(&failed.correlation)?,
        json!([{"phase":"google_workspace_directory","http_status":429,"request_id":null,
            "statement_handle":null,"retry_after_seconds":30}])
    );
    // The refused exchange was still provider traffic, and is settled as such.
    assert_eq!(failed.usage.calls, 3);
    assert!(failed.usage.known && failed.usage.response_bytes > 0);
    assert_eq!(budget(&runtime)?["calls"], (3, 0));
    Ok(())
}

#[test]
fn a_grant_on_another_provider_or_connection_never_reaches_the_directory() -> Result<()> {
    let (_directory, runtime) = runtime(Setup::default())?;
    // A Workspace Directory grant cannot carry a Google Workspace action.
    let refused = authorize(&runtime, "directory", "other-provider", GROUP, group)
        .err()
        .context("another provider's grant was accepted")?;
    assert!(
        matches!(
            refused.downcast_ref::<crate::error::Failure>(),
            Some(crate::error::Failure::ResourceForbidden)
        ),
        "{refused:#}"
    );
    assert!(calls(&runtime)?.is_empty());
    // A grant through a connection naming another service account is refused
    // by IAM before any Directory request.
    let other = admitted(&runtime, "lookup_other", "other-connection", GROUP, group)?;
    assert_eq!(
        other.result,
        Err("google_workspace_authentication_failed".into())
    );
    let served = calls(&runtime)?;
    assert_eq!(served.len(), 2);
    assert!(!served.iter().any(|call| call.contains("directory")));
    // Membership across domains is refused before anything is reserved.
    let cross = authorize(&runtime, "lookup", "cross-domain", MEMBER, |handle| {
        json!({"handle":handle,"group_email":"engineering@synthetic.example",
            "member_email":"ada@other.example"})
    })
    .err()
    .context("a member outside the group's domain was accepted")?;
    assert!(matches!(
        cross.downcast_ref::<crate::error::Failure>(),
        Some(crate::error::Failure::ResourceForbidden)
    ));
    Ok(())
}

fn calendar(handle: &str) -> Value {
    json!({"handle":handle,"calendar_id":GOOGLE_DEVELOPMENT_CALENDAR,
        "group_email":"engineering@synthetic.example"})
}

#[test]
fn limits_below_the_envelope_are_refused_before_any_reservation() -> Result<()> {
    let directory = crate::google_workspace::MAX_DIRECTORY_RESPONSE_BYTES as u64;
    let calendar_response = crate::google_workspace_calendar::MAX_CALENDAR_RESPONSE_BYTES as u64;
    for (setup, capability, data) in [
        (
            Setup {
                max_request_bytes: crate::google_workspace::MAX_ACTION_REQUEST_BYTES - 1,
                ..Setup::default()
            },
            GROUP,
            group as fn(&str) -> Value,
        ),
        (
            Setup {
                max_response_bytes: directory - 1,
                ..Setup::default()
            },
            GROUP,
            group,
        ),
        (
            Setup {
                max_request_bytes: crate::google_workspace::MAX_ACTION_REQUEST_BYTES - 1,
                ..Setup::default()
            },
            CALENDAR,
            calendar,
        ),
        // A grant sized for the Directory is too small for a Calendar page.
        (
            Setup {
                max_response_bytes: directory,
                ..Setup::default()
            },
            CALENDAR,
            calendar,
        ),
        (
            Setup {
                max_response_bytes: calendar_response - 1,
                ..Setup::default()
            },
            CALENDAR,
            calendar,
        ),
    ] {
        let (_directory, runtime) = runtime(setup)?;
        let refused = authorize(&runtime, "lookup", "short-grant", capability, data)
            .err()
            .context("a grant below the envelope was accepted")?;
        assert!(matches!(
            refused.downcast_ref::<crate::error::Failure>(),
            Some(crate::error::Failure::ResourceForbidden)
        ));
        assert!(calls(&runtime)?.is_empty());
        assert!(budget(&runtime)?.is_empty(), "nothing was reserved");
    }
    // The Directory envelope is enough for a Directory read.
    let (_directory, runtime) = runtime(Setup {
        max_response_bytes: directory,
        ..Setup::default()
    })?;
    assert!(authorize(&runtime, "lookup", "directory-sized", GROUP, group).is_ok());
    Ok(())
}

#[test]
fn calendar_reads_are_delegated_reserved_and_settled_like_any_read() -> Result<()> {
    let (_directory, runtime) = runtime(Setup::default())?;
    let read = admitted(&runtime, "lookup", "calendar-read", CALENDAR, calendar)?;
    assert_eq!(
        read.result,
        Ok(format!(
            r#"{{"Found":{{"group_role":"Reader","id":"{GOOGLE_DEVELOPMENT_CALENDAR}","summary":"Engineering"}}}}"#
        ))
    );
    // Metadata, signJwt, the token exchange, the reader's own rule, the
    // calendar and one ACL page, against a reservation of every ACL page the
    // ceiling allows.
    assert_eq!(read.usage.calls, 6);
    assert!(read.usage.known && read.usage.request_bytes > 0);
    assert!(read.usage.response_bytes < read.reserved.response_bytes);
    let settled = budget(&runtime)?;
    assert_eq!(settled["calls"], (6, 0));
    assert_eq!(
        settled["bytes"],
        (
            (read.usage.request_bytes + read.usage.response_bytes) as i64,
            0
        )
    );
    let served = calls(&runtime)?;
    assert!(served[1].starts_with("google_workspace.iam.sign_jwt"));
    let events = admitted(&runtime, "lookup", "events-read", EVENTS, |handle| {
        json!({"handle":handle,"calendar_id":GOOGLE_DEVELOPMENT_CALENDAR,
            "time_min":"2026-01-01T00:00:00Z","time_max":"2026-01-31T00:00:00Z","page_token":"None"})
    })?;
    let page: Value = serde_json::from_str(
        events
            .result
            .as_deref()
            .map_err(|code| anyhow::anyhow!("{code}"))?,
    )?;
    assert_eq!(page["Found"]["events"].as_array().map(Vec::len), Some(2));
    assert_eq!(page["Found"]["all_day_omitted"], 1);
    assert_eq!(events.usage.calls, 5);
    let event = admitted(
        &runtime,
        "lookup",
        "event-read",
        EVENT,
        |handle| json!({"handle":handle,"calendar_id":GOOGLE_DEVELOPMENT_CALENDAR,"event_id":"standup0001"}),
    )?;
    assert!(
        event
            .result
            .as_deref()
            .is_ok_and(|result| result.starts_with(r#"{"Found""#))
    );
    assert_eq!(budget(&runtime)?["calls"], (16, 0));
    // A Workspace Directory grant cannot carry a Calendar action either.
    let refused = authorize(
        &runtime,
        "directory",
        "calendar-other-provider",
        CALENDAR,
        calendar,
    )
    .err()
    .context("another provider's grant was accepted")?;
    assert!(matches!(
        refused.downcast_ref::<crate::error::Failure>(),
        Some(crate::error::Failure::ResourceForbidden)
    ));
    // The plan is frozen with the simulated source.
    let (.., authorized, _) = authorize(&runtime, "lookup", "calendar-source", CALENDAR, calendar)?;
    assert_eq!(
        authorized
            .google_workspace_plan()
            .context("a Google Workspace plan")?
            .source(),
        crate::google_workspace::Source::Simulated
    );
    Ok(())
}

/// The delegated subject is the grant's reader and no one else: a calendar
/// only the reader has a rule on is found, and one only another person owns is
/// not. Delegating as anyone else would answer the other way round.
#[test]
fn calendar_reads_are_delegated_as_the_grants_reader() -> Result<()> {
    use crate::integrations::simulated::{GoogleAclRule, GoogleCalendar};
    const READERS_ONLY: &str = "c_readers-only@group.calendar.google.com";
    const ADAS_OWN: &str = "c_adas-own@group.calendar.google.com";
    let (_directory, runtime) = runtime(Setup::default())?;
    let rule = |person: &str, role: &str| GoogleAclRule {
        scope_type: "user".into(),
        scope_value: Some(person.into()),
        role: role.into(),
    };
    crate::integrations::simulated::update_google_workspace(runtime.db(), SCOPE, |state| {
        for (id, owner) in [
            (READERS_ONLY, GOOGLE_DEVELOPMENT_CALENDAR_READER),
            (ADAS_OWN, "ada@synthetic.example"),
        ] {
            state.world.calendars.insert(
                id.into(),
                GoogleCalendar {
                    summary: "Synthetic".into(),
                    acl: vec![rule(owner, "owner")],
                    events: Vec::new(),
                },
            );
        }
        Ok(())
    })?;
    let read = |invocation: &str, id: &'static str| -> Result<Result<String, String>> {
        Ok(admitted(&runtime, "lookup", invocation, CALENDAR, |handle| {
            json!({"handle":handle,"calendar_id":id,"group_email":"engineering@synthetic.example"})
        })?
        .result)
    };
    assert_eq!(
        read("readers-only", READERS_ONLY)?,
        Ok(format!(
            r#"{{"Found":{{"group_role":"None","id":"{READERS_ONLY}","summary":"Synthetic"}}}}"#
        ))
    );
    assert_eq!(read("adas-own", ADAS_OWN)?, Ok(r#""NotFound""#.into()));
    Ok(())
}

#[test]
fn a_failed_calendar_read_correlates_its_calendar_phase() -> Result<()> {
    let (_directory, runtime) = runtime(Setup::default())?;
    crate::integrations::simulated::schedule_faults(
        runtime.db(),
        SCOPE,
        crate::integrations::simulated::GOOGLE_WORKSPACE_WORLD,
        vec![ScheduledFault {
            endpoint: GOOGLE_ACL_ENDPOINT.into(),
            remaining: 1,
            fault: SimulatedFault::ServerError,
        }],
    )?;
    let failed = admitted(&runtime, "lookup", "acl-unavailable", CALENDAR, calendar)?;
    assert_eq!(failed.result, Err("google_workspace_unavailable".into()));
    assert_eq!(
        serde_json::to_value(&failed.correlation)?,
        json!([{"phase":"google_workspace_calendar","http_status":500,"request_id":null,
            "statement_handle":null}])
    );
    assert_eq!(failed.usage.calls, 6);
    assert_eq!(budget(&runtime)?["calls"], (6, 0));
    // A 403 rate limit is classified by its reason, and only its status is
    // kept: the reason never reaches the code or the correlation.
    crate::integrations::simulated::schedule_faults(
        runtime.db(),
        SCOPE,
        crate::integrations::simulated::GOOGLE_WORKSPACE_WORLD,
        vec![ScheduledFault {
            endpoint: crate::integrations::simulated::GOOGLE_ACL_RULE_ENDPOINT.into(),
            remaining: 1,
            fault: SimulatedFault::RateLimitForbidden,
        }],
    )?;
    let limited = admitted(&runtime, "lookup", "rule-rate-limited", CALENDAR, calendar)?;
    assert_eq!(limited.result, Err("google_workspace_rate_limited".into()));
    assert_eq!(
        serde_json::to_value(&limited.correlation)?,
        json!([{"phase":"google_workspace_calendar","http_status":403,"request_id":null,
            "statement_handle":null}])
    );
    assert_eq!(limited.usage.calls, 4);
    Ok(())
}

#[test]
fn the_source_is_frozen_at_authorization_and_a_simulated_host_never_goes_native() -> Result<()> {
    let (_directory, simulated) = runtime(Setup::default())?;
    let (.., authorized, _) = authorize(&simulated, "lookup", "simulated-source", GROUP, group)?;
    assert_eq!(
        authorized
            .google_workspace_plan()
            .context("a Google Workspace plan")?
            .source(),
        crate::google_workspace::Source::Simulated
    );
    // Served by the world: every exchange is in its request log.
    let read = admitted(&simulated, "lookup", "simulated-read", GROUP, group)?;
    assert!(read.result.is_ok());
    assert_eq!(calls(&simulated)?.len(), 3);

    // A host without simulated providers freezes the native source; nothing
    // is dispatched here, and the seeded world is never a fallback.
    let (_directory, native) = runtime(Setup {
        simulated: false,
        ..Setup::default()
    })?;
    let (.., authorized, _) = authorize(&native, "lookup", "native-source", GROUP, group)?;
    assert_eq!(
        authorized
            .google_workspace_plan()
            .context("a Google Workspace plan")?
            .source(),
        crate::google_workspace::Source::Native
    );
    assert!(calls(&native)?.is_empty());
    Ok(())
}

fn conferences(handle: &str) -> Value {
    json!({"handle":handle,"calendar_id":GOOGLE_DEVELOPMENT_CALENDAR,"event_id":"standup0001"})
}

/// Who each signJwt the world served asked to sign for, in order.
fn impersonated(runtime: &Runtime) -> Result<Vec<String>> {
    Ok(calls(runtime)?
        .iter()
        .filter(|call| call.starts_with("google_workspace.iam.sign_jwt"))
        .map(|call| call.rsplit(':').next().unwrap_or_default().to_owned())
        .collect())
}

/// An event's conferences reserve both delegations and every page the
/// ceilings admit, settle what was read, and impersonate only the reader and
/// the owner derived from the event: never an organizer outside the grant's
/// email domain.
#[test]
fn event_conferences_are_reserved_settled_and_delegated_only_to_the_derived_owner() -> Result<()> {
    let (_native_directory, native) = runtime(Setup {
        simulated: false,
        ..Setup::default()
    })?;
    let (_directory, runtime) = runtime(Setup::default())?;
    let read = admitted(
        &runtime,
        "lookup",
        "conferences-read",
        CONFERENCES,
        conferences,
    )?;
    let found: Value = serde_json::from_str(
        read.result
            .as_deref()
            .map_err(|code| anyhow::anyhow!("{code}"))?,
    )?;
    assert_eq!(found["Found"]["owner"], "ada@synthetic.example");
    assert_eq!(found["Found"]["records"].as_array().map(Vec::len), Some(2));
    // The reader's exchanges, rule and event; the owner's exchanges; one page
    // of records; three artifact lists for each of two records.
    assert_eq!(read.usage.calls, 15);
    assert!(read.usage.known && read.usage.response_bytes < read.reserved.response_bytes);
    assert_eq!(budget(&runtime)?["calls"], (15, 0));
    assert_eq!(
        impersonated(&runtime)?,
        [GOOGLE_DEVELOPMENT_CALENDAR_READER, "ada@synthetic.example"]
    );
    // An event organized from outside the grant's email domain is read, and
    // its organizer is never asked for.
    crate::integrations::simulated::update_google_workspace(runtime.db(), SCOPE, |state| {
        let calendar = state
            .world
            .calendars
            .get_mut(GOOGLE_DEVELOPMENT_CALENDAR)
            .context("calendar")?;
        calendar
            .events
            .push(crate::integrations::simulated::GoogleEvent {
                id: "outside0001".into(),
                status: "confirmed".into(),
                start: Some(crate::integrations::simulated::GoogleTime::at(
                    "2026-01-05T17:00:00Z",
                )),
                end: Some(crate::integrations::simulated::GoogleTime::at(
                    "2026-01-05T17:30:00Z",
                )),
                organizer: Some("ada@other.example".into()),
                conference_id: Some("abc-defg-hij".into()),
                conference_type: Some("hangoutsMeet".into()),
                ..Default::default()
            });
        Ok(())
    })?;
    let outside = admitted(
        &runtime,
        "lookup",
        "conferences-outside",
        CONFERENCES,
        |handle| json!({"handle":handle,"calendar_id":GOOGLE_DEVELOPMENT_CALENDAR,"event_id":"outside0001"}),
    )?;
    assert_eq!(outside.result, Ok(r#""NoOwner""#.into()));
    assert_eq!(outside.usage.calls, 5);
    assert!(
        !impersonated(&runtime)?
            .iter()
            .any(|subject| subject == "ada@other.example")
    );
    // Another provider's grant cannot carry the action, and the source is
    // frozen with the plan.
    let refused = authorize(
        &runtime,
        "directory",
        "conferences-other-provider",
        CONFERENCES,
        conferences,
    )
    .err()
    .context("another provider's grant was accepted")?;
    assert!(matches!(
        refused.downcast_ref::<crate::error::Failure>(),
        Some(crate::error::Failure::ResourceForbidden)
    ));
    let (.., authorized, _) = authorize(
        &native,
        "lookup",
        "native-conferences",
        CONFERENCES,
        conferences,
    )?;
    assert_eq!(
        authorized
            .google_workspace_plan()
            .context("a Google Workspace plan")?
            .source(),
        crate::google_workspace::Source::Native
    );
    assert!(calls(&native)?.is_empty());
    Ok(())
}

/// A grant whose call limit is below the action's reserved calls is refused
/// before any exchange or reservation; Calendar reads still fit it.
#[test]
fn a_grant_below_the_conferences_calls_is_refused_before_any_exchange() -> Result<()> {
    let (_directory, runtime) = runtime(Setup {
        max_calls: 24,
        ..Setup::default()
    })?;
    let refused = admitted(
        &runtime,
        "lookup",
        "conferences-short",
        CONFERENCES,
        conferences,
    )
    .err()
    .context("a grant below the envelope was accepted")?;
    assert!(matches!(
        refused.downcast_ref::<crate::error::Failure>(),
        Some(crate::error::Failure::ResourceLimitExceeded)
    ));
    assert!(calls(&runtime)?.is_empty());
    assert!(budget(&runtime)?.is_empty(), "nothing was reserved");
    let event = admitted(
        &runtime,
        "lookup",
        "event-fits",
        EVENT,
        |handle| json!({"handle":handle,"calendar_id":GOOGLE_DEVELOPMENT_CALENDAR,"event_id":"standup0001"}),
    )?;
    assert!(event.result.is_ok());
    Ok(())
}

/// A failed Meet read keeps its Meet phase and status, and a refused owner
/// its token phase, as correlation; nothing Google said is kept.
#[test]
fn a_failed_conferences_read_correlates_its_final_phase() -> Result<()> {
    let (_directory, runtime) = runtime(Setup::default())?;
    crate::integrations::simulated::schedule_faults(
        runtime.db(),
        SCOPE,
        crate::integrations::simulated::GOOGLE_WORKSPACE_WORLD,
        vec![ScheduledFault {
            endpoint: crate::integrations::simulated::GOOGLE_MEET_RECORDS_ENDPOINT.into(),
            remaining: 1,
            fault: SimulatedFault::ServerError,
        }],
    )?;
    let failed = admitted(
        &runtime,
        "lookup",
        "records-unavailable",
        CONFERENCES,
        conferences,
    )?;
    assert_eq!(failed.result, Err("google_workspace_unavailable".into()));
    assert_eq!(
        serde_json::to_value(&failed.correlation)?,
        json!([{"phase":"google_workspace_meet","http_status":500,"request_id":null,
            "statement_handle":null}])
    );
    assert_eq!(failed.usage.calls, 9);
    crate::integrations::simulated::update_google_workspace(runtime.db(), SCOPE, |state| {
        state.world.suspended.insert("ada@synthetic.example".into());
        Ok(())
    })?;
    let refused = admitted(
        &runtime,
        "lookup",
        "owner-refused",
        CONFERENCES,
        conferences,
    )?;
    assert_eq!(refused.result, Err("google_workspace_owner_refused".into()));
    assert_eq!(
        serde_json::to_value(&refused.correlation)?,
        json!([{"phase":"google_workspace_token","http_status":400,"request_id":null,
            "statement_handle":null}])
    );
    Ok(())
}
