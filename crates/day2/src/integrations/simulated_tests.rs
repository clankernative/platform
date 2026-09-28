//! The offline worlds, exercised through the real adapters. Every assertion here
//! goes through `integrations::prepare` and `integrations::execute`, so what is
//! under test is the adapter running against a simulated socket — not the
//! simulation talking to itself.

use super::*;
use crate::integrations::{PreparedCall, prepare};
use day2_capabilities::{
    integrations::{OpenAiText, SlackChannel, SnowflakeScalarType, SnowflakeView},
    resources::{Action, ResourceTarget, VersionRef},
};
use std::collections::BTreeMap;

const SCOPE: &str = "installation/app";

struct Fixture {
    _directory: tempfile::TempDir,
    database: PathBuf,
    transport: SimulatedTransport,
}

impl Fixture {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("app.sqlite");
        seed(&database, SCOPE, &fixture())?;
        let transport = SimulatedTransport::new(&database, SCOPE);
        Ok(Self {
            _directory: directory,
            database,
            transport,
        })
    }

    fn run(&self, call: &PreparedCall) -> super::super::AdapterOutcome {
        super::super::execute(
            call,
            &SimulatedCredentials::new(true),
            &self.transport,
            "attempt-one",
        )
    }

    fn schedule(&self, world: &str, fault: SimulatedFault) -> Result<()> {
        schedule_faults(
            &self.database,
            SCOPE,
            world,
            vec![ScheduledFault {
                endpoint: String::new(),
                remaining: 1,
                fault,
            }],
        )
    }

    /// Queue a fault against one endpoint, leaving Slack's preflight to succeed.
    fn schedule_on(&self, world: &str, endpoint: &str, fault: SimulatedFault) -> Result<()> {
        schedule_faults(
            &self.database,
            SCOPE,
            world,
            vec![ScheduledFault {
                endpoint: endpoint.into(),
                remaining: 1,
                fault,
            }],
        )
    }
}

fn fixture() -> SimulatedFixture {
    SimulatedFixture {
        slack_webhook: crate::integrations::simulated::slack_webhook_fixture(),
        delegation: Default::default(),
        gitea_actions: Default::default(),
        github_actions: Default::default(),
        linear_work: Default::default(),
        object_store: Default::default(),
        slack: SlackWorld {
            workspace_id: "T123".into(),
            channels: BTreeMap::from([
                ("C123".into(), SlackChannelWorld::default()),
                (
                    "C999".into(),
                    SlackChannelWorld {
                        messages: vec![],
                        archived: true,
                    },
                ),
            ]),
            sequence: 0,
        },
        snowflake: SnowflakeWorld {
            account: "org-account".into(),
            views: BTreeMap::from([(
                "APP_DB.PUBLIC.APP_VIEW".into(),
                SnowflakeViewWorld {
                    columns: vec!["NAME".into(), "TEAM".into()],
                    rows: vec![
                        vec![Some("ada".into()), Some("core".into())],
                        vec![Some("grace".into()), Some("core".into())],
                        vec![None, Some("other".into())],
                    ],
                },
            )]),
        },
        openai: OpenAiWorld {
            project_id: "proj_test".into(),
            organization_id: Some("org-test".into()),
            model: "model-snapshot".into(),
            max_input_tokens: 100_000,
        },
    }
}

fn reference() -> VersionRef {
    VersionRef {
        id: "test".into(),
        revision: 1,
    }
}

fn slack_pair() -> (LiveConnection, ResourceTarget) {
    (
        LiveConnection::Slack {
            credential_ref: reference(),
            signing_secret_ref: None,
            workspace_id: "T123".into(),
        },
        ResourceTarget::SlackChannel {
            channel: SlackChannel {
                channel_id: "C123".into(),
            },
        },
    )
}

fn snowflake_pair(max_rows: u32) -> (LiveConnection, ResourceTarget) {
    (
        LiveConnection::Snowflake {
            credential_ref: reference(),
            account: "org-account".into(),
            role: "READER".into(),
            warehouse: "WH".into(),
        },
        ResourceTarget::SnowflakeView {
            query: SnowflakeView {
                database: "APP_DB".into(),
                schema: "PUBLIC".into(),
                view: "APP_VIEW".into(),
                columns: vec!["NAME".into()],
                filters: BTreeMap::from([("TEAM".into(), SnowflakeScalarType::Text)]),
                max_rows,
            },
        },
    )
}

fn openai_pair() -> (LiveConnection, ResourceTarget) {
    (
        LiveConnection::OpenAi {
            credential_ref: reference(),
            project_id: "proj_test".into(),
            organization_id: Some("org-test".into()),
        },
        ResourceTarget::OpenAiText {
            profile: OpenAiText {
                model: "model-snapshot".into(),
                max_input_bytes: 2048,
                max_input_tokens: 100_000,
                max_output_tokens: 1000,
                input_nanos_per_token: 1250,
                output_nanos_per_token: 10_000,
            },
        },
    )
}

fn prepared(action: Action, pair: &(LiveConnection, ResourceTarget), input: Value) -> PreparedCall {
    prepare(
        &action,
        &pair.0,
        &pair.1,
        &input.to_string(),
        65_536,
        65_536,
    )
    .expect("prepared call")
}

#[test]
fn slack_post_is_visible_to_a_later_read_through_the_real_adapter() -> Result<()> {
    let fixture = Fixture::new()?;
    let pair = slack_pair();
    let post = fixture.run(&prepared(
        Action::SlackPost,
        &pair,
        json!({"handle":"opaque","text":"first message"}),
    ));
    let accepted: Value = serde_json::from_str(&post.result.expect("post accepted"))?;
    assert_eq!(accepted["channel"], "C123");
    assert_eq!(accepted["status"], "accepted");
    // The identity preflight and the post are both counted, as they are live.
    assert_eq!(post.calls, 2);

    let read = fixture.run(&prepared(
        Action::SlackRead,
        &pair,
        json!({"handle":"opaque","limit":10}),
    ));
    let history: Value = serde_json::from_str(&read.result.expect("read accepted"))?;
    assert_eq!(history["messages"][0]["text"], "first message");
    assert_eq!(history["messages"][0]["timestamp"], accepted["timestamp"]);
    assert_eq!(history["has_more"], false);
    Ok(())
}

#[test]
fn slack_history_honours_the_admitted_page_limit() -> Result<()> {
    let fixture = Fixture::new()?;
    let pair = slack_pair();
    for index in 0..3 {
        fixture
            .run(&prepared(
                Action::SlackPost,
                &pair,
                json!({"handle":"opaque","text":format!("message {index}")}),
            ))
            .result
            .expect("post accepted");
    }
    let read = fixture.run(&prepared(
        Action::SlackRead,
        &pair,
        json!({"handle":"opaque","limit":2}),
    ));
    let history: Value = serde_json::from_str(&read.result.expect("read accepted"))?;
    assert_eq!(history["messages"].as_array().expect("messages").len(), 2);
    // Newest first, and the page is reported as partial rather than complete.
    assert_eq!(history["messages"][0]["text"], "message 2");
    assert_eq!(history["has_more"], true);
    Ok(())
}

#[test]
fn a_simulated_workspace_mismatch_denies_before_content_is_transmitted() -> Result<()> {
    let fixture = Fixture::new()?;
    let pair = (
        LiveConnection::Slack {
            credential_ref: reference(),
            signing_secret_ref: None,
            workspace_id: "T999".into(),
        },
        ResourceTarget::SlackChannel {
            channel: SlackChannel {
                channel_id: "C123".into(),
            },
        },
    );
    let outcome = fixture.run(&prepared(
        Action::SlackPost,
        &pair,
        json!({"handle":"opaque","text":"must not be sent"}),
    ));
    assert_eq!(outcome.result, Err(AdapterError::ProviderDenied));
    assert_eq!(outcome.calls, 1);
    // Nothing reached the channel.
    let read = fixture.run(&prepared(
        Action::SlackRead,
        &slack_pair(),
        json!({"handle":"opaque","limit":10}),
    ));
    let history: Value = serde_json::from_str(&read.result.expect("read accepted"))?;
    assert!(history["messages"].as_array().expect("messages").is_empty());
    Ok(())
}

#[test]
fn snowflake_serves_the_generated_statement_and_binds_its_filter() -> Result<()> {
    let fixture = Fixture::new()?;
    let outcome = fixture.run(&prepared(
        Action::SnowflakeRead,
        &snowflake_pair(10),
        json!({"handle":"opaque","parameters":[{"name":"TEAM","kind":"text","value":"core"}]}),
    ));
    let rows: Value = serde_json::from_str(&outcome.result.expect("read accepted"))?;
    assert_eq!(rows["columns"], json!(["NAME"]));
    assert_eq!(
        rows["rows"],
        json!([[{"is_null":false,"value":"ada"}],[{"is_null":false,"value":"grace"}]])
    );
    Ok(())
}

#[test]
fn snowflake_row_overflow_is_rejected_rather_than_truncated() -> Result<()> {
    let fixture = Fixture::new()?;
    // Two rows match the filter, so a one-row ceiling must fail rather than
    // silently return a short answer.
    let outcome = fixture.run(&prepared(
        Action::SnowflakeRead,
        &snowflake_pair(1),
        json!({"handle":"opaque","parameters":[{"name":"TEAM","kind":"text","value":"core"}]}),
    ));
    assert_eq!(outcome.result, Err(AdapterError::ResponseTooLarge));
    Ok(())
}

#[test]
fn snowflake_reports_a_null_cell_without_inventing_a_value() -> Result<()> {
    let fixture = Fixture::new()?;
    let outcome = fixture.run(&prepared(
        Action::SnowflakeRead,
        &snowflake_pair(10),
        json!({"handle":"opaque","parameters":[{"name":"TEAM","kind":"text","value":"other"}]}),
    ));
    let rows: Value = serde_json::from_str(&outcome.result.expect("read accepted"))?;
    assert_eq!(rows["rows"], json!([[{"is_null":true,"value":""}]]));
    Ok(())
}

#[test]
fn model_generation_is_deterministic_input_sensitive_and_priced() -> Result<()> {
    let fixture = Fixture::new()?;
    let pair = openai_pair();
    let ask = |text: &str| -> Result<(Value, Option<u64>)> {
        let outcome = fixture.run(&prepared(
            Action::OpenAiGenerate,
            &pair,
            json!({"handle":"opaque","text":text,"max_output_tokens":64}),
        ));
        Ok((
            serde_json::from_str(&outcome.result.expect("generated"))?,
            outcome.monetary_microusd,
        ))
    };
    let (first, cost) = ask("summarise the report")?;
    let (repeat, _) = ask("summarise the report")?;
    let (other, _) = ask("summarise a different report")?;
    assert_eq!(first["text"], repeat["text"]);
    // A simulation that returned a constant would satisfy the mandate and prove
    // nothing; distinct prompts must produce distinct completions.
    assert_ne!(first["text"], other["text"]);
    assert!(first["input_tokens"].as_u64().expect("input tokens") > 0);
    assert!(cost.expect("settled cost") > 0);
    Ok(())
}

#[test]
fn a_model_the_simulated_account_does_not_serve_is_denied() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut pair = openai_pair();
    let ResourceTarget::OpenAiText { profile } = &mut pair.1 else {
        unreachable!("openai target")
    };
    profile.model = "model-unavailable".into();
    let outcome = fixture.run(&prepared(
        Action::OpenAiGenerate,
        &pair,
        json!({"handle":"opaque","text":"hello","max_output_tokens":64}),
    ));
    assert_eq!(outcome.result, Err(AdapterError::ProviderDenied));
    Ok(())
}

/// The coverage property Phase 4 builds on: every failure an adapter can report
/// must be reachable offline. A classification with no offline path is one the
/// deterministic campaign can never exercise.
#[test]
fn every_adapter_failure_is_reachable_from_the_offline_worlds() -> Result<()> {
    let slack_post = || {
        (
            Action::SlackPost,
            slack_pair(),
            json!({"handle":"opaque","text":"hello"}),
            SLACK_WORLD,
            "chat.postMessage",
        )
    };
    let cases: Vec<(SimulatedFault, AdapterError)> = vec![
        (SimulatedFault::RateLimited, AdapterError::RateLimited),
        (SimulatedFault::Denied, AdapterError::ProviderDenied),
        (SimulatedFault::ServerError, AdapterError::Incomplete),
        (
            SimulatedFault::ConnectionLost,
            AdapterError::TransportUnavailable,
        ),
        (SimulatedFault::Oversized, AdapterError::ResponseTooLarge),
        (SimulatedFault::NotJson, AdapterError::ResponseInvalid),
        (SimulatedFault::Rejected, AdapterError::ProviderDenied),
    ];
    for (fault, expected) in cases {
        let fixture = Fixture::new()?;
        let (action, pair, input, world, endpoint) = slack_post();
        fixture.schedule_on(world, endpoint, fault)?;
        let outcome = fixture.run(&prepared(action, &pair, input));
        assert_eq!(outcome.result, Err(expected), "fault {fault:?}");
    }

    // Snowflake reports a split result the adapter must refuse to follow.
    let fixture = Fixture::new()?;
    fixture.schedule(SNOWFLAKE_WORLD, SimulatedFault::Partitioned)?;
    let outcome = fixture.run(&prepared(
        Action::SnowflakeRead,
        &snowflake_pair(10),
        json!({"handle":"opaque","parameters":[{"name":"TEAM","kind":"text","value":"core"}]}),
    ));
    assert_eq!(outcome.result, Err(AdapterError::Incomplete));

    // A model refusal and usage past the admitted ceiling.
    for (fault, expected) in [
        (SimulatedFault::Refused, AdapterError::ProviderDenied),
        (SimulatedFault::TokenOverrun, AdapterError::ResponseInvalid),
    ] {
        let fixture = Fixture::new()?;
        fixture.schedule(OPENAI_WORLD, fault)?;
        let outcome = fixture.run(&prepared(
            Action::OpenAiGenerate,
            &openai_pair(),
            json!({"handle":"opaque","text":"hello","max_output_tokens":64}),
        ));
        assert_eq!(outcome.result, Err(expected), "fault {fault:?}");
    }

    // The credential path is the resolver's, not the transport's.
    let fixture = Fixture::new()?;
    let outcome = super::super::execute(
        &prepared(
            Action::SlackPost,
            &slack_pair(),
            json!({"handle":"opaque","text":"hello"}),
        ),
        &SimulatedCredentials::new(false),
        &fixture.transport,
        "attempt-one",
    );
    assert_eq!(outcome.result, Err(AdapterError::CredentialUnavailable));
    assert!(!outcome.dispatched);
    Ok(())
}

#[test]
fn a_lost_response_after_dispatch_leaves_a_write_outcome_unknown() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.schedule_on(
        SLACK_WORLD,
        "chat.postMessage",
        SimulatedFault::ConnectionLost,
    )?;
    let outcome = fixture.run(&prepared(
        Action::SlackPost,
        &slack_pair(),
        json!({"handle":"opaque","text":"may or may not have landed"}),
    ));
    assert_eq!(outcome.result, Err(AdapterError::TransportUnavailable));
    assert!(outcome.dispatched);
    // The defining property of the ambiguous-write case the runtime must not retry.
    assert!(outcome.outcome_unknown);
    Ok(())
}

#[test]
fn a_posted_message_survives_a_host_restart() -> Result<()> {
    let fixture = Fixture::new()?;
    let pair = slack_pair();
    fixture
        .run(&prepared(
            Action::SlackPost,
            &pair,
            json!({"handle":"opaque","text":"durable"}),
        ))
        .result
        .expect("post accepted");
    // A fresh transport over the same committed world, as a restarted host has.
    let restarted = SimulatedTransport::new(&fixture.database, SCOPE);
    let outcome = super::super::execute(
        &prepared(
            Action::SlackRead,
            &pair,
            json!({"handle":"opaque","limit":10}),
        ),
        &SimulatedCredentials::new(true),
        &restarted,
        "attempt-two",
    );
    let history: Value = serde_json::from_str(&outcome.result.expect("read accepted"))?;
    assert_eq!(history["messages"][0]["text"], "durable");
    Ok(())
}

#[test]
fn an_unseeded_world_reports_an_unreachable_provider_instead_of_inventing_a_reply() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("app.sqlite");
    let transport = SimulatedTransport::new(&database, SCOPE);
    let outcome = super::super::execute(
        &prepared(
            Action::SlackPost,
            &slack_pair(),
            json!({"handle":"opaque","text":"hello"}),
        ),
        &SimulatedCredentials::new(true),
        &transport,
        "attempt-one",
    );
    assert_eq!(outcome.result, Err(AdapterError::TransportUnavailable));
    assert!(!transport.detail().is_empty());
    Ok(())
}

#[test]
fn seeding_never_silently_resets_a_configured_world() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("app.sqlite");
    seed(&database, SCOPE, &fixture())?;
    assert!(seed(&database, SCOPE, &fixture()).is_err());
    Ok(())
}

#[test]
fn a_drifted_statement_stops_the_simulation_answering() {
    // The strictness that makes the offline lane meaningful: if the adapter's
    // generated SQL changes shape, the simulation refuses rather than serving a
    // query the live provider would have rejected.
    assert!(parse_select("SELECT \"A\" FROM \"D\".\"S\".\"V\" LIMIT 11").is_ok());
    for drifted in [
        "SELECT * FROM \"D\".\"S\".\"V\" LIMIT 11",
        "SELECT \"A\" FROM \"D\".\"S\".\"V\"",
        "SELECT \"A\" FROM D.S.V LIMIT 11",
        "WITH x AS (SELECT 1) SELECT \"A\" FROM \"D\".\"S\".\"V\" LIMIT 11",
    ] {
        assert!(parse_select(drifted).is_err(), "accepted drift: {drifted}");
    }
}
