//! The parity gate: pins each adapter to the *real* provider, not to its own
//! simulation.
//!
//! The coverage gate proves a simulation is real. It cannot prove it is
//! *faithful*. An adapter and a simulation written by the same author from the
//! same misreading agree with each other perfectly and are both wrong about the
//! provider — which is exactly what my Phase 2 Slack tests assert, and why they
//! were listed as expected findings before this gate existed.
//!
//! The property:
//!
//! > The same production code is driven by two sources of truth — one recorded
//! > and one generated — and must agree.
//!
//! **Recorded** is a response body taken verbatim from the provider's published
//! documentation. **Generated** is what `SimulatedTransport` emits. The rules
//! that keep that honest:
//!
//! - The **base** must originate outside the code under test. A base produced by
//!   calling into the adapter or the simulation proves nothing: it moves
//!   whenever they move. `RecordedBase` can only be built from `include_bytes!`
//!   of a checked-in file, in a `const` initialiser — which cannot run the
//!   adapter, so the rule is enforced by the compiler rather than by review.
//! - **Mutations** of that base may be generated, and should be: that is where
//!   coverage comes from. A mutation expected to still succeed is not a
//!   mutation, it is a second base, so every mutation names the failure it
//!   expects.
//! - Each base names the **claim** it establishes. A base is external only with
//!   respect to a particular claim, and without saying which, a legitimately
//!   self-produced fixture is indistinguishable from the self-consistency trap.

use super::*;
use anyhow::Result;
use day2_capabilities::integrations::{OpenAiText, SlackChannel, SnowflakeView};
use day2_capabilities::resources::{Action, ResourceTarget, VersionRef};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// External data establishing one claim about one provider.
///
/// The only constructor takes `&'static [u8]`, and every base below is a `const`
/// item. A const initialiser cannot call into the adapter or the simulation, so
/// a base cannot be produced by running the code it is used to check. Generating
/// one would mean writing a file by hand first, which appears in review rather
/// than hiding inside a helper.
struct RecordedBase {
    /// What this base establishes. Named, not implied.
    claim: &'static str,
    /// Where the bytes came from. For these, the provider's own documentation.
    origin: &'static str,
    bytes: &'static [u8],
}

impl RecordedBase {
    const fn from_repository(
        claim: &'static str,
        origin: &'static str,
        bytes: &'static [u8],
    ) -> Self {
        Self {
            claim,
            origin,
            bytes,
        }
    }

    fn value(&self) -> Result<Value> {
        Ok(serde_json::from_slice(self.bytes)?)
    }
}

const SLACK_HISTORY: RecordedBase = RecordedBase::from_repository(
    "conversations.history returns messages with type/text/ts and a has_more flag",
    "https://docs.slack.dev/reference/methods/conversations.history/ (published example response)",
    include_bytes!("../../fixtures/provider-responses/slack.conversations.history.json"),
);

const SLACK_POST: RecordedBase = RecordedBase::from_repository(
    "chat.postMessage returns ok, the channel it posted to, and a ts",
    "https://docs.slack.dev/reference/methods/chat.postMessage/ (published example response)",
    include_bytes!("../../fixtures/provider-responses/slack.chat.postMessage.json"),
);

const SNOWFLAKE_STATEMENT: RecordedBase = RecordedBase::from_repository(
    "a synchronous statement returns code 090001 with jsonv2 resultSetMetaData and data rows",
    "https://docs.snowflake.com/en/developer-guide/sql-api/reference (published example response)",
    include_bytes!("../../fixtures/provider-responses/snowflake.statements.json"),
);

/// The reply to a **generic** Responses request. That is the claim this base can
/// establish, and no more.
///
/// It is deliberately *not* a base for the claim the adapter actually makes.
/// `openai::prepare` pins `store:false`, `background:false`, `tools:[]` and
/// `service_tier:"default"` in the request it sends, and `openai::response`
/// checks the reply echoes all four back — a price-identity guard, because the
/// reservation was computed assuming those terms. A reply that silently ran
/// under different ones would invalidate the price, not merely the metadata.
///
/// The published example answers a request that pinned none of them, so it
/// legitimately lacks the echoes. A base is external only with respect to a
/// particular claim; this one is external with respect to the generic shape and
/// simply mismatched against the pinned-request claim. See
/// `no_external_base_yet_for_the_pinned_request_reply` for that gap.
const OPENAI_GENERIC_RESPONSE: RecordedBase = RecordedBase::from_repository(
    "a completed generic response carries model, output message content and token usage",
    "https://developers.openai.com/api/reference/typescript/resources/responses/methods/create \
     (published example response to a request that pins no cost-determining parameters)",
    include_bytes!("../../fixtures/provider-responses/openai.responses.json"),
);

/// A transport that replays fixed bytes, so the adapter under test sees exactly
/// the recorded provider response and nothing this crate produced.
struct Replay {
    bodies: std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>,
}

impl Replay {
    fn of(bodies: Vec<Vec<u8>>) -> Self {
        Self {
            bodies: std::sync::Mutex::new(bodies.into()),
        }
    }
}

impl Transport for Replay {
    fn send(
        &self,
        _request: &WireRequest,
        _authorization: super::Authorization<'_>,
        _max: u64,
    ) -> std::result::Result<WireResponse, TransportError> {
        Ok(WireResponse {
            status: 200,
            json_content_type: true,
            body: self
                .bodies
                .lock()
                .unwrap()
                .pop_front()
                .expect("no unplanned transport call"),
            request_id: None,
            metadata: vec![],
        })
    }
}

struct Credentialed;
impl CredentialResolver for Credentialed {
    fn resolve(&self, _: &LiveConnection) -> std::result::Result<Credentials, AdapterError> {
        Credentials::bearer("parity-fixture".into())
    }
}

fn reference() -> VersionRef {
    VersionRef {
        id: "parity".into(),
        revision: 1,
    }
}

/// Drive the real adapter against recorded bytes.
fn against(
    action: Action,
    connection: LiveConnection,
    target: ResourceTarget,
    input: Value,
    bodies: Vec<Vec<u8>>,
) -> std::result::Result<String, AdapterError> {
    let call = prepare(
        &action,
        &connection,
        &target,
        &input.to_string(),
        65_536,
        65_536,
    )?;
    execute(&call, &Credentialed, &Replay::of(bodies), "parity-attempt").result
}

fn slack_identity() -> Vec<u8> {
    json!({"ok":true,"team_id":"T123"}).to_string().into_bytes()
}

fn slack_connection() -> LiveConnection {
    LiveConnection::Slack {
        credential_ref: reference(),
        signing_secret_ref: None,
        workspace_id: "T123".into(),
    }
}

fn slack_channel(id: &str) -> ResourceTarget {
    ResourceTarget::SlackChannel {
        channel: SlackChannel {
            channel_id: id.into(),
        },
    }
}

#[test]
fn slack_history_parses_the_published_provider_response() -> Result<()> {
    let base = SLACK_HISTORY.value()?;
    let result = against(
        Action::SlackRead,
        slack_connection(),
        slack_channel("C123"),
        json!({"handle":"opaque","limit":10}),
        vec![slack_identity(), SLACK_HISTORY.bytes.to_vec()],
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "the adapter rejected Slack's own documented response ({}): {error}",
            SLACK_HISTORY.origin
        )
    })?;
    let projected: Value = serde_json::from_str(&result)?;
    // The claim, checked against the recorded base rather than against the
    // simulation: the projection must carry exactly the documented text and
    // timestamps, and the documented has_more.
    assert_eq!(
        projected["messages"][0]["text"],
        base["messages"][0]["text"]
    );
    assert_eq!(
        projected["messages"][0]["timestamp"],
        base["messages"][0]["ts"]
    );
    assert_eq!(
        projected["messages"][1]["timestamp"],
        base["messages"][1]["ts"]
    );
    assert_eq!(projected["has_more"], base["has_more"]);
    // And it must carry nothing else: user IDs and pagination cursors are in the
    // documented response and must not reach the app.
    let message = projected["messages"][0]
        .as_object()
        .expect("message object");
    assert_eq!(
        message.keys().collect::<Vec<_>>(),
        vec!["text", "timestamp"],
        "the projection leaked provider fields beyond text and timestamp"
    );
    assert!(projected.get("response_metadata").is_none());
    Ok(())
}

#[test]
fn slack_post_parses_the_published_provider_response() -> Result<()> {
    let base = SLACK_POST.value()?;
    let channel = base["channel"].as_str().expect("documented channel");
    let result = against(
        Action::SlackPost,
        slack_connection(),
        slack_channel(channel),
        json!({"handle":"opaque","text":"parity"}),
        vec![slack_identity(), SLACK_POST.bytes.to_vec()],
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "the adapter rejected Slack's own documented response ({}): {error}",
            SLACK_POST.origin
        )
    })?;
    let projected: Value = serde_json::from_str(&result)?;
    assert_eq!(projected["channel"], base["channel"]);
    assert_eq!(projected["timestamp"], base["ts"]);
    assert_eq!(projected["status"], "accepted");
    Ok(())
}

#[test]
fn snowflake_parses_the_published_provider_response() -> Result<()> {
    let base = SNOWFLAKE_STATEMENT.value()?;
    let columns: Vec<String> = base["resultSetMetaData"]["rowType"]
        .as_array()
        .expect("documented rowType")
        .iter()
        .map(|column| column["name"].as_str().expect("column name").to_owned())
        .collect();
    let result = against(
        Action::SnowflakeRead,
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
                columns: columns.clone(),
                filters: BTreeMap::new(),
                max_rows: 10,
            },
        },
        json!({"handle":"opaque","parameters":[]}),
        vec![SNOWFLAKE_STATEMENT.bytes.to_vec()],
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "the adapter rejected Snowflake's own documented response ({}): {error}",
            SNOWFLAKE_STATEMENT.origin
        )
    })?;
    let projected: Value = serde_json::from_str(&result)?;
    assert_eq!(projected["columns"], json!(columns));
    let rows = projected["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), base["data"].as_array().expect("data").len());
    assert_eq!(rows[0][0]["value"], base["data"][0][0]);
    assert_eq!(rows[0][0]["is_null"], json!(false));
    // Statement handles and status URLs are in the documented response and must
    // not reach the app.
    assert!(projected.get("statementHandle").is_none());
    assert!(projected.get("statementStatusUrl").is_none());
    Ok(())
}

/// Every mutation of a base must be rejected, and must name the rejection it
/// expects. A mutation that still succeeds is not a mutation, it is a second
/// base — that rule is what stops the mutation set decaying into a pile of
/// assertions that the code does what it does.
#[test]
fn mutating_the_published_response_is_rejected_in_the_named_way() -> Result<()> {
    let mutate = |apply: fn(&mut Value)| -> std::result::Result<String, AdapterError> {
        let mut body = SLACK_HISTORY.value().expect("base parses");
        apply(&mut body);
        against(
            Action::SlackRead,
            slack_connection(),
            slack_channel("C123"),
            json!({"handle":"opaque","limit":10}),
            vec![slack_identity(), body.to_string().into_bytes()],
        )
    };
    /// A named mutation and the rejection it must produce.
    struct Case {
        name: &'static str,
        apply: fn(&mut Value),
        expect: AdapterError,
    }
    let cases = vec![
        Case {
            name: "has_more removed — a bounded page must not be reported as a whole archive",
            apply: |body| {
                body.as_object_mut().expect("object").remove("has_more");
            },
            expect: AdapterError::ResponseInvalid,
        },
        Case {
            name: "a message that is not of type message",
            apply: |body| body["messages"][0]["type"] = json!("file_share"),
            expect: AdapterError::ResponseInvalid,
        },
        Case {
            name: "a malformed timestamp",
            apply: |body| body["messages"][0]["ts"] = json!("not-a-timestamp"),
            expect: AdapterError::ResponseInvalid,
        },
        Case {
            name: "a provider rejection in an otherwise well-formed body",
            apply: |body| {
                *body = json!({"ok":false,"error":"channel_not_found"});
            },
            expect: AdapterError::ProviderDenied,
        },
        Case {
            name: "more messages than the admitted page limit",
            apply: |body| {
                let message = body["messages"][0].clone();
                let messages = body["messages"].as_array_mut().expect("messages");
                for _ in 0..20 {
                    messages.push(message.clone());
                }
            },
            expect: AdapterError::ResponseInvalid,
        },
    ];
    for case in cases {
        assert_eq!(
            mutate(case.apply),
            Err(case.expect),
            "mutation was not rejected as expected: {}",
            case.name
        );
    }
    Ok(())
}

/// The parity link itself: the simulation must not emit a shape the provider
/// does not. Subset rather than equality — the documented response carries
/// fields the simulation has no reason to invent (`user`, `pin_count`,
/// `response_metadata`), and omitting them is safe. Emitting something the
/// provider never sends is not: it lets an adapter come to depend on a field
/// that will never arrive in production, and the offline lane would never notice.
#[test]
fn the_simulation_emits_no_field_the_provider_does_not() -> Result<()> {
    fn skeleton(value: &Value, path: &str, into: &mut Vec<String>) {
        match value {
            Value::Object(fields) => {
                for (key, nested) in fields {
                    let child = format!("{path}.{key}");
                    into.push(child.clone());
                    skeleton(nested, &child, into);
                }
            }
            // One element stands for the array: providers document homogeneous
            // element shapes, and comparing every index would only add noise.
            Value::Array(items) => {
                if let Some(first) = items.first() {
                    skeleton(first, &format!("{path}[]"), into);
                }
            }
            _ => {}
        }
    }
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("app.sqlite");
    crate::integrations::simulated::seed(
        &database,
        "parity/app",
        &crate::integrations::simulated::SimulatedFixture {
            delegation: Default::default(),
            github_actions: Default::default(),
            linear_work: Default::default(),
            object_store: Default::default(),
            slack: crate::integrations::simulated::SlackWorld {
                workspace_id: "T123".into(),
                channels: BTreeMap::from([(
                    "C123".into(),
                    crate::integrations::simulated::SlackChannelWorld {
                        messages: vec![crate::integrations::simulated::SlackMessage {
                            text: "simulated".into(),
                            timestamp: "1700000001.000000".into(),
                        }],
                        archived: false,
                    },
                )]),
                sequence: 0,
            },
            // seed() requires a complete fixture for every provider; only the
            // Slack world is read by this test.
            snowflake: crate::integrations::simulated::SnowflakeWorld {
                account: "org-account".into(),
                views: BTreeMap::new(),
            },
            openai: crate::integrations::simulated::OpenAiWorld {
                project_id: "proj_parity".into(),
                organization_id: None,
                model: "model-parity".into(),
                max_input_tokens: 10,
            },
        },
    )?;
    // Capture what the simulation puts on the wire by replaying its own reply
    // shape: the simulated transport answers the same request the adapter builds.
    let emitted = capture_simulated_history(&database)?;
    let mut simulated_keys = Vec::new();
    skeleton(&emitted, "", &mut simulated_keys);
    let mut documented_keys = Vec::new();
    skeleton(&SLACK_HISTORY.value()?, "", &mut documented_keys);
    let invented: Vec<_> = simulated_keys
        .iter()
        .filter(|key| !documented_keys.contains(key))
        .collect();
    assert!(
        invented.is_empty(),
        "the Slack simulation emits fields the published provider response does not: {invented:?}"
    );
    Ok(())
}

/// Ask the simulated transport for a history page and return the raw body it
/// produced, so its shape can be compared with the recorded provider response.
fn capture_simulated_history(database: &std::path::Path) -> Result<Value> {
    struct Capture {
        inner: crate::integrations::simulated::SimulatedTransport,
        seen: std::sync::Mutex<Vec<Value>>,
    }
    impl Transport for Capture {
        fn send(
            &self,
            request: &WireRequest,
            authorization: super::Authorization<'_>,
            max: u64,
        ) -> std::result::Result<WireResponse, TransportError> {
            let response = self.inner.send(request, authorization, max)?;
            if let Ok(value) = serde_json::from_slice::<Value>(&response.body) {
                self.seen.lock().unwrap().push(value);
            }
            Ok(response)
        }
    }
    let capture = Capture {
        inner: crate::integrations::simulated::SimulatedTransport::new(database, "parity/app"),
        seen: std::sync::Mutex::new(Vec::new()),
    };
    let call = prepare(
        &Action::SlackRead,
        &slack_connection(),
        &slack_channel("C123"),
        &json!({"handle":"opaque","limit":10}).to_string(),
        65_536,
        65_536,
    )
    .map_err(|error| anyhow::anyhow!("prepare: {error}"))?;
    let _ = execute(
        &call,
        &crate::integrations::simulated::SimulatedCredentials::new(true),
        &capture,
        "parity-capture",
    );
    let seen = capture.seen.lock().unwrap();
    // The last exchange is the history page; the first is the identity preflight.
    seen.last()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("the simulation produced no response to compare"))
}

/// The gap, recorded as an executable statement rather than left implicit.
///
/// No external base exists yet for the claim the adapter actually makes — *what
/// a reply to our pinned request looks like*. The published example answers a
/// generic request, so it carries none of the four echoes the adapter checks,
/// and driving the adapter against it fails. That failure is the base being
/// wrong for the claim, **not** the adapter being wrong: relaxing
/// `openai::response` to accept missing echoes would trade a loud failure for a
/// silently mispriced call.
///
/// Closing this needs a captured reply to a request that pins the four
/// parameters, which only the credential-gated live lane can produce. Until
/// then the claim is unestablished and this test says so, so the gap is visible
/// rather than looking covered by the base above.
///
/// The residual risk stands and is worth keeping in view: if a live reply ever
/// omits an echo, generation fails closed *and* holds the full reservation
/// against the budget. One live call settles it.
#[test]
fn no_external_base_yet_for_the_pinned_request_reply() -> Result<()> {
    let base = OPENAI_GENERIC_RESPONSE.value()?;
    for echo in ["store", "background", "service_tier", "tools"] {
        assert!(
            base.get(echo).is_none(),
            "the published example now shows {echo}; it may have become a base for \
             the pinned-request claim, which would close this gap"
        );
    }
    let outcome = against(
        Action::OpenAiGenerate,
        LiveConnection::OpenAi {
            credential_ref: reference(),
            project_id: "proj_parity".into(),
            organization_id: None,
        },
        ResourceTarget::OpenAiText {
            profile: OpenAiText {
                model: base["model"].as_str().expect("model").into(),
                max_input_bytes: 2048,
                max_input_tokens: 100_000,
                max_output_tokens: 1000,
                input_nanos_per_token: 1250,
                output_nanos_per_token: 10_000,
            },
        },
        json!({"handle":"opaque","text":"parity","max_output_tokens":64}),
        vec![OPENAI_GENERIC_RESPONSE.bytes.to_vec()],
    );
    assert_eq!(
        outcome,
        Err(AdapterError::ResponseInvalid),
        "a generic-request reply must not satisfy the pinned-request claim — if it \
         does, the price-identity echo check has been weakened"
    );
    Ok(())
}

/// Every base names its claim and an origin outside this repository. The rule is
/// enforced structurally by `RecordedBase`'s constructor; this checks the
/// declarations are actually filled in rather than left as placeholders.
#[test]
fn every_base_declares_a_claim_and_an_external_origin() {
    for base in [
        &SLACK_HISTORY,
        &SLACK_POST,
        &SNOWFLAKE_STATEMENT,
        &OPENAI_GENERIC_RESPONSE,
    ] {
        assert!(base.claim.len() > 20, "claim is not a real sentence");
        assert!(
            base.origin.starts_with("https://"),
            "a base's origin must be a published document, not a description: {}",
            base.origin
        );
        assert!(!base.bytes.is_empty());
    }
}
