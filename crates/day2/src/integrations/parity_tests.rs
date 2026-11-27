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
use anyhow::{Context, Result};
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
            slack_webhook: super::simulated::slack_webhook_fixture(),
            delegation: Default::default(),
            gitea_actions: Default::default(),
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
            workspace_directory: Default::default(),
            ramp: crate::integrations::simulated::ramp_fixture(),
            google_workspace: Default::default(),
            carta: None,
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

/// Carta has no published example yet: these bases are reconstructed from the
/// production client that consumed Carta's responses, which is external to this
/// adapter and its simulation. See `CARTA-PROVENANCE.md`; the gap test below
/// keeps that limitation visible until a redacted playground recording lands.
const CARTA_TOKEN: RecordedBase = RecordedBase::from_repository(
    "the client-credentials endpoint returns access_token, token_type, expires_in and scope",
    "reconstructed from nexusbird-equity Types.fs CartaTokenResponse (see CARTA-PROVENANCE.md)",
    include_bytes!("../../fixtures/provider-responses/carta.access_token.json"),
);

const CARTA_STAKEHOLDERS: RecordedBase = RecordedBase::from_repository(
    "a stakeholders page carries stakeholder objects with nullable employeeId, group and address and a nextPageToken",
    "reconstructed from nexusbird-equity Types.fs StakeholdersResponse (see CARTA-PROVENANCE.md)",
    include_bytes!("../../fixtures/provider-responses/carta.stakeholders.json"),
);

const CARTA_OPTION_GRANTS: RecordedBase = RecordedBase::from_repository(
    "an optionGrants page carries grants with value-wrapped dates and quantities, nested vesting events and exercises",
    "reconstructed from nexusbird-equity Types.fs OptionGrantsResponse (see CARTA-PROVENANCE.md)",
    include_bytes!("../../fixtures/provider-responses/carta.optionGrants.json"),
);

/// Replays recorded Carta bodies to the live pipeline in request order.
struct CartaReplay(std::collections::VecDeque<Vec<u8>>);

impl crate::carta_live::CartaPort for CartaReplay {
    fn token(
        &mut self,
        _form: &str,
        _max_bytes: usize,
    ) -> std::result::Result<crate::carta_live::Reply, crate::carta_live::TransportFailure> {
        Ok(self.reply())
    }

    fn page(
        &mut self,
        _collection: crate::carta_live::Collection,
        _query: Option<&str>,
        _token: &crate::carta_live::AccessToken,
        _max_bytes: usize,
    ) -> std::result::Result<crate::carta_live::Reply, crate::carta_live::TransportFailure> {
        Ok(self.reply())
    }
}

impl CartaReplay {
    fn reply(&mut self) -> crate::carta_live::Reply {
        crate::carta_live::Reply {
            status: 200,
            json: true,
            body: self.0.pop_front().expect("no unplanned Carta request"),
            retry_after_seconds: None,
        }
    }
}

fn carta_against(
    children: day2_capabilities::resources::CartaChildren,
    token: Vec<u8>,
    stakeholders: Vec<u8>,
    grants: Vec<u8>,
) -> Result<crate::carta::Snapshot> {
    let plan = crate::carta_live::CapturePlan::authorize(
        "parity/app",
        &reference(),
        &LiveConnection::Carta {
            credential_ref: reference(),
            client_id: "parity-client".into(),
            environment: day2_capabilities::integrations::CartaEnvironment::Playground,
            max_pages_per_collection: 1,
        },
        "1234567",
        children,
        false,
    )?;
    let mut replay = CartaReplay(vec![token, stakeholders, grants].into());
    let capture = crate::carta_live::collect_complete(
        &plan,
        &mut replay,
        crate::carta_live::MAX_PAGE_RESPONSE_BYTES,
    )
    .0?;
    Ok(capture.snapshot().clone())
}

#[test]
fn carta_parses_the_reconstructed_provider_responses() -> Result<()> {
    use day2_capabilities::resources::CartaChildren;
    let include = carta_against(
        CartaChildren::Include,
        CARTA_TOKEN.bytes.to_vec(),
        CARTA_STAKEHOLDERS.bytes.to_vec(),
        CARTA_OPTION_GRANTS.bytes.to_vec(),
    )?;
    assert_eq!(
        (
            include.stakeholder_count,
            include.grant_count,
            include.vesting_event_count,
            include.exercise_count
        ),
        (2, 1, 1, 1)
    );
    let omit = carta_against(
        CartaChildren::Omit,
        CARTA_TOKEN.bytes.to_vec(),
        CARTA_STAKEHOLDERS.bytes.to_vec(),
        CARTA_OPTION_GRANTS.bytes.to_vec(),
    )?;
    assert_eq!((omit.record_count, omit.vesting_event_count), (3, 0));
    Ok(())
}

/// Each mutation of a Carta base names the failure it must produce.
#[test]
fn mutating_the_carta_responses_is_rejected_in_the_named_way() -> Result<()> {
    use day2_capabilities::resources::CartaChildren;
    struct Case {
        name: &'static str,
        apply: fn(&mut Value, &mut Value, &mut Value),
        expect: &'static str,
    }
    let cases = [
        Case {
            name: "a token that is not a bearer",
            apply: |token, _, _| token["token_type"] = json!("mac"),
            expect: "carta_authentication_failed",
        },
        Case {
            name: "a granted scope missing securities",
            apply: |token, _, _| token["scope"] = json!("read_issuer_stakeholders"),
            expect: "carta_scope_denied",
        },
        Case {
            name: "a stakeholder without an email",
            apply: |_, stakeholders, _| {
                stakeholders["stakeholders"][0]
                    .as_object_mut()
                    .expect("object")
                    .remove("email");
            },
            expect: "carta_response_invalid",
        },
        Case {
            name: "a stakeholder of another issuer",
            apply: |_, stakeholders, _| stakeholders["stakeholders"][1]["issuerId"] = json!("1"),
            expect: "carta_issuer_scope_mismatch",
        },
        Case {
            name: "an unwrapped quantity",
            apply: |_, _, grants| grants["optionGrants"][0]["quantity"] = json!("48000"),
            expect: "carta_response_invalid",
        },
        Case {
            name: "a null exercise price",
            apply: |_, _, grants| grants["optionGrants"][0]["exercisePrice"] = Value::Null,
            expect: "carta_response_invalid",
        },
        Case {
            name: "a continuation beyond the one admitted page",
            apply: |_, stakeholders, _| stakeholders["nextPageToken"] = json!("more"),
            expect: "carta_page_budget",
        },
    ];
    for case in cases {
        let mut token = CARTA_TOKEN.value()?;
        let mut stakeholders = CARTA_STAKEHOLDERS.value()?;
        let mut grants = CARTA_OPTION_GRANTS.value()?;
        (case.apply)(&mut token, &mut stakeholders, &mut grants);
        let outcome = carta_against(
            CartaChildren::Include,
            token.to_string().into_bytes(),
            stakeholders.to_string().into_bytes(),
            grants.to_string().into_bytes(),
        );
        assert_eq!(
            outcome.err().map(|error| error.to_string()).as_deref(),
            Some(case.expect),
            "mutation was not rejected as expected: {}",
            case.name
        );
    }
    Ok(())
}

/// The gap, as an executable statement: no Carta base is a provider recording
/// yet. When a redacted playground recording replaces these files, its origin
/// becomes the recording and this test is updated with it.
#[test]
fn carta_bases_are_reconstructions_until_a_playground_recording_lands() {
    for base in [&CARTA_TOKEN, &CARTA_STAKEHOLDERS, &CARTA_OPTION_GRANTS] {
        assert!(base.claim.len() > 20, "claim is not a real sentence");
        assert!(
            base.origin
                .starts_with("reconstructed from nexusbird-equity"),
            "a Carta base's origin must say what it is: {}",
            base.origin
        );
        assert!(!base.bytes.is_empty());
    }
}

/// Google Workspace has no live recording yet: these bases follow the response
/// shapes in Google's published references, with illustrative values. See
/// `GOOGLE-WORKSPACE-PROVENANCE.md`.
const GOOGLE_METADATA_TOKEN: RecordedBase = RecordedBase::from_repository(
    "the metadata server returns access_token, expires_in and token_type for the default service account",
    "https://cloud.google.com/compute/docs/access/authenticate-workloads",
    include_bytes!("../../fixtures/provider-responses/google_workspace.metadata_token.json"),
);

const GOOGLE_GENERATE_ACCESS_TOKEN: RecordedBase = RecordedBase::from_repository(
    "generateAccessToken returns accessToken and expireTime and nothing that names a delegated flow",
    "https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken",
    include_bytes!("../../fixtures/provider-responses/google_workspace.generate_access_token.json"),
);

const GOOGLE_GROUP: RecordedBase = RecordedBase::from_repository(
    "groups.get with the fields=id,email,name mask returns exactly the group's id, primary email and name",
    "https://developers.google.com/workspace/admin/directory/reference/rest/v1/groups/get",
    include_bytes!("../../fixtures/provider-responses/google_workspace.groups.get.json"),
);

const GOOGLE_HAS_MEMBER: RecordedBase = RecordedBase::from_repository(
    "members.hasMember returns a single isMember boolean for direct or nested membership",
    "https://developers.google.com/workspace/admin/directory/reference/rest/v1/members/hasMember",
    include_bytes!("../../fixtures/provider-responses/google_workspace.groups.has_member.json"),
);

/// Replays bodies to the Google pipeline in request order, each with its
/// status.
struct GoogleReplay {
    replies: std::collections::VecDeque<(u16, Vec<u8>)>,
}

impl GoogleReplay {
    /// Every body answered `200`.
    fn ok(bodies: Vec<Vec<u8>>) -> Self {
        Self {
            replies: bodies.into_iter().map(|body| (200, body)).collect(),
        }
    }

    fn reply(&mut self, metadata: bool) -> crate::google_auth::Reply {
        let (status, body) = self
            .replies
            .pop_front()
            .expect("no unplanned Google request");
        crate::google_auth::Reply {
            status,
            metadata_flavor: metadata,
            json: true,
            body,
            retry_after_seconds: None,
        }
    }
}

impl crate::google_workspace::GooglePort for GoogleReplay {
    fn authenticate(
        &mut self,
        exchange: &crate::google_auth::Exchange<'_>,
        _max_bytes: usize,
    ) -> std::result::Result<crate::google_auth::Reply, crate::google_auth::Unreached> {
        Ok(self.reply(matches!(exchange, crate::google_auth::Exchange::Metadata)))
    }

    fn call(
        &mut self,
        _request: &crate::google_workspace::ApiRequest,
        _token: &crate::google_auth::AccessToken,
        _max_bytes: usize,
    ) -> std::result::Result<crate::google_auth::Reply, crate::google_auth::Unreached> {
        Ok(self.reply(false))
    }
}

fn google_plan(action: Action) -> Result<crate::google_workspace::Plan> {
    let request = match action {
        Action::GoogleWorkspaceGroup => json!({"handle":"h","group_email":"team@example.com"}),
        _ => {
            json!({"handle":"h","group_email":"team@example.com","member_email":"person@example.com"})
        }
    };
    Ok(crate::google_workspace::Plan::authorize(
        action,
        &LiveConnection::GoogleWorkspace {
            service_account: "reader@example-project.iam.gserviceaccount.com".into(),
        },
        &google_target(),
        &request.to_string(),
        crate::google_workspace::Source::Simulated,
    )?
    .0)
}

fn google_target() -> ResourceTarget {
    ResourceTarget::GoogleWorkspaceDomain {
        calendar_reader: "calendar@example.com".into(),
        email_domain: "example.com".into(),
        grantee_domains: vec!["example.com".into()],
    }
}

fn google_against(action: Action, bodies: Vec<Vec<u8>>) -> Result<String> {
    let mut replay = GoogleReplay::ok(bodies);
    let (result, _) = crate::google_workspace::observe(&google_plan(action)?, &mut replay, 100);
    result
}

fn google_bases() -> Vec<Vec<u8>> {
    [
        &GOOGLE_METADATA_TOKEN,
        &GOOGLE_GENERATE_ACCESS_TOKEN,
        &GOOGLE_GROUP,
        &GOOGLE_HAS_MEMBER,
    ]
    .iter()
    .map(|base| base.bytes.to_vec())
    .collect()
}

#[test]
fn google_workspace_parses_the_published_provider_responses() -> Result<()> {
    let bases = google_bases();
    assert_eq!(
        google_against(Action::GoogleWorkspaceGroup, bases[..3].to_vec())?,
        r#"{"Found":{"email":"team@example.com","id":"03ep43zb2k3mixc","name":"Team"}}"#
    );
    assert_eq!(
        google_against(Action::GoogleWorkspaceGroupMember, bases)?,
        r#""Member""#
    );
    Ok(())
}

/// Each mutation of a Google base names the failure it must produce.
#[test]
fn mutating_the_google_responses_is_rejected_in_the_named_way() -> Result<()> {
    type Mutation = fn(&mut [Value; 4]);
    let cases: [(&str, Mutation, &str); 6] = [
        (
            "a workload token that is not a bearer",
            |bases| bases[0]["token_type"] = json!("mac"),
            "google_workspace_workload_identity_unavailable",
        ),
        (
            "a delegated flow's answer to a direct request",
            |bases| bases[1] = json!({"keyId":"k","signedJwt":"a.b.c"}),
            "google_workspace_authentication_failed",
        ),
        (
            "a group whose primary address left the grant",
            |bases| bases[2]["email"] = json!("team@elsewhere.example"),
            "google_workspace_group_outside_grant",
        ),
        (
            "a group without an id",
            |bases| {
                bases[2].as_object_mut().expect("object").remove("id");
            },
            "google_workspace_response_invalid",
        ),
        (
            "a membership answer that is not a boolean",
            |bases| bases[3]["isMember"] = json!("true"),
            "google_workspace_response_invalid",
        ),
        (
            "an access token with whitespace",
            |bases| bases[1]["accessToken"] = json!("not a token"),
            "google_workspace_authentication_failed",
        ),
    ];
    for (name, mutate, expect) in cases {
        let mut bases = [
            GOOGLE_METADATA_TOKEN.value()?,
            GOOGLE_GENERATE_ACCESS_TOKEN.value()?,
            GOOGLE_GROUP.value()?,
            GOOGLE_HAS_MEMBER.value()?,
        ];
        mutate(&mut bases);
        let outcome = google_against(
            Action::GoogleWorkspaceGroupMember,
            bases
                .iter()
                .map(|base| base.to_string().into_bytes())
                .collect(),
        );
        assert_eq!(
            outcome.err().map(|error| error.to_string()).as_deref(),
            Some(expect),
            "mutation was not rejected as expected: {name}"
        );
    }
    Ok(())
}

/// The simulated world answers with exactly the fields Google documents, in
/// every exchange a membership read makes.
#[test]
fn the_google_simulation_emits_exactly_the_documented_fields() -> Result<()> {
    struct Recording<'a> {
        inner: crate::google_workspace::SimulatedGooglePort,
        bodies: &'a mut Vec<Vec<u8>>,
    }
    impl crate::google_workspace::GooglePort for Recording<'_> {
        fn authenticate(
            &mut self,
            exchange: &crate::google_auth::Exchange<'_>,
            max_bytes: usize,
        ) -> std::result::Result<crate::google_auth::Reply, crate::google_auth::Unreached> {
            let reply = self.inner.authenticate(exchange, max_bytes)?;
            self.bodies.push(reply.body.clone());
            Ok(reply)
        }

        fn call(
            &mut self,
            request: &crate::google_workspace::ApiRequest,
            token: &crate::google_auth::AccessToken,
            max_bytes: usize,
        ) -> std::result::Result<crate::google_auth::Reply, crate::google_auth::Unreached> {
            let reply = self.inner.call(request, token, max_bytes)?;
            self.bodies.push(reply.body.clone());
            Ok(reply)
        }
    }
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("app.sqlite");
    let mut world = super::simulated::google_workspace_development_fixture();
    world.domain = "example.com".into();
    world.service_account = "reader@example-project.iam.gserviceaccount.com".into();
    world.users = ["person@example.com".to_owned()].into();
    world.groups = BTreeMap::from([(
        "team@example.com".to_owned(),
        super::simulated::GoogleGroup {
            id: "group-team".into(),
            name: "Team".into(),
            members: ["person@example.com".to_owned()].into(),
            aliases: Default::default(),
        },
    )]);
    super::simulated::seed(
        &database,
        "parity/app",
        &super::simulated::SimulatedFixture {
            slack: super::simulated::SlackWorld {
                workspace_id: "TPARITY".into(),
                ..Default::default()
            },
            snowflake: super::simulated::SnowflakeWorld {
                account: "parity".into(),
                ..Default::default()
            },
            openai: super::simulated::OpenAiWorld {
                project_id: "proj_parity".into(),
                model: "model-parity".into(),
                max_input_tokens: 1,
                ..Default::default()
            },
            ramp: crate::integrations::simulated::ramp_fixture(),
            google_workspace: world,
            ..Default::default()
        },
    )?;
    let mut bodies = Vec::new();
    let mut port = Recording {
        inner: crate::google_workspace::SimulatedGooglePort::new(&database, "parity/app")?,
        bodies: &mut bodies,
    };
    let (result, _) = crate::google_workspace::observe(
        &google_plan(Action::GoogleWorkspaceGroupMember)?,
        &mut port,
        100,
    );
    assert_eq!(result?, r#""Member""#);
    let keys = |bytes: &[u8]| -> Result<Vec<String>> {
        let value: Value = serde_json::from_slice(bytes)?;
        Ok(value
            .as_object()
            .context("object")?
            .keys()
            .cloned()
            .collect())
    };
    assert_eq!(bodies.len(), 4);
    for (simulated, base) in bodies.iter().zip(google_bases()) {
        assert_eq!(keys(simulated)?, keys(&base)?);
    }
    Ok(())
}

#[test]
fn google_bases_cite_the_published_reference_they_follow() {
    for base in [
        &GOOGLE_METADATA_TOKEN,
        &GOOGLE_GENERATE_ACCESS_TOKEN,
        &GOOGLE_GROUP,
        &GOOGLE_HAS_MEMBER,
    ] {
        assert!(base.claim.len() > 20, "claim is not a real sentence");
        assert!(base.origin.starts_with("https://"));
        assert!(!base.bytes.is_empty());
    }
}

const GOOGLE_SIGN_JWT: RecordedBase = RecordedBase::from_repository(
    "signJwt returns the signing key's id and the signed JWT, and nothing that names a direct token",
    "https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/signJwt",
    include_bytes!("../../fixtures/provider-responses/google_workspace.sign_jwt.json"),
);

const GOOGLE_OAUTH_TOKEN: RecordedBase = RecordedBase::from_repository(
    "the JWT-bearer grant returns access_token, expires_in and token_type for the delegated subject",
    "https://developers.google.com/identity/protocols/oauth2/service-account#httprest",
    include_bytes!("../../fixtures/provider-responses/google_workspace.oauth_token.json"),
);

const GOOGLE_ACL_RULE: RecordedBase = RecordedBase::from_repository(
    "acl.get for the rule id user:{email} with the scope/role mask returns that one rule's scope and role",
    "https://developers.google.com/workspace/calendar/api/v3/reference/acl/get",
    include_bytes!("../../fixtures/provider-responses/google_workspace.calendar.acl.get.json"),
);

const GOOGLE_CALENDAR_RATE_LIMIT: RecordedBase = RecordedBase::from_repository(
    "Calendar reports a rate limit as a 403 whose errors[].reason is rateLimitExceeded, in Google's error envelope",
    "https://developers.google.com/workspace/calendar/api/guides/errors",
    include_bytes!(
        "../../fixtures/provider-responses/google_workspace.calendar.error.rate_limit.json"
    ),
);

const GOOGLE_CALENDAR_FORBIDDEN: RecordedBase = RecordedBase::from_repository(
    "Calendar reports a refusal as a 403 in the same envelope, with a reason that is not a rate or quota limit",
    "https://developers.google.com/workspace/calendar/api/guides/errors",
    include_bytes!(
        "../../fixtures/provider-responses/google_workspace.calendar.error.forbidden.json"
    ),
);

const GOOGLE_CALENDAR: RecordedBase = RecordedBase::from_repository(
    "calendars.get with the fields=id,summary mask returns exactly the calendar's id and summary",
    "https://developers.google.com/workspace/calendar/api/v3/reference/calendars/get",
    include_bytes!("../../fixtures/provider-responses/google_workspace.calendars.get.json"),
);

const GOOGLE_ACL: RecordedBase = RecordedBase::from_repository(
    "acl.list with the scope/role mask returns rules whose scope has a type and, except for default, a value",
    "https://developers.google.com/workspace/calendar/api/v3/reference/acl/list",
    include_bytes!("../../fixtures/provider-responses/google_workspace.calendar.acl.list.json"),
);

const GOOGLE_EVENTS: RecordedBase = RecordedBase::from_repository(
    "events.list with singleEvents reports timed, recurring-instance, cancelled and all-day items under the item mask",
    "https://developers.google.com/workspace/calendar/api/v3/reference/events/list",
    include_bytes!("../../fixtures/provider-responses/google_workspace.calendar.events.list.json"),
);

const GOOGLE_EVENT: RecordedBase = RecordedBase::from_repository(
    "events.get reports one item under the same mask, with visibility only when it is not default",
    "https://developers.google.com/workspace/calendar/api/v3/reference/events/get",
    include_bytes!("../../fixtures/provider-responses/google_workspace.calendar.events.get.json"),
);

/// The signJwt base with its JWT replaced by one that carries the plan's claims:
/// the adapter checks every claim, so a recorded JWT for another subject could
/// never be exchanged.
fn google_signed(scopes: &[&str]) -> Result<Vec<u8>> {
    google_signed_as("calendar@example.com", scopes)
}

fn google_signed_as(subject: &str, scopes: &[&str]) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let claims = crate::google_auth::delegated_claims(
        "reader@example-project.iam.gserviceaccount.com",
        subject,
        scopes,
        100,
    )
    .map_err(|failure| anyhow::anyhow!("{failure:?}"))?;
    let mut base = GOOGLE_SIGN_JWT.value()?;
    let key = base["keyId"].as_str().unwrap_or_default().to_owned();
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    base["signedJwt"] = json!(format!(
        "{}.{}.{}",
        encode(json!({"alg":"RS256","kid":key}).to_string().as_bytes()),
        encode(claims.as_bytes()),
        encode(&[7u8; 64])
    ));
    Ok(base.to_string().into_bytes())
}

fn calendar_plan(action: Action, request: Value) -> Result<crate::google_workspace::Plan> {
    Ok(crate::google_workspace::Plan::authorize(
        action,
        &LiveConnection::GoogleWorkspace {
            service_account: "reader@example-project.iam.gserviceaccount.com".into(),
        },
        &google_target(),
        &request.to_string(),
        crate::google_workspace::Source::Simulated,
    )?
    .0)
}

fn calendar_request(action: Action) -> Value {
    match action {
        Action::GoogleWorkspaceCalendar => json!({"handle":"h",
            "calendar_id":"c_team@group.calendar.google.com","group_email":"team@example.com"}),
        Action::GoogleWorkspaceCalendarEvents => json!({"handle":"h",
            "calendar_id":"c_team@group.calendar.google.com","time_min":"2026-01-01T00:00:00Z",
            "time_max":"2026-01-31T00:00:00Z","page_token":"None"}),
        _ => json!({"handle":"h","calendar_id":"c_team@group.calendar.google.com",
            "event_id":"abc123def456ghi789jkl012mn"}),
    }
}

/// Every Calendar action reads the reader's own rule, so each is delegated
/// with both Calendar scopes.
const CALENDAR_SCOPES: [&str; 2] = [
    crate::google_workspace_calendar::CALENDAR_READ_SCOPE,
    crate::google_workspace_calendar::CALENDAR_ACL_READ_SCOPE,
];

fn calendar_against(action: Action, api: Vec<Vec<u8>>) -> Result<String> {
    calendar_replies(action, api.into_iter().map(|body| (200, body)).collect())
}

fn calendar_replies(action: Action, api: Vec<(u16, Vec<u8>)>) -> Result<String> {
    let mut replay = GoogleReplay::ok(vec![
        GOOGLE_METADATA_TOKEN.bytes.to_vec(),
        google_signed(&CALENDAR_SCOPES)?,
        GOOGLE_OAUTH_TOKEN.bytes.to_vec(),
    ]);
    replay.replies.extend(api);
    let (result, _) = crate::google_workspace::observe(
        &calendar_plan(action, calendar_request(action))?,
        &mut replay,
        100,
    );
    result
}

/// Each action's API replies in order: the reader's own rule first.
fn calendar_bases(action: Action) -> Vec<Vec<u8>> {
    let rest = match action {
        Action::GoogleWorkspaceCalendar => vec![&GOOGLE_CALENDAR, &GOOGLE_ACL],
        Action::GoogleWorkspaceCalendarEvents => vec![&GOOGLE_EVENTS],
        _ => vec![&GOOGLE_EVENT],
    };
    std::iter::once(&GOOGLE_ACL_RULE)
        .chain(rest)
        .map(|base| base.bytes.to_vec())
        .collect()
}

const CALENDAR_ACTIONS: [Action; 3] = [
    Action::GoogleWorkspaceCalendar,
    Action::GoogleWorkspaceCalendarEvents,
    Action::GoogleWorkspaceCalendarEvent,
];

#[test]
fn google_calendar_parses_the_published_provider_responses() -> Result<()> {
    let calendar: Value = serde_json::from_str(&calendar_against(
        Action::GoogleWorkspaceCalendar,
        calendar_bases(Action::GoogleWorkspaceCalendar),
    )?)?;
    assert_eq!(
        calendar,
        json!({"Found":{"id":"c_team@group.calendar.google.com","summary":"Team","group_role":"Reader"}})
    );
    let page: Value = serde_json::from_str(&calendar_against(
        Action::GoogleWorkspaceCalendarEvents,
        calendar_bases(Action::GoogleWorkspaceCalendarEvents),
    )?)?;
    let page = &page["Found"];
    assert_eq!(page["all_day_omitted"], 1);
    // Google's token reaches the application bound to the query that issued it.
    let plan = calendar_plan(
        Action::GoogleWorkspaceCalendarEvents,
        calendar_request(Action::GoogleWorkspaceCalendarEvents),
    )?;
    let crate::google_workspace::Read::CalendarEvents { query, .. } = plan.read() else {
        anyhow::bail!("an events read");
    };
    assert_eq!(
        page["next_page_token"],
        json!({"Some":query.bind("EXAMPLE_NEXT_PAGE_TOKEN")})
    );
    let events = page["events"].as_array().context("events")?;
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["meeting_code"], json!({"Some":"abc-defg-hij"}));
    assert_eq!(
        events[0]["status"],
        json!({"Confirmed":{"start":"2026-01-05T09:00:00-08:00","end":"2026-01-05T09:30:00-08:00"}})
    );
    // A hangoutLink is the fallback when there is no conferenceData.
    assert_eq!(events[1]["meeting_code"], json!({"Some":"klm-nopq-rst"}));
    assert_eq!(events[1]["visibility"], "Private");
    assert_eq!(
        events[1]["original_start"],
        json!({"Some":"2026-01-06T09:00:00-08:00"})
    );
    assert_eq!(
        events[1]["organizer"],
        json!({"Some":"c_team@group.calendar.google.com"})
    );
    // A cancelled instance may carry no times at all.
    assert_eq!(events[2]["status"], json!("CancelledUntimed"));
    assert_eq!(
        events[2]["original_start"],
        json!({"Some":"2026-01-13T09:00:00-08:00"})
    );
    let event: Value = serde_json::from_str(&calendar_against(
        Action::GoogleWorkspaceCalendarEvent,
        calendar_bases(Action::GoogleWorkspaceCalendarEvent),
    )?)?;
    assert_eq!(
        event["Found"]["status"],
        json!({"Tentative":{"start":"2026-01-05T17:00:00Z","end":"2026-01-05T17:30:00Z"}})
    );
    assert_eq!(event["Found"]["visibility"], "Confidential");
    assert_eq!(
        event["Found"]["meeting_code"],
        json!({"Some":"abc-defg-hij"})
    );
    // A conference ID is a Meet code only from the hangoutsMeet solution.
    let mut bases: Vec<Value> = calendar_bases(Action::GoogleWorkspaceCalendarEvent)
        .iter()
        .map(|bytes| serde_json::from_slice(bytes))
        .collect::<serde_json::Result<_>>()?;
    bases[1]["conferenceData"]["conferenceSolution"]["key"]["type"] = json!("addOn");
    let event: Value = serde_json::from_str(&calendar_against(
        Action::GoogleWorkspaceCalendarEvent,
        bases
            .iter()
            .map(|base| base.to_string().into_bytes())
            .collect(),
    )?)?;
    assert_eq!(event["Found"]["meeting_code"], "None");
    // The reader's own rule with a lesser role: not shared, on every action,
    // before anything else is read.
    for action in CALENDAR_ACTIONS {
        let mut rule = GOOGLE_ACL_RULE.value()?;
        rule["role"] = json!("reader");
        assert_eq!(
            calendar_against(action, vec![rule.to_string().into_bytes()])?,
            r#""NotShared""#,
            "{action:?}"
        );
    }
    Ok(())
}

/// Google's 403s on every Calendar call: a rate or quota reason is a limit;
/// any other reason is a refusal. A refused read of the reader's own rule is
/// not shared only if the reader can still see the calendar.
#[test]
fn google_calendar_classifies_the_published_403s() -> Result<()> {
    for action in CALENDAR_ACTIONS {
        let bases = calendar_bases(action);
        for position in 0..bases.len() {
            let answered = |error: &RecordedBase| -> Vec<(u16, Vec<u8>)> {
                bases[..position]
                    .iter()
                    .map(|body| (200, body.clone()))
                    .chain([(403, error.bytes.to_vec())])
                    .collect()
            };
            assert_eq!(
                calendar_replies(action, answered(&GOOGLE_CALENDAR_RATE_LIMIT))
                    .err()
                    .map(|error| error.to_string())
                    .as_deref(),
                Some("google_workspace_rate_limited"),
                "{action:?} {position}"
            );
            let mut refused = answered(&GOOGLE_CALENDAR_FORBIDDEN);
            if position == 0 {
                // A rule the reader may not read: the calendar is read next.
                // Visible, it is not shared; refused again, it is a refusal.
                let mut visible = refused.clone();
                visible.push((200, GOOGLE_CALENDAR.bytes.to_vec()));
                assert_eq!(
                    calendar_replies(action, visible)?,
                    r#""NotShared""#,
                    "{action:?}"
                );
                refused.push((403, GOOGLE_CALENDAR_FORBIDDEN.bytes.to_vec()));
            }
            assert_eq!(
                calendar_replies(action, refused)
                    .err()
                    .map(|error| error.to_string())
                    .as_deref(),
                Some("google_workspace_denied"),
                "{action:?} {position}"
            );
        }
    }
    Ok(())
}

/// Each mutation of a Calendar base names the failure it must produce.
#[test]
fn mutating_the_calendar_responses_is_rejected_in_the_named_way() -> Result<()> {
    type Mutation = fn(&mut Value);
    let cases: [(Action, usize, &str, Mutation, &str); 11] = [
        (
            Action::GoogleWorkspaceCalendar,
            0,
            "the reader's rule with a role outside Google's set",
            |rule| rule["role"] = json!("editor"),
            "google_workspace_response_invalid",
        ),
        (
            Action::GoogleWorkspaceCalendarEvents,
            0,
            "a rule other than the reader's own",
            |rule| rule["scope"] = json!({"type":"domain","value":"example.com"}),
            "google_workspace_response_invalid",
        ),
        (
            Action::GoogleWorkspaceCalendar,
            1,
            "a calendar other than the one asked for",
            |calendar| calendar["id"] = json!("c_other@group.calendar.google.com"),
            "google_workspace_response_invalid",
        ),
        (
            Action::GoogleWorkspaceCalendar,
            2,
            "an ACL role outside Google's set",
            |acl| acl["items"][2]["role"] = json!("editor"),
            "google_workspace_response_invalid",
        ),
        (
            Action::GoogleWorkspaceCalendarEvents,
            1,
            "an event without a status",
            |page| {
                page["items"][0]
                    .as_object_mut()
                    .expect("event")
                    .remove("status");
            },
            "google_workspace_response_invalid",
        ),
        (
            Action::GoogleWorkspaceCalendarEvents,
            1,
            "a timed event whose time has no offset",
            |page| page["items"][0]["start"]["dateTime"] = json!("2026-01-05T09:00:00"),
            "google_workspace_response_invalid",
        ),
        (
            Action::GoogleWorkspaceCalendarEvents,
            1,
            "a confirmed event without an end",
            |page| {
                page["items"][0]
                    .as_object_mut()
                    .expect("event")
                    .remove("end");
            },
            "google_workspace_response_invalid",
        ),
        (
            Action::GoogleWorkspaceCalendarEvents,
            1,
            "an event that ends before it starts",
            |page| page["items"][0]["end"]["dateTime"] = json!("2026-01-05T08:00:00-08:00"),
            "google_workspace_response_invalid",
        ),
        (
            Action::GoogleWorkspaceCalendarEvents,
            1,
            "an event id that could escape a path",
            |page| page["items"][0]["id"] = json!("../abc"),
            "google_workspace_response_invalid",
        ),
        (
            Action::GoogleWorkspaceCalendarEvents,
            1,
            "more events than one page admits",
            |page| {
                let item = page["items"][0].clone();
                page["items"] = json!(vec![item; 26]);
            },
            "google_workspace_response_invalid",
        ),
        (
            Action::GoogleWorkspaceCalendarEvent,
            1,
            "an event other than the one asked for",
            |event| event["id"] = json!("other0001"),
            "google_workspace_response_invalid",
        ),
    ];
    for (action, index, name, mutate, expect) in cases {
        let mut bases: Vec<Value> = calendar_bases(action)
            .iter()
            .map(|bytes| serde_json::from_slice(bytes))
            .collect::<serde_json::Result<_>>()?;
        mutate(&mut bases[index]);
        let outcome = calendar_against(
            action,
            bases
                .iter()
                .map(|base| base.to_string().into_bytes())
                .collect(),
        );
        assert_eq!(
            outcome.err().map(|error| error.to_string()).as_deref(),
            Some(expect),
            "mutation was not rejected as expected: {name}"
        );
    }
    // A delegated token that is not a bearer is refused before Calendar.
    let mut token = GOOGLE_OAUTH_TOKEN.value()?;
    token["token_type"] = json!("mac");
    let mut replay = GoogleReplay::ok(vec![
        GOOGLE_METADATA_TOKEN.bytes.to_vec(),
        google_signed(&CALENDAR_SCOPES)?,
        token.to_string().into_bytes(),
    ]);
    let (result, _) = crate::google_workspace::observe(
        &calendar_plan(
            Action::GoogleWorkspaceCalendarEvent,
            calendar_request(Action::GoogleWorkspaceCalendarEvent),
        )?,
        &mut replay,
        100,
    );
    assert_eq!(
        result.err().map(|error| error.to_string()).as_deref(),
        Some("google_workspace_authentication_failed")
    );
    Ok(())
}

/// Records every reply a simulated port serves, so the simulation's own
/// bodies can be compared with the published shapes.
struct Recording<'a> {
    inner: crate::google_workspace::SimulatedGooglePort,
    bodies: &'a mut Vec<Vec<u8>>,
}
impl crate::google_workspace::GooglePort for Recording<'_> {
    fn authenticate(
        &mut self,
        exchange: &crate::google_auth::Exchange<'_>,
        max_bytes: usize,
    ) -> std::result::Result<crate::google_auth::Reply, crate::google_auth::Unreached> {
        let reply = self.inner.authenticate(exchange, max_bytes)?;
        self.bodies.push(reply.body.clone());
        Ok(reply)
    }

    fn call(
        &mut self,
        request: &crate::google_workspace::ApiRequest,
        token: &crate::google_auth::AccessToken,
        max_bytes: usize,
    ) -> std::result::Result<crate::google_auth::Reply, crate::google_auth::Unreached> {
        let reply = self.inner.call(request, token, max_bytes)?;
        self.bodies.push(reply.body.clone());
        Ok(reply)
    }
}
fn keys(value: &Value, path: &str, into: &mut std::collections::BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let path = format!("{path}.{key}");
                into.insert(path.clone());
                keys(child, &path, into);
            }
        }
        Value::Array(items) => {
            for item in items {
                keys(item, &format!("{path}[]"), into);
            }
        }
        _ => {}
    }
}

/// The simulated world answers every Calendar route with only the fields the
/// published shapes carry, at every level of the response.
#[test]
fn the_google_calendar_simulation_emits_only_documented_fields() -> Result<()> {
    let documented = |bases: &[&RecordedBase]| -> Result<std::collections::BTreeSet<String>> {
        let mut into = std::collections::BTreeSet::new();
        for base in bases {
            keys(&base.value()?, "", &mut into);
        }
        Ok(into)
    };
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("app.sqlite");
    let mut world = super::simulated::google_workspace_development_fixture();
    world.service_account = "reader@example-project.iam.gserviceaccount.com".into();
    world.users.insert("calendar@example.com".into());
    let mut calendar = world
        .calendars
        .remove(super::simulated::GOOGLE_DEVELOPMENT_CALENDAR)
        .context("development calendar")?;
    for rule in &mut calendar.acl {
        if rule.scope_value.as_deref() == Some(super::simulated::GOOGLE_DEVELOPMENT_CALENDAR_READER)
        {
            rule.scope_value = Some("calendar@example.com".into());
        }
    }
    calendar.acl.push(super::simulated::GoogleAclRule {
        scope_type: "group".into(),
        scope_value: Some("team@example.com".into()),
        role: "reader".into(),
    });
    calendar.events.push(super::simulated::GoogleEvent {
        id: "abc123def456ghi789jkl012mn".into(),
        status: "cancelled".into(),
        original_start: Some(super::simulated::GoogleTime::at("2026-01-09T17:00:00Z")),
        ..Default::default()
    });
    world
        .calendars
        .insert("c_team@group.calendar.google.com".into(), calendar);
    super::simulated::seed(
        &database,
        "parity/app",
        &super::simulated::SimulatedFixture {
            slack: super::simulated::SlackWorld {
                workspace_id: "TPARITY".into(),
                ..Default::default()
            },
            snowflake: super::simulated::SnowflakeWorld {
                account: "parity".into(),
                ..Default::default()
            },
            openai: super::simulated::OpenAiWorld {
                project_id: "proj_parity".into(),
                model: "model-parity".into(),
                max_input_tokens: 1,
                ..Default::default()
            },
            ramp: crate::integrations::simulated::ramp_fixture(),
            google_workspace: world,
            ..Default::default()
        },
    )?;
    for (action, documented) in [
        (
            Action::GoogleWorkspaceCalendar,
            documented(&[&GOOGLE_ACL_RULE, &GOOGLE_CALENDAR, &GOOGLE_ACL])?,
        ),
        (
            Action::GoogleWorkspaceCalendarEvents,
            documented(&[&GOOGLE_ACL_RULE, &GOOGLE_EVENTS])?,
        ),
        (
            Action::GoogleWorkspaceCalendarEvent,
            documented(&[&GOOGLE_ACL_RULE, &GOOGLE_EVENT, &GOOGLE_EVENTS])?,
        ),
    ] {
        let mut bodies = Vec::new();
        let mut port = Recording {
            inner: crate::google_workspace::SimulatedGooglePort::new(&database, "parity/app")?,
            bodies: &mut bodies,
        };
        let (result, _) = crate::google_workspace::observe(
            &calendar_plan(action, calendar_request(action))?,
            &mut port,
            100,
        );
        result?;
        // The three authentication replies, then the Calendar replies.
        assert!(bodies.len() >= 4, "{action:?}");
        let mut emitted = std::collections::BTreeSet::new();
        for body in &bodies[3..] {
            keys(&serde_json::from_slice(body)?, "", &mut emitted);
        }
        let mut documented_items = documented.clone();
        // An events.get item is a list item without the list's envelope.
        for key in &documented {
            if let Some(item) = key.strip_prefix(".items[]") {
                documented_items.insert(item.to_owned());
            }
        }
        let extra: Vec<_> = emitted.difference(&documented_items).collect();
        assert!(extra.is_empty(), "{action:?} emits undocumented {extra:?}");
    }
    // The simulation's 403s carry the documented error envelope and nothing
    // else.
    let errors = documented(&[&GOOGLE_CALENDAR_RATE_LIMIT, &GOOGLE_CALENDAR_FORBIDDEN])?;
    for fault in [
        super::simulated::SimulatedFault::RateLimitForbidden,
        super::simulated::SimulatedFault::Denied,
    ] {
        super::simulated::schedule_faults(
            &database,
            "parity/app",
            super::simulated::GOOGLE_WORKSPACE_WORLD,
            vec![super::simulated::ScheduledFault {
                endpoint: super::simulated::GOOGLE_ACL_RULE_ENDPOINT.into(),
                remaining: 1,
                fault,
            }],
        )?;
        let mut bodies = Vec::new();
        let mut port = Recording {
            inner: crate::google_workspace::SimulatedGooglePort::new(&database, "parity/app")?,
            bodies: &mut bodies,
        };
        let action = Action::GoogleWorkspaceCalendarEvent;
        let _ = crate::google_workspace::observe(
            &calendar_plan(action, calendar_request(action))?,
            &mut port,
            100,
        );
        let mut emitted = std::collections::BTreeSet::new();
        keys(&serde_json::from_slice(&bodies[3])?, "", &mut emitted);
        assert_eq!(emitted, errors, "{fault:?}");
    }
    let signed: Value = serde_json::from_slice(&google_signed(&CALENDAR_SCOPES)?)?;
    assert_eq!(
        signed
            .as_object()
            .context("object")?
            .keys()
            .collect::<Vec<_>>(),
        GOOGLE_SIGN_JWT
            .value()?
            .as_object()
            .context("object")?
            .keys()
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn google_calendar_bases_cite_the_published_reference_they_follow() {
    for base in [
        &GOOGLE_SIGN_JWT,
        &GOOGLE_OAUTH_TOKEN,
        &GOOGLE_ACL_RULE,
        &GOOGLE_CALENDAR_RATE_LIMIT,
        &GOOGLE_CALENDAR_FORBIDDEN,
        &GOOGLE_CALENDAR,
        &GOOGLE_ACL,
        &GOOGLE_EVENTS,
        &GOOGLE_EVENT,
    ] {
        assert!(base.claim.len() > 20, "claim is not a real sentence");
        assert!(base.origin.starts_with("https://"));
        assert!(!base.bytes.is_empty());
    }
}

const GOOGLE_MEET_RECORDS: RecordedBase = RecordedBase::from_repository(
    "conferenceRecords.list with the name/space/startTime/endTime mask returns records latest start first, an ongoing one without endTime",
    "https://developers.google.com/workspace/meet/api/reference/rest/v2/conferenceRecords/list",
    include_bytes!(
        "../../fixtures/provider-responses/google_workspace.meet.conference_records.list.json"
    ),
);

const GOOGLE_MEET_RECORDINGS: RecordedBase = RecordedBase::from_repository(
    "recordings.list with the name/state/driveDestination(file) mask names each recording's state and, once saved, its Drive file",
    "https://developers.google.com/workspace/meet/api/reference/rest/v2/conferenceRecords.recordings/list",
    include_bytes!("../../fixtures/provider-responses/google_workspace.meet.recordings.list.json"),
);

const GOOGLE_MEET_SMART_NOTES: RecordedBase = RecordedBase::from_repository(
    "smartNotes.list with the name/state/docsDestination(document) mask names each smart note's state and Docs document",
    "https://developers.google.com/workspace/meet/api/reference/rest/v2/conferenceRecords.smartNotes/list",
    include_bytes!("../../fixtures/provider-responses/google_workspace.meet.smart_notes.list.json"),
);

const GOOGLE_MEET_TRANSCRIPTS: RecordedBase = RecordedBase::from_repository(
    "transcripts.list with the name/state/docsDestination(document) mask names each transcript's state and Docs document",
    "https://developers.google.com/workspace/meet/api/reference/rest/v2/conferenceRecords.transcripts/list",
    include_bytes!("../../fixtures/provider-responses/google_workspace.meet.transcripts.list.json"),
);

const GOOGLE_MEET_PERMISSION_DENIED: RecordedBase = RecordedBase::from_repository(
    "Meet refuses in the newer error envelope: a code, a message and a status name, with no errors[] reasons",
    "https://cloud.google.com/apis/design/errors",
    include_bytes!(
        "../../fixtures/provider-responses/google_workspace.meet.error.permission_denied.json"
    ),
);

const GOOGLE_MEET_RATE_LIMIT: RecordedBase = RecordedBase::from_repository(
    "a rate limit in the newer envelope is 429 RESOURCE_EXHAUSTED with an ErrorInfo detail whose reason is RATE_LIMIT_EXCEEDED",
    "https://cloud.google.com/apis/design/errors",
    include_bytes!("../../fixtures/provider-responses/google_workspace.meet.error.rate_limit.json"),
);

/// The Meet replies of an event's conferences in order: the records, then
/// for the rejoin (listed first) no artifacts, then the first call's.
fn meet_bases() -> Vec<Vec<u8>> {
    let mut bases = vec![GOOGLE_MEET_RECORDS.bytes.to_vec()];
    bases.extend((0..3).map(|_| b"{}".to_vec()));
    bases.extend(
        [
            &GOOGLE_MEET_RECORDINGS,
            &GOOGLE_MEET_SMART_NOTES,
            &GOOGLE_MEET_TRANSCRIPTS,
        ]
        .iter()
        .map(|base| base.bytes.to_vec()),
    );
    bases
}

/// The event's conferences against the published bases: the reader's
/// exchanges, rule and event, then the owner's exchanges and `meet`.
fn meet_replies(meet: Vec<(u16, Vec<u8>)>) -> Result<String> {
    let mut replay = GoogleReplay::ok(vec![
        GOOGLE_METADATA_TOKEN.bytes.to_vec(),
        google_signed(&CALENDAR_SCOPES)?,
        GOOGLE_OAUTH_TOKEN.bytes.to_vec(),
        GOOGLE_ACL_RULE.bytes.to_vec(),
        GOOGLE_EVENT.bytes.to_vec(),
        GOOGLE_METADATA_TOKEN.bytes.to_vec(),
        google_signed_as(
            "person@example.com",
            &[crate::google_workspace_meet::MEET_READ_SCOPE],
        )?,
        GOOGLE_OAUTH_TOKEN.bytes.to_vec(),
    ]);
    replay.replies.extend(meet);
    let action = Action::GoogleWorkspaceEventConferences;
    let (result, _) = crate::google_workspace::observe(
        &calendar_plan(
            action,
            calendar_request(Action::GoogleWorkspaceCalendarEvent),
        )?,
        &mut replay,
        100,
    );
    result
}

fn meet_against(meet: Vec<Vec<u8>>) -> Result<String> {
    meet_replies(meet.into_iter().map(|body| (200, body)).collect())
}

#[test]
fn google_meet_parses_the_published_provider_responses() -> Result<()> {
    let found: Value = serde_json::from_str(&meet_against(meet_bases())?)?;
    let found = &found["Found"];
    // The event's organizer is a person in the grant's email domain.
    assert_eq!(found["owner"], "person@example.com");
    assert_eq!(found["meeting_code"], "abc-defg-hij");
    let records = found["records"].as_array().context("records")?;
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["name"], "conferenceRecords/rejoin-5678");
    assert_eq!(records[0]["end_time"], "None");
    assert_eq!(records[0]["recordings"], json!([]));
    assert_eq!(records[1]["space"], "spaces/jQCFfuBOdN5z");
    assert_eq!(records[1]["start_time"], "2026-01-05T17:01:02.345Z");
    assert_eq!(
        records[1]["recordings"],
        json!([
            {"name":"conferenceRecords/first-1234/recordings/rec-1","state":"FileGenerated",
                "file_id":{"Some":"1kuceFZohVoCh6FulBHxwy6I15Ogpc4hP"}},
            {"name":"conferenceRecords/first-1234/recordings/rec-2","state":"Ended","file_id":"None"}
        ])
    );
    assert_eq!(
        records[1]["smart_notes"][0]["document_id"],
        json!({"Some":"1kuceFZohVoCh6FulBHxwy6I15Ogpc4hP"})
    );
    assert_eq!(records[1]["transcripts"][0]["state"], "Started");
    assert_eq!(records[1]["transcripts"][0]["document_id"], "None");
    // Records in two spaces for one code are a conflict, not a choice.
    let mut bases: Vec<Value> = meet_bases()
        .iter()
        .map(|bytes| serde_json::from_slice(bytes))
        .collect::<serde_json::Result<_>>()?;
    bases[0]["conferenceRecords"][1]["space"] = json!("spaces/other");
    assert_eq!(
        meet_against(vec![bases[0].to_string().into_bytes()])?,
        r#""Conflict""#
    );
    Ok(())
}

/// Each mutation of a Meet base names the failure it must produce.
#[test]
fn mutating_the_meet_responses_is_rejected_in_the_named_way() -> Result<()> {
    type Mutation = fn(&mut Value);
    let cases: [(usize, &str, Mutation); 10] = [
        (0, "a record name with a path", |page| {
            page["conferenceRecords"][0]["name"] = json!("conferenceRecords/a/b")
        }),
        (0, "a space that is not a space", |page| {
            page["conferenceRecords"][0]["space"] = json!("rooms/jQCFfuBOdN5z")
        }),
        (0, "a record starting after the window", |page| {
            page["conferenceRecords"][0]["startTime"] = json!("2026-01-05T18:00:01Z")
        }),
        (0, "a record starting before the window", |page| {
            page["conferenceRecords"][1]["startTime"] = json!("2026-01-05T16:29:59.999Z")
        }),
        (0, "an offset timestamp", |page| {
            page["conferenceRecords"][1]["startTime"] = json!("2026-01-05T09:01:02-08:00")
        }),
        (4, "another record's recording", |page| {
            page["recordings"][0]["name"] = json!("conferenceRecords/rejoin-5678/recordings/rec-1")
        }),
        (4, "an unspecified state", |page| {
            page["recordings"][1]["state"] = json!("STATE_UNSPECIFIED")
        }),
        (4, "a file ID that is a path", |page| {
            page["recordings"][0]["driveDestination"]["file"] = json!("../1kuce")
        }),
        (5, "a Drive destination on a smart note", |page| {
            page["smartNotes"][0]["driveDestination"] = json!({"file":"1kuce"})
        }),
        (6, "more transcripts than a page admits", |page| {
            let item = page["transcripts"][0].clone();
            page["transcripts"] = json!(vec![item; 6]);
        }),
    ];
    for (index, name, mutate) in cases {
        let mut bases: Vec<Value> = meet_bases()
            .iter()
            .map(|bytes| serde_json::from_slice(bytes))
            .collect::<serde_json::Result<_>>()?;
        mutate(&mut bases[index]);
        let outcome = meet_against(
            bases
                .iter()
                .map(|base| base.to_string().into_bytes())
                .collect(),
        );
        assert_eq!(
            outcome.err().map(|error| error.to_string()).as_deref(),
            Some("google_workspace_response_invalid"),
            "mutation was not rejected as expected: {name}"
        );
    }
    Ok(())
}

/// Meet's published refusals: a status alone is a refusal, and the newer
/// envelope's rate limit is a limit, at the records and at an artifact list.
#[test]
fn google_meet_classifies_the_published_errors() -> Result<()> {
    for position in [0, 4] {
        let answered = |status: u16, error: &RecordedBase| -> Vec<(u16, Vec<u8>)> {
            meet_bases()[..position]
                .iter()
                .map(|body| (200, body.clone()))
                .chain([(status, error.bytes.to_vec())])
                .collect()
        };
        for (status, error, expected) in [
            (
                403,
                &GOOGLE_MEET_PERMISSION_DENIED,
                "google_workspace_denied",
            ),
            (
                429,
                &GOOGLE_MEET_RATE_LIMIT,
                "google_workspace_rate_limited",
            ),
            (
                403,
                &GOOGLE_MEET_RATE_LIMIT,
                "google_workspace_rate_limited",
            ),
        ] {
            assert_eq!(
                meet_replies(answered(status, error))
                    .err()
                    .map(|error| error.to_string())
                    .as_deref(),
                Some(expected),
                "{position} {status}"
            );
        }
    }
    Ok(())
}

/// The simulated world answers every Meet route, and its refusals, with only
/// the fields the published shapes carry.
#[test]
fn the_google_meet_simulation_emits_only_documented_fields() -> Result<()> {
    use super::simulated::{GoogleArtifact, GoogleConferenceRecord, GoogleSpace};
    let documented = |bases: &[&RecordedBase]| -> Result<std::collections::BTreeSet<String>> {
        let mut into = std::collections::BTreeSet::new();
        for base in bases {
            keys(&base.value()?, "", &mut into);
        }
        Ok(into)
    };
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("app.sqlite");
    let mut world = super::simulated::google_workspace_development_fixture();
    world.service_account = "reader@example-project.iam.gserviceaccount.com".into();
    world.domain = "example.com".into();
    world
        .users
        .extend(["calendar@example.com".into(), "person@example.com".into()]);
    world.calendars = std::collections::BTreeMap::from([(
        "c_team@group.calendar.google.com".into(),
        super::simulated::GoogleCalendar {
            summary: "Team".into(),
            acl: vec![super::simulated::GoogleAclRule {
                scope_type: "user".into(),
                scope_value: Some("calendar@example.com".into()),
                role: "writer".into(),
            }],
            events: vec![super::simulated::GoogleEvent {
                id: "abc123def456ghi789jkl012mn".into(),
                status: "confirmed".into(),
                start: Some(super::simulated::GoogleTime::at("2026-01-05T17:00:00Z")),
                end: Some(super::simulated::GoogleTime::at("2026-01-05T17:30:00Z")),
                organizer: Some("person@example.com".into()),
                creator: Some("person@example.com".into()),
                conference_id: Some("abc-defg-hij".into()),
                conference_type: Some("hangoutsMeet".into()),
                ..Default::default()
            }],
        },
    )]);
    world.spaces = std::collections::BTreeMap::from([(
        "jQCFfuBOdN5z".into(),
        GoogleSpace {
            meeting_code: "abc-defg-hij".into(),
            owner: "person@example.com".into(),
        },
    )]);
    let artifact = |id: &str, state: &str, file: Option<&str>| GoogleArtifact {
        id: id.into(),
        state: state.into(),
        file: file.map(str::to_owned),
    };
    world.conference_records = std::collections::BTreeMap::from([
        (
            "first-1234".into(),
            GoogleConferenceRecord {
                space: "jQCFfuBOdN5z".into(),
                start_time: "2026-01-05T17:01:02.345Z".into(),
                end_time: Some("2026-01-05T17:20:00Z".into()),
                recordings: vec![
                    artifact("rec-1", "FILE_GENERATED", Some("1kuce")),
                    artifact("rec-2", "ENDED", None),
                ],
                smart_notes: vec![artifact("note-1", "FILE_GENERATED", Some("1note"))],
                transcripts: vec![artifact("tr-1", "STARTED", None)],
            },
        ),
        (
            "rejoin-5678".into(),
            GoogleConferenceRecord {
                space: "jQCFfuBOdN5z".into(),
                start_time: "2026-01-05T17:22:01Z".into(),
                ..Default::default()
            },
        ),
    ]);
    super::simulated::seed(
        &database,
        "parity/app",
        &super::simulated::SimulatedFixture {
            slack: super::simulated::SlackWorld {
                workspace_id: "TPARITY".into(),
                ..Default::default()
            },
            snowflake: super::simulated::SnowflakeWorld {
                account: "parity".into(),
                ..Default::default()
            },
            openai: super::simulated::OpenAiWorld {
                project_id: "proj_parity".into(),
                model: "model-parity".into(),
                max_input_tokens: 1,
                ..Default::default()
            },
            ramp: crate::integrations::simulated::ramp_fixture(),
            google_workspace: {
                world.groups.insert(
                    "team@example.com".into(),
                    super::simulated::GoogleGroup {
                        id: "group-team".into(),
                        name: "Team".into(),
                        ..Default::default()
                    },
                );
                world.drive_files = std::collections::BTreeMap::from([(
                    "1kuce".into(),
                    super::simulated::GoogleDriveFile {
                        name: "Recording".into(),
                        mime_type: "video/mp4".into(),
                        owner: "person@example.com".into(),
                        permissions: vec![super::simulated::GoogleDrivePermission::owner(
                            "person@example.com",
                        )],
                    },
                )]);
                world
            },
            ..Default::default()
        },
    )?;
    let action = Action::GoogleWorkspaceEventConferences;
    let plan = calendar_plan(
        action,
        calendar_request(Action::GoogleWorkspaceCalendarEvent),
    )?;
    let mut bodies = Vec::new();
    let mut port = Recording {
        inner: crate::google_workspace::SimulatedGooglePort::new(&database, "parity/app")?,
        bodies: &mut bodies,
    };
    let (result, _) = crate::google_workspace::observe(&plan, &mut port, 100);
    let found: Value = serde_json::from_str(&result?)?;
    assert_eq!(found["Found"]["records"].as_array().map(Vec::len), Some(2));
    // Two delegations, the rule and the event, then Meet.
    let mut emitted = std::collections::BTreeSet::new();
    for body in &bodies[8..] {
        keys(&serde_json::from_slice(body)?, "", &mut emitted);
    }
    let listed = documented(&[
        &GOOGLE_MEET_RECORDS,
        &GOOGLE_MEET_RECORDINGS,
        &GOOGLE_MEET_SMART_NOTES,
        &GOOGLE_MEET_TRANSCRIPTS,
    ])?;
    let extra: Vec<_> = emitted.difference(&listed).collect();
    assert!(extra.is_empty(), "Meet emits undocumented {extra:?}");
    let errors = documented(&[&GOOGLE_MEET_PERMISSION_DENIED, &GOOGLE_MEET_RATE_LIMIT])?;
    for fault in [
        super::simulated::SimulatedFault::Denied,
        super::simulated::SimulatedFault::RateLimited,
    ] {
        super::simulated::schedule_faults(
            &database,
            "parity/app",
            super::simulated::GOOGLE_WORKSPACE_WORLD,
            vec![super::simulated::ScheduledFault {
                endpoint: super::simulated::GOOGLE_MEET_RECORDS_ENDPOINT.into(),
                remaining: 1,
                fault,
            }],
        )?;
        let mut bodies = Vec::new();
        let mut port = Recording {
            inner: crate::google_workspace::SimulatedGooglePort::new(&database, "parity/app")?,
            bodies: &mut bodies,
        };
        let _ = crate::google_workspace::observe(&plan, &mut port, 100);
        let mut emitted = std::collections::BTreeSet::new();
        keys(&serde_json::from_slice(&bodies[8])?, "", &mut emitted);
        let extra: Vec<_> = emitted.difference(&errors).collect();
        assert!(extra.is_empty(), "{fault:?} emits undocumented {extra:?}");
    }
    // The share: the artifact read, the permission list and the create, and
    // Drive's refusals, carry only documented fields.
    let share = share_plan()?;
    let mut bodies = Vec::new();
    let mut port = Recording {
        inner: crate::google_workspace::SimulatedGooglePort::new(&database, "parity/app")?,
        bodies: &mut bodies,
    };
    let (result, _) = crate::google_workspace::observe(&share, &mut port, 100);
    assert!(result?.starts_with(r#"{"Shared""#));
    let mut emitted = std::collections::BTreeSet::new();
    for body in &bodies[12..] {
        keys(&serde_json::from_slice(body)?, "", &mut emitted);
    }
    let listed = documented(&[
        &GOOGLE_MEET_RECORDING,
        &GOOGLE_DRIVE_PERMISSIONS,
        &GOOGLE_DRIVE_CREATED,
    ])?;
    let extra: Vec<_> = emitted.difference(&listed).collect();
    assert!(extra.is_empty(), "the share emits undocumented {extra:?}");
    let errors = documented(&[&GOOGLE_DRIVE_INSUFFICIENT, &GOOGLE_DRIVE_INVALID_SHARING])?;
    super::simulated::schedule_faults(
        &database,
        "parity/app",
        super::simulated::GOOGLE_WORKSPACE_WORLD,
        vec![super::simulated::ScheduledFault {
            endpoint: super::simulated::GOOGLE_DRIVE_PERMISSIONS_ENDPOINT.into(),
            remaining: 1,
            fault: super::simulated::SimulatedFault::Denied,
        }],
    )?;
    let mut bodies = Vec::new();
    let mut port = Recording {
        inner: crate::google_workspace::SimulatedGooglePort::new(&database, "parity/app")?,
        bodies: &mut bodies,
    };
    let _ = crate::google_workspace::observe(&share, &mut port, 100);
    let mut emitted = std::collections::BTreeSet::new();
    keys(&serde_json::from_slice(&bodies[13])?, "", &mut emitted);
    let extra: Vec<_> = emitted.difference(&errors).collect();
    assert!(
        extra.is_empty(),
        "Drive's refusal emits undocumented {extra:?}"
    );
    Ok(())
}

const GOOGLE_MEET_RECORDING: RecordedBase = RecordedBase::from_repository(
    "recordings.get with the name/state/driveDestination(file) mask returns that one recording, named exactly",
    "https://developers.google.com/workspace/meet/api/reference/rest/v2/conferenceRecords.recordings/get",
    include_bytes!("../../fixtures/provider-responses/google_workspace.meet.recordings.get.json"),
);

const GOOGLE_DRIVE_PERMISSIONS: RecordedBase = RecordedBase::from_repository(
    "permissions.list with the id/type/role/emailAddress/deleted mask lists a file's permissions; anyone and domain grants carry no address",
    "https://developers.google.com/workspace/drive/api/reference/rest/v3/permissions/list",
    include_bytes!(
        "../../fixtures/provider-responses/google_workspace.drive.permissions.list.json"
    ),
);

const GOOGLE_DRIVE_CREATED: RecordedBase = RecordedBase::from_repository(
    "permissions.create with the id/type/role/emailAddress mask returns the created permission",
    "https://developers.google.com/workspace/drive/api/reference/rest/v3/permissions/create",
    include_bytes!(
        "../../fixtures/provider-responses/google_workspace.drive.permissions.create.json"
    ),
);

const GOOGLE_DRIVE_INSUFFICIENT: RecordedBase = RecordedBase::from_repository(
    "Drive refuses a change the user may not make with 403 insufficientFilePermissions in the errors[] envelope",
    "https://developers.google.com/workspace/drive/api/guides/handle-errors",
    include_bytes!(
        "../../fixtures/provider-responses/google_workspace.drive.error.insufficient_permissions.json"
    ),
);

const GOOGLE_DRIVE_INVALID_SHARING: RecordedBase = RecordedBase::from_repository(
    "Drive refuses a sharing request it will not make with 400 invalidSharingRequest in the errors[] envelope",
    "https://developers.google.com/workspace/drive/api/guides/handle-errors",
    include_bytes!(
        "../../fixtures/provider-responses/google_workspace.drive.error.invalid_sharing.json"
    ),
);

fn share_plan() -> Result<crate::google_workspace::Plan> {
    calendar_plan(
        Action::GoogleWorkspaceShareArtifact,
        json!({"handle":"h","calendar_id":"c_team@group.calendar.google.com",
            "event_id":"abc123def456ghi789jkl012mn","artifact":"conferenceRecords/first-1234/recordings/rec-1",
            "group_email":"team@example.com"}),
    )
}

/// The share against the published bases: the reader's exchanges, rule and
/// event, the service account's exchanges and the group, the owner's
/// exchanges with Meet's and Drive's scopes, then `rest`.
fn share_replies(rest: Vec<(u16, Vec<u8>)>) -> Result<String> {
    let mut replay = GoogleReplay::ok(vec![
        GOOGLE_METADATA_TOKEN.bytes.to_vec(),
        google_signed(&CALENDAR_SCOPES)?,
        GOOGLE_OAUTH_TOKEN.bytes.to_vec(),
        GOOGLE_ACL_RULE.bytes.to_vec(),
        GOOGLE_EVENT.bytes.to_vec(),
        GOOGLE_METADATA_TOKEN.bytes.to_vec(),
        GOOGLE_GENERATE_ACCESS_TOKEN.bytes.to_vec(),
        GOOGLE_GROUP.bytes.to_vec(),
        GOOGLE_METADATA_TOKEN.bytes.to_vec(),
        google_signed_as(
            "person@example.com",
            &[
                crate::google_workspace_meet::MEET_READ_SCOPE,
                crate::google_workspace_drive::DRIVE_SCOPE,
            ],
        )?,
        GOOGLE_OAUTH_TOKEN.bytes.to_vec(),
        GOOGLE_MEET_RECORDS.bytes.to_vec(),
    ]);
    replay.replies.extend(rest);
    let (result, _) = crate::google_workspace::observe(&share_plan()?, &mut replay, 100);
    result
}

#[test]
fn google_share_parses_the_published_responses_and_their_mutations() -> Result<()> {
    let ok = |base: &RecordedBase| (200, base.bytes.to_vec());
    let bases = || {
        vec![
            ok(&GOOGLE_MEET_RECORDING),
            ok(&GOOGLE_DRIVE_PERMISSIONS),
            ok(&GOOGLE_DRIVE_CREATED),
        ]
    };
    assert_eq!(
        share_replies(bases())?,
        r#"{"Shared":{"permission_id":"09876543210987654321"}}"#
    );
    let mutated = |index: usize, status: u16, edit: &dyn Fn(&mut Value)| -> Result<String> {
        let mut replies = bases();
        let mut value: Value = serde_json::from_slice(&replies[index].1)?;
        edit(&mut value);
        replies[index] = (status, value.to_string().into_bytes());
        replies.truncate(index + 1);
        share_replies(replies)
    };
    let failed = |result: Result<String>| result.err().map(|error| error.to_string());
    // The group already reads the file under another address case: found.
    assert_eq!(
        mutated(1, 200, &|list| list["permissions"][1]["emailAddress"] =
            json!("TEAM@example.com"))?,
        r#"{"AlreadyShared":{"permission_id":"12345678901234567890"}}"#
    );
    assert_eq!(
        mutated(0, 200, &|artifact| artifact["state"] = json!("ENDED"))?,
        r#""NotReady""#
    );
    for (index, name, edit) in [
        (
            0,
            "another recording",
            &(|artifact: &mut Value| {
                artifact["name"] = json!("conferenceRecords/first-1234/recordings/rec-2")
            }) as &dyn Fn(&mut Value),
        ),
        (1, "a role Drive does not have", &|list: &mut Value| {
            list["permissions"][0]["role"] = json!("editor")
        }),
    ] {
        assert_eq!(
            failed(mutated(index, 200, edit)).as_deref(),
            Some("google_workspace_response_invalid"),
            "{name}"
        );
    }
    // A create that does not echo what was asked is settled by listing
    // again: a list without the group's grant leaves it unknown, and one
    // with it is the share.
    let mut writer: Value = serde_json::from_slice(GOOGLE_DRIVE_CREATED.bytes)?;
    writer["role"] = json!("writer");
    let with_group = || -> Result<Vec<u8>> {
        let mut list = GOOGLE_DRIVE_PERMISSIONS.value()?;
        list["permissions"][1]["emailAddress"] = json!("team@example.com");
        Ok(list.to_string().into_bytes())
    };
    let mut replies = bases();
    replies[2] = (200, writer.to_string().into_bytes());
    replies.push(ok(&GOOGLE_DRIVE_PERMISSIONS));
    assert_eq!(
        failed(share_replies(replies.clone())).as_deref(),
        Some("google_workspace_share_outcome_unknown")
    );
    replies[3] = (200, with_group()?);
    assert_eq!(
        share_replies(replies)?,
        r#"{"Shared":{"permission_id":"12345678901234567890"}}"#
    );
    // Drive's published refusals: a file the owner may not share, and a
    // sharing request Drive will not make.
    let refused = |index: usize, status: u16, base: &RecordedBase| {
        let mut replies = bases();
        replies[index] = (status, base.bytes.to_vec());
        replies.truncate(index + 1);
        share_replies(replies)
    };
    for index in [1, 2] {
        assert_eq!(
            failed(refused(index, 403, &GOOGLE_DRIVE_INSUFFICIENT)).as_deref(),
            Some("google_workspace_denied")
        );
    }
    // A sharing refusal is believed only once the list shows no grant.
    let mut replies = bases();
    replies[2] = (400, GOOGLE_DRIVE_INVALID_SHARING.bytes.to_vec());
    replies.push(ok(&GOOGLE_DRIVE_PERMISSIONS));
    assert_eq!(share_replies(replies)?, r#""SharingRefused""#);
    Ok(())
}

#[test]
fn google_meet_bases_cite_the_published_reference_they_follow() {
    for base in [
        &GOOGLE_MEET_RECORDING,
        &GOOGLE_DRIVE_PERMISSIONS,
        &GOOGLE_DRIVE_CREATED,
        &GOOGLE_DRIVE_INSUFFICIENT,
        &GOOGLE_DRIVE_INVALID_SHARING,
        &GOOGLE_MEET_RECORDS,
        &GOOGLE_MEET_RECORDINGS,
        &GOOGLE_MEET_SMART_NOTES,
        &GOOGLE_MEET_TRANSCRIPTS,
        &GOOGLE_MEET_PERMISSION_DENIED,
        &GOOGLE_MEET_RATE_LIMIT,
    ] {
        assert!(base.claim.len() > 20, "claim is not a real sentence");
        assert!(base.origin.starts_with("https://"));
        assert!(!base.bytes.is_empty());
    }
}
