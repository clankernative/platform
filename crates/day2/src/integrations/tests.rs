use super::*;
use day2_capabilities::{
    integrations::{LiveConnection, OpenAiText, SlackChannel, SnowflakeScalarType, SnowflakeView},
    resources::{Action, ResourceTarget, VersionRef},
};
use serde_json::json;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Mutex,
};

fn execute(
    call: &PreparedCall,
    resolver: &dyn CredentialResolver,
    transport: &dyn Transport,
) -> AdapterOutcome {
    super::execute(call, resolver, transport, "test-attempt")
}

struct TestCredentials;
impl CredentialResolver for TestCredentials {
    fn resolve(&self, _: &LiveConnection) -> Result<Credentials, AdapterError> {
        Credentials::bearer("secret-never-in-errors".into())
    }
}

struct MissingCredentials;
impl CredentialResolver for MissingCredentials {
    fn resolve(&self, _: &LiveConnection) -> Result<Credentials, AdapterError> {
        Err(AdapterError::CredentialUnavailable)
    }
}

struct FakeTransport {
    responses: Mutex<VecDeque<Result<WireResponse, TransportError>>>,
    requests: Mutex<Vec<CapturedRequest>>,
}

type CapturedRequest = (String, Value, Vec<(&'static str, String)>);

impl FakeTransport {
    fn json(values: Vec<Value>) -> Self {
        Self {
            responses: Mutex::new(
                values
                    .into_iter()
                    .map(|value| {
                        Ok(WireResponse {
                            status: 200,
                            json_content_type: true,
                            body: value.to_string().into_bytes(),
                            request_id: None,
                            metadata: vec![],
                        })
                    })
                    .collect(),
            ),
            requests: Mutex::new(vec![]),
        }
    }
}

impl Transport for FakeTransport {
    fn send(
        &self,
        request: &WireRequest,
        _: super::Authorization<'_>,
        _: u64,
    ) -> Result<WireResponse, TransportError> {
        self.requests.lock().unwrap().push((
            request.url.clone(),
            serde_json::from_slice(&request.body).unwrap_or(Value::Null),
            request.headers.clone(),
        ));
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("no unplanned transport call")
    }
}

fn reference() -> VersionRef {
    VersionRef {
        id: "test".into(),
        revision: 1,
    }
}

fn slack() -> (LiveConnection, ResourceTarget) {
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

fn snowflake() -> (LiveConnection, ResourceTarget) {
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
                max_rows: 10,
            },
        },
    )
}

fn openai() -> (LiveConnection, ResourceTarget) {
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
    .unwrap()
}

fn model_response() -> Value {
    json!({"model":"model-snapshot","object":"response","status":"completed","store":false,"background":false,
        "tools":[],"service_tier":"default","output":[{"type":"message","role":"assistant","status":"completed",
            "content":[{"type":"output_text","text":"hello","annotations":[]}]}],
        "usage":{"input_tokens":10,"output_tokens":20,"total_tokens":30}})
}

#[test]
fn slack_workspace_is_verified_before_any_content_or_channel_access() {
    let call = prepared(
        Action::SlackPost,
        &slack(),
        json!({"handle":"opaque","text":"private"}),
    );
    let transport = FakeTransport::json(vec![json!({"ok":true,"team_id":"T999"})]);
    let outcome = execute(&call, &TestCredentials, &transport);
    assert_eq!(outcome.result, Err(AdapterError::ProviderDenied));
    assert_eq!(outcome.calls, 1);
    assert!(!outcome.outcome_unknown);
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, "https://slack.com/api/auth.test");
    assert_eq!(requests[0].1, json!({}));
}

#[test]
fn slack_posts_only_escaped_text_to_pinned_channel_and_counts_both_calls() {
    let call = prepared(
        Action::SlackPost,
        &slack(),
        json!({"handle":"opaque","text":"<!channel> <@U123> <https://evil.test|click> &"}),
    );
    assert_eq!(call.max_calls(), 2);
    let transport = FakeTransport::json(vec![
        json!({"ok":true,"team_id":"T123"}),
        json!({"ok":true,"channel":"C123","ts":"123.001"}),
    ]);
    let outcome = execute(&call, &TestCredentials, &transport);
    assert!(outcome.result.is_ok());
    assert_eq!(outcome.calls, 2);
    assert_eq!(outcome.request_bytes, call.request_bytes());
    let requests = transport.requests.lock().unwrap();
    let body = &requests[1].1;
    assert_eq!(body["channel"], "C123");
    assert!(!body["text"].as_str().unwrap().contains('<'));
    for key in ["mrkdwn", "link_names", "unfurl_links", "unfurl_media"] {
        assert_eq!(body[key], false);
    }
    for key in ["blocks", "attachments", "thread_ts", "username", "icon_url"] {
        assert!(body.get(key).is_none());
    }
}

#[test]
fn app_cannot_override_destinations_models_profiles_or_unknown_fields() {
    let cases = [
        (
            Action::SlackPost,
            slack(),
            json!({"handle":"opaque","text":"hello","channel":"C999"}),
        ),
        (
            Action::SlackRead,
            slack(),
            json!({"handle":"opaque","limit":1001}),
        ),
        (
            Action::SlackRead,
            slack(),
            json!({"handle":"opaque","limit":1,"cursor":"unbound"}),
        ),
        (
            Action::SnowflakeRead,
            snowflake(),
            json!({"handle":"opaque","parameters":[],"statement":"DROP DATABASE app"}),
        ),
        (
            Action::OpenAiGenerate,
            openai(),
            json!({"handle":"opaque","text":"hello","max_output_tokens":20,"model":"other"}),
        ),
        (
            Action::OpenAiGenerate,
            openai(),
            json!({"handle":"opaque","text":"hello","max_output_tokens":20,"tools":[{"type":"web_search"}]}),
        ),
    ];
    for (action, (connection, target), input) in cases {
        assert!(
            prepare(
                &action,
                &connection,
                &target,
                &input.to_string(),
                65_536,
                65_536
            )
            .is_err()
        );
    }
}

#[test]
fn missing_credentials_never_dispatch_and_errors_are_redacted() {
    let call = prepared(
        Action::OpenAiGenerate,
        &openai(),
        json!({"handle":"opaque","text":"private text","max_output_tokens":20}),
    );
    let transport = FakeTransport::json(vec![]);
    let outcome = execute(&call, &MissingCredentials, &transport);
    assert_eq!(
        outcome.result.unwrap_err().to_string(),
        "integration_credential_unavailable"
    );
    assert!(!outcome.dispatched);
    assert_eq!(outcome.calls, 0);
    assert!(!outcome.outcome_unknown);
}

#[test]
fn snowflake_sql_is_constructed_and_values_never_enter_sql() {
    let call = prepared(
        Action::SnowflakeRead,
        &snowflake(),
        json!({"handle":"opaque","parameters":[
        {"name":"TEAM","kind":"text","value":"x'; DROP TABLE SECRET; --"}]}),
    );
    let body: Value = serde_json::from_slice(&call.request.body).unwrap();
    assert_eq!(
        body["statement"],
        "SELECT \"NAME\" FROM \"APP_DB\".\"PUBLIC\".\"APP_VIEW\" WHERE \"TEAM\" = ? LIMIT 11"
    );
    assert_eq!(body["bindings"]["1"]["value"], "x'; DROP TABLE SECRET; --");
    assert_eq!(body["role"], "READER");
    assert_eq!(body["warehouse"], "WH");
    assert_eq!(body["parameters"]["MULTI_STATEMENT_COUNT"], "1");
    assert_eq!(call.reserved_monetary_microusd(), None);
    for parameters in [
        json!([]),
        json!([{ "name":"OTHER","kind":"text","value":"x" }]),
        json!([{ "name":"TEAM","kind":"text","value":"x" },{ "name":"TEAM","kind":"text","value":"y" }]),
        json!([{ "name":"TEAM","kind":"boolean","value":"true" }]),
    ] {
        assert!(
            prepare(
                &Action::SnowflakeRead,
                &snowflake().0,
                &snowflake().1,
                &json!({"handle":"opaque","parameters":parameters}).to_string(),
                65_536,
                65_536
            )
            .is_err()
        );
    }
}

#[test]
fn snowflake_rejects_partial_wrong_shape_and_cross_column_results() {
    let pair = snowflake();
    let call = prepared(
        Action::SnowflakeRead,
        &pair,
        json!({"handle":"opaque","parameters":[{"name":"TEAM","kind":"text","value":"x"}]}),
    );
    let good = json!({"code":"090001","resultSetMetaData":{"numRows":1,"format":"jsonv2", "rowType":[{"name":"NAME","type":"text"}],
        "partitionInfo":[{"rowCount":1}]},"data":[[null]],"statementStatusUrl":"https://evil.test/never-follow"});
    let transport = FakeTransport::json(vec![good.clone()]);
    let outcome = execute(&call, &TestCredentials, &transport);
    assert_eq!(
        serde_json::from_str::<Value>(&outcome.result.unwrap()).unwrap(),
        json!({"columns":["NAME"],"rows":[[{"is_null":true,"value":""}]]})
    );
    for mutate in 0..4 {
        let mut bad = good.clone();
        match mutate {
            0 => bad["resultSetMetaData"]["rowType"][0]["name"] = json!("SECRET"),
            1 => bad["resultSetMetaData"]["partitionInfo"] = json!([{"rowCount":1},{"rowCount":1}]),
            2 => bad["data"] = json!([["x", "secret"]]),
            _ => bad["resultSetMetaData"]["numRows"] = json!(11),
        }
        let transport = FakeTransport::json(vec![bad]);
        assert!(execute(&call, &TestCredentials, &transport).result.is_err());
        assert_eq!(transport.requests.lock().unwrap().len(), 1);
    }
}

#[test]
fn model_uses_fixed_project_stateless_text_and_reserves_full_context() {
    let call = prepared(
        Action::OpenAiGenerate,
        &openai(),
        json!({"handle":"opaque","text":"hello","max_output_tokens":20}),
    );
    assert_eq!(call.reserved_monetary_microusd(), Some(125_200));
    let body: Value = serde_json::from_slice(&call.request.body).unwrap();
    assert_eq!(body["model"], "model-snapshot");
    for key in ["store", "background", "stream"] {
        assert_eq!(body[key], false);
    }
    assert_eq!(body["tools"], json!([]));
    assert_eq!(body["tool_choice"], "none");
    assert_eq!(body["service_tier"], "default");
    assert!(
        call.request
            .headers
            .contains(&("openai-project", "proj_test".into()))
    );
    let transport = FakeTransport::json(vec![model_response()]);
    let outcome = execute(&call, &TestCredentials, &transport);
    assert_eq!(outcome.monetary_microusd, Some(213));
    assert!(!outcome.outcome_unknown);
    assert!(outcome.result.is_ok());
}

#[test]
fn model_malformed_or_differently_priced_outcomes_keep_reservations() {
    let call = prepared(
        Action::OpenAiGenerate,
        &openai(),
        json!({"handle":"opaque","text":"hello","max_output_tokens":20}),
    );
    for mutate in 0..5 {
        let mut bad = model_response();
        match mutate {
            0 => bad["usage"] = Value::Null,
            1 => bad["usage"]["total_tokens"] = json!(1234),
            2 => bad["model"] = json!("another-model"),
            3 => bad["service_tier"] = json!("priority"),
            _ => bad["output"][0]["type"] = json!("web_search_call"),
        }
        let outcome = execute(&call, &TestCredentials, &FakeTransport::json(vec![bad]));
        assert!(outcome.result.is_err());
        assert!(outcome.outcome_unknown);
        assert_eq!(outcome.monetary_microusd, None);
    }
    let mut refusal = model_response();
    refusal["output"][0]["content"] = json!([{"type":"refusal","refusal":"Cannot help"}]);
    let outcome = execute(&call, &TestCredentials, &FakeTransport::json(vec![refusal]));
    assert_eq!(outcome.result, Err(AdapterError::ProviderDenied));
    assert_eq!(outcome.monetary_microusd, Some(213));
    assert!(!outcome.outcome_unknown);
}

#[test]
fn ambiguous_effect_transport_is_never_retried_and_response_bounds_apply() {
    let call = prepared(
        Action::OpenAiGenerate,
        &openai(),
        json!({"handle":"opaque","text":"hello","max_output_tokens":20}),
    );
    let transport = FakeTransport::json(vec![]);
    transport
        .responses
        .lock()
        .unwrap()
        .push_back(Err(TransportError {
            kind: AdapterError::TransportUnavailable,
            response_bytes: 12,
            http_status: None,
            request_id: None,
        }));
    let outcome = execute(&call, &TestCredentials, &transport);
    assert!(outcome.outcome_unknown);
    assert_eq!(outcome.calls, 1);
    assert_eq!(outcome.response_bytes, 12);
    assert_eq!(transport.requests.lock().unwrap().len(), 1);
    for (status, unknown) in [(301, true), (429, false), (500, true)] {
        let transport = FakeTransport::json(vec![]);
        transport
            .responses
            .lock()
            .unwrap()
            .push_back(Ok(WireResponse {
                status,
                json_content_type: true,
                body: b"{\"error\":\"secret-never-in-errors\"}".to_vec(),
                request_id: None,
                metadata: vec![],
            }));
        let outcome = execute(&call, &TestCredentials, &transport);
        assert_eq!(outcome.outcome_unknown, unknown);
        assert!(!outcome.result.unwrap_err().to_string().contains("secret"));
        assert_eq!(transport.requests.lock().unwrap().len(), 1);
    }
    let mut call = call;
    call.response_limit = 8;
    let outcome = execute(
        &call,
        &TestCredentials,
        &FakeTransport::json(vec![model_response()]),
    );
    assert_eq!(outcome.result, Err(AdapterError::ResponseTooLarge));
    assert!(outcome.outcome_unknown);
}

#[test]
fn credentials_reject_header_injection() {
    for value in [
        "",
        "secret\r\nX-Other: attacker",
        "secret value",
        "secret\0",
    ] {
        assert!(Credentials::bearer(value.into()).is_err());
    }
}

#[test]
fn correlation_retains_support_ids_after_body_loss_without_exposing_headers() {
    let call = prepared(
        Action::OpenAiGenerate,
        &openai(),
        json!({"handle":"opaque","text":"private","max_output_tokens":20}),
    );
    let transport = FakeTransport::json(vec![]);
    transport
        .responses
        .lock()
        .unwrap()
        .push_back(Err(TransportError {
            kind: AdapterError::TransportUnavailable,
            response_bytes: 12,
            http_status: Some(200),
            request_id: Some("req_provider_123".into()),
        }));
    let outcome = super::execute(&call, &TestCredentials, &transport, "host-attempt-123");
    assert!(outcome.outcome_unknown);
    assert_eq!(
        outcome.correlation,
        vec![ExchangeCorrelation {
            phase: ExchangePhase::Operation,
            http_status: Some(200),
            request_id: Some("req_provider_123".into()),
            statement_handle: None
        }]
    );
    let requests = transport.requests.lock().unwrap();
    assert!(
        requests[0]
            .2
            .contains(&("x-client-request-id", "host-attempt-123".into()))
    );
    assert!(
        !requests[0]
            .2
            .iter()
            .any(|(header, _)| *header == "idempotency-key")
    );
    assert!(
        !serde_json::to_string(&outcome.correlation)
            .unwrap()
            .contains("private")
    );
    drop(requests);
    for bad in ["", "attempt\r\nX-Other: bad", "not a host id"] {
        let outcome = super::execute(&call, &TestCredentials, &FakeTransport::json(vec![]), bad);
        assert_eq!(outcome.result, Err(AdapterError::InvalidRequest));
        assert_eq!(outcome.calls, 0);
    }
    let transport = FakeTransport::json(vec![]);
    transport
        .responses
        .lock()
        .unwrap()
        .push_back(Ok(WireResponse {
            status: 200,
            json_content_type: true,
            body: model_response().to_string().into_bytes(),
            request_id: Some("sensitive text\r\n".into()),
            metadata: vec![],
        }));
    let outcome = execute(&call, &TestCredentials, &transport);
    assert_eq!(outcome.correlation[0].request_id, None);
}

#[test]
fn snowflake_async_status_keeps_only_a_bounded_statement_uuid_and_never_polls() {
    let call = prepared(
        Action::SnowflakeRead,
        &snowflake(),
        json!({"handle":"opaque","parameters":[
        {"name":"TEAM","kind":"text","value":"test"}]}),
    );
    for handle in [
        "536fad38-b564-4dc5-9892-a4543504df6c",
        "https://evil.test/copy-private-data",
    ] {
        let transport = FakeTransport::json(vec![]);
        transport.responses.lock().unwrap().push_back(Ok(WireResponse {
            status: 202, json_content_type: true,
            body: json!({"statementHandle":handle,"statementStatusUrl":"https://evil.test","message":"private query"}).to_string().into_bytes(),
            request_id: Some("not-an-openai-request".into()),
            metadata: vec![],
        }));
        let outcome = execute(&call, &TestCredentials, &transport);
        assert!(outcome.outcome_unknown);
        assert_eq!(outcome.correlation[0].http_status, Some(202));
        assert_eq!(outcome.correlation[0].request_id, None);
        assert_eq!(
            outcome.correlation[0].statement_handle.is_some(),
            handle.starts_with("536")
        );
        assert_eq!(transport.requests.lock().unwrap().len(), 1);
        let encoded = serde_json::to_string(&outcome.correlation).unwrap();
        assert!(!encoded.contains("evil"));
        assert!(!encoded.contains("private"));
    }
}

/// A resolver that refuses to hand out a credential at all.
///
/// The object store's mounted secret is its S3 secret access key. Resolving it
/// on this path would put it in an Authorization header and hand the store — and
/// every proxy and log between here and it — the key to the whole bucket. So the
/// property under test is not "the header was omitted" but "the secret was never
/// read", which is why this panics rather than returning an error.
struct NoCredentialResolver;

impl super::CredentialResolver for NoCredentialResolver {
    fn resolve(&self, _: &LiveConnection) -> Result<super::Credentials, AdapterError> {
        panic!("an object-store request resolved a bearer credential");
    }
}

struct RecordingTransport {
    presigned: Mutex<Option<bool>>,
}

impl Transport for RecordingTransport {
    fn send(
        &self,
        _: &WireRequest,
        authorization: super::Authorization<'_>,
        _: u64,
    ) -> Result<WireResponse, TransportError> {
        *self.presigned.lock().unwrap() =
            Some(matches!(authorization, super::Authorization::Presigned));
        Ok(WireResponse {
            status: 404,
            json_content_type: false,
            body: vec![],
            request_id: None,
            metadata: vec![],
        })
    }
}

#[test]
fn an_object_request_carries_no_bearer_credential_and_never_reads_the_secret() {
    let connection = LiveConnection::ObjectStore {
        credential_ref: day2_capabilities::resources::VersionRef {
            id: "object".into(),
            revision: 1,
        },
        endpoint: "https://s3.example.com".into(),
        region: "us-east-1".into(),
        bucket: "bucket".into(),
        access_key_id: "AKIAEXAMPLE".into(),
    };
    let call = super::object_call(
        &connection,
        super::ObjectOperation::Head,
        "https://bucket.s3.example.com/k?X-Amz-Signature=abc".into(),
        4096,
    );
    let transport = RecordingTransport {
        presigned: Mutex::new(None),
    };
    // Reaching the transport at all is the point: the resolver panics if touched,
    // so completing this call proves the secret was not read on the way.
    let outcome = super::execute(&call, &NoCredentialResolver, &transport, "attempt-1");
    assert_eq!(
        *transport.presigned.lock().unwrap(),
        Some(true),
        "an object request was authorized as a bearer token"
    );
    // And the 404 is an answer rather than a failure, end to end.
    let value: Value = serde_json::from_str(&outcome.result.expect("answered")).unwrap();
    assert_eq!(value["exists"], serde_json::json!(false));
}
