use super::*;
use serde_json::{Value, json};
use std::collections::VecDeque;

const SCOPE: &str = "cartaco/test/equity";
const ISSUER: &str = "1234567";
const ACCESS_TOKEN: &str = "fixture-access-token";

fn connection(pages: u16) -> LiveConnection {
    LiveConnection::Carta {
        credential_ref: day2_capabilities::resources::VersionRef {
            id: "carta-secret".into(),
            revision: 1,
        },
        client_id: "fixture-client".into(),
        environment: CartaEnvironment::Playground,
        max_pages_per_collection: pages,
    }
}

fn connection_ref() -> VersionRef {
    VersionRef {
        id: "carta-playground".into(),
        revision: 1,
    }
}

fn plan_with(children: CartaChildren, pages: u16) -> CapturePlan {
    CapturePlan::authorize(
        SCOPE,
        &connection_ref(),
        &connection(pages),
        ISSUER,
        children,
        false,
    )
    .expect("valid plan")
}

fn plan(children: CartaChildren) -> CapturePlan {
    plan_with(children, 10)
}

fn token_body() -> Value {
    json!({"access_token":ACCESS_TOKEN,"token_type":"Bearer","expires_in":3600,
        "scope":"read_issuer_stakeholders read_issuer_securities read_issuer_info"})
}

fn wrapped(value: &str) -> Value {
    json!({ "value": value })
}

fn stakeholder(id: &str) -> Value {
    json!({"id":id,"issuerId":ISSUER,"fullName":format!("Holder {id}"),"email":format!("{id}@example.test"),
        "employeeId":format!("employee-{id}"),"relationship":"EMPLOYEE","group":"Engineering",
        "entityType":"INDIVIDUAL","address":{"country":"US"},"unreviewedField":{"nested":true}})
}

fn grant(id: &str, stakeholder: &str) -> Value {
    json!({"id":id,"issuerId":ISSUER,"stakeholderId":stakeholder,"equityIncentivePlanName":"2020 Plan",
        "issueDate":wrapped("2024-01-01"),"vestingStartDate":wrapped("2024-01-01"),
        "boardApprovalDate":wrapped("2023-12-15"),"stakeholderAcceptanceDate":wrapped("2024-01-02"),
        "grantExpirationDate":wrapped("2034-01-01"),"isoNsoSplit":false,"stockOptionType":"ISO",
        "quantity":wrapped("1000"),"outstandingQuantity":wrapped("900"),"vestedQuantity":wrapped("500"),
        "exercisedQuantity":wrapped("100"),
        "exercisePrice":{"currencyCode":wrapped("USD"),"amount":wrapped("0.25")},
        "securityLabel":format!("ES-{id}"),"earlyExercisable":true,
        "vestingEvents":[{"id":format!("{id}-vest"),"vestDate":wrapped("2025-01-01"),"quantity":wrapped("250"),
            "isoQuantity":wrapped("250"),"nsoQuantity":wrapped("0"),"performanceCondition":false,"vested":true,
            "maxQuantity":wrapped("250"),"targetQuantity":wrapped("250"),"vestedQuantity":null}],
        "exercises":[{"exerciseId":format!("{id}-exercise"),"quantity":wrapped("100"),
            "exerciseDate":wrapped("2025-02-01"),"status":"COMPLETED","certificateId":"CS-1",
            "exerciseType":"CASH","qualified":true}],
        "vestingSchedule":{"name":"4y/1y cliff","lastModifiedDate":wrapped("2024-01-01"),
            "startDate":wrapped("2024-01-01"),"endDate":wrapped("2028-01-01")},
        "lastModifiedDatetime":wrapped("2026-01-01T00:00:00Z")})
}

fn reply(status: u16, body: &Value) -> Reply {
    Reply {
        status,
        json: true,
        body: serde_json::to_vec(body).unwrap(),
        retry_after_seconds: None,
    }
}

type Scripted = std::result::Result<Reply, TransportFailure>;

/// Scripted wire replies that record every request the pipeline sends.
struct FixturePort {
    replies: VecDeque<Scripted>,
    requests: Vec<String>,
}

impl FixturePort {
    fn new(replies: Vec<Scripted>) -> Self {
        Self {
            replies: replies.into(),
            requests: Vec::new(),
        }
    }

    fn of(token: Value, stakeholders: Vec<Value>, grants: Vec<Value>) -> Self {
        let mut replies = vec![Ok(reply(200, &token))];
        replies.extend(stakeholders.iter().map(|page| Ok(reply(200, page))));
        replies.extend(grants.iter().map(|page| Ok(reply(200, page))));
        Self::new(replies)
    }

    fn next(&mut self, max_bytes: usize) -> std::result::Result<Reply, TransportFailure> {
        let mut reply = self.replies.pop_front().expect("unplanned Carta request")?;
        reply.body.truncate(max_bytes + 1);
        Ok(reply)
    }
}

impl CartaPort for FixturePort {
    fn token(
        &mut self,
        form: &str,
        max_bytes: usize,
    ) -> std::result::Result<Reply, TransportFailure> {
        self.requests.push(format!("token {form}"));
        self.next(max_bytes)
    }

    fn page(
        &mut self,
        collection: Collection,
        query: Option<&str>,
        token: &AccessToken,
        max_bytes: usize,
    ) -> std::result::Result<Reply, TransportFailure> {
        self.requests.push(format!(
            "{} {} {}",
            collection_path(ISSUER, collection),
            query.unwrap_or("-"),
            token.bearer()
        ));
        self.next(max_bytes)
    }
}

fn run(plan: &CapturePlan, port: &mut FixturePort) -> (Result<CompleteCapture>, Meter) {
    collect_complete(plan, port, MAX_PAGE_RESPONSE_BYTES)
}

fn failure(result: Result<CompleteCapture>) -> Failure {
    *result
        .err()
        .expect("capture must fail")
        .downcast_ref::<Failure>()
        .expect("a typed Carta failure")
}

fn envelopes(capture: &CompleteCapture) -> Vec<Value> {
    capture
        .envelopes
        .iter()
        .map(|envelope| {
            let envelope: Value = serde_json::from_str(envelope).unwrap();
            json!({"kind":envelope["kind"],"data":serde_json::from_str::<Value>(envelope["data"].as_str().unwrap()).unwrap()})
        })
        .collect()
}

#[test]
fn a_complete_capture_maps_every_reviewed_field_in_provider_order() -> Result<()> {
    let mut sparse = stakeholder("s2");
    for field in ["employeeId", "address"] {
        sparse.as_object_mut().unwrap().remove(field);
    }
    sparse["group"] = json!("");
    let mut grant_two = grant("g2", "s2");
    grant_two["stakeholderAcceptanceDate"] = Value::Null;
    grant_two.as_object_mut().unwrap().remove("exercises");
    let mut port = FixturePort::of(
        token_body(),
        vec![json!({"stakeholders":[stakeholder("s1"),sparse.clone(),sparse],"nextPageToken":""})],
        vec![json!({"optionGrants":[grant("g1","s1"),grant_two]})],
    );
    let (capture, meter) = run(&plan(CartaChildren::Include), &mut port);
    let capture = capture?;
    let snapshot = capture.snapshot();
    assert_eq!(
        (
            snapshot.record_count,
            snapshot.stakeholder_count,
            snapshot.grant_count,
            snapshot.vesting_event_count,
            snapshot.exercise_count
        ),
        (8, 3, 2, 2, 1),
        "duplicates are preserved and children follow their grant"
    );
    assert_eq!(snapshot.source_profile, "carta_playground");
    assert_eq!(snapshot.issuer_id, ISSUER);
    let records = envelopes(&capture);
    let kinds: Vec<_> = records
        .iter()
        .map(|record| record["kind"].clone())
        .collect();
    assert_eq!(
        kinds,
        [
            "stakeholder",
            "stakeholder",
            "stakeholder",
            "grant",
            "vesting_event",
            "exercise",
            "grant",
            "vesting_event"
        ]
    );
    assert_eq!(records[1], records[2]);
    assert_eq!(
        records[0]["data"]["employee_id"],
        json!({"Some":"employee-s1"})
    );
    assert_eq!(records[0]["data"]["address_country"], json!({"Some":"US"}));
    assert_eq!(records[1]["data"]["employee_id"], "None");
    assert_eq!(records[1]["data"]["address_country"], "None");
    assert_eq!(records[1]["data"]["group"], json!({"Some":""}));
    let first_grant = &records[3]["data"];
    assert_eq!(first_grant["exercise_price_currency"], "USD");
    assert_eq!(first_grant["exercise_price_amount"], "0.25");
    assert_eq!(first_grant["vesting_schedule_end_date"], "2028-01-01");
    assert_eq!(
        first_grant["last_modified_datetime"],
        "2026-01-01T00:00:00Z"
    );
    assert_eq!(
        first_grant["stakeholder_acceptance_date"],
        json!({"Some":"2024-01-02"})
    );
    assert_eq!(first_grant["early_exercisable"], true);
    assert_eq!(records[4]["data"]["grant_id"], "g1");
    assert_eq!(records[4]["data"]["vested_quantity"], "None");
    assert_eq!(records[5]["data"]["grant_id"], "g1");
    assert_eq!(records[5]["data"]["fair_market_value_as_of_date"], "None");
    assert_eq!(records[6]["data"]["stakeholder_acceptance_date"], "None");
    assert_eq!(
        port.requests,
        [
            "token grant_type=CLIENT_CREDENTIALS&scope=read_issuer_stakeholders+read_issuer_securities"
                .to_owned(),
            format!("/v1alpha1/issuers/{ISSUER}/stakeholders - {ACCESS_TOKEN}"),
            format!("/v1alpha1/issuers/{ISSUER}/optionGrants - {ACCESS_TOKEN}"),
        ]
    );
    assert_eq!(meter.calls, 3);
    assert_eq!(meter.request_bytes, token_form().len() as u64);
    assert!(meter.response_bytes > 0);
    Ok(())
}

#[test]
fn omitted_children_are_neither_decoded_nor_published() -> Result<()> {
    let mut malformed = grant("g1", "s1");
    malformed["vestingEvents"] = json!("not an array");
    malformed["exercises"] = json!([{"unexpected":true}]);
    let mut port = FixturePort::of(
        token_body(),
        vec![json!({"stakeholders":[stakeholder("s1")]})],
        vec![json!({"optionGrants":[malformed.clone()]})],
    );
    let capture = run(&plan(CartaChildren::Omit), &mut port).0?;
    assert_eq!(capture.snapshot().record_count, 2);
    assert_eq!(capture.snapshot().vesting_event_count, 0);
    assert_eq!(capture.snapshot().exercise_count, 0);
    let mut port = FixturePort::of(
        token_body(),
        vec![json!({"stakeholders":[stakeholder("s1")]})],
        vec![json!({"optionGrants":[malformed]})],
    );
    assert_eq!(
        failure(run(&plan(CartaChildren::Include), &mut port).0),
        Failure::ResponseInvalid,
        "include mode types the same arrays"
    );
    Ok(())
}

#[test]
fn identity_is_content_addressed_and_binds_scope_mode_and_source() -> Result<()> {
    let capture = |plan: &CapturePlan| {
        let mut port = FixturePort::of(
            token_body(),
            vec![json!({"stakeholders":[stakeholder("s1")]})],
            vec![json!({"optionGrants":[grant("g1","s1")]})],
        );
        run(plan, &mut port)
            .0
            .map(|capture| capture.snapshot().id.clone())
    };
    let base = capture(&plan(CartaChildren::Include))?;
    assert_eq!(base.len(), 70);
    assert!(base.starts_with("carta_"));
    assert_eq!(base, capture(&plan(CartaChildren::Include))?);
    let mut other_scope = plan(CartaChildren::Include);
    other_scope.scope = "cartaco/test/other".into();
    let simulated = CapturePlan::authorize(
        SCOPE,
        &connection_ref(),
        &connection(10),
        ISSUER,
        CartaChildren::Include,
        true,
    )?;
    let mut production = plan(CartaChildren::Include);
    production.environment = CartaEnvironment::Production;
    production.source_profile = SourceProfile::Production;
    for different in [
        capture(&plan(CartaChildren::Omit))?,
        capture(&other_scope)?,
        capture(&simulated)?,
        capture(&production)?,
    ] {
        assert_ne!(different, base);
    }
    Ok(())
}

#[test]
fn pagination_encodes_tokens_and_fails_closed_on_repeats_and_ceilings() -> Result<()> {
    let token = "a+b/c=d&e%f";
    let mut port = FixturePort::of(
        token_body(),
        vec![
            json!({"stakeholders":[stakeholder("s1")],"nextPageToken":token}),
            json!({"stakeholders":[stakeholder("s2")],"nextPageToken":null}),
        ],
        vec![json!({"nextPageToken":""})],
    );
    let capture = run(&plan(CartaChildren::Include), &mut port).0?;
    assert_eq!(capture.snapshot().stakeholder_count, 2);
    assert_eq!(
        capture.snapshot().grant_count,
        0,
        "an omitted array is empty"
    );
    assert_eq!(
        port.requests[2],
        format!(
            "/v1alpha1/issuers/{ISSUER}/stakeholders pageToken=a%2Bb%2Fc%3Dd%26e%25f {ACCESS_TOKEN}"
        )
    );
    assert_eq!(page_query(token), "pageToken=a%2Bb%2Fc%3Dd%26e%25f");

    // A token Carta has already issued would loop or silently stop; neither is
    // a complete capture.
    let mut repeated = FixturePort::of(
        token_body(),
        vec![
            json!({"stakeholders":[],"nextPageToken":"t1"}),
            json!({"stakeholders":[],"nextPageToken":"t2"}),
            json!({"stakeholders":[],"nextPageToken":"t1"}),
        ],
        vec![],
    );
    let (result, meter) = run(&plan(CartaChildren::Include), &mut repeated);
    assert_eq!(failure(result), Failure::PaginationInvalid);
    assert_eq!(meter.calls, 4, "nothing is requested after the repeat");

    let mut endless = FixturePort::new(
        std::iter::once(Ok(reply(200, &token_body())))
            .chain((0..3).map(|page| {
                Ok(reply(
                    200,
                    &json!({"stakeholders":[],"nextPageToken":format!("t{page}")}),
                ))
            }))
            .collect(),
    );
    let (result, meter) = run(&plan_with(CartaChildren::Include, 3), &mut endless);
    assert_eq!(failure(result), Failure::PageBudget);
    assert_eq!(meter.calls, 4);

    for invalid in [
        json!("bad\ntoken"),
        json!("x".repeat(MAX_PAGE_TOKEN_BYTES + 1)),
        json!(7),
    ] {
        let mut port = FixturePort::of(
            token_body(),
            vec![json!({"stakeholders":[],"nextPageToken":invalid})],
            vec![],
        );
        let code = failure(run(&plan(CartaChildren::Include), &mut port).0);
        assert!(
            matches!(code, Failure::PaginationInvalid | Failure::ResponseInvalid),
            "{code}"
        );
    }
    Ok(())
}

#[test]
fn aggregate_request_bytes_are_bounded_before_sending() {
    let long = "%".repeat(MAX_PAGE_TOKEN_BYTES);
    let mut replies = vec![Ok(reply(200, &token_body()))];
    for page in 0..100 {
        replies.push(Ok(reply(
            200,
            &json!({"stakeholders":[],"nextPageToken":format!("{page:03}{}", &long[3..])}),
        )));
    }
    let mut port = FixturePort::new(replies);
    let (result, meter) = run(&plan_with(CartaChildren::Include, 100), &mut port);
    assert_eq!(failure(result), Failure::RequestBudget);
    assert!(meter.request_bytes <= MAX_CAPTURE_REQUEST_BYTES);
    assert!(meter.calls < 30);
}

#[test]
fn statuses_classify_by_phase_without_reading_provider_content() {
    let page = json!({"stakeholders":[]});
    let cases: Vec<(Vec<Scripted>, Failure, Phase)> = vec![
        (
            vec![Ok(reply(400, &json!({"error":"invalid_client"})))],
            Failure::AuthenticationFailed,
            Phase::Token,
        ),
        (
            vec![Ok(reply(401, &json!({})))],
            Failure::AuthenticationFailed,
            Phase::Token,
        ),
        (
            vec![Ok(reply(403, &json!({})))],
            Failure::ScopeDenied,
            Phase::Token,
        ),
        (
            vec![Ok(reply(429, &json!({})))],
            Failure::RateLimited,
            Phase::Token,
        ),
        (
            vec![Ok(reply(503, &json!({})))],
            Failure::Unavailable,
            Phase::Token,
        ),
        (
            vec![Err(Failure::Unavailable.into())],
            Failure::Unavailable,
            Phase::Token,
        ),
        (
            vec![Ok(reply(302, &json!({})))],
            Failure::ResponseInvalid,
            Phase::Token,
        ),
        (
            vec![Ok(reply(200, &token_body())), Ok(reply(401, &page))],
            Failure::AuthenticationFailed,
            Phase::Stakeholders,
        ),
        (
            vec![Ok(reply(200, &token_body())), Ok(reply(403, &page))],
            Failure::ScopeDenied,
            Phase::Stakeholders,
        ),
        (
            vec![Ok(reply(200, &token_body())), Ok(reply(404, &page))],
            Failure::ScopeDenied,
            Phase::Stakeholders,
        ),
        (
            vec![Ok(reply(200, &token_body())), Ok(reply(400, &page))],
            Failure::ResponseInvalid,
            Phase::Stakeholders,
        ),
        (
            vec![Ok(reply(200, &token_body())), Ok(reply(500, &page))],
            Failure::Unavailable,
            Phase::Stakeholders,
        ),
        (
            vec![
                Ok(reply(200, &token_body())),
                Ok(reply(200, &page)),
                Ok(reply(429, &page)),
            ],
            Failure::RateLimited,
            Phase::OptionGrants,
        ),
        (
            vec![
                Ok(reply(200, &token_body())),
                Ok(reply(200, &page)),
                Err(Failure::Unavailable.into()),
            ],
            Failure::Unavailable,
            Phase::OptionGrants,
        ),
        (
            vec![
                Ok(reply(200, &token_body())),
                Ok(Reply {
                    status: 200,
                    json: false,
                    body: b"<html>".to_vec(),
                    retry_after_seconds: None,
                }),
            ],
            Failure::ResponseInvalid,
            Phase::Stakeholders,
        ),
        (
            vec![
                Ok(reply(200, &token_body())),
                Ok(reply(200, &json!("not a page"))),
            ],
            Failure::ResponseInvalid,
            Phase::Stakeholders,
        ),
    ];
    for (replies, expected, phase) in cases {
        let calls = replies.len() as u64;
        let mut port = FixturePort::new(replies);
        let (result, meter) = run(&plan(CartaChildren::Include), &mut port);
        assert_eq!(failure(result), expected, "{phase:?}");
        assert_eq!(meter.calls, calls);
        assert_eq!(meter.last.map(|last| last.phase), Some(phase));
    }
    // A continuation the provider refuses is a pagination failure, and a 429
    // keeps its Retry-After for the operator without being retried.
    let mut port = FixturePort::new(vec![
        Ok(reply(200, &token_body())),
        Ok(reply(200, &json!({"stakeholders":[],"nextPageToken":"t1"}))),
        Ok(Reply {
            retry_after_seconds: Some(17),
            ..reply(400, &json!({}))
        }),
    ]);
    let (result, meter) = run(&plan(CartaChildren::Include), &mut port);
    assert_eq!(failure(result), Failure::PaginationInvalid);
    let last = meter.last.unwrap();
    assert_eq!(
        (last.page, last.http_status, last.retry_after_seconds),
        (1, Some(400), Some(17))
    );
}

#[test]
fn a_failed_exchange_meters_the_bytes_and_metadata_it_already_consumed() {
    let token = reply(200, &token_body());
    let token_bytes = token.body.len() as u64;
    let mut port = FixturePort::new(vec![
        Ok(token),
        Err(TransportFailure {
            failure: Failure::Unavailable,
            response_bytes: 1024,
            http_status: Some(200),
            retry_after_seconds: None,
        }),
    ]);
    let (result, meter) = run(&plan(CartaChildren::Include), &mut port);
    assert_eq!(failure(result), Failure::Unavailable);
    assert_eq!(meter.calls, 2);
    assert_eq!(meter.response_bytes, token_bytes + 1024);
    assert_eq!(
        meter.last,
        Some(Exchange {
            phase: Phase::Stakeholders,
            page: 0,
            http_status: Some(200),
            retry_after_seconds: None,
        })
    );
    // A response refused from its headers keeps the status it declared.
    let mut port = FixturePort::new(vec![Err(TransportFailure {
        failure: Failure::ResponseTooLarge,
        response_bytes: 0,
        http_status: Some(429),
        retry_after_seconds: Some(7),
    })]);
    let (result, meter) = run(&plan(CartaChildren::Include), &mut port);
    assert_eq!(failure(result), Failure::ResponseTooLarge);
    assert_eq!(
        meter
            .last
            .map(|last| (last.http_status, last.retry_after_seconds)),
        Some((Some(429), Some(7)))
    );
}

#[test]
fn token_responses_must_be_a_bounded_bearer_with_the_required_scopes() {
    let mut cases = Vec::new();
    for (field, value) in [
        ("token_type", json!("mac")),
        ("expires_in", json!(59)),
        ("access_token", json!("")),
        ("access_token", json!("has space")),
        (
            "access_token",
            json!("x".repeat(MAX_ACCESS_TOKEN_BYTES + 1)),
        ),
        ("access_token", Value::Null),
    ] {
        let mut body = token_body();
        body[field] = value;
        cases.push((body, Failure::AuthenticationFailed));
    }
    let mut narrow = token_body();
    narrow["scope"] = json!("read_issuer_stakeholders");
    cases.push((narrow, Failure::ScopeDenied));
    cases.push((json!(["not", "a", "token"]), Failure::AuthenticationFailed));
    for (body, expected) in cases {
        let mut port = FixturePort::new(vec![Ok(reply(200, &body))]);
        let (result, meter) = run(&plan(CartaChildren::Include), &mut port);
        assert_eq!(failure(result), expected, "{body}");
        assert_eq!(meter.calls, 1, "no page is requested with a rejected token");
    }
    // Scope may be omitted when it equals the request, and the type is
    // case-insensitive.
    let mut omitted = token_body();
    omitted.as_object_mut().unwrap().remove("scope");
    omitted["token_type"] = json!("bearer");
    let mut port = FixturePort::of(omitted, vec![json!({})], vec![json!({})]);
    assert!(run(&plan(CartaChildren::Include), &mut port).0.is_ok());
}

#[test]
fn provider_shapes_fail_closed_on_missing_null_or_foreign_values() {
    let page = |body: Value| vec![json!({"stakeholders":[body]})];
    let mut cases = Vec::new();
    for field in [
        "email",
        "issuerId",
        "fullName",
        "relationship",
        "entityType",
    ] {
        let mut missing = stakeholder("s1");
        missing.as_object_mut().unwrap().remove(field);
        cases.push((page(missing), vec![], Failure::ResponseInvalid));
        let mut null = stakeholder("s1");
        null[field] = Value::Null;
        cases.push((page(null), vec![], Failure::ResponseInvalid));
    }
    let mut foreign = stakeholder("s1");
    foreign["issuerId"] = json!("7654321");
    cases.push((page(foreign), vec![], Failure::IssuerScopeMismatch));
    for (field, value) in [
        ("exercisePrice", Value::Null),
        ("vestingSchedule", Value::Null),
        ("issueDate", json!({})),
        ("issueDate", json!("2024-01-01")),
        ("earlyExercisable", json!("true")),
        ("quantity", json!({"value":1000})),
    ] {
        let mut grant = grant("g1", "s1");
        grant[field] = value;
        cases.push((
            vec![json!({})],
            vec![json!({"optionGrants":[grant]})],
            Failure::ResponseInvalid,
        ));
    }
    let mut foreign_grant = grant("g1", "s1");
    foreign_grant["issuerId"] = json!("1");
    cases.push((
        vec![json!({})],
        vec![json!({"optionGrants":[foreign_grant]})],
        Failure::IssuerScopeMismatch,
    ));
    let duplicate_key = Reply {
        status: 200,
        json: true,
        body: br#"{"stakeholders":[],"stakeholders":[]}"#.to_vec(),
        retry_after_seconds: None,
    };
    for (stakeholders, grants, expected) in cases {
        let mut port = FixturePort::of(token_body(), stakeholders, grants);
        assert_eq!(
            failure(run(&plan(CartaChildren::Include), &mut port).0),
            expected
        );
    }
    let mut port = FixturePort::new(vec![Ok(reply(200, &token_body())), Ok(duplicate_key)]);
    assert_eq!(
        failure(run(&plan(CartaChildren::Include), &mut port).0),
        Failure::ResponseInvalid
    );
}

#[test]
fn response_record_and_capture_bounds_fail_before_publication() {
    let mut port = FixturePort::of(
        token_body(),
        vec![json!({"stakeholders":[stakeholder("s1")]})],
        vec![],
    );
    let (result, meter) = collect_complete(&plan(CartaChildren::Include), &mut port, 64);
    assert_eq!(failure(result), Failure::ResponseTooLarge);
    assert_eq!(
        meter.response_bytes,
        token_body().to_string().len() as u64 + 65
    );

    let mut huge = stakeholder("s1");
    huge["fullName"] = json!("x".repeat(crate::carta::MAX_RECORD_BYTES));
    let mut port = FixturePort::of(token_body(), vec![json!({"stakeholders":[huge]})], vec![]);
    assert_eq!(
        failure(run(&plan(CartaChildren::Include), &mut port).0),
        Failure::RecordByteBudget
    );

    let small = json!({"id":"s","issuerId":ISSUER,"fullName":"","email":"","relationship":"","entityType":""});
    let mut port = FixturePort::of(
        token_body(),
        vec![json!({"stakeholders":vec![small; crate::carta::MAX_RECORDS + 1]})],
        vec![],
    );
    assert_eq!(
        failure(run(&plan(CartaChildren::Include), &mut port).0),
        Failure::RecordCountBudget
    );
}

fn complete_capture(plan: &CapturePlan, stakeholders: &[&str]) -> Result<CompleteCapture> {
    let mut port = FixturePort::of(
        token_body(),
        vec![
            json!({"stakeholders":stakeholders.iter().map(|id| stakeholder(id)).collect::<Vec<_>>()}),
        ],
        vec![json!({})],
    );
    run(plan, &mut port).0
}

fn record_read(plan: &CapturePlan, snapshot: &str, cursor: u64) -> RecordRead {
    RecordRead::authorize(
        plan,
        &crate::protocol::Instruction {
            kind: "observe".into(),
            model: "carta.record.v1".into(),
            data: json!({"handle":"h","snapshot_id":snapshot,"cursor":cursor}).to_string(),
            ..Default::default()
        },
    )
    .expect("a well-formed record read")
}

#[test]
fn published_captures_are_immutable_and_retain_current_and_previous() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join(STORE);
    let plan = plan(CartaChildren::Include);
    assert_eq!(
        read_record(
            &path,
            &record_read(&plan, &format!("carta_{}", "0".repeat(64)), 0)
        )
        .unwrap_err()
        .to_string(),
        "carta_snapshot_unavailable"
    );
    assert!(!path.exists(), "a read never creates the live store");
    let first = complete_capture(&plan, &["s1"])?;
    let second = complete_capture(&plan, &["s1", "s2"])?;
    let third = complete_capture(&plan, &["s3"])?;
    publish(&path, &first, 100, 110)?;
    let original = read_record(&path, &record_read(&plan, &first.snapshot().id, 0))?;
    publish(&path, &second, 200, 210)?;
    assert_eq!(
        original,
        read_record(&path, &record_read(&plan, &first.snapshot().id, 0))?,
        "an import reading the previous capture continues while a newer one lands"
    );
    // An unchanged recapture is the same capture and does not evict the previous.
    for at in [300, 400] {
        publish(&path, &complete_capture(&plan, &["s1", "s2"])?, at, at)?;
        assert!(read_record(&path, &record_read(&plan, &first.snapshot().id, 0)).is_ok());
    }
    publish(&path, &third, 500, 510)?;
    assert_eq!(
        read_record(&path, &record_read(&plan, &first.snapshot().id, 0))
            .unwrap_err()
            .to_string(),
        "carta_snapshot_unavailable"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&read_record(
            &path,
            &record_read(&plan, &second.snapshot().id, 2)
        )?)?,
        json!({"kind":"done","data":"{}"})
    );
    assert!(read_record(&path, &record_read(&plan, &second.snapshot().id, 3)).is_err());
    assert!(read_record(&path, &record_read(&plan, &third.snapshot().id, 0)).is_ok());
    let connection = Connection::open(&path)?;
    let (snapshots, records, selections): (i64, i64, i64) = connection.query_row(
        "SELECT (SELECT count(*) FROM carta_snapshots),(SELECT count(*) FROM carta_records),(SELECT count(*) FROM carta_selection)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!((snapshots, records, selections), (2, 3, 2));
    connection.pragma_update(None, "foreign_keys", true)?;
    for statement in [
        "UPDATE carta_records SET envelope='{}'",
        "UPDATE carta_snapshots SET record_count=0",
        "UPDATE carta_selection SET collected_to=collected_to+1",
        "DELETE FROM carta_records",
        "DELETE FROM carta_snapshots",
        "DELETE FROM carta_selection",
        "INSERT OR REPLACE INTO carta_records SELECT * FROM carta_records LIMIT 1",
        "INSERT OR REPLACE INTO carta_snapshots SELECT * FROM carta_snapshots LIMIT 1",
    ] {
        assert!(connection.execute(statement, []).is_err(), "{statement}");
    }
    assert!(read_record(&path, &record_read(&plan, &second.snapshot().id, 1)).is_ok());
    Ok(())
}

#[test]
fn record_reads_are_bound_to_scope_issuer_source_and_mode() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join(STORE);
    let plan = plan(CartaChildren::Include);
    let capture = complete_capture(&plan, &["s1"])?;
    publish(&path, &capture, 100, 100)?;
    let id = &capture.snapshot().id;
    assert!(read_record(&path, &record_read(&plan, id, 0)).is_ok());
    let mut foreign = record_read(&plan, id, 0);
    foreign.scope = "cartaco/test/other".into();
    let mut issuer = record_read(&plan, id, 0);
    issuer.issuer_id = "7654321".into();
    let mut source = record_read(&plan, id, 0);
    source.source_profile = SourceProfile::Simulated;
    let mut mode = record_read(&plan, id, 0);
    mode.children = CartaChildren::Omit;
    for read in [foreign, issuer, source, mode] {
        assert_eq!(
            read_record(&path, &read).unwrap_err().to_string(),
            "carta_snapshot_unavailable"
        );
    }
    Ok(())
}

/// A plan for the same scope, issuer and mode under a differently reviewed
/// connection profile.
fn plan_through(
    connection_ref: VersionRef,
    edit: impl FnOnce(&mut String, &mut VersionRef, &mut CartaEnvironment),
    simulated: bool,
) -> CapturePlan {
    let LiveConnection::Carta {
        mut credential_ref,
        mut client_id,
        mut environment,
        max_pages_per_collection,
    } = connection(10)
    else {
        unreachable!()
    };
    edit(&mut client_id, &mut credential_ref, &mut environment);
    CapturePlan::authorize(
        SCOPE,
        &connection_ref,
        &LiveConnection::Carta {
            credential_ref,
            client_id,
            environment,
            max_pages_per_collection,
        },
        ISSUER,
        CartaChildren::Include,
        simulated,
    )
    .expect("valid plan")
}

#[test]
fn record_reads_are_bound_to_the_authorizing_connection_client_and_credential() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join(STORE);
    let plan = plan(CartaChildren::Include);
    let capture = complete_capture(&plan, &["s1"])?;
    publish(&path, &capture, 100, 100)?;
    let id = &capture.snapshot().id;
    assert!(read_record(&path, &record_read(&plan, id, 0)).is_ok());
    let other_client = plan_through(
        connection_ref(),
        |client, _, _| *client = "other-client".into(),
        false,
    );
    let other_credential = plan_through(
        connection_ref(),
        |_, credential, _| credential.revision = 2,
        false,
    );
    let other_connection = plan_through(
        VersionRef {
            id: "carta-other".into(),
            revision: 1,
        },
        |_, _, _| {},
        false,
    );
    let other_revision = plan_through(
        VersionRef {
            id: "carta-playground".into(),
            revision: 2,
        },
        |_, _, _| {},
        false,
    );
    for (name, other) in [
        ("client", &other_client),
        ("credential", &other_credential),
        ("connection", &other_connection),
        ("revision", &other_revision),
    ] {
        assert_eq!(
            (other.source_profile, other.environment, other.children),
            (plan.source_profile, plan.environment, plan.children),
            "{name}: only the connection authority differs"
        );
        assert_eq!(
            read_record(&path, &record_read(other, id, 0))
                .unwrap_err()
                .to_string(),
            "carta_snapshot_unavailable",
            "{name}"
        );
        // The same provider content collected through it is a distinct
        // capture with its own selection, never the original's identity.
        let theirs = complete_capture(other, &["s1"])?;
        assert_ne!(&theirs.snapshot().id, id, "{name}");
    }
    Ok(())
}

#[test]
fn a_simulated_production_connection_cannot_read_a_simulated_playground_capture() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join(STORE);
    let playground = plan_through(connection_ref(), |_, _, _| {}, true);
    let production = plan_through(
        connection_ref(),
        |_, _, environment| *environment = CartaEnvironment::Production,
        true,
    );
    // Both source profiles are carta_simulated; the environment still binds.
    assert_eq!(playground.source_profile, production.source_profile);
    let capture = complete_capture(&playground, &["s1"])?;
    publish(&path, &capture, 100, 100)?;
    let id = &capture.snapshot().id;
    assert!(read_record(&path, &record_read(&playground, id, 0)).is_ok());
    assert_eq!(
        read_record(&path, &record_read(&production, id, 0))
            .unwrap_err()
            .to_string(),
        "carta_snapshot_unavailable"
    );
    // Same authority but a different environment column is also refused.
    let mut forged = record_read(&playground, id, 0);
    forged.environment = CartaEnvironment::Production;
    assert_eq!(
        read_record(&path, &forged).unwrap_err().to_string(),
        "carta_snapshot_unavailable"
    );
    Ok(())
}

#[test]
fn retention_is_per_connection_so_another_connection_never_prunes_a_capture() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join(STORE);
    let ours = plan(CartaChildren::Include);
    let theirs = plan_through(
        connection_ref(),
        |client, _, _| *client = "other-client".into(),
        false,
    );
    let kept = complete_capture(&ours, &["s1"])?;
    publish(&path, &kept, 100, 100)?;
    for (at, holders) in [(200, &["s2"][..]), (300, &["s3"]), (400, &["s4"])] {
        publish(&path, &complete_capture(&theirs, holders)?, at, at)?;
    }
    assert!(
        read_record(&path, &record_read(&ours, &kept.snapshot().id, 0)).is_ok(),
        "three captures through another connection leave ours selected"
    );
    let selections: i64 =
        Connection::open(&path)?
            .query_row("SELECT count(*) FROM carta_selection", [], |row| row.get(0))?;
    assert_eq!(selections, 3, "ours plus their current and previous");
    Ok(())
}

#[test]
fn the_live_store_has_an_explicit_fail_closed_capacity() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join(STORE);
    let plan = plan(CartaChildren::Include);
    let capture = complete_capture(&plan, &["s1"])?;
    let error = publish_with_limit(&path, &capture, 1, 1, 1).unwrap_err();
    assert_eq!(error.downcast_ref::<Failure>(), Some(&Failure::StoreFull));
    assert_eq!(
        read_record(&path, &record_read(&plan, &capture.snapshot().id, 0))
            .unwrap_err()
            .to_string(),
        "carta_snapshot_unavailable",
        "a refused publication leaves nothing selected"
    );
    publish(&path, &capture, 1, 1)?;
    assert!(
        publish(&path, &capture, 2, 1).is_err(),
        "time cannot run backwards"
    );
    Ok(())
}

#[test]
fn plans_refuse_foreign_connections_and_non_numeric_issuers() {
    assert!(
        CapturePlan::authorize(
            SCOPE,
            &connection_ref(),
            &connection(10),
            "synthetic-issuer-1",
            CartaChildren::Include,
            false
        )
        .is_err()
    );
    assert!(
        CapturePlan::authorize(
            SCOPE,
            &connection_ref(),
            &connection(0),
            ISSUER,
            CartaChildren::Include,
            false
        )
        .is_err()
    );
    assert!(
        CapturePlan::authorize(
            SCOPE,
            &connection_ref(),
            &LiveConnection::WorkspaceDirectory {
                service_account: "reader@company.iam.gserviceaccount.com".into(),
                auth: day2_capabilities::integrations::WorkspaceDirectoryAuth::DirectServiceAccount,
            },
            ISSUER,
            CartaChildren::Include,
            false
        )
        .is_err()
    );
    let plan = plan_with(CartaChildren::Include, 50);
    assert_eq!(plan.planned_calls(), 101);
    assert_eq!(plan.source_profile().name(), "carta_playground");
}

mod simulated {
    use super::*;
    use crate::integrations::simulated::{
        CARTA_OPTION_GRANTS_ENDPOINT, CARTA_STAKEHOLDERS_ENDPOINT, CARTA_TOKEN_ENDPOINT,
        CARTA_WORLD, CartaWireWorld, ScheduledFault, SimulatedFault, schedule_faults, update_carta,
    };

    pub(super) fn world() -> CartaWireWorld {
        CartaWireWorld {
            issuer_id: ISSUER.into(),
            token: token_body(),
            stakeholder_pages: vec![
                json!({"stakeholders":[stakeholder("s1")],"nextPageToken":"page+2/="}),
                json!({"stakeholders":[stakeholder("s2")]}),
            ],
            grant_pages: vec![json!({"optionGrants":[grant("g1","s1")],"nextPageToken":""})],
        }
    }

    pub(super) fn seed(database: &Path, world: Option<CartaWireWorld>) -> Result<()> {
        crate::integrations::simulated::seed(
            database,
            SCOPE,
            &crate::integrations::simulated::SimulatedFixture {
                slack: crate::integrations::simulated::SlackWorld {
                    workspace_id: "TCARTA".into(),
                    ..Default::default()
                },
                snowflake: crate::integrations::simulated::SnowflakeWorld {
                    account: "carta-test".into(),
                    ..Default::default()
                },
                openai: crate::integrations::simulated::OpenAiWorld {
                    project_id: "proj_carta".into(),
                    model: "model-carta".into(),
                    max_input_tokens: 100_000,
                    ..Default::default()
                },
                carta: world,
                ..Default::default()
            },
        )
    }

    fn simulated_plan() -> CapturePlan {
        CapturePlan::authorize(
            SCOPE,
            &connection_ref(),
            &connection(10),
            ISSUER,
            CartaChildren::Include,
            true,
        )
        .unwrap()
    }

    #[test]
    fn the_simulated_port_runs_the_live_pipeline_against_wire_bodies() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("app.sqlite");
        seed(&database, Some(world()))?;
        let mut port = SimulatedCartaPort::new(&database, SCOPE, ISSUER)?;
        let (capture, meter) =
            collect_complete(&simulated_plan(), &mut port, MAX_PAGE_RESPONSE_BYTES);
        let capture = capture?;
        assert_eq!(capture.snapshot().source_profile, "carta_simulated");
        assert_eq!(capture.snapshot().record_count, 5);
        assert_eq!(meter.calls, 4);
        let calls = update_carta(&database, SCOPE, |state| Ok(state.calls.clone()))?;
        assert_eq!(
            calls,
            [
                CARTA_TOKEN_ENDPOINT.to_owned(),
                format!("{CARTA_STAKEHOLDERS_ENDPOINT}:{ISSUER}:"),
                format!("{CARTA_STAKEHOLDERS_ENDPOINT}:{ISSUER}:pageToken=page%2B2%2F%3D"),
                format!("{CARTA_OPTION_GRANTS_ENDPOINT}:{ISSUER}:"),
            ]
        );
        Ok(())
    }

    #[test]
    fn every_scheduled_fault_classifies_on_each_phase() -> Result<()> {
        use SimulatedFault::*;
        for (endpoint, phase) in [
            (CARTA_TOKEN_ENDPOINT, Phase::Token),
            (CARTA_STAKEHOLDERS_ENDPOINT, Phase::Stakeholders),
            (CARTA_OPTION_GRANTS_ENDPOINT, Phase::OptionGrants),
        ] {
            for (fault, expected) in [
                (RateLimited, Failure::RateLimited),
                (Denied, Failure::ScopeDenied),
                (ServerError, Failure::Unavailable),
                (ConnectionLost, Failure::Unavailable),
                (Oversized, Failure::ResponseTooLarge),
                (NotJson, Failure::ResponseInvalid),
            ] {
                let directory = tempfile::tempdir()?;
                let database = directory.path().join("app.sqlite");
                seed(&database, Some(world()))?;
                schedule_faults(
                    &database,
                    SCOPE,
                    CARTA_WORLD,
                    vec![ScheduledFault {
                        endpoint: endpoint.into(),
                        remaining: 1,
                        fault,
                    }],
                )?;
                let mut port = SimulatedCartaPort::new(&database, SCOPE, ISSUER)?;
                let (result, meter) =
                    collect_complete(&simulated_plan(), &mut port, MAX_PAGE_RESPONSE_BYTES);
                assert_eq!(failure(result), expected, "{endpoint} {fault:?}");
                let last = meter.last.unwrap();
                assert_eq!(last.phase, phase);
                assert_eq!(
                    last.retry_after_seconds,
                    (fault == RateLimited).then_some(30)
                );
                // The fault is consumed: an identical retry completes.
                let mut port = SimulatedCartaPort::new(&database, SCOPE, ISSUER)?;
                assert!(
                    collect_complete(&simulated_plan(), &mut port, MAX_PAGE_RESPONSE_BYTES)
                        .0
                        .is_ok()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn the_world_answers_like_the_provider_for_foreign_issuers_tokens_and_bearers() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("app.sqlite");
        seed(&database, Some(world()))?;
        let mut foreign = SimulatedCartaPort::new(&database, SCOPE, "7654321")?;
        let foreign_plan = CapturePlan::authorize(
            SCOPE,
            &connection_ref(),
            &connection(10),
            "7654321",
            CartaChildren::Include,
            true,
        )?;
        assert_eq!(
            failure(collect_complete(&foreign_plan, &mut foreign, MAX_PAGE_RESPONSE_BYTES).0),
            Failure::ScopeDenied
        );
        // The last page names a continuation no page answers: Carta refuses an
        // unknown page token, and the pipeline reports a pagination failure.
        update_carta(&database, SCOPE, |state| {
            state.world.stakeholder_pages[1]["nextPageToken"] = json!("never-issued");
            Ok(())
        })?;
        let mut port = SimulatedCartaPort::new(&database, SCOPE, ISSUER)?;
        assert_eq!(
            failure(collect_complete(&simulated_plan(), &mut port, MAX_PAGE_RESPONSE_BYTES).0),
            Failure::PaginationInvalid
        );
        // Pages require the bearer the token endpoint issued.
        let stale = crate::integrations::simulated::carta_read(
            &database,
            SCOPE,
            crate::integrations::simulated::CartaRead::Page {
                issuer_id: ISSUER,
                collection: Collection::Stakeholders,
                query: None,
                bearer: "stale-token",
            },
            MAX_PAGE_RESPONSE_BYTES,
        )
        .map_err(|failure| anyhow::Error::from(failure.failure))?;
        assert_eq!(stale.status, 401);
        let directory = tempfile::tempdir()?;
        let unseeded = directory.path().join("app.sqlite");
        seed(&unseeded, None)?;
        assert_eq!(
            SimulatedCartaPort::new(&unseeded, SCOPE, ISSUER)
                .err()
                .expect("unseeded world")
                .to_string(),
            "simulated_provider_unconfigured"
        );
        assert!(
            !unseeded.with_file_name(CARTA_WORLD).exists(),
            "an absent Carta world leaves the synthetic store untouched"
        );
        Ok(())
    }
}
