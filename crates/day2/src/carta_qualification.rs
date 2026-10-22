//! Operator-run live Carta qualification. Never part of verification and never
//! reached by an application: the private `ops/CartaQualification.roc` recipe,
//! run by `xtask carta-qualify`, calls [`qualify`] as its collection capability
//! with a reviewed profile and secret.
//!
//! It drives the native port through the production pipeline into a scratch
//! store and returns a receipt describing what Carta actually sent: page and
//! byte counts, end-of-pagination forms, and per-field presence counts. Every
//! receipt entry is a count, a closed classification, a reviewed name or an
//! operator-supplied profile field. No provider-owned value or JSON subtree is
//! retained, including when a response is malformed or the capture fails, and
//! the receipt always reports `provider_qualified: false` until a reviewer
//! accepts it.
use crate::carta_live::{
    AccessToken, CapturePlan, CartaPort, Collection, Failure, MAX_PAGE_RESPONSE_BYTES, Reply,
    TransportFailure,
};
use anyhow::{Result, ensure};
use day2_capabilities::{
    integrations::{CartaEnvironment, LiveConnection},
    resources::{CartaChildren, VersionRef},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, path::Path};

/// What an operator reviewed before a qualification run.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationProfile {
    pub format: u32,
    pub environment: CartaEnvironment,
    pub client_id: String,
    pub issuer_id: String,
    #[serde(default)]
    pub children: CartaChildren,
    pub max_pages_per_collection: u16,
    /// Unix seconds after which this profile no longer authorizes a run.
    pub expires_at: i64,
}

const STAKEHOLDER_FIELDS: &[&str] = &[
    "id",
    "issuerId",
    "fullName",
    "email",
    "employeeId",
    "relationship",
    "group",
    "entityType",
    "address",
    "address.country",
];
const GRANT_FIELDS: &[&str] = &[
    "id",
    "issuerId",
    "stakeholderId",
    "equityIncentivePlanName",
    "issueDate",
    "vestingStartDate",
    "boardApprovalDate",
    "stakeholderAcceptanceDate",
    "grantExpirationDate",
    "isoNsoSplit",
    "stockOptionType",
    "quantity",
    "outstandingQuantity",
    "vestedQuantity",
    "exercisedQuantity",
    "exercisePrice",
    "exercisePrice.currencyCode",
    "exercisePrice.amount",
    "securityLabel",
    "earlyExercisable",
    "vestingEvents",
    "exercises",
    "vestingSchedule",
    "vestingSchedule.name",
    "vestingSchedule.lastModifiedDate",
    "vestingSchedule.startDate",
    "vestingSchedule.endDate",
    "lastModifiedDatetime",
];
const VESTING_EVENT_FIELDS: &[&str] = &[
    "id",
    "vestDate",
    "quantity",
    "isoQuantity",
    "nsoQuantity",
    "performanceCondition",
    "vested",
    "maxQuantity",
    "targetQuantity",
    "vestedQuantity",
];
const EXERCISE_FIELDS: &[&str] = &[
    "exerciseId",
    "quantity",
    "fairMarketValueAsOfDate",
    "exerciseDate",
    "status",
    "certificateId",
    "exerciseType",
    "qualified",
];

/// The JSON shape of a provider value, never the value itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Shape {
    Absent,
    Null,
    Bool,
    Number,
    EmptyString,
    String,
    Array,
    Object,
}

fn shape(value: Option<&Value>) -> Shape {
    match value {
        None => Shape::Absent,
        Some(Value::Null) => Shape::Null,
        Some(Value::Bool(_)) => Shape::Bool,
        Some(Value::Number(_)) => Shape::Number,
        Some(Value::String(text)) if text.is_empty() => Shape::EmptyString,
        Some(Value::String(_)) => Shape::String,
        Some(Value::Array(_)) => Shape::Array,
        Some(Value::Object(_)) => Shape::Object,
    }
}

/// Scope names this receipt may name. The required scopes and the read scopes
/// the earlier Equity client requested; anything else is only counted.
const KNOWN_SCOPES: &[&str] = &[
    "read_issuer_stakeholders",
    "read_issuer_securities",
    "read_issuer_capitalizationtablesummary",
    "read_issuer_securitiestemplates",
    "read_issuer_info",
    "read_issuer_valuations",
    "read_issuer_stakeholdercapitalizationtable",
    "read_issuer_shareclasses",
    "read_issuer_interests",
    "read_issuer_draftsecurities",
];
/// A token lifetime is recorded as a number only within a year.
const MAX_RECORDED_LIFETIME_SECONDS: u64 = 366 * 86_400;

/// The token exchange as typed classifications. It is built from the reply
/// before any validation, so every field is a closed shape, a bounded number
/// or a reviewed scope name: a malformed or hostile response cannot place its
/// own text here.
#[derive(Debug, PartialEq, Eq, Serialize)]
struct TokenEnvelope {
    http_status: Option<u16>,
    json_content_type: bool,
    response_bytes: u64,
    /// The stable code of a transport failure, when no complete reply arrived.
    transport_failure: Option<&'static str>,
    /// `None` when the body is not a JSON document.
    body: Option<Shape>,
    access_token: Shape,
    token_type: Shape,
    /// Whether `token_type` is the string `Bearer`, compared without case.
    token_type_bearer: bool,
    expires_in: Shape,
    expires_in_seconds: Option<u64>,
    scope: Shape,
    granted_known_scopes: Vec<&'static str>,
    other_scope_entries: u64,
}

impl TokenEnvelope {
    fn of(reply: &std::result::Result<Reply, TransportFailure>) -> Self {
        let reply = match reply {
            Ok(reply) => reply,
            Err(failure) => {
                return Self {
                    http_status: failure.http_status,
                    json_content_type: false,
                    response_bytes: failure.response_bytes,
                    transport_failure: Some(failure.failure.code()),
                    body: None,
                    access_token: Shape::Absent,
                    token_type: Shape::Absent,
                    token_type_bearer: false,
                    expires_in: Shape::Absent,
                    expires_in_seconds: None,
                    scope: Shape::Absent,
                    granted_known_scopes: Vec::new(),
                    other_scope_entries: 0,
                };
            }
        };
        let parsed: Option<Value> = serde_json::from_slice(&reply.body).ok();
        let field = |name: &str| parsed.as_ref().and_then(|body| body.get(name));
        let scopes = field("scope").and_then(Value::as_str).map(|granted| {
            granted
                .split(' ')
                .filter(|entry| !entry.is_empty())
                .collect::<Vec<_>>()
        });
        let granted_known_scopes: Vec<&'static str> = KNOWN_SCOPES
            .iter()
            .copied()
            .filter(|known| scopes.as_ref().is_some_and(|scopes| scopes.contains(known)))
            .collect();
        Self {
            http_status: Some(reply.status),
            json_content_type: reply.json,
            response_bytes: reply.body.len() as u64,
            transport_failure: None,
            body: parsed.as_ref().map(|body| shape(Some(body))),
            access_token: shape(field("access_token")),
            token_type: shape(field("token_type")),
            token_type_bearer: field("token_type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.eq_ignore_ascii_case("bearer")),
            expires_in: shape(field("expires_in")),
            expires_in_seconds: field("expires_in")
                .and_then(Value::as_u64)
                .filter(|seconds| *seconds <= MAX_RECORDED_LIFETIME_SECONDS),
            scope: shape(field("scope")),
            other_scope_entries: scopes.map_or(0, |scopes| {
                scopes
                    .iter()
                    .filter(|entry| !KNOWN_SCOPES.contains(entry))
                    .count() as u64
            }),
            granted_known_scopes,
        }
    }
}

/// Presence of one reviewed field across every object of its kind.
#[derive(Clone, Copy, Debug, Default, Serialize)]
struct Presence {
    present: u64,
    null: u64,
    absent: u64,
    empty_string: u64,
}

/// Unmapped field names kept per kind. Names are provider-chosen, so only a
/// bounded number of identifier-shaped names is kept; the rest are counted.
const MAX_UNMAPPED_NAMES: usize = 64;
const MAX_UNMAPPED_NAME_BYTES: usize = 64;

fn identifier(name: &str) -> bool {
    name.len() <= MAX_UNMAPPED_NAME_BYTES
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[derive(Default, Serialize)]
struct Kind {
    objects: u64,
    fields: BTreeMap<&'static str, Presence>,
    /// Names only: identifier-shaped fields Carta sent that are not mapped.
    unmapped: BTreeMap<String, u64>,
    /// Unmapped fields whose name was not identifier-shaped or past the bound.
    unmapped_unnamed: u64,
}

/// A reviewed dotted field path within one provider object.
fn lookup<'a>(object: &'a Map<String, Value>, field: &str) -> Option<&'a Value> {
    let mut parts = field.split('.');
    let mut value = object.get(parts.next()?)?;
    for part in parts {
        value = value.get(part)?;
    }
    Some(value)
}

impl Kind {
    fn observe(&mut self, object: &Map<String, Value>, fields: &'static [&'static str]) {
        self.objects += 1;
        for field in fields {
            let presence = self.fields.entry(field).or_default();
            match lookup(object, field) {
                None => presence.absent += 1,
                Some(Value::Null) => presence.null += 1,
                Some(Value::String(text)) if text.is_empty() => presence.empty_string += 1,
                Some(_) => presence.present += 1,
            }
        }
        for key in object.keys() {
            if fields.contains(&key.as_str()) {
                continue;
            }
            if identifier(key)
                && (self.unmapped.contains_key(key) || self.unmapped.len() < MAX_UNMAPPED_NAMES)
            {
                *self.unmapped.entry(key.clone()).or_default() += 1;
            } else {
                self.unmapped_unnamed += 1;
            }
        }
    }
}

#[derive(Serialize)]
struct PageSummary {
    collection: &'static str,
    ordinal: usize,
    http_status: Option<u16>,
    response_bytes: u64,
    /// The stable code of a transport failure, when no complete reply arrived.
    transport_failure: Option<&'static str>,
    items: Option<usize>,
    /// `absent`, `null`, `empty` or `present`; a token's value is not kept.
    next_page_token: Option<&'static str>,
}

/// Records shapes and counts of each reply on its way to the pipeline.
struct Recording<P> {
    inner: P,
    token: Option<TokenEnvelope>,
    pages: Vec<PageSummary>,
    stakeholders: Kind,
    grants: Kind,
    vesting_events: Kind,
    exercises: Kind,
}

impl<P> Recording<P> {
    fn new(inner: P) -> Self {
        Self {
            inner,
            token: None,
            pages: Vec::new(),
            stakeholders: Kind::default(),
            grants: Kind::default(),
            vesting_events: Kind::default(),
            exercises: Kind::default(),
        }
    }
}

fn token_form(value: Option<&Value>) -> &'static str {
    match value {
        None => "absent",
        Some(Value::Null) => "null",
        Some(Value::String(token)) if token.is_empty() => "empty",
        Some(_) => "present",
    }
}

impl<P: CartaPort> CartaPort for Recording<P> {
    fn token(
        &mut self,
        form: &str,
        max_bytes: usize,
    ) -> std::result::Result<Reply, TransportFailure> {
        let reply = self.inner.token(form, max_bytes);
        // Never the access token or any other value: only its classified envelope.
        self.token = Some(TokenEnvelope::of(&reply));
        reply
    }

    fn page(
        &mut self,
        collection: Collection,
        query: Option<&str>,
        token: &AccessToken,
        max_bytes: usize,
    ) -> std::result::Result<Reply, TransportFailure> {
        let ordinal = self
            .pages
            .iter()
            .filter(|page| page.collection == collection.segment())
            .count();
        let reply = match self.inner.page(collection, query, token, max_bytes) {
            Ok(reply) => reply,
            Err(failure) => {
                self.pages.push(PageSummary {
                    collection: collection.segment(),
                    ordinal,
                    http_status: failure.http_status,
                    response_bytes: failure.response_bytes,
                    transport_failure: Some(failure.failure.code()),
                    items: None,
                    next_page_token: None,
                });
                return Err(failure);
            }
        };
        let parsed: Option<Value> = (reply.status == 200 && reply.body.len() <= max_bytes)
            .then(|| serde_json::from_slice(&reply.body).ok())
            .flatten();
        let array = match collection {
            Collection::Stakeholders => "stakeholders",
            Collection::OptionGrants => "optionGrants",
        };
        let items = parsed
            .as_ref()
            .and_then(|page| page.get(array))
            .and_then(Value::as_array);
        for item in items.into_iter().flatten().filter_map(Value::as_object) {
            match collection {
                Collection::Stakeholders => self.stakeholders.observe(item, STAKEHOLDER_FIELDS),
                Collection::OptionGrants => {
                    self.grants.observe(item, GRANT_FIELDS);
                    for (field, kind, fields) in [
                        (
                            "vestingEvents",
                            &mut self.vesting_events,
                            VESTING_EVENT_FIELDS,
                        ),
                        ("exercises", &mut self.exercises, EXERCISE_FIELDS),
                    ] {
                        let children = item.get(field).and_then(Value::as_array);
                        for child in children.into_iter().flatten().filter_map(Value::as_object) {
                            kind.observe(child, fields);
                        }
                    }
                }
            }
        }
        self.pages.push(PageSummary {
            collection: collection.segment(),
            ordinal,
            http_status: Some(reply.status),
            response_bytes: reply.body.len() as u64,
            transport_failure: None,
            items: items.map(Vec::len),
            next_page_token: parsed
                .as_ref()
                .map(|page| token_form(page.get("nextPageToken"))),
        });
        Ok(reply)
    }
}

/// The mandatory profile guard, checked before any secret is read or request
/// sent and again before collection: a supported format, the playground
/// environment, and an unexpired authorization.
pub fn admit(profile: &QualificationProfile, now: i64) -> Result<()> {
    ensure!(profile.format == 1, "carta_qualification_profile_format");
    // Production cut-over is a separately reviewed profile, not this run.
    ensure!(
        profile.environment == CartaEnvironment::Playground,
        "carta_qualification_requires_playground"
    );
    ensure!(
        now < profile.expires_at,
        "carta_qualification_profile_expired"
    );
    Ok(())
}

fn plan(profile: &QualificationProfile) -> Result<CapturePlan> {
    CapturePlan::authorize(
        "qualification/carta",
        &VersionRef {
            id: "carta-qualification".into(),
            revision: 1,
        },
        &LiveConnection::Carta {
            credential_ref: VersionRef {
                id: "carta-qualification".into(),
                revision: 1,
            },
            client_id: profile.client_id.clone(),
            environment: profile.environment,
            max_pages_per_collection: profile.max_pages_per_collection,
        },
        &profile.issuer_id,
        profile.children,
        false,
    )
}

/// Run one qualification capture through the native port. `scratch` is a store
/// path the caller discards; it receives real records, so it must never be
/// retained as evidence.
pub fn qualify(profile: &QualificationProfile, secret: String, scratch: &Path) -> Result<Value> {
    let started = crate::oauth::effects::wall_time()?;
    admit(profile, started)?;
    let plan = plan(profile)?;
    let secret = crate::carta_http::CartaClientSecret::new(secret)?;
    let native = crate::carta_http::NativeCartaPort::new(&plan, &profile.client_id, secret)?;
    qualify_through(profile, &plan, native, scratch, started)
}

/// The capture and receipt for any port. The outcome is a closed code: a
/// capture failure's stable code, or `carta_publication_failed` for the
/// scratch store, never an error's text.
fn qualify_through<P: CartaPort>(
    profile: &QualificationProfile,
    plan: &CapturePlan,
    port: P,
    scratch: &Path,
    started: i64,
) -> Result<Value> {
    let mut recording = Recording::new(port);
    let (capture, meter) =
        crate::carta_live::collect_complete(plan, &mut recording, MAX_PAGE_RESPONSE_BYTES);
    let finished = crate::oauth::effects::wall_time()?;
    let (outcome, snapshot) = match capture.and_then(|capture| {
        crate::carta_live::publish(scratch, &capture, started, finished.max(started))?;
        Ok(capture.snapshot().clone())
    }) {
        Ok(snapshot) => ("captured", Some(snapshot)),
        Err(error) => (
            error
                .downcast_ref::<Failure>()
                .map_or("carta_publication_failed", |failure| failure.code()),
            None,
        ),
    };
    let (login_origin, api_origin) = crate::carta_http::origins(profile.environment);
    Ok(json!({
        "format": 2,
        "adapter": "carta-live-v1",
        "provider_qualified": false,
        "environment": profile.environment.name(),
        "login_origin": login_origin,
        "api_origin": api_origin,
        "client_id": profile.client_id,
        "issuer_id": profile.issuer_id,
        "children": profile.children.name(),
        "max_pages_per_collection": profile.max_pages_per_collection,
        "required_scopes": crate::carta_live::REQUIRED_SCOPES,
        "started_at": started,
        "finished_at": finished,
        "outcome": outcome,
        "snapshot": snapshot.map(|snapshot| json!({
            "record_count": snapshot.record_count,
            "stakeholder_count": snapshot.stakeholder_count,
            "grant_count": snapshot.grant_count,
            "vesting_event_count": snapshot.vesting_event_count,
            "exercise_count": snapshot.exercise_count,
            "source_profile": snapshot.source_profile,
        })),
        "usage": {
            "calls": meter.calls,
            "request_bytes": meter.request_bytes,
            "response_bytes": meter.response_bytes,
        },
        "last_exchange": meter.last.map(|last| json!({
            "phase": match last.phase {
                crate::carta_live::Phase::Token => "token",
                crate::carta_live::Phase::Stakeholders => "stakeholders",
                crate::carta_live::Phase::OptionGrants => "option_grants",
            },
            "page": last.page,
            "http_status": last.http_status,
            "retry_after_seconds": last.retry_after_seconds,
        })),
        "token_exchange": recording.token,
        "pages": recording.pages,
        "field_presence": {
            "stakeholder": recording.stakeholders,
            "grant": recording.grants,
            "vesting_event": recording.vesting_events,
            "exercise": recording.exercises,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL: &str = "PRIVATE_VALUE_SENTINEL";

    struct Replay(std::collections::VecDeque<std::result::Result<Reply, TransportFailure>>);

    impl CartaPort for Replay {
        fn token(&mut self, _: &str, _: usize) -> std::result::Result<Reply, TransportFailure> {
            self.0.pop_front().expect("token reply")
        }

        fn page(
            &mut self,
            _: Collection,
            _: Option<&str>,
            _: &AccessToken,
            _: usize,
        ) -> std::result::Result<Reply, TransportFailure> {
            self.0.pop_front().expect("page reply")
        }
    }

    fn reply(body: Value) -> std::result::Result<Reply, TransportFailure> {
        raw(body.to_string().into_bytes())
    }

    fn raw(body: Vec<u8>) -> std::result::Result<Reply, TransportFailure> {
        Ok(Reply {
            status: 200,
            json: true,
            body,
            retry_after_seconds: None,
        })
    }

    fn profile() -> QualificationProfile {
        QualificationProfile {
            format: 1,
            environment: CartaEnvironment::Playground,
            client_id: "client".into(),
            issuer_id: "42".into(),
            children: CartaChildren::Include,
            max_pages_per_collection: 2,
            expires_at: i64::MAX,
        }
    }

    /// The whole receipt for scripted replies, as `qualify` would build it.
    fn receipt(replies: Vec<std::result::Result<Reply, TransportFailure>>) -> Result<Value> {
        let directory = tempfile::tempdir()?;
        let profile = profile();
        qualify_through(
            &profile,
            &plan(&profile)?,
            Replay(replies.into()),
            &directory.path().join("carta.sqlite"),
            1,
        )
    }

    #[test]
    fn the_recording_keeps_shapes_and_counts_but_no_values() -> Result<()> {
        let secret_value = "SYNTHETIC_NEVER_EXPORT_HOLDER_EMAIL@example.test";
        let receipt = receipt(vec![
            reply(
                json!({"access_token":"SYNTHETIC_NEVER_EXPORT_TOKEN","token_type":"Bearer",
                "expires_in":3600,"scope":"read_issuer_stakeholders read_issuer_securities x"}),
            ),
            reply(
                json!({"stakeholders":[{"id":"1","issuerId":"42","fullName":"","email":secret_value,
                "employeeId":null,"relationship":"EMPLOYEE","entityType":"INDIVIDUAL","extra":1}],
                "nextPageToken":"SYNTHETIC_NEVER_EXPORT_PAGE_TOKEN"}),
            ),
            reply(json!({"stakeholders":[]})),
            reply(json!({"nextPageToken":""})),
        ])?;
        let rendered = serde_json::to_string(&receipt)?;
        for private in [
            secret_value,
            "SYNTHETIC_NEVER_EXPORT_TOKEN",
            "SYNTHETIC_NEVER_EXPORT_PAGE_TOKEN",
        ] {
            assert!(
                !rendered.contains(private),
                "{private} leaked into the receipt"
            );
        }
        assert_eq!(receipt["outcome"], "captured");
        assert_eq!(receipt["provider_qualified"], false);
        assert_eq!(receipt["snapshot"]["stakeholder_count"], 1);
        let stakeholders = &receipt["field_presence"]["stakeholder"];
        assert_eq!(stakeholders["fields"]["employeeId"]["null"], 1);
        assert_eq!(stakeholders["fields"]["group"]["absent"], 1);
        assert_eq!(stakeholders["fields"]["fullName"]["empty_string"], 1);
        assert_eq!(stakeholders["unmapped"]["extra"], 1);
        let pages = &receipt["pages"];
        assert_eq!(pages[0]["next_page_token"], "present");
        assert_eq!(pages[1]["next_page_token"], "absent");
        assert_eq!(pages[2]["next_page_token"], "empty");
        assert_eq!(pages[2]["items"], Value::Null);
        let token = &receipt["token_exchange"];
        assert_eq!(token["token_type"], "string");
        assert_eq!(token["token_type_bearer"], true);
        assert_eq!(token["expires_in_seconds"], 3600);
        assert_eq!(
            token["granted_known_scopes"],
            json!(["read_issuer_stakeholders", "read_issuer_securities"])
        );
        assert_eq!(token["other_scope_entries"], 1);
        Ok(())
    }

    #[test]
    fn malformed_responses_never_place_provider_values_in_the_receipt() -> Result<()> {
        let nested = json!({ "access_token": SENTINEL });
        let cases = [
            // The reviewed failure: a secret nested under expires_in.
            (
                vec![reply(json!({"access_token":"t","token_type":"Bearer",
                    "expires_in":nested,"scope":"read_issuer_stakeholders read_issuer_securities"}))],
                "carta_authentication_failed",
            ),
            (
                vec![reply(
                    json!({"access_token":SENTINEL,"token_type":{"kind":SENTINEL},
                    "expires_in":SENTINEL,"scope":{"granted":SENTINEL}}),
                )],
                "carta_authentication_failed",
            ),
            (
                vec![reply(json!({"access_token":"t","token_type":[SENTINEL],
                    "expires_in":[3600],"scope":format!("{SENTINEL} read_issuer_stakeholders")}))],
                "carta_authentication_failed",
            ),
            (
                vec![reply(json!({"access_token":"t","token_type":SENTINEL,
                    "expires_in":3600,"scope":SENTINEL}))],
                "carta_authentication_failed",
            ),
            (
                vec![reply(json!({"access_token":"t","token_type":"Bearer",
                    "expires_in":3600,"scope":SENTINEL}))],
                "carta_scope_denied",
            ),
            (
                vec![raw(format!("{SENTINEL} not json").into_bytes())],
                "carta_authentication_failed",
            ),
            (
                vec![Err(TransportFailure {
                    failure: Failure::Unavailable,
                    response_bytes: 7,
                    http_status: Some(200),
                    retry_after_seconds: None,
                })],
                "carta_unavailable",
            ),
            // A malformed page: hostile values, nested objects and a
            // non-identifier field name all stay out of the evidence.
            (
                vec![
                    reply(json!({"access_token":"t","token_type":"Bearer","expires_in":3600})),
                    reply(
                        json!({"stakeholders":[{"id":{"value":SENTINEL},"issuerId":"42",
                        "fullName":SENTINEL,"email":[SENTINEL],"relationship":"EMPLOYEE",
                        "entityType":"INDIVIDUAL","address":{"country":SENTINEL},
                        format!("{SENTINEL}-name"):SENTINEL}],"nextPageToken":SENTINEL}),
                    ),
                ],
                "carta_response_invalid",
            ),
        ];
        for (index, (replies, outcome)) in cases.into_iter().enumerate() {
            let receipt = receipt(replies)?;
            let rendered = serde_json::to_string_pretty(&receipt)?;
            assert!(
                !rendered.contains(SENTINEL),
                "case {index} leaked a provider value:\n{rendered}"
            );
            assert_eq!(receipt["outcome"], outcome, "case {index}");
            assert_eq!(receipt["provider_qualified"], false);
        }
        let envelope = receipt(vec![reply(
            json!({"access_token":"t","token_type":"Bearer","expires_in":nested}),
        )])?;
        let token = &envelope["token_exchange"];
        assert_eq!(token["expires_in"], "object");
        assert_eq!(token["expires_in_seconds"], Value::Null);
        let failed = receipt(vec![Err(TransportFailure {
            failure: Failure::Unavailable,
            response_bytes: 7,
            http_status: Some(200),
            retry_after_seconds: None,
        })])?;
        assert_eq!(
            failed["token_exchange"]["transport_failure"],
            "carta_unavailable"
        );
        assert_eq!(failed["token_exchange"]["response_bytes"], 7);
        assert_eq!(failed["usage"]["response_bytes"], 7);
        Ok(())
    }

    #[test]
    fn unmapped_field_names_are_identifier_shaped_and_bounded() {
        let mut kind = Kind::default();
        let mut object = Map::new();
        for index in 0..(MAX_UNMAPPED_NAMES + 3) {
            object.insert(format!("field{index}"), Value::Null);
        }
        object.insert("not an identifier".into(), Value::Null);
        object.insert("1numeric".into(), Value::Null);
        object.insert("a".repeat(MAX_UNMAPPED_NAME_BYTES + 1), Value::Null);
        kind.observe(&object, STAKEHOLDER_FIELDS);
        assert_eq!(kind.unmapped.len(), MAX_UNMAPPED_NAMES);
        assert_eq!(kind.unmapped_unnamed, 6);
    }

    #[test]
    fn only_an_unexpired_playground_profile_may_run() {
        let profile = |environment, expires_at| QualificationProfile {
            format: 1,
            environment,
            client_id: "client".into(),
            issuer_id: "42".into(),
            children: CartaChildren::Omit,
            max_pages_per_collection: 1,
            expires_at,
        };
        let directory = tempfile::tempdir().unwrap();
        let scratch = directory.path().join("carta.sqlite");
        for (profile, expected) in [
            (
                profile(CartaEnvironment::Production, i64::MAX),
                "carta_qualification_requires_playground",
            ),
            (
                profile(CartaEnvironment::Playground, 0),
                "carta_qualification_profile_expired",
            ),
        ] {
            assert_eq!(admit(&profile, 1).unwrap_err().to_string(), expected);
            assert_eq!(
                qualify(&profile, "secret".into(), &scratch)
                    .unwrap_err()
                    .to_string(),
                expected
            );
        }
        assert!(!scratch.exists());
    }
}
