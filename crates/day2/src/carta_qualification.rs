//! Operator-run live Carta qualification. Never part of verification and never
//! reached by an application: `xtask carta-qualify` calls it with a reviewed
//! profile and a secret file.
//!
//! It drives the native port through the production pipeline into a scratch
//! store and returns a receipt describing what Carta actually sent: page and
//! byte counts, end-of-pagination forms, and per-field presence counts. The
//! receipt holds field names and counts only, never a value, token or secret,
//! and always reports `provider_qualified: false` until a reviewer accepts it.
use crate::carta_live::{
    AccessToken, CapturePlan, CartaPort, Collection, Failure, MAX_PAGE_RESPONSE_BYTES, Reply,
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

/// Presence of one reviewed field across every object of its kind.
#[derive(Clone, Copy, Debug, Default, Serialize)]
struct Presence {
    present: u64,
    null: u64,
    absent: u64,
    empty_string: u64,
}

#[derive(Default, Serialize)]
struct Kind {
    objects: u64,
    fields: BTreeMap<&'static str, Presence>,
    /// Names only: fields Carta sent that the adapter does not map.
    unmapped: BTreeMap<String, u64>,
}

impl Kind {
    fn observe(&mut self, object: &Map<String, Value>, fields: &'static [&'static str]) {
        self.objects += 1;
        for field in fields {
            let mut value = Some(&Value::Object(object.clone()));
            for part in field.split('.') {
                value = value.and_then(|value| value.get(part));
            }
            let presence = self.fields.entry(field).or_default();
            match value {
                None => presence.absent += 1,
                Some(Value::Null) => presence.null += 1,
                Some(Value::String(text)) if text.is_empty() => presence.empty_string += 1,
                Some(_) => presence.present += 1,
            }
        }
        for key in object.keys() {
            if !fields.contains(&key.as_str()) {
                *self.unmapped.entry(key.clone()).or_default() += 1;
            }
        }
    }
}

#[derive(Serialize)]
struct PageSummary {
    collection: &'static str,
    ordinal: usize,
    status: u16,
    bytes: usize,
    items: Option<usize>,
    /// `absent`, `null`, `empty` or `present`; a token's value is not kept.
    next_page_token: Option<&'static str>,
}

/// Records shapes and counts of each reply on its way to the pipeline.
struct Recording<P> {
    inner: P,
    token: Option<Value>,
    pages: Vec<PageSummary>,
    stakeholders: Kind,
    grants: Kind,
    vesting_events: Kind,
    exercises: Kind,
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
    fn token(&mut self, form: &str, max_bytes: usize) -> std::result::Result<Reply, Failure> {
        let reply = self.inner.token(form, max_bytes)?;
        let parsed: Option<Value> = serde_json::from_slice(&reply.body).ok();
        // Never the access token: only its envelope.
        self.token = Some(json!({
            "status": reply.status,
            "token_type": parsed.as_ref().and_then(|value| value.get("token_type")).cloned(),
            "expires_in": parsed.as_ref().and_then(|value| value.get("expires_in")).cloned(),
            "scope": parsed.as_ref().and_then(|value| value.get("scope")).cloned(),
        }));
        Ok(reply)
    }

    fn page(
        &mut self,
        collection: Collection,
        query: Option<&str>,
        token: &AccessToken,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Failure> {
        let reply = self.inner.page(collection, query, token, max_bytes)?;
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
            ordinal: self
                .pages
                .iter()
                .filter(|page| page.collection == collection.segment())
                .count(),
            status: reply.status,
            bytes: reply.body.len(),
            items: items.map(Vec::len),
            next_page_token: parsed
                .as_ref()
                .map(|page| token_form(page.get("nextPageToken"))),
        });
        Ok(reply)
    }
}

/// Run one qualification capture. `scratch` is a store path the caller
/// discards; it receives real records, so it must never be retained as evidence.
pub fn qualify(profile: &QualificationProfile, secret: String, scratch: &Path) -> Result<Value> {
    ensure!(profile.format == 1, "carta_qualification_profile_format");
    // Production cut-over is a separately reviewed profile, not this run.
    ensure!(
        profile.environment == CartaEnvironment::Playground,
        "carta_qualification_requires_playground"
    );
    let started = crate::oauth::effects::wall_time()?;
    ensure!(
        started < profile.expires_at,
        "carta_qualification_profile_expired"
    );
    let connection = LiveConnection::Carta {
        credential_ref: VersionRef {
            id: "carta-qualification".into(),
            revision: 1,
        },
        client_id: profile.client_id.clone(),
        environment: profile.environment,
        max_pages_per_collection: profile.max_pages_per_collection,
    };
    let plan = CapturePlan::authorize(
        "qualification/carta",
        &VersionRef {
            id: "carta-qualification".into(),
            revision: 1,
        },
        &connection,
        &profile.issuer_id,
        profile.children,
        false,
    )?;
    let secret = crate::carta_http::CartaClientSecret::new(secret)?;
    let native = crate::carta_http::NativeCartaPort::new(&plan, &profile.client_id, secret)?;
    let mut recording = Recording {
        inner: native,
        token: None,
        pages: Vec::new(),
        stakeholders: Kind::default(),
        grants: Kind::default(),
        vesting_events: Kind::default(),
        exercises: Kind::default(),
    };
    let (capture, meter) =
        crate::carta_live::collect_complete(&plan, &mut recording, MAX_PAGE_RESPONSE_BYTES);
    let finished = crate::oauth::effects::wall_time()?;
    let (outcome, snapshot) = match capture.and_then(|capture| {
        crate::carta_live::publish(scratch, &capture, started, finished.max(started))?;
        Ok(capture.snapshot().clone())
    }) {
        Ok(snapshot) => ("captured".to_owned(), Some(snapshot)),
        Err(error) => (crate::error::observation_code(&error), None),
    };
    let (login_origin, api_origin) = crate::carta_http::origins(profile.environment);
    Ok(json!({
        "format": 1,
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
            "phase": format!("{:?}", last.phase),
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

    struct Replay(std::collections::VecDeque<Reply>);

    impl CartaPort for Replay {
        fn token(&mut self, _: &str, _: usize) -> std::result::Result<Reply, Failure> {
            Ok(self.0.pop_front().expect("token reply"))
        }

        fn page(
            &mut self,
            _: Collection,
            _: Option<&str>,
            _: &AccessToken,
            _: usize,
        ) -> std::result::Result<Reply, Failure> {
            Ok(self.0.pop_front().expect("page reply"))
        }
    }

    fn reply(body: Value) -> Reply {
        Reply {
            status: 200,
            json: true,
            body: body.to_string().into_bytes(),
            retry_after_seconds: None,
        }
    }

    #[test]
    fn the_recording_keeps_shapes_and_counts_but_no_values() -> Result<()> {
        let secret_value = "SYNTHETIC_NEVER_EXPORT_HOLDER_EMAIL@example.test";
        let plan = CapturePlan::authorize(
            "qualification/carta",
            &VersionRef {
                id: "q".into(),
                revision: 1,
            },
            &LiveConnection::Carta {
                credential_ref: VersionRef {
                    id: "q".into(),
                    revision: 1,
                },
                client_id: "client".into(),
                environment: CartaEnvironment::Playground,
                max_pages_per_collection: 2,
            },
            "42",
            CartaChildren::Include,
            false,
        )?;
        let mut recording = Recording {
            inner: Replay(
                vec![
                    reply(json!({"access_token":"SYNTHETIC_NEVER_EXPORT_TOKEN","token_type":"Bearer","expires_in":3600})),
                    reply(json!({"stakeholders":[{"id":"1","issuerId":"42","fullName":"","email":secret_value,
                        "employeeId":null,"relationship":"EMPLOYEE","entityType":"INDIVIDUAL","extra":1}],
                        "nextPageToken":"SYNTHETIC_NEVER_EXPORT_PAGE_TOKEN"})),
                    reply(json!({"stakeholders":[]})),
                    reply(json!({"nextPageToken":""})),
                ]
                .into(),
            ),
            token: None,
            pages: Vec::new(),
            stakeholders: Kind::default(),
            grants: Kind::default(),
            vesting_events: Kind::default(),
            exercises: Kind::default(),
        };
        let (capture, _) =
            crate::carta_live::collect_complete(&plan, &mut recording, MAX_PAGE_RESPONSE_BYTES);
        assert_eq!(capture?.snapshot().stakeholder_count, 1);
        let receipt = serde_json::to_string(&json!({
            "token": recording.token,
            "pages": recording.pages,
            "stakeholders": recording.stakeholders,
        }))?;
        for private in [
            secret_value,
            "SYNTHETIC_NEVER_EXPORT_TOKEN",
            "SYNTHETIC_NEVER_EXPORT_PAGE_TOKEN",
        ] {
            assert!(
                !receipt.contains(private),
                "{private} leaked into the receipt"
            );
        }
        let receipt: Value = serde_json::from_str(&receipt)?;
        assert_eq!(receipt["stakeholders"]["fields"]["employeeId"]["null"], 1);
        assert_eq!(receipt["stakeholders"]["fields"]["group"]["absent"], 1);
        assert_eq!(
            receipt["stakeholders"]["fields"]["fullName"]["empty_string"],
            1
        );
        assert_eq!(receipt["stakeholders"]["unmapped"]["extra"], 1);
        assert_eq!(receipt["pages"][0]["next_page_token"], "present");
        assert_eq!(receipt["pages"][1]["next_page_token"], "absent");
        assert_eq!(receipt["pages"][2]["next_page_token"], "empty");
        assert_eq!(receipt["pages"][2]["items"], Value::Null);
        assert_eq!(receipt["token"]["token_type"], "Bearer");
        Ok(())
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
