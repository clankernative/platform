//! Admitted Carta actions against independent, scoped wire worlds.
//! No Roc worker, network request or live-provider qualification is claimed.
use super::{Observed, Variant, check, fixture, worlds_in_scope};
use crate::{
    artifact::{Instance, LoadedArtifact},
    capabilities,
    carta::{Grant, OptionalText, Record, Stakeholder},
    integrations::simulated::{self, CartaWireWorld, World},
    protocol::{Instruction, Request},
    simulation::Simulation,
    store::Runtime,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::resources::{Action, Provider};
use serde_json::{Value, json};
use std::{cell::Cell, fs};

const ACTOR: &str = "alice";
const INVOCATION: &str = "carta-coverage";
const ISSUER: &str = "4242";
const SYNTHETIC_ISSUER: &str = "synthetic-issuer-1";
const ACTIONS: [Action; 2] = [Action::CartaSnapshot, Action::CartaRecord];
/// Every action the admitted slot grants, including the v2 held delivery.
const GRANTED: [Action; 5] = [
    Action::CartaSnapshot,
    Action::CartaRecord,
    Action::CartaSnapshotDelivery,
    Action::CartaDeliveryPage,
    Action::CartaRelease,
];

fn label(variant: Variant) -> &'static str {
    match variant {
        Variant::A => "Alpha",
        Variant::B => "Beta",
    }
}

fn wire_world(variant: Variant) -> CartaWireWorld {
    CartaWireWorld {
        issuer_id: ISSUER.into(),
        token: json!({"access_token":"offline-carta-fixture","token_type":"Bearer","expires_in":3600}),
        stakeholder_pages: vec![
            json!({"stakeholders":[{"id":"holder-1","issuerId":ISSUER,"fullName":label(variant),
                "email":"alice@example.test","relationship":"EMPLOYEE","entityType":"INDIVIDUAL"}],
                "nextPageToken":"second/page"}),
            json!({"stakeholders":[{"id":"holder-2","issuerId":ISSUER,"fullName":"Bob",
                "email":"bob@example.test","relationship":"EMPLOYEE","entityType":"INDIVIDUAL"}]}),
        ],
        grant_pages: vec![json!({"optionGrants":[{
            "id":"grant-1","issuerId":ISSUER,"stakeholderId":"holder-1",
            "equityIncentivePlanName":label(variant),"issueDate":{"value":"2024-01-01"},
            "vestingStartDate":{"value":"2024-01-01"},"boardApprovalDate":{"value":"2023-12-15"},
            "grantExpirationDate":{"value":"2034-01-01"},"isoNsoSplit":false,"stockOptionType":"ISO",
            "quantity":{"value":"1000"},"outstandingQuantity":{"value":"1000"},
            "vestedQuantity":{"value":"0"},"exercisedQuantity":{"value":"0"},
            "exercisePrice":{"currencyCode":{"value":"USD"},"amount":{"value":"0.25"}},
            "securityLabel":"ES-1","earlyExercisable":false,
            "vestingSchedule":{"name":"4y","lastModifiedDate":{"value":"2024-01-01"},
                "startDate":{"value":"2024-01-01"},"endDate":{"value":"2028-01-01"}},
            "lastModifiedDatetime":{"value":"2026-01-01T00:00:00Z"}
        }]})],
    }
}

// Independent expected records: neither the production DTO decoder nor its
// capture constructor supplies the expected result.
fn expected_records(variant: Variant) -> Vec<Record> {
    let stakeholder = |id: &str, name: &str, email: &str| {
        Record::Stakeholder(Stakeholder {
            id: id.into(),
            issuer_id: ISSUER.into(),
            full_name: name.into(),
            email: email.into(),
            relationship: "EMPLOYEE".into(),
            entity_type: "INDIVIDUAL".into(),
            ..Default::default()
        })
    };
    vec![
        stakeholder("holder-1", label(variant), "alice@example.test"),
        stakeholder("holder-2", "Bob", "bob@example.test"),
        Record::Grant(Box::new(Grant {
            id: "grant-1".into(),
            issuer_id: ISSUER.into(),
            stakeholder_id: "holder-1".into(),
            equity_incentive_plan_name: label(variant).into(),
            issue_date: "2024-01-01".into(),
            vesting_start_date: "2024-01-01".into(),
            board_approval_date: "2023-12-15".into(),
            stakeholder_acceptance_date: OptionalText::None,
            grant_expiration_date: "2034-01-01".into(),
            stock_option_type: "ISO".into(),
            quantity: "1000".into(),
            outstanding_quantity: "1000".into(),
            vested_quantity: "0".into(),
            exercised_quantity: "0".into(),
            exercise_price_currency: "USD".into(),
            exercise_price_amount: "0.25".into(),
            security_label: "ES-1".into(),
            vesting_schedule_name: "4y".into(),
            vesting_schedule_last_modified_date: "2024-01-01".into(),
            vesting_schedule_start_date: "2024-01-01".into(),
            vesting_schedule_end_date: "2028-01-01".into(),
            last_modified_datetime: "2026-01-01T00:00:00Z".into(),
            ..Default::default()
        })),
    ]
}

struct Harness {
    _directory: tempfile::TempDir,
    simulation: Simulation,
}

impl Harness {
    fn new(variant: Variant) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("instance.json");
        let artifact_path = directory.path().join("contract");
        fs::create_dir(&artifact_path)?;
        let connection = |client: &str| {
            json!({"revision":1,"provider":"carta","live":{
            "provider":"carta","credential_ref":{"id":"fixture-secret","revision":1},
            "client_id":client,"environment":"playground","max_pages_per_collection":2}})
        };
        let resource = |connection: &str, issuer: &str| {
            json!({"revision":1,
            "connection":{"id":connection,"revision":1},"target":{"kind":"carta_issuer","issuer_id":issuer}})
        };
        let slot = |id: &str| {
            json!({"kind":"carta_issuer","allowed_resources":[{"id":id,"revision":1}],
            "actions":GRANTED,"limits":{"max_request_bytes":65536,"max_response_bytes":4194304,
                "max_calls_per_invocation":16},"budgets":[{"id":"calls","revision":1}]})
        };
        let instance = json!({"installation":"cartaco","environment":"test","resources":{
            "version":1,"connections":{"carta":connection("coverage-client"),"other":connection("other-client"),
                "synthetic":{"revision":1,"provider":"carta"}},
            "resources":{"main":resource("carta",ISSUER),"other_connection":resource("other",ISSUER),
                "other_issuer":resource("carta","4343"),"synthetic":resource("synthetic",SYNTHETIC_ISSUER)},
            "policies":{"carta":{"revision":1,"owner":"it","actors":[ACTOR],"allowed_apps":["app"],
                "max_duration_seconds":null,"slots":{"carta":slot("main"),
                    "other_connection":slot("other_connection"),"other_issuer":slot("other_issuer"),
                    "synthetic":slot("synthetic")}}},
            "budgets":{"calls":{"revision":1,"scope":"app","period_seconds":3600,
                "limits":{"calls":100,"bytes":100000000,"concurrency":1}}}},
            "apps":{"app":{"artifact":artifact_path,"readers":[ACTOR],"writers":[ACTOR],
                "authority":{"version":1,"admins":[],"operations":{"carta":{"actors":[ACTOR],
                    "mode":{"kind":"current_state"},"models":{},
                    "observations":GRANTED.iter().filter(|action| !action.is_write()).map(|action|action.capability()).collect::<Vec<_>>(),
                    "effects":GRANTED.iter().filter(|action| action.is_write()).map(|action|action.capability()).collect::<Vec<_>>()}}},
                "resource_policies":[{"policy":{"id":"carta","revision":1},"operation":"carta",
                    "bindings":{"carta":{"id":"main","revision":1},
                        "other_connection":{"id":"other_connection","revision":1},
                        "other_issuer":{"id":"other_issuer","revision":1},
                        "synthetic":{"id":"synthetic","revision":1}}}]}}});
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let admitted = Instance::load(&path)?;
        let artifact = LoadedArtifact::from_contract_for_tests(
            crate::digest(b"admitted-carta-coverage-contract"),
            artifact_path,
            serde_json::from_value(json!({"format":crate::artifact::CURRENT_FORMAT,
                "verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
                "roc_version":"provider-boundary-fixture","worker_digest":"not-executed",
                "schema_digest":crate::digest(b"carta-coverage-schema"),"namespace":"app",
                "schema":{"models":{"items":{"fields":{"value":"text"}}},
                    "inputs":{"empty":{"fields":{}}},"foreign_keys":[]},
                "operations":[{"name":"carta","kind":"command","input_type":"empty","output_type":""}],
                "sources":{},"admission":"local-spike-only"}))?,
        );
        crate::authority_state::AuthorityDocument::resolve_at(&admitted, "app", &artifact, 100000)?;
        let simulation = Simulation::new(
            Runtime::from_artifact_for_tests(
                path,
                "app".into(),
                directory.path().join("app.sqlite"),
                artifact,
            )?,
            [17; 32],
            100000,
        )?;
        simulation.runtime().initialize()?;
        // Every unrelated provider stays fixed across the two runs.
        let mut worlds = fixture(Variant::A);
        worlds.carta = Some(wire_world(variant));
        simulated::seed(
            simulation.runtime().db(),
            simulation.runtime().scope(),
            &worlds,
        )?;
        Ok(Self {
            _directory: directory,
            simulation,
        })
    }

    fn runtime(&self) -> &Runtime {
        self.simulation.runtime()
    }

    fn provider(&self) -> Result<World<CartaWireWorld>> {
        let db = rusqlite::Connection::open_with_flags(
            self.runtime()
                .db()
                .with_file_name(Provider::Carta.world().unwrap()),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let stored: String = db.query_row(
            "SELECT state FROM simulated_provider WHERE scope=?1",
            [self.runtime().scope()],
            |row| row.get(0),
        )?;
        Ok(serde_json::from_str(&stored)?)
    }

    fn authorize(
        &self,
        action: Action,
        mut data: Value,
        binding: &str,
        actor: &str,
    ) -> Result<capabilities::Authorized> {
        let runtime = self.runtime();
        runtime.accept("carta", ACTOR, INVOCATION, &json!({}), 100)?;
        let mut db = crate::store::open(runtime.db())?;
        let tx = crate::write_queue::immediate(&mut db)?;
        let active = crate::authority_state::require_invocation_in(
            &tx, runtime, INVOCATION, "carta", ACTOR,
        )?;
        let mut context = crate::store::invocation_context(&tx, INVOCATION)?;
        context.actor = actor.into();
        let request = Request {
            operation: "carta".into(),
            input: "{}".into(),
            context,
            observations: Vec::new(),
        };
        let handle = crate::resources::host_operation(
            &tx,
            runtime,
            &request,
            &Instruction {
                model: crate::resources::BIND.into(),
                data: json!({"binding":binding,"invocation":INVOCATION}).to_string(),
                ..Default::default()
            },
        )?
        .context("resource handle missing")?;
        let handle: Value = serde_json::from_str(&handle)?;
        data.as_object_mut()
            .context("request object")?
            .entry("handle")
            .or_insert(handle["token"].clone());
        let authorized = capabilities::authorized(
            &tx,
            runtime,
            &request,
            &Instruction {
                kind: if action.is_write() {
                    "external"
                } else {
                    "observe"
                }
                .into(),
                model: action.capability().into(),
                data: data.to_string(),
                ..Default::default()
            },
            active.policy()?,
            action.capability(),
        )?;
        tx.commit()?;
        Ok(authorized)
    }

    fn dispatch(&self, action: Action, data: Value) -> Result<Observed> {
        let authorized = self.authorize(action, data, "carta", ACTOR)?;
        ensure!(
            authorized.resource().grant.provider == Provider::Carta
                && authorized.resource().grant.connection.id == "carta"
                && authorized.resource().grant.resource.id == "main",
            "wrong admitted Carta resource"
        );
        let before = worlds_in_scope(self.runtime().db(), self.runtime().scope())?;
        let resource = authorized.resource().clone();
        // The admission transaction has closed before provider I/O.
        let outcome = if action.is_write() {
            capabilities::execute(self.runtime(), authorized, "carta-effect", "carta-attempt")
        } else {
            capabilities::observe(self.runtime(), authorized, "carta-attempt")
        };
        let result = outcome.result?;
        crate::resources::validate_result(&resource, &result)?;
        let after = worlds_in_scope(self.runtime().db(), self.runtime().scope())?;
        Ok(Observed {
            result,
            before,
            after,
        })
    }

    fn snapshot(&self) -> Result<crate::carta::Snapshot> {
        Ok(serde_json::from_str(
            &self.dispatch(Action::CartaSnapshot, json!({}))?.result,
        )?)
    }

    fn deliver(&self) -> Result<crate::carta::Delivery> {
        Ok(serde_json::from_str(
            &self
                .dispatch(Action::CartaSnapshotDelivery, json!({}))?
                .result,
        )?)
    }

    fn page(&self, id: &str, page: u64) -> Result<Value> {
        Ok(serde_json::from_str(
            &self
                .dispatch(
                    Action::CartaDeliveryPage,
                    json!({"capture_id":id,"page":page}),
                )?
                .result,
        )?)
    }

    fn release(&self, id: &str) -> Result<Value> {
        Ok(serde_json::from_str(
            &self
                .dispatch(Action::CartaRelease, json!({"capture_id":id}))?
                .result,
        )?)
    }

    fn held(&self) -> Result<i64> {
        Ok(crate::store::open(self.runtime().db())?.query_row(
            "SELECT count(DISTINCT id) FROM day2_capture_deliveries WHERE holder=''",
            [],
            |row| row.get(0),
        )?)
    }

    fn record(&self, id: &str, cursor: u64) -> Result<String> {
        Ok(self
            .dispatch(
                Action::CartaRecord,
                json!({"snapshot_id":id,"cursor":cursor}),
            )?
            .result)
    }
}

pub(super) fn observe(action: Action, variant: Variant) -> Result<Observed> {
    let harness = Harness::new(variant)?;
    match action {
        Action::CartaSnapshot => harness.dispatch(action, json!({})),
        Action::CartaRecord => {
            let snapshot = harness.snapshot()?;
            harness.dispatch(action, json!({"snapshot_id":snapshot.id,"cursor":0}))
        }
        Action::CartaSnapshotDelivery => harness.dispatch(action, json!({})),
        Action::CartaDeliveryPage => {
            let delivery = harness.deliver()?;
            harness.dispatch(action, json!({"capture_id":delivery.id,"page":0}))
        }
        _ => anyhow::bail!("not a Carta coverage action"),
    }
}

#[test]
fn carta_actions_use_admitted_handles_and_independent_complete_records() -> Result<()> {
    for action in ACTIONS {
        check(action, |variant| observe(action, variant)).map_err(anyhow::Error::msg)?;
    }
    for variant in [Variant::A, Variant::B] {
        let harness = Harness::new(variant)?;
        let before = harness.provider()?.world;
        let snapshot = harness.snapshot()?;
        assert_eq!(snapshot.issuer_id, ISSUER);
        assert_eq!(snapshot.source_profile, "carta_simulated");
        assert_eq!(
            (
                snapshot.record_count,
                snapshot.stakeholder_count,
                snapshot.grant_count,
                snapshot.vesting_event_count,
                snapshot.exercise_count
            ),
            (3, 2, 1, 0, 0)
        );
        assert!(snapshot.id.starts_with("carta_"));
        let collected = harness.provider()?;
        assert_eq!(
            collected.world, before,
            "capture must not mutate upstream provider DATA"
        );
        assert_eq!(
            collected.calls.len(),
            4,
            "token, both stakeholder pages, then grant page"
        );
        for (cursor, record) in expected_records(variant).iter().enumerate() {
            let actual: Value =
                serde_json::from_str(&harness.record(&snapshot.id, cursor as u64)?)?;
            let expected = serde_json::to_value(record)?;
            assert_eq!(actual["kind"], expected["kind"]);
            let body: Value =
                serde_json::from_str(actual["data"].as_str().context("record data")?)?;
            assert_eq!(body, expected["data"]);
        }
        assert_eq!(
            serde_json::from_str::<Value>(&harness.record(&snapshot.id, 3)?)?,
            json!({"kind":"done","data":"{}"})
        );
        assert_eq!(
            harness.provider()?,
            collected,
            "local records make zero provider calls"
        );
    }
    Ok(())
}

#[test]
fn carta_gate_rejects_constant_and_wrong_world_results_through_the_same_observer() -> Result<()> {
    for action in ACTIONS {
        check(action, |variant| observe(action, variant)).map_err(anyhow::Error::msg)?;
        for wrong_world in [false, true] {
            let calls = Cell::new(0);
            let sabotage = |variant| {
                calls.set(calls.get() + 1);
                let mut actual = observe(action, variant)?;
                actual.result = if wrong_world {
                    actual.before[Provider::Slack.world().unwrap()]
                        .clone()
                        .context("foreign world missing")?
                } else {
                    "constant-carta-result".into()
                };
                Ok(actual)
            };
            assert!(check(action, sabotage).is_err());
            assert_eq!(
                calls.get(),
                2,
                "the common gate must exercise its supplied observer"
            );
        }
    }
    Ok(())
}

#[test]
fn carta_variants_change_only_carta_and_reject_mutating_readers() -> Result<()> {
    for action in ACTIONS {
        let first = observe(action, Variant::A)?;
        let second = observe(action, Variant::B)?;
        for provider in Provider::ALL {
            let key = provider.world().unwrap();
            assert_eq!(
                first.before[key] == second.before[key],
                *provider != Provider::Carta
            );
        }
        assert!(first.changed().is_empty() && second.changed().is_empty());
        for provider in [Provider::Carta, Provider::Slack] {
            assert!(
                check(action, |variant| {
                    let mut actual = observe(action, variant)?;
                    actual
                        .after
                        .insert(provider.world().unwrap(), Some("mutated".into()));
                    Ok(actual)
                })
                .is_err()
            );
        }
    }
    Ok(())
}

#[test]
fn carta_authorization_refuses_foreign_actor_handle_and_binding_before_provider_io() -> Result<()> {
    for action in ACTIONS {
        let harness = Harness::new(Variant::A)?;
        let snapshot = harness.snapshot()?;
        let input = if action == Action::CartaRecord {
            json!({"snapshot_id":snapshot.id,"cursor":0})
        } else {
            json!({})
        };
        let before = harness.provider()?;
        assert!(
            harness
                .authorize(action, input.clone(), "carta", "mallory")
                .is_err()
        );
        let mut forged = input.clone();
        forged["handle"] = json!("forged");
        assert!(harness.authorize(action, forged, "carta", ACTOR).is_err());
        assert!(harness.authorize(action, input, "unbound", ACTOR).is_err());
        assert_eq!(harness.provider()?, before);
    }
    Ok(())
}

#[test]
fn carta_record_refuses_other_connections_issuers_cursors_and_unknown_captures() -> Result<()> {
    let harness = Harness::new(Variant::A)?;
    let snapshot = harness.snapshot()?;
    let before = harness.provider()?;
    for binding in ["other_connection", "other_issuer"] {
        let authorized = harness.authorize(
            Action::CartaRecord,
            json!({"snapshot_id":snapshot.id,"cursor":0}),
            binding,
            ACTOR,
        )?;
        assert!(
            capabilities::observe(harness.runtime(), authorized, "foreign-read")
                .result
                .is_err()
        );
    }
    assert!(harness.record(&snapshot.id, 4).is_err());
    assert!(harness.record(&snapshot.id, u64::MAX).is_err());
    assert!(harness.record("carta_unavailable", 0).is_err());
    assert_eq!(harness.provider()?, before);
    // A refused lookup must not replace the selected capture.
    assert!(harness.record(&snapshot.id, 0).is_ok());
    Ok(())
}

#[test]
fn carta_capture_refuses_a_different_admitted_issuer() -> Result<()> {
    let harness = Harness::new(Variant::A)?;
    let before = harness.provider()?.world;
    let authorized = harness.authorize(Action::CartaSnapshot, json!({}), "other_issuer", ACTOR)?;
    assert!(
        capabilities::observe(harness.runtime(), authorized, "wrong-issuer")
            .result
            .is_err()
    );
    assert_eq!(harness.provider()?.world, before);
    assert!(
        !harness
            .runtime()
            .db()
            .with_file_name(crate::carta_live::STORE)
            .exists(),
        "failed capture must publish nothing"
    );
    Ok(())
}

/// The SDK's tag encoding of a record, built independently of the page encoder.
fn tagged(record: &Record) -> Result<Value> {
    let value = serde_json::to_value(record)?;
    let tag = match value["kind"].as_str().context("record kind")? {
        "stakeholder" => "Stakeholder",
        "grant" => "Grant",
        "vesting_event" => "VestingEvent",
        "exercise" => "Exercise",
        other => anyhow::bail!("unexpected record kind {other}"),
    };
    Ok(json!({ tag: value["data"] }))
}

/// Release changes no provider world: it removes the application's own held
/// copy. Demonstrated by holding a capture of each world, releasing it, and
/// observing that its pages are gone while every world is unchanged.
pub(super) fn check_release(action: Action) -> std::result::Result<(), String> {
    let run = |variant| -> Result<()> {
        ensure!(action == Action::CartaRelease, "not a Carta release");
        let harness = Harness::new(variant)?;
        let delivery = harness.deliver()?;
        ensure!(harness.held()? == 1, "the capture was not held");
        let before = worlds_in_scope(harness.runtime().db(), harness.runtime().scope())?;
        ensure!(
            harness.release(&delivery.id)? == json!({"released":true}),
            "first release must release"
        );
        ensure!(
            harness.release(&delivery.id)? == json!({"released":false}),
            "release must be idempotent"
        );
        ensure!(harness.held()? == 0, "the released capture is still held");
        ensure!(
            harness.page(&delivery.id, 0).is_err(),
            "a released capture still answered a page"
        );
        ensure!(
            worlds_in_scope(harness.runtime().db(), harness.runtime().scope())? == before,
            "release changed a provider world"
        );
        Ok(())
    };
    for variant in [Variant::A, Variant::B] {
        run(variant).map_err(|error| format!("{action:?}: {error:#}"))?;
    }
    Ok(())
}

#[test]
fn carta_delivery_holds_the_complete_capture_in_the_app_database_until_released() -> Result<()> {
    for variant in [Variant::A, Variant::B] {
        let harness = Harness::new(variant)?;
        let delivery = harness.deliver()?;
        assert_eq!(delivery.issuer_id, ISSUER);
        assert_eq!(delivery.source_profile, "carta_simulated");
        assert_eq!(
            (
                delivery.record_count,
                delivery.stakeholder_count,
                delivery.grant_count,
                delivery.vesting_event_count,
                delivery.exercise_count,
                delivery.page_count,
            ),
            (3, 2, 1, 0, 0, 1)
        );
        assert!(delivery.id.starts_with("carta_"));
        assert_eq!(harness.provider()?.calls.len(), 4);
        assert!(
            !harness
                .runtime()
                .db()
                .with_file_name(crate::carta_live::STORE)
                .exists(),
            "v2 publishes nothing beside the app database"
        );
        let page = harness.page(&delivery.id, 0)?;
        let expected = expected_records(variant)
            .iter()
            .map(tagged)
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(page, json!({"records":expected,"page":0,"done":true}));
        assert_eq!(
            harness.provider()?.calls.len(),
            4,
            "pages make no provider call"
        );
        assert!(harness.page(&delivery.id, 1).is_err());

        // A later invocation of the same app reads the held capture: the
        // harness reuses the invocation, so read it from the store directly too.
        assert_eq!(harness.held()?, 1);
        // An unchanged recapture is the capture already held.
        assert_eq!(harness.deliver()?.id, delivery.id);
        assert_eq!(harness.held()?, 1);
        assert_eq!(harness.provider()?.calls.len(), 8);

        // Another connection or issuer cannot read or release it.
        for binding in ["other_connection", "other_issuer"] {
            for (action, input) in [
                (
                    Action::CartaDeliveryPage,
                    json!({"capture_id":delivery.id,"page":0}),
                ),
                (Action::CartaRelease, json!({"capture_id":delivery.id})),
            ] {
                let authorized = harness.authorize(action, input, binding, ACTOR)?;
                let outcome = if action.is_write() {
                    capabilities::execute(harness.runtime(), authorized, "foreign", "foreign")
                } else {
                    capabilities::observe(harness.runtime(), authorized, "foreign")
                };
                assert_eq!(
                    outcome.result.unwrap_err().to_string(),
                    "capture_delivery_authority_changed",
                    "{binding} {action:?}"
                );
            }
        }
        assert_eq!(harness.held()?, 1);
        assert_eq!(harness.release(&delivery.id)?, json!({"released":true}));
        assert_eq!(
            harness.page(&delivery.id, 0).unwrap_err().to_string(),
            "capture_delivery_unavailable"
        );
    }
    Ok(())
}

#[test]
fn carta_delivery_refuses_a_third_unreleased_capture_instead_of_pruning() -> Result<()> {
    let harness = Harness::new(Variant::A)?;
    let mut held = Vec::new();
    for name in ["First", "Second"] {
        simulated::update_carta(harness.runtime().db(), harness.runtime().scope(), |world| {
            world.world.stakeholder_pages[1]["stakeholders"][0]["fullName"] = json!(name);
            Ok(())
        })?;
        held.push(harness.deliver()?.id);
    }
    assert_ne!(held[0], held[1]);
    simulated::update_carta(harness.runtime().db(), harness.runtime().scope(), |world| {
        world.world.stakeholder_pages[1]["stakeholders"][0]["fullName"] = json!("Third");
        Ok(())
    })?;
    let Err(refused) = harness.dispatch(Action::CartaSnapshotDelivery, json!({})) else {
        anyhow::bail!("a third unreleased capture was held")
    };
    let refused = refused.to_string();
    assert_eq!(refused, "capture_delivery_release_required");
    // Nothing the application holds was discarded to make room.
    for id in &held {
        assert!(harness.page(id, 0).is_ok());
    }
    assert_eq!(harness.release(&held[0])?, json!({"released":true}));
    let third = harness.deliver()?;
    assert!(!held.contains(&third.id));
    assert!(harness.page(&held[1], 0).is_ok());
    Ok(())
}

#[test]
fn synthetic_carta_delivery_holds_the_seeded_capture() -> Result<()> {
    let harness = Harness::new(Variant::A)?;
    let observe = |action: Action, data: Value| -> Result<String> {
        let authorized = harness.authorize(action, data, "synthetic", ACTOR)?;
        let outcome = if action.is_write() {
            capabilities::execute(harness.runtime(), authorized, "synthetic", "synthetic")
        } else {
            capabilities::observe(harness.runtime(), authorized, "synthetic")
        };
        outcome.result
    };
    // An unseeded synthetic source is unconfigured, never an empty capture.
    assert_eq!(
        observe(Action::CartaSnapshotDelivery, json!({}))
            .unwrap_err()
            .to_string(),
        "carta_unconfigured"
    );
    let example = crate::carta::synthetic_example();
    let seeded = crate::carta::seed_synthetic(harness.runtime(), &example)?;
    let delivery: crate::carta::Delivery =
        serde_json::from_str(&observe(Action::CartaSnapshotDelivery, json!({}))?)?;
    assert_eq!(delivery.id, seeded.id);
    assert_eq!(delivery.source_profile, "synthetic");
    assert_eq!(delivery.record_count, 8);
    assert_eq!(delivery.page_count, 1);
    let page: Value = serde_json::from_str(&observe(
        Action::CartaDeliveryPage,
        json!({"capture_id":delivery.id,"page":0}),
    )?)?;
    let expected = example
        .records
        .iter()
        .map(tagged)
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(page, json!({"records":expected,"page":0,"done":true}));
    // The live binding of the same app cannot read the synthetic capture.
    let authorized = harness.authorize(
        Action::CartaDeliveryPage,
        json!({"capture_id":delivery.id,"page":0}),
        "carta",
        ACTOR,
    )?;
    assert!(
        capabilities::observe(harness.runtime(), authorized, "cross")
            .result
            .is_err()
    );
    assert_eq!(
        serde_json::from_str::<Value>(&observe(
            Action::CartaRelease,
            json!({"capture_id":delivery.id})
        )?)?,
        json!({"released":true})
    );
    Ok(())
}
