//! Admitted synthetic Google Directory actions and independent world attribution.
//! Contract-only fixture: no Roc worker, Google wire protocol or live provider claim.
use super::{Observed, Variant, check, fixture, worlds_in_scope};
use crate::{
    artifact::{Instance, LoadedArtifact},
    capabilities,
    people_providers::{self, DirectoryRecord, GoogleWorld, ProviderState},
    protocol::{Instruction, Request},
    simulation::Simulation,
    store::Runtime,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::resources::{Action, Provider};
use serde_json::{Value, json};
use std::fs;

const ACTOR: &str = "alice";
const INVOCATION: &str = "directory-coverage";
const CUSTOMER: &str = "synthetic-customer-1";
const FOREIGN_CUSTOMER: &str = "other-customer";
const EMAIL: &str = "alice@exampleco.example";
const GROUP: &str = "engineering@exampleco.example";
const ACTIONS: [Action; 5] = [
    Action::GoogleDirectorySnapshot,
    Action::GoogleDirectoryRecord,
    Action::GoogleDirectoryCreateUser,
    Action::GoogleDirectoryPatchAttributes,
    Action::GoogleDirectoryEnsureGroupMember,
];

fn synthetic(variant: Variant) -> people_providers::SyntheticFixture {
    let mut fixture = people_providers::synthetic_example();
    let name = if variant == Variant::A {
        "Alpha"
    } else {
        "Beta"
    };
    let account = fixture.google.users.get_mut(EMAIL).unwrap();
    account.user.given_name = name.into();
    account.user.full_name = format!("{name} Example");
    fixture
}

struct Harness {
    _directory: tempfile::TempDir,
    simulation: Simulation,
}

impl Harness {
    fn new(variant: Variant) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("instance.json");
        let target = |customer: &str| {
            json!({
                "kind":"google_directory","customer_id":customer,
                "email_domain":"exampleco.example","org_unit_prefix":"/Engineering",
                "groups":{"engineering":GROUP}
            })
        };
        let slot = |resource: &str| {
            json!({"kind":"google_directory",
            "allowed_resources":[{"id":resource,"revision":1}],"actions":ACTIONS,
            "limits":{"max_request_bytes":16384,"max_response_bytes":65536,"max_calls_per_invocation":16},
            "budgets":[{"id":"calls","revision":1}]})
        };
        let instance = json!({
            "installation":"coverageco","environment":"test",
            "resources":{"version":1,
                "connections":{"google":{"revision":1,"provider":"synthetic_google_directory"}},
                "resources":{
                    "main":{"revision":1,"connection":{"id":"google","revision":1},"target":target(CUSTOMER)},
                    "other":{"revision":1,"connection":{"id":"google","revision":1},"target":target(FOREIGN_CUSTOMER)}
                },
                "policies":{"directory":{"revision":1,"owner":"it","actors":[ACTOR],"allowed_apps":["app"],
                    "max_duration_seconds":null,"slots":{"directory":slot("main"),"foreign":slot("other")}}},
                "budgets":{"calls":{"revision":1,"scope":"app","period_seconds":3600,
                    "limits":{"calls":100,"bytes":1000000,"concurrency":1}}}
            },
            "apps":{"app":{"artifact":directory.path().join("contract"),"readers":[],"writers":[ACTOR],
                "authority":{"version":1,"admins":[],"operations":{"directory":{"actors":[ACTOR],
                    "mode":{"kind":"current_state"},"models":{},
                    "observations":ACTIONS.iter().filter(|a|!a.is_write()).map(|a|a.capability()).collect::<Vec<_>>(),
                    "effects":ACTIONS.iter().filter(|a|a.is_write()).map(|a|a.capability()).collect::<Vec<_>>()}}},
                "resource_policies":[{"policy":{"id":"directory","revision":1},"operation":"directory",
                    "bindings":{"directory":{"id":"main","revision":1},"foreign":{"id":"other","revision":1}}}]
            }}
        });
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let admitted = Instance::load(&path)?;
        let artifact_path = directory.path().join("contract");
        fs::create_dir(&artifact_path)?;
        let artifact = LoadedArtifact::from_contract_for_tests(
            crate::digest(b"synthetic-directory-coverage-contract"),
            artifact_path,
            serde_json::from_value(json!({
                "format":crate::artifact::CURRENT_FORMAT,
                "verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
                "roc_version":"provider-boundary-fixture","worker_digest":"not-executed",
                "schema_digest":crate::digest(b"directory-coverage-schema"),"namespace":"app",
                "schema":{"models":{"items":{"fields":{"value":"text"}}},
                    "inputs":{"empty":{"fields":{}}},"foreign_keys":[]},
                "operations":[{"name":"directory","kind":"command","input_type":"empty","output_type":""}],
                "sources":{},"admission":"local-spike-only"
            }))?,
        );
        crate::authority_state::AuthorityDocument::resolve_at(&admitted, "app", &artifact, 100000)?;
        let simulation = Simulation::new(
            Runtime::from_artifact_for_tests(
                path,
                "app".into(),
                directory.path().join("app.sqlite"),
                artifact,
            )?,
            [13; 32],
            100000,
        )?;
        let runtime = simulation.runtime();
        runtime.initialize()?;
        // All transport worlds and the two other synthetic providers stay fixed.
        super::super::simulated::seed(runtime.db(), runtime.scope(), &fixture(Variant::A))?;
        people_providers::seed_synthetic(runtime, &synthetic(variant))?;
        let mut foreign = synthetic(Variant::A);
        foreign.customer_id = FOREIGN_CUSTOMER.into();
        foreign.organization_id = "other-linear".into();
        foreign.destination = "other-alerts".into();
        people_providers::seed_synthetic(runtime, &foreign)?;
        Ok(Self {
            _directory: directory,
            simulation,
        })
    }

    fn runtime(&self) -> &Runtime {
        self.simulation.runtime()
    }

    fn world(&self) -> Result<ProviderState<GoogleWorld>> {
        people_providers::inspect_google(self.runtime(), CUSTOMER)
    }

    fn authorize(
        &self,
        action: Action,
        mut data: Value,
        binding: &str,
        actor: &str,
    ) -> Result<capabilities::Authorized> {
        let runtime = self.runtime();
        runtime.accept("directory", ACTOR, INVOCATION, &json!({}), 100)?;
        let mut db = crate::store::open(runtime.db())?;
        let tx = crate::write_queue::immediate(&mut db)?;
        let active = crate::authority_state::require_invocation_in(
            &tx,
            runtime,
            INVOCATION,
            "directory",
            ACTOR,
        )?;
        let mut context = crate::store::invocation_context(&tx, INVOCATION)?;
        context.actor = actor.into();
        let request = Request {
            operation: "directory".into(),
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
                ..Instruction::default()
            },
        )?
        .context("resource binding missing")?;
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
                ..Instruction::default()
            },
            active.policy()?,
            action.capability(),
        )?;
        tx.commit()?;
        Ok(authorized)
    }

    fn dispatch(&self, action: Action, data: Value) -> Result<Observed> {
        let authorized = self.authorize(action, data, "directory", ACTOR)?;
        // Positive linkage assertion outside authorization; negative controls
        // must fail in production admission rather than in this harness assertion.
        ensure!(
            authorized.resource().grant.provider == Provider::SyntheticGoogleDirectory
                && authorized.resource().grant.connection.id == "google"
                && authorized.resource().grant.resource.id == "main",
            "wrong admitted directory resource"
        );
        let before = worlds_in_scope(self.runtime().db(), self.runtime().scope())?;
        let resource = authorized.resource().clone();
        let outcome = if action.is_write() {
            capabilities::execute(
                self.runtime(),
                authorized,
                action.capability(),
                "directory-attempt",
            )
        } else {
            capabilities::observe(self.runtime(), authorized, "directory-attempt")
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

    fn snapshot(&self) -> Result<String> {
        let result: Value = serde_json::from_str(
            &self
                .dispatch(Action::GoogleDirectorySnapshot, json!({}))?
                .result,
        )?;
        result["id"]
            .as_str()
            .map(str::to_owned)
            .context("snapshot id missing")
    }

    fn run(&self, action: Action) -> Result<Observed> {
        let data = match action {
            Action::GoogleDirectorySnapshot => json!({}),
            Action::GoogleDirectoryRecord => json!({"snapshot_id":self.snapshot()?,"cursor":0}),
            Action::GoogleDirectoryCreateUser => {
                json!({"input":{"given_name":"New","family_name":"Person",
                "primary_email":"new@exampleco.example","personal_email":"new@personal.example",
                "org_unit_path":"/Engineering","start_date":"2026-11-01"}})
            }
            Action::GoogleDirectoryPatchAttributes => json!({"input":{"primary_email":EMAIL,
                "attributes":[{"key":"team","value":"Platform"}]}}),
            Action::GoogleDirectoryEnsureGroupMember => {
                json!({"input":{"primary_email":EMAIL,"group":"engineering"}})
            }
            _ => anyhow::bail!("not a Google Directory action"),
        };
        self.dispatch(action, data)
    }
}

pub(super) fn observe(action: Action, variant: Variant) -> Result<Observed> {
    ensure!(ACTIONS.contains(&action), "not a Google Directory action");
    Harness::new(variant)?.run(action)
}

#[test]
fn all_directory_actions_use_admitted_resources_and_the_common_gate() -> Result<()> {
    for action in ACTIONS {
        check(action, |variant| observe(action, variant)).map_err(anyhow::Error::msg)?;
        for variant in [Variant::A, Variant::B] {
            let harness = Harness::new(variant)?;
            let before = harness.world()?.world;
            let foreign_before =
                people_providers::inspect_google(harness.runtime(), FOREIGN_CUSTOMER)?;
            let observed = harness.run(action)?;
            let result: Value = serde_json::from_str(&observed.result)?;
            let after = harness.world()?.world;
            assert_eq!(
                people_providers::inspect_google(harness.runtime(), FOREIGN_CUSTOMER)?,
                foreign_before,
                "no action may change another customer's state or bookkeeping"
            );
            match action {
                Action::GoogleDirectorySnapshot => {
                    assert_eq!(result["customer_id"], CUSTOMER);
                    let id = result["id"].as_str().context("snapshot id")?;
                    assert!(id.starts_with("directory_") && id.len() == 74);
                    let expected = vec![
                        DirectoryRecord::User(before.users[EMAIL].user.clone()),
                        DirectoryRecord::User(before.users["bob@exampleco.example"].user.clone()),
                        DirectoryRecord::Group(before.groups[GROUP].clone()),
                        DirectoryRecord::OrgUnit(before.org_units[1].clone()),
                        DirectoryRecord::OrgUnit(before.org_units[2].clone()),
                    ];
                    assert_eq!(after.captures[id], expected);
                    assert_eq!(after.captures.len(), 1);
                    let mut expected_world = before;
                    expected_world.captures.insert(id.into(), expected);
                    assert_eq!(
                        after, expected_world,
                        "only the immutable scoped capture may change"
                    );
                    assert_eq!(
                        observed.changed(),
                        [Provider::SyntheticGoogleDirectory.world().unwrap()]
                    );
                }
                Action::GoogleDirectoryRecord => {
                    assert_eq!(result["kind"], "user");
                    let user: Value = serde_json::from_str(result["data"].as_str().unwrap())?;
                    assert_eq!(user, serde_json::to_value(&before.users[EMAIL].user)?);
                    assert!(
                        observed.changed().is_empty(),
                        "record reads do not mutate the provider"
                    );
                }
                Action::GoogleDirectoryCreateUser => {
                    assert_eq!(result["Created"]["primary_email"], "new@exampleco.example");
                    let mut expected = before;
                    let created = after.users["new@exampleco.example"].clone();
                    assert_eq!(created.user.given_name, "New");
                    assert_eq!(created.user.org_unit_path, "/Engineering");
                    assert_eq!(created.personal_email, "new@personal.example");
                    assert_eq!(created.start_date, "2026-11-01");
                    assert!(created.attributes.is_empty());
                    assert_eq!(result["Created"]["id"], created.user.id);
                    assert!(created.user.id.starts_with("google_") && created.user.id.len() > 7);
                    assert_eq!(created.user.primary_email, "new@exampleco.example");
                    assert_eq!(created.user.family_name, "Person");
                    assert_eq!(created.user.full_name, "New Person");
                    assert!(!created.user.suspended);
                    assert_eq!(
                        created.user.thumbnail_photo_url,
                        people_providers::OptionalText::None
                    );
                    expected
                        .users
                        .insert("new@exampleco.example".into(), created);
                    assert_eq!(after, expected);
                }
                Action::GoogleDirectoryPatchAttributes => {
                    assert_eq!(result, json!("Patched"));
                    let mut expected = before;
                    expected
                        .users
                        .get_mut(EMAIL)
                        .unwrap()
                        .attributes
                        .insert("team".into(), "Platform".into());
                    assert_eq!(after, expected);
                }
                Action::GoogleDirectoryEnsureGroupMember => {
                    assert_eq!(result, json!("Added"));
                    let mut expected = before;
                    expected
                        .memberships
                        .entry(GROUP.into())
                        .or_default()
                        .insert(EMAIL.into());
                    assert_eq!(after, expected);
                }
                _ => unreachable!(),
            }
            if action.is_write() {
                assert_eq!(
                    observed.changed(),
                    [Provider::SyntheticGoogleDirectory.world().unwrap()]
                );
            }
        }
    }
    Ok(())
}

#[test]
fn directory_gate_rejects_constant_and_wrong_world_implementations() -> Result<()> {
    for action in ACTIONS {
        check(action, |variant| observe(action, variant)).map_err(anyhow::Error::msg)?;
        assert!(
            check(action, |variant| {
                let mut actual = observe(action, variant)?;
                actual.result = "constant".into();
                actual.after = actual.before.clone();
                Ok(actual)
            })
            .is_err()
        );
        assert!(
            check(action, |variant| {
                let mut actual = observe(action, variant)?;
                let own = Provider::SyntheticGoogleDirectory.world().unwrap();
                let foreign = Provider::Slack.world().unwrap();
                if action.is_write() {
                    actual.after.insert(own, actual.before[own].clone());
                    actual.after.insert(foreign, Some("foreign change".into()));
                } else {
                    actual.result = actual.before[foreign]
                        .clone()
                        .context("fixed foreign world")?;
                }
                Ok(actual)
            })
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn directory_admission_refuses_foreign_actor_handles_and_out_of_scope_inputs() -> Result<()> {
    for action in ACTIONS {
        let harness = Harness::new(Variant::A)?;
        harness.run(action)?; // Establish a positive fixture before every sabotage.
        let before = worlds_in_scope(harness.runtime().db(), harness.runtime().scope())?;
        let data = if action == Action::GoogleDirectoryRecord {
            json!({"snapshot_id":harness.snapshot()?,"cursor":0})
        } else if action.is_write() {
            match action {
                Action::GoogleDirectoryCreateUser => {
                    json!({"input":{"given_name":"New","family_name":"Person",
                    "primary_email":"else@exampleco.example","personal_email":"new@personal.example",
                    "org_unit_path":"/Engineering","start_date":"2026-11-01"}})
                }
                Action::GoogleDirectoryPatchAttributes => {
                    json!({"input":{"primary_email":EMAIL,"attributes":[]}})
                }
                _ => json!({"input":{"primary_email":EMAIL,"group":"engineering"}}),
            }
        } else {
            json!({})
        };
        assert!(
            harness
                .authorize(action, data.clone(), "directory", "mallory")
                .is_err()
        );
        let mut forged = data;
        forged["handle"] = json!(format!("resource_{}", "0".repeat(64)));
        assert!(
            harness
                .authorize(action, forged, "directory", ACTOR)
                .is_err()
        );
        assert_eq!(
            worlds_in_scope(harness.runtime().db(), harness.runtime().scope())?,
            before
        );
    }
    for (action, data) in [
        (
            Action::GoogleDirectoryCreateUser,
            json!({"input":{"given_name":"New","family_name":"Person",
            "primary_email":"new@foreign.example","personal_email":"new@personal.example",
            "org_unit_path":"/Engineering","start_date":"2026-11-01"}}),
        ),
        (
            Action::GoogleDirectoryCreateUser,
            json!({"input":{"given_name":"New","family_name":"Person",
            "primary_email":"new@exampleco.example","personal_email":"new@personal.example",
            "org_unit_path":"/EngineeringOther","start_date":"2026-11-01"}}),
        ),
        (
            Action::GoogleDirectoryPatchAttributes,
            json!({"input":{"primary_email":"user@foreign.example","attributes":[]}}),
        ),
        (
            Action::GoogleDirectoryEnsureGroupMember,
            json!({"input":{"primary_email":EMAIL,"group":"growth"}}),
        ),
    ] {
        let harness = Harness::new(Variant::A)?;
        let before = harness.world()?;
        assert!(harness.authorize(action, data, "directory", ACTOR).is_err());
        assert_eq!(harness.world()?, before);
    }
    Ok(())
}

#[test]
fn directory_records_keep_the_actual_customer_capture_and_complete_cursor() -> Result<()> {
    let harness = Harness::new(Variant::A)?;
    let id = harness.snapshot()?;
    for cursor in 0..=5 {
        let observed = harness.dispatch(
            Action::GoogleDirectoryRecord,
            json!({"snapshot_id":id,"cursor":cursor}),
        )?;
        let value: Value = serde_json::from_str(&observed.result)?;
        assert_eq!(
            value["kind"],
            ["user", "user", "group", "org_unit", "org_unit", "done"][cursor]
        );
    }
    let foreign_snapshot =
        harness.authorize(Action::GoogleDirectorySnapshot, json!({}), "foreign", ACTOR)?;
    let resource = foreign_snapshot.resource().clone();
    let foreign_result =
        capabilities::observe(harness.runtime(), foreign_snapshot, "foreign-snapshot").result?;
    crate::resources::validate_result(&resource, &foreign_result)?;
    let foreign_result: Value = serde_json::from_str(&foreign_result)?;
    assert_eq!(foreign_result["customer_id"], FOREIGN_CUSTOMER);
    assert_ne!(foreign_result["id"], id);
    let foreign = harness.authorize(
        Action::GoogleDirectoryRecord,
        json!({"snapshot_id":id,"cursor":0}),
        "foreign",
        ACTOR,
    )?;
    assert_eq!(foreign.resource().grant.resource.id, "other");
    assert!(
        capabilities::observe(harness.runtime(), foreign, "foreign-attempt")
            .result
            .is_err()
    );
    for data in [
        json!({"snapshot_id":id,"cursor":6}),
        json!({"snapshot_id":"directory_bad","cursor":0}),
    ] {
        assert!(
            harness
                .dispatch(Action::GoogleDirectoryRecord, data)
                .is_err()
        );
    }
    let authorized = harness.authorize(
        Action::GoogleDirectorySnapshot,
        json!({}),
        "directory",
        ACTOR,
    )?;
    assert!(
        crate::resources::validate_result(
            authorized.resource(),
            &json!({"id":id,"customer_id":FOREIGN_CUSTOMER}).to_string()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn directory_effect_retries_preserve_the_world_and_result() -> Result<()> {
    for action in ACTIONS.into_iter().filter(|a| a.is_write()) {
        let harness = Harness::new(Variant::A)?;
        let first = harness.run(action)?;
        let retry = harness.run(action)?;
        assert_eq!(retry.result, first.result);
        assert_eq!(retry.before, retry.after);
        let state = harness.world()?;
        assert_eq!(state.ledger.len(), 1);
        assert_eq!(state.calls.len(), 2);
        assert!(state.calls[0].changed && state.calls[1].replayed && !state.calls[1].changed);
    }
    Ok(())
}

#[test]
fn directory_attribution_cannot_read_another_scope_or_return_to_pending() -> Result<()> {
    let harness = Harness::new(Variant::A)?;
    let runtime = harness.runtime();
    let before = worlds_in_scope(runtime.db(), runtime.scope())?;
    let path = runtime
        .db()
        .with_file_name(Provider::SyntheticGoogleDirectory.world().unwrap());
    let db = crate::store::open(&path)?;
    let mut foreign = harness.world()?;
    foreign.world.users.get_mut(EMAIL).unwrap().user.full_name = "Foreign scope".into();
    db.execute(
        "INSERT INTO people_provider VALUES(?1,?2,?3)",
        rusqlite::params!["foreign/app", CUSTOMER, serde_json::to_string(&foreign)?],
    )?;
    assert_eq!(worlds_in_scope(runtime.db(), runtime.scope())?, before);
    let mut coverage = super::current_coverage();
    for action in ACTIONS {
        coverage.insert(action, super::Demonstration::PendingAdapterSeam);
    }
    super::validate_provider_coverage(&coverage)?;
    assert!(super::validate_pending_debt(&coverage, super::REVIEWED_PENDING_DEBT).is_err());
    Ok(())
}
