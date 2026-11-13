//! Delegation's offline provider boundary, admitted by the real instance,
//! imported-contract and activated resource-policy paths. Contract fixtures do
//! not qualify a compiled Roc worker or a separately served native callee.
use super::{Observed, Variant, check, fixture, worlds_in_scope};
use crate::{
    artifact::{Instance, LoadedArtifact},
    capabilities,
    instance_catalog::{CandidateCatalog, ImportedContracts, ResolvedImports, SelectedApp},
    operation_contract::{Codec, Kind, Manifest, OperationSpec, TypeObject},
    protocol::{Instruction, Request},
    simulation::Simulation,
    store::Runtime,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::resources::{Action, Provider};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

const ACTOR: &str = "alice";
const RECEIPT: &str = "rcp_recorded";
const INVOCATION: &str = "provider-coverage";
const STEP: &str = "ob_provider_coverage_0";

const ACTIONS: [Action; 3] = [
    Action::DelegateQuery,
    Action::DelegateSend,
    Action::DelegateStatus,
];

fn operation(action: Action) -> &'static str {
    match action {
        Action::DelegateQuery => "query_peer",
        Action::DelegateSend => "send_peer",
        Action::DelegateStatus => "peer_status",
        _ => panic!("not a delegation action"),
    }
}

fn target(action: Action) -> &'static str {
    if action == Action::DelegateQuery {
        "callee.list"
    } else {
        "callee.make"
    }
}

fn input(action: Action) -> String {
    if action == Action::DelegateStatus {
        json!({"id": RECEIPT}).to_string()
    } else {
        "{}".into()
    }
}

struct Harness {
    _directory: tempfile::TempDir,
    caller: Simulation,
    _callee: Simulation,
    imports: ImportedContracts,
}

impl Harness {
    fn new(variant: Variant) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let instance_path = directory.path().join("instance.json");
        let schema_digest = crate::digest(b"delegation-coverage-schema");
        let types = BTreeMap::from([
            (
                "callee.input.v1".into(),
                TypeObject {
                    id: "callee.input.v1".into(),
                    codec: Codec::RocJsonV1,
                    schema: json!({"fields": {}}),
                    dependencies: BTreeSet::new(),
                },
            ),
            (
                "callee.output.v1".into(),
                TypeObject {
                    id: "callee.output.v1".into(),
                    codec: Codec::RocJsonV1,
                    schema: json!({"shape":{"record":{"value":"string"}},"roc_type":"{ value : Str }"}),
                    dependencies: BTreeSet::new(),
                },
            ),
            (
                "callee.error.v1".into(),
                TypeObject {
                    id: "callee.error.v1".into(),
                    codec: Codec::RocJsonV1,
                    schema: json!([]),
                    dependencies: BTreeSet::new(),
                },
            ),
        ]);
        let exports = Manifest::derive(
            "callee".into(),
            [("callee.list", Kind::Query), ("callee.make", Kind::Command)].map(|(id, kind)| {
                OperationSpec {
                    id: id.into(),
                    version: 1,
                    kind,
                    input: "callee.input.v1".into(),
                    output: "callee.output.v1".into(),
                    error: "callee.error.v1".into(),
                    semantics: json!({}),
                }
            }),
            &types,
        )?;
        let imports = ImportedContracts::from_resolved(ResolvedImports {
            operations: exports.exports.clone(),
            types: exports
                .exports
                .values()
                .flat_map(|p| p.types.clone())
                .collect(),
        })?;
        let mut policies = serde_json::Map::new();
        let mut resources = serde_json::Map::new();
        let mut bindings = Vec::new();
        for action in ACTIONS {
            let name = operation(action);
            let resource = if action == Action::DelegateQuery {
                "peer_query"
            } else {
                "peer_command"
            };
            policies.insert(name.into(), json!({"actors":[ACTOR],"mode":{"kind":"current_state"},
                "models":{},"observations":if action == Action::DelegateSend {Vec::<&str>::new()} else {vec![action.capability()]},
                "effects":if action == Action::DelegateSend {vec![action.capability()]} else {Vec::<&str>::new()}}));
            resources.insert(resource.into(), json!({"revision":1,
                "connection":{"id":"delegation","revision":1},
                "target":{"kind":"app_operation","app":"callee","operation":target(action),"schema_digest":schema_digest}}));
            bindings.push(json!({"policy":{"id":"peer","revision":1},"operation":name,
                "bindings":{"peer":{"id":resource,"revision":1}}}));
        }
        let instance = json!({"installation":"coverageco","environment":"test",
            "resources":{"version":1,
                "connections":{"delegation":{"revision":1,"provider":"local_delegation"}},
                "resources":resources,
                "policies":{"peer":{"revision":1,"owner":"it","actors":[ACTOR],"allowed_apps":["caller"],
                    "max_duration_seconds":null,"slots":{"peer":{"kind":"app_operation",
                        "allowed_resources":[{"id":"peer_query","revision":1},{"id":"peer_command","revision":1}],
                        "actions":["delegate_query","delegate_send","delegate_status"],
                        "limits":{"max_request_bytes":16384,"max_response_bytes":65536,"max_calls_per_invocation":4},
                        "budgets":[{"id":"calls","revision":1}]}}}},
                "budgets":{"calls":{"revision":1,"scope":"app","period_seconds":3600,
                    "limits":{"calls":100,"bytes":1000000,"concurrency":1}}}},
            "apps":{
                "caller":{"artifact":directory.path().join("caller-contract"),"readers":[],"writers":[ACTOR],
                    "authority":{"version":1,"admins":[],"operations":policies},"resource_policies":bindings},
                "callee":{"artifact":directory.path().join("callee-contract"),"readers":[ACTOR],"writers":[ACTOR],
                    "authority":{"version":1,"admins":[],"operations":{
                        "callee.list":{"actors":[ACTOR],"mode":{"kind":"read"},"models":{},"observations":[],"effects":[]},
                        "callee.make":{"actors":[ACTOR],"mode":{"kind":"current_state"},"models":{},"observations":[],"effects":[]}}}}}});
        fs::write(&instance_path, serde_json::to_vec(&instance)?)?;
        let admitted = Instance::load(&instance_path)?;
        let artifact = |app: &str| -> Result<LoadedArtifact> {
            let operations = if app == "caller" {
                ACTIONS.iter().map(|action| json!({"name":operation(*action),"kind":"command","input_type":"empty","output_type":""})).collect::<Vec<_>>()
            } else {
                vec![
                    json!({"name":"callee.list","kind":"query","input_type":"empty","output_type":""}),
                    json!({"name":"callee.make","kind":"command","input_type":"empty","output_type":""}),
                ]
            };
            let contract = serde_json::from_value(json!({
                "format":crate::artifact::CURRENT_FORMAT,"verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
                "roc_version":"provider-boundary-fixture","worker_digest":"not-executed",
                "schema_digest":schema_digest,"namespace":app,
                "schema":{"models":{"items":{"fields":{"value":"text"}}},"inputs":{"empty":{"fields":{}}},"foreign_keys":[]},
                "operations":operations,"sources":{},"admission":"local-spike-only",
                "imports":if app == "caller" {Some(imports.clone())} else {None},
            }))?;
            let path = directory.path().join(format!("{app}-contract"));
            fs::create_dir(&path)?;
            Ok(LoadedArtifact::from_contract_for_tests(
                crate::digest(app.as_bytes()),
                path,
                contract,
            ))
        };
        let caller_artifact = artifact("caller")?;
        let callee_artifact = artifact("callee")?;
        let catalog = CandidateCatalog::derive(
            "coverageco".into(),
            "test".into(),
            BTreeMap::from([
                (
                    "caller".into(),
                    SelectedApp {
                        artifact: caller_artifact.id().into(),
                        manifest: Manifest::derive("caller".into(), [], &BTreeMap::new())?,
                    },
                ),
                (
                    "callee".into(),
                    SelectedApp {
                        artifact: callee_artifact.id().into(),
                        manifest: exports,
                    },
                ),
            ]),
        )?;
        catalog.check_embedded_consumers(&BTreeMap::from([("caller".into(), imports.clone())]))?;
        for (app, artifact) in [("caller", &caller_artifact), ("callee", &callee_artifact)] {
            crate::authority_state::AuthorityDocument::resolve_at(
                &admitted, app, artifact, 100000,
            )?;
        }
        let caller = Simulation::new(
            Runtime::from_artifact_for_tests(
                instance_path.clone(),
                "caller".into(),
                directory.path().join("caller.sqlite"),
                caller_artifact,
            )?,
            [7; 32],
            100000,
        )?;
        let callee = Simulation::new(
            Runtime::from_artifact_for_tests(
                instance_path,
                "callee".into(),
                directory.path().join("callee.sqlite"),
                callee_artifact,
            )?,
            [9; 32],
            100000,
        )?;
        caller.runtime().initialize()?;
        callee.runtime().initialize()?;
        // Every OTHER provider is held constant while delegation varies. A
        // result from another provider therefore cannot pass the twin-world gate.
        let mut world = fixture(Variant::A);
        let value = match variant {
            Variant::A => "alpha",
            Variant::B => "beta",
        };
        world.delegation.reads.insert(
            super::super::simulated::DelegationWorld::key("callee", "callee.list", "{}"),
            json!({"value":value}).to_string(),
        );
        world.delegation.reads.insert(
            super::super::simulated::DelegationWorld::key("decoy", "decoy.list", "{}"),
            json!({"value":"wrong-callee"}).to_string(),
        );
        if matches!(variant, Variant::A) {
            world
                .delegation
                .accepted
                .insert(RECEIPT.into(), "recorded-fingerprint".into());
        }
        super::super::simulated::seed(caller.runtime().db(), caller.runtime().scope(), &world)?;
        Ok(Self {
            _directory: directory,
            caller,
            _callee: callee,
            imports,
        })
    }

    fn data(&self, action: Action) -> Value {
        let operation = target(action);
        json!({"contract":{"operation":operation,"digest":self.imports.operations[operation].digest},"input":input(action)})
    }

    fn authorize(&self, action: Action, data: Value) -> Result<capabilities::Authorized> {
        self.caller
            .runtime()
            .accept(operation(action), ACTOR, INVOCATION, &json!({}), 100)?;
        self.authorize_accepted(action, data)
    }

    fn authorize_accepted(&self, action: Action, data: Value) -> Result<capabilities::Authorized> {
        let runtime = self.caller.runtime();
        let mut db = crate::store::open(runtime.db())?;
        let tx = crate::write_queue::immediate(&mut db)?;
        let active = crate::authority_state::require_invocation_in(
            &tx,
            runtime,
            INVOCATION,
            operation(action),
            ACTOR,
        )?;
        let request = Request {
            operation: operation(action).into(),
            input: "{}".into(),
            context: crate::store::invocation_context(&tx, INVOCATION)?,
            observations: Vec::new(),
        };
        let authorized = capabilities::authorized(
            &tx,
            runtime,
            &request,
            &Instruction {
                kind: if action == Action::DelegateSend {
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
            STEP,
        )?;
        tx.commit()?;
        Ok(authorized)
    }

    fn run(&self, action: Action) -> Result<Observed> {
        let runtime = self.caller.runtime();
        let authorized = self.authorize(action, self.data(action))?;
        let call = authorized
            .delegated_call()
            .context("delegation action was not admitted")?;
        ensure!(
            call.actor == ACTOR
                && call.caller == "caller"
                && call.app == "callee"
                && call.operation == target(action)
                && call.input == input(action)
                && call.contract_digest.as_ref()
                    == Some(&self.imports.operations[target(action)].digest),
            "admitted delegation identity or target changed"
        );
        let before = worlds_in_scope(runtime.db(), runtime.scope())?;
        let outcome = if action == Action::DelegateSend {
            capabilities::execute(runtime, authorized, STEP, "coverage-attempt")
        } else {
            capabilities::observe(runtime, authorized, "coverage-attempt")
        };
        let result = outcome.result?;
        let after = worlds_in_scope(runtime.db(), runtime.scope())?;
        Ok(Observed {
            result,
            before,
            after,
        })
    }
}

pub(super) fn observe(action: Action, variant: Variant) -> Result<Observed> {
    ensure!(ACTIONS.contains(&action), "not a delegation action");
    Harness::new(variant)?.run(action)
}

#[test]
fn every_delegation_action_runs_through_admitted_resources_and_the_common_gate() -> Result<()> {
    for action in ACTIONS {
        check(action, |variant| observe(action, variant)).map_err(anyhow::Error::msg)?;
        for variant in [Variant::A, Variant::B] {
            let observed = observe(action, variant)?;
            let result: Value = serde_json::from_str(&observed.result)?;
            match action {
                Action::DelegateQuery => {
                    assert_eq!(
                        result,
                        json!({"value":if matches!(variant, Variant::A) { "alpha" } else { "beta" }})
                    );
                    assert!(observed.changed().is_empty());
                }
                Action::DelegateStatus => {
                    assert_eq!(
                        result,
                        json!({"id":RECEIPT,"status":if matches!(variant, Variant::A) { "pending" } else { "unknown" },"output":""})
                    );
                    assert!(observed.changed().is_empty());
                }
                Action::DelegateSend => {
                    assert_eq!(result["status"], "accepted");
                    assert!(result["id"].as_str().unwrap().starts_with("rcp_"));
                    assert_eq!(
                        observed.changed(),
                        [Provider::LocalDelegation.world().unwrap()]
                    );
                }
                _ => unreachable!(),
            }
        }
    }
    Ok(())
}

#[test]
fn delegation_gate_rejects_constant_and_wrong_world_observations() -> Result<()> {
    for action in ACTIONS {
        // A refusal from fixture setup is not evidence that a saboteur was
        // caught. Establish the unmodified action first in this same test.
        check(action, |variant| observe(action, variant)).map_err(anyhow::Error::msg)?;
        let constant = |variant| {
            let mut actual = observe(action, variant)?;
            actual.result = "constant".into();
            actual.after = actual.before.clone();
            Ok(actual)
        };
        assert!(
            check(action, constant).is_err(),
            "{action:?} constant adapter passed"
        );
        let wrong_world = |variant| {
            let mut actual = observe(action, variant)?;
            let own = Provider::LocalDelegation.world().unwrap();
            let foreign = Provider::Slack.world().unwrap();
            if action == Action::DelegateSend {
                actual.after.insert(own, actual.before[own].clone());
                actual
                    .after
                    .insert(foreign, Some("foreign provider changed".into()));
            } else {
                // This provider's world is deliberately fixed between variants.
                actual.result = actual.before[foreign]
                    .clone()
                    .context("foreign world absent")?;
            }
            Ok(actual)
        };
        assert!(
            check(action, wrong_world).is_err(),
            "{action:?} wrong provider passed"
        );
    }
    Ok(())
}

#[test]
fn delegation_refuses_forged_actor_target_and_contract_before_dispatch() -> Result<()> {
    for action in ACTIONS {
        for mutation in ["actor", "target", "digest"] {
            let harness = Harness::new(Variant::A)?;
            let runtime = harness.caller.runtime();
            let before = worlds_in_scope(runtime.db(), runtime.scope())?;
            let mut data = harness.data(action);
            match mutation {
                "actor" => data["actor"] = json!("mallory"),
                "target" => data["contract"]["operation"] = json!("decoy.list"),
                "digest" => data["contract"]["digest"] = json!(crate::digest(b"wrong contract")),
                _ => unreachable!(),
            }
            assert!(
                harness.authorize(action, data).is_err(),
                "{action:?} accepted forged {mutation}"
            );
            assert_eq!(worlds_in_scope(runtime.db(), runtime.scope())?, before);
        }
    }
    Ok(())
}

#[test]
fn delegated_send_deduplicates_the_same_admitted_attempt_without_another_effect() -> Result<()> {
    let harness = Harness::new(Variant::A)?;
    let first = harness.run(Action::DelegateSend)?;
    let retry = harness.run(Action::DelegateSend)?;
    assert_eq!(first.result, retry.result);
    assert_eq!(retry.before, retry.after);
    Ok(())
}

#[test]
fn delegation_cannot_return_to_pending_without_reviewed_debt() -> Result<()> {
    let mut coverage = super::current_coverage();
    for action in ACTIONS {
        coverage.insert(action, super::Demonstration::PendingAdapterSeam);
    }
    super::validate_provider_coverage(&coverage)?;
    let error = super::validate_pending_debt(&coverage, super::REVIEWED_PENDING_DEBT).unwrap_err();
    assert!(error.to_string().contains("unreviewed pending coverage"));
    Ok(())
}

/// `observation IS NULL` on an external effect means "not settled", not
/// "outcome unknown and still sendable". A send proof is issued only for the
/// exact unsettled effect of a pending, unblocked origin; a completed origin is
/// refused before its effect row is read, even if that row never settled.
#[test]
fn delegated_send_proof_requires_a_pending_origin_and_its_unsettled_effect() -> Result<()> {
    let harness = Harness::new(Variant::A)?;
    let runtime = harness.caller.runtime();
    let admission = crate::delegation_commands::Admission::query_for_test(
        "human-root",
        ACTOR,
        &crate::digest(b"human-subject"),
        63,
    );
    runtime.accept_delegated(
        operation(Action::DelegateSend),
        INVOCATION,
        &json!({}),
        100,
        crate::store::Cause::delegated(ACTOR, "entry", "app:entry").remote(&admission),
    )?;
    let data = harness.data(Action::DelegateSend);
    let call = harness
        .authorize_accepted(Action::DelegateSend, data.clone())?
        .delegated_call()
        .context("send was not admitted")?
        .clone();
    let intent = serde_json::to_string(&Instruction {
        kind: "external".into(),
        model: Action::DelegateSend.capability().into(),
        data: data.to_string(),
        ..Instruction::default()
    })?;
    let db = crate::store::open(runtime.db())?;
    db.execute(
        "INSERT INTO day2_external_effects VALUES(?1,0,?2,?3,NULL)",
        rusqlite::params![INVOCATION, STEP, intent],
    )?;
    let refusal = |call: &crate::delegation::Call| {
        crate::delegation::verify_origin(runtime, call)
            .err()
            .map(|error| format!("{error:#}"))
    };

    // Pending and unsettled: the retryable send keeps its proof.
    let origin = crate::delegation::verify_origin(runtime, &call)?;
    assert_eq!(origin.root, "human-root");
    assert_eq!(origin.principal, ACTOR);
    let mut unrelated = call.clone();
    unrelated.step = "fx_not_journaled".into();
    assert!(
        refusal(&unrelated).is_some(),
        "a step without an effect row was admitted"
    );

    // Settled: no second proof for the same effect.
    db.execute(
        "UPDATE day2_external_effects SET observation='{}' WHERE identity=?1",
        [STEP],
    )?;
    assert!(
        refusal(&call).is_some(),
        "a settled effect issued another send proof"
    );
    db.execute(
        "UPDATE day2_external_effects SET observation=NULL WHERE identity=?1",
        [STEP],
    )?;
    crate::delegation::verify_origin(runtime, &call)?;

    // Completed while the effect row never settled: refused on the origin's
    // status, and the stored receipt still replays through completed_outcome.
    let outcome = crate::protocol::Outcome {
        status: "success".into(),
        result: json!({"sent":true}),
        error: String::new(),
    };
    let (policy, stamp, context) = {
        let active = crate::authority_state::current(&db)?;
        (
            active.policy()?.clone(),
            crate::authority_state::invocation_stamp(&db, INVOCATION)?,
            crate::store::invocation_context(&db, INVOCATION)?,
        )
    };
    let trace = crate::protocol::Trace {
        format: 2,
        artifact: runtime.artifact().id().into(),
        scope: runtime.scope().into(),
        request: Request {
            operation: operation(Action::DelegateSend).into(),
            input: "{}".into(),
            context,
            observations: Vec::new(),
        },
        outcome: outcome.clone(),
        guard: Some(crate::protocol::ExecutionGuard {
            policy,
            authority: Some(stamp),
            precondition_row: None,
            error: String::new(),
        }),
    };
    assert_eq!(
        db.execute(
            "UPDATE day2_invocations SET status='success',outcome=?1,trace=?2
             WHERE id=?3 AND status='pending'",
            rusqlite::params![
                serde_json::to_string(&outcome)?,
                serde_json::to_string(&trace)?,
                INVOCATION
            ],
        )?,
        1
    );
    let unsettled: i64 = db.query_row(
        "SELECT count(*) FROM day2_external_effects WHERE invocation=?1 AND observation IS NULL",
        [INVOCATION],
        |row| row.get(0),
    )?;
    assert_eq!(unsettled, 1);
    let refused = refusal(&call).context("a completed origin issued a send proof")?;
    assert!(refused.contains("delegated_origin_changed"), "{refused}");
    assert_eq!(
        runtime.execute(INVOCATION, crate::store::Fault::None)?,
        outcome
    );
    assert_eq!(
        runtime.execute(INVOCATION, crate::store::Fault::None)?,
        outcome
    );
    Ok(())
}
