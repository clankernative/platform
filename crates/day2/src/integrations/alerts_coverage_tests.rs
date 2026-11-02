//! Real synthetic operator-alert capability admission with an independent provider oracle.
//! A contract fixture supplies host metadata; no Roc worker or live service runs.
use super::{Action, Observed, Provider, Variant, worlds_in_scope};
use crate::{
    artifact::LoadedArtifact,
    capabilities, people_providers as people,
    protocol::{Instruction, Request},
    store::{self, Runtime},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{cell::Cell, collections::BTreeMap, fs, path::Path, sync::Arc, time::Duration};

const SCOPE: &str = "alertscoverage/test/app";
const DESTINATION: &str = "alerts-main";
const NOW: i64 = 1_700_000_000;

fn runtime_at(
    directory: &Path,
    installation: &str,
    database: &str,
    entropy: u64,
) -> Result<Runtime> {
    let instance_path = directory.join(format!("{installation}.json"));
    let artifact_directory = directory.join(format!("contract-{installation}"));
    fs::create_dir(&artifact_directory)?;
    let db = directory.join(database);
    let policy = json!({"version":1,"admins":[],"operations":{"run":{
        "actors":["alice","bob"],"mode":{"kind":"current_state"},"models":{},
        "observations":[],"effects":["operator_alerts.send.v1"]}}});
    let target = json!({"kind":"operator_alert_destination","destination":DESTINATION,"topics":{"kind":"only","topics":["incident","recovery"]}});
    let catalog = json!({"version":1,
        "connections":{"alerts":{"revision":1,"provider":"synthetic_operator_alerts"}},
        "resources":{
            "alerts":{"revision":1,"connection":{"id":"alerts","revision":1},"target":target},
            "foreign":{"revision":1,"connection":{"id":"alerts","revision":1},
                "target":{"kind":"operator_alert_destination","destination":"alerts-other","topics":{"kind":"only","topics":["incident"]}}}},
        "policies":{"provision":{"revision":1,"owner":"it","actors":["alice","bob"],"allowed_apps":["app"],
            "max_duration_seconds":null,"slots":{"alerts":{"kind":"operator_alert_destination",
                "allowed_resources":[{"id":"alerts","revision":1}],"actions":["operator_alerts_send"],
                "limits":{"max_request_bytes":16384,"max_response_bytes":16384,"max_calls_per_invocation":8},
                "budgets":[{"id":"alerts","revision":1}]}}}},
        "budgets":{"alerts":{"revision":1,"scope":"app","period_seconds":3600,
            "limits":{"calls":10000,"bytes":100000000,"concurrency":1}}}});
    fs::write(
        &instance_path,
        serde_json::to_vec(&json!({
        "installation":installation,"environment":"test","resources":catalog,
        "control":{"version":1,"state_directory":directory.join(format!("control-{installation}")),
            "operators":["alerts-test-operator"],"sources":{"repo":{"kind":"local_git","repository":directory.join("repo")}},
            "apps":{"app":{"source":"repo"}}},
        "apps":{"app":{"artifact":artifact_directory,"readers":["alice","bob"],"writers":["alice","bob"],
            "authority":policy,"resource_policies":[{"policy":{"id":"provision","revision":1},
                "operation":"run","bindings":{"alerts":{"id":"alerts","revision":1}}}]}}}))?,
    )?;
    let contract = serde_json::from_value(json!({
        "format":crate::artifact::CURRENT_FORMAT,"verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
        "roc_version":"alerts-host-test","worker_digest":"alerts-host-test","schema_digest":"alerts-host-test",
        "schema":{"models":{"items":{"fields":{"value":"text"}}},"inputs":{"input":{"fields":{}}},"foreign_keys":[]},
        "operations":[{"name":"run","kind":"command","input_type":"input","output_type":""}],"sources":{},"admission":"local-spike-only"}))?;
    let inputs = crate::host_inputs::Inputs {
        entropy: Arc::new(crate::host_inputs::simulation::SeededEntropy::new(entropy)),
        clock: Arc::new(crate::host_inputs::simulation::VirtualClock(
            std::sync::Mutex::new((Duration::from_secs(1_700_000_000), Duration::ZERO)),
        )),
        ..Default::default()
    };
    let runtime = Runtime::from_artifact_for_tests(
        instance_path,
        "app".into(),
        db.clone(),
        LoadedArtifact::from_contract_for_tests(
            "alerts-host-test".into(),
            artifact_directory,
            contract,
        ),
    )?
    .with_integrations(crate::integration_host::Host::simulated(
        &db,
        &format!("{installation}/test/app"),
    ))
    .with_inputs(inputs);
    runtime.initialize()?;
    Ok(runtime)
}

fn world(enabled: bool) -> people::AlertWorld {
    people::AlertWorld {
        enabled,
        messages: vec![people::Alert {
            id: "prior-alert".into(),
            topic: "incident".into(),
            body: "Prior synthetic alert".into(),
        }],
    }
}

fn seed_people(
    runtime: &Runtime,
    destination: &str,
    suffix: &str,
    alerts: people::AlertWorld,
) -> Result<()> {
    people::seed_synthetic(
        runtime,
        &people::SyntheticFixture {
            customer_id: format!("google-{suffix}"),
            google: Default::default(),
            organization_id: format!("linear-{suffix}"),
            linear: Default::default(),
            destination: destination.into(),
            alerts,
        },
    )
}

struct Fixture {
    _directory: tempfile::TempDir,
    runtime: Runtime,
    foreign: Runtime,
    attempts: Cell<u64>,
}

impl Fixture {
    fn new(initial: people::AlertWorld, entropy: u64) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let runtime = runtime_at(directory.path(), "alertscoverage", "app.sqlite", entropy)?;
        let foreign = runtime_at(directory.path(), "otheralerts", "foreign.sqlite", entropy)?;
        super::seed(runtime.db(), runtime.scope(), &super::fixture(Variant::A))?;
        super::seed(foreign.db(), foreign.scope(), &super::fixture(Variant::B))?;
        seed_people(&runtime, DESTINATION, "allowed", initial)?;
        seed_people(&runtime, "alerts-other", "foreign-target", world(true))?;
        seed_people(&foreign, DESTINATION, "foreign-scope", world(true))?;
        Ok(Self {
            _directory: directory,
            runtime,
            foreign,
            attempts: Cell::new(0),
        })
    }

    fn state(&self) -> Result<people::ProviderState<people::AlertWorld>> {
        people::inspect_alerts(&self.runtime, DESTINATION)
    }

    // All foreign targets/scopes/providers are protected, including bookkeeping.
    fn protected(&self) -> Result<BTreeMap<String, Value>> {
        let mut snapshot = BTreeMap::new();
        for provider in Provider::ALL {
            let name = provider.world().context("provider world")?;
            let path = self.runtime.db().with_file_name(name);
            if !path.is_file() {
                continue;
            }
            let db = rusqlite::Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            if matches!(
                provider,
                Provider::SyntheticGoogleDirectory
                    | Provider::SyntheticLinear
                    | Provider::SyntheticOperatorAlerts
            ) {
                let mut query = db.prepare(
                    "SELECT scope,target,state FROM people_provider ORDER BY scope,target",
                )?;
                let rows = query
                    .query_map([], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                for (scope, target, state) in rows {
                    if *provider == Provider::SyntheticOperatorAlerts
                        && scope == SCOPE
                        && target == DESTINATION
                    {
                        continue;
                    }
                    snapshot.insert(
                        format!("{name}/{scope}/{target}"),
                        serde_json::from_str(&state)?,
                    );
                }
            } else {
                let mut query =
                    db.prepare("SELECT scope,state FROM simulated_provider ORDER BY scope")?;
                let rows = query
                    .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                for (scope, state) in rows {
                    snapshot.insert(format!("{name}/{scope}"), serde_json::from_str(&state)?);
                }
            }
        }
        Ok(snapshot)
    }

    fn bind(&self, actor: &str, invocation: &str) -> Result<(Request, Value)> {
        bind(&self.runtime, actor, invocation)
    }

    fn assert_budget_state(&self, held: bool) -> Result<()> {
        let mut db = store::open(self.runtime.db())?;
        let tx = db.transaction()?;
        let status = crate::budget::inspect_in(&tx)?;
        ensure!(
            status.unknown_usage.len() == if held { 1 } else { 0 },
            "unexpected unknown alerts usage"
        );
        let account = status
            .accounts
            .iter()
            .find(|a| a.budget_id == "alerts" && a.unit == "concurrency")
            .context("alerts concurrency account")?;
        ensure!(
            account.limit == 1 && account.used == 0 && account.reserved == if held { 1 } else { 0 },
            "alerts concurrency accounting differs"
        );
        if held {
            ensure!(
                status.unknown_usage[0].quote.concurrency == 1,
                "unknown usage lost its quote"
            );
        }
        Ok(())
    }

    fn require_protected(&self, expected: &BTreeMap<String, Value>) -> Result<()> {
        ensure!(
            self.protected()? == *expected,
            "Alerts request changed a protected target/scope/provider"
        );
        Ok(())
    }

    fn call(
        &self,
        action: Action,
        actor: &str,
        invocation: &str,
        effect: &str,
        input: Value,
    ) -> Result<String> {
        self.call_in(&self.runtime, action, actor, invocation, effect, input)
    }

    fn call_in(
        &self,
        runtime: &Runtime,
        action: Action,
        actor: &str,
        invocation: &str,
        effect: &str,
        mut input: Value,
    ) -> Result<String> {
        let (request, bound) = bind(runtime, actor, invocation)?;
        let mut connection = store::open(runtime.db())?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if input.get("handle").is_none() {
            input["handle"] = bound["token"].clone();
        }
        let sequence = self.attempts.get();
        self.attempts.set(sequence + 1);
        let attempt = format!("attempt-{sequence}");
        let instruction = Instruction {
            kind: "external".into(),
            model: action.capability().into(),
            data: input.to_string(),
            ..Default::default()
        };
        let active = crate::authority_state::current(&tx)?;
        let capability = capabilities::authorized(
            &tx,
            runtime,
            &request,
            &instruction,
            active.policy()?,
            effect,
        )?;
        crate::resources::record_use(&tx, &attempt, capability.resource())?;
        let reservation = crate::resources::reserve_in(
            &tx,
            runtime,
            &request,
            &instruction,
            &attempt,
            capability.resource(),
            capability.quote(),
        )?;
        let resource = capability.resource().clone();
        tx.commit()?;
        let outcome = capabilities::execute(runtime, capability, effect, &attempt);
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        crate::resources::settle_in(&tx, &reservation, outcome.usage)?;
        tx.commit()?;
        outcome.result.and_then(|result| {
            crate::resources::validate_result(&resource, &result)?;
            Ok(result)
        })
    }
}

fn bind(runtime: &Runtime, actor: &str, invocation: &str) -> Result<(Request, Value)> {
    runtime.accept("run", actor, invocation, &json!({}), NOW)?;
    let mut connection = store::open(runtime.db())?;
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let request = Request {
        operation: "run".into(),
        input: "{}".into(),
        context: store::invocation_context(&tx, invocation)?,
        observations: vec![],
    };
    let bound = crate::resources::host_operation(
        &tx,
        runtime,
        &request,
        &Instruction {
            kind: "observe".into(),
            model: crate::resources::BIND.into(),
            data: json!({"binding":"alerts","invocation":invocation}).to_string(),
            ..Default::default()
        },
    )?
    .context("alerts resource binding")?;
    let bound: Value = serde_json::from_str(&bound)?;
    tx.commit()?;
    Ok((request, bound))
}

pub(super) fn observe(action: Action, variant: Variant) -> Result<Observed> {
    ensure!(
        action == Action::OperatorAlertsSend,
        "operator-alert action required"
    );
    let fixture = Fixture::new(world(variant == Variant::A), 42)?;
    let before = worlds_in_scope(fixture.runtime.db(), SCOPE)?;
    let result = fixture.call(
        action,
        "alice",
        "attribution",
        "attribution-effect",
        json!({"topic":"incident","body":"Synthetic incident\nManual action required."}),
    )?;
    let after = worlds_in_scope(fixture.runtime.db(), SCOPE)?;
    Ok(Observed {
        result,
        before,
        after,
    })
}

pub(super) fn check(
    action: Action,
    observe: impl Fn(Variant) -> Result<Observed>,
) -> std::result::Result<(), String> {
    if action != Action::OperatorAlertsSend {
        return Err("operator-alert action required".into());
    }
    let own = Provider::SyntheticOperatorAlerts
        .world()
        .expect("declared alerts world");
    for variant in [Variant::A, Variant::B] {
        let actual = observe(variant).map_err(|_| "admitted operator-alert adapter failed")?;
        let result: Value =
            serde_json::from_str(&actual.result).map_err(|_| "alert result shape")?;
        let (expected, changed) = if variant == Variant::A {
            (
                json!({"Accepted":format!("alert_{}", &crate::digest(b"attribution-effect")[7..31])}),
                vec![own],
            )
        } else {
            (json!("Disabled"), vec![])
        };
        if result != expected || actual.changed() != changed {
            return Err("alert result or scoped effect differs".into());
        }
    }
    Ok(())
}

// An accepted-request list models the contract independently of the provider's
// state maps and production transition functions.
#[derive(Clone)]
struct Entry {
    effect: String,
    invocation: String,
    topic: String,
    body: String,
    result: Value,
}

struct Oracle {
    enabled: bool,
    messages: Vec<people::Alert>,
    entries: Vec<Entry>,
    calls: Vec<Value>,
    faults: Vec<people::ScheduledFailure>,
}

impl Oracle {
    fn new(initial: &people::AlertWorld) -> Self {
        Self {
            enabled: initial.enabled,
            messages: initial.messages.clone(),
            entries: vec![],
            calls: vec![],
            faults: vec![],
        }
    }

    fn snapshot(&self) -> Value {
        let ledger = self.entries.iter().map(|entry| (entry.effect.clone(), json!({
            "capability":"operator_alerts.send.v1", "payload":{"topic":entry.topic,"body":entry.body}, "result":entry.result,
        }))).collect::<BTreeMap<_,_>>();
        json!({"world":{"enabled":self.enabled,"messages":self.messages},"ledger":ledger,"calls":self.calls,"faults":self.faults})
    }

    fn step(&mut self, effect: &str, invocation: &str, topic: &str, body: &str) -> Result<Value> {
        if let Some(prior) = self.entries.iter().find(|entry| entry.effect == effect) {
            ensure!(
                prior.topic == topic && prior.body == body,
                "oracle alert effect identity conflict"
            );
            let result = prior.result.clone();
            self.calls.push(json!({"effect_id":effect,"capability":"operator_alerts.send.v1","replayed":true,"changed":false}));
            return Ok(result);
        }
        let fault = self
            .faults
            .iter_mut()
            .find(|fault| {
                fault.remaining > 0
                    && fault.capability == "operator_alerts.send.v1"
                    && (fault.subject.is_empty() || fault.subject == topic)
            })
            .map(|fault| {
                fault.remaining -= 1;
                fault.mode.clone()
            });
        let (result, changed) = if let Some(people::FailureMode::Definite {
            code,
            message,
            retryable,
        }) = fault
        {
            (
                json!({"Failed":{"code":code,"message":message,"retryable":retryable}}),
                false,
            )
        } else if !self.enabled {
            (json!("Disabled"), false)
        } else {
            let id = format!("alert_{}", &crate::digest(effect.as_bytes())[7..31]);
            self.messages.push(people::Alert {
                id: id.clone(),
                topic: topic.into(),
                body: body.into(),
            });
            (json!({"Accepted":id}), true)
        };
        self.entries.push(Entry {
            effect: effect.into(),
            invocation: invocation.into(),
            topic: topic.into(),
            body: body.into(),
            result: result.clone(),
        });
        self.calls.push(json!({"effect_id":effect,"capability":"operator_alerts.send.v1","replayed":false,"changed":changed}));
        Ok(result)
    }
}

fn observed_step(fixture: &Fixture, oracle: &mut Oracle, entry: &Entry) -> Result<Value> {
    let expected = oracle.step(&entry.effect, &entry.invocation, &entry.topic, &entry.body)?;
    let actual: Value = serde_json::from_str(&fixture.call(
        Action::OperatorAlertsSend,
        "alice",
        &entry.invocation,
        &entry.effect,
        json!({"topic":entry.topic,"body":entry.body}),
    )?)?;
    ensure!(
        actual == expected,
        "operator-alert result differs from independent oracle"
    );
    ensure!(
        serde_json::to_value(fixture.state()?)? == oracle.snapshot(),
        "complete committed alert store differs"
    );
    fixture.assert_budget_state(false)?;
    Ok(actual)
}

fn request(id: &str, topic: &str, body: &str) -> Entry {
    Entry {
        effect: id.into(),
        invocation: id.into(),
        topic: topic.into(),
        body: body.into(),
        result: Value::Null,
    }
}

fn forbidden(result: Result<String>) -> Result<()> {
    let Err(error) = result else {
        anyhow::bail!("foreign alert authority admitted");
    };
    ensure!(
        matches!(
            error.downcast_ref::<crate::error::Failure>(),
            Some(crate::error::Failure::ResourceForbidden)
        ),
        "alert authority refused at wrong boundary"
    );
    Ok(())
}

fn quarantined(result: Result<String>) -> Result<()> {
    let Err(error) = result else {
        anyhow::bail!("uncertain alert usage released concurrency");
    };
    ensure!(
        matches!(
            error.downcast_ref::<crate::error::Failure>(),
            Some(crate::error::Failure::BudgetExhausted)
        ) && error.to_string() == "budget_exhausted:alerts:concurrency",
        "alert quota refused at wrong boundary"
    );
    Ok(())
}

#[test]
fn alerts_use_the_same_common_gate_and_reject_constant_missing_landless_and_wrong_world_substitutes()
-> Result<()> {
    let action = Action::OperatorAlertsSend;
    super::check(action, |variant| super::observe(action, variant)).map_err(anyhow::Error::msg)?;
    assert!(super::check(action, |_| anyhow::bail!("missing adapter")).is_err());
    for mutant in 0..4 {
        assert!(
            super::check(action, |variant| {
                let mut value = observe(action, variant)?;
                match mutant {
                    0 => value.result = json!({"Accepted":"constant"}).to_string(),
                    1 => value.after = value.before.clone(),
                    2 => {
                        let own = Provider::SyntheticOperatorAlerts.world().unwrap();
                        let wrong = value.after[own].clone();
                        value.after.insert(own, value.before[own].clone());
                        value
                            .after
                            .insert(Provider::Snowflake.world().unwrap(), wrong);
                    }
                    _ => {
                        if variant == Variant::B {
                            value.after.insert(
                                Provider::SyntheticOperatorAlerts.world().unwrap(),
                                Some("mutated disabled world".into()),
                            );
                        }
                    }
                }
                Ok(value)
            })
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn foreign_topics_handles_actors_and_malformed_payloads_refuse_before_provider_changes()
-> Result<()> {
    let fixture = Fixture::new(world(true), 17)?;
    let protected = fixture.protected()?;
    // Accounts are created on the first reservation. Establish a real admitted
    // baseline before checking that rejected inputs leave accounting unchanged.
    let baseline: Value = serde_json::from_str(&fixture.call(
        Action::OperatorAlertsSend,
        "alice",
        "negative-baseline",
        "negative-baseline",
        json!({"topic":"incident","body":"Synthetic baseline"}),
    )?)?;
    ensure!(
        baseline
            == json!({"Accepted":format!("alert_{}", &crate::digest(b"negative-baseline")[7..31])}),
        "negative-control admitted baseline failed"
    );
    fixture.assert_budget_state(false)?;
    fixture.require_protected(&protected)?;
    let before = serde_json::to_value(fixture.state()?)?;
    forbidden(fixture.call(
        Action::OperatorAlertsSend,
        "alice",
        "foreign-topic",
        "foreign-topic",
        json!({"topic":"foreign","body":"alert"}),
    ))?;
    let (_, token) = bind(&fixture.foreign, "alice", "foreign-handle")?;
    forbidden(fixture.call(
        Action::OperatorAlertsSend,
        "alice",
        "foreign-scope",
        "foreign-scope",
        json!({"topic":"incident","body":"alert","handle":token["token"]}),
    ))?;
    let (_, token) = fixture.bind("alice", "handle-owner")?;
    forbidden(fixture.call(
        Action::OperatorAlertsSend,
        "bob",
        "foreign-owner",
        "foreign-owner",
        json!({"topic":"incident","body":"alert","handle":token["token"]}),
    ))?;
    for (i, input) in [
        json!({"topic":"incident","body":"alert","handle":"substituted"}),
        json!({"topic":"incident","body":"alert","destination":"alerts-other"}),
        json!({"topic":"incident","body":"\n\t\r\n"}),
        json!({"topic":"incident","body":"x".repeat(8001)}),
        json!({"topic":"","body":"alert"}),
    ]
    .into_iter()
    .enumerate()
    {
        ensure!(
            fixture
                .call(
                    Action::OperatorAlertsSend,
                    "alice",
                    &format!("malformed-{i}"),
                    "malformed",
                    input
                )
                .is_err(),
            "malformed alert admitted"
        );
    }
    ensure!(
        serde_json::to_value(fixture.state()?)? == before,
        "refused alert changed world/ledger"
    );
    fixture.require_protected(&protected)?;
    fixture.assert_budget_state(false)?;
    Ok(())
}

#[test]
fn alert_resource_revocation_refuses_a_fresh_attempt_and_cached_effect() -> Result<()> {
    let fixture = Fixture::new(world(true), 19)?;
    let admitted: Value = serde_json::from_str(&fixture.call(
        Action::OperatorAlertsSend,
        "alice",
        "original",
        "original",
        json!({"topic":"incident","body":"alert"}),
    )?)?;
    ensure!(
        admitted.get("Accepted").is_some(),
        "revocation baseline failed"
    );
    let before = serde_json::to_value(fixture.state()?)?;
    let protected = fixture.protected()?;
    let db = store::open(fixture.runtime.db())?;
    let current = crate::authority_state::current(&db)?;
    let path = fixture.runtime.instance_path();
    let mut instance: Value = serde_json::from_slice(&fs::read(path)?)?;
    instance["resources"]["policies"]["provision"]["actors"] = json!(["bob"]);
    fs::write(path, serde_json::to_vec(&instance)?)?;
    crate::authority_state::apply_desired(
        &fixture.runtime,
        &crate::authority_state::LocalOperator::assert_local("alerts-test-operator")?,
        "remove-alerts",
        Some(current.stamp),
    )?;
    forbidden(fixture.call(
        Action::OperatorAlertsSend,
        "alice",
        "revoked",
        "revoked",
        json!({"topic":"incident","body":"alert"}),
    ))?;
    ensure!(
        fixture
            .call(
                Action::OperatorAlertsSend,
                "alice",
                "original",
                "original",
                json!({"topic":"incident","body":"alert"})
            )
            .is_err(),
        "cached alert bypassed revocation"
    );
    ensure!(
        serde_json::to_value(fixture.state()?)? == before,
        "revocation changed provider state"
    );
    fixture.require_protected(&protected)?;
    fixture.assert_budget_state(false)?;
    Ok(())
}

#[test]
fn foreign_partition_guard_rejects_an_actual_foreign_alert() -> Result<()> {
    let fixture = Fixture::new(world(true), 23)?;
    let protected = fixture.protected()?;
    for key in [
        "operator_alerts.synthetic.sqlite/alertscoverage/test/app/alerts-other",
        "operator_alerts.synthetic.sqlite/otheralerts/test/app/alerts-main",
    ] {
        ensure!(
            protected.contains_key(key),
            "foreign alert partition omitted"
        );
    }
    fixture.require_protected(&protected)?;
    let before = serde_json::to_value(fixture.state()?)?;
    let response: Value = serde_json::from_str(&fixture.call_in(
        &fixture.foreign,
        Action::OperatorAlertsSend,
        "alice",
        "foreign-change",
        "foreign-change",
        json!({"topic":"incident","body":"foreign control"}),
    )?)?;
    ensure!(
        response.get("Accepted").is_some(),
        "foreign-write baseline failed"
    );
    ensure!(
        serde_json::to_value(fixture.state()?)? == before,
        "foreign write escaped its scope"
    );
    ensure!(
        fixture.require_protected(&protected).is_err(),
        "guard ignored actual foreign mutation"
    );
    Ok(())
}

#[test]
fn definite_alert_failure_replays_its_result_until_a_new_intent_recovers() -> Result<()> {
    let initial = world(true);
    let fixture = Fixture::new(initial.clone(), 29)?;
    let protected = fixture.protected()?;
    let mut oracle = Oracle::new(&initial);
    let fault = people::ScheduledFailure {
        capability: Action::OperatorAlertsSend.capability().into(),
        subject: "incident".into(),
        remaining: 1,
        mode: people::FailureMode::Definite {
            code: "SyntheticTransient".into(),
            message: "Synthetic alert refusal".into(),
            retryable: true,
        },
    };
    oracle.faults.push(fault.clone());
    people::schedule_failure(
        &fixture.runtime,
        people::SyntheticProvider::OperatorAlerts,
        DESTINATION,
        &fault,
    )?;
    let entry = request("failure", "incident", "Synthetic alert");
    let failed = observed_step(&fixture, &mut oracle, &entry)?;
    ensure!(
        failed.get("Failed").is_some(),
        "definite failure not observed"
    );
    ensure!(
        observed_step(&fixture, &mut oracle, &entry)? == failed,
        "retry re-executed definite failure"
    );
    ensure!(
        observed_step(
            &fixture,
            &mut oracle,
            &request("new-intent", "incident", "Synthetic alert")
        )?
        .get("Accepted")
        .is_some(),
        "new intent did not recover"
    );
    fixture.require_protected(&protected)?;
    Ok(())
}

fn observation(fixture: &Fixture, result: &Value, lost_reply: bool) -> Result<Value> {
    let state = fixture.state()?;
    let outcome = if result.get("Accepted").is_some() {
        "accepted"
    } else if result == &json!("Disabled") {
        "disabled"
    } else if result.get("Failed").is_some() {
        "failed"
    } else {
        anyhow::bail!("unknown alert result");
    };
    let call = state.calls.last().context("actual alert call")?;
    Ok(
        json!({"outcome":outcome,"replayed":call.replayed,"lost_reply":lost_reply,"state":crate::digest(&serde_json::to_vec(&state)?)}),
    )
}

fn history(seed: u64) -> Result<Vec<Value>> {
    let initial = world(!seed.is_multiple_of(4));
    let fixture = Fixture::new(initial.clone(), seed)?;
    let protected = fixture.protected()?;
    let mut oracle = Oracle::new(&initial);
    let mut observed = Vec::new();
    let first = request(
        "original",
        "incident",
        "Synthetic incident\nManual action required.",
    );
    for entry in [
        first.clone(),
        request("second", "recovery", "Synthetic recovery"),
        first,
    ] {
        let result = observed_step(&fixture, &mut oracle, &entry)?;
        observed.push(observation(&fixture, &result, false)?);
        fixture.require_protected(&protected)?;
    }
    let mut random = seed;
    for i in 0..24 {
        random = random
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let choice = (random >> 32) % 5;
        let id = format!("generated-{seed}-{i}");
        if choice == 4 {
            forbidden(fixture.call(
                Action::OperatorAlertsSend,
                "alice",
                &id,
                &id,
                json!({"topic":"foreign","body":"Synthetic alert"}),
            ))?;
            ensure!(
                serde_json::to_value(fixture.state()?)? == oracle.snapshot(),
                "foreign-topic refusal changed provider"
            );
            fixture.assert_budget_state(false)?;
            observed.push(
                json!({"outcome":"foreign_topic_refused","replayed":false,"lost_reply":false}),
            );
        } else {
            let entry = if choice == 1 {
                oracle.entries[(random as usize) % oracle.entries.len()].clone()
            } else {
                request(
                    &id,
                    if random & 1 == 0 {
                        "incident"
                    } else {
                        "recovery"
                    },
                    "Synthetic alert body",
                )
            };
            if choice == 3 {
                let fault = people::ScheduledFailure {
                    capability: Action::OperatorAlertsSend.capability().into(),
                    subject: entry.topic.clone(),
                    remaining: 1,
                    mode: people::FailureMode::Definite {
                        code: "SyntheticTransient".into(),
                        message: "Synthetic alert refusal".into(),
                        retryable: true,
                    },
                };
                oracle.faults.push(fault.clone());
                people::schedule_failure(
                    &fixture.runtime,
                    people::SyntheticProvider::OperatorAlerts,
                    DESTINATION,
                    &fault,
                )?;
                ensure!(
                    serde_json::to_value(fixture.state()?)? == oracle.snapshot(),
                    "fault setup changed provider"
                );
            }
            let result = observed_step(&fixture, &mut oracle, &entry)?;
            if choice == 2 {
                ensure!(
                    observed_step(&fixture, &mut oracle, &entry)? == result,
                    "lost accepted reply changed result"
                );
            }
            observed.push(observation(&fixture, &result, choice == 2)?);
        }
        fixture.require_protected(&protected)?;
    }
    let first = oracle.entries.first().context("original alert")?;
    let conflict = fixture.call(
        Action::OperatorAlertsSend,
        "alice",
        &first.invocation,
        &first.effect,
        json!({"topic":first.topic,"body":"substituted"}),
    );
    let Err(error) = conflict else {
        anyhow::bail!("conflicting alert effect admitted");
    };
    ensure!(
        error.to_string() == "people_provider_idempotency_conflict",
        "alert conflict refused at wrong boundary"
    );
    fixture.assert_budget_state(true)?;
    ensure!(
        serde_json::to_value(fixture.state()?)? == oracle.snapshot(),
        "conflict altered provider world/ledger"
    );
    observed
        .push(json!({"outcome":"payload_conflict_refused","replayed":false,"lost_reply":false}));
    quarantined(fixture.call(
        Action::OperatorAlertsSend,
        "alice",
        "quarantined",
        "quarantined",
        json!({"topic":"incident","body":"Synthetic alert"}),
    ))?;
    fixture.assert_budget_state(true)?;
    ensure!(
        serde_json::to_value(fixture.state()?)? == oracle.snapshot(),
        "quarantined request changed provider"
    );
    fixture.require_protected(&protected)?;
    observed.push(
        json!({"outcome":"unknown_usage_quarantines_budget","replayed":false,"lost_reply":false}),
    );
    Ok(observed)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplaySeed {
    format: u32,
    campaign_source: String,
    seed: u64,
}

fn campaign_source() -> String {
    crate::digest(include_bytes!("alerts_coverage_tests.rs"))
}

fn checked_history(seed: u64) -> Result<Vec<Value>> {
    let result = (|| {
        let first = history(seed)?;
        ensure!(history(seed)? == first, "alert history not replayable");
        Ok(first)
    })();
    match result {
        Ok(observed) => Ok(observed),
        Err(error) => {
            let saved = (|| -> Result<()> {
                let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../artifacts/alerts-provider-simulation");
                fs::create_dir_all(&root)?;
                let dir = tempfile::Builder::new()
                    .prefix("failure-")
                    .tempdir_in(root)?
                    .keep();
                fs::write(
                    dir.join("failure.json"),
                    serde_json::to_vec(&ReplaySeed {
                        format: 1,
                        campaign_source: campaign_source(),
                        seed,
                    })?,
                )?;
                Ok(())
            })();
            if let Err(retention) = saved {
                return Err(error
                    .context(retention)
                    .context("alert replay retention failed"));
            }
            Err(error)
        }
    }
}

fn replay_seed(bytes: &[u8]) -> Result<u64> {
    ensure!(bytes.len() <= 4096, "alert replay byte bound");
    let value: ReplaySeed = crate::json::decode(bytes)?;
    ensure!(
        value.format == 1 && value.campaign_source == campaign_source(),
        "alert replay source or format differs"
    );
    Ok(value.seed)
}

#[test]
fn seeded_admitted_alert_histories_match_complete_independent_oracle_and_replay() -> Result<()> {
    let mut counts = BTreeMap::<String, u64>::new();
    let mut seeds = Vec::new();
    for seed in 0..8 {
        let observed = checked_history(seed)?;
        ensure!(observed.len() == 29, "alert campaign incomplete");
        for step in observed {
            let name = step["outcome"].as_str().context("observed alert outcome")?;
            ensure!(
                [
                    "accepted",
                    "disabled",
                    "failed",
                    "foreign_topic_refused",
                    "payload_conflict_refused",
                    "unknown_usage_quarantines_budget"
                ]
                .contains(&name),
                "unknown alert outcome"
            );
            *counts.entry(name.into()).or_default() += 1;
            if step["replayed"] == true {
                *counts.entry("duplicate_replayed".into()).or_default() += 1;
            }
            if step["lost_reply"] == true {
                *counts.entry("reply_loss_replayed".into()).or_default() += 1;
            }
        }
        seeds.push(seed);
    }
    ensure!(
        seeds == (0..8).collect::<Vec<_>>() && counts.len() == 8 && counts.values().all(|n| *n > 0),
        "declared alert campaign/outcome did not run"
    );
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/alerts-provider-simulation");
    fs::create_dir_all(&root)?;
    let dir = tempfile::Builder::new()
        .prefix("campaign-")
        .tempdir_in(root)?
        .keep();
    fs::write(
        dir.join("receipt.json"),
        serde_json::to_vec_pretty(&json!({"format":1,"status":"passed",
        "scope":"authorized_synthetic_operator_alerts_not_native_worker_or_live_service","campaign_source":campaign_source(),
        "seeds":seeds,"steps_per_history":29,"each_history_replayed":true,"observed_outcomes":counts}))?,
    )?;
    Ok(())
}

#[test]
fn replay_schema_source_and_size_refuse_before_alert_dispatch() -> Result<()> {
    let mut value = json!({"format":1,"campaign_source":campaign_source(),"seed":3});
    ensure!(
        replay_seed(&serde_json::to_vec(&value)?)? == 3,
        "valid alert replay refused"
    );
    value["campaign_source"] = json!("changed");
    assert!(replay_seed(&serde_json::to_vec(&value)?).is_err());
    value["campaign_source"] = json!(campaign_source());
    value["provider_payload"] = json!("forbidden");
    assert!(replay_seed(&serde_json::to_vec(&value)?).is_err());
    assert!(replay_seed(&[b' '; 4097]).is_err());
    Ok(())
}

#[test]
fn replay_saved_alert_history() -> Result<()> {
    let Some(path) = std::env::var_os("DAY2_ALERTS_REPLAY") else {
        return Ok(());
    };
    use std::io::Read as _;
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    checked_history(replay_seed(&bytes)?)?;
    Ok(())
}
