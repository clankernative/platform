//! Real synthetic Linear capability admission with an independent provider oracle.
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

const SCOPE: &str = "linearcoverage/test/app";
const ORGANIZATION: &str = "linear-main";
const DOMAIN: &str = "linear.test";
const NOW: i64 = 1_700_000_000;
const SUBJECT: &str = "alice@linear.test";

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
        "observations":[],"effects":["linear.ensure_access.v1","linear.suspend.v1"]}}});
    let target =
        json!({"kind":"linear_organization","organization_id":ORGANIZATION,"email_domain":DOMAIN});
    let catalog = json!({"version":1,
        "connections":{"linear":{"revision":1,"provider":"synthetic_linear"}},
        "resources":{
            "linear":{"revision":1,"connection":{"id":"linear","revision":1},"target":target},
            "foreign":{"revision":1,"connection":{"id":"linear","revision":1},
                "target":{"kind":"linear_organization","organization_id":"linear-other","email_domain":DOMAIN}}},
        "policies":{"provision":{"revision":1,"owner":"it","actors":["alice","bob"],"allowed_apps":["app"],
            "max_duration_seconds":null,"slots":{"linear":{"kind":"linear_organization",
                "allowed_resources":[{"id":"linear","revision":1}],"actions":["linear_ensure_access","linear_suspend"],
                "limits":{"max_request_bytes":16384,"max_response_bytes":16384,"max_calls_per_invocation":8},
                "budgets":[{"id":"linear","revision":1}]}}}},
        "budgets":{"linear":{"revision":1,"scope":"app","period_seconds":3600,
            "limits":{"calls":10000,"bytes":100000000,"concurrency":1}}}});
    fs::write(
        &instance_path,
        serde_json::to_vec(&json!({
        "installation":installation,"environment":"test","resources":catalog,
        "control":{"version":1,"state_directory":directory.join(format!("control-{installation}")),
            "operators":["linear-test-operator"],"sources":{"repo":{"kind":"local_git","repository":directory.join("repo")}},
            "apps":{"app":{"source":"repo"}}},
        "apps":{"app":{"artifact":artifact_directory,"readers":["alice","bob"],"writers":["alice","bob"],
            "authority":policy,"resource_policies":[{"policy":{"id":"provision","revision":1},
                "operation":"run","bindings":{"linear":{"id":"linear","revision":1}}}]}}}))?,
    )?;
    let contract = serde_json::from_value(json!({
        "format":crate::artifact::CURRENT_FORMAT,"verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
        "roc_version":"linear-host-test","worker_digest":"linear-host-test","schema_digest":"linear-host-test",
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
            "linear-host-test".into(),
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

fn world(enabled: bool) -> people::LinearWorld {
    people::LinearWorld {
        enabled,
        users: [
            (
                SUBJECT.into(),
                people::LinearUser {
                    id: "user-alice".into(),
                    active: true,
                },
            ),
            (
                "bob@linear.test".into(),
                people::LinearUser {
                    id: "user-bob".into(),
                    active: false,
                },
            ),
        ]
        .into(),
        invitations: vec![
            people::Invitation {
                id: "accepted-old".into(),
                email: "new@linear.test".into(),
                accepted: true,
                expired: false,
            },
            people::Invitation {
                id: "expired-old".into(),
                email: "new@linear.test".into(),
                accepted: false,
                expired: true,
            },
            people::Invitation {
                id: "pending".into(),
                email: "PENDING@linear.test".into(),
                accepted: false,
                expired: false,
            },
        ],
    }
}

fn seed_people(
    runtime: &Runtime,
    organization: &str,
    suffix: &str,
    linear: people::LinearWorld,
) -> Result<()> {
    people::seed_synthetic(
        runtime,
        &people::SyntheticFixture {
            customer_id: format!("google-{suffix}"),
            google: Default::default(),
            organization_id: organization.into(),
            linear,
            destination: format!("alerts-{suffix}"),
            alerts: people::AlertWorld {
                enabled: true,
                messages: vec![],
            },
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
    fn new(initial: people::LinearWorld, entropy: u64) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let runtime = runtime_at(directory.path(), "linearcoverage", "app.sqlite", entropy)?;
        let foreign = runtime_at(directory.path(), "otherlinear", "foreign.sqlite", entropy)?;
        super::seed(runtime.db(), runtime.scope(), &super::fixture(Variant::A))?;
        super::seed(foreign.db(), foreign.scope(), &super::fixture(Variant::B))?;
        seed_people(&runtime, ORGANIZATION, "allowed", initial)?;
        seed_people(&runtime, "linear-other", "foreign-target", world(true))?;
        seed_people(&foreign, ORGANIZATION, "foreign-scope", world(true))?;
        Ok(Self {
            _directory: directory,
            runtime,
            foreign,
            attempts: Cell::new(0),
        })
    }

    fn state(&self) -> Result<people::ProviderState<people::LinearWorld>> {
        people::inspect_linear(&self.runtime, ORGANIZATION)
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
                    if *provider == Provider::SyntheticLinear
                        && scope == SCOPE
                        && target == ORGANIZATION
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
            "unexpected unknown linear usage"
        );
        let account = status
            .accounts
            .iter()
            .find(|a| a.budget_id == "linear" && a.unit == "concurrency")
            .context("linear concurrency account")?;
        ensure!(
            account.limit == 1 && account.used == 0 && account.reserved == if held { 1 } else { 0 },
            "linear concurrency accounting differs"
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
            "Linear request changed a protected target/scope/provider"
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
            data: json!({"binding":"linear","invocation":invocation}).to_string(),
            ..Default::default()
        },
    )?
    .context("linear resource binding")?;
    let bound: Value = serde_json::from_str(&bound)?;
    tx.commit()?;
    Ok((request, bound))
}

pub(super) fn observe(action: Action, variant: Variant) -> Result<Observed> {
    ensure!(
        matches!(action, Action::LinearEnsureAccess | Action::LinearSuspend),
        "Linear action required"
    );
    let mut initial = world(true);
    let user = initial.users.get_mut(SUBJECT).context("attribution user")?;
    user.active = action == Action::LinearSuspend;
    user.id = match variant {
        Variant::A => "attribution-a",
        Variant::B => "attribution-b",
    }
    .into();
    let fixture = Fixture::new(initial, 42)?;
    let before = worlds_in_scope(fixture.runtime.db(), SCOPE)?;
    let result = fixture.call(
        action,
        "alice",
        "attribution",
        "attribution-effect",
        json!({"primary_email":SUBJECT}),
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
    let own = Provider::SyntheticLinear
        .world()
        .expect("declared Linear world");
    for (variant, id) in [(Variant::A, "attribution-a"), (Variant::B, "attribution-b")] {
        let observed = observe(variant).map_err(|_| "admitted Linear adapter failed")?;
        let result: Value =
            serde_json::from_str(&observed.result).map_err(|_| "Linear result shape")?;
        let expected = match action {
            Action::LinearEnsureAccess => json!({"Reactivated":id}),
            Action::LinearSuspend => json!({"Suspended":id}),
            _ => return Err("Linear action required".into()),
        };
        if result != expected || observed.changed() != vec![own] {
            return Err("Linear action lost its scoped result or declared world effect".into());
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    Ensure,
    Suspend,
}

impl Operation {
    fn action(self) -> Action {
        match self {
            Self::Ensure => Action::LinearEnsureAccess,
            Self::Suspend => Action::LinearSuspend,
        }
    }
}

#[derive(Clone)]
struct Entry {
    operation: Operation,
    effect: String,
    invocation: String,
    email: String,
    result: Value,
}

// Independent representation: an ordered account list and accepted request
// history, not the provider's user/ledger maps or transition implementation.
struct Oracle {
    enabled: bool,
    users: Vec<(String, String, bool)>,
    invitations: Vec<people::Invitation>,
    entries: Vec<Entry>,
    calls: Vec<Value>,
    faults: Vec<people::ScheduledFailure>,
}

impl Oracle {
    fn new(initial: &people::LinearWorld) -> Self {
        Self {
            enabled: initial.enabled,
            users: initial
                .users
                .iter()
                .map(|(email, u)| (email.clone(), u.id.clone(), u.active))
                .collect(),
            invitations: initial.invitations.clone(),
            entries: vec![],
            calls: vec![],
            faults: vec![],
        }
    }

    fn world(&self) -> Value {
        let users = self
            .users
            .iter()
            .map(|(email, id, active)| (email.clone(), json!({"id":id,"active":active})))
            .collect::<BTreeMap<_, _>>();
        json!({"enabled":self.enabled,"users":users,"invitations":self.invitations})
    }

    fn snapshot(&self) -> Value {
        let ledger = self.entries.iter().map(|entry|(entry.effect.clone(),json!({
            "capability":entry.operation.action().capability(),"payload":{"primary_email":entry.email},"result":entry.result,
        }))).collect::<BTreeMap<_,_>>();
        json!({"world":self.world(),"ledger":ledger,"calls":self.calls,"faults":self.faults})
    }

    fn step(
        &mut self,
        operation: Operation,
        effect: &str,
        invocation: &str,
        input: &str,
    ) -> Result<Value> {
        let email = input.to_ascii_lowercase();
        if let Some(entry) = self.entries.iter().find(|e| e.effect == effect) {
            ensure!(
                entry.operation == operation && entry.email == email,
                "oracle effect identity conflict"
            );
            let result = entry.result.clone();
            self.calls.push(json!({"effect_id":effect,"capability":operation.action().capability(),"replayed":true,"changed":false}));
            return Ok(result);
        }
        let before = self.world();
        let fault = self
            .faults
            .iter_mut()
            .find(|f| {
                f.remaining > 0
                    && f.capability == operation.action().capability()
                    && (f.subject.is_empty() || f.subject == email)
            })
            .map(|f| {
                f.remaining -= 1;
                f.mode.clone()
            });
        let result =
            if let Some(people::FailureMode::Definite {
                code,
                message,
                retryable,
            }) = fault
            {
                json!({"Failed":{"code":code,"message":message,"retryable":retryable}})
            } else if !self.enabled {
                json!("Disabled")
            } else {
                match operation {
                    Operation::Ensure => {
                        if let Some((_, id, active)) = self
                            .users
                            .iter_mut()
                            .find(|(address, _, _)| address == &email)
                        {
                            let was = *active;
                            *active = true;
                            if was {
                                json!({"Active":id})
                            } else {
                                json!({"Reactivated":id})
                            }
                        } else if let Some(invitation) = self.invitations.iter().find(|i| {
                            i.email.eq_ignore_ascii_case(&email) && !i.accepted && !i.expired
                        }) {
                            json!({"PendingInvitation":invitation.id})
                        } else {
                            let id = format!("invite_{}", &crate::digest(effect.as_bytes())[7..31]);
                            self.invitations.push(people::Invitation {
                                id: id.clone(),
                                email: email.clone(),
                                accepted: false,
                                expired: false,
                            });
                            json!({"Invited":id})
                        }
                    }
                    Operation::Suspend => match self
                        .users
                        .iter_mut()
                        .find(|(address, _, _)| address == &email)
                    {
                        Some((_, id, active)) => {
                            let was = *active;
                            *active = false;
                            if was {
                                json!({"Suspended":id})
                            } else {
                                json!({"AlreadySuspended":id})
                            }
                        }
                        None => json!("NotFound"),
                    },
                }
            };
        let changed = before != self.world();
        self.entries.push(Entry {
            operation,
            effect: effect.into(),
            invocation: invocation.into(),
            email,
            result: result.clone(),
        });
        self.calls.push(json!({"effect_id":effect,"capability":operation.action().capability(),"replayed":false,"changed":changed}));
        Ok(result)
    }
}

fn forbidden(result: Result<String>) -> Result<()> {
    let Err(error) = result else {
        anyhow::bail!("foreign Linear authority was admitted");
    };
    ensure!(
        matches!(
            error.downcast_ref::<crate::error::Failure>(),
            Some(crate::error::Failure::ResourceForbidden)
        ),
        "Linear refusal occurred at wrong authority boundary"
    );
    Ok(())
}

fn quota_refusal(result: Result<String>) -> Result<()> {
    let Err(error) = result else {
        anyhow::bail!("uncertain Linear usage released concurrency");
    };
    ensure!(
        matches!(
            error.downcast_ref::<crate::error::Failure>(),
            Some(crate::error::Failure::BudgetExhausted)
        ) && error.to_string() == "budget_exhausted:linear:concurrency",
        "Linear quarantine refused at wrong boundary"
    );
    Ok(())
}

fn observed_step(
    fixture: &Fixture,
    oracle: &mut Oracle,
    operation: Operation,
    effect: &str,
    invocation: &str,
    email: &str,
) -> Result<Value> {
    let expected = oracle.step(operation, effect, invocation, email)?;
    let actual: Value = serde_json::from_str(&fixture.call(
        operation.action(),
        "alice",
        invocation,
        effect,
        json!({"primary_email":email}),
    )?)?;
    ensure!(
        actual == expected,
        "Linear semantic result differs from independent oracle"
    );
    ensure!(
        serde_json::to_value(fixture.state()?)? == oracle.snapshot(),
        "complete committed Linear state differs"
    );
    fixture.assert_budget_state(false)?;
    Ok(actual)
}

#[test]
fn protected_snapshot_sees_every_foreign_partition_and_refuses_a_real_foreign_write() -> Result<()>
{
    let fixture = Fixture::new(world(true), 31)?;
    let protected = fixture.protected()?;
    for partition in [
        "linear.synthetic.sqlite/linearcoverage/test/app/linear-other",
        "linear.synthetic.sqlite/otherlinear/test/app/linear-main",
    ] {
        ensure!(
            protected.contains_key(partition),
            "foreign partition omitted"
        );
    }
    fixture.require_protected(&protected)?;
    let own = serde_json::to_value(fixture.state()?)?;
    let result: Value = serde_json::from_str(&fixture.call_in(
        &fixture.foreign,
        Action::LinearSuspend,
        "alice",
        "foreign-change",
        "foreign-change",
        json!({"primary_email":SUBJECT}),
    )?)?;
    ensure!(
        result == json!({"Suspended":"user-alice"}),
        "foreign-write control failed"
    );
    ensure!(
        serde_json::to_value(fixture.state()?)? == own,
        "foreign write crossed scopes"
    );
    ensure!(
        fixture.require_protected(&protected).is_err(),
        "guard ignored actual foreign mutation"
    );
    Ok(())
}

#[test]
fn both_linear_actions_pass_the_same_admitted_common_gate() -> Result<()> {
    for action in [Action::LinearEnsureAccess, Action::LinearSuspend] {
        super::check(action, |variant| super::observe(action, variant))
            .map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

#[test]
fn actual_common_gate_rejects_constant_missing_landless_and_wrong_world_substitutes() -> Result<()>
{
    for action in [Action::LinearEnsureAccess, Action::LinearSuspend] {
        super::check(action, |variant| observe(action, variant)).map_err(anyhow::Error::msg)?;
        assert!(super::check(action, |_| anyhow::bail!("missing adapter")).is_err());
        for mutation in 0..3 {
            assert!(
                super::check(action, |variant| {
                    let mut result = observe(action, variant)?;
                    match mutation {
                        0 => result.result = json!({"Active":"constant"}).to_string(),
                        1 => result.after = result.before.clone(),
                        _ => {
                            let own = Provider::SyntheticLinear.world().unwrap();
                            let changed = result.after[own].clone();
                            result.after.insert(own, result.before[own].clone());
                            result
                                .after
                                .insert(Provider::Snowflake.world().unwrap(), changed);
                        }
                    }
                    Ok(result)
                })
                .is_err()
            );
        }
    }
    Ok(())
}

#[test]
fn domain_handles_target_substitution_and_malformed_inputs_refuse_without_provider_calls()
-> Result<()> {
    let fixture = Fixture::new(world(true), 17)?;
    let before = serde_json::to_value(fixture.state()?)?;
    let protected = fixture.protected()?;
    for action in [Action::LinearEnsureAccess, Action::LinearSuspend] {
        forbidden(fixture.call(
            action,
            "alice",
            &format!("foreign-{}", action.capability()),
            "foreign",
            json!({"primary_email":"alice@foreign.test"}),
        ))?;
    }
    let (_, token) = bind(&fixture.foreign, "alice", "foreign-handle")?;
    forbidden(fixture.call(
        Action::LinearEnsureAccess,
        "alice",
        "wrong-scope",
        "wrong-scope",
        json!({"primary_email":SUBJECT,"handle":token["token"]}),
    ))?;
    let (_, token) = fixture.bind("alice", "handle-owner")?;
    forbidden(fixture.call(
        Action::LinearEnsureAccess,
        "bob",
        "wrong-owner",
        "wrong-owner",
        json!({"primary_email":SUBJECT,"handle":token["token"]}),
    ))?;
    for (index, input) in [
        json!({"primary_email":SUBJECT,"handle":"substituted"}),
        json!({"primary_email":SUBJECT,"organization_id":"linear-other"}),
        json!({"primary_email":""}),
        json!({"primary_email":"alice\n@linear.test"}),
    ]
    .into_iter()
    .enumerate()
    {
        ensure!(
            fixture
                .call(
                    Action::LinearEnsureAccess,
                    "alice",
                    &format!("malformed-{index}"),
                    "malformed",
                    input
                )
                .is_err(),
            "malformed Linear input admitted"
        );
    }
    ensure!(
        serde_json::to_value(fixture.state()?)? == before && fixture.protected()? == protected,
        "refused request changed provider state/history"
    );
    Ok(())
}

#[test]
fn resource_action_revocation_is_an_independent_ceiling() -> Result<()> {
    let fixture = Fixture::new(world(true), 19)?;
    let original = fixture.call(
        Action::LinearEnsureAccess,
        "alice",
        "admitted-original",
        "cached-original",
        json!({"primary_email":SUBJECT}),
    )?;
    ensure!(
        serde_json::from_str::<Value>(&original)? == json!({"Active":"user-alice"}),
        "revocation control baseline failed"
    );
    fixture.assert_budget_state(false)?;
    let before = fixture.state()?;
    let db = store::open(fixture.runtime.db())?;
    let current = crate::authority_state::current(&db)?;
    let path = fixture.runtime.instance_path();
    let mut instance: Value = serde_json::from_slice(&fs::read(path)?)?;
    instance["resources"]["policies"]["provision"]["slots"]["linear"]["actions"] =
        json!(["linear_suspend"]);
    fs::write(path, serde_json::to_vec(&instance)?)?;
    crate::authority_state::apply_desired(
        &fixture.runtime,
        &crate::authority_state::LocalOperator::assert_local("linear-test-operator")?,
        "remove-ensure",
        Some(current.stamp),
    )?;
    forbidden(fixture.call(
        Action::LinearEnsureAccess,
        "alice",
        "revoked",
        "revoked",
        json!({"primary_email":SUBJECT}),
    ))?;
    ensure!(
        fixture
            .call(
                Action::LinearEnsureAccess,
                "alice",
                "admitted-original",
                "cached-original",
                json!({"primary_email":SUBJECT})
            )
            .is_err(),
        "cached provider result bypassed current authority"
    );
    fixture.assert_budget_state(false)?;
    ensure!(
        serde_json::to_value(fixture.state()?)? == serde_json::to_value(before)?,
        "revocation changed provider state"
    );
    ensure!(
        fixture
            .call(
                Action::LinearSuspend,
                "alice",
                "still-suspends",
                "still-suspends",
                json!({"primary_email":SUBJECT})
            )
            .is_ok(),
        "unrelated action lost authority"
    );
    Ok(())
}

#[test]
fn definite_failure_is_cached_for_its_original_effect_and_new_intent_can_recover() -> Result<()> {
    let initial = world(true);
    let fixture = Fixture::new(initial.clone(), 29)?;
    let mut oracle = Oracle::new(&initial);
    let protected = fixture.protected()?;
    let fault = people::ScheduledFailure {
        capability: Action::LinearEnsureAccess.capability().into(),
        subject: "recover@linear.test".into(),
        remaining: 1,
        mode: people::FailureMode::Definite {
            code: "SyntheticTransient".into(),
            message: "synthetic provider refusal".into(),
            retryable: true,
        },
    };
    oracle.faults.push(fault.clone());
    people::schedule_failure(
        &fixture.runtime,
        people::SyntheticProvider::Linear,
        ORGANIZATION,
        &fault,
    )?;
    let failed = observed_step(
        &fixture,
        &mut oracle,
        Operation::Ensure,
        "failure",
        "failure",
        "recover@linear.test",
    )?;
    ensure!(
        outcome(&failed)? == "failed",
        "definite failure lost its semantic result"
    );
    let retry = observed_step(
        &fixture,
        &mut oracle,
        Operation::Ensure,
        "failure",
        "failure",
        "RECOVER@LINEAR.TEST",
    )?;
    ensure!(
        retry == failed,
        "retry re-executed a cached definite failure"
    );
    let recovered = observed_step(
        &fixture,
        &mut oracle,
        Operation::Ensure,
        "new-intent",
        "new-intent",
        "recover@linear.test",
    )?;
    ensure!(
        outcome(&recovered)? == "invited",
        "new explicit intent did not recover after definite failure"
    );
    fixture.require_protected(&protected)?;
    Ok(())
}

#[test]
fn lost_reply_same_effect_and_conflicting_payload_keep_the_real_ledger_contract() -> Result<()> {
    let fixture = Fixture::new(world(true), 23)?;
    let protected = fixture.protected()?;
    let first = fixture.call(
        Action::LinearEnsureAccess,
        "alice",
        "original",
        "stable",
        json!({"primary_email":"NEW@LINEAR.TEST"}),
    )?;
    let accepted = fixture.state()?;
    let second = fixture.call(
        Action::LinearEnsureAccess,
        "alice",
        "original",
        "stable",
        json!({"primary_email":"new@linear.test"}),
    )?;
    let duplicate = fixture.state()?;
    ensure!(
        first == second
            && accepted.world == duplicate.world
            && accepted.ledger == duplicate.ledger
            && duplicate
                .calls
                .last()
                .is_some_and(|c| c.replayed && !c.changed),
        "lost accepted reply repeated provider mutation"
    );
    fixture.assert_budget_state(false)?;
    let conflict = fixture.call(
        Action::LinearSuspend,
        "alice",
        "original",
        "stable",
        json!({"primary_email":"new@linear.test"}),
    );
    let Err(error) = conflict else {
        anyhow::bail!("conflicting effect reused provider result");
    };
    ensure!(
        error.to_string() == "people_provider_idempotency_conflict",
        "effect conflict refused at wrong boundary"
    );
    ensure!(
        serde_json::to_value(fixture.state()?)? == serde_json::to_value(duplicate)?,
        "conflict altered provider ledger/world"
    );
    fixture.assert_budget_state(true)?;
    quota_refusal(fixture.call(
        Action::LinearEnsureAccess,
        "alice",
        "quarantined",
        "quarantined",
        json!({"primary_email":SUBJECT}),
    ))?;
    fixture.require_protected(&protected)?;
    Ok(())
}

fn outcome(value: &Value) -> Result<&'static str> {
    if value == &json!("Disabled") {
        return Ok("disabled");
    }
    if value == &json!("NotFound") {
        return Ok("not_found");
    }
    for (key, name) in [
        ("Active", "active"),
        ("Reactivated", "reactivated"),
        ("PendingInvitation", "pending_invitation"),
        ("Invited", "invited"),
        ("Suspended", "suspended"),
        ("AlreadySuspended", "already_suspended"),
        ("Failed", "failed"),
    ] {
        if value.get(key).is_some() {
            return Ok(name);
        }
    }
    anyhow::bail!("unknown Linear semantic outcome")
}

fn observation(fixture: &Fixture, result: &Value, lost_reply: bool) -> Result<Value> {
    let state = fixture.state()?;
    let call = state.calls.last().context("actual Linear provider call")?;
    Ok(
        json!({"outcome":outcome(result)?,"replayed":call.replayed,"lost_reply":lost_reply,
        "state":crate::digest(&serde_json::to_vec(&state)?)}),
    )
}

fn history(seed: u64) -> Result<Vec<Value>> {
    let initial = world(!seed.is_multiple_of(4));
    let fixture = Fixture::new(initial.clone(), seed)?;
    let protected = fixture.protected()?;
    let mut oracle = Oracle::new(&initial);
    let mut observed = Vec::new();
    // Witness every ordinary/no-op outcome, then compose seeded interleavings.
    let prefix = [
        (Operation::Ensure, SUBJECT),
        (Operation::Ensure, "bob@linear.test"),
        (Operation::Ensure, "pending@linear.test"),
        (Operation::Ensure, "new@linear.test"),
        (Operation::Suspend, SUBJECT),
        (Operation::Suspend, SUBJECT),
        (Operation::Suspend, "missing@linear.test"),
        (Operation::Ensure, "bob@linear.test"),
    ];
    for (index, (operation, email)) in prefix.into_iter().enumerate() {
        let id = format!("prefix-{seed}-{index}");
        let result = observed_step(&fixture, &mut oracle, operation, &id, &id, email)?;
        fixture.require_protected(&protected)?;
        observed.push(observation(&fixture, &result, false)?);
    }
    let mut random = seed;
    for index in 0..24 {
        random = random
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let choice = (random >> 32) % 6;
        let id = format!("generated-{seed}-{index}");
        if choice == 5 {
            forbidden(fixture.call(
                Action::LinearEnsureAccess,
                "alice",
                &id,
                &id,
                json!({"primary_email":"outside@foreign.test"}),
            ))?;
            ensure!(
                serde_json::to_value(fixture.state()?)? == oracle.snapshot(),
                "domain refusal changed Linear history"
            );
            fixture.assert_budget_state(false)?;
            observed.push(json!({"outcome":"domain_refused","replayed":false,"lost_reply":false}));
        } else {
            let (operation, effect, invocation, email) = if choice == 2 {
                let prior = oracle.entries[(random as usize) % oracle.entries.len()].clone();
                (prior.operation, prior.effect, prior.invocation, prior.email)
            } else {
                let operation = if choice == 1 {
                    Operation::Suspend
                } else {
                    Operation::Ensure
                };
                let email = if choice == 4 {
                    format!("fault-{seed}-{index}@linear.test")
                } else {
                    [
                        SUBJECT,
                        "bob@linear.test",
                        "pending@linear.test",
                        "new@linear.test",
                        "missing@linear.test",
                    ][(random as usize) % 5]
                        .into()
                };
                (operation, id.clone(), id.clone(), email)
            };
            if choice == 4 {
                let failure = people::ScheduledFailure {
                    capability: operation.action().capability().into(),
                    subject: email.clone(),
                    remaining: 1,
                    mode: people::FailureMode::Definite {
                        code: "SyntheticTransient".into(),
                        message: "synthetic provider refusal".into(),
                        retryable: true,
                    },
                };
                oracle.faults.push(failure.clone());
                people::schedule_failure(
                    &fixture.runtime,
                    people::SyntheticProvider::Linear,
                    ORGANIZATION,
                    &failure,
                )?;
                ensure!(
                    serde_json::to_value(fixture.state()?)? == oracle.snapshot(),
                    "fault setup changed business state"
                );
            }
            let result = observed_step(
                &fixture,
                &mut oracle,
                operation,
                &effect,
                &invocation,
                &email,
            )?;
            if choice == 3 {
                // Discard the reply, preserve the original effect/invocation,
                // and authorize a fresh attempt through the same real path.
                let replay = observed_step(
                    &fixture,
                    &mut oracle,
                    operation,
                    &effect,
                    &invocation,
                    &email,
                )?;
                ensure!(
                    replay == result,
                    "lost Linear reply changed the terminal result"
                );
            }
            observed.push(observation(&fixture, &result, choice == 3)?);
        }
        fixture.require_protected(&protected)?;
    }
    // A substituted payload is an error, not a fresh effect or a free quote.
    let first = oracle
        .entries
        .first()
        .context("original Linear request")?
        .clone();
    let conflict = fixture.call(
        Action::LinearSuspend,
        "alice",
        &first.invocation,
        &first.effect,
        json!({"primary_email":"substituted@linear.test"}),
    );
    let Err(error) = conflict else {
        anyhow::bail!("substituted Linear effect admitted");
    };
    ensure!(
        error.to_string() == "people_provider_idempotency_conflict",
        "Linear conflict refused at wrong boundary"
    );
    fixture.assert_budget_state(true)?;
    ensure!(
        serde_json::to_value(fixture.state()?)? == oracle.snapshot(),
        "conflict changed the complete Linear store"
    );
    observed
        .push(json!({"outcome":"payload_conflict_refused","replayed":false,"lost_reply":false}));
    quota_refusal(fixture.call(
        Action::LinearEnsureAccess,
        "alice",
        "quarantined",
        "quarantined",
        json!({"primary_email":SUBJECT}),
    ))?;
    fixture.assert_budget_state(true)?;
    ensure!(
        serde_json::to_value(fixture.state()?)? == oracle.snapshot(),
        "quarantined call changed provider state"
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
    crate::digest(include_bytes!("linear_coverage_tests.rs"))
}

fn checked_history(seed: u64) -> Result<Vec<Value>> {
    let result = (|| {
        let first = history(seed)?;
        ensure!(history(seed)? == first, "Linear history is not replayable");
        Ok(first)
    })();
    match result {
        Ok(observed) => Ok(observed),
        Err(error) => {
            let saved = (|| -> Result<()> {
                let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../artifacts/linear-provider-simulation");
                fs::create_dir_all(&root)?;
                let directory = tempfile::Builder::new()
                    .prefix("failure-")
                    .tempdir_in(root)?
                    .keep();
                fs::write(
                    directory.join("failure.json"),
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
                    .context("Linear replay retention failed"));
            }
            Err(error)
        }
    }
}

fn replay_seed(bytes: &[u8]) -> Result<u64> {
    ensure!(bytes.len() <= 4096, "Linear replay byte bound");
    let value: ReplaySeed = crate::json::decode(bytes)?;
    ensure!(
        value.format == 1 && value.campaign_source == campaign_source(),
        "Linear replay source or format differs"
    );
    Ok(value.seed)
}

#[test]
fn seeded_authorized_linear_histories_match_the_complete_independent_oracle_and_replay()
-> Result<()> {
    let mut counts = BTreeMap::<String, u64>::new();
    let mut seeds = Vec::new();
    for seed in 0..8 {
        let observed = checked_history(seed)?;
        ensure!(observed.len() == 34, "Linear campaign incomplete");
        for step in observed {
            let name = step["outcome"]
                .as_str()
                .context("observed Linear outcome")?;
            ensure!(
                [
                    "active",
                    "reactivated",
                    "pending_invitation",
                    "invited",
                    "suspended",
                    "already_suspended",
                    "not_found",
                    "disabled",
                    "failed",
                    "domain_refused",
                    "payload_conflict_refused",
                    "unknown_usage_quarantines_budget"
                ]
                .contains(&name),
                "unknown observed Linear outcome"
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
        seeds == (0..8).collect::<Vec<_>>()
            && counts.len() == 14
            && counts.values().all(|n| *n > 0),
        "declared Linear campaign/outcome family did not run"
    );
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/linear-provider-simulation");
    fs::create_dir_all(&root)?;
    let directory = tempfile::Builder::new()
        .prefix("campaign-")
        .tempdir_in(root)?
        .keep();
    fs::write(
        directory.join("receipt.json"),
        serde_json::to_vec_pretty(&json!({
            "format":1,"status":"passed","scope":"authorized_synthetic_linear_not_native_worker_or_live_linear",
            "campaign_source":campaign_source(),"seeds":seeds,"steps_per_history":34,"each_history_replayed":true,"observed_outcomes":counts,
        }))?,
    )?;
    Ok(())
}

#[test]
fn replay_schema_source_and_size_refuse_before_linear_dispatch() -> Result<()> {
    let mut value = json!({"format":1,"campaign_source":campaign_source(),"seed":3});
    ensure!(
        replay_seed(&serde_json::to_vec(&value)?)? == 3,
        "valid Linear replay refused"
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
fn replay_saved_linear_history() -> Result<()> {
    let Some(path) = std::env::var_os("DAY2_LINEAR_REPLAY") else {
        return Ok(());
    };
    use std::io::Read as _;
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    checked_history(replay_seed(&bytes)?)?;
    Ok(())
}
