//! The actual admitted local adapter, not a transport substitute. The fixture
//! supplies a contract because no Roc worker executes at this capability seam.
use super::{Action, Observed, Provider, Variant, fixture, seed, worlds};
use crate::{
    artifact::LoadedArtifact,
    capabilities,
    protocol::{Instruction, Request},
    store::{self, Runtime},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{cell::Cell, fs, sync::Arc, time::Duration};

const SCOPE: &str = "notificationcoverage/test/app";
const TOPIC: &str = "updates";
const NOW: i64 = 1_700_000_000;

pub(super) fn actor(variant: Variant) -> &'static str {
    match variant {
        Variant::A => "alice",
        Variant::B => "bob",
    }
}

fn starting_messages(variant: Variant) -> Vec<(String, capabilities::Message)> {
    let mut messages = Vec::new();
    for (index, (scope, actor, topic)) in [
        (SCOPE, "alice", TOPIC),
        (SCOPE, "bob", TOPIC),
        ("other/test/app", "alice", TOPIC),
        (SCOPE, "alice", "other"),
    ]
    .into_iter()
    .enumerate()
    {
        messages.push((
            format!("seed-{index}"),
            capabilities::Message {
                scope: scope.into(),
                actor: actor.into(),
                topic: topic.into(),
                body: "synthetic seed body".into(),
            },
        ));
    }
    if variant == Variant::B {
        messages.push((
            "seed-extra".into(),
            capabilities::Message {
                scope: SCOPE.into(),
                actor: "alice".into(),
                topic: TOPIC.into(),
                body: "synthetic extra body".into(),
            },
        ));
    }
    messages
}

fn accepted(effect: &str) -> Value {
    json!({"id":format!("msg_{}",&crate::digest(effect.as_bytes())[7..31]),"status":"accepted"})
}

struct Fixture {
    _directory: tempfile::TempDir,
    runtime: Runtime,
    attempts: Cell<u64>,
}

impl Fixture {
    fn new(variant: Variant, entropy_seed: u64) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let instance_path = directory.path().join("instance.json");
        let artifact_directory = directory.path().join("notification-contract");
        fs::create_dir(&artifact_directory)?;
        let database = directory.path().join("app.sqlite");
        let policy = json!({"version":1,"admins":[],"operations":{"run":{
            "actors":["alice","bob"],"mode":{"kind":"current_state"},"models":{},
            "observations":["notifications.recipient.v1","notifications.latest.v1"],
            "effects":["notifications.send.v1"]}}});
        let target =
            json!({"kind":"notification_mailbox","topics":{"kind":"only","topics":[TOPIC]}});
        let catalog = json!({"version":1,
            "connections":{"mail":{"revision":1,"provider":"local_notifications"}},
            "resources":{"mail":{"revision":1,"connection":{"id":"mail","revision":1},"target":target}},
            "policies":{"notify":{"revision":1,"owner":"it","actors":["alice","bob"],
                "allowed_apps":["app"],"max_duration_seconds":null,
                "slots":{"mail":{"kind":"notification_mailbox","allowed_resources":[{"id":"mail","revision":1}],
                    "actions":["notifications_resolve","notifications_latest","notifications_send"],
                    "limits":{"max_request_bytes":16384,"max_response_bytes":16384,"max_calls_per_invocation":8},
                    "budgets":[{"id":"mail","revision":1}]}}}},
            "budgets":{"mail":{"revision":1,"scope":"app","period_seconds":3600,
                "limits":{"calls":10000,"bytes":100000000,"concurrency":1}}}});
        let instance = json!({"installation":"notificationcoverage","environment":"test","resources":catalog,
            "control":{"version":1,"state_directory":directory.path().join("control"),
                "operators":["notification-test-operator"],
                "sources":{"repo":{"kind":"local_git","repository":directory.path().join("repo")}},
                "apps":{"app":{"source":"repo"}}},
            "apps":{"app":{"artifact":artifact_directory,"readers":["alice","bob"],"writers":["alice","bob"],
                "authority":policy,"resource_policies":[{"policy":{"id":"notify","revision":1},
                    "operation":"run","bindings":{"mail":{"id":"mail","revision":1}}}]}}});
        fs::write(&instance_path, serde_json::to_vec(&instance)?)?;
        let contract = serde_json::from_value(json!({
            "format":crate::artifact::CURRENT_FORMAT,"verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
            "roc_version":"notification-seam-test","worker_digest":"notification-seam-test","schema_digest":"notification-seam-test",
            "schema":{"models":{"items":{"fields":{"value":"text"}}},"inputs":{"input":{"fields":{}}},"foreign_keys":[]},
            "operations":[{"name":"run","kind":"command","input_type":"input","output_type":""}],
            "sources":{},"admission":"local-spike-only"}))?;
        let inputs = crate::host_inputs::Inputs {
            entropy: Arc::new(crate::host_inputs::simulation::SeededEntropy::new(
                entropy_seed,
            )),
            clock: Arc::new(crate::host_inputs::simulation::VirtualClock(
                std::sync::Mutex::new((Duration::from_secs(NOW as u64), Duration::ZERO)),
            )),
            ..Default::default()
        };
        let runtime = Runtime::from_artifact_for_tests(
            instance_path,
            "app".into(),
            database.clone(),
            LoadedArtifact::from_contract_for_tests(
                "notification-seam-test".into(),
                artifact_directory,
                contract,
            ),
        )?
        .with_integrations(crate::integration_host::Host::simulated(&database, SCOPE))
        .with_inputs(inputs);
        runtime.initialize()?;
        // Other provider worlds are independently visible to the same checker.
        seed(runtime.db(), super::SCOPE, &fixture(Variant::A))?;
        capabilities::with_world(&runtime, |world| {
            for (effect, message) in starting_messages(variant) {
                world.send(&effect, message)?;
            }
            Ok(json!({}))
        })?;
        Ok(Self {
            _directory: directory,
            runtime,
            attempts: Cell::new(0),
        })
    }

    fn bind(&self, actor: &str, invocation: &str) -> Result<(Request, Value)> {
        self.runtime
            .accept("run", actor, invocation, &json!({}), NOW)?;
        let mut connection = store::open(self.runtime.db())?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let request = Request {
            operation: "run".into(),
            input: "{}".into(),
            context: store::invocation_context(&tx, invocation)?,
            observations: vec![],
        };
        let bound = crate::resources::host_operation(
            &tx,
            &self.runtime,
            &request,
            &Instruction {
                kind: "observe".into(),
                model: crate::resources::BIND.into(),
                data: json!({"binding":"mail","invocation":invocation}).to_string(),
                ..Default::default()
            },
        )?
        .context("notification resource binding")?;
        let bound: Value = serde_json::from_str(&bound)?;
        tx.commit()?;
        Ok((request, bound))
    }

    fn call(
        &self,
        action: Action,
        actor: &str,
        invocation: &str,
        effect: &str,
        mut input: Value,
    ) -> Result<String> {
        let (request, bound) = self.bind(actor, invocation)?;
        let mut connection = store::open(self.runtime.db())?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if input.get("handle").is_none() {
            input["handle"] = bound["token"].clone();
        }
        let sequence = self.attempts.get();
        self.attempts.set(sequence + 1);
        let attempt = format!("attempt-{sequence}");
        let instruction = Instruction {
            kind: if action == Action::NotificationsSend {
                "external"
            } else {
                "observe"
            }
            .into(),
            model: action.capability().into(),
            data: input.to_string(),
            ..Default::default()
        };
        let active = crate::authority_state::current(&tx)?;
        let capability = capabilities::authorized(
            &tx,
            &self.runtime,
            &request,
            &instruction,
            active.policy()?,
            effect,
        )?;
        crate::resources::record_use(&tx, &attempt, capability.resource())?;
        let reservation = crate::resources::reserve_in(
            &tx,
            &self.runtime,
            &request,
            &instruction,
            &attempt,
            capability.resource(),
            capability.quote(),
        )?;
        let resource = capability.resource().clone();
        tx.commit()?;
        let outcome = if action == Action::NotificationsSend {
            capabilities::execute(&self.runtime, capability, effect, &attempt)
        } else {
            capabilities::observe(&self.runtime, capability, &attempt)
        };
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        crate::resources::settle_in(&tx, &reservation, outcome.usage)?;
        tx.commit()?;
        outcome.result.and_then(|result| {
            crate::resources::validate_result(&resource, &result)?;
            Ok(result)
        })
    }
}

pub(super) fn observe(action: Action, variant: Variant) -> Result<Observed> {
    ensure!(
        action.provider() == Provider::LocalNotifications,
        "notification action required"
    );
    let fixture = Fixture::new(variant, 42)?;
    let who = if action == Action::NotificationsResolve {
        actor(variant)
    } else {
        "alice"
    };
    let input = match action {
        Action::NotificationsResolve => json!({"actor":who}),
        Action::NotificationsLatest => json!({"topic":TOPIC}),
        Action::NotificationsSend => json!({"actor":who,"topic":TOPIC,"body":"new synthetic body"}),
        _ => anyhow::bail!("notification action required"),
    };
    let before = worlds(fixture.runtime.db())?;
    let result = fixture.call(action, who, "attribution", "attribution-effect", input)?;
    let after = worlds(fixture.runtime.db())?;
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
    let run =
        |variant| observe(variant).map_err(|_| "notification admitted adapter failed".to_owned());
    let first = run(Variant::A)?;
    let second = run(Variant::B)?;
    let own = Provider::LocalNotifications
        .world()
        .expect("declared notification world");
    let valid = match action {
        Action::NotificationsResolve => {
            let left: Value =
                serde_json::from_str(&first.result).map_err(|_| "notification result shape")?;
            let right: Value =
                serde_json::from_str(&second.result).map_err(|_| "notification result shape")?;
            left == json!({"actor":actor(Variant::A)})
                && right == json!({"actor":actor(Variant::B)})
                && first.changed().is_empty()
                && second.changed().is_empty()
        }
        Action::NotificationsLatest => {
            first.result != second.result
                && first.changed().is_empty()
                && second.changed().is_empty()
        }
        Action::NotificationsSend => {
            let expected = accepted("attribution-effect");
            let left: Value =
                serde_json::from_str(&first.result).map_err(|_| "notification result shape")?;
            let right: Value =
                serde_json::from_str(&second.result).map_err(|_| "notification result shape")?;
            first.changed() == vec![own]
                && second.changed() == vec![own]
                && left == expected
                && right == expected
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err("notification action failed actor/world/effect attribution".into())
    }
}

#[test]
fn all_notification_actions_use_the_same_admitted_gate() -> Result<()> {
    for action in [
        Action::NotificationsResolve,
        Action::NotificationsLatest,
        Action::NotificationsSend,
    ] {
        super::check(action, |variant| super::observe(action, variant))
            .map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

#[test]
fn actual_gate_refuses_constant_missing_mutating_and_wrong_world_substitutes() -> Result<()> {
    // A dead fixture is not a successful mutant rejection. Admit the exact real
    // baseline before any substitute is allowed to count as a negative control.
    for action in [
        Action::NotificationsResolve,
        Action::NotificationsLatest,
        Action::NotificationsSend,
    ] {
        super::check(action, |variant| observe(action, variant)).map_err(anyhow::Error::msg)?;
    }
    for action in [Action::NotificationsResolve, Action::NotificationsLatest] {
        assert!(
            super::check(action, |variant| {
                let mut result = observe(action, variant)?;
                result.result = json!({"actor":"alice"}).to_string();
                Ok(result)
            })
            .is_err()
        );
        assert!(super::check(action, |_| anyhow::bail!("missing adapter")).is_err());
    }
    assert!(
        super::check(Action::NotificationsSend, |variant| {
            let mut result = observe(Action::NotificationsSend, variant)?;
            result.after = result.before.clone();
            Ok(result)
        })
        .is_err()
    );
    assert!(
        super::check(Action::NotificationsSend, |variant| {
            let mut result = observe(Action::NotificationsSend, variant)?;
            let own = Provider::LocalNotifications.world().unwrap();
            let changed = result.after[own].clone();
            result.after.insert(own, result.before[own].clone());
            result
                .after
                .insert(Provider::Snowflake.world().unwrap(), changed);
            Ok(result)
        })
        .is_err()
    );
    assert!(
        super::check(Action::NotificationsLatest, |variant| {
            let mut result = observe(Action::NotificationsLatest, variant)?;
            result.after.insert(
                Provider::Snowflake.world().unwrap(),
                Some("wrong world".into()),
            );
            Ok(result)
        })
        .is_err()
    );
    Ok(())
}

#[test]
fn other_actors_and_topics_are_refused_before_mailbox_mutation() -> Result<()> {
    let fixture = Fixture::new(Variant::A, 7)?;
    let before = worlds(fixture.runtime.db())?;
    for (index, (action, input)) in [
        (Action::NotificationsResolve, json!({"actor":"bob"})),
        (
            Action::NotificationsSend,
            json!({"actor":"bob","topic":TOPIC,"body":"impersonated"}),
        ),
        (Action::NotificationsLatest, json!({"topic":"other"})),
        (
            Action::NotificationsSend,
            json!({"actor":"alice","topic":"other","body":"ungranted"}),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        ensure!(
            fixture
                .call(
                    action,
                    "alice",
                    &format!("refused-{index}"),
                    &format!("refused-effect-{index}"),
                    input
                )
                .is_err(),
            "notification authorization accepted substitution"
        );
        ensure!(
            worlds(fixture.runtime.db())? == before,
            "refusal mutated a provider world"
        );
    }
    Ok(())
}

#[test]
fn lost_reply_retry_and_conflicting_payload_use_the_persisted_provider_world() -> Result<()> {
    let fixture = Fixture::new(Variant::A, 11)?;
    let input = json!({"actor":"alice","topic":TOPIC,"body":"original synthetic body"});
    // Provider acceptance commits independently. Deliberately discard its first
    // reply, then authorize another attempt of the same original effect.
    let accepted = fixture.call(
        Action::NotificationsSend,
        "alice",
        "retry-origin",
        "stable-effect",
        input.clone(),
    )?;
    let committed = worlds(fixture.runtime.db())?;
    let reply = fixture.call(
        Action::NotificationsSend,
        "alice",
        "retry-origin",
        "stable-effect",
        input,
    )?;
    ensure!(
        reply == accepted && worlds(fixture.runtime.db())? == committed,
        "duplicate changed provider acceptance"
    );
    ensure!(
        fixture
            .call(
                Action::NotificationsSend,
                "alice",
                "retry-origin",
                "stable-effect",
                json!({"actor":"alice","topic":TOPIC,"body":"conflicting body"})
            )
            .is_err(),
        "same effect accepted substituted payload"
    );
    ensure!(
        worlds(fixture.runtime.db())? == committed,
        "conflicting retry changed provider world"
    );
    let result: Value = serde_json::from_str(&fixture.call(
        Action::NotificationsLatest,
        "alice",
        "read-original",
        "read-effect",
        json!({"topic":TOPIC}),
    )?)?;
    let accepted: Value = serde_json::from_str(&accepted)?;
    ensure!(
        result["id"] == accepted["id"] && result["count"] == 2,
        "latest lost original acceptance or crossed actor/scope/topic"
    );
    Ok(())
}

#[test]
fn foreign_handles_and_malformed_inputs_cannot_reach_the_mailbox() -> Result<()> {
    let fixture = Fixture::new(Variant::A, 13)?;
    let (_, bound) = fixture.bind("alice", "original-handle")?;
    let before = worlds(fixture.runtime.db())?;
    for (index, (action, who, input)) in [
        (
            Action::NotificationsResolve,
            "bob",
            json!({"actor":"bob","handle":bound["token"]}),
        ),
        (
            Action::NotificationsResolve,
            "alice",
            json!({"actor":"alice","handle":"substituted"}),
        ),
        (
            Action::NotificationsResolve,
            "alice",
            json!({"actor":"alice","connection":"other"}),
        ),
        (Action::NotificationsLatest, "alice", json!({"topic":""})),
        (
            Action::NotificationsLatest,
            "alice",
            json!({"topic":"x".repeat(129)}),
        ),
        (
            Action::NotificationsSend,
            "alice",
            json!({"actor":"alice","topic":TOPIC,"body":"x".repeat(8001)}),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        ensure!(
            fixture
                .call(
                    action,
                    who,
                    &format!("bad-{index}"),
                    &format!("bad-effect-{index}"),
                    input
                )
                .is_err(),
            "invalid notification input admitted"
        );
        ensure!(
            worlds(fixture.runtime.db())? == before,
            "invalid input mutated a provider world"
        );
    }
    Ok(())
}

#[test]
fn current_resource_policy_rejects_send_even_when_operation_policy_allows_it() -> Result<()> {
    let fixture = Fixture::new(Variant::A, 17)?;
    let before = worlds(fixture.runtime.db())?;
    let db = store::open(fixture.runtime.db())?;
    let active = crate::authority_state::current(&db)?;
    let path = fixture.runtime.instance_path();
    let mut instance: Value = serde_json::from_slice(&fs::read(path)?)?;
    instance["resources"]["policies"]["notify"]["slots"]["mail"]["actions"] =
        json!(["notifications_resolve", "notifications_latest"]);
    fs::write(path, serde_json::to_vec(&instance)?)?;
    crate::authority_state::apply_desired(
        &fixture.runtime,
        &crate::authority_state::LocalOperator::assert_local("notification-test-operator")?,
        "remove-notification-send",
        Some(active.stamp),
    )?;
    ensure!(
        fixture
            .call(
                Action::NotificationsSend,
                "alice",
                "revoked",
                "revoked-effect",
                json!({"actor":"alice","topic":TOPIC,"body":"denied"})
            )
            .is_err(),
        "missing resource action was ignored"
    );
    ensure!(
        worlds(fixture.runtime.db())? == before,
        "resource refusal mutated provider state"
    );
    ensure!(
        fixture
            .call(
                Action::NotificationsResolve,
                "alice",
                "still-resolves",
                "resolve-effect",
                json!({"actor":"alice"})
            )
            .is_ok(),
        "unrelated read action was removed"
    );
    Ok(())
}

/// Independent representation: accepted requests in order, not the provider's
/// map plus delivery index. No provider transition/read implementation is used.
struct MailboxOracle(Vec<(String, capabilities::Message)>);

impl MailboxOracle {
    fn send(&mut self, effect: &str, message: capabilities::Message) -> bool {
        match self.0.iter().find(|(id, _)| id == effect) {
            Some((_, original)) => original == &message,
            None => {
                self.0.push((effect.into(), message));
                true
            }
        }
    }

    fn latest(&self) -> Value {
        let matching = self
            .0
            .iter()
            .filter(|(_, m)| m.scope == SCOPE && m.actor == "alice" && m.topic == TOPIC)
            .collect::<Vec<_>>();
        match matching.last() {
            Some((effect, _)) => {
                let mut result = accepted(effect);
                result["count"] = json!(matching.len());
                result
            }
            None => json!({"id":"","status":"none","count":0}),
        }
    }

    fn complete_state(&self) -> Value {
        json!({"messages":self.0.iter().cloned().collect::<std::collections::BTreeMap<_,_>>(),"order":self.0.iter().map(|(id,_)|id).collect::<Vec<_>>()})
    }
}

fn history(seed: u64) -> Result<Vec<Value>> {
    let fixture = Fixture::new(Variant::A, seed)?;
    let mut oracle = MailboxOracle(starting_messages(Variant::A));
    let initial = worlds(fixture.runtime.db())?;
    let mut observed = Vec::new();
    let mut random = seed;
    let mut previous = None;
    for index in 0..24 {
        random = random
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let choice = if previous.is_none() {
            0
        } else {
            (random >> 32) % 7
        };
        let invocation = format!("history-{seed}-{index}");
        let mut lost_reply = false;
        let allowed = match choice {
            0 | 1 | 3 => {
                let effect = format!("history-effect-{seed}-{index}");
                let body = format!("synthetic-body-{}", random % 11);
                let input = json!({"actor":"alice","topic":TOPIC,"body":body});
                if choice == 3 {
                    let _ = fixture.call(
                        Action::NotificationsSend,
                        "alice",
                        &invocation,
                        &effect,
                        input.clone(),
                    )?;
                    lost_reply = true;
                }
                let result: Value = serde_json::from_str(&fixture.call(
                    Action::NotificationsSend,
                    "alice",
                    &invocation,
                    &effect,
                    input,
                )?)?;
                ensure!(
                    result == accepted(&effect),
                    "notification send response differs"
                );
                ensure!(
                    oracle.send(
                        &effect,
                        capabilities::Message {
                            scope: SCOPE.into(),
                            actor: "alice".into(),
                            topic: TOPIC.into(),
                            body: body.clone()
                        }
                    ),
                    "new request unexpectedly conflicted"
                );
                previous = Some((effect, body));
                true
            }
            2 | 4 => {
                let (effect, body) = previous.clone().context("prior accepted effect")?;
                let body = if choice == 4 {
                    format!("conflict-{body}")
                } else {
                    body
                };
                let expected = oracle.send(
                    &effect,
                    capabilities::Message {
                        scope: SCOPE.into(),
                        actor: "alice".into(),
                        topic: TOPIC.into(),
                        body: body.clone(),
                    },
                );
                let result = fixture.call(
                    Action::NotificationsSend,
                    "alice",
                    &invocation,
                    &effect,
                    json!({"actor":"alice","topic":TOPIC,"body":body}),
                );
                ensure!(
                    result.is_ok() == expected,
                    "notification idempotency differs"
                );
                match result {
                    Ok(value) => ensure!(
                        serde_json::from_str::<Value>(&value)? == accepted(&effect),
                        "duplicate receipt differs"
                    ),
                    Err(error) => ensure!(
                        error.to_string() == "notification_idempotency_conflict",
                        "conflict refused at the wrong boundary"
                    ),
                }
                expected
            }
            5 => {
                ensure!(
                    fixture
                        .call(
                            Action::NotificationsSend,
                            "alice",
                            &invocation,
                            "denied-actor",
                            json!({"actor":"bob","topic":TOPIC,"body":"denied"})
                        )
                        .is_err(),
                    "history impersonation accepted"
                );
                false
            }
            _ => {
                let result: Value = serde_json::from_str(&fixture.call(
                    Action::NotificationsLatest,
                    "alice",
                    &invocation,
                    "history-read",
                    json!({"topic":TOPIC}),
                )?)?;
                ensure!(
                    result == oracle.latest(),
                    "notification latest crossed scope/actor/topic or lost ordering"
                );
                true
            }
        };
        // Reopen the actual committed store and compare every row/message; do
        // not derive expectations from this readback or truncate the snapshot.
        let store = rusqlite::Connection::open_with_flags(
            fixture
                .runtime
                .db()
                .with_file_name(Provider::LocalNotifications.world().unwrap()),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let encoded: String = store.query_row(
            "SELECT state FROM notification_world WHERE id=1",
            [],
            |row| row.get(0),
        )?;
        ensure!(
            serde_json::from_str::<Value>(&encoded)? == oracle.complete_state(),
            "notification world diverged from independent accepted history"
        );
        let after = worlds(fixture.runtime.db())?;
        ensure!(
            initial
                .iter()
                .filter(|(name, _)| **name != Provider::LocalNotifications.world().unwrap())
                .all(|(name, state)| after.get(name) == Some(state)),
            "notification history changed another provider world"
        );
        observed.push(json!({"choice":choice,"accepted":allowed,"discarded_reply":lost_reply,"world":crate::digest(encoded.as_bytes())}));
    }
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
    crate::digest(include_bytes!("notifications_coverage_tests.rs"))
}

fn checked_history(seed: u64) -> Result<Vec<Value>> {
    let result = (|| {
        let first = history(seed)?;
        ensure!(
            history(seed)? == first,
            "notification history is not replayable"
        );
        Ok(first)
    })();
    match result {
        Ok(observed) => Ok(observed),
        Err(error) => {
            let saved = (|| -> Result<()> {
                let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../artifacts/notification-provider-simulation");
                fs::create_dir_all(&root)?;
                let directory = tempfile::Builder::new()
                    .prefix("failure-")
                    .tempdir_in(root)?
                    .keep();
                let bundle = ReplaySeed {
                    format: 1,
                    campaign_source: campaign_source(),
                    seed,
                };
                fs::write(directory.join("failure.json"), serde_json::to_vec(&bundle)?)?;
                Ok(())
            })();
            if let Err(retention) = saved {
                return Err(error
                    .context(retention)
                    .context("notification replay retention failed"));
            }
            Err(error)
        }
    }
}

fn replay_seed(bytes: &[u8]) -> Result<u64> {
    ensure!(bytes.len() <= 4096, "notification replay byte bound");
    let bundle: ReplaySeed = crate::json::decode(bytes)?;
    ensure!(
        bundle.format == 1 && bundle.campaign_source == campaign_source(),
        "notification replay campaign source differs"
    );
    Ok(bundle.seed)
}

#[test]
fn seeded_admitted_mailbox_histories_match_independent_oracle_and_replay() -> Result<()> {
    let mut seeds = Vec::new();
    let mut counts = std::collections::BTreeMap::<&str, u64>::new();
    for seed in 0..8 {
        let observed = checked_history(seed)?;
        ensure!(observed.len() == 24, "notification history incomplete");
        for step in observed {
            let accepted = step["accepted"]
                .as_bool()
                .context("observed notification acceptance")?;
            let category = match (step["choice"].as_u64(), accepted) {
                (Some(0 | 1 | 3), true) => "send_accepted",
                (Some(2), true) => "duplicate_accepted_once",
                (Some(4), false) => "conflicting_payload_refused",
                (Some(5), false) => "impersonation_refused",
                (Some(6), true) => "scoped_latest_read",
                _ => anyhow::bail!("unclassified observed notification step"),
            };
            *counts.entry(category).or_default() += 1;
            if step["discarded_reply"] == true {
                *counts
                    .entry("accepted_reply_discarded_and_retried")
                    .or_default() += 1;
            }
        }
        seeds.push(seed);
    }
    ensure!(
        seeds == (0..8).collect::<Vec<_>>() && counts.len() == 6 && counts.values().all(|n| *n > 0),
        "declared notification campaign/fault family did not run"
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/notification-provider-simulation");
    fs::create_dir_all(&root)?;
    let directory = tempfile::Builder::new()
        .prefix("campaign-")
        .tempdir_in(root)?
        .keep();
    fs::write(
        directory.join("receipt.json"),
        serde_json::to_vec_pretty(&json!({
            "format":1,"status":"passed","scope":"admitted_local_adapter_not_native_worker_or_live_provider",
            "campaign_source":campaign_source(),"seeds":seeds,"steps_per_history":24,"each_history_replayed":true,"observed_transitions":counts,
        }))?,
    )?;
    Ok(())
}

#[test]
fn replay_seed_schema_source_and_size_refuse_before_provider_execution() -> Result<()> {
    let mut value = json!({"format":1,"campaign_source":campaign_source(),"seed":3});
    ensure!(
        replay_seed(&serde_json::to_vec(&value)?)? == 3,
        "valid replay seed refused"
    );
    value["campaign_source"] = json!("changed");
    assert!(replay_seed(&serde_json::to_vec(&value)?).is_err());
    value["campaign_source"] = json!(campaign_source());
    value["private_body"] = json!("never admitted");
    assert!(replay_seed(&serde_json::to_vec(&value)?).is_err());
    assert!(replay_seed(&[b' '; 4097]).is_err());
    Ok(())
}

#[test]
fn replay_saved_notification_history() -> Result<()> {
    let Some(path) = std::env::var_os("DAY2_NOTIFICATIONS_REPLAY") else {
        return Ok(());
    };
    use std::io::Read as _;
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    checked_history(replay_seed(&bytes)?)?;
    Ok(())
}
