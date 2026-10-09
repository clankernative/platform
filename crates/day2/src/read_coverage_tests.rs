//! Host-only tests using real acceptance, authority activation and SQLite
//! transactions. The supplied contract does not claim compiled Roc admission.
use super::*;
use crate::{
    authority::{ModelGrant, Rows},
    authority_state::{self, ActiveAuthority, ApplyAuthority, AuthorityDocument, LocalOperator},
    error::{Failure, classify},
};
use rusqlite::TransactionBehavior;
use std::collections::BTreeMap;

struct Fixture {
    _directory: tempfile::TempDir,
    runtime: Runtime,
}

impl Fixture {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let artifact_directory = directory.path().join("host-contract");
        fs::create_dir(&artifact_directory)?;
        let state = directory.path().join(".state");
        fs::create_dir(&state)?;
        let instance_path = directory.path().join("instance.json");
        let mut operation_contracts = BTreeMap::new();
        let mut policies = BTreeMap::new();
        let mut operations = Vec::new();
        for (name, kind, required) in [
            ("guarded_write", "command", vec!["items", "fences"]),
            ("guarded_read", "query", vec!["items", "fences"]),
            ("plain_write", "command", vec![]),
        ] {
            operation_contracts.insert(
                name,
                json!({
                    "intent":{
                        "target":{"operation":name,"input_type":"input","output_type":"output"},
                        "title":name,"usage":{"purpose":"Host authority conformance","use_when":[],
                            "avoid_when":[],"preconditions":[],"effects":[],"result":"Checked result"},
                        "input_sources":[],"follow_ups":[]
                    },
                    "request_example":"{}","response_example":"{}","deprecated":false,
                    "execution":{"model":"","id_field":"","version_field":"","effects":[]},
                    "errors":[],"required_all_rows":required
                }),
            );
            let grant = json!({"read":true,"create":false,
                "update_fields":if kind == "command" { vec!["status"] } else { vec![] },
                "rows":{"kind":"all"}});
            policies.insert(
                name,
                json!({"actors":["alice","bob","admin"],
                    "mode":{"kind":if kind == "query" {"read"} else {"current_state"}},
                    "models":{"items":grant,"fences":grant},
                    "commands":if name == "plain_write" {vec!["guarded_write"]} else {vec![]}}),
            );
            operations
                .push(json!({"name":name,"kind":kind,"input_type":"input","output_type":"output"}));
        }
        let policy = json!({"version":1,"admins":["admin"],"operations":policies});
        fs::write(
            &instance_path,
            serde_json::to_vec(&json!({
                "installation":"coverage","environment":"test",
                "apps":{"app":{"artifact":artifact_directory,"readers":["alice","bob","admin"],
                    "writers":["alice","bob","admin"],"authority":policy}}
            }))?,
        )?;
        let model = json!({"fields":{"owner":"text","status":"text"}});
        let contract = serde_json::from_value(json!({
            "format":crate::artifact::CURRENT_FORMAT,"roc_version":"host-test","worker_digest":"host-test",
            "schema_digest":"host-test","schema":{"models":{"items":model,"fences":model},
                "inputs":{"input":{"fields":{}}},"foreign_keys":[]},
            "operations":operations,"sources":{
                "compiler/roc":crate::digest(b"synthetic compiler evidence"),
                "crates/day2/src/admission.rs":crate::digest(b"synthetic admission evidence"),
                "sdk/main.roc":crate::digest(b"synthetic pure worker evidence"),
                "sdk/contracts/Resource.roc":crate::digest(b"synthetic resource evidence")
            },"admission":"local-spike-only",
            "pages":[{"name":"overview","title":"Overview","operation":"guarded_read","defaults":"{}"}],
            "app_contract":{"operations":operation_contracts,"presentation":{"stylesheet":"","script":""},
                "identities":"","invariants":{},"domains":{},"errors":{}}
        }))?;
        let inputs = crate::host_inputs::Inputs::default();
        let runtime = Runtime {
            integrations: Arc::new(crate::integration_host::Host::local(&instance_path)?),
            app_calls: None,
            credentials: None,
            instance_path,
            app: "app".into(),
            db: state.join("app.sqlite"),
            scope: "coverage/test/app".into(),
            hosted_domain: None,
            artifact: Arc::new(LoadedArtifact::from_contract_for_tests(
                "read-coverage-host-test".into(),
                artifact_directory,
                contract,
            )),
            host: Arc::new(crate::host::System(inputs.clone())),
            inputs,
        };
        runtime.initialize()?;
        let db = open(runtime.db())?;
        db.execute("INSERT INTO items(id,version,created_at,owner,status) VALUES(1,1,100,'alice','Applying')", [])?;
        db.execute("INSERT INTO fences(id,version,created_at,owner,status) VALUES(1,1,100,'alice','Pending')", [])?;
        Ok(Self {
            _directory: directory,
            runtime,
        })
    }

    fn active(&self) -> Result<ActiveAuthority> {
        authority_state::current(&open(self.runtime.db())?)
    }

    fn activate(&self, document: AuthorityDocument, request: &str) -> Result<ActiveAuthority> {
        let previous = self.active()?;
        // The full activation path validates and atomically publishes the policy.
        let receipt = authority_state::apply(
            &self.runtime,
            &LocalOperator::assert_local("operator")?,
            &ApplyAuthority {
                request_id: request.into(),
                expected: Some(previous.stamp.clone()),
                document,
            },
        )?;
        let current = self.active()?;
        assert_eq!(current.stamp, receipt.stamp);
        assert_eq!(current.stamp.epoch, previous.stamp.epoch);
        assert_eq!(current.stamp.revision, previous.stamp.revision + 1);
        Ok(current)
    }

    fn assert_unmodified_business(&self) -> Result<()> {
        let db = open(self.runtime.db())?;
        for (model, expected) in [("items", "Applying"), ("fences", "Pending")] {
            let row = get(
                &db,
                model,
                &self.runtime.artifact().contract().schema.models[model],
                Id::Legacy(1),
            )?;
            assert_eq!(row.version, 1);
            assert_eq!(row.created_at, 100);
            assert_eq!(
                serde_json::from_str::<Value>(&row.data)?,
                json!({"owner":"alice","status":expected})
            );
            let count: i64 = db.query_row(&format!("SELECT count(*) FROM {model}"), [], |row| {
                row.get(0)
            })?;
            assert_eq!(count, 1);
        }
        for table in [
            "day2_audit_changes",
            "day2_command_requests",
            "day2_external_effects",
            "day2_execution",
        ] {
            let count: i64 = db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
            assert_eq!(count, 0, "unexpected mutation in {table}");
        }
        Ok(())
    }

    fn assert_denied(
        &self,
        operation: &str,
        actor: &str,
        id: &str,
        expected: Failure,
    ) -> Result<()> {
        let before = self.active()?;
        let error = self
            .runtime
            .invoke(operation, actor, id, &json!({}), 100, Fault::None)
            .unwrap_err();
        assert_eq!(classify(&error), expected);
        assert_eq!(self.active()?, before);
        let db = open(self.runtime.db())?;
        let count: i64 = db.query_row(
            "SELECT count(*) FROM day2_invocations WHERE id=?1",
            [id],
            |row| row.get(0),
        )?;
        assert_eq!(count, 0, "a denied operation must never be accepted");
        let event: (String, String, String) = db.query_row(
            "SELECT kind,outcome,reason FROM day2_audit_events WHERE identity=?1 ORDER BY sequence DESC LIMIT 1",
            [id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(
            event,
            (
                "admission".into(),
                "rejected".into(),
                "authorization_rejected".into()
            )
        );
        self.assert_unmodified_business()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_input_clones_survive_nested_async_and_blocking_boundaries_without_leakage()
-> Result<()> {
    use crate::host_inputs::{
        Entropy, Inputs,
        simulation::{SeededEntropy, VirtualClock},
    };
    use std::sync::Mutex;
    let left = Fixture::new()?;
    let right = Fixture::new()?;
    let left_clock = Arc::new(VirtualClock(Mutex::new((
        Duration::from_secs(11),
        Duration::from_secs(3),
    ))));
    let right_clock = Arc::new(VirtualClock(Mutex::new((
        Duration::from_secs(22),
        Duration::from_secs(4),
    ))));
    let left = left.runtime.clone().with_inputs(Inputs {
        entropy: Arc::new(SeededEntropy::new(10)),
        clock: left_clock.clone(),
        ..Inputs::default()
    });
    let right = right.runtime.clone().with_inputs(Inputs {
        entropy: Arc::new(SeededEntropy::new(20)),
        clock: right_clock.clone(),
        ..Inputs::default()
    });
    let sample = |runtime: &Runtime| -> Result<(i64, Duration, [u8; 32])> {
        let mut secret = [0; 32];
        runtime.inputs().entropy.fill(&mut secret)?;
        Ok((runtime.host().now_ms()?, runtime.host().monotonic(), secret))
    };
    let first = sample(&left)?;
    let nested = sample(&right)?;
    let left_task = left.clone();
    let right_task = right.clone();
    let (after, other) = tokio::try_join!(
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            tokio::task::spawn_blocking(move || sample(&left_task)).await
        }),
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            tokio::task::spawn_blocking(move || sample(&right_task)).await
        }),
    )?;
    let after = after??;
    let other = other??;
    assert_eq!((first.0, first.1), (11000, Duration::from_secs(3)));
    assert_eq!((after.0, after.1), (first.0, first.1));
    assert_eq!((nested.0, nested.1), (22000, Duration::from_secs(4)));
    assert_eq!((other.0, other.1), (nested.0, nested.1));
    for (seed, observed) in [(10, [first.2, after.2]), (20, [nested.2, other.2])] {
        let reference = SeededEntropy::new(seed);
        for bytes in observed {
            let mut expected = [0; 32];
            reference.fill(&mut expected)?;
            assert_eq!(bytes, expected);
        }
    }
    right_clock.0.lock().unwrap().0 = Duration::from_secs(99);
    assert_eq!(right.host().now_ms()?, 99000);
    assert_eq!(left.host().now_ms()?, 11000);
    Ok(())
}

#[tokio::test]
async fn local_server_refuses_host_only_contract_before_drawing_runtime_secret_entropy()
-> Result<()> {
    use crate::host_inputs::{Entropy, Inputs};
    struct RefusingEntropy(AtomicUsize);
    impl Entropy for RefusingEntropy {
        fn fill(&self, _: &mut [u8]) -> Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            bail!("injected_secret_entropy_failure")
        }
    }
    let fixture = Fixture::new()?;
    let entropy = Arc::new(RefusingEntropy(AtomicUsize::new(0)));
    let runtime = fixture.runtime.clone().with_inputs(Inputs {
        entropy: entropy.clone(),
        ..Inputs::default()
    });
    // This fixture intentionally proves host guards, not native Roc admission.
    // Do not make it serve by weakening the complete application contract guard.
    let error = crate::web::LocalServer::bind(runtime.clone(), "alice", 0)
        .await
        .err()
        .context("host-only contract unexpectedly admitted")?;
    assert_eq!(
        error.to_string(),
        "every persistent model requires a verification obligation"
    );
    assert_eq!(entropy.0.load(Ordering::Relaxed), 0);
    let count: i64 =
        open(runtime.db())?
            .query_row("SELECT count(*) FROM day2_web_secret", [], |row| row.get(0))?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn fresh_runtime_id_seeds_are_scope_stable_and_simulation_clock_is_composed() -> Result<()> {
    let root = Path::new("/tmp/dst-platform-input-composition");
    fs::create_dir_all(root)?;
    let evidence = tempfile::Builder::new()
        .prefix("id-traces-")
        .tempdir_in(root)?
        .keep();
    let mut traces = Vec::new();
    for replay in 0..2 {
        let fixture = Fixture::new()?;
        let simulation = crate::simulation::Simulation::with_scripted_providers(
            fixture.runtime.clone(),
            [42; 32],
            7000,
        )?;
        let runtime = simulation.runtime();
        let path = evidence.join(format!("replay-{replay}.json"));
        fs::write(
            &path,
            serde_json::to_vec(
                &json!({"seed":vec![42; 32],"wall_ms":7000,"invocations":["one","two"]}),
            )?,
        )?;
        for id in if replay == 0 {
            ["one", "two"]
        } else {
            ["two", "one"]
        } {
            runtime.accept("guarded_read", "alice", id, &json!({}), 7)?;
        }
        let db = open(runtime.db())?;
        let seeds = db
            .prepare("SELECT invocation,seed FROM day2_id_seeds ORDER BY invocation")?
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(seeds.len(), 2);
        for (id, seed) in &seeds {
            assert_eq!(seed, &runtime.host().entropy(runtime.scope(), id)?.to_vec());
            assert_ne!(
                seed,
                &runtime.host().entropy("different/scope/app", id)?.to_vec()
            );
        }
        assert_ne!(seeds[0].1, seeds[1].1);
        let ids = seeds.iter().map(|(id, seed)| -> Result<Value> {
            let seed: [u8; 32] = seed.as_slice().try_into()?;
            Ok(json!({"invocation":id,"uuid":crate::identity::generate(&seed, 7000, "items", 0)?}))
        }).collect::<Result<Vec<_>>>()?;
        fs::write(
            &path,
            serde_json::to_vec(&json!({"seeds":seeds,"ids":ids}))?,
        )?;
        traces.push(json!({"seeds":seeds,"ids":ids}));
        let started = runtime.host().monotonic();
        simulation.set_time(9000)?;
        assert_eq!(runtime.inputs().clock.wall_time()?, Duration::from_secs(9));
        runtime.host().deadline(Phase::Decide, started)?;
        simulation.advance_monotonic(Duration::from_secs(15))?;
        assert_eq!(runtime.inputs().clock.monotonic(), Duration::from_secs(15));
        assert_eq!(
            classify(&runtime.host().deadline(Phase::Decide, started).unwrap_err()),
            Failure::TransactionDeadline
        );
        assert_eq!(runtime.host().now_ms()?, 9000);
    }
    assert_eq!(traces[0], traces[1], "{}", evidence.display());
    Ok(())
}

fn fence_grant<'a>(document: &'a mut AuthorityDocument, operation: &str) -> &'a mut ModelGrant {
    document
        .policy
        .as_mut()
        .unwrap()
        .operations
        .get_mut(operation)
        .unwrap()
        .models
        .get_mut("fences")
        .unwrap()
}

#[test]
fn mismatched_security_profile_blocks_app_and_audit_access_but_not_operator_revocation()
-> Result<()> {
    use crate::security_admission::{Containment, Requirements, platform_inventory_digest};
    let fixture = Fixture::new()?;
    fixture.runtime.authorize("plain_write", "admin")?;
    fixture.runtime.authorize_audit("admin")?;
    let mut document = fixture.active()?.document;
    document.security = Some(Requirements {
        version: 1,
        artifact: fixture.runtime.artifact().id().into(),
        platform_inventory: platform_inventory_digest(fixture.runtime.artifact())?,
        roc_version: fixture.runtime.artifact().contract().roc_version.clone(),
        containment: Containment::MacosSandboxV1 {
            supervisor: crate::digest(b"deliberately different supervisor binary"),
        },
    });
    let activated = fixture.activate(document, "pin-different-supervisor")?;
    for result in [
        fixture.runtime.authorize("plain_write", "admin"),
        fixture.runtime.authorize_audit("admin"),
        fixture.runtime.audit_events("admin", 0).map(|_| ()),
    ] {
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("security_runtime_mismatch")
                || error.contains("security_host_evidence_unavailable"),
            "unexpected denial: {error}"
        );
    }
    // Operator authority inspection and a narrower activation must remain
    // possible from an executable different from the approved app supervisor.
    assert_eq!(fixture.active()?, activated);
    let mut revoked = activated.document.clone();
    revoked.enabled = false;
    let current = fixture.activate(revoked, "operator-disable-incompatible-app")?;
    assert!(!current.document.enabled);
    assert_eq!(current.document.security, activated.document.security);
    fixture.assert_unmodified_business()
}

#[test]
fn required_all_rows_denies_scoped_missing_and_unreadable_models_before_app_execution() -> Result<()>
{
    for restriction in ["owner", "unreadable", "missing"] {
        let fixture = Fixture::new()?;
        let mut document = fixture.active()?.document;
        for operation in ["guarded_write", "guarded_read"] {
            match restriction {
                "owner" => {
                    fence_grant(&mut document, operation).rows = Rows::OwnerOrAdmin {
                        field: "owner".into(),
                    }
                }
                "unreadable" => {
                    let grant = fence_grant(&mut document, operation);
                    grant.read = false;
                    grant.update_fields.clear();
                }
                _ => {
                    document
                        .policy
                        .as_mut()
                        .unwrap()
                        .operations
                        .get_mut(operation)
                        .unwrap()
                        .models
                        .remove("fences");
                }
            }
        }
        // The first required model is still readable. The guard must check all
        // requirements, including a missing or unreadable second model.
        fixture.activate(document, "narrow")?;
        for operation in ["guarded_write", "guarded_read"] {
            fixture.assert_denied(
                operation,
                "bob",
                operation,
                Failure::RequiredAllRowsUnavailable,
            )?;
            if restriction == "owner" {
                fixture.runtime.accept(
                    operation,
                    "admin",
                    &format!("admin-{operation}"),
                    &json!({}),
                    100,
                )?;
            } else {
                fixture.assert_denied(
                    operation,
                    "admin",
                    &format!("admin-{operation}"),
                    Failure::RequiredAllRowsUnavailable,
                )?;
            }
        }
        let error = fixture
            .runtime
            .accept_route(
                "$page.overview",
                "bob",
                "page-denied",
                &json!({}),
                100,
                crate::audit::Trigger::Request,
            )
            .unwrap_err();
        assert_eq!(classify(&error), Failure::RequiredAllRowsUnavailable);
        if restriction == "owner" {
            fixture.runtime.accept_route(
                "$page.overview",
                "admin",
                "page-admin",
                &json!({}),
                100,
                crate::audit::Trigger::Request,
            )?;
        }
        // Operations without the prerequisite keep their ordinary permissions.
        fixture
            .runtime
            .accept("plain_write", "bob", "plain", &json!({}), 100)?;
        fixture.assert_unmodified_business()?;
    }
    Ok(())
}

#[test]
fn required_all_rows_policy_revocation_commits_and_regrant_never_revives_old_intents() -> Result<()>
{
    for restriction in [
        "owner",
        "unreadable",
        "missing",
        "actor",
        "membership",
        "disabled",
    ] {
        let fixture = Fixture::new()?;
        let original = fixture.active()?;
        fixture
            .runtime
            .accept("guarded_write", "bob", "old", &json!({}), 100)?;
        let mut narrowed = original.document.clone();
        match restriction {
            "owner" => {
                fence_grant(&mut narrowed, "guarded_write").rows = Rows::OwnerOrAdmin {
                    field: "owner".into(),
                }
            }
            "unreadable" => {
                let grant = fence_grant(&mut narrowed, "guarded_write");
                grant.read = false;
                grant.update_fields.clear();
            }
            "missing" => {
                narrowed
                    .policy
                    .as_mut()
                    .unwrap()
                    .operations
                    .get_mut("guarded_write")
                    .unwrap()
                    .models
                    .remove("fences");
            }
            "actor" => {
                narrowed
                    .policy
                    .as_mut()
                    .unwrap()
                    .operations
                    .get_mut("guarded_write")
                    .unwrap()
                    .actors
                    .clear();
            }
            "membership" => narrowed.writers.clear(),
            _ => narrowed.enabled = false,
        }
        let active = fixture.activate(narrowed, "revoke")?;
        let expected = if ["actor", "membership", "disabled"].contains(&restriction) {
            Failure::Forbidden
        } else {
            Failure::RequiredAllRowsUnavailable
        };
        fixture.assert_denied("guarded_write", "bob", "denied", expected)?;
        assert!(authority_state::is_blocked(
            &open(fixture.runtime.db())?,
            "old"
        )?);
        let blocked = fixture.runtime.execute("old", Fault::None)?;
        assert_eq!(blocked.status, "blocked");
        assert_eq!(blocked.error, "authority_policy_changed");
        let restored = fixture.activate(original.document, "regrant")?;
        assert_eq!(restored.stamp.revision, active.stamp.revision + 1);
        assert_eq!(
            fixture.runtime.execute("old", Fault::None)?.status,
            "blocked"
        );
        let mut db = open(fixture.runtime.db())?;
        let tx = db.transaction()?;
        let error = authority_state::require_invocation_in(
            &tx,
            &fixture.runtime,
            "old",
            "guarded_write",
            "bob",
        )
        .unwrap_err();
        assert_eq!(classify(&error), Failure::AuthorityPolicyChanged);
        assert_eq!(
            authority_state::invocation_stamp(&tx, "old")?,
            original.stamp
        );
        tx.commit()?;
        fixture
            .runtime
            .accept("guarded_write", "bob", "fresh", &json!({}), 100)?;
        fixture.assert_unmodified_business()?;
    }
    Ok(())
}

#[test]
fn required_all_rows_denies_child_request_and_rolls_back_prior_parent_write() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut document = fixture.active()?.document;
    fence_grant(&mut document, "guarded_write").rows = Rows::OwnerOrAdmin {
        field: "owner".into(),
    };
    fixture.activate(document, "scope-child")?;
    fixture
        .runtime
        .accept("plain_write", "bob", "parent", &json!({}), 100)?;
    let active = fixture.active()?;
    let mut db = open(fixture.runtime.db())?;
    {
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut origin = Request {
            operation: "plain_write".into(),
            input: "{}".into(),
            context: Context {
                authentication: "request".into(),
                caller: Vec::new(),
                authenticated: String::new(),
                delegation_rule: String::new(),
                invocation_id: "parent".into(),
                actor: "bob".into(),
                now: 100,
            },
            observations: vec![],
        };
        let update = Instruction {
            kind: "update".into(),
            model: "items".into(),
            id: Id::Legacy(1),
            expected_version: 1,
            data: json!({"owner":"alice","status":"Offboarded"}).to_string(),
            ..Instruction::default()
        };
        let result = effect(
            &tx,
            &fixture.runtime.artifact().contract().schema,
            &origin,
            &update,
            EffectContext {
                scope: fixture.runtime.scope(),
                policy: active.policy()?,
                operation: "plain_write",
                entropy: &crate::host_inputs::SecureEntropy,
            },
        )?;
        origin.observations.push(Observation {
            instruction: update,
            result,
            error: String::new(),
        });
        assert_eq!(
            get(
                &tx,
                "items",
                &fixture.runtime.artifact().contract().schema.models["items"],
                Id::Legacy(1)
            )?
            .version,
            2
        );
        let request = Instruction { kind: "request".into(), model: "items".into(), id: Id::Legacy(1),
            expected_version: 2, data: json!({"command":"guarded_write","input_type":"input","output_type":"output","payload":"{}"}).to_string(),
            ..Instruction::default() };
        let error = crate::invocations::request(
            &fixture.runtime,
            &tx,
            &origin,
            &request,
            active.policy()?,
            "plain_write",
        )
        .unwrap_err();
        assert_eq!(classify(&error), Failure::RequiredAllRowsUnavailable);
        // Drop the same business transaction, as the native command driver does.
    }
    fixture.assert_unmodified_business()?;
    assert_eq!(
        db.query_row("SELECT count(*) FROM day2_invocations", [], |row| row
            .get::<_, i64>(0))?,
        1
    );
    Ok(())
}

#[test]
fn required_all_rows_offline_replay_rejects_missing_or_incompatible_captured_authority()
-> Result<()> {
    let fixture = Fixture::new()?;
    let mut document = fixture.active()?.document;
    fence_grant(&mut document, "guarded_write").rows = Rows::OwnerOrAdmin {
        field: "owner".into(),
    };
    let mut trace = Trace {
        format: 2,
        artifact: fixture.runtime.artifact().id().into(),
        scope: fixture.runtime.scope().into(),
        request: Request {
            operation: "guarded_write".into(),
            input: "{}".into(),
            context: Context {
                authentication: "request".into(),
                caller: Vec::new(),
                authenticated: String::new(),
                delegation_rule: String::new(),
                invocation_id: "forged".into(),
                actor: "bob".into(),
                now: 100,
            },
            observations: vec![],
        },
        outcome: Outcome {
            status: "success".into(),
            result: json!({}),
            error: String::new(),
        },
        guard: Some(ExecutionGuard {
            policy: document.policy.unwrap(),
            authority: Some(fixture.active()?.stamp),
            precondition_row: None,
            error: String::new(),
        }),
    };
    assert_eq!(
        classify(&replay(fixture.runtime.artifact(), &trace).unwrap_err()),
        Failure::RequiredAllRowsUnavailable
    );
    trace.format = 1;
    trace.guard = None;
    assert_eq!(
        classify(&replay(fixture.runtime.artifact(), &trace).unwrap_err()),
        Failure::RequiredAllRowsUnavailable
    );
    fixture.assert_unmodified_business()
}
