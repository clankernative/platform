//! Host-only conformance: real acceptance, opaque handles, authority transactions,
//! dispatch permits and SQLite settlement. The contract is supplied by the test;
//! these tests deliberately do not claim compiled Roc artifact admission.
use super::*;
use crate::{authority_state, execution, integration_host, integrations};
use day2_capabilities::{
    integrations::{LiveConnection, OpenAiText, SlackChannel},
    resources::{Action, ResourceTarget, VersionRef},
};
use rusqlite::TransactionBehavior;
use std::{
    collections::{BTreeMap, VecDeque},
    os::unix::fs::PermissionsExt,
    sync::{Mutex, atomic::AtomicU64},
};

struct Resolver;
impl integrations::CredentialResolver for Resolver {
    fn resolve(
        &self,
        _: &LiveConnection,
    ) -> std::result::Result<integrations::Credentials, integrations::AdapterError> {
        integrations::Credentials::bearer("test-secret".into())
    }
}

struct Provider {
    calls: AtomicU64,
    request_ids: Mutex<Vec<Option<String>>>,
    replies: Mutex<VecDeque<std::result::Result<Value, integrations::AdapterError>>>,
    database: Mutex<Option<PathBuf>>,
}

impl Provider {
    fn new(replies: Vec<std::result::Result<Value, integrations::AdapterError>>) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicU64::new(0),
            request_ids: Mutex::new(vec![]),
            replies: Mutex::new(replies.into()),
            database: Mutex::new(None),
        })
    }

    fn count(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl integrations::Transport for Provider {
    fn send(
        &self,
        request: &integrations::WireRequest,
        _: integrations::Authorization<'_>,
        _: u64,
    ) -> std::result::Result<integrations::WireResponse, integrations::TransportError> {
        // Provider I/O must happen after commit. An independent writer can take
        // the lock during every network request, including Slack's preflight.
        let path = self.database.lock().unwrap().clone().unwrap();
        let db = open(&path).unwrap();
        db.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.request_ids
            .lock()
            .unwrap()
            .push(request.client_request_id().map(str::to_owned));
        match self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected provider retry")
        {
            Ok(value) => Ok(integrations::WireResponse {
                status: 200,
                json_content_type: true,
                body: value.to_string().into_bytes(),
                request_id: Some("req_host_test".into()),
                metadata: vec![],
            }),
            Err(kind) => Err(integrations::TransportError {
                kind,
                response_bytes: 0,
                http_status: Some(200),
                request_id: Some("req_host_test".into()),
            }),
        }
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    runtime: Runtime,
    action: Action,
    live: LiveConnection,
}

impl Fixture {
    fn new(
        action: Action,
        max_calls: u64,
        budget_calls: u64,
        provider: Arc<Provider>,
    ) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("instance.json");
        let state = directory.path().join(".state");
        fs::create_dir_all(&state)?;
        let artifact_directory = directory.path().join("host-test-contract");
        fs::create_dir(&artifact_directory)?;
        let (live, target) = if matches!(
            action,
            Action::ObjectStoreGrantUpload | Action::ObjectStoreDelete
        ) {
            (
                LiveConnection::ObjectStore {
                    credential_ref: VersionRef {
                        id: "objects".into(),
                        revision: 1,
                    },
                    endpoint: "https://s3.example.com".into(),
                    region: "us-east-1".into(),
                    bucket: "evidence".into(),
                    access_key_id: "AKIAEXAMPLE".into(),
                },
                ResourceTarget::ObjectBucket {
                    bucket: "evidence".into(),
                    key_prefix: "uploads/".into(),
                },
            )
        } else if action == Action::SlackPost {
            (
                LiveConnection::Slack {
                    credential_ref: VersionRef {
                        id: "slack".into(),
                        revision: 1,
                    },
                    signing_secret_ref: None,
                    workspace_id: "T123".into(),
                },
                ResourceTarget::SlackChannel {
                    channel: SlackChannel {
                        channel_id: "C123".into(),
                    },
                },
            )
        } else {
            (
                LiveConnection::OpenAi {
                    credential_ref: VersionRef {
                        id: "openai".into(),
                        revision: 1,
                    },
                    project_id: "proj_test".into(),
                    organization_id: None,
                },
                ResourceTarget::OpenAiText {
                    profile: OpenAiText {
                        model: "model-snapshot".into(),
                        max_input_bytes: 1024,
                        max_input_tokens: 10,
                        max_output_tokens: 20,
                        input_nanos_per_token: 1000,
                        output_nanos_per_token: 1000,
                    },
                },
            )
        };
        let provider_name = match action {
            Action::ObjectStoreGrantUpload | Action::ObjectStoreDelete => "object_store",
            Action::SlackPost => "slack",
            _ => "open_ai",
        };
        let policy = json!({"version":1,"admins":[],"operations":{"run":{"actors":["alice","bob"],
            "mode":{"kind":"current_state"},"models":{},"observations":[],"effects":[action.capability()]}}});
        let limits = json!({"max_request_bytes":16_384,"max_response_bytes":16_384,"max_calls_per_invocation":max_calls});
        let catalog = json!({"version":1,"connections":{"connection":{"revision":1,"provider":provider_name,"live":live}},
            "resources":{"resource":{"revision":1,"connection":{"id":"connection","revision":1},"target":target}},
            "policies":{"policy":{"revision":1,"owner":"it","actors":["alice","bob"],"allowed_apps":["app"],"max_duration_seconds":null,
                "slots":{"resource":{"kind":target.kind(),"allowed_resources":[{"id":"resource","revision":1}],"actions":[action],"limits":limits,
                    "budgets":[{"id":"budget","revision":1}]}}}},
            "budgets":{"budget":{"revision":1,"scope":"app","period_seconds":3600,
                "limits":{"calls":budget_calls,"bytes":1_000_000,"cost_microunits":300,"concurrency":1}}}});
        let instance = json!({"installation":"integrationco","environment":"test","resources":catalog,
            "control":{"version":1,"state_directory":directory.path().join("control"),"operators":["it"],
                "sources":{"repo":{"kind":"local_git","repository":directory.path().join("repo")}},"apps":{"app":{"source":"repo"}}},
            "apps":{"app":{"artifact":artifact_directory,"readers":[],"writers":["alice","bob"],"authority":policy,
                "resource_policies":[{"policy":{"id":"policy","revision":1},"operation":"run","bindings":{"resource":{"id":"resource","revision":1}}}]}}});
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let contract = serde_json::from_value(
            json!({"format":crate::artifact::CURRENT_FORMAT,"verification_limits":crate::artifact::VerificationLimits::QUALIFIED,"roc_version":"host-test","worker_digest":"host-test",
            "schema_digest":"host-test","schema":{"models":{"items":{"fields":{"value":"text"}}},"inputs":{"input":{"fields":{}}},"foreign_keys":[]},
            "operations":[{"name":"run","kind":"command","input_type":"input","output_type":""}],"sources":{},"admission":"local-spike-only"}),
        )?;
        let inputs = crate::host_inputs::Inputs::default();
        let runtime = Runtime {
            integrations: Arc::new(integration_host::Host::local(&path)?),
            app_calls: None,
            credentials: None,
            connections: None,
            instance_path: path,
            app: "app".into(),
            db: state.join("app.sqlite"),
            scope: "integrationco/test/app".into(),
            hosted_domain: None,
            artifact: Arc::new(LoadedArtifact::from_contract_for_tests(
                "host-test".into(),
                artifact_directory,
                contract,
            )),
            host: Arc::new(crate::host::System(inputs.clone())),
            inputs,
        }
        .with_integrations(integration_host::Host::injected(
            Arc::new(Resolver),
            provider.clone(),
        ));
        // The scripted transport installed above is the subject of these tests,
        // so the campaign must run against it rather than the offline worlds.
        let runtime =
            crate::simulation::Simulation::with_scripted_providers(runtime, [17; 32], 100_000)?
                .runtime()
                .clone();
        *provider.database.lock().unwrap() = Some(runtime.db().to_path_buf());
        runtime.initialize()?;
        Ok(Self {
            directory,
            runtime,
            action,
            live,
        })
    }

    fn accept(&self, id: &str, actor: &str) -> Result<(Request, String)> {
        self.runtime.accept("run", actor, id, &json!({}), 100)?;
        let request = Request {
            operation: "run".into(),
            input: "{}".into(),
            context: Context {
                authentication: "request".into(),
                caller: Vec::new(),
                authenticated: String::new(),
                delegation_rule: String::new(),
                invocation_id: id.into(),
                actor: actor.into(),
                now: 100,
            },
            observations: vec![],
        };
        let mut db = open(self.runtime.db())?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let encoded = crate::resources::host_operation(
            &tx,
            &self.runtime,
            &request,
            &Instruction {
                kind: "observe".into(),
                model: crate::resources::BIND.into(),
                data: json!({"binding":"resource","invocation":id}).to_string(),
                ..Instruction::default()
            },
        )?
        .context("resource binding result")?;
        tx.commit()?;
        let token = serde_json::from_str::<Value>(&encoded)?["token"]
            .as_str()
            .unwrap()
            .to_owned();
        Ok((request, token))
    }

    fn intent(&self, request: Request, token: &str, ordinal: i64) -> Result<execution::Work> {
        let input = match self.action {
            Action::ObjectStoreGrantUpload | Action::ObjectStoreDelete => {
                json!({"handle":token,"key":"uploads/evidence.pdf"})
            }
            Action::SlackPost => json!({"handle":token,"text":"approved test message"}),
            _ => json!({"handle":token,"text":"approved test prompt","max_output_tokens":20}),
        };
        let instruction = Instruction {
            kind: "external".into(),
            model: self.action.capability().into(),
            data: input.to_string(),
            ..Instruction::default()
        };
        self.raw_intent(request, instruction, ordinal)
    }

    fn raw_intent(
        &self,
        request: Request,
        instruction: Instruction,
        ordinal: i64,
    ) -> Result<execution::Work> {
        let mut db = open(self.runtime.db())?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active = authority_state::current(&tx)?;
        let trace = Trace {
            format: 1,
            artifact: self.runtime.artifact().id().into(),
            scope: self.runtime.scope().into(),
            request,
            outcome: Outcome {
                status: "pending".into(),
                result: Value::Null,
                error: String::new(),
            },
            guard: Some(ExecutionGuard {
                policy: active.policy()?.clone(),
                authority: Some(active.stamp),
                precondition_row: None,
                error: String::new(),
            }),
        };
        let id = &trace.request.context.invocation_id;
        let identity = format!("effect-{id}-{ordinal}");
        tx.execute(
            "INSERT OR IGNORE INTO day2_execution VALUES(?1,'effects',?2)",
            params![id, serde_json::to_string(&trace)?],
        )?;
        tx.execute(
            "INSERT INTO day2_external_effects VALUES(?1,?2,?3,?4,NULL)",
            params![id, ordinal, identity, serde_json::to_string(&instruction)?],
        )?;
        tx.commit()?;
        Ok(execution::Work::from_intent_for_tests(
            &self.runtime,
            trace,
            instruction,
            ordinal,
            identity,
        ))
    }

    /// Register the signing secret a presign needs, the way an operator does.
    fn mount_signing_secret(&self) -> Result<()> {
        let file = self.directory.path().join("object-secret");
        fs::write(&file, b"SYNTHETIC_NEVER_EXPORT_OBJECT_SECRET")?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600))?;
        crate::integration_host::mount(
            self.runtime.instance_path(),
            "it",
            &crate::integration_host::Mount {
                connection: self.live.clone(),
                reference: None,
                credential_file: file,
                expected_fingerprint: None,
            },
        )?;
        Ok(())
    }

    /// The observation an effect settled with.
    fn observed(&self, invocation: &str, ordinal: i64) -> Result<Value> {
        let db = open(self.runtime.db())?;
        let observation: String = db.query_row(
            "SELECT observation FROM day2_external_effects WHERE invocation=?1 AND ordinal=?2",
            params![invocation, ordinal],
            |row| row.get(0),
        )?;
        let observation: Observation = serde_json::from_str(&observation)?;
        anyhow::ensure!(observation.error.is_empty(), "{}", observation.error);
        Ok(serde_json::from_str(&observation.result)?)
    }

    fn ledger(&self) -> Result<crate::budget::LedgerStatus> {
        let mut db = open(self.runtime.db())?;
        let tx = db.transaction()?;
        crate::budget::inspect_in(&tx)
    }

    fn complete(&self, work: &execution::Work) -> Result<()> {
        let permit = execution::admit_dispatch(&self.runtime, work)?;
        let result = execution::perform(&self.runtime, permit)?;
        execution::settle(&self.runtime, work, result)
    }
}

fn model_response(input: u64, output: u64) -> Value {
    json!({"model":"model-snapshot","object":"response","status":"completed","store":false,"background":false,"tools":[],"service_tier":"default",
        "output":[{"type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"result"}]}],
        "usage":{"input_tokens":input,"output_tokens":output,"total_tokens":input+output}})
}

#[test]
fn a_recorded_dispatch_reuses_its_observation_without_an_attempt_or_reservation() -> Result<()> {
    let provider = Provider::new(vec![Ok(model_response(3, 4))]);
    let fixture = Fixture::new(Action::OpenAiGenerate, 10, 10, provider.clone())?;
    let (request, token) = fixture.accept("recorded", "alice")?;
    let work = fixture.intent(request, &token, 0)?;
    fixture.complete(&work)?;
    let observed = fixture.observed("recorded", 0)?;
    let ledger = serde_json::to_value(fixture.ledger()?)?;

    fixture.complete(&work)?;

    assert_eq!(provider.count(), 1);
    assert_eq!(fixture.observed("recorded", 0)?, observed);
    assert_eq!(serde_json::to_value(fixture.ledger()?)?, ledger);
    let db = open(fixture.runtime.db())?;
    let attempts: i64 = db.query_row(
        "SELECT count(*) FROM day2_external_attempts WHERE effect='effect-recorded-0'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(attempts, 1);
    Ok(())
}

#[test]
fn host_live_unknown_attempt_survives_reopen_and_cannot_retry_or_spend_held_capacity() -> Result<()>
{
    let provider = Provider::new(vec![Err(integrations::AdapterError::TransportUnavailable)]);
    let fixture = Fixture::new(Action::OpenAiGenerate, 10, 10, provider.clone())?;
    let (request, token) = fixture.accept("unknown", "alice")?;
    let work = fixture.intent(request, &token, 0)?;
    let permit = execution::admit_dispatch(&fixture.runtime, &work)?;
    assert_eq!(fixture.ledger()?.outstanding_attempts, 1);
    let result = execution::perform(&fixture.runtime, permit)?;
    assert_eq!(provider.count(), 1);
    // Simulate losing the result before settlement: the actual persisted attempt
    // cannot be admitted a second time, even with a fresh executor connection.
    assert_eq!(
        execution::admit_dispatch(&fixture.runtime, &work)
            .err()
            .unwrap()
            .to_string(),
        "external_outcome_requires_reconciliation"
    );
    execution::settle(&fixture.runtime, &work, result)?;
    assert_eq!(
        provider.request_ids.lock().unwrap().as_slice(),
        &[Some("effect-unknown-0_attempt_1".into())]
    );
    let db = open(fixture.runtime.db())?;
    let encoded: String = db.query_row("SELECT exchanges FROM day2_resource_correlations WHERE attempt='effect-unknown-0_attempt_1'", [], |row| row.get(0))?;
    let exchanges: Value = serde_json::from_str(&encoded)?;
    assert_eq!(exchanges[0]["request_id"], "req_host_test");
    assert_eq!(exchanges[0]["http_status"], 200);
    assert!(
        db.execute("UPDATE day2_resource_correlations SET exchanges='[]'", [])
            .is_err()
    );
    assert!(
        db.execute("DELETE FROM day2_resource_correlations", [])
            .is_err()
    );
    let ledger = fixture.ledger()?;
    assert_eq!(ledger.outstanding_attempts, 1);
    assert!(
        ledger
            .accounts
            .iter()
            .any(|account| account.unit == "cost_microunits"
                && account.reserved == 30
                && account.used == 0)
    );
    let (request, token) = fixture.accept("later", "alice")?;
    let later = fixture.intent(request, &token, 0)?;
    assert!(execution::admit_dispatch(&fixture.runtime, &later).is_err());
    assert_eq!(provider.count(), 1);
    Ok(())
}

#[test]
fn host_live_usage_overrun_records_full_charge_and_freezes_next_dispatch() -> Result<()> {
    let provider = Provider::new(vec![Ok(model_response(15, 20))]);
    let fixture = Fixture::new(Action::OpenAiGenerate, 10, 10, provider.clone())?;
    let (request, token) = fixture.accept("overrun", "alice")?;
    fixture.complete(&fixture.intent(request, &token, 0)?)?;
    let ledger = fixture.ledger()?;
    assert!(ledger.frozen_after_overrun);
    assert_eq!(ledger.known_usage.cost_microunits, 35);
    assert_eq!(ledger.overruns.len(), 1);
    assert_eq!(ledger.overruns[0].quote.cost_microunits, 30);
    assert_eq!(ledger.overruns[0].actual.cost_microunits, 35);
    let (request, token) = fixture.accept("blocked", "alice")?;
    assert!(
        execution::admit_dispatch(&fixture.runtime, &fixture.intent(request, &token, 0)?).is_err()
    );
    assert_eq!(provider.count(), 1);
    Ok(())
}

#[test]
fn host_live_foreign_handles_and_caller_resource_overrides_never_reach_http() -> Result<()> {
    let provider = Provider::new(vec![]);
    let fixture = Fixture::new(Action::SlackPost, 10, 10, provider.clone())?;
    let (_, alice_token) = fixture.accept("alice-call", "alice")?;
    let (bob, _) = fixture.accept("bob-call", "bob")?;
    assert!(
        execution::admit_dispatch(&fixture.runtime, &fixture.intent(bob, &alice_token, 0)?)
            .is_err()
    );
    let (request, token) = fixture.accept("override", "alice")?;
    let instruction = Instruction {
        kind: "external".into(),
        model: "slack.post.v1".into(),
        data: json!({"handle":token,"text":"message","channel":"C999"}).to_string(),
        ..Instruction::default()
    };
    assert!(
        execution::admit_dispatch(
            &fixture.runtime,
            &fixture.raw_intent(request, instruction, 0)?
        )
        .is_err()
    );
    assert_eq!(provider.count(), 0);
    assert_eq!(fixture.ledger()?.outstanding_attempts, 0);

    let fixture = Fixture::new(Action::OpenAiGenerate, 10, 10, provider.clone())?;
    let db = open(fixture.runtime.db())?;
    let active = authority_state::current(&db)?;
    let mut document = active.document;
    let grant = document
        .resources
        .operations
        .get_mut("run")
        .unwrap()
        .get_mut("resource")
        .unwrap();
    grant.limits.max_request_bytes = 100_000;
    if let ResourceTarget::OpenAiText { profile } = &mut grant.target {
        profile.max_input_bytes = 30_000;
    }
    authority_state::apply(
        &fixture.runtime,
        &authority_state::LocalOperator::assert_local("it")?,
        &authority_state::ApplyAuthority {
            request_id: "large-instruction-profile".into(),
            expected: Some(active.stamp),
            document,
        },
    )?;
    let (request, token) = fixture.accept("large-instruction", "alice")?;
    let instruction = Instruction {
        kind: "external".into(),
        model: "openai.generate.v1".into(),
        data: json!({"handle":token,"text":"\"".repeat(20_000),"max_output_tokens":20}).to_string(),
        ..Instruction::default()
    };
    // The provider profile allows this input, but escaped instruction data
    // exceeds the tighter 16-KiB capability protocol ceiling before dispatch.
    assert!(instruction.data.len() < 65_536);
    assert!(instruction.data.len() > 16_384);
    let error = execution::admit_dispatch(
        &fixture.runtime,
        &fixture.raw_intent(request, instruction, 0)?,
    )
    .err()
    .expect("unjournalable instruction must be rejected before provider I/O");
    assert!(
        format!("{error:#}").contains("invalid_capability_instruction"),
        "unexpected admission rejection: {error:#}"
    );
    assert_eq!(provider.count(), 0);
    assert_eq!(fixture.ledger()?.outstanding_attempts, 0);
    Ok(())
}

#[test]
fn host_slack_reserves_and_counts_two_requests_against_each_ceiling() -> Result<()> {
    for (max_calls, budget_calls) in [(1, 10), (10, 1)] {
        let provider = Provider::new(vec![]);
        let fixture = Fixture::new(Action::SlackPost, max_calls, budget_calls, provider.clone())?;
        let (request, token) = fixture.accept("denied", "alice")?;
        assert!(
            execution::admit_dispatch(&fixture.runtime, &fixture.intent(request, &token, 0)?)
                .is_err()
        );
        assert_eq!(provider.count(), 0);
        assert_eq!(fixture.ledger()?.outstanding_attempts, 0);
        assert_eq!(
            open(fixture.runtime.db())?.query_row(
                "SELECT count(*) FROM day2_resource_uses",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
    }
    let provider = Provider::new(vec![
        Ok(json!({"ok":true,"team_id":"T123"})),
        Ok(json!({"ok":true,"channel":"C123","ts":"123.001"})),
    ]);
    let fixture = Fixture::new(Action::SlackPost, 2, 2, provider.clone())?;
    let (request, token) = fixture.accept("accepted", "alice")?;
    fixture.complete(&fixture.intent(request, &token, 0)?)?;
    assert_eq!(provider.count(), 2);
    assert_eq!(fixture.ledger()?.known_usage.calls, 2);
    assert_eq!(fixture.ledger()?.outstanding_attempts, 0);
    let (request, token) = fixture.accept("exhausted", "alice")?;
    assert!(
        execution::admit_dispatch(&fixture.runtime, &fixture.intent(request, &token, 0)?).is_err()
    );
    assert_eq!(provider.count(), 2);
    Ok(())
}

#[test]
fn mounted_credential_rotation_requires_new_version_and_active_binding() -> Result<()> {
    let provider = Provider::new(vec![Ok(model_response(5, 10))]);
    let mut fixture = Fixture::new(Action::OpenAiGenerate, 10, 10, provider.clone())?;
    let secret = fixture.directory.path().join("provider-token");
    fs::write(&secret, "old-secret")?;
    let mount = integration_host::Mount {
        connection: fixture.live.clone(),
        reference: None,
        credential_file: secret.clone(),
        expected_fingerprint: None,
    };
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o640))?;
    assert!(integration_host::mount(fixture.runtime.instance_path(), "it", &mount).is_err());
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600))?;
    let linked = fixture.directory.path().join("provider-link");
    std::os::unix::fs::symlink(&secret, &linked)?;
    assert!(
        integration_host::mount(
            fixture.runtime.instance_path(),
            "it",
            &integration_host::Mount {
                connection: fixture.live.clone(),
                reference: None,
                credential_file: linked,
                expected_fingerprint: None,
            }
        )
        .is_err()
    );
    integration_host::mount(fixture.runtime.instance_path(), "it", &mount)?;
    fs::write(&secret, "new-secret")?;
    assert!(integration_host::mount(fixture.runtime.instance_path(), "it", &mount).is_err());
    let mut rotated = fixture.live.clone();
    if let LiveConnection::OpenAi { credential_ref, .. } = &mut rotated {
        credential_ref.revision = 2;
    }
    integration_host::mount(
        fixture.runtime.instance_path(),
        "it",
        &integration_host::Mount {
            connection: rotated.clone(),
            reference: None,
            credential_file: secret,
            expected_fingerprint: None,
        },
    )?;
    // Production mounted resolver, injected transport only. A new mount does
    // not transfer the existing activated grant to the newly selected token.
    fixture.runtime =
        fixture
            .runtime
            .clone()
            .with_integrations(integration_host::Host::with_test_transport(
                fixture.runtime.instance_path(),
                provider.clone(),
            )?);
    let (request, token) = fixture.accept("old-binding", "alice")?;
    fixture.complete(&fixture.intent(request, &token, 0)?)?;
    assert_eq!(provider.count(), 0);
    assert_eq!(fixture.ledger()?.outstanding_attempts, 0);
    let db = open(fixture.runtime.db())?;
    let active = authority_state::current(&db)?;
    let mut document = active.document;
    document
        .resources
        .operations
        .get_mut("run")
        .unwrap()
        .get_mut("resource")
        .unwrap()
        .live = Some(rotated);
    authority_state::apply(
        &fixture.runtime,
        &authority_state::LocalOperator::assert_local("it")?,
        &authority_state::ApplyAuthority {
            request_id: "activate-rotated".into(),
            expected: Some(active.stamp),
            document,
        },
    )?;
    let (request, token) = fixture.accept("new-binding", "alice")?;
    fixture.complete(&fixture.intent(request, &token, 0)?)?;
    assert_eq!(provider.count(), 1);
    Ok(())
}

#[test]
fn host_large_model_output_settles_known_usage_and_records_a_small_failure() -> Result<()> {
    for content in ["plain".repeat(16_000), "\"\\".repeat(20_000)] {
        let mut response = model_response(5, 10);
        response["output"][0]["content"][0]["text"] = json!(content);
        let provider = Provider::new(vec![Ok(response)]);
        let fixture = Fixture::new(Action::OpenAiGenerate, 10, 10, provider.clone())?;
        let db = open(fixture.runtime.db())?;
        let active = authority_state::current(&db)?;
        let mut document = active.document;
        document
            .resources
            .operations
            .get_mut("run")
            .unwrap()
            .get_mut("resource")
            .unwrap()
            .limits
            .max_response_bytes = 200_000;
        authority_state::apply(
            &fixture.runtime,
            &authority_state::LocalOperator::assert_local("it")?,
            &authority_state::ApplyAuthority {
                request_id: "large-response-profile".into(),
                expected: Some(active.stamp),
                document,
            },
        )?;
        let (request, token) = fixture.accept("large-response", "alice")?;
        fixture.complete(&fixture.intent(request, &token, 0)?)?;
        assert_eq!(provider.count(), 1);
        let ledger = fixture.ledger()?;
        assert_eq!(ledger.outstanding_attempts, 0);
        assert_eq!(ledger.known_usage.cost_microunits, 15);
        let recorded: String =
            db.query_row("SELECT observation FROM day2_external_effects", [], |row| {
                row.get(0)
            })?;
        assert!(recorded.len() < 65_536);
        let observation: Observation = serde_json::from_str(&recorded)?;
        assert!(!observation.error.is_empty());
        assert!(observation.result.is_empty());
        let correlation: String = db.query_row(
            "SELECT exchanges FROM day2_resource_correlations",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            serde_json::from_str::<Value>(&correlation)?[0]["request_id"],
            "req_host_test"
        );
    }
    Ok(())
}

/// A Slack connection declaring both of its secrets.
fn slack_with_signing_secret() -> LiveConnection {
    LiveConnection::Slack {
        credential_ref: VersionRef {
            id: "slack-bot".into(),
            revision: 1,
        },
        signing_secret_ref: Some(VersionRef {
            id: "slack-signing".into(),
            revision: 1,
        }),
        workspace_id: "T123".into(),
    }
}

#[test]
fn every_declared_secret_is_enumerated_and_validated_not_only_the_first() -> Result<()> {
    let connection = slack_with_signing_secret();
    // Both refs are enumerated. This is what mounting and validation walk, and it
    // is why `credential_refs` forbids `..` when destructuring: with it, adding a
    // secret field would compile and the new secret would go unvalidated.
    let refs: Vec<_> = connection
        .credential_refs()
        .into_iter()
        .map(|reference| reference.id.as_str())
        .collect();
    assert_eq!(refs, ["slack-bot", "slack-signing"]);
    assert_eq!(
        connection.verification_ref().map(|r| r.id.as_str()),
        Some("slack-signing")
    );
    connection.validate()?;

    // A malformed signing reference is refused, which it would not be if
    // validation only ever looked at the outbound credential.
    let LiveConnection::Slack {
        credential_ref,
        workspace_id,
        ..
    } = connection
    else {
        unreachable!("constructed as Slack")
    };
    let invalid = LiveConnection::Slack {
        credential_ref,
        signing_secret_ref: Some(VersionRef {
            id: "slack-signing".into(),
            revision: 0,
        }),
        workspace_id,
    };
    assert!(invalid.validate().is_err(), "revision 0 was accepted");

    // A connection that accepts no deliveries has no such secret and says so.
    let outbound_only = LiveConnection::OpenAi {
        credential_ref: VersionRef {
            id: "openai".into(),
            revision: 1,
        },
        project_id: "proj_1".into(),
        organization_id: None,
    };
    assert!(outbound_only.verification_ref().is_none());
    assert_eq!(outbound_only.credential_refs().len(), 1);
    Ok(())
}

#[test]
fn a_mount_may_only_name_a_secret_its_connection_declares() -> Result<()> {
    let provider = Provider::new(vec![Ok(model_response(5, 10))]);
    let fixture = Fixture::new(Action::OpenAiGenerate, 10, 10, provider)?;
    let secret = fixture.directory.path().join("signing-secret");
    fs::write(&secret, "v0-signing-secret")?;
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600))?;

    // Naming a reference the connection never declares is refused: otherwise an
    // operator could install a secret under an identity nothing validated.
    let undeclared = integration_host::Mount {
        connection: slack_with_signing_secret(),
        reference: Some(VersionRef {
            id: "some-other-secret".into(),
            revision: 1,
        }),
        credential_file: secret.clone(),
        expected_fingerprint: None,
    };
    assert!(
        integration_host::mount(fixture.runtime.instance_path(), "it", &undeclared).is_err(),
        "an undeclared reference was mounted"
    );

    // The declared signing secret mounts under its own identity, separately from
    // the bot token, which is what lets one connection hold both.
    let declared = integration_host::Mount {
        connection: slack_with_signing_secret(),
        reference: Some(VersionRef {
            id: "slack-signing".into(),
            revision: 1,
        }),
        credential_file: secret,
        expected_fingerprint: None,
    };
    integration_host::mount(fixture.runtime.instance_path(), "it", &declared)?;
    Ok(())
}

#[test]
fn a_verification_key_resolves_separately_from_the_outbound_credential() -> Result<()> {
    let provider = Provider::new(vec![Ok(model_response(5, 10))]);
    let fixture = Fixture::new(Action::OpenAiGenerate, 10, 10, provider)?;
    let connection = slack_with_signing_secret();
    let mounts = integration_host::MountedCredentials::new(fixture.runtime.instance_path())?;

    // Nothing mounted yet: resolution fails rather than producing an empty key.
    assert!(mounts.verification_key(&connection).is_err());

    let secret = fixture.directory.path().join("signing-secret");
    fs::write(&secret, "v0-signing-secret")?;
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600))?;
    integration_host::mount(
        fixture.runtime.instance_path(),
        "it",
        &integration_host::Mount {
            connection: connection.clone(),
            reference: Some(VersionRef {
                id: "slack-signing".into(),
                revision: 1,
            }),
            credential_file: secret,
            expected_fingerprint: None,
        },
    )?;

    // Resolved by its own reference, and it is a LocalSecret rather than
    // Credentials, so it has no constructor that could place it in a header.
    let key = mounts.verification_key(&connection)?;
    assert_eq!(key.as_hmac_key(), "v0-signing-secret");

    // The outbound credential is a different secret entirely and is not mounted,
    // so resolving it fails even though verification succeeds.
    use crate::integrations::CredentialResolver;
    assert!(mounts.resolve(&connection).is_err());
    Ok(())
}

/// An application cannot name the object it uploads to, so it cannot overwrite.
///
/// The object-store half of the platform's deletion stance. Deletion is refused
/// outright (below), but refusing deletion alone would leave the easier way to
/// destroy bytes wide open: an upload aimed at a key that already holds an
/// object replaces it silently, with no version, no audit entry naming it as a
/// removal, and nothing to restore from. So the host chooses the object, and
/// overwriting stops being something to guard against and becomes something an
/// application cannot say.
#[test]
fn an_upload_lands_on_an_object_the_application_did_not_choose() -> Result<()> {
    let provider = Provider::new(vec![]);
    let fixture = Fixture::new(Action::ObjectStoreGrantUpload, 10, 10, provider.clone())?;
    fixture.mount_signing_secret()?;

    let (request, token) = fixture.accept("upload", "alice")?;
    let first = fixture.intent(request.clone(), &token, 0)?;
    fixture.complete(&first)?;
    let second = fixture.intent(request, &token, 1)?;
    fixture.complete(&second)?;

    let one = fixture.observed("upload", 0)?;
    let two = fixture.observed("upload", 1)?;
    let key = one["key"].as_str().context("key")?;
    let other = two["key"].as_str().context("key")?;

    assert_ne!(
        key, "uploads/evidence.pdf",
        "the application got back the key it asked for, so it can overwrite"
    );
    assert_ne!(key, other, "two uploads in one invocation share an object");
    assert!(
        key.starts_with("uploads/"),
        "{key} escaped the grant prefix"
    );
    assert!(key.ends_with("/evidence.pdf"), "{key} lost the file name");

    // The URL signs the object the application was told about; if it signed the
    // requested key instead, the key in the answer would be decoration.
    let url = one["url"].as_str().context("url")?;
    assert!(
        url.contains(key),
        "the signed URL does not name {key}: {url}"
    );
    assert!(
        url.starts_with("https://evidence.s3.example.com/uploads/"),
        "unexpected signed URL: {url}"
    );

    // Signing reaches no network: a grant is computed, not dispatched.
    assert_eq!(provider.count(), 0);
    Ok(())
}

/// A grant that names object deletion still cannot delete.
///
/// The policy here allows the capability — this is the case that matters. If
/// the refusal lived in the SDK alone, an artifact built before the rule, or a
/// future contract that reached the capability another way, would delete. The
/// choke point is the host, so the answer is the same whatever the app is.
#[test]
fn object_deletion_is_refused_to_an_application_that_was_granted_it() -> Result<()> {
    let provider = Provider::new(vec![]);
    let fixture = Fixture::new(Action::ObjectStoreDelete, 10, 10, provider.clone())?;
    fixture.mount_signing_secret()?;
    let (request, token) = fixture.accept("delete", "alice")?;
    let work = fixture.intent(request, &token, 0)?;

    let error = fixture
        .complete(&work)
        .expect_err("a destroying capability must be refused");
    assert_eq!(
        crate::error::observation_code(&error),
        "capability_forbidden",
        "unexpected refusal: {error:?}"
    );
    assert_eq!(provider.count(), 0, "the store was reached anyway");
    Ok(())
}

#[test]
fn provider_mode_is_independent_from_delegation_simulation_mode() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("instance.json");
    fs::create_dir_all(directory.path().join(".state"))?;
    fs::write(&path, b"{}")?;
    let local = integration_host::Host::local(&path)?;
    assert!(!local.is_simulated());
    assert!(!local.uses_simulated_providers());
    let injected = integration_host::Host::injected(Arc::new(Resolver), Provider::new(vec![]));
    assert!(!injected.is_simulated());
    assert!(!injected.uses_simulated_providers());
    let test_transport = integration_host::Host::with_test_transport(&path, Provider::new(vec![]))?;
    assert!(!test_transport.is_simulated());
    assert!(!test_transport.uses_simulated_providers());
    let simulated =
        integration_host::Host::simulated(&directory.path().join("app.sqlite"), "test/app");
    assert!(simulated.is_simulated());
    assert!(simulated.uses_simulated_providers());
    let hybrid = integration_host::Host::simulated_providers_with_app_calls(
        &directory.path().join("app.sqlite"),
        "test/app",
    );
    assert!(!hybrid.is_simulated());
    assert!(hybrid.uses_simulated_providers());
    Ok(())
}

#[test]
fn hybrid_qualification_keeps_workspace_directory_offline_through_admitted_capability() -> Result<()>
{
    const ACTOR: &str = "directory-reader@coverage.test";
    const NEWHIRE: &str = "newhire@coverage.test";
    const CONTRACTOR: &str = "contractor@partner.test";
    const CUSTOMER: &str = "Ccoverage";
    const SCOPE: &str = "hybridco/test/app";
    const NOW: i64 = 1_700_000_001;

    fn fixture_runtime(
        with_world: bool,
        with_user: bool,
        allow_hierarchy: bool,
        response_limit: u64,
    ) -> Result<(tempfile::TempDir, Runtime)> {
        fixture_runtime_in(with_world, with_user, allow_hierarchy, response_limit, None)
    }

    /// With a hosted domain, the resource policy names only `domain:D`, while
    /// membership and the operation also name `CONTRACTOR` from another domain.
    fn fixture_runtime_in(
        with_world: bool,
        with_user: bool,
        allow_hierarchy: bool,
        response_limit: u64,
        hosted_domain: Option<&str>,
    ) -> Result<(tempfile::TempDir, Runtime)> {
        let domain_entry = hosted_domain.map(|domain| format!("domain:{domain}"));
        let (members, granted) = match &domain_entry {
            Some(entry) => (
                vec![ACTOR.to_owned(), entry.clone(), CONTRACTOR.to_owned()],
                vec![entry.clone()],
            ),
            None => (vec![ACTOR.to_owned()], vec![ACTOR.to_owned()]),
        };
        let directory = tempfile::tempdir()?;
        let instance_path = directory.path().join("instance.json");
        let state = directory.path().join(".state");
        fs::create_dir_all(&state)?;
        let artifact_directory = directory.path().join("hybrid-directory-contract");
        fs::create_dir(&artifact_directory)?;
        let live = serde_json::to_value(LiveConnection::WorkspaceDirectory {
            service_account: "directory-reader@company.iam.gserviceaccount.com".into(),
            auth: day2_capabilities::integrations::WorkspaceDirectoryAuth::DirectServiceAccount,
        })?;
        let target = serde_json::to_value(ResourceTarget::WorkspaceDirectory {
            customer_id: CUSTOMER.into(),
        })?;
        let mut actions = vec![Action::WorkspaceDirectoryCapture];
        if allow_hierarchy {
            actions.push(Action::WorkspaceDirectoryHierarchy);
        }
        let observations: Vec<_> = actions.iter().map(|action| action.capability()).collect();
        let policy = json!({"version":1,"admins":[],"operations":{"run":{"actors":members,
            "mode":{"kind":"read"},"models":{},"observations":observations,"effects":[]}}});
        let catalog = json!({"version":1,
            "connections":{"directory":{"revision":1,"provider":"workspace_directory","live":live}},
            "resources":{"directory":{"revision":1,"connection":{"id":"directory","revision":1},"target":target}},
            "policies":{"directory_read":{"revision":1,"owner":"it","actors":granted,"allowed_apps":["app"],"max_duration_seconds":null,
                "slots":{"directory":{"kind":"workspace_directory","allowed_resources":[{"id":"directory","revision":1}],
                    "actions":actions,"limits":{"max_request_bytes":32768,"max_response_bytes":response_limit,"max_calls_per_invocation":5},
                    "budgets":[{"id":"directory_budget","revision":1}]}}}},
            "budgets":{"directory_budget":{"revision":1,"scope":"app","period_seconds":3600,
                "limits":{"calls":100,"bytes":10000000,"concurrency":1}}}});
        let mut instance = json!({"installation":"hybridco","environment":"test","resources":catalog,
            "apps":{"app":{"artifact":artifact_directory,"readers":members,"writers":members,"authority":policy,
                "resource_policies":[{"policy":{"id":"directory_read","revision":1},"operation":"run",
                    "bindings":{"directory":{"id":"directory","revision":1}}}]}}});
        if let Some(domain) = hosted_domain {
            instance["identity"] = json!({"scheme":"google_iap","hosted_domain":domain});
        }
        fs::write(&instance_path, serde_json::to_vec(&instance)?)?;
        let contract = serde_json::from_value(json!({
            "format":crate::artifact::CURRENT_FORMAT,"verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
            "roc_version":"hybrid-directory-test","worker_digest":"hybrid-directory-test","schema_digest":"hybrid-directory-test",
            "schema":{"models":{"items":{"fields":{"value":"text"}}},"inputs":{"input":{"fields":{}}},"foreign_keys":[]},
            "operations":[{"name":"run","kind":"query","input_type":"input","output_type":"output"}],
            "sources":{},"admission":"local-spike-only"}))?;
        let inputs = crate::host_inputs::Inputs {
            clock: Arc::new(crate::host_inputs::simulation::VirtualClock(
                std::sync::Mutex::new((
                    std::time::Duration::from_secs(NOW as u64),
                    std::time::Duration::ZERO,
                )),
            )),
            ..Default::default()
        };
        let runtime = Runtime {
            integrations: Arc::new(integration_host::Host::local(&instance_path)?),
            app_calls: None,
            credentials: None,
            connections: None,
            instance_path,
            app: "app".into(),
            db: state.join("app.sqlite"),
            scope: SCOPE.into(),
            hosted_domain: hosted_domain.map(str::to_owned),
            artifact: Arc::new(LoadedArtifact::from_contract_for_tests(
                "hybrid-directory-test".into(),
                artifact_directory,
                contract,
            )),
            host: Arc::new(crate::host::System(inputs.clone())),
            inputs,
        }
        .with_integrations(integration_host::Host::simulated_providers_with_app_calls(
            &state.join("app.sqlite"),
            SCOPE,
        ));
        runtime.initialize()?;
        let world = if with_world {
            crate::integrations::simulated::WorkspaceDirectoryWorld {
                customer_id: CUSTOMER.into(),
                users: if with_user {
                    [ACTOR, NEWHIRE, CONTRACTOR]
                        .into_iter()
                        .map(|person| {
                            (
                                person.into(),
                                json!({"customerId":CUSTOMER,
                                "orgUnitPath":"/Engineering","primaryEmail":person,"kind":"admin#directory#user"}),
                            )
                        })
                        .collect()
                } else {
                    BTreeMap::new()
                },
                hierarchy: json!({"kind":"admin#directory#orgUnits","organizationUnits":[
                    {"orgUnitId":"root","name":"Root","orgUnitPath":"/","parentOrgUnitId":null,"parentOrgUnitPath":null},
                    {"orgUnitId":"engineering","name":"Engineering","orgUnitPath":"/Engineering","parentOrgUnitId":"root","parentOrgUnitPath":"/"}]}),
            }
        } else {
            Default::default()
        };
        crate::integrations::simulated::seed(
            runtime.db(),
            SCOPE,
            &crate::integrations::simulated::SimulatedFixture {
                workspace_directory: world,
                slack: crate::integrations::simulated::SlackWorld {
                    workspace_id: "THYBRID".into(),
                    ..Default::default()
                },
                snowflake: crate::integrations::simulated::SnowflakeWorld {
                    account: "hybrid-test".into(),
                    ..Default::default()
                },
                openai: crate::integrations::simulated::OpenAiWorld {
                    project_id: "proj_hybrid".into(),
                    model: "model-hybrid".into(),
                    max_input_tokens: 100_000,
                    ..Default::default()
                },
                ..Default::default()
            },
        )?;
        if !with_world {
            let world_path = runtime.db().with_file_name(crate::simulations::simulation(
                day2_capabilities::resources::Provider::WorkspaceDirectory,
            ));
            fs::remove_file(world_path)?;
        }
        Ok((directory, runtime))
    }

    fn admitted_capture(
        runtime: &Runtime,
        invocation: &str,
        capability_name: &str,
        now: i64,
        expect_cache_hit: bool,
    ) -> Result<String> {
        admitted_capture_as(
            runtime,
            ACTOR,
            invocation,
            capability_name,
            now,
            expect_cache_hit,
        )
    }

    fn admitted_capture_as(
        runtime: &Runtime,
        actor: &str,
        invocation: &str,
        capability_name: &str,
        now: i64,
        expect_cache_hit: bool,
    ) -> Result<String> {
        runtime.accept("run", actor, invocation, &json!({}), now)?;
        let mut connection = open(runtime.db())?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let request = Request {
            operation: "run".into(),
            input: "{}".into(),
            context: crate::store::invocation_context(&tx, invocation)?,
            observations: vec![],
        };
        let bound = crate::resources::host_operation(
            &tx,
            runtime,
            &request,
            &Instruction {
                kind: "observe".into(),
                model: crate::resources::BIND.into(),
                data: json!({"binding":"directory","invocation":invocation}).to_string(),
                ..Default::default()
            },
        )?
        .context("directory resource binding")?;
        let bound: Value = serde_json::from_str(&bound)?;
        let handle = bound["token"]
            .as_str()
            .context("opaque directory handle")?
            .to_owned();
        let active = authority_state::current(&tx)?;
        let instruction = Instruction {
            kind: "observe".into(),
            model: capability_name.into(),
            data: json!({"handle":handle}).to_string(),
            ..Default::default()
        };
        let capability = crate::capabilities::authorized(
            &tx,
            runtime,
            &request,
            &instruction,
            active.policy()?,
            "ob_hybrid_directory",
        )?;
        crate::resources::record_use(&tx, invocation, capability.resource())?;
        let reservation = crate::resources::reserve_in(
            &tx,
            runtime,
            &request,
            &instruction,
            invocation,
            capability.resource(),
            capability.quote(),
        )?;
        tx.commit()?;
        let outcome = crate::capabilities::observe(runtime, capability, "hybrid-directory-test");
        if expect_cache_hit {
            assert_eq!(outcome.usage.calls, 0);
            assert_eq!(outcome.usage.request_bytes, 0);
            assert_eq!(outcome.usage.response_bytes, 0);
            assert!(!outcome.usage.dispatched);
        } else {
            assert!(outcome.usage.calls > 0);
            assert_eq!(
                outcome.usage.response_bytes,
                crate::workspace_directory::MAX_CAPTURE_RESPONSE_BYTES
            );
            assert_eq!(
                outcome.usage.request_bytes,
                crate::workspace_directory::MAX_CAPTURE_REQUEST_BYTES
            );
            assert!(outcome.usage.dispatched);
        }
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        crate::resources::settle_in(&tx, &reservation, outcome.usage)?;
        tx.commit()?;
        outcome.result
    }

    let response_limit = crate::workspace_directory::MAX_RESPONSE_BYTES as u64;
    let (_directory, runtime) = fixture_runtime(true, true, true, response_limit)?;
    assert!(
        !runtime.integrations().is_simulated(),
        "delegation semantics changed"
    );
    assert!(runtime.integrations().uses_simulated_providers());
    let capture: Value = serde_json::from_str(&admitted_capture(
        &runtime,
        "seeded",
        "workspace_directory.capture.v1",
        NOW,
        false,
    )?)?;
    assert_eq!(capture["customer_id"], CUSTOMER);
    assert_eq!(capture["actor"], ACTOR);
    assert_eq!(capture["user_path"], "/Engineering");
    assert_eq!(capture["org_unit_count"], 2);
    admitted_capture(
        &runtime,
        "second",
        "workspace_directory.capture.v1",
        NOW,
        false,
    )?;
    let exhausted = admitted_capture(
        &runtime,
        "budget-exhausted",
        "workspace_directory.capture.v1",
        NOW,
        false,
    )
    .unwrap_err()
    .to_string();
    assert!(
        exhausted.starts_with("budget_exhausted:") && exhausted.ends_with(":bytes"),
        "{exhausted}"
    );

    // Cache plans reserve and consume no provider traffic, even after another
    // full provider envelope no longer fits. They still record current authority.
    admitted_capture(
        &runtime,
        "cached-with-spent-budget",
        "workspace_directory.hierarchy.v1",
        NOW,
        true,
    )?;
    assert!(
        admitted_capture(
            &runtime,
            "cold-with-spent-budget",
            "workspace_directory.hierarchy.v1",
            NOW + crate::workspace_directory::SOURCE_TTL_SECONDS,
            false
        )
        .unwrap_err()
        .to_string()
        .starts_with("budget_exhausted:")
    );

    let mut replay_traces = Vec::new();
    for replay in 0..2 {
        let (_directory, runtime) = fixture_runtime(true, true, true, response_limit)?;
        use crate::integrations::simulated::{
            ScheduledFault, SimulatedFault, schedule_faults, update_workspace_directory,
        };
        schedule_faults(
            runtime.db(),
            SCOPE,
            day2_capabilities::resources::Provider::WorkspaceDirectory
                .world()
                .unwrap(),
            vec![ScheduledFault {
                endpoint: String::new(),
                remaining: 1,
                fault: SimulatedFault::Denied,
            }],
        )?;
        assert_eq!(
            admitted_capture(
                &runtime,
                "denied-cold",
                "workspace_directory.hierarchy.v1",
                NOW,
                false
            )
            .unwrap_err()
            .to_string(),
            "workspace_directory_hierarchy_lookup_failed",
            "replay {replay}"
        );
        let recovered: Value = serde_json::from_str(&admitted_capture(
            &runtime,
            "recovered",
            "workspace_directory.hierarchy.v1",
            NOW + 1,
            false,
        )?)?;
        assert_eq!(recovered["source_captured_at"], NOW + 1);
        let cached: Value = serde_json::from_str(&admitted_capture(
            &runtime,
            "recovered-cache",
            "workspace_directory.hierarchy.v1",
            NOW + 2,
            true,
        )?)?;
        let world = update_workspace_directory(runtime.db(), SCOPE, |world| {
            assert!(world.faults.is_empty());
            assert_eq!(world.calls.len(), 2, "cache must not call the provider");
            Ok(serde_json::to_value(world)?)
        })?;
        replay_traces.push(json!({"recovered":recovered,"cached":cached,"world":world}));
    }
    assert_eq!(replay_traces[0], replay_traces[1]);

    let (_directory, runtime) = fixture_runtime(true, false, true, response_limit)?;
    admitted_capture(
        &runtime,
        "before-expiry",
        "workspace_directory.hierarchy.v1",
        NOW,
        false,
    )?;
    let refreshed: Value = serde_json::from_str(&admitted_capture(
        &runtime,
        "at-expiry",
        "workspace_directory.hierarchy.v1",
        NOW + 900,
        false,
    )?)?;
    assert_eq!(refreshed["source_captured_at"], NOW + 900);
    assert_eq!(refreshed["expires_at"], NOW + 1800);

    let (_directory, runtime) = fixture_runtime(true, false, true, response_limit)?;
    let cold: Value = serde_json::from_str(&admitted_capture(
        &runtime,
        "hierarchy-cold",
        "workspace_directory.hierarchy.v1",
        NOW,
        false,
    )?)?;
    assert_eq!(cold["customer_id"], CUSTOMER);
    assert_eq!(cold["actor"], ACTOR);
    assert_eq!(cold["org_unit_count"], 2);
    assert!(cold.get("user_path").is_none());
    assert_eq!(cold["source_captured_at"], NOW);
    assert_eq!(
        cold["expires_at"],
        NOW + crate::workspace_directory::SOURCE_TTL_SECONDS
    );
    for (invocation, now) in [("hierarchy-hit-1", NOW + 1), ("hierarchy-hit-2", NOW + 899)] {
        let reused: Value = serde_json::from_str(&admitted_capture(
            &runtime,
            invocation,
            "workspace_directory.hierarchy.v1",
            now,
            true,
        )?)?;
        assert_eq!(reused["captured_at"], now);
        assert_eq!(reused["source_captured_at"], NOW);
        assert_eq!(
            reused["expires_at"],
            NOW + crate::workspace_directory::SOURCE_TTL_SECONDS
        );
        assert!(reused.get("user_path").is_none());
    }
    assert_eq!(
        admitted_capture(
            &runtime,
            "membership-user-outage",
            "workspace_directory.capture.v1",
            NOW + 2,
            false,
        )
        .unwrap_err()
        .to_string(),
        "workspace_directory_user_lookup_failed",
        "a cached hierarchy must not establish membership during user lookup outage"
    );
    let (_directory, runtime) = fixture_runtime(false, true, true, response_limit)?;
    assert_eq!(
        admitted_capture(
            &runtime,
            "hierarchy-missing-world",
            "workspace_directory.hierarchy.v1",
            NOW,
            false
        )
        .unwrap_err()
        .to_string(),
        "simulated_provider_unconfigured",
        "missing simulated world must not fall through to live HTTP"
    );
    assert_eq!(
        admitted_capture(
            &runtime,
            "missing-world-second-failure",
            "workspace_directory.hierarchy.v1",
            NOW,
            false
        )
        .unwrap_err()
        .to_string(),
        "simulated_provider_unconfigured"
    );
    let exhausted = admitted_capture(
        &runtime,
        "failure-budget-exhausted",
        "workspace_directory.hierarchy.v1",
        NOW,
        false,
    )
    .unwrap_err()
    .to_string();
    assert!(
        exhausted.starts_with("budget_exhausted:") && exhausted.ends_with(":bytes"),
        "{exhausted}"
    );
    let (_directory, runtime) = fixture_runtime(true, true, false, response_limit)?;
    let mut simulated = crate::workspace_directory::SimulatedDirectoryPort::new(
        runtime.db(),
        SCOPE,
        CUSTOMER,
        ACTOR,
        NOW,
    )?;
    let cached = crate::workspace_directory::collect_hierarchy(
        crate::workspace_directory::CaptureInput {
            customer_id: CUSTOMER.into(),
            connection_id: "directory@1".into(),
            actor: ACTOR.into(),
            captured_at: NOW,
        },
        &mut simulated,
    )?;
    let cache_path = runtime.db().with_file_name("workspace_directory.sqlite");
    let mut cache = crate::workspace_directory::open_store(&cache_path)?;
    crate::workspace_directory::publish(&mut cache, &cached)?;
    assert_eq!(
        admitted_capture(
            &runtime,
            "denied-hierarchy-action-with-cache",
            "workspace_directory.hierarchy.v1",
            NOW,
            false,
        )
        .unwrap_err()
        .to_string(),
        crate::error::Failure::CapabilityForbidden.to_string(),
        "a cached result must not bypass the operation's narrowed action grant"
    );
    assert!(
        runtime
            .accept(
                "run",
                "ungranted@coverage.test",
                "denied-actor",
                &json!({}),
                NOW
            )
            .is_err()
    );

    let (_directory, runtime) = fixture_runtime(true, true, true, response_limit - 1)?;
    assert_eq!(
        admitted_capture(
            &runtime,
            "insufficient-response-allowance",
            "workspace_directory.capture.v1",
            NOW,
            false,
        )
        .unwrap_err()
        .to_string(),
        crate::error::Failure::ResourceForbidden.to_string()
    );

    // A grant naming only the verified domain reads the Directory for someone
    // nobody listed by name, and binds nothing for a member of another domain.
    let (_directory, runtime) =
        fixture_runtime_in(true, true, true, response_limit, Some("coverage.test"))?;
    let capture: Value = serde_json::from_str(&admitted_capture_as(
        &runtime,
        NEWHIRE,
        "domain-member",
        "workspace_directory.capture.v1",
        NOW,
        false,
    )?)?;
    assert_eq!(capture["actor"], NEWHIRE);
    assert_eq!(capture["user_path"], "/Engineering");
    assert_eq!(
        admitted_capture_as(
            &runtime,
            CONTRACTOR,
            "named-outside-domain",
            "workspace_directory.capture.v1",
            NOW,
            false,
        )
        .unwrap_err()
        .to_string(),
        crate::error::Failure::ResourceForbidden.to_string()
    );
    Ok(())
}
