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
    collections::VecDeque,
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
            json!({"format":crate::artifact::CURRENT_FORMAT,"roc_version":"host-test","worker_digest":"host-test",
            "schema_digest":"host-test","schema":{"models":{"items":{"fields":{"value":"text"}}},"inputs":{"input":{"fields":{}}},"foreign_keys":[]},
            "operations":[{"name":"run","kind":"command","input_type":"input","output_type":""}],"sources":{},"admission":"local-spike-only"}),
        )?;
        let runtime = Runtime {
            integrations: Arc::new(integration_host::Host::local(&path)?),
            app_calls: None,
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
            host: Arc::new(crate::host::System),
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
