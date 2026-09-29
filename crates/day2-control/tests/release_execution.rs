#[path = "support/release.rs"]
mod support;

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    routing::{any, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use day2::{
    delegation::{self, Call},
    delegation_wire::{
        IssuerSigner, IssuerVerifier, Query, Scope, Signer, TrustedKey, Verifier, issued_query,
    },
    iap::{self, KeySource},
    store::Runtime,
};
use day2_control::iap_service_jwt::{Gate, GkeMetadataAccessTokens, IapServiceJwt};
use day2_control::journal::{Journal, RecoveryMode};
use day2_control::provider_evidence::{ReadBarrier, RevisionToken, StateEvidence};
use day2_control::release::{ReleaseApproval, ReleaseTarget, SecretObservation};
use day2_control::release_execution::{
    Capabilities, LEASE_MILLIS, ObservedServingBinding, Recipe, ReleaseClaim, ReleaseEffectResult,
    ReleaseExecutionHost, ReleaseExecutionPlan, ReleaseLease, ReleaseObservation, ReleaseObserved,
    ReleaseOperation, ReleasePhase, ReleaseRejection, ReleaseTerminal, ServingProbe,
};
use day2_control::release_recipe::CompiledReleaseRecipe;
use day2_control::remote_query::{
    RemoteQueryAuth, RemoteQueryIssuer, RemoteQueryPort, RemoteQueryReceiver,
};
use day2_control::{BindingRef, Digest};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair},
};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use support::*;

struct Provider {
    plan: ReleaseExecutionPlan,
    approval: ReleaseApproval,
    secret: Mutex<Option<SecretObservation>>,
    resources: Mutex<BTreeMap<Digest, Option<Digest>>>,
    preparations: Mutex<BTreeMap<Digest, Digest>>,
    writes: Mutex<Vec<Digest>>,
    retry_deployment: AtomicBool,
    unknown_mutation: AtomicBool,
    denied: AtomicBool,
}

impl Capabilities for Provider {
    fn validate(&self, plan: &ReleaseExecutionPlan, approval: &ReleaseApproval) -> Result<()> {
        ensure!(!self.denied.load(Ordering::SeqCst), "test provider revoked");
        ensure!(
            plan == &self.plan && approval == &self.approval,
            "test provider scope mismatch"
        );
        Ok(())
    }

    fn perform(&self, lease: &ReleaseLease) -> Result<ReleaseEffectResult> {
        let fact = lease.fact(Digest::new(b"qualified-test-metadata"))?;
        let outcome = match lease.step.operation {
            ReleaseOperation::PrepareDependency | ReleaseOperation::PrepareDeployment => {
                if self.unknown_mutation.swap(false, Ordering::SeqCst) {
                    return Ok(ReleaseEffectResult::Ambiguous {});
                }
                if lease.step.operation == ReleaseOperation::PrepareDeployment
                    && self.retry_deployment.swap(false, Ordering::SeqCst)
                {
                    return Ok(ReleaseEffectResult::RetryNotApplied {});
                }
                let mut resources = self.resources.lock().unwrap();
                if lease.recovery == RecoveryMode::Reconcile {
                    if resources.get(&fact.resource) != Some(&fact.readiness) {
                        return Ok(ReleaseEffectResult::ReconciledAbsent {
                            fact: Box::new(fact),
                        });
                    }
                } else {
                    resources.insert(fact.resource.clone(), fact.readiness.clone());
                    self.writes.lock().unwrap().push(lease.effect.clone());
                    if lease.step.operation == ReleaseOperation::PrepareDeployment {
                        self.preparations
                            .lock()
                            .unwrap()
                            .insert(fact.resource.clone(), lease.effect.clone());
                    }
                }
                if lease.step.operation == ReleaseOperation::PrepareDependency {
                    ReleaseObserved::DependencyPrepared {}
                } else {
                    ReleaseObserved::DeploymentPrepared {
                        incarnation: incarnation(&lease.effect),
                    }
                }
            }
            ReleaseOperation::ObserveSecret => ReleaseObserved::Secret {
                metadata: self.secret.lock().unwrap().clone(),
            },
            ReleaseOperation::ObserveDeployment => {
                let prepared = self
                    .preparations
                    .lock()
                    .unwrap()
                    .get(&fact.resource)
                    .cloned()
                    .expect("prepared deployment effect");
                ReleaseObserved::Deployment {
                    ready: self.resources.lock().unwrap().get(&fact.resource)
                        == Some(&fact.readiness),
                    incarnation: incarnation(&prepared),
                    evidence: StateEvidence::Qualified {
                        revision: RevisionToken::Ordered {
                            stream: fact.resource.clone(),
                            sequence: 1_u64.try_into().unwrap(),
                        },
                        barrier: ReadBarrier {
                            authority: lease.execution.plan.deployment.clone(),
                            resource: fact.resource.clone(),
                            after_effect: Some(prepared),
                            receipt: Digest::new(b"qualified-deployment-read"),
                        },
                    },
                }
            }
            ReleaseOperation::Activate => anyhow::bail!("activation must never reach provider"),
        };
        Ok(ReleaseEffectResult::Observed(Box::new(
            ReleaseObservation { fact, outcome },
        )))
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    host: ReleaseExecutionHost,
    recipe: Arc<CompiledReleaseRecipe>,
    provider: Arc<Provider>,
    id: Digest,
}

struct WorkloadProbe(Mutex<ObservedServingBinding>);

impl ServingProbe for WorkloadProbe {
    fn observe(&self, _: &day2_control::release::ReleaseTarget) -> Result<ObservedServingBinding> {
        Ok(self.0.lock().unwrap().clone())
    }
}

impl Fixture {
    fn serving_probe(&self) -> WorkloadProbe {
        let effect = self
            .provider
            .preparations
            .lock()
            .unwrap()
            .values()
            .next()
            .cloned()
            .expect("prepared deployment");
        WorkloadProbe(Mutex::new(ObservedServingBinding {
            target: self.provider.approval.target.clone(),
            artifact: self.provider.approval.artifact.clone(),
            deployment: self.provider.plan.deployment.clone(),
            incarnation: incarnation(&effect),
        }))
    }
}

#[test]
fn serving_fence_requires_an_active_release_and_fresh_matching_workload() {
    let fixture = Fixture::new(true);
    let mut now = 0;
    fixture.until(ReleasePhase::WaitingDeployment, &mut now);
    let probe = fixture.serving_probe();
    let target = &fixture.provider.approval.target;
    let journal = Journal::open(&fixture.path).unwrap();
    let mut called = false;
    assert!(
        journal
            .with_serving_fence(target, &probe, || {
                called = true;
                Ok(())
            })
            .is_err()
    );
    assert!(!called);

    fixture.until(ReleasePhase::Active, &mut now);
    assert_eq!(
        journal
            .with_serving_fence(target, &probe, || Ok(7))
            .unwrap(),
        7
    );
    let original = probe.0.lock().unwrap().clone();
    let audit = journal.release_event_count(target).unwrap();
    for field in 0..5 {
        let mut changed = original.clone();
        match field {
            0 => changed.target.app = name("another"),
            1 => changed.artifact = Digest::new(b"other-serving-artifact"),
            2 => changed.deployment.revision = Digest::new(b"other-deployment-binding"),
            3 => changed.incarnation.controller = "other-controller".to_owned().try_into().unwrap(),
            _ => changed.incarnation.generation = "other-generation".to_owned().try_into().unwrap(),
        }
        *probe.0.lock().unwrap() = changed;
        called = false;
        assert!(
            journal
                .with_serving_fence(target, &probe, || {
                    called = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(!called);
        assert_eq!(journal.release_event_count(target).unwrap(), audit);
    }
    *probe.0.lock().unwrap() = original;
    assert!(
        journal
            .with_serving_fence(target, &probe, || {
                probe.0.lock().unwrap().incarnation.generation =
                    "replacement-generation".to_owned().try_into().unwrap();
                Ok("answer")
            })
            .is_err(),
        "a changed provider generation must suppress a completed result"
    );
    assert_eq!(journal.release_event_count(target).unwrap(), audit);
}

#[test]
fn serving_fence_rechecks_the_selected_release_after_the_call() {
    let fixture = Fixture::new(true);
    fixture.until(ReleasePhase::Active, &mut 0);
    let probe = fixture.serving_probe();
    let target = &fixture.provider.approval.target;
    let journal = Journal::open(&fixture.path).unwrap();
    assert!(
        journal
            .with_serving_fence(target, &probe, || {
                Connection::open(&fixture.path)?
                    .execute("UPDATE release_slots SET active=NULL", [])?;
                Ok("answer")
            })
            .is_err(),
        "a changed release selection must suppress a completed result"
    );
}

struct QueryServer {
    origin: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<Result<()>>>,
}

struct FixtureIap {
    key: EcdsaKeyPair,
    keys: String,
}

struct FixtureKeys(String);

impl KeySource for FixtureKeys {
    fn fetch(&self) -> Result<String> {
        Ok(self.0.clone())
    }
}

impl FixtureIap {
    fn new() -> Result<Self> {
        let random = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
            .map_err(|_| anyhow::anyhow!("test IAP key generation failed"))?;
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &random)
                .map_err(|_| anyhow::anyhow!("test IAP key loading failed"))?;
        let point = key.public_key().as_ref();
        let keys = json!({"keys":[{"kid":"fixture-iap","kty":"EC","crv":"P-256",
            "x":URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y":URL_SAFE_NO_PAD.encode(&point[33..65])}]})
        .to_string();
        Ok(Self { key, keys })
    }

    fn assertion(&self, audience: &str, email: &str, at: i64) -> Result<String> {
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(json!({"alg":"ES256","kid":"fixture-iap"}).to_string()),
            URL_SAFE_NO_PAD.encode(
                json!({
                    "iss":iap::ISSUER,"aud":audience,"exp":at+600,
                    "sub":"service-account-fixture","email":email
                })
                .to_string()
            )
        );
        let signature = self
            .key
            .sign(&SystemRandom::new(), signed.as_bytes())
            .map_err(|_| anyhow::anyhow!("test IAP signing failed"))?;
        Ok(format!(
            "{signed}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        ))
    }

    fn verifier(&self, audience: &str, email: &str) -> Result<iap::Verifier> {
        iap::Verifier::for_workload(audience, email, Box::new(FixtureKeys(self.keys.clone())))
    }
}

impl QueryServer {
    fn start(receiver: Arc<RemoteQueryReceiver>) -> Result<Self> {
        let (send, receive) = mpsc::channel();
        let (stop, done) = tokio::sync::oneshot::channel();
        let thread = thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?
                .block_on(async move {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                    send.send(format!("http://{}", listener.local_addr()?))?;
                    let router = Router::new()
                        .route(
                            "/_platform/app-query",
                            post(
                                |State(receiver): State<Arc<RemoteQueryReceiver>>,
                                 headers: HeaderMap,
                                 body: Bytes| async move {
                                    let mut assertions =
                                        headers.get_all(iap::ASSERTION_HEADER).iter();
                                    let assertion = match (assertions.next(), assertions.next()) {
                                        (Some(value), None) => {
                                            value.to_str().ok().map(str::to_owned)
                                        }
                                        _ => None,
                                    };
                                    let answer = tokio::task::spawn_blocking(move || {
                                        let at = i64::try_from(
                                            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                                        )?;
                                        receiver.handle(
                                            &body,
                                            assertion.as_deref().unwrap_or(""),
                                            at,
                                        )
                                    })
                                    .await;
                                    match answer {
                                        Ok(Ok(result)) => (StatusCode::OK, result),
                                        _ => (StatusCode::FORBIDDEN, "refused".to_owned()),
                                    }
                                },
                            ),
                        )
                        .with_state(receiver);
                    axum::serve(listener, router)
                        .with_graceful_shutdown(async {
                            let _ = done.await;
                        })
                        .await?;
                    Ok(())
                })
        });
        Ok(Self {
            origin: receive.recv_timeout(Duration::from_secs(10))?,
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

struct GatedServer {
    origin: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<Result<()>>>,
}

struct GatedState {
    origin: String,
    caller: Runtime,
    issuer: Arc<RemoteQueryIssuer>,
    receiver: Arc<RemoteQueryReceiver>,
    iap: Arc<FixtureIap>,
    workload_email: String,
    issuer_audience: String,
    target_audience: String,
}

impl GatedState {
    // This is a protocol fixture for IAP. It checks the service-account JWT's
    // exact claims, then supplies a separately signed IAP assertion. The real
    // edge verifies the JWT signature before forwarding either request.
    fn admit(&self, headers: &HeaderMap, path: &str, at: i64) -> Result<String> {
        let mut values = headers.get_all("Authorization").iter();
        let (Some(value), None) = (values.next(), values.next()) else {
            anyhow::bail!("missing IAP bearer credential");
        };
        let token = value
            .to_str()?
            .strip_prefix("Bearer ")
            .context("IAP bearer")?;
        let mut parts = token.split('.');
        let (Some(_), Some(body), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            anyhow::bail!("invalid IAP bearer credential");
        };
        ensure!(!signature.is_empty(), "unsigned IAP bearer credential");
        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body)?)?;
        ensure!(
            claims["iss"] == self.workload_email
                && claims["sub"] == self.workload_email
                && claims["aud"] == format!("{}{path}", self.origin)
                && claims["iat"].as_i64().is_some_and(|value| value <= at)
                && claims["exp"].as_i64().is_some_and(|value| at < value),
            "wrong IAP bearer scope"
        );
        let audience = if path == "/_platform/app-issue" {
            &self.issuer_audience
        } else {
            &self.target_audience
        };
        self.iap.assertion(audience, &self.workload_email, at)
    }
}

async fn gated_request(
    State(state): State<Arc<GatedState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Vec<u8>) {
    if method == Method::GET
        && uri.path() == "/computeMetadata/v1/instance/service-accounts/default/token"
    {
        if headers
            .get("Metadata-Flavor")
            .and_then(|value| value.to_str().ok())
            == Some("Google")
        {
            return (
                StatusCode::OK,
                json!({"access_token":"metadata-access","token_type":"Bearer"})
                    .to_string()
                    .into_bytes(),
            );
        }
        return (StatusCode::FORBIDDEN, Vec::new());
    }
    if method == Method::POST
        && uri.path()
            == "/v1/projects/-/serviceAccounts/caller@project.iam.gserviceaccount.com:signJwt"
    {
        if headers
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            != Some("Bearer metadata-access")
        {
            return (StatusCode::FORBIDDEN, Vec::new());
        }
        let request: Value = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(_) => return (StatusCode::BAD_REQUEST, Vec::new()),
        };
        let Some(payload) = request["payload"].as_str() else {
            return (StatusCode::BAD_REQUEST, Vec::new());
        };
        let jwt = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(json!({"alg":"RS256","kid":"managed-key"}).to_string()),
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode([7_u8; 64])
        );
        return (
            StatusCode::OK,
            json!({"keyId":"managed-key","signedJwt":jwt})
                .to_string()
                .into_bytes(),
        );
    }
    if method != Method::POST
        || !matches!(uri.path(), "/_platform/app-issue" | "/_platform/app-query")
    {
        return (StatusCode::FORBIDDEN, Vec::new());
    }
    let at = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(_) => return (StatusCode::FORBIDDEN, Vec::new()),
    };
    let assertion = match state.admit(&headers, uri.path(), at) {
        Ok(assertion) => assertion,
        Err(_) => return (StatusCode::FORBIDDEN, Vec::new()),
    };
    let result = tokio::task::spawn_blocking(move || {
        if uri.path() == "/_platform/app-issue" {
            state.issuer.handle(&state.caller, &body, &assertion, at)
        } else {
            Ok(state.receiver.handle(&body, &assertion, at)?.into_bytes())
        }
    })
    .await;
    match result {
        Ok(Ok(body)) => (StatusCode::OK, body),
        _ => (StatusCode::FORBIDDEN, Vec::new()),
    }
}

impl GatedServer {
    fn start(
        caller: Runtime,
        issuer: Arc<RemoteQueryIssuer>,
        receiver: Arc<RemoteQueryReceiver>,
        iap: Arc<FixtureIap>,
        workload_email: &str,
        issuer_audience: &str,
        target_audience: &str,
    ) -> Result<Self> {
        let (send, receive) = mpsc::channel();
        let (stop, done) = tokio::sync::oneshot::channel();
        let workload_email = workload_email.to_owned();
        let issuer_audience = issuer_audience.to_owned();
        let target_audience = target_audience.to_owned();
        let thread = thread::spawn(move || -> Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?
                .block_on(async move {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                    let origin = format!("http://{}", listener.local_addr()?);
                    let state = Arc::new(GatedState {
                        origin: origin.clone(),
                        caller,
                        issuer,
                        receiver,
                        iap,
                        workload_email,
                        issuer_audience,
                        target_audience,
                    });
                    send.send(origin)?;
                    axum::serve(
                        listener,
                        Router::new().fallback(any(gated_request)).with_state(state),
                    )
                    .with_graceful_shutdown(async {
                        let _ = done.await;
                    })
                    .await?;
                    Ok(())
                })
        });
        Ok(Self {
            origin: receive.recv_timeout(Duration::from_secs(10))?,
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for GatedServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for QueryServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            assert!(thread.join().expect("query server").is_ok());
        }
    }
}

#[test]
fn signed_query_crosses_separate_host_databases_and_fences_serving_generation() -> Result<()> {
    let artifact = std::env::var_os("DAY2_TEST_REPORTS_ARTIFACT")
        .map(PathBuf::from)
        .context("run xtask verify with compiled fixtures")?;
    let policy: Value = serde_json::from_str(include_str!(
        "../../../fixtures/authority-policies/reports.json"
    ))?;
    let host = |app: &str| -> Result<(tempfile::TempDir, Runtime)> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("instance.json");
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "installation":"alpha","environment":"production",
                "apps":{app:{
                    "artifact":artifact,"readers":["alice"],"writers":["alice"],
                    "authority":policy
                }}
            }))?,
        )?;
        let runtime = Runtime::load(&path, app)?;
        runtime.initialize()?;
        Ok((directory, runtime))
    };
    let (callee_directory, callee) = host("reports")?;
    let (caller_directory, caller) = host("caller")?;
    let artifact_id: Digest = callee.artifact().id().to_owned().try_into()?;
    let fixture = Fixture::new_with_artifact(true, Some(&artifact_id));
    fixture.until(ReleasePhase::Active, &mut 0);
    let probe = Arc::new(fixture.serving_probe());
    let target = fixture.provider.approval.target.clone();
    let source = ReleaseTarget {
        app: name("caller"),
        ..target.clone()
    };
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("test key generation failed"))?;
    let signer = Signer::from_pkcs8("caller-key-1", pkcs8.as_ref())?;
    let source_scope = Scope::from_runtime(&caller)?;
    let issuer_workload_verifier = Verifier::new(BTreeMap::from([(
        "caller-key-1".to_owned(),
        TrustedKey {
            source: source_scope.clone(),
            public_key: signer.public_key(),
        },
    )]))?;
    let receiver_workload_verifier = Verifier::new(BTreeMap::from([(
        "caller-key-1".to_owned(),
        TrustedKey {
            source: source_scope.clone(),
            public_key: signer.public_key(),
        },
    )]))?;
    let issuer_pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("test issuer key generation failed"))?;
    let issuer_signer =
        IssuerSigner::from_pkcs8("platform-issuer", "issuer-key-1", issuer_pkcs8.as_ref())?;
    let issuer_verifier = IssuerVerifier::new(
        "platform-issuer",
        BTreeMap::from([("issuer-key-1".to_owned(), issuer_signer.public_key())]),
        "/projects/123/global/backendServices/target",
    )?;
    let iap = Arc::new(FixtureIap::new()?);
    let workload_email = "caller@project.iam.gserviceaccount.com";
    let issuer_audience = "/projects/123/global/backendServices/issuer";
    let target_audience = "/projects/123/global/backendServices/target";
    let at = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let issuer_assertion = iap.assertion(issuer_audience, workload_email, at)?;
    let target_assertion = iap.assertion(target_audience, workload_email, at)?;
    let issuer = Arc::new(RemoteQueryIssuer::new(
        source.clone(),
        target.clone(),
        workload_email,
        issuer_audience,
        iap.verifier(issuer_audience, workload_email)?,
        issuer_workload_verifier,
        issuer_signer,
    )?);
    let receiver = Arc::new(RemoteQueryReceiver::new(
        fixture.path.clone(),
        probe.clone(),
        target.clone(),
        callee.clone(),
        receiver_workload_verifier,
        issuer_verifier,
        iap.verifier(target_audience, workload_email)?,
    )?);
    let server = QueryServer::start(receiver.clone())?;
    let port = RemoteQueryPort::loopback_fixture(
        fixture.path.clone(),
        probe.clone(),
        source.clone(),
        target.clone(),
        &format!("{}/_platform/app-query", server.origin),
        RemoteQueryAuth {
            workload_signer: signer,
            issuer: issuer.clone(),
            issuer_assertion: issuer_assertion.clone(),
            target_assertion: target_assertion.clone(),
        },
    )?;
    let caller = caller.with_app_call_port(Arc::new(port));
    let call = Call {
        app: "reports".into(),
        operation: "reports.list".into(),
        schema_digest: delegation::schema_digest(&callee, "reports.list")?,
        contract_digest: None,
        input: json!({"after":"","limit":20}).to_string(),
        actor: "alice".into(),
        origin: "root-invocation".into(),
        step: "ob_root-invocation_0".into(),
        chain: String::new(),
        caller: "caller".into(),
        now: 100,
    };
    caller.accept(
        "reports.list",
        "alice",
        "root-invocation",
        &serde_json::from_str(&call.input)?,
        100,
    )?;
    assert!(
        delegation::read(&caller, &call).is_err(),
        "a durable actor without verified root evidence cannot be signed"
    );
    // The loopback fixture stands in for the IAP edge, which writes these
    // private bindings atomically with root admission in a served app.
    Connection::open(caller.db())?.execute(
        "INSERT INTO day2_principals VALUES('alice','fixture-iap-subject',100)",
        [],
    )?;
    Connection::open(caller.db())?.execute(
        "INSERT INTO day2_invocation_origins VALUES('root-invocation','alice','fixture-iap-subject','iap')",
        [],
    )?;
    let answer: Value = serde_json::from_str(&delegation::read(&caller, &call)?)?;
    assert!(answer.is_object() || answer.is_array());
    let gated = GatedServer::start(
        caller.clone(),
        issuer.clone(),
        receiver,
        iap,
        workload_email,
        issuer_audience,
        target_audience,
    )?;
    let tokens = Arc::new(GkeMetadataAccessTokens::transport_fixture(&format!(
        "{}/computeMetadata/v1/instance/service-accounts/default/token",
        gated.origin
    ))?);
    let credentials = Arc::new(IapServiceJwt::transport_fixture(
        workload_email,
        &format!("{}/_platform/app-issue", gated.origin),
        &format!("{}/_platform/app-query", gated.origin),
        &format!("{}/", gated.origin),
        tokens,
    )?);
    let http_port = RemoteQueryPort::iap_http(
        fixture.path.clone(),
        probe.clone(),
        source,
        target.clone(),
        Signer::from_pkcs8("caller-key-1", pkcs8.as_ref())?,
        credentials.clone(),
    )?;
    let http_caller = caller.clone().with_app_call_port(Arc::new(http_port));
    let http_answer: Value = serde_json::from_str(&delegation::read(&http_caller, &call)?)?;
    assert_eq!(
        http_answer, answer,
        "both IAP gates and issuer HTTP preserve the query result"
    );
    assert!(
        !caller_directory
            .path()
            .join(".state/reports.sqlite")
            .exists()
    );
    assert!(
        !callee_directory
            .path()
            .join(".state/caller.sqlite")
            .exists()
    );
    let attribution: (String, String, String) = Connection::open(callee.db())?.query_row(
        "SELECT actor,authenticated,caller FROM day2_invocations WHERE id LIKE 'dlg_%'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(
        attribution,
        ("alice".into(), "app:caller".into(), "caller".into())
    );

    let endpoint = format!("{}/_platform/app-query", server.origin);
    let client = reqwest::blocking::Client::new();
    assert_eq!(
        client.post(&endpoint).body("{}").send()?.status(),
        StatusCode::FORBIDDEN
    );
    let signer = Signer::from_pkcs8("caller-key-1", pkcs8.as_ref())?;
    let active = Journal::open(&fixture.path)?
        .release_state(&target)?
        .active
        .context("active test release")?;
    let forged = Query {
        version: 1,
        source: source_scope,
        target: Scope::from_runtime(&callee)?,
        operation: call.operation.clone(),
        schema_digest: call.schema_digest.clone(),
        contract_digest: None,
        input: serde_json::from_str(&call.input)?,
        actor: "mallory".into(),
        origin: "forged-origin".into(),
        step: "ob_forged_0".into(),
        chain: String::new(),
        now: 100,
        issued_at: at,
        expires_at: at + 30,
        activation: active.id,
        generation: active.generation,
        serving: serde_json::to_value(probe.0.lock().unwrap().clone())?,
    };
    assert_eq!(
        client
            .post(&endpoint)
            .header(iap::ASSERTION_HEADER, &target_assertion)
            .body(signer.sign(&forged)?)
            .send()?
            .status(),
        StatusCode::FORBIDDEN,
        "a workload signature without issuer proof is refused"
    );
    assert!(
        issuer
            .issue(
                &caller,
                &call,
                &forged,
                &signer.sign(&forged)?,
                &issuer_assertion,
                at
            )
            .is_err(),
        "the issuer cannot endorse a workload-selected actor"
    );
    let mut valid = forged.clone();
    valid.actor = call.actor.clone();
    valid.origin = call.origin.clone();
    valid.step = call.step.clone();
    let valid_workload = signer.sign(&valid)?;
    let valid_proof = issuer.issue(
        &caller,
        &call,
        &valid,
        &valid_workload,
        &issuer_assertion,
        at,
    )?;
    let gated_client = reqwest::blocking::Client::new();
    let issued = issued_query(&valid_workload, &valid_proof)?;
    assert_eq!(
        gated_client
            .post(format!("{}/_platform/app-query", gated.origin))
            .header(iap::ASSERTION_HEADER, &target_assertion)
            .body(issued.clone())
            .send()?
            .status(),
        StatusCode::FORBIDDEN,
        "a client cannot supply its own target IAP assertion"
    );
    assert_eq!(
        gated_client
            .post(format!("{}/_platform/app-query", gated.origin))
            .bearer_auth(credentials.sign_for(Gate::Issuer)?.as_str())
            .body(issued)
            .send()?
            .status(),
        StatusCode::FORBIDDEN,
        "an issuer URL credential cannot open the receiver gate"
    );
    assert!(
        issuer
            .issue(
                &caller,
                &call,
                &valid,
                &valid_workload,
                &target_assertion,
                at
            )
            .is_err(),
        "the target IAP audience cannot open the issuer gate"
    );
    assert_eq!(
        client
            .post(&endpoint)
            .body(issued_query(&valid_workload, &valid_proof)?)
            .send()?
            .status(),
        StatusCode::FORBIDDEN,
        "the receiver requires its own IAP assertion"
    );
    assert_eq!(
        client
            .post(&endpoint)
            .header(iap::ASSERTION_HEADER, &issuer_assertion)
            .body(issued_query(&valid_workload, &valid_proof)?)
            .send()?
            .status(),
        StatusCode::FORBIDDEN,
        "an issuer-gated assertion is not a target-gated assertion"
    );
    assert_eq!(
        client
            .post(&endpoint)
            .header(iap::ASSERTION_HEADER, &target_assertion)
            .body(issued_query(&signer.sign(&forged)?, &valid_proof)?)
            .send()?
            .status(),
        StatusCode::FORBIDDEN,
        "issuer proof binds the exact signed workload request"
    );
    let mut wrong_generation = valid.clone();
    wrong_generation.generation += 1;
    let wrong_workload = signer.sign(&wrong_generation)?;
    let wrong_proof = issuer.issue(
        &caller,
        &call,
        &wrong_generation,
        &wrong_workload,
        &issuer_assertion,
        at,
    )?;
    assert_eq!(
        client
            .post(&endpoint)
            .header(iap::ASSERTION_HEADER, &target_assertion)
            .body(issued_query(&wrong_workload, &wrong_proof)?)
            .send()?
            .status(),
        StatusCode::FORBIDDEN,
        "even two valid signatures cannot replay a different release generation"
    );
    let mut wrong_audience = valid.clone();
    wrong_audience.target.app = "another".into();
    assert!(
        issuer
            .issue(
                &caller,
                &call,
                &wrong_audience,
                &signer.sign(&wrong_audience)?,
                &issuer_assertion,
                at,
            )
            .is_err(),
        "issuer scope does not include another target"
    );
    let mut expired = valid.clone();
    expired.issued_at = at - 60;
    expired.expires_at = at - 1;
    let expired_workload = signer.sign(&expired)?;
    let expired_proof = issuer.issue(
        &caller,
        &call,
        &expired,
        &expired_workload,
        &issuer_assertion,
        at - 50,
    )?;
    assert_eq!(
        client
            .post(&endpoint)
            .header(iap::ASSERTION_HEADER, &target_assertion)
            .body(issued_query(&expired_workload, &expired_proof)?)
            .send()?
            .status(),
        StatusCode::FORBIDDEN,
        "expired workload and issuer proofs cannot be replayed"
    );
    let count: i64 = Connection::open(callee.db())?.query_row(
        "SELECT count(*) FROM day2_invocations WHERE id LIKE 'dlg_%'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1, "denied requests never enter the callee");
    let mut changed_actor = call.clone();
    changed_actor.actor = "mallory".into();
    assert!(
        delegation::read(&caller, &changed_actor).is_err(),
        "the source host cannot sign an actor absent from its durable invocation"
    );
    Connection::open(caller.db())?.execute(
        "UPDATE day2_principals SET subject='reassigned-subject' WHERE email='alice'",
        [],
    )?;
    assert!(
        delegation::read(&caller, &call).is_err(),
        "a reassigned root account cannot receive a new transport proof"
    );
    Connection::open(caller.db())?.execute(
        "UPDATE day2_principals SET subject='fixture-iap-subject' WHERE email='alice'",
        [],
    )?;
    probe.0.lock().unwrap().incarnation.generation =
        "replacement-generation".to_owned().try_into()?;
    assert!(delegation::read(&caller, &call).is_err());
    Ok(())
}

impl Fixture {
    fn new(secret_ready: bool) -> Self {
        Self::new_with_artifact(secret_ready, None)
    }

    fn new_with_artifact(secret_ready: bool, artifact: Option<&Digest>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("release.sqlite");
        let mut journal = Journal::open(&path).unwrap();
        configure(&mut journal, &target("alpha"), &plan("alpha", 1));
        let approval = approval_with_artifact(&mut journal, "alpha", 1, 0, artifact);
        let approved = journal.approve_release(&approval).unwrap();
        let recipe = Arc::new(CompiledReleaseRecipe::installed().unwrap());
        let plan = ReleaseExecutionPlan {
            release: approved.id().to_owned(),
            recipe: recipe.revision().unwrap(),
            durability: plan("alpha", 1).profile.durability,
            resources: approval.secret.binding.clone(),
            deployment: BindingRef::pin(name("deployment"), &"synthetic-runtime-v1").unwrap(),
        };
        let provider = Arc::new(Provider {
            plan: plan.clone(),
            approval: approval.clone(),
            secret: Mutex::new(secret_ready.then(|| observation(&approval, 1))),
            resources: Mutex::new(BTreeMap::new()),
            preparations: Mutex::new(BTreeMap::new()),
            writes: Mutex::new(vec![]),
            retry_deployment: AtomicBool::new(false),
            unknown_mutation: AtomicBool::new(false),
            denied: AtomicBool::new(false),
        });
        let host = ReleaseExecutionHost::new(
            path.clone(),
            name("alpha"),
            name("host"),
            plan.durability.clone(),
            provider.clone(),
            recipe.clone(),
        );
        let id = host.accept(&plan).unwrap();
        Self {
            _directory: directory,
            path,
            host,
            recipe,
            provider,
            id,
        }
    }

    fn lease(&self, now: u64) -> ReleaseLease {
        let snapshot = self.host.inspect(&self.id).unwrap();
        let request = self.recipe.choose(&snapshot).unwrap();
        match self.host.claim_at(&self.id, &request, now).unwrap() {
            ReleaseClaim::Acquired(lease) => *lease,
            other => panic!("expected lease, got {other:?}"),
        }
    }

    fn until(&self, phase: ReleasePhase, now: &mut u64) {
        for _ in 0..16 {
            if self.host.inspect(&self.id).unwrap().phase == phase {
                return;
            }
            self.host.advance_at(&self.id, *now).unwrap();
            *now += 1;
        }
        panic!("workflow failed to reach {phase:?}");
    }
}

#[test]
fn weak_secret_reads_are_durable_waits_and_cannot_poison_later_qualified_readiness() {
    let fixture = Fixture::new(false);
    fixture.host.advance_at(&fixture.id, 0).unwrap();
    for (index, revision) in [
        RevisionToken::Opaque {
            token: "opaque-weak-read".to_owned().try_into().unwrap(),
        },
        RevisionToken::Ordered {
            stream: Digest::of(&fixture.provider.approval.secret).unwrap(),
            sequence: 999_u64.try_into().unwrap(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let mut weak = observation(&fixture.provider.approval, 999);
        weak.provider_state = StateEvidence::Observed { revision };
        *fixture.provider.secret.lock().unwrap() = Some(weak);
        fixture
            .host
            .advance_at(&fixture.id, index as u64 + 1)
            .unwrap();
        assert_eq!(
            fixture.host.inspect(&fixture.id).unwrap().phase,
            ReleasePhase::WaitingSecret
        );
        let journal = Journal::open(&fixture.path).unwrap();
        assert!(
            journal
                .release_secret_metadata(
                    &fixture.provider.approval.target,
                    &fixture.provider.approval.secret
                )
                .unwrap()
                .is_none()
        );
        assert!(
            journal
                .release_state(&fixture.provider.approval.target)
                .unwrap()
                .active
                .is_none()
        );
    }
    assert_eq!(fixture.provider.writes.lock().unwrap().len(), 1);
    let weak_records: i64 = Connection::open(&fixture.path).unwrap().query_row(
        "SELECT count(*) FROM release_steps WHERE status='complete' AND json_extract(result,'$.outcome.metadata.provider_state.kind')='observed'",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(weak_records, 2);
    *fixture.provider.secret.lock().unwrap() = Some(observation(&fixture.provider.approval, 1));
    fixture.until(ReleasePhase::Active, &mut 3);
}

#[test]
fn contradictory_qualified_secret_invalidates_queued_activation_until_fresh_preparation() {
    let fixture = Fixture::new(true);
    let mut now = 0;
    fixture.until(ReleasePhase::DeploymentReady, &mut now);
    let writes = fixture.provider.writes.lock().unwrap().len();
    let approval = &fixture.provider.approval;
    let mut conflicting = observation(approval, 1);
    conflicting.enabled = false;
    let mut journal = Journal::open(&fixture.path).unwrap();
    assert!(
        journal
            .observe_release_secret(&approval.target, &name("contradictory"), 1, &conflicting)
            .is_err()
    );
    fixture.host.advance_at(&fixture.id, now).unwrap();
    now += 1;
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().phase,
        ReleasePhase::WaitingSecret
    );
    assert!(
        journal
            .release_state(&approval.target)
            .unwrap()
            .active
            .is_none()
    );
    *fixture.provider.secret.lock().unwrap() = Some(observation(approval, 2));
    fixture.until(ReleasePhase::DeploymentReady, &mut now);
    assert_eq!(fixture.provider.writes.lock().unwrap().len(), writes + 1);
    fixture.until(ReleasePhase::Active, &mut now);
}

#[test]
fn deployment_readback_requires_qualified_exact_prepared_effect_not_weak_state() {
    let fixture = Fixture::new(true);
    let mut now = 0;
    fixture.until(ReleasePhase::WaitingDeployment, &mut now);
    let lease = fixture.lease(now);
    let original = fixture.host.perform_at(&lease, now).unwrap();
    let ReleaseEffectResult::Observed(mut weak) = original else {
        panic!("expected deployment read")
    };
    let ReleaseObserved::Deployment { evidence, .. } = &mut weak.outcome else {
        panic!("expected deployment read")
    };
    *evidence = StateEvidence::Observed {
        revision: RevisionToken::Opaque {
            token: "weak-ready".to_owned().try_into().unwrap(),
        },
    };
    fixture
        .host
        .settle_at(&lease, ReleaseEffectResult::Observed(weak), now)
        .unwrap();
    now += 1;
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().phase,
        ReleasePhase::WaitingDeployment
    );
    let lease = fixture.lease(now);
    let original = fixture.host.perform_at(&lease, now).unwrap();
    for field in 0..5 {
        let ReleaseEffectResult::Observed(mut wrong) = original.clone() else {
            panic!("expected deployment read")
        };
        let ReleaseObserved::Deployment {
            incarnation,
            evidence: StateEvidence::Qualified { barrier, .. },
            ..
        } = &mut wrong.outcome
        else {
            panic!("expected qualified deployment read")
        };
        match field {
            0 => barrier.after_effect = Some(Digest::new(b"other-deployment-effect")),
            1 => barrier.resource = Digest::new(b"other-resource"),
            2 => barrier.authority.revision = Digest::new(b"other-authority"),
            3 => incarnation.controller = "other-controller".to_owned().try_into().unwrap(),
            _ => incarnation.generation = "other-generation".to_owned().try_into().unwrap(),
        }
        let before = fixture.host.inspect(&fixture.id).unwrap();
        let journal = Journal::open(&fixture.path).unwrap();
        let audit = journal
            .release_event_count(&fixture.provider.approval.target)
            .unwrap();
        assert!(
            fixture
                .host
                .settle_at(&lease, ReleaseEffectResult::Observed(wrong), now)
                .is_err()
        );
        assert_eq!(fixture.host.inspect(&fixture.id).unwrap(), before);
        assert_eq!(
            journal
                .release_event_count(&fixture.provider.approval.target)
                .unwrap(),
            audit
        );
    }
    fixture.host.settle_at(&lease, original, now).unwrap();
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().phase,
        ReleasePhase::DeploymentReady
    );
    fixture.until(ReleasePhase::Active, &mut (now + 1));
}

#[test]
fn compiled_recipe_waits_reopens_and_uses_distinct_read_steps_before_atomic_activation() {
    let fixture = Fixture::new(false);
    fixture.host.advance_at(&fixture.id, 0).unwrap();
    for now in 1..=3 {
        fixture.host.advance_at(&fixture.id, now).unwrap();
    }
    let snapshot = fixture.host.inspect(&fixture.id).unwrap();
    assert_eq!(snapshot.phase, ReleasePhase::WaitingSecret);
    assert_eq!(snapshot.next_step, 4);
    let connection = Connection::open(&fixture.path).unwrap();
    let (steps, identities): (i64, i64) = connection
        .query_row(
            "SELECT count(*),count(DISTINCT id) FROM release_steps
        WHERE json_extract(request,'$.operation')='observe_secret'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((steps, identities), (3, 3));
    *fixture.provider.secret.lock().unwrap() = Some(observation(&fixture.provider.approval, 1));
    let restored = ReleaseExecutionHost::new(
        fixture.path.clone(),
        name("alpha"),
        name("restored"),
        fixture.provider.plan.durability.clone(),
        fixture.provider.clone(),
        Arc::new(CompiledReleaseRecipe::installed().unwrap()),
    );
    assert_eq!(restored.inspect(&fixture.id).unwrap(), snapshot);
    for now in 4..=7 {
        restored.advance_at(&fixture.id, now).unwrap();
    }
    assert_eq!(
        restored.inspect(&fixture.id).unwrap().terminal,
        Some(ReleaseTerminal::Activated)
    );
    let journal = Journal::open(&fixture.path).unwrap();
    assert_eq!(
        journal
            .release_state(&fixture.provider.approval.target)
            .unwrap()
            .active
            .unwrap()
            .artifact,
        fixture.provider.approval.artifact
    );
    let (activation, completion): (i64, i64) = connection
        .query_row(
            "SELECT
        (SELECT count(*) FROM release_events WHERE kind='activated'),
        (SELECT count(*) FROM release_events WHERE kind='workflow_completed_step'
            AND json_extract(body,'$[1][2].terminal')='activated')",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((activation, completion), (1, 1));
}

#[test]
fn lost_ack_reconciles_same_step_and_forged_recovery_or_expired_dispatch_is_fenced() {
    let fixture = Fixture::new(true);
    let old = fixture.lease(0);
    let result = fixture.host.perform_at(&old, 1).unwrap();
    assert!(fixture.host.perform_at(&old, 2).is_err());
    assert!(
        fixture
            .host
            .settle_at(&old, result.clone(), LEASE_MILLIS)
            .is_err()
    );
    let recovered = fixture.lease(LEASE_MILLIS);
    assert_eq!(recovered.effect, old.effect);
    assert_eq!(recovered.recovery, RecoveryMode::Reconcile);
    let mut forged = recovered.clone();
    forged.recovery = RecoveryMode::Execute;
    assert_eq!(
        fixture
            .host
            .perform_at(&forged, LEASE_MILLIS + 1)
            .unwrap_err()
            .downcast_ref::<ReleaseRejection>(),
        Some(&ReleaseRejection::FencedLease)
    );
    let actual = fixture
        .host
        .perform_at(&recovered, LEASE_MILLIS + 1)
        .unwrap();
    assert_eq!(
        fixture
            .host
            .settle_at(
                &forged,
                ReleaseEffectResult::RetryNotApplied {},
                LEASE_MILLIS + 2
            )
            .unwrap_err()
            .downcast_ref::<ReleaseRejection>(),
        Some(&ReleaseRejection::FencedLease)
    );
    assert_eq!(
        fixture
            .host
            .settle_at(
                &recovered,
                ReleaseEffectResult::RetryNotApplied {},
                LEASE_MILLIS + 2
            )
            .unwrap_err()
            .downcast_ref::<ReleaseRejection>(),
        Some(&ReleaseRejection::UncertainMutation)
    );
    fixture
        .host
        .settle_at(&recovered, actual, LEASE_MILLIS + 2)
        .unwrap();
    assert_eq!(fixture.provider.writes.lock().unwrap().len(), 1);
    let expired = fixture.lease(LEASE_MILLIS + 3);
    assert_eq!(
        fixture
            .host
            .perform_at(&expired, expired.until)
            .unwrap_err()
            .downcast_ref::<ReleaseRejection>(),
        Some(&ReleaseRejection::FencedLease)
    );
}

#[test]
fn crash_before_dispatch_is_proven_unapplied_and_reclaims_execute_without_blind_reconciliation() {
    let fixture = Fixture::new(true);
    let old = fixture.lease(0);
    let restored = fixture.lease(LEASE_MILLIS);
    assert_eq!(restored.effect, old.effect);
    assert_eq!(restored.recovery, RecoveryMode::Execute);
    assert_eq!(
        fixture
            .host
            .perform_at(&old, LEASE_MILLIS + 1)
            .unwrap_err()
            .downcast_ref::<ReleaseRejection>(),
        Some(&ReleaseRejection::FencedLease)
    );
    let result = fixture
        .host
        .perform_at(&restored, LEASE_MILLIS + 1)
        .unwrap();
    fixture
        .host
        .settle_at(&restored, result, LEASE_MILLIS + 2)
        .unwrap();
    assert_eq!(fixture.provider.writes.lock().unwrap().len(), 1);
}

#[test]
fn wrong_provider_facts_never_advance_and_binding_revocation_does_not_erase_inflight_receipt() {
    let fixture = Fixture::new(true);
    let lease = fixture.lease(0);
    let ReleaseEffectResult::Observed(valid) = fixture.host.perform_at(&lease, 1).unwrap() else {
        panic!("observation")
    };
    for field in 0..8 {
        let mut invalid = valid.clone();
        match field {
            0 => invalid.fact.target.company = name("beta"),
            1 => invalid.fact.artifact = Digest::new(b"wrong"),
            2 => invalid.fact.binding.revision = Digest::new(b"wrong"),
            3 => invalid.fact.secret.version = 2.try_into().unwrap(),
            4 => invalid.fact.resource = Digest::new(b"wrong"),
            5 => invalid.fact.plan = Digest::new(b"wrong"),
            6 => invalid.fact.effect = Digest::new(b"wrong"),
            _ => invalid.fact.readiness = Some(Digest::new(b"wrong")),
        }
        assert_eq!(
            fixture
                .host
                .settle_at(&lease, ReleaseEffectResult::Observed(invalid), 2)
                .unwrap_err()
                .downcast_ref::<ReleaseRejection>(),
            Some(&ReleaseRejection::InvalidFact)
        );
    }
    fixture.provider.denied.store(true, Ordering::SeqCst);
    fixture
        .host
        .settle_at(&lease, ReleaseEffectResult::Observed(valid), 2)
        .unwrap();
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().phase,
        ReleasePhase::WaitingSecret
    );
}

#[test]
fn superseded_provider_read_is_recorded_then_stopped_without_a_new_mutation() {
    let fixture = Fixture::new(true);
    fixture.host.advance_at(&fixture.id, 0).unwrap();
    let read = fixture.lease(1);
    let result = fixture.host.perform_at(&read, 2).unwrap();
    let mut journal = Journal::open(&fixture.path).unwrap();
    let successor = approval(&mut journal, "alpha", 2, 1);
    journal.approve_release(&successor).unwrap();
    let mut wrong_reference = result.clone();
    if let ReleaseEffectResult::Observed(observation) = &mut wrong_reference
        && let ReleaseObserved::Secret {
            metadata: Some(metadata),
        } = &mut observation.outcome
    {
        metadata.reference.version = 2.try_into().unwrap();
    } else {
        panic!("expected secret metadata");
    }
    assert_eq!(
        fixture
            .host
            .settle_at(&read, wrong_reference, 3)
            .unwrap_err()
            .downcast_ref::<ReleaseRejection>(),
        Some(&ReleaseRejection::InvalidFact)
    );
    fixture.host.settle_at(&read, result, 3).unwrap();
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().terminal,
        Some(ReleaseTerminal::AuthorityLost)
    );
    assert_eq!(fixture.provider.writes.lock().unwrap().len(), 1);
    assert_eq!(
        journal.release_state(&successor.target).unwrap().active,
        None
    );
    let connection = Connection::open(&fixture.path).unwrap();
    let complete: i64 = connection
        .query_row(
            "SELECT count(*) FROM release_steps WHERE status='complete'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(complete, 2);
}

#[test]
fn changed_guard_between_claim_and_dispatch_never_calls_provider() {
    let fixture = Fixture::new(true);
    let lease = fixture.lease(0);
    let mut journal = Journal::open(&fixture.path).unwrap();
    let approved = journal
        .load_approved_release(&fixture.provider.plan.release)
        .unwrap();
    journal
        .revoke_release(&approved, &actor("reviewer"))
        .unwrap();
    let result = fixture.host.perform_at(&lease, 1).unwrap();
    assert_eq!(result, ReleaseEffectResult::GuardChanged {});
    fixture.host.settle_at(&lease, result, 2).unwrap();
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().terminal,
        Some(ReleaseTerminal::AuthorityLost)
    );
    assert!(fixture.provider.writes.lock().unwrap().is_empty());
}

#[test]
fn secret_invalidation_retires_unapplied_step_then_requires_fresh_deployment_generation() {
    let fixture = Fixture::new(true);
    let mut now = 0;
    fixture.until(ReleasePhase::SecretReady, &mut now);
    fixture
        .provider
        .retry_deployment
        .store(true, Ordering::SeqCst);
    fixture.host.advance_at(&fixture.id, now).unwrap();
    now += 1;
    let old_ordinal = fixture.host.inspect(&fixture.id).unwrap().next_step;
    let mut journal = Journal::open(&fixture.path).unwrap();
    let mut disabled = observation(&fixture.provider.approval, 2);
    disabled.enabled = false;
    journal
        .observe_release_secret(
            &fixture.provider.approval.target,
            &name("disabled"),
            1,
            &disabled,
        )
        .unwrap();
    fixture.host.advance_at(&fixture.id, now).unwrap();
    now += 1;
    let waiting = fixture.host.inspect(&fixture.id).unwrap();
    assert_eq!(waiting.phase, ReleasePhase::WaitingSecret);
    assert_eq!(waiting.next_step, old_ordinal + 1);
    *fixture.provider.secret.lock().unwrap() = Some(observation(&fixture.provider.approval, 3));
    fixture.until(ReleasePhase::DeploymentReady, &mut now);
    let prior_preparation = fixture.provider.resources.lock().unwrap().clone();
    let mut disabled = observation(&fixture.provider.approval, 4);
    disabled.access_granted = false;
    journal
        .observe_release_secret(
            &fixture.provider.approval.target,
            &name("access-lost"),
            3,
            &disabled,
        )
        .unwrap();
    fixture.host.advance_at(&fixture.id, now).unwrap();
    now += 1;
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().phase,
        ReleasePhase::WaitingSecret
    );
    *fixture.provider.secret.lock().unwrap() = Some(observation(&fixture.provider.approval, 5));
    fixture.until(ReleasePhase::Active, &mut now);
    assert_ne!(
        *fixture.provider.resources.lock().unwrap(),
        prior_preparation
    );
    assert_eq!(fixture.provider.writes.lock().unwrap().len(), 3);
}

#[test]
fn enrolled_release_cannot_bypass_deployment_and_activation_failure_rolls_back_workflow_together() {
    let fixture = Fixture::new(true);
    let mut now = 0;
    fixture.until(ReleasePhase::DeploymentReady, &mut now);
    let mut journal = Journal::open(&fixture.path).unwrap();
    let approved = journal
        .load_approved_release(&fixture.provider.plan.release)
        .unwrap();
    let ready = journal.prepare_release(&approved).unwrap();
    assert!(journal.activate_release(&ready).is_err());
    let lease = fixture.lease(now);
    let result = fixture.host.perform_at(&lease, now + 1).unwrap();
    let connection = Connection::open(&fixture.path).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_workflow_completion BEFORE INSERT ON release_events
        WHEN NEW.kind='workflow_completed_step' BEGIN SELECT RAISE(ABORT,'test workflow audit outage'); END;").unwrap();
    assert!(
        fixture
            .host
            .settle_at(&lease, result.clone(), now + 2)
            .is_err()
    );
    assert_eq!(
        journal
            .release_state(&fixture.provider.approval.target)
            .unwrap()
            .active,
        None
    );
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().phase,
        ReleasePhase::DeploymentReady
    );
    connection
        .execute_batch("DROP TRIGGER fail_workflow_completion;")
        .unwrap();
    fixture.host.settle_at(&lease, result, now + 2).unwrap();
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().terminal,
        Some(ReleaseTerminal::Activated)
    );
    assert!(journal.activate_release(&ready).is_err());
}

#[test]
fn strict_provider_result_contract_rejects_payload_on_empty_variants() {
    for kind in [
        "retry_not_applied",
        "ambiguous",
        "activate",
        "guard_changed",
    ] {
        assert!(
            serde_json::from_value::<ReleaseEffectResult>(
                serde_json::json!({"kind":kind,"unexpected":true})
            )
            .is_err()
        );
    }
    for kind in ["dependency_prepared", "deployment_prepared"] {
        assert!(
            serde_json::from_value::<ReleaseObserved>(
                serde_json::json!({"kind":kind,"unexpected":true})
            )
            .is_err()
        );
    }
}

#[test]
fn contradictory_persisted_phase_or_success_without_authority_receipt_is_rejected() {
    let fixture = Fixture::new(true);
    let connection = Connection::open(&fixture.path).unwrap();
    let original: String = connection
        .query_row(
            "SELECT body FROM release_workflows WHERE id=?1",
            [fixture.id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    for field in 0..4 {
        let mut body: serde_json::Value = serde_json::from_str(&original).unwrap();
        match field {
            0 => body["snapshot"]["terminal"] = serde_json::json!("activated"),
            1 => body["snapshot"]["phase"] = serde_json::json!("deployment_ready"),
            2 => body["snapshot"]["phase"] = serde_json::json!("stopped"),
            _ => body["snapshot"]["phase"] = serde_json::json!("secret_ready"),
        }
        connection
            .execute(
                "UPDATE release_workflows SET body=?1 WHERE id=?2",
                rusqlite::params![serde_json::to_string(&body).unwrap(), fixture.id.as_str()],
            )
            .unwrap();
        assert!(fixture.host.inspect(&fixture.id).is_err());
    }
    connection
        .execute(
            "UPDATE release_workflows SET body=?1 WHERE id=?2",
            rusqlite::params![original, fixture.id.as_str()],
        )
        .unwrap();
    let mut now = 0;
    fixture.until(ReleasePhase::Active, &mut now);
    let (mut body, original): (serde_json::Value, String) = {
        let original: String = connection
            .query_row(
                "SELECT body FROM release_workflows WHERE id=?1",
                [fixture.id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        (serde_json::from_str(&original).unwrap(), original)
    };
    body["activation"]["artifact"] = serde_json::to_value(Digest::new(b"forged-artifact")).unwrap();
    connection
        .execute(
            "UPDATE release_workflows SET body=?1 WHERE id=?2",
            rusqlite::params![serde_json::to_string(&body).unwrap(), fixture.id.as_str()],
        )
        .unwrap();
    assert!(fixture.host.inspect(&fixture.id).is_err());
    connection
        .execute(
            "UPDATE release_workflows SET body=?1 WHERE id=?2",
            rusqlite::params![original, fixture.id.as_str()],
        )
        .unwrap();
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().terminal,
        Some(ReleaseTerminal::Activated)
    );
}

#[test]
fn explicit_absence_evidence_is_durable_before_an_uncertain_mutation_can_execute_again() {
    let fixture = Fixture::new(true);
    fixture
        .provider
        .unknown_mutation
        .store(true, Ordering::SeqCst);
    let first = fixture.lease(0);
    let ambiguous = fixture.host.perform_at(&first, 1).unwrap();
    assert_eq!(ambiguous, ReleaseEffectResult::Ambiguous {});
    fixture.host.settle_at(&first, ambiguous, 2).unwrap();
    let restored = ReleaseExecutionHost::new(
        fixture.path.clone(),
        name("alpha"),
        name("restored"),
        fixture.provider.plan.durability.clone(),
        fixture.provider.clone(),
        Arc::new(CompiledReleaseRecipe::installed().unwrap()),
    );
    let snapshot = restored.inspect(&fixture.id).unwrap();
    let request = fixture.recipe.choose(&snapshot).unwrap();
    let ReleaseClaim::Acquired(reconcile) = restored.claim_at(&fixture.id, &request, 3).unwrap()
    else {
        panic!("reconcile")
    };
    assert_eq!(reconcile.recovery, RecoveryMode::Reconcile);
    let absence = restored.perform_at(&reconcile, 4).unwrap();
    assert!(matches!(
        absence,
        ReleaseEffectResult::ReconciledAbsent { .. }
    ));
    let connection = Connection::open(&fixture.path).unwrap();
    connection.execute_batch("CREATE TRIGGER reject_absence_audit BEFORE INSERT ON release_events
        WHEN NEW.kind='workflow_settlement' AND json_extract(NEW.body,'$[1][1].kind')='reconciled_absent'
        BEGIN SELECT RAISE(ABORT,'test audit unavailable'); END;").unwrap();
    assert!(restored.settle_at(&reconcile, absence.clone(), 5).is_err());
    assert!(matches!(
        restored.claim_at(&fixture.id, &request, 6).unwrap(),
        ReleaseClaim::Busy
    ));
    assert!(fixture.provider.writes.lock().unwrap().is_empty());
    connection
        .execute_batch("DROP TRIGGER reject_absence_audit;")
        .unwrap();
    restored.settle_at(&reconcile, absence.clone(), 7).unwrap();
    let (sequence, body): (i64, String) = connection
        .query_row(
            "SELECT sequence,body FROM release_events
        WHERE kind='workflow_settlement' AND json_extract(body,'$[1][1].kind')='reconciled_absent'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let persisted: ReleaseEffectResult = serde_json::from_value(body[1][1].clone()).unwrap();
    assert_eq!(persisted, absence);
    let ReleaseClaim::Acquired(retry) = restored.claim_at(&fixture.id, &request, 8).unwrap() else {
        panic!("retry")
    };
    assert_eq!(retry.recovery, RecoveryMode::Execute);
    assert_eq!(retry.effect, first.effect);
    let completed = restored.perform_at(&retry, 9).unwrap();
    restored.settle_at(&retry, completed, 10).unwrap();
    assert_eq!(fixture.provider.writes.lock().unwrap().len(), 1);
    let dispatch: i64 = connection
        .query_row(
            "SELECT max(sequence) FROM release_events WHERE kind='workflow_provider_dispatch'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(sequence < dispatch);
}
