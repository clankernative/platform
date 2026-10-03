//! HTTP protocol fixtures, not live GKE qualification or forge authentication.
#[path = "support/release.rs"]
mod support;

use anyhow::Result;
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    routing::any,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use day2_control::{
    BindingRef, Digest,
    gke_release::{Deployment, GkeReleaseProvider},
    journal::Journal,
    kubernetes_conformance::GkeServingBinding,
    release::ReleaseApproval,
    release_execution::{
        Capabilities, ReleaseExecutionHost, ReleaseExecutionPlan, ReleasePhase, ReleaseTerminal,
    },
    release_recipe::CompiledReleaseRecipe,
    secrets::{AccessToken, AccessTokenProvider, SecretVersion},
    source::SourceError,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex, mpsc},
    thread,
};
use support::*;

const NS: &str = "disposable";
const WORKLOAD: &str = "/apis/apps/v1/namespaces/disposable/statefulsets/day2-reports";
const CMS: &str = "/api/v1/namespaces/disposable/configmaps";
const TOKEN: &str = "fixture-only-token";
struct Tokens;
impl AccessTokenProvider for Tokens {
    fn access_token(&self) -> std::result::Result<AccessToken, SourceError> {
        AccessToken::new(TOKEN.into())
    }
}

struct Cloud {
    controller: Value,
    maps: BTreeMap<String, Value>,
    versions: Vec<String>,
    patches: usize,
    publications: usize,
    secret_denied: bool,
    drop_deployment_ack: bool,
    drop_publication_ack: bool,
    conflict: bool,
    wrong_pod: bool,
    unknown_absence: bool,
}

async fn serve(
    State(state): State<Arc<Mutex<Cloud>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> (StatusCode, axum::Json<Value>) {
    assert_eq!(headers["authorization"], format!("Bearer {TOKEN}"));
    let mut cloud = state.lock().unwrap();
    let path = uri.path();
    let mut status = StatusCode::OK;
    let body = if path == "/v1/projects/12345/locations/us-central1/clusters/probe" {
        json!({"name":"probe","location":"us-central1","status":"RUNNING","id":"cluster-uid", "currentMasterVersion":"1.34-fixture", "endpoint":"203.0.113.1", "masterAuth":{"clusterCaCertificate":STANDARD.encode("fixture-ca")}})
    } else if path.starts_with("/v1/projects/12345/secrets/") && path.ends_with(":access") {
        if cloud.secret_denied {
            status = StatusCode::FORBIDDEN;
            json!({})
        } else {
            let payload = b"synthetic-private-key-never-journaled";
            json!({"name":path.trim_start_matches("/v1/").trim_end_matches(":access"), "payload":{"data":STANDARD.encode(payload),"dataCrc32c":crc32c::crc32c(payload).to_string()}})
        }
    } else if path
        == "/apis/secrets-store.csi.x-k8s.io/v1/namespaces/disposable/secretproviderclasses/keys"
    {
        json!({"spec":{"provider":"gke","parameters":{"secrets":serde_json::to_string(&json!([
            {"resourceName":cloud.versions[0],"path":"workload"},{"resourceName":cloud.versions[1],"path":"issuer"}
        ])).unwrap()}}})
    } else if path == WORKLOAD {
        if method == Method::PATCH {
            let patch: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(headers["content-type"], "application/json-patch+json");
            assert_eq!(patch[0]["path"], "/metadata/uid");
            assert_eq!(patch[1]["path"], "/metadata/resourceVersion");
            cloud.patches += 1;
            if cloud.conflict
                || patch[0]["value"] != cloud.controller["metadata"]["uid"]
                || patch[1]["value"] != cloud.controller["metadata"]["resourceVersion"]
            {
                cloud.conflict = false;
                status = StatusCode::CONFLICT;
            } else if cloud.unknown_absence {
                status = StatusCode::INTERNAL_SERVER_ERROR;
            } else {
                cloud.controller["metadata"]["annotations"]["day2.dev/release-effect"] =
                    patch[2]["value"].clone();
                cloud.controller["metadata"]["annotations"]["day2.dev/release-id"] =
                    patch[3]["value"].clone();
                cloud.controller["spec"]["template"] = patch[4]["value"].clone();
                let generation = cloud.controller["metadata"]["generation"].as_u64().unwrap() + 1;
                cloud.controller["metadata"]["generation"] = json!(generation);
                cloud.controller["metadata"]["resourceVersion"] = json!(format!("rv-{generation}"));
                cloud.controller["status"] = json!({"observedGeneration":generation,"readyReplicas":1,"updatedReplicas":1,"currentRevision":format!("rev-{generation}"),"updateRevision":format!("rev-{generation}")});
                if cloud.drop_deployment_ack {
                    cloud.drop_deployment_ack = false;
                    status = StatusCode::INTERNAL_SERVER_ERROR;
                }
            }
        }
        cloud.controller.clone()
    } else if path == "/api/v1/namespaces/disposable/pods/day2-reports-0" {
        let controller = &cloud.controller;
        let mut annotations = controller["spec"]["template"]["metadata"]["annotations"].clone();
        if cloud.wrong_pod {
            annotations["day2.dev/artifact"] = json!(Digest::new(b"wrong"));
        }
        let spec = controller["spec"]["template"]["spec"].clone();
        json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"day2-reports-0","namespace":NS,"uid":"pod-uid", "resourceVersion":"pod-rv", "annotations":annotations,"labels":{"controller-revision-hash":controller["status"]["updateRevision"]}, "ownerReferences":[{"kind":"StatefulSet","name":"day2-reports","uid":controller["metadata"]["uid"],"controller":true}]}, "spec":spec,"status":{"phase":"Running","containerStatuses":[{"name":"day2","ready":true,"started":true,"imageID":spec["containers"][0]["image"],"state":{"running":{}}}]}})
    } else if path == "/api/v1/namespaces/disposable/serviceaccounts/runtime" {
        json!({"metadata":{"name":"runtime","namespace":NS,"uid":"account-uid","resourceVersion":"account-rv","annotations":{"iam.gke.io/gcp-service-account":"reports@project.iam.gserviceaccount.com"}}})
    } else if path == CMS && method == Method::POST {
        let mut cm: Value = serde_json::from_slice(&bytes).unwrap();
        let name = cm["metadata"]["name"].as_str().unwrap().to_owned();
        if cloud.maps.contains_key(&name) {
            status = StatusCode::CONFLICT;
        } else {
            cm["metadata"]["uid"] = json!(format!("cm-{name}"));
            cm["metadata"]["resourceVersion"] = json!("1");
            cloud.maps.insert(name.clone(), cm);
            if name == "serving" {
                cloud.publications += 1;
                if cloud.drop_publication_ack {
                    cloud.drop_publication_ack = false;
                    status = StatusCode::INTERNAL_SERVER_ERROR;
                }
            }
        }
        cloud.maps[&name].clone()
    } else if let Some(name) = path.strip_prefix(&format!("{CMS}/")) {
        if method == Method::PUT {
            let mut cm: Value = serde_json::from_slice(&bytes).unwrap();
            let old = cloud.maps.get(name).unwrap();
            if cm["metadata"]["uid"] != old["metadata"]["uid"]
                || cm["metadata"]["resourceVersion"] != old["metadata"]["resourceVersion"]
            {
                status = StatusCode::CONFLICT;
            } else {
                let rv = old["metadata"]["resourceVersion"]
                    .as_str()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
                    + 1;
                cm["metadata"]["resourceVersion"] = json!(rv.to_string());
                cloud.maps.insert(name.to_owned(), cm);
                cloud.publications += 1;
                if cloud.drop_publication_ack {
                    cloud.drop_publication_ack = false;
                    status = StatusCode::INTERNAL_SERVER_ERROR;
                }
            }
        }
        cloud.maps.get(name).cloned().unwrap_or_else(|| {
            status = StatusCode::NOT_FOUND;
            json!({})
        })
    } else {
        status = StatusCode::NOT_FOUND;
        json!({})
    };
    (status, axum::Json(body))
}

struct Fixture {
    endpoint: String,
    cloud: Arc<Mutex<Cloud>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new(deployment: &Deployment) -> Self {
        let annotations = json!({"day2.dev/installation":"alpha","day2.dev/environment":"production","day2.dev/app":"reports","day2.dev/artifact":Digest::new(b"bootstrap")});
        let cloud = Arc::new(Mutex::new(Cloud {
            controller: json!({"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"day2-reports","namespace":NS,"uid":"controller-uid","generation":1,"resourceVersion":"rv-1","annotations":{"day2.dev/release-managed":"true"}},"spec":{"replicas":1,"template":{"metadata":{"annotations":annotations},"spec":{"serviceAccountName":"runtime","containers":[{"name":"day2","image":deployment.image,"env":[{"name":"DAY2_EXPECTED_ARTIFACT","value":Digest::new(b"bootstrap")}]}],"volumes":[{"name":"instance","configMap":{"name":"bootstrap-instance"}},{"name":"keys","csi":{"driver":"secrets-store-gke.csi.k8s.io","volumeAttributes":{"secretProviderClass":"keys"}}}]}}},"status":{"observedGeneration":1,"readyReplicas":1,"updatedReplicas":1,"currentRevision":"rev-1","updateRevision":"rev-1"}}),
            maps: BTreeMap::new(),
            versions: deployment
                .secret_versions
                .iter()
                .map(SecretVersion::resource_name)
                .collect(),
            patches: 0,
            publications: 0,
            secret_denied: false,
            drop_deployment_ack: false,
            drop_publication_ack: false,
            conflict: false,
            wrong_pod: false,
            unknown_absence: false,
        }));
        let (send, receive) = mpsc::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let state = cloud.clone();
        let thread = thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                    send.send(format!("http://{}/", listener.local_addr().unwrap()))
                        .unwrap();
                    axum::serve(
                        listener,
                        Router::new().fallback(any(serve)).with_state(state),
                    )
                    .with_graceful_shutdown(async {
                        let _ = stopped.await;
                    })
                    .await
                    .unwrap();
                });
        });
        Self {
            endpoint: receive.recv().unwrap(),
            cloud,
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.thread.take().unwrap().join().unwrap();
    }
}

struct World {
    _directory: tempfile::TempDir,
    journal: PathBuf,
    fixture: Fixture,
    recipe: Arc<CompiledReleaseRecipe>,
    host: ReleaseExecutionHost,
    provider: Arc<GkeReleaseProvider>,
    approval: ReleaseApproval,
    deployment: Deployment,
    id: Digest,
    clock: u64,
}

impl World {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let journal = directory.path().join("journal.sqlite");
        let mut storage = Journal::open(&journal)?;
        configure(&mut storage, &target("alpha"), &plan("alpha", 1));
        let approval = approval(&mut storage, "alpha", 1, 0);
        storage.approve_release(&approval)?;
        let instance = json!({"installation":"alpha","environment":"production","identity":{"scheme":"google_iap","hosted_domain":"example.com"},"apps":{"reports":{"artifact":format!("artifacts/{}",approval.artifact.as_str().trim_start_matches("sha256:")),"readers":["alice@example.com"],"writers":["alice@example.com"],"authority":{"version":1,"operations":{}},"edge":{"origin":"https://reports.example.com","iap_audience":"/projects/12345/global/backendServices/67890"}}}});
        let mut deployment = Deployment {
            serving: GkeServingBinding {
                target: approval.target.clone(),
                project_number: 12345.try_into()?,
                location: "us-central1".into(),
                cluster: "probe".into(),
                namespace: NS.into(),
                workload: "day2-reports".into(),
                workload_email: "reports@project.iam.gserviceaccount.com".into(),
                deployment: BindingRef::pin(name("deployment"), &"initial")?,
            },
            image: format!("registry.example/day2@sha256:{}", "1".repeat(64)),
            instance,
            secret_projection: "keys".into(),
            secret_versions: vec![
                SecretVersion {
                    project_number: 12345,
                    secret: "api-credential".into(),
                    version: 1,
                },
                SecretVersion {
                    project_number: 12345,
                    secret: "issuer".into(),
                    version: 1,
                },
            ],
            serving_config_map: "serving".into(),
        };
        deployment.serving.deployment = deployment.binding(name("deployment"))?;
        let fixture = Fixture::new(&deployment);
        let recipe = Arc::new(CompiledReleaseRecipe::installed()?);
        let provider = Arc::new(GkeReleaseProvider::transport_fixture(
            journal.clone(),
            deployment.clone(),
            Arc::new(Tokens),
            &fixture.endpoint,
            &fixture.endpoint,
            &fixture.endpoint,
        )?);
        let durability = BindingRef::pin(name("durability"), &"local-journal")?;
        let host = ReleaseExecutionHost::new(
            journal.clone(),
            name("alpha"),
            name("worker"),
            durability.clone(),
            provider.clone(),
            recipe.clone(),
        );
        let release_plan = ReleaseExecutionPlan {
            release: Digest::of(&("day2-release-v1", &approval.target, &approval.request))?,
            recipe: recipe.identity()?,
            durability,
            resources: approval.secret.binding.clone(),
            deployment: deployment.serving.deployment.clone(),
            deployment_input: Some(Digest::of(&deployment)?),
        };
        let id = host.accept(&release_plan)?;
        Ok(Self {
            _directory: directory,
            journal,
            fixture,
            recipe,
            host,
            provider,
            approval,
            deployment,
            id,
            clock: 100_000,
        })
    }
    fn step(&mut self) -> Result<()> {
        self.clock += 40_000;
        self.host.advance_at(&self.id, self.clock)?;
        Ok(())
    }
    fn until(&mut self, phase: ReleasePhase) -> Result<()> {
        for _ in 0..12 {
            if self.host.inspect(&self.id)?.phase == phase {
                return Ok(());
            }
            self.step()?;
        }
        anyhow::bail!("phase did not advance")
    }
    fn activate(&mut self) -> Result<()> {
        self.until(ReleasePhase::Active)?;
        assert_eq!(
            self.host.inspect(&self.id)?.terminal,
            Some(ReleaseTerminal::Activated)
        );
        Ok(())
    }
    fn redeploy(&mut self) -> Result<()> {
        let mut journal = Journal::open(&self.journal)?;
        let mut approval = approval(&mut journal, "alpha", 2, 1);
        // Same key and infrastructure; only the actual app candidate changes.
        approval.secret = self.approval.secret.clone();
        journal.approve_release(&approval)?;
        self.deployment.instance["apps"]["reports"]["artifact"] = json!(format!(
            "artifacts/{}",
            approval.artifact.as_str().trim_start_matches("sha256:")
        ));
        self.deployment.image = format!("registry.example/day2@sha256:{}", "2".repeat(64));
        assert_eq!(
            self.deployment.binding(name("deployment"))?,
            self.deployment.serving.deployment
        );
        self.provider = Arc::new(GkeReleaseProvider::transport_fixture(
            self.journal.clone(),
            self.deployment.clone(),
            Arc::new(Tokens),
            &self.fixture.endpoint,
            &self.fixture.endpoint,
            &self.fixture.endpoint,
        )?);
        let durability = BindingRef::pin(name("durability"), &"local-journal")?;
        self.host = ReleaseExecutionHost::new(
            self.journal.clone(),
            name("alpha"),
            name("worker"),
            durability.clone(),
            self.provider.clone(),
            self.recipe.clone(),
        );
        self.id = self.host.accept(&ReleaseExecutionPlan {
            release: Digest::of(&("day2-release-v1", &approval.target, &approval.request))?,
            recipe: self.recipe.identity()?,
            durability,
            resources: approval.secret.binding.clone(),
            deployment: self.deployment.serving.deployment.clone(),
            deployment_input: Some(Digest::of(&self.deployment)?),
        })?;
        self.approval = approval;
        Ok(())
    }
}

#[test]
fn redeploy_and_lost_publication_ack_are_durable_and_stale_publishers_cannot_roll_back()
-> Result<()> {
    let mut world = World::new()?;
    world.activate()?;
    let mut journal = Journal::open(&world.journal)?;
    assert!(journal.serving_publication_pending(&world.approval.target)?);
    let first = journal.serving_publication(&[world.approval.target.clone()])?;
    world.provider.publish(&first)?;
    assert!(journal.acknowledge_serving_publication(&first)?);
    assert!(!journal.serving_publication_pending(&world.approval.target)?);
    assert_eq!(first.revision, 1);
    world.redeploy()?;
    world.activate()?;
    let second = journal.serving_publication(&[world.approval.target.clone()])?;
    assert_eq!(second.revision, 2);
    assert_ne!(second.digest, first.digest);
    assert!(world.provider.publish(&first).is_err());
    assert!(!journal.acknowledge_serving_publication(&first)?);
    world.fixture.cloud.lock().unwrap().drop_publication_ack = true;
    assert!(world.provider.publish(&second).is_err());
    assert!(journal.serving_publication_pending(&world.approval.target)?);
    world.provider.publish(&second)?;
    assert!(journal.acknowledge_serving_publication(&second)?);
    let cloud = world.fixture.cloud.lock().unwrap();
    assert_eq!(cloud.patches, 2);
    assert_eq!(cloud.publications, 2);
    assert_eq!(
        cloud.maps["serving"]["metadata"]["annotations"]["day2.dev/selection-revision"],
        "2"
    );
    assert_eq!(
        cloud.maps["serving"]["metadata"]["annotations"]["day2.dev/selection-digest"],
        second.digest.as_str()
    );
    let dump = std::fs::read(&world.journal)?;
    assert!(
        !dump
            .windows(b"synthetic-private-key".len())
            .any(|w| w == b"synthetic-private-key")
    );
    Ok(())
}

#[test]
fn lost_deployment_ack_reconciles_the_same_effect_without_a_second_patch() -> Result<()> {
    let mut world = World::new()?;
    world.fixture.cloud.lock().unwrap().drop_deployment_ack = true;
    world.activate()?;
    assert_eq!(world.fixture.cloud.lock().unwrap().patches, 1);
    Ok(())
}

#[test]
fn unknown_absence_never_authorizes_a_blind_second_write() -> Result<()> {
    let mut world = World::new()?;
    world.fixture.cloud.lock().unwrap().unknown_absence = true;
    world.until(ReleasePhase::SecretReady)?;
    for _ in 0..6 {
        world.step()?;
    }
    assert_eq!(world.fixture.cloud.lock().unwrap().patches, 1);
    assert_ne!(world.host.inspect(&world.id)?.phase, ReleasePhase::Active);
    assert!(!Journal::open(&world.journal)?.serving_publication_pending(&world.approval.target)?);
    Ok(())
}

#[test]
fn conditional_rejection_is_retryable_but_wrong_pod_and_activation_time_key_denial_block()
-> Result<()> {
    let mut world = World::new()?;
    world.fixture.cloud.lock().unwrap().conflict = true;
    world.until(ReleasePhase::WaitingDeployment)?;
    world.fixture.cloud.lock().unwrap().wrong_pod = true;
    world.step()?;
    assert_eq!(
        world.host.inspect(&world.id)?.phase,
        ReleasePhase::WaitingDeployment
    );
    world.fixture.cloud.lock().unwrap().wrong_pod = false;
    world.until(ReleasePhase::DeploymentReady)?;
    world.fixture.cloud.lock().unwrap().secret_denied = true;
    assert!(world.step().is_err());
    assert_ne!(world.host.inspect(&world.id)?.phase, ReleasePhase::Active);
    assert!(!Journal::open(&world.journal)?.serving_publication_pending(&world.approval.target)?);
    world.fixture.cloud.lock().unwrap().secret_denied = false;
    world.activate()?;
    assert_eq!(world.fixture.cloud.lock().unwrap().patches, 2);
    Ok(())
}

#[test]
fn candidate_input_is_pinned_and_unrelated_publication_destinations_are_refused() -> Result<()> {
    let mut world = World::new()?;
    let mut changed = world.deployment.clone();
    changed.image = format!("registry.example/other@sha256:{}", "3".repeat(64));
    let provider = GkeReleaseProvider::transport_fixture(
        world.journal.clone(),
        changed,
        Arc::new(Tokens),
        &world.fixture.endpoint,
        &world.fixture.endpoint,
        &world.fixture.endpoint,
    )?;
    assert!(
        provider
            .validate(&world.host.inspect(&world.id)?.plan, &world.approval)
            .is_err()
    );
    world.activate()?;
    let publication =
        Journal::open(&world.journal)?.serving_publication(&[world.approval.target.clone()])?;
    world.fixture.cloud.lock().unwrap().maps.insert("serving".into(),json!({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"serving","namespace":NS,"uid":"unrelated","resourceVersion":"1"},"data":{"unrelated":"data"}}));
    assert!(world.provider.publish(&publication).is_err());
    assert_eq!(world.fixture.cloud.lock().unwrap().publications, 0);
    Ok(())
}

#[test]
fn replacement_controller_and_swapped_key_paths_cannot_activate() -> Result<()> {
    let mut world = World::new()?;
    world.until(ReleasePhase::DeploymentReady)?;
    world.fixture.cloud.lock().unwrap().controller["metadata"]["uid"] = json!("replacement-uid");
    assert!(world.step().is_err());
    assert!(!Journal::open(&world.journal)?.serving_publication_pending(&world.approval.target)?);
    let mut swapped = World::new()?;
    swapped.fixture.cloud.lock().unwrap().versions.swap(0, 1);
    assert!(swapped.step().is_err());
    assert_eq!(swapped.fixture.cloud.lock().unwrap().patches, 0);
    Ok(())
}

#[test]
fn qualified_build_receipt_requires_complete_real_profile_and_exact_worker() -> Result<()> {
    let artifact = Digest::new(b"native-artifact");
    let mut receipt = json!({"format":1,"status":"passed","scope":"linux_sqlite_single_v1",
        "environment":{"architecture":"x86_64"},"applications":{"stock":{"artifact":artifact,"worker":"worker-one"}},
        "checks":["linux-build-check","linux-build-delegation","linux-build-delegation-business","linux-build-owned","linux-build-probe","linux-build-runtime","linux-build-tooling","linux-capture","linux-runtime-forced-restart","linux-runtime-graceful-restart","linux-runtime-isolation","linux-runtime-package","linux-runtime-read-write","linux-runtime-restore","linux-runtime-revoke","linux-runtime-start","linux-runtime-stop","linux-start-tooling","linux-stop-tooling","linux-test-delegation","test-backup","test-http","test-sandbox","test-worker"]});
    let check = |value: &Value| {
        day2_control::qualified_release_build::check_receipt(
            value,
            &artifact,
            "worker-one",
            "x86_64",
        )
    };
    check(&receipt)?;
    for case in 0..6 {
        let mut changed = receipt.clone();
        match case {
            0 => changed["status"] = json!("failed"),
            1 => changed["environment"]["architecture"] = json!("aarch64"),
            2 => {
                changed["checks"].as_array_mut().unwrap().pop();
            }
            3 => changed["checks"][0] = changed["checks"][1].clone(),
            4 => changed["applications"]["stock"]["worker"] = json!("other-worker"),
            _ => changed["applications"]["stock"]["artifact"] = json!(Digest::new(b"other-app")),
        }
        assert!(check(&changed).is_err(), "case {case}");
    }
    receipt["checks"].as_array_mut().unwrap().reverse();
    check(&receipt)?;
    Ok(())
}

#[test]
fn roc_driver_runs_the_bounded_release_sequence_and_publishes_only_after_all_are_active()
-> Result<()> {
    let mut actions = Vec::new();
    let mut polls = 0;
    let result =
        day2::automation::run(&day2::automation::runner()?, &["gke-release"], |request| {
            actions.push(request.action.clone());
            Ok(match request.action.as_str() {
                "gke-release-open" => json!({"executions":["one","two"]}),
                "gke-release-advance" => {
                    polls += 1;
                    json!({"state":if polls==1 {"pending"} else {"active"},"wait_millis":0})
                }
                "gke-release-wait" => json!({}),
                "gke-release-publish" => json!({"status":"activated_and_published"}),
                _ => anyhow::bail!("unexpected capability"),
            })
        })?;
    assert_eq!(result["status"], "activated_and_published");
    assert_eq!(
        actions,
        vec![
            "gke-release-open",
            "gke-release-advance",
            "gke-release-wait",
            "gke-release-advance",
            "gke-release-advance",
            "gke-release-publish"
        ]
    );
    let mut polls = 0;
    assert!(
        day2::automation::run(
            &day2::automation::runner()?,
            &["gke-release"],
            |request| Ok(match request.action.as_str() {
                "gke-release-open" => json!({"executions":["pending"]}),
                "gke-release-advance" => {
                    polls += 1;
                    json!({"state":"pending","wait_millis":0})
                }
                "gke-release-wait" => json!({}),
                _ => panic!("pending campaign must never publish"),
            })
        )
        .is_err()
    );
    assert_eq!(polls, 60);
    Ok(())
}
