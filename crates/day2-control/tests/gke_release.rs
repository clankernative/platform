//! HTTP protocol fixtures, not live GKE qualification or forge authentication.
use crate::support::release as support;

use anyhow::Result;
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    routing::any,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use day2_capabilities::resources::VersionRef;
use day2_control::{
    BindingRef, Digest,
    gke_release::{Deployment, GkeReleaseProvider, ProviderCredential, ProviderCredentials},
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
// day2's reference key of {"id":"alerts-webhook","revision":1}.
const KEY: &str = "ef04e428d3b9a659ce6eaee5c890220e9ff59ac9f9b3889f2176569021744d2a";
const CREDENTIAL: &[u8] = b"https://hooks.slack.example/synthetic-credential-never-journaled\n";
const CREDENTIAL_VERSION: &str = "projects/12345/secrets/alerts-webhook/versions/4";
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
    credential_versions: Vec<(String, String)>,
    payloads: BTreeMap<String, Vec<u8>>,
    patches: usize,
    last_patch: Value,
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
            let name = path.trim_start_matches("/v1/").trim_end_matches(":access");
            let payload = cloud
                .payloads
                .get(name)
                .map_or(&b"synthetic-private-key-never-journaled"[..], Vec::as_slice);
            json!({"name":name, "payload":{"data":STANDARD.encode(payload),"dataCrc32c":crc32c::crc32c(payload).to_string()}})
        }
    } else if path
        == "/apis/secrets-store.csi.x-k8s.io/v1/namespaces/disposable/secretproviderclasses/keys"
    {
        json!({"spec":{"provider":"gke","parameters":{"secrets":serde_json::to_string(&json!([
            {"resourceName":cloud.versions[0],"path":"workload"},{"resourceName":cloud.versions[1],"path":"issuer"}
        ])).unwrap()}}})
    } else if path
        == "/apis/secrets-store.csi.x-k8s.io/v1/namespaces/disposable/secretproviderclasses/credentials"
    {
        let secrets: Vec<_> = cloud
            .credential_versions
            .iter()
            .map(|(path, version)| json!({"resourceName":version,"path":path}))
            .collect();
        json!({"spec":{"provider":"gke","parameters":{"secrets":serde_json::to_string(&secrets).unwrap()}}})
    } else if path == WORKLOAD {
        if method == Method::PATCH {
            let patch: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(headers["content-type"], "application/json-patch+json");
            assert_eq!(patch[0]["path"], "/metadata/uid");
            assert_eq!(patch[1]["path"], "/metadata/resourceVersion");
            cloud.patches += 1;
            cloud.last_patch = patch.clone();
            if cloud.conflict
                || patch[0]["value"] != cloud.controller["metadata"]["uid"]
                || patch[1]["value"] != cloud.controller["metadata"]["resourceVersion"]
            {
                cloud.conflict = false;
                status = StatusCode::CONFLICT;
            } else if cloud.unknown_absence {
                status = StatusCode::INTERNAL_SERVER_ERROR;
            } else if !json_patch(&mut cloud.controller, &patch) {
                status = StatusCode::UNPROCESSABLE_ENTITY;
            } else {
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

/// RFC 6902 `test`/`add`/`replace`/`remove` on object members, atomically.
fn json_patch(target: &mut Value, patch: &Value) -> bool {
    let mut next = target.clone();
    for op in patch.as_array().unwrap() {
        let path = op["path"].as_str().unwrap();
        if op["op"] == "test" {
            if next.pointer(path) != Some(&op["value"]) {
                return false;
            }
            continue;
        }
        let (parent, key) = path.rsplit_once('/').unwrap();
        let key = key.replace("~1", "/").replace("~0", "~");
        let Some(parent) = next.pointer_mut(parent).and_then(Value::as_object_mut) else {
            return false;
        };
        let present = parent.contains_key(&key);
        match op["op"].as_str().unwrap() {
            "add" => {
                parent.insert(key, op["value"].clone());
            }
            "replace" if present => {
                parent.insert(key, op["value"].clone());
            }
            "remove" if present => {
                parent.remove(&key);
            }
            _ => return false,
        }
    }
    *target = next;
    true
}

struct Fixture {
    endpoint: String,
    cloud: Arc<Mutex<Cloud>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new(deployment: &Deployment) -> Self {
        // The day2-app stack bootstraps the first candidate's artifact.
        let bootstrap = format!(
            "sha256:{}",
            deployment.instance["apps"]["reports"]["artifact"]
                .as_str()
                .unwrap()
                .trim_start_matches("artifacts/")
        );
        let mut annotations = json!({"day2.dev/installation":"alpha","day2.dev/environment":"production","day2.dev/app":"reports","day2.dev/artifact":bootstrap});
        let mut controller = json!({"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"day2-reports","namespace":NS,"uid":"controller-uid","generation":1,"resourceVersion":"rv-1","annotations":{"day2.dev/release-managed":"true"}},"spec":{"replicas":1,"template":{"metadata":{"annotations":{}},"spec":{"serviceAccountName":"runtime","initContainers":[{"name":"state-ownership","image":"busybox@sha256:fixture","command":["/busybox/chown","10001:10001","/srv/day2/.state"]}],"containers":[{"name":"day2","image":deployment.image,"env":[{"name":"DAY2_EXPECTED_ARTIFACT","value":bootstrap}]}],"volumes":[{"name":"instance","configMap":{"name":"bootstrap-instance"}},{"name":"keys","csi":{"driver":"secrets-store-gke.csi.k8s.io","volumeAttributes":{"secretProviderClass":"keys"}}}]}}},"status":{"observedGeneration":1,"readyReplicas":1,"updatedReplicas":1,"currentRevision":"rev-1","updateRevision":"rev-1"}});
        let mut credential_versions = Vec::new();
        if let Some(credentials) = &deployment.credentials {
            // As the day2-app stack installs it, before the first release.
            annotations["day2.dev/credentials-sha256"] = json!("bootstrap-credentials");
            let spec = &mut controller["spec"]["template"]["spec"];
            let mut mounts: Vec<_> = credentials
                .metadata
                .keys()
                .map(|file| {
                    let path = if file.starts_with("credential-") {
                        format!("/srv/day2/provisioning/{file}")
                    } else {
                        format!("/srv/day2/{file}")
                    };
                    json!({"name":"credential-metadata","mountPath":path,"subPath":file,"readOnly":true})
                })
                .collect();
            mounts.push(
                json!({"name":"credentials","mountPath":"/run/day2/credentials","readOnly":true}),
            );
            mounts.push(json!({"name":"state","mountPath":"/srv/day2/.state"}));
            let init = spec["initContainers"].as_array_mut().unwrap();
            init.push(json!({"name":"credential-files","image":"busybox@sha256:fixture","command":["/busybox/install","-o","10001","-g","10001","-m","0400","-t","/run/day2/credentials",format!("/run/day2/credential-sources/{KEY}")]}));
            init.push(json!({"name":"credential-registration","image":deployment.image,"command":["/usr/local/bin/day2-provision-credentials"],"args":["/srv/day2/operator-instance.json","reports","operator@example.com","/srv/day2/provisioning.json"],"volumeMounts":mounts}));
            let volumes = spec["volumes"].as_array_mut().unwrap();
            volumes.push(json!({"name":"credential-sources","csi":{"driver":"secrets-store-gke.csi.k8s.io","readOnly":true,"volumeAttributes":{"secretProviderClass":"credentials"}}}));
            volumes.push(
                json!({"name":"credentials","emptyDir":{"medium":"Memory","sizeLimit":"1Mi"}}),
            );
            volumes.push(json!({"name":"credential-metadata","configMap":{"name":"day2-reports-credentials","defaultMode":292}}));
            credential_versions = credentials
                .entries
                .iter()
                .map(|entry| (entry.key.clone(), entry.secret_version.resource_name()))
                .collect();
        }
        controller["spec"]["template"]["metadata"]["annotations"] = annotations;
        let cloud = Arc::new(Mutex::new(Cloud {
            controller,
            maps: BTreeMap::new(),
            versions: deployment
                .secret_versions
                .iter()
                .map(SecretVersion::resource_name)
                .collect(),
            credential_versions,
            payloads: BTreeMap::from([(CREDENTIAL_VERSION.to_owned(), CREDENTIAL.to_vec())]),
            patches: 0,
            last_patch: Value::Null,
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
        Self::build(false, |_| {})
    }

    /// A workload with one provider credential; `change` edits the candidate.
    fn with_credentials(change: impl FnOnce(&mut Deployment)) -> Result<Self> {
        Self::build(true, change)
    }

    fn build(credentials: bool, change: impl FnOnce(&mut Deployment)) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let journal = directory.path().join("journal.sqlite");
        let mut storage = Journal::open(&journal)?;
        configure(&mut storage, &target("alpha"), &plan("alpha", 1));
        let approval = approval(&mut storage, "alpha", 1, 0);
        storage.approve_release(&approval)?;
        let mut instance = json!({"installation":"alpha","environment":"production","identity":{"scheme":"google_iap","hosted_domain":"example.com"},"apps":{"reports":{"artifact":format!("artifacts/{}",approval.artifact.as_str().trim_start_matches("sha256:")),"readers":["alice@example.com"],"writers":["alice@example.com"],"authority":{"version":1,"operations":{}},"edge":{"origin":"https://reports.example.com","iap_audience":"/projects/12345/global/backendServices/67890"}}}});
        if credentials {
            instance["resources"] = json!({"version":1,"connections":{"alerts":{"revision":1,"provider":"slack_webhook","live":{"provider":"slack_webhook","credential_ref":{"id":"alerts-webhook","revision":1}}}},"resources":{},"policies":{}});
        }
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
            credentials: None,
        };
        if credentials {
            deployment.credentials = Some(provider_credentials(&operator_instance(
                &deployment.instance,
            )));
        }
        change(&mut deployment);
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
    /// What `day2 platform maintain activate` leaves: the app stopped and
    /// stamped with the artifact its database now activates.
    fn mark_activated(&self, artifact: &Digest) {
        let mut cloud = self.fixture.cloud.lock().unwrap();
        cloud.controller["metadata"]["annotations"]["day2.dev/activated-artifact"] =
            json!(artifact);
        cloud.controller["spec"]["replicas"] = json!(0);
        let generation = cloud.controller["metadata"]["generation"].as_u64().unwrap() + 1;
        cloud.controller["metadata"]["generation"] = json!(generation);
        cloud.controller["metadata"]["resourceVersion"] = json!(format!("rv-{generation}"));
    }

    fn controller(&self) -> Value {
        self.fixture.cloud.lock().unwrap().controller.clone()
    }

    /// Approve and accept a candidate with a new artifact and image.
    fn redeploy(&mut self) -> Result<()> {
        let mut journal = Journal::open(&self.journal)?;
        let generation = self.approval.expected_generation + 1;
        let mut approval = approval(
            &mut journal,
            "alpha",
            u8::try_from(generation + 1)?,
            generation,
        );
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
    world.mark_activated(&world.approval.artifact);
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
            let input: Value = request.decode()?;
            let expected = match request.action.as_str() {
                "gke-release-advance" => json!({"execution":if polls < 2 {"one"} else {"two"}}),
                "gke-release-wait" => json!({"millis":0}),
                _ => json!({}),
            };
            assert_eq!(input, expected, "{} payload", request.action);
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
                    assert_eq!(request.decode::<Value>()?, json!({"execution":"pending"}));
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
    let mut advances = 0;
    let built = day2::automation::run(
        &day2::automation::runner()?,
        &["gke-release-build"],
        |request| {
            let input: Value = request.decode()?;
            Ok(match request.action.as_str() {
                "gke-build-open" => {
                    assert_eq!(input, json!({}));
                    json!({"executions":["native-build"]})
                }
                "gke-build-advance" => {
                    assert_eq!(input, json!({"execution":"native-build"}));
                    advances += 1;
                    json!({"state":if advances == 3 {"active"} else {"pending"},"wait_millis":0})
                }
                "gke-release-wait" => {
                    assert_eq!(input, json!({"millis":0}));
                    json!({})
                }
                "gke-build-finish" => {
                    assert_eq!(input, json!({}));
                    json!({"builds":"succeeded"})
                }
                _ => anyhow::bail!("unexpected build capability"),
            })
        },
    )?;
    assert_eq!(advances, 3);
    assert_eq!(built, json!({"builds":"succeeded"}));
    Ok(())
}

fn fingerprint() -> String {
    day2::digest(CREDENTIAL.strip_suffix(b"\n").unwrap())
}

/// The serving instance plus the operator-only control section, as the
/// day2-app stack renders it.
fn operator_instance(instance: &Value) -> Value {
    let mut operator = instance.clone();
    operator["control"] = json!({"version":1,"state_directory":"/srv/day2/.state/operator-control","operators":["operator@example.com"],"sources":{},"apps":{}});
    operator
}

/// Registration metadata pinned to `operator`, as the day2-app stack renders it.
fn provider_credentials(operator: &Value) -> ProviderCredentials {
    let fingerprint = fingerprint();
    let input = serde_json::to_string(&json!({"connection":{"provider":"slack_webhook","credential_ref":{"id":"alerts-webhook","revision":1}},"credential_file":format!("/run/day2/credentials/{KEY}"),"expected_fingerprint":fingerprint})).unwrap();
    let operator = serde_json::to_string(operator).unwrap();
    let plan = serde_json::to_string(&json!({"version":1,"app":"reports","operator":"operator@example.com","instance_digest":day2::digest(operator.as_bytes()),"inputs":[{"file":format!("credential-{KEY}.json"),"digest":day2::digest(input.as_bytes()),"credential_digest":fingerprint}]})).unwrap();
    ProviderCredentials {
        projection: "credentials".into(),
        operator: "operator@example.com".into(),
        entries: vec![ProviderCredential {
            key: KEY.into(),
            credential_ref: VersionRef {
                id: "alerts-webhook".into(),
                revision: 1,
            },
            secret_version: SecretVersion {
                project_number: 12345,
                secret: "alerts-webhook".into(),
                version: 4,
            },
            fingerprint,
        }],
        metadata: BTreeMap::from([
            (format!("credential-{KEY}.json"), input),
            ("operator-instance.json".into(), operator),
            ("provisioning.json".into(), plan),
        ]),
    }
}

fn credentials_map(world: &World) -> Option<Value> {
    let cloud = world.fixture.cloud.lock().unwrap();
    let release = cloud.controller["metadata"]["annotations"]["day2.dev/release-id"].as_str()?;
    cloud
        .maps
        .get(&format!("day2-release-{}-credentials", &release[7..39]))
        .cloned()
}

/// Refused before any workload write or release-owned ConfigMap.
fn refused(mut world: World) -> Result<()> {
    for _ in 0..4 {
        let _ = world.step();
    }
    assert_eq!(world.fixture.cloud.lock().unwrap().patches, 0);
    assert!(world.fixture.cloud.lock().unwrap().maps.is_empty());
    assert_ne!(world.host.inspect(&world.id)?.phase, ReleasePhase::Active);
    Ok(())
}

#[test]
fn provider_credentials_release_registration_from_the_released_image_and_instance() -> Result<()> {
    let mut world = World::with_credentials(|_| {})?;
    let before = world.fixture.cloud.lock().unwrap().controller["spec"]["template"].clone();
    world.activate()?;
    let cloud = world.fixture.cloud.lock().unwrap();
    assert_eq!(cloud.patches, 1);
    let after = cloud.controller["spec"]["template"].clone();
    let release = after["metadata"]["annotations"]["day2.dev/release-id"]
        .as_str()
        .unwrap()
        .to_owned();
    let name = format!("day2-release-{}", &release[7..39]);
    let credentials = world.deployment.credentials.as_ref().unwrap();
    // Exactly the release-owned fields change; everything else is the stack's.
    let mut expected = before.clone();
    let annotations = &mut expected["metadata"]["annotations"];
    annotations["day2.dev/artifact"] = json!(world.approval.artifact);
    annotations["day2.dev/instance-sha256"] = json!(
        day2::digest(serde_json::to_string(&world.deployment.instance)?.as_bytes())
            .trim_start_matches("sha256:")
    );
    annotations["day2.dev/release-id"] = json!(release);
    annotations["day2.dev/credentials-sha256"] = json!(
        day2::digest(credentials.metadata["provisioning.json"].as_bytes())
            .trim_start_matches("sha256:")
    );
    let spec = &mut expected["spec"];
    spec["containers"][0]["image"] = json!(world.deployment.image);
    spec["containers"][0]["env"][0]["value"] = json!(world.approval.artifact);
    spec["volumes"][0]["configMap"]["name"] = json!(name);
    spec["volumes"][4]["configMap"]["name"] = json!(format!("{name}-credentials"));
    spec["initContainers"][2]["image"] = json!(world.deployment.image);
    assert_eq!(after, expected);
    let map = &cloud.maps[&format!("{name}-credentials")];
    assert_eq!(map["immutable"], true);
    assert_eq!(map["data"], serde_json::to_value(&credentials.metadata)?);
    assert_eq!(
        map["metadata"]["annotations"]["day2.dev/release-id"],
        release
    );
    drop(cloud);
    let dump = std::fs::read(&world.journal)?;
    assert!(
        !dump
            .windows(b"synthetic-credential".len())
            .any(|w| w == b"synthetic-credential")
    );
    Ok(())
}

#[test]
fn lost_deployment_ack_reconciles_with_the_credentials_config_map_present() -> Result<()> {
    let mut world = World::with_credentials(|_| {})?;
    world.fixture.cloud.lock().unwrap().drop_deployment_ack = true;
    world.activate()?;
    assert_eq!(world.fixture.cloud.lock().unwrap().patches, 1);
    assert!(credentials_map(&world).is_some());
    Ok(())
}

#[test]
fn a_credential_version_that_differs_from_its_reviewed_fingerprint_is_refused() -> Result<()> {
    let world = World::with_credentials(|_| {})?;
    world.fixture.cloud.lock().unwrap().payloads.insert(
        CREDENTIAL_VERSION.into(),
        b"another-synthetic-value".to_vec(),
    );
    refused(world)
}

#[test]
fn a_credential_projection_without_the_pinned_version_is_refused() -> Result<()> {
    let world = World::with_credentials(|_| {})?;
    world.fixture.cloud.lock().unwrap().credential_versions[0].1 =
        "projects/12345/secrets/alerts-webhook/versions/3".into();
    refused(world)?;
    let world = World::with_credentials(|_| {})?;
    world
        .fixture
        .cloud
        .lock()
        .unwrap()
        .credential_versions
        .clear();
    refused(world)
}

#[test]
fn registration_metadata_for_another_instance_is_refused() -> Result<()> {
    // The candidate is refused at admission, before any provider access.
    let refusal = |change: fn(&mut Deployment)| match World::with_credentials(change) {
        Ok(_) => panic!("inconsistent registration metadata was admitted"),
        Err(error) => error.to_string(),
    };
    assert_eq!(
        refusal(|deployment| {
            // Consistently pinned, but registering against a different instance.
            let mut operator = operator_instance(&deployment.instance);
            operator["apps"]["reports"]["readers"] = json!(["mallory@example.com"]);
            deployment.credentials = Some(provider_credentials(&operator));
        }),
        "gke_release_credential_instance_changed"
    );
    assert_eq!(
        refusal(|deployment| {
            let credentials = deployment.credentials.as_mut().unwrap();
            credentials.entries[0].fingerprint = format!("sha256:{}", "0".repeat(64));
        }),
        "gke_release_credential_plan_changed"
    );
    assert_eq!(
        refusal(|deployment| {
            let credentials = deployment.credentials.as_mut().unwrap();
            credentials.entries[0].key = "0".repeat(64);
        }),
        "gke_release_credential_scope_changed"
    );
    Ok(())
}

#[test]
fn a_workload_without_its_registration_container_is_refused() -> Result<()> {
    let world = World::with_credentials(|_| {})?;
    world.fixture.cloud.lock().unwrap().controller["spec"]["template"]["spec"]["initContainers"]
        .as_array_mut()
        .unwrap()
        .retain(|init| init["name"] != "credential-registration");
    refused(world)?;
    // Nor may a candidate without credentials leave stale registration behind.
    let world = World::new()?;
    world.fixture.cloud.lock().unwrap().controller["spec"]["template"]["spec"]["volumes"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"name":"credential-metadata","configMap":{"name":"day2-reports-credentials"}}),
        );
    refused(world)
}

#[test]
fn the_first_release_of_the_bootstrap_artifact_leaves_replicas_and_stamps_alone() -> Result<()> {
    let mut world = World::new()?;
    world.activate()?;
    let cloud = world.fixture.cloud.lock().unwrap();
    let ops: Vec<_> = cloud
        .last_patch
        .as_array()
        .unwrap()
        .iter()
        .map(|op| op["path"].clone())
        .collect();
    assert_eq!(
        ops,
        [
            "/metadata/uid",
            "/metadata/resourceVersion",
            "/metadata/annotations/day2.dev~1release-effect",
            "/metadata/annotations/day2.dev~1release-id",
            "/spec/template"
        ]
    );
    assert_eq!(cloud.controller["spec"]["replicas"], 1);
    Ok(())
}

#[test]
fn an_artifact_change_needs_the_candidates_maintenance_activation() -> Result<()> {
    let mut world = World::new()?;
    world.activate()?;
    let live = world.approval.artifact.clone();
    let maps = world.fixture.cloud.lock().unwrap().maps.len();
    world.redeploy()?;
    let candidate = world.approval.artifact.clone();
    let error = world.step().unwrap_err().to_string();
    assert!(
        error.starts_with("release_artifact_requires_activation: ")
            && error.contains(live.as_str())
            && error.contains(candidate.as_str())
            && error.contains("day2 platform maintain activate"),
        "{error}"
    );
    // An activation for another artifact authorizes nothing either.
    world.mark_activated(&Digest::new(b"another-activated-artifact"));
    for _ in 0..4 {
        let _ = world.step();
    }
    {
        let cloud = world.fixture.cloud.lock().unwrap();
        assert_eq!(cloud.patches, 1);
        assert_eq!(cloud.maps.len(), maps);
        assert_eq!(
            cloud.controller["spec"]["template"]["metadata"]["annotations"]["day2.dev/artifact"],
            live.as_str()
        );
    }
    assert_ne!(world.host.inspect(&world.id)?.phase, ReleasePhase::Active);
    // The candidate's own activation lets the same execution continue.
    world.mark_activated(&candidate);
    world.activate()?;
    let controller = world.controller();
    assert_eq!(world.fixture.cloud.lock().unwrap().patches, 2);
    assert_eq!(controller["spec"]["replicas"], 1);
    assert!(controller["metadata"]["annotations"]["day2.dev/activated-artifact"].is_null());
    assert_eq!(
        controller["spec"]["template"]["metadata"]["annotations"]["day2.dev/artifact"],
        candidate.as_str()
    );
    Ok(())
}

#[test]
fn a_consumed_activation_reconciles_a_lost_ack_and_cannot_authorize_again() -> Result<()> {
    let mut world = World::new()?;
    world.activate()?;
    world.redeploy()?;
    world.mark_activated(&world.approval.artifact);
    world.fixture.cloud.lock().unwrap().drop_deployment_ack = true;
    world.activate()?;
    let controller = world.controller();
    assert_eq!(world.fixture.cloud.lock().unwrap().patches, 2);
    assert_eq!(controller["spec"]["replicas"], 1);
    assert!(controller["metadata"]["annotations"]["day2.dev/activated-artifact"].is_null());
    // The next artifact needs its own activation.
    world.redeploy()?;
    let error = world.step().unwrap_err().to_string();
    assert!(
        error.starts_with("release_artifact_requires_activation: "),
        "{error}"
    );
    assert_eq!(world.fixture.cloud.lock().unwrap().patches, 2);
    Ok(())
}

#[test]
fn a_stopped_workload_without_an_activation_is_refused() -> Result<()> {
    let world = World::new()?;
    world.fixture.cloud.lock().unwrap().controller["spec"]["replicas"] = json!(0);
    refused(world)
}

#[test]
fn the_release_scope_is_every_app_the_catalog_instance_binds() -> Result<()> {
    let scope = target("alpha");
    let instance = json!({"apps":{"reports":{},"notifications":{}}});
    let targets = day2_control::gke_release_driver::release_scope(&instance, &scope)?;
    let apps: Vec<_> = targets.iter().map(|target| target.app.as_str()).collect();
    assert_eq!(apps, ["notifications", "reports"]);
    assert!(
        targets.iter().all(
            |target| target.company == scope.company && target.environment == scope.environment
        )
    );
    assert!(day2_control::gke_release_driver::release_scope(&json!({"apps":{}}), &scope).is_err());
    Ok(())
}
