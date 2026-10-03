//! HTTP protocol fixtures only: these never attest that a real GKE process exited.
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use day2_control::{
    kubernetes_conformance::{
        GkeKubernetesProbe, GkeServingBinding, GkeTarget, ObservationOrigin, PhysicalQuiescence,
        QuiescenceBlocker,
    },
    secrets::{AccessToken, AccessTokenProvider},
    source::SourceError,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const DEPLOYMENT: &str = "/apis/apps/v1/namespaces/disposable/deployments/old";
const REPLICAS: &str = "/apis/apps/v1/namespaces/disposable/replicasets";
const PODS: &str = "/api/v1/namespaces/disposable/pods";
const NODE: &str = "/api/v1/nodes/node-one";
const DISCOVERY: &str = "/v1/projects/12345/locations/us-central1/clusters/probe";
const TOKEN: &str = "fixture-not-a-live-token";

struct Tokens;
impl AccessTokenProvider for Tokens {
    fn access_token(&self) -> std::result::Result<AccessToken, SourceError> {
        AccessToken::new(TOKEN.into())
    }
}

#[test]
fn serving_probe_authenticates_the_ready_app_artifact_and_workload() -> Result<()> {
    let artifact = day2_control::Digest::new(b"serving-artifact");
    let image = format!("registry.example/app@sha256:{}", "1".repeat(64));
    let annotations = json!({"day2.dev/installation":"alpha","day2.dev/environment":"production","day2.dev/app":"reports","day2.dev/artifact":artifact});
    let statefulset = json!({"apiVersion":"apps/v1","kind":"StatefulSet","metadata":metadata("day2-reports","controller-uid"),
        "spec":{"replicas":1,"template":{"metadata":{"annotations":annotations},"spec":{"serviceAccountName":"runtime","containers":[{"name":"day2","image":image}]}}},
        "status":{"observedGeneration":1,"readyReplicas":1,"updatedReplicas":1,"currentRevision":"rev-one","updateRevision":"rev-one"}});
    let mut pod_metadata = metadata("day2-reports-0", "pod-uid");
    pod_metadata["ownerReferences"] = json!([{"name":"day2-reports","uid":"controller-uid","kind":"StatefulSet","controller":true}]);
    pod_metadata["annotations"] = annotations;
    pod_metadata["labels"] = json!({"controller-revision-hash":"rev-one"});
    let pod = json!({"metadata":pod_metadata,"spec":{"serviceAccountName":"runtime","containers":[{"name":"day2","image":image,"env":[{"name":"DAY2_EXPECTED_ARTIFACT","value":artifact}]}]},
        "status":{"phase":"Running","containerStatuses":[{"name":"day2","ready":true,"started":true,"imageID":image,"state":{"running":{}}}]}});
    let mut account = metadata("runtime", "account-uid");
    account["annotations"] =
        json!({"iam.gke.io/gcp-service-account":"reports@project.iam.gserviceaccount.com"});
    let controller_path = "/apis/apps/v1/namespaces/disposable/statefulsets/day2-reports";
    let pod_path = "/api/v1/namespaces/disposable/pods/day2-reports-0";
    let account_path = "/api/v1/namespaces/disposable/serviceaccounts/runtime";
    let mut replies = routes();
    replies.insert(controller_path.into(), Reply::json(statefulset.clone()));
    replies.insert(pod_path.into(), Reply::json(pod.clone()));
    replies.insert(
        account_path.into(),
        Reply::json(json!({"metadata":account})),
    );
    let fixture = Fixture::new(replies);
    let binding = GkeServingBinding {
        target: serde_json::from_value(
            json!({"company":"alpha","environment":"production","app":"reports"}),
        )?,
        project_number: 12345.try_into()?,
        location: "us-central1".into(),
        cluster: "probe".into(),
        namespace: "disposable".into(),
        workload: "day2-reports".into(),
        workload_email: "reports@project.iam.gserviceaccount.com".into(),
        deployment: day2_control::BindingRef::pin(
            "reports-deployment".to_owned().try_into()?,
            &"gke-fixture",
        )?,
    };
    let probe =
        GkeKubernetesProbe::transport_fixture(&fixture.endpoint, &fixture.endpoint, &Tokens)?;
    let observed = probe.inspect_serving(&binding)?;
    assert_eq!(observed.artifact, artifact);
    assert_eq!(observed.incarnation.controller.as_str(), "controller-uid");
    assert_eq!(observed.incarnation.generation.as_str(), "1");
    assert!(fixture.requests.lock().unwrap().iter().all(|request| {
        request
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {TOKEN}"))
    }));
    for variant in 0..7 {
        let mut changed = pod.clone();
        match variant {
            0 => {
                changed["metadata"]["annotations"]["day2.dev/artifact"] =
                    json!(day2_control::Digest::new(b"wrong-artifact"))
            }
            1 => changed["metadata"]["ownerReferences"][0]["uid"] = json!("other-controller"),
            2 => changed["status"]["containerStatuses"][0]["ready"] = json!(false),
            3 => changed["metadata"]["labels"]["controller-revision-hash"] = json!("old-revision"),
            4 => changed["spec"]["containers"][0]["env"] = json!([]),
            5 => changed["status"]["containerStatuses"][0]["imageID"] = json!("other-image"),
            _ => {
                let other = format!("registry.example/app@sha256:{}", "2".repeat(64));
                changed["spec"]["containers"][0]["image"] = json!(other);
                changed["status"]["containerStatuses"][0]["imageID"] = json!(other);
            }
        }
        fixture
            .routes
            .lock()
            .unwrap()
            .insert(pod_path.into(), Reply::json(changed));
        assert!(
            probe.inspect_serving(&binding).is_err(),
            "variant {variant}"
        );
    }
    fixture
        .routes
        .lock()
        .unwrap()
        .insert(pod_path.into(), Reply::json(pod));
    let mut changed = statefulset;
    changed["status"]["observedGeneration"] = json!(0);
    fixture
        .routes
        .lock()
        .unwrap()
        .insert(controller_path.into(), Reply::json(changed));
    assert!(probe.inspect_serving(&binding).is_err());
    Ok(())
}

fn target() -> GkeTarget {
    GkeTarget {
        project_number: 12345.try_into().unwrap(),
        location: "us-central1".into(),
        cluster: "probe".into(),
        namespace: "disposable".into(),
        deployment: "old".into(),
        deployment_uid: "deployment-old-uid".into(),
        revision: "1".into(),
    }
}
fn metadata(name: &str, uid: &str) -> Value {
    json!({"name":name,"uid":uid,"namespace":"disposable","resourceVersion":"opaque-rv-A","generation":1,"annotations":{"deployment.kubernetes.io/revision":"1"}})
}
fn controller(name: &str, uid: &str, kind: &str, replicas: u32) -> Value {
    json!({"apiVersion":"apps/v1","kind":kind,"metadata":metadata(name,uid),"spec":{"replicas":replicas},"status":{"observedGeneration":1}})
}
fn replica(replicas: u32) -> Value {
    let mut value = controller("old-rs", "rs-old-uid", "ReplicaSet", replicas);
    value["metadata"]["ownerReferences"] =
        json!([{"name":"old","uid":"deployment-old-uid","kind":"Deployment","controller":true}]);
    value
}
fn pod() -> Value {
    let mut meta = metadata("old-pod", "pod-old-uid");
    meta["ownerReferences"] =
        json!([{"name":"old-rs","uid":"rs-old-uid","kind":"ReplicaSet","controller":true}]);
    json!({"apiVersion":"v1","kind":"Pod","metadata":meta,"spec":{"nodeName":"node-one","containers":[{"name":"worker","env":[{"name":"DONT_RETAIN","value":"synthetic-private-configuration"}]}]},"status":{"phase":"Running","containerStatuses":[{"name":"worker","restartCount":0,"state":{"running":{"startedAt":"2026-09-09T00:00:00Z"}}}]}})
}
fn list(kind: &str, items: Vec<Value>) -> Value {
    json!({"apiVersion":if kind=="ReplicaSetList" {"apps/v1"} else {"v1"},"kind":kind,"metadata":{"resourceVersion":"list-opaque-rv"},"items":items})
}
fn routes() -> BTreeMap<String, Reply> {
    BTreeMap::from([
        (
            DISCOVERY.into(),
            Reply::json(
                json!({"name":"probe","id":"cluster-uid","location":"us-central1","status":"RUNNING","currentMasterVersion":"1.34.1-gke-fixture","endpoint":"203.0.113.1","masterAuth":{"clusterCaCertificate":STANDARD.encode("fixture-public-ca")}}),
            ),
        ),
        (
            DEPLOYMENT.into(),
            Reply::json(controller("old", "deployment-old-uid", "Deployment", 1)),
        ),
        (
            REPLICAS.into(),
            Reply::json(list("ReplicaSetList", vec![replica(1)])),
        ),
        (PODS.into(), Reply::json(list("PodList", vec![pod()]))),
        (
            NODE.into(),
            Reply::json(
                json!({"apiVersion":"v1","kind":"Node","metadata":{"name":"node-one","uid":"node-uid","resourceVersion":"node-rv"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}),
            ),
        ),
    ])
}

#[derive(Clone)]
struct Reply {
    status: u16,
    body: Vec<u8>,
}
impl Reply {
    fn json(value: Value) -> Self {
        Self {
            status: 200,
            body: serde_json::to_vec(&value).unwrap(),
        }
    }
    fn missing() -> Self {
        Self {
            status: 404,
            body: b"{}".to_vec(),
        }
    }
}
struct Fixture {
    endpoint: String,
    routes: Arc<Mutex<BTreeMap<String, Reply>>>,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl Fixture {
    fn new(routes: BTreeMap<String, Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let routes = Arc::new(Mutex::new(routes));
        let (shutdown, seen, replies) = (stop.clone(), requests.clone(), routes.clone());
        let thread = thread::spawn(move || {
            while !shutdown.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    if stream.read_exact(&mut byte).is_err() {
                        break;
                    }
                    headers.push(byte[0]);
                    assert!(headers.len() < 16384);
                }
                let text = String::from_utf8(headers).unwrap();
                let path = text.split_whitespace().nth(1).unwrap_or("").to_owned();
                seen.lock().unwrap().push(text);
                let replies = replies.lock().unwrap();
                let reply = replies
                    .get(&path)
                    .or_else(|| replies.get(path.split('?').next().unwrap()))
                    .cloned()
                    .unwrap_or_else(Reply::missing);
                drop(replies);
                let header = format!(
                    "HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nLocation: http://127.0.0.1:1/forbidden\r\n\r\n",
                    reply.status,
                    reply.body.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(&reply.body);
            }
        });
        Self {
            endpoint,
            routes,
            requests,
            stop,
            thread: Some(thread),
        }
    }
    fn inspect(&self) -> Result<day2_control::kubernetes_conformance::KubernetesObservation> {
        GkeKubernetesProbe::transport_fixture(&self.endpoint, &self.endpoint, &Tokens)?
            .inspect(&target())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}

#[test]
fn running_work_is_scoped_read_only_redacted_and_never_a_drain_receipt() -> Result<()> {
    let fixture = Fixture::new(routes());
    let observed = fixture.inspect()?;
    assert_eq!(observed.origin, ObservationOrigin::TransportFixture);
    assert_eq!(observed.physical_quiescence, PhysicalQuiescence::Unproven);
    assert!(
        observed
            .reasons
            .contains(&QuiescenceBlocker::RunningContainers)
    );
    assert!(
        observed
            .reasons
            .contains(&QuiescenceBlocker::ControllerCanRecreate)
    );
    assert_eq!(observed.pods[0].uid, "pod-old-uid");
    let report = serde_json::to_string(&observed)?;
    assert!(!report.contains(TOKEN));
    assert!(!report.contains("synthetic-private-configuration"));
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert!(requests.iter().all(|request| request.starts_with("GET ")));
    assert!(requests[0].contains("fields="));
    assert!(requests[0].contains("clusterCaCertificate"));
    assert!(!requests[0].contains("clientKey"));
    assert!(requests.iter().all(|request| {
        request
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {TOKEN}"))
    }));
    Ok(())
}

#[test]
fn zero_replicas_and_force_deleted_pod_ghosts_are_not_physical_quiescence() -> Result<()> {
    let mut values = routes();
    values.insert(DEPLOYMENT.into(), Reply::missing());
    values.insert(REPLICAS.into(), Reply::json(list("ReplicaSetList", vec![])));
    values.insert(PODS.into(), Reply::json(list("PodList", vec![])));
    let fixture = Fixture::new(values);
    let ghost_may_still_run = fixture.inspect()?;
    assert_eq!(
        ghost_may_still_run.physical_quiescence,
        PhysicalQuiescence::Unproven
    );
    assert!(
        ghost_may_still_run
            .reasons
            .contains(&QuiescenceBlocker::ApiAbsenceNotProof)
    );
    assert!(
        ghost_may_still_run
            .reasons
            .contains(&QuiescenceBlocker::PhysicalFencingUnproven)
    );
    fixture.routes.lock().unwrap().insert(
        DEPLOYMENT.into(),
        Reply::json(controller("old", "deployment-old-uid", "Deployment", 0)),
    );
    let zero = fixture.inspect()?;
    assert!(
        zero.reasons
            .contains(&QuiescenceBlocker::ControllerCanRecreate)
    );
    assert_eq!(zero.physical_quiescence, PhysicalQuiescence::Unproven);
    Ok(())
}

#[test]
fn controller_recreation_late_work_restart_and_unreachable_node_remain_blocked() -> Result<()> {
    let mut values = routes();
    values.insert(
        DEPLOYMENT.into(),
        Reply::json(controller("old", "deployment-old-uid", "Deployment", 0)),
    );
    let mut current = pod();
    current["metadata"]["deletionTimestamp"] = json!("2026-09-09T00:00:00Z");
    current["status"]["containerStatuses"][0]["restartCount"] = json!(2);
    values.insert(PODS.into(), Reply::json(list("PodList", vec![current])));
    values.insert(NODE.into(),Reply::json(json!({"apiVersion":"v1","kind":"Node","metadata":{"name":"node-one","uid":"node-uid","resourceVersion":"node-rv"},"status":{"conditions":[{"type":"Ready","status":"False"}]}})));
    let fixture = Fixture::new(values);
    let observed = fixture.inspect()?;
    for reason in [
        QuiescenceBlocker::ControllerCanRecreate,
        QuiescenceBlocker::RunningContainers,
        QuiescenceBlocker::RestartObserved,
        QuiescenceBlocker::TerminatingPods,
        QuiescenceBlocker::NodeUnreachable,
    ] {
        assert!(observed.reasons.contains(&reason));
    }
    fixture.routes.lock().unwrap().insert(
        DEPLOYMENT.into(),
        Reply::json(controller("old", "new-deployment-uid", "Deployment", 1)),
    );
    assert!(
        fixture
            .inspect()
            .unwrap_err()
            .to_string()
            .contains("identity_changed")
    );
    Ok(())
}

#[test]
fn owner_graph_namespace_and_controller_revision_are_not_conventions() -> Result<()> {
    let mut values = routes();
    let mut wrong = pod();
    wrong["metadata"]["ownerReferences"][0]["uid"] = json!("wrong-rs-uid");
    values.insert(PODS.into(), Reply::json(list("PodList", vec![wrong])));
    let fixture = Fixture::new(values);
    assert!(
        fixture
            .inspect()
            .unwrap_err()
            .to_string()
            .contains("owner_uid_mismatch")
    );
    let mut wrong = replica(0);
    wrong["metadata"]["namespace"] = json!("another-company");
    fixture.routes.lock().unwrap().insert(
        REPLICAS.into(),
        Reply::json(list("ReplicaSetList", vec![wrong])),
    );
    assert!(
        fixture
            .inspect()
            .unwrap_err()
            .to_string()
            .contains("namespace_mismatch")
    );
    let mut changed = controller("old", "deployment-old-uid", "Deployment", 0);
    changed["metadata"]["annotations"]["deployment.kubernetes.io/revision"] = json!("2");
    fixture.routes.lock().unwrap().extend([
        (DEPLOYMENT.into(), Reply::json(changed)),
        (REPLICAS.into(), Reply::json(list("ReplicaSetList", vec![]))),
        (PODS.into(), Reply::json(list("PodList", vec![]))),
    ]);
    assert!(
        fixture
            .inspect()?
            .reasons
            .contains(&QuiescenceBlocker::ControllerRevisionChanged)
    );
    Ok(())
}

#[test]
fn pagination_must_be_complete_consistent_unique_and_bounded() -> Result<()> {
    let mut values = routes();
    let mut first = list("ReplicaSetList", vec![]);
    first["metadata"]["continue"] = json!("next");
    values.insert(REPLICAS.into(), Reply::json(first.clone()));
    let fixture = Fixture::new(values);
    assert!(
        fixture
            .inspect()
            .unwrap_err()
            .to_string()
            .contains("continuation_invalid")
    );
    let mut second = list("ReplicaSetList", vec![replica(1)]);
    second["metadata"]["resourceVersion"] = json!("different-snapshot");
    fixture.routes.lock().unwrap().insert(
        format!("{REPLICAS}?limit=100&continue=next"),
        Reply::json(second.clone()),
    );
    assert!(
        fixture
            .inspect()
            .unwrap_err()
            .to_string()
            .contains("snapshot_changed")
    );
    second["metadata"]["resourceVersion"] = json!("list-opaque-rv");
    fixture.routes.lock().unwrap().insert(
        format!("{REPLICAS}?limit=100&continue=next"),
        Reply::json(second),
    );
    assert_eq!(fixture.inspect()?.replica_sets.len(), 1);
    let mut page2 = list("ReplicaSetList", vec![]);
    page2["metadata"]["continue"] = json!("third");
    let mut page3 = list("ReplicaSetList", vec![]);
    page3["metadata"]["continue"] = json!("fourth");
    fixture.routes.lock().unwrap().extend([
        (
            format!("{REPLICAS}?limit=100&continue=next"),
            Reply::json(page2),
        ),
        (
            format!("{REPLICAS}?limit=100&continue=third"),
            Reply::json(page3),
        ),
    ]);
    assert!(
        fixture
            .inspect()
            .unwrap_err()
            .to_string()
            .contains("page_budget")
    );
    Ok(())
}

#[test]
fn redirects_duplicate_json_and_oversized_payloads_fail_without_leaking_credentials() -> Result<()>
{
    let fixture = Fixture::new(routes());
    fixture.routes.lock().unwrap().insert(
        DISCOVERY.into(),
        Reply {
            status: 302,
            body: b"{}".to_vec(),
        },
    );
    let error = fixture.inspect().unwrap_err().to_string();
    assert_eq!(error, "kubernetes_http_failure");
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    assert!(!error.contains(TOKEN));
    fixture.routes.lock().unwrap().insert(
        DISCOVERY.into(),
        Reply {
            status: 200,
            body: br#"{"name":"probe","n\u0061me":"another"}"#.to_vec(),
        },
    );
    assert_eq!(
        fixture.inspect().unwrap_err().to_string(),
        "invalid_kubernetes_response"
    );
    fixture.routes.lock().unwrap().insert(
        DISCOVERY.into(),
        Reply {
            status: 200,
            body: vec![b' '; 512 * 1024 + 1],
        },
    );
    assert_eq!(
        fixture.inspect().unwrap_err().to_string(),
        "kubernetes_response_budget"
    );
    Ok(())
}

#[test]
fn scope_and_fixture_endpoints_are_explicit_and_fail_before_network() -> Result<()> {
    for endpoint in [
        "http://localhost/",
        "https://127.0.0.1/",
        "http://example.com/",
        "http://127.0.0.1/other",
        "http://user@127.0.0.1/",
        "http://127.0.0.1/?token=bad",
    ] {
        assert!(
            GkeKubernetesProbe::transport_fixture(endpoint, "http://127.0.0.1/", &Tokens).is_err()
        );
    }
    let fixture = Fixture::new(routes());
    let mut scope = target();
    scope.namespace = "../production".into();
    let probe =
        GkeKubernetesProbe::transport_fixture(&fixture.endpoint, &fixture.endpoint, &Tokens)?;
    assert!(probe.inspect(&scope).is_err());
    scope = target();
    scope.revision = "latest".into();
    assert!(probe.inspect(&scope).is_err());
    assert!(fixture.requests.lock().unwrap().is_empty());
    assert!(serde_json::from_value::<GkeTarget>(json!({"project_number":12345,"location":"us-central1","cluster":"probe","namespace":"disposable","deployment":"old","deployment_uid":"uid","revision":"1","allow_physical_quiescence":true})).is_err());
    Ok(())
}
