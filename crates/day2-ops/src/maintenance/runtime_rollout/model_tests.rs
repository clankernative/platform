//! Scripted Kubernetes/provider port, separate from the real-SQLite kernel
//! tests. Native journal responses are fixture DATA here, not qualification.
use super::tests::{request, source};
use super::*;
use day2::runtime_pair::{Backend, Endpoint, PodObservation, ResourceIdentity};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

struct World {
    objects: BTreeMap<(String, String), Value>,
    release: Release,
    raw_backend: Value,
    raw_check: Value,
    raw_neg: Value,
    healthy: bool,
    mutations: usize,
    lose: Option<String>,
}

fn identity(name: &str, uid: &str) -> ResourceIdentity {
    ResourceIdentity {
        name: name.into(),
        uid: uid.into(),
    }
}

fn patch(value: &mut Value, operations: &Value) -> Result<()> {
    for op in operations.as_array().context("patch operations")? {
        let path = op["path"].as_str().context("patch path")?;
        if op["op"] == "test" {
            ensure!(
                value.pointer(path) == Some(&op["value"]),
                "compare-and-swap refused"
            );
            continue;
        }
        let (parent, last) = path.rsplit_once('/').context("patch parent")?;
        let key = last.replace("~1", "/").replace("~0", "~");
        let target = value
            .pointer_mut(parent)
            .context("patch parent missing")?
            .as_object_mut()
            .context("patch parent object")?;
        match op["op"].as_str() {
            Some("add" | "replace") => {
                target.insert(key, op["value"].clone());
            }
            Some("remove") => {
                ensure!(target.remove(&key).is_some(), "patch remove absent");
            }
            _ => bail!("unexpected patch"),
        }
    }
    Ok(())
}

struct Port(Rc<RefCell<World>>);
impl Cluster for Port {
    fn kubectl(
        &mut self,
        args: &[String],
        _stdin: Option<&[u8]>,
        _timeout: Duration,
    ) -> Result<String> {
        let args = &args[2..];
        let mut world = self.0.borrow_mut();
        match args[0].as_str() {
            "get" => {
                let kind = args[1].as_str();
                if matches!(kind, "pods" | "replicasets") && args[2] == "-o" {
                    let single = if kind == "pods" { "pod" } else { "replicaset" };
                    return Ok(json!({"items":world.objects.iter().filter(|((kind,_),_)|kind==single).map(|(_,value)|value.clone()).collect::<Vec<_>>()}).to_string());
                }
                if args.iter().any(|arg| arg == "--ignore-not-found")
                    && !world.objects.contains_key(&(kind.into(), args[2].clone()))
                {
                    return Ok(String::new());
                }
                Ok(world
                    .objects
                    .get(&(kind.into(), args[2].clone()))
                    .context("unknown scripted object")?
                    .to_string())
            }
            "exec" => Ok(serde_json::to_string(&world.release)?),
            "delete" => {
                let options: Value = serde_json::from_slice(_stdin.context("delete options")?)?;
                let path = args[2].as_str();
                let name = path.rsplit('/').next().unwrap().to_owned();
                let kind = if path.contains("/replicasets/") {
                    "replicaset"
                } else {
                    "pod"
                };
                let object = world
                    .objects
                    .get(&(kind.into(), name.clone()))
                    .context("delete object")?;
                ensure!(
                    object["metadata"]["uid"] == options["preconditions"]["uid"],
                    "delete UID changed"
                );
                world.objects.remove(&(kind.into(), name));
                if kind == "replicaset" {
                    world.objects.remove(&("pod".into(), "target-pod".into()));
                }
                world.mutations += 1;
                Ok("{}".into())
            }
            "wait" => Ok("{}".into()),
            "patch" => {
                let kind = &args[1];
                let name = &args[2];
                let operations: Value = serde_json::from_str(args.last().unwrap())?;
                let object = world
                    .objects
                    .get_mut(&(kind.clone(), name.clone()))
                    .context("patch object")?;
                patch(object, &operations)?;
                let step = if kind == "replicaset" {
                    "adopt"
                } else if operations
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|op| op["path"] == "/spec/template" && op["op"] == "replace")
                {
                    "retarget"
                } else if object["spec"]["paused"] == true {
                    "pause"
                } else {
                    "unpause"
                };
                world.mutations += 1;
                if kind == "deployment"
                    && step == "unpause"
                    && operations
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|op| op["path"] == "/spec/paused")
                {
                    world.objects.remove(&("pod".into(), "source-pod".into()));
                }
                if world.lose.as_deref() == Some(step) {
                    world.lose = None;
                    bail!("lost response after committed API mutation");
                }
                Ok("{}".into())
            }
            _ => bail!("unexpected scripted kubectl verb"),
        }
    }

    fn backend_read(
        &mut self,
        _project: &str,
        read: &BackendRead,
        _timeout: Duration,
    ) -> Result<String> {
        let world = self.0.borrow();
        Ok(match read {
            BackendRead::Service {..}=>world.raw_backend.clone(),
            BackendRead::HealthCheck {..}=>world.raw_check.clone(),
            BackendRead::Neg {..}=>world.raw_neg.clone(),
            BackendRead::Health {..}=>json!([{"backend":{"group":world.raw_backend["backends"][0]["group"]},
                "status":{"kind":"compute#backendServiceGroupHealth","healthStatus":[{"ipAddress":"10.0.0.2","port":8080,"instance":"https://www.googleapis.com/compute/v1/projects/project-one/zones/us-central1-a/instances/node-one",
                    "healthState":if world.healthy {"HEALTHY"} else {"UNHEALTHY"}}]}}]),
            _=>bail!("unexpected scripted provider read"),
        }.to_string())
    }
}

struct RegistryPort;
impl Registry for RegistryPort {
    fn get(&mut self, _host: &str, _path: &str, _accept: &str, _limit: u64) -> Result<Vec<u8>> {
        bail!("registry not used")
    }
}
struct PromptPort;
impl Prompt for PromptPort {
    fn confirm(&mut self, _question: &str, _word: &str) -> Result<bool> {
        Ok(true)
    }
}

fn fixture() -> Result<(Request, Rc<RefCell<World>>)> {
    let mut request = request();
    request.runtime_pair = Some(RuntimePairRequest {
        receipt: "receipt.json".into(),
        receipt_digest: day2::digest(b"receipt"),
        project: "project-one".into(),
        backend_service: "backend-one".into(),
        service: "app-service".into(),
    });
    let source = template(&source(&request));
    let target = candidate(&request, &source, "{}")?;
    let map_name = selection_name(&request)?;
    let replica_name = target_name(&request)?;
    let service = json!({"metadata":{"name":"app-service","uid":"service-one","annotations":{"cloud.google.com/neg-status":
        json!({"network_endpoint_groups":{"8080":"neg-one"},"zones":["us-central1-a"]}).to_string()}},
        "spec":{"selector":{"app.kubernetes.io/name":"day2-app"},"ports":[{"port":8080,"targetPort":"http"}]}});
    let prefix = "https://www.googleapis.com/compute/v1/projects/project-one";
    let raw_backend = json!({"name":"backend-one","id":"123","selfLink":format!("{prefix}/global/backendServices/backend-one"),
        "protocol":"HTTP","loadBalancingScheme":"EXTERNAL_MANAGED","healthChecks":[format!("{prefix}/global/healthChecks/ready")],
        "backends":[{"group":format!("{prefix}/zones/us-central1-a/networkEndpointGroups/neg-one"),"capacityScaler":1.0}],
        "connectionDraining":{"drainingTimeoutSec":30}});
    let raw_check = json!({"id":"456","name":"ready","selfLink":format!("{prefix}/global/healthChecks/ready"),"type":"HTTP",
        "httpHealthCheck":{"requestPath":"/health/ready","portSpecification":"USE_SERVING_PORT"}});
    let backend: Backend = provider::checked_backend(
        request.runtime_pair.as_ref().unwrap(),
        &service,
        &raw_backend,
        &raw_check,
    )?;
    let node = json!({"metadata":{"name":"node-one","uid":"node-id"},"spec":{"providerID":"gce://project-one/us-central1-a/node-one"}});
    let raw_neg = json!({"id":"789","name":"neg-one","selfLink":provider::group(&backend),"networkEndpointType":"GCE_VM_IP_PORT",
        "zone":format!("{prefix}/zones/us-central1-a")});
    let backend = provider::placed_backend(backend, &node, &raw_neg, "node-one")?;
    let pod_observation = |is_target: bool| PodObservation {
        pod: identity(
            if is_target {
                "target-pod"
            } else {
                "source-pod"
            },
            if is_target {
                "target-pod-one"
            } else {
                "source-pod-one"
            },
        ),
        replicaset_uid: if is_target { "target-rs" } else { "source-rs" }.into(),
        owner_uid: if is_target {
            "selection-one"
        } else {
            "controller-one"
        }
        .into(),
        node: "node-one".into(),
        pvc_uid: "pvc-one".into(),
        image: if is_target {
            request.target.as_ref().unwrap().app_image.clone()
        } else {
            request.app_image.clone()
        },
        image_id: if is_target {
            request.target.as_ref().unwrap().app_image.clone()
        } else {
            request.app_image.clone()
        },
        endpoint: Endpoint {
            ip: if is_target { "10.0.0.2" } else { "10.0.0.1" }.into(),
            port: 8080,
        },
    };
    let authority = day2::authority_state::AuthorityStamp {
        epoch: day2::digest(b"epoch"),
        revision: 1,
    };
    let health = HealthObservation {
        round: 1,
        authority: authority.clone(),
        service: identity("app-service", "service-one"),
        backend: backend.clone(),
        target: pod_observation(true),
        source: Some(pod_observation(false)),
        healthy: vec![pod_observation(true).endpoint],
    };
    let protocols = day2::runtime_pair::Protocols {
        private_schema: day2::digest(b"schema"),
        artifact_catalog_schema: day2::digest(b"catalog"),
        serving_lease: 2,
        operation_lease: 2,
        execution_lease: 2,
        release_journal: 4,
        authority: 1,
        invocation_effect: 2,
        web_ticket: 1,
        worker: 1,
        artifact_catalog: 1,
    };
    let source_manifest = day2::runtime_pair::Manifest {
        runtime: day2::runtime_pair::RuntimeIdentity {
            platform_inventory: day2::digest(b"source"),
            containment: None,
        },
        protocols: protocols.clone(),
    };
    let target_manifest = day2::runtime_pair::Manifest {
        runtime: day2::runtime_pair::RuntimeIdentity {
            platform_inventory: day2::digest(b"target"),
            containment: None,
        },
        protocols,
    };
    let generation = |runtime, image| day2::rollout::Generation {
        artifact: format!("sha256:{}", request.artifact_id),
        runtime,
        instance_digest: day2::digest(b"instance"),
        image,
    };
    let release = Release {
        id: "pair-one".into(),
        scope: "test".into(),
        source: generation(source_manifest.runtime.clone(), request.app_image.clone()),
        target: generation(
            target_manifest.runtime.clone(),
            request.target.as_ref().unwrap().app_image.clone(),
        ),
        kind: ReleaseKind::RuntimePair {
            admission: Box::new(day2::runtime_pair::Admission {
                receipt_digest: day2::digest(b"receipt"),
                receipt: day2::runtime_pair::Receipt {
                    version: 1,
                    source: source_manifest,
                    target: target_manifest,
                    profile: day2::runtime_pair::Profile::SqliteLocalV1,
                    verifier: day2::digest(b"verifier"),
                    recipe: day2::digest(b"recipe"),
                    outcome: day2::runtime_pair::Outcome::Passed,
                    checks: Default::default(),
                },
            }),
            execution: day2::runtime_pair::Execution::Admitted {
                source: day2::digest(b"source-generation"),
                candidate: day2::digest(b"target-generation"),
                attempt: 1,
                check: None,
                handoff: Some(Box::new(day2::runtime_pair::Handoff {
                    binding: HandoffBinding {
                        service: health.service.clone(),
                        candidate_controller: identity(&replica_name, "target-rs"),
                        selection: identity(&map_name, "selection-one"),
                        source_template: template_digest(&source)?,
                        target_template: template_digest(&target)?,
                        backend,
                    },
                    round: 1,
                    stage: HandoffStage::Quiesced {
                        health: Box::new(health.clone()),
                        drain: Box::new(DrainObservation {
                            health,
                            absent: vec![pod_observation(false).endpoint],
                            elapsed_ms: 30_000,
                            source_inflight: 0,
                            source_streams: 0,
                            source_stopped: true,
                        }),
                    },
                })),
            },
        },
        target_instance_digest: day2::digest(b"{}"),
        probe: None,
        authority,
        target_security: None,
        placement: Some(serde_json::from_value(
            json!({"namespace":request.namespace,"controller_uid":"controller-one","pvc_uid":"pvc-one","node":"node-one","request_digest":day2::digest(b"request")}),
        )?),
        phase: Phase::Draining,
    };
    let pod = |is_target: bool| {
        let observation = pod_observation(is_target);
        let mut spec = if is_target {
            target["spec"].clone()
        } else {
            source["spec"].clone()
        };
        spec["nodeName"] = json!("node-one");
        json!({"metadata":{"name":observation.pod.name,"uid":observation.pod.uid,"ownerReferences":[{"kind":"ReplicaSet","uid":observation.replicaset_uid,"controller":true}]},
            "spec":spec,"status":{"phase":"Running","podIP":observation.endpoint.ip,"containerStatuses":[{"name":"day2","imageID":observation.image_id,
                "state":if is_target {json!({"running":{}})} else {json!({"terminated":{"exitCode":0}})}}]}})
    };
    let blueprint = json!({"request":day2::digest(b"request"),"controller":"controller-one","receipt":day2::digest(b"receipt"),"source":source,"target":target});
    let mut objects = BTreeMap::new();
    objects.insert(("node".into(), "node-one".into()), node);
    for (kind, name, value) in [
        (
            "deployment",
            request.statefulset.clone(),
            json!({"metadata":{"name":request.statefulset,"uid":"controller-one","resourceVersion":"1",
            "annotations":{"day2.dev/runtime-pair":day2::digest(b"request")}},"spec":{"replicas":1,"strategy":{"type":"RollingUpdate","rollingUpdate":{"maxSurge":1,"maxUnavailable":0}},"template":source}}),
        ),
        (
            "configmap",
            map_name.clone(),
            json!({"metadata":{"name":map_name,"uid":"selection-one"},"immutable":true,
            "data":{"request-digest":day2::digest(b"request"),"blueprint.json":blueprint.to_string()}}),
        ),
        (
            "replicaset",
            replica_name.clone(),
            json!({"metadata":{"name":replica_name,"uid":"target-rs","resourceVersion":"1",
            "annotations":{"day2.dev/rollout-request":day2::digest(b"request")},"ownerReferences":[{"kind":"ConfigMap","name":map_name,"uid":"selection-one","controller":true}]},
            "spec":{"replicas":1,"template":target}}),
        ),
        (
            "replicaset",
            "source-replica".into(),
            json!({"metadata":{"name":"source-replica","uid":"source-rs","ownerReferences":[{"kind":"Deployment","uid":"controller-one","controller":true}]},"spec":{"replicas":1,"template":source}}),
        ),
        ("pod", "source-pod".into(), pod(false)),
        ("pod", "target-pod".into(), pod(true)),
        ("service", "app-service".into(), service),
        (
            "pvc",
            "app-state".into(),
            json!({"metadata":{"uid":"pvc-one"},"spec":{"accessModes":["ReadWriteOnce"]},"status":{"phase":"Bound"}}),
        ),
    ] {
        objects.insert((kind.into(), name), value);
    }
    Ok((
        request,
        Rc::new(RefCell::new(World {
            objects,
            release,
            raw_backend,
            raw_check,
            raw_neg,
            healthy: true,
            mutations: 0,
            lose: None,
        })),
    ))
}

fn session(request: &Request, world: &Rc<RefCell<World>>) -> Result<Session> {
    let work = tempfile::tempdir()?;
    Ok(Session {
        tools: Tools {
            cluster: Box::new(Port(world.clone())),
            registry: Box::new(RegistryPort),
            prompt: Box::new(PromptPort),
        },
        request: request.clone(),
        request_file: work.path().join("request.json"),
        request_json: "{}".into(),
        request_digest: day2::digest(b"request"),
        operation: Operation::RuntimeRollout,
        stamp: "test".into(),
        pod: "helper".into(),
        replicas: 1,
        backup_root: work.path().join("backups"),
        journal: work.path().join("journal"),
        events: Vec::new(),
        target_instance: Some("{}".into()),
        controller: world.borrow().objects[&("deployment".into(), request.statefulset.clone())]
            .clone(),
        online_node: Some("node-one".into()),
        pvc_uid: Some("pvc-one".into()),
        incumbent: None,
        activation: None,
        state: State {
            resumed: true,
            ..State::default()
        },
        work,
    })
}

#[test]
fn every_adoption_response_can_be_lost_and_retried_without_a_target_restart_or_scale_to_zero()
-> Result<()> {
    let steps = ["pause", "retarget", "adopt", "unpause"];
    for lost in steps {
        let (request, world) = fixture()?;
        world.borrow_mut().lose = Some(lost.into());
        let mut attempt = session(&request, &world)?;
        for step in steps {
            let result = attempt.runtime_adoption(step);
            if step == lost {
                assert!(result.is_err());
                break;
            }
            result?;
        }
        // Model abrupt controller death: no Drop cleanup may restore old code or
        // delete the already serving Target. Only the new exact request resumes.
        attempt.state.finished = true;
        drop(attempt);
        let mut resumed = session(&request, &world)?;
        for step in steps {
            resumed.runtime_adoption(step)?;
        }
        let observed = world.borrow();
        let controller = &observed.objects[&("deployment".into(), request.statefulset.clone())];
        assert_eq!(controller["spec"]["replicas"], 1);
        assert_eq!(controller["spec"]["paused"], false);
        assert_eq!(
            observed.objects[&("pod".into(), "target-pod".into())]["metadata"]["uid"],
            "target-pod-one"
        );
        assert!(
            !observed
                .objects
                .contains_key(&("pod".into(), "source-pod".into()))
        );
        let replica = &observed.objects[&("replicaset".into(), target_name(&request)?)];
        assert_eq!(provider::owner(replica, "Deployment")?, "controller-one");
        assert_eq!(
            template_digest(&controller["spec"]["template"])?,
            template_digest(&replica["spec"]["template"])?
        );
        resumed.state.finished = true;
    }
    Ok(())
}

#[test]
fn stale_backend_pod_claim_template_or_missing_stop_ack_refuses_before_any_adoption_mutation()
-> Result<()> {
    for fault in 0..14 {
        let (request, world) = fixture()?;
        {
            let mut data = world.borrow_mut();
            match fault {
                0 => data.healthy = false,
                1 => data.raw_backend["id"] = json!("999"),
                2 => {
                    data.objects
                        .get_mut(&("service".into(), "app-service".into()))
                        .unwrap()["metadata"]["uid"] = json!("replacement")
                }
                3 => {
                    data.objects
                        .get_mut(&("pod".into(), "target-pod".into()))
                        .unwrap()["status"]["containerStatuses"][0]["imageID"] =
                        json!("registry/wrong@sha256:wrong")
                }
                4 => {
                    data.objects
                        .get_mut(&("pvc".into(), "app-state".into()))
                        .unwrap()["metadata"]["uid"] = json!("replacement")
                }
                5 => {
                    data.objects
                        .get_mut(&("deployment".into(), request.statefulset.clone()))
                        .unwrap()["spec"]["template"]["metadata"]["annotations"]["concurrent-edit"] =
                        json!("changed")
                }
                6 => {
                    data.objects
                        .get_mut(&("pod".into(), "target-pod".into()))
                        .unwrap()["spec"]["nodeName"] = json!("another-node")
                }
                8 => {
                    data.objects
                        .get_mut(&("node".into(), "node-one".into()))
                        .unwrap()["spec"]["providerID"] =
                        json!("gce://foreign-project/us-central1-a/node-one")
                }
                9 => {
                    data.objects
                        .get_mut(&("replicaset".into(), target_name(&request)?))
                        .unwrap()["metadata"]["deletionTimestamp"] = json!("deleting")
                }
                10 => {
                    data.objects
                        .get_mut(&("configmap".into(), selection_name(&request)?))
                        .unwrap()["metadata"]["deletionTimestamp"] = json!("deleting")
                }
                11 => {
                    data.objects
                        .get_mut(&("deployment".into(), request.statefulset.clone()))
                        .unwrap()["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"] = json!(1)
                }
                12 => {
                    data.objects
                        .get_mut(&("pod".into(), "source-pod".into()))
                        .unwrap()["spec"]["containers"][0]["args"] = json!(["wrong"])
                }
                13 => {
                    data.objects
                        .get_mut(&("pod".into(), "target-pod".into()))
                        .unwrap()["spec"]["containers"][0]["args"] = json!(["wrong"])
                }
                _ => {
                    if let ReleaseKind::RuntimePair {
                        execution:
                            day2::runtime_pair::Execution::Admitted {
                                handoff: Some(h), ..
                            },
                        ..
                    } = &mut data.release.kind
                        && let HandoffStage::Quiesced { drain, .. } = &mut h.stage
                    {
                        drain.source_stopped = false;
                    }
                }
            }
        }
        let mut attempt = session(&request, &world)?;
        assert!(
            attempt.runtime_adoption("pause").is_err(),
            "fault {fault} admitted"
        );
        assert_eq!(
            world.borrow().mutations,
            0,
            "fault {fault} mutated deployment"
        );
        attempt.state.finished = true;
    }
    Ok(())
}

#[test]
fn an_aborted_never_public_candidate_is_removed_without_stopping_source_and_retry_is_safe()
-> Result<()> {
    let (request, world) = fixture()?;
    {
        let mut data = world.borrow_mut();
        data.release.phase = Phase::Aborted;
        if let ReleaseKind::RuntimePair {
            execution:
                day2::runtime_pair::Execution::Admitted {
                    handoff: Some(h), ..
                },
            ..
        } = &mut data.release.kind
        {
            h.stage = HandoffStage::Bound;
        }
        data.objects
            .get_mut(&("pod".into(), "source-pod".into()))
            .unwrap()["status"]["containerStatuses"][0]["state"] = json!({"running":{}});
    }
    let mut attempt = session(&request, &world)?;
    attempt.runtime_abort_cleanup()?;
    attempt.runtime_abort_cleanup()?;
    let observed = world.borrow();
    assert!(
        observed
            .objects
            .contains_key(&("pod".into(), "source-pod".into()))
    );
    assert!(
        !observed
            .objects
            .contains_key(&("pod".into(), "target-pod".into()))
    );
    assert_eq!(
        observed.objects[&("deployment".into(), request.statefulset.clone())]["spec"]["replicas"],
        1
    );
    assert!(observed.objects[&("deployment".into(),request.statefulset.clone())]["metadata"]["annotations"]["day2.dev/runtime-pair"].is_null());
    attempt.state.finished = true;
    Ok(())
}
