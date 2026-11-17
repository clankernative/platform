//! Allowlisted observations of the selected global GCP backend. Neither Pod
//! readiness nor a NEG readiness gate substitutes for endpoint health here.
use super::*;
use day2::runtime_pair::{Backend, Endpoint, PodObservation, ResourceIdentity};
use std::collections::BTreeSet;

pub(super) fn decode(raw: &str) -> Result<Value> {
    ensure!(
        raw.len() <= 1 << 20,
        "runtime_pair_provider_response_budget"
    );
    day2::json::decode(raw.as_bytes())
        .map_err(|_| anyhow::anyhow!("runtime_pair_provider_response_invalid"))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .filter(|text| !text.is_empty() && text.len() <= 2048)
        .context("runtime_pair_provider_field_invalid")
}

fn items(value: &Value) -> Result<&Vec<Value>> {
    let items = value
        .as_array()
        .context("runtime_pair_provider_inventory_invalid")?;
    ensure!(items.len() <= 256, "runtime_pair_provider_inventory_bound");
    Ok(items)
}

fn url(project: &str, path: &str) -> String {
    format!("https://www.googleapis.com/compute/v1/projects/{project}/{path}")
}

pub(super) fn group(backend: &Backend) -> String {
    url(
        &backend.project,
        &format!(
            "zones/{}/networkEndpointGroups/{}",
            backend.zone, backend.neg
        ),
    )
}

pub(super) fn node_uri(backend: &Backend, node: &str) -> String {
    url(
        &backend.project,
        &format!("zones/{}/instances/{node}", backend.zone),
    )
}

pub(super) fn placed_backend(
    mut backend: Backend,
    node: &Value,
    neg: &Value,
    expected_node: &str,
) -> Result<Backend> {
    let identity = resource(node)?;
    ensure!(
        identity.name == expected_node
            && node["metadata"]["deletionTimestamp"].is_null()
            && node["spec"]["providerID"]
                == format!("gce://{}/{}/{expected_node}", backend.project, backend.zone)
            && neg["selfLink"] == group(&backend)
            && neg["name"] == backend.neg
            && neg["networkEndpointType"] == "GCE_VM_IP_PORT"
            && neg["zone"] == url(&backend.project, &format!("zones/{}", backend.zone))
            && neg["id"].as_str().is_some_and(|id| !id.is_empty()
                && id.len() <= 32
                && id.bytes().all(|byte| byte.is_ascii_digit())),
        "runtime_pair_node_project_or_neg_changed"
    );
    let configuration = json!({"backend":backend.configuration,"node":identity,"provider":node["spec"]["providerID"],
        "neg":{"id":neg["id"],"selfLink":neg["selfLink"],"type":neg["networkEndpointType"],"zone":neg["zone"],
            "network":neg["network"],"subnetwork":neg["subnetwork"],"defaultPort":neg["defaultPort"]}});
    backend.configuration = day2::digest(&serde_json::to_vec(&configuration)?);
    Ok(backend)
}

pub(super) fn checked_backend(
    request: &RuntimePairRequest,
    service: &Value,
    raw: &Value,
    check: &Value,
) -> Result<Backend> {
    let mut backend = backend(request, service, raw)?;
    ensure!(
        check["selfLink"]
            == url(
                &request.project,
                &format!("global/healthChecks/{}", backend.health_check)
            )
            && check["name"] == backend.health_check
            && check["id"].as_str().is_some_and(|id| !id.is_empty()
                && id.len() <= 32
                && id.bytes().all(|b| b.is_ascii_digit()))
            && check["type"] == "HTTP"
            && check["httpHealthCheck"]["requestPath"] == "/health/ready"
            && (check["httpHealthCheck"]["portSpecification"] == "USE_SERVING_PORT"
                || (matches!(
                    check["httpHealthCheck"]["portSpecification"].as_str(),
                    None | Some("USE_FIXED_PORT")
                ) && check["httpHealthCheck"]["port"].as_u64()
                    == Some(u64::from(backend.port)))),
        "runtime_pair_ready_health_check_required"
    );
    backend.configuration = day2::digest(&serde_json::to_vec(
        &json!({"backend":backend.configuration,"health_check":check}),
    )?);
    Ok(backend)
}

pub(super) fn backend(
    request: &RuntimePairRequest,
    service: &Value,
    raw: &Value,
) -> Result<Backend> {
    ensure!(
        service["metadata"]["name"] == request.service
            && service["metadata"]["deletionTimestamp"].is_null(),
        "runtime_pair_service_changed"
    );
    let status: Value = decode(text(
        &service["metadata"]["annotations"],
        "cloud.google.com/neg-status",
    )?)?;
    let ports = status["network_endpoint_groups"]
        .as_object()
        .context("runtime_pair_neg_mapping_required")?;
    ensure!(ports.len() == 1, "runtime_pair_single_neg_port_required");
    let (port, neg) = ports
        .iter()
        .next()
        .context("runtime_pair_neg_mapping_required")?;
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("runtime_pair_neg_port_invalid"))?;
    let neg = neg.as_str().context("runtime_pair_neg_name_invalid")?;
    let zones = items(&status["zones"])?;
    ensure!(zones.len() == 1, "runtime_pair_single_neg_zone_required");
    let zone = zones[0].as_str().context("runtime_pair_neg_zone_invalid")?;
    let checks = items(&raw["healthChecks"])?;
    let backends = items(&raw["backends"])?;
    ensure!(
        checks.len() == 1 && backends.len() == 1,
        "runtime_pair_health_checked_backend_required"
    );
    let health = checks[0]
        .as_str()
        .context("runtime_pair_health_check_invalid")?;
    let prefix = url(&request.project, "global/healthChecks/");
    let health_check = health
        .strip_prefix(&prefix)
        .context("runtime_pair_health_check_project_changed")?;
    let seconds = raw["connectionDraining"]["drainingTimeoutSec"]
        .as_u64()
        .and_then(|seconds| u16::try_from(seconds).ok())
        .context("runtime_pair_lb_drain_required")?;
    let configuration = json!({"selfLink":raw["selfLink"],"id":raw["id"],"protocol":raw["protocol"],
        "loadBalancingScheme":raw["loadBalancingScheme"],"healthChecks":raw["healthChecks"],
        "backends":raw["backends"],"connectionDraining":raw["connectionDraining"],
        "timeoutSec":raw["timeoutSec"],"sessionAffinity":raw["sessionAffinity"],
        "securityPolicy":raw["securityPolicy"],"iap":raw["iap"],"portName":raw["portName"]});
    let backend = Backend {
        project: request.project.clone(),
        service: request.backend_service.clone(),
        id: text(raw, "id")?.into(),
        neg: neg.into(),
        zone: zone.into(),
        health_check: health_check.into(),
        configuration: day2::digest(&serde_json::to_vec(&configuration)?),
        port,
        drain_seconds: seconds,
    };
    backend.validate()?;
    ensure!(
        raw["selfLink"]
            == url(
                &request.project,
                &format!("global/backendServices/{}", request.backend_service)
            )
            && raw["name"] == request.backend_service
            && raw["protocol"] == "HTTP"
            && matches!(
                raw["loadBalancingScheme"].as_str(),
                Some("EXTERNAL" | "EXTERNAL_MANAGED")
            )
            && backends[0]["group"] == group(&backend)
            && backends[0]["capacityScaler"]
                .as_f64()
                .is_some_and(|capacity| capacity > 0.0)
            && service["spec"]["ports"]
                .as_array()
                .is_some_and(|ports| ports.len() == 1
                    && ports[0]["port"].as_u64() == Some(u64::from(port))
                    && (ports[0]["targetPort"].as_u64() == Some(u64::from(port))
                        || ports[0]["targetPort"] == "http")),
        "runtime_pair_backend_topology_changed"
    );
    Ok(backend)
}

fn endpoint(value: &Value) -> Result<Endpoint> {
    let endpoint = Endpoint {
        ip: text(value, "ipAddress")?.into(),
        port: value["port"]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .context("runtime_pair_endpoint_port_invalid")?,
    };
    endpoint.validate()?;
    Ok(endpoint)
}

pub(super) fn healthy(backend: &Backend, raw: &Value, node: &str) -> Result<Vec<Endpoint>> {
    let groups = items(raw)?;
    ensure!(
        groups.len() == 1
            && groups[0]["backend"]["group"] == group(backend)
            && groups[0]["status"]["kind"] == "compute#backendServiceGroupHealth",
        "runtime_pair_health_group_changed"
    );
    let mut unique = BTreeSet::new();
    let mut healthy = Vec::new();
    for value in items(&groups[0]["status"]["healthStatus"])? {
        let endpoint = endpoint(value)?;
        ensure!(
            unique.insert(endpoint.clone()),
            "runtime_pair_duplicate_endpoint"
        );
        match value["healthState"].as_str() {
            Some("HEALTHY") => {
                ensure!(
                    value["instance"] == node_uri(backend, node),
                    "runtime_pair_health_instance_changed"
                );
                healthy.push(endpoint);
            }
            Some("UNHEALTHY" | "DRAINING" | "UNKNOWN" | "TIMEOUT") => {}
            _ => bail!("runtime_pair_health_state_invalid"),
        }
    }
    Ok(healthy)
}

pub(super) fn members(raw: &Value) -> Result<BTreeSet<Endpoint>> {
    let mut members = BTreeSet::new();
    for value in items(raw)? {
        ensure!(
            members.insert(endpoint(&value["networkEndpoint"])?),
            "runtime_pair_duplicate_endpoint"
        );
    }
    Ok(members)
}

pub(super) fn resource(value: &Value) -> Result<ResourceIdentity> {
    let identity = ResourceIdentity {
        name: text(&value["metadata"], "name")?.into(),
        uid: text(&value["metadata"], "uid")?.into(),
    };
    identity.validate()?;
    Ok(identity)
}

pub(super) fn owner(value: &Value, kind: &str) -> Result<String> {
    let refs = items(&value["metadata"]["ownerReferences"])?;
    ensure!(
        refs.len() == 1 && refs[0]["kind"] == kind && refs[0]["controller"] == true,
        "runtime_pair_resource_owner_changed"
    );
    Ok(text(&refs[0], "uid")?.into())
}

pub(super) fn pod(
    request: &Request,
    value: &Value,
    replica: &Value,
    port: u16,
) -> Result<PodObservation> {
    let placement = request
        .placement
        .as_ref()
        .context("runtime_pair_placement_required")?;
    let containers = items(&value["spec"]["containers"])?;
    let expected = &replica["spec"]["template"]["spec"]["containers"][0];
    let statuses = items(&value["status"]["containerStatuses"])?;
    let image = if replica["metadata"]["name"] == target_name(request)? {
        &request
            .target
            .as_ref()
            .context("runtime_pair_target_required")?
            .app_image
    } else {
        &request.app_image
    };
    let image_digest = image
        .split_once('@')
        .context("runtime_pair_image_invalid")?
        .1;
    ensure!(
        containers.len() == 1
            && containers[0]["name"] == "day2"
            && ["command", "args", "env", "volumeMounts"]
                .iter()
                .all(|field| containers[0][field] == expected[field])
            && containers[0]["image"] == *image
            && statuses.len() == 1
            && statuses[0]["name"] == "day2"
            && statuses[0]["imageID"]
                .as_str()
                .is_some_and(|id| id.ends_with(&format!("@{image_digest}")))
            && value["spec"]["nodeName"] == placement.node
            && owner(value, "ReplicaSet")? == text(&replica["metadata"], "uid")?
            && value["spec"]["volumes"]
                .as_array()
                .is_some_and(|volumes| volumes.iter().any(|v| v["name"] == "state"
                    && v["persistentVolumeClaim"]["claimName"] == request.pvc)),
        "runtime_pair_pod_placement_changed"
    );
    Ok(PodObservation {
        pod: resource(value)?,
        replicaset_uid: resource(replica)?.uid,
        owner_uid: owner(
            replica,
            if replica["metadata"]["ownerReferences"][0]["kind"] == "ConfigMap" {
                "ConfigMap"
            } else {
                "Deployment"
            },
        )?,
        node: placement.node.clone(),
        pvc_uid: placement.pvc_uid.clone(),
        image: text(&containers[0], "image")?.into(),
        image_id: text(&statuses[0], "imageID")?.into(),
        endpoint: Endpoint {
            ip: text(&value["status"], "podIP")?.into(),
            port,
        },
    })
}

/// A previous successful termination is never evidence that a currently
/// running/restarting container completed its present HTTP drain.
pub(super) fn stopped(pod: &Value) -> bool {
    pod["status"]["containerStatuses"]
        .as_array()
        .is_some_and(|statuses| {
            statuses.len() == 1
                && statuses[0]["name"] == "day2"
                && (statuses[0]["state"]["terminated"]["exitCode"] == 0
                    || (statuses[0]["state"]["waiting"]["reason"] == "CrashLoopBackOff"
                        && statuses[0]["lastState"]["terminated"]["exitCode"] == 0))
                && statuses[0]["state"]["running"].is_null()
                && (statuses[0]["state"]["waiting"].is_null()
                    || statuses[0]["state"]["waiting"]["reason"] == "CrashLoopBackOff")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_project_vm_and_neg_identity_bind_health_without_freezing_endpoint_membership()
    -> Result<()> {
        let (request, service, raw, check) = fixture();
        let backend = checked_backend(&request, &service, &raw, &check)?;
        let node = json!({"metadata":{"name":"node-one","uid":"node-id"},"spec":{"providerID":"gce://project-one/us-central1-a/node-one"}});
        let neg = json!({"id":"789","name":"neg-one","selfLink":group(&backend),"networkEndpointType":"GCE_VM_IP_PORT",
            "zone":url("project-one","zones/us-central1-a"),"size":1});
        let bound = placed_backend(backend.clone(), &node, &neg, "node-one")?;
        let mut foreign = node.clone();
        foreign["spec"]["providerID"] = json!("gce://foreign-project/us-central1-a/node-one");
        assert!(placed_backend(backend.clone(), &foreign, &neg, "node-one").is_err());
        let mut resized = neg.clone();
        resized["size"] = json!(2);
        assert_eq!(
            placed_backend(backend.clone(), &node, &resized, "node-one")?,
            bound
        );
        let mut replaced = neg;
        replaced["id"] = json!("790");
        assert_ne!(
            placed_backend(backend, &node, &replaced, "node-one")?.configuration,
            bound.configuration
        );
        Ok(())
    }

    fn fixture() -> (RuntimePairRequest, Value, Value, Value) {
        let request = RuntimePairRequest {
            receipt: "receipt.json".into(),
            receipt_digest: day2::digest(b"receipt"),
            project: "project-one".into(),
            backend_service: "backend-one".into(),
            service: "app-service".into(),
        };
        let service = json!({"metadata":{"name":"app-service","annotations":{"cloud.google.com/neg-status":
            json!({"network_endpoint_groups":{"8080":"neg-one"},"zones":["us-central1-a"]}).to_string()}},
            "spec":{"ports":[{"port":8080,"targetPort":"http"}]}});
        let backend = json!({"id":"12345","name":"backend-one","selfLink":url("project-one","global/backendServices/backend-one"),
            "protocol":"HTTP","loadBalancingScheme":"EXTERNAL_MANAGED","healthChecks":[url("project-one","global/healthChecks/ready")],
            "backends":[{"group":url("project-one","zones/us-central1-a/networkEndpointGroups/neg-one"),"capacityScaler":1.0}],
            "connectionDraining":{"drainingTimeoutSec":30}});
        let check = json!({"id":"99","name":"ready","selfLink":url("project-one","global/healthChecks/ready"),
            "type":"HTTP","httpHealthCheck":{"requestPath":"/health/ready","portSpecification":"USE_SERVING_PORT"}});
        (request, service, backend, check)
    }

    #[test]
    fn actual_ready_check_and_exact_project_group_configuration_are_required() -> Result<()> {
        let (request, service, raw, check) = fixture();
        let baseline = checked_backend(&request, &service, &raw, &check)?;
        let mut unsupported = Vec::new();
        let mut value = raw.clone();
        value["healthChecks"] = json!([]);
        unsupported.push((service.clone(), value, check.clone()));
        let mut value = raw.clone();
        value["id"] = json!("not-an-id");
        unsupported.push((service.clone(), value, check.clone()));
        let mut value = raw.clone();
        value["backends"][0]["group"] = json!(url(
            "other-project",
            "zones/us-central1-a/networkEndpointGroups/neg-one"
        ));
        unsupported.push((service.clone(), value, check.clone()));
        let mut value = raw.clone();
        value["connectionDraining"]["drainingTimeoutSec"] = json!(0);
        unsupported.push((service.clone(), value, check.clone()));
        let mut value = check.clone();
        value["httpHealthCheck"]["requestPath"] = json!("/health/candidate");
        unsupported.push((service.clone(), raw.clone(), value));
        let mut value = check.clone();
        value["selfLink"] = json!(url("other-project", "global/healthChecks/ready"));
        unsupported.push((service.clone(), raw.clone(), value));
        let mut value = service.clone();
        value["metadata"]["annotations"]["cloud.google.com/neg-status"]=json!(json!({"network_endpoint_groups":{"8080":"neg-one"},"zones":["us-central1-a","us-central1-b"]}).to_string());
        unsupported.push((value, raw.clone(), check.clone()));
        for (service, raw, check) in unsupported {
            assert!(checked_backend(&request, &service, &raw, &check).is_err());
        }
        let mut replaced = raw.clone();
        replaced["id"] = json!("12346");
        assert_ne!(
            checked_backend(&request, &service, &replaced, &check)?.id,
            baseline.id
        );
        let mut replaced = check.clone();
        replaced["id"] = json!("100");
        assert_ne!(
            checked_backend(&request, &service, &raw, &replaced)?.configuration,
            baseline.configuration
        );
        Ok(())
    }

    #[test]
    fn endpoint_health_and_neg_membership_are_separate_bounded_observations() -> Result<()> {
        let (request, service, raw, check) = fixture();
        let backend = checked_backend(&request, &service, &raw, &check)?;
        let endpoint = Endpoint {
            ip: "10.0.0.2".into(),
            port: 8080,
        };
        let response = json!([{"backend":{"group":group(&backend)},"status":{"kind":"compute#backendServiceGroupHealth",
            "healthStatus":[{"ipAddress":"10.0.0.2","port":8080,"healthState":"HEALTHY","instance":node_uri(&backend,"node-one")},
                {"ipAddress":"10.0.0.1","port":8080,"healthState":"UNHEALTHY"}]}}]);
        assert_eq!(
            healthy(&backend, &response, "node-one")?,
            vec![endpoint.clone()]
        );
        let mut wrong = response.clone();
        wrong[0]["backend"]["group"] = json!("some-other-neg");
        assert!(healthy(&backend, &wrong, "node-one").is_err());
        let mut duplicate = response.clone();
        duplicate[0]["status"]["healthStatus"][1] =
            duplicate[0]["status"]["healthStatus"][0].clone();
        assert!(healthy(&backend, &duplicate, "node-one").is_err());
        let mut foreign = response.clone();
        foreign[0]["status"]["healthStatus"][0]["instance"] =
            json!(node_uri(&backend, "another-node"));
        assert!(healthy(&backend, &foreign, "node-one").is_err());
        let members = members(&json!([{"networkEndpoint":{"ipAddress":"10.0.0.1","port":8080}}]))?;
        assert!(!members.contains(&endpoint)); // health does not prove NEG membership or removal.
        assert!(decode(&"x".repeat((1 << 20) + 1)).is_err());
        let error = decode("{\"private-provider-value\":").unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            "runtime_pair_provider_response_invalid"
        );
        Ok(())
    }

    #[test]
    fn a_historical_zero_exit_never_proves_a_current_running_transport_stopped() {
        let mut pod = json!({"status":{"containerStatuses":[{"name":"day2","state":{"running":{"startedAt":"now"}},
            "lastState":{"terminated":{"exitCode":0}}}]}});
        assert!(!stopped(&pod));
        pod["status"]["containerStatuses"][0]["state"] = json!({"terminated":{"exitCode":0}});
        assert!(stopped(&pod));
        pod["status"]["containerStatuses"][0]["state"] = json!({"terminated":{"exitCode":137}});
        assert!(!stopped(&pod));
        pod["status"]["containerStatuses"][0]["state"] =
            json!({"waiting":{"reason":"ContainerCreating"}});
        assert!(!stopped(&pod));
        pod["status"]["containerStatuses"][0]["state"] =
            json!({"waiting":{"reason":"CrashLoopBackOff"}});
        assert!(stopped(&pod));
    }
}
