use super::*;

pub(super) fn template(value: &Value) -> Value {
    let mut value = value.clone();
    if let Some(metadata) = value["metadata"].as_object_mut() {
        metadata.remove("creationTimestamp");
        if let Some(labels) = metadata.get_mut("labels").and_then(Value::as_object_mut) {
            labels.remove("pod-template-hash");
        }
    }
    value
}

pub(super) fn template_digest(value: &Value) -> Result<String> {
    Ok(day2::digest(&serde_json::to_vec(&template(value))?))
}

/// Add the same-node constraint to every OR term. Never bypass the scheduler
/// with nodeName or discard the source's existing placement constraints.
pub(super) fn pin(spec: &mut Value, node: &str) -> Result<()> {
    ensure!(
        dns_label(node) && spec["nodeName"].is_null(),
        "runtime_pair_scheduler_placement_required"
    );
    if spec["affinity"].is_null() {
        spec["affinity"] = json!({});
    }
    if spec["affinity"]["nodeAffinity"].is_null() {
        spec["affinity"]["nodeAffinity"] = json!({});
    }
    let required =
        &mut spec["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"];
    if required.is_null() {
        *required = json!({"nodeSelectorTerms":[{}]});
    }
    let terms = required["nodeSelectorTerms"]
        .as_array_mut()
        .context("runtime_pair_node_affinity_invalid")?;
    ensure!(
        !terms.is_empty() && terms.len() <= 32,
        "runtime_pair_node_affinity_bound"
    );
    for term in terms {
        if term["matchFields"].is_null() {
            term["matchFields"] = json!([]);
        }
        term["matchFields"]
            .as_array_mut()
            .context("runtime_pair_node_affinity_invalid")?
            .push(json!({"key":"metadata.name","operator":"In","values":[node]}));
    }
    Ok(())
}

pub(super) fn candidate(request: &Request, source: &Value, instance: &str) -> Result<Value> {
    let target = request
        .target
        .as_ref()
        .context("runtime_pair_target_required")?;
    let mut target_template = template(source);
    let spec = &mut target_template["spec"];
    ensure!(
        spec["hostPID"] != true
            && spec["hostIPC"] != true
            && spec["hostNetwork"] != true
            && spec["automountServiceAccountToken"] == false
            && spec["ephemeralContainers"]
                .as_array()
                .is_none_or(Vec::is_empty),
        "runtime_pair_pod_isolation_required"
    );
    // The initial local-only class has no credential, OAuth, provider or app-call
    // initialization. A live claim is already owned; do not chown it on surge.
    ensure!(
        spec["initContainers"]
            .as_array()
            .is_none_or(
                |inits| inits.iter().all(|init| init["name"] == "state-ownership"
                    && init["command"]
                        == json!(["/busybox/chown", "10001:10001", "/srv/day2/.state"]))
            ),
        "runtime_pair_initialization_unsupported"
    );
    spec.as_object_mut()
        .context("runtime_pair_pod_spec_required")?
        .remove("initContainers");
    let containers = spec["containers"]
        .as_array_mut()
        .context("runtime_pair_containers_required")?;
    ensure!(
        containers.len() == 1
            && containers[0]["name"] == "day2"
            && containers[0]["image"] == request.app_image
            && containers[0]["command"] == json!([SERVE])
            && (containers[0]["args"] == json!(["/srv/day2/instance.json", request.app, "--edge"])
                || containers[0]["args"]
                    == json!([
                        "/srv/day2/instance.json",
                        request.app,
                        "--runtime-candidate",
                        format!("{PAIR_ROOT}/candidate.json"),
                        EVIDENCE
                    ]))
            && containers[0]["securityContext"]["readOnlyRootFilesystem"] == true
            && containers[0]["securityContext"]["allowPrivilegeEscalation"] == false
            && containers[0]["resources"]["requests"].is_object()
            && containers[0]["resources"]["limits"].is_object(),
        "runtime_pair_source_template_unsupported"
    );
    let container = &mut containers[0];
    container["image"] = json!(target.app_image);
    container["args"] = json!([
        "/srv/day2/instance.json",
        request.app,
        "--runtime-candidate",
        format!("{PAIR_ROOT}/candidate.json"),
        EVIDENCE
    ]);
    let env = container["env"]
        .as_array_mut()
        .context("runtime_pair_environment_required")?;
    env.retain(|entry| entry["name"] != "DAY2_EXPECTED_ROLLOUT");
    env.push(json!({"name":"DAY2_EXPECTED_ROLLOUT","value":request.request_id}));
    let mounts = container["volumeMounts"]
        .as_array_mut()
        .context("runtime_pair_mounts_required")?;
    ensure!(
        mounts.iter().all(|mount| matches!(
            mount["name"].as_str(),
            Some("state" | "instance" | "tmp" | "runtime-pair")
        )) && mounts.iter().any(|mount| mount["name"] == "instance"
            && mount["mountPath"] == "/srv/day2/instance.json"
            && mount["subPath"] == "instance.json"
            && mount["readOnly"] == true)
            && mounts.iter().any(|mount| mount["name"] == "state"
                && mount["mountPath"] == "/srv/day2/.state"
                && mount["subPath"].is_null()
                && mount["subPathExpr"].is_null()),
        "runtime_pair_mounts_unsupported"
    );
    mounts.retain(|mount| mount["name"] != "runtime-pair");
    for name in ["candidate.json", "source.json"] {
        mounts.push(json!({"name":"runtime-pair","mountPath":format!("{PAIR_ROOT}/{name}"),"subPath":name,"readOnly":true}));
    }
    let volumes = spec["volumes"]
        .as_array_mut()
        .context("runtime_pair_volumes_required")?;
    ensure!(
        volumes.iter().all(|v| matches!(
            v["name"].as_str(),
            Some("state" | "instance" | "tmp" | "runtime-pair")
        )),
        "runtime_pair_volumes_unsupported"
    );
    volumes.retain(|volume| volume["name"] != "runtime-pair");
    for volume in volumes.iter_mut() {
        if volume["name"] == "instance" {
            volume["configMap"] = json!({"name":selection_name(request)?,"defaultMode":292,"items":[{"key":"instance.json","path":"instance.json"}]});
        }
    }
    volumes.push(json!({"name":"runtime-pair","configMap":{"name":selection_name(request)?,"defaultMode":292}}));
    pin(
        spec,
        &request
            .placement
            .as_ref()
            .context("runtime_pair_placement_required")?
            .node,
    )?;
    target_template["metadata"]["labels"]["day2.dev/runtime-pair"] = json!(suffix(request)?);
    target_template["metadata"]["annotations"]["day2.dev/instance-sha256"] =
        json!(day2::digest(instance.as_bytes()).trim_start_matches("sha256:"));
    Ok(target_template)
}

pub(super) fn checkpoint_pod(
    request: &Request,
    target: &Value,
    name: &str,
    scratch: u64,
) -> Result<Value> {
    let mut value = target.clone();
    value["metadata"]["labels"] = helper_labels(request);
    let spec = &mut value["spec"];
    spec["restartPolicy"] = json!("Never");
    spec["activeDeadlineSeconds"] = json!(900);
    spec["securityContext"]["fsGroup"] = json!(10001);
    for volume in spec["volumes"]
        .as_array_mut()
        .context("runtime_pair_volumes_required")?
    {
        if volume["name"] == "state" {
            *volume = json!({"name":"state","emptyDir":{"sizeLimit":scratch.to_string()}});
        }
    }
    let container = &mut spec["containers"][0];
    container["resources"]["requests"]["ephemeral-storage"] = json!(scratch.to_string());
    container["resources"]["limits"]["ephemeral-storage"] = json!(scratch.to_string());
    container["args"][2] = json!("--runtime-candidate-check");
    for field in [
        "readinessProbe",
        "livenessProbe",
        "startupProbe",
        "lifecycle",
    ] {
        container.as_object_mut().unwrap().remove(field);
    }
    for mount in container["volumeMounts"]
        .as_array_mut()
        .context("runtime_pair_mounts_required")?
    {
        if mount["name"] == "state" {
            mount["subPath"] = json!("state");
        }
    }
    spec["initContainers"] = json!([{"name":"checkpoint","image":request.tooling_image,
        "command":[DAY2,"runtime-pair-rehearsal-wait","/rehearsal"],
        "securityContext":{"runAsUser":10001,"runAsGroup":10001,"runAsNonRoot":true,
            "allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}},
        "resources":{"requests":{"cpu":"100m","memory":"128Mi","ephemeral-storage":scratch.to_string()},
            "limits":{"cpu":"1","memory":"512Mi","ephemeral-storage":scratch.to_string()}},
        "volumeMounts":[{"name":"state","mountPath":"/rehearsal"}]}]);
    Ok(
        json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":name,"namespace":request.namespace,
        "labels":value["metadata"]["labels"]},"spec":value["spec"]}),
    )
}

pub(super) fn helper_labels(request: &Request) -> Value {
    let mut labels =
        json!({"app.kubernetes.io/name":"day2-maintenance","app.kubernetes.io/part-of":"day2"});
    labels[&request.pod_label.key] = json!(request.pod_label.value);
    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn request() -> Request {
        serde_json::from_value(json!({"namespace":"app-pair","statefulset":"day2-app","configmap":"instance",
            "app":"app","pvc":"app-state","app_image":format!("registry/app@{}",day2::digest(b"source")),
            "artifact_id":"a".repeat(64),"tooling_image":format!("registry/tooling@{}",day2::digest(b"tooling")),
            "operator":"operator@example.com","pod_label":{"key":"day2.dev/service","value":"background"},
            "request_id":"pair-one","target":{"app_image":format!("registry/app@{}",day2::digest(b"target")),
                "artifact_id":"a".repeat(64),"instance":"target.json"},
            "placement":{"controller_uid":"controller-one","pvc_uid":"pvc-one","node":"node-one"}})).unwrap()
    }

    pub(super) fn source(request: &Request) -> Value {
        json!({"metadata":{"labels":{"app.kubernetes.io/name":"day2-app","pod-template-hash":"old"},"annotations":{}},
            "spec":{"automountServiceAccountToken":false,"containers":[{"name":"day2","image":request.app_image,
                "command":[SERVE],"args":["/srv/day2/instance.json","app","--edge"],"env":[],
                "securityContext":{"readOnlyRootFilesystem":true,"allowPrivilegeEscalation":false},
                "resources":{"requests":{"cpu":"1","memory":"512Mi"},"limits":{"cpu":"1","memory":"512Mi"}},
                "volumeMounts":[{"name":"instance","mountPath":"/srv/day2/instance.json","subPath":"instance.json","readOnly":true},
                    {"name":"state","mountPath":"/srv/day2/.state"},{"name":"tmp","mountPath":"/tmp"}]}],
                "volumes":[{"name":"state","persistentVolumeClaim":{"claimName":"app-state"}},
                    {"name":"instance","configMap":{"name":"instance"}},{"name":"tmp","emptyDir":{}}]}})
    }

    #[test]
    fn scheduler_constraints_survive_every_or_term_and_checkpoint_has_no_live_claim() -> Result<()>
    {
        let request = request();
        let mut source = source(&request);
        source["spec"]["affinity"] = json!({"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[
            {"matchExpressions":[{"key":"zone","operator":"In","values":["a"]}]},
            {"matchExpressions":[{"key":"zone","operator":"In","values":["b"]}]}]}}});
        let target = candidate(&request, &source, "{}")?;
        let terms=target["spec"]["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"].as_array().unwrap();
        assert_eq!(terms.len(), 2);
        for term in terms {
            assert_eq!(term["matchExpressions"].as_array().unwrap().len(), 1);
            assert_eq!(term["matchFields"][0]["values"], json!(["node-one"]));
        }
        assert!(target["spec"]["nodeName"].is_null());
        assert!(target["metadata"]["labels"]["pod-template-hash"].is_null());
        let checkpoint = checkpoint_pod(&request, &target, "checkpoint", 2 << 30)?;
        assert!(
            checkpoint["spec"]["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|volume| volume["persistentVolumeClaim"].is_null())
        );
        assert_eq!(
            checkpoint["spec"]["containers"][0]["image"],
            request.target.as_ref().unwrap().app_image
        );
        assert_eq!(
            checkpoint["spec"]["containers"][0]["args"][2],
            "--runtime-candidate-check"
        );
        assert_eq!(
            checkpoint["spec"]["containers"][0]["resources"]["limits"]["ephemeral-storage"],
            (2_u64 << 30).to_string()
        );
        // A later pair replaces the immutable selection without rebuilding app
        // code or dropping the serving container's reviewed resource bounds.
        let mut next = request.clone();
        next.app_image = request.target.as_ref().unwrap().app_image.clone();
        next.request_id = Some("pair-two".into());
        let next_template = candidate(&next, &target, "{}")?;
        assert_eq!(
            next_template["spec"]["containers"][0]["resources"],
            source["spec"]["containers"][0]["resources"]
        );
        assert_eq!(
            next_template["spec"]["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|v| v["name"] == "runtime-pair")
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn a_sidecar_native_mount_or_scheduler_bypass_cannot_enter_the_initial_profile() {
        let request = request();
        let original = source(&request);
        let mut wrong = original.clone();
        wrong["spec"]["nodeName"] = json!("node-one");
        assert!(candidate(&request, &wrong, "{}").is_err());
        let mut wrong = original.clone();
        wrong["spec"]["containers"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":"sidecar"}));
        assert!(candidate(&request, &wrong, "{}").is_err());
        let mut wrong = original.clone();
        wrong["spec"]["volumes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":"native-enrollment"}));
        assert!(candidate(&request, &wrong, "{}").is_err());
        let mut wrong = original.clone();
        wrong["spec"]["initContainers"] = json!([{"name":"credential-registration"}]);
        assert!(candidate(&request, &wrong, "{}").is_err());
        let mut wrong = original;
        wrong["spec"]["hostPID"] = json!(true);
        assert!(candidate(&request, &wrong, "{}").is_err());
    }
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod model_tests;
