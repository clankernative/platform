//! Controlled identity response oracle; no live Kubernetes/Google role is minted.
use super::identity_protocol;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use day2_capabilities::{
    Digest,
    security_epoch::{
        EpochStore,
        bootstrap::{GkeClusterSelection, GkeRoleSelection, WorkloadKind},
    },
};
use serde_json::{Value, json};

fn role() -> GkeRoleSelection {
    serde_json::from_value(json!({
        "namespace":{"name":"native","uid":"namespace-uid"},
        "kubernetes_service_account":{"name":"controller","uid":"ksa-uid"},
        "google_service_account":{"kind":"gke_workload_identity_v1","service_account":"controller@project-seven.iam.gserviceaccount.com","service_account_uid":"100000000000000000007"},
        "workload_kind":"deployment_v1","workload":{"name":"controller","uid":"deployment-uid"},
        "token_review_audience":"https://native.example/subject"
    })).unwrap()
}

fn review() -> Value {
    json!({"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{
        "authenticated":true,"audiences":["https://native.example/subject"],
        "user":{"username":"system:serviceaccount:native:controller","uid":"ksa-uid","extra":{
            "authentication.kubernetes.io/pod-name":["controller-abc"],
            "authentication.kubernetes.io/pod-uid":["pod-uid"],
            "authentication.kubernetes.io/node-uid":["unvalidated-node-uid"]}}}})
}

fn object(kind: &str, name: &str, uid: &str, owner: Option<Value>) -> Value {
    let mut value = json!({"apiVersion":if matches!(kind,"Namespace"|"ServiceAccount"|"Pod") {"v1"} else {"apps/v1"},"kind":kind,
        "metadata":{"name":name,"uid":uid,"namespace":"native"},"spec":{"serviceAccountName":"controller","template":{"spec":{"serviceAccountName":"controller"}}},"status":{"phase":"Running"}});
    if let Some(owner) = owner {
        value["metadata"]["ownerReferences"] = json!([owner]);
    }
    value
}

fn owner(kind: &str, name: &str, uid: &str) -> Value {
    json!({"apiVersion":"apps/v1","kind":kind,"name":name,"uid":uid,"controller":true})
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

#[test]
fn explicit_returned_audience_and_current_bound_ksa_are_mandatory() {
    let role = role();
    let good = review();
    let subject = identity_protocol::token_review(&role, &bytes(&good)).unwrap();
    assert_eq!(subject.pod_uid, "pod-uid");
    for (pointer, value) in [
        ("/status/authenticated", json!(false)),
        ("/status/audiences", json!([])),
        ("/status/audiences", json!(["other"])),
        ("/status/user/uid", json!("recreated-ksa")),
        (
            "/status/user/username",
            json!("system:serviceaccount:other:controller"),
        ),
        (
            "/status/user/extra/authentication.kubernetes.io~1pod-uid",
            json!([]),
        ),
        (
            "/status/user/extra/authentication.kubernetes.io~1pod-uid",
            json!(["pod-uid", "other"]),
        ),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            identity_protocol::token_review(&role, &bytes(&bad)).is_err(),
            "{pointer}"
        );
    }
    let mut missing = good.clone();
    missing["status"]
        .as_object_mut()
        .unwrap()
        .remove("audiences");
    assert!(identity_protocol::token_review(&role, &bytes(&missing)).is_err());
    let mut node = good;
    node["status"]["user"]["extra"]["authentication.kubernetes.io/node-uid"] =
        json!(["changed-node"]);
    assert!(identity_protocol::token_review(&role, &bytes(&node)).is_ok());
    assert!(identity_protocol::token_review(&role,br#"{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","status":{"authenticated":true,"authenticated":false}}"#).is_err());
}

#[test]
fn deleting_or_replaced_objects_and_workload_lineage_refuse() {
    let role = role();
    let subject = identity_protocol::token_review(&role, &bytes(&review())).unwrap();
    let namespace = object("Namespace", "native", "namespace-uid", None);
    identity_protocol::namespace(&role, &bytes(&namespace)).unwrap();
    let mut deleted = namespace.clone();
    deleted["metadata"]["deletionTimestamp"] = json!("2026-10-14T00:00:00Z");
    assert!(identity_protocol::namespace(&role, &bytes(&deleted)).is_err());
    let mut replaced = namespace;
    replaced["metadata"]["uid"] = json!("replacement");
    assert!(identity_protocol::namespace(&role, &bytes(&replaced)).is_err());
    let pod = object(
        "Pod",
        "controller-abc",
        "pod-uid",
        Some(owner("ReplicaSet", "replica", "replica-uid")),
    );
    let selected = identity_protocol::pod(&role, &subject, &bytes(&pod)).unwrap();
    let replica = object(
        "ReplicaSet",
        "replica",
        "replica-uid",
        Some(owner("Deployment", "controller", "deployment-uid")),
    );
    let deployment = object("Deployment", "controller", "deployment-uid", None);
    identity_protocol::workload(
        &role,
        &selected,
        Some(&bytes(&replica)),
        &bytes(&deployment),
    )
    .unwrap();
    let mut wrong = replica;
    wrong["metadata"]["ownerReferences"][0]["uid"] = json!("recreated-deployment");
    assert!(
        identity_protocol::workload(&role, &selected, Some(&bytes(&wrong)), &bytes(&deployment))
            .is_err()
    );
    let mut dead = pod;
    dead["status"]["phase"] = json!("Succeeded");
    assert!(identity_protocol::pod(&role, &subject, &bytes(&dead)).is_err());
}

#[test]
fn google_metadata_checks_immutable_uid_instead_of_reused_email() {
    let role = role();
    let project = "project-seven".to_owned().try_into().unwrap();
    let good = json!({"projectId":"project-seven","email":"controller@project-seven.iam.gserviceaccount.com","uniqueId":"100000000000000000007","disabled":false});
    identity_protocol::google_service_account(
        &role.google_service_account,
        &project,
        &bytes(&good),
    )
    .unwrap();
    for (field, value) in [
        ("uniqueId", json!("100000000000000000008")),
        ("uniqueId", json!(7)),
        ("disabled", json!(true)),
        ("projectId", json!("other-project")),
    ] {
        let mut bad = good.clone();
        bad[field] = value;
        assert!(
            identity_protocol::google_service_account(
                &role.google_service_account,
                &project,
                &bytes(&bad)
            )
            .is_err()
        );
    }
}

#[test]
fn current_cluster_requires_uid_endpoint_ca_and_running_state() {
    let ca = b"controlled-ca-bytes";
    let selection:GkeClusterSelection=serde_json::from_value(json!({"project":"project-seven","location":"us-central1",
        "name":"native","uid":"cluster-uid","api_origin":"https://10.0.0.1:443","certificate_authority":Digest::new(ca)})).unwrap();
    let good = json!({"name":"native","location":"us-central1","id":"cluster-uid","status":"RUNNING",
        "endpoint":"10.0.0.1","masterAuth":{"clusterCaCertificate":STANDARD.encode(ca)}});
    identity_protocol::cluster(&selection, ca, &bytes(&good)).unwrap();
    for (pointer, value) in [
        ("/id", json!("recreated-cluster")),
        ("/status", json!("STOPPING")),
        ("/endpoint", json!("10.0.0.2")),
        ("/location", json!("other-location")),
        (
            "/masterAuth/clusterCaCertificate",
            json!(STANDARD.encode(b"other-ca")),
        ),
        ("/masterAuth/clusterCaCertificate", json!("%%%")),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            identity_protocol::cluster(&selection, ca, &bytes(&bad)).is_err(),
            "{pointer}"
        );
    }
    let mut private = good.clone();
    private["endpoint"] = json!("10.0.0.2");
    private["controlPlaneEndpointsConfig"] =
        json!({"ipEndpointsConfig":{"privateEndpoint":"10.0.0.1"}});
    identity_protocol::cluster(&selection, ca, &bytes(&private)).unwrap();
    let mut dns = selection;
    dns.api_origin = "https://uid.us-central1.gke.goog".into();
    assert!(identity_protocol::cluster(&dns, ca, &bytes(&good)).is_err());
}

#[test]
fn stateful_set_requires_one_current_controller_and_exact_service_account() {
    let mut role = role();
    role.workload_kind = WorkloadKind::StatefulSetV1;
    let subject = identity_protocol::token_review(&role, &bytes(&review())).unwrap();
    let pod = object(
        "Pod",
        "controller-abc",
        "pod-uid",
        Some(owner("StatefulSet", "controller", "deployment-uid")),
    );
    let selected = identity_protocol::pod(&role, &subject, &bytes(&pod)).unwrap();
    let workload = object("StatefulSet", "controller", "deployment-uid", None);
    identity_protocol::workload(&role, &selected, None, &bytes(&workload)).unwrap();
    let mut ambiguous = pod.clone();
    ambiguous["metadata"]["ownerReferences"] = json!([selected.clone(), selected.clone()]);
    assert!(identity_protocol::pod(&role, &subject, &bytes(&ambiguous)).is_err());
    let mut deleting = workload.clone();
    deleting["metadata"]["deletionTimestamp"] = json!("2026-10-14T00:00:00Z");
    assert!(identity_protocol::workload(&role, &selected, None, &bytes(&deleting)).is_err());
    let mut wrong = workload;
    wrong["spec"]["template"]["spec"]["serviceAccountName"] = json!("other");
    assert!(identity_protocol::workload(&role, &selected, None, &bytes(&wrong)).is_err());
    let mut invalid = review();
    invalid["status"]["user"]["extra"]["authentication.kubernetes.io/pod-name"] =
        json!(["../../other"]);
    assert!(identity_protocol::token_review(&role, &bytes(&invalid)).is_err());
}

#[test]
fn database_and_project_require_exact_physical_identity_and_native_type() {
    let selection:EpochStore=serde_json::from_value(json!({
        "scope":{"installation":"company","environment":"canary","app":"calendar"},
        "provider":{"kind":"firestore_native_v1","project":"project-seven","project_number":7,"database":"security",
            "database_uid":"01234567-89ab-4cde-8fab-0123456789ab","iam_source":role().google_service_account},
        "key_set":Digest::new(b"keys"),"max_lease_seconds":5})).unwrap();
    let database = json!({"name":"projects/project-seven/databases/security","uid":"01234567-89ab-4cde-8fab-0123456789ab","type":"FIRESTORE_NATIVE"});
    identity_protocol::database(&selection, &bytes(&database)).unwrap();
    for (field, value) in [
        ("uid", json!("recreated-database")),
        ("type", json!("DATASTORE_MODE")),
        ("name", json!("projects/project-seven/databases/other")),
    ] {
        let mut bad = database.clone();
        bad[field] = value;
        assert!(identity_protocol::database(&selection, &bytes(&bad)).is_err());
    }
    let project =
        json!({"projectId":"project-seven","projectNumber":"7","lifecycleState":"ACTIVE"});
    identity_protocol::project(&selection, &bytes(&project)).unwrap();
    for (field, value) in [
        ("projectNumber", json!(7)),
        ("projectNumber", json!("8")),
        ("lifecycleState", json!("DELETE_REQUESTED")),
    ] {
        let mut bad = project.clone();
        bad[field] = value;
        assert!(identity_protocol::project(&selection, &bytes(&bad)).is_err());
    }
    assert!(identity_protocol::database(&selection, b"[]").is_err());
    assert!(identity_protocol::database(&selection, &vec![b' '; 65_537]).is_err());
}
