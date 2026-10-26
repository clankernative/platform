//! Closed native identity response checks. Parsed replies below are DATA;
//! authenticated transport, original acquisition and current native ownership
//! must be retained separately. These functions never construct a current proof.

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use day2_capabilities::{
    Digest, Name,
    security_epoch::{
        EpochIam, EpochProvider, EpochStore,
        bootstrap::{GkeClusterSelection, GkeRoleSelection, WorkloadKind},
    },
};
use serde_json::Value;

pub(super) struct ReviewedSubject {
    pub pod_name: String,
    pub pod_uid: String,
}

fn string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .context("epoch_identity_reply_field")
}

fn singleton<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    let values = value
        .get(key)
        .and_then(Value::as_array)
        .context("epoch_identity_bound_claim_missing")?;
    ensure!(values.len() == 1, "epoch_identity_bound_claim_ambiguous");
    values[0]
        .as_str()
        .context("epoch_identity_bound_claim_type")
}

fn decode(bytes: &[u8]) -> Result<Value> {
    ensure!(bytes.len() <= 65_536, "epoch_identity_reply_bound");
    let value: Value =
        crate::json::decode(bytes).map_err(|_| anyhow::anyhow!("epoch_identity_reply_shape"))?;
    ensure!(value.is_object(), "epoch_identity_reply_not_object");
    Ok(value)
}

pub(super) fn token_review(role: &GkeRoleSelection, bytes: &[u8]) -> Result<ReviewedSubject> {
    ensure!(bytes.len() <= 65_536, "epoch_identity_reply_bound");
    let value = decode(bytes)?;
    ensure!(
        string(&value, "/apiVersion")? == "authentication.k8s.io/v1"
            && string(&value, "/kind")? == "TokenReview",
        "epoch_identity_token_review_kind"
    );
    ensure!(
        value
            .pointer("/status/authenticated")
            .and_then(Value::as_bool)
            == Some(true)
            && value
                .pointer("/status/error")
                .is_none_or(|error| error.as_str() == Some("")),
        "epoch_identity_token_review_refused"
    );
    let audiences = value
        .pointer("/status/audiences")
        .and_then(Value::as_array)
        .context("epoch_identity_returned_audience_missing")?;
    ensure!(
        audiences.len() == 1 && audiences[0].as_str() == Some(&role.token_review_audience),
        "epoch_identity_returned_audience_mismatch"
    );
    let expected = format!(
        "system:serviceaccount:{}:{}",
        role.namespace.name, role.kubernetes_service_account.name
    );
    ensure!(
        string(&value, "/status/user/username")? == expected
            && string(&value, "/status/user/uid")? == role.kubernetes_service_account.uid,
        "epoch_identity_ksa_mismatch"
    );
    let extra = value
        .pointer("/status/user/extra")
        .context("epoch_identity_bound_claim_missing")?;
    let pod_name = singleton(extra, "authentication.kubernetes.io/pod-name")?;
    let pod_uid = singleton(extra, "authentication.kubernetes.io/pod-uid")?;
    ensure!(
        dns_name(pod_name) && identifier(pod_uid, 128),
        "epoch_identity_bound_pod_invalid"
    );
    // Node extras are deliberately unused: TokenReview does not verify them.
    Ok(ReviewedSubject {
        pod_name: pod_name.into(),
        pod_uid: pod_uid.into(),
    })
}

fn identifier(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && !value.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// The selected API endpoint must belong to the authenticated, current cluster
/// reply. This profile supports direct IP endpoints; DNS endpoint authentication
/// and CA handling require a separate supported profile.
pub(super) fn cluster(
    selection: &GkeClusterSelection,
    observed_ca: &[u8],
    bytes: &[u8],
) -> Result<()> {
    let value = decode(bytes)?;
    ensure!(
        string(&value, "/name")? == selection.name.as_str()
            && string(&value, "/location")? == selection.location.as_str()
            && string(&value, "/id")? == selection.uid
            && string(&value, "/status")? == "RUNNING",
        "epoch_identity_cluster_mismatch_or_inactive"
    );
    let origin = url::Url::parse(&selection.api_origin)?;
    ensure!(
        origin.scheme() == "https"
            && origin.path() == "/"
            && origin.port_or_known_default() == Some(443)
            && origin.username().is_empty()
            && origin.password().is_none()
            && origin.query().is_none()
            && origin.fragment().is_none(),
        "epoch_identity_cluster_origin"
    );
    let selected_ip = origin
        .host_str()
        .context("epoch_identity_cluster_origin")?
        .parse::<std::net::IpAddr>()
        .context("epoch_identity_cluster_ip_profile_required")?;
    let endpoints = [
        "/endpoint",
        "/controlPlaneEndpointsConfig/ipEndpointsConfig/privateEndpoint",
        "/controlPlaneEndpointsConfig/ipEndpointsConfig/publicEndpoint",
    ];
    ensure!(
        endpoints.iter().any(|pointer| value
            .pointer(pointer)
            .and_then(Value::as_str)
            .and_then(|endpoint| endpoint.parse::<std::net::IpAddr>().ok())
            == Some(selected_ip)),
        "epoch_identity_cluster_endpoint_mismatch"
    );
    let encoded = string(&value, "/masterAuth/clusterCaCertificate")?;
    ensure!(encoded.len() <= 65_536, "epoch_identity_cluster_ca_bound");
    let ca = STANDARD
        .decode(encoded)
        .map_err(|_| anyhow::anyhow!("epoch_identity_cluster_ca_shape"))?;
    ensure!(
        ca == observed_ca && !ca.is_empty() && Digest::new(&ca) == selection.certificate_authority,
        "epoch_identity_cluster_ca_mismatch"
    );
    Ok(())
}

fn live_object(
    value: &Value,
    api: &str,
    kind: &str,
    name: &str,
    uid: &str,
    namespace: Option<&str>,
) -> Result<()> {
    ensure!(
        string(value, "/apiVersion")? == api
            && string(value, "/kind")? == kind
            && string(value, "/metadata/name")? == name
            && string(value, "/metadata/uid")? == uid,
        "epoch_identity_object_mismatch"
    );
    ensure!(
        value
            .pointer("/metadata/deletionTimestamp")
            .is_none_or(Value::is_null),
        "epoch_identity_object_deleting"
    );
    if let Some(namespace) = namespace {
        ensure!(
            string(value, "/metadata/namespace")? == namespace,
            "epoch_identity_namespace_mismatch"
        );
    }
    Ok(())
}

pub(super) fn namespace(role: &GkeRoleSelection, bytes: &[u8]) -> Result<()> {
    let value = decode(bytes)?;
    live_object(
        &value,
        "v1",
        "Namespace",
        &role.namespace.name,
        &role.namespace.uid,
        None,
    )
}

pub(super) fn service_account(role: &GkeRoleSelection, bytes: &[u8]) -> Result<()> {
    let value = decode(bytes)?;
    live_object(
        &value,
        "v1",
        "ServiceAccount",
        &role.kubernetes_service_account.name,
        &role.kubernetes_service_account.uid,
        Some(&role.namespace.name),
    )
}

/// The exact current Pod supplies its controlling owner DATA. A Deployment
/// requires the current ReplicaSet object and the selected Deployment lineage.
pub(super) struct PodObservation {
    value: Value,
    owner: Value,
}

impl PodObservation {
    /// Move both DATA projections from the one bounded, checked reply. This
    /// neither supplies a runtime witness nor accepts an unchecked parsed body.
    pub(super) fn into_parts(self) -> (Value, Value) {
        (self.value, self.owner)
    }
}

pub(super) fn pod(
    role: &GkeRoleSelection,
    subject: &ReviewedSubject,
    bytes: &[u8],
) -> Result<PodObservation> {
    let value = decode(bytes)?;
    live_object(
        &value,
        "v1",
        "Pod",
        &subject.pod_name,
        &subject.pod_uid,
        Some(&role.namespace.name),
    )?;
    ensure!(
        string(&value, "/spec/serviceAccountName")? == role.kubernetes_service_account.name
            && string(&value, "/status/phase")? == "Running",
        "epoch_identity_pod_not_running_or_wrong_ksa"
    );
    let owner = controlling_owner(&value)?;
    Ok(PodObservation { value, owner })
}

fn controlling_owner(value: &Value) -> Result<Value> {
    let owners = value
        .pointer("/metadata/ownerReferences")
        .and_then(Value::as_array)
        .context("epoch_identity_owner_missing")?;
    ensure!(
        !owners.is_empty() && owners.len() <= 16,
        "epoch_identity_owner_bound"
    );
    let mut selected = owners
        .iter()
        .filter(|owner| owner.get("controller").and_then(Value::as_bool) == Some(true));
    let owner = selected
        .next()
        .context("epoch_identity_controller_missing")?;
    ensure!(
        selected.next().is_none(),
        "epoch_identity_controller_ambiguous"
    );
    ensure!(
        dns_name(string(owner, "/name")?) && identifier(string(owner, "/uid")?, 128),
        "epoch_identity_owner_invalid"
    );
    Ok(owner.clone())
}

pub(super) fn workload(
    role: &GkeRoleSelection,
    owner: &Value,
    replica_set: Option<&[u8]>,
    bytes: &[u8],
) -> Result<()> {
    let kind = match role.workload_kind {
        WorkloadKind::DeploymentV1 => "Deployment",
        WorkloadKind::StatefulSetV1 => "StatefulSet",
    };
    let selected_owner = match role.workload_kind {
        WorkloadKind::DeploymentV1 => {
            let replica = decode(replica_set.context("epoch_identity_replica_set_missing")?)?;
            ensure!(
                string(owner, "/apiVersion")? == "apps/v1"
                    && string(owner, "/kind")? == "ReplicaSet",
                "epoch_identity_replica_set_owner"
            );
            live_object(
                &replica,
                "apps/v1",
                "ReplicaSet",
                string(owner, "/name")?,
                string(owner, "/uid")?,
                Some(&role.namespace.name),
            )?;
            controlling_owner(&replica)?
        }
        WorkloadKind::StatefulSetV1 => {
            ensure!(
                replica_set.is_none(),
                "epoch_identity_unexpected_replica_set"
            );
            owner.clone()
        }
    };
    ensure!(
        string(&selected_owner, "/apiVersion")? == "apps/v1"
            && string(&selected_owner, "/kind")? == kind
            && string(&selected_owner, "/name")? == role.workload.name
            && string(&selected_owner, "/uid")? == role.workload.uid,
        "epoch_identity_workload_lineage_mismatch"
    );
    let value = decode(bytes)?;
    live_object(
        &value,
        "apps/v1",
        kind,
        &role.workload.name,
        &role.workload.uid,
        Some(&role.namespace.name),
    )?;
    ensure!(
        string(&value, "/spec/template/spec/serviceAccountName")?
            == role.kubernetes_service_account.name,
        "epoch_identity_workload_ksa_mismatch"
    );
    Ok(())
}

pub(super) fn google_service_account(
    selection: &EpochIam,
    project: &Name,
    bytes: &[u8],
) -> Result<()> {
    let value = decode(bytes)?;
    let EpochIam::GkeWorkloadIdentityV1 {
        service_account,
        service_account_uid,
    } = selection;
    ensure!(
        string(&value, "/projectId")? == project.as_str()
            && string(&value, "/email")? == service_account
            && string(&value, "/uniqueId")? == service_account_uid.as_str()
            && value
                .get("disabled")
                .is_none_or(|disabled| disabled.as_bool() == Some(false)),
        "epoch_identity_google_account_mismatch_or_disabled"
    );
    // Metadata equality alone is not an outbound token's authenticated subject.
    Ok(())
}

pub(super) fn project(selection: &EpochStore, bytes: &[u8]) -> Result<()> {
    let value = decode(bytes)?;
    let EpochProvider::FirestoreNativeV1 {
        project,
        project_number,
        ..
    } = &selection.provider;
    ensure!(
        string(&value, "/projectId")? == project.as_str()
            && string(&value, "/projectNumber")? == project_number.to_string()
            && string(&value, "/lifecycleState")? == "ACTIVE",
        "epoch_identity_project_mismatch_or_inactive"
    );
    Ok(())
}

pub(super) fn database(selection: &EpochStore, bytes: &[u8]) -> Result<()> {
    let value = decode(bytes)?;
    let EpochProvider::FirestoreNativeV1 {
        project,
        database,
        database_uid,
        ..
    } = &selection.provider;
    let expected = format!(
        "projects/{}/databases/{}",
        project.as_str(),
        database.as_str()
    );
    ensure!(
        string(&value, "/name")? == expected
            && string(&value, "/uid")? == database_uid
            && string(&value, "/type")? == "FIRESTORE_NATIVE",
        "epoch_identity_physical_database_mismatch"
    );
    Ok(())
}
