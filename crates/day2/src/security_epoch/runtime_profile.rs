//! Closed selected-container/image DATA. Neither a Kubernetes response nor its
//! joins below bind the calling PID to the Pod or mint current runtime authority.
//! The actual native runtime witness/qualified issuer remains unavailable.

use super::identity_protocol::{self, ReviewedSubject};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{Digest, security_epoch::bootstrap::GkeRoleSelection};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ContainerSelection {
    pub name: String,
    pub image: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ContainerFacts {
    pub pod_name: String,
    pub pod_uid: String,
    pub node_name: String,
    pub container_name: String,
    pub container_id: String,
    pub image: Digest,
    pub restart_count: u64,
}

fn selected_digest(value: &str) -> Result<Digest> {
    ensure!(value.len() <= 1024, "epoch_native_image_bound");
    let (repository, hash) = value
        .rsplit_once("@sha256:")
        .context("epoch_native_image_not_digest_pinned")?;
    let repository = repository
        .strip_prefix("docker-pullable://")
        .unwrap_or(repository);
    ensure!(
        !repository.is_empty() && !repository.contains('@') && !repository.contains("://")
            && repository.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b,b'.'|b'/'|b':'|b'_'|b'-')),
        "epoch_native_image_repository"
    );
    ensure!(
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "epoch_native_image_digest"
    );
    format!("sha256:{hash}").try_into()
}

fn dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub(super) fn container(
    role: &GkeRoleSelection,
    reviewed: &ReviewedSubject,
    selected: &ContainerSelection,
    bytes: &[u8],
) -> Result<ContainerFacts> {
    ensure!(
        dns_label(&selected.name),
        "epoch_native_container_selection"
    );
    // Reuse actual response-shape/lifecycle/role/owner joins. This remains DATA:
    // authenticated transport and real runtime identity are separate owners.
    identity_protocol::pod(role, reviewed, bytes)?;
    let value: Value = crate::json::decode(bytes)?;
    let containers = value
        .pointer("/spec/containers")
        .and_then(Value::as_array)
        .context("epoch_native_container_list")?;
    let statuses = value
        .pointer("/status/containerStatuses")
        .and_then(Value::as_array)
        .context("epoch_native_container_status")?;
    ensure!(
        !containers.is_empty()
            && containers.len() <= 8
            && !statuses.is_empty()
            && statuses.len() <= 8,
        "epoch_native_container_count"
    );
    let matching = |items: &Vec<Value>| {
        items
            .iter()
            .filter(|v| v.get("name").and_then(Value::as_str) == Some(selected.name.as_str()))
            .cloned()
            .collect::<Vec<_>>()
    };
    let configured = matching(containers);
    let current = matching(statuses);
    ensure!(
        configured.len() == 1 && current.len() == 1,
        "epoch_native_container_ambiguous"
    );
    let configured = &configured[0];
    let current = &current[0];
    let image = configured
        .get("image")
        .and_then(Value::as_str)
        .context("epoch_native_container_image")?;
    let image_id = current
        .get("imageID")
        .and_then(Value::as_str)
        .context("epoch_native_container_image")?;
    ensure!(
        selected_digest(image)? == selected.image && selected_digest(image_id)? == selected.image,
        "epoch_native_container_image_mismatch"
    );
    // Startup/readiness may depend on bootstrap completion. Their values do
    // not identify this process or become preconditions for initial enrollment.
    ensure!(
        current.get("state").and_then(Value::as_object).is_some_and(
            |state| state.len() == 1 && state.get("running").is_some_and(Value::is_object)
        ),
        "epoch_native_container_not_running"
    );
    let container_id = current
        .get("containerID")
        .and_then(Value::as_str)
        .context("epoch_native_container_id")?;
    let id = container_id
        .strip_prefix("containerd://")
        .context("epoch_native_runtime_profile_unsupported")?;
    ensure!(
        id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "epoch_native_container_id"
    );
    let node_name = value
        .pointer("/spec/nodeName")
        .and_then(Value::as_str)
        .context("epoch_native_node_name")?;
    ensure!(
        node_name.len() <= 253 && node_name.split('.').all(dns_label),
        "epoch_native_node_name"
    );
    let restart_count = current
        .get("restartCount")
        .and_then(Value::as_u64)
        .context("epoch_native_restart_count")?;
    Ok(ContainerFacts {
        pod_name: reviewed.pod_name.clone(),
        pod_uid: reviewed.pod_uid.clone(),
        node_name: node_name.to_owned(),
        container_name: selected.name.clone(),
        container_id: container_id.to_owned(),
        image: selected.image.clone(),
        restart_count,
    })
}
