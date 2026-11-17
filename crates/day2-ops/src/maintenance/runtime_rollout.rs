//! Native runtime-pair deployment/health adapter. Maintain.roc owns ordering;
//! these methods observe and enforce one fixed operation at a time. No app or
//! instance can supply executable commands or replace the provider port.
use super::*;
use day2::rollout::{Phase, Release, ReleaseKind};
use day2::runtime_pair::{
    AdoptionObservation, DrainObservation, ExecutorRole, HandoffBinding, HandoffStage,
    HealthObservation, Selection,
};
use std::{path::PathBuf, time::Duration};
mod controller;
mod operations;
mod provider;
mod resources;

#[derive(Default)]
pub(super) struct Progress {
    pub(super) stale_helpers: Vec<Value>,
    pub temporary_pods: Vec<String>,
    rehearsal: Option<String>,
    rehearsal_checked: bool,
    blueprint: Option<Value>,
    drain: Option<DrainObservation>,
    backup_selected: bool,
}

impl Progress {
    pub(super) fn with_stale(stale_helpers: Vec<Value>) -> Self {
        Self {
            stale_helpers,
            ..Self::default()
        }
    }
}

const SERVE: &str = "/usr/local/bin/day2-serve";
const HEALTH: &str = "/usr/local/bin/day2-health";
const PAIR_ROOT: &str = "/run/day2-pair";
const EVIDENCE: &str = "/tmp/day2-runtime-pair";

fn stage(release: &Release) -> Result<Option<&day2::runtime_pair::Handoff>> {
    match &release.kind {
        ReleaseKind::RuntimePair {
            execution: day2::runtime_pair::Execution::Admitted { handoff, .. },
            ..
        } => Ok(handoff.as_deref()),
        ReleaseKind::RuntimePair { .. } => Ok(None),
        _ => bail!("runtime_pair_release_required"),
    }
}

fn selection_name(request: &Request) -> Result<String> {
    Ok(format!("day2-pair-{}-selection", suffix(request)?))
}

fn target_name(request: &Request) -> Result<String> {
    Ok(format!("day2-pair-{}-target", suffix(request)?))
}

/// Cleanup is restricted to this request's disposable checkpoint or headless
/// Source executor. This capability can never select a public Pod or a PVC.
pub(super) fn remove_pod(
    cluster: &mut dyn Cluster,
    request: &Request,
    name: &str,
    digest: &str,
    expected_uid: Option<&str>,
) -> Result<()> {
    ensure!(dns_label(name), "runtime_pair_cleanup_name_invalid");
    let invoke = |cluster: &mut dyn Cluster, args: &[&str], stdin: Option<&[u8]>| {
        let mut full = vec!["-n".to_owned(), request.namespace.clone()];
        full.extend(args.iter().map(|arg| (*arg).to_owned()));
        cluster.kubectl(&full, stdin, Duration::from_secs(330))
    };
    let raw = invoke(
        cluster,
        &["get", "pod", name, "--ignore-not-found", "-o", "json"],
        None,
    )?;
    if raw.trim().is_empty() {
        return Ok(());
    }
    let pod = provider::decode(&raw)?;
    let identity = provider::resource(&pod)?;
    let checkpoint = name.starts_with(&format!("day2-pair-{}-check-", suffix(request)?))
        && pod["spec"]["containers"][0]["image"]
            == request.target.as_ref().context("target")?.app_image
        && pod["spec"]["containers"][0]["args"]
            == json!([
                "/srv/day2/instance.json",
                request.app,
                "--runtime-candidate-check",
                format!("{PAIR_ROOT}/candidate.json"),
                EVIDENCE
            ])
        && pod["spec"]["volumes"].as_array().is_some_and(|volumes| {
            volumes
                .iter()
                .all(|volume| volume["persistentVolumeClaim"].is_null())
        });
    ensure!(
        identity.name == name
            && expected_uid.is_none_or(|uid| identity.uid == uid)
            && pod["metadata"]["annotations"]["day2.dev/rollout-request"] == digest
            && pod["metadata"]["labels"] == resources::helper_labels(request)
            && (checkpoint || owned_recovery(&pod, request, digest)),
        "runtime_pair_cleanup_identity_changed"
    );
    let path = format!("/api/v1/namespaces/{}/pods/{name}", request.namespace);
    invoke(
        cluster,
        &["delete", "--raw", &path, "-f", "-"],
        Some(&serde_json::to_vec(
            &json!({"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":identity.uid}}),
        )?),
    )?;
    invoke(
        cluster,
        &[
            "wait",
            "--for=delete",
            &format!("pod/{name}"),
            "--timeout=300s",
        ],
        None,
    )?;
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePairRequest {
    pub receipt: PathBuf,
    pub receipt_digest: String,
    pub source_composition: day2::runtime_pair::Composition,
    pub target_composition: day2::runtime_pair::Composition,
    pub project: String,
    pub backend_service: String,
    pub service: String,
}

impl RuntimePairRequest {
    pub(super) fn validate(&self) -> Result<()> {
        self.source_composition.validate()?;
        self.target_composition.validate()?;
        ensure!(
            dns_label(&self.project)
                && dns_label(&self.backend_service)
                && dns_label(&self.service),
            "runtime_pair_backend_selection_invalid"
        );
        hex64(
            self.receipt_digest
                .strip_prefix("sha256:")
                .context("runtime_pair_receipt_digest_invalid")?,
            "runtime_pair_receipt_digest",
        )?;
        ensure!(
            !self.receipt.as_os_str().is_empty(),
            "runtime_pair_receipt_file_required"
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum BackendRead {
    Service { name: String },
    Health { name: String },
    HealthCheck { name: String },
    Neg { name: String, zone: String },
    Endpoints { name: String, zone: String },
}

pub(super) fn owned_recovery(pod: &Value, request: &Request, digest: &str) -> bool {
    let Ok(suffix) = suffix(request) else {
        return false;
    };
    pod["metadata"]["name"] == format!("day2-pair-{suffix}-source")
        && pod["metadata"]["annotations"]["day2.dev/rollout-request"] == digest
        && pod["metadata"]["ownerReferences"]
            .as_array()
            .is_some_and(|refs| {
                refs.len() == 1
                    && refs[0]["kind"] == "ConfigMap"
                    && refs[0]["controller"] == true
                    && refs[0]["name"] == format!("day2-pair-{suffix}-selection")
                    && refs[0]["uid"].as_str().is_some_and(|uid| !uid.is_empty())
            })
        && pod["spec"]["containers"]
            .as_array()
            .is_some_and(|containers| {
                containers.len() == 1
                    && containers[0]["name"] == "day2"
                    && containers[0]["image"] == request.app_image
                    && containers[0]["command"] == json!([SERVE])
                    && containers[0]["args"]
                        == json!([
                            "/srv/day2/instance.json",
                            request.app,
                            "--runtime-source-executor",
                            format!("{PAIR_ROOT}/source.json"),
                            "1000"
                        ])
            })
        && pod["spec"]["nodeName"].as_str()
            == request
                .placement
                .as_ref()
                .map(|placement| placement.node.as_str())
        && pod["metadata"]["labels"] == resources::helper_labels(request)
}

fn suffix(request: &Request) -> Result<String> {
    let id = request
        .request_id
        .as_deref()
        .context("runtime_pair_request_id_required")?;
    Ok(day2::digest(id.as_bytes())[7..23].to_owned())
}

pub(super) fn owned_candidate(replica: &Value, request: &Request, digest: &str) -> bool {
    let Ok(suffix) = suffix(request) else {
        return false;
    };
    let Some(target) = &request.target else {
        return false;
    };
    replica["metadata"]["name"] == format!("day2-pair-{suffix}-target")
        && replica["metadata"]["annotations"]["day2.dev/rollout-request"] == digest
        && replica["metadata"]["ownerReferences"]
            .as_array()
            .is_some_and(|owners| {
                owners.iter().any(|owner| {
                    owner["controller"] == true
                        && owner["kind"] == "ConfigMap"
                        && owner["name"] == format!("day2-pair-{suffix}-selection")
                        && owner["uid"].as_str().is_some_and(|uid| !uid.is_empty())
                })
            })
        && replica["spec"]["template"]["metadata"]["labels"]["day2.dev/runtime-pair"] == suffix
        && replica["spec"]["template"]["spec"]["containers"]
            .as_array()
            .is_some_and(|containers| {
                containers.iter().any(|container| {
                    container["name"] == "day2" && container["image"] == target.app_image
                })
            })
}

// Synthetic adapter DATA only; shared by port fixtures, never qualification.
#[cfg(test)]
pub(super) fn fixture_composition(image: &str, artifact: &str) -> day2::runtime_pair::Composition {
    day2::runtime_pair::Composition {
        version: 1,
        base_image: format!("registry/runtime@{}", day2::digest(b"base native")),
        base_native: day2::digest(b"base native"),
        base_config: day2::digest(b"base config"),
        base_manifest: day2::digest(b"base manifest"),
        image: image.into(),
        manifest: day2::digest(format!("manifest:{image}").as_bytes()),
        config: day2::digest(b"app config"),
        artifact: format!("sha256:{artifact}"),
        artifact_tree: day2::digest(b"tree"),
        layer: day2::digest(b"layer"),
        verifier: day2::digest(b"verifier"),
        recipe: day2::digest(b"recipe"),
    }
}
