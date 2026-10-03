//! Read-only, explicitly scoped GKE observations. Kubernetes API convergence is
//! not physical process fencing, so this module cannot construct a drain receipt.
//! See https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/:
//! force-deleted Pod objects do not establish that their processes terminated.
use crate::{
    BindingRef,
    provider_evidence::DeploymentIncarnation,
    release::ReleaseTarget,
    release_execution::{ObservedServingBinding, ServingProbe},
};
use crate::{Digest, secrets::AccessTokenProvider};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::{Certificate, blocking::Client, header::AUTHORIZATION};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::sync::Arc;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    net::IpAddr,
    num::NonZeroU64,
    time::{Duration, Instant},
};
use url::Url;

const MAX_BYTES: usize = 512 * 1024;
const PAGE_SIZE: usize = 100;
const MAX_PAGES: usize = 3;
const MAX_NODES: usize = 16;
const MAX_REQUESTS: usize = 26;
const DEADLINE: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GkeTarget {
    pub project_number: NonZeroU64,
    pub location: String,
    pub cluster: String,
    pub namespace: String,
    pub deployment: String,
    pub deployment_uid: String,
    pub revision: String,
}

impl GkeTarget {
    pub fn validate(&self) -> Result<()> {
        for name in [&self.location, &self.cluster, &self.namespace] {
            dns_name(name, 63)?;
            ensure!(!name.contains('.'), "invalid_kubernetes_scope_label");
        }
        dns_name(&self.deployment, 253)?;
        opaque(&self.deployment_uid)?;
        ensure!(
            !self.revision.is_empty()
                && self.revision.len() <= 40
                && !self.revision.starts_with('0')
                && self.revision.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid_kubernetes_revision"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationOrigin {
    LiveGke,
    TransportFixture,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuiescenceBlocker {
    PhysicalFencingUnproven,
    ApiAbsenceNotProof,
    ControllerCanRecreate,
    ControllerObservationBehind,
    ControllerRevisionChanged,
    RunningContainers,
    WaitingContainers,
    TerminatingPods,
    RestartObserved,
    NodeUnreachable,
    NodeStateUnknown,
    UntrackedReplicaSetOwner,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhysicalQuiescence {
    Unproven,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerObservation {
    pub name: String,
    pub uid: String,
    pub resource_version: String,
    pub generation: u64,
    pub observed_generation: Option<u64>,
    pub revision: Option<String>,
    pub desired_replicas: u32,
    pub deleting: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PodObservation {
    pub name: String,
    pub uid: String,
    pub resource_version: String,
    pub replica_set_uid: String,
    pub node: Option<String>,
    pub phase: String,
    pub deleting: bool,
    pub running_containers: u32,
    pub waiting_containers: u32,
    pub terminated_containers: u32,
    pub restart_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeObservation {
    pub name: String,
    pub uid: Option<String>,
    pub resource_version: Option<String>,
    pub ready: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesObservation {
    pub format: u32,
    pub origin: ObservationOrigin,
    pub target: GkeTarget,
    pub cluster_uid: String,
    pub control_plane_version: String,
    pub cluster_ca: Digest,
    pub deployment: Option<ControllerObservation>,
    pub replica_sets: Vec<ControllerObservation>,
    pub pods: Vec<PodObservation>,
    pub nodes: Vec<NodeObservation>,
    pub replica_set_list_version: String,
    pub pod_list_version: String,
    pub physical_quiescence: PhysicalQuiescence,
    pub reasons: BTreeSet<QuiescenceBlocker>,
}

pub struct GkeKubernetesProbe<'a> {
    discovery: Url,
    fixture_kubernetes: Option<Url>,
    client: Client,
    tokens: &'a dyn AccessTokenProvider,
}

/// Host-owned mapping to the single SQLite StatefulSet. Its labels and loaded
/// artifact are checked against fresh authenticated Kubernetes observations.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GkeServingBinding {
    pub target: ReleaseTarget,
    pub project_number: NonZeroU64,
    pub location: String,
    pub cluster: String,
    pub namespace: String,
    pub workload: String,
    pub workload_email: String,
    pub deployment: BindingRef,
}

pub struct GkeServingProbe {
    bindings: BTreeMap<String, GkeServingBinding>,
    tokens: Arc<dyn AccessTokenProvider>,
}

impl GkeServingProbe {
    pub fn new(
        bindings: BTreeMap<String, GkeServingBinding>,
        tokens: Arc<dyn AccessTokenProvider>,
    ) -> Result<Self> {
        ensure!(
            !bindings.is_empty() && bindings.len() <= 32,
            "serving_binding_budget"
        );
        for (app, binding) in &bindings {
            ensure!(
                app == binding.target.app.as_str(),
                "serving_binding_app_changed"
            );
            for name in [
                &binding.location,
                &binding.cluster,
                &binding.namespace,
                &binding.workload,
            ] {
                dns_name(name, 63)?;
            }
            ensure!(
                binding.workload_email.ends_with(".iam.gserviceaccount.com"),
                "serving_workload_identity_invalid"
            );
        }
        Ok(Self { bindings, tokens })
    }
}

impl ServingProbe for GkeServingProbe {
    fn observe(&self, target: &ReleaseTarget) -> Result<ObservedServingBinding> {
        let binding = self
            .bindings
            .get(target.app.as_str())
            .ok_or_else(|| anyhow::anyhow!("serving_target_unbound"))?;
        ensure!(&binding.target == target, "serving_target_scope_changed");
        GkeKubernetesProbe::new(self.tokens.as_ref())?.inspect_serving(binding)
    }
}

impl<'a> GkeKubernetesProbe<'a> {
    pub fn new(tokens: &'a dyn AccessTokenProvider) -> Result<Self> {
        Ok(Self {
            discovery: Url::parse("https://container.googleapis.com/")?,
            fixture_kubernetes: None,
            client: client(None)?,
            tokens,
        })
    }

    /// Loopback HTTP protocol fixtures are permanently labeled non-cloud evidence.
    pub fn transport_fixture(
        discovery: &str,
        kubernetes: &str,
        tokens: &'a dyn AccessTokenProvider,
    ) -> Result<Self> {
        Ok(Self {
            discovery: loopback(discovery)?,
            fixture_kubernetes: Some(loopback(kubernetes)?),
            client: client(None)?,
            tokens,
        })
    }

    pub fn inspect_serving(&self, target: &GkeServingBinding) -> Result<ObservedServingBinding> {
        for name in [
            &target.location,
            &target.cluster,
            &target.namespace,
            &target.workload,
        ] {
            dns_name(name, 63)?;
        }
        let mut budget = Budget::new();
        let mut discovery = self.discovery.join(&format!(
            "v1/projects/{}/locations/{}/clusters/{}",
            target.project_number, target.location, target.cluster
        ))?;
        discovery.query_pairs_mut().append_pair(
            "fields",
            "name,id,location,status,currentMasterVersion,endpoint,masterAuth/clusterCaCertificate",
        );
        let cluster: Cluster = self
            .get(&self.client, discovery, &mut budget, false)?
            .context("gke_cluster_not_found")?;
        ensure!(
            cluster.name == target.cluster
                && cluster.location == target.location
                && cluster.status == "RUNNING",
            "gke_cluster_identity_or_state_mismatch"
        );
        let ca = STANDARD.decode(&cluster.master_auth.cluster_ca_certificate)?;
        ensure!(ca.len() <= 32_768, "gke_ca_budget");
        let (endpoint, kube) = if let Some(endpoint) = &self.fixture_kubernetes {
            (endpoint.clone(), client(None)?)
        } else {
            let ip: IpAddr = cluster.endpoint.parse()?;
            ensure!(
                !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast(),
                "invalid_gke_endpoint"
            );
            let host = match ip {
                IpAddr::V4(ip) => ip.to_string(),
                IpAddr::V6(ip) => format!("[{ip}]"),
            };
            (
                Url::parse(&format!("https://{host}/"))?,
                client(Some(Certificate::from_pem(&ca)?))?,
            )
        };
        let controller_url = endpoint.join(&format!(
            "apis/apps/v1/namespaces/{}/statefulsets/{}",
            target.namespace, target.workload
        ))?;
        let controller: serde_json::Value = self
            .get(&kube, controller_url.clone(), &mut budget, false)?
            .context("serving_controller_missing")?;
        let metadata: Metadata = serde_json::from_value(controller["metadata"].clone())?;
        metadata.validate(Some(&target.namespace))?;
        ensure!(
            controller["kind"] == "StatefulSet"
                && controller["apiVersion"] == "apps/v1"
                && metadata.name == target.workload
                && metadata.deletion_timestamp.is_none()
                && metadata.generation > 0,
            "serving_controller_changed"
        );
        ensure!(
            controller["spec"]["replicas"] == 1
                && controller["status"]["observedGeneration"].as_u64() == Some(metadata.generation)
                && controller["status"]["readyReplicas"] == 1
                && controller["status"]["updatedReplicas"] == 1
                && controller["status"]["currentRevision"]
                    == controller["status"]["updateRevision"]
                && controller["status"]["updateRevision"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty()),
            "serving_controller_not_ready"
        );
        let annotations = &controller["spec"]["template"]["metadata"]["annotations"];
        for (key, expected) in [
            ("day2.dev/installation", target.target.company.as_str()),
            ("day2.dev/environment", target.target.environment.as_str()),
            ("day2.dev/app", target.target.app.as_str()),
        ] {
            ensure!(
                annotations[key].as_str() == Some(expected),
                "serving_scope_changed"
            );
        }
        let artifact: Digest = annotations["day2.dev/artifact"]
            .as_str()
            .context("serving_artifact_missing")?
            .to_owned()
            .try_into()?;
        let account = controller["spec"]["template"]["spec"]["serviceAccountName"]
            .as_str()
            .context("serving_account_missing")?;
        dns_name(account, 63)?;
        let service_account: serde_json::Value = self
            .get(
                &kube,
                endpoint.join(&format!(
                    "api/v1/namespaces/{}/serviceaccounts/{account}",
                    target.namespace
                ))?,
                &mut budget,
                false,
            )?
            .context("serving_account_missing")?;
        let account_metadata: Metadata =
            serde_json::from_value(service_account["metadata"].clone())?;
        account_metadata.validate(Some(&target.namespace))?;
        ensure!(
            account_metadata.name == account
                && account_metadata.deletion_timestamp.is_none()
                && account_metadata
                    .annotations
                    .get("iam.gke.io/gcp-service-account")
                    == Some(&target.workload_email),
            "serving_workload_identity_changed"
        );
        let pod: serde_json::Value = self
            .get(
                &kube,
                endpoint.join(&format!(
                    "api/v1/namespaces/{}/pods/{}-0",
                    target.namespace, target.workload
                ))?,
                &mut budget,
                false,
            )?
            .context("serving_pod_missing")?;
        let pod_metadata: Metadata = serde_json::from_value(pod["metadata"].clone())?;
        pod_metadata.validate(Some(&target.namespace))?;
        let owner = pod_metadata
            .controller()?
            .context("serving_pod_owner_missing")?;
        ensure!(
            owner.kind == "StatefulSet"
                && owner.uid == metadata.uid
                && owner.name == metadata.name
                && pod_metadata.deletion_timestamp.is_none()
                && pod["metadata"]["labels"]["controller-revision-hash"]
                    == controller["status"]["updateRevision"]
                && pod["spec"]["serviceAccountName"].as_str() == Some(account)
                && pod["status"]["phase"] == "Running",
            "serving_pod_changed"
        );
        for key in [
            "day2.dev/installation",
            "day2.dev/environment",
            "day2.dev/app",
            "day2.dev/artifact",
        ] {
            ensure!(
                pod["metadata"]["annotations"][key] == annotations[key],
                "serving_pod_scope_changed"
            );
        }
        let containers = pod["spec"]["containers"]
            .as_array()
            .context("serving_container_missing")?;
        ensure!(containers.len() <= 8, "serving_container_budget");
        let runtime = containers
            .iter()
            .find(|container| container["name"] == "day2")
            .context("serving_container_missing")?;
        let image = runtime["image"].as_str().context("serving_image_missing")?;
        let intended = controller["spec"]["template"]["spec"]["containers"]
            .as_array()
            .context("serving_template_container_missing")?;
        ensure!(
            intended.len() <= 8
                && intended.iter().any(|container| container["name"] == "day2"
                    && container["image"].as_str() == Some(image)),
            "serving_image_differs_from_controller"
        );
        let (_, image_digest) = image
            .rsplit_once("@sha256:")
            .context("serving_image_not_immutable")?;
        ensure!(
            image_digest.len() == 64 && image_digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "serving_image_not_immutable"
        );
        ensure!(
            runtime["env"].as_array().is_some_and(|env| env
                .iter()
                .any(|value| value["name"] == "DAY2_EXPECTED_ARTIFACT"
                    && value["value"].as_str() == Some(artifact.as_str()))),
            "serving_artifact_not_enforced"
        );
        let statuses = pod["status"]["containerStatuses"]
            .as_array()
            .context("serving_container_status_missing")?;
        ensure!(statuses.len() <= 8, "serving_container_budget");
        let status = statuses
            .iter()
            .find(|status| status["name"] == "day2")
            .context("serving_container_status_missing")?;
        ensure!(
            status["ready"] == true
                && status["started"] == true
                && status["state"]["running"].is_object()
                && status["imageID"]
                    .as_str()
                    .is_some_and(|id| id.ends_with(&format!("@sha256:{image_digest}"))),
            "serving_container_not_ready"
        );
        let after: serde_json::Value = self
            .get(&kube, controller_url, &mut budget, false)?
            .context("serving_controller_missing")?;
        ensure!(
            after["metadata"]["uid"] == controller["metadata"]["uid"]
                && after["metadata"]["generation"] == controller["metadata"]["generation"]
                && after["status"] == controller["status"],
            "serving_controller_changed_during_probe"
        );
        Ok(ObservedServingBinding {
            target: target.target.clone(),
            artifact,
            deployment: target.deployment.clone(),
            incarnation: DeploymentIncarnation {
                controller: metadata.uid.try_into()?,
                generation: metadata.generation.to_string().try_into()?,
            },
        })
    }

    pub fn inspect(&self, target: &GkeTarget) -> Result<KubernetesObservation> {
        target.validate()?;
        let mut budget = Budget::new();
        let mut discovery = self.discovery.join(&format!(
            "v1/projects/{}/locations/{}/clusters/{}",
            target.project_number, target.location, target.cluster
        ))?;
        // A full Cluster response can contain legacy client credentials. Request
        // only the public CA and the minimum identity/endpoint projection.
        discovery.query_pairs_mut().append_pair(
            "fields",
            "name,id,location,status,currentMasterVersion,endpoint,masterAuth/clusterCaCertificate",
        );
        let cluster: Cluster = self
            .get(&self.client, discovery, &mut budget, false)?
            .ok_or_else(|| anyhow::anyhow!("gke_cluster_not_found"))?;
        ensure!(
            cluster.name == target.cluster
                && cluster.location == target.location
                && cluster.status == "RUNNING",
            "gke_cluster_identity_or_state_mismatch"
        );
        opaque(&cluster.id)?;
        opaque(&cluster.current_master_version)?;
        ensure!(
            cluster.master_auth.cluster_ca_certificate.len() <= 32_768,
            "gke_ca_budget"
        );
        let ca = STANDARD
            .decode(&cluster.master_auth.cluster_ca_certificate)
            .map_err(|_| anyhow::anyhow!("invalid_gke_cluster_ca"))?;
        let (endpoint, kube_client, origin) = if let Some(endpoint) = &self.fixture_kubernetes {
            (
                endpoint.clone(),
                client(None)?,
                ObservationOrigin::TransportFixture,
            )
        } else {
            let ip: IpAddr = cluster
                .endpoint
                .parse()
                .map_err(|_| anyhow::anyhow!("unsupported_gke_endpoint"))?;
            ensure!(
                !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast(),
                "invalid_gke_endpoint"
            );
            let host = match ip {
                IpAddr::V4(ip) => ip.to_string(),
                IpAddr::V6(ip) => format!("[{ip}]"),
            };
            let certificate = Certificate::from_pem(&ca)
                .map_err(|_| anyhow::anyhow!("invalid_gke_cluster_ca"))?;
            (
                Url::parse(&format!("https://{host}/"))?,
                client(Some(certificate))?,
                ObservationOrigin::LiveGke,
            )
        };
        let namespace = &target.namespace;
        let deployment_url = endpoint.join(&format!(
            "apis/apps/v1/namespaces/{namespace}/deployments/{}",
            target.deployment
        ))?;
        let deployment: Option<Controller> =
            self.get(&kube_client, deployment_url, &mut budget, true)?;
        if let Some(deployment) = &deployment {
            deployment.validate(namespace, "Deployment")?;
            ensure!(
                deployment.metadata.uid == target.deployment_uid
                    && deployment.metadata.name == target.deployment,
                "kubernetes_deployment_identity_changed"
            );
        }
        let (replica_sets, replica_set_list_version): (Vec<Controller>, _) = self.list(
            &kube_client,
            endpoint.join(&format!("apis/apps/v1/namespaces/{namespace}/replicasets"))?,
            &mut budget,
            "ReplicaSetList",
        )?;
        let mut owned = BTreeMap::new();
        let mut replica_names = BTreeMap::new();
        for replica in replica_sets {
            replica.validate(namespace, "ReplicaSet")?;
            if let Some(owner) = replica.metadata.controller()? {
                if owner.kind == "Deployment" && owner.name == target.deployment {
                    ensure!(
                        owner.uid == target.deployment_uid,
                        "kubernetes_owner_identity_changed"
                    );
                }
                if owner.kind == "Deployment" && owner.uid == target.deployment_uid {
                    ensure!(
                        owner.name == target.deployment,
                        "kubernetes_owner_name_mismatch"
                    );
                    ensure!(
                        replica_names
                            .insert(replica.metadata.name.clone(), replica.metadata.uid.clone())
                            .is_none(),
                        "duplicate_kubernetes_replica_set_name"
                    );
                    ensure!(
                        owned
                            .insert(replica.metadata.uid.clone(), replica.observation()?)
                            .is_none(),
                        "duplicate_kubernetes_replica_set_uid"
                    );
                }
            }
        }
        let (pods, pod_list_version): (Vec<Pod>, _) = self.list(
            &kube_client,
            endpoint.join(&format!("api/v1/namespaces/{namespace}/pods"))?,
            &mut budget,
            "PodList",
        )?;
        let mut reasons = BTreeSet::from([QuiescenceBlocker::PhysicalFencingUnproven]);
        let mut selected = Vec::new();
        let mut pod_ids = BTreeSet::new();
        let mut node_names = BTreeSet::new();
        for pod in pods {
            pod.metadata.validate(Some(namespace))?;
            ensure!(
                pod.kind == "Pod" && pod.api_version == "v1",
                "invalid_kubernetes_pod_kind"
            );
            ensure!(
                pod_ids.insert(pod.metadata.uid.clone()),
                "duplicate_kubernetes_pod_uid"
            );
            if let Some(owner) = pod.metadata.controller()? {
                if owner.kind != "ReplicaSet" {
                    continue;
                }
                if let Some(expected) = replica_names.get(&owner.name) {
                    ensure!(*expected == owner.uid, "kubernetes_pod_owner_uid_mismatch");
                }
                if !owned.contains_key(&owner.uid) {
                    reasons.insert(QuiescenceBlocker::UntrackedReplicaSetOwner);
                    continue;
                }
                ensure!(
                    owned[&owner.uid].name == owner.name,
                    "kubernetes_pod_owner_name_mismatch"
                );
                let observation = pod.observation(&owner.uid)?;
                if let Some(node) = &observation.node {
                    dns_name(node, 253)?;
                    node_names.insert(node.clone());
                }
                selected.push(observation);
            }
        }
        ensure!(node_names.len() <= MAX_NODES, "kubernetes_node_budget");
        let mut nodes = Vec::new();
        for name in node_names {
            let node: Option<Node> = self.get(
                &kube_client,
                endpoint.join(&format!("api/v1/nodes/{name}"))?,
                &mut budget,
                true,
            )?;
            let observation = if let Some(node) = node {
                node.metadata.validate(None)?;
                ensure!(
                    node.kind == "Node" && node.api_version == "v1" && node.metadata.name == name,
                    "kubernetes_node_identity_mismatch"
                );
                let ready = condition(&node.status.conditions, "Ready")?;
                NodeObservation {
                    name,
                    uid: Some(node.metadata.uid),
                    resource_version: Some(node.metadata.resource_version),
                    ready,
                }
            } else {
                NodeObservation {
                    name,
                    uid: None,
                    resource_version: None,
                    ready: None,
                }
            };
            nodes.push(observation);
        }
        let deployment = deployment.map(|value| value.observation()).transpose()?;
        let replica_sets: Vec<_> = owned.into_values().collect();
        classify(
            target,
            deployment.as_ref(),
            &replica_sets,
            &selected,
            &nodes,
            &mut reasons,
        );
        selected.sort_by(|left, right| left.uid.cmp(&right.uid));
        Ok(KubernetesObservation {
            format: 1,
            origin,
            target: target.clone(),
            cluster_uid: cluster.id,
            control_plane_version: cluster.current_master_version,
            cluster_ca: Digest::new(&ca),
            deployment,
            replica_sets,
            pods: selected,
            nodes,
            replica_set_list_version,
            pod_list_version,
            physical_quiescence: PhysicalQuiescence::Unproven,
            reasons,
        })
    }

    fn get<T: DeserializeOwned>(
        &self,
        client: &Client,
        url: Url,
        budget: &mut Budget,
        missing: bool,
    ) -> Result<Option<T>> {
        let timeout = budget.request()?;
        let token = self
            .tokens
            .access_token()
            .map_err(|_| anyhow::anyhow!("kubernetes_credentials_unavailable"))?;
        let header = token
            .authorization_header()
            .map_err(|_| anyhow::anyhow!("kubernetes_credentials_invalid"))?;
        let response = client
            .get(url)
            .header(AUTHORIZATION, header)
            .timeout(timeout)
            .send()
            .map_err(|_| anyhow::anyhow!("kubernetes_transport_failure"))?;
        if missing && response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure!(response.status().is_success(), "kubernetes_http_failure");
        let mut bytes = Vec::new();
        response
            .take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("kubernetes_response_failure"))?;
        ensure!(bytes.len() <= MAX_BYTES, "kubernetes_response_budget");
        day2::json::decode(&bytes)
            .map(Some)
            .map_err(|_| anyhow::anyhow!("invalid_kubernetes_response"))
    }

    fn list<T: DeserializeOwned>(
        &self,
        client: &Client,
        base: Url,
        budget: &mut Budget,
        kind: &str,
    ) -> Result<(Vec<T>, String)> {
        let mut items = Vec::new();
        let mut continuation = String::new();
        let mut seen = BTreeSet::new();
        let mut revision = None;
        for _ in 0..MAX_PAGES {
            let mut url = base.clone();
            url.query_pairs_mut()
                .append_pair("limit", &PAGE_SIZE.to_string());
            if !continuation.is_empty() {
                url.query_pairs_mut().append_pair("continue", &continuation);
            }
            let page: List<T> = self
                .get(client, url, budget, false)?
                .ok_or_else(|| anyhow::anyhow!("kubernetes_inventory_missing"))?;
            let version = if kind == "ReplicaSetList" {
                "apps/v1"
            } else {
                "v1"
            };
            ensure!(
                page.kind == kind && page.api_version == version && page.items.len() <= PAGE_SIZE,
                "kubernetes_inventory_page_mismatch"
            );
            opaque(&page.metadata.resource_version)?;
            if let Some(expected) = &revision {
                ensure!(
                    *expected == page.metadata.resource_version,
                    "kubernetes_inventory_snapshot_changed"
                );
            } else {
                revision = Some(page.metadata.resource_version.clone());
            }
            items.extend(page.items);
            continuation = page.metadata.continuation;
            if continuation.is_empty() {
                return Ok((items, page.metadata.resource_version));
            }
            ensure!(
                continuation.len() <= 4096
                    && !continuation.chars().any(char::is_control)
                    && seen.insert(continuation.clone()),
                "kubernetes_continuation_invalid"
            );
        }
        anyhow::bail!("kubernetes_inventory_page_budget")
    }
}

fn classify(
    target: &GkeTarget,
    deployment: Option<&ControllerObservation>,
    replicas: &[ControllerObservation],
    pods: &[PodObservation],
    nodes: &[NodeObservation],
    reasons: &mut BTreeSet<QuiescenceBlocker>,
) {
    if deployment.is_none() || pods.is_empty() {
        reasons.insert(QuiescenceBlocker::ApiAbsenceNotProof);
    }
    for controller in deployment.into_iter().chain(replicas) {
        // Even a controller presently scaled to zero is not an anti-recreation fence.
        reasons.insert(QuiescenceBlocker::ControllerCanRecreate);
        if controller
            .observed_generation
            .is_none_or(|generation| generation < controller.generation)
        {
            reasons.insert(QuiescenceBlocker::ControllerObservationBehind);
        }
    }
    if deployment.is_some_and(|value| value.revision.as_ref() != Some(&target.revision)) {
        reasons.insert(QuiescenceBlocker::ControllerRevisionChanged);
    }
    for pod in pods {
        if pod.running_containers > 0 || pod.phase == "Running" {
            reasons.insert(QuiescenceBlocker::RunningContainers);
        }
        if pod.waiting_containers > 0 || pod.phase == "Pending" {
            reasons.insert(QuiescenceBlocker::WaitingContainers);
        }
        if pod.deleting {
            reasons.insert(QuiescenceBlocker::TerminatingPods);
        }
        if pod.restart_count > 0 {
            reasons.insert(QuiescenceBlocker::RestartObserved);
        }
        if pod.node.is_none() || pod.phase == "Unknown" {
            reasons.insert(QuiescenceBlocker::NodeStateUnknown);
        }
    }
    for node in nodes {
        match node.ready {
            Some(true) => {}
            Some(false) => {
                reasons.insert(QuiescenceBlocker::NodeUnreachable);
            }
            None => {
                reasons.insert(QuiescenceBlocker::NodeStateUnknown);
            }
        }
    }
}

fn client(certificate: Option<Certificate>) -> Result<Client> {
    let mut builder = Client::builder()
        .no_proxy()
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5));
    if let Some(certificate) = certificate {
        builder = builder
            .tls_built_in_root_certs(false)
            .add_root_certificate(certificate);
    }
    builder
        .build()
        .map_err(|_| anyhow::anyhow!("kubernetes_client_initialization_failed"))
}
fn loopback(value: &str) -> Result<Url> {
    let url = Url::parse(value)?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    ensure!(
        url.scheme() == "http"
            && loopback
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "invalid_kubernetes_fixture_endpoint"
    );
    Ok(url)
}
fn dns_name(value: &str, max: usize) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= max
            && value.split('.').all(|part| !part.is_empty()
                && part.len() <= 63
                && part.as_bytes()[0].is_ascii_alphanumeric()
                && part.as_bytes()[part.len() - 1].is_ascii_alphanumeric()
                && part.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || byte == b'-')),
        "invalid_kubernetes_name"
    );
    Ok(())
}
fn opaque(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 256
            && value.bytes().all(|byte| byte.is_ascii_graphic()),
        "invalid_kubernetes_identity"
    );
    Ok(())
}
struct Budget {
    started: Instant,
    requests: usize,
}
impl Budget {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            requests: 0,
        }
    }
    fn request(&mut self) -> Result<Duration> {
        ensure!(self.requests < MAX_REQUESTS, "kubernetes_request_budget");
        self.requests += 1;
        let remaining = DEADLINE
            .checked_sub(self.started.elapsed())
            .ok_or_else(|| anyhow::anyhow!("kubernetes_probe_deadline"))?;
        ensure!(!remaining.is_zero(), "kubernetes_probe_deadline");
        Ok(remaining.min(Duration::from_secs(5)))
    }
}

// API projections intentionally ignore unrelated provider fields. The shared
// decoder still rejects duplicate keys, excessive depth and oversized JSON.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Cluster {
    name: String,
    id: String,
    location: String,
    status: String,
    current_master_version: String,
    endpoint: String,
    master_auth: MasterAuth,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MasterAuth {
    cluster_ca_certificate: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    name: String,
    uid: String,
    resource_version: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    deletion_timestamp: Option<String>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
    #[serde(default)]
    owner_references: Vec<Owner>,
}
impl Metadata {
    fn validate(&self, namespace: Option<&str>) -> Result<()> {
        dns_name(&self.name, 253)?;
        opaque(&self.uid)?;
        opaque(&self.resource_version)?;
        ensure!(
            self.namespace.as_deref() == namespace,
            "kubernetes_namespace_mismatch"
        );
        ensure!(self.owner_references.len() <= 16, "kubernetes_owner_budget");
        for owner in &self.owner_references {
            opaque(&owner.uid)?;
            dns_name(&owner.name, 253)?;
        }
        self.controller()?;
        Ok(())
    }
    fn controller(&self) -> Result<Option<&Owner>> {
        let mut owners = self
            .owner_references
            .iter()
            .filter(|owner| owner.controller);
        let owner = owners.next();
        ensure!(owners.next().is_none(), "ambiguous_kubernetes_controller");
        Ok(owner)
    }
}
#[derive(Deserialize)]
struct Owner {
    name: String,
    uid: String,
    kind: String,
    #[serde(default)]
    controller: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Controller {
    api_version: String,
    kind: String,
    metadata: Metadata,
    spec: ControllerSpec,
    #[serde(default)]
    status: ControllerStatus,
}
#[derive(Deserialize)]
struct ControllerSpec {
    replicas: u32,
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ControllerStatus {
    observed_generation: Option<u64>,
}
impl Controller {
    fn validate(&self, namespace: &str, kind: &str) -> Result<()> {
        ensure!(
            self.kind == kind && self.api_version == "apps/v1" && self.metadata.generation > 0,
            "invalid_kubernetes_controller_kind"
        );
        self.metadata.validate(Some(namespace))
    }
    fn observation(&self) -> Result<ControllerObservation> {
        let revision = self
            .metadata
            .annotations
            .get("deployment.kubernetes.io/revision")
            .cloned();
        if let Some(revision) = &revision {
            opaque(revision)?;
        }
        Ok(ControllerObservation {
            name: self.metadata.name.clone(),
            uid: self.metadata.uid.clone(),
            resource_version: self.metadata.resource_version.clone(),
            generation: self.metadata.generation,
            observed_generation: self.status.observed_generation,
            revision,
            desired_replicas: self.spec.replicas,
            deleting: self.metadata.deletion_timestamp.is_some(),
        })
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct List<T> {
    api_version: String,
    kind: String,
    metadata: ListMetadata,
    items: Vec<T>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListMetadata {
    resource_version: String,
    #[serde(default, rename = "continue")]
    continuation: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pod {
    api_version: String,
    kind: String,
    metadata: Metadata,
    spec: PodSpec,
    #[serde(default)]
    status: PodStatus,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodSpec {
    node_name: Option<String>,
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodStatus {
    #[serde(default)]
    phase: String,
    #[serde(default)]
    container_statuses: Vec<ContainerStatus>,
    #[serde(default)]
    init_container_statuses: Vec<ContainerStatus>,
    #[serde(default)]
    ephemeral_container_statuses: Vec<ContainerStatus>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContainerStatus {
    restart_count: u64,
    state: BTreeMap<String, serde_json::Value>,
}
impl Pod {
    fn observation(&self, owner: &str) -> Result<PodObservation> {
        ensure!(
            ["", "Pending", "Running", "Succeeded", "Failed", "Unknown"]
                .contains(&self.status.phase.as_str()),
            "invalid_kubernetes_pod_phase"
        );
        let mut result = PodObservation {
            name: self.metadata.name.clone(),
            uid: self.metadata.uid.clone(),
            resource_version: self.metadata.resource_version.clone(),
            replica_set_uid: owner.into(),
            node: self.spec.node_name.clone(),
            phase: self.status.phase.clone(),
            deleting: self.metadata.deletion_timestamp.is_some(),
            running_containers: 0,
            waiting_containers: 0,
            terminated_containers: 0,
            restart_count: 0,
        };
        for status in self
            .status
            .container_statuses
            .iter()
            .chain(&self.status.init_container_statuses)
            .chain(&self.status.ephemeral_container_statuses)
        {
            ensure!(
                status.state.len() <= 1,
                "invalid_kubernetes_container_state"
            );
            for state in status.state.keys() {
                match state.as_str() {
                    "running" => result.running_containers += 1,
                    "waiting" => result.waiting_containers += 1,
                    "terminated" => result.terminated_containers += 1,
                    _ => anyhow::bail!("invalid_kubernetes_container_state"),
                }
            }
            result.restart_count = result
                .restart_count
                .checked_add(status.restart_count)
                .ok_or_else(|| anyhow::anyhow!("kubernetes_restart_budget"))?;
        }
        Ok(result)
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Node {
    api_version: String,
    kind: String,
    metadata: Metadata,
    status: NodeStatus,
}
#[derive(Deserialize)]
struct NodeStatus {
    conditions: Vec<Condition>,
}
#[derive(Deserialize)]
struct Condition {
    #[serde(rename = "type")]
    kind: String,
    status: String,
}
fn condition(conditions: &[Condition], kind: &str) -> Result<Option<bool>> {
    let mut matching = conditions.iter().filter(|condition| condition.kind == kind);
    let value = match matching.next().map(|condition| condition.status.as_str()) {
        Some("True") => Some(true),
        Some("False") => Some(false),
        Some("Unknown") | None => None,
        _ => anyhow::bail!("invalid_kubernetes_condition"),
    };
    ensure!(matching.next().is_none(), "duplicate_kubernetes_condition");
    Ok(value)
}
