//! Scoped releases of installed single-SQLite GKE workloads. Namespace, identity,
//! storage, IAP and key installation remain the infrastructure stack's inputs.
use crate::{
    BindingRef, Digest,
    journal::{Journal, RecoveryMode},
    kubernetes_conformance::{GkeKubernetesProbe, GkeServingBinding},
    provider_evidence::{DeploymentIncarnation, ReadBarrier, RevisionToken, StateEvidence},
    release::{ReleaseApproval, SecretObservation},
    release_execution::{
        Capabilities, ReleaseEffectResult, ReleaseExecutionPlan, ReleaseLease, ReleaseObservation,
        ReleaseObserved, ReleaseOperation,
    },
    secrets::{AccessTokenProvider, SecretVersion},
    serving_publication::Publication,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{Certificate, Method, StatusCode, blocking::Client};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{io::Read, net::IpAddr, path::PathBuf, sync::Arc, time::Duration};
use url::Url;

const MAX_BYTES: u64 = 1_048_576;
const EFFECT: &str = "day2.dev/release-effect";
const RELEASE: &str = "day2.dev/release-id";
const REVISION: &str = "day2.dev/selection-revision";
const SNAPSHOT: &str = "day2.dev/selection-digest";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub serving: GkeServingBinding,
    pub image: String,
    /// Admitted instance rendering, without private credential bytes.
    pub instance: Value,
    pub secret_projection: String,
    /// Exactly [workload, issuer], matching the CSI file paths of that name.
    pub secret_versions: Vec<SecretVersion>,
    pub serving_config_map: String,
}

fn dns(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 63
            && !value.starts_with('-')
            && !value.ends_with('-')
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "gke_release_invalid_name"
    );
    Ok(())
}

impl Deployment {
    pub fn validate(&self, artifact: &Digest) -> Result<()> {
        for name in [
            &self.serving.location,
            &self.serving.cluster,
            &self.serving.namespace,
            &self.serving.workload,
            &self.secret_projection,
            &self.serving_config_map,
        ] {
            dns(name)?;
        }
        let image: Vec<_> = self.image.split("@sha256:").collect();
        ensure!(
            image.len() == 2
                && !image[0].is_empty()
                && image[1].len() == 64
                && image[1].bytes().all(|b| b.is_ascii_hexdigit())
                && self.image.bytes().all(|b| b.is_ascii_graphic()),
            "gke_release_image_not_immutable"
        );
        let target = &self.serving.target;
        ensure!(
            self.instance["installation"].as_str() == Some(target.company.as_str())
                && self.instance["environment"].as_str() == Some(target.environment.as_str()),
            "gke_release_instance_scope_changed"
        );
        ensure!(
            self.instance["apps"][target.app.as_str()]["artifact"].as_str()
                == Some(&format!(
                    "artifacts/{}",
                    artifact.as_str().trim_start_matches("sha256:")
                )),
            "gke_release_instance_artifact_changed"
        );
        ensure!(self.secret_versions.len() == 2, "gke_release_secret_budget");
        let mut seen = std::collections::BTreeSet::new();
        for version in &self.secret_versions {
            version.validate()?;
            ensure!(
                version.project_number == self.serving.project_number.get()
                    && seen.insert(version.resource_name()),
                "gke_release_secret_scope_changed"
            );
        }
        let bytes = serde_json::to_vec(&self.instance)?;
        ensure!(bytes.len() <= 900_000, "gke_release_instance_budget");
        day2::artifact::Instance::from_bytes(&bytes)?;
        Ok(())
    }

    pub fn binding(&self, id: crate::Name) -> Result<BindingRef> {
        // Avoid a circular fingerprint: the serving mapping contains this binding.
        BindingRef::pin(
            id,
            &(
                "gke-sqlite-release-v1",
                &self.serving.target,
                self.serving.project_number,
                &self.serving.location,
                &self.serving.cluster,
                &self.serving.namespace,
                &self.serving.workload,
                &self.serving.workload_email,
                &self.secret_projection,
                &self.serving_config_map,
            ),
        )
    }
}

#[derive(Clone)]
struct Endpoints {
    discovery: Url,
    secrets: Url,
    fixture_kubernetes: Option<Url>,
}

fn client(ca: Option<&[u8]>) -> Result<Client> {
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(3));
    if let Some(ca) = ca {
        builder = builder.add_root_certificate(Certificate::from_pem(ca)?);
    }
    Ok(builder.build()?)
}

struct Api<'a> {
    client: Client,
    endpoint: Url,
    tokens: &'a dyn AccessTokenProvider,
}

impl Api<'_> {
    fn request(
        &self,
        method: Method,
        path: &str,
        value: Option<&Value>,
        patch: bool,
    ) -> Result<(StatusCode, Option<Value>)> {
        let header = self
            .tokens
            .access_token()
            .map_err(|_| anyhow::anyhow!("gke_release_credentials_unavailable"))?
            .authorization_header()?;
        let mut request = self
            .client
            .request(method, self.endpoint.join(path)?)
            .header(reqwest::header::AUTHORIZATION, header);
        if let Some(value) = value {
            let bytes = serde_json::to_vec(value)?;
            ensure!(
                bytes.len() as u64 <= MAX_BYTES,
                "gke_release_request_budget"
            );
            request = request
                .header(
                    reqwest::header::CONTENT_TYPE,
                    if patch {
                        "application/json-patch+json"
                    } else {
                        "application/json"
                    },
                )
                .body(bytes);
        }
        let response = request
            .send()
            .map_err(|_| anyhow::anyhow!("gke_release_transport_unknown"))?;
        let status = response.status();
        if !status.is_success() {
            return Ok((status, None));
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("gke_release_response_unknown"))?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "gke_release_response_budget"
        );
        Ok((
            status,
            Some(
                day2::json::decode(&bytes)
                    .map_err(|_| anyhow::anyhow!("gke_release_invalid_response"))?,
            ),
        ))
    }

    fn get(&self, path: &str) -> Result<Option<Value>> {
        let (status, value) = self.request(Method::GET, path, None, false)?;
        ensure!(
            status.is_success() || status == StatusCode::NOT_FOUND,
            "gke_release_read_rejected"
        );
        Ok(value)
    }
}

pub struct GkeReleaseProvider {
    journal: PathBuf,
    deployment: Deployment,
    tokens: Arc<dyn AccessTokenProvider>,
    endpoints: Endpoints,
}

impl GkeReleaseProvider {
    pub fn new(
        journal: PathBuf,
        deployment: Deployment,
        tokens: Arc<dyn AccessTokenProvider>,
    ) -> Result<Self> {
        Ok(Self {
            journal,
            deployment,
            tokens,
            endpoints: Endpoints {
                discovery: Url::parse("https://container.googleapis.com/")?,
                secrets: Url::parse("https://secretmanager.googleapis.com/")?,
                fixture_kubernetes: None,
            },
        })
    }

    /// Protocol fixtures use loopback only and cannot be selected by the live CLI.
    pub fn transport_fixture(
        journal: PathBuf,
        deployment: Deployment,
        tokens: Arc<dyn AccessTokenProvider>,
        discovery: &str,
        kubernetes: &str,
        secrets: &str,
    ) -> Result<Self> {
        fn endpoint(raw: &str) -> Result<Url> {
            let url = Url::parse(raw)?;
            ensure!(
                url.scheme() == "http"
                    && url.host_str().is_some_and(|host| host == "127.0.0.1"
                        || host == "[::1]"
                        || host == "localhost")
                    && url.path() == "/"
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "gke_release_fixture_not_loopback"
            );
            Ok(url)
        }
        Ok(Self {
            journal,
            deployment,
            tokens,
            endpoints: Endpoints {
                discovery: endpoint(discovery)?,
                secrets: endpoint(secrets)?,
                fixture_kubernetes: Some(endpoint(kubernetes)?),
            },
        })
    }

    fn api(&self) -> Result<Api<'_>> {
        let target = &self.deployment.serving;
        let discovery = Api {
            client: client(None)?,
            endpoint: self.endpoints.discovery.clone(),
            tokens: self.tokens.as_ref(),
        };
        let cluster = discovery
            .get(&format!(
                "v1/projects/{}/locations/{}/clusters/{}?fields=name,location,status,endpoint,masterAuth/clusterCaCertificate",
                target.project_number, target.location, target.cluster
            ))?
            .context("gke_release_cluster_missing")?;
        ensure!(
            cluster["name"] == target.cluster
                && cluster["location"] == target.location
                && cluster["status"] == "RUNNING",
            "gke_release_cluster_changed"
        );
        if let Some(endpoint) = &self.endpoints.fixture_kubernetes {
            return Ok(Api {
                client: client(None)?,
                endpoint: endpoint.clone(),
                tokens: self.tokens.as_ref(),
            });
        }
        let ip: IpAddr = cluster["endpoint"]
            .as_str()
            .context("gke_release_endpoint_missing")?
            .parse()?;
        ensure!(
            !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast(),
            "gke_release_endpoint_invalid"
        );
        let ca = STANDARD.decode(
            cluster["masterAuth"]["clusterCaCertificate"]
                .as_str()
                .context("gke_release_ca_missing")?,
        )?;
        ensure!(ca.len() <= 32768, "gke_release_ca_budget");
        let host = match ip {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };
        Ok(Api {
            client: client(Some(&ca))?,
            endpoint: Url::parse(&format!("https://{host}/"))?,
            tokens: self.tokens.as_ref(),
        })
    }

    fn controller_path(&self) -> String {
        format!(
            "apis/apps/v1/namespaces/{}/statefulsets/{}",
            self.deployment.serving.namespace, self.deployment.serving.workload
        )
    }

    fn controller(&self, api: &Api<'_>) -> Result<Value> {
        let controller = api
            .get(&self.controller_path())?
            .context("gke_release_workload_not_installed")?;
        ensure!(
            controller["apiVersion"] == "apps/v1"
                && controller["kind"] == "StatefulSet"
                && controller["metadata"]["name"] == self.deployment.serving.workload
                && controller["metadata"]["namespace"] == self.deployment.serving.namespace
                && controller["metadata"]["deletionTimestamp"].is_null(),
            "gke_release_controller_changed"
        );
        ensure!(
            controller["spec"]["replicas"] == 1
                && controller["spec"]["template"]["spec"]["serviceAccountName"] == "runtime"
                && controller["metadata"]["annotations"]["day2.dev/release-managed"] == "true",
            "gke_release_topology_changed"
        );
        for (key, expected) in [
            (
                "day2.dev/installation",
                self.deployment.serving.target.company.as_str(),
            ),
            (
                "day2.dev/environment",
                self.deployment.serving.target.environment.as_str(),
            ),
            ("day2.dev/app", self.deployment.serving.target.app.as_str()),
        ] {
            ensure!(
                controller["spec"]["template"]["metadata"]["annotations"][key].as_str()
                    == Some(expected),
                "gke_release_controller_scope_changed"
            );
        }
        incarnation(&controller)?;
        ensure!(
            controller["metadata"]["resourceVersion"]
                .as_str()
                .is_some_and(|v| !v.is_empty() && v.len() <= 256),
            "gke_release_resource_version_missing"
        );
        Ok(controller)
    }

    fn secret(&self, lease: &ReleaseLease) -> Result<SecretObservation> {
        let api = Api {
            client: client(None)?,
            endpoint: self.endpoints.secrets.clone(),
            tokens: self.tokens.as_ref(),
        };
        for version in &self.deployment.secret_versions {
            let name = version.resource_name();
            let value = api
                .get(&format!("v1/{name}:access"))?
                .context("gke_release_secret_unavailable")?;
            ensure!(value["name"] == name, "gke_release_secret_version_changed");
            let mut bytes = STANDARD
                .decode(
                    value["payload"]["data"]
                        .as_str()
                        .context("gke_release_secret_payload_missing")?,
                )
                .map_err(|_| anyhow::anyhow!("gke_release_secret_payload_invalid"))?;
            ensure!(
                !bytes.is_empty() && bytes.len() <= 65536,
                "gke_release_secret_payload_budget"
            );
            let checksum = value["payload"]["dataCrc32c"]
                .as_str()
                .context("gke_release_secret_checksum_missing")?
                .parse::<u32>()?;
            let valid = crc32c::crc32c(&bytes) == checksum;
            bytes.fill(0);
            ensure!(valid, "gke_release_secret_checksum_changed");
        }
        let reference = lease.approval.secret.clone();
        let resource = Digest::of(&reference)?;
        let evidence = Digest::of(&(
            "gke-exact-secret-access-v1",
            &reference,
            &self.deployment.secret_versions,
        ))?;
        Ok(SecretObservation {
            reference: reference.clone(),
            provider_state: StateEvidence::Qualified {
                // Numeric versions are immutable. This token proves equality only;
                // failures never synthesize an ordered disable/permission observation.
                revision: RevisionToken::Opaque {
                    token: resource.as_str().to_owned().try_into()?,
                },
                barrier: ReadBarrier {
                    authority: reference.binding,
                    resource,
                    after_effect: None,
                    receipt: evidence.clone(),
                },
            },
            evidence,
            enabled: true,
            access_granted: true,
            projection_ready: true,
        })
    }

    fn projection(&self, api: &Api<'_>) -> Result<()> {
        let namespace = &self.deployment.serving.namespace;
        let projection = api.get(&format!("apis/secrets-store.csi.x-k8s.io/v1/namespaces/{namespace}/secretproviderclasses/{}", self.deployment.secret_projection))?.context("gke_release_projection_missing")?;
        ensure!(
            projection["spec"]["provider"] == "gke",
            "gke_release_projection_changed"
        );
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Projected {
            resource_name: String,
            path: String,
        }
        let projected: Vec<Projected> = serde_yaml::from_str(
            projection["spec"]["parameters"]["secrets"]
                .as_str()
                .context("gke_release_projection_invalid")?,
        )
        .map_err(|_| anyhow::anyhow!("gke_release_projection_invalid"))?;
        let mut names = std::collections::BTreeMap::new();
        let mut paths = std::collections::BTreeSet::new();
        for value in &projected {
            ensure!(
                matches!(value.path.as_str(), "workload" | "issuer")
                    && paths.insert(value.path.clone())
                    && names
                        .insert(value.path.clone(), value.resource_name.clone())
                        .is_none(),
                "gke_release_projection_changed"
            );
        }
        ensure!(
            projected.len() == 2
                && names
                    == std::collections::BTreeMap::from([
                        (
                            "workload".to_owned(),
                            self.deployment.secret_versions[0].resource_name()
                        ),
                        (
                            "issuer".to_owned(),
                            self.deployment.secret_versions[1].resource_name()
                        ),
                    ]),
            "gke_release_projection_versions_changed"
        );
        Ok(())
    }

    fn instance_name(&self, lease: &ReleaseLease) -> String {
        format!(
            "day2-release-{}",
            &lease
                .execution
                .plan
                .release
                .as_str()
                .trim_start_matches("sha256:")[..32]
        )
    }

    fn instance(&self, api: &Api<'_>, lease: &ReleaseLease) -> Result<()> {
        let name = self.instance_name(lease);
        let collection = format!(
            "api/v1/namespaces/{}/configmaps",
            self.deployment.serving.namespace
        );
        let path = format!("{collection}/{name}");
        let data = json!({"instance.json": serde_json::to_string(&self.deployment.instance)?});
        let desired = json!({"apiVersion":"v1", "kind":"ConfigMap", "metadata":{"name":name,"namespace":self.deployment.serving.namespace,"annotations":{RELEASE:lease.execution.plan.release}},"immutable":true,"data":data});
        if api.get(&path)?.is_none() {
            let (status, _) = api.request(Method::POST, &collection, Some(&desired), false)?;
            ensure!(
                status.is_success() || status == StatusCode::CONFLICT,
                "gke_release_instance_create_unknown"
            );
        }
        let actual = api
            .get(&path)?
            .context("gke_release_instance_readback_missing")?;
        ensure!(
            actual["immutable"] == true
                && actual["data"] == data
                && actual["metadata"]["annotations"][RELEASE]
                    == lease.execution.plan.release.as_str(),
            "gke_release_instance_conflict"
        );
        Ok(())
    }

    fn template(&self, controller: &Value, lease: &ReleaseLease) -> Result<Value> {
        let mut template = controller["spec"]["template"].clone();
        let annotations = template["metadata"]["annotations"]
            .as_object_mut()
            .context("gke_release_annotations_missing")?;
        annotations.insert("day2.dev/artifact".into(), json!(lease.approval.artifact));
        annotations.insert(
            "day2.dev/instance-sha256".into(),
            json!(
                day2::digest(serde_json::to_string(&self.deployment.instance)?.as_bytes())
                    .trim_start_matches("sha256:")
            ),
        );
        annotations.insert(RELEASE.into(), json!(lease.execution.plan.release));
        let containers = template["spec"]["containers"]
            .as_array_mut()
            .context("gke_release_container_missing")?;
        ensure!(containers.len() == 1, "gke_release_container_budget");
        let runtime = &mut containers[0];
        ensure!(runtime["name"] == "day2", "gke_release_container_changed");
        runtime["image"] = json!(self.deployment.image);
        let env = runtime["env"]
            .as_array_mut()
            .context("gke_release_environment_missing")?;
        let expected = env
            .iter_mut()
            .find(|value| value["name"] == "DAY2_EXPECTED_ARTIFACT")
            .context("gke_release_artifact_guard_missing")?;
        *expected = json!({"name":"DAY2_EXPECTED_ARTIFACT","value":lease.approval.artifact});
        let volumes = template["spec"]["volumes"]
            .as_array_mut()
            .context("gke_release_volumes_missing")?;
        let instance = volumes
            .iter_mut()
            .find(|value| value["name"] == "instance")
            .context("gke_release_instance_mount_missing")?;
        instance["configMap"]["name"] = json!(self.instance_name(lease));
        ensure!(
            volumes.iter().any(
                |volume| volume["csi"]["driver"] == "secrets-store-gke.csi.k8s.io"
                    && volume["csi"]["volumeAttributes"]["secretProviderClass"]
                        == self.deployment.secret_projection
            ),
            "gke_release_projection_not_mounted"
        );
        Ok(template)
    }

    fn prepared(&self, api: &Api<'_>, lease: &ReleaseLease, controller: &Value) -> Result<bool> {
        Ok(
            controller["metadata"]["annotations"][EFFECT] == lease.effect.as_str()
                && controller["metadata"]["annotations"][RELEASE]
                    == lease.execution.plan.release.as_str()
                && controller["spec"]["template"] == self.template(controller, lease)?
                && api
                    .get(&format!(
                        "api/v1/namespaces/{}/configmaps/{}",
                        self.deployment.serving.namespace,
                        self.instance_name(lease)
                    ))?
                    .is_some_and(|cm| {
                        cm["immutable"] == true
                            && cm["data"]["instance.json"]
                                == serde_json::to_string(&self.deployment.instance)
                                    .unwrap_or_default()
                    }),
        )
    }

    fn ready(&self, lease: &ReleaseLease) -> Result<(DeploymentIncarnation, StateEvidence)> {
        let (prepared, incarnation) = Journal::open_readonly(&self.journal)?
            .prepared_release_deployment(&lease.execution.id)?
            .context("gke_release_preparation_missing")?;
        let api = self.api()?;
        let before = self.controller(&api)?;
        ensure!(
            before["metadata"]["annotations"][EFFECT] == prepared.effect.as_str()
                && before["metadata"]["annotations"][RELEASE]
                    == lease.execution.plan.release.as_str()
                && before["spec"]["template"] == self.template(&before, lease)?,
            "gke_release_preparation_changed"
        );
        self.secret(lease)?;
        self.projection(&api)?;
        let probe = if let Some(kubernetes) = &self.endpoints.fixture_kubernetes {
            GkeKubernetesProbe::transport_fixture(
                self.endpoints.discovery.as_str(),
                kubernetes.as_str(),
                self.tokens.as_ref(),
            )?
        } else {
            GkeKubernetesProbe::new(self.tokens.as_ref())?
        };
        let observed = probe.inspect_serving(&self.deployment.serving)?;
        ensure!(
            observed.artifact == lease.approval.artifact && observed.incarnation == incarnation,
            "gke_release_serving_changed"
        );
        let after = self.controller(&api)?;
        ensure!(
            before["metadata"]["uid"] == after["metadata"]["uid"]
                && before["metadata"]["generation"] == after["metadata"]["generation"]
                && before["spec"] == after["spec"]
                && before["metadata"]["annotations"] == after["metadata"]["annotations"],
            "gke_release_changed_during_readback"
        );
        let receipt = Digest::of(&("gke-deployment-readback-v1", &observed, &after))?;
        Ok((
            incarnation,
            StateEvidence::Qualified {
                revision: RevisionToken::Opaque {
                    token: after["metadata"]["resourceVersion"]
                        .as_str()
                        .context("gke_release_resource_version_missing")?
                        .to_owned()
                        .try_into()?,
                },
                barrier: ReadBarrier {
                    authority: prepared.binding,
                    resource: prepared.resource,
                    after_effect: Some(prepared.effect),
                    receipt,
                },
            },
        ))
    }

    /// Conditional per-destination writes plus a final durable acknowledgment.
    /// A crash after any destination leaves the activation intent retryable.
    pub fn publish(&self, publication: &Publication) -> Result<()> {
        publication.require_scope(&self.deployment.serving.target)?;
        publication
            .snapshot
            .require_scope(&self.deployment.serving.target)?;
        ensure!(
            Digest::of(&publication.snapshot)? == publication.digest,
            "gke_publication_digest_changed"
        );
        ensure!(
            Journal::open_readonly(&self.journal)?.serving_publication_is_current(publication)?,
            "gke_publication_superseded"
        );
        let api = self.api()?;
        let target = &self.deployment.serving.target;
        let collection = format!(
            "api/v1/namespaces/{}/configmaps",
            self.deployment.serving.namespace
        );
        let path = format!("{collection}/{}", self.deployment.serving_config_map);
        let existing = api.get(&path)?;
        let payload = serde_json::to_string(&publication.snapshot)?;
        if let Some(cm) = &existing {
            ensure!(
                cm["apiVersion"] == "v1"
                    && cm["kind"] == "ConfigMap"
                    && cm["metadata"]["name"] == self.deployment.serving_config_map
                    && cm["metadata"]["namespace"] == self.deployment.serving.namespace
                    && cm["metadata"]["deletionTimestamp"].is_null()
                    && cm["metadata"]["uid"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty())
                    && cm["metadata"]["resourceVersion"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty()),
                "gke_publication_destination_changed"
            );
            crate::serving_snapshot::ServingSnapshot::from_bytes(
                cm["data"]["serving.json"]
                    .as_str()
                    .context("gke_publication_destination_unowned")?
                    .as_bytes(),
            )?
            .require_scope(target)?;
            if let Some(revision) = cm["metadata"]["annotations"][REVISION].as_str() {
                let revision: u64 = revision.parse()?;
                ensure!(
                    revision <= publication.revision,
                    "gke_publication_superseded"
                );
                if revision == publication.revision {
                    ensure!(
                        cm["metadata"]["annotations"][SNAPSHOT] == publication.digest.as_str()
                            && cm["data"]["serving.json"] == payload,
                        "gke_publication_conflict"
                    );
                    return Ok(());
                }
            }
        }
        let mut desired = json!({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":self.deployment.serving_config_map,"namespace":self.deployment.serving.namespace,"annotations":{REVISION:publication.revision.to_string(), SNAPSHOT:publication.digest, "day2.dev/installation":target.company,"day2.dev/environment":target.environment}},"data":{"serving.json":payload}});
        let (method, endpoint) = if let Some(existing) = &existing {
            ensure!(
                existing["metadata"]["deletionTimestamp"].is_null(),
                "gke_publication_destination_deleting"
            );
            desired["metadata"]["resourceVersion"] =
                existing["metadata"]["resourceVersion"].clone();
            desired["metadata"]["uid"] = existing["metadata"]["uid"].clone();
            (Method::PUT, path.clone())
        } else {
            (Method::POST, collection)
        };
        let (status, _) = api.request(method, &endpoint, Some(&desired), false)?;
        ensure!(
            status.is_success(),
            "gke_publication_write_unknown_or_conflicted"
        );
        let actual = api
            .get(&path)?
            .context("gke_publication_readback_missing")?;
        ensure!(
            actual["data"] == desired["data"]
                && actual["metadata"]["annotations"] == desired["metadata"]["annotations"],
            "gke_publication_readback_changed"
        );
        Ok(())
    }
}

fn incarnation(controller: &Value) -> Result<DeploymentIncarnation> {
    let incarnation = DeploymentIncarnation {
        controller: controller["metadata"]["uid"]
            .as_str()
            .context("gke_release_uid_missing")?
            .to_owned()
            .try_into()?,
        generation: controller["metadata"]["generation"]
            .as_u64()
            .filter(|value| *value > 0)
            .context("gke_release_generation_missing")?
            .to_string()
            .try_into()?,
    };
    incarnation.validate()?;
    Ok(incarnation)
}

impl Capabilities for GkeReleaseProvider {
    fn validate(&self, plan: &ReleaseExecutionPlan, approval: &ReleaseApproval) -> Result<()> {
        self.deployment.validate(&approval.artifact)?;
        ensure!(
            approval.target == self.deployment.serving.target
                && plan.deployment == self.deployment.serving.deployment
                && plan.deployment_input == Some(Digest::of(&self.deployment)?)
                && plan.resources == approval.secret.binding,
            "gke_release_binding_changed"
        );
        ensure!(
            self.deployment
                .secret_versions
                .iter()
                .take(1)
                .any(|version| version.secret == approval.secret.secret.as_str()
                    && version.version == approval.secret.version.get()),
            "gke_release_approved_secret_not_projected"
        );
        Ok(())
    }

    fn perform(&self, lease: &ReleaseLease) -> Result<ReleaseEffectResult> {
        self.validate(&lease.execution.plan, &lease.approval)?;
        let api = self.api()?;
        let fact = lease.fact(Digest::of(&(
            "gke-release-provider-v1",
            &lease.execution.plan.deployment,
            &lease.effect,
        ))?)?;
        let outcome = match lease.step.operation {
            ReleaseOperation::PrepareDependency => {
                self.controller(&api)?;
                self.projection(&api)?;
                ReleaseObserved::DependencyPrepared {}
            }
            ReleaseOperation::ObserveSecret => {
                self.projection(&api)?;
                ReleaseObserved::Secret {
                    metadata: Some(self.secret(lease)?),
                }
            }
            ReleaseOperation::PrepareDeployment => {
                let controller = self.controller(&api)?;
                if !self.prepared(&api, lease, &controller)? {
                    if lease.recovery == RecoveryMode::Reconcile {
                        return Ok(ReleaseEffectResult::Ambiguous {});
                    }
                    self.secret(lease)?;
                    self.projection(&api)?;
                    self.instance(&api, lease)?;
                    let patch = json!([
                        {"op":"test","path":"/metadata/uid","value":controller["metadata"]["uid"]},
                        {"op":"test","path":"/metadata/resourceVersion","value":controller["metadata"]["resourceVersion"]},
                        {"op":"add","path":"/metadata/annotations/day2.dev~1release-effect","value":lease.effect},
                        {"op":"add","path":"/metadata/annotations/day2.dev~1release-id","value":lease.execution.plan.release},
                        {"op":"replace","path":"/spec/template","value":self.template(&controller, lease)?}
                    ]);
                    let write =
                        api.request(Method::PATCH, &self.controller_path(), Some(&patch), true);
                    match write {
                        Ok((status, _))
                            if status == StatusCode::CONFLICT
                                || status == StatusCode::UNPROCESSABLE_ENTITY
                                || status == StatusCode::TOO_MANY_REQUESTS =>
                        {
                            return Ok(ReleaseEffectResult::RetryNotApplied {});
                        }
                        Ok((status, _)) if status.is_success() => {}
                        _ => return Ok(ReleaseEffectResult::Ambiguous {}),
                    }
                }
                let actual = self.controller(&api)?;
                ensure!(
                    self.prepared(&api, lease, &actual)?,
                    "gke_release_prepare_readback_changed"
                );
                ReleaseObserved::DeploymentPrepared {
                    incarnation: incarnation(&actual)?,
                }
            }
            ReleaseOperation::ObserveDeployment => {
                // Not-ready is a bounded wait, not a successful deployment.
                let (incarnation, evidence) = match self.ready(lease) {
                    Ok(value) => value,
                    Err(_) => return Ok(ReleaseEffectResult::RetryNotApplied {}),
                };
                ReleaseObserved::Deployment {
                    ready: true,
                    incarnation,
                    evidence,
                }
            }
            ReleaseOperation::Activate => anyhow::bail!("activation_is_journal_owned"),
        };
        Ok(ReleaseEffectResult::Observed(Box::new(
            ReleaseObservation { fact, outcome },
        )))
    }

    fn verify_activation(&self, lease: &ReleaseLease) -> Result<()> {
        self.ready(lease)?;
        Ok(())
    }
}
