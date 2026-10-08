//! Scoped releases of installed single-SQLite GKE workloads. Namespace, identity,
//! storage, IAP and key installation remain the infrastructure stack's inputs.
use crate::{
    BindingRef, Digest,
    journal::{Journal, RecoveryMode},
    kubernetes_conformance::{GkeKubernetesProbe, GkeServingBinding},
    provider_evidence::{DeploymentIncarnation, ReadBarrier, RevisionToken, StateEvidence},
    release::{ReleaseApproval, SecretObservation},
    release_execution::{
        Capabilities, ProviderRefusal, ReleaseEffectResult, ReleaseExecutionPlan, ReleaseLease,
        ReleaseObservation, ReleaseObserved, ReleaseOperation,
    },
    secrets::{AccessTokenProvider, SecretVersion},
    serving_publication::Publication,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use day2_capabilities::resources::VersionRef;
use reqwest::{Certificate, Method, StatusCode, blocking::Client};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use url::Url;

const MAX_BYTES: u64 = 1_048_576;
const EFFECT: &str = "day2.dev/release-effect";
const RELEASE: &str = "day2.dev/release-id";
const REVISION: &str = "day2.dev/selection-revision";
const SNAPSHOT: &str = "day2.dev/selection-digest";
const CREDENTIALS_SHA256: &str = "day2.dev/credentials-sha256";
const ARTIFACT: &str = "day2.dev/artifact";
/// Stamped on the StatefulSet by `day2 platform maintain activate` once the
/// target artifact is activated in the app's database. Only that artifact may
/// replace the live one; the release that does so consumes the stamp.
const ACTIVATED: &str = "day2.dev/activated-artifact";
const CSI_DRIVER: &str = "secrets-store-gke.csi.k8s.io";
const OPERATOR_INSTANCE: &str = "operator-instance.json";
const PROVISIONING: &str = "provisioning.json";
// The day2-app stack's credential-files init container: copy each projected
// version into the in-memory credential directory as a 10001-owned 0400 file.
const CREDENTIAL_FILES: [&str; 9] = [
    "/busybox/install",
    "-o",
    "10001",
    "-g",
    "10001",
    "-m",
    "0400",
    "-t",
    "/run/day2/credentials",
];
const CREDENTIAL_SOURCES: &str = "/run/day2/credential-sources";

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
    /// Provider credentials registered before day2-serve starts, if the app has any.
    pub credentials: Option<ProviderCredentials>,
}

/// The infrastructure stack owns the credential SecretProviderClass and its IAM.
/// A release pins these exact versions (through the deployment input digest),
/// verifies them and owns the registration metadata derived from its instance.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCredentials {
    pub projection: String,
    pub operator: String,
    pub entries: Vec<ProviderCredential>,
    /// The registration ConfigMap data exactly as the stack renders it: one
    /// provisioning input per entry, the operator-only instance and the plan.
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCredential {
    /// day2's reference key: the projected path and mounted file name.
    pub key: String,
    pub credential_ref: VersionRef,
    pub secret_version: SecretVersion,
    /// `sha256:` of the reviewed value without trailing newlines.
    pub fingerprint: String,
}

/// day2::packaging's reviewed provisioning plan.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisioningPlan {
    version: u32,
    app: String,
    operator: String,
    instance_digest: String,
    inputs: Vec<ProvisioningPin>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisioningPin {
    file: String,
    digest: String,
    credential_digest: String,
}

impl ProviderCredentials {
    fn validate(&self, deployment: &Deployment) -> Result<()> {
        dns(&self.projection)?;
        ensure!(
            self.projection != deployment.secret_projection
                && !self.operator.trim().is_empty()
                && self.operator.len() <= 254
                && !self.operator.chars().any(char::is_control)
                && !self.entries.is_empty()
                && self.entries.len() <= 64,
            "gke_release_credentials_invalid"
        );
        let mut entries = BTreeMap::new();
        let mut versions = BTreeSet::new();
        for entry in &self.entries {
            entry.secret_version.validate()?;
            ensure!(
                entry.key == day2::packaging::reference_key(&entry.credential_ref)?
                    && entry.fingerprint.len() == 71
                    && entry.fingerprint.starts_with("sha256:")
                    && entry.fingerprint[7..]
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    && entry.secret_version.project_number
                        == deployment.serving.project_number.get()
                    && deployment
                        .secret_versions
                        .iter()
                        .all(|version| version != &entry.secret_version)
                    && versions.insert(entry.secret_version.resource_name())
                    && entries
                        .insert(format!("credential-{}.json", entry.key), entry)
                        .is_none(),
                "gke_release_credential_scope_changed"
            );
        }
        ensure!(
            serde_json::to_vec(&self.metadata)?.len() <= 900_000,
            "gke_release_credential_budget"
        );
        ensure!(
            self.metadata
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == entries
                    .keys()
                    .map(String::as_str)
                    .chain([OPERATOR_INSTANCE, PROVISIONING])
                    .collect(),
            "gke_release_credential_metadata_changed"
        );
        // The operator-only instance is the serving instance plus a control
        // section that asserts this operator and nothing else.
        let operator = self.metadata[OPERATOR_INSTANCE].as_bytes();
        let parsed = day2::artifact::Instance::from_bytes(operator)?;
        let control = parsed
            .control
            .as_ref()
            .context("gke_release_credential_operator_missing")?;
        ensure!(
            control.operators == BTreeSet::from([self.operator.clone()])
                && control.apps.is_empty()
                && control.sources.is_empty()
                && control.builders.is_empty()
                && control.runtimes.is_empty()
                && control.secrets.is_empty(),
            "gke_release_credential_operator_scope_changed"
        );
        let mut serving: Value = day2::json::decode(operator)?;
        serving
            .as_object_mut()
            .context("gke_release_credential_instance_changed")?
            .remove("control");
        ensure!(
            serving == deployment.instance,
            "gke_release_credential_instance_changed"
        );
        let plan: ProvisioningPlan = day2::json::decode(self.metadata[PROVISIONING].as_bytes())?;
        ensure!(
            plan.version == 1
                && plan.app == deployment.serving.target.app.as_str()
                && plan.operator == self.operator
                && plan.instance_digest == day2::digest(operator)
                && plan.inputs.len() == self.entries.len(),
            "gke_release_credential_plan_changed"
        );
        let mut pinned = BTreeSet::new();
        for pin in &plan.inputs {
            let entry = entries
                .get(&pin.file)
                .context("gke_release_credential_plan_changed")?;
            let input = self.metadata[&pin.file].as_bytes();
            let mount: day2::integration_host::Mount = day2::json::decode(input)?;
            ensure!(
                pinned.insert(&pin.file)
                    && pin.digest == day2::digest(input)
                    && pin.credential_digest == entry.fingerprint
                    && mount.expected_fingerprint.as_ref() == Some(&entry.fingerprint)
                    && mount.credential_file
                        == Path::new(&day2::packaging::credential_path(&entry.credential_ref)?)
                    && mount
                        .reference
                        .as_ref()
                        .unwrap_or(mount.connection.credential_ref())
                        == &entry.credential_ref,
                "gke_release_credential_plan_changed"
            );
        }
        Ok(())
    }

    /// The pod annotation the stack stamps: the plan's hex SHA-256.
    fn digest(&self) -> String {
        day2::digest(self.metadata[PROVISIONING].as_bytes())
            .trim_start_matches("sha256:")
            .to_owned()
    }
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
        if let Some(credentials) = &self.credentials {
            credentials.validate(self)?;
        }
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
                self.credentials
                    .as_ref()
                    .map(|credentials| &credentials.projection),
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
        // Zero only after a maintenance activation; see `admit`.
        ensure!(
            controller["spec"]["replicas"]
                .as_u64()
                .is_some_and(|replicas| replicas <= 1)
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

    /// Before any write: once initialized, the app's database (not the
    /// instance) selects the served artifact, so a release may change the
    /// artifact only onto state activated for it. Returns whether the release
    /// consumes the activation stamp and restores the profile's one replica.
    fn admit(&self, controller: &Value, lease: &ReleaseLease) -> Result<bool> {
        let candidate = lease.approval.artifact.as_str();
        let live = controller["spec"]["template"]["metadata"]["annotations"][ARTIFACT]
            .as_str()
            .context("gke_release_artifact_annotation_missing")?;
        if live == candidate {
            ensure!(
                controller["spec"]["replicas"] == 1,
                "gke_release_topology_changed"
            );
            return Ok(false);
        }
        let activated = controller["metadata"]["annotations"][ACTIVATED].as_str();
        if activated != Some(candidate) {
            return Err(ProviderRefusal(format!(
                "release_artifact_requires_activation: {} serves {live}{}; run `day2 platform maintain activate` for {candidate} first",
                self.deployment.serving.target.app.as_str(),
                activated.map_or_else(String::new, |other| format!(
                    " and is activated for {other}"
                )),
            ))
            .into());
        }
        Ok(true)
    }

    fn secret(&self, lease: &ReleaseLease) -> Result<SecretObservation> {
        let api = Api {
            client: client(None)?,
            endpoint: self.endpoints.secrets.clone(),
            tokens: self.tokens.as_ref(),
        };
        // App-call keys are checked for integrity; provider credentials also
        // against the reviewed fingerprint registration will require.
        let credentials = self
            .deployment
            .credentials
            .iter()
            .flat_map(|credentials| &credentials.entries);
        let accesses = self
            .deployment
            .secret_versions
            .iter()
            .map(|version| (version, None))
            .chain(credentials.map(|entry| (&entry.secret_version, Some(&entry.fingerprint))));
        for (version, fingerprint) in accesses {
            let name = version.resource_name();
            let value = api
                .get(&format!("v1/{name}:access"))?
                .context("gke_release_secret_unavailable")?;
            ensure!(value["name"] == name, "gke_release_secret_version_changed");
            let checksum = value["payload"]["dataCrc32c"]
                .as_str()
                .context("gke_release_secret_checksum_missing")?
                .parse::<u32>()?;
            let mut bytes = STANDARD
                .decode(
                    value["payload"]["data"]
                        .as_str()
                        .context("gke_release_secret_payload_missing")?,
                )
                .map_err(|_| anyhow::anyhow!("gke_release_secret_payload_invalid"))?;
            let bounded = !bytes.is_empty() && bytes.len() <= 65536;
            let valid = crc32c::crc32c(&bytes) == checksum;
            let reviewed = fingerprint.is_none_or(|expected| {
                day2::integration_host::credential_fingerprint(&bytes)
                    .is_ok_and(|actual| &actual == expected)
            });
            bytes.fill(0);
            ensure!(bounded, "gke_release_secret_payload_budget");
            ensure!(valid, "gke_release_secret_checksum_changed");
            ensure!(reviewed, "gke_release_credential_fingerprint_changed");
        }
        let reference = lease.approval.secret.clone();
        let resource = Digest::of(&reference)?;
        let evidence = Digest::of(&(
            "gke-exact-secret-access-v1",
            &reference,
            &self.deployment.secret_versions,
            &self.deployment.credentials.as_ref().map(|credentials| {
                credentials
                    .entries
                    .iter()
                    .map(|entry| (&entry.secret_version, &entry.fingerprint))
                    .collect::<Vec<_>>()
            }),
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

    /// The tofu-owned SecretProviderClasses must project exactly the pinned
    /// versions at their paths; the release never writes them.
    fn projection(&self, api: &Api<'_>) -> Result<()> {
        projected(
            api,
            &self.deployment.serving.namespace,
            &self.deployment.secret_projection,
            BTreeMap::from([
                (
                    "workload".to_owned(),
                    self.deployment.secret_versions[0].resource_name(),
                ),
                (
                    "issuer".to_owned(),
                    self.deployment.secret_versions[1].resource_name(),
                ),
            ]),
        )?;
        if let Some(credentials) = &self.deployment.credentials {
            projected(
                api,
                &self.deployment.serving.namespace,
                &credentials.projection,
                credentials
                    .entries
                    .iter()
                    .map(|entry| (entry.key.clone(), entry.secret_version.resource_name()))
                    .collect(),
            )?;
        }
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

    fn credentials_name(&self, lease: &ReleaseLease) -> String {
        format!("{}-credentials", self.instance_name(lease))
    }

    /// The immutable ConfigMaps this release's template mounts: its instance
    /// and, with provider credentials, their registration metadata.
    fn config_maps(&self, lease: &ReleaseLease) -> Result<Vec<(String, Value)>> {
        let mut maps = vec![(
            self.instance_name(lease),
            json!({"instance.json": serde_json::to_string(&self.deployment.instance)?}),
        )];
        if let Some(credentials) = &self.deployment.credentials {
            maps.push((
                self.credentials_name(lease),
                serde_json::to_value(&credentials.metadata)?,
            ));
        }
        Ok(maps)
    }

    fn config_map_path(&self, name: &str) -> String {
        format!(
            "api/v1/namespaces/{}/configmaps/{name}",
            self.deployment.serving.namespace
        )
    }

    fn config_map_matches(&self, actual: &Value, lease: &ReleaseLease, data: &Value) -> bool {
        actual["immutable"] == true
            && actual["data"] == *data
            && actual["metadata"]["annotations"][RELEASE] == lease.execution.plan.release.as_str()
    }

    fn instance(&self, api: &Api<'_>, lease: &ReleaseLease) -> Result<()> {
        let collection = format!(
            "api/v1/namespaces/{}/configmaps",
            self.deployment.serving.namespace
        );
        for (name, data) in self.config_maps(lease)? {
            let path = self.config_map_path(&name);
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
                self.config_map_matches(&actual, lease, &data),
                "gke_release_instance_conflict"
            );
        }
        Ok(())
    }

    /// Registration runs the released image against metadata derived from the
    /// released instance. Everything else in the credential machinery (the
    /// SecretProviderClass, its paths and mounts) stays the stack's.
    fn credential_template(&self, template: &mut Value, lease: &ReleaseLease) -> Result<()> {
        let initial: &[Value] = template["spec"]["initContainers"]
            .as_array()
            .map_or(&[], Vec::as_slice);
        let machinery = initial.iter().any(|init| {
            init["name"] == "credential-files" || init["name"] == "credential-registration"
        }) || template["spec"]["volumes"]
            .as_array()
            .is_some_and(|volumes| {
                volumes.iter().any(|volume| {
                    matches!(
                        volume["name"].as_str(),
                        Some("credential-sources" | "credentials" | "credential-metadata")
                    )
                })
            })
            || !template["metadata"]["annotations"][CREDENTIALS_SHA256].is_null();
        let Some(credentials) = &self.deployment.credentials else {
            ensure!(!machinery, "gke_release_credentials_not_declared");
            return Ok(());
        };
        template["metadata"]["annotations"][CREDENTIALS_SHA256] = json!(credentials.digest());
        let init = template["spec"]["initContainers"]
            .as_array_mut()
            .context("gke_release_credential_registration_missing")?;
        let files = init
            .iter_mut()
            .find(|init| init["name"] == "credential-files")
            .context("gke_release_credential_files_missing")?;
        ensure!(
            files["command"]
                .as_array()
                .is_some_and(|command| command.len() > CREDENTIAL_FILES.len()
                    && command.iter().zip(CREDENTIAL_FILES).all(|(a, b)| a == b)),
            "gke_release_credential_files_changed"
        );
        files["command"] = json!(
            CREDENTIAL_FILES
                .iter()
                .map(|part| (*part).to_owned())
                .chain(
                    credentials
                        .entries
                        .iter()
                        .map(|entry| format!("{CREDENTIAL_SOURCES}/{}", entry.key))
                )
                .collect::<Vec<_>>()
        );
        let registration = init
            .iter_mut()
            .find(|init| init["name"] == "credential-registration")
            .context("gke_release_credential_registration_missing")?;
        let mounted: BTreeSet<_> = registration["volumeMounts"]
            .as_array()
            .context("gke_release_credential_registration_changed")?
            .iter()
            .filter(|mount| mount["name"] == "credential-metadata")
            .map(|mount| mount["subPath"].as_str())
            .collect();
        ensure!(
            registration["command"] == json!(["/usr/local/bin/day2-provision-credentials"])
                && registration["args"][1] == self.deployment.serving.target.app.as_str()
                && registration["args"][2] == credentials.operator.as_str()
                && registration["args"]
                    .as_array()
                    .is_some_and(|args| args.len() == 4)
                && mounted
                    == credentials
                        .metadata
                        .keys()
                        .map(|key| Some(key.as_str()))
                        .collect(),
            "gke_release_credential_registration_changed"
        );
        registration["image"] = json!(self.deployment.image);
        let volumes = template["spec"]["volumes"]
            .as_array_mut()
            .context("gke_release_volumes_missing")?;
        ensure!(
            volumes.iter().any(|volume| volume["name"] == "credential-sources"
                && volume["csi"]["driver"] == CSI_DRIVER
                && volume["csi"]["volumeAttributes"]["secretProviderClass"]
                    == credentials.projection.as_str())
                && volumes
                    .iter()
                    .any(|volume| volume["name"] == "credentials" && volume["emptyDir"].is_object()),
            "gke_release_credential_projection_not_mounted"
        );
        let metadata = volumes
            .iter_mut()
            .find(|volume| volume["name"] == "credential-metadata")
            .context("gke_release_credential_metadata_missing")?;
        ensure!(
            metadata["configMap"].is_object(),
            "gke_release_credential_metadata_missing"
        );
        metadata["configMap"]["name"] = json!(self.credentials_name(lease));
        Ok(())
    }

    fn template(&self, controller: &Value, lease: &ReleaseLease) -> Result<Value> {
        let mut template = controller["spec"]["template"].clone();
        let annotations = template["metadata"]["annotations"]
            .as_object_mut()
            .context("gke_release_annotations_missing")?;
        annotations.insert(ARTIFACT.into(), json!(lease.approval.artifact));
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
            volumes
                .iter()
                .any(|volume| volume["csi"]["driver"] == CSI_DRIVER
                    && volume["csi"]["volumeAttributes"]["secretProviderClass"]
                        == self.deployment.secret_projection),
            "gke_release_projection_not_mounted"
        );
        self.credential_template(&mut template, lease)?;
        Ok(template)
    }

    fn prepared(&self, api: &Api<'_>, lease: &ReleaseLease, controller: &Value) -> Result<bool> {
        if !(controller["metadata"]["annotations"][EFFECT] == lease.effect.as_str()
            && controller["metadata"]["annotations"][RELEASE]
                == lease.execution.plan.release.as_str()
            && controller["spec"]["replicas"] == 1
            && controller["spec"]["template"] == self.template(controller, lease)?)
        {
            return Ok(false);
        }
        for (name, data) in self.config_maps(lease)? {
            if !api
                .get(&self.config_map_path(&name))?
                .is_some_and(|actual| self.config_map_matches(&actual, lease, &data))
            {
                return Ok(false);
            }
        }
        Ok(true)
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
                && before["spec"]["replicas"] == 1
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
        // Never publish to an app a snapshot its own calls cannot select from.
        publication
            .snapshot
            .selected(&self.deployment.serving.target)?;
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

fn projected(
    api: &Api<'_>,
    namespace: &str,
    name: &str,
    expected: BTreeMap<String, String>,
) -> Result<()> {
    let projection = api
        .get(&format!(
            "apis/secrets-store.csi.x-k8s.io/v1/namespaces/{namespace}/secretproviderclasses/{name}"
        ))?
        .context("gke_release_projection_missing")?;
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
    let mut names = BTreeMap::new();
    for value in projected {
        ensure!(
            names.insert(value.path, value.resource_name).is_none(),
            "gke_release_projection_changed"
        );
    }
    ensure!(names == expected, "gke_release_projection_versions_changed");
    Ok(())
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
                // Refuse an installed workload this candidate cannot be released into.
                let controller = self.controller(&api)?;
                self.admit(&controller, lease)?;
                self.template(&controller, lease)?;
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
                    let activated = self.admit(&controller, lease)?;
                    self.secret(lease)?;
                    self.projection(&api)?;
                    self.instance(&api, lease)?;
                    let mut patch = vec![
                        json!({"op":"test","path":"/metadata/uid","value":controller["metadata"]["uid"]}),
                        json!({"op":"test","path":"/metadata/resourceVersion","value":controller["metadata"]["resourceVersion"]}),
                        json!({"op":"add","path":"/metadata/annotations/day2.dev~1release-effect","value":lease.effect}),
                        json!({"op":"add","path":"/metadata/annotations/day2.dev~1release-id","value":lease.execution.plan.release}),
                        json!({"op":"replace","path":"/spec/template","value":self.template(&controller, lease)?}),
                    ];
                    if activated {
                        // Activation left the app stopped. Consume the stamp the
                        // resourceVersion test pins, so it cannot authorize a
                        // later artifact change.
                        patch.extend([
                            json!({"op":"remove","path":"/metadata/annotations/day2.dev~1activated-artifact"}),
                            json!({"op":"replace","path":"/spec/replicas","value":1}),
                        ]);
                    }
                    let patch = Value::Array(patch);
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
