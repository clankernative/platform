//! Private bounded HTTPS requests. Routes are selected by the native protocol,
//! never by an app effect or forwarded URL. Transport alone grants no role proof.

use super::{identity_protocol, native_clock::NativeAcquisition};
use anyhow::{Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochIam, EpochProvider, EpochStore, bootstrap::GkeClusterSelection},
};
use reqwest::{Method, blocking::Client, header::HeaderValue};
use std::{io::Read, time::Duration};
use url::Url;
use zeroize::Zeroizing;

const MAX_BYTES: usize = 65_536;
// The complete validator input, with EVERY attachment retained. Instance
// metadata/startup scripts are unnecessary and can exceed the response bound.
const COMPUTE_INSTANCE_FIELDS: &str =
    "id,name,selfLink,status,disks(source,deviceName,type,mode,boot)";

/// Failure-only DATA: [last sampled elapsed microseconds, selected request
/// timeout microseconds, reqwest timeout classification]. Both time values
/// already exist before send; this adds no clock read or deadline change.
/// A timeout is not proof of stage expiry, transmission or a remote no-effect.
/// The compact fixed tuple keeps even a maximal Controller record below its
/// unchanged byte bound. No URL, credential, body or reqwest error is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(in crate::security_epoch) struct FailedRequestWindow(Option<u32>, u32, bool);

impl std::fmt::Display for FailedRequestWindow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native request did not complete")
    }
}

impl std::error::Error for FailedRequestWindow {}

impl FailedRequestWindow {
    pub(in crate::security_epoch) fn observe(error: &anyhow::Error) -> Option<Self> {
        error.downcast_ref::<Self>().copied()
    }

    #[cfg(test)]
    pub(in crate::security_epoch) fn maximal_fixture(timeout: bool) -> Self {
        Self(Some(u32::MAX), 5_000_000, timeout)
    }
}

pub(super) enum Route<'a> {
    TokenReview,
    Namespace(&'a str),
    ServiceAccount { namespace: &'a str, name: &'a str },
    Pod { namespace: &'a str, name: &'a str },
    PersistentVolumeClaim { namespace: &'a str, name: &'a str },
    PersistentVolume(&'a str),
    ComputeDisk { zone: &'a str, name: &'a str },
    ComputeInstance { zone: &'a str, name: &'a str },
    Node(&'a str),
    ReplicaSet { namespace: &'a str, name: &'a str },
    Deployment { namespace: &'a str, name: &'a str },
    StatefulSet { namespace: &'a str, name: &'a str },
    GoogleAccount(&'a EpochIam),
    GoogleMint(&'a EpochIam),
    Cluster,
    Project,
    Database,
    EpochRead,
    EpochRollback,
    EpochCommit,
}

pub(super) struct NativeHttp {
    google: Client,
    kubernetes: Client,
    kube_origin: Url,
    selection: EpochStore,
    cluster: GkeClusterSelection,
    verified_cluster_domain: Option<Digest>,
}

impl NativeHttp {
    /// No factory accepts a verified flag or parsed JSON as recipient proof.
    /// The fixed authenticated Google request and original interval are owned
    /// here; its result only unlocks this adapter's selected Kubernetes route.
    pub(super) fn verify_cluster(
        &mut self,
        observed_ca: &[u8],
        source: &HeaderValue,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        self.verified_cluster_domain = None;
        let result = (|| {
            let bytes = Zeroizing::new(self.request(Route::Cluster, source, None, acquisition)?);
            identity_protocol::cluster(&self.cluster, observed_ca, &bytes)?;
            self.verified_cluster_domain = Some(acquisition.sample()?.domain);
            Ok(())
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }

    pub(super) fn matches(&self, route: &Route<'_>, url: &str) -> Result<bool> {
        Ok(self.address(route)?.0.as_str() == url)
    }

    pub(super) fn new(
        selection: &EpochStore,
        cluster: &GkeClusterSelection,
        observed_ca: &[u8],
    ) -> Result<Self> {
        selection.validate()?;
        ensure!(
            !observed_ca.is_empty()
                && observed_ca.len() <= MAX_BYTES
                && Digest::new(observed_ca) == cluster.certificate_authority,
            "epoch_native_cluster_ca_mismatch"
        );
        let origin = Url::parse(&cluster.api_origin)?;
        ensure!(
            origin.scheme() == "https"
                && origin.host().is_some()
                && origin.path() == "/"
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none(),
            "epoch_native_cluster_origin"
        );
        let google = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()?;
        let kubernetes = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(observed_ca)?)
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()?;
        Ok(Self {
            google,
            kubernetes,
            kube_origin: origin,
            selection: selection.clone(),
            cluster: cluster.clone(),
            verified_cluster_domain: None,
        })
    }

    fn address(&self, route: &Route<'_>) -> Result<(Url, Method, bool)> {
        let EpochProvider::FirestoreNativeV1 {
            project, database, ..
        } = &self.selection.provider;
        let project = project.as_str();
        let kube = |segments: &[&str]| -> Result<Url> {
            let mut url = self.kube_origin.clone();
            url.path_segments_mut()
                .map_err(|_| anyhow::anyhow!("epoch_native_cluster_origin"))?
                .clear()
                .extend(segments);
            Ok(url)
        };
        let result = match route {
            Route::TokenReview => (
                kube(&["apis", "authentication.k8s.io", "v1", "tokenreviews"])?,
                Method::POST,
                true,
            ),
            Route::Namespace(name) => {
                (kube(&["api", "v1", "namespaces", name])?, Method::GET, true)
            }
            Route::ServiceAccount { namespace, name } => (
                kube(&[
                    "api",
                    "v1",
                    "namespaces",
                    namespace,
                    "serviceaccounts",
                    name,
                ])?,
                Method::GET,
                true,
            ),
            Route::Pod { namespace, name } => (
                kube(&["api", "v1", "namespaces", namespace, "pods", name])?,
                Method::GET,
                true,
            ),
            Route::PersistentVolumeClaim { namespace, name } => (
                kube(&[
                    "api",
                    "v1",
                    "namespaces",
                    namespace,
                    "persistentvolumeclaims",
                    name,
                ])?,
                Method::GET,
                true,
            ),
            Route::PersistentVolume(name) => (
                kube(&["api", "v1", "persistentvolumes", name])?,
                Method::GET,
                true,
            ),
            Route::ComputeDisk { zone, name } | Route::ComputeInstance { zone, name } => {
                let collection = match route {
                    Route::ComputeDisk { .. } => "disks",
                    _ => "instances",
                };
                let mut url = Url::parse("https://compute.googleapis.com/compute/v1/")?;
                url.path_segments_mut()
                    .map_err(|_| anyhow::anyhow!("storage_provider_origin"))?
                    .pop_if_empty()
                    .extend(["projects", project, "zones", zone, collection, name]);
                if matches!(route, Route::ComputeInstance { .. }) {
                    url.query_pairs_mut()
                        .append_pair("fields", COMPUTE_INSTANCE_FIELDS);
                }
                (url, Method::GET, false)
            }
            Route::Node(name) => (kube(&["api", "v1", "nodes", name])?, Method::GET, true),
            Route::ReplicaSet { namespace, name } => (
                kube(&[
                    "apis",
                    "apps",
                    "v1",
                    "namespaces",
                    namespace,
                    "replicasets",
                    name,
                ])?,
                Method::GET,
                true,
            ),
            Route::Deployment { namespace, name } => (
                kube(&[
                    "apis",
                    "apps",
                    "v1",
                    "namespaces",
                    namespace,
                    "deployments",
                    name,
                ])?,
                Method::GET,
                true,
            ),
            Route::StatefulSet { namespace, name } => (
                kube(&[
                    "apis",
                    "apps",
                    "v1",
                    "namespaces",
                    namespace,
                    "statefulsets",
                    name,
                ])?,
                Method::GET,
                true,
            ),
            Route::GoogleAccount(account) => {
                let EpochIam::GkeWorkloadIdentityV1 {
                    service_account_uid,
                    ..
                } = account;
                (
                    Url::parse(&format!(
                        "https://iam.googleapis.com/v1/projects/{project}/serviceAccounts/{}",
                        service_account_uid.as_str()
                    ))?,
                    Method::GET,
                    false,
                )
            }
            Route::GoogleMint(account) => (
                Url::parse(&format!(
                    "https://iamcredentials.googleapis.com/v1/{}:generateAccessToken",
                    account.access_token_target()
                ))?,
                Method::POST,
                false,
            ),
            Route::Cluster => (
                Url::parse(&format!(
                    "https://container.googleapis.com/v1/projects/{}/locations/{}/clusters/{}",
                    self.cluster.project.as_str(),
                    self.cluster.location.as_str(),
                    self.cluster.name.as_str()
                ))?,
                Method::GET,
                false,
            ),
            Route::Project => (
                Url::parse(&format!(
                    "https://cloudresourcemanager.googleapis.com/v1/projects/{project}"
                ))?,
                Method::GET,
                false,
            ),
            Route::Database => (
                Url::parse(&format!(
                    "https://firestore.googleapis.com/v1/projects/{project}/databases/{}",
                    database.as_str()
                ))?,
                Method::GET,
                false,
            ),
            Route::EpochRead | Route::EpochRollback | Route::EpochCommit => {
                let operation = match route {
                    Route::EpochRead => "batchGet",
                    Route::EpochRollback => "rollback",
                    _ => "commit",
                };
                (
                    Url::parse(&format!(
                        "https://firestore.googleapis.com/v1/projects/{project}/databases/{}/documents:{operation}",
                        database.as_str()
                    ))?,
                    Method::POST,
                    false,
                )
            }
        };
        Ok(result)
    }

    pub(super) fn request(
        &self,
        route: Route<'_>,
        bearer: &HeaderValue,
        body: Option<&[u8]>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Vec<u8>> {
        self.request_with_ceiling(route, bearer, body, acquisition, Duration::from_secs(5))
    }

    pub(super) fn request_with_ceiling(
        &self,
        route: Route<'_>,
        bearer: &HeaderValue,
        body: Option<&[u8]>,
        acquisition: &mut NativeAcquisition,
        ceiling: Duration,
    ) -> Result<Vec<u8>> {
        let mut profile =
            super::self_check_profile::enter(super::self_check_profile::Category::ProviderHttp);
        let result = (|| {
            let (address, method, kube) = self.address(&route)?;
            ensure!(
                bearer.is_sensitive(),
                "epoch_native_sensitive_credential_required"
            );
            ensure!(
                body.is_none_or(|body| body.len() <= MAX_BYTES),
                "epoch_native_request_bound"
            );
            ensure!(
                (method == Method::POST) == body.is_some(),
                "epoch_native_request_method_body"
            );
            if kube {
                let domain = self
                    .verified_cluster_domain
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("epoch_native_cluster_recipient_unverified"))?;
                ensure!(
                    acquisition.sample()?.domain == *domain,
                    "epoch_native_cluster_recipient_domain_changed"
                );
            }
            let remaining = request_timeout(acquisition.remaining()?, ceiling)?;
            let sampled_us = acquisition.last_checked_elapsed_micros();
            let limit_us = u32::try_from(remaining.as_micros())?;
            let client: &Client = if kube { &self.kubernetes } else { &self.google };
            let mut request = client
                .request(method, address)
                .header(reqwest::header::AUTHORIZATION, bearer.clone())
                .timeout(remaining);
            if let Some(body) = body {
                request = request
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body.to_vec());
            }
            let response = request.send().map_err(|error| {
                anyhow::Error::new(FailedRequestWindow(
                    sampled_us,
                    limit_us,
                    error.is_timeout(),
                ))
                .context("epoch_native_transport_unavailable")
            })?;
            acquisition.remaining()?;
            ensure!(
                response.status().is_success()
                    && response
                        .content_length()
                        .is_none_or(|bytes| bytes <= MAX_BYTES as u64),
                "epoch_native_response_status_or_bound"
            );
            let mut bytes = Vec::new();
            response
                .take(MAX_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| anyhow::anyhow!("epoch_native_response_unavailable"))?;
            profile.finish();
            acquisition.remaining()?;
            ensure!(bytes.len() <= MAX_BYTES, "epoch_native_response_bound");
            Ok(bytes)
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }
}

fn request_timeout(remaining: Duration, ceiling: Duration) -> Result<Duration> {
    ensure!(
        !remaining.is_zero() && !ceiling.is_zero() && ceiling <= Duration::from_secs(5),
        "epoch_native_request_deadline"
    );
    Ok(remaining.min(ceiling))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> NativeHttp {
        let selection:EpochStore=serde_json::from_value(json!({
            "scope":{"installation":"company","environment":"canary","app":"calendar"},
            "provider":{"kind":"firestore_native_v1","project":"project-seven","project_number":7,"database":"security",
                "database_uid":"01234567-89ab-4cde-8fab-0123456789ab","iam_source":{"kind":"gke_workload_identity_v1",
                    "service_account":"epoch@project-seven.iam.gserviceaccount.com","service_account_uid":"100000000000000000007"}},
            "key_set":Digest::new(b"keys"),"max_lease_seconds":5})).unwrap();
        let cluster=serde_json::from_value(json!({"project":"project-seven","location":"us-central1","name":"native",
            "uid":"cluster-uid","api_origin":"https://10.0.0.1:443","certificate_authority":Digest::new(b"ca")})).unwrap();
        NativeHttp {
            google: Client::builder().no_proxy().build().unwrap(),
            kubernetes: Client::builder().no_proxy().build().unwrap(),
            kube_origin: Url::parse("https://10.0.0.1:443").unwrap(),
            selection,
            cluster,
            verified_cluster_domain: None,
        }
    }

    #[test]
    fn fixed_routes_and_uid_target_reject_url_forwarding_and_writer_endpoints() {
        let http = fixture();
        let EpochProvider::FirestoreNativeV1 { iam_source, .. } = &http.selection.provider;
        assert_eq!(
            http.address(&Route::GoogleMint(iam_source))
                .unwrap()
                .0
                .as_str(),
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/100000000000000000007:generateAccessToken"
        );
        assert_eq!(
            http.address(&Route::Cluster).unwrap().0.as_str(),
            "https://container.googleapis.com/v1/projects/project-seven/locations/us-central1/clusters/native"
        );
        let read = "https://firestore.googleapis.com/v1/projects/project-seven/databases/security/documents:batchGet";
        assert!(http.matches(&Route::EpochRead, read).unwrap());
        for wrong in [
            read.replace("project-seven", "other-project"),
            read.replace("security", "other-db"),
            read.replace("batchGet", "commit"),
            format!("{read}?forward=1"),
            format!("{read}#fragment"),
            read.replace("firestore.googleapis.com", "elsewhere.example"),
        ] {
            assert!(!http.matches(&Route::EpochRead, &wrong).unwrap());
        }
        let path = http
            .address(&Route::Pod {
                namespace: "native",
                name: "a/b?c",
            })
            .unwrap()
            .0;
        assert!(path.as_str().ends_with("/pods/a%2Fb%3Fc"));
        assert!(path.query().is_none());
    }

    #[test]
    fn prior_elapsed_time_and_caller_timeout_both_bound_the_request() {
        assert_eq!(
            request_timeout(Duration::from_millis(100), Duration::from_secs(5)).unwrap(),
            Duration::from_millis(100)
        );
        assert_eq!(
            request_timeout(Duration::from_secs(2), Duration::from_millis(100)).unwrap(),
            Duration::from_millis(100)
        );
        assert!(request_timeout(Duration::ZERO, Duration::from_secs(5)).is_err());
        assert!(request_timeout(Duration::from_secs(2), Duration::ZERO).is_err());
        assert!(request_timeout(Duration::from_secs(2), Duration::from_secs(6)).is_err());
    }

    #[test]
    fn token_review_and_namespace_refuse_before_send_without_current_recipient() {
        let http = fixture();
        let mut bearer = HeaderValue::from_static("Bearer controlled-secret");
        bearer.set_sensitive(true);
        for (route, body) in [
            (Route::TokenReview, Some(b"{}".as_slice())),
            (Route::Namespace("native"), None),
        ] {
            let mut acquisition = NativeAcquisition::fixture(
                Digest::new(b"clock"),
                std::process::id(),
                Duration::from_secs(100),
                Duration::from_secs(5),
            );
            let error = http
                .request(route, &bearer, body, &mut acquisition)
                .err()
                .unwrap()
                .to_string();
            assert_eq!(error, "epoch_native_cluster_recipient_unverified");
            assert!(acquisition.remaining().is_err());
        }
    }

    #[test]
    fn recipient_domain_expiry_and_process_change_latch_before_send() {
        let mut bearer = HeaderValue::from_static("Bearer controlled-secret");
        bearer.set_sensitive(true);
        for (stored, process, limit, error) in [
            (
                Digest::new(b"other-clock"),
                std::process::id(),
                Duration::from_secs(5),
                "epoch_native_cluster_recipient_domain_changed",
            ),
            (
                Digest::new(b"clock"),
                std::process::id(),
                Duration::ZERO,
                "epoch_native_clock_rewind_or_expired",
            ),
            (
                Digest::new(b"clock"),
                std::process::id().wrapping_add(1),
                Duration::from_secs(5),
                "epoch_native_process_changed",
            ),
        ] {
            let mut http = fixture();
            http.verified_cluster_domain = Some(stored);
            let mut acquisition = NativeAcquisition::fixture(
                Digest::new(b"clock"),
                process,
                Duration::from_secs(100),
                limit,
            );
            let actual = http
                .request(Route::TokenReview, &bearer, Some(b"{}"), &mut acquisition)
                .err()
                .unwrap()
                .to_string();
            assert_eq!(actual, error);
            assert!(acquisition.remaining().is_err());
        }
    }

    #[test]
    fn rejected_request_latches_acquisition_before_any_network_send() {
        let http = fixture();
        let mut acquisition = NativeAcquisition::fixture(
            Digest::new(b"clock"),
            std::process::id(),
            Duration::from_secs(100),
            Duration::from_secs(5),
        );
        let bearer = HeaderValue::from_static("Bearer controlled-secret");
        let error = http
            .request(Route::EpochRead, &bearer, Some(b"{}"), &mut acquisition)
            .err()
            .unwrap()
            .to_string();
        assert_eq!(error, "epoch_native_sensitive_credential_required");
        assert!(acquisition.remaining().is_err());
    }
    #[test]
    fn compute_instance_uses_only_fixed_complete_attachment_fields() {
        let http = fixture();
        let route = Route::ComputeInstance {
            zone: "zone-one",
            name: "node-one",
        };
        let (url, method, kube) = http.address(&route).unwrap();
        assert_eq!(method, Method::GET);
        assert!(!kube);
        assert_eq!(
            url.path(),
            "/compute/v1/projects/project-seven/zones/zone-one/instances/node-one"
        );
        assert_eq!(
            url.query_pairs().collect::<Vec<_>>(),
            vec![(
                "fields".into(),
                "id,name,selfLink,status,disks(source,deviceName,type,mode,boot)".into()
            )]
        );
        assert!(http.matches(&route, url.as_str()).unwrap());
        let mut forwarded = url.clone();
        forwarded.set_query(None);
        assert!(!http.matches(&route, forwarded.as_str()).unwrap());
        forwarded.query_pairs_mut().append_pair("fields", "*");
        assert!(!http.matches(&route, forwarded.as_str()).unwrap());
        let disk = http
            .address(&Route::ComputeDisk {
                zone: "zone-one",
                name: "disk-one",
            })
            .unwrap()
            .0;
        assert!(disk.query().is_none());
    }
}
