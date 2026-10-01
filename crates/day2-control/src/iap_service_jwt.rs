//! Keyless, per-request service-account credentials for the two remote-app IAP
//! gates. Google-managed IAP accepts a service-account JWT whose audience is
//! the exact protected URL. IAM Credentials signs it; no app pod holds a key.
//! The IAP assertion delivered *after* each gate remains separately verified
//! by `RemoteQueryIssuer` and `RemoteQueryReceiver`.

use crate::{
    secrets::{AccessToken, AccessTokenProvider},
    source::{FailureClass, SourceError},
};
use anyhow::{Result, ensure};
use reqwest::{blocking::Client, redirect::Policy};
use serde::Deserialize;
use std::{io::Read, sync::Arc, time::Duration};
use url::{Host, Url};

const METADATA_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
const MAX_RESPONSE_BYTES: u64 = 16_384;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Issuer,
    Receiver,
}

pub use day2::iap_workload::BearerToken;

struct Tokens(Arc<dyn AccessTokenProvider>);

impl day2::iap_workload::AccessTokens for Tokens {
    fn authorization(&self) -> Result<reqwest::header::HeaderValue> {
        Ok(self.0.access_token()?.authorization_header()?)
    }
}

/// The two URLs are host-owned bindings, never app-supplied. A new credential
/// is requested for each gate entry, including retries. The access-token
/// provider is injected by the host and must itself be scoped to this signer.
pub struct IapServiceJwt {
    issuer: Url,
    receiver: Url,
    signer: day2::iap_workload::Signer,
}

impl IapServiceJwt {
    pub fn url(&self, gate: Gate) -> &Url {
        match gate {
            Gate::Issuer => &self.issuer,
            Gate::Receiver => &self.receiver,
        }
    }

    pub fn new(
        service_account: &str,
        issuer_url: &str,
        receiver_url: &str,
        tokens: Arc<dyn AccessTokenProvider>,
    ) -> Result<Self> {
        Self::with_iam(
            service_account,
            issuer_url,
            receiver_url,
            "https://iamcredentials.googleapis.com/",
            tokens,
            false,
        )
    }

    /// Only an HTTP loopback IAM fixture may replace Google's signing origin.
    pub fn transport_fixture(
        service_account: &str,
        issuer_url: &str,
        receiver_url: &str,
        iam_origin: &str,
        tokens: Arc<dyn AccessTokenProvider>,
    ) -> Result<Self> {
        Self::with_iam(
            service_account,
            issuer_url,
            receiver_url,
            iam_origin,
            tokens,
            true,
        )
    }

    fn with_iam(
        service_account: &str,
        issuer_url: &str,
        receiver_url: &str,
        iam_origin: &str,
        tokens: Arc<dyn AccessTokenProvider>,
        fixture: bool,
    ) -> Result<Self> {
        let issuer = gate_url(issuer_url, "/_platform/app-issue", fixture)?;
        let receiver = gate_url(receiver_url, "/_platform/app-query", fixture)?;
        ensure!(issuer != receiver, "iap_gates_not_distinct");
        let audiences = [issuer.clone(), receiver.clone()].into();
        let tokens = Arc::new(Tokens(tokens));
        let signer = if fixture {
            day2::iap_workload::Signer::transport_fixture(
                service_account,
                audiences,
                tokens,
                iam_origin,
            )?
        } else {
            day2::iap_workload::Signer::new(service_account, audiences, tokens)?
        };
        Ok(Self {
            issuer,
            receiver,
            signer,
        })
    }

    pub fn sign_for(&self, gate: Gate) -> Result<BearerToken> {
        self.signer.sign_for(self.url(gate))
    }
}

fn gate_url(raw: &str, path: &str, fixture: bool) -> Result<Url> {
    let url = Url::parse(raw)?;
    ensure!(
        url.path() == path
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && if fixture {
                loopback_host(&url)
            } else {
                url.scheme() == "https"
                    && url.port().is_none()
                    && matches!(url.host(), Some(Host::Domain(_)))
            },
        "invalid_iap_gate_url"
    );
    Ok(url)
}

fn loopback_host(url: &Url) -> bool {
    url.scheme() == "http"
        && matches!(
            url.host(),
            Some(Host::Ipv4(ip)) if ip.is_loopback()
        )
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

/// A deliberately opt-in metadata source for GKE. It obtains a fresh access
/// token for IAM Credentials; no token is read from process environment or an
/// app-controlled endpoint.
pub struct GkeMetadataAccessTokens {
    client: Client,
    endpoint: Url,
}

#[derive(Deserialize)]
struct MetadataToken {
    access_token: String,
    token_type: String,
}

impl GkeMetadataAccessTokens {
    pub fn new() -> Result<Self> {
        Self::with_endpoint(METADATA_URL, false)
    }

    pub fn transport_fixture(endpoint: &str) -> Result<Self> {
        Self::with_endpoint(endpoint, true)
    }

    fn with_endpoint(endpoint: &str, fixture: bool) -> Result<Self> {
        let endpoint = Url::parse(endpoint)?;
        ensure!(
            if fixture {
                endpoint.scheme() == "http"
                    && matches!(endpoint.host(), Some(Host::Ipv4(ip)) if ip.is_loopback())
                    && endpoint.path()
                        == "/computeMetadata/v1/instance/service-accounts/default/token"
                    && endpoint.query().is_none()
                    && endpoint.fragment().is_none()
                    && endpoint.username().is_empty()
                    && endpoint.password().is_none()
            } else {
                endpoint.as_str() == METADATA_URL
            },
            "invalid_gke_metadata_endpoint"
        );
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(2))
            .build()?;
        Ok(Self { client, endpoint })
    }
}

impl AccessTokenProvider for GkeMetadataAccessTokens {
    fn access_token(&self) -> std::result::Result<AccessToken, SourceError> {
        let transient = || SourceError {
            class: FailureClass::Transient,
            code: "gke_metadata_unavailable",
        };
        let invalid = || SourceError {
            class: FailureClass::Integrity,
            code: "invalid_gke_metadata_token",
        };
        let response = self
            .client
            .get(self.endpoint.clone())
            .header("Metadata-Flavor", "Google")
            .send()
            .map_err(|_| transient())?;
        if !response.status().is_success() {
            return Err(transient());
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| transient())?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(invalid());
        }
        let token: MetadataToken = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if !token.token_type.eq_ignore_ascii_case("bearer") {
            return Err(invalid());
        }
        AccessToken::new(token.access_token).map_err(|_| invalid())
    }
}
