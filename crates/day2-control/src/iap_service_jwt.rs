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
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{blocking::Client, header::AUTHORIZATION, redirect::Policy};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::{Host, Url};

const IAM_ORIGIN: &str = "https://iamcredentials.googleapis.com/";
const METADATA_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
const MAX_RESPONSE_BYTES: u64 = 16_384;
const JWT_LIFETIME_SECONDS: i64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Issuer,
    Receiver,
}

pub struct BearerToken(String);

impl BearerToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BearerToken([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedJwt {
    key_id: String,
    signed_jwt: String,
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    kid: String,
}

/// The two URLs are host-owned bindings, never app-supplied. A new credential
/// is requested for each gate entry, including retries. The access-token
/// provider is injected by the host and must itself be scoped to this signer.
pub struct IapServiceJwt {
    service_account: String,
    issuer: Url,
    receiver: Url,
    iam: Url,
    client: Client,
    tokens: Arc<dyn AccessTokenProvider>,
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
            IAM_ORIGIN,
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
        let service_account = service_account.trim().to_ascii_lowercase();
        ensure!(
            service_account.ends_with(".iam.gserviceaccount.com")
                && service_account.matches('@').count() == 1
                && service_account.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'@' | b'.' | b'-' | b'_')
                }),
            "invalid_iap_service_account"
        );
        let issuer = gate_url(issuer_url, "/_platform/app-issue", fixture)?;
        let receiver = gate_url(receiver_url, "/_platform/app-query", fixture)?;
        ensure!(issuer != receiver, "iap_gates_not_distinct");
        let iam = Url::parse(iam_origin)?;
        ensure!(
            if fixture {
                loopback_origin(&iam)
            } else {
                iam.as_str() == IAM_ORIGIN
            },
            "invalid_iam_signing_origin"
        );
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(3))
            .build()?;
        Ok(Self {
            service_account,
            issuer,
            receiver,
            iam,
            client,
            tokens,
        })
    }

    pub fn sign_for(&self, gate: Gate) -> Result<BearerToken> {
        let at = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        self.sign_at(gate, at)
    }

    fn sign_at(&self, gate: Gate, at: i64) -> Result<BearerToken> {
        ensure!(at > 0, "invalid_iap_credential_time");
        let audience = match gate {
            Gate::Issuer => &self.issuer,
            Gate::Receiver => &self.receiver,
        };
        let claims = Claims {
            iss: self.service_account.clone(),
            sub: self.service_account.clone(),
            aud: audience.as_str().to_owned(),
            iat: at,
            exp: at
                .checked_add(JWT_LIFETIME_SECONDS)
                .ok_or_else(|| anyhow::anyhow!("invalid_iap_credential_time"))?,
        };
        let mut endpoint = self.iam.clone();
        endpoint.set_path(&format!(
            "/v1/projects/-/serviceAccounts/{}:signJwt",
            self.service_account
        ));
        let access = self.tokens.access_token()?;
        let response = self
            .client
            .post(endpoint)
            .header(AUTHORIZATION, access.authorization_header()?)
            .json(&serde_json::json!({"payload":serde_json::to_string(&claims)?}))
            .send()
            .map_err(|_| anyhow::anyhow!("iam_sign_jwt_unavailable"))?;
        ensure!(response.status().is_success(), "iam_sign_jwt_refused");
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_RESPONSE_BYTES,
            "iam_sign_jwt_response_too_large"
        );
        let signed: SignedJwt = serde_json::from_slice(&bytes)?;
        ensure!(
            !signed.key_id.is_empty() && signed.key_id.len() <= 256,
            "invalid_iam_signed_jwt"
        );
        let mut parts = signed.signed_jwt.split('.');
        let (Some(head), Some(body), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            anyhow::bail!("invalid_iam_signed_jwt");
        };
        let header: JwtHeader = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(head)?)?;
        let returned: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body)?)?;
        ensure!(
            header.alg == "RS256"
                && header.kid == signed.key_id
                && returned == claims
                && URL_SAFE_NO_PAD.decode(signature)?.len() >= 64,
            "invalid_iam_signed_jwt"
        );
        Ok(BearerToken(signed.signed_jwt))
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

fn loopback_origin(url: &Url) -> bool {
    loopback_host(url) && url.path() == "/"
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
