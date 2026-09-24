//! Explicit, version-pinned Secret Manager access for provider credentials.
//! Token acquisition is trusted-host injected; no ADC, environment, or metadata lookup.

use crate::Digest;
use crate::source::{FailureClass, SecretRef, SecretResolver, SecretValue, SourceError};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::{
    blocking::Client,
    header::{AUTHORIZATION, HeaderValue},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, io::Read, time::Duration};
use url::{Host, Url};

type Result<T> = std::result::Result<T, SourceError>;
const MAX_RESPONSE_BYTES: usize = 32 * 1024;

fn error(class: FailureClass, code: &'static str) -> SourceError {
    SourceError { class, code }
}

pub struct AccessToken(String);
impl AccessToken {
    pub fn new(value: String) -> Result<Self> {
        if value.is_empty() || value.len() > 8192 || !value.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(error(
                FailureClass::InvalidInput,
                "invalid_gcp_access_token",
            ));
        }
        Ok(Self(value))
    }

    pub(crate) fn authorization_header(&self) -> Result<HeaderValue> {
        let mut header = HeaderValue::from_str(&format!("Bearer {}", self.0))
            .map_err(|_| error(FailureClass::InvalidInput, "invalid_gcp_access_token"))?;
        header.set_sensitive(true);
        Ok(header)
    }
}
impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessToken([REDACTED])")
    }
}
pub trait AccessTokenProvider: Send + Sync {
    fn access_token(&self) -> Result<AccessToken>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretVersion {
    pub project_number: u64,
    pub secret: String,
    pub version: u64,
}
impl SecretVersion {
    pub fn validate(&self) -> Result<()> {
        if self.project_number == 0
            || self.version == 0
            || self.secret.is_empty()
            || self.secret.len() > 255
            || !self
                .secret
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err(error(
                FailureClass::InvalidInput,
                "invalid_gcp_secret_version",
            ));
        }
        Ok(())
    }
    pub fn resource_name(&self) -> String {
        format!(
            "projects/{}/secrets/{}/versions/{}",
            self.project_number, self.secret, self.version
        )
    }
}

pub struct GcpSecretManager<'a> {
    client: Client,
    endpoint: Url,
    bindings: BTreeMap<SecretRef, SecretVersion>,
    tokens: &'a dyn AccessTokenProvider,
    revision: Digest,
}
impl<'a> GcpSecretManager<'a> {
    pub fn new(
        bindings: BTreeMap<SecretRef, SecretVersion>,
        tokens: &'a dyn AccessTokenProvider,
    ) -> Result<Self> {
        Self::with_endpoint("https://secretmanager.googleapis.com/", bindings, tokens)
    }
    pub fn with_endpoint(
        endpoint: &str,
        bindings: BTreeMap<SecretRef, SecretVersion>,
        tokens: &'a dyn AccessTokenProvider,
    ) -> Result<Self> {
        let endpoint = Url::parse(endpoint)
            .map_err(|_| error(FailureClass::InvalidInput, "invalid_gcp_endpoint"))?;
        let loopback = match endpoint.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            Some(Host::Domain("localhost")) => true,
            _ => false,
        };
        let production = endpoint.scheme() == "https"
            && endpoint.host_str() == Some("secretmanager.googleapis.com")
            && endpoint.port().is_none();
        if !(production || (endpoint.scheme() == "http" && loopback))
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
        {
            return Err(error(FailureClass::InvalidInput, "invalid_gcp_endpoint"));
        }
        if bindings.is_empty() || bindings.len() > 128 {
            return Err(error(FailureClass::Limit, "gcp_secret_binding_budget"));
        }
        for version in bindings.values() {
            version.validate()?;
        }
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(3))
            .user_agent("day2-control/0.1")
            .build()
            .map_err(|_| error(FailureClass::InvalidInput, "gcp_client_configuration"))?;
        let revision =
            Digest::of(&("day2-gcp-secret-bindings-v1", endpoint.as_str(), &bindings))
                .map_err(|_| error(FailureClass::Integrity, "gcp_secret_binding_encoding"))?;
        Ok(Self {
            client,
            endpoint,
            bindings,
            tokens,
            revision,
        })
    }
    pub fn bindings(&self) -> &BTreeMap<SecretRef, SecretVersion> {
        &self.bindings
    }
}
impl SecretResolver for GcpSecretManager<'_> {
    fn binding_revision(&self) -> Digest {
        self.revision.clone()
    }
    fn resolve(&self, reference: &SecretRef) -> Result<SecretValue> {
        let version = self
            .bindings
            .get(reference)
            .ok_or_else(|| error(FailureClass::Unauthorized, "gcp_secret_not_bound"))?;
        let token = self.tokens.access_token()?;
        let header = token.authorization_header()?;
        let name = version.resource_name();
        let url = self
            .endpoint
            .join(&format!("v1/{name}:access"))
            .map_err(|_| error(FailureClass::InvalidInput, "invalid_gcp_secret_version"))?;
        let response = self
            .client
            .get(url)
            .header(AUTHORIZATION, header)
            .header("accept", "application/json")
            .send()
            .map_err(|_| error(FailureClass::Transient, "gcp_secret_read_transport"))?;
        if response.status().as_u16() != 200 {
            return Err(match response.status().as_u16() {
                401 | 403 => error(FailureClass::Unauthorized, "gcp_secret_unauthorized"),
                404 => error(FailureClass::NotFound, "gcp_secret_not_found"),
                429 => error(FailureClass::RateLimited, "gcp_secret_rate_limited"),
                408 | 500..=599 => error(FailureClass::Transient, "gcp_secret_unavailable"),
                300..=399 => error(FailureClass::Unsupported, "gcp_secret_redirect_forbidden"),
                _ => error(FailureClass::InvalidInput, "gcp_secret_request_rejected"),
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(error(FailureClass::Limit, "gcp_secret_response_budget"));
        }
        let mut body = vec![];
        response
            .take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|_| error(FailureClass::Transient, "gcp_secret_read_transport"))?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(error(FailureClass::Limit, "gcp_secret_response_budget"));
        }
        let response: AccessResponse = serde_json::from_slice(&body)
            .map_err(|_| error(FailureClass::Integrity, "gcp_secret_invalid_response"))?;
        if response.name != name {
            return Err(error(FailureClass::Integrity, "gcp_secret_version_changed"));
        }
        let bytes = STANDARD
            .decode(response.payload.data)
            .map_err(|_| error(FailureClass::Integrity, "gcp_secret_invalid_encoding"))?;
        let checksum: u32 = response
            .payload
            .data_crc32c
            .parse()
            .map_err(|_| error(FailureClass::Integrity, "gcp_secret_invalid_checksum"))?;
        if crc32c::crc32c(&bytes) != checksum {
            return Err(error(
                FailureClass::Integrity,
                "gcp_secret_checksum_mismatch",
            ));
        }
        let value = String::from_utf8(bytes)
            .map_err(|_| error(FailureClass::Unsupported, "gcp_secret_not_token"))?;
        SecretValue::new(value)
    }
}
#[derive(Deserialize)]
struct AccessResponse {
    name: String,
    payload: Payload,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    data: String,
    data_crc32c: String,
}
