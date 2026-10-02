//! Exact-version Google Secret Manager keys for OAuth custody and shell attestations.
//! The host injects its access-token source; this adapter never uses ADC or a
//! mounted application credential. Secret bytes stay outside app databases.

use super::approval_registry::{
    ApprovalKeyMaterial, ApprovalKeyProvider, ApprovalKeyPurpose, ApprovalKeyRef,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use day2_capabilities::BindingRef;
use reqwest::{
    blocking::Client,
    header::{AUTHORIZATION, HeaderValue},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    sync::Arc,
    time::Duration,
};
use url::{Host, Url};

const MAX_RESPONSE_BYTES: usize = 4096;
const METADATA_URL: &str =
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token";
const MAX_METADATA_BYTES: usize = 12 * 1024;

pub(crate) trait AccessTokenSource: Send + Sync {
    fn access_token(&self) -> Result<String>;
}

/// Opt in only in a host running under the selected GKE workload identity.
/// Each key read requests a current token; no ADC, process environment,
/// application credential, proxy or redirect can choose another source.
pub(crate) struct GkeMetadataAccessTokens {
    client: Client,
    endpoint: Url,
    selected_account: Option<String>,
}

impl GkeMetadataAccessTokens {
    pub(crate) fn new() -> Result<Self> {
        Self::at(Url::parse(METADATA_URL)?)
    }

    pub(crate) fn selected(account: &str) -> Result<Self> {
        day2_capabilities::oauth::ShellTransport {
            service_account: account.into(),
        }
        .validate()?;
        let mut source = Self::new()?;
        source.selected_account = Some(account.into());
        Ok(source)
    }

    fn at(endpoint: Url) -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .connect_timeout(Duration::from_secs(2))
                .timeout(Duration::from_secs(5))
                .build()?,
            endpoint,
            selected_account: None,
        })
    }

    #[cfg(test)]
    fn fixture(endpoint: &str) -> Result<Self> {
        let endpoint = Url::parse(endpoint)?;
        ensure!(
            endpoint.scheme() == "http"
                && matches!(endpoint.host(), Some(Host::Ipv4(ip)) if ip.is_loopback())
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.query().is_none()
                && endpoint.fragment().is_none(),
            "invalid metadata fixture"
        );
        Self::at(endpoint.join("/computeMetadata/v1/instance/service-accounts/default/token")?)
    }
}

impl AccessTokenSource for GkeMetadataAccessTokens {
    fn access_token(&self) -> Result<String> {
        if let Some(account) = &self.selected_account {
            let response = self
                .client
                .get(self.endpoint.join("email")?)
                .header("Metadata-Flavor", "Google")
                .send()?;
            ensure!(
                response.status().is_success()
                    && response
                        .headers()
                        .get("Metadata-Flavor")
                        .is_some_and(|v| v == "Google")
                    && response.content_length().is_none_or(|n| n <= 255),
                "GKE workload identity unavailable"
            );
            let mut email = String::new();
            response.take(256).read_to_string(&mut email)?;
            ensure!(
                email.len() <= 255 && email == *account,
                "GKE workload identity mismatch"
            );
        }
        let response = self
            .client
            .get(self.endpoint.clone())
            .header("Metadata-Flavor", "Google")
            .send()?;
        ensure!(
            response.status().is_success()
                && response
                    .headers()
                    .get("Metadata-Flavor")
                    .is_some_and(|value| value == "Google"),
            "GKE metadata token unavailable"
        );
        ensure!(
            response
                .content_length()
                .is_none_or(|length| length <= MAX_METADATA_BYTES as u64),
            "GKE metadata response too large"
        );
        let mut body = Vec::new();
        response
            .take(MAX_METADATA_BYTES as u64 + 1)
            .read_to_end(&mut body)?;
        ensure!(
            body.len() <= MAX_METADATA_BYTES,
            "GKE metadata response too large"
        );
        let token: MetadataToken = serde_json::from_slice(&body)
            .map_err(|_| anyhow::anyhow!("invalid GKE metadata token"))?;
        ensure!(
            token.token_type == "Bearer"
                && (30..=3600).contains(&token.expires_in)
                && !token.access_token.is_empty()
                && token.access_token.len() <= 8192
                && token
                    .access_token
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic()),
            "invalid GKE metadata token"
        );
        Ok(token.access_token)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataToken {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GcpSecretVersion {
    pub project_number: u64,
    pub secret: String,
    pub version: u64,
}

impl GcpSecretVersion {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.project_number > 0
                && self.version > 0
                && !self.secret.is_empty()
                && self.secret.len() <= 255
                && self
                    .secret
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'),
            "invalid OAuth Secret Manager version"
        );
        Ok(())
    }

    pub(super) fn resource_name(&self) -> String {
        format!(
            "projects/{}/secrets/{}/versions/{}",
            self.project_number, self.secret, self.version
        )
    }
}

pub(crate) struct GcpApprovalKeys {
    client: Client,
    endpoint: Url,
    bindings: BTreeMap<(String, ApprovalKeyPurpose), (BindingRef, GcpSecretVersion)>,
    tokens: Arc<dyn AccessTokenSource>,
}

/// Exact-version client secrets share the same bounded Secret Manager transport
/// as approval keys, without treating a client secret as a 32-byte custody key.
pub(super) struct GcpSecretReader {
    client: Client,
    endpoint: Url,
    tokens: Arc<dyn AccessTokenSource>,
}

impl GcpSecretReader {
    pub(super) fn new(tokens: Arc<dyn AccessTokenSource>) -> Result<Self> {
        Self::at(Url::parse("https://secretmanager.googleapis.com/")?, tokens)
    }

    fn at(endpoint: Url, tokens: Arc<dyn AccessTokenSource>) -> Result<Self> {
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            endpoint,
            tokens,
        })
    }

    pub(super) fn load(&self, version: &GcpSecretVersion) -> Result<Vec<u8>> {
        version.validate()?;
        read_secret(&self.client, &self.endpoint, self.tokens.as_ref(), version)
    }

    #[cfg(test)]
    pub(super) fn fixture(endpoint: &str, tokens: Arc<dyn AccessTokenSource>) -> Result<Self> {
        let endpoint = Url::parse(endpoint)?;
        ensure!(
            endpoint.scheme() == "http"
                && matches!(endpoint.host(), Some(Host::Ipv4(ip)) if ip.is_loopback())
                && endpoint.path() == "/"
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.query().is_none()
                && endpoint.fragment().is_none(),
            "invalid Secret Manager fixture"
        );
        Self::at(endpoint, tokens)
    }
}

fn read_secret(
    client: &Client,
    endpoint: &Url,
    tokens: &dyn AccessTokenSource,
    version: &GcpSecretVersion,
) -> Result<Vec<u8>> {
    let token = tokens.access_token()?;
    ensure!(
        !token.is_empty()
            && token.len() <= 8192
            && token.bytes().all(|byte| byte.is_ascii_graphic()),
        "invalid Secret Manager access token"
    );
    let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))?;
    authorization.set_sensitive(true);
    let name = version.resource_name();
    let response = client
        .get(endpoint.join(&format!("v1/{name}:access"))?)
        .header(AUTHORIZATION, authorization)
        .header("accept", "application/json")
        .send()?;
    ensure!(
        response.status().is_success(),
        "OAuth secret version unavailable"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= MAX_RESPONSE_BYTES as u64),
        "OAuth secret response too large"
    );
    let mut body = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut body)?;
    ensure!(
        body.len() <= MAX_RESPONSE_BYTES,
        "OAuth secret response too large"
    );
    let response: AccessResponse =
        crate::json::decode(&body).map_err(|_| anyhow::anyhow!("invalid OAuth secret response"))?;
    ensure!(response.name == name, "OAuth secret version changed");
    let decoded = STANDARD
        .decode(response.payload.data)
        .map_err(|_| anyhow::anyhow!("invalid OAuth secret encoding"))?;
    ensure!(
        !decoded.is_empty() && decoded.len() <= 2048,
        "invalid OAuth secret length"
    );
    let checksum: u32 = response
        .payload
        .data_crc32c
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid OAuth secret checksum"))?;
    ensure!(
        crc32c::crc32c(&decoded) == checksum,
        "OAuth secret checksum mismatch"
    );
    Ok(decoded)
}

impl GcpApprovalKeys {
    pub(crate) fn new(
        bindings: Vec<(BindingRef, ApprovalKeyPurpose, GcpSecretVersion)>,
        tokens: Arc<dyn AccessTokenSource>,
    ) -> Result<Self> {
        Self::with_endpoint("https://secretmanager.googleapis.com/", bindings, tokens)
    }

    fn with_endpoint(
        endpoint: &str,
        bindings: Vec<(BindingRef, ApprovalKeyPurpose, GcpSecretVersion)>,
        tokens: Arc<dyn AccessTokenSource>,
    ) -> Result<Self> {
        let endpoint = Url::parse(endpoint)?;
        let loopback = match endpoint.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            Some(Host::Domain("localhost")) => true,
            _ => false,
        };
        ensure!(
            (endpoint.scheme() == "https"
                && endpoint.host_str() == Some("secretmanager.googleapis.com")
                && endpoint.port().is_none())
                || (endpoint.scheme() == "http" && loopback),
            "invalid OAuth Secret Manager endpoint"
        );
        ensure!(
            endpoint.path() == "/"
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.query().is_none()
                && endpoint.fragment().is_none(),
            "invalid OAuth Secret Manager endpoint"
        );
        ensure!(
            !bindings.is_empty() && bindings.len() <= 128,
            "invalid OAuth key binding set"
        );
        let mut selected = BTreeMap::new();
        let mut resources = BTreeSet::new();
        for (binding, purpose, version) in bindings {
            version.validate()?;
            ensure!(
                resources.insert(version.resource_name()),
                "OAuth key roles must use distinct secret versions"
            );
            ensure!(
                selected
                    .insert(
                        (binding.id.as_str().to_owned(), purpose),
                        (binding, version)
                    )
                    .is_none(),
                "duplicate OAuth key binding"
            );
        }
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            endpoint,
            bindings: selected,
            tokens,
        })
    }
}

impl ApprovalKeyProvider for GcpApprovalKeys {
    fn load(
        &self,
        reference: &ApprovalKeyRef,
        purpose: ApprovalKeyPurpose,
    ) -> Result<ApprovalKeyMaterial> {
        let (binding, version) = self
            .bindings
            .get(&(reference.binding.id.as_str().to_owned(), purpose))
            .context("OAuth key purpose is not bound")?;
        ensure!(
            binding == &reference.binding && reference.version == version.version.to_string(),
            "OAuth key version does not match selected binding"
        );
        let decoded = read_secret(&self.client, &self.endpoint, self.tokens.as_ref(), version)?;
        ensure!(decoded.len() == 32, "invalid OAuth key length");
        let mut bytes = [0; 32];
        bytes.copy_from_slice(&decoded);
        Ok(ApprovalKeyMaterial {
            binding: reference.binding.clone(),
            version: reference.version.clone(),
            purpose,
            bytes,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessResponse {
    name: String,
    payload: Payload,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Payload {
    data: String,
    data_crc32c: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use day2_capabilities::Name;
    use serde_json::json;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    struct Tokens;

    impl AccessTokenSource for Tokens {
        fn access_token(&self) -> Result<String> {
            Ok("host-injected-token".into())
        }
    }

    fn fixture() -> (ApprovalKeyRef, GcpSecretVersion) {
        (
            ApprovalKeyRef {
                binding: BindingRef::pin(
                    Name::try_from("oauth_custody".to_owned()).unwrap(),
                    &"selected-key-binding",
                )
                .unwrap(),
                version: "7".into(),
            },
            GcpSecretVersion {
                project_number: 12345,
                secret: "oauth-custody-verifier".into(),
                version: 7,
            },
        )
    }

    fn server(status: u16, body: serde_json::Value) -> (String, thread::JoinHandle<String>) {
        server_with_flavor(status, body, "Google")
    }

    fn server_with_flavor(
        status: u16,
        body: serde_json::Value,
        flavor: &str,
    ) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let flavor = flavor.to_owned();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 8192);
            }
            let body = serde_json::to_vec(&body).unwrap();
            write!(
                stream,
                "HTTP/1.1 {status} Fixture\r\nMetadata-Flavor: {flavor}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
            String::from_utf8(request).unwrap()
        });
        (endpoint, worker)
    }

    #[test]
    fn metadata_tokens_use_the_fixed_path_and_flavor_on_every_read() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = format!("http://{}/", listener.local_addr()?);
        let worker = thread::spawn(move || {
            for sequence in 1..=2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 8192);
                }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                assert!(request.starts_with(
                    "get /computemetadata/v1/instance/service-accounts/default/token http/1.1\r\n"
                ));
                assert!(request.contains("metadata-flavor: google\r\n"));
                assert!(!request.contains("authorization:"));
                let body = json!({"access_token":format!("workload-token-{sequence}"),"token_type":"Bearer","expires_in":3599}).to_string();
                write!(stream, "HTTP/1.1 200 Fixture\r\nMetadata-Flavor: Google\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let source = GkeMetadataAccessTokens::fixture(&endpoint)?;
        assert_eq!(source.access_token()?, "workload-token-1");
        assert_eq!(source.access_token()?, "workload-token-2");
        worker.join().unwrap();
        assert_eq!(
            GkeMetadataAccessTokens::new()?.endpoint.as_str(),
            METADATA_URL
        );
        Ok(())
    }

    #[test]
    fn selected_metadata_identity_is_checked_before_every_token_request() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = format!("http://{}/", listener.local_addr()?);
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            for body in [
                "app@company-tools.iam.gserviceaccount.com",
                "{\"access_token\":\"native-selected-token\",\"token_type\":\"Bearer\",\"expires_in\":3599}",
                "another@company-tools.iam.gserviceaccount.com",
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 8192);
                }
                requests.push(String::from_utf8(request).unwrap().to_ascii_lowercase());
                write!(stream,"HTTP/1.1 200 Fixture\r\nMetadata-Flavor: Google\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            }
            requests
        });
        let mut source = GkeMetadataAccessTokens::fixture(&endpoint)?;
        source.selected_account = Some("app@company-tools.iam.gserviceaccount.com".into());
        assert_eq!(source.access_token()?, "native-selected-token");
        assert!(source.access_token().is_err());
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 3);
        for index in [0, 2] {
            assert!(requests[index].starts_with(
                "get /computemetadata/v1/instance/service-accounts/default/email http/1.1"
            ));
        }
        assert!(requests[1].starts_with(
            "get /computemetadata/v1/instance/service-accounts/default/token http/1.1"
        ));
        for request in requests {
            assert!(request.contains("metadata-flavor: google\r\n"));
            assert!(!request.contains("authorization:"));
        }
        assert!(GkeMetadataAccessTokens::selected("operator@example.com").is_err());
        Ok(())
    }

    #[test]
    fn metadata_rejects_unusable_tokens_errors_redirects_and_oversized_responses() -> Result<()> {
        let valid =
            json!({"access_token":"workload-token","token_type":"Bearer","expires_in":3599});
        let (endpoint, worker) = server_with_flavor(200, valid.clone(), "");
        assert!(
            GkeMetadataAccessTokens::fixture(&endpoint)?
                .access_token()
                .is_err()
        );
        worker.join().unwrap();
        for (status, body) in [
            (302, valid.clone()),
            (403, valid.clone()),
            (
                200,
                json!({"access_token":"","token_type":"Bearer","expires_in":3599}),
            ),
            (
                200,
                json!({"access_token":"unsafe\r\nvalue","token_type":"Bearer","expires_in":3599}),
            ),
            (
                200,
                json!({"access_token":"token","token_type":"Basic","expires_in":3599}),
            ),
            (
                200,
                json!({"access_token":"token","token_type":"Bearer","expires_in":0}),
            ),
            (
                200,
                json!({"access_token":"token","token_type":"Bearer","expires_in":7200}),
            ),
            (200, json!({"access_token":"token","token_type":"Bearer"})),
            (
                200,
                json!({"access_token":"x".repeat(MAX_METADATA_BYTES),"token_type":"Bearer","expires_in":3599}),
            ),
        ] {
            let (endpoint, worker) = server(status, body);
            assert!(
                GkeMetadataAccessTokens::fixture(&endpoint)?
                    .access_token()
                    .is_err()
            );
            worker.join().unwrap();
        }
        Ok(())
    }

    fn response(name: &str, checksum: u32) -> serde_json::Value {
        json!({
            "name": name,
            "payload": {
                "data": STANDARD.encode([9; 32]),
                "dataCrc32c": checksum.to_string()
            }
        })
    }

    #[test]
    fn exact_version_purpose_resource_and_checksum_gate_key_lease() {
        let (reference, version) = fixture();
        let name = version.resource_name();
        let purpose = ApprovalKeyPurpose::CustodyVerifier;
        assert!(
            GcpApprovalKeys::new(
                vec![
                    (reference.binding.clone(), purpose, version.clone()),
                    (
                        reference.binding.clone(),
                        ApprovalKeyPurpose::CustodyEncryption,
                        version.clone(),
                    ),
                ],
                Arc::new(Tokens),
            )
            .is_err()
        );
        let (endpoint, worker) = server(200, response(&name, crc32c::crc32c(&[9; 32])));
        let keys = GcpApprovalKeys::with_endpoint(
            &endpoint,
            vec![(reference.binding.clone(), purpose, version.clone())],
            Arc::new(Tokens),
        )
        .unwrap();
        let loaded = keys.load(&reference, purpose).unwrap();
        assert_eq!(loaded.bytes, [9; 32]);
        assert_eq!(loaded.binding, reference.binding);
        assert_eq!(loaded.version, "7");
        let request = worker.join().unwrap();
        assert!(request.starts_with(&format!("GET /v1/{name}:access HTTP/1.1\r\n")));
        assert!(request.contains("host-injected-token"));
        assert!(
            keys.load(&reference, ApprovalKeyPurpose::ShellAttestation)
                .is_err()
        );
        let mut stale = reference.clone();
        stale.version = "8".into();
        assert!(keys.load(&stale, purpose).is_err());
        let mut wrong_binding = reference.clone();
        wrong_binding.binding.revision = day2_capabilities::Digest::new(b"other");
        assert!(keys.load(&wrong_binding, purpose).is_err());

        for (status, body) in [
            (200, response(&name, 0)),
            (302, response(&name, crc32c::crc32c(&[9; 32]))),
            (
                200,
                response(
                    "projects/12345/secrets/other/versions/7",
                    crc32c::crc32c(&[9; 32]),
                ),
            ),
            (404, json!({"error": "exact version retired"})),
        ] {
            let (endpoint, worker) = server(status, body);
            let keys = GcpApprovalKeys::with_endpoint(
                &endpoint,
                vec![(reference.binding.clone(), purpose, version.clone())],
                Arc::new(Tokens),
            )
            .unwrap();
            assert!(keys.load(&reference, purpose).is_err());
            worker.join().unwrap();
        }
    }
}
