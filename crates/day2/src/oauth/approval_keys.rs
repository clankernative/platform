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

pub(crate) trait AccessTokenSource: Send + Sync {
    fn access_token(&self) -> Result<String>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GcpSecretVersion {
    pub project_number: u64,
    pub secret: String,
    pub version: u64,
}

impl GcpSecretVersion {
    fn validate(&self) -> Result<()> {
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

    fn resource_name(&self) -> String {
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
        let token = self.tokens.access_token()?;
        ensure!(
            !token.is_empty()
                && token.len() <= 8192
                && token.bytes().all(|byte| byte.is_ascii_graphic()),
            "invalid Secret Manager access token"
        );
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))?;
        authorization.set_sensitive(true);
        let name = version.resource_name();
        let url = self.endpoint.join(&format!("v1/{name}:access"))?;
        let response = self
            .client
            .get(url)
            .header(AUTHORIZATION, authorization)
            .header("accept", "application/json")
            .send()?
            .error_for_status()?;
        ensure!(
            response
                .content_length()
                .is_none_or(|length| length <= MAX_RESPONSE_BYTES as u64),
            "OAuth key response too large"
        );
        let mut body = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut body)?;
        ensure!(
            body.len() <= MAX_RESPONSE_BYTES,
            "OAuth key response too large"
        );
        let response: AccessResponse = serde_json::from_slice(&body)
            .map_err(|_| anyhow::anyhow!("invalid OAuth key response"))?;
        ensure!(response.name == name, "OAuth key version changed");
        let decoded = STANDARD
            .decode(response.payload.data)
            .map_err(|_| anyhow::anyhow!("invalid OAuth key encoding"))?;
        ensure!(decoded.len() == 32, "invalid OAuth key length");
        let checksum: u32 = response
            .payload
            .data_crc32c
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid OAuth key checksum"))?;
        ensure!(
            crc32c::crc32c(&decoded) == checksum,
            "OAuth key checksum mismatch"
        );
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
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
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
                "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
            String::from_utf8(request).unwrap()
        });
        (endpoint, worker)
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
