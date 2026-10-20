//! One fixed KMS root operation: sign the provisioner's owned issuer birth.
//! The key never enters this process. A signature alone is not native authority.

use super::{
    policy::decode_key,
    protocol::{self, IssuerData},
};
use crate::security_epoch::{CredentialMaterial, NativeAcquisition};
use anyhow::{Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use reqwest::{Method, blocking::Client, header::HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Read;

const ORIGIN: &str = "https://cloudkms.googleapis.com";
const LIMIT: usize = 16_384;
const ALGORITHM: &str = "EC_SIGN_ED25519";
const PROTECTION: &str = "SOFTWARE";

/// Instance-owned public selection, never a private key or signer grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KmsRootSelection {
    pub version: String,
    pub public_key: String,
}

impl KmsRootSelection {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.version.len() <= 512,
            "native_enrollment_kms_version_selection"
        );
        let parts: Vec<_> = self.version.split('/').collect();
        ensure!(
            parts.len() == 10
                && parts[0] == "projects"
                && parts[2] == "locations"
                && parts[4] == "keyRings"
                && parts[6] == "cryptoKeys"
                && parts[8] == "cryptoKeyVersions"
                && [1, 3, 5, 7].iter().all(|i| {
                    let s = parts[*i];
                    !s.is_empty()
                        && s.len() <= 63
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                })
                && parts[9]
                    .parse::<u64>()
                    .is_ok_and(|v| v > 0 && v.to_string() == parts[9]),
            "native_enrollment_kms_version_selection"
        );
        decode_key(&self.public_key)?;
        Ok(())
    }
}

pub(super) struct RootKms {
    client: Client,
    origin: String,
}

impl RootKms {
    pub(super) fn new() -> Result<Self> {
        Ok(Self {
            client: client(true)?,
            origin: ORIGIN.into(),
        })
    }

    /// The private birth owner calls this only after joining its actual Child,
    /// received pidfd, nonce and issuer key possession. It retains and rechecks
    /// those owners around this call and the final private-channel publication.
    pub(super) fn issuer_birth(
        &self,
        selected: &KmsRootSelection,
        data: &IssuerData,
        acquisition: &mut NativeAcquisition,
    ) -> Result<String> {
        let result = (|| {
            acquisition.remaining()?;
            selected.validate()?;
            ensure!(
                data.root_version == selected.version,
                "native_enrollment_kms_birth_version"
            );
            let frame = protocol::issuer_birth_frame(data)?;
            let credential = CredentialMaterial::metadata_source(acquisition)?;
            self.sign_frame(selected, &frame, credential.authorization()?, acquisition)
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }

    fn sign_frame(
        &self,
        selected: &KmsRootSelection,
        frame: &[u8],
        authorization: HeaderValue,
        acquisition: &mut NativeAcquisition,
    ) -> Result<String> {
        let result = (|| {
            acquisition.remaining()?;
            selected.validate()?;
            ensure!(
                !frame.is_empty() && frame.len() <= protocol::MAX_PACKET,
                "native_enrollment_kms_frame_bound"
            );
            let metadata = self.request(
                selected,
                Route::Version,
                authorization.clone(),
                None,
                acquisition,
            )?;
            ensure!(
                text(&metadata, "name")? == selected.version
                    && text(&metadata, "algorithm")? == ALGORITHM
                    && text(&metadata, "protectionLevel")? == PROTECTION
                    && text(&metadata, "state")? == "ENABLED",
                "native_enrollment_kms_version_mismatch"
            );
            let public = self.request(
                selected,
                Route::PublicKey,
                authorization.clone(),
                None,
                acquisition,
            )?;
            verify_public_key(selected, &public)?;
            let request = serde_json::to_vec(&serde_json::json!({
                "data": STANDARD.encode(frame), "dataCrc32c": crc32c::crc32c(frame).to_string()
            }))?;
            let reply = self.request(
                selected,
                Route::Sign,
                authorization,
                Some(request),
                acquisition,
            )?;
            ensure!(
                text(&reply, "name")? == selected.version
                    && text(&reply, "protectionLevel")? == PROTECTION
                    && reply.get("verifiedDataCrc32c").and_then(Value::as_bool) == Some(true)
                    && reply
                        .get("verifiedDigestCrc32c")
                        .is_none_or(|v| v.as_bool() == Some(false)),
                "native_enrollment_kms_sign_integrity"
            );
            let signature = STANDARD
                .decode(text(&reply, "signature")?)
                .map_err(|_| anyhow::anyhow!("native_enrollment_kms_signature_encoding"))?;
            ensure!(
                signature.len() == 64,
                "native_enrollment_kms_signature_length"
            );
            require_crc(&reply, "signatureCrc32c", &signature)?;
            ring::signature::UnparsedPublicKey::new(
                &ring::signature::ED25519,
                decode_key(&selected.public_key)?,
            )
            .verify(frame, &signature)
            .map_err(|_| anyhow::anyhow!("native_enrollment_kms_signature_refused"))?;
            acquisition.remaining()?;
            Ok(URL_SAFE_NO_PAD.encode(signature))
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }

    fn request(
        &self,
        selected: &KmsRootSelection,
        route: Route,
        authorization: HeaderValue,
        body: Option<Vec<u8>>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Value> {
        let (method, suffix) = match route {
            Route::Version => (Method::GET, ""),
            Route::PublicKey => (Method::GET, "/publicKey"),
            Route::Sign => (Method::POST, ":asymmetricSign"),
        };
        let mut request = self
            .client
            .request(
                method,
                format!("{}/v1/{}{suffix}", self.origin, selected.version),
            )
            .header(reqwest::header::AUTHORIZATION, authorization)
            .timeout(acquisition.remaining()?);
        if let Some(body) = body {
            ensure!(body.len() <= LIMIT, "native_enrollment_kms_request_bound");
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body);
        }
        let response = request
            .send()
            .map_err(|_| anyhow::anyhow!("native_enrollment_kms_transport"))?;
        acquisition.remaining()?;
        ensure!(
            response.status().is_success(),
            "native_enrollment_kms_status"
        );
        ensure!(
            response.content_length().is_none_or(|n| n <= LIMIT as u64),
            "native_enrollment_kms_reply_bound"
        );
        let mut bytes = Vec::new();
        response
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("native_enrollment_kms_transport"))?;
        acquisition.remaining()?;
        ensure!(bytes.len() <= LIMIT, "native_enrollment_kms_reply_bound");
        crate::json::decode(&bytes)
            .map_err(|_| anyhow::anyhow!("native_enrollment_kms_reply_shape"))
    }
}

enum Route {
    Version,
    PublicKey,
    Sign,
}

fn client(https_only: bool) -> Result<Client> {
    Ok(Client::builder()
        .https_only(https_only)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .build()?)
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("native_enrollment_kms_reply_shape"))
}

fn require_crc(value: &Value, field: &str, bytes: &[u8]) -> Result<()> {
    let encoded = text(value, field)?;
    ensure!(
        encoded == crc32c::crc32c(bytes).to_string(),
        "native_enrollment_kms_crc_mismatch"
    );
    Ok(())
}

fn verify_public_key(selected: &KmsRootSelection, public: &Value) -> Result<()> {
    ensure!(
        text(public, "name")? == selected.version
            && text(public, "algorithm")? == ALGORITHM
            && text(public, "protectionLevel")? == PROTECTION,
        "native_enrollment_kms_public_selection"
    );
    let pem = text(public, "pem")?;
    require_crc(public, "pemCrc32c", pem.as_bytes())?;
    let encoded = pem
        .strip_prefix("-----BEGIN PUBLIC KEY-----\n")
        .and_then(|p| p.strip_suffix("\n-----END PUBLIC KEY-----\n"))
        .ok_or_else(|| anyhow::anyhow!("native_enrollment_kms_public_encoding"))?;
    ensure!(
        encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=\n".contains(&b)),
        "native_enrollment_kms_public_encoding"
    );
    let der = STANDARD
        .decode(encoded.replace('\n', ""))
        .map_err(|_| anyhow::anyhow!("native_enrollment_kms_public_encoding"))?;
    // RFC 8410 Ed25519 SubjectPublicKeyInfo, with no algorithm parameters.
    const PREFIX: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    ensure!(
        der.len() == 44
            && der.starts_with(PREFIX)
            && der[12..] == decode_key(&selected.public_key)?,
        "native_enrollment_kms_public_mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
