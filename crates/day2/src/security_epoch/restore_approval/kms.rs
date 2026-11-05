//! Fixed restore-signature transport, deliberately closed to this module.
//! There is no production caller or signing-owner factory yet. A request clock,
//! bearer header, statement or successful signature is not approval authority.
//! Opening this leaf requires the real purpose-specific producer join, including
//! current registry, durable challenge/counter completion and fenced host time.
use super::signed::{ApprovalStatement, SignedApprovalRecord};
use crate::security_epoch::NativeAcquisition;
use anyhow::{Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use day2_capabilities::restore_signing::KeySelection;
use reqwest::{Method, blocking::Client, header::HeaderValue};
use serde_json::{Value, json};
use std::{io::Read, marker::PhantomData, rc::Rc};

const ORIGIN: &str = "https://cloudkms.googleapis.com";
const REPLY_LIMIT: usize = 16_384;
const REQUEST_LIMIT: usize = 24_576;
const ALGORITHM: &str = "EC_SIGN_ED25519";
const PROTECTION: &str = "SOFTWARE";

// Private fields AND private methods: parent modules cannot use a DATA-only
// acquisition/header as a signer. The eventual native join must change this
// boundary explicitly; there is no public trait, callback or test fallback.
struct Kms {
    client: Client,
    attempted: bool,
    local: PhantomData<Rc<()>>,
    #[cfg(test)]
    fixture_origin: Option<String>,
}

impl Kms {
    fn new() -> Result<Self> {
        Ok(Self {
            client: client(true)?,
            attempted: false,
            local: PhantomData,
            #[cfg(test)]
            fixture_origin: None,
        })
    }

    // One attempt, fixed purpose and algorithm. This does not mark durable
    // grant consumption or publish a result; even success returns only DATA.
    fn sign(
        &mut self,
        selected: &KeySelection,
        statement: &ApprovalStatement,
        authorization: HeaderValue,
        acquisition: &mut NativeAcquisition,
    ) -> Result<SignedApprovalRecord> {
        let result = (|| {
            ensure!(!self.attempted, "restore_kms_attempt_spent");
            self.attempted = true;
            acquisition.remaining()?;
            ensure!(
                statement.signing_key == selected.commitment()?,
                "restore_kms_selection_changed"
            );
            let frame = statement.signature_input_data()?;
            let version =
                self.request(selected, Route::Version, &authorization, None, acquisition)?;
            check_version(selected, &version)?;
            let public = self.request(
                selected,
                Route::PublicKey,
                &authorization,
                None,
                acquisition,
            )?;
            check_public(selected, &public)?;
            let body = serde_json::to_vec(&json!({
                "data": STANDARD.encode(&frame),
                "dataCrc32c": crc32c::crc32c(&frame).to_string(),
            }))?;
            ensure!(body.len() <= REQUEST_LIMIT, "restore_kms_request_bound");
            let reply = self.request(
                selected,
                Route::Sign,
                &authorization,
                Some(body),
                acquisition,
            )?;
            ensure!(
                text(&reply, "name")? == selected.version.as_str()
                    && text(&reply, "protectionLevel")? == PROTECTION
                    && reply.get("verifiedDataCrc32c").and_then(Value::as_bool) == Some(true)
                    && reply
                        .get("verifiedDigestCrc32c")
                        .is_none_or(|v| v.as_bool() == Some(false)),
                "restore_kms_sign_integrity"
            );
            let encoded = text(&reply, "signature")?;
            let bytes = STANDARD
                .decode(encoded)
                .map_err(|_| anyhow::anyhow!("restore_kms_signature_encoding"))?;
            ensure!(
                bytes.len() == 64 && STANDARD.encode(&bytes) == encoded,
                "restore_kms_signature_encoding"
            );
            check_crc(&reply, "signatureCrc32c", &bytes)?;
            let signed = SignedApprovalRecord {
                statement: statement.clone(),
                signature: URL_SAFE_NO_PAD.encode(bytes),
            };
            // Verify the complete canonical frame with the exact selected
            // version AND public bytes, independently of the provider's CRC.
            signed.verify_signature_data(statement, selected)?;
            // Do not return a signature after observing a disabled/different
            // selected version. Publication still needs its own real owners.
            let version =
                self.request(selected, Route::Version, &authorization, None, acquisition)?;
            check_version(selected, &version)?;
            acquisition.remaining()?;
            Ok(signed)
        })();
        if result.is_err() {
            self.attempted = true;
            acquisition.refuse();
        }
        result
    }

    fn request(
        &self,
        selected: &KeySelection,
        route: Route,
        authorization: &HeaderValue,
        body: Option<Vec<u8>>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Value> {
        let (method, suffix) = match route {
            Route::Version => (Method::GET, ""),
            Route::PublicKey => (Method::GET, "/publicKey"),
            Route::Sign => (Method::POST, ":asymmetricSign"),
        };
        let origin = ORIGIN;
        #[cfg(test)]
        let origin = self.fixture_origin.as_deref().unwrap_or(origin);
        acquisition.remaining()?;
        let mut authorization = authorization.clone();
        authorization.set_sensitive(true);
        let mut request = self
            .client
            .request(
                method,
                format!("{origin}/v1/{}{suffix}", selected.version.as_str()),
            )
            .header(reqwest::header::AUTHORIZATION, authorization)
            .timeout(acquisition.remaining()?);
        if let Some(body) = body {
            ensure!(body.len() <= REQUEST_LIMIT, "restore_kms_request_bound");
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body);
        }
        let requested = request
            .send()
            .map_err(|_| anyhow::anyhow!("restore_kms_transport"));
        // Both actual results are evaluated. The first request error remains
        // primary even when the unchanged original also expires/refuses.
        let checked = acquisition.remaining();
        let response = requested?;
        checked?;
        ensure!(response.status().is_success(), "restore_kms_status");
        ensure!(
            response
                .content_length()
                .is_none_or(|n| n <= REPLY_LIMIT as u64),
            "restore_kms_reply_bound"
        );
        let mut bytes = Vec::new();
        let read = response
            .take((REPLY_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("restore_kms_transport"));
        let checked = acquisition.remaining();
        read?;
        checked?;
        ensure!(bytes.len() <= REPLY_LIMIT, "restore_kms_reply_bound");
        crate::json::decode(&bytes).map_err(|_| anyhow::anyhow!("restore_kms_reply_shape"))
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
        .ok_or_else(|| anyhow::anyhow!("restore_kms_reply_shape"))
}

fn check_crc(value: &Value, field: &str, bytes: &[u8]) -> Result<()> {
    ensure!(
        text(value, field)? == crc32c::crc32c(bytes).to_string(),
        "restore_kms_crc_mismatch"
    );
    Ok(())
}

fn check_version(selected: &KeySelection, value: &Value) -> Result<()> {
    ensure!(
        text(value, "name")? == selected.version.as_str()
            && text(value, "algorithm")? == ALGORITHM
            && text(value, "protectionLevel")? == PROTECTION
            && text(value, "state")? == "ENABLED",
        "restore_kms_version_mismatch"
    );
    Ok(())
}

fn check_public(selected: &KeySelection, value: &Value) -> Result<()> {
    ensure!(
        text(value, "name")? == selected.version.as_str()
            && text(value, "algorithm")? == ALGORITHM
            && text(value, "protectionLevel")? == PROTECTION,
        "restore_kms_public_selection"
    );
    let pem = text(value, "pem")?;
    check_crc(value, "pemCrc32c", pem.as_bytes())?;
    let encoded = pem
        .strip_prefix("-----BEGIN PUBLIC KEY-----\n")
        .and_then(|s| s.strip_suffix("\n-----END PUBLIC KEY-----\n"))
        .ok_or_else(|| anyhow::anyhow!("restore_kms_public_encoding"))?;
    ensure!(
        encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=\n".contains(&b)),
        "restore_kms_public_encoding"
    );
    let compact = encoded.replace('\n', "");
    let der = STANDARD
        .decode(&compact)
        .map_err(|_| anyhow::anyhow!("restore_kms_public_encoding"))?;
    // RFC8410 Ed25519 SubjectPublicKeyInfo, no algorithm parameters.
    const PREFIX: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    ensure!(
        der.len() == 44
            && der.starts_with(PREFIX)
            && der[12..] == selected.public_key
            && STANDARD.encode(&der) == compact,
        "restore_kms_public_mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
