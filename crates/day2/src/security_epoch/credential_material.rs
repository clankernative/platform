//! Native request credentials are secret material, not a transferable identity
//! proof. UID-target minting must retain its authenticated request provenance.

use super::{
    native_clock::NativeAcquisition,
    transport::{NativeHttp, Route},
};
use anyhow::{Result, ensure};
use day2_capabilities::security_epoch::EpochIam;
use reqwest::{blocking::Client, header::HeaderValue};
use serde::Deserialize;
use std::{io::Read, marker::PhantomData, rc::Rc};
use zeroize::{Zeroize, Zeroizing};

pub(crate) struct CredentialMaterial {
    bytes: Vec<u8>,
    local: PhantomData<Rc<()>>,
}

impl CredentialMaterial {
    fn from_bytes(mut bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty()
            || bytes.len() > 8192
            || !bytes.iter().all(|byte| byte.is_ascii_graphic())
        {
            bytes.zeroize();
            anyhow::bail!("epoch_native_credential_shape");
        }
        Ok(Self {
            bytes,
            local: PhantomData,
        })
    }

    pub(super) fn authorization(&self) -> Result<HeaderValue> {
        let mut value = Zeroizing::new(Vec::with_capacity(7 + self.bytes.len()));
        value.extend_from_slice(b"Bearer ");
        value.extend_from_slice(&self.bytes);
        let header = HeaderValue::from_bytes(&value)
            .map_err(|_| anyhow::anyhow!("epoch_native_credential_shape"));
        value.zeroize();
        let mut header = header?;
        header.set_sensitive(true);
        Ok(header)
    }

    /// Fixed trusted-native profile paths. Reading a projection alone does not
    /// authenticate it or bind the caller process to the token's Pod.
    pub(super) fn kubernetes_api(acquisition: &mut NativeAcquisition) -> Result<Self> {
        Self::projection(
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            acquisition,
        )
    }

    pub(super) fn subject(acquisition: &mut NativeAcquisition) -> Result<Self> {
        Self::projection("/var/run/secrets/day2-native/subject-token", acquisition)
    }

    fn projection(path: &str, acquisition: &mut NativeAcquisition) -> Result<Self> {
        let result = (|| {
            acquisition.remaining()?;
            let mut bytes = Zeroizing::new(Vec::new());
            let file = std::fs::File::from(rustix::fs::open(
                path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?);
            ensure!(
                file.metadata()?.is_file(),
                "epoch_native_projection_not_regular"
            );
            file.take(8193).read_to_end(&mut bytes)?;
            acquisition.remaining()?;
            Self::from_bytes(std::mem::take(&mut *bytes))
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }

    pub(super) fn metadata_source(acquisition: &mut NativeAcquisition) -> Result<Self> {
        let result = (|| {
            acquisition.remaining()?;
            let client = Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .build()?;
            let response = client.get("http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token")
                .header("Metadata-Flavor","Google").timeout(acquisition.remaining()?)
                .send().map_err(|_| anyhow::anyhow!("epoch_native_metadata_unavailable"))?;
            acquisition.remaining()?;
            ensure!(
                response.status().is_success()
                    && response
                        .headers()
                        .get("Metadata-Flavor")
                        .is_some_and(|value| value == "Google")
                    && response
                        .content_length()
                        .is_none_or(|bytes| bytes <= 12_288),
                "epoch_native_metadata_status_or_bound"
            );
            let mut bytes = Zeroizing::new(Vec::new());
            response
                .take(12_289)
                .read_to_end(&mut bytes)
                .map_err(|_| anyhow::anyhow!("epoch_native_metadata_unavailable"))?;
            acquisition.remaining()?;
            ensure!(bytes.len() <= 12_288, "epoch_native_metadata_bound");
            Self::metadata_reply(&bytes)
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }

    /// Successful authenticated mint for the immutable target is retained by
    /// the native owning caller; expireTime is DATA, not qualified host UTC.
    pub(super) fn mint_target(
        source: &Self,
        selected: &EpochIam,
        http: &NativeHttp,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Self> {
        let body = br#"{"scope":["https://www.googleapis.com/auth/datastore"],"lifetime":"300s"}"#;
        let mut bytes = Zeroizing::new(http.request(
            Route::GoogleMint(selected),
            &source.authorization()?,
            Some(body),
            acquisition,
        )?);
        let result = Self::mint_reply(&bytes);
        bytes.zeroize();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }

    fn metadata_reply(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 12_288, "epoch_native_metadata_bound");
        let mut value: MetadataReply = crate::json::decode(bytes)
            .map_err(|_| anyhow::anyhow!("epoch_native_metadata_shape"))?;
        ensure!(
            value.token_type == "Bearer" && value.expires_in > 0 && value.expires_in <= 3600,
            "epoch_native_metadata_shape"
        );
        Self::from_bytes(std::mem::take(&mut value.access_token).into_bytes())
    }

    fn mint_reply(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 65_536, "epoch_native_mint_reply_bound");
        let mut value: MintReply = crate::json::decode(&bytes)
            .map_err(|_| anyhow::anyhow!("epoch_native_mint_reply_shape"))?;
        let expiry = time::OffsetDateTime::parse(
            &value.expire_time,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| anyhow::anyhow!("epoch_native_mint_expiry_shape"))?;
        ensure!(
            expiry.offset() == time::UtcOffset::UTC,
            "epoch_native_mint_expiry_shape"
        );
        Self::from_bytes(std::mem::take(&mut value.access_token).into_bytes())
    }

    pub(super) fn subject_text(&self) -> Result<&str> {
        std::str::from_utf8(&self.bytes)
            .map_err(|_| anyhow::anyhow!("epoch_native_credential_shape"))
    }
}

impl Drop for CredentialMaterial {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataReply {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

impl Drop for MetadataReply {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MintReply {
    access_token: String,
    expire_time: String,
}

impl Drop for MintReply {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn material_and_headers_reject_injection_and_do_not_format_the_secret() {
        for bytes in [
            Vec::new(),
            b"a\r\nb".to_vec(),
            b"a b".to_vec(),
            vec![b'a'; 8193],
            vec![0xff],
        ] {
            let error = CredentialMaterial::from_bytes(bytes)
                .err()
                .unwrap()
                .to_string();
            assert_eq!(error, "epoch_native_credential_shape");
        }
        let material = CredentialMaterial::from_bytes(b"controlled-secret".to_vec()).unwrap();
        let header = material.authorization().unwrap();
        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains("controlled-secret"));
    }

    #[test]
    fn malformed_duplicate_or_unexpected_secret_replies_return_only_codes() {
        let good =
            br#"{"access_token":"controlled-secret","token_type":"Bearer","expires_in":300}"#;
        assert!(CredentialMaterial::metadata_reply(good).is_ok());
        for bad in [
            br#"{"access_token":"controlled-secret","token_type":"Other","expires_in":300}"#.as_slice(),
            br#"{"access_token":"controlled-secret","token_type":"Bearer","expires_in":0}"#,
            br#"{"access_token":"controlled-secret","access_token":"second","token_type":"Bearer","expires_in":300}"#,
            br#"{"access_token":"controlled-secret","token_type":"Bearer","expires_in":300,"extra":"secret"}"#,
            b"controlled-secret"
        ] {
            let error=CredentialMaterial::metadata_reply(bad).err().unwrap().to_string();
            assert!(error.starts_with("epoch_native_metadata_"));
            assert!(!error.contains("controlled-secret"));
        }
        let minted = br#"{"accessToken":"controlled-secret","expireTime":"2026-10-14T00:05:00Z"}"#;
        assert!(CredentialMaterial::mint_reply(minted).is_ok());
        assert!(
            CredentialMaterial::mint_reply(
                br#"{"accessToken":"controlled-secret","expireTime":"2026-10-14T00:05:00+01:00"}"#
            )
            .is_err()
        );
        assert!(
            CredentialMaterial::mint_reply(
                br#"{"accessToken":"controlled-secret","expireTime":"not-time"}"#
            )
            .is_err()
        );
        // The accepted timestamp is historical syntax only, never a UTC clock.
    }
}
