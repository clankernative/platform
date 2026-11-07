//! Reviewed public selection for the fixed restore-approval signing purpose.
//! This module contains no signer, native proof, credentials or provider calls.
use crate::Digest;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// A canonical, exact Google KMS key VERSION, never a key alias or URL. Its
/// private field prevents a parsed invalid reference from becoming this DATA.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct KeyVersion(String);

impl KeyVersion {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for KeyVersion {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        ensure!(value.len() <= 512, "restore_signing_key_version_bound");
        let parts: Vec<_> = value.split('/').collect();
        ensure!(
            parts.len() == 10
                && parts[0] == "projects"
                && parts[2] == "locations"
                && parts[4] == "keyRings"
                && parts[6] == "cryptoKeys"
                && parts[8] == "cryptoKeyVersions"
                && [1, 3, 5, 7].iter().all(|i| {
                    let part = parts[*i];
                    (1..=63).contains(&part.len())
                        && part
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                })
                && parts[9]
                    .parse::<u64>()
                    .is_ok_and(|n| n > 0 && n.to_string() == parts[9]),
            "restore_signing_key_version_shape"
        );
        Ok(Self(value))
    }
}

impl From<KeyVersion> for String {
    fn from(value: KeyVersion) -> Self {
        value.0
    }
}

/// Fixed Ed25519 public key selection. No algorithm/provider choice or private
/// key is accepted. Point validity, actual version state/algorithm/public key
/// and permission must still be checked by the real exact-purpose native client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySelection {
    pub version: KeyVersion,
    pub public_key: [u8; 32],
}

impl KeySelection {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.public_key.iter().any(|b| *b != 0),
            "restore_signing_public_key_shape"
        );
        Ok(())
    }

    /// Version AND public bytes participate. This is an identity commitment,
    /// not a trusted revision, key-possession proof, clock or signing authority.
    pub fn commitment(&self) -> Result<Digest> {
        self.validate()?;
        Digest::of(&("day2-restore-approval-kms-selection-v1", self))
    }
}

#[cfg(test)]
mod tests;
