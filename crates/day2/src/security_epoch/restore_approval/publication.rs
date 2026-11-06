//! Immutable publication DATA. Only a genuine native producer may create its
//! provider document; decoding a signature or this record constructs no owner.
use super::signed::SignedApprovalRecord;
use anyhow::{Result, ensure};
use day2_capabilities::{Digest, security_epoch::EpochStore};
use serde::{Deserialize, Serialize};

const MAX_BYTES: usize = 20_480;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Format {
    #[serde(rename = "day2_restore_approval_publication_v1")]
    V1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Publication {
    format: Format,
    authority: Digest,
    record: SignedApprovalRecord,
}

/// Stable across process, target epoch/incarnation and signing-key rotation.
/// Its namespace is distinct from G1's consuming approval-use receipt.
pub(in crate::security_epoch) fn key(selected: &EpochStore, grant: &Digest) -> Result<Digest> {
    Digest::of(&(
        "day2-restore-approval-publication-key-v1",
        selected.authority_key()?,
        grant,
    ))
}

impl Publication {
    pub(in crate::security_epoch) fn record_data(
        selected: &EpochStore,
        record: SignedApprovalRecord,
    ) -> Result<Self> {
        let value = Self {
            format: Format::V1,
            authority: selected.authority_key()?,
            record,
        };
        value.validate(selected, &value.record.statement.request.grant_id)?;
        Ok(value)
    }

    fn validate(&self, selected: &EpochStore, grant: &Digest) -> Result<()> {
        selected.validate()?;
        let request = &self.record.statement.request;
        ensure!(
            self.format == Format::V1
                && self.authority == selected.authority_key()?
                && request.grant_id == *grant
                && request.target.authority == self.authority
                && request.target.scope == selected.scope
                && request.target.selection == Digest::of(selected)?,
            "restore_approval_publication_binding"
        );
        self.record.encode()?;
        Ok(())
    }

    pub(in crate::security_epoch) fn decode(
        bytes: &[u8],
        selected: &EpochStore,
        grant: &Digest,
    ) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_BYTES,
            "restore_approval_publication_bound"
        );
        let value: Self = crate::json::decode(bytes)
            .map_err(|_| anyhow::anyhow!("restore_approval_publication_encoding"))?;
        value.validate(selected, grant)?;
        Ok(value)
    }

    pub(in crate::security_epoch) fn encode(&self, selected: &EpochStore) -> Result<Vec<u8>> {
        self.validate(selected, &self.record.statement.request.grant_id)?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_BYTES,
            "restore_approval_publication_bound"
        );
        Ok(bytes)
    }

    pub(in crate::security_epoch) fn require_exact(
        &self,
        selected: &EpochStore,
        expected: &SignedApprovalRecord,
    ) -> Result<()> {
        self.validate(selected, &expected.statement.request.grant_id)?;
        ensure!(
            &self.record == expected,
            "restore_approval_publication_changed"
        );
        Ok(())
    }
}
