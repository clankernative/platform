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

#[cfg(test)]
pub(super) mod tests {
    use super::super::{AdminIdentity, signed::ApprovalStatement};
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    pub(in crate::security_epoch::restore_approval) fn fixture()
    -> Result<(EpochStore, SignedApprovalRecord)> {
        let selected = crate::security_epoch::tests::selection();
        let mut request = super::super::fixture_request_data()?;
        request.target.scope = selected.scope.clone();
        request.target.authority = selected.authority_key()?;
        request.target.selection = Digest::of(&selected)?;
        let pair = Ed25519KeyPair::from_seed_unchecked(&[31; 32]).unwrap();
        let selection=day2_capabilities::restore_signing::KeySelection{
            version:"projects/fixture/locations/global/keyRings/restore/cryptoKeys/approval/cryptoKeyVersions/7".to_owned().try_into()?,
            public_key:pair.public_key().as_ref().try_into()?,
        };
        let statement = ApprovalStatement {
            request,
            approver: AdminIdentity {
                email: "approver@example.org".into(),
                subject: "stable-subject".into(),
            },
            registry: Digest::new(b"registry"),
            credential: Digest::new(b"credential"),
            assertion: Digest::new(b"actual-fixture-assertion"),
            signing_key: selection.commitment()?,
        };
        let bytes = serde_json::to_vec(&("day2-restore-approval-grant-ed25519-v1", &statement))?;
        Ok((
            selected,
            SignedApprovalRecord {
                statement,
                signature: URL_SAFE_NO_PAD.encode(pair.sign(&bytes).as_ref()),
            },
        ))
    }

    #[test]
    fn publication_binds_full_record_authority_and_grant_in_a_distinct_stable_namespace()
    -> Result<()> {
        let (selected, record) = fixture()?;
        let value = Publication::record_data(&selected, record.clone())?;
        let encoded = value.encode(&selected)?;
        Publication::decode(&encoded, &selected, &record.statement.request.grant_id)?
            .require_exact(&selected, &record)?;
        let mut changed = record.clone();
        changed.statement.request.full_archive_digest = Digest::new(b"foreign-archive");
        assert!(value.require_exact(&selected, &changed).is_err());
        assert!(Publication::decode(&encoded, &selected, &Digest::new(b"other-grant")).is_err());
        let mut foreign = selected.clone();
        foreign.scope.app = "foreign".to_owned().try_into()?;
        assert!(
            Publication::decode(&encoded, &foreign, &record.statement.request.grant_id).is_err()
        );
        assert_ne!(
            key(&selected, &record.statement.request.grant_id)?,
            Digest::of(&(
                "day2-restore-approval-use-key-v1",
                selected.authority_key()?,
                &record.statement.request.grant_id
            ))?
        );
        let mut rotated = selected.clone();
        rotated.key_set = Digest::new(b"new-key-set");
        assert_eq!(
            key(&selected, &record.statement.request.grant_id)?,
            key(&rotated, &record.statement.request.grant_id)?
        );
        assert!(
            Publication::decode(&encoded, &rotated, &record.statement.request.grant_id).is_err()
        );
        let mut unknown = serde_json::to_value(&value)?;
        unknown["approved"] = true.into();
        assert!(
            Publication::decode(
                &serde_json::to_vec(&unknown)?,
                &selected,
                &record.statement.request.grant_id
            )
            .is_err()
        );
        let text = String::from_utf8(encoded)?;
        let duplicate = text.replacen(
            '{',
            "{\"format\":\"day2_restore_approval_publication_v1\",",
            1,
        );
        assert!(
            Publication::decode(
                duplicate.as_bytes(),
                &selected,
                &record.statement.request.grant_id
            )
            .is_err()
        );
        assert!(
            Publication::decode(
                &vec![b' '; MAX_BYTES + 1],
                &selected,
                &record.statement.request.grant_id
            )
            .is_err()
        );
        Ok(())
    }
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

    pub(in crate::security_epoch) fn grant_id_data(&self) -> &Digest {
        &self.record.statement.request.grant_id
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

    /// Full request equality is DATA validation only. It authenticates neither
    /// the signed record nor its executor and constructs no consuming owner.
    pub(in crate::security_epoch) fn require_request_data(
        &self,
        selected: &EpochStore,
        expected: &super::ApprovalRequest,
    ) -> Result<()> {
        self.validate(selected, &expected.grant_id)?;
        self.record.statement.request.require_exact(expected)
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
