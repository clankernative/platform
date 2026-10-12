//! Closed instance selection for security authority outside an app backup.
//! These contracts select a resource; they never constitute current readiness.

use crate::{Digest, Name};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityScope {
    pub installation: Name,
    pub environment: Name,
    pub app: Name,
}

/// A stored epoch value is historical data, not an authority proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecurityEpoch(NonZeroU64);

impl SecurityEpoch {
    pub fn value(self) -> u64 {
        self.0.get()
    }

    pub fn successor(self) -> Result<Self> {
        self.value()
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("security_epoch_exhausted"))?
            .try_into()
    }
}

impl TryFrom<u64> for SecurityEpoch {
    type Error = anyhow::Error;

    fn try_from(value: u64) -> Result<Self> {
        Ok(Self(NonZeroU64::new(value).ok_or_else(|| {
            anyhow::anyhow!("invalid_security_epoch")
        })?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EpochProvider {
    FirestoreNativeV1 {
        project: Name,
        project_number: NonZeroU64,
        database: Name,
        /// System-generated database identity, checked by the live adapter.
        database_uid: String,
        iam_source: EpochIam,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EpochIam {
    GkeWorkloadIdentityV1 { service_account: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochStore {
    pub scope: AuthorityScope,
    pub provider: EpochProvider,
    /// Includes exact key bindings, purposes and immutable versions.
    pub key_set: Digest,
    pub max_lease_seconds: u32,
}

impl EpochStore {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=60).contains(&self.max_lease_seconds),
            "security_epoch_freshness_budget"
        );
        let EpochProvider::FirestoreNativeV1 {
            project,
            database_uid,
            iam_source,
            ..
        } = &self.provider;
        let project = project.as_str();
        ensure!(
            (6..=30).contains(&project.len())
                && project.as_bytes()[0].is_ascii_lowercase()
                && project
                    .as_bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && project
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
            "invalid_security_epoch_project"
        );
        let EpochIam::GkeWorkloadIdentityV1 { service_account } = iam_source;
        crate::oauth::ShellTransport {
            service_account: service_account.clone(),
        }
        .validate()?;
        ensure!(
            database_uid.len() == 36
                && database_uid.bytes().enumerate().all(|(index, byte)| {
                    if matches!(index, 8 | 13 | 18 | 23) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                    }
                }),
            "invalid_security_epoch_database_uid"
        );
        Ok(())
    }

    /// The immutable database UID participates in every app authority key.
    pub fn authority_key(&self) -> Result<Digest> {
        self.validate()?;
        let EpochProvider::FirestoreNativeV1 {
            project_number,
            database_uid,
            ..
        } = &self.provider;
        // IAM and named selectors are replaceable access/configuration. Their
        // complete BindingRef remains pinned, but rotating them must not create
        // another counter for the same immutable database and app scope.
        Digest::of(&(
            "day2-security-authority-firestore-v1",
            project_number,
            database_uid,
            &self.scope,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selection() -> EpochStore {
        EpochStore {
            scope: AuthorityScope {
                installation: "company".to_owned().try_into().unwrap(),
                environment: "staging".to_owned().try_into().unwrap(),
                app: "reports".to_owned().try_into().unwrap(),
            },
            provider: EpochProvider::FirestoreNativeV1 {
                project: "project-seven".to_owned().try_into().unwrap(),
                project_number: NonZeroU64::new(7).unwrap(),
                database: "security".to_owned().try_into().unwrap(),
                database_uid: "01234567-89ab-4cde-8fab-0123456789ab".into(),
                iam_source: EpochIam::GkeWorkloadIdentityV1 {
                    service_account: "epoch@project-seven.iam.gserviceaccount.com".into(),
                },
            },
            key_set: Digest::new(b"exact keys"),
            max_lease_seconds: 30,
        }
    }

    #[test]
    fn epoch_cannot_wrap_or_admit_zero() {
        assert!(SecurityEpoch::try_from(0).is_err());
        assert!(
            SecurityEpoch::try_from(u64::MAX)
                .unwrap()
                .successor()
                .is_err()
        );
        assert_eq!(
            SecurityEpoch::try_from(1)
                .unwrap()
                .successor()
                .unwrap()
                .value(),
            2
        );
    }

    #[test]
    fn recreated_database_is_a_different_authority() {
        let original = selection();
        let mut recreated = original.clone();
        let EpochProvider::FirestoreNativeV1 { database_uid, .. } = &mut recreated.provider;
        *database_uid = "11234567-89ab-4cde-8fab-0123456789ab".into();
        assert_ne!(
            original.authority_key().unwrap(),
            recreated.authority_key().unwrap()
        );
    }

    #[test]
    fn rotating_access_selector_preserves_the_scoped_counter_identity() {
        let original = selection();
        let mut rotated = original.clone();
        let EpochProvider::FirestoreNativeV1 { iam_source, .. } = &mut rotated.provider;
        *iam_source = EpochIam::GkeWorkloadIdentityV1 {
            service_account: "successor@project-seven.iam.gserviceaccount.com".into(),
        };
        assert_eq!(
            original.authority_key().unwrap(),
            rotated.authority_key().unwrap()
        );
        assert_ne!(
            Digest::of(&original).unwrap(),
            Digest::of(&rotated).unwrap()
        );
    }

    #[test]
    fn invalid_or_unbounded_selection_fails_closed() {
        let mut store = selection();
        store.max_lease_seconds = 0;
        assert!(store.validate().is_err());
        store.max_lease_seconds = 61;
        assert!(store.validate().is_err());
        store.max_lease_seconds = 30;
        let EpochProvider::FirestoreNativeV1 { database_uid, .. } = &mut store.provider;
        *database_uid = "same-name-is-not-an-identity".into();
        assert!(store.validate().is_err());
    }
}
