//! Acyclic public seed and marker projections. These values are DATA. A copied
//! core/marker or matching hash cannot reconstruct an original CreatorFD,
//! durable-preparation ACK, current file, app key or process capability.

use super::{
    control_slot::create_operation,
    kernel::{Bootstrap, Manifest},
};
use anyhow::{Result, ensure};
use day2_capabilities::{
    Digest, Name,
    security_epoch::{
        AuthorityScope, EpochProvider, EpochStore, bootstrap::InitialBootstrapPolicy,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SeedFormat {
    Day2OriginalSeedV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Incarnations {
    pub record: Digest,
    pub database: Digest,
    pub activation: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalSeedCore {
    pub format: SeedFormat,
    pub policy: Digest,
    pub authority: Digest,
    pub scope: AuthorityScope,
    pub project_number: String,
    pub database_uid: String,
    pub key_set: Digest,
    pub controller_role: Digest,
    pub provider_volume_uid: String,
    pub mount_binding: Digest,
    pub schema_contract: Digest,
    pub artifact: Digest,
    pub app_workload: Digest,
    pub marker_format: Name,
    pub incarnations: Incarnations,
}

impl OriginalSeedCore {
    pub(super) fn new(
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
        incarnations: Incarnations,
    ) -> Result<Self> {
        let stores = BTreeMap::from([(policy.epoch_store.id.clone(), store.clone())]);
        policy.validate(&stores)?;
        let EpochProvider::FirestoreNativeV1 {
            project_number,
            database_uid,
            ..
        } = &store.provider;
        Ok(Self {
            format: SeedFormat::Day2OriginalSeedV1,
            policy: policy.digest(&stores)?,
            authority: store.authority_key()?,
            scope: store.scope.clone(),
            project_number: project_number.to_string(),
            database_uid: database_uid.clone(),
            key_set: store.key_set.clone(),
            controller_role: Digest::of(&(
                "day2-stable-controller-selection-v1",
                &policy.cluster,
                &policy.controller,
            ))?,
            provider_volume_uid: policy.fresh_storage.provider_volume_uid.clone(),
            mount_binding: policy.fresh_storage.mount_binding.clone(),
            schema_contract: policy.fresh_storage.schema_contract.clone(),
            artifact: policy.runtime_profile.app_artifact.clone(),
            app_workload: Digest::of(&(
                "day2-stable-app-selection-v1",
                &policy.cluster,
                &policy.app,
            ))?,
            marker_format: policy.fresh_storage.marker_format.clone(),
            incarnations,
        })
    }

    pub(super) fn digest(&self) -> Result<Digest> {
        // No actual marker digest, operation/request/receipt ID, after-state,
        // holder, attempt, clock, challenge or executor incarnation is present.
        Digest::of(&("day2-original-seed-core-v1", self))
    }

    pub(super) fn validate(
        &self,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
    ) -> Result<()> {
        ensure!(
            *self == Self::new(policy, store, self.incarnations.clone())?,
            "control_seed_selection_mismatch"
        );
        Ok(())
    }

    pub(super) fn marker(&self) -> Result<InitialMarker> {
        Ok(InitialMarker {
            marker_format: self.marker_format.clone(),
            seed: self.digest()?,
            schema: self.schema_contract.clone(),
        })
    }

    pub(super) fn bootstrap(&self) -> Result<Bootstrap> {
        let seed = self.digest()?;
        Ok(Bootstrap {
            authority: self.authority.clone(),
            scope: self.scope.clone(),
            project_number: self.project_number.clone(),
            database_uid: self.database_uid.clone(),
            record_incarnation: self.incarnations.record.clone(),
            key_set: self.key_set.clone(),
            policy: self.policy.clone(),
            controller_role: self.controller_role.clone(),
            create_operation: create_operation(&self.authority, &seed)?,
            manifest: Manifest {
                activation: self.incarnations.activation.clone(),
                database_incarnation: self.incarnations.database.clone(),
                provider_volume_uid: self.provider_volume_uid.clone(),
                mount_binding: self.mount_binding.clone(),
                schema: self.schema_contract.clone(),
                marker: self.marker()?.digest()?,
                artifact: self.artifact.clone(),
                app_workload: self.app_workload.clone(),
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InitialMarker {
    pub marker_format: Name,
    pub seed: Digest,
    pub schema: Digest,
}

impl InitialMarker {
    pub(super) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-initial-marker-v1", self))
    }
}
