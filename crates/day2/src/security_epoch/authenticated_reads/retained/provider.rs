//! Closed storage metadata reads from the SAME genuine full authentication.
//! Profile DATA narrows routes through its policy-bound digest; it cannot
//! construct this owner or select an epoch/counter write.
use super::{ControllerEpochReads, ProviderEpochReads, RefusalGuard, RetainedEpochReads};
use crate::security_epoch::{
    native_clock::NativeAcquisition, native_enrollment::EnrolledRoleStage,
    storage_authority::PersistentDiskSelection, transport::Route,
};
use anyhow::Result;
use day2_capabilities::security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy};
use std::rc::Rc;

#[derive(Clone, Copy)]
pub(in crate::security_epoch) enum StorageMetadataRead {
    Claim,
    Volume,
    Node,
    Disk,
    Instance,
}

impl StorageMetadataRead {
    pub(in crate::security_epoch) fn route<'a>(
        self,
        profile: &'a PersistentDiskSelection,
        policy: &'a InitialBootstrapPolicy,
    ) -> Route<'a> {
        match self {
            Self::Claim => Route::PersistentVolumeClaim {
                namespace: &policy.app.namespace.name,
                name: &profile.claim.name,
            },
            Self::Volume => Route::PersistentVolume(&profile.volume.name),
            Self::Node => Route::Node(&profile.node.name),
            Self::Disk => Route::ComputeDisk {
                zone: profile.zone.as_str(),
                name: profile.disk.as_str(),
            },
            Self::Instance => Route::ComputeInstance {
                zone: profile.zone.as_str(),
                name: profile.instance.as_str(),
            },
        }
    }

    pub(in crate::security_epoch) fn google(self) -> bool {
        matches!(self, Self::Disk | Self::Instance)
    }
}

impl ProviderEpochReads {
    pub(in crate::security_epoch) fn arm_refusal(&self) -> Result<RefusalGuard> {
        self.state.gate.guard()
    }

    pub(in crate::security_epoch) fn matches(&self, writer: &ControllerEpochReads) -> bool {
        Rc::ptr_eq(&self.state, &writer.state)
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.state.refuse();
    }

    pub(in crate::security_epoch) fn check(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            let use_guard = self.state.gate.enter()?;
            let mut material = self.state.material.try_borrow_mut()?;
            // Import the actual last provider view before sampling another
            // view; reversing that order could hide a rewind. Hand the actual
            // latest authenticated view back, with no scalar timestamp/max.
            material.acquisition.exchange_current_views(acquisition)?;
            material.check_bootstrap(stage, policy, store)?;
            material.acquisition.exchange_current_views(acquisition)?;
            drop(material);
            use_guard.complete()
        })();
        if result.is_err() {
            self.refuse();
            acquisition.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn get(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
        profile: &PersistentDiskSelection,
        operation: StorageMetadataRead,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Vec<u8>> {
        let result = (|| {
            self.check(stage, policy, store, acquisition)?;
            let use_guard = self.state.gate.enter()?;
            let mut material = self.state.material.try_borrow_mut()?;
            // Includes exact policy.fresh_storage.mount_binding digest and
            // immutable disk ID, not merely an arbitrary namespace/name.
            profile.validate(&material.policy)?;
            let route = operation.route(profile, policy);
            let authorization = if operation.google() {
                material.source.authorization()?
            } else {
                material.kubernetes.authorization()?
            };
            let RetainedEpochReads {
                http,
                acquisition: clock,
                ..
            } = &mut *material;
            let requested = http.request(route, &authorization, None, clock);
            let checked = material.check_bootstrap(stage, policy, store);
            let bytes = requested?;
            checked?;
            material.acquisition.exchange_current_views(acquisition)?;
            drop(material);
            use_guard.complete()?;
            Ok(bytes)
        })();
        if result.is_err() {
            self.refuse();
            acquisition.refuse();
        }
        result
    }
}
