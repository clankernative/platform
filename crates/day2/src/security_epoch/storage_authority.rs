//! Storage creation's owning boundary. No production issuer or factory exists.
//! The empty production issuer enum makes that absence explicit in the type.
//! Namespace, image, Kubernetes and volume DATA cannot construct this owner.

use super::{firestore::Budget, native_clock::NativeAcquisition, seed_core::OriginalSeedCore};
use anyhow::{Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs::File, marker::PhantomData, rc::Rc, thread::ThreadId};

mod preparation;
pub(crate) use preparation::{
    BeforeAttemptRefusal, NativeOriginalPreparationOutcome, OriginalCreatorFd,
    PreparationCoordinator, RefusedOriginalPreparation,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionData {
    policy: InitialBootstrapPolicy,
    store: EpochStore,
    seed: OriginalSeedCore,
}

/// Checked selection DATA; neither the name nor its digest supplies an issuer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ReviewedStorageSelection {
    data: SelectionData,
    digest: Digest,
}

impl ReviewedStorageSelection {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 65_536, "storage_selection_bound");
        let value: serde_json::Value = crate::json::decode(bytes)?;
        ensure!(value.is_object(), "storage_selection_object_required");
        for field in ["policy", "store", "seed"] {
            ensure!(
                value.get(field).is_some_and(serde_json::Value::is_object),
                "storage_selection_record_object_required"
            );
        }
        let data: SelectionData = serde_json::from_value(value)?;
        data.policy.validate(&BTreeMap::from([(
            data.policy.epoch_store.id.clone(),
            data.store.clone(),
        )]))?;
        data.seed.validate(&data.policy, &data.store)?;
        let digest = Digest::of(&("day2-native-storage-selection-v1", &data))?;
        Ok(Self { data, digest })
    }

    pub(super) fn digest(&self) -> &Digest {
        &self.digest
    }

    pub(super) fn policy(&self) -> &InitialBootstrapPolicy {
        &self.data.policy
    }

    pub(super) fn store(&self) -> &EpochStore {
        &self.data.store
    }

    pub(super) fn seed(&self) -> &OriginalSeedCore {
        &self.data.seed
    }
}

#[derive(PartialEq, Eq)]
struct DirectoryIdentity {
    #[cfg(target_os = "linux")]
    filesystem: rustix::fs::FsWord,
    device_major: u32,
    device_minor: u32,
    inode: u64,
    mount: u64,
}

/// There are deliberately NO production variants or constructors. An actual
/// runtime/role/provider issuer must be implemented and reviewed before this
/// can contain an actual owning witness. Do not replace it with a boolean,
/// receipt, scalar identity or a blanket successful check.
enum StorageIssuerOwner {
    #[cfg(test)]
    UnqualifiedFilesystemFixture {
        domain: Digest,
        process: u32,
        thread: ThreadId,
    },
}

impl StorageIssuerOwner {
    fn check_current(&mut self, acquisition: &mut NativeAcquisition) -> Result<()> {
        let sample = acquisition.sample()?;
        let _ = &sample;
        match *self {
            #[cfg(test)]
            Self::UnqualifiedFilesystemFixture {
                ref domain,
                process,
                ref thread,
            } => {
                ensure!(
                    sample.domain == *domain
                        && std::process::id() == process
                        && std::thread::current().id() == *thread,
                    "storage_fixture_owner_changed"
                );
                Ok(())
            }
        }
    }
}

enum StorageRefusal {
    CurrentCheckFailed,
    PreparationFailed,
}

/// Not constructible in production. Root's closed preparation child will own
/// fixed file operations with private access to these anchors. No descriptor
/// getter, AsFd/AsRawFd, clone/dup/export or callback API is supplied.
pub(crate) struct NativeStorageCreationAuthority {
    selection: ReviewedStorageSelection,
    directory: File,
    identity: DirectoryIdentity,
    issuer: StorageIssuerOwner,
    preparation: Budget,
    process: u32,
    thread: ThreadId,
    refusal: Option<StorageRefusal>,
    local: PhantomData<Rc<()>>,
}

impl NativeStorageCreationAuthority {
    pub(super) fn check_current(&mut self, acquisition: &mut NativeAcquisition) -> Result<()> {
        let result = (|| {
            ensure!(self.refusal.is_none(), "storage_creation_authority_refused");
            self.preparation.remaining_native(acquisition)?;
            ensure!(
                std::process::id() == self.process && std::thread::current().id() == self.thread,
                "storage_creation_owner_changed"
            );
            let identity = directory_identity(&self.directory)?;
            ensure!(identity == self.identity, "storage_creation_anchor_changed");
            self.preparation.remaining_native(acquisition)?;
            // An actual issuer must also perform its actual current runtime,
            // role, provider and fresh anchor-path join. No production variant
            // exists, so these filesystem checks cannot authorize creation.
            self.issuer.check_current(acquisition)?;
            self.preparation.remaining_native(acquisition)?;
            Ok(())
        })();
        if result.is_err() {
            self.refusal = Some(StorageRefusal::CurrentCheckFailed);
            acquisition.refuse();
        }
        result
    }

    /// This refusal retains every owned descriptor; it grants no retry or
    /// future use and cannot be cleared by another acquisition.
    fn refuse_preparation(&mut self, acquisition: &mut NativeAcquisition) {
        self.refusal = Some(StorageRefusal::PreparationFailed);
        acquisition.refuse();
    }

    /// Only unqualified filesystem fault controls may create a test owner.
    /// This is not runtime, role, provider, volume or P3 qualification.
    #[cfg(test)]
    fn filesystem_fixture(
        selection: ReviewedStorageSelection,
        directory: File,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Self> {
        let result = (|| {
            let sample = acquisition.sample()?;
            let preparation = acquisition.budget()?;
            let process = std::process::id();
            let thread = std::thread::current().id();
            let identity = directory_identity(&directory)?;
            acquisition.remaining()?;
            let mut authority = Self {
                selection,
                directory,
                identity,
                issuer: StorageIssuerOwner::UnqualifiedFilesystemFixture {
                    domain: sample.domain,
                    process,
                    thread,
                },
                preparation,
                process,
                thread,
                refusal: None,
                local: PhantomData,
            };
            authority.check_current(acquisition)?;
            Ok(authority)
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }
}

#[cfg(target_os = "linux")]
fn directory_identity(file: &File) -> Result<DirectoryIdentity> {
    use rustix::fs::{AtFlags, StatxFlags};
    ensure!(
        file.metadata()?.is_dir(),
        "storage_creation_directory_required"
    );
    let filesystem = rustix::fs::fstatfs(file)?;
    let mask = StatxFlags::INO | StatxFlags::MNT_ID;
    let observed = rustix::fs::statx(file, "", AtFlags::EMPTY_PATH, mask)?;
    ensure!(
        observed.stx_mask & mask.bits() == mask.bits()
            && observed.stx_ino != 0
            && observed.stx_mnt_id != 0,
        "storage_creation_anchor_identity_required"
    );
    Ok(DirectoryIdentity {
        filesystem: filesystem.f_type,
        device_major: observed.stx_dev_major,
        device_minor: observed.stx_dev_minor,
        inode: observed.stx_ino,
        mount: observed.stx_mnt_id,
    })
}

#[cfg(not(target_os = "linux"))]
fn directory_identity(_file: &File) -> Result<DirectoryIdentity> {
    anyhow::bail!("storage_creation_directory_platform_unsupported")
}

#[cfg(test)]
mod tests;
