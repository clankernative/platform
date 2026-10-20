//! Controller-only native storage creation. The native factory consumes an
//! enrolled controller and performs real provider/device/mount acquisition.
//! Namespace, Kubernetes and volume DATA cannot construct the native owner.
//! Live profile qualification and current counter/writer admission are separate.

use super::{firestore::Budget, native_clock::NativeAcquisition, seed_core::OriginalSeedCore};
use anyhow::{Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs::File, marker::PhantomData, rc::Rc, thread::ThreadId};

mod native_volume;
use native_volume::NativeVolumeObservation;
mod persistent_disk;
mod preparation;
pub(crate) use preparation::{
    AppPreparedFile, BeforeAttemptRefusal, CurrentPreparedFilePhase,
    NativeOriginalPreparationOutcome, OriginalCreatorFd, PreparationCoordinator,
    PreparedFileContinuity, PreparedFileProjection, PreparedInitialFile, PreparedRetentionOutcome,
    RefusedOriginalPreparation,
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

/// Retains the actual enrolled stage and provider/mount owners. The controlled
/// filesystem fixture remains a distinct test-only variant, never a fallback.
enum StorageIssuerOwner<'role> {
    Native(Box<NativeVolumeObservation<'role>>),
    #[cfg(test)]
    UnqualifiedFilesystemFixture {
        domain: Digest,
        process: u32,
        thread: ThreadId,
    },
}

impl StorageIssuerOwner<'_> {
    fn check_current(
        &mut self,
        directory: &File,
        identity: &DirectoryIdentity,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let sample = acquisition.sample()?;
        let _ = &sample;
        match *self {
            Self::Native(ref mut volume) => volume.check_directory(directory, identity),
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

/// The native factory owns fixed file operations and the actual enrolled
/// controller/provider anchors. No descriptor
/// getter, AsFd/AsRawFd, clone/dup/export or callback API is supplied.
pub(crate) struct NativeStorageCreationAuthority<'role> {
    selection: ReviewedStorageSelection,
    directory: File,
    identity: DirectoryIdentity,
    issuer: StorageIssuerOwner<'role>,
    preparation: Budget,
    process: u32,
    thread: ThreadId,
    refusal: Option<StorageRefusal>,
    local: PhantomData<Rc<()>>,
}

impl<'role> NativeStorageCreationAuthority<'role> {
    /// The only native creation factory consumes an actual enrolled controller
    /// stage and performs the fixed provider/device/mount acquisition itself.
    /// Nothing accepts an issuer flag, parsed provider proof or caller FD.
    pub(super) fn acquire_initial(
        stage: crate::security_epoch::native_enrollment::EnrolledRoleStage<'role>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
    ) -> Result<(Self, NativeAcquisition)> {
        let mut volume = NativeVolumeObservation::acquire(stage, policy, store)?;
        let seed = volume.original_seed()?;
        let selection = ReviewedStorageSelection::decode(&serde_json::to_vec(&SelectionData {
            policy: policy.clone(),
            store: store.clone(),
            seed,
        })?)?;
        let (directory, identity, mut acquisition) = volume.create_initial_directory()?;
        let preparation = acquisition.budget()?;
        let mut authority = Self {
            selection,
            directory,
            identity,
            issuer: StorageIssuerOwner::Native(Box::new(volume)),
            preparation,
            process: std::process::id(),
            thread: std::thread::current().id(),
            refusal: None,
            local: PhantomData,
        };
        authority.check_current(&mut acquisition)?;
        Ok((authority, acquisition))
    }
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
            // The native issuer performs current role, original provider lease,
            // actual device/mount and fresh private-anchor path joins.
            self.issuer
                .check_current(&self.directory, &self.identity, acquisition)?;
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
