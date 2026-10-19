//! App-side initial-file observation under the actual original enrolled stage.
//! This does not construct a first holder, P3 acknowledgement or writer grant.
//! Only the closed peer/activation composition may consume it for that purpose.

use super::{
    FileIdentity, InitialPreparationImage, NativeAcquisition, PreparedFileProjection,
    observe_anchored_file,
};
#[cfg(target_os = "linux")]
use super::{INITIAL_FILE, IO_CHUNK_BYTES};
use crate::security_epoch::{
    native_enrollment::{EnrolledRoleStage, NativeRole},
    storage_authority::{DirectoryIdentity, directory_identity},
};
use anyhow::{Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy},
};
use std::fs::File;

const ANCHOR: &str = "/state/day2-native";

pub(crate) struct AppPreparedFile<'stage, 'role> {
    stage: &'stage mut EnrolledRoleStage<'role>,
    policy: InitialBootstrapPolicy,
    store: EpochStore,
    projection: PreparedFileProjection,
    image: InitialPreparationImage,
    directory: File,
    anchor: DirectoryIdentity,
    file: File,
    identity: FileIdentity,
    acquisition: NativeAcquisition,
    valid: bool,
}

impl<'stage, 'role> AppPreparedFile<'stage, 'role> {
    /// Opens only the existing fixed leaf, never CREATE, an arbitrary path or a
    /// supplied descriptor. The original role borrow cannot be replaced later.
    pub(crate) fn observe_existing(
        stage: &'stage mut EnrolledRoleStage<'role>,
        runtime: &crate::store::Runtime,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
        projection: PreparedFileProjection,
    ) -> Result<Self> {
        stage.check_selection(policy, store, NativeRole::AppHost)?;
        let mut acquisition = stage.narrow_io_acquisition(store.max_lease_seconds)?;
        projection.validate_selection(policy, store)?;
        let image = InitialPreparationImage::prepare(
            runtime,
            policy,
            store,
            projection.core.incarnations.clone(),
            &mut acquisition,
        )?;
        ensure!(
            image.core() == &projection.core
                && image.marker() == &projection.marker
                && image.bytes().len() as u64 == projection.length
                && Digest::new(image.bytes()) == projection.image,
            "app_prepared_admitted_image_mismatch"
        );
        stage.check_selection(policy, store, NativeRole::AppHost)?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (runtime, projection, image, acquisition);
            anyhow::bail!("app_prepared_file_platform_unsupported")
        }
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{Mode, OFlags, ResolveFlags};
            let directory = File::from(rustix::fs::open(
                ANCHOR,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )?);
            stage.check_selection(policy, store, NativeRole::AppHost)?;
            acquisition.remaining()?;
            let anchor = directory_identity(&directory)?;
            let file = File::from(rustix::fs::openat2(
                &directory,
                INITIAL_FILE,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
                ResolveFlags::BENEATH
                    | ResolveFlags::NO_SYMLINKS
                    | ResolveFlags::NO_MAGICLINKS
                    | ResolveFlags::NO_XDEV,
            )?);
            let identity = observe_anchored_file(&directory, &anchor, &file, image.bytes().len())?;
            let mut owner = Self {
                stage,
                policy: policy.clone(),
                store: store.clone(),
                projection,
                image,
                directory,
                anchor,
                file,
                identity,
                acquisition,
                valid: true,
            };
            owner.check_original()?;
            Ok(owner)
        }
    }

    fn check_identity(&mut self) -> Result<()> {
        ensure!(self.valid, "app_prepared_file_refused");
        self.stage
            .check_selection(&self.policy, &self.store, NativeRole::AppHost)?;
        self.acquisition.remaining()?;
        ensure!(
            directory_identity(&self.directory)? == self.anchor,
            "app_prepared_anchor_changed"
        );
        let observed = observe_anchored_file(
            &self.directory,
            &self.anchor,
            &self.file,
            self.image.bytes().len(),
        )?;
        ensure!(
            observed == self.identity,
            "app_prepared_file_identity_changed"
        );
        // The creator mount ID belongs to its own namespace. Compare the shared
        // device/inode/UID; retain and recheck this App's independent mount ID.
        let creator = &self.projection.identity;
        ensure!(
            observed.device_major == creator.device_major
                && observed.device_minor == creator.device_minor
                && observed.inode == creator.inode
                && observed.uid == creator.uid,
            "app_prepared_creator_file_mismatch"
        );
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{AtFlags, StatxFlags};
            let mask = StatxFlags::INO | StatxFlags::MNT_ID;
            let named = rustix::fs::statx(
                &self.directory,
                INITIAL_FILE,
                AtFlags::SYMLINK_NOFOLLOW,
                mask,
            )?;
            ensure!(
                named.stx_mask & mask.bits() == mask.bits()
                    && named.stx_ino == observed.inode
                    && named.stx_mnt_id == observed.mount
                    && named.stx_dev_major == observed.device_major
                    && named.stx_dev_minor == observed.device_minor,
                "app_prepared_leaf_changed"
            );
        }
        self.stage
            .check_selection(&self.policy, &self.store, NativeRole::AppHost)?;
        self.acquisition.remaining()?;
        Ok(())
    }

    pub(crate) fn check_original(&mut self) -> Result<()> {
        let result = (|| {
            self.check_identity()?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("app_prepared_file_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let mut bytes = vec![0_u8; self.image.bytes().len()];
                let mut offset = 0;
                while offset < bytes.len() {
                    self.check_identity()?;
                    let end = (offset + IO_CHUNK_BYTES).min(bytes.len());
                    let read =
                        rustix::io::pread(&self.file, &mut bytes[offset..end], offset as u64)?;
                    ensure!(
                        read > 0 && read <= end - offset,
                        "app_prepared_read_progress"
                    );
                    offset += read;
                    self.check_identity()?;
                }
                ensure!(
                    bytes == self.image.bytes(),
                    "app_prepared_file_bytes_changed"
                );
                self.image
                    .decode_exact_readback(&bytes, &mut self.acquisition)?;
                self.check_identity()
            }
        })();
        if result.is_err() {
            self.valid = false;
            self.acquisition.refuse();
        }
        result
    }

    pub(crate) fn projection(&mut self) -> Result<PreparedFileProjection> {
        self.check_original()?;
        Ok(self.projection.clone())
    }
}
