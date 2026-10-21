//! App-side initial-file observation under the actual original enrolled stage.
//! This does not construct a first holder, P3 acknowledgement or writer grant.
//! Only the closed peer/activation composition may consume it for that purpose.

use super::{FileIdentity, NativeAcquisition, PreparedFileProjection, observe_anchored_file};
#[cfg(target_os = "linux")]
use super::{INITIAL_FILE, IO_CHUNK_BYTES, observe_current_anchored_file};
use crate::security_epoch::{
    native_enrollment::{
        AuthenticatedInitialHolderOffer, EnrolledRoleStage, NativeRole, SameEnrolledOwner,
    },
    preparation_image::ObservedInitialImage,
    storage_authority::{DirectoryIdentity, directory_identity},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy};
use std::{fs::File, thread::ThreadId};

const ANCHOR: &str = "/state/day2-native";

pub(crate) struct AppPreparedFile<'stage, 'role> {
    stage: &'stage mut EnrolledRoleStage<'role>,
    policy: InitialBootstrapPolicy,
    store: EpochStore,
    projection: PreparedFileProjection,
    image: Option<ObservedInitialImage>,
    directory: File,
    anchor: DirectoryIdentity,
    file: File,
    identity: FileIdentity,
    acquisition: NativeAcquisition,
    valid: bool,
}

/// Physical continuation of the SAME observed file after the original exchange.
/// It is not an activated holder, P3 acknowledgement or serving permission.
/// No pathname, descriptor, scalar grant or serialized projection can adopt it.
pub(crate) struct AppFileContinuity {
    owner: SameEnrolledOwner,
    policy: InitialBootstrapPolicy,
    store: EpochStore,
    projection: PreparedFileProjection,
    image: ObservedInitialImage,
    directory: File,
    anchor: DirectoryIdentity,
    file: File,
    identity: FileIdentity,
    process: u32,
    thread: ThreadId,
    valid: bool,
}

impl<'stage, 'role> AppPreparedFile<'stage, 'role> {
    /// Opens only the existing fixed leaf, never CREATE, an arbitrary path or a
    /// supplied descriptor. The original role borrow cannot be replaced later.
    pub(crate) fn observe_existing(
        stage: &'stage mut EnrolledRoleStage<'role>,
        runtime: &crate::store::InitialStoreMetadata,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
        offer: &mut AuthenticatedInitialHolderOffer,
    ) -> Result<Self> {
        // Authenticate the Controller and exact original exchange BEFORE any
        // file open, byte read or SQLite parsing; DATA cannot bypass this gate.
        let projection = offer.projection(stage, policy, store)?;
        stage.check_selection(policy, store, NativeRole::AppHost)?;
        let acquisition = stage.narrow_io_acquisition(store.max_lease_seconds)?;
        projection.validate_selection(policy, store)?;
        stage.check_selection(policy, store, NativeRole::AppHost)?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (runtime, projection, acquisition);
            anyhow::bail!("app_prepared_file_platform_unsupported")
        }
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{Mode, OFlags, ResolveFlags};
            let mut acquisition = acquisition;
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
            let identity =
                observe_anchored_file(&directory, &anchor, &file, projection.length.try_into()?)?;
            let mut owner = Self {
                stage,
                policy: policy.clone(),
                store: store.clone(),
                projection,
                image: None,
                directory,
                anchor,
                file,
                identity,
                acquisition,
                valid: true,
            };
            let bytes = owner.read_current()?;
            let image = ObservedInitialImage::admit(
                runtime,
                policy,
                store,
                owner.projection.core.clone(),
                &bytes,
                &owner.projection.image,
                &mut owner.acquisition,
            )?;
            owner.image = Some(image);
            owner.check_original()?;
            offer.check(owner.stage)?;
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
            self.projection.length.try_into()?,
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

    fn read_current(&mut self) -> Result<Vec<u8>> {
        self.check_identity()?;
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("app_prepared_file_platform_unsupported");
        #[cfg(target_os = "linux")]
        {
            let length = usize::try_from(self.projection.length)?;
            ensure!(
                (100..=super::MAX_IMAGE_BYTES).contains(&length),
                "app_prepared_image_bound"
            );
            let mut bytes = vec![0_u8; length];
            let mut offset = 0;
            while offset < bytes.len() {
                self.check_identity()?;
                let end = (offset + IO_CHUNK_BYTES).min(bytes.len());
                let read = rustix::io::pread(&self.file, &mut bytes[offset..end], offset as u64)?;
                ensure!(
                    read > 0 && read <= end - offset,
                    "app_prepared_read_progress"
                );
                offset += read;
                self.check_identity()?;
            }
            self.check_identity()?;
            Ok(bytes)
        }
    }

    pub(crate) fn check_original(&mut self) -> Result<()> {
        let result = (|| {
            let bytes = self.read_current()?;
            let image = self
                .image
                .as_ref()
                .context("app_prepared_image_not_admitted")?;
            ensure!(bytes == image.bytes(), "app_prepared_file_bytes_changed");
            image.decode_exact_readback(&bytes, &mut self.acquisition)?;
            self.check_identity()
        })();
        if result.is_err() {
            self.valid = false;
            self.acquisition.refuse();
        }
        result
    }

    /// Lend only the same originally borrowed stage, after current file checks.
    /// The fixed peer must recheck this file after its I/O before completion.
    pub(crate) fn app_stage(&mut self) -> Result<&mut EnrolledRoleStage<'role>> {
        self.check_original()?;
        Ok(self.stage)
    }

    /// The authenticated holder's consuming continuation calls this while its
    /// original offer/file checks still pass. Capture the actual enrollment
    /// identity before releasing the old stage; move descriptors without reopen.
    /// This transition alone grants no activation or later mutation permission.
    pub(crate) fn retain_physical(mut self) -> Result<AppFileContinuity> {
        let result = (|| {
            self.check_original()?;
            let owner = self.stage.capture_same_owner()?;
            self.check_original()?;
            Ok(owner)
        })();
        let owner = match result {
            Ok(owner) => owner,
            Err(error) => {
                self.refuse();
                return Err(error);
            }
        };
        Ok(AppFileContinuity {
            owner,
            policy: self.policy,
            store: self.store,
            projection: self.projection,
            // check_original above already requires this exact admitted image.
            image: self.image.context("app_prepared_image_not_admitted")?,
            directory: self.directory,
            anchor: self.anchor,
            file: self.file,
            identity: self.identity,
            process: std::process::id(),
            thread: std::thread::current().id(),
            valid: true,
        })
    }

    pub(crate) fn refuse(&mut self) {
        self.valid = false;
        self.acquisition.refuse();
    }

    pub(crate) fn projection(&mut self) -> Result<PreparedFileProjection> {
        self.check_original()?;
        Ok(self.projection.clone())
    }
}

impl AppFileContinuity {
    /// Checks physical continuity with a NEW bounded stage of the SAME live
    /// enrollment. It intentionally does not compare initial bytes or length:
    /// legitimate SQLite writes change those after activation. No active epoch,
    /// provider durability or writer permission is inferred from this check.
    pub(crate) fn check_current(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        let result = (|| {
            ensure!(self.valid, "app_file_continuity_refused");
            ensure!(
                self.process == std::process::id() && self.thread == std::thread::current().id(),
                "app_file_continuity_executor_changed"
            );
            self.owner.check(stage)?;
            stage.check_selection(&self.policy, &self.store, NativeRole::AppHost)?;
            ensure!(
                directory_identity(&self.directory)? == self.anchor,
                "app_file_continuity_anchor_changed"
            );
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("app_file_continuity_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags, StatxFlags};
                let acquisition = &mut stage.narrow_io_acquisition(self.store.max_lease_seconds)?;
                acquisition.remaining()?;
                use std::os::unix::fs::MetadataExt;
                let directory_metadata = self.directory.metadata()?;
                ensure!(
                    directory_metadata.mode() & 0o7777 == 0o700
                        && directory_metadata.uid() == self.identity.uid,
                    "app_file_continuity_directory_profile_changed"
                );
                // App writes may grow/shrink the SAME file between checks.
                // Size is not a physical identity and must not be sampled once
                // then compared against a later legitimate writer's size.
                let observed =
                    observe_current_anchored_file(&self.directory, &self.anchor, &self.file)?;
                ensure!(
                    observed == self.identity,
                    "app_file_continuity_file_changed"
                );
                let mask = StatxFlags::INO | StatxFlags::MNT_ID;
                let named = rustix::fs::statx(
                    &self.directory,
                    INITIAL_FILE,
                    AtFlags::SYMLINK_NOFOLLOW,
                    mask,
                )?;
                ensure!(
                    named.stx_mask & mask.bits() == mask.bits()
                        && named.stx_ino == self.identity.inode
                        && named.stx_mnt_id == self.identity.mount
                        && named.stx_dev_major == self.identity.device_major
                        && named.stx_dev_minor == self.identity.device_minor,
                    "app_file_continuity_leaf_changed"
                );
                // A retained directory alone does not establish that the actual
                // fixed App mount still names it. Observe its path separately;
                // never replace the retained directory with this temporary FD.
                let named_directory = File::from(rustix::fs::openat2(
                    rustix::fs::CWD,
                    ANCHOR,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                    ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )?);
                ensure!(
                    directory_identity(&named_directory)? == self.anchor,
                    "app_file_continuity_mount_path_changed"
                );
                acquisition.remaining()?;
                self.owner.check(stage)?;
                stage.check_selection(&self.policy, &self.store, NativeRole::AppHost)
            }
        })();
        if result.is_err() {
            self.valid = false;
        }
        result
    }

    /// Before first activation only. The caller cannot switch to an active
    /// interpretation merely because current physical identity still matches.
    pub(crate) fn check_initial(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        let result = (|| {
            self.check_current(stage)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("app_file_continuity_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let length = usize::try_from(self.projection.length)?;
                ensure!(
                    self.file.metadata()?.len() == self.projection.length,
                    "app_file_initial_length_changed"
                );
                let mut bytes = vec![0; length];
                let mut offset = 0;
                while offset < length {
                    self.check_current(stage)?;
                    let end = (offset + IO_CHUNK_BYTES).min(length);
                    let read =
                        rustix::io::pread(&self.file, &mut bytes[offset..end], offset as u64)?;
                    ensure!(
                        read > 0 && read <= end - offset,
                        "app_file_initial_read_progress"
                    );
                    offset += read;
                    self.check_current(stage)?;
                }
                let mut acquisition = stage.narrow_io_acquisition(self.store.max_lease_seconds)?;
                self.image.decode_exact_readback(&bytes, &mut acquisition)?;
                self.check_current(stage)
            }
        })();
        if result.is_err() {
            self.valid = false;
        }
        result
    }

    /// Terminal invalidation needs no live stage, clock or provider request.
    /// Restoring a name, dropping a phase or waiting cannot renew this owner.
    pub(crate) fn refuse(&mut self) {
        self.valid = false;
    }
}
