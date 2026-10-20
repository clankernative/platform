//! Retain the actual successfully prepared file across later bounded phases.
//! This owns continuity, not P3, activation, an app holder or writer authority.

#[cfg(target_os = "linux")]
use super::observe_anchored_file;
use super::{FileIdentity, OriginalCreatorFd, PreparedInitialFile, ReviewedFileLayout};
#[cfg(target_os = "linux")]
use crate::security_epoch::storage_authority::native_volume::CurrentVolumePhase;
use crate::security_epoch::{
    native_enrollment::{EnrolledRoleStage, SameEnrolledOwner},
    storage_authority::{
        DirectoryIdentity, ReviewedStorageSelection, native_volume::NativeVolumeContinuity,
    },
};
use anyhow::{Result, ensure};
use std::{fs::File, thread::ThreadId};

pub(crate) enum PreparedRetentionOutcome<'role> {
    Retained(PreparedFileContinuity),
    Refused {
        original: PreparedInitialFile<'role>,
        error: anyhow::Error,
    },
}

pub(crate) struct PreparedFileContinuity {
    selection: ReviewedStorageSelection,
    directory: File,
    anchor: DirectoryIdentity,
    file: File,
    identity: FileIdentity,
    layout: ReviewedFileLayout,
    volume: NativeVolumeContinuity,
    process: u32,
    thread: ThreadId,
    valid: bool,
}

impl PreparedFileContinuity {
    // Only retain_for_current_phases calls this, after the final original-clock
    // file check and genuine same-enrolled-owner capture. No fallible I/O or
    // descriptor reopen occurs between that check and retaining these owners.
    pub(super) fn retain(original: PreparedInitialFile<'_>, binding: SameEnrolledOwner) -> Self {
        let OriginalCreatorFd {
            authority,
            file,
            identity,
            ..
        } = original.creator;
        let volume = match authority.issuer {
            crate::security_epoch::storage_authority::StorageIssuerOwner::Native(volume) =>
                volume.retain_resources(binding),
            #[cfg(test)]
            crate::security_epoch::storage_authority::StorageIssuerOwner::UnqualifiedFilesystemFixture { .. } =>
                unreachable!("fixture retention is refused before consuming the original"),
        };
        Self {
            selection: authority.selection,
            directory: authority.directory,
            anchor: authority.identity,
            file,
            identity,
            layout: original.layout,
            volume,
            process: authority.process,
            thread: authority.thread,
            valid: true,
        }
    }

    /// A fixed unchanged-initial-file operation inside a fresh stage belonging
    /// to the SAME still-live controller. This does not resume preparation or
    /// create a current-use token. Legitimate later SQLite writes require a
    /// separately qualified activation/serving transition and refuse here.
    pub(crate) fn check_initial(&mut self, stage: EnrolledRoleStage<'_>) -> Result<()> {
        let result = (|| {
            ensure!(self.valid, "retained_preparation_refused");
            ensure!(
                self.process == std::process::id() && self.thread == std::thread::current().id(),
                "retained_preparation_owner_changed"
            );
            ensure!(
                self.layout.proposal.selection == *self.selection.digest()
                    && self.layout.proposal.core == *self.selection.seed()
                    && self.layout.proposal.length == self.layout.image.bytes().len(),
                "retained_preparation_layout_changed"
            );
            let mut phase = self.volume.begin_current(stage)?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = &mut phase;
                anyhow::bail!("original_file_platform_unsupported")
            }
            #[cfg(target_os = "linux")]
            {
                let mut bytes = vec![0_u8; self.layout.proposal.length];
                let mut offset = 0;
                while offset < bytes.len() {
                    check_identity(
                        &mut phase,
                        &self.directory,
                        &self.anchor,
                        &self.file,
                        &self.identity,
                        bytes.len(),
                    )?;
                    let end = (offset + super::IO_CHUNK_BYTES).min(bytes.len());
                    let read =
                        rustix::io::pread(&self.file, &mut bytes[offset..end], offset as u64)?;
                    ensure!(
                        read > 0 && read <= end - offset,
                        "retained_initial_read_progress"
                    );
                    offset += read;
                    check_identity(
                        &mut phase,
                        &self.directory,
                        &self.anchor,
                        &self.file,
                        &self.identity,
                        bytes.len(),
                    )?;
                }
                ensure!(
                    bytes == self.layout.image.bytes(),
                    "retained_initial_bytes_changed"
                );
                check_identity(
                    &mut phase,
                    &self.directory,
                    &self.anchor,
                    &self.file,
                    &self.identity,
                    bytes.len(),
                )
            }
        })();
        if result.is_err() {
            self.valid = false;
        }
        result
    }
}

#[cfg(target_os = "linux")]
fn check_identity(
    phase: &mut CurrentVolumePhase<'_, '_>,
    directory: &File,
    anchor: &DirectoryIdentity,
    file: &File,
    identity: &FileIdentity,
    length: usize,
) -> Result<()> {
    use rustix::fs::{AtFlags, StatxFlags};
    phase.check_directory(directory, anchor)?;
    phase.acquisition().remaining()?;
    let observed = observe_anchored_file(directory, anchor, file, length)?;
    ensure!(observed == *identity, "retained_initial_file_changed");
    let flags = StatxFlags::INO | StatxFlags::MNT_ID;
    let named = rustix::fs::statx(
        directory,
        super::INITIAL_FILE,
        AtFlags::SYMLINK_NOFOLLOW,
        flags,
    )?;
    ensure!(
        named.stx_mask & flags.bits() == flags.bits()
            && named.stx_ino == identity.inode
            && named.stx_mnt_id == identity.mount
            && named.stx_dev_major == identity.device_major
            && named.stx_dev_minor == identity.device_minor,
        "retained_initial_leaf_changed"
    );
    phase.acquisition().remaining()?;
    phase.check_directory(directory, anchor)
}
