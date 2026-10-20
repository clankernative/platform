//! Retain the actual successfully prepared file across later bounded phases.
//! This owns continuity, not P3, activation, an app holder or writer authority.

use super::{
    FileIdentity, OriginalCreatorFd, PreparedFileProjection, PreparedInitialFile,
    ReviewedFileLayout,
};
#[cfg(target_os = "linux")]
use super::{observe_anchored_file, observe_current_anchored_file};
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
    Retained(Box<PreparedFileContinuity>),
    Refused {
        original: Box<PreparedInitialFile<'role>>,
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

/// Borrows the SAME retained file/device owners and owns one fresh actual
/// controller stage. It is neither a first-holder proof nor a writer permit.
/// An unfinished phase leaves its parent refused without relying on Drop.
pub(crate) struct CurrentPreparedFilePhase<'file, 'role> {
    phase: CurrentVolumePhase<'file, 'role>,
    selection: &'file ReviewedStorageSelection,
    directory: &'file File,
    anchor: &'file DirectoryIdentity,
    file: &'file File,
    identity: &'file FileIdentity,
    layout: &'file ReviewedFileLayout,
    process: u32,
    thread: ThreadId,
    disposition: FilePhaseDisposition<'file>,
}

/// A current physical-file phase after legitimate application writes. It is
/// deliberately distinct from CurrentPreparedFilePhase: the initial exchange
/// cannot accept it or reinterpret modified bytes as a prepared initial image.
/// It supplies no provider P3, activation, counter or current writer authority.
pub(crate) struct CurrentPhysicalFilePhase<'file, 'role> {
    inner: CurrentPreparedFilePhase<'file, 'role>,
}

/// Pessimistically close continuity before any fallible phase work. Only the
/// fixed operation's known successful final check may restore it. This helper
/// has no native constructor, clock, descriptor or authority of its own.
struct FilePhaseDisposition<'file> {
    continuation: &'file mut bool,
    active: bool,
}

impl<'file> FilePhaseDisposition<'file> {
    fn begin(continuation: &'file mut bool) -> Result<Self> {
        ensure!(*continuation, "retained_preparation_refused");
        *continuation = false;
        Ok(Self {
            continuation,
            active: true,
        })
    }

    fn check(&self) -> Result<()> {
        ensure!(
            self.active && !*self.continuation,
            "retained_file_phase_refused"
        );
        Ok(())
    }

    fn refuse(&mut self) {
        self.active = false;
    }

    fn complete(self) -> Result<()> {
        self.check()?;
        *self.continuation = true;
        Ok(())
    }
}

impl<'role> PreparedInitialFile<'role> {
    /// Consume only a SUCCESSFULLY checked preparation. On any failure the
    /// original file/anchor/stage remain owned by the refused outcome. A later
    /// acquisition cannot restart an expired or failed preparation.
    pub(crate) fn retain_for_current_phases(mut self) -> PreparedRetentionOutcome<'role> {
        let binding = (|| {
            self.check_original()?;
            let binding = match &mut self.creator.authority.issuer {
                crate::security_epoch::storage_authority::StorageIssuerOwner::Native(volume) => volume.capture_same_owner()?,
                #[cfg(test)]
                crate::security_epoch::storage_authority::StorageIssuerOwner::UnqualifiedFilesystemFixture { .. } => {
                    anyhow::bail!("storage_native_retention_requires_enrolled_controller")
                }
            };
            self.check_original()?;
            Ok(binding)
        })();
        match binding {
            Ok(binding) => PreparedRetentionOutcome::Retained(Box::new(
                PreparedFileContinuity::retain(self, binding),
            )),
            Err(error) => {
                self.creator
                    .authority
                    .refuse_preparation(&mut self.acquisition);
                PreparedRetentionOutcome::Refused {
                    original: Box::new(self),
                    error,
                }
            }
        }
    }
}

impl PreparedFileContinuity {
    // Only retain_for_current_phases calls this, after the final original-clock
    // file check and genuine same-enrolled-owner capture. No fallible I/O or
    // descriptor reopen occurs between that check and retaining these owners.
    fn retain(original: PreparedInitialFile<'_>, binding: SameEnrolledOwner) -> Self {
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

    /// Completed preparation is not renewed. All provider reads, file checks
    /// and later peer work spend THIS stage's original interval. An abandoned,
    /// failed or unknown operation cannot start another phase on this file.
    pub(crate) fn begin_initial_phase<'file, 'role>(
        &'file mut self,
        stage: EnrolledRoleStage<'role>,
    ) -> Result<CurrentPreparedFilePhase<'file, 'role>> {
        let disposition = FilePhaseDisposition::begin(&mut self.valid)?;
        let phase = self.volume.begin_current(stage)?;
        let mut current = CurrentPreparedFilePhase {
            phase,
            selection: &self.selection,
            directory: &self.directory,
            anchor: &self.anchor,
            file: &self.file,
            identity: &self.identity,
            layout: &self.layout,
            process: self.process,
            thread: self.thread,
            disposition,
        };
        current.check()?;
        Ok(current)
    }

    /// Own a fresh provider/device/mount phase on the SAME original file.
    /// Closing the continuation before any I/O retains abandonment/refusal.
    /// Only native activation/serving composition may use this physical input;
    /// constructing it alone never grants an active writer or control send.
    pub(crate) fn begin_physical_phase<'file, 'role>(
        &'file mut self,
        stage: EnrolledRoleStage<'role>,
    ) -> Result<CurrentPhysicalFilePhase<'file, 'role>> {
        let disposition = FilePhaseDisposition::begin(&mut self.valid)?;
        let phase = self.volume.begin_current(stage)?;
        let mut current = CurrentPhysicalFilePhase {
            inner: CurrentPreparedFilePhase {
                phase,
                selection: &self.selection,
                directory: &self.directory,
                anchor: &self.anchor,
                file: &self.file,
                identity: &self.identity,
                layout: &self.layout,
                process: self.process,
                thread: self.thread,
                disposition,
            },
        };
        current.check()?;
        Ok(current)
    }

    /// Read-only continuity observation; it grants no peer, P3 or writer
    /// authority. Legitimate later writes need the serving transition.
    pub(crate) fn check_initial(&mut self, stage: EnrolledRoleStage<'_>) -> Result<()> {
        self.begin_initial_phase(stage)?.finish_checked()
    }
}

impl<'file, 'role> CurrentPreparedFilePhase<'file, 'role> {
    pub(crate) fn check(&mut self) -> Result<()> {
        let result = (|| {
            self.disposition.check()?;
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
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("original_file_platform_unsupported")
            }
            #[cfg(target_os = "linux")]
            {
                let mut bytes = vec![0_u8; self.layout.proposal.length];
                let mut offset = 0;
                while offset < bytes.len() {
                    check_identity(
                        &mut self.phase,
                        self.directory,
                        self.anchor,
                        self.file,
                        self.identity,
                        Some(bytes.len()),
                    )?;
                    let end = (offset + super::IO_CHUNK_BYTES).min(bytes.len());
                    let read =
                        rustix::io::pread(self.file, &mut bytes[offset..end], offset as u64)?;
                    ensure!(
                        read > 0 && read <= end - offset,
                        "retained_initial_read_progress"
                    );
                    offset += read;
                    check_identity(
                        &mut self.phase,
                        self.directory,
                        self.anchor,
                        self.file,
                        self.identity,
                        Some(bytes.len()),
                    )?;
                }
                ensure!(
                    bytes == self.layout.image.bytes(),
                    "retained_initial_bytes_changed"
                );
                check_identity(
                    &mut self.phase,
                    self.directory,
                    self.anchor,
                    self.file,
                    self.identity,
                    Some(bytes.len()),
                )
            }
        })();
        if result.is_err() {
            self.disposition.refuse();
        }
        result
    }

    /// Only the authenticated initial-holder composition may interpret this
    /// fixed operation as P3. All real resources remain owned by THIS phase;
    /// a local filesystem fixture cannot construct its native volume owner.
    pub(crate) fn check_initial_durability(&mut self) -> Result<()> {
        let result = (|| {
            self.check()?;
            self.phase.check_durability_profile()?;
            self.check()?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("original_file_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                rustix::fs::fsync(self.file)?;
                self.check()?;
                rustix::fs::fsync(self.directory)?;
                self.check()?;
                self.phase.check_durability_profile()?;
                self.check()
            }
        })();
        if result.is_err() {
            self.disposition.refuse();
        }
        result
    }

    /// A statement only, after current file/provider checks. The closed S1
    /// exchange must authenticate it before the App parses any SQLite bytes.
    pub(crate) fn projection(&mut self) -> Result<PreparedFileProjection> {
        let result = (|| {
            self.check()?;
            let value = PreparedFileProjection {
                core: self.layout.proposal.core.clone(),
                marker: self.layout.proposal.marker.clone(),
                image: self.layout.proposal.image.clone(),
                length: self.layout.proposal.length.try_into()?,
                identity: self.identity.clone(),
            };
            self.check()?;
            Ok(value)
        })();
        if result.is_err() {
            self.disposition.refuse();
        }
        result
    }

    /// Lend the SAME phase's controller stage, never a replacement acquisition.
    /// The fixed peer releases this borrow and checks the file again after I/O.
    pub(crate) fn controller_stage(&mut self) -> Result<&mut EnrolledRoleStage<'role>> {
        self.check()?;
        let result = self.phase.controller_stage();
        if result.is_err() {
            self.disposition.refuse();
        }
        result
    }

    /// The fixed consumer calls this only after a known successful operation
    /// and final message/result checks. An unknown or failed handshake must
    /// retain/refuse this phase, never complete it. This creates no peer proof.
    pub(crate) fn finish_checked(mut self) -> Result<()> {
        self.check()?;
        self.disposition.complete()
    }

    pub(crate) fn refuse(&mut self) {
        self.disposition.refuse();
    }
}

impl<'role> CurrentPhysicalFilePhase<'_, 'role> {
    pub(crate) fn check(&mut self) -> Result<()> {
        let result = (|| {
            self.inner.disposition.check()?;
            ensure!(
                self.inner.process == std::process::id()
                    && self.inner.thread == std::thread::current().id(),
                "retained_storage_executor_changed"
            );
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("original_file_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                // Active length/content may change under legitimate writes.
                // Identity/modes/nlink/mount and fixed named leaf remain exact;
                // this does not validate or grant the active contents.
                check_identity(
                    &mut self.inner.phase,
                    self.inner.directory,
                    self.inner.anchor,
                    self.inner.file,
                    self.inner.identity,
                    None,
                )
            }
        })();
        if result.is_err() {
            self.inner.disposition.refuse();
        }
        result
    }

    pub(crate) fn controller_stage(&mut self) -> Result<&mut EnrolledRoleStage<'role>> {
        self.check()?;
        let result = self.inner.phase.controller_stage();
        if result.is_err() {
            self.inner.disposition.refuse();
        }
        result
    }

    pub(crate) fn finish_checked(mut self) -> Result<()> {
        self.check()?;
        self.inner.disposition.complete()
    }

    pub(crate) fn refuse(&mut self) {
        self.inner.disposition.refuse();
    }
}

#[cfg(target_os = "linux")]
fn check_identity(
    phase: &mut CurrentVolumePhase<'_, '_>,
    directory: &File,
    anchor: &DirectoryIdentity,
    file: &File,
    identity: &FileIdentity,
    length: Option<usize>,
) -> Result<()> {
    use rustix::fs::{AtFlags, StatxFlags};
    phase.check_directory(directory, anchor)?;
    phase.acquisition().remaining()?;
    let observed = match length {
        Some(length) => observe_anchored_file(directory, anchor, file, length)?,
        None => observe_current_anchored_file(directory, anchor, file)?,
    };
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

#[cfg(test)]
mod phase_disposition_tests {
    use super::FilePhaseDisposition;

    #[test]
    fn abandoning_an_unsettled_phase_cannot_rearm_continuity() {
        let mut continuation = true;
        {
            let phase = FilePhaseDisposition::begin(&mut continuation).unwrap();
            phase.check().unwrap();
        }
        assert!(!continuation);
        assert!(FilePhaseDisposition::begin(&mut continuation).is_err());
    }

    #[test]
    fn a_refused_phase_cannot_complete_or_start_another_phase() {
        let mut continuation = true;
        let mut phase = FilePhaseDisposition::begin(&mut continuation).unwrap();
        phase.check().unwrap();
        phase.refuse();
        assert!(phase.check().is_err());
        assert!(phase.complete().is_err());
        assert!(!continuation);
        assert!(FilePhaseDisposition::begin(&mut continuation).is_err());
    }

    #[test]
    fn only_known_completion_restores_the_continuation_gate() {
        let mut continuation = true;
        FilePhaseDisposition::begin(&mut continuation)
            .unwrap()
            .complete()
            .unwrap();
        assert!(continuation);
        let next = FilePhaseDisposition::begin(&mut continuation).unwrap();
        next.check().unwrap();
        next.complete().unwrap();
        assert!(continuation);
    }

    #[test]
    fn a_previously_refused_file_stays_refused() {
        let mut continuation = false;
        assert!(FilePhaseDisposition::begin(&mut continuation).is_err());
        assert!(!continuation);
    }
}
