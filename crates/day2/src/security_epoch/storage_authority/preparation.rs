//! Exclusive original-file preparation. The production storage issuer is still
//! absent. Successful local persistence is not a provider durability proof or
//! a P3 acknowledgment, and cannot create a current execution permit.

use super::{NativeStorageCreationAuthority, ReviewedStorageSelection};
use crate::security_epoch::{
    native_clock::NativeAcquisition,
    preparation_image::InitialPreparationImage,
    seed_core::{InitialMarker, OriginalSeedCore},
};
use anyhow::{Result, ensure};
use day2_capabilities::{Digest, security_epoch::EpochStore};
use std::fs::File;

const INITIAL_FILE: &str = "day2-initial.sqlite";
const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const IO_CHUNK_BYTES: usize = 64 * 1024;

/// Complete admitted image DATA with a fixed leaf. There is no caller pathname,
/// descriptor adoption or arbitrary image constructor.
pub(super) struct ReviewedFileLayout {
    image: InitialPreparationImage,
    proposal: OriginalFileProposal,
    #[cfg(test)]
    fixture_refusal: Option<PreparationPhase>,
}

impl ReviewedFileLayout {
    pub(super) fn prepare(
        runtime: &crate::store::Runtime,
        selection: &ReviewedStorageSelection,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Self> {
        let result = (|| {
            acquisition.remaining()?;
            let image = InitialPreparationImage::prepare(
                runtime,
                selection.policy(),
                selection.store(),
                selection.seed().incarnations.clone(),
                acquisition,
            )?;
            ensure!(image.core() == selection.seed(), "original_file_seed_selection");
            let proposal = OriginalFileProposal {
                selection: selection.digest().clone(),
                store: image.store().clone(),
                core: image.core().clone(),
                marker: image.marker().clone(),
                image: Digest::new(image.bytes()),
                length: image.bytes().len(),
            };
            acquisition.remaining()?;
            Ok(Self {
                image,
                proposal,
                #[cfg(test)]
                fixture_refusal: None,
            })
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }
}

/// Immutable selection/proposal DATA retained on success and on every refusal.
/// Its fields are private; it grants no permission and cannot adopt an owner.
#[derive(Clone)]
struct OriginalFileProposal {
    selection: Digest,
    store: EpochStore,
    core: OriginalSeedCore,
    marker: InitialMarker,
    image: Digest,
    length: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PreparationPhase {
    BeforeAttempt,
    ExclusiveCreate,
    Identity,
    Write,
    FileSync,
    DirectorySync,
    Readback,
    Decode,
    FinalCheck,
}

/// These are owning native states, not wire responses. There is no promotion,
/// retry, descriptor getter, renewal or permission conversion on a refusal.
pub(crate) enum NativeOriginalPreparationOutcome {
    RefusedBeforeAttempt(RefusedBeforeAttempt),
    Prepared(OriginalCreatorFd),
    RefusedAfterAttempt(RefusedOriginalPreparation),
}

pub(crate) struct RefusedBeforeAttempt {
    authority: NativeStorageCreationAuthority,
    proposal: OriginalFileProposal,
    phase: PreparationPhase,
}

pub(crate) struct RefusedOriginalPreparation {
    authority: NativeStorageCreationAuthority,
    proposal: OriginalFileProposal,
    // None means that no descriptor returned. It never proves noncreation.
    file: Option<File>,
    phase: PreparationPhase,
}

/// Retains the original file and consumed anchor/runtime/provider owner. No
/// current-use or P3 factory is supplied. Drop can permanently forfeit this
/// owner; Rust ownership does not prevent explicit drop, unwind or process exit.
pub(crate) struct OriginalCreatorFd {
    authority: NativeStorageCreationAuthority,
    proposal: OriginalFileProposal,
    file: File,
    identity: FileIdentity,
}

#[derive(PartialEq, Eq)]
struct FileIdentity {
    device_major: u32,
    device_minor: u32,
    inode: u64,
    mount: u64,
    uid: u32,
}

/// Sole owners live outside every fallible stage. Once a descriptor returns,
/// assigning it here is infallible and precedes all post-create checks.
struct PreparationCoordinator {
    authority: NativeStorageCreationAuthority,
    proposal: OriginalFileProposal,
    file: Option<File>,
    identity: Option<FileIdentity>,
    phase: PreparationPhase,
}

pub(super) fn prepare_original_file(
    authority: NativeStorageCreationAuthority,
    plan: &ReviewedFileLayout,
    acquisition: &mut NativeAcquisition,
) -> NativeOriginalPreparationOutcome {
    let mut owner = PreparationCoordinator {
        authority,
        proposal: plan.proposal.clone(),
        file: None,
        identity: None,
        phase: PreparationPhase::BeforeAttempt,
    };
    let result = owner.prepare(plan, acquisition);
    match result {
        Ok(()) => match (owner.file, owner.identity) {
            (Some(file), Some(identity)) => NativeOriginalPreparationOutcome::Prepared(
                OriginalCreatorFd {
                    authority: owner.authority,
                    proposal: owner.proposal,
                    file,
                    identity,
                },
            ),
            (file, _) => {
                owner.authority.refuse_preparation(acquisition);
                NativeOriginalPreparationOutcome::RefusedAfterAttempt(RefusedOriginalPreparation {
                    authority: owner.authority,
                    proposal: owner.proposal,
                    file,
                    phase: owner.phase,
                })
            }
        },
        Err(_) => {
            // Error text is deliberately not exported: fixed bounded phase
            // evidence is sufficient and contains no path, token or SQL data.
            owner.authority.refuse_preparation(acquisition);
            if owner.phase == PreparationPhase::BeforeAttempt {
                NativeOriginalPreparationOutcome::RefusedBeforeAttempt(RefusedBeforeAttempt {
                    authority: owner.authority,
                    proposal: owner.proposal,
                    phase: owner.phase,
                })
            } else {
                NativeOriginalPreparationOutcome::RefusedAfterAttempt(RefusedOriginalPreparation {
                    authority: owner.authority,
                    proposal: owner.proposal,
                    file: owner.file,
                    phase: owner.phase,
                })
            }
        }
    }
}

impl PreparationCoordinator {
    fn validate_plan(&mut self, plan: &ReviewedFileLayout, acquisition: &mut NativeAcquisition) -> Result<()> {
        self.authority.check_current(acquisition)?;
        ensure!(
            self.proposal.selection == *self.authority.selection.digest()
                && self.proposal.store == *self.authority.selection.store()
                && self.proposal.core == *self.authority.selection.seed()
                && self.proposal.marker == self.proposal.core.marker()?
                && self.proposal.length == plan.image.bytes().len()
                && (100..=MAX_IMAGE_BYTES).contains(&self.proposal.length)
                && self.proposal.image == Digest::new(plan.image.bytes()),
            "original_file_layout_selection"
        );
        self.authority.check_current(acquisition)
    }

    #[cfg(not(target_os = "linux"))]
    fn prepare(&mut self, plan: &ReviewedFileLayout, acquisition: &mut NativeAcquisition) -> Result<()> {
        self.validate_plan(plan, acquisition)?;
        anyhow::bail!("original_file_platform_unsupported")
    }

    #[cfg(target_os = "linux")]
    fn prepare(&mut self, plan: &ReviewedFileLayout, acquisition: &mut NativeAcquisition) -> Result<()> {
        use rustix::fs::{Mode, OFlags, ResolveFlags};
        self.validate_plan(plan, acquisition)?;
        // Set the attempted phase BEFORE dispatch. A syscall error does not
        // authorize a retry or assert that no filesystem object was created.
        self.phase = PreparationPhase::ExclusiveCreate;
        let descriptor = rustix::fs::openat2(
            &self.authority.directory,
            INITIAL_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC
                | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV,
        )?;
        self.file = Some(File::from(descriptor));
        #[cfg(test)]
        plan.fixture_cut(self.phase)?;
        self.phase = PreparationPhase::Identity;
        self.authority.check_current(acquisition)?;
        let file = self.file.as_ref().ok_or_else(|| anyhow::anyhow!("original_file_owner_missing"))?;
        self.identity = Some(self.observe_file(file, 0)?);
        self.check_file(0, acquisition)?;

        self.phase = PreparationPhase::Write;
        let bytes = plan.image.bytes();
        let mut offset = 0;
        while offset < bytes.len() {
            self.check_file(offset, acquisition)?;
            let end = (offset + IO_CHUNK_BYTES).min(bytes.len());
            let written = rustix::io::pwrite(self.file_ref()?, &bytes[offset..end], offset as u64)?;
            ensure!(written > 0 && written <= end - offset, "original_file_write_progress");
            offset += written;
            self.check_file(offset, acquisition)?;
            #[cfg(test)]
            plan.fixture_cut(self.phase)?;
        }
        self.phase = PreparationPhase::FileSync;
        self.check_file(bytes.len(), acquisition)?;
        rustix::fs::fsync(self.file_ref()?)?;
        self.check_file(bytes.len(), acquisition)?;
        #[cfg(test)]
        plan.fixture_cut(self.phase)?;
        self.phase = PreparationPhase::DirectorySync;
        rustix::fs::fsync(&self.authority.directory)?;
        self.check_file(bytes.len(), acquisition)?;
        #[cfg(test)]
        plan.fixture_cut(self.phase)?;

        self.phase = PreparationPhase::Readback;
        let mut readback = vec![0_u8; bytes.len()];
        let mut offset = 0;
        while offset < readback.len() {
            self.check_file(bytes.len(), acquisition)?;
            let end = (offset + IO_CHUNK_BYTES).min(readback.len());
            let read = rustix::io::pread(self.file_ref()?, &mut readback[offset..end], offset as u64)?;
            ensure!(read > 0 && read <= end - offset, "original_file_read_progress");
            offset += read;
            self.check_file(bytes.len(), acquisition)?;
        }
        ensure!(readback == bytes, "original_file_exact_readback");
        #[cfg(test)]
        plan.fixture_cut(self.phase)?;
        self.phase = PreparationPhase::Decode;
        // Equality of all bytes precedes the trusted memory-only decoder.
        let decoded = plan.image.decode_exact_readback(&readback, acquisition)?;
        drop(decoded);
        #[cfg(test)]
        plan.fixture_cut(self.phase)?;
        self.phase = PreparationPhase::FinalCheck;
        self.validate_plan(plan, acquisition)?;
        self.check_file(bytes.len(), acquisition)
    }

    #[cfg(target_os = "linux")]
    fn file_ref(&self) -> Result<&File> {
        self.file.as_ref().ok_or_else(|| anyhow::anyhow!("original_file_owner_missing"))
    }

    #[cfg(target_os = "linux")]
    fn observe_file(&self, file: &File, expected_length: usize) -> Result<FileIdentity> {
        use rustix::fs::{AtFlags, FileType, StatxFlags};
        let mask = StatxFlags::TYPE | StatxFlags::MODE | StatxFlags::NLINK
            | StatxFlags::UID | StatxFlags::INO | StatxFlags::SIZE | StatxFlags::MNT_ID;
        let observed = rustix::fs::statx(file, "", AtFlags::EMPTY_PATH, mask)?;
        let directory = rustix::fs::statx(&self.authority.directory, "", AtFlags::EMPTY_PATH, StatxFlags::UID)?;
        ensure!(
            observed.stx_mask & mask.bits() == mask.bits()
                && directory.stx_mask & StatxFlags::UID.bits() != 0
                && FileType::from_raw_mode(u32::from(observed.stx_mode)) == FileType::RegularFile
                && observed.stx_mode & 0o7777 == 0o600
                && observed.stx_uid == directory.stx_uid
                && observed.stx_nlink == 1 && observed.stx_ino != 0
                && observed.stx_size == expected_length as u64
                && observed.stx_dev_major == self.authority.identity.device_major
                && observed.stx_dev_minor == self.authority.identity.device_minor
                && observed.stx_mnt_id == self.authority.identity.mount,
            "original_file_identity_required"
        );
        Ok(FileIdentity {
            device_major: observed.stx_dev_major,
            device_minor: observed.stx_dev_minor,
            inode: observed.stx_ino,
            mount: observed.stx_mnt_id,
            uid: observed.stx_uid,
        })
    }

    #[cfg(target_os = "linux")]
    fn check_file(&mut self, expected_length: usize, acquisition: &mut NativeAcquisition) -> Result<()> {
        use rustix::fs::{AtFlags, StatxFlags};
        self.authority.check_current(acquisition)?;
        let observed = self.observe_file(self.file_ref()?, expected_length)?;
        ensure!(self.identity.as_ref() == Some(&observed), "original_file_identity_changed");
        // Join the fixed leaf to the SAME anchor without opening or adopting it.
        // The issuer must separately qualify the physical volume/anchor root.
        let mask = StatxFlags::INO | StatxFlags::MNT_ID;
        let named = rustix::fs::statx(&self.authority.directory, INITIAL_FILE, AtFlags::SYMLINK_NOFOLLOW, mask)?;
        ensure!(
            named.stx_mask & mask.bits() == mask.bits()
                && named.stx_ino == observed.inode && named.stx_mnt_id == observed.mount
                && named.stx_dev_major == observed.device_major && named.stx_dev_minor == observed.device_minor,
            "original_file_leaf_changed"
        );
        self.authority.check_current(acquisition)
    }
}

#[cfg(test)]
impl ReviewedFileLayout {
    // A deterministic local error cut, not a provider or kernel failure proof.
    fn fixture_cut(&self, phase: PreparationPhase) -> Result<()> {
        ensure!(self.fixture_refusal != Some(phase), "original_file_fixture_refusal");
        Ok(())
    }
}

#[cfg(test)]
mod tests;
