//! Exclusive original-file preparation under its retained issuer. Local
//! persistence alone is not provider qualification or a current execution
//! permit. The native provider composition and its campaign remain separate.

use super::{NativeStorageCreationAuthority, ReviewedStorageSelection};
use crate::security_epoch::{
    native_clock::NativeAcquisition,
    preparation_image::InitialPreparationImage,
    seed_core::{InitialMarker, OriginalSeedCore},
};
use anyhow::{Result, ensure};
use day2_capabilities::{Digest, security_epoch::EpochStore};
use serde::{Deserialize, Serialize};
use std::fs::File;

const INITIAL_FILE: &str = "day2-initial.sqlite";
const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const IO_CHUNK_BYTES: usize = 64 * 1024;

mod app;
pub(crate) use app::AppPreparedFile;

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
            ensure!(
                image.core() == selection.seed(),
                "original_file_seed_selection"
            );
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
#[derive(Clone, PartialEq, Eq)]
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
pub(crate) enum NativeOriginalPreparationOutcome<'role> {
    RefusedBeforeAttempt(BeforeAttemptRefusal<'role>),
    Prepared(OriginalCreatorFd<'role>),
    RefusedAfterAttempt(RefusedOriginalPreparation<'role>),
}

pub(crate) struct BeforeAttemptRefusal<'role> {
    authority: NativeStorageCreationAuthority<'role>,
    proposal: OriginalFileProposal,
    phase: PreparationPhase,
}

pub(crate) struct RefusedOriginalPreparation<'role> {
    authority: NativeStorageCreationAuthority<'role>,
    proposal: OriginalFileProposal,
    // None means that no descriptor returned. It never proves noncreation.
    file: Option<File>,
    phase: PreparationPhase,
}

/// Retains the original file and consumed anchor/runtime/provider owner. No
/// current-use or P3 factory is supplied. Drop can permanently forfeit this
/// owner; Rust ownership does not prevent explicit drop, unwind or process exit.
pub(crate) struct OriginalCreatorFd<'role> {
    authority: NativeStorageCreationAuthority<'role>,
    proposal: OriginalFileProposal,
    file: File,
    identity: FileIdentity,
}

/// Owns the ORIGINAL interval as well as the creator and exact admitted image.
/// This is a continuity owner, not provider P3, an app holder or a writer grant.
/// Its only constructor consumes the existing creator; DATA cannot recreate it.
pub(crate) struct PreparedInitialFile<'role> {
    creator: OriginalCreatorFd<'role>,
    layout: ReviewedFileLayout,
    acquisition: NativeAcquisition,
}

/// A closed statement for the native first-holder exchange. Even an exact copy
/// of this value does not own the file, its original clock or the controller.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedFileProjection {
    core: OriginalSeedCore,
    marker: InitialMarker,
    image: Digest,
    length: u64,
    identity: FileIdentity,
}

impl<'role> PreparedInitialFile<'role> {
    /// Package owners without a fallible gap. Every subsequent use checks the
    /// supplied interval against the creator's retained original domain/budget.
    pub(super) fn retain_original(
        creator: OriginalCreatorFd<'role>,
        layout: ReviewedFileLayout,
        acquisition: NativeAcquisition,
    ) -> Self {
        Self {
            creator,
            layout,
            acquisition,
        }
    }

    pub(crate) fn check_original(&mut self) -> Result<()> {
        self.creator
            .check_unchanged_initial_file(&self.layout, &mut self.acquisition)
    }

    pub(crate) fn projection(&mut self) -> Result<crate::security_epoch::PreparedFileProjection> {
        self.check_original()?;
        let value = PreparedFileProjection {
            core: self.creator.proposal.core.clone(),
            marker: self.creator.proposal.marker.clone(),
            image: self.creator.proposal.image.clone(),
            length: self.creator.proposal.length.try_into()?,
            identity: self.creator.identity.clone(),
        };
        self.check_original()?;
        Ok(value)
    }
}

impl PreparedFileProjection {
    pub(crate) fn scope(&self) -> &day2_capabilities::security_epoch::AuthorityScope {
        &self.core.scope
    }

    pub(crate) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-original-prepared-file-projection-v1", self))
    }

    pub(super) fn validate_selection(
        &self,
        policy: &day2_capabilities::security_epoch::bootstrap::InitialBootstrapPolicy,
        store: &EpochStore,
    ) -> Result<()> {
        self.core.validate(policy, store)?;
        ensure!(
            self.marker == self.core.marker()?
                && (100..=MAX_IMAGE_BYTES as u64).contains(&self.length)
                && self.identity.inode != 0
                && self.identity.mount != 0,
            "original_file_projection_mismatch"
        );
        Ok(())
    }
}

impl OriginalCreatorFd<'_> {
    /// Checks only unchanged initial-file continuity under the ORIGINAL budget.
    /// A later SQLite write deliberately refuses this check. Returning unit is
    /// not a reusable witness, current-role permission or P3 acknowledgment.
    pub(super) fn check_unchanged_initial_file(
        &mut self,
        plan: &ReviewedFileLayout,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            self.authority.check_current(acquisition)?;
            ensure!(
                self.proposal == plan.proposal
                    && self.proposal.selection == *self.authority.selection.digest()
                    && self.proposal.store == *self.authority.selection.store()
                    && self.proposal.core == *self.authority.selection.seed()
                    && self.proposal.marker == self.proposal.core.marker()?
                    && self.proposal.length == plan.image.bytes().len()
                    && (100..=MAX_IMAGE_BYTES).contains(&self.proposal.length)
                    && self.proposal.image == Digest::new(plan.image.bytes()),
                "original_file_continuity_layout"
            );
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("original_file_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let mut readback = vec![0_u8; self.proposal.length];
                let mut offset = 0;
                while offset < readback.len() {
                    check_file_identity(
                        &mut self.authority,
                        &self.file,
                        &self.identity,
                        self.proposal.length,
                        acquisition,
                    )?;
                    let end = (offset + IO_CHUNK_BYTES).min(readback.len());
                    let read =
                        rustix::io::pread(&self.file, &mut readback[offset..end], offset as u64)?;
                    ensure!(
                        read > 0 && read <= end - offset,
                        "original_file_read_progress"
                    );
                    offset += read;
                    check_file_identity(
                        &mut self.authority,
                        &self.file,
                        &self.identity,
                        self.proposal.length,
                        acquisition,
                    )?;
                }
                ensure!(
                    readback == plan.image.bytes(),
                    "original_file_continuity_bytes"
                );
                check_file_identity(
                    &mut self.authority,
                    &self.file,
                    &self.identity,
                    self.proposal.length,
                    acquisition,
                )
            }
        })();
        if result.is_err() {
            // Keep the same FD, anchor and proposal even after a failed check.
            self.authority.refuse_preparation(acquisition);
        }
        result
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    device_major: u32,
    device_minor: u32,
    inode: u64,
    mount: u64,
    uid: u32,
}

/// Sole owners live outside every fallible stage. Once a descriptor returns,
/// assigning it here is infallible and precedes all post-create checks.
pub(crate) struct PreparationCoordinator<'role> {
    authority: NativeStorageCreationAuthority<'role>,
    proposal: OriginalFileProposal,
    file: Option<File>,
    identity: Option<FileIdentity>,
    phase: PreparationPhase,
}

pub(super) fn prepare_original_file<'role>(
    authority: NativeStorageCreationAuthority<'role>,
    plan: &ReviewedFileLayout,
    acquisition: &mut NativeAcquisition,
) -> NativeOriginalPreparationOutcome<'role> {
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
            (Some(file), Some(identity)) => {
                NativeOriginalPreparationOutcome::Prepared(OriginalCreatorFd {
                    authority: owner.authority,
                    proposal: owner.proposal,
                    file,
                    identity,
                })
            }
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
                NativeOriginalPreparationOutcome::RefusedBeforeAttempt(BeforeAttemptRefusal {
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

impl PreparationCoordinator<'_> {
    fn validate_plan(
        &mut self,
        plan: &ReviewedFileLayout,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
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

    fn prepare(
        &mut self,
        plan: &ReviewedFileLayout,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        self.validate_plan(plan, acquisition)?;
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("original_file_platform_unsupported")
        }
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{Mode, OFlags, ResolveFlags};
            // Set the attempted phase BEFORE dispatch. A syscall error does not
            // authorize a retry or assert that no filesystem object was created.
            self.phase = PreparationPhase::ExclusiveCreate;
            let descriptor = rustix::fs::openat2(
                &self.authority.directory,
                INITIAL_FILE,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::CLOEXEC
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK,
                Mode::from_raw_mode(0o600),
                ResolveFlags::BENEATH
                    | ResolveFlags::NO_SYMLINKS
                    | ResolveFlags::NO_MAGICLINKS
                    | ResolveFlags::NO_XDEV,
            )?;
            self.file = Some(File::from(descriptor));
            #[cfg(test)]
            plan.fixture_cut(self.phase)?;
            self.phase = PreparationPhase::Identity;
            self.authority.check_current(acquisition)?;
            let file = self
                .file
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("original_file_owner_missing"))?;
            self.identity = Some(observe_file(&self.authority, file, 0)?);
            self.check_file(0, acquisition)?;

            self.phase = PreparationPhase::Write;
            let bytes = plan.image.bytes();
            let mut offset = 0;
            while offset < bytes.len() {
                self.check_file(offset, acquisition)?;
                let end = (offset + IO_CHUNK_BYTES).min(bytes.len());
                let written =
                    rustix::io::pwrite(self.file_ref()?, &bytes[offset..end], offset as u64)?;
                ensure!(
                    written > 0 && written <= end - offset,
                    "original_file_write_progress"
                );
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
                let read =
                    rustix::io::pread(self.file_ref()?, &mut readback[offset..end], offset as u64)?;
                ensure!(
                    read > 0 && read <= end - offset,
                    "original_file_read_progress"
                );
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
    }

    fn file_ref(&self) -> Result<&File> {
        self.file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("original_file_owner_missing"))
    }

    fn check_file(
        &mut self,
        expected_length: usize,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("original_file_owner_missing"))?;
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("original_file_identity_missing"))?;
        check_file_identity(
            &mut self.authority,
            file,
            identity,
            expected_length,
            acquisition,
        )
    }
}

fn observe_file(
    authority: &NativeStorageCreationAuthority<'_>,
    file: &File,
    expected_length: usize,
) -> Result<FileIdentity> {
    observe_anchored_file(
        &authority.directory,
        &authority.identity,
        file,
        expected_length,
    )
}

fn observe_anchored_file(
    directory: &File,
    anchor: &super::DirectoryIdentity,
    file: &File,
    expected_length: usize,
) -> Result<FileIdentity> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (directory, anchor, file, expected_length);
        anyhow::bail!("original_file_platform_unsupported")
    }
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{AtFlags, FileType, StatxFlags};
        let mask = StatxFlags::TYPE
            | StatxFlags::MODE
            | StatxFlags::NLINK
            | StatxFlags::UID
            | StatxFlags::INO
            | StatxFlags::SIZE
            | StatxFlags::MNT_ID;
        let observed = rustix::fs::statx(file, "", AtFlags::EMPTY_PATH, mask)?;
        let directory = rustix::fs::statx(directory, "", AtFlags::EMPTY_PATH, StatxFlags::UID)?;
        ensure!(
            observed.stx_mask & mask.bits() == mask.bits()
                && directory.stx_mask & StatxFlags::UID.bits() != 0
                && FileType::from_raw_mode(u32::from(observed.stx_mode)) == FileType::RegularFile
                && observed.stx_mode & 0o7777 == 0o600
                && observed.stx_uid == directory.stx_uid
                && observed.stx_nlink == 1
                && observed.stx_ino != 0
                && observed.stx_size == expected_length as u64
                && observed.stx_dev_major == anchor.device_major
                && observed.stx_dev_minor == anchor.device_minor
                && observed.stx_mnt_id == anchor.mount,
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
}

fn check_file_identity(
    authority: &mut NativeStorageCreationAuthority<'_>,
    file: &File,
    identity: &FileIdentity,
    expected_length: usize,
    acquisition: &mut NativeAcquisition,
) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (authority, file, identity, expected_length, acquisition);
        anyhow::bail!("original_file_platform_unsupported")
    }
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{AtFlags, StatxFlags};
        authority.check_current(acquisition)?;
        let observed = observe_file(authority, file, expected_length)?;
        ensure!(identity == &observed, "original_file_identity_changed");
        // Join the fixed leaf to the SAME anchor without opening or adopting it.
        // The issuer must separately qualify the physical volume/anchor root.
        let mask = StatxFlags::INO | StatxFlags::MNT_ID;
        let named = rustix::fs::statx(
            &authority.directory,
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
            "original_file_leaf_changed"
        );
        authority.check_current(acquisition)
    }
}

#[cfg(test)]
impl ReviewedFileLayout {
    // A deterministic local error cut, not a provider or kernel failure proof.
    fn fixture_cut(&self, phase: PreparationPhase) -> Result<()> {
        ensure!(
            self.fixture_refusal != Some(phase),
            "original_file_fixture_refusal"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
