//! Actual Linux original descriptors, explicitly unqualified filesystem issuer.
//! Current checks below exercise the production physical identity observer;
//! they cannot instantiate a current native phase or a writer grant.
use super::*;
use crate::security_epoch::control_slot_tests::lifecycle::{FileChange, FileState};
use std::os::unix::{
    fs::{FileExt, MetadataExt},
    io::AsRawFd,
};

pub(in crate::security_epoch) struct FileFixture {
    directory: tempfile::TempDir,
    creator: OriginalCreatorFd<'static>,
    layout: ReviewedFileLayout,
    acquisition: NativeAcquisition,
    descriptor: i32,
    inode: u64,
    initial_failed: bool,
}

impl FileFixture {
    pub(in crate::security_epoch) fn new() -> Result<Self> {
        let (directory, selected, layout, mut acquisition) = layout();
        let authority = NativeStorageCreationAuthority::filesystem_fixture(
            selected,
            File::open(directory.path())?,
            &mut acquisition,
        )?;
        let NativeOriginalPreparationOutcome::Prepared(creator) =
            prepare_original_file(authority, &layout, &mut acquisition)
        else {
            anyhow::bail!("lifecycle local file preparation refused");
        };
        let descriptor = creator.file.as_raw_fd();
        let inode = creator.file.metadata()?.ino();
        Ok(Self {
            directory,
            creator,
            layout,
            acquisition,
            descriptor,
            inode,
            initial_failed: false,
        })
    }

    pub(in crate::security_epoch) fn check(&mut self, current: bool) -> Result<()> {
        let result = if current {
            (|| {
                self.creator
                    .authority
                    .check_current(&mut self.acquisition)?;
                let observed = observe_current_anchored_file(
                    &self.creator.authority.directory,
                    &self.creator.authority.identity,
                    &self.creator.file,
                )?;
                ensure!(
                    observed == self.creator.identity,
                    "lifecycle current physical identity changed"
                );
                ensure!(
                    self.named_original()?,
                    "lifecycle current physical leaf changed"
                );
                self.creator.authority.check_current(&mut self.acquisition)
            })()
        } else {
            self.creator
                .check_unchanged_initial_file(&self.layout, &mut self.acquisition)
        };
        if result.is_err() && !current {
            self.initial_failed = true;
        }
        result
    }

    /// Project immutable fixture inputs once, while the original is still
    /// exact. This is DATA, not a native role, P3 or permission factory. Current
    /// operations retain these inputs and never project a modified file again.
    pub(in crate::security_epoch) fn blueprint(
        &mut self,
    ) -> Result<(
        day2_capabilities::security_epoch::bootstrap::InitialBootstrapPolicy,
        EpochStore,
        OriginalSeedCore,
        Digest,
    )> {
        self.check(false)?;
        let selected = &self.creator.authority.selection;
        ensure!(
            self.creator.proposal == self.layout.proposal
                && self.layout.proposal.core == *selected.seed()
                && self.layout.proposal.marker == selected.seed().marker()?
                && self.layout.proposal.selection == *selected.digest()
                && self.layout.proposal.store == *selected.store()
                && self.layout.proposal.image == Digest::new(self.layout.image.bytes())
                && self.layout.proposal.length == self.layout.image.bytes().len(),
            "lifecycle original fixture blueprint changed"
        );
        let data = (
            selected.policy().clone(),
            selected.store().clone(),
            selected.seed().clone(),
            Digest::of(&(
                "day2-storage-lifecycle-image-v1",
                &self.layout.proposal.image,
                self.layout.proposal.length,
            ))?,
        );
        self.check(false)?;
        Ok(data)
    }

    pub(in crate::security_epoch) fn change(&mut self, change: FileChange) -> Result<()> {
        let leaf = self.directory.path().join(INITIAL_FILE);
        let retained = self.directory.path().join("held-original.sqlite");
        match change {
            FileChange::Tamper => {
                self.creator
                    .file
                    .write_all_at(&[self.layout.image.bytes()[100] ^ 1], 100)?;
            }
            FileChange::Replace => {
                if !retained.exists() {
                    std::fs::rename(&leaf, &retained)?;
                    std::fs::write(&leaf, self.layout.image.bytes())?;
                }
            }
            FileChange::AppWrite => {
                let db = rusqlite::Connection::open(&leaf)?;
                db.execute_batch("PRAGMA user_version=42")?;
            }
            FileChange::Shorten => {
                ensure!(
                    self.layout.image.bytes().len() > 4096,
                    "shorter-file control must change length"
                );
                self.creator.file.set_len(4096)?;
            }
            FileChange::Restore => {
                if retained.exists() {
                    std::fs::remove_file(&leaf)?;
                    std::fs::rename(&retained, &leaf)?;
                }
                self.creator
                    .file
                    .write_all_at(self.layout.image.bytes(), 0)?;
                if self.initial_failed {
                    // This is an expectation, never a synthetic refusal. Probe
                    // the actual original after restoration so a missing
                    // production latch cannot be hidden by the outer gate.
                    ensure!(
                        self.creator
                            .check_unchanged_initial_file(&self.layout, &mut self.acquisition)
                            .is_err(),
                        "restored original file cleared production refusal"
                    );
                }
            }
        }
        Ok(())
    }

    pub(in crate::security_epoch) fn snapshot(&self) -> Result<FileState> {
        let metadata = self.creator.file.metadata()?;
        let image_exact = if metadata.len() == self.layout.image.bytes().len() as u64 {
            let mut bytes = vec![0; self.layout.image.bytes().len()];
            self.creator.file.read_exact_at(&mut bytes, 0)?;
            bytes == self.layout.image.bytes()
        } else {
            false
        };
        Ok(FileState {
            held_original: self.creator.file.as_raw_fd() == self.descriptor
                && metadata.ino() == self.inode,
            named_original: self.named_original()?,
            image_exact,
        })
    }

    fn named_original(&self) -> Result<bool> {
        let held = self.creator.file.metadata()?;
        let named = std::fs::symlink_metadata(self.directory.path().join(INITIAL_FILE))?;
        Ok(named.ino() == held.ino() && named.dev() == held.dev())
    }
}
