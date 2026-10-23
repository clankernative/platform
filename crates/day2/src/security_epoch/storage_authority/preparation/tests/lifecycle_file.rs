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
                    self.snapshot()?.named_original,
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
        let named = std::fs::symlink_metadata(self.directory.path().join(INITIAL_FILE))?;
        let mut bytes = vec![0; self.layout.image.bytes().len()];
        self.creator.file.read_exact_at(&mut bytes, 0)?;
        Ok(FileState {
            held_original: self.creator.file.as_raw_fd() == self.descriptor
                && metadata.ino() == self.inode,
            named_original: named.ino() == metadata.ino() && named.dev() == metadata.dev(),
            image_exact: metadata.len() == bytes.len() as u64 && bytes == self.layout.image.bytes(),
        })
    }
}
