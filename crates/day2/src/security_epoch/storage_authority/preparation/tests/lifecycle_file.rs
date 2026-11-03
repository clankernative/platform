//! Actual Linux original descriptors, explicitly unqualified filesystem issuer.
//! Current checks below exercise the production physical identity observer;
//! they cannot instantiate a current native phase or a writer grant.
use super::*;
use crate::security_epoch::control_slot_tests::lifecycle::{
    FileChange, FileState,
    preparation::{
        EXISTING_BYTES, FOREIGN_BYTES, PreparationBytes, PreparationCheckpoint,
        PreparationDisposition, PreparationFault, PreparationFiles, PreparationInput,
        PreparationLeaf, PreparationNamed, PreparationObservation,
    },
};
use anyhow::Context;
use std::os::unix::{
    fs::{FileExt, MetadataExt},
    io::AsRawFd,
};

pub(in crate::security_epoch) struct FileFixture {
    directory: tempfile::TempDir,
    authority: Option<NativeStorageCreationAuthority<'static>>,
    outcome: Option<NativeOriginalPreparationOutcome<'static>>,
    returned: Option<PreparationObservation>,
    admitted_selection: Digest,
    anchor: i32,
    layout: ReviewedFileLayout,
    acquisition: NativeAcquisition,
    descriptor: Option<(i32, u64)>,
    initial_failed: bool,
}

impl FileFixture {
    pub(in crate::security_epoch) fn initial_image() -> Vec<u8> {
        let (_, _, layout, _) = layout();
        layout.image.bytes().to_vec()
    }

    pub(in crate::security_epoch) fn multi_batch_image() -> Vec<u8> {
        let (_, _, mut layout, _) = layout();
        image_fixture::reserve_empty_fixture_pages(
            &mut layout.image,
            2 * INITIAL_IO_CHUNK_BYTES + 17,
        );
        layout.image.bytes().to_vec()
    }

    pub(in crate::security_epoch) fn new(image: &[u8]) -> Result<Self> {
        let (directory, selected, layout, mut acquisition) = layout_for_replay(Some(image))?;
        let authority = NativeStorageCreationAuthority::filesystem_fixture(
            selected,
            File::open(directory.path())?,
            &mut acquisition,
        )?;
        let anchor = authority.directory.as_raw_fd();
        let admitted_selection = authority.selection.digest().clone();
        Ok(Self {
            directory,
            authority: Some(authority),
            outcome: None,
            returned: None,
            admitted_selection,
            anchor,
            layout,
            acquisition,
            descriptor: None,
            initial_failed: false,
        })
    }

    /// Immutable proposed DATA only. Unlike blueprint, this neither observes a
    /// prepared file nor authorizes a provider or a first-holder attempt.
    pub(in crate::security_epoch) fn proposed_blueprint(
        &self,
    ) -> Result<(
        day2_capabilities::security_epoch::bootstrap::InitialBootstrapPolicy,
        EpochStore,
        OriginalSeedCore,
        Digest,
    )> {
        let selected = &self
            .authority
            .as_ref()
            .context("fixture proposal already consumed")?
            .selection;
        Ok((
            selected.policy().clone(),
            selected.store().clone(),
            selected.seed().clone(),
            Digest::of(&(
                "day2-storage-lifecycle-image-v1",
                &self.layout.proposal.image,
                self.layout.proposal.length,
            ))?,
        ))
    }

    pub(in crate::security_epoch) fn prepare(&mut self, input: PreparationInput) -> Result<bool> {
        ensure!(
            self.outcome.is_none(),
            "original preparation cannot be retried"
        );
        let foreign = self.directory.path().join("foreign.sqlite");
        std::fs::write(&foreign, FOREIGN_BYTES)?;
        let leaf = self.directory.path().join(INITIAL_FILE);
        match input.leaf {
            PreparationLeaf::Missing => {}
            PreparationLeaf::File => std::fs::write(&leaf, EXISTING_BYTES)?,
            PreparationLeaf::Symlink => std::os::unix::fs::symlink(&foreign, &leaf)?,
            PreparationLeaf::Directory => std::fs::create_dir(&leaf)?,
            PreparationLeaf::Hardlink => std::fs::hard_link(&foreign, &leaf)?,
        }
        self.layout.fixture_refusal = match input.fault {
            PreparationFault::AfterCreate => Some(PreparationPhase::ExclusiveCreate),
            PreparationFault::AfterWrite => Some(PreparationPhase::Write),
            PreparationFault::AfterFileSync => Some(PreparationPhase::FileSync),
            PreparationFault::AfterDirectorySync => Some(PreparationPhase::DirectorySync),
            PreparationFault::AfterReadback => Some(PreparationPhase::Readback),
            PreparationFault::AfterDecode => Some(PreparationPhase::Decode),
            PreparationFault::None | PreparationFault::WrongProposal => None,
        };
        if input.fault == PreparationFault::WrongProposal {
            self.layout.proposal.selection = Digest::new(b"not-the-admitted-preparation-selection");
        }
        let authority = self
            .authority
            .take()
            .context("original preparation owner missing")?;
        // Retain the exact owning result before any fallible observation. A
        // refused descriptor is never discarded, adopted or promoted.
        self.outcome = Some(prepare_original_file(
            authority,
            &self.layout,
            &mut self.acquisition,
        ));
        if let Some(file) = self.held_file() {
            self.descriptor = Some((file.as_raw_fd(), file.metadata()?.ino()));
        }
        self.returned = Some(self.observe_return()?);
        if matches!(
            self.outcome,
            Some(NativeOriginalPreparationOutcome::Prepared(_))
        ) {
            // Keep the existing strict checked blueprint. Pending proposal DATA
            // never substitutes for this check after the real preparation.
            self.blueprint()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(in crate::security_epoch) fn preparation_observation(
        &self,
    ) -> Option<PreparationObservation> {
        self.returned.clone()
    }

    fn held_file(&self) -> Option<&File> {
        match self.outcome.as_ref()? {
            NativeOriginalPreparationOutcome::Prepared(owner) => Some(&owner.file),
            NativeOriginalPreparationOutcome::RefusedAfterAttempt(owner) => owner.file.as_ref(),
            NativeOriginalPreparationOutcome::RefusedBeforeAttempt(_) => None,
        }
    }

    fn bytes(&self, bytes: Vec<u8>) -> PreparationBytes {
        if self.layout.image.bytes().starts_with(&bytes) {
            PreparationBytes::InitialPrefix {
                length: bytes.len(),
            }
        } else {
            PreparationBytes::Other { contents: bytes }
        }
    }

    fn read_file(&self, file: &File) -> Result<Vec<u8>> {
        let length: usize = file.metadata()?.len().try_into()?;
        ensure!(
            length <= MAX_IMAGE_BYTES,
            "preparation observation byte bound"
        );
        let mut bytes = vec![0; length];
        file.read_exact_at(&mut bytes, 0)?;
        Ok(bytes)
    }

    fn observe_return(&self) -> Result<PreparationObservation> {
        let (disposition, authority, proposal, attempted) = match self
            .outcome
            .as_ref()
            .context("preparation outcome missing")?
        {
            NativeOriginalPreparationOutcome::Prepared(owner) => (
                PreparationDisposition::Prepared,
                &owner.authority,
                &owner.proposal,
                true,
            ),
            NativeOriginalPreparationOutcome::RefusedBeforeAttempt(owner) => (
                PreparationDisposition::RefusedBeforeAttempt,
                &owner.authority,
                &owner.proposal,
                false,
            ),
            NativeOriginalPreparationOutcome::RefusedAfterAttempt(owner) => (
                PreparationDisposition::RefusedAfterAttempt,
                &owner.authority,
                &owner.proposal,
                true,
            ),
        };
        let phase = match self.outcome.as_ref().unwrap() {
            NativeOriginalPreparationOutcome::Prepared(_) => PreparationPhase::FinalCheck,
            NativeOriginalPreparationOutcome::RefusedBeforeAttempt(owner) => owner.phase,
            NativeOriginalPreparationOutcome::RefusedAfterAttempt(owner) => owner.phase,
        };
        let stopped_at = match phase {
            PreparationPhase::BeforeAttempt => PreparationCheckpoint::BeforeAttempt,
            PreparationPhase::ExclusiveCreate => PreparationCheckpoint::ExclusiveCreate,
            PreparationPhase::Identity => PreparationCheckpoint::Identity,
            PreparationPhase::Write => PreparationCheckpoint::Write,
            PreparationPhase::FileSync => PreparationCheckpoint::FileSync,
            PreparationPhase::DirectorySync => PreparationCheckpoint::DirectorySync,
            PreparationPhase::Readback => PreparationCheckpoint::Readback,
            PreparationPhase::Decode => PreparationCheckpoint::Decode,
            PreparationPhase::FinalCheck => PreparationCheckpoint::FinalCheck,
        };
        let files = self.observe_files()?;
        Ok(PreparationObservation {
            disposition,
            attempted,
            stopped_at,
            descriptor_returned: self.held_file().is_some(),
            anchor_retained: authority.directory.as_raw_fd() == self.anchor,
            proposal_retained: *proposal == self.layout.proposal,
            selection_matches_admitted: proposal.selection == self.admitted_selection,
            named: files.named,
            held: files.held,
            same_named_and_held: self
                .held_file()
                .map(|file| self.named_matches(file))
                .transpose()?
                .unwrap_or(false),
            foreign: files
                .foreign
                .context("foreign fixture missing after preparation")?,
        })
    }

    fn observe_files(&self) -> Result<PreparationFiles> {
        let leaf = self.directory.path().join(INITIAL_FILE);
        let named = match std::fs::symlink_metadata(&leaf) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => PreparationNamed::Missing,
            Err(error) => return Err(error.into()),
            Ok(meta) if meta.is_dir() => PreparationNamed::Directory,
            Ok(meta) if meta.file_type().is_symlink() => {
                ensure!(
                    std::fs::read_link(&leaf)? == self.directory.path().join("foreign.sqlite"),
                    "foreign symlink changed"
                );
                PreparationNamed::SymlinkToForeign
            }
            Ok(meta) => {
                ensure!(meta.is_file(), "unexpected preparation leaf type");
                PreparationNamed::File {
                    contents: self.bytes(self.read_file(&File::open(&leaf)?)?),
                    links: meta.nlink(),
                }
            }
        };
        let held = self
            .held_file()
            .map(|file| self.read_file(file).map(|bytes| self.bytes(bytes)))
            .transpose()?;
        let foreign = match File::open(self.directory.path().join("foreign.sqlite")) {
            Ok(file) => Some(self.read_file(&file)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        Ok(PreparationFiles {
            named,
            held,
            foreign,
        })
    }

    pub(in crate::security_epoch) fn preparation_files(&self) -> Result<Option<PreparationFiles>> {
        if matches!(
            self.outcome,
            Some(NativeOriginalPreparationOutcome::Prepared(_))
        ) {
            Ok(None)
        } else {
            self.observe_files().map(Some)
        }
    }

    pub(in crate::security_epoch) fn restore_preparation(&mut self) -> Result<()> {
        let refused = matches!(
            self.outcome,
            Some(
                NativeOriginalPreparationOutcome::RefusedBeforeAttempt(_)
                    | NativeOriginalPreparationOutcome::RefusedAfterAttempt(_)
            )
        );
        ensure!(refused, "restoration control requires refused preparation");
        // Repair the injected inputs too. The retained native refusal, rather
        // than a stale wrong proposal or fixture error flag, must prevent use.
        self.layout.fixture_refusal = None;
        self.layout.proposal.selection = self.admitted_selection.clone();
        if let Some(file) = self.held_file() {
            file.write_all_at(self.layout.image.bytes(), 0)?;
            file.set_len(self.layout.image.bytes().len() as u64)?;
        } else {
            let leaf = self.directory.path().join(INITIAL_FILE);
            if let Ok(meta) = std::fs::symlink_metadata(&leaf) {
                if meta.is_dir() {
                    std::fs::remove_dir(&leaf)?;
                } else {
                    std::fs::remove_file(&leaf)?;
                }
            }
        }
        let authority = match self.outcome.as_mut().unwrap() {
            NativeOriginalPreparationOutcome::RefusedBeforeAttempt(owner) => &mut owner.authority,
            NativeOriginalPreparationOutcome::RefusedAfterAttempt(owner) => &mut owner.authority,
            NativeOriginalPreparationOutcome::Prepared(_) => unreachable!(),
        };
        // These assertions run OUTSIDE the expected refusal path: deleting the
        // actual permanent latch must fail the adapter, not become a matching
        // ordinary refusal in both worlds. A new interval cannot repair it.
        ensure!(
            authority.check_current(&mut self.acquisition).is_err(),
            "original preparation refusal cleared"
        );
        ensure!(
            authority.check_current(&mut acquisition()).is_err(),
            "replacement interval restored preparation authority"
        );
        ensure!(
            std::fs::read(self.directory.path().join("foreign.sqlite"))? == FOREIGN_BYTES,
            "foreign bytes changed"
        );
        Ok(())
    }

    pub(in crate::security_epoch) fn check(&mut self, current: bool) -> Result<()> {
        let Some(NativeOriginalPreparationOutcome::Prepared(creator)) = self.outcome.as_mut()
        else {
            anyhow::bail!("actual prepared original required");
        };
        let result = if current {
            (|| {
                creator.authority.check_current(&mut self.acquisition)?;
                let observed = observe_current_anchored_file(
                    &creator.authority.directory,
                    &creator.authority.identity,
                    &creator.file,
                )?;
                ensure!(
                    observed == creator.identity,
                    "lifecycle current physical identity changed"
                );
                let named = std::fs::symlink_metadata(self.directory.path().join(INITIAL_FILE))?;
                let held = creator.file.metadata()?;
                ensure!(
                    named.ino() == held.ino() && named.dev() == held.dev(),
                    "lifecycle current physical leaf changed"
                );
                creator.authority.check_current(&mut self.acquisition)
            })()
        } else {
            creator.check_unchanged_initial_file(&self.layout, &mut self.acquisition)
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
        let Some(NativeOriginalPreparationOutcome::Prepared(creator)) = self.outcome.as_ref()
        else {
            anyhow::bail!("actual prepared blueprint required");
        };
        let selected = &creator.authority.selection;
        ensure!(
            creator.proposal == self.layout.proposal
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
        let Some(NativeOriginalPreparationOutcome::Prepared(creator)) = self.outcome.as_mut()
        else {
            anyhow::bail!("actual prepared file required");
        };
        let leaf = self.directory.path().join(INITIAL_FILE);
        let retained = self.directory.path().join("held-original.sqlite");
        match change {
            FileChange::Tamper => {
                creator
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
                creator.file.set_len(4096)?;
            }
            FileChange::Restore => {
                if retained.exists() {
                    std::fs::remove_file(&leaf)?;
                    std::fs::rename(&retained, &leaf)?;
                }
                creator.file.write_all_at(self.layout.image.bytes(), 0)?;
                if self.initial_failed {
                    // This is an expectation, never a synthetic refusal. Probe
                    // the actual original after restoration so a missing
                    // production latch cannot be hidden by the outer gate.
                    ensure!(
                        creator
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
        let Some(file) = self.held_file() else {
            return Ok(FileState {
                held_original: false,
                named_original: false,
                image_exact: false,
            });
        };
        let metadata = file.metadata()?;
        let bytes = self.read_file(file)?;
        Ok(FileState {
            held_original: self.descriptor == Some((file.as_raw_fd(), metadata.ino())),
            named_original: self.named_matches(file)?,
            image_exact: bytes == self.layout.image.bytes(),
        })
    }

    fn named_matches(&self, file: &File) -> Result<bool> {
        let held = file.metadata()?;
        match std::fs::symlink_metadata(self.directory.path().join(INITIAL_FILE)) {
            Ok(named) => Ok(named.ino() == held.ino() && named.dev() == held.dev()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}
