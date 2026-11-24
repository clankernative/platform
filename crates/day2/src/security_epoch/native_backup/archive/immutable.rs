//! Mechanical immutable archive DATA. This neither supplies a completed native
//! handoff nor exposes upload, source, signing, exclusion or authority APIs.
//! The actual native caller must independently guard every bounded step with
//! its same retained parent and original; no clock is created here.

use super::{CHUNK, ENTRY_LIMIT, FILE_LIMIT, HistoricalArchive, Identity, hash_text};
use crate::backup_archive::{Manifest, NativeArchiveMember, native_archive_commitment};
use anyhow::{Context, Result, ensure};
use day2_capabilities::Digest;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::File,
    io::Write,
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

// Same supported native archive profile; no new file/aggregate allowance.
const TOTAL_BYTES: u64 = 256 * 1024 * 1024 + 16 * 1024 * 1024 + 1024 * 1024;
const MAX_STEPS: usize = 2 * (TOTAL_BYTES as usize).div_ceil(CHUNK) + 7 * ENTRY_LIMIT + 4;

struct SealedMember {
    file: File,
    identity: Identity,
    bytes: u64,
    digest: Digest,
    mode: u32,
}

struct Copying {
    path: PathBuf,
    output: File,
    position: u64,
    hash: ring::digest::Context,
}

struct Readback {
    name: String,
    position: u64,
    hash: ring::digest::Context,
}

/// Only a borrow of the actual historical encoder output. Abandonment drops
/// private partial DATA; a native caller must refuse its own actual parent.
pub(super) struct ImageCopy<'archive> {
    archive: &'archive HistoricalArchive,
    pending: VecDeque<PathBuf>,
    directories: VecDeque<PathBuf>,
    final_files: VecDeque<PathBuf>,
    copying: Option<Copying>,
    readback: Option<Readback>,
    files: BTreeMap<String, SealedMember>,
    total: u64,
    steps: usize,
    refused: bool,
    finishing: bool,
    ready: bool,
}

/// Retains the exact sealed byte image, not a pathname or Manifest-only digest.
/// There is intentionally no completed-handoff or uploader constructor/getter.
pub(super) struct ImmutableArchiveImage {
    manifest: Manifest,
    files: BTreeMap<String, SealedMember>,
    inventory: BTreeMap<String, NativeArchiveMember>,
    commitment: Digest,
}

impl<'archive> ImageCopy<'archive> {
    pub(super) fn new(archive: &'archive HistoricalArchive) -> Result<Self> {
        ensure!(!archive.refused.get(), "backup_image_source_refused");
        archive.tree.check()?;
        ensure!(
            !archive.files.is_empty()
                && archive.files.len() + archive.directories.len() <= ENTRY_LIMIT,
            "backup_image_entry_bound"
        );
        Ok(Self {
            archive,
            pending: archive.files.keys().cloned().collect(),
            directories: archive.directories.keys().cloned().collect(),
            final_files: archive.files.keys().cloned().collect(),
            copying: None,
            readback: None,
            files: BTreeMap::new(),
            total: 0,
            steps: 0,
            refused: false,
            finishing: false,
            ready: false,
        })
    }

    /// One create, at most64KiB copy, seal/file check, or bounded4096-name
    /// directory check. Final inventory hashing is separately memory-bounded.
    /// No blocking retry,
    /// callback, source Connection, upload or native observation is hidden here.
    pub(super) fn step(&mut self) -> Result<bool> {
        ensure!(!self.refused, "backup_image_refused");
        self.refused = true;
        ensure!(!self.archive.refused.get(), "backup_image_source_refused");
        ensure!(!self.ready, "backup_image_spent");
        ensure!(self.steps < MAX_STEPS, "backup_image_step_bound");
        self.steps += 1;
        let done = if let Some(path) = self.directories.pop_front() {
            self.check_directory(&path)?;
            false
        } else if self.finishing {
            if self.readback.is_some() {
                self.readback_step()?;
                false
            } else if let Some(path) = self.final_files.pop_front() {
                self.check_file(&path)?;
                self.readback = Some(Readback {
                    name: path.to_str().context("backup_image_utf8")?.to_owned(),
                    position: 0,
                    hash: ring::digest::Context::new(&ring::digest::SHA256),
                });
                false
            } else {
                self.ready = true;
                true
            }
        } else if self.copying.is_none() && self.pending.is_empty() {
            self.finishing = true;
            self.directories = self.archive.directories.keys().cloned().collect();
            false
        } else {
            self.copy_step()?;
            false
        };
        self.refused = false;
        Ok(done)
    }

    fn readback_step(&mut self) -> Result<()> {
        let reading = self.readback.as_mut().context("backup_image_readback")?;
        let member = self
            .files
            .get(&reading.name)
            .context("backup_image_member")?;
        ensure!(
            reading.position <= member.bytes,
            "backup_image_readback_bound"
        );
        if reading.position < member.bytes {
            let mut buffer = Zeroizing::new([0_u8; CHUNK]);
            let limit = usize::try_from((member.bytes - reading.position).min(CHUNK as u64))?;
            let read = member
                .file
                .read_at(&mut buffer[..limit], reading.position)?;
            ensure!(read != 0, "backup_image_readback_truncated");
            reading.hash.update(&buffer[..read]);
            reading.position += u64::try_from(read)?;
            return Ok(());
        }
        let reading = self.readback.take().context("backup_image_readback")?;
        ensure!(
            hash_text(reading.hash.finish()) == member.digest.as_str(),
            "backup_image_readback_digest"
        );
        check_target(&member.file, member.bytes)?;
        ensure!(
            Identity::of(&member.file.metadata()?) == member.identity,
            "backup_image_identity"
        );
        Ok(())
    }

    fn check_directory(&self, relative: &Path) -> Result<()> {
        self.archive.tree.check()?;
        let (directory, expected) = self
            .archive
            .directories
            .get(relative)
            .context("backup_image_directory")?;
        let before = directory.metadata()?;
        ensure!(
            Identity::of(&before) == *expected && before.mode() & 0o7777 == 0o700,
            "backup_image_directory_changed"
        );
        let wanted = self
            .archive
            .files
            .keys()
            .chain(self.archive.directories.keys())
            .filter(|path| path.parent() == Some(relative))
            .map(|path| {
                path.file_name()
                    .context("backup_image_member")
                    .and_then(|name| name.to_str().context("backup_image_utf8"))
                    .map(str::to_owned)
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let mut observed = BTreeSet::new();
        for entry in rustix::fs::Dir::read_from(directory)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            ensure!(
                name.len() <= 255 && observed.len() < ENTRY_LIMIT,
                "backup_image_directory_bound"
            );
            ensure!(
                observed.insert(std::str::from_utf8(name)?.to_owned()),
                "backup_image_duplicate"
            );
        }
        ensure!(
            observed == wanted && Identity::of(&directory.metadata()?) == *expected,
            "backup_image_inventory"
        );
        Ok(())
    }

    fn check_file(&self, path: &Path) -> Result<()> {
        let source = self
            .archive
            .files
            .get(path)
            .context("backup_image_member")?;
        self.archive
            .tree
            .check_file(path, &source.file, source.identity)?;
        ensure!(
            Identity::of(&source.file.metadata()?) == source.identity,
            "backup_image_source_changed"
        );
        let member = self
            .files
            .get(path.to_str().context("backup_image_utf8")?)
            .context("backup_image_member")?;
        check_target(&member.file, member.bytes)?;
        ensure!(
            Identity::of(&member.file.metadata()?) == member.identity,
            "backup_image_identity"
        );
        Ok(())
    }

    fn copy_step(&mut self) -> Result<()> {
        if self.copying.is_none() {
            let path = self.pending.pop_front().context("backup_image_member")?;
            let held = self
                .archive
                .files
                .get(&path)
                .context("backup_image_member")?;
            self.archive
                .tree
                .check_file(&path, &held.file, held.identity)?;
            let metadata = held.file.metadata()?;
            ensure!(
                Identity::of(&metadata) == held.identity && metadata.len() <= FILE_LIMIT,
                "backup_image_source_changed"
            );
            self.total = self
                .total
                .checked_add(metadata.len())
                .context("backup_image_total")?;
            ensure!(self.total <= TOTAL_BYTES, "backup_image_total");
            self.copying = Some(Copying {
                path,
                output: create_sealed_target()?,
                position: 0,
                hash: ring::digest::Context::new(&ring::digest::SHA256),
            });
            return Ok(());
        }
        let copying = self.copying.as_mut().context("backup_image_copy")?;
        let held = self
            .archive
            .files
            .get(&copying.path)
            .context("backup_image_member")?;
        self.archive
            .tree
            .check_file(&copying.path, &held.file, held.identity)?;
        let before = held.file.metadata()?;
        ensure!(
            Identity::of(&before) == held.identity && copying.position <= before.len(),
            "backup_image_source_changed"
        );
        if copying.position < before.len() {
            let mut buffer = Zeroizing::new([0_u8; CHUNK]);
            let limit = usize::try_from((before.len() - copying.position).min(CHUNK as u64))?;
            let read = held.file.read_at(&mut buffer[..limit], copying.position)?;
            ensure!(read != 0, "backup_image_source_truncated");
            copying.output.write_all(&buffer[..read])?;
            copying.hash.update(&buffer[..read]);
            copying.position += u64::try_from(read)?;
            ensure!(
                Identity::of(&held.file.metadata()?) == held.identity,
                "backup_image_source_changed"
            );
            self.archive
                .tree
                .check_file(&copying.path, &held.file, held.identity)?;
            return Ok(());
        }
        let copying = self.copying.take().context("backup_image_copy")?;
        ensure!(
            hash_text(copying.hash.finish()) == held.digest,
            "backup_image_digest"
        );
        seal_target(&copying.output, copying.position)?;
        let name = copying
            .path
            .to_str()
            .context("backup_image_utf8")?
            .to_owned();
        ensure!(
            self.files
                .insert(
                    name,
                    SealedMember {
                        identity: Identity::of(&copying.output.metadata()?),
                        file: copying.output,
                        bytes: copying.position,
                        digest: Digest::try_from(held.digest.clone())?,
                        mode: before.mode() & 0o7777,
                    }
                )
                .is_none(),
            "backup_image_duplicate"
        );
        Ok(())
    }

    pub(super) fn finish(self) -> Result<ImmutableArchiveImage> {
        ensure!(!self.archive.refused.get(), "backup_image_source_refused");
        ensure!(
            !self.refused
                && self.ready
                && self.copying.is_none()
                && self.readback.is_none()
                && self.pending.is_empty()
                && self.files.len() == self.archive.files.len(),
            "backup_image_incomplete"
        );
        let mut inventory = BTreeMap::new();
        for path in self.archive.directories.keys() {
            inventory.insert(
                path.to_str().context("backup_image_utf8")?.to_owned(),
                NativeArchiveMember::Directory { mode: 0o700 },
            );
        }
        for (path, member) in &self.files {
            ensure!(
                inventory
                    .insert(
                        path.clone(),
                        NativeArchiveMember::File {
                            bytes: member.bytes,
                            sha256: member.digest.clone(),
                            mode: member.mode,
                        }
                    )
                    .is_none(),
                "backup_image_duplicate"
            );
        }
        let manifest = crate::json::decode_evidence(&serde_json::to_vec(&self.archive.manifest)?)?;
        let commitment = native_archive_commitment(&manifest, &inventory)?;
        ensure!(
            commitment == self.archive.commitment,
            "backup_image_commitment"
        );
        let image = ImmutableArchiveImage {
            manifest,
            files: self.files,
            inventory,
            commitment,
        };
        image.check_inventory()?;
        Ok(image)
    }
}

impl ImmutableArchiveImage {
    /// Pure bounded inventory DATA check. Each sealed handle is separately
    /// checked by its explicit per-member transition, not hidden in this loop.
    fn check_inventory(&self) -> Result<()> {
        ensure!(
            !self.files.is_empty()
                && self.inventory.len() <= ENTRY_LIMIT
                && self
                    .inventory
                    .values()
                    .filter(|member| matches!(member, NativeArchiveMember::File { .. }))
                    .count()
                    == self.files.len(),
            "backup_image_entry_bound"
        );
        let mut total = 0_u64;
        for (name, member) in &self.files {
            ensure!(
                matches!(self.inventory.get(name), Some(NativeArchiveMember::File { bytes, sha256, mode })
                if *bytes == member.bytes && *sha256 == member.digest && *mode == member.mode),
                "backup_image_inventory"
            );
            total = total
                .checked_add(member.bytes)
                .context("backup_image_total")?;
            ensure!(
                member.bytes <= FILE_LIMIT && total <= TOTAL_BYTES,
                "backup_image_total"
            );
        }
        ensure!(
            native_archive_commitment(&self.manifest, &self.inventory)? == self.commitment,
            "backup_image_commitment"
        );
        Ok(())
    }

    fn check_member(&self, name: &str) -> Result<()> {
        let member = self.files.get(name).context("backup_image_member")?;
        check_target(&member.file, member.bytes)?;
        ensure!(
            Identity::of(&member.file.metadata()?) == member.identity,
            "backup_image_identity"
        );
        Ok(())
    }

    #[cfg(test)]
    fn check(&self) -> Result<()> {
        self.check_inventory()?;
        for name in self.files.keys() {
            self.check_member(name)?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn create_sealed_target() -> Result<File> {
    Ok(File::from(rustix::fs::memfd_create(
        "day2-backup-immutable-member",
        rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
    )?))
}

#[cfg(target_os = "linux")]
fn check_target(file: &File, bytes: u64) -> Result<()> {
    use rustix::fs::SealFlags;
    let required = SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL;
    ensure!(
        rustix::fs::fcntl_get_seals(file)?.contains(required)
            && file.metadata()?.is_file()
            && file.metadata()?.len() == bytes,
        "backup_image_not_sealed"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn seal_target(file: &File, bytes: u64) -> Result<()> {
    use rustix::fs::SealFlags;
    rustix::fs::fcntl_add_seals(
        file,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )?;
    check_target(file, bytes)
}

#[cfg(not(target_os = "linux"))]
fn create_sealed_target() -> Result<File> {
    anyhow::bail!("backup_image_linux_sealing_required")
}
#[cfg(not(target_os = "linux"))]
fn check_target(_file: &File, _bytes: u64) -> Result<()> {
    anyhow::bail!("backup_image_linux_sealing_required")
}
#[cfg(not(target_os = "linux"))]
fn seal_target(_file: &File, _bytes: u64) -> Result<()> {
    anyhow::bail!("backup_image_linux_sealing_required")
}

#[cfg(all(test, not(target_os = "linux")))]
mod unsupported_tests {
    use super::*;

    #[test]
    fn unavailable_kernel_sealing_refuses_instead_of_returning_a_path_or_mutable_image()
    -> Result<()> {
        let file = tempfile::tempfile()?;
        for error in [
            create_sealed_target()
                .err()
                .context("unsupported image target admitted")?,
            check_target(&file, 0).unwrap_err(),
            seal_target(&file, 0).unwrap_err(),
        ] {
            assert_eq!(error.to_string(), "backup_image_linux_sealing_required");
        }
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn fresh_sealed_member_refuses_writes_growth_shrink_and_unsealed_substitution() -> Result<()> {
        use rustix::fs::SealFlags;
        let mut file = create_sealed_target()?;
        file.write_all(b"controlled historical DATA, not an authority fixture")?;
        let bytes = file.metadata()?.len();
        let mut prior_alias = file.try_clone()?;
        assert!(check_target(&file, bytes).is_err());
        seal_target(&file, bytes)?;
        assert!(file.write_all(b"changed").is_err());
        assert!(prior_alias.write_all(b"changed").is_err());
        assert!(file.set_len(bytes - 1).is_err());
        assert!(file.set_len(bytes + 1).is_err());
        check_target(&prior_alias, bytes)?;
        assert!(check_target(&file, bytes + 1).is_err());
        let mut unsealed = create_sealed_target()?;
        unsealed.write_all(&vec![0; usize::try_from(bytes)?])?;
        assert!(check_target(&unsealed, bytes).is_err());
        rustix::fs::fcntl_add_seals(
            &unsealed,
            SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
        )?;
        assert!(check_target(&unsealed, bytes).is_err());
        assert!(seal_target(&unsealed, bytes).is_err());
        Ok(())
    }
}

// Normal Build fixture only: actual production encoder and sealing machinery,
// never a native owner, accepting handoff, destination or upload constructor.
#[cfg(all(test, target_os = "linux"))]
pub(super) fn fixture_cuts(
    image: &super::super::SnapshotImage,
    manifest: &Manifest,
    artifact: &crate::artifact::LoadedArtifact,
) -> Result<()> {
    use super::super::{CopyProgress, SnapshotImage};
    use super::ArchiveWriter;
    let fresh = || -> Result<HistoricalArchive> {
        let copied = SnapshotImage {
            bytes: Zeroizing::new(image.bytes.to_vec()),
        };
        let manifest = crate::json::decode_evidence(&serde_json::to_vec(manifest)?)?;
        let mut writer = ArchiveWriter::new(copied, manifest, artifact)?;
        while writer.step()? != CopyProgress::Complete {}
        writer.finish()
    };
    for _ in 0..2 {
        let archive = fresh()?;
        let mut copying = ImageCopy::new(&archive)?;
        while !copying.step()? {}
        let mut frozen = copying.finish()?;
        frozen.check()?;
        let expected = std::fs::read(archive.directory().join("backup.json"))?;
        std::fs::write(archive.directory().join("backup.json"), b"{}")?;
        // Changing/replacing the named source cannot alter the held image.
        frozen.check()?;
        let member = frozen
            .files
            .get("backup.json")
            .context("backup_image_fixture_manifest")?;
        let mut received = vec![0; expected.len()];
        member.file.read_exact_at(&mut received, 0)?;
        assert_eq!(received, expected);
        assert!(archive.check().is_err());
        let held = frozen.files.remove("backup.json").unwrap();
        assert!(frozen.check().is_err());
        frozen.files.insert("backup.json".into(), held);
        frozen.check()?;
        let row = frozen.inventory.remove("backup.json").unwrap();
        assert!(frozen.check().is_err());
        frozen.inventory.insert("backup.json".into(), row);
        frozen.check()?;
        frozen.inventory.insert(
            "extra".into(),
            NativeArchiveMember::Directory { mode: 0o700 },
        );
        assert!(frozen.check().is_err());
        frozen.inventory.remove("extra");
        let held = frozen.files.get_mut("backup.json").unwrap();
        let mut replacement = create_sealed_target()?;
        replacement.write_all(&vec![0; usize::try_from(held.bytes)?])?;
        seal_target(&replacement, held.bytes)?;
        let original = std::mem::replace(&mut held.file, replacement);
        assert!(frozen.check().is_err());
        frozen.files.get_mut("backup.json").unwrap().file = original;
        frozen.check()?;

        let archive = fresh()?;
        let mut copying = ImageCopy::new(&archive)?;
        std::fs::write(archive.directory().join("backup.json"), b"{}")?;
        loop {
            match copying.step() {
                Ok(false) => {}
                Ok(true) => anyhow::bail!("changed archive was accepted"),
                Err(_) => break,
            }
        }
        assert!(copying.step().is_err());
        assert!(copying.finish().is_err());

        let archive = fresh()?;
        let mut copying = ImageCopy::new(&archive)?;
        loop {
            assert!(!copying.step()?);
            if let Some(member) = &copying.copying
                && member.path == Path::new("backup.json")
                && member.position == archive.files[&member.path].file.metadata()?.len()
            {
                let mut byte = [0];
                member.output.read_exact_at(&mut byte, 0)?;
                byte[0] ^= 1;
                member.output.write_all_at(&byte, 0)?;
                break;
            }
        }
        // Mutate the actual target before sealing, after its source hash was
        // collected. Only the real sealed-target readback can detect this cut.
        loop {
            match copying.step() {
                Ok(false) => {}
                Ok(true) => anyhow::bail!("changed sealed target was accepted"),
                Err(error) => {
                    assert_eq!(error.to_string(), "backup_image_readback_digest");
                    break;
                }
            }
        }
        assert!(copying.finish().is_err());
        archive.check()?;

        let archive = fresh()?;
        let mut copying = ImageCopy::new(&archive)?;
        while !copying.step()? {}
        assert!(copying.step().is_err());
        assert!(copying.finish().is_err());

        let archive = fresh()?;
        let mut copying = ImageCopy::new(&archive)?;
        std::fs::write(archive.directory().join("unexpected"), b"fixture")?;
        assert!(archive.check().is_err());
        assert_eq!(
            copying.step().unwrap_err().to_string(),
            "backup_image_source_refused"
        );
        assert!(copying.step().is_err());
        assert!(copying.finish().is_err());

        let archive = fresh()?;
        let mut copying = ImageCopy::new(&archive)?;
        while !copying.step()? {}
        std::fs::write(archive.directory().join("unexpected"), b"fixture")?;
        assert!(archive.check().is_err());
        let error = copying
            .finish()
            .err()
            .context("refused source became an image")?;
        assert_eq!(error.to_string(), "backup_image_source_refused");
    }
    Ok(())
}
