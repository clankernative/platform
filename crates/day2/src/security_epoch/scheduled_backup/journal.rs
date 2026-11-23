//! Bounded append-only attempt-file mechanics, NOT native admission.
//!
//! No runtime caller is installed. A future accepting Controller must separately
//! retain its genuine physical root, protected requester, original and external
//! create-only birth binding. A complete file/row, nonce, checksum or file lock
//! never supplies these owners or proves that a disk was not rolled back.
//!
//! Only the same qualified nonrollback root may use an absent slot as preparation
//! DATA. Missing/replaced activated state, ambiguous birth and malformed tails
//! must refuse; never recreate, repair, truncate, adopt or retry them. ACK must
//! follow file+directory durability and actual native postchecks, before counter
//! May. Every complete attempt is spent even when ACK or remote outcome is lost.
use super::{Intent, ScheduledSlot, Slot, WorkloadUid, decode_canonical};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{Digest, security_epoch::AuthorityScope};
use rustix::fs::{AtFlags, Mode, OFlags};
use serde::{Deserialize, Serialize};
use std::{
    cell::Cell,
    collections::BTreeSet,
    fs::{File, Metadata},
    io::{Read, Seek, SeekFrom, Write},
    marker::PhantomData,
    os::unix::fs::MetadataExt,
    rc::Rc,
};

const FILE_NAME: &str = "attempts-v1.log";
const ROOT_DOMAIN: &str = "day2-scheduled-backup-root-v1";
const RECORD_DOMAIN: &str = "day2-scheduled-backup-journal-v1";
const MAX_RECORDS: usize = 4_096;
const MAX_LINE: usize = 1_024;
const MAX_BYTES: usize = 2_097_152;

pub(in crate::security_epoch) mod birth;
mod root_files;
pub(in crate::security_epoch) use root_files::PendingRootFiles;

#[cfg(test)]
mod tests;

/// Historical binding DATA. Neither deserialization nor equality authenticates
/// an external birth acknowledgement, persistent disk, or Controller creator.
/// Epoch/key/generation/Job/operation are deliberately absent from the address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootBindingData {
    scope: AuthorityScope,
    cron_job_uid: WorkloadUid,
    physical_disk: Digest,
    creator_nonce: Digest,
}

impl RootBindingData {
    fn key_data(&self) -> Result<Digest> {
        Digest::of(&(ROOT_DOMAIN, &self.scope, &self.cron_job_uid))
    }

    fn require_slot_data(&self, slot: &Slot) -> Result<()> {
        ensure!(
            self.scope == slot.scope && self.cron_job_uid == slot.cron_job_uid,
            "backup_journal_domain_changed"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderData {
    format: u8,
    binding: RootBindingData,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordData {
    ordinal: u32,
    scheduled_at: ScheduledSlot,
    intent: Digest,
    previous: Digest,
    checksum: Digest,
}

impl RecordData {
    fn checksum_data(&self) -> Result<Digest> {
        Digest::of(&(
            RECORD_DOMAIN,
            self.ordinal,
            &self.scheduled_at,
            &self.intent,
            &self.previous,
        ))
    }
}

/// Entire validated historical image, never a runtime acknowledgement. Valid
/// emptiness alone is NOT a new attempt permission or nonrollback evidence.
struct ImageData {
    bytes: Vec<u8>,
    binding: RootBindingData,
    slots: BTreeSet<String>,
    tail: Digest,
}

fn line_data<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() < MAX_LINE, "backup_journal_line_bound");
    bytes.push(b'\n');
    Ok(bytes)
}

impl ImageData {
    fn new_data(binding: RootBindingData) -> Result<Self> {
        let header = HeaderData { format: 1, binding };
        let bytes = line_data(&header)?;
        Self::decode_data(&bytes, &header.binding)
    }

    fn decode_data(bytes: &[u8], expected: &RootBindingData) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_BYTES && bytes.last() == Some(&b'\n'),
            "backup_journal_incomplete_or_bound"
        );
        let mut lines = bytes[..bytes.len() - 1].split(|byte| *byte == b'\n');
        let header_bytes = lines.next().context("backup_journal_header_missing")?;
        ensure!(header_bytes.len() < MAX_LINE, "backup_journal_line_bound");
        let header: HeaderData = decode_canonical(header_bytes)?;
        ensure!(
            header.format == 1 && &header.binding == expected,
            "backup_journal_birth_changed"
        );
        let mut tail = Digest::of(&(ROOT_DOMAIN, &header))?;
        let mut slots = BTreeSet::new();
        for (index, line) in lines.enumerate() {
            ensure!(
                index < MAX_RECORDS && !line.is_empty() && line.len() < MAX_LINE,
                "backup_journal_record_bound"
            );
            let record: RecordData = decode_canonical(line)?;
            ensure!(
                usize::try_from(record.ordinal)? == index + 1
                    && record.previous == tail
                    && record.checksum == record.checksum_data()?
                    && slots.insert(record.scheduled_at.0.clone()),
                "backup_journal_chain_or_duplicate"
            );
            tail = record.checksum;
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            binding: header.binding,
            slots,
            tail,
        })
    }

    fn append_data(&self, intent: &Intent) -> Result<Vec<u8>> {
        self.binding.require_slot_data(&intent.slot)?;
        ensure!(
            self.slots.len() < MAX_RECORDS && !self.slots.contains(&intent.slot.scheduled_at.0),
            "backup_journal_slot_spent_or_full"
        );
        let mut record = RecordData {
            ordinal: u32::try_from(self.slots.len() + 1)?,
            scheduled_at: intent.slot.scheduled_at.clone(),
            intent: intent.commitment_data()?,
            previous: self.tail.clone(),
            checksum: self.tail.clone(),
        };
        record.checksum = record.checksum_data()?;
        let bytes = line_data(&record)?;
        ensure!(
            self.bytes
                .len()
                .checked_add(bytes.len())
                .context("backup_journal_size")?
                <= MAX_BYTES,
            "backup_journal_image_bound"
        );
        Ok(bytes)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct CreatorData {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    links: u64,
}

impl CreatorData {
    fn of(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            links: metadata.nlink(),
        }
    }
}

/// Owns filesystem resources only. No native factory or runtime caller exists.
/// The borrowed parent must ultimately be the actual admitted fixed private
/// domain directory; this component cannot obtain, create or authenticate it.
/// Retain exclusive ownership through durability and the caller's final guards.
struct AttemptFile<'root> {
    parent: &'root File,
    file: File,
    parent_creator: CreatorData,
    creator: CreatorData,
    image: ImageData,
    refused: Cell<bool>,
    thread_bound: PhantomData<Rc<()>>,
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <AttemptFile<'static> as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(Clone);
    assert_not_impl!(Copy);
    assert_not_impl!(Default);
    assert_not_impl!(std::fmt::Debug);
    assert_not_impl!(Send);
    assert_not_impl!(Sync);
    assert_not_impl!(serde::Serialize);
    assert_not_impl!(serde::Deserialize<'static>);
    assert_not_impl!(std::os::fd::AsFd);
    assert_not_impl!(std::os::fd::AsRawFd);
    assert_not_impl!(std::os::fd::IntoRawFd);
    assert_not_impl!(std::ops::Deref);
    assert_not_impl!(AsRef<File>);
    assert_not_impl!(std::borrow::Borrow<File>);
};

impl<'root> AttemptFile<'root> {
    /// Mechanical create-only initialization, NOT activation. On ANY ambiguous
    /// initialization outcome preserve the orphan; runtime must never adopt it.
    fn create_new(parent: &'root File, binding: RootBindingData) -> Result<Self> {
        let image = ImageData::new_data(binding)?;
        require_parent(parent)?;
        let file = File::from(rustix::fs::openat(
            parent,
            FILE_NAME,
            OFlags::RDWR
                | OFlags::APPEND
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        file.try_lock()?;
        let mut value = Self::hold(parent, file, image)?;
        value.file.write_all(&value.image.bytes)?;
        value.file.sync_all()?;
        value.parent.sync_all()?;
        value.require_identity()?;
        value.require_image()?;
        value.require_identity()?;
        value.refused.set(false);
        Ok(value)
    }

    /// Mechanical existing-only decoding. A native caller still needs the SAME
    /// known activated root and independently qualified nonrollback history.
    /// There is no create-on-missing, repair, truncation, reset or rollover.
    fn open_existing(parent: &'root File, binding: &RootBindingData) -> Result<Self> {
        require_parent(parent)?;
        let mut file = File::from(rustix::fs::openat(
            parent,
            FILE_NAME,
            OFlags::RDWR | OFlags::APPEND | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        file.try_lock()?;
        require_file(parent, &file)?;
        let bytes = read_data(&mut file)?;
        let image = ImageData::decode_data(&bytes, binding)?;
        let mut value = Self::hold(parent, file, image)?;
        value.require_identity()?;
        value.require_image()?;
        value.require_identity()?;
        value.refused.set(false);
        Ok(value)
    }

    fn hold(parent: &'root File, file: File, image: ImageData) -> Result<Self> {
        require_parent(parent)?;
        require_file(parent, &file)?;
        let parent_metadata = parent.metadata()?;
        let metadata = file.metadata()?;
        let value = Self {
            parent,
            parent_creator: CreatorData::of(&parent_metadata),
            creator: CreatorData::of(&metadata),
            file,
            image,
            refused: Cell::new(true),
            thread_bound: PhantomData,
        };
        value.require_identity()?;
        Ok(value)
    }

    fn require_identity(&self) -> Result<()> {
        ensure!(
            CreatorData::of(&self.parent.metadata()?) == self.parent_creator
                && CreatorData::of(&self.file.metadata()?) == self.creator,
            "backup_journal_held_changed"
        );
        let named = rustix::fs::statat(self.parent, FILE_NAME, AtFlags::SYMLINK_NOFOLLOW)?;
        ensure!(
            number(named.st_dev)? == self.creator.device
                && number(named.st_ino)? == self.creator.inode
                && number(named.st_mode)? == u64::from(self.creator.mode)
                && number(named.st_uid)? == u64::from(self.creator.uid)
                && number(named.st_nlink)? == self.creator.links,
            "backup_journal_named_changed"
        );
        Ok(())
    }

    fn require_image(&mut self) -> Result<()> {
        let bytes = read_data(&mut self.file)?;
        ensure!(bytes == self.image.bytes, "backup_journal_contents_changed");
        Ok(())
    }

    /// Returns only historical commitment DATA after local durability and
    /// readback. It is NOT a native ACK; native postguards and known activation
    /// must still succeed before counter May. Failure is sticky on this owner;
    /// partial tails remain on disk and refuse every existing-only decoder.
    fn append(&mut self, intent: &Intent) -> Result<Digest> {
        ensure!(!self.refused.replace(true), "backup_journal_owner_refused");
        self.require_identity()?;
        self.require_image()?;
        let bytes = self.image.append_data(intent)?;
        self.file.write_all(&bytes)?;
        self.file.sync_all()?;
        self.parent.sync_all()?;
        self.require_identity()?;
        let all = read_data(&mut self.file)?;
        let mut expected = self.image.bytes.clone();
        expected.extend_from_slice(&bytes);
        ensure!(all == expected, "backup_journal_append_changed");
        self.image = ImageData::decode_data(&all, &self.image.binding)?;
        self.require_identity()?;
        self.refused.set(false);
        Ok(self.image.tail.clone())
    }
}

fn number(value: impl TryInto<u64>) -> Result<u64> {
    value
        .try_into()
        .map_err(|_| anyhow::anyhow!("backup_journal_identity_width"))
}

fn require_parent(parent: &File) -> Result<()> {
    let metadata = parent.metadata()?;
    ensure!(
        metadata.is_dir() && metadata.mode() & 0o7777 == 0o700,
        "backup_journal_parent_profile"
    );
    Ok(())
}

fn require_file(parent: &File, file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.mode() & 0o7777 == 0o600
            && metadata.nlink() == 1
            && metadata.uid() == parent.metadata()?.uid(),
        "backup_journal_file_profile"
    );
    Ok(())
}

fn read_data(file: &mut File) -> Result<Vec<u8>> {
    ensure!(
        file.metadata()?.len() <= u64::try_from(MAX_BYTES)?,
        "backup_journal_file_bound"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(MAX_BYTES + 1)?)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_BYTES, "backup_journal_file_bound");
    Ok(bytes)
}
